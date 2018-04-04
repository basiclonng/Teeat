/*
 *  The RSA public-key cryptosystem
 *
 *  Copyright (C) 2006-2010, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
/*
 *  RSA was designed by Ron Rivest, Adi Shamir and Len Adleman.
 *
 *  http://theory.lcs.mit.edu/~rivest/rsapaper.pdf
 *  http://www.cacr.math.uwaterloo.ca/hac/about/chap8.pdf
 */

#include "config.h"
#include "ADIBL_MD5.h"
#include "ADIBL_Sha1_Sha256.h"
#include "ADIBL_RSA.h"
#include "ADIBL_CRC.h"

#if defined(POLARSSL_RSA_C)

#include "polarssl_rsa.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "time.h"
/*
 * Initialize an RSA context
 */
void rsa_init( rsa_context *ctx,
               int padding,
               int hash_id )
{
    memset( ctx, 0, sizeof( rsa_context ) );

    ctx->padding = padding;
    ctx->hash_id = hash_id;
}

#if defined(POLARSSL_GENPRIME)

/*
 * Generate an RSA keypair
 */
int rsa_gen_key( rsa_context *ctx,
        int (*f_rng)(void *),
        void *p_rng,
        int nbits, int exponent )
{
    int ret;
    mpi P1, Q1, H, G;

    if( f_rng == NULL || nbits < 128 || exponent < 3 )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    mpi_init( &P1, &Q1, &H, &G, NULL );

    /*
     * find primes P and Q with Q < P so that:
     * GCD( E, (P-1)*(Q-1) ) == 1
     */
    MPI_CHK( mpi_lset( &ctx->E, exponent ) );

    do
    {
        MPI_CHK( mpi_gen_prime( &ctx->P, ( nbits + 1 ) >> 1, 0, 
                                f_rng, p_rng ) );

        MPI_CHK( mpi_gen_prime( &ctx->Q, ( nbits + 1 ) >> 1, 0,
                                f_rng, p_rng ) );

        if( mpi_cmp_mpi( &ctx->P, &ctx->Q ) < 0 )
            mpi_swap( &ctx->P, &ctx->Q );

        if( mpi_cmp_mpi( &ctx->P, &ctx->Q ) == 0 )
            continue;

        MPI_CHK( mpi_mul_mpi( &ctx->N, &ctx->P, &ctx->Q ) );
        if( mpi_msb( &ctx->N ) != nbits )
            continue;

        MPI_CHK( mpi_sub_int( &P1, &ctx->P, 1 ) );
        MPI_CHK( mpi_sub_int( &Q1, &ctx->Q, 1 ) );
        MPI_CHK( mpi_mul_mpi( &H, &P1, &Q1 ) );
        MPI_CHK( mpi_gcd( &G, &ctx->E, &H  ) );
    }
    while( mpi_cmp_int( &G, 1 ) != 0 );

    /*
     * D  = E^-1 mod ((P-1)*(Q-1))
     * DP = D mod (P - 1)
     * DQ = D mod (Q - 1)
     * QP = Q^-1 mod P
     */
    MPI_CHK( mpi_inv_mod( &ctx->D , &ctx->E, &H  ) );
    MPI_CHK( mpi_mod_mpi( &ctx->DP, &ctx->D, &P1 ) );
    MPI_CHK( mpi_mod_mpi( &ctx->DQ, &ctx->D, &Q1 ) );
    MPI_CHK( mpi_inv_mod( &ctx->QP, &ctx->Q, &ctx->P ) );

    ctx->len = ( mpi_msb( &ctx->N ) + 7 ) >> 3;

cleanup:

    mpi_free( &G, &H, &Q1, &P1, NULL );

    if( ret != 0 )
    {
        rsa_free( ctx );
        return( POLARSSL_ERR_RSA_KEY_GEN_FAILED | ret );
    }

    return( 0 );   
}

#endif

/*
 * Check a public RSA key
 */
int rsa_check_pubkey( const rsa_context *ctx )
{
    if( !ctx->N.p || !ctx->E.p )
        return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );

    if( ( ctx->N.p[0] & 1 ) == 0 || 
        ( ctx->E.p[0] & 1 ) == 0 )
        return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );

    if( mpi_msb( &ctx->N ) < 128 ||
        mpi_msb( &ctx->N ) > 4096 )
        return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );

    if( mpi_msb( &ctx->E ) < 2 ||
        mpi_msb( &ctx->E ) > 64 )
        return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );

    return( 0 );
}

/*
 * Check a private RSA key
 */
int rsa_check_privkey( const rsa_context *ctx )
{
    int ret;
    mpi PQ, DE, P1, Q1, H, I, G, G2, L1, L2;

    if( ( ret = rsa_check_pubkey( ctx ) ) != 0 )
        return( ret );

    if( !ctx->P.p || !ctx->Q.p || !ctx->D.p )
        return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );

    mpi_init( &PQ, &DE, &P1, &Q1, &H, &I, &G, &G2, &L1, &L2, NULL );

    MPI_CHK( mpi_mul_mpi( &PQ, &ctx->P, &ctx->Q ) );
    MPI_CHK( mpi_mul_mpi( &DE, &ctx->D, &ctx->E ) );
    MPI_CHK( mpi_sub_int( &P1, &ctx->P, 1 ) );
    MPI_CHK( mpi_sub_int( &Q1, &ctx->Q, 1 ) );
    MPI_CHK( mpi_mul_mpi( &H, &P1, &Q1 ) );
    MPI_CHK( mpi_gcd( &G, &ctx->E, &H  ) );

    MPI_CHK( mpi_gcd( &G2, &P1, &Q1 ) );
    MPI_CHK( mpi_div_mpi( &L1, &L2, &H, &G2 ) );  
    MPI_CHK( mpi_mod_mpi( &I, &DE, &L1  ) );

    /*
     * Check for a valid PKCS1v2 private key
     */
    if( mpi_cmp_mpi( &PQ, &ctx->N ) == 0 &&
        mpi_cmp_int( &L2, 0 ) == 0 &&
        mpi_cmp_int( &I, 1 ) == 0 &&
        mpi_cmp_int( &G, 1 ) == 0 )
    {
        mpi_free( &G, &I, &H, &Q1, &P1, &DE, &PQ, &G2, &L1, &L2, NULL );
        return( 0 );
    }

    
cleanup:

    mpi_free( &G, &I, &H, &Q1, &P1, &DE, &PQ, &G2, &L1, &L2, NULL );
    return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED | ret );
}

/*
 * Do an RSA public key operation
 */
int rsa_public( rsa_context *ctx,
                const unsigned char *input,
                unsigned char *output )
{
    int ret, olen;
    mpi T;

    mpi_init( &T, NULL );

    MPI_CHK( mpi_read_binary( &T, input, ctx->len ) );

    if( mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        mpi_free( &T, NULL );
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
    }

    olen = ctx->len;
    MPI_CHK( mpi_exp_mod( &T, &T, &ctx->E, &ctx->N, &ctx->RN ) );
    MPI_CHK( mpi_write_binary( &T, output, olen ) );

cleanup:

    mpi_free( &T, NULL );

    if( ret != 0 )
        return( POLARSSL_ERR_RSA_PUBLIC_FAILED | ret );

    return( 0 );
}

/*
 * Do an RSA private key operation
 */
int rsa_private( rsa_context *ctx,
                 const unsigned char *input,
                 unsigned char *output )
{
    int ret, olen;
    mpi T, T1, T2;

    mpi_init( &T, &T1, &T2, NULL );

    MPI_CHK( mpi_read_binary( &T, input, ctx->len ) );

    if( mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        mpi_free( &T, NULL );
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
    }

#if 0
    MPI_CHK( mpi_exp_mod( &T, &T, &ctx->D, &ctx->N, &ctx->RN ) );
#else
    /*
     * faster decryption using the CRT
     *
     * T1 = input ^ dP mod P
     * T2 = input ^ dQ mod Q
     */
    MPI_CHK( mpi_exp_mod( &T1, &T, &ctx->DP, &ctx->P, &ctx->RP ) );
    MPI_CHK( mpi_exp_mod( &T2, &T, &ctx->DQ, &ctx->Q, &ctx->RQ ) );

    /*
     * T = (T1 - T2) * (Q^-1 mod P) mod P
     */
    MPI_CHK( mpi_sub_mpi( &T, &T1, &T2 ) );
    MPI_CHK( mpi_mul_mpi( &T1, &T, &ctx->QP ) );
    MPI_CHK( mpi_mod_mpi( &T, &T1, &ctx->P ) );

    /*
     * output = T2 + T * Q
     */
    MPI_CHK( mpi_mul_mpi( &T1, &T, &ctx->Q ) );
    MPI_CHK( mpi_add_mpi( &T, &T2, &T1 ) );
#endif

    olen = ctx->len;
    MPI_CHK( mpi_write_binary( &T, output, olen ) );

cleanup:

    mpi_free( &T, &T1, &T2, NULL );

    if( ret != 0 )
        return( POLARSSL_ERR_RSA_PRIVATE_FAILED | ret );

    return( 0 );
}

/*
 * Add the message padding, then do an RSA operation
 */
int rsa_pkcs1_encrypt( rsa_context *ctx,
                       int (*f_rng)(void *),
                       void *p_rng,
                       int mode, int  ilen,
                       const unsigned char *input,
                       unsigned char *output )
{
    int nb_pad, olen;
    unsigned char *p = output;

    olen = ctx->len;

    switch( ctx->padding )
    {
        case RSA_PKCS_V15:

            if( ilen < 0 || olen < ilen + 11 || f_rng == NULL )
                return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

            nb_pad = olen - 3 - ilen;

            *p++ = 0;
            *p++ = RSA_CRYPT;

            while( nb_pad-- > 0 )
            {
                int rng_dl = 100;

                do {
                    *p = (unsigned char) f_rng( p_rng );
                } while( *p == 0 && --rng_dl );

                // Check if RNG failed to generate data
                //
                if( rng_dl == 0 )
                    return POLARSSL_ERR_RSA_RNG_FAILED;

                p++;
            }
            *p++ = 0;
            memcpy( p, input, ilen );
            break;

        default:

            return( POLARSSL_ERR_RSA_INVALID_PADDING );
    }

    return( ( mode == RSA_PUBLIC )
            ? rsa_public(  ctx, output, output )
            : rsa_private( ctx, output, output ) );
}

/*
 * Do an RSA operation, then remove the message padding
 */
int rsa_pkcs1_decrypt( rsa_context *ctx,
                       int mode, int *olen,
                       const unsigned char *input,
                       unsigned char *output,
                       int output_max_len)
{
    int ret, ilen;
    unsigned char *p;
    unsigned char buf[1024];

    ilen = ctx->len;

    if( ilen < 16 || ilen > (int) sizeof( buf ) )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    ret = ( mode == RSA_PUBLIC )
          ? rsa_public(  ctx, input, buf )
          : rsa_private( ctx, input, buf );

    if( ret != 0 )
        return( ret );

    p = buf;

    switch( ctx->padding )
    {
        case RSA_PKCS_V15:

            if( *p++ != 0 || *p++ != RSA_CRYPT )
                return( POLARSSL_ERR_RSA_INVALID_PADDING );

            while( *p != 0 )
            {
                if( p >= buf + ilen - 1 )
                    return( POLARSSL_ERR_RSA_INVALID_PADDING );
                p++;
            }
            p++;
            break;

        default:

            return( POLARSSL_ERR_RSA_INVALID_PADDING );
    }

    if (ilen - (int)(p - buf) > output_max_len)
    	return( POLARSSL_ERR_RSA_OUTPUT_TOO_LARGE );

    *olen = ilen - (int)(p - buf);
    memcpy( output, p, *olen );

    return( 0 );
}

/*
 * Do an RSA operation to sign the message digest
 */
int rsa_pkcs1_sign( rsa_context *ctx,
                    int mode,
                    int hash_id,
                    int hashlen,
                    const unsigned char *hash,
                    unsigned char *sig )
{
    int nb_pad, olen;
    unsigned char *p = sig;

    olen = ctx->len;

    switch( ctx->padding )
    {
        case RSA_PKCS_V15:

            switch( hash_id )
            {
                case SIG_RSA_RAW:
                    nb_pad = olen - 3 - hashlen;
                    break;

                case SIG_RSA_MD2:
                case SIG_RSA_MD4:
                case SIG_RSA_MD5:
                    nb_pad = olen - 3 - 34;
                    break;

                case SIG_RSA_SHA1:
                    nb_pad = olen - 3 - 35;
                    break;

                case SIG_RSA_SHA224:
                    nb_pad = olen - 3 - 47;
                    break;

                case SIG_RSA_SHA256:
                    nb_pad = olen - 3 - 51;
                    break;

                case SIG_RSA_SHA384:
                    nb_pad = olen - 3 - 67;
                    break;

                case SIG_RSA_SHA512:
                    nb_pad = olen - 3 - 83;
                    break;


                default:
                    return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
            }

            if( nb_pad < 8 )
                return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

            *p++ = 0;
            *p++ = RSA_SIGN;
            memset( p, 0xFF, nb_pad );
            p += nb_pad;
            *p++ = 0;
            break;

        default:

            return( POLARSSL_ERR_RSA_INVALID_PADDING );
    }

    switch( hash_id )
    {
        case SIG_RSA_RAW:
            memcpy( p, hash, hashlen );
            break;

        case SIG_RSA_MD2:
            memcpy( p, ASN1_HASH_MDX, 18 );
            memcpy( p + 18, hash, 16 );
            p[13] = 2; break;

        case SIG_RSA_MD4:
            memcpy( p, ASN1_HASH_MDX, 18 );
            memcpy( p + 18, hash, 16 );
            p[13] = 4; break;

        case SIG_RSA_MD5:
            memcpy( p, ASN1_HASH_MDX, 18 );
            memcpy( p + 18, hash, 16 );
            p[13] = 5; break;

        case SIG_RSA_SHA1:
            memcpy( p, ASN1_HASH_SHA1, 15 );
            memcpy( p + 15, hash, 20 );
            break;

        case SIG_RSA_SHA224:
            memcpy( p, ASN1_HASH_SHA2X, 19 );
            memcpy( p + 19, hash, 28 );
            p[1] += 28; p[14] = 4; p[18] += 28; break;

        case SIG_RSA_SHA256:
            memcpy( p, ASN1_HASH_SHA2X, 19 );
            memcpy( p + 19, hash, 32 );
            p[1] += 32; p[14] = 1; p[18] += 32; break;

        case SIG_RSA_SHA384:
            memcpy( p, ASN1_HASH_SHA2X, 19 );
            memcpy( p + 19, hash, 48 );
            p[1] += 48; p[14] = 2; p[18] += 48; break;

        case SIG_RSA_SHA512:
            memcpy( p, ASN1_HASH_SHA2X, 19 );
            memcpy( p + 19, hash, 64 );
            p[1] += 64; p[14] = 3; p[18] += 64; break;

        default:
            return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
    }

    return( ( mode == RSA_PUBLIC )
            ? rsa_public(  ctx, sig, sig )
            : rsa_private( ctx, sig, sig ) );
}

/*
 * Do an RSA operation and check the message digest
 */
int rsa_pkcs1_verify( rsa_context *ctx,
                      int mode,
                      int hash_id,
                      int hashlen,
                      const unsigned char *hash,
                      unsigned char *sig )
{
    int ret, len, siglen;
    unsigned char *p, c;
    unsigned char buf[1024];

    siglen = ctx->len;

    if( siglen < 16 || siglen > (int) sizeof( buf ) )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    ret = ( mode == RSA_PUBLIC )
          ? rsa_public(  ctx, sig, buf )
          : rsa_private( ctx, sig, buf );

    if( ret != 0 )
        return( ret );

    p = buf;

    switch( ctx->padding )
    {
        case RSA_PKCS_V15:

            if( *p++ != 0 || *p++ != RSA_SIGN )
                return( POLARSSL_ERR_RSA_INVALID_PADDING );

            while( *p != 0 )
            {
                if( p >= buf + siglen - 1 || *p != 0xFF )
                    return( POLARSSL_ERR_RSA_INVALID_PADDING );
                p++;
            }
            p++;
            break;

        default:

            return( POLARSSL_ERR_RSA_INVALID_PADDING );
    }

    len = siglen - (int)( p - buf );

    if( len == 34 )
    {
        c = p[13];
        p[13] = 0;

        if( memcmp( p, ASN1_HASH_MDX, 18 ) != 0 )
            return( POLARSSL_ERR_RSA_VERIFY_FAILED );

        if( ( c == 2 && hash_id == SIG_RSA_MD2 ) ||
            ( c == 4 && hash_id == SIG_RSA_MD4 ) ||
            ( c == 5 && hash_id == SIG_RSA_MD5 ) )
        {
            if( memcmp( p + 18, hash, 16 ) == 0 ) 
                return( 0 );
            else
                return( POLARSSL_ERR_RSA_VERIFY_FAILED );
        }
    }

    if( len == 35 && hash_id == SIG_RSA_SHA1 )
    {
        if( memcmp( p, ASN1_HASH_SHA1, 15 ) == 0 &&
            memcmp( p + 15, hash, 20 ) == 0 )
            return( 0 );
        else
            return( POLARSSL_ERR_RSA_VERIFY_FAILED );
    }
    if( ( len == 19 + 28 && p[14] == 4 && hash_id == SIG_RSA_SHA224 ) ||
        ( len == 19 + 32 && p[14] == 1 && hash_id == SIG_RSA_SHA256 ) ||
        ( len == 19 + 48 && p[14] == 2 && hash_id == SIG_RSA_SHA384 ) ||
        ( len == 19 + 64 && p[14] == 3 && hash_id == SIG_RSA_SHA512 ) )
    {
    	//int iii = 0;
    	//printf("11111111111>>>>>>>>>\n");
		
		//for(iii=0; iii<32; iii++)
		//{
		//	printf("%02x---%02x\n", p[iii+19], hash[iii]);
    	//}
		//printf("\n222222222<<<<<<<<<<<<\n");
		
    	c = p[1] - 17;
        p[1] = 17;
        p[14] = 0;

        if( p[18] == c &&
                memcmp( p, ASN1_HASH_SHA2X, 18 ) == 0 &&
                memcmp( p + 19, hash, c ) == 0 )
        	{
        	//printf("2222222222\n");
            return( 0 );
        	}
        else
            return( POLARSSL_ERR_RSA_VERIFY_FAILED );
    }

    if( len == hashlen && hash_id == SIG_RSA_RAW )
    {
        if( memcmp( p, hash, hashlen ) == 0 )
            return( 0 );
        else
            return( POLARSSL_ERR_RSA_VERIFY_FAILED );
    }

    return( POLARSSL_ERR_RSA_INVALID_PADDING );
}

/*
 * Free the components of an RSA key
 */
void rsa_free( rsa_context *ctx )
{
    mpi_free( &ctx->RQ, &ctx->RP, &ctx->RN,
              &ctx->QP, &ctx->DQ, &ctx->DP,
              &ctx->Q,  &ctx->P,  &ctx->D,
              &ctx->E,  &ctx->N,  NULL );
}

int myrand( void *rng_state )
{
    if( rng_state != NULL )
        rng_state  = NULL;

	//printf("rand:%d\n", rand());
    return( rand() );
}

int rsa_fill_crt_privatekey(rsa_context *ctx, rsa_crt_prikey *prikey)  
{  
    int ret;  
    mpi P1,Q1,H;  
   // mpi_init(&P1);  mpi_init(&Q1);  mpi_init(&H);
   mpi_init( &P1, &Q1, &H, NULL );
    //  
    rsa_init(ctx,RSA_PKCS_V15,0);  
	
    //  
    mpi_read_binary(&ctx->P, prikey->P, prikey->bit/16);//从CRT格式的私钥中读取P  
  
    mpi_read_binary(&ctx->Q, prikey->Q, prikey->bit/16);//从CRT格式的私钥中读取Q  
    mpi_read_binary(&ctx->E, (unsigned char*)"\x00\x01\x00\x01", 4);//填充固定的指数E=0x10001  
    //  
    MPI_CHK(mpi_mul_mpi( &ctx->N, &ctx->P, &ctx->Q ));//计算N,N=P*Q  
    //  
    MPI_CHK(mpi_sub_int( &P1, &ctx->P, 1 ));  
    MPI_CHK(mpi_sub_int( &Q1, &ctx->Q, 1 ));  
    MPI_CHK(mpi_mul_mpi( &H, &P1, &Q1 ));  
    MPI_CHK(mpi_inv_mod( &ctx->D , &ctx->E, &H  ));//计算出D,D=(P-1)*(Q-1) MOD E  
    MPI_CHK(mpi_mod_mpi( &ctx->DP, &ctx->D, &P1 ));//计算DP  
    MPI_CHK(mpi_mod_mpi( &ctx->DQ, &ctx->D, &Q1 ));//计算DP  
  
    MPI_CHK(mpi_inv_mod( &ctx->QP, &ctx->Q, &ctx->P ));//计算QP  
    //  
    ctx->len = ( mpi_msb( &ctx->N ) + 7 ) >> 3;//填充长度  
    //  
    ret = rsa_check_privkey(ctx); 
cleanup:  
    //mpi_free(&P1);  mpi_free(&Q1);  mpi_free(&H);
	mpi_free(&P1, &Q1, &H, NULL);
    return ret;   
}  
  
int rsa_fill_crt_publickey(rsa_context *ctx,  rsa_crt_pubkey *pubkey)  
{  
    int ret;  
    //  
    rsa_init(ctx,RSA_PKCS_V15,0);  
    //  
    mpi_read_binary(&ctx->N, pubkey->N, pubkey->bit/8);  
    mpi_read_binary(&ctx->E, (unsigned char*)"\x00\x01\x00\x01", 4);  
    //  
    ctx->len = ( mpi_msb( &ctx->N ) + 7 ) >> 3;  
    //  
    ret = rsa_check_pubkey(ctx);  
    //  
    return ret;  
}
  
static int g_rsabit = 1024;

void setRSA_bit(int RSAbit)
{
	g_rsabit = RSAbit;
}

int rsa_getkeypairs(rsa_context* ctx, rsa_crt_prikey *prikey, rsa_crt_pubkey *pubkey)  
{  
    int ret; 
	unsigned char p[1024];
	FILE* pvhFile = 0;
	char keyName[256];
	time_t nowTime;
	struct tm *sysTime = 0;
	
	nowTime = time(NULL); 
	sysTime = localtime(&nowTime);

    //  
    if (NULL != prikey)  
    {  
        prikey->bit = ctx->len * 8;  
        ret = mpi_write_binary(&ctx->P, prikey->P, ctx->len/2);  
        if (0 != ret)  
        {   
            return ret;  
        }  
        ret = mpi_write_binary(&ctx->Q, prikey->Q, ctx->len/2);  
        if (0 != ret)  
        {   
            return ret;  
        }  
    }  
    //  
    if (NULL != pubkey)  
    {  
        pubkey->bit = ctx->len * 8;  
        ret = mpi_write_binary(&ctx->N,pubkey->N, ctx->len);  
        if (0 != ret)  
        {   
            return ret;  
        }  
    }
	
#if 1 // key dump out!!!!!!!!!!!!!!!!!!!!!
	memset(keyName, 0, sizeof(keyName));

	sprintf(keyName, "%04d%02d%02d_%02d%02d%02d_private_key_RSA-%d.bin",
		sysTime->tm_year + 1900, sysTime->tm_mon + 1, sysTime->tm_mday, sysTime->tm_hour, sysTime->tm_min, sysTime->tm_sec, g_rsabit);
	pvhFile = fopen(keyName, "wb");
	memset(p, 0xBB, sizeof(p));
	prikey->crc32 = ADIBLCalculateCRC32((void *)&prikey, (sizeof(rsa_crt_prikey)-4));
	memcpy(p, prikey, sizeof(rsa_crt_prikey));
	printf("%s write>>>>>>>>>!\n", keyName);
	fwrite(p, 1, sizeof(rsa_crt_prikey), pvhFile);
	printf("%s write<<<<<<<<<!\n", keyName);
	fclose(pvhFile);

	sprintf(keyName, "%04d%02d%02d_%02d%02d%02d_public_key_RSA-%d.bin",
		sysTime->tm_year + 1900, sysTime->tm_mon + 1, sysTime->tm_mday, sysTime->tm_hour, sysTime->tm_min, sysTime->tm_sec, g_rsabit);
	pvhFile = fopen(keyName, "wb");
	memset(p, 0xBB, sizeof(p));
	pubkey->crc32 = ADIBLCalculateCRC32((void *)&pubkey, (sizeof(rsa_crt_pubkey)-4));
	memcpy(p, pubkey, sizeof(rsa_crt_pubkey));
	printf("%s write>>>>>>>>>!\n", keyName);
	fwrite(p, 1, sizeof(rsa_crt_pubkey), pvhFile);
	printf("%s write>>>>>>>>>!\n", keyName);
	fclose(pvhFile);
#endif
    //  
    return 0;  
}

#if defined(POLARSSL_SELF_TEST)
#include "time.h"
//#include "sha1.h"

//Example RSA-1024 keypair, for test purposes

#define KEY_LEN (128*2) //支持RSA-2048

#define RSA_N   "9292758453063D803DD603D5E777D788" \
                "8ED1D5BF35786190FA2F23EBC0848AEA" \
                "DDA92CA6C3D80B32C4D109BE0F36D6AE" \
                "7130B9CED7ACDF54CFC7555AC14EEBAB" \
                "93A89813FBF3C4F8066D2D800F7C38A8" \
                "1AE31942917403FF4946B0A83D3D3E05" \
                "EE57C6F5F5606FB5D4BC6CD34EE0801A" \
                "5E94BB77B07507233A0BC7BAC8F90F79"

#define RSA_E   "10001"

#define RSA_D   "24BF6185468786FDD303083D25E64EFC" \
                "66CA472BC44D253102F8B4A9D3BFA750" \
                "91386C0077937FE33FA3252D28855837" \
                "AE1B484A8A9A45F7EE8C0C634F99E8CD" \
                "DF79C5CE07EE72C7F123142198164234" \
                "CABB724CF78B8173B9F880FC86322407" \
                "AF1FEDFDDE2BEB674CA15F3E81A1521E" \
                "071513A1E85B5DFA031F21ECAE91A34D"

#define RSA_P   "C36D0EB7FCD285223CFB5AABA5BDA3D8" \
                "2C01CAD19EA484A87EA4377637E75500" \
                "FCB2005C5C7DD6EC4AC023CDA285D796" \
                "C3D9E75E1EFC42488BB4F1D13AC30A57"

#define RSA_Q   "C000DF51A7C77AE8D7C7370C1FF55B69" \
                "E211C2B9E5DB1ED0BF61D0D9899620F4" \
                "910E4168387E3C30AA1E00C339A79508" \
                "8452DD96A9A5EA5D9DCA68DA636032AF"

#define RSA_DP  "C1ACF567564274FB07A0BBAD5D26E298" \
                "3C94D22288ACD763FD8E5600ED4A702D" \
                "F84198A5F06C2E72236AE490C93F07F8" \
                "3CC559CD27BC2D1CA488811730BB5725"

#define RSA_DQ  "4959CBF6F8FEF750AEE6977C155579C7" \
                "D8AAEA56749EA28623272E4F7D0592AF" \
                "7C1F1313CAC9471B5C523BFE592F517B" \
                "407A1BD76C164B93DA2D32A383E58357"

#define RSA_QP  "9AE7FBC99546432DF71896FC239EADAE" \
                "F38D18D2B2F0E2DD275AA977E2BF4411" \
                "F5A3B2A5D33605AEBBCCBA7FEB9F2D2F" \
                "A74206CEC169D74BF5A8C50D6F48EA08"

#define PT_LEN  24
#define RSA_PT  "\xAA\xBB\xCC\x03\x02\x01\x00\xFF\xFF\xFF\xFF\xFF" \
                "\x11\x22\x33\x0A\x0B\x0C\xCC\xDD\xDD\xDD\xDD\xDD"

// Checkup routine
int rsa_self_test( int verbose )
{
    int len;
    rsa_context rsa;
    unsigned char sha1sum[20];
    unsigned char rsa_plaintext[PT_LEN];
    unsigned char rsa_decrypted[PT_LEN];
    unsigned char rsa_ciphertext[KEY_LEN];
	int result = 0;
	rsa_context rsaprivate;
	rsa_context rsapublic;
	rsa_crt_prikey privateKey;
	rsa_crt_pubkey publicKey;
	FILE *pvhFile = 0;
#if 0
    rsa.len = KEY_LEN;
    mpi_read_string( &rsa.N , 16, RSA_N  );
    mpi_read_string( &rsa.E , 16, RSA_E  );
    mpi_read_string( &rsa.D , 16, RSA_D  );
    mpi_read_string( &rsa.P , 16, RSA_P  );
    mpi_read_string( &rsa.Q , 16, RSA_Q  );
    mpi_read_string( &rsa.DP, 16, RSA_DP );
    mpi_read_string( &rsa.DQ, 16, RSA_DQ );
    mpi_read_string( &rsa.QP, 16, RSA_QP );
#else
	rsa_init( &rsa, RSA_PKCS_V15, 0 );
	rsa_gen_key( &rsa, myrand, NULL, g_rsabit, 65537 );
	printf("rsa.len:%d\n", rsa.len);
	printf("sizeof(rsa_crt_prikey):%d\n", sizeof(rsa_crt_prikey));
	printf("sizeof(rsa_crt_pubkey):%d\n", sizeof(rsa_crt_pubkey));

#if 1
	result = rsa_getkeypairs(&rsa, &privateKey, &publicKey); /*分离得到privatekey publickey*/
	printf( "rsa_getkeypairs result:%d verbose:%d\n",  result, verbose);
#else

	pvhFile = fopen("20150911_122012_private_key.bin", "rb");
	result = fread(&privateKey, sizeof(privateKey), 1, pvhFile);
	printf( "fread privateKey result:%d\n",  result);
	fclose(pvhFile);

	pvhFile = fopen("20150911_122012_public_key.bin", "rb");
	result = fread(&publicKey, sizeof(publicKey), 1, pvhFile);
	printf( "fread publicKey result:%d\n",  result);
	fclose(pvhFile);
#endif
	
	result = rsa_fill_crt_publickey(&rsapublic, &publicKey);
	printf( "rsa_fill_crt_publickey result:%d  bit:%d  verbose:%d\n",  result, publicKey.bit, verbose);

	result = rsa_fill_crt_privatekey(&rsaprivate, &privateKey);
	printf( "rsa_fill_crt_privatekey result:%d privateKey.bit:%d verbose:%d\n",  result, privateKey.bit, verbose);

#endif

    if( verbose != 0 )
        printf( "  RSA key validation: " );

    if( rsa_check_pubkey(  &rsapublic ) != 0 ||
        rsa_check_privkey( &rsaprivate ) != 0 )
    {
        if( verbose != 0 )
            printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        printf( "passed\n  PKCS#1 encryption : " );

    memcpy( rsa_plaintext, RSA_PT, PT_LEN );

    if( rsa_pkcs1_encrypt( &rsapublic, &myrand, NULL, RSA_PUBLIC, PT_LEN,
                           rsa_plaintext, rsa_ciphertext ) != 0 )
    {
        if( verbose != 0 )
            printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        printf( "passed\n  PKCS#1 decryption : " );

    if( rsa_pkcs1_decrypt( &rsaprivate, RSA_PRIVATE, &len,
                           rsa_ciphertext, rsa_decrypted,
			   sizeof(rsa_decrypted) ) != 0 )
    {
        if( verbose != 0 )
            printf( "failed\n" );

        return( 1 );
    }

    if( memcmp( rsa_decrypted, rsa_plaintext, len ) != 0 )
    {
        if( verbose != 0 )
            printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        printf( "passed\n  PKCS#1 data sign  : " );

    ADIBLCalculateSHA1( rsa_plaintext, PT_LEN, sha1sum );

    if( rsa_pkcs1_sign( &rsaprivate, RSA_PRIVATE, SIG_RSA_SHA1, 20,
                        sha1sum, rsa_ciphertext ) != 0 )
    {
        if( verbose != 0 )
            printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        printf( "passed\n  PKCS#1 sig. verify: " );

    if( rsa_pkcs1_verify( &rsapublic, RSA_PUBLIC, SIG_RSA_SHA1, 20,
                          sha1sum, rsa_ciphertext ) != 0 )
    {
        if( verbose != 0 )
            printf( "failed\n" );

        return( 1 );
    }

   if( verbose != 0 )
        printf( "passed\n\n" );

    rsa_free( &rsa );
	rsa_free( &rsapublic );
	rsa_free( &rsaprivate );

    return( 0 );
}

#endif

int ADIBLRsa_PKCS1_Encrypt(ADIBLRSAMode_E mode, unsigned char *pMiniKey, 
		unsigned char* in_rsa_plaintext, int in_rsa_plaintext_len, unsigned char* out_rsa_ciphertext)
{
	rsa_context rsapublic;
	rsa_context rsaprivate;
	int result = 0;

	switch (mode)
	{
		case RSA_PUBLIC:
		{
			result = rsa_fill_crt_publickey(&rsapublic, (rsa_crt_pubkey *)pMiniKey);
			if(0 == result)
			{					
		    	result = rsa_pkcs1_encrypt( &rsapublic, &myrand, NULL, RSA_PUBLIC, in_rsa_plaintext_len, in_rsa_plaintext, out_rsa_ciphertext);

				rsa_free( &rsapublic );
			}
			break;
		}
		
		case RSA_PRIVATE:
		{
			result = rsa_fill_crt_privatekey(&rsaprivate, (rsa_crt_prikey*)pMiniKey);
			if(0 == result)
			{				
		    	result = rsa_pkcs1_encrypt( &rsaprivate, &myrand, NULL, RSA_PRIVATE, in_rsa_plaintext_len, in_rsa_plaintext, out_rsa_ciphertext );

				rsa_free( &rsaprivate );
			}
			break;
		}
		
		default:
			result = -5;
	}

	return result;
}

int ADIBLRsa_PKCS1_Decrypt(ADIBLRSAMode_E mode, unsigned char *pMiniKey, unsigned char* in_rsa_ciphertext, unsigned char* out_rsa_plaintext, int *out_rsa_plaintext_len)
{
	rsa_context rsapublic;
	rsa_context rsaprivate;
	int result = 0;

	switch (mode)
	{
		case RSA_PRIVATE:
		{
			result = rsa_fill_crt_privatekey(&rsaprivate, (rsa_crt_prikey*)pMiniKey);
			if(0 == result)
			{
			    result = rsa_pkcs1_decrypt( &rsaprivate, RSA_PRIVATE, out_rsa_plaintext_len, in_rsa_ciphertext, out_rsa_plaintext, *out_rsa_plaintext_len );

				rsa_free( &rsaprivate );
			}
			break;
		}

		case RSA_PUBLIC:
		{
			result = rsa_fill_crt_publickey(&rsapublic, (rsa_crt_pubkey *)pMiniKey);
			if(0 == result)
			{
			    result = rsa_pkcs1_decrypt( &rsapublic, RSA_PUBLIC, out_rsa_plaintext_len, in_rsa_ciphertext, out_rsa_plaintext, *out_rsa_plaintext_len );

				rsa_free( &rsapublic );
			}
			break;
		}

		default:
			result = -5;
	}
	
	return result;
}

int ADIBLRsa_PKCS1_Sign(ADIBLRSAMode_E mode, unsigned char *pMiniKey, ADIBLRSAHashMode_E hashmode, int hashdata_len, unsigned char* hashdata, unsigned char* out_rsa_ciphertext)
{
	rsa_context rsapublic;
	rsa_context rsaprivate;
	int result = 0;

	switch (mode)
	{
		case RSA_PRIVATE:
		{
			result = rsa_fill_crt_privatekey(&rsaprivate, (rsa_crt_prikey*)pMiniKey);
			if(0 == result)
			{
			    result = rsa_pkcs1_sign( &rsaprivate, RSA_PRIVATE, hashmode, hashdata_len, hashdata, out_rsa_ciphertext);

				rsa_free( &rsaprivate );
			}
			break;
		}

		case RSA_PUBLIC:
		{
			result = rsa_fill_crt_publickey(&rsapublic, (rsa_crt_pubkey *)pMiniKey);
			if(0 == result)
			{
			     result = rsa_pkcs1_sign( &rsapublic, RSA_PUBLIC, hashmode, hashdata_len, hashdata, out_rsa_ciphertext);

				rsa_free( &rsapublic );
			}
			break;
		}

		default:
			result = -5;
	}
	
	return result;
}

int ADIBLRsa_PKCS1_Verify(ADIBLRSAMode_E mode, unsigned char *pMiniKey, ADIBLRSAHashMode_E hashmode, int hashdata_len, unsigned char* hashdata, unsigned char* in_rsa_ciphertext)
{
	rsa_context rsapublic;
	rsa_context rsaprivate;
	int result = 0;

	switch (mode)
	{
		case RSA_PUBLIC:
		{
			result = rsa_fill_crt_publickey(&rsapublic, (rsa_crt_pubkey *)pMiniKey);
			if(0 == result)
			{
			     result = rsa_pkcs1_verify( &rsapublic, RSA_PUBLIC, hashmode, hashdata_len, hashdata, in_rsa_ciphertext);

				rsa_free( &rsapublic );
			}
			break;
		}
		
		case RSA_PRIVATE:
		{
			result = rsa_fill_crt_privatekey(&rsaprivate, (rsa_crt_prikey*)pMiniKey);
			if(0 == result)
			{
			    result = rsa_pkcs1_verify( &rsaprivate, RSA_PRIVATE, hashmode, hashdata_len, hashdata, in_rsa_ciphertext);

				rsa_free( &rsaprivate );
			}
			break;
		}
		default:
			result = -5;
	}
	
	return result;
}

#if 1

#define __MAX_SIGNATURE_LEN (512)

typedef struct
{
	unsigned char ucSignature[__MAX_SIGNATURE_LEN];
	unsigned int unSignatureLen;
	unsigned int unCRC32;
}ADIBLImageSignature_S;

int RSAVerifySignApp(char *OrgAppFileName, char* SignFileName, char* KeyFileName, char* Hash)
{
	int nRet = 0;
	FILE *pInputFile = 0;
	FILE *pSignFile = 0;
	FILE *pKeyFile = 0;
	int filelen = 0;
	unsigned char* pucInputFileBuffer = NULL;
	unsigned char hash_sha256[ 32 ];
	unsigned char signdata[512];
	rsa_crt_pubkey pubKey;
	
	printf("OrgAppFileName:%s, SignFileName:%s, KeyFileName:%s, Hash:%s\n", OrgAppFileName, SignFileName, KeyFileName, Hash);

	memset(hash_sha256, 0, sizeof(hash_sha256));
	memset(signdata, 0, sizeof(signdata));
	memset(&pubKey, 0, sizeof(pubKey));

	// OrgAppFileName
	pInputFile = fopen(OrgAppFileName, "rb");
	if(pInputFile == NULL)
	{
		printf("can not open input file:%s!!..\n", OrgAppFileName);
		goto ERR;
	}

	fseek(pInputFile,0,SEEK_END); 
	filelen = ftell(pInputFile);
	if(filelen == 0)
	{
		printf("org img size is 0!!..\n");
		goto ERR;		
	}

	pucInputFileBuffer = (unsigned char*)malloc(filelen);
	if(pucInputFileBuffer == NULL)
	{
		printf("malloc unOrgImgSize:0x%x failed!!..\n", filelen);
		goto ERR;
	}

	fseek(pInputFile, 0, SEEK_SET);
	nRet = fread(pucInputFileBuffer, 1, filelen, pInputFile);
	if(nRet == 0)
	{
		printf("fread is 0!!..\n");
		goto ERR;	
	}
	
	printf("OrgAppFileName:%s LOAD OK, size:%d \n", OrgAppFileName, filelen);
	ADIBLCalculateSHA256(pucInputFileBuffer, filelen, hash_sha256);

	//KeyFileName
	pKeyFile = fopen(KeyFileName, "rb");
	if(pKeyFile == NULL)
	{
		printf("can not open input file:%s!!..\n", KeyFileName);
		goto ERR;
	}
	fseek(pKeyFile,0,SEEK_END); 
	filelen = ftell(pKeyFile);
	if(filelen == 0)
	{
		printf("key size is 0!!..\n");
		goto ERR;		
	}
	if(filelen != sizeof(rsa_crt_prikey))
	{
		printf("key File size is error<should%d---but:%d>!!..\n", sizeof(rsa_crt_prikey), filelen);
		goto ERR;	

	}
	fseek(pKeyFile, 0, SEEK_SET);
	nRet = fread((unsigned char*)&pubKey, 1, filelen, pKeyFile);
	if(nRet == 0)
	{
		printf("fread is 0!!..\n");
		goto ERR;	
	}
	printf("KeyFileName:%s LOAD OK, size:%d \n", KeyFileName, filelen);


	//SignFileName
	pSignFile = fopen(SignFileName, "rb");
	if(pSignFile == NULL)
	{
		printf("can not open input file:%s!!..\n", SignFileName);
		goto ERR;
	}
	fseek(pSignFile,0,SEEK_END); 
	filelen = ftell(pSignFile);
	if(filelen == 0)
	{
		printf("key size is 0!!..\n");
		goto ERR;		
	}

	fseek(pSignFile, 0, SEEK_SET);
	nRet = fread(signdata, 1, filelen, pSignFile);
	if(nRet == 0)
	{
		printf("fread is 0!!..\n");
		goto ERR;	
	}
	printf("SignFileName:%s LOAD OK, size:%d \n", SignFileName, filelen);

	nRet = ADIBLRsa_PKCS1_Verify(E_ADIBL_RSA_MODE_PUBLIC, (unsigned char*)&pubKey, E_ADIBL_SIG_RSA_SHA256, 32, hash_sha256, signdata); //public verify
	printf("#################ADIBLRsa_PKCS1_Verify nRet:%d\n", nRet);

ERR:
	if(pInputFile!=0)
	{
		fclose(pInputFile);
		pInputFile = 0;
	}
	if(pSignFile!=0)
	{
		fclose(pSignFile);
		pSignFile = 0;
	}
	if(pKeyFile!=0)
	{
		fclose(pKeyFile);
		pKeyFile = 0;
	}
	if(pucInputFileBuffer != 0)
	{
		free(pucInputFileBuffer);
		pucInputFileBuffer = 0;
	}

	return 0;
}


int RSASignApp(char *OrgAppFileName, char* SignFileName, char* KeyFileName, char* Hash)
{
	int nRet = 0;
	FILE *pInputFile = 0;
	FILE *pSignFile = 0;
	FILE *pKeyFile = 0;
	int filelen = 0;
	unsigned char* pucInputFileBuffer = NULL;
	unsigned char hash_sha256[ 32 ];
	unsigned char signdata[512];
	rsa_crt_prikey privateKey;
	rsa_crt_pubkey pubKey;
	
	printf("OrgAppFileName:%s, SignFileName:%s, KeyFileName:%s, Hash:%s\n", OrgAppFileName, SignFileName, KeyFileName, Hash);

	memset(hash_sha256, 0, sizeof(hash_sha256));
	memset(signdata, 0, sizeof(signdata));
	memset(&privateKey, 0, sizeof(privateKey));
	memset(&pubKey, 0, sizeof(pubKey));

	// OrgAppFileName
	pInputFile = fopen(OrgAppFileName, "rb");
	if(pInputFile == NULL)
	{
		printf("can not open input file:%s!!..\n", OrgAppFileName);
		goto ERR;
	}

	fseek(pInputFile,0,SEEK_END); 
	filelen = ftell(pInputFile);
	if(filelen == 0)
	{
		printf("org img size is 0!!..\n");
		goto ERR;		
	}

	pucInputFileBuffer = (unsigned char*)malloc(filelen);
	if(pucInputFileBuffer == NULL)
	{
		printf("malloc unOrgImgSize:0x%x failed!!..\n", filelen);
		goto ERR;
	}

	fseek(pInputFile, 0, SEEK_SET);
	nRet = fread(pucInputFileBuffer, 1, filelen, pInputFile);
	if(nRet == 0)
	{
		printf("fread is 0!!..\n");
		goto ERR;	
	}
	
	printf("OrgAppFileName:%s LOAD OK, size:%d \n", OrgAppFileName, filelen);		
	ADIBLCalculateSHA256(pucInputFileBuffer, filelen, hash_sha256);

	//KeyFileName
	pKeyFile = fopen(KeyFileName, "rb");
	if(pKeyFile == NULL)
	{
		printf("can not open input file:%s!!..\n", KeyFileName);
		goto ERR;
	}
	fseek(pKeyFile,0,SEEK_END); 
	filelen = ftell(pKeyFile);
	if(filelen == 0)
	{
		printf("key size is 0!!..\n");
		goto ERR;		
	}
	if(filelen != sizeof(rsa_crt_prikey))
	{
		printf("key File size is error<should%d---but:%d>!!..\n", sizeof(rsa_crt_prikey), filelen);
		goto ERR;	

	}
	fseek(pKeyFile, 0, SEEK_SET);
	nRet = fread((unsigned char*)&privateKey, 1, filelen, pKeyFile);
	if(nRet == 0)
	{
		printf("fread is 0!!..\n");
		goto ERR;	
	}
	printf("KeyFileName:%s LOAD OK, size:%d \n", KeyFileName, filelen);

	nRet = ADIBLRsa_PKCS1_Sign(E_ADIBL_RSA_MODE_PRIVATE, (unsigned char*)&privateKey, E_ADIBL_SIG_RSA_SHA256, 32, hash_sha256, signdata); // private sign
	printf("#################ADIBLRsa_PKCS1_Sign nRet:%d\n", nRet);
	
#if 0
	//KeyFileName
	pKeyFile = fopen("20151124_101809_public_key_RSA-2048.bin", "rb");
	if(pKeyFile == NULL)
	{
		printf("can not open input file:%s!!..\n", KeyFileName);
		goto ERR;
	}
	fseek(pKeyFile,0,SEEK_END); 
	filelen = ftell(pKeyFile);
	if(filelen == 0)
	{
		printf("key size is 0!!..\n");
		goto ERR;		
	}
	if(filelen != sizeof(rsa_crt_prikey))
	{
		printf("key File size is error<should%d---but:%d>!!..\n", sizeof(rsa_crt_prikey), filelen);
		goto ERR;	

	}
	fseek(pKeyFile, 0, SEEK_SET);
	nRet = fread((unsigned char*)&pubKey, 1, filelen, pKeyFile);
	if(nRet == 0)
	{
		printf("fread is 0!!..\n");
		goto ERR;	
	}
	printf("KeyFileName:%s LOAD OK, size:%d \n", "20151124_101809_public_key_RSA-2048.bin", filelen);

	{
		int i = 0;
		unsigned char *p = (unsigned char*)&pubKey;
	
		printf("pubKey>>>>>>>>>\n");
		for(i=0; i<sizeof(rsa_crt_pubkey); i++)
		{
			printf("%02x ", p[i]);
			if(((i+1)%32 == 0))
			{
				printf("\n");
			}
		}
		printf("\npubKey<<<<<<<\n");
	
		printf("hash_sha256>>>>>>>>>\n");
		p = hash_sha256;
		for(i=0; i<sizeof(hash_sha256); i++)
		{
			printf("%02x ", p[i]);
			if(((i+1)%32 == 0))
			{
				printf("\n");
			}
		}
		printf("\nhash_sha256<<<<<<<\n");
	
		printf("ucSignature>>>>>>>>>\n");
		p = signInfo.ucSignature;
		for(i=0; i<sizeof(signInfo.ucSignature); i++)
		{
			printf("%02x ", p[i]);
			if(((i+1)%32 == 0))
			{
				printf("\n");
			}
		}
		printf("\nucSignature<<<<<<<\n");
	
	}

	nRet = ADIBLRsa_PKCS1_Verify(E_ADIBL_RSA_MODE_PUBLIC, (unsigned char*)&pubKey, E_ADIBL_SIG_RSA_SHA256, 32, hash_sha256, signInfo.ucSignature); //public verify
	printf("ADIBLRsa_PKCS1_Verify nRet:%d\n", nRet);
#endif

	//SignFileName
	pSignFile = fopen(SignFileName, "wb");
	if(pSignFile == NULL)
	{
		printf("can not open input file:%s!!..\n", SignFileName);
		goto ERR;
	}	
	nRet = fwrite(signdata, 1, (privateKey.bit/8), pSignFile);
	printf("fwrite signInfo nRet:%d\n", nRet);
	if(nRet == 0)
	{
		printf("fwrite is 0!!..\n");
		goto ERR;	
	}

ERR:
	if(pInputFile!=0)
	{
		fclose(pInputFile);
		pInputFile = 0;
	}
	if(pSignFile!=0)
	{
		fclose(pSignFile);
		pSignFile = 0;
	}
	if(pKeyFile!=0)
	{
		fclose(pKeyFile);
		pKeyFile = 0;
	}
	if(pucInputFileBuffer != 0)
	{
		free(pucInputFileBuffer);
		pucInputFileBuffer = 0;
	}

	return 0;
}

int RSAGenKeys(void)
{
#if 0
#define __text_len (100)
#define __rsa_max (256)
	unsigned char rsa_plaintext[__text_len];
	unsigned char rsa_decrypted[__text_len];
	unsigned char rsa_ciphertext[__rsa_max];
#endif
	rsa_context rsa;
	int result = 0;
	rsa_crt_prikey privateKey;
	rsa_crt_pubkey publicKey;
#if 0
	int n = 0;
	int m = 0;
	int i = 0;
	unsigned char hash_sha1[20];
	unsigned char hash_sha256[ 32 ];
	unsigned char md5[ 16 ];
	unsigned char ciphertext[__rsa_max];
	memset(rsa_ciphertext, 0xbb, sizeof(rsa_ciphertext));
#endif
	//rsa_self_test(1);
	//printf("[%s %d]11\n", __FUNCTION__, __LINE__);
	rsa_init( &rsa, RSA_PKCS_V15, 0 );
	//printf("[%s %d]22\n", __FUNCTION__, __LINE__);
	rsa_gen_key( &rsa, myrand, NULL, 2048, 65537 );
	//printf("[%s %d]33\n", __FUNCTION__, __LINE__);
	
	result = rsa_getkeypairs(&rsa, &privateKey, &publicKey); /*分离得到privatekey publickey*/
	printf( "rsa_getkeypairs result:%d\n",  result);

#if 0
	//memcpy( rsa_plaintext, RSA_PT, PT_LEN );
	memset(rsa_plaintext, 0x09, sizeof(rsa_plaintext));
	
	ADIBLRsa_PKCS1_Encrypt(E_ADIBL_RSA_MODE_PUBLIC, (unsigned char*)&publicKey, rsa_plaintext, __text_len, rsa_ciphertext);
	printf("n:%d\n", n);

	for(i=0; i<__rsa_max; i++)
	{
		printf("%02x ", rsa_ciphertext[i]);
		if((i+1)%32 == 0)
			{
			printf("\n");
			}
	}
	printf("\n");

	m = sizeof(rsa_decrypted);
	ADIBLRsa_PKCS1_Decrypt(E_ADIBL_RSA_MODE_PRIVATE, (unsigned char*)&privateKey, rsa_ciphertext, rsa_decrypted, &m);
	//printf("m:%d\n", m);

	//for(i=0; i<__text_len; i++)
	//{
	//	printf("0x%x----0x%x\n", rsa_plaintext[i], rsa_decrypted[i]);
	//}
	//printf("over!!!!\n\n");

	memset(rsa_plaintext, 0x0E, sizeof(rsa_plaintext));

	ADIBLCalculateSHA1(ciphertext, __text_len, hash_sha1);
	ADIBLCalculateSHA256(ciphertext, __text_len, hash_sha256);
	ADIBLCalculateMD5(ciphertext, __text_len, md5);
	
	result = ADIBLRsa_PKCS1_Sign(E_ADIBL_RSA_MODE_PRIVATE, (unsigned char*)&privateKey, E_ADIBL_SIG_RSA_MD5, 16, md5, ciphertext); // private sign
	printf("md5 sign result:%d\n", result);
	result = ADIBLRsa_PKCS1_Verify(E_ADIBL_RSA_MODE_PUBLIC, (unsigned char*)&publicKey, E_ADIBL_SIG_RSA_MD5, 16, md5, ciphertext); //public verify
	printf("md5 sign verify result:%d\n\n", result);

	result = ADIBLRsa_PKCS1_Sign(E_ADIBL_RSA_MODE_PRIVATE, (unsigned char*)&privateKey, E_ADIBL_SIG_RSA_SHA1, 20, hash_sha1, ciphertext); // private sign
	printf("sha1 sign result:%d\n", result);
	result = ADIBLRsa_PKCS1_Verify(E_ADIBL_RSA_MODE_PUBLIC, (unsigned char*)&publicKey, E_ADIBL_SIG_RSA_SHA1, 20, hash_sha1, ciphertext); //public verify
	printf("sha1 sign verify result:%d\n\n", result);

	result = ADIBLRsa_PKCS1_Sign(E_ADIBL_RSA_MODE_PRIVATE, (unsigned char*)&privateKey, E_ADIBL_SIG_RSA_SHA256, 32, hash_sha256, ciphertext); // private sign
	printf("sha256 sign result:%d\n", result);
	//hash_sha256[9] = 9;
	result = ADIBLRsa_PKCS1_Verify(E_ADIBL_RSA_MODE_PUBLIC, (unsigned char*)&publicKey, E_ADIBL_SIG_RSA_SHA256, 32, hash_sha256, ciphertext); //public verify
	printf("sha256 sign verify result:%d\n\n", result);

	result = ADIBLRsa_PKCS1_Sign(E_ADIBL_RSA_MODE_PUBLIC, (unsigned char*)&publicKey, E_ADIBL_SIG_RSA_SHA256, 32, hash_sha256, ciphertext);
	printf("3 sha256 sign result:%d\n\n", result);
	result = ADIBLRsa_PKCS1_Verify(E_ADIBL_RSA_MODE_PRIVATE, (unsigned char*)&privateKey, E_ADIBL_SIG_RSA_SHA256, 32, hash_sha256, ciphertext);
	printf("3 sha256 sign verify result:%d\n\n", result);
#endif

	return 0;
}
#endif

#endif
