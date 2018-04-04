#include "string.h"
#include "stdio.h"

typedef struct
{
  	unsigned int   	i[2];             		/* number of _bits_ handled mod 2^64 */
  	unsigned int   	buf[4];          		/* scratch buffer */
  	unsigned char 	in[64];          		/* input buffer */
  	unsigned char 	digest[16];     		/* actual digest after BLMD5Final call */
} md5_ctx_t;

/* F, G and H are basic MD5 functions: selection, majority, parity */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z))) 

/* ROTATE_LEFT rotates x left n bits */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II BLMD5Transform for rounds 1, 2, 3, and 4 */
/* Rotation is separate from addition to prevent recomputation */
#define FF(a, b, c, d, x, s, ac) \
  {(a) += F ((b), (c), (d)) + (x) + (unsigned int )(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) \
  {(a) += G ((b), (c), (d)) + (x) + (unsigned int  )(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) \
  {(a) += H ((b), (c), (d)) + (x) + (unsigned int  )(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) \
  {(a) += I ((b), (c), (d)) + (x) + (unsigned int  )(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }

static unsigned char PADDING[64] = 
{
  	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static void BLMD5Init (md5_ctx_t *mdContext);
static void BLMD5Transform (unsigned int   *buf, unsigned int   *in);
static void BLMD5Update (md5_ctx_t *mdContext, unsigned char *inBuf, unsigned int   inLen);
static void BLMD5Final (md5_ctx_t *mdContext);

static void BLMD5Init (md5_ctx_t *mdContext)
{
  	mdContext->i[0] = mdContext->i[1] = (unsigned int  )0;

  	/* Load magic initialization constants.*/
  	mdContext->buf[0] = (unsigned int  )0x67452301;
  	mdContext->buf[1] = (unsigned int  )0xefcdab89;
  	mdContext->buf[2] = (unsigned int  )0x98badcfe;
  	mdContext->buf[3] = (unsigned int  )0x10325476;
}

static void BLMD5Update (md5_ctx_t *mdContext, unsigned char *inBuf, unsigned int   inLen)
{
  	unsigned int   in[16];
  	int mdi;
  	unsigned int   i, ii;

  	/* compute number of bytes mod 64 */
  	mdi = (int)((mdContext->i[0] >> 3) & 0x3F);

  	/* update number of bits */
  	if ((mdContext->i[0] + ((unsigned int  )inLen << 3)) < mdContext->i[0])
  	{
    		mdContext->i[1]++;
  	}
	
  	mdContext->i[0] += ((unsigned int  )inLen << 3);
  	mdContext->i[1] += ((unsigned int  )inLen >> 29);

  	while (inLen--) 
	{
    		/* add new character to buffer, increment mdi */
    		mdContext->in[mdi++] = *inBuf++;

    		/* BLMD5Transform if necessary */
    		if (mdi == 0x40) 
		{
      			for (i = 0, ii = 0; i < 16; i++, ii += 4)
      			{
       			 in[i] = (((unsigned int  )mdContext->in[ii+3]) << 24) |
                				(((unsigned int  )mdContext->in[ii+2]) << 16) |
                				(((unsigned int  )mdContext->in[ii+1]) << 8) |
                				((unsigned int  )mdContext->in[ii]);
      			}
				
      			BLMD5Transform (mdContext->buf, in);
				
      			mdi = 0;
    		}
  	}
}

static void BLMD5Final (md5_ctx_t *mdContext)
{
  	unsigned int   in[16];
  	int mdi;
  	unsigned int   i, ii;
  	unsigned int   padLen;

  	/* save number of bits */
  	in[14] = mdContext->i[0];
  	in[15] = mdContext->i[1];

  	/* compute number of bytes mod 64 */
  	mdi = (int)((mdContext->i[0] >> 3) & 0x3F);

  	/* pad out to 56 mod 64 */
  	padLen = (mdi < 56) ? (56 - mdi) : (120 - mdi);
  	BLMD5Update (mdContext, PADDING, padLen);

  	/* append length in bits and BLMD5Transform */
  	for (i = 0, ii = 0; i < 14; i++, ii += 4)
    		in[i] = (((unsigned int  )mdContext->in[ii+3]) << 24) |
		            (((unsigned int  )mdContext->in[ii+2]) << 16) |
		            (((unsigned int  )mdContext->in[ii+1]) << 8) |
		            ((unsigned int  )mdContext->in[ii]);
	
  	BLMD5Transform (mdContext->buf, in);

  	/* store buffer in digest */
  	for (i = 0, ii = 0; i < 4; i++, ii += 4) 
	{
    		mdContext->digest[ii] = (unsigned char)(mdContext->buf[i] & 0xFF);
		
    		mdContext->digest[ii+1] =
      			(unsigned char)((mdContext->buf[i] >> 8) & 0xFF);
			
    		mdContext->digest[ii+2] =
      			(unsigned char)((mdContext->buf[i] >> 16) & 0xFF);
			
    		mdContext->digest[ii+3] =
      			(unsigned char)((mdContext->buf[i] >> 24) & 0xFF);
  	}
}

/* Basic MD5 step. BLMD5Transform buf based on in.
 */
static void BLMD5Transform (unsigned int   *buf, unsigned int   *in)
{
  	unsigned int   a = buf[0], b = buf[1], c = buf[2], d = buf[3];

  	/* Round 1 */
	#define S11 7
	#define S12 12
	#define S13 17
	#define S14 22
	
  	FF ( a, b, c, d, in[ 0], S11, /*3614090360*/(unsigned int  )0xd76aa478); /* 1 */
  	FF ( d, a, b, c, in[ 1], S12, /*3905402710*/(unsigned int  )0xe8c7b756); /* 2 */
  	FF ( c, d, a, b, in[ 2], S13,  /*606105819*/(unsigned int  )0x242070db); /* 3 */
  	FF ( b, c, d, a, in[ 3], S14, /*3250441966*/(unsigned int  )0xc1bdceee); /* 4 */
  	FF ( a, b, c, d, in[ 4], S11, /*4118548399*/(unsigned int  )0xf57c0faf); /* 5 */
  	FF ( d, a, b, c, in[ 5], S12, /*1200080426*/(unsigned int  )0x4787c62a); /* 6 */
  	FF ( c, d, a, b, in[ 6], S13, /*2821735955*/(unsigned int  )0xa8304613); /* 7 */
  	FF ( b, c, d, a, in[ 7], S14, /*4249261313*/(unsigned int  )0xfd469501); /* 8 */
  	FF ( a, b, c, d, in[ 8], S11, /*1770035416*/(unsigned int  )0x698098d8); /* 9 */
  	FF ( d, a, b, c, in[ 9], S12, /*2336552879*/(unsigned int  )0x8b44f7af); /* 10 */
  	FF ( c, d, a, b, in[10], S13, /*4294925233*/(unsigned int  )0xffff5bb1); /* 11 */
  	FF ( b, c, d, a, in[11], S14, /*2304563134*/(unsigned int  )0x895cd7be); /* 12 */
  	FF ( a, b, c, d, in[12], S11, /*1804603682*/(unsigned int  )0x6b901122); /* 13 */
  	FF ( d, a, b, c, in[13], S12, /*4254626195*/(unsigned int  )0xfd987193); /* 14 */
  	FF ( c, d, a, b, in[14], S13, /*2792965006*/(unsigned int  )0xa679438e); /* 15 */
  	FF ( b, c, d, a, in[15], S14, /*1236535329*/(unsigned int  )0x49b40821); /* 16 */

  	/* Round 2 */
	#define S21 5
	#define S22 9
	#define S23 14
	#define S24 20
	
  	GG ( a, b, c, d, in[ 1], S21, /*4129170786*/(unsigned int  )0xf61e2562); /* 17 */
  	GG ( d, a, b, c, in[ 6], S22, /*3225465664*/(unsigned int  )0xc040b340); /* 18 */
  	GG ( c, d, a, b, in[11], S23,  /*643717713*/(unsigned int  )0x265e5a51); /* 19 */
  	GG ( b, c, d, a, in[ 0], S24, /*3921069994*/(unsigned int  )0xe9b6c7aa); /* 20 */
  	GG ( a, b, c, d, in[ 5], S21, /*3593408605*/(unsigned int  )0xd62f105d); /* 21 */
  	GG ( d, a, b, c, in[10], S22,   /*38016083*/(unsigned int  )0x02441453); /* 22 */
  	GG ( c, d, a, b, in[15], S23, /*3634488961*/(unsigned int  )0xd8a1e681); /* 23 */
  	GG ( b, c, d, a, in[ 4], S24, /*3889429448*/(unsigned int  )0xe7d3fbc8); /* 24 */
  	GG ( a, b, c, d, in[ 9], S21,  /*568446438*/(unsigned int  )0x21e1cde6); /* 25 */
  	GG ( d, a, b, c, in[14], S22, /*3275163606*/(unsigned int  )0xc33707d6); /* 26 */
  	GG ( c, d, a, b, in[ 3], S23, /*4107603335*/(unsigned int  )0xf4d50d87); /* 27 */
  	GG ( b, c, d, a, in[ 8], S24, /*1163531501*/(unsigned int  )0x455a14ed); /* 28 */
  	GG ( a, b, c, d, in[13], S21, /*2850285829*/(unsigned int  )0xa9e3e905); /* 29 */
  	GG ( d, a, b, c, in[ 2], S22, /*4243563512*/(unsigned int  )0xfcefa3f8); /* 30 */
  	GG ( c, d, a, b, in[ 7], S23, /*1735328473*/(unsigned int  )0x676f02d9); /* 31 */
  	GG ( b, c, d, a, in[12], S24, /*2368359562*/(unsigned int  )0x8d2a4c8a); /* 32 */

  	/* Round 3 */
	#define S31 4
	#define S32 11
	#define S33 16
	#define S34 23
	
  	HH ( a, b, c, d, in[ 5], S31, /*4294588738*/(unsigned int  )0xfffa3942); /* 33 */
  	HH ( d, a, b, c, in[ 8], S32, /*2272392833*/(unsigned int  )0x8771f681); /* 34 */
  	HH ( c, d, a, b, in[11], S33, /*1839030562*/(unsigned int  )0x6d9d6122); /* 35 */
  	HH ( b, c, d, a, in[14], S34, /*4259657740*/(unsigned int  )0xfde5380c); /* 36 */
  	HH ( a, b, c, d, in[ 1], S31, /*2763975236*/(unsigned int  )0xa4beea44); /* 37 */
  	HH ( d, a, b, c, in[ 4], S32, /*1272893353*/(unsigned int  )0x4bdecfa9); /* 38 */
  	HH ( c, d, a, b, in[ 7], S33, /*4139469664*/(unsigned int  )0xf6bb4b60); /* 39 */
  	HH ( b, c, d, a, in[10], S34, /*3200236656*/(unsigned int  )0xbebfbc70); /* 40 */
  	HH ( a, b, c, d, in[13], S31,  /*681279174*/(unsigned int  )0x289b7ec6); /* 41 */
  	HH ( d, a, b, c, in[ 0], S32, /*3936430074*/(unsigned int  )0xeaa127fa); /* 42 */
  	HH ( c, d, a, b, in[ 3], S33, /*3572445317*/(unsigned int  )0xd4ef3085); /* 43 */
  	HH ( b, c, d, a, in[ 6], S34,   /*76029189*/(unsigned int  )0x04881d05); /* 44 */
  	HH ( a, b, c, d, in[ 9], S31, /*3654602809*/(unsigned int  )0xd9d4d039); /* 45 */
  	HH ( d, a, b, c, in[12], S32, /*3873151461*/(unsigned int  )0xe6db99e5); /* 46 */
  	HH ( c, d, a, b, in[15], S33,  /*530742520*/(unsigned int  )0x1fa27cf8); /* 47 */
  	HH ( b, c, d, a, in[ 2], S34, /*3299628645*/(unsigned int  )0xc4ac5665); /* 48 */

  	/* Round 4 */
	#define S41 6
	#define S42 10
	#define S43 15
	#define S44 21
	
  	II ( a, b, c, d, in[ 0], S41, /*4096336452*/(unsigned int  )0xf4292244); /* 49 */
  	II ( d, a, b, c, in[ 7], S42, /*1126891415*/(unsigned int  )0x432aff97); /* 50 */
  	II ( c, d, a, b, in[14], S43, /*2878612391*/(unsigned int  )0xab9423a7); /* 51 */
  	II ( b, c, d, a, in[ 5], S44, /*4237533241*/(unsigned int  )0xfc93a039); /* 52 */
  	II ( a, b, c, d, in[12], S41, /*1700485571*/(unsigned int  )0x655b59c3); /* 53 */
  	II ( d, a, b, c, in[ 3], S42, /*2399980690*/(unsigned int  )0x8f0ccc92); /* 54 */
  	II ( c, d, a, b, in[10], S43, /*4293915773*/(unsigned int  )0xffeff47d); /* 55 */
  	II ( b, c, d, a, in[ 1], S44, /*2240044497*/(unsigned int  )0x85845dd1); /* 56 */
  	II ( a, b, c, d, in[ 8], S41, /*1873313359*/(unsigned int  )0x6fa87e4f); /* 57 */
  	II ( d, a, b, c, in[15], S42, /*4264355552*/(unsigned int  )0xfe2ce6e0); /* 58 */
  	II ( c, d, a, b, in[ 6], S43, /*2734768916*/(unsigned int  )0xa3014314); /* 59 */
  	II ( b, c, d, a, in[13], S44, /*1309151649*/(unsigned int  )0x4e0811a1); /* 60 */
  	II ( a, b, c, d, in[ 4], S41, /*4149444226*/(unsigned int  )0xf7537e82); /* 61 */
  	II ( d, a, b, c, in[11], S42, /*3174756917*/(unsigned int  )0xbd3af235); /* 62 */
  	II ( c, d, a, b, in[ 2], S43,  /*718787259*/(unsigned int  )0x2ad7d2bb); /* 63 */
  	II ( b, c, d, a, in[ 9], S44, /*3951481745*/(unsigned int  )0xeb86d391); /* 64 */

  	buf[0] += a;
  	buf[1] += b;
  	buf[2] += c;
  	buf[3] += d;
}

int ADIBLCalculateMD5(const unsigned char* pucBuffer, int nLength, unsigned char ucMD5[16])
{
	md5_ctx_t sContext;
	
	if ((0==pucBuffer) || (nLength <= 0) || (0==ucMD5))
	{
		return -1;
	}

	BLMD5Init(&sContext);

	BLMD5Update(&sContext, (unsigned char *)pucBuffer, nLength);

	BLMD5Final(&sContext);

	memcpy(ucMD5, sContext.digest, 16);
	
	return 0;
}
