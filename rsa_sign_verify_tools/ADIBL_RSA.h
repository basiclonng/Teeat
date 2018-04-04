#ifndef ___ADIBL_RSA__H_227722__
#define ___ADIBL_RSA__H_227722__

#include "adi_typedef.h"

#ifdef __cplusplus
extern "C" {
#endif

/*RSA hash签字校验模式*/
typedef enum
{
	//E_ADIBL_SIG_RSA_RAW = 0, // not support
	//E_ADIBL_SIG_RSA_MD2 = 2, // not support
	//E_ADIBL_SIG_RSA_MD4 = 3, // not support
	E_ADIBL_SIG_RSA_MD5 = 4,
	E_ADIBL_SIG_RSA_SHA1 = 5,
	//E_ADIBL_SIG_RSA_SHA224 = 14, // not support
	E_ADIBL_SIG_RSA_SHA256 = 11, 
	//E_ADIBL_SIG_RSA_SHA384 = 12, // not support
	//E_ADIBL_SIG_RSA_SHA512 = 13, // not support
	E_ADIBL_SIG_RSA_MAX
}ADIBLRSAHashMode_E;

/*RSA加解密操作的模式*/
typedef enum
{
	E_ADIBL_RSA_MODE_PUBLIC   =   (0),
	E_ADIBL_RSA_MODE_PRIVATE  =   (1),
	E_ADIBL_RSA_MODE_MAX = 2
}ADIBLRSAMode_E;

typedef struct  
{  
    int             bit;                  
    unsigned char   P[128];  
    unsigned char   Q[128];
	unsigned int crc32; /*以上260字节数据crc32*/
}rsa_crt_prikey;  
  
  
typedef struct  
{  
    int         bit;  
    unsigned char   N[256];
	unsigned int crc32; /*以上260字节数据crc32*/
}rsa_crt_pubkey; 

/*
 * Description: RSA PKCS1 加密数据
 *
 * Note: [默认为E_ADIBL_RSA_MODE_PUBLIC加密, E_ADIBL_RSA_MODE_PRIVATE解密]
 *		 out_rsa_ciphertext 空间的大小:::RSA-1024此空间需要大于等于128,  RSA-2048此空间需要大于等于256
 *		 RSA-1024 还是RSA-2048 取决于传入的pMiniKey的bit 也就是key的值
 *
 * Parameters : mode[输入参数]: 加密模式  
 *					E_ADIBL_RSA_MODE_PUBLIC:: public key加密模式;  
 *					E_ADIBL_RSA_MODE_PRIVATE:: private key加密模式 
 *				pMiniKey[输入参数]: key
 *					--如果是E_ADIBL_RSA_MODE_PUBLIC模式 请传入rsa_crt_pubkey * 结构指针
 *					--如果是E_ADIBL_RSA_MODE_PRIVATE模式 请传入rsa_crt_prikey * 结构指针
 *				in_rsa_plaintext[输入参数]: 原始待加密的数据	
 *				in_rsa_plaintext_len[输入参数]: 原始待加密的数据的长度
 *				out_rsa_ciphertext[输出参数]: 加密后得到的密文<<<RSA-1024此空间需要大于等于128,  RSA-2048此空间需要大于等于256>>>
 *
 * Returns	  :  0 success
 *				其他 failed		   
 */
int ADIBLRsa_PKCS1_Encrypt(ADIBLRSAMode_E mode, unsigned char *pMiniKey, 
		unsigned char* in_rsa_plaintext, int in_rsa_plaintext_len, unsigned char* out_rsa_ciphertext);

/*
 * Description: RSA PKCS1 解密
 *
 * Note: [默认为E_ADIBL_RSA_MODE_PUBLIC加密, E_ADIBL_RSA_MODE_PRIVATE解密]
 *		 in_rsa_ciphertext 空间的大小:::RSA-1024此空间需要大于等于128,  RSA-2048此空间需要大于等于256
 *		 RSA-1024 还是RSA-2048 取决于传入的pMiniKey的bit 也就是key的值
 *
 * Parameters : mode[输入参数]: 解密模式 
 *					E_ADIBL_RSA_MODE_PRIVATE:: private key解密模式
 *					E_ADIBL_RSA_MODE_PUBLIC:: public key解密模式
 *				pMiniKey[输入参数]: key
 *					--如果是E_ADIBL_RSA_MODE_PUBLIC模式 请传入rsa_crt_pubkey * 结构指针
 *					--如果是E_ADIBL_RSA_MODE_PRIVATE模式 请传入rsa_crt_prikey * 结构指针
 *				in_rsa_ciphertext[输入参数]: 被加密之后的数据<<<RSA1024此空间大小应该为大于等于128 RSA2048此空间大小应该大于等于256>>>
 *				out_rsa_plaintext[输出参数]:解密之后明文数据
 *				out_rsa_plaintext_len[输出参数]: 解密之后明文数据长度  输入为buffer空间大小*输出为实际解密后数据的长度
 *
 * Returns	  :  0 success
 *				其他 failed		   
 */
int ADIBLRsa_PKCS1_Decrypt(ADIBLRSAMode_E mode, unsigned char *pMiniKey, unsigned char* in_rsa_ciphertext, unsigned char* out_rsa_plaintext, int *out_rsa_plaintext_len);

/*
 * Description: RSA PKCS1 sign签字
 *
 * Note: [默认为E_ADIBL_RSA_MODE_PRIVATE签字, E_ADIBL_RSA_MODE_PUBLIC签字校验]
 *		 out_rsa_ciphertext 空间的大小:::RSA-1024此空间需要大于等于128,  RSA-2048此空间需要大于等于256
 *		 RSA-1024 还是RSA-2048 取决于传入的pMiniKey的bit 也就是key的值
 *
 * Parameters : mode[输入参数]: RSA签字模式
 *					E_ADIBL_RSA_MODE_PRIVATE:: private key签字
 *					E_ADIBL_RSA_MODE_PUBLIC:: public key签字
 *				pMiniKey[输入参数]: key
 *					--如果是E_ADIBL_RSA_MODE_PRIVATE模式 请算入rsa_crt_prikey * 结构指针
 *					--如果是E_ADIBL_RSA_MODE_PUBLIC模式 请算入rsa_crt_pubkey * 结构指针
 *				hashmode[输入参数]: 目前支持SHA1 SHA256 MD5
 *				hashdata_len[输入参数]:原始数据计算的摘要hash数据的长度
 *				hashdata[输入参数]:原始数据计算的摘要hash数据
 *				out_rsa_ciphertext[输出参数]: hash数据计算出来的数字签字
 *
 * Returns	  :  0 success
 *				其他 failed		   
 */
int ADIBLRsa_PKCS1_Sign(ADIBLRSAMode_E mode, unsigned char *pMiniKey, ADIBLRSAHashMode_E hashmode, int hashdata_len, unsigned char* hashdata, unsigned char* out_rsa_ciphertext);

/*
 * Description: RSA PKCS1 sign签字校验
 *
 * Note: [默认为E_ADIBL_RSA_MODE_PRIVATE签字, E_ADIBL_RSA_MODE_PUBLIC签字校验]
 *		 rsa_ciphertext_in 空间的大小:::RSA-1024此空间需要大于等于128,  RSA-2048此空间需要大于等于256
 *		 RSA-1024 还是RSA-2048 取决于传入的pMiniKey的bit 也就是key的值
 *
 * Parameters : mode[输入参数]: RSA签字校验模式
 *					E_ADIBL_RSA_MODE_PUBLIC:: public key签字校验
 *					E_ADIBL_RSA_MODE_PRIVATE:: private key签字校验
 *				pMiniKey[输入参数]: key
 *					--如果是E_ADIBL_RSA_MODE_PRIVATE模式 请传入rsa_crt_prikey * 结构指针
 *					--如果是E_ADIBL_RSA_MODE_PUBLIC模式 请传入rsa_crt_pubkey * 结构指针
 *				hashmode[输入参数]: 目前支持SHA1 SHA256 MD5
 *				hashdata_len[输入参数]:原始数据计算的摘要hash数据的长度
 *				hashdata[输入参数]:原始数据计算的摘要hash数据
 *				in_rsa_ciphertext[输入参数]: hash数据计算出来的数字签字
 *
 * Returns	  :  0 success
 *				其他 failed
 */
int ADIBLRsa_PKCS1_Verify(ADIBLRSAMode_E mode, unsigned char *pMiniKey, ADIBLRSAHashMode_E hashmode, int hashdata_len, unsigned char* hashdata, unsigned char* in_rsa_ciphertext);

#ifdef __cplusplus
}
#endif

#endif

