#ifndef ___ADIBL_RSA__H_227722__
#define ___ADIBL_RSA__H_227722__

#include "adi_typedef.h"

#ifdef __cplusplus
extern "C" {
#endif

/*RSA hashǩ��У��ģʽ*/
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

/*RSA�ӽ��ܲ�����ģʽ*/
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
	unsigned int crc32; /*����260�ֽ�����crc32*/
}rsa_crt_prikey;  
  
  
typedef struct  
{  
    int         bit;  
    unsigned char   N[256];
	unsigned int crc32; /*����260�ֽ�����crc32*/
}rsa_crt_pubkey; 

/*
 * Description: RSA PKCS1 ��������
 *
 * Note: [Ĭ��ΪE_ADIBL_RSA_MODE_PUBLIC����, E_ADIBL_RSA_MODE_PRIVATE����]
 *		 out_rsa_ciphertext �ռ�Ĵ�С:::RSA-1024�˿ռ���Ҫ���ڵ���128,  RSA-2048�˿ռ���Ҫ���ڵ���256
 *		 RSA-1024 ����RSA-2048 ȡ���ڴ����pMiniKey��bit Ҳ����key��ֵ
 *
 * Parameters : mode[�������]: ����ģʽ  
 *					E_ADIBL_RSA_MODE_PUBLIC:: public key����ģʽ;  
 *					E_ADIBL_RSA_MODE_PRIVATE:: private key����ģʽ 
 *				pMiniKey[�������]: key
 *					--�����E_ADIBL_RSA_MODE_PUBLICģʽ �봫��rsa_crt_pubkey * �ṹָ��
 *					--�����E_ADIBL_RSA_MODE_PRIVATEģʽ �봫��rsa_crt_prikey * �ṹָ��
 *				in_rsa_plaintext[�������]: ԭʼ�����ܵ�����	
 *				in_rsa_plaintext_len[�������]: ԭʼ�����ܵ����ݵĳ���
 *				out_rsa_ciphertext[�������]: ���ܺ�õ�������<<<RSA-1024�˿ռ���Ҫ���ڵ���128,  RSA-2048�˿ռ���Ҫ���ڵ���256>>>
 *
 * Returns	  :  0 success
 *				���� failed		   
 */
int ADIBLRsa_PKCS1_Encrypt(ADIBLRSAMode_E mode, unsigned char *pMiniKey, 
		unsigned char* in_rsa_plaintext, int in_rsa_plaintext_len, unsigned char* out_rsa_ciphertext);

/*
 * Description: RSA PKCS1 ����
 *
 * Note: [Ĭ��ΪE_ADIBL_RSA_MODE_PUBLIC����, E_ADIBL_RSA_MODE_PRIVATE����]
 *		 in_rsa_ciphertext �ռ�Ĵ�С:::RSA-1024�˿ռ���Ҫ���ڵ���128,  RSA-2048�˿ռ���Ҫ���ڵ���256
 *		 RSA-1024 ����RSA-2048 ȡ���ڴ����pMiniKey��bit Ҳ����key��ֵ
 *
 * Parameters : mode[�������]: ����ģʽ 
 *					E_ADIBL_RSA_MODE_PRIVATE:: private key����ģʽ
 *					E_ADIBL_RSA_MODE_PUBLIC:: public key����ģʽ
 *				pMiniKey[�������]: key
 *					--�����E_ADIBL_RSA_MODE_PUBLICģʽ �봫��rsa_crt_pubkey * �ṹָ��
 *					--�����E_ADIBL_RSA_MODE_PRIVATEģʽ �봫��rsa_crt_prikey * �ṹָ��
 *				in_rsa_ciphertext[�������]: ������֮�������<<<RSA1024�˿ռ��СӦ��Ϊ���ڵ���128 RSA2048�˿ռ��СӦ�ô��ڵ���256>>>
 *				out_rsa_plaintext[�������]:����֮����������
 *				out_rsa_plaintext_len[�������]: ����֮���������ݳ���  ����Ϊbuffer�ռ��С*���Ϊʵ�ʽ��ܺ����ݵĳ���
 *
 * Returns	  :  0 success
 *				���� failed		   
 */
int ADIBLRsa_PKCS1_Decrypt(ADIBLRSAMode_E mode, unsigned char *pMiniKey, unsigned char* in_rsa_ciphertext, unsigned char* out_rsa_plaintext, int *out_rsa_plaintext_len);

/*
 * Description: RSA PKCS1 signǩ��
 *
 * Note: [Ĭ��ΪE_ADIBL_RSA_MODE_PRIVATEǩ��, E_ADIBL_RSA_MODE_PUBLICǩ��У��]
 *		 out_rsa_ciphertext �ռ�Ĵ�С:::RSA-1024�˿ռ���Ҫ���ڵ���128,  RSA-2048�˿ռ���Ҫ���ڵ���256
 *		 RSA-1024 ����RSA-2048 ȡ���ڴ����pMiniKey��bit Ҳ����key��ֵ
 *
 * Parameters : mode[�������]: RSAǩ��ģʽ
 *					E_ADIBL_RSA_MODE_PRIVATE:: private keyǩ��
 *					E_ADIBL_RSA_MODE_PUBLIC:: public keyǩ��
 *				pMiniKey[�������]: key
 *					--�����E_ADIBL_RSA_MODE_PRIVATEģʽ ������rsa_crt_prikey * �ṹָ��
 *					--�����E_ADIBL_RSA_MODE_PUBLICģʽ ������rsa_crt_pubkey * �ṹָ��
 *				hashmode[�������]: Ŀǰ֧��SHA1 SHA256 MD5
 *				hashdata_len[�������]:ԭʼ���ݼ����ժҪhash���ݵĳ���
 *				hashdata[�������]:ԭʼ���ݼ����ժҪhash����
 *				out_rsa_ciphertext[�������]: hash���ݼ������������ǩ��
 *
 * Returns	  :  0 success
 *				���� failed		   
 */
int ADIBLRsa_PKCS1_Sign(ADIBLRSAMode_E mode, unsigned char *pMiniKey, ADIBLRSAHashMode_E hashmode, int hashdata_len, unsigned char* hashdata, unsigned char* out_rsa_ciphertext);

/*
 * Description: RSA PKCS1 signǩ��У��
 *
 * Note: [Ĭ��ΪE_ADIBL_RSA_MODE_PRIVATEǩ��, E_ADIBL_RSA_MODE_PUBLICǩ��У��]
 *		 rsa_ciphertext_in �ռ�Ĵ�С:::RSA-1024�˿ռ���Ҫ���ڵ���128,  RSA-2048�˿ռ���Ҫ���ڵ���256
 *		 RSA-1024 ����RSA-2048 ȡ���ڴ����pMiniKey��bit Ҳ����key��ֵ
 *
 * Parameters : mode[�������]: RSAǩ��У��ģʽ
 *					E_ADIBL_RSA_MODE_PUBLIC:: public keyǩ��У��
 *					E_ADIBL_RSA_MODE_PRIVATE:: private keyǩ��У��
 *				pMiniKey[�������]: key
 *					--�����E_ADIBL_RSA_MODE_PRIVATEģʽ �봫��rsa_crt_prikey * �ṹָ��
 *					--�����E_ADIBL_RSA_MODE_PUBLICģʽ �봫��rsa_crt_pubkey * �ṹָ��
 *				hashmode[�������]: Ŀǰ֧��SHA1 SHA256 MD5
 *				hashdata_len[�������]:ԭʼ���ݼ����ժҪhash���ݵĳ���
 *				hashdata[�������]:ԭʼ���ݼ����ժҪhash����
 *				in_rsa_ciphertext[�������]: hash���ݼ������������ǩ��
 *
 * Returns	  :  0 success
 *				���� failed
 */
int ADIBLRsa_PKCS1_Verify(ADIBLRSAMode_E mode, unsigned char *pMiniKey, ADIBLRSAHashMode_E hashmode, int hashdata_len, unsigned char* hashdata, unsigned char* in_rsa_ciphertext);

#ifdef __cplusplus
}
#endif

#endif

