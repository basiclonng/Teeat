#ifndef ___ADIBL_SHA1_SHA256___H_342234__
#define ___ADIBL_SHA1_SHA256___H_342234__

#include "adi_typedef.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Description: 计算一组16进制的SHA1
 *
 * Parameters : pucBuffer 输入16进制数据buffer
 *				nLength 输入数据的长度
 *				sha1 计算出来的sha1 空间固定为20字节
 *
 * note:	由于sha1计算结果的长度是固定的, 请固定sha1 buffer 20字节
 *
 * Returns	  : 0--成功
 * 				其他--失败
 *			   
 */
int ADIBLCalculateSHA1(const unsigned char * psrcdata, unsigned int len,unsigned char sha1[20]);

/*
 * Description: 计算一组16进制的SHA256
 *
 * Parameters : pucBuffer 输入16进制数据buffer
 *				nLength 输入数据的长度
 *				sha256 计算出来的sha256 空间固定为32字节
 *
 * note:	由于sha256计算结果的长度是固定的, 请固定sha256 buffer 32字节
 *
 * Returns	  : 0--成功
 * 				其他--失败
 *			   
 */
int ADIBLCalculateSHA256(const unsigned char * psrcdata, unsigned int len,unsigned char sha256[32]);


#ifdef __cplusplus
}
#endif

#endif

