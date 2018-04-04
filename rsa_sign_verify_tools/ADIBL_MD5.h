#ifndef ___ADIBL_MD5___H_342234__
#define ___ADIBL_MD5___H_342234__

#include "adi_typedef.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Description: 计算一组16进制的MD5
 *
 * Parameters : pucBuffer 输入16进制数据buffer
 *				nLength 输入数据的长度
 *				ucMD5 计算出来的MD5 空间固定为16字节
 *
 * note:	由于MD5计算结果的长度是固定的, 请固定MD5 buffer 16字节
 *
 * Returns	  : 0--成功
 * 				其他--失败
 *			   
 */
int ADIBLCalculateMD5(const unsigned char* pucBuffer, int nLength, unsigned char ucMD5[16]);

#ifdef __cplusplus
}
#endif

#endif

