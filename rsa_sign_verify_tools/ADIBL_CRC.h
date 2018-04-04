
#ifndef ___ADIBL_CRC___H_345_
#define ___ADIBL_CRC___H_345_

#include "adi_typedef.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Description: 计算数据CRC16
 *
 * Parameters : 
 *				输入参数
 *					pvDataIn 数据内存地址
 *					unSizeInBytes 数据长度
 *				输出参数
 *					无
 *
 * Returns	  : 计算出来的CRC16
 */
unsigned short ADIBLCalculateCRC16(void* pvDataIn, unsigned int unSizeInBytes);

/*
 * Description: 计算数据CRC32
 *
 * Parameters : 
 *				输入参数
 *					pvDataIn 数据内存地址
 *					unSizeInBytes 数据长度
 *				输出参数
 *					无
 *
 * Returns	  : 计算出来的CRC32
 */
unsigned int ADIBLCalculateCRC32(void* pvDataIn, unsigned int unSizeInBytes);

/*
 * Description: 计算数据MPEGCRC32
 *
 * Parameters : 
 *				输入参数
 *					pvDataIn 数据内存地址
 *					unSizeInBytes 数据长度
 *				输出参数
 *					无
 *
 * Returns	  : 计算出来的MPEGCRC32
 */
unsigned int ADIBLCalculateMPEGCRC32(void* pvDataIn, unsigned int unSizeInBytes);

#ifdef __cplusplus
}
#endif

#endif

