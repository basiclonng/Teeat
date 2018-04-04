
#ifndef ___ADIBL_CRC___H_345_
#define ___ADIBL_CRC___H_345_

#include "adi_typedef.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Description: ��������CRC16
 *
 * Parameters : 
 *				�������
 *					pvDataIn �����ڴ��ַ
 *					unSizeInBytes ���ݳ���
 *				�������
 *					��
 *
 * Returns	  : ���������CRC16
 */
unsigned short ADIBLCalculateCRC16(void* pvDataIn, unsigned int unSizeInBytes);

/*
 * Description: ��������CRC32
 *
 * Parameters : 
 *				�������
 *					pvDataIn �����ڴ��ַ
 *					unSizeInBytes ���ݳ���
 *				�������
 *					��
 *
 * Returns	  : ���������CRC32
 */
unsigned int ADIBLCalculateCRC32(void* pvDataIn, unsigned int unSizeInBytes);

/*
 * Description: ��������MPEGCRC32
 *
 * Parameters : 
 *				�������
 *					pvDataIn �����ڴ��ַ
 *					unSizeInBytes ���ݳ���
 *				�������
 *					��
 *
 * Returns	  : ���������MPEGCRC32
 */
unsigned int ADIBLCalculateMPEGCRC32(void* pvDataIn, unsigned int unSizeInBytes);

#ifdef __cplusplus
}
#endif

#endif

