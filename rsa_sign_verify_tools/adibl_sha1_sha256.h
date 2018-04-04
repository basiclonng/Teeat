#ifndef ___ADIBL_SHA1_SHA256___H_342234__
#define ___ADIBL_SHA1_SHA256___H_342234__

#include "adi_typedef.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Description: ����һ��16���Ƶ�SHA1
 *
 * Parameters : pucBuffer ����16��������buffer
 *				nLength �������ݵĳ���
 *				sha1 ���������sha1 �ռ�̶�Ϊ20�ֽ�
 *
 * note:	����sha1�������ĳ����ǹ̶���, ��̶�sha1 buffer 20�ֽ�
 *
 * Returns	  : 0--�ɹ�
 * 				����--ʧ��
 *			   
 */
int ADIBLCalculateSHA1(const unsigned char * psrcdata, unsigned int len,unsigned char sha1[20]);

/*
 * Description: ����һ��16���Ƶ�SHA256
 *
 * Parameters : pucBuffer ����16��������buffer
 *				nLength �������ݵĳ���
 *				sha256 ���������sha256 �ռ�̶�Ϊ32�ֽ�
 *
 * note:	����sha256�������ĳ����ǹ̶���, ��̶�sha256 buffer 32�ֽ�
 *
 * Returns	  : 0--�ɹ�
 * 				����--ʧ��
 *			   
 */
int ADIBLCalculateSHA256(const unsigned char * psrcdata, unsigned int len,unsigned char sha256[32]);


#ifdef __cplusplus
}
#endif

#endif

