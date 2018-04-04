#ifndef ___ADIBL_MD5___H_342234__
#define ___ADIBL_MD5___H_342234__

#include "adi_typedef.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Description: ����һ��16���Ƶ�MD5
 *
 * Parameters : pucBuffer ����16��������buffer
 *				nLength �������ݵĳ���
 *				ucMD5 ���������MD5 �ռ�̶�Ϊ16�ֽ�
 *
 * note:	����MD5�������ĳ����ǹ̶���, ��̶�MD5 buffer 16�ֽ�
 *
 * Returns	  : 0--�ɹ�
 * 				����--ʧ��
 *			   
 */
int ADIBLCalculateMD5(const unsigned char* pucBuffer, int nLength, unsigned char ucMD5[16]);

#ifdef __cplusplus
}
#endif

#endif

