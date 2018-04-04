
#ifndef _ADI_TYPEDEF_H_
#define _ADI_TYPEDEF_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef int                 ADI_BOOL;

typedef void *			    ADI_HANDLE;         // �������,�䳤�ȵ���ָ�볤�ȡ�@note Eastwin�ὫADI_NULL����һ���Ƿ��ľ��������ʵ��ʱ�ر�ע������Handle��ȡֵ��Χ

#define ADI_FALSE         (0 == 1)
#define ADI_TRUE          (!(ADI_FALSE))

#ifdef PLATFORM_SUPPORT_LL

typedef long long           ADI_INT64;            ///< 64λ�з�����,������PLATFORM_SUPPORT_LLʱ��Ч
typedef unsigned long long  ADI_UINT64;          ///< 64λ�޷�����,������PLATFORM_SUPPORT_LLʱ��Ч

#else
/*64λ�з������ṹ��*/
typedef	struct
{
	unsigned int	 low; // ��32λ
	int	             high;// ��32λ
}ADI_INT64;

/*64λ�޷������ṹ��*/
typedef	struct
{
	unsigned int	low;// ��32λ
	unsigned int	high;// ��32λ
}ADI_UINT64;
#endif

#ifdef __cplusplus
}
#endif

#define __FUNCTION__ "notKnow"

#endif  

