#include "stdio.h"
#include "string.h"
#include <stdlib.h>
#include "time.h"
#include "polarssl_rsa.h"

//void  setRSA_bit(int RSAbit);

void main(int argc, char* argv[])
{
	int RSAbit = 0;

	printf("It is argc-%d\n", argc);

	if(argc<=1)
	{
		printf("please run **.bat!\n");
		goto ERR_END;
	}

	if(strlen(argv[1]) == 0)
	{
		printf("*.param error!\n");
		goto ERR_END;
	}
	
	if(memcmp(argv[1], "gen_keys", strlen("gen_keys"))==0)
	{
		srand(time(NULL));
		printf(">>>>>>>>>>>>>>>>>>>>gen_keys>>>>>>>>>>>>>>>>\n");
		if(argc>=3)
		{	
			RSAbit = atoi(argv[2]);
			printf("It is RSA-%d\n", RSAbit);
			
			if((RSAbit!=1024) && (RSAbit!=2048))
			{
				printf("RSAbit:%d error!, should be 1024 or 2048\n", RSAbit);
				goto ERR_END;		
			}
			
			setRSA_bit(RSAbit);
			RSAGenKeys();
		}
		else
		{
			printf("ERROR!!, please run bat as <<<<rsa_sign_verify gen_keys 2048>>>>\n");
		}
		printf("<<<<<<<<<<<<<<<<<<<<gen_keys<<<<<<<<<<<<<<<<\n");
	}
	else if(memcmp(argv[1], "sign_app", strlen("sign_app"))==0)
	{
		printf(">>>>>>>>>>>>>>>>>>>>sign_app>>>>>>>>>>>>>>>>\n");
		if(argc>=6)
		{
			RSASignApp(argv[2], argv[3], argv[4], argv[5]);
		}
		else
		{
			printf("ERROR!!, please run bat as [rsa_sign_verify  sign_app  dvbt_keltic.bin  sign.bin  20151124_101809_private_key_RSA-2048.bin  sha256]\n");
		}
		printf("<<<<<<<<<<<<<<<<<<<<sign_app<<<<<<<<<<<<<<<<\n");
	}
	else if(memcmp(argv[1], "sign_verify", strlen("sign_verify"))==0)
	{
		printf(">>>>>>>>>>>>>>>>>>>> sign_verify>>>>>>>>>>>>>>>>\n");
		if(argc>=6)
		{
			RSAVerifySignApp(argv[2], argv[3], argv[4], argv[5]);
		}
		else
		{
			printf("ERROR!!, please run bat as [rsa_sign_verify  sign_verify  dvbt_keltic.bin   sign.bin  20151124_101809_public_key_RSA-2048.bin  sha256]\n");
		}
		printf("<<<<<<<<<<<<<<<<<<<< sign_verify<<<<<<<<<<<<<<<<\n");
	}

	//rsa_self_test(1);

ERR_END:
	return;
}
