@echo =============================================================
@echo 以下sign_app为签字校验命令， 
@echo dvbt_keltic.bin为原始待签字app，  
@echo sign.bin为签字bin文件， 
@echo 20151124_101809_private_key_RSA-2048.bin为签字使用的私钥 , 
@echo sha256 为hash算法
@echo =============================================================

rsa_sign_verify       sign_app    dvbt_keltic.bin     sign.bin  20151124_101809_private_key_RSA-2048.bin     sha256
pause