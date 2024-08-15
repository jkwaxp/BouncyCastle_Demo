# bc-tool
bc算法库(bouncycastle)的二次封装，便捷API调用算法函数

# 目前只支持的算法
## 国际算法
- [AES](src/test/java/alg/bc/internation/AESTest)
- [DES3](src/test/java/alg/bc/internation/Des3Test)
- [RSA](src/test/java/alg/bc/internation/RsaTest)
- [MD5](src/test/java/alg/bc/internation/DigestTest)
- [SHA1](src/test/java/alg/bc/internation/DigestTest)
- [SHA256](src/test/java/alg/bc/internation/DigestTest)
- [SHA512](src/test/java/alg/bc/internation/DigestTest)
- [RSA证书](src/test/java/alg/bc/internation/CertTest)
    
## 国密算法
- [SM2](src/test/java/alg/bc/nation/SM2Test)
- [SM3](src/test/java/alg/bc/nation/SM3Test)
- [SM4](src/test/java/alg/bc/nation/SM4Test)
- [祖冲之算法(ZUC)](src/test/java/alg/bc/nation/ZucTest)
- [SM2证书](src/test/java/alg/bc/nation/GmCertTest)
    
详细的调用方式见对应的测试类    