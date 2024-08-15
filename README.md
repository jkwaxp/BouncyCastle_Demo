# bc-tool
bc算法库(bouncycastle)的二次封装，便捷API调用算法函数

# 目前只支持的算法
## 国际算法
- [AES](src/test/java/alg/bc/internation/AESTest.java)
- [DES3](src/test/java/alg/bc/internation/Des3Test.java)
- [RSA](src/test/java/alg/bc/internation/RsaTest.java)
- [MD5](src/test/java/alg/bc/internation/DigestTest.java)
- [SHA1](src/test/java/alg/bc/internation/DigestTest.java)
- [SHA256](src/test/java/alg/bc/internation/DigestTest.java)
- [SHA512](src/test/java/alg/bc/internation/DigestTest.java)
- [RSA证书](src/test/java/alg/bc/internation/CertTest.java)
    
## 国密算法
- [SM2](src/test/java/alg/bc/nation/SM2Test.java)
- [SM3](src/test/java/alg/bc/nation/SM3Test.java)
- [SM4](src/test/java/alg/bc/nation/SM4Test.java)
- [祖冲之算法(ZUC)](src/test/java/alg/bc/nation/ZucTest.java)
- [SM2证书](src/test/java/alg/bc/nation/GmCertTest.java)
    
详细的调用方式见对应的测试类    