package alg.bc.nation;

import alg.bc.ProviderRegist;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.*;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.*;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;

/**
 * GM/T 0003-2012 标准推荐参数 sm2p256v1
 * 椭圆曲线方程 y^2 = x^3 + ax + b
 */
public class SM2 extends ProviderRegist {

    static final byte[] DEFAULT_ID = Strings.toByteArray("1234567812345678");

    static final BigInteger SM2_ECC_P = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16);
    static final BigInteger SM2_ECC_A = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16);
    static final BigInteger SM2_ECC_B = new BigInteger("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16);
    static final BigInteger SM2_ECC_N = new BigInteger("fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123", 16);
    static final BigInteger SM2_ECC_H = ECConstants.ONE;
    static final BigInteger SM2_ECC_GX = new BigInteger("32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7", 16);
    static final BigInteger SM2_ECC_GY = new BigInteger("bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0", 16);
    static final ECCurve curve = new ECCurve.Fp(SM2_ECC_P, SM2_ECC_A, SM2_ECC_B, SM2_ECC_N, SM2_ECC_H);
    static final ECPoint g = curve.createPoint(SM2_ECC_GX, SM2_ECC_GY);
    static final ECDomainParameters domainParams = new ECDomainParameters(curve, g, SM2_ECC_N);
    static final int CURVE_LEN = (domainParams.getCurve().getFieldSize() + 7) / 8;

    /**
     * 生成公私钥对
     * @return
     * @throws Exception
     */
    public static KeyPair generateKeyPair() throws Exception{
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        ECParameterSpec aKeyGenParams = new ECParameterSpec(domainParams.getCurve(), domainParams.getG(), domainParams.getN(), domainParams.getH());
        keyPairGenerator.initialize(aKeyGenParams);
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * 公钥对象转字节数据，内容为公钥坐标信息，65字节
     * @param publicKey
     * @return
     */
    public static byte[] pubKeyToBytes(PublicKey publicKey){
        byte[] q = ((BCECPublicKey)publicKey).getQ().getEncoded(false);
        byte[] rawXY = new byte[CURVE_LEN * 2];
        System.arraycopy(q, 1, rawXY, 0, rawXY.length);
        return rawXY;
    }

    /**
     * 公钥字节数组转公钥对象
     * @param buffer    支持33字节(压缩公钥)/64、65字节（未压缩公钥）
     * @return
     * @throws Exception
     */
    public static PublicKey bytesToPubKey(byte[] buffer) throws Exception{
        if(buffer.length == 33){
            buffer = decompress(buffer);
        }
        if(buffer.length == 64){
            byte[] tmp = new byte[65];
            tmp[0] = 0x04;
            System.arraycopy(buffer, 0, tmp, 1, 64);
            buffer = tmp;
        }
        ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(curve.decodePoint(buffer), domainParams);
        ECParameterSpec parameterSpec = new ECParameterSpec(domainParams.getCurve(), domainParams.getG(),
                domainParams.getN(), domainParams.getH());
        return new BCECPublicKey("EC", publicKeyParameters, parameterSpec, BouncyCastleProvider.CONFIGURATION);
    }

    /**
     * 私钥对象转字节数据，32字节
     * @param privateKey
     * @return
     */
    public static byte[] prvKeyToBytes(PrivateKey privateKey){
        byte[] d = ((BCECPrivateKey)privateKey).getD().toByteArray();
        if (d.length <= CURVE_LEN) {
            return d;
        } else {
            byte[] result = new byte[CURVE_LEN];
            System.arraycopy(d, d.length - CURVE_LEN, result, 0, CURVE_LEN);
            return result;
        }
    }

    /**
     * 字节数组(32字节)转成私钥对象
     * @param buffer
     * @return
     * @throws Exception
     */
    public static PrivateKey bytesToPrvKey(byte[] buffer) throws Exception{
        ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(new BigInteger(1, buffer), domainParams);
        return new BCECPrivateKey("EC", privateKeyParameters, BouncyCastleProvider.CONFIGURATION);
    }

    /**
     * 使用公钥字节数组进行SM2加密（密文结构:C1C3C2）
     * @param pubKey
     * @param input
     * @return
     * @throws Exception
     */
    public static byte[] encrypt(byte[] pubKey, byte[] input) throws Exception{
        PublicKey publicKey = bytesToPubKey(pubKey);
        return encrypt(publicKey, input);
    }

    /**
     * 使用公钥字节数组进行指定模式(C1C2C3/C1C3C2)的SM2加密
     * @param pubKey
     * @param input
     * @param mode
     * @return
     * @throws Exception
     */
    public static byte[] encrypt(byte[] pubKey, byte[] input, SM2Engine.Mode mode) throws Exception{
        PublicKey publicKey = bytesToPubKey(pubKey);
        return encrypt(publicKey, input, mode);
    }

    /**
     * 使用公钥字节数组进行SM2加密（密文结构:C1C3C2）
     * @param publicKey
     * @param input
     * @return
     * @throws Exception
     */
    public static byte[] encrypt(PublicKey publicKey, byte[] input) throws Exception{
        return encrypt(publicKey, input, SM2Engine.Mode.C1C3C2);
    }

    /**
     * 使用公钥对象进行指定模式(C1C2C3/C1C3C2)的SM2加密
     * @param publicKey
     * @param input
     * @param mode
     * @return
     * @throws Exception
     */
    public static byte[] encrypt(PublicKey publicKey, byte[] input, SM2Engine.Mode mode) throws Exception{
        ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(((BCECPublicKey)publicKey).getQ(), domainParams);
        SM2Engine sm2Engine = new SM2Engine(mode);
        sm2Engine.init(true, new ParametersWithRandom(publicKeyParameters, new SecureRandom()));
        return sm2Engine.processBlock(input, 0, input.length);
    }

    /**
     * 使用私钥字节数组进行SM2解密（密文结构:C1C3C2）
     * @param prvKey
     * @param input
     * @return
     * @throws Exception
     */
    public static byte[] decrypt(byte[] prvKey, byte[] input)throws Exception{
        PrivateKey privateKey = bytesToPrvKey(prvKey);
        return decrypt(privateKey, input);
    }

    /**
     * 使用私钥字节数组进行指定模式(C1C2C3/C1C3C2)的SM2加密
     * @param prvKey
     * @param input
     * @param mode
     * @return
     * @throws Exception
     */
    public static byte[] decrypt(byte[] prvKey, byte[] input, SM2Engine.Mode mode)throws Exception{
        PrivateKey privateKey = bytesToPrvKey(prvKey);
        return decrypt(privateKey, input, mode);
    }

    /**
     * 使用私钥对象进行SM2解密（密文结构:C1C3C2）
     * @param privateKey
     * @param input
     * @return
     * @throws Exception
     */
    public static byte[] decrypt(PrivateKey privateKey, byte[] input) throws Exception{
        return decrypt(privateKey, input, SM2Engine.Mode.C1C3C2);
    }

    /**
     * 使用私钥对象进行指定模式(C1C2C3/C1C3C2)的SM2加密
     * @param privateKey
     * @param input
     * @param mode
     * @return
     * @throws Exception
     */
    public static byte[] decrypt(PrivateKey privateKey, byte[] input, SM2Engine.Mode mode) throws Exception{
        ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(((BCECPrivateKey)privateKey).getD(), domainParams);
        SM2Engine sm2Engine = new SM2Engine(mode);
        sm2Engine.init(false, privateKeyParameters);
        return sm2Engine.processBlock(input, 0, input.length);
    }

    /**
     * 使用私钥字节数组计算标准SM2签名
     * 签名值为64字节 R || S
     * @param prvKey
     * @param msg
     * @return
     * @throws Exception
     */
    public static byte[] sign(byte[] prvKey, byte[] msg) throws Exception{
        PrivateKey privateKey = bytesToPrvKey(prvKey);
        return sign(privateKey, msg, DEFAULT_ID);
    }

    /**
     * 使用私钥字节数组，指定标识，计算SM2签名
     * 签名值为64字节 R || S
     * @param prvKey
     * @param msg
     * @return
     * @throws Exception
     */
    public static byte[] sign(byte[] prvKey, byte[] msg, byte[] id) throws Exception{
        PrivateKey privateKey = bytesToPrvKey(prvKey);
        return sign(privateKey, msg, id);
    }

    /**
     * 使用私钥对象计算标准SM2签名
     * 签名值为64字节 R || S
     * @param privateKey
     * @param msg
     * @return
     * @throws Exception
     */
    public static byte[] sign(PrivateKey privateKey, byte[] msg) throws Exception{
        return sign(privateKey, msg, DEFAULT_ID);
    }

    /**
     * 使用私钥对象，指定标识，计算SM2签名
     * 签名值为64字节 R || S
     * @param privateKey
     * @param msg
     * @return
     * @throws Exception
     */
    public static byte[] sign(PrivateKey privateKey, byte[] msg, byte[] id) throws Exception{
        SM2Signer signer = new SM2Signer(PlainDSAEncoding.INSTANCE);
        return signBySm2(signer, privateKey, msg, id);
    }

    /**
     * 使用私钥对象计算标准SM2签名
     * 签名结果为ANS.1编码
     * @param privateKey
     * @param msg
     * @return
     * @throws Exception
     */
    public static byte[] signAsn1(PrivateKey privateKey, byte[] msg) throws Exception{
        SM2Signer signer = new SM2Signer(StandardDSAEncoding.INSTANCE);
        return signBySm2(signer, privateKey, msg, DEFAULT_ID);
    }

    private static byte[] signBySm2(SM2Signer signer, PrivateKey privateKey, byte[] msg, byte[] id) throws Exception{
        ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(((BCECPrivateKey)privateKey).getD(), domainParams);
        CipherParameters param = new ParametersWithID(new ParametersWithRandom(privateKeyParameters, new SecureRandom()), id);
        signer.init(true, param);
        signer.update(msg, 0, msg.length);
        return signer.generateSignature();
    }

    /**
     * 拆解步骤，与直接调用sign一致
     * @param prvKey
     * @param msg
     * @return
     * @throws Exception
     */
    public static byte[] signStd(byte[] prvKey, byte[] msg) throws Exception{
        PrivateKey privateKey = bytesToPrvKey(prvKey);
        return signStd(privateKey, msg);
    }

    /**
     * 拆解步骤，与直接调用sign一致
     * 1. Z = SM3(ENTL || ID || a || b || x_G || y_G || x_A || y_A)
     * 2. e = SM3(Z || M)
     * 3. S = sign(e)
     * @param privateKey
     * @param msg
     * @return
     * @throws Exception
     */
    public static byte[] signStd(PrivateKey privateKey, byte[] msg) throws Exception{
        BigInteger d = ((BCECPrivateKey)privateKey).getD();
        ECPublicKeyParameters publicKeyParams = new ECPublicKeyParameters(g.multiply(d), domainParams);
        ECPoint publicKey = publicKeyParams.getQ();

        byte[] z = generateZ(DEFAULT_ID, publicKey);
        byte[] eHash = generateE(z, msg);
        return signRaw(privateKey, eHash);
    }

    /**
     * 直接对原始数据签名（不计算z、e）
     * @param privateKey
     * @param input
     * @return
     * @throws Exception
     */
    public static byte[] signRaw(PrivateKey privateKey, byte[] input) throws Exception{
        BigInteger d = ((BCECPrivateKey)privateKey).getD();
        BigInteger e = new BigInteger(1, input);

        BigInteger n = domainParams.getN();
        BigInteger r, s;

        ECMultiplier basePointMultiplier = new FixedPointCombMultiplier();
        DSAKCalculator kCalculator = new RandomDSAKCalculator();
        kCalculator.init(domainParams.getN(), new SecureRandom());
        do{
            BigInteger k;
            do{
                k = kCalculator.nextK();
                ECPoint p = basePointMultiplier.multiply(domainParams.getG(), k).normalize();
                r = e.add(p.getAffineXCoord().toBigInteger()).mod(n);
            }while (r.equals(ECConstants.ZERO) || r.add(k).equals(n));

            BigInteger dPlus1ModN = BigIntegers.modOddInverse(n, d.add(ECConstants.ONE));
            s = k.subtract(r.multiply(d)).mod(n);
            s = dPlus1ModN.multiply(s).mod(n);
        }while (s.equals(ECConstants.ZERO));

        try{
            return PlainDSAEncoding.INSTANCE.encode(domainParams.getN(), r, s);
        }catch (Exception ex){
            throw new CryptoException("unable to encode signature: " + ex.getMessage(), ex);
        }
    }

    public static boolean verify(byte[] pubKey, byte[] msg, byte[] signature) throws Exception{
        PublicKey publicKey = bytesToPubKey(pubKey);
        return verify(publicKey, msg, signature, DEFAULT_ID);
    }

    public static boolean verify(byte[] pubKey, byte[] msg, byte[] signature, byte[] id) throws Exception{
        PublicKey publicKey = bytesToPubKey(pubKey);
        return verify(publicKey, msg, signature, id);
    }

    public static boolean verify(PublicKey publicKey, byte[] msg, byte[] signature) {
        return verify(publicKey, msg, signature, DEFAULT_ID);
    }

    public static boolean verify(PublicKey publicKey, byte[] msg, byte[] signature, byte[] id) {
        SM2Signer signer = new SM2Signer(PlainDSAEncoding.INSTANCE);
        return verifyBySm2(signer, publicKey, msg, signature, id);
    }

    /**
     * ANS.1签名结构验证
     * @param publicKey
     * @param msg
     * @param signature
     * @return
     * @throws Exception
     */
    public static boolean verifyAsn1(PublicKey publicKey, byte[] msg, byte[] signature) {
        SM2Signer signer = new SM2Signer(StandardDSAEncoding.INSTANCE);
        return verifyBySm2(signer, publicKey, msg, signature, DEFAULT_ID);
    }

    private static boolean verifyBySm2(SM2Signer signer, PublicKey publicKey, byte[] msg, byte[] signature, byte[] id){
        ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(((BCECPublicKey)publicKey).getQ(), domainParams);
        CipherParameters param = new ParametersWithID(publicKeyParameters, id);
        signer.init(false, param);
        signer.update(msg, 0, msg.length);
        return signer.verifySignature(signature);
    }

    /**
     * 拆解步骤，与直接调用verify一致
     * @param pubKey
     * @param msg
     * @param signature
     * @return
     * @throws Exception
     */
    public static boolean verifyStd(byte[] pubKey, byte[] msg, byte[] signature) throws Exception{
        PublicKey publicKey = bytesToPubKey(pubKey);
        return verifyStd(publicKey, msg, signature);
    }

    /**
     * 拆解步骤，与直接调用verify一致
     * @param publicKey
     * @param msg
     * @param signature
     * @return
     * @throws Exception
     */
    public static boolean verifyStd(PublicKey publicKey, byte[] msg, byte[] signature) throws Exception{
        ECPoint q = ((BCECPublicKey)publicKey).getQ();

        byte[] z = generateZ(DEFAULT_ID, q);
        byte[] eHash = generateE(z, msg);

        return verifyRaw(publicKey, eHash, signature);
    }

    /**
     * 原始数据签名验证（不计算z、e）
     * @param publicKey
     * @param msg
     * @param signature
     * @return
     * @throws Exception
     */
    public static boolean verifyRaw(PublicKey publicKey, byte[] msg, byte[] signature) throws Exception{
        ECPoint q = ((BCECPublicKey)publicKey).getQ();

        BigInteger[] rs = decode(rsToAns1(signature));
        BigInteger r = rs[0];
        BigInteger s = rs[1];

        BigInteger n = domainParams.getN();
        if (r.compareTo(ECConstants.ONE) < 0 || r.compareTo(n) >= 0){
            return false;
        }
        if (s.compareTo(ECConstants.ONE) < 0 || s.compareTo(n) >= 0){
            return false;
        }

        BigInteger e = new BigInteger(1, msg);
        BigInteger t = r.add(s).mod(n);
        if (t.equals(ECConstants.ZERO)){
            return false;
        }
        ECPoint x1y1 = ECAlgorithms.sumOfTwoMultiplies(domainParams.getG(), s, q, t).normalize();
        if (x1y1.isInfinity()){
            return false;
        }
        BigInteger expectedR = e.add(x1y1.getAffineXCoord().toBigInteger()).mod(n);
        return expectedR.equals(r);
    }

    private static BigInteger[] decode(byte[] sig) {
        ASN1Sequence s = ASN1Sequence.getInstance(sig);
        return new BigInteger[]{ASN1Integer.getInstance(s.getObjectAt(0)).getValue(),
                ASN1Integer.getInstance(s.getObjectAt(1)).getValue()};
    }

    /**
     * Z = SM3(ENTL || ID || a || b || x_G || y_G || x_A || y_A)
     * ENTL 是签名者 ID 的位长度，占两个字节
     * ID是签名者ID 国密标准里定义的缺省签名者ID用UFT_8字符串表示是“1234567812345678”
     * a, b, x_G, y_G 都是SM2算法标准中给定的值
     * a和b是椭圆曲线y=x+ax+b的系数
     * x_G, y_G是SM2算法选定的基点的坐标
     * x_A || y_A就是公钥两部分值的拼接，注意，没有0x04的部分
     * @param userId
     * @param userKey
     * @return
     */
    public static byte[] generateZ(byte[] userId, ECPoint userKey) {
        SM3Digest sm3 = new SM3Digest();

        int len = userId.length * 8;
        sm3.update((byte)(len >> 8 & 255));
        sm3.update((byte)(len & 255));
        sm3.update(userId, 0, userId.length);

        byte[] a = SM2_ECC_A.toByteArray();
        sm3.update(a, 1, 32);
        byte[] b = SM2_ECC_B.toByteArray();
        sm3.update(b, 0, 32);
        byte[] gx = SM2_ECC_GX.toByteArray();
        sm3.update(gx, 0, 32);
        byte[] gy = SM2_ECC_GY.toByteArray();
        sm3.update(gy, 1, 32);

        byte[] xa = userKey.normalize().getXCoord().toBigInteger().toByteArray();
        sm3.update(xa, xa.length == 33 ? 1 : 0, 32);
        byte[] ya = userKey.normalize().getYCoord().toBigInteger().toByteArray();
        sm3.update(ya, ya.length == 33 ? 1 : 0, 32);

        byte[] md = new byte[sm3.getDigestSize()];
        sm3.doFinal(md, 0);
        return md;
    }

    /**
     * E=SM3(Z || M)
     * Z是第一步运算得到的摘要
     * M是签名的原文
     * 将两者拼接，再进行SM3摘要运算
     * @param z
     * @param m
     * @return
     */
    public static byte[] generateE(byte[] z, byte[] m) {
        SM3Digest sm3 = new SM3Digest();
        sm3.update(z, 0, z.length);
        sm3.update(m, 0, m.length);
        byte[] md = new byte[sm3.getDigestSize()];
        sm3.doFinal(md, 0);
        return md;
    }

    /**
     * 压缩公钥
     * @param pubBytes
     * @return
     * @throws Exception
     */
    public static byte[] compress(byte[] pubBytes) throws Exception{
        PublicKey publicKey = bytesToPubKey(pubBytes);
        return compress(publicKey);
    }

    /**
     * 压缩公钥
     * 0x02: y为偶数
     * 0x03：y为奇数
     * @param publicKey
     * @return
     */
    public static byte[] compress(PublicKey publicKey){
        ECPoint ecPoint = ((BCECPublicKey)publicKey).getQ();
        return ecPoint.getEncoded(true);
    }

    /**
     * 解压缩公钥
     * @param pubBytes 33字节,且已0x02或0x03开头
     * @return
     */
    public static byte[] decompress(byte[] pubBytes){
        ECPoint publicKeyPoint = curve.decodePoint(pubBytes);
        byte[] x = publicKeyPoint.getXCoord().toBigInteger().toByteArray();
        byte[] y = publicKeyPoint.getYCoord().toBigInteger().toByteArray();
        byte[] data = new byte[64];
        System.arraycopy(x, x.length - 32, data, 0, 32);
        System.arraycopy(y, y.length - 32, data, 32, 32);
        return data;
    }

    /**
     * ans1格式的签名转成rs结构
     * @param ans1
     * @return
     */
    public static byte[] ans1ToRs(byte[] ans1){
        BigInteger[] rs = decode(ans1);
        String r = Hex.toHexString(rs[0].toByteArray());
        String s = Hex.toHexString(rs[1].toByteArray());
        return Hex.decode(r.substring(r.length() - CURVE_LEN * 2) + s.substring(s.length() - CURVE_LEN * 2));
    }

    /**
     * rs结构的签名数据转成ans1结构
     * @param rs
     * @return
     * @throws IOException
     */
    public static byte[] rsToAns1(byte[] rs) throws IOException {
        byte[] r = new byte[32], s = new byte[32];
        System.arraycopy(rs, 0, r, 0, 32);
        System.arraycopy(rs, 32, s, 0, 32);
        ASN1EncodableVector v2 = new ASN1EncodableVector();
        v2.add(new ASN1Integer(new BigInteger(1, r)));
        v2.add(new ASN1Integer(new BigInteger(1, s)));
        DERSequence sign = new DERSequence(v2);
        return sign.getEncoded("DER");
    }

}
