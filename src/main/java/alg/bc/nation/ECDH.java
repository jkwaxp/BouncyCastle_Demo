package alg.bc.nation;

import alg.bc.ProviderRegist;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * ECDH 密钥协商算法是 ECC 算法和 DH 密钥交换原理结合使用，用于密钥磋商
 * 交换双方可以在不共享任何秘密的情况下协商出一个密钥
 */
public class ECDH extends ProviderRegist {

    private static final String ECDH = "ECDH";

    //ECC 推荐参数 secp256k1/secp256r1
    private static final String CURVE_NAME = "secp256k1";

    /**
     * 生成公私钥对
     * @return
     * @throws Exception
     */
    public static KeyPair generateKeyPair() throws Exception{
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ECDH, BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(new ECGenParameterSpec(CURVE_NAME), new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * 派生密钥
     * @param publicKey     Alice的公钥
     * @param privateKey    Bob的私钥
     * @return
     * @throws Exception
     */
    public static byte[] generateSessionKey(PublicKey publicKey, PrivateKey privateKey) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance(ECDH, BouncyCastleProvider.PROVIDER_NAME);
        ka.init(privateKey);
        ka.doPhase(publicKey, true);
        return ka.generateSecret();
    }

    /**
     * 公钥对象转字节数组(未压缩)
     * @param publicKey
     * @return
     */
    public static byte[] pubKeyToBytes(PublicKey publicKey){
        ECPublicKey eckey = (ECPublicKey)publicKey;
        return eckey.getQ().getEncoded(false);
    }

    /**
     * 字节数组转公钥对象
     * @param buffer
     * @return
     * @throws Exception
     */
    public static PublicKey bytesToPubKey(byte[] buffer) throws Exception{
        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec(CURVE_NAME);
        ECPublicKeySpec pubKey = new ECPublicKeySpec(params.getCurve().decodePoint(buffer), params);
        KeyFactory kf = KeyFactory.getInstance(ECDH, BouncyCastleProvider.PROVIDER_NAME);
        return kf.generatePublic(pubKey);
    }

    /**
     * 私钥对象转字节数组
     * @param privateKey
     * @return
     */
    public static byte[] prvKeyToBytes(PrivateKey privateKey){
        return privateKey.getEncoded();
    }

    /**
     * 字节数组转私钥对象
     * @param buffer
     * @return
     * @throws Exception
     */
    public static PrivateKey bytesToPrvKey(byte[] buffer) throws Exception{
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(buffer);
        KeyFactory keyFactory = KeyFactory.getInstance(ECDH, BouncyCastleProvider.PROVIDER_NAME);
        return keyFactory.generatePrivate(spec);
    }

}
