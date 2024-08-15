package alg.bc.nation;

import alg.bc.ProviderRegist;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * ECDSA是一种基于椭圆曲线数学问题的数字签名算法。
 * 它利用了离散对数难题的复杂度来确保安全性，并且提供了比传统RSA算法更短的密钥长度和更高的性能
 */
public class ECDSA extends ProviderRegist {

    private static final String ECDSA = "ECDSA";

    //ECC 推荐参数 secp256k1/secp256r1
    private static final String CURVE_NAME = "secp256k1";

    private static final String SIGN_ALG_NAME = "SHA256withECDSA";

    /**
     * 生成公私钥对
     * @return
     * @throws Exception
     */
    public static KeyPair generateKeyPair() throws Exception{
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ECDSA, BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(new ECGenParameterSpec(CURVE_NAME), new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * 消息签名
     * @param privateKey    私钥
     * @param msg           待签名的消息
     * @return
     * @throws Exception
     */
    public static byte[] sign(PrivateKey privateKey, byte[] msg) throws Exception{
        Signature signature = Signature.getInstance(SIGN_ALG_NAME, BouncyCastleProvider.PROVIDER_NAME);
        signature.initSign(privateKey);
        signature.update(msg);
        return signature.sign();
    }

    /**
     * 签名验证
     * @param publicKey     公钥
     * @param msg           待签名的消息
     * @param signature     签名值
     * @return
     * @throws Exception
     */
    public static boolean verify(PublicKey publicKey, byte[] msg, byte[] signature) throws Exception{
        Signature verifySignature = Signature.getInstance(SIGN_ALG_NAME, BouncyCastleProvider.PROVIDER_NAME);
        verifySignature.initVerify(publicKey);
        verifySignature.update(msg);
        return verifySignature.verify(signature);
    }

    /**
     * 公钥对象转字节数组
     * @param publicKey
     * @return
     */
    public static byte[] pubKeyToBytes(PublicKey publicKey){
        return publicKey.getEncoded();
    }

    /**
     * 字节数组转公钥对象
     * @param buffer
     * @return
     * @throws Exception
     */
    public static PublicKey bytesToPubKey(byte[] buffer) throws Exception{
        X509EncodedKeySpec ecpks = new X509EncodedKeySpec(buffer);
        KeyFactory kf = KeyFactory.getInstance(ECDSA, BouncyCastleProvider.PROVIDER_NAME);
        return kf.generatePublic(ecpks);
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
        KeyFactory keyFactory = KeyFactory.getInstance(ECDSA, BouncyCastleProvider.PROVIDER_NAME);
        return keyFactory.generatePrivate(spec);
    }
}
