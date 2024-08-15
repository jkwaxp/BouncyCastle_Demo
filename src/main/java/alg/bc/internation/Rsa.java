package alg.bc.internation;

import alg.bc.ProviderRegist;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Rsa extends ProviderRegist {

    private static final int DEFAULT_KEY_SIZE = 2048;

    /**
     * RSA
     * RSA/ECB/RAW
     * RSA/ECB/PKCS1Padding
     * RSA/ECB/NOPADDING
     * RSA/ECB/ISO9796-1PADDING
     * RSA/NONE/PKCS1Padding
     * RSA/NONE/NoPadding
     * RSA/NONE/OAEPPADDING
     * RSA/NONE/OAEPWithSHA1AndMGF1Padding
     * RSA/NONE/OAEPWithSHA224AndMGF1Padding
     * RSA/NONE/OAEPWithSHA256AndMGF1Padding
     * RSA/NONE/OAEPWithSHA384AndMGF1Padding
     * RSA/NONE/OAEPWithMD5AndMGF1Padding
     * RSA/NONE/ISO9796-1Padding
     */
    private static final String DEFAULT_MODE = "RSA/ECB/PKCS1Padding";

    public static KeyPair generateKeyPair() throws Exception{
        return generateKeyPair(DEFAULT_KEY_SIZE);
    }

    public static KeyPair generateKeyPair(int keySize) throws Exception{
        KeyPairGenerator pairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        pairGenerator.initialize(keySize);
        return pairGenerator.generateKeyPair();
    }

    public static int getKeyLength(PublicKey publicKey) {
        return ((java.security.interfaces.RSAPublicKey) publicKey).getModulus().bitLength();
    }

    public static int getKeyLength(PrivateKey privateKey) {
        return ((java.security.interfaces.RSAPrivateKey) privateKey).getModulus().bitLength();
    }

    public static PublicKey bytes2PubKey(byte[] data) throws Exception{
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(data);
        return keyFactory.generatePublic(publicKeySpec);
    }

    public static PrivateKey bytes2PrvKey(byte[] data) throws Exception{
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(data);
        return keyFactory.generatePrivate(privateKeySpec);
    }

    public static byte[] encrypt(PublicKey publicKey, byte[] data) throws Exception{
        Cipher cipher = Cipher.getInstance(DEFAULT_MODE, BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return doEncrypt(cipher, data, getKeyLength(publicKey));
    }

    public static byte[] encrypt(PrivateKey privateKey, byte[] data) throws Exception{
        Cipher cipher = Cipher.getInstance(DEFAULT_MODE, BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return doEncrypt(cipher, data, getKeyLength(privateKey));
    }

    private static byte[] doEncrypt(Cipher cipher, byte[] data, int keySize) throws Exception{
        return doFinal(cipher, data, keySize / 8 - 11);
    }

    public static byte[] decrypt(PrivateKey privateKey, byte[] data) throws Exception{
        Cipher cipher = Cipher.getInstance(DEFAULT_MODE, BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return doDecrypt(cipher, data, getKeyLength(privateKey));
    }

    public static byte[] decrypt(PublicKey publicKey, byte[] data) throws Exception{
        Cipher cipher = Cipher.getInstance(DEFAULT_MODE, BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return doDecrypt(cipher, data, getKeyLength(publicKey));
    }

    private static byte[] doDecrypt(Cipher cipher, byte[] data, int keySize) throws Exception{
        return doFinal(cipher, data, keySize / 8);
    }

    private static byte[] doFinal(Cipher cipher, byte[] data, int blockSize) throws Exception{
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int inputLen = data.length;
        int offSet = 0;
        for(int i = 0; inputLen - offSet > 0; offSet = i * blockSize) {
            byte[] cache;
            if (inputLen - offSet > blockSize) {
                cache = cipher.doFinal(data, offSet, blockSize);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            ++i;
        }
        out.close();
        return out.toByteArray();
    }

    public static byte[] sign(PrivateKey privateKey, byte[] msg) throws Exception{
        Signature signature = Signature.getInstance("SHA256withRSA", BouncyCastleProvider.PROVIDER_NAME);
        signature.initSign(privateKey);
        signature.update(msg);
        return signature.sign();
    }

    public static boolean verify(PublicKey publicKey, byte[] msg, byte[] signature) throws Exception{
        Signature verifySignature = Signature.getInstance("SHA256withRSA", BouncyCastleProvider.PROVIDER_NAME);
        verifySignature.initVerify(publicKey);
        verifySignature.update(msg);
        return verifySignature.verify(signature);
    }
}
