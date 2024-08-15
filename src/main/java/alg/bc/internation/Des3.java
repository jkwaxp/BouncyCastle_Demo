package alg.bc.internation;

import alg.bc.ProviderRegist;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;

public class Des3 extends ProviderRegist {

    private static final String DES3 = "DESEDE";

    private static final String ECB_PKCS7_PADDING = "DESEDE/ECB/PKCS7Padding";
    private static final String CBC_PKCS7_PADDING = "DESEDE/CBC/PKCS7Padding";

    /**
     * 生成3DES密钥
     * @param keySize   112/128/168/192
     * @return
     * @throws Exception
     */
    public static byte[] generateKey(int keySize) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance(DES3, BouncyCastleProvider.PROVIDER_NAME);
        kg.init(keySize, new SecureRandom());
        return kg.generateKey().getEncoded();
    }

    public static byte[] ecbEncPkcs7(byte[] key, byte[] input) throws Exception{
        Cipher cipher = Cipher.getInstance(ECB_PKCS7_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, DES3);
        cipher.init(Cipher.ENCRYPT_MODE, cipherKey, new SecureRandom());
        return cipher.doFinal(input);
    }

    public static byte[] ecbDecPkcs7(byte[] key, byte[] input) throws Exception{
        Cipher cipher = Cipher.getInstance(ECB_PKCS7_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, DES3);
        cipher.init(Cipher.DECRYPT_MODE, cipherKey);
        return cipher.doFinal(input);
    }

    public static byte[] cbcEncPkcs7(byte[] key, byte[] iv, byte[] input) throws Exception{
        Cipher cipher = Cipher.getInstance(CBC_PKCS7_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, DES3);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, cipherKey, ivParam);
        return cipher.doFinal(input);
    }

    public static byte[] cbcDecPkcs7(byte[] key, byte[] iv, byte[] input) throws Exception{
        Cipher cipher = Cipher.getInstance(CBC_PKCS7_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, DES3);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, cipherKey, ivParam);
        return cipher.doFinal(input);
    }
}
