package alg.bc.internation;

import alg.bc.ProviderRegist;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

/**
 * AES加密
 */
public class AES extends ProviderRegist {

    private static final String AES = "AES";

    private static final String ECB_NO_PADDING = "AES/ECB/NoPadding";
    private static final String ECB_PKCS7_PADDING = "AES/ECB/PKCS7Padding";

    private static final String CBC_NO_PADDING = "AES/CBC/NoPadding";
    private static final String CBC_PKCS7_PADDING = "AES/CBC/PKCS7Padding";

    /**
     * 生成一个密钥
     * @param keySize 128/192/256
     * @return
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static byte[] generateKey(int keySize) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance(AES, BouncyCastleProvider.PROVIDER_NAME);
        kg.init(keySize, new SecureRandom());
        return kg.generateKey().getEncoded();
    }

    public static byte[] ecbEncNoPadding(byte[] key, byte[] input) throws Exception{
        Cipher cipher = Cipher.getInstance(ECB_NO_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, AES);
        cipher.init(Cipher.ENCRYPT_MODE, cipherKey);
        return cipher.doFinal(input);
    }

    public static byte[] ecbDecNoPadding(byte[] key, byte[] input) throws Exception{
        Cipher cipher = Cipher.getInstance(ECB_NO_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, AES);
        cipher.init(Cipher.DECRYPT_MODE, cipherKey);
        return cipher.doFinal(input);
    }

    public static byte[] ecbEncPkcs7(byte[] key, byte[] input) throws Exception{
        Cipher cipher = Cipher.getInstance(ECB_PKCS7_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, AES);
        cipher.init(Cipher.ENCRYPT_MODE, cipherKey);
        return cipher.doFinal(input);
    }

    public static byte[] ecbDecPkcs7(byte[] key, byte[] input) throws Exception{
        Cipher cipher = Cipher.getInstance(ECB_PKCS7_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, AES);
        cipher.init(Cipher.DECRYPT_MODE, cipherKey);
        return cipher.doFinal(input);
    }

    public static byte[] cbcEncNoPadding(byte[] key, byte[] iv, byte[] input) throws Exception{
        Cipher cipher = Cipher.getInstance(CBC_NO_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, AES);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, cipherKey, ivParam);
        return cipher.doFinal(input);
    }

    public static byte[] cbcEncPkcs7(byte[] key, byte[] iv, byte[] input) throws Exception{
        Cipher cipher = Cipher.getInstance(CBC_PKCS7_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, AES);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, cipherKey, ivParam);
        return cipher.doFinal(input);
    }

    public static byte[] cbcDecNoPadding(byte[] key, byte[] iv, byte[] input) throws Exception{
        Cipher cipher = Cipher.getInstance(CBC_NO_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, AES);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, cipherKey, ivParam);
        return cipher.doFinal(input);
    }

    public static byte[] cbcDecPkcs7(byte[] key, byte[] iv, byte[] input) throws Exception{
        Cipher cipher = Cipher.getInstance(CBC_PKCS7_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, AES);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, cipherKey, ivParam);
        return cipher.doFinal(input);
    }

    public static byte[] encrypt(String transformation, byte[] key, byte[] iv, byte[] input) throws Exception{
        Cipher cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, AES);
        if(iv != null){
            IvParameterSpec ivParam = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, cipherKey, ivParam);
        }else{
            cipher.init(Cipher.ENCRYPT_MODE, cipherKey);
        }
        return cipher.doFinal(input);
    }

    public static byte[] decrypt(String transformation, byte[] key, byte[] iv, byte[] input) throws Exception{
        Cipher cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, AES);
        if(iv != null){
            IvParameterSpec ivParam = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, cipherKey, ivParam);
        }else{
            cipher.init(Cipher.DECRYPT_MODE, cipherKey);
        }
        return cipher.doFinal(input);
    }

    public static void ecbEncStream(byte[] key, InputStream is, OutputStream os) throws Exception{
        Cipher cipher = Cipher.getInstance(ECB_PKCS7_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, AES);
        cipher.init(Cipher.ENCRYPT_MODE, cipherKey);
        cipherStream(is, os, cipher);
    }

    public static void ecbDecStream(byte[] key, InputStream is, OutputStream os) throws Exception{
        Cipher cipher = Cipher.getInstance(ECB_PKCS7_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, AES);
        cipher.init(Cipher.DECRYPT_MODE, cipherKey);
        cipherStream(is, os, cipher);
    }

    public static void cbcEncStream(byte[] key, byte[] iv, InputStream is, OutputStream os) throws Exception{
        Cipher cipher = Cipher.getInstance(CBC_PKCS7_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, AES);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, cipherKey, ivParam);
        cipherStream(is, os, cipher);
    }

    public static void cbcDecStream(byte[] key, byte[] iv, InputStream is, OutputStream os) throws Exception{
        Cipher cipher = Cipher.getInstance(CBC_PKCS7_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, AES);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, cipherKey, ivParam);
        cipherStream(is, os, cipher);
    }

    private static void cipherStream(InputStream is, OutputStream os, Cipher cipher) throws IOException, IllegalBlockSizeException, BadPaddingException {
        byte[] tmp = new byte[512];
        int i;
        while((i = is.read(tmp)) >= 0) {
            byte[] out = cipher.update(tmp, 0, i);
            os.write(out);
        }
        os.write(cipher.doFinal());
    }
}
