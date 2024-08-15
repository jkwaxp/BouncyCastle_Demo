package alg.bc.nation;

import alg.bc.ProviderRegist;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * SM4加密
 * 支持模式：ECB/CBC/CFB/OFB/CTR/CCM/GCM
 */
public class SM4 extends ProviderRegist {

    private static final int KEY_SIZE = 128;

    private static final String SM4 = "SM4";

    private static final String ECB_NO_PADDING = "SM4/ECB/NoPadding";
    private static final String ECB_PKCS7_PADDING = "SM4/ECB/PKCS7Padding";

    private static final String CBC_NO_PADDING = "SM4/CBC/NoPadding";
    private static final String CBC_PKCS7_PADDING = "SM4/CBC/PKCS7Padding";

    private static final String CFB_NO_PADDING = "SM4/CFB/NoPadding";
    private static final String CFB_PKCS7_PADDING = "SM4/CFB/PKCS7Padding";

    private static final String OFB_NO_PADDING = "SM4/OFB/NoPadding";
    private static final String OFB_PKCS7_PADDING = "SM4/OFB/PKCS7Padding";

    private static final String GCM_NO_PADDING = "SM4/GCM/NoPadding";

    /**
     * 生成密钥--16字节
     * @return
     * @throws Exception
     */
    public static byte[] generateKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance(SM4, BouncyCastleProvider.PROVIDER_NAME);
        kg.init(KEY_SIZE, new SecureRandom());
        return kg.generateKey().getEncoded();
    }

    public static byte[] ecbEncNoPadding(byte[] key, byte[] input) throws Exception{
        Cipher cipher = Cipher.getInstance(ECB_NO_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, SM4);
        cipher.init(Cipher.ENCRYPT_MODE, cipherKey);
        return cipher.doFinal(input);
    }

    public static byte[] ecbEncPkcs7(byte[] key, byte[] input) throws Exception{
        Cipher cipher = Cipher.getInstance(ECB_PKCS7_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, SM4);
        cipher.init(Cipher.ENCRYPT_MODE, cipherKey);
        return cipher.doFinal(input);
    }

    public static byte[] ecbDecNoPadding(byte[] key, byte[] input) throws Exception{
        Cipher cipher = Cipher.getInstance(ECB_NO_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, SM4);
        cipher.init(Cipher.DECRYPT_MODE, cipherKey);
        return cipher.doFinal(input);
    }

    public static byte[] ecbDecPkcs7(byte[] key, byte[] input) throws Exception{
        Cipher cipher = Cipher.getInstance(ECB_PKCS7_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, SM4);
        cipher.init(Cipher.DECRYPT_MODE, cipherKey);
        return cipher.doFinal(input);
    }

    public static byte[] cbcEncNoPadding(byte[] key, byte[] iv, byte[] input) throws Exception{
        Cipher cipher = Cipher.getInstance(CBC_NO_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, SM4);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, cipherKey, ivParam);
        return cipher.doFinal(input);
    }

    public static byte[] cbcEncPkcs7(byte[] key, byte[] iv, byte[] input) throws Exception{
        Cipher cipher = Cipher.getInstance(CBC_PKCS7_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, SM4);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, cipherKey, ivParam);
        return cipher.doFinal(input);
    }

    public static byte[] cbcDecNoPadding(byte[] key, byte[] iv, byte[] input) throws Exception{
        Cipher cipher = Cipher.getInstance(CBC_NO_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, SM4);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, cipherKey, ivParam);
        return cipher.doFinal(input);
    }

    public static byte[] cbcDecPkcs7(byte[] key, byte[] iv, byte[] input) throws Exception{
        Cipher cipher = Cipher.getInstance(CBC_PKCS7_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, SM4);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, cipherKey, ivParam);
        return cipher.doFinal(input);
    }

    public static byte[] cfbEncNoPadding(byte[] key, byte[] iv, byte[] input) throws Exception{
        Cipher cipher = Cipher.getInstance(CFB_NO_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, SM4);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, cipherKey, ivParam);
        return cipher.doFinal(input);
    }

    public static byte[] cfbEncPkcs7(byte[] key, byte[] iv, byte[] input) throws Exception{
        Cipher cipher = Cipher.getInstance(CFB_PKCS7_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, SM4);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, cipherKey, ivParam);
        return cipher.doFinal(input);
    }

    public static byte[] cfbDecNoPadding(byte[] key, byte[] iv, byte[] input) throws Exception{
        Cipher cipher = Cipher.getInstance(CFB_NO_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, SM4);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, cipherKey, ivParam);
        return cipher.doFinal(input);
    }

    public static byte[] cfbDecPkcs7(byte[] key, byte[] iv, byte[] input) throws Exception{
        Cipher cipher = Cipher.getInstance(CFB_PKCS7_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, SM4);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, cipherKey, ivParam);
        return cipher.doFinal(input);
    }

    public static byte[] ofbEncNoPadding(byte[] key, byte[] iv, byte[] input) throws Exception{
        Cipher cipher = Cipher.getInstance(OFB_NO_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, SM4);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, cipherKey, ivParam);
        return cipher.doFinal(input);
    }

    public static byte[] ofbEncPkcs7(byte[] key, byte[] iv, byte[] input) throws Exception{
        Cipher cipher = Cipher.getInstance(OFB_PKCS7_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, SM4);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, cipherKey, ivParam);
        return cipher.doFinal(input);
    }

    public static byte[] ofbDecNoPadding(byte[] key, byte[] iv, byte[] input) throws Exception{
        Cipher cipher = Cipher.getInstance(OFB_NO_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, SM4);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, cipherKey, ivParam);
        return cipher.doFinal(input);
    }

    public static byte[] ofbDecPkcs7(byte[] key, byte[] iv, byte[] input) throws Exception{
        Cipher cipher = Cipher.getInstance(OFB_PKCS7_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, SM4);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, cipherKey, ivParam);
        return cipher.doFinal(input);
    }

    /**
     * gcm 仅支持NoPadding
     * @param key 密钥
     * @param iv 初始向量
     * @param input 待加密数据
     * @return
     * @throws Exception
     */
    public static byte[] gcmEnc(byte[] key, byte[] iv, byte[] input) throws Exception{
        //Only NoPadding can be used with AEAD modes
        Cipher cipher = Cipher.getInstance(GCM_NO_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, SM4);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, cipherKey, ivParam);
        return cipher.doFinal(input);
    }

    /**
     * gcm 仅支持NoPadding
     * @param key 密钥
     * @param iv 初始向量
     * @param input 待解密数据
     * @return
     * @throws Exception
     */
    public static byte[] gcmDec(byte[] key, byte[] iv, byte[] input) throws Exception{
        //Only NoPadding can be used with AEAD modes
        Cipher cipher = Cipher.getInstance(GCM_NO_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, SM4);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, cipherKey, ivParam);
        return cipher.doFinal(input);
    }

    /**
     * 可指定加密模式进行SM4加密
     * @param transformation    示例：SM4/CBC/PKCS7PADDING
     * @param key
     * @param iv                根据所选模式，无需iv时传null
     * @param input
     * @return
     * @throws Exception
     */
    public static byte[] encrypt(String transformation, byte[] key, byte[] iv, byte[] input) throws Exception{
        Cipher cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, SM4);
        if(iv != null){
            IvParameterSpec ivParam = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, cipherKey, ivParam);
        }else{
            cipher.init(Cipher.ENCRYPT_MODE, cipherKey);
        }
        return cipher.doFinal(input);
    }

    /**
     * 可指定加密模式进行SM4解密
     * @param transformation    示例：SM4/CBC/PKCS7PADDING
     * @param key
     * @param iv                根据所选模式，无需iv时传null
     * @param input
     * @return
     * @throws Exception
     */
    public static byte[] decrypt(String transformation, byte[] key, byte[] iv, byte[] input) throws Exception{
        Cipher cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, SM4);
        if(iv != null){
            IvParameterSpec ivParam = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, cipherKey, ivParam);
        }else{
            cipher.init(Cipher.DECRYPT_MODE, cipherKey);
        }
        return cipher.doFinal(input);
    }

    public static byte[] cmac(byte[] key, byte[] input) throws Exception{
        Mac mac = Mac.getInstance("SM4-CMAC", BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, SM4);
        mac.init(cipherKey);
        return mac.doFinal(input);
    }

    public static void ecbEncStream(byte[] key, InputStream is, OutputStream os) throws Exception{
        Cipher cipher = Cipher.getInstance(ECB_PKCS7_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, SM4);
        cipher.init(Cipher.ENCRYPT_MODE, cipherKey);
        cipherStream(is, os, cipher);
    }

    public static void ecbDecStream(byte[] key, InputStream is, OutputStream os) throws Exception{
        Cipher cipher = Cipher.getInstance(ECB_PKCS7_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, SM4);
        cipher.init(Cipher.DECRYPT_MODE, cipherKey);
        cipherStream(is, os, cipher);
    }

    public static void cbcEncStream(byte[] key, byte[] iv, InputStream is, OutputStream os) throws Exception{
        Cipher cipher = Cipher.getInstance(CBC_PKCS7_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, SM4);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, cipherKey, ivParam);
        cipherStream(is, os, cipher);
    }

    public static void cbcDecStream(byte[] key, byte[] iv, InputStream is, OutputStream os) throws Exception{
        Cipher cipher = Cipher.getInstance(CBC_PKCS7_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key cipherKey = new SecretKeySpec(key, SM4);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, cipherKey, ivParam);
        cipherStream(is, os, cipher);
    }

    private static void cipherStream(InputStream is, OutputStream os, Cipher cipher) throws IOException, IllegalBlockSizeException, BadPaddingException {
        byte[] buf = new byte[512];
        int i;
        while((i = is.read(buf)) >= 0) {
            byte[] out = cipher.update(buf, 0, i);
            os.write(out);
        }
        os.write(cipher.doFinal());
    }

    public static byte[] zeroIv(String algName) throws Exception{
        Cipher cipher = Cipher.getInstance(algName, BouncyCastleProvider.PROVIDER_NAME);
        int blockSize = cipher.getBlockSize();
        byte[] iv = new byte[blockSize];
        Arrays.fill(iv, (byte)0);
        return iv;
    }
}
