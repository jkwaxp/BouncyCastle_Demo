package alg.bc.nation;

import alg.bc.ProviderRegist;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;

/**
 * 祖冲之算法
 */
public class Zuc extends ProviderRegist {

    private static final int KEY_128 = 128;
    private static final int KEY_256 = 256;

    private static final String ZUC_128 = "Zuc-128";
    private static final String ZUC_256 = "Zuc-256";

    /**
     * 生成密钥
     * @param length 128/256
     * @return
     * @throws Exception
     */
    public static byte[] generateKey(int length) throws Exception{
        if(length != KEY_128 && length != KEY_256){
            throw new IllegalArgumentException("illegal key length");
        }
        KeyGenerator kg = KeyGenerator.getInstance(length == KEY_128 ? ZUC_128 : ZUC_256, BouncyCastleProvider.PROVIDER_NAME);
        kg.init(length, new SecureRandom());
        return kg.generateKey().getEncoded();
    }

    /**
     * 加解密使用同一个函数
     * @param key 16字节
     * @param iv  16字节
     * @param input
     * @return
     * @throws Exception
     */
    public static byte[] cipher128(byte[] key, byte[] iv, byte[] input) throws Exception{
        Cipher zuc = Cipher.getInstance(ZUC_128, BouncyCastleProvider.PROVIDER_NAME);
        Key k = new SecretKeySpec(key, ZUC_128);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        zuc.init(1, k, ivParam);
        return zuc.doFinal(input);
    }

    /**
     * 加解密使用同一个函数
     * @param key 32字节
     * @param iv 25字节
     * @param input
     * @return
     * @throws Exception
     */
    public static byte[] cipher256(byte[] key, byte[] iv, byte[] input) throws Exception{
        Cipher zuc = Cipher.getInstance(ZUC_256, BouncyCastleProvider.PROVIDER_NAME);
        Key k = new SecretKeySpec(key, ZUC_256);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        zuc.init(1, k, ivParam);
        return zuc.doFinal(input);
    }

    /**
     * 计算MAC值
     * @param key 16字节
     * @param iv  16字节
     * @param input
     * @return
     * @throws Exception
     */
    public static byte[] mac128(byte[] key, byte[] iv, byte[] input) throws Exception{
        Mac mac128 = Mac.getInstance(ZUC_128, BouncyCastleProvider.PROVIDER_NAME);
        mac128.reset();
        byte[] myOutput = new byte[mac128.getMacLength()];
        Key k = new SecretKeySpec(key, ZUC_128);
        mac128.init(k, new IvParameterSpec(iv));
        mac128.update(input, 0, input.length);
        mac128.doFinal(myOutput, 0);
        return myOutput;
    }

    /**
     * 计算MAC值
     * @param key 32字节
     * @param iv  25字节
     * @param input
     * @return
     * @throws Exception
     */
    public static byte[] mac256(byte[] key, byte[] iv, byte[] input) throws Exception{
        Mac mac128 = Mac.getInstance(ZUC_256, BouncyCastleProvider.PROVIDER_NAME);
        mac128.reset();
        byte[] myOutput = new byte[mac128.getMacLength()];
        Key k = new SecretKeySpec(key, ZUC_256);
        mac128.init(k, new IvParameterSpec(iv));
        mac128.update(input, 0, input.length);
        mac128.doFinal(myOutput, 0);
        return myOutput;
    }
}
