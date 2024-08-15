package alg.bc.internation;

import alg.bc.ProviderRegist;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.FileInputStream;
import java.security.MessageDigest;

public class Digest extends ProviderRegist {

    private static final String MD5 = "MD5";
    private static final String SHA1 = "SHA-1";
    private static final String SHA256 = "SHA-256";
    private static final String SHA512 = "SHA-512";

    public static byte[] md5(byte[] msg) throws Exception{
        MessageDigest digest = MessageDigest.getInstance(MD5, BouncyCastleProvider.PROVIDER_NAME);
        return digest.digest(msg);
    }

    public static byte[] md5(byte[] msg, byte[] salt) throws Exception{
        MessageDigest digest = MessageDigest.getInstance(MD5, BouncyCastleProvider.PROVIDER_NAME);
        digest.update(msg);
        digest.update(salt);
        return digest.digest();
    }

    public static byte[] md5(String filePath) throws Exception{
        MessageDigest digest = MessageDigest.getInstance(MD5, BouncyCastleProvider.PROVIDER_NAME);
        byte[] buf = new byte[1024];
        int i = -1;
        try(FileInputStream is = new FileInputStream(new File(filePath))){
            while((i = is.read(buf)) > 0){
                digest.update(buf, 0, i);
            }
        }
        return digest.digest();
    }

    public static byte[] sha1(byte[] msg) throws Exception{
        MessageDigest digest = MessageDigest.getInstance(SHA1, BouncyCastleProvider.PROVIDER_NAME);
        return digest.digest(msg);
    }

    public static byte[] sha1(byte[] msg, byte[] salt) throws Exception{
        MessageDigest digest = MessageDigest.getInstance(SHA1, BouncyCastleProvider.PROVIDER_NAME);
        digest.update(msg);
        digest.update(salt);
        return digest.digest();
    }

    public static byte[] sha256(byte[] msg) throws Exception{
        MessageDigest digest = MessageDigest.getInstance(SHA256, BouncyCastleProvider.PROVIDER_NAME);
        return digest.digest(msg);
    }

    public static byte[] sha256(byte[] msg, byte[] salt) throws Exception{
        MessageDigest digest = MessageDigest.getInstance(SHA256, BouncyCastleProvider.PROVIDER_NAME);
        digest.update(msg);
        digest.update(salt);
        return digest.digest();
    }

    public static byte[] sha512(byte[] msg) throws Exception{
        MessageDigest digest = MessageDigest.getInstance(SHA512, BouncyCastleProvider.PROVIDER_NAME);
        return digest.digest(msg);
    }

    public static byte[] sha512(byte[] msg, byte[] salt) throws Exception{
        MessageDigest digest = MessageDigest.getInstance(SHA512, BouncyCastleProvider.PROVIDER_NAME);
        digest.update(msg);
        digest.update(salt);
        return digest.digest();
    }

    /**
     * 指定算法的摘要
     * @param alg   BC库支持的哈希算法
     * @param msg
     * @return
     * @throws Exception
     */
    public static byte[] doDigest(String alg, byte[] msg) throws Exception{
        MessageDigest digest = MessageDigest.getInstance(alg, BouncyCastleProvider.PROVIDER_NAME);
        return digest.digest(msg);
    }
}
