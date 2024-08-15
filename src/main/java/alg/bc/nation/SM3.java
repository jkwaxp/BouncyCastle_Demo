package alg.bc.nation;


import alg.bc.ProviderRegist;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.security.MessageDigest;

public class SM3 extends ProviderRegist {

    /**
     * 计算SM3哈希值
     * @param message
     * @return
     * @throws Exception
     */
    public static byte[] hash(byte[] message)throws Exception{
        MessageDigest digest = MessageDigest.getInstance("SM3", BouncyCastleProvider.PROVIDER_NAME);
        return digest.digest(message);
    }

    /**
     * 计算加盐的SM3哈希值
     * @param message
     * @return
     * @throws Exception
     */
    public static byte[] hash(byte[] message, byte[] salt)throws Exception{
        MessageDigest digest = MessageDigest.getInstance("SM3", BouncyCastleProvider.PROVIDER_NAME);
        digest.update(message);
        digest.update(salt);
        return digest.digest();
    }

    /**
     * 计算文件(流)的哈希值
     * @param is
     * @return
     * @throws Exception
     */
    public static byte[] hash(InputStream is)throws Exception{
        MessageDigest digest = MessageDigest.getInstance("SM3", BouncyCastleProvider.PROVIDER_NAME);
        byte[] buf = new byte[512];
        int i;
        while((i = is.read(buf)) >= 0) {
            digest.update(buf, 0, i);
        }
        return digest.digest();
    }

    /**
     * 计算SM3哈希值
     * @param message
     * @return
     * @throws Exception
     */
    public static byte[] hash2(byte[] message)throws Exception{
        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(message, 0, message.length);
        byte[] out = new byte[sm3Digest.getDigestSize()];
        sm3Digest.doFinal(out, 0);
        return out;
    }

    /**
     * 计算SM3的MAC值
     * @param key
     * @param message
     * @return
     * @throws Exception
     */
    public static byte[] hmac(byte[] key, byte[] message) throws Exception{
        Mac mac = Mac.getInstance("Hmac/SM3", BouncyCastleProvider.PROVIDER_NAME);
        mac.init(new SecretKeySpec(key, "sm3"));
        mac.reset();
        mac.update(message, 0, message.length);
        return mac.doFinal();
    }

}
