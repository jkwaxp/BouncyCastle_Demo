package alg.bc.internation;


import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.macs.CMacWithIV;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;


public class MAC {

    public static byte[] md5HMac(byte[] msg, byte[] key) throws Exception{
        HMac hmac = new HMac(new MD5Digest());
        return doMac(hmac, msg, new KeyParameter(key));
    }

    public static byte[] sha256HMac(byte[] msg, byte[] key) throws Exception{
        HMac hmac = new HMac(new SHA256Digest());
        return doMac(hmac, msg, new KeyParameter(key));
    }

    public static byte[] aesCMac(byte[] msg, byte[] key) throws Exception{
        BlockCipher cipher = new AESEngine();
        Mac mac = new CMac(cipher);
        return doMac(mac, msg, new KeyParameter(key));
    }

    public static byte[] aesCMac(byte[] msg, byte[] key, byte[] iv) throws Exception{
        BlockCipher cipher = new AESEngine();
        Mac mac = new CMacWithIV(cipher);
        return doMac(mac, msg, new ParametersWithIV(new KeyParameter(key), iv));
    }

    public static byte[] desCMac(byte[] msg, byte[] key) throws Exception{
        BlockCipher cipher = new DESEngine();
        Mac mac = new CMac(cipher);
        return doMac(mac, msg, new KeyParameter(key));
    }

    private static byte[] doMac(Mac hmac, byte[] msg, CipherParameters key) throws Exception{
        byte[] buf = new byte[hmac.getMacSize()];
        hmac.init(key);
        hmac.update(msg, 0, msg.length);
        hmac.doFinal(buf, 0);
        return buf;
    }
}
