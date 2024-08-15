package alg.bc.internation;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class MACTest {

    @Test
    public void testMd5HMac() throws Exception{
        byte[] in = Hex.decode("00112233445566778899aabbccddeeff");
        byte[] key = "123456".getBytes();

        String exp = "8a78bb06a21449d55aac3bbb2b67d848";
        byte[] mac = MAC.md5HMac(in, key);
        System.out.println("mac: " + Hex.toHexString(mac));
        assertEquals(exp, Hex.toHexString(mac));
    }

    @Test
    public void testSha256HMac() throws Exception{
        byte[] in = Hex.decode("00112233445566778899aabbccddeeff");
        byte[] key = "123456".getBytes();

        String exp = "659eecc469be2ed876992f478a9d939c1f0b281f68d6445e9352b154eae58e14";
        byte[] mac = MAC.sha256HMac(in, key);
        System.out.println("mac: " + Hex.toHexString(mac));
        assertEquals(exp, Hex.toHexString(mac));
    }

    @Test
    public void testAesCMac() throws Exception{
        byte[] in = Hex.decode("00112233445566778899aabbccddeeff");
        byte[] key = AES.generateKey(128);
        byte[] mac = MAC.aesCMac(in, key);
        System.out.println("mac: " + Hex.toHexString(mac));

        byte[] iv = AES.generateKey(128);
        mac = MAC.aesCMac(in, key, iv);
        System.out.println("mac: " + Hex.toHexString(mac));
    }

    @Test
    public void testDesCMac() throws Exception{
        byte[] in = Hex.decode("00112233445566778899aabbccddeeff");
        byte[] key = Hex.decode("8899aabbccddeeff");
        byte[] mac = MAC.desCMac(in, key);
        System.out.println("mac: " + Hex.toHexString(mac));

    }
}
