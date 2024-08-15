package alg.bc.nation;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

public class ZucTest {

    @Test
    public void testCipher128() throws Exception{
        byte[] key = Zuc.generateKey(128);
        System.out.println("key:" + Hex.toHexString(key));
        byte[] iv = Zuc.generateKey(128);
        System.out.println("iv:" + Hex.toHexString(iv));

        byte[] in = Hex.decode("00112233445566778899aabbccddeeff");

        byte[] out = Zuc.cipher128(key, iv, in);
        System.out.println("enc:" + Hex.toHexString(out));
        System.out.println("dec:" + Hex.toHexString(Zuc.cipher128(key, iv, out)));
    }

    @Test
    public void testCipher256() throws Exception{
        byte[] key = Zuc.generateKey(256);
        System.out.println("key:" + Hex.toHexString(key));
        byte[] iv = new byte[25];
        System.out.println("iv:" + Hex.toHexString(iv));

        byte[] in = Hex.decode("00112233445566778899aabbccddeeff");

        byte[] out = Zuc.cipher256(key, iv, in);
        System.out.println("enc:" + Hex.toHexString(out));
        System.out.println("dec:" + Hex.toHexString(Zuc.cipher256(key, iv, out)));
    }

    @Test
    public void testMac128() throws Exception{
        byte[] key = Zuc.generateKey(128);
        System.out.println("key:" + Hex.toHexString(key));
        byte[] iv = new byte[16];
        byte[] in = Hex.decode("00112233445566778899aabbccddeeff");

        System.out.println(Hex.toHexString(Zuc.mac128(key, iv, in)));
    }

    @Test
    public void testMac256() throws Exception{
        byte[] key = Zuc.generateKey(256);
        System.out.println("key:" + Hex.toHexString(key));
        byte[] iv = new byte[25];
        byte[] in = Hex.decode("00112233445566778899aabbccddeeff");

        System.out.println(Hex.toHexString(Zuc.mac256(key, iv, in)));
    }
}
