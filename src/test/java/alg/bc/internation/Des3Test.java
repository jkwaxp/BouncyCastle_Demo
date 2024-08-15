package alg.bc.internation;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

public class Des3Test {

    @Test
    public void testGenerateKey() throws Exception{
        byte[] key = Des3.generateKey(128);
        assertTrue(16 == key.length);
    }

    @Test
    public void testEncrypt() throws Exception{
        byte[] key = Des3.generateKey(128);
        System.out.println("key: " + Hex.toHexString(key));
        byte[] in = Hex.decode("00112233445566778899aabbccddeeff");

        byte[] out = Des3.ecbEncPkcs7(key, in);
        System.out.println(Hex.toHexString(out));
        byte[] dec = Des3.ecbDecPkcs7(key, out);
        System.out.println(Hex.toHexString(dec));
        assertArrayEquals(in, dec);

        byte[] iv = Hex.decode("8899aabbccddeeff");
        out = Des3.cbcEncPkcs7(key, iv, in);
        System.out.println(Hex.toHexString(out));
        dec = Des3.cbcDecPkcs7(key, iv, out);
        System.out.println(Hex.toHexString(dec));
        assertArrayEquals(in, dec);
    }
}
