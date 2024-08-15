package alg.bc.nation;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.io.ByteArrayInputStream;

public class SM3Test {

    @Test
    public void testHash() throws Exception{
        byte[] in = Hex.decode("00112233445566778899aabbccddeeff");
        System.out.println(Hex.toHexString(SM3.hash(in)));

        System.out.println(Hex.toHexString(SM3.hash(in, "123456".getBytes())));

        System.out.println(Hex.toHexString(SM3.hash(new ByteArrayInputStream(in))));

    }

    @Test
    public void testHash2() throws Exception{
        byte[] in = Hex.decode("00112233445566778899aabbccddeeff");
        System.out.println(Hex.toHexString(SM3.hash2(in)));
    }

    @Test
    public void testMac() throws Exception{
        byte[] key = Hex.decode("00112233445566778899aabbccddeeff");
        byte[] in = Hex.decode("00112233445566778899aabbccddeeff");
        System.out.println(Hex.toHexString(SM3.hmac(key, in)));
    }
}
