package alg.bc.internation;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class DigestTest {

    @Test
    public void testMd5() throws Exception{
        byte[] in = Hex.decode("00112233445566778899aabbccddeeff");
        byte[] salt = "123456".getBytes();

        byte[] md5 = Digest.md5("0003-06C3-BFEB-FBFF-7FFA-FBFF".getBytes());
        System.out.println("md5: " + Hex.toHexString(md5));

        md5 = Digest.md5(in, salt);
        System.out.println("md5+salt: " + Hex.toHexString(md5));

        String fileMd5 = "e1f0dc001bd1a092e409d57f124421a6";
        md5 = Digest.md5("src/test/resources/1.png");
        System.out.println("md5(file): " + Hex.toHexString(md5));
        assertEquals(fileMd5, Hex.toHexString(md5));
    }

    @Test
    public void testSha1() throws Exception{
        byte[] in = Hex.decode("00112233445566778899aabbccddeeff");
        byte[] salt = "123456".getBytes();

        byte[] md5 = Digest.sha1(in);
        System.out.println("sha1: " + Hex.toHexString(md5));

        md5 = Digest.sha1(in, salt);
        System.out.println("sha1+salt: " + Hex.toHexString(md5));
    }

    @Test
    public void testSha256() throws Exception{
        byte[] in = Hex.decode("00112233445566778899aabbccddeeff");
        byte[] salt = "123456".getBytes();

        byte[] md5 = Digest.sha256(in);
        System.out.println("sha256: " + Hex.toHexString(md5));

        md5 = Digest.sha256(in, salt);
        System.out.println("sha256+salt: " + Hex.toHexString(md5));
    }

    @Test
    public void testSha512() throws Exception{
        byte[] in = Hex.decode("00112233445566778899aabbccddeeff");
        byte[] salt = "123456".getBytes();

        byte[] md5 = Digest.sha512(in);
        System.out.println("sha512: " + Hex.toHexString(md5));

        md5 = Digest.sha512(in, salt);
        System.out.println("sha512+salt: " + Hex.toHexString(md5));
    }

    @Test
    public void testDigest() throws Exception{
        byte[] in = Hex.decode("00112233445566778899aabbccddeeff");

        byte[] digest = Digest.doDigest("Tiger", in);
        System.out.println("digest: " + Hex.toHexString(digest));
    }
}
