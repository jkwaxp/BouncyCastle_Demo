package alg.bc.internation;


import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;
import util.FileUtil;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import static org.junit.Assert.assertArrayEquals;

public class AESTest {

    @Test
    public void testEcb() throws Exception{
        String key_128 = Hex.toHexString(AES.generateKey(128));
        System.out.println("key:" + key_128);
        byte[] in = Hex.decode("00112233445566778899aabbccddeeff");

        byte[] out = AES.ecbEncNoPadding(Hex.decode(key_128), in);
        System.out.println(Hex.toHexString(out));
        byte[] dec = AES.ecbDecNoPadding(Hex.decode(key_128), out);
        System.out.println(Hex.toHexString(dec));
        assertArrayEquals(in, dec);

        out = AES.ecbEncPkcs7(Hex.decode(key_128), in);
        System.out.println(Hex.toHexString(out));
        dec = AES.ecbDecPkcs7(Hex.decode(key_128), out);
        System.out.println(Hex.toHexString(dec));
        assertArrayEquals(in, dec);
    }

    @Test
    public void testCbc() throws Exception{
        String key_128 = Hex.toHexString(AES.generateKey(128));
        System.out.println("key:" + key_128);
        String iv = Hex.toHexString(AES.generateKey(128));
        System.out.println("iv:" + iv);
        byte[] in = Hex.decode("00112233445566778899aabbccddeeff");

        byte[] out = AES.cbcEncNoPadding(Hex.decode(key_128), Hex.decode(iv), in);
        System.out.println(Hex.toHexString(out));
        byte[] dec = AES.cbcDecNoPadding(Hex.decode(key_128), Hex.decode(iv), out);
        System.out.println(Hex.toHexString(dec));
        assertArrayEquals(in, dec);

        out = AES.cbcEncPkcs7(Hex.decode(key_128), Hex.decode(iv), in);
        System.out.println(Hex.toHexString(out));
        dec = AES.cbcDecPkcs7(Hex.decode(key_128), Hex.decode(iv), out);
        System.out.println(Hex.toHexString(dec));
        assertArrayEquals(in, dec);
    }

    @Test
    public void testDiyTransformation() throws Exception{
        String key_128 = Hex.toHexString(AES.generateKey(128));
        String iv = Hex.toHexString(AES.generateKey(128));
        byte[] in = Hex.decode("112233445566778899aabbccddeeff");
        byte[] out = AES.encrypt("AES/CTR/NOPADDING", Hex.decode(key_128), Hex.decode(iv), in);
        System.out.println(Hex.toHexString(out));
        byte[] dec = AES.decrypt("AES/CTR/NOPADDING", Hex.decode(key_128), Hex.decode(iv), out);
        System.out.println(Hex.toHexString(dec));
        assertArrayEquals(in, dec);
    }

    @Test
    public void testStream() throws Exception{
        String key_128 = Hex.toHexString(AES.generateKey(128));
        try(FileInputStream fis = new FileInputStream(new File(FileUtil.class.getClassLoader().getResource("test.txt").getFile()));
            FileOutputStream fos = new FileOutputStream(new File(FileUtil.class.getClassLoader().getResource("test2.txt").getFile()))){

            AES.ecbEncStream(Hex.decode(key_128), fis, fos);

            ByteArrayOutputStream os = new ByteArrayOutputStream();
            try(FileInputStream test2 = new FileInputStream(new File(FileUtil.class.getClassLoader().getResource("test2.txt").getFile()))) {
                AES.ecbDecStream(Hex.decode(key_128), test2, os);
                System.out.println(new String(os.toByteArray()));
            }
        }

        String iv = Hex.toHexString(AES.generateKey(128));
        try(FileInputStream fis = new FileInputStream(new File(FileUtil.class.getClassLoader().getResource("test.txt").getFile()));
            FileOutputStream fos = new FileOutputStream(new File(FileUtil.class.getClassLoader().getResource("test2.txt").getFile()))){

            AES.cbcEncStream(Hex.decode(key_128), Hex.decode(iv), fis, fos);

            ByteArrayOutputStream os = new ByteArrayOutputStream();
            try(FileInputStream test2 = new FileInputStream(new File(FileUtil.class.getClassLoader().getResource("test2.txt").getFile()))) {
                AES.cbcDecStream(Hex.decode(key_128), Hex.decode(iv), test2, os);
                System.out.println(new String(os.toByteArray()));
            }
        }
    }
}