package alg.bc.nation;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;
import util.FileUtil;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import static org.junit.Assert.assertArrayEquals;

public class SM4Test {

    @Test
    public void testEcb() throws Exception{
        byte[] key = SM4.generateKey();
//        byte[] key = Hex.decode("3a3fff495744d9ec5bf1b4f0c58c36fd");
        System.out.println("key:" + Hex.toHexString(key));

        byte[] in = Hex.decode("00112233445566778899aabbccddeeff");

        byte[] out = SM4.ecbEncNoPadding(key, in);
        System.out.println("enc:" + Hex.toHexString(out));
        byte[] dec = SM4.ecbDecNoPadding(key, out);
        System.out.println("dec:" + Hex.toHexString(dec));
        assertArrayEquals(in, dec);

        out = SM4.ecbEncPkcs7(key, in);
        System.out.println("enc:" + Hex.toHexString(out));
        dec = SM4.ecbDecPkcs7(key, out);
        System.out.println("dec:" + Hex.toHexString(dec));
        assertArrayEquals(in, dec);
    }

    @Test
    public void testCbc() throws Exception{
        byte[] key = SM4.generateKey();
//        byte[] key = Hex.decode("3a3fff495744d9ec5bf1b4f0c58c36fd");
        System.out.println("key:" + Hex.toHexString(key));
        byte[] iv = SM4.generateKey();
        System.out.println("iv:" + Hex.toHexString(iv));

        byte[] in = Hex.decode("00112233445566778899aabbccddeeff");

        byte[] out = SM4.cbcEncNoPadding(key, iv, in);
        System.out.println("enc:" + Hex.toHexString(out));
        byte[] dec = SM4.cbcDecNoPadding(key, iv, out);
        System.out.println("dec:" + Hex.toHexString(dec));
        assertArrayEquals(in, dec);

        out = SM4.cbcEncPkcs7(key, iv, in);
        System.out.println("enc:" + Hex.toHexString(out));
        dec = SM4.cbcDecPkcs7(key, iv, out);
        System.out.println("dec:" + Hex.toHexString(dec));
        assertArrayEquals(in, dec);
    }

    @Test
    public void testCfb() throws Exception{
        byte[] key = SM4.generateKey();
        System.out.println("key:" + Hex.toHexString(key));
        byte[] iv = SM4.generateKey();
        System.out.println("iv:" + Hex.toHexString(iv));

        byte[] in = Hex.decode("00112233445566778899aabbccddeeffaabbccdd");

        byte[] out = SM4.cfbEncNoPadding(key, iv, in);
        System.out.println("enc:" + Hex.toHexString(out));
        byte[] dec = SM4.cfbDecNoPadding(key, iv, out);
        System.out.println("dec:" + Hex.toHexString(dec));
        assertArrayEquals(in, dec);

        out = SM4.cfbEncPkcs7(key, iv, in);
        System.out.println("enc:" + Hex.toHexString(out));
        dec = SM4.cfbDecPkcs7(key, iv, out);
        System.out.println("dec:" + Hex.toHexString(dec));
        assertArrayEquals(in, dec);
    }

    @Test
    public void testOfb() throws Exception{
        byte[] key = SM4.generateKey();
        System.out.println("key:" + Hex.toHexString(key));
        byte[] iv = SM4.generateKey();
        System.out.println("iv:" + Hex.toHexString(iv));

        byte[] in = Hex.decode("00112233445566778899aabbccddeeffaabbccdd");

        byte[] out = SM4.ofbEncNoPadding(key, iv, in);
        System.out.println("enc:" + Hex.toHexString(out));
        byte[] dec = SM4.ofbDecNoPadding(key, iv, out);
        System.out.println("dec:" + Hex.toHexString(dec));
        assertArrayEquals(in, dec);

        out = SM4.ofbEncPkcs7(key, iv, in);
        System.out.println("enc:" + Hex.toHexString(out));
        dec = SM4.ofbDecPkcs7(key, iv, out);
        System.out.println("dec:" + Hex.toHexString(dec));
        assertArrayEquals(in, dec);
    }

    @Test
    public void testGCm() throws Exception{
        byte[] key = SM4.generateKey();
        System.out.println("key:" + Hex.toHexString(key));
        byte[] iv = SM4.generateKey();
        System.out.println("iv:" + Hex.toHexString(iv));

        byte[] in = Hex.decode("00112233445566778899aabbccddeeffaabbccdd");
        byte[] out = SM4.gcmEnc(key, iv, in);
        System.out.println("enc:" + Hex.toHexString(out));

        byte[] dec = SM4.gcmDec(key, iv, out);
        System.out.println("dec:" + Hex.toHexString(dec));
        assertArrayEquals(in, dec);
    }

    @Test
    public void testDiyTransformation() throws Exception{
        String key = Hex.toHexString(SM4.generateKey());
        byte[] in = Hex.decode("00112233445566778899aabbccddeeff");

        byte[] out = SM4.encrypt("SM4/ECB/NOPADDING", Hex.decode(key), null, in);
        System.out.println(Hex.toHexString(out));
        byte[] dec = SM4.decrypt("SM4/ECB/NOPADDING", Hex.decode(key), null, out);
        System.out.println(Hex.toHexString(dec));
        assertArrayEquals(in, dec);
    }

    @Test
    public void testCmac() throws Exception{
        byte[] key = SM4.generateKey();
        System.out.println("key:" + Hex.toHexString(key));

        byte[] in = Hex.decode("00112233445566778899aabbccddeeffaabbccdd");
        byte[] out = SM4.cmac(key, in);
        System.out.println("cmac:" + Hex.toHexString(out));
    }

    @Test
    public void testStream() throws Exception{
        byte[] key = SM4.generateKey();
        System.out.println("key:" + Hex.toHexString(key));
        byte[] iv = SM4.generateKey();
        System.out.println("iv:" + Hex.toHexString(iv));

        try(FileInputStream fis = new FileInputStream(new File(FileUtil.class.getClassLoader().getResource("test.txt").getFile()));
            FileOutputStream fos = new FileOutputStream(new File(FileUtil.class.getClassLoader().getResource("test2.txt").getFile()))){

            SM4.ecbEncStream(key, fis, fos);

            ByteArrayOutputStream os = new ByteArrayOutputStream();
            SM4.ecbDecStream(key, new FileInputStream(new File(FileUtil.class.getClassLoader().getResource("test2.txt").getFile())), os);
            System.out.println(new String(os.toByteArray()));
        }

        try(FileInputStream fis = new FileInputStream(new File(FileUtil.class.getClassLoader().getResource("test.txt").getFile()));
            FileOutputStream fos = new FileOutputStream(new File(FileUtil.class.getClassLoader().getResource("test2.txt").getFile()))){

            SM4.cbcEncStream(key, iv, fis, fos);

            ByteArrayOutputStream os = new ByteArrayOutputStream();
            SM4.cbcDecStream(key, iv, new FileInputStream(new File(FileUtil.class.getClassLoader().getResource("test2.txt").getFile())), os);
            System.out.println(new String(os.toByteArray()));
        }
    }
}
