package alg.bc.internation;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Random;

import static org.junit.Assert.*;

public class RsaTest {

    @Test
    public void testGenerateKeyPair() throws Exception{
        KeyPair keyPair = Rsa.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        System.out.println("publicKey: " + Hex.toHexString(publicKey.getEncoded()));
        System.out.println("privateKey: " + Hex.toHexString(privateKey.getEncoded()));
    }

    @Test
    public void testSerial() throws Exception{
        KeyPair keyPair = Rsa.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        byte[] pubData = publicKey.getEncoded();
        byte[] prvData = privateKey.getEncoded();
        System.out.println("publicKey: " + Hex.toHexString(pubData));
        System.out.println("privateKey: " + Hex.toHexString(prvData));

        PublicKey deSerialPubKey = Rsa.bytes2PubKey(pubData);
        PrivateKey deSerialPrvKey = Rsa.bytes2PrvKey(prvData);
        System.out.println(deSerialPubKey.getAlgorithm());
        System.out.println(deSerialPrvKey.getAlgorithm());
    }

    @Test
    public void testKeySize() throws Exception{
        assertEquals(1024, Rsa.getKeyLength(Rsa.generateKeyPair(1024).getPublic()));
        assertEquals(2048, Rsa.getKeyLength(Rsa.generateKeyPair(2048).getPublic()));
        assertEquals(4096, Rsa.getKeyLength(Rsa.generateKeyPair(4096).getPublic()));
    }

    @Test
    public void testKeySize2() throws Exception{
        assertEquals(1024, Rsa.getKeyLength(Rsa.generateKeyPair(1024).getPrivate()));
        assertEquals(2048, Rsa.getKeyLength(Rsa.generateKeyPair(2048).getPrivate()));
        assertEquals(4096, Rsa.getKeyLength(Rsa.generateKeyPair(4096).getPrivate()));
    }

    @Test
    public void testEncrypt1() throws Exception{
        KeyPair keyPair = Rsa.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        byte[] in = Hex.decode("00112233445566778899aabbccddeeff");

        byte[] out = Rsa.encrypt(publicKey, in);
        System.out.println("encrypt:" + Hex.toHexString(out));
        byte[] dec = Rsa.decrypt(privateKey, out);
        System.out.println("decrypt:" + Hex.toHexString(dec));
        assertArrayEquals(in, dec);
    }

    @Test
    public void testEncrypt2() throws Exception{
        KeyPair keyPair = Rsa.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        byte[] in = Hex.decode("00112233445566778899aabbccddeeff");

        byte[] out = Rsa.encrypt(privateKey, in);
        System.out.println("encrypt:" + Hex.toHexString(out));
        byte[] dec = Rsa.decrypt(publicKey, out);
        System.out.println("decrypt:" + Hex.toHexString(dec));
        assertArrayEquals(in, dec);
    }

    @Test
    public void testEncrypt3() throws Exception{
        KeyPair keyPair = Rsa.generateKeyPair(1024);
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        byte[] in = new byte[4096];
        new Random().nextBytes(in);

        byte[] out = Rsa.encrypt(publicKey, in);
        System.out.println("encrypt:" + Hex.toHexString(out));
        byte[] dec = Rsa.decrypt(privateKey, out);
        System.out.println("decrypt:" + Hex.toHexString(dec));
        assertArrayEquals(in, dec);
    }

    @Test
    public void testSign() throws Exception{
        KeyPair keyPair = Rsa.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        byte[] in = Hex.decode("00112233445566778899aabbccddeeff");

        byte[] sig = Rsa.sign(privateKey, in);
        System.out.println("sig:" + Hex.toHexString(sig));
        boolean ret = Rsa.verify(publicKey, in, sig);
        System.out.println(ret);
        assertTrue(ret);
    }

    @Test
    public void testSign2() throws Exception{
        KeyPair keyPair = Rsa.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        byte[] in = new byte[4096];
        new Random().nextBytes(in);

        byte[] sig = Rsa.sign(privateKey, in);
        System.out.println("sig:" + Hex.toHexString(sig));
        boolean ret = Rsa.verify(publicKey, in, sig);
        System.out.println(ret);
        assertTrue(ret);
    }
}
