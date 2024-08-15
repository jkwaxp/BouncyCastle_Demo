package alg.bc.nation;

import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

public class SM2Test {

    @Test
    public void testGenerateKey() throws Exception{
        KeyPair keyPair = SM2.generateKeyPair();
        byte[] pub = SM2.pubKeyToBytes(keyPair.getPublic());
        byte[] prv = SM2.prvKeyToBytes(keyPair.getPrivate());
        System.out.println("pub key:" + Hex.toHexString(pub));
        System.out.println("prv key:" + Hex.toHexString(prv));

        System.out.println(SM2.bytesToPubKey(pub).getAlgorithm());
        System.out.println(SM2.bytesToPrvKey(prv).getAlgorithm());
    }

    @Test
    public void testEncrypt() throws Exception{
        KeyPair keyPair = SM2.generateKeyPair();
        byte[] pub = SM2.pubKeyToBytes(keyPair.getPublic());
        byte[] prv = SM2.prvKeyToBytes(keyPair.getPrivate());
        System.out.println("pub key:" + Hex.toHexString(pub));
        System.out.println("prv key:" + Hex.toHexString(prv));

        byte[] in = Hex.decode("00112233445566778899aabbccddeeff");

        byte[] out = SM2.encrypt(keyPair.getPublic(), in);
        System.out.println("encrypt:" + Hex.toHexString(out));
        byte[] dec = SM2.decrypt(keyPair.getPrivate(), out);
        System.out.println("decrypt:" + Hex.toHexString(dec));
        assertArrayEquals(in, dec);

        out = SM2.encrypt(pub, in);
        System.out.println("encrypt:" + Hex.toHexString(out));
        dec = SM2.decrypt(prv, out);
        System.out.println("decrypt:" + Hex.toHexString(dec));
        assertArrayEquals(in, dec);

        out = SM2.encrypt(SM2.compress(pub), in);
        System.out.println("encrypt:" + Hex.toHexString(out));
        dec = SM2.decrypt(prv, out);
        System.out.println("decrypt:" + Hex.toHexString(dec));
        assertArrayEquals(in, dec);
    }

    @Test
    public void testEncryptC123() throws Exception{
        KeyPair keyPair = SM2.generateKeyPair();
        byte[] pub = SM2.pubKeyToBytes(keyPair.getPublic());
        byte[] prv = SM2.prvKeyToBytes(keyPair.getPrivate());
        System.out.println("pub key:" + Hex.toHexString(pub));
        System.out.println("prv key:" + Hex.toHexString(prv));

        byte[] in = Hex.decode("00112233445566778899aabbccddeeff");

        byte[] out = SM2.encrypt(keyPair.getPublic(), in, SM2Engine.Mode.C1C2C3);
        System.out.println("encrypt:" + Hex.toHexString(out));
        byte[] dec = SM2.decrypt(keyPair.getPrivate(), out, SM2Engine.Mode.C1C2C3);
        System.out.println("decrypt:" + Hex.toHexString(dec));
        assertArrayEquals(in, dec);

        out = SM2.encrypt(pub, in, SM2Engine.Mode.C1C2C3);
        System.out.println("encrypt:" + Hex.toHexString(out));
        dec = SM2.decrypt(prv, out, SM2Engine.Mode.C1C2C3);
        System.out.println("decrypt:" + Hex.toHexString(dec));
        assertArrayEquals(in, dec);
    }

    @Test
    public void testSign() throws Exception{
        KeyPair keyPair = SM2.generateKeyPair();
        byte[] pub = SM2.pubKeyToBytes(keyPair.getPublic());
        byte[] prv = SM2.prvKeyToBytes(keyPair.getPrivate());
        System.out.println("pub key:" + Hex.toHexString(pub));
        System.out.println("prv key:" + Hex.toHexString(prv));

        byte[] in = Hex.decode("00112233445566778899aabbccddeeff");

        byte[] sig = SM2.sign(keyPair.getPrivate(), in);
        System.out.println("sig:" + Hex.toHexString(sig));
        assertTrue(64 == sig.length);
        boolean ret = SM2.verify(keyPair.getPublic(), in, sig);
        System.out.println(ret);
        assertTrue(ret);

        sig = SM2.sign(keyPair.getPrivate(), in, "test".getBytes());
        System.out.println("sig:" + Hex.toHexString(sig));
        assertTrue(64 == sig.length);
        ret = SM2.verify(keyPair.getPublic(), in, sig, "test".getBytes());
        System.out.println(ret);
        assertTrue(ret);

        sig = SM2.sign(prv, in);
        assertTrue(64 == sig.length);
        System.out.println("sig:" + Hex.toHexString(sig));
        ret = SM2.verify(pub, in, sig);
        System.out.println(ret);
        assertTrue(ret);

        byte[] ans1 = SM2.rsToAns1(sig);
        System.out.println("ans1:" + Hex.toHexString(ans1));
        ret = SM2.verifyAsn1(keyPair.getPublic(), in, ans1);
        System.out.println(ret);
        assertTrue(ret);

        sig = SM2.sign(prv, in, "test".getBytes());
        assertTrue(64 == sig.length);
        System.out.println("sig:" + Hex.toHexString(sig));
        ret = SM2.verify(pub, in, sig, "test".getBytes());
        System.out.println(ret);
        assertTrue(ret);
    }

    @Test
    public void testSignStd() throws Exception{
        KeyPair keyPair = SM2.generateKeyPair();
        byte[] pub = SM2.pubKeyToBytes(keyPair.getPublic());
        byte[] prv = SM2.prvKeyToBytes(keyPair.getPrivate());

        System.out.println("pub key:" + Hex.toHexString(pub));
        System.out.println("prv key:" + Hex.toHexString(prv));

        byte[] in = Hex.decode("00112233445566778899aabbccddeeff");

        byte[] sig = SM2.signStd(keyPair.getPrivate(), in);
        System.out.println("sig:" + Hex.toHexString(sig));
        boolean ret = SM2.verifyStd(keyPair.getPublic(), in, sig);
        System.out.println(ret);
        assertTrue(ret);
        ret = SM2.verify(keyPair.getPublic(), in, sig);
        System.out.println(ret);
        assertTrue(ret);

        sig = SM2.signStd(prv, in);
        System.out.println("sig:" + Hex.toHexString(sig));
        ret = SM2.verifyStd(pub, in, sig);
        System.out.println(ret);
        assertTrue(ret);
        ret = SM2.verify(pub, in, sig);
        System.out.println(ret);
        assertTrue(ret);
    }

    @Test
    public void testSignAsn1() throws Exception{
        KeyPair keyPair = SM2.generateKeyPair();
        byte[] pub = SM2.pubKeyToBytes(keyPair.getPublic());
        byte[] prv = SM2.prvKeyToBytes(keyPair.getPrivate());

        System.out.println("pub key:" + Hex.toHexString(pub));
        System.out.println("prv key:" + Hex.toHexString(prv));

        byte[] in = Hex.decode("00112233445566778899aabbccddeeff");

        byte[] sig = SM2.signAsn1(keyPair.getPrivate(), in);
        assertTrue(64 < sig.length);
        System.out.println("sig:" + Hex.toHexString(sig));
        boolean ret = SM2.verifyAsn1(keyPair.getPublic(), in, sig);
        System.out.println(ret);
        assertTrue(ret);

        byte[] rs = SM2.ans1ToRs(sig);
        System.out.println("rs:" + Hex.toHexString(rs));
        ret = SM2.verify(keyPair.getPublic(), in, rs);
        System.out.println(ret);
        assertTrue(ret);
    }

    @Test
    public void testSignStd2() throws Exception{
        byte[] pub = Hex.decode("25f3ea46b4f7c75b2a36097b373d47185763cd092d529f8b5670f4610ea1f2274241ba9ba602e1abd1d9c2d1fce2e2416516b322adc16e9188a988c3975cc163");
        byte[] prv = Hex.decode("d0c37f3f112b9469d43f883c98f9d56ecfdf12aefc387a09ce6dffc99b7f03f1");

        byte[] in = Hex.decode("00112233445566778899aabbccddeeff");

        byte[] sig = SM2.signStd(prv, in);
        System.out.println("sig:" + Hex.toHexString(sig));
        boolean ret = SM2.verifyStd(pub, in, sig);
        System.out.println(ret);
        assertTrue(ret);
    }

    @Test
    public void testSignRaw() throws Exception{
        byte[] pub = Hex.decode("04c11fec19d4304c3e4484b84cde6b5541a099cdeb4351fd4212c517df14e17eaa5c7a6552f679f825f162a43a2a49f093ff7ca41450d153ce8f1b5c5ade26a938");
        byte[] prv = Hex.decode("217971bae5a4eaced6643a0ed5ad9e0be0671170739bc488e4c219354a1f7a15");
        PrivateKey privateKey = SM2.bytesToPrvKey(prv);
        PublicKey publicKey = SM2.bytesToPubKey(pub);

        byte[] in = Hex.decode("00112233445566778899aabbccddeeff");
        byte[] msg = SM3.hash(in);
        System.out.println("msg:" + Hex.toHexString(msg));
        byte[] sig = SM2.signRaw(privateKey, msg);
        System.out.println("sig:" + Hex.toHexString(sig));
        boolean ret = SM2.verifyRaw(publicKey, msg, sig);
        System.out.println(ret);
        assertTrue(ret);
    }

    @Test
    public void testCompress() throws Exception{
        KeyPair keyPair = SM2.generateKeyPair();
        byte[] pub = SM2.pubKeyToBytes(keyPair.getPublic());
        byte[] prv = SM2.prvKeyToBytes(keyPair.getPrivate());
        System.out.println("pub key:" + Hex.toHexString(pub));
        System.out.println("prv key:" + Hex.toHexString(prv));

        byte[] compressedPubKey = SM2.compress(keyPair.getPublic());
        System.out.println("compressedPubKey:" + Hex.toHexString(compressedPubKey));
        byte[] decompressedPubKey = SM2.decompress(compressedPubKey);
        System.out.println("decompressedPubKey:" + Hex.toHexString(decompressedPubKey));
        assertArrayEquals(pub, decompressedPubKey);
    }
}
