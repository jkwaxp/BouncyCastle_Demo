package alg.bc.nation;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.security.KeyPair;

import static org.junit.Assert.assertTrue;

public class ECDSATest {

    @Test
    public void testGenerateKeyPair() throws Exception{
        KeyPair keyPair = ECDSA.generateKeyPair();
        byte[] pub = ECDSA.pubKeyToBytes(keyPair.getPublic());
        byte[] prv = ECDSA.prvKeyToBytes(keyPair.getPrivate());

        System.out.println("pub key:" + Hex.toHexString(pub));
        System.out.println("prv key:" + Hex.toHexString(prv));

        System.out.println(ECDSA.bytesToPubKey(pub).getAlgorithm());
        System.out.println(ECDSA.bytesToPrvKey(prv).getAlgorithm());
    }

    @Test
    public void testSign() throws Exception{
        KeyPair keyPair = ECDSA.generateKeyPair();
        byte[] msg = Hex.decode("00112233445566778899aabbccddeeff");

        byte[] signature = ECDSA.sign(keyPair.getPrivate(), msg);
        boolean result = ECDSA.verify(keyPair.getPublic(), msg, signature);
        System.out.println("result:" + result);
        assertTrue(result);
    }

    @Test
    public void testSign2() throws Exception{
        KeyPair keyPair = ECDSA.generateKeyPair();
        byte[] pub = ECDSA.pubKeyToBytes(keyPair.getPublic());
        byte[] prv = ECDSA.prvKeyToBytes(keyPair.getPrivate());
        byte[] msg = Hex.decode("00112233445566778899aabbccddeeff");

        byte[] signature = ECDSA.sign(ECDSA.bytesToPrvKey(prv), msg);
        boolean result = ECDSA.verify(ECDSA.bytesToPubKey(pub), msg, signature);
        System.out.println("result:" + result);
        assertTrue(result);
    }
}
