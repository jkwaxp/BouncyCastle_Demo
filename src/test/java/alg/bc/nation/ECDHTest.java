package alg.bc.nation;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.security.KeyPair;

import static org.junit.Assert.assertArrayEquals;

public class ECDHTest {

    @Test
    public void testGenerateKeyPair() throws Exception{
        KeyPair keyPair = ECDH.generateKeyPair();
        byte[] pub = ECDH.pubKeyToBytes(keyPair.getPublic());
        byte[] prv = ECDH.prvKeyToBytes(keyPair.getPrivate());

        System.out.println("pub key:" + Hex.toHexString(pub));
        System.out.println("prv key:" + Hex.toHexString(prv));

        System.out.println(ECDH.bytesToPubKey(pub).getAlgorithm());
        System.out.println(ECDH.bytesToPrvKey(prv).getAlgorithm());
    }

    @Test
    public void testGenerateSessionKey() throws Exception{
        KeyPair client = ECDH.generateKeyPair();
        byte[] clientPub = ECDH.pubKeyToBytes(client.getPublic());
        byte[] clientPrv = ECDH.prvKeyToBytes(client.getPrivate());

        KeyPair server = ECDH.generateKeyPair();
        byte[] serverPub = ECDH.pubKeyToBytes(server.getPublic());
        byte[] serverPrv = ECDH.prvKeyToBytes(server.getPrivate());

        byte[] serverKey1 = ECDH.generateSessionKey(client.getPublic(), server.getPrivate());
        System.out.println("serverKey1:" + Hex.toHexString(serverKey1));
        byte[] clientKey1 = ECDH.generateSessionKey(server.getPublic(), client.getPrivate());
        System.out.println("clientKey1:" + Hex.toHexString(clientKey1));
        assertArrayEquals(serverKey1, clientKey1);

        byte[] serverKey2 = ECDH.generateSessionKey(ECDH.bytesToPubKey(clientPub), ECDH.bytesToPrvKey(serverPrv));
        System.out.println("serverKey2:" + Hex.toHexString(serverKey2));
        byte[] clientKey2 = ECDH.generateSessionKey(ECDH.bytesToPubKey(serverPub), ECDH.bytesToPrvKey(clientPrv));
        System.out.println("clientKey2:" + Hex.toHexString(clientKey2));
        assertArrayEquals(serverKey2, clientKey2);
    }
}
