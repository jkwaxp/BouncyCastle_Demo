package alg.bc.internation;

import org.junit.Test;
import util.FileUtil;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

import static org.junit.Assert.assertNotNull;

public class CertTest {

    @Test
    public void testPublicKeyPem() throws Exception{
        KeyPair keyPair = Rsa.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();

        String publicPem = Cert.pubKey2Pem(publicKey);
        System.out.println("public key in pem: " + publicPem);

        PublicKey pub = Cert.pem2PubKey(FileUtil.readResource("rsa.pub.pem"));
        System.out.println(pub.getAlgorithm());
        assertNotNull(pub);
    }

    @Test
    public void testPrivateKeyPem() throws Exception {
        KeyPair keyPair = Rsa.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();

        String privatePem = Cert.prvKey2Pem(privateKey, "123456");
        System.out.println("private key in pem: " + privatePem);
        privatePem = Cert.prvKey2Pem(privateKey, null);
        System.out.println("private key in pem: " + privatePem);

        PrivateKey prv = Cert.pem2PrvKey(FileUtil.readResource("rsa.prv.pem"), "123456");
        System.out.println(prv.getAlgorithm());
        assertNotNull(prv);
    }

    @Test
    public void testCert() throws Exception{
        Certificate cert = Cert.pem2Cert(FileUtil.readResource("rsa.cert.pem"));
        System.out.println(cert);

        System.out.println(Cert.cert2Pem(cert));
    }
}
