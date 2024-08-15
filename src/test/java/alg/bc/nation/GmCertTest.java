package alg.bc.nation;

import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Test;
import util.FileUtil;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertNotNull;

public class GmCertTest {

    @Test
    public void testGenerateCertRequest() throws Exception{
        KeyPair keyPair = SM2.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        PKCS10CertificationRequest cr = GmCert.generateCsr(publicKey, privateKey, "Alice");
        assertNotNull(cr);
        String crStr = GmCert.getPemFmtStr(cr);
        System.out.println("cr in pem: " + crStr);
    }

    @Test
    public void testPublicKeyPem() throws Exception{
        KeyPair keyPair = SM2.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();

        String publicPem = GmCert.getPemFmtStr(publicKey);
        System.out.println("public key in pem: " + publicPem);

        PublicKey pub = GmCert.pubKeyInPem2Obj(FileUtil.readResource("sm2pub.pem"));
        System.out.println(pub.getAlgorithm());
        assertNotNull(pub);
    }

    @Test
    public void testPrivateKeyPem() throws Exception{
        KeyPair keyPair = SM2.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();

        String privatePem = GmCert.getPemFmtStr(privateKey, "123456");
        System.out.println("private key in pem: " + privatePem);
        privatePem = GmCert.getPemFmtStr(privateKey, null);
        System.out.println("private key in pem: " + privatePem);

        PrivateKey prv = GmCert.decryptPrivateKey(FileUtil.readResource("sm2prv.pem"), "123456");
        System.out.println(prv.getAlgorithm());
        assertNotNull(prv);
    }

    @Test
    public void testGenerateCert() throws Exception{
        KeyPair keyPair = SM2.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        PKCS10CertificationRequest cr = GmCert.generateCsr(publicKey, privateKey, "Alice");

        KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyAgreement
                | KeyUsage.dataEncipherment | KeyUsage.keyEncipherment);
        KeyPurposeId[] keyPurposeIds = new KeyPurposeId[] {KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth};

        X509Certificate cert = GmCert.generateCert(GmCert.CertLevel.EndEntity, GmCert.getPemFmtStr(cr), keyUsage, keyPurposeIds);
        System.out.println(cert.getEncoded());
    }

    @Test
    public void testGetAlgName() throws Exception{
        System.out.println(GmCert.getAlgName("1.2.840.113549.1.1.11"));
    }

    @Test
    public void testX5092P12() throws Exception{
        PrivateKey privateKey = GmCert.decryptPrivateKey(FileUtil.readResource("xxx.private"), "123456");
        KeyStore ks = GmCert.x5092keyStore("src/test/resources/xxx.crt", "xxx", privateKey, "123456");
        System.out.println(ks);

        GmCert.x5092P12File("src/test/resources/xxx.crt", "xxx", privateKey, "123456", "src/test/resources/xxx.pfx");
    }

    @Test
    public void testP122X509() throws Exception{
        Certificate cert = GmCert.keyStore2x509("src/test/resources/xxx.keystore", "123456", "xxx");
        System.out.println(cert);
    }
}
