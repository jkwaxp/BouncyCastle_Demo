package alg.bc.internation;

import alg.bc.ProviderRegist;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.bc.BcPEMDecryptorProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Cert extends ProviderRegist {

    private static final String PUBLIC_KEY = "PUBLIC KEY";
    private static final String PRIVATE_KEY = "PRIVATE KEY";
    private static final String CERTIFICATE = "CERTIFICATE";

    public static String pubKey2Pem(PublicKey publicKey) throws Exception{
        PemObject pem = new PemObject(PUBLIC_KEY, publicKey.getEncoded());
        StringWriter str = new StringWriter();
        try(PemWriter pemWriter = new PemWriter(str)){
            pemWriter.writeObject(pem);
        }
        return str.toString();
    }

    public static PublicKey pem2PubKey(String pemStr) throws Exception{
        String[] lines = pemStr.split("\n");
        StringBuilder sb = new StringBuilder();
        for(String line : lines){
            if(line.startsWith("--")){
                continue;
            }
            sb.append(line);
        }
        String str = sb.toString();
        str = str.replaceAll("\r", "");
        byte[] buffer = Base64.getDecoder().decode(str);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        return keyFactory.generatePublic(keySpec);
    }

    public static String prvKey2Pem(PrivateKey privateKey, String pin) throws Exception{
        PemObject pem;
        if(pin == null) {
            pem = new PemObject(PRIVATE_KEY, privateKey.getEncoded());
        }else{
            JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.PBE_SHA1_RC2_128);
            encryptorBuilder.setRandom(new SecureRandom());
            encryptorBuilder.setPassword(pin.toCharArray());
            OutputEncryptor encryptor = encryptorBuilder.build();
            JcaPKCS8Generator pkcsGenerator = new JcaPKCS8Generator(privateKey, encryptor);
            pem = pkcsGenerator.generate();
        }
        StringWriter str = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(str)) {
            pemWriter.writeObject(pem);
        }
        return str.toString();
    }

    public static PrivateKey pem2PrvKey(String privateKeyPemStr, String pin) throws Exception {
        PrivateKeyInfo pki;
        try (PEMParser pemParser = new PEMParser(new StringReader(privateKeyPemStr))) {
            Object o = pemParser.readObject();
            if (o instanceof PKCS8EncryptedPrivateKeyInfo) {
                PKCS8EncryptedPrivateKeyInfo epki = (PKCS8EncryptedPrivateKeyInfo) o;
                JcePKCSPBEInputDecryptorProviderBuilder builder =
                        new JcePKCSPBEInputDecryptorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME);
                InputDecryptorProvider idp = builder.build(pin.toCharArray());
                pki = epki.decryptPrivateKeyInfo(idp);
            } else if (o instanceof PEMEncryptedKeyPair) {
                PEMEncryptedKeyPair epki = (PEMEncryptedKeyPair) o;
                PEMKeyPair pkp = epki.decryptKeyPair(new BcPEMDecryptorProvider(pin.toCharArray()));
                pki = pkp.getPrivateKeyInfo();
            } else if (o instanceof PEMKeyPair){
                pki = ((PEMKeyPair)o).getPrivateKeyInfo();
                byte[] buffer = pki.getPrivateKey().getOctets();
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
                PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
                return privateKey;
            } else if (o instanceof PrivateKeyInfo){
                pki = (PrivateKeyInfo)o;
            }else {
                throw new PKCSException("Invalid encrypted private key class: " + o.getClass().getName());
            }
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
            return converter.getPrivateKey(pki);
        }
    }

    public static String cert2Pem(Certificate cert) throws Exception{
        PemObject pem = new PemObject(CERTIFICATE, cert.getEncoded());
        StringWriter str = new StringWriter();
        try(PemWriter pemWriter = new PemWriter(str)){
            pemWriter.writeObject(pem);
        }
        return str.toString();
    }

    public static Certificate pem2Cert(String pemStr) throws Exception{
        String[] lines = pemStr.split("\n");
        StringBuilder sb = new StringBuilder();
        for(String line : lines){
            if(line.startsWith("--")){
                continue;
            }
            sb.append(line);
        }
        String str = sb.toString();
        str = str.replaceAll("\r", "");
        byte[] buffer = Base64.getDecoder().decode(str);
        return CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME)
                .generateCertificate(new ByteArrayInputStream(buffer));
    }
}
