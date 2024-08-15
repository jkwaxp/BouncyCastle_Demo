package alg.bc.nation;

import alg.bc.ProviderRegist;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
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
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

/**
 * 证书格式：
 * .crt/.cer    DER编码，二进制存储，只有证书不包含私钥
 * .pem         pem编码，base64字符串，首尾有关键字----BEGIN/END----,私钥可以加密
 * .pfx/.p12    PKCS#12 用于存放个人证书/私钥，通常包含保护密码，二进制存储
 * .p10         PKCS#10 证书请求
 * .p7r         PKCS#7 CA对证书请求的回复，只用于导入
 * .p7b         PKCS#7 以树状展示证书链(certificate chain)，同时也支持单个证书，不含私钥。
 * KeyStore     用于存放个人证书/私钥，通常包含保护密码，二进制存储
 */
public class GmCert extends ProviderRegist {

    /**
     * 生成证书请求
     * @param publicKey  公钥
     * @param privateKey 私钥
     * @param sn         证书拥有者
     * @return
     * @throws Exception
     */
    public static PKCS10CertificationRequest generateCsr(PublicKey publicKey, PrivateKey privateKey, String sn) throws Exception {
        String subjectParam = "CN=" + sn;
        X500Principal subject = new X500Principal(subjectParam);
        ContentSigner signer = new JcaContentSignerBuilder("SM3withSM2")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(privateKey);
        return new JcaPKCS10CertificationRequestBuilder(subject, publicKey).build(signer);
    }

    /**
     * 证书请求对象转成PEM格式
     * @param csr
     * @return
     * @throws Exception
     */
    public static String getPemFmtStr(PKCS10CertificationRequest csr) throws Exception {
        PemObject pem = new PemObject("CERTIFICATE REQUEST", csr.getEncoded());
        StringWriter str = new StringWriter();
        try(PemWriter pemWriter = new PemWriter(str)) {
            pemWriter.writeObject(pem);
            str.close();
        }
        return str.toString();
    }

    /**
     * 将PEM格式的证书请求字符串转成对象
     * @param csrStr
     * @return
     * @throws Exception
     */
    public static PKCS10CertificationRequest csrInPem2Obj(String csrStr) throws Exception{
        PKCS10CertificationRequest csr = null;
        ByteArrayInputStream pemStream = null;
        pemStream = new ByteArrayInputStream(csrStr.getBytes("UTF-8"));
        Reader pemReader = new BufferedReader(new InputStreamReader(pemStream));
        PEMParser pemParser = new PEMParser(pemReader);
        Object parsedObj = pemParser.readObject();
        if (parsedObj instanceof PKCS10CertificationRequest) {
            csr = (PKCS10CertificationRequest) parsedObj;
        }
        return csr;
    }

    /**
     * 公钥对象转成PEM格式
     * @param publicKeyKey
     * @return
     * @throws IOException
     */
    public static String getPemFmtStr(PublicKey publicKeyKey) throws Exception {
        PemObject pem = new PemObject("EC PUBLIC KEY", publicKeyKey.getEncoded());
        StringWriter str = new StringWriter();
        PemWriter pemWriter = new PemWriter(str);
        pemWriter.writeObject(pem);
        pemWriter.close();
        str.close();
        return str.toString();
    }

    /**
     * 将PEM格式的公钥字符串转成对象
     * @param pemStr
     * @return
     * @throws Exception
     */
    public static PublicKey pubKeyInPem2Obj(String pemStr) throws Exception {
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
        KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        return keyFactory.generatePublic(keySpec);
    }

    /**
     * 私钥对象转成PEM格式
     * @param privateKey
     * @param pin 传null时不加密
     * @return
     * @throws IOException
     * @throws OperatorCreationException
     */
    public static String getPemFmtStr(PrivateKey privateKey, String pin) throws IOException, OperatorCreationException {
        if(pin == null) {
            PemObject pem = new PemObject("EC PRIVATE KEY", privateKey.getEncoded());
            StringWriter str = new StringWriter();
            try(PemWriter pemWriter = new PemWriter(str)) {
                pemWriter.writeObject(pem);
                str.close();
            }
            return str.toString();
        }else{
            JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.PBE_SHA1_RC2_128);
            encryptorBuilder.setRandom(new SecureRandom());
            encryptorBuilder.setPassword(pin.toCharArray());
            OutputEncryptor encryptor = encryptorBuilder.build();
            JcaPKCS8Generator pkcsGenerator = new JcaPKCS8Generator(privateKey, encryptor);
            PemObject pemObj = pkcsGenerator.generate();
            StringWriter str = new StringWriter();
            try (JcaPEMWriter pemWriter = new JcaPEMWriter(str)) {
                pemWriter.writeObject(pemObj);
                str.close();
            }
            return str.toString();
        }
    }

    /**
     * 解密证书私钥
     * @param privateKeyPemStr PEM格式的私钥
     * @param pin   私钥口令
     * @return
     * @throws Exception
     */
    public static PrivateKey decryptPrivateKey(String privateKeyPemStr, String pin) throws Exception {
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
                KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
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

    public static String getAlgName(String algorithm){
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(algorithm);
        String name = new DefaultAlgorithmNameFinder().getAlgorithmName(oid);
        if(algorithm.equals(name)){
            name = new DefaultSignatureNameFinder().getAlgorithmName(oid);
        }
        return name;
    }

    /**
     * 将证书与私钥转成keyStore对象
     * @param crtPath
     * @param alias
     * @param privateKey
     * @param password
     * @return
     * @throws Exception
     */
    public static KeyStore x5092keyStore(String crtPath, String alias, PrivateKey privateKey, String password) throws Exception{
        try(FileInputStream certFileInputStream = new FileInputStream(crtPath)){
            Certificate certificate = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME).generateCertificate(certFileInputStream);
            KeyStore keyStore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            keyStore.load(null, null);
            keyStore.setKeyEntry(alias, privateKey, password.toCharArray(), new Certificate[]{certificate});
            return keyStore;
        }
    }

    /**
     * 将证书与私钥写入keystore文件
     * @param crtPath
     * @param alias
     * @param privateKey
     * @param password
     * @param keyStorePath
     * @throws Exception
     */
    public static void x5092P12File(String crtPath, String alias, PrivateKey privateKey, String password, String keyStorePath)throws Exception{
        try(FileOutputStream outputStream = new FileOutputStream(keyStorePath)){
            KeyStore keyStore = x5092keyStore(crtPath, alias, privateKey, password);
            keyStore.store(outputStream, password.toCharArray());
        }
    }

    /**
     * 从keystore文件中读取证书
     * @param keyStorePath
     * @param keyStorePassword
     * @param alias
     * @return
     * @throws Exception
     */
    public static Certificate keyStore2x509(String keyStorePath, String keyStorePassword, String alias) throws Exception{
        try(FileInputStream p12FileInputStream = new FileInputStream(keyStorePath)){
            KeyStore keyStore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            keyStore.load(p12FileInputStream, keyStorePassword.toCharArray());
            return keyStore.getCertificate(alias);
        }
    }

    public static enum CertLevel {
        RootCA,
        SubCA,
        EndEntity
    }

    /**
     * 生成自签证书
     * @param certLevel
     * @param csrInPem  pem格式的证书请求内容
     * @return
     * @throws Exception
     */
    public static X509Certificate generateCert(CertLevel certLevel, String csrInPem) throws Exception{
        KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyAgreement
                | KeyUsage.dataEncipherment | KeyUsage.keyEncipherment);
        KeyPurposeId[] keyPurposeIds = new KeyPurposeId[] {KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth};
        return generateCert(certLevel, csrInPem, keyUsage, keyPurposeIds);
    }

    /**
     * 生成自签证书
     * @param certLevel
     * @param csrInPem      pem格式的证书请求内容
     * @param keyUsage      证书用途
     * @param extendedKeyUsages
     * @return
     * @throws Exception
     */
    public static X509Certificate generateCert(CertLevel certLevel, String csrInPem, KeyUsage keyUsage,
                                               KeyPurposeId[] extendedKeyUsages) throws Exception{
        if (certLevel == CertLevel.EndEntity) {
            if (keyUsage.hasUsages(KeyUsage.keyCertSign)) {
                throw new IllegalArgumentException("keyusage keyCertSign is not allowed in EndEntity Certificate");
            }
        }
        PKCS10CertificationRequest pkcsCSR = csrInPem2Obj(csrInPem);
        PKCS10CertificationRequest request = new PKCS10CertificationRequest(pkcsCSR.getEncoded());
        SubjectPublicKeyInfo subPub = request.getSubjectPublicKeyInfo();

        X500Name subject = request.getSubject();
        String email = null;
        String commonName = null;
        RDN[] rdns = subject.getRDNs();
        List<RDN> newRdns = new ArrayList<>(rdns.length);
        for (int i = 0; i < rdns.length; i++) {
            RDN rdn = rdns[i];

            AttributeTypeAndValue atv = rdn.getFirst();
            ASN1ObjectIdentifier type = atv.getType();
            if (BCStyle.EmailAddress.equals(type)) {
                email = IETFUtils.valueToString(atv.getValue());
            } else {
                if (BCStyle.CN.equals(type)) {
                    commonName = IETFUtils.valueToString(atv.getValue());
                }
                newRdns.add(rdn);
            }
        }

        List<GeneralName> subjectAltNames = new LinkedList<>();
        if (email != null) {
            subject = new X500Name(newRdns.toArray(new RDN[0]));
            subjectAltNames.add(new GeneralName(GeneralName.rfc822Name, new DERIA5String(email, true)));
        }

        boolean selfSignedEECert = false;
        switch (certLevel) {
            case RootCA:
                if (rootDN.equals(subject)) {
                    subject = rootDN;
                } else {
                    throw new IllegalArgumentException("subject != issuer for certLevel " + CertLevel.RootCA);
                }
                break;
            case SubCA:
                if (rootDN.equals(subject)) {
                    throw new IllegalArgumentException("subject MUST not equals issuer for certLevel " + certLevel);
                }
                break;
            default:
                if (rootDN.equals(subject)) {
                    selfSignedEECert = true;
                    subject = rootDN;
                }
        }

        BigInteger serialNumber = nextSerialNumber();
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 20L * 365 * 24 * 60 * 60 * 1000);  // 20年
        X509v3CertificateBuilder v3CertGen = new X509v3CertificateBuilder(rootDN, serialNumber, notBefore, notAfter, subject, subPub);

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        v3CertGen.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(subPub));
        if (certLevel != CertLevel.RootCA && !selfSignedEECert) {
            v3CertGen.addExtension(Extension.authorityKeyIdentifier, false,
                    extUtils.createAuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(issPub.getEncoded())));
        }

        BasicConstraints basicConstraints;
        if (certLevel == CertLevel.EndEntity) {
            basicConstraints = new BasicConstraints(false);
        } else {
            basicConstraints = new BasicConstraints(true);
        }
        v3CertGen.addExtension(Extension.basicConstraints, true, basicConstraints);
        v3CertGen.addExtension(Extension.keyUsage, true, keyUsage);

        if (extendedKeyUsages != null) {
            ExtendedKeyUsage xku = new ExtendedKeyUsage(extendedKeyUsages);
            v3CertGen.addExtension(Extension.extendedKeyUsage, false, xku);

            boolean forSSLServer = false;
            for (KeyPurposeId purposeId : extendedKeyUsages) {
                if (KeyPurposeId.id_kp_serverAuth.equals(purposeId)) {
                    forSSLServer = true;
                    break;
                }
            }

            if (forSSLServer) {
                if (commonName == null) {
                    throw new IllegalArgumentException("commonName must not be null");
                }
                GeneralName name = new GeneralName(GeneralName.dNSName, new DERIA5String(commonName, true));
                subjectAltNames.add(name);
            }
        }

        if (!subjectAltNames.isEmpty()) {
            v3CertGen.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(subjectAltNames.toArray(new GeneralName[0])));
        }
        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SM3withSM2");
        contentSignerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(v3CertGen.build(contentSignerBuilder.build(issPriv)));
        cert.verify(issPub);
        return cert;
    }

    public static X500Name buildDN(String c, String o, String ou, String cn) {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.C, c);
        builder.addRDN(BCStyle.O, o);
        builder.addRDN(BCStyle.OU, ou);
        builder.addRDN(BCStyle.CN, cn);
        return builder.build();
    }

    private static BigInteger nextSerialNumber() {
        int bitLen = 100; // 65 - 159
        SecureRandom random = new SecureRandom();
        final byte[] rdnBytes = new byte[(bitLen + 7) / 8];
        final int ci = bitLen % 8;

        random.nextBytes(rdnBytes);
        if (ci != 0) {
            rdnBytes[0] = (byte) (rdnBytes[0] & AND_MASKS[ci]);
        }
        rdnBytes[0] = (byte) (rdnBytes[0] | OR_MASKS[ci]);

        return new BigInteger(1, rdnBytes);
    }

    private static int[] AND_MASKS = new int[] {0xFF, 0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3F, 0x7F};

    private static int[] OR_MASKS = new int[] {0x80, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40};

    static PublicKey issPub;
    static PrivateKey issPriv;
    static X500Name rootDN = buildDN("CN", "org.zz", "org.zz", "ZZ Root CA");

    static {
        try {
            issPub = pubKeyInPem2Obj("-----BEGIN EC PUBLIC KEY-----\n" +
                    "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE4JNMJeAMBGaFNd+lYEU07Hjwnu0r\n" +
                    "9IjZqWQz9q7/XJeJxu0+4VfjsIuAgxI9FuPo4XM0eVRVh9UQVKbYfhGm1w==\n" +
                    "-----END EC PUBLIC KEY-----");
            issPriv = decryptPrivateKey("-----BEGIN EC PRIVATE KEY-----\n" +
                    "MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgDr50ywZDYVf7Az40\n" +
                    "L1rb9T9r+V8Dw7FFWlFOZieW1sWgCgYIKoEcz1UBgi2hRANCAATgk0wl4AwEZoU1\n" +
                    "36VgRTTsePCe7Sv0iNmpZDP2rv9cl4nG7T7hV+Owi4CDEj0W4+jhczR5VFWH1RBU\n" +
                    "pth+EabX\n" +
                    "-----END EC PRIVATE KEY-----", null);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
