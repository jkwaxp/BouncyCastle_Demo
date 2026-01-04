package alg.bc.gui.util;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * 通用 X.509 工具箱（解析 / 格式识别 / 格式转换 / 信息展示）
 *
 * 目标：给 GUI 证书模块提供“粘贴什么就能识别什么”的能力。
 */
public final class X509Toolbox {

    private static final DateTimeFormatter TS_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    static {
        // 确保 BC provider 已注册（解析/转换时会用到）
        if (java.security.Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            java.security.Security.addProvider(new BouncyCastleProvider());
        }
    }

    private X509Toolbox() {
    }

    public static boolean looksLikeHex(String s) {
        if (s == null) return false;
        String t = s.replaceAll("\\s+", "");
        if (t.isEmpty()) return false;
        if ((t.length() % 2) != 0) return false;
        return t.matches("^[0-9a-fA-F]+$");
    }

    public static byte[] decodeTextToBytesBestEffort(String text) {
        if (text == null) return new byte[0];
        String t = text.trim();
        if (t.isEmpty()) return new byte[0];
        // PEM 直接按 UTF-8 给后续 PEMParser
        if (t.startsWith("-----BEGIN")) {
            return t.getBytes(StandardCharsets.UTF_8);
        }
        String compact = t.replaceAll("\\s+", "");
        if (looksLikeHex(compact)) {
            return Hex.decode(compact);
        }
        try {
            return Base64.decode(compact);
        } catch (Exception ignored) {
        }
        return t.getBytes(StandardCharsets.UTF_8);
    }

    public static String toPem(Object obj) throws IOException {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter w = new JcaPEMWriter(sw)) {
            w.writeObject(obj);
        }
        return sw.toString();
    }

    public static List<Object> parsePemObjects(String pemText) throws IOException {
        List<Object> out = new ArrayList<>();
        try (PEMParser parser = new PEMParser(new StringReader(pemText))) {
            Object o;
            while ((o = parser.readObject()) != null) {
                out.add(o);
            }
        }
        return out;
    }

    public static List<X509Certificate> parseCertificatesWithJca(byte[] bytes) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> certs = cf.generateCertificates(new ByteArrayInputStream(bytes));
            List<X509Certificate> list = new ArrayList<>();
            for (Certificate c : certs) {
                if (c instanceof X509Certificate) list.add((X509Certificate) c);
            }
            return list;
        } catch (Exception e) {
            return Collections.emptyList();
        }
    }

    public static List<X509Certificate> parsePkcs7Certificates(byte[] bytes) {
        try {
            CMSSignedData cms = new CMSSignedData(bytes);
            Store<X509CertificateHolder> store = cms.getCertificates();
            Collection<X509CertificateHolder> holders = store.getMatches(null);
            List<X509Certificate> certs = new ArrayList<>();
            org.bouncycastle.cert.jcajce.JcaX509CertificateConverter conv =
                    new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
            for (X509CertificateHolder h : holders) {
                certs.add(conv.getCertificate(h));
            }
            return certs;
        } catch (Exception e) {
            return Collections.emptyList();
        }
    }

    public static PKCS10CertificationRequest tryParseCsr(byte[] bytes) {
        try {
            return new PKCS10CertificationRequest(bytes);
        } catch (Exception e) {
            return null;
        }
    }

    public static PrivateKey tryParsePrivateKeyFromPemObject(Object pemObj) {
        try {
            JcaPEMKeyConverter conv = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
            if (pemObj instanceof PrivateKeyInfo) {
                return conv.getPrivateKey((PrivateKeyInfo) pemObj);
            }
            if (pemObj instanceof PEMKeyPair) {
                return conv.getPrivateKey(((PEMKeyPair) pemObj).getPrivateKeyInfo());
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    public static KeyStore tryLoadPkcs12(byte[] bytes, char[] password) {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new ByteArrayInputStream(bytes), password);
            return ks;
        } catch (Exception e) {
            return null;
        }
    }

    public static String describeKeyStorePkcs12(KeyStore ks) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("类型：PKCS#12\n");
            Enumeration<String> aliases = ks.aliases();
            List<String> list = new ArrayList<>();
            while (aliases.hasMoreElements()) list.add(aliases.nextElement());
            sb.append("别名数量：").append(list.size()).append("\n");
            for (String a : list) {
                sb.append("\n--- Alias: ").append(a).append(" ---\n");
                sb.append("isKeyEntry=").append(ks.isKeyEntry(a)).append(", isCertificateEntry=").append(ks.isCertificateEntry(a)).append("\n");
                Certificate c = ks.getCertificate(a);
                if (c instanceof X509Certificate) {
                    sb.append(describeCertificate((X509Certificate) c));
                } else if (c != null) {
                    sb.append("证书类型：").append(c.getType()).append("\n");
                }
                Certificate[] chain = ks.getCertificateChain(a);
                if (chain != null && chain.length > 0) {
                    sb.append("证书链长度：").append(chain.length).append("\n");
                    for (int i = 0; i < chain.length; i++) {
                        Certificate cc = chain[i];
                        if (cc instanceof X509Certificate) {
                            sb.append("  [").append(i).append("] ").append(((X509Certificate) cc).getSubjectX500Principal().getName()).append("\n");
                        }
                    }
                }
            }
            return sb.toString();
        } catch (Exception e) {
            return "解析 PKCS#12 失败: " + e.getMessage();
        }
    }

    public static String describeCsr(PKCS10CertificationRequest csr) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("类型：CSR (PKCS#10)\n");
            sb.append("Subject：").append(csr.getSubject()).append("\n");
            sb.append("签名算法：").append(csr.getSignatureAlgorithm().getAlgorithm()).append("\n");
            try {
                Extensions exts = getCsrExtensions(csr);
                if (exts != null) {
                    sb.append("扩展：\n");
                    appendExtensionsSummary(sb, exts);
                }
            } catch (Exception ignored) {
            }
            return sb.toString();
        } catch (Exception e) {
            return "CSR 解析失败: " + e.getMessage();
        }
    }

    private static Extensions getCsrExtensions(PKCS10CertificationRequest csr) {
        org.bouncycastle.asn1.pkcs.Attribute[] attrs = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        if (attrs == null || attrs.length == 0) return null;
        ASN1Encodable[] values = attrs[0].getAttributeValues();
        if (values == null || values.length == 0) return null;
        return Extensions.getInstance(values[0]);
    }

    public static String describeCertificate(X509Certificate cert) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("类型：X.509 Certificate\n");
            sb.append("Subject：").append(cert.getSubjectX500Principal().getName()).append("\n");
            sb.append("Issuer ：").append(cert.getIssuerX500Principal().getName()).append("\n");
            sb.append("Serial ：").append(toHex(cert.getSerialNumber())).append("\n");
            sb.append("Version：v").append(cert.getVersion()).append("\n");
            sb.append("有效期：").append(formatDate(cert.getNotBefore())).append("  ~  ").append(formatDate(cert.getNotAfter())).append("\n");
            sb.append("签名算法：").append(cert.getSigAlgName()).append(" (").append(cert.getSigAlgOID()).append(")\n");
            sb.append("公钥：").append(describePublicKey(cert.getPublicKey())).append("\n");
            sb.append("指纹：SHA-256=").append(fingerprint("SHA-256", cert.getEncoded())).append("\n");
            sb.append("     SHA-1  =").append(fingerprint("SHA-1", cert.getEncoded())).append("\n");

            // Extensions（用 BC 更易解析）
            try {
                JcaX509CertificateHolder holder = new JcaX509CertificateHolder(cert);
                Extensions exts = holder.getExtensions();
                if (exts != null) {
                    sb.append("扩展：\n");
                    appendExtensionsSummary(sb, exts);
                }
            } catch (Exception ignored) {
            }
            return sb.toString();
        } catch (Exception e) {
            return "证书解析失败: " + e.getMessage();
        }
    }

    private static void appendExtensionsSummary(StringBuilder sb, Extensions exts) throws IOException {
        // BasicConstraints
        Extension bcExt = exts.getExtension(Extension.basicConstraints);
        if (bcExt != null) {
            BasicConstraints bc = BasicConstraints.getInstance(bcExt.getParsedValue());
            sb.append("- BasicConstraints: CA=").append(bc.isCA());
            if (bc.isCA() && bc.getPathLenConstraint() != null) sb.append(", pathLen=").append(bc.getPathLenConstraint());
            sb.append("\n");
        }

        // KeyUsage
        Extension kuExt = exts.getExtension(Extension.keyUsage);
        if (kuExt != null) {
            KeyUsage ku = KeyUsage.getInstance(kuExt.getParsedValue());
            sb.append("- KeyUsage: ").append(describeKeyUsage(ku)).append("\n");
        }

        // EKU
        Extension ekuExt = exts.getExtension(Extension.extendedKeyUsage);
        if (ekuExt != null) {
            ExtendedKeyUsage eku = ExtendedKeyUsage.getInstance(ekuExt.getParsedValue());
            sb.append("- ExtendedKeyUsage: ").append(describeEku(eku)).append("\n");
        }

        // SAN
        Extension sanExt = exts.getExtension(Extension.subjectAlternativeName);
        if (sanExt != null) {
            GeneralNames gns = GeneralNames.getInstance(sanExt.getParsedValue());
            sb.append("- SubjectAltName: ").append(describeGeneralNames(gns)).append("\n");
        }

        // SKI / AKI
        Extension skiExt = exts.getExtension(Extension.subjectKeyIdentifier);
        if (skiExt != null) {
            SubjectKeyIdentifier ski = SubjectKeyIdentifier.getInstance(skiExt.getParsedValue());
            sb.append("- SubjectKeyIdentifier: ").append(Hex.toHexString(ski.getKeyIdentifier())).append("\n");
        }
        Extension akiExt = exts.getExtension(Extension.authorityKeyIdentifier);
        if (akiExt != null) {
            AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(akiExt.getParsedValue());
            byte[] kid = aki.getKeyIdentifier();
            if (kid != null) {
                sb.append("- AuthorityKeyIdentifier: ").append(Hex.toHexString(kid)).append("\n");
            }
        }

        // CRLDP
        Extension crldpExt = exts.getExtension(Extension.cRLDistributionPoints);
        if (crldpExt != null) {
            CRLDistPoint dp = CRLDistPoint.getInstance(crldpExt.getParsedValue());
            List<String> urls = extractUrisFromCrlDistPoint(dp);
            if (!urls.isEmpty()) sb.append("- CRLDistributionPoints: ").append(urls).append("\n");
        }

        // AIA
        Extension aiaExt = exts.getExtension(Extension.authorityInfoAccess);
        if (aiaExt != null) {
            AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(aiaExt.getParsedValue());
            List<String> desc = new ArrayList<>();
            for (AccessDescription ad : aia.getAccessDescriptions()) {
                String method = ad.getAccessMethod().getId();
                GeneralName loc = ad.getAccessLocation();
                desc.add(method + "=" + describeGeneralName(loc));
            }
            if (!desc.isEmpty()) sb.append("- AuthorityInfoAccess: ").append(desc).append("\n");
        }
    }

    private static String describePublicKey(PublicKey pk) {
        if (pk == null) return "null";
        if (pk instanceof RSAPublicKey) {
            RSAPublicKey r = (RSAPublicKey) pk;
            return "RSA " + r.getModulus().bitLength() + " bits";
        }
        if (pk instanceof ECPublicKey) {
            ECPublicKey e = (ECPublicKey) pk;
            return "EC " + e.getParams().getCurve().getField().getFieldSize() + " bits";
        }
        return pk.getAlgorithm() + " (" + pk.getFormat() + ")";
    }

    private static String describeKeyUsage(KeyUsage ku) {
        List<String> list = new ArrayList<>();
        if (ku.hasUsages(KeyUsage.digitalSignature)) list.add("digitalSignature");
        if (ku.hasUsages(KeyUsage.nonRepudiation)) list.add("nonRepudiation");
        if (ku.hasUsages(KeyUsage.keyEncipherment)) list.add("keyEncipherment");
        if (ku.hasUsages(KeyUsage.dataEncipherment)) list.add("dataEncipherment");
        if (ku.hasUsages(KeyUsage.keyAgreement)) list.add("keyAgreement");
        if (ku.hasUsages(KeyUsage.keyCertSign)) list.add("keyCertSign");
        if (ku.hasUsages(KeyUsage.cRLSign)) list.add("cRLSign");
        if (ku.hasUsages(KeyUsage.encipherOnly)) list.add("encipherOnly");
        if (ku.hasUsages(KeyUsage.decipherOnly)) list.add("decipherOnly");
        return list.isEmpty() ? "<empty>" : String.join(",", list);
    }

    private static String describeEku(ExtendedKeyUsage eku) {
        KeyPurposeId[] ids = eku.getUsages();
        List<String> list = new ArrayList<>();
        for (KeyPurposeId id : ids) list.add(id.getId());
        return list.isEmpty() ? "<empty>" : String.join(",", list);
    }

    private static String describeGeneralNames(GeneralNames gns) {
        List<String> list = new ArrayList<>();
        for (GeneralName n : gns.getNames()) list.add(describeGeneralName(n));
        return list.isEmpty() ? "<empty>" : String.join(", ", list);
    }

    private static String describeGeneralName(GeneralName n) {
        if (n == null) return "null";
        int tag = n.getTagNo();
        switch (tag) {
            case GeneralName.dNSName:
            case GeneralName.rfc822Name:
            case GeneralName.uniformResourceIdentifier:
                return tagName(tag) + ":" + DERIA5String.getInstance(n.getName()).getString();
            case GeneralName.iPAddress:
                // 可能是原始 octets 或字符串，尽量展示 hex
                try {
                    byte[] ip = ASN1OctetString.getInstance(n.getName()).getOctets();
                    return tagName(tag) + ":" + Hex.toHexString(ip);
                } catch (Exception ignored) {
                    return tagName(tag) + ":" + n.getName().toString();
                }
            default:
                return tagName(tag) + ":" + n.getName().toString();
        }
    }

    private static String tagName(int tag) {
        switch (tag) {
            case GeneralName.dNSName:
                return "DNS";
            case GeneralName.rfc822Name:
                return "EMAIL";
            case GeneralName.uniformResourceIdentifier:
                return "URI";
            case GeneralName.iPAddress:
                return "IP";
            default:
                return "TAG(" + tag + ")";
        }
    }

    private static List<String> extractUrisFromCrlDistPoint(CRLDistPoint dp) {
        List<String> urls = new ArrayList<>();
        if (dp == null) return urls;
        for (DistributionPoint p : dp.getDistributionPoints()) {
            DistributionPointName name = p.getDistributionPoint();
            if (name == null) continue;
            if (name.getType() == DistributionPointName.FULL_NAME) {
                GeneralNames gns = GeneralNames.getInstance(name.getName());
                for (GeneralName gn : gns.getNames()) {
                    if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        urls.add(DERIA5String.getInstance(gn.getName()).getString());
                    }
                }
            }
        }
        return urls;
    }

    private static String toHex(BigInteger bi) {
        if (bi == null) return "null";
        return "0x" + bi.toString(16);
    }

    private static String formatDate(Date d) {
        if (d == null) return "null";
        return TS_FMT.format(Instant.ofEpochMilli(d.getTime()));
    }

    private static String fingerprint(String alg, byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance(alg);
            byte[] dig = md.digest(data);
            String hex = Hex.toHexString(dig).toUpperCase(Locale.ROOT);
            // 常见展示为冒号分隔
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < hex.length(); i += 2) {
                if (i > 0) sb.append(':');
                sb.append(hex, i, i + 2);
            }
            return sb.toString();
        } catch (Exception e) {
            return "<error:" + e.getMessage() + ">";
        }
    }
}


