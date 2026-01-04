package alg.bc.gui.action.international;

import alg.bc.gui.Boot;
import alg.bc.gui.util.ByteUtil;
import alg.bc.gui.util.CompUtil;
import alg.bc.gui.util.Validate;
import alg.bc.gui.util.X509Toolbox;
import alg.bc.internation.Rsa;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import javax.swing.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * 国际算法 - 证书模块动作实现（RSA）
 * 保留“最后加载文件”的状态，支持空输入直接解析文件内容。
 */
public class IntlCertActions {
    private final InternationalViewProvider ui;

    private byte[] lastLoadedBytes;
    private String lastLoadedPath;

    public IntlCertActions(InternationalViewProvider ui) {
        this.ui = ui;
    }

    public void intRsaCertGenerateKeyPair() throws Exception {
        Integer sizeObj = (Integer) ui.getIntCertForm().getGenKeySizeComboBox().getSelectedItem();
        if (sizeObj == null) {
            throw new IllegalArgumentException("KeySize 未选择，无法生成密钥对");
        }
        Object encObj = ui.getIntCertForm().getGenKeyEncodeComboBox().getSelectedItem();
        if (encObj == null) {
            throw new IllegalArgumentException("密钥编码未选择，无法生成密钥对");
        }
        int size = sizeObj;
        KeyPair kp = Rsa.generateKeyPair(size);
        String enc = encObj.toString();
        ui.getIntCertForm().getGenPubKeyTextArea().setText(ByteUtil.bytes2Str(kp.getPublic().getEncoded(), enc));
        ui.getIntCertForm().getGenPrvKeyTextArea().setText(ByteUtil.bytes2Str(kp.getPrivate().getEncoded(), enc));
        ui.getIntCertForm().getGenResultTextArea().setText("已生成 RSA KeyPair（公钥X.509 / 私钥PKCS#8）。\n");
    }

    public void intRsaCertGenerateCsr() {
        try {
            String subject = Validate.requireNotBlank(ui.getIntCertForm().getGenSubjectTextField().getText(), "证书Subject");
            String enc = ui.getIntCertForm().getGenKeyEncodeComboBox().getSelectedItem().toString();
            byte[] pubBytes = Validate.requireBytes(ui.getIntCertForm().getGenPubKeyTextArea().getText(), enc, "公钥");
            byte[] prvBytes = Validate.requireBytes(ui.getIntCertForm().getGenPrvKeyTextArea().getText(), enc, "私钥");
            PublicKey publicKey = Rsa.bytes2PubKey(pubBytes);
            PrivateKey privateKey = Rsa.bytes2PrvKey(prvBytes);

            String dn = normalizeDn(subject);
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(privateKey);
            PKCS10CertificationRequest csr = new JcaPKCS10CertificationRequestBuilder(
                    new javax.security.auth.x500.X500Principal(dn), publicKey
            ).build(signer);

            String csrPem = X509Toolbox.toPem(csr);
            ui.getIntCertForm().getGenResultTextArea().setText(csrPem + "\n" + X509Toolbox.describeCsr(csr));
        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, "生成CSR失败: " + ex.getMessage());
        }
    }

    public void intRsaCertGenerateSelfSigned() {
        try {
            String subject = Validate.requireNotBlank(ui.getIntCertForm().getGenSubjectTextField().getText(), "证书Subject");
            int days;
            try {
                days = Integer.parseInt(ui.getIntCertForm().getGenDaysTextField().getText().trim());
            } catch (Exception e) {
                throw new IllegalArgumentException("有效天数必须是整数");
            }
            if (days <= 0) throw new IllegalArgumentException("有效天数必须 > 0");

            String enc = ui.getIntCertForm().getGenKeyEncodeComboBox().getSelectedItem().toString();
            byte[] pubBytes = Validate.requireBytes(ui.getIntCertForm().getGenPubKeyTextArea().getText(), enc, "公钥");
            byte[] prvBytes = Validate.requireBytes(ui.getIntCertForm().getGenPrvKeyTextArea().getText(), enc, "私钥");
            PublicKey publicKey = Rsa.bytes2PubKey(pubBytes);
            PrivateKey privateKey = Rsa.bytes2PrvKey(prvBytes);

            String dn = normalizeDn(subject);
            X500Name x500Name = new X500Name(dn);
            BigInteger serial = new BigInteger(160, new SecureRandom()).abs();
            Date notBefore = new Date(System.currentTimeMillis() - 5L * 60 * 1000);
            Date notAfter = new Date(System.currentTimeMillis() + (long) days * 24 * 60 * 60 * 1000);

            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
            X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                    x500Name, serial, notBefore, notAfter, x500Name, spki
            );
            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            builder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(spki));
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            builder.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment));

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(privateKey);
            X509CertificateHolder holder = builder.build(signer);
            X509Certificate cert = new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(holder);
            cert.verify(publicKey);

            String certPem = X509Toolbox.toPem(cert);
            String keyPem = X509Toolbox.toPem(privateKey);
            ui.getIntCertForm().getGenResultTextArea().setText(
                    certPem +
                            "\n# ---- Private Key (PKCS#8) ----\n" +
                            keyPem +
                            "\n" +
                            X509Toolbox.describeCertificate(cert)
            );
        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, "生成自签证书失败: " + ex.getMessage());
        }
    }

    public void intRsaCertLoadFile() {
        try {
            String filePath = CompUtil.chooseFile(Boot.frame, "选择证书文件");
            if (filePath == null || filePath.isEmpty()) return;
            byte[] bytes = Files.readAllBytes(Paths.get(filePath));
            lastLoadedBytes = bytes;
            lastLoadedPath = filePath;

            String asText = new String(bytes, StandardCharsets.UTF_8);
            if (asText.contains("-----BEGIN")) {
                ui.getIntCertForm().getCertInputTextArea().setText(asText);
            } else {
                String b64 = java.util.Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(bytes);
                ui.getIntCertForm().getCertInputTextArea().setText(b64);
                CompUtil.showMsg(Boot.frame, "提示", "已加载二进制文件，已以 BASE64 形式显示（点击“解析”即可自动识别）");
            }
        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, "加载证书文件失败: " + ex.getMessage());
        }
    }

    public void intRsaCertParse() {
        try {
            String text = ui.getIntCertForm().getCertInputTextArea().getText();
            byte[] bytes = null;
            boolean hasText = text != null && !text.trim().isEmpty();
            if (!hasText) {
                if (lastLoadedBytes == null || lastLoadedBytes.length == 0) {
                    throw new IllegalArgumentException("证书内容不能为空");
                }
                bytes = lastLoadedBytes;
            }

            StringBuilder sb = new StringBuilder();
            sb.append("=== X.509 工具箱解析结果（国际/RSA）===\n");
            if (lastLoadedPath != null && !lastLoadedPath.trim().isEmpty()) {
                sb.append("来源文件：").append(lastLoadedPath).append("\n");
            }

            if (hasText && text.trim().startsWith("-----BEGIN")) {
                sb.append("输入类型：PEM\n\n");
                List<Object> objs = X509Toolbox.parsePemObjects(text);
                if (objs.isEmpty()) {
                    throw new IllegalArgumentException("未识别到任何 PEM 块（请确认包含 -----BEGIN/END-----）");
                }
                int idx = 0;
                for (Object o : objs) {
                    sb.append("## 块 ").append(idx++).append("：").append(o.getClass().getSimpleName()).append("\n");
                    if (o instanceof X509CertificateHolder) {
                        X509Certificate cert = new JcaX509CertificateConverter()
                                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                                .getCertificate((X509CertificateHolder) o);
                        sb.append(X509Toolbox.describeCertificate(cert)).append("\n");
                        sb.append("PEM：\n").append(X509Toolbox.toPem(cert)).append("\n");
                    } else if (o instanceof PKCS10CertificationRequest) {
                        PKCS10CertificationRequest csr = (PKCS10CertificationRequest) o;
                        sb.append(X509Toolbox.describeCsr(csr)).append("\n");
                        sb.append("PEM：\n").append(X509Toolbox.toPem(csr)).append("\n");
                    } else {
                        sb.append(String.valueOf(o)).append("\n\n");
                    }
                }
            } else {
                if (bytes == null) {
                    bytes = X509Toolbox.decodeTextToBytesBestEffort(text);
                }
                sb.append("输入类型：DER/BASE64/HEX/二进制（自动识别）\n");
                sb.append("输入字节数：").append(bytes.length).append("\n\n");

                List<X509Certificate> pkcs7Certs = X509Toolbox.parsePkcs7Certificates(bytes);
                if (!pkcs7Certs.isEmpty()) {
                    sb.append("检测到：PKCS#7/CMS SignedData\n");
                    sb.append("证书数量：").append(pkcs7Certs.size()).append("\n\n");
                    for (int i = 0; i < pkcs7Certs.size(); i++) {
                        sb.append("## Certificate[").append(i).append("]\n");
                        sb.append(X509Toolbox.describeCertificate(pkcs7Certs.get(i))).append("\n");
                    }
                    ui.getIntCertForm().getCertInfoTextArea().setText(sb.toString());
                    return;
                }

                List<X509Certificate> certs = X509Toolbox.parseCertificatesWithJca(bytes);
                if (!certs.isEmpty()) {
                    sb.append("检测到：X.509 证书\n");
                    sb.append("证书数量：").append(certs.size()).append("\n\n");
                    for (int i = 0; i < certs.size(); i++) {
                        sb.append("## Certificate[").append(i).append("]\n");
                        sb.append(X509Toolbox.describeCertificate(certs.get(i))).append("\n");
                        if (i == 0) {
                            sb.append("PEM：\n").append(X509Toolbox.toPem(certs.get(i))).append("\n");
                        }
                    }
                    ui.getIntCertForm().getCertInfoTextArea().setText(sb.toString());
                    return;
                }

                PKCS10CertificationRequest csr = X509Toolbox.tryParseCsr(bytes);
                if (csr != null) {
                    sb.append("检测到：CSR (PKCS#10)\n\n");
                    sb.append(X509Toolbox.describeCsr(csr)).append("\n");
                    sb.append("PEM：\n").append(X509Toolbox.toPem(csr)).append("\n");
                    ui.getIntCertForm().getCertInfoTextArea().setText(sb.toString());
                    return;
                }

                boolean maybeP12 = (lastLoadedPath != null) && lastLoadedPath.toLowerCase(Locale.ROOT).matches(".*\\.(p12|pfx)$");
                if (maybeP12) {
                    char[] presetPwd = readP12Password();
                    KeyStore ks = (presetPwd == null) ? X509Toolbox.tryLoadPkcs12(bytes, new char[0]) : X509Toolbox.tryLoadPkcs12(bytes, presetPwd);
                    if (ks == null) {
                        char[] pwd = promptPassword("请输入 PKCS#12 口令（p12/pfx）：");
                        if (pwd != null) ks = X509Toolbox.tryLoadPkcs12(bytes, pwd);
                    }
                    if (ks != null) {
                        sb.append(X509Toolbox.describeKeyStorePkcs12(ks)).append("\n");
                        ui.getIntCertForm().getCertInfoTextArea().setText(sb.toString());
                        return;
                    }
                }

                sb.append("未识别输入内容：目前支持 X.509/CSR/PKCS#7（p7b）以及通过文件扩展名识别 PKCS#12（p12/pfx）。\n");
                sb.append("建议：如果是 p12/pfx，请使用“加载文件”导入；如果是 DER，请尝试先转为 BASE64 再粘贴。\n");
            }

            ui.getIntCertForm().getCertInfoTextArea().setText(sb.toString());
        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, "解析证书失败: " + ex.getMessage());
        }
    }

    public void intRsaCertReset() {
        ui.getIntCertForm().getCertInputTextArea().setText("");
        ui.getIntCertForm().getCertInfoTextArea().setText("");
        ui.getIntCertForm().getTrustPemTextArea().setText("");
        ui.getIntCertForm().getP12PasswordField().setText("");
        lastLoadedBytes = null;
        lastLoadedPath = null;
    }

    public void intRsaCertToPem() {
        try {
            ParsedInput in = parseInputBestEffort();
            if (in.certs != null && !in.certs.isEmpty()) {
                StringBuilder out = new StringBuilder();
                for (X509Certificate c : in.certs) out.append(X509Toolbox.toPem(c)).append("\n");
                ui.getIntCertForm().getCertInputTextArea().setText(out.toString());
                CompUtil.showMsg(Boot.frame, "已转换为 PEM（证书可多张）");
                return;
            }
            if (in.csr != null) {
                ui.getIntCertForm().getCertInputTextArea().setText(X509Toolbox.toPem(in.csr));
                CompUtil.showMsg(Boot.frame, "已转换为 CSR PEM");
                return;
            }
            throw new IllegalArgumentException("未识别到证书/CSR，无法转换为 PEM");
        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, "转换失败: " + ex.getMessage());
        }
    }

    public void intRsaCertToDerBase64() {
        try {
            ParsedInput in = parseInputBestEffort();
            byte[] der = pickFirstDer(in);
            String b64 = java.util.Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der);
            ui.getIntCertForm().getCertInputTextArea().setText(b64);
            CompUtil.showMsg(Boot.frame, "已输出 DER(Base64)");
        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, "转换失败: " + ex.getMessage());
        }
    }

    public void intRsaCertToDerHex() {
        try {
            ParsedInput in = parseInputBestEffort();
            byte[] der = pickFirstDer(in);
            ui.getIntCertForm().getCertInputTextArea().setText(org.bouncycastle.util.encoders.Hex.toHexString(der));
            CompUtil.showMsg(Boot.frame, "已输出 DER(HEX)");
        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, "转换失败: " + ex.getMessage());
        }
    }

    public void intRsaCertSplitPem() {
        try {
            String text = ui.getIntCertForm().getCertInputTextArea().getText();
            if (text == null || text.trim().isEmpty()) throw new IllegalArgumentException("输入不能为空");
            if (!text.trim().startsWith("-----BEGIN")) {
                ParsedInput in = parseInputBestEffort();
                if (in.certs == null || in.certs.isEmpty()) throw new IllegalArgumentException("未识别到证书，无法拆分");
                StringBuilder out = new StringBuilder();
                for (X509Certificate c : in.certs) out.append(X509Toolbox.toPem(c)).append("\n");
                ui.getIntCertForm().getCertInputTextArea().setText(out.toString());
                return;
            }
            List<Object> objs = X509Toolbox.parsePemObjects(text);
            StringBuilder out = new StringBuilder();
            int idx = 0;
            for (Object o : objs) {
                if (o instanceof X509CertificateHolder) {
                    X509Certificate cert = new JcaX509CertificateConverter()
                            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                            .getCertificate((X509CertificateHolder) o);
                    out.append("# Certificate[").append(idx++).append("]\n");
                    out.append(X509Toolbox.toPem(cert)).append("\n");
                }
            }
            if (idx == 0) throw new IllegalArgumentException("未找到 CERTIFICATE PEM 块");
            ui.getIntCertForm().getCertInputTextArea().setText(out.toString());
            CompUtil.showMsg(Boot.frame, "已拆分 PEM（仅提取 CERTIFICATE 块）");
        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, "拆分失败: " + ex.getMessage());
        }
    }

    public void intRsaCertVerifyChain() {
        try {
            ParsedInput in = parseInputBestEffort();
            if (in.certs == null || in.certs.isEmpty()) {
                throw new IllegalArgumentException("请先在输入区提供待验证的证书（leaf 或链）");
            }
            List<X509Certificate> trust = parseTrustCertificates();
            if (trust.isEmpty()) {
                throw new IllegalArgumentException("请在“信任根/中间证书(PEM，可多张)”中提供至少一张根证书（TrustAnchor）");
            }

            X509Certificate leaf = pickLeaf(in.certs);
            List<TrustAnchor> anchors = new ArrayList<>();
            for (X509Certificate c : trust) anchors.add(new TrustAnchor(c, null));

            List<X509Certificate> pool = new ArrayList<>(in.certs);
            pool.addAll(trust);
            CertStore store = CertStore.getInstance("Collection", new CollectionCertStoreParameters(pool));

            X509CertSelector selector = new X509CertSelector();
            selector.setCertificate(leaf);
            PKIXBuilderParameters params = new PKIXBuilderParameters(new HashSet<>(anchors), selector);
            params.addCertStore(store);
            params.setRevocationEnabled(false);

            CertPathBuilder builder = CertPathBuilder.getInstance("PKIX");
            PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) builder.build(params);

            StringBuilder sb = new StringBuilder();
            sb.append("链验证：通过\n");
            sb.append("TrustAnchor：").append(result.getTrustAnchor().getTrustedCert().getSubjectX500Principal().getName()).append("\n");
            sb.append("路径：\n");
            int i = 0;
            for (java.security.cert.Certificate c : result.getCertPath().getCertificates()) {
                if (c instanceof X509Certificate) {
                    sb.append("  [").append(i++).append("] ").append(((X509Certificate) c).getSubjectX500Principal().getName()).append("\n");
                }
            }
            ui.getIntCertForm().getCertInfoTextArea().setText(sb.toString());
            CompUtil.showMsg(Boot.frame, "链验证通过");
        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, "链验证失败: " + ex.getMessage());
        }
    }

    public void intRsaCertSaveInfo() {
        try {
            String path = CompUtil.saveFile(Boot.frame, "保存输出");
            if (path == null || path.trim().isEmpty()) return;
            String content = ui.getIntCertForm().getCertInfoTextArea().getText();
            if (content == null) content = "";
            Files.write(Paths.get(path), content.getBytes(StandardCharsets.UTF_8));
            CompUtil.showMsg(Boot.frame, "已保存到: " + path);
        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, "保存失败: " + ex.getMessage());
        }
    }

    public void intRsaCertExportPemFile() {
        try {
            ParsedInput in = parseInputBestEffort();
            if (in.certs == null || in.certs.isEmpty()) {
                throw new IllegalArgumentException("未识别到证书（建议先解析/加载文件）");
            }
            String path = CompUtil.saveFile(Boot.frame, "导出 PEM（证书链）");
            if (path == null || path.trim().isEmpty()) return;
            StringBuilder pem = new StringBuilder();
            for (X509Certificate c : in.certs) pem.append(X509Toolbox.toPem(c)).append("\n");
            Files.write(Paths.get(path), pem.toString().getBytes(StandardCharsets.UTF_8));
            CompUtil.showMsg(Boot.frame, "已导出 PEM 到: " + path);
        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, "导出失败: " + ex.getMessage());
        }
    }

    public void intRsaCertExportDerFile() {
        try {
            ParsedInput in = parseInputBestEffort();
            if (in.certs == null || in.certs.isEmpty()) {
                throw new IllegalArgumentException("未识别到证书（DER 导出仅支持单张证书）");
            }
            String path = CompUtil.saveFile(Boot.frame, "导出 DER（单证书）");
            if (path == null || path.trim().isEmpty()) return;
            byte[] der = in.certs.get(0).getEncoded();
            Files.write(Paths.get(path), der);
            CompUtil.showMsg(Boot.frame, "已导出 DER 到: " + path);
        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, "导出失败: " + ex.getMessage());
        }
    }

    public void intRsaCertBuildChain() {
        try {
            ParsedInput in = parseInputBestEffort();
            if (in.certs == null || in.certs.isEmpty()) {
                throw new IllegalArgumentException("请先在输入区提供待构建的证书集合（可乱序、多张）");
            }
            List<X509Certificate> trust = parseTrustCertificates();
            List<X509Certificate> pool = new ArrayList<>(in.certs);
            pool.addAll(trust);

            List<X509Certificate> chain = buildBestEffortChain(pool);
            if (chain.isEmpty()) throw new IllegalArgumentException("无法从当前证书集合构建链（可能缺少上级证书）");

            StringBuilder pem = new StringBuilder();
            for (X509Certificate c : chain) pem.append(X509Toolbox.toPem(c)).append("\n");
            ui.getIntCertForm().getCertInputTextArea().setText(pem.toString());

            StringBuilder info = new StringBuilder();
            info.append("构建链（leaf → root）：\n");
            for (int i = 0; i < chain.size(); i++) {
                X509Certificate c = chain.get(i);
                info.append("  [").append(i).append("] ").append(c.getSubjectX500Principal().getName()).append("\n");
            }
            ui.getIntCertForm().getCertInfoTextArea().setText(info.toString());
            CompUtil.showMsg(Boot.frame, "已构建并排序证书链（已回填到输入框）");
        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, "构建链失败: " + ex.getMessage());
        }
    }

    // ----------------- helpers -----------------
    private static class ParsedInput {
        List<X509Certificate> certs;
        PKCS10CertificationRequest csr;
        byte[] rawBytes;
    }

    private ParsedInput parseInputBestEffort() throws Exception {
        ParsedInput out = new ParsedInput();
        String text = ui.getIntCertForm().getCertInputTextArea().getText();
        boolean hasText = text != null && !text.trim().isEmpty();
        byte[] bytes = null;
        if (!hasText) {
            if (lastLoadedBytes == null || lastLoadedBytes.length == 0) {
                throw new IllegalArgumentException("输入不能为空（请粘贴内容或加载文件）");
            }
            bytes = lastLoadedBytes;
        }

        if (hasText && text.trim().startsWith("-----BEGIN")) {
            List<Object> objs = X509Toolbox.parsePemObjects(text);
            List<X509Certificate> certs = new ArrayList<>();
            for (Object o : objs) {
                if (o instanceof X509CertificateHolder) {
                    X509Certificate cert = new JcaX509CertificateConverter()
                            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                            .getCertificate((X509CertificateHolder) o);
                    certs.add(cert);
                } else if (o instanceof PKCS10CertificationRequest) {
                    out.csr = (PKCS10CertificationRequest) o;
                }
            }
            out.certs = certs;
            return out;
        }

        if (bytes == null) bytes = X509Toolbox.decodeTextToBytesBestEffort(text);
        out.rawBytes = bytes;

        List<X509Certificate> pkcs7Certs = X509Toolbox.parsePkcs7Certificates(bytes);
        if (!pkcs7Certs.isEmpty()) {
            out.certs = pkcs7Certs;
            return out;
        }
        List<X509Certificate> certs = X509Toolbox.parseCertificatesWithJca(bytes);
        if (!certs.isEmpty()) {
            out.certs = certs;
            return out;
        }
        out.csr = X509Toolbox.tryParseCsr(bytes);
        return out;
    }

    private byte[] pickFirstDer(ParsedInput in) throws Exception {
        if (in == null) throw new IllegalArgumentException("输入为空");
        if (in.certs != null && !in.certs.isEmpty()) return in.certs.get(0).getEncoded();
        if (in.csr != null) return in.csr.getEncoded();
        if (in.rawBytes != null && in.rawBytes.length > 0) return in.rawBytes;
        throw new IllegalArgumentException("未识别到证书/CSR/DER");
    }

    private char[] readP12Password() {
        try {
            if (ui.getIntCertForm().getP12PasswordField() == null) return null;
            char[] pwd = ui.getIntCertForm().getP12PasswordField().getPassword();
            if (pwd == null || pwd.length == 0) return null;
            return pwd;
        } catch (Exception e) {
            return null;
        }
    }

    private List<X509Certificate> parseTrustCertificates() throws Exception {
        String text = ui.getIntCertForm().getTrustPemTextArea().getText();
        if (text == null || text.trim().isEmpty()) return new ArrayList<>();
        if (!text.trim().startsWith("-----BEGIN")) {
            byte[] bytes = X509Toolbox.decodeTextToBytesBestEffort(text);
            return X509Toolbox.parseCertificatesWithJca(bytes);
        }
        List<Object> objs = X509Toolbox.parsePemObjects(text);
        List<X509Certificate> certs = new ArrayList<>();
        for (Object o : objs) {
            if (o instanceof X509CertificateHolder) {
                X509Certificate cert = new JcaX509CertificateConverter()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .getCertificate((X509CertificateHolder) o);
                certs.add(cert);
            }
        }
        return certs;
    }

    private X509Certificate pickLeaf(List<X509Certificate> certs) {
        if (certs == null || certs.isEmpty()) return null;
        for (X509Certificate c : certs) {
            if (c == null) continue;
            if (c.getBasicConstraints() == -1) return c;
        }
        return certs.get(0);
    }

    private List<X509Certificate> buildBestEffortChain(List<X509Certificate> certs) {
        Map<String, X509Certificate> bySubject = new LinkedHashMap<>();
        Set<String> allIssuers = new HashSet<>();
        for (X509Certificate c : certs) {
            if (c == null) continue;
            String subj = c.getSubjectX500Principal().getName();
            String iss = c.getIssuerX500Principal().getName();
            allIssuers.add(iss);
            bySubject.putIfAbsent(subj, c);
        }
        if (bySubject.isEmpty()) return new ArrayList<>();

        X509Certificate leaf = null;
        for (X509Certificate c : bySubject.values()) {
            String subj = c.getSubjectX500Principal().getName();
            if (!allIssuers.contains(subj) && !isSelfSigned(c)) {
                leaf = c;
                break;
            }
        }
        if (leaf == null) {
            for (X509Certificate c : bySubject.values()) {
                if (c.getBasicConstraints() == -1) {
                    leaf = c;
                    break;
                }
            }
        }
        if (leaf == null) leaf = bySubject.values().iterator().next();

        List<X509Certificate> chain = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        X509Certificate cur = leaf;
        while (cur != null) {
            String subj = cur.getSubjectX500Principal().getName();
            if (!seen.add(subj)) break;
            chain.add(cur);
            if (isSelfSigned(cur)) break;
            String iss = cur.getIssuerX500Principal().getName();
            cur = bySubject.get(iss);
        }
        return chain;
    }

    private boolean isSelfSigned(X509Certificate cert) {
        try {
            cert.verify(cert.getPublicKey());
            return cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
        } catch (Exception e) {
            return false;
        }
    }

    private static char[] promptPassword(String title) {
        JPasswordField pf = new JPasswordField();
        int ok = JOptionPane.showConfirmDialog(Boot.frame, pf, title == null ? "Password" : title, JOptionPane.OK_CANCEL_OPTION);
        if (ok != JOptionPane.OK_OPTION) return null;
        return pf.getPassword();
    }

    private static String normalizeDn(String subjectInput) {
        if (subjectInput == null) return "CN=Unknown";
        String s = subjectInput.trim();
        if (s.isEmpty()) return "CN=Unknown";
        s = s.replace('，', ',').replace('；', ';');
        if (!s.contains("=")) {
            return "CN=" + s;
        }
        return s;
    }
}


