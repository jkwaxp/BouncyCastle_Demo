package alg.bc.gui.action;

import alg.bc.gui.Boot;
import alg.bc.gui.util.CompUtil;
import alg.bc.gui.util.Logger;
import alg.bc.gui.util.Validate;
import alg.bc.gui.util.X509Toolbox;
import alg.bc.gui.view.TabCert;
import alg.bc.nation.GmCert;
import alg.bc.nation.SM2;
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

import javax.security.auth.x500.X500Principal;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class ActionCert implements ActionListener {
    TabCert tabCert;
    private byte[] lastLoadedBytes;
    private String lastLoadedPath;

    public ActionCert(TabCert tabCert) {
        this.tabCert = tabCert;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        String cmd = e.getActionCommand();
        Logger.logAction(cmd, "ActionCert");
        try {
            switch (cmd) {
                case "generateCsr":
                    generateCsr();
                    break;
                case "generateSelfSigned":
                    generateSelfSigned();
                    break;
                case "parseCert":
                    parseCert();
                    break;
                case "loadCertFile":
                    loadCertFile();
                    break;
                case "certToPem":
                    certToPem();
                    break;
                case "certToDerBase64":
                    certToDerBase64();
                    break;
                case "certToDerHex":
                    certToDerHex();
                    break;
                case "certSplitPem":
                    certSplitPem();
                    break;
                case "certVerifyChain":
                    certVerifyChain();
                    break;
                case "certSaveInfo":
                    certSaveInfo();
                    break;
                case "certExportPemFile":
                    certExportPemFile();
                    break;
                case "certExportDerFile":
                    certExportDerFile();
                    break;
                case "certBuildChain":
                    certBuildChain();
                    break;
                case "resetForm":
                    resetForm();
                    break;
                default:
                    Logger.debug("未知的命令: " + cmd);
                    break;
            }
        } catch (Exception ex) {
            Logger.logActionError(cmd, "ActionCert", ex);
            throw ex;
        }
    }

    private void generateCsr() {
        try {
            // 获取参数
            String pubKeyHex = tabCert.getGenerateForm().getPubKeyTextArea().getText();
            String prvKeyHex = tabCert.getGenerateForm().getPrvKeyTextArea().getText();
            String subject = tabCert.getGenerateForm().getSubjectTextField().getText();

            // 转换密钥
            Validate.requireNotBlank(subject, "证书Subject");
            byte[] pubKeyBytes = Validate.requireSm2PublicKey(pubKeyHex, "HEX", "公钥（HEX）");
            byte[] prvKeyBytes = Validate.requireSm2PrivateKey(prvKeyHex, "HEX", "私钥（HEX）");
            PublicKey publicKey = SM2.bytesToPubKey(pubKeyBytes);
            PrivateKey privateKey = SM2.bytesToPrvKey(prvKeyBytes);

            // 生成CSR
            String dn = normalizeDn(subject);
            ContentSigner signer = new JcaContentSignerBuilder("SM3withSM2")
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(privateKey);
            PKCS10CertificationRequest csr = new JcaPKCS10CertificationRequestBuilder(
                    new X500Principal(dn), publicKey)
                    .build(signer);

            // 转换为PEM格式
            String csrPem = GmCert.getPemFmtStr(csr);

            // 显示结果
            tabCert.getGenerateForm().getResultTextArea().setText(csrPem + "\n" + X509Toolbox.describeCsr(csr));

        } catch (Exception ex) {
            String errMsg = ex.getMessage();
            if (errMsg == null || errMsg.trim().isEmpty()) {
                errMsg = ex.getClass().getSimpleName() + ": " + ex.toString();
            }
            CompUtil.showErr(Boot.frame, "生成CSR失败: " + errMsg);
        }
    }

    private void generateSelfSigned() {
        try {
            // 获取参数
            String pubKeyHex = tabCert.getGenerateForm().getPubKeyTextArea().getText();
            String prvKeyHex = tabCert.getGenerateForm().getPrvKeyTextArea().getText();
            String subject = tabCert.getGenerateForm().getSubjectTextField().getText();

            // 转换密钥
            Validate.requireNotBlank(subject, "证书Subject");
            byte[] pubKeyBytes = Validate.requireSm2PublicKey(pubKeyHex, "HEX", "公钥（HEX）");
            byte[] prvKeyBytes = Validate.requireSm2PrivateKey(prvKeyHex, "HEX", "私钥（HEX）");
            PublicKey publicKey = SM2.bytesToPubKey(pubKeyBytes);
            PrivateKey privateKey = SM2.bytesToPrvKey(prvKeyBytes);

            // 生成真正的“自签证书”（issuer == subject，使用输入私钥签名）
            String dn = normalizeDn(subject);
            X500Name x500Name = new X500Name(dn);
            BigInteger serial = new BigInteger(160, new SecureRandom()).abs();
            Date notBefore = new Date(System.currentTimeMillis() - 5L * 60 * 1000);
            Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);

            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
            X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                    x500Name, serial, notBefore, notAfter, x500Name, spki);
            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            builder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(spki));
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            builder.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyAgreement | KeyUsage.keyEncipherment
                            | KeyUsage.dataEncipherment));

            ContentSigner signer = new JcaContentSignerBuilder("SM3withSM2")
                    .setProvider(org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME)
                    .build(privateKey);
            X509CertificateHolder holder = builder.build(signer);
            X509Certificate cert = new JcaX509CertificateConverter()
                    .setProvider(org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(holder);
            cert.verify(publicKey);

            String certPem = X509Toolbox.toPem(cert);
            String keyPem = X509Toolbox.toPem(privateKey);

            // 显示结果
            tabCert.getGenerateForm().getResultTextArea().setText(
                    certPem +
                            "\n# ---- Private Key (PKCS#8) ----\n" +
                            keyPem +
                            "\n" +
                            X509Toolbox.describeCertificate(cert));

        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, "生成自签证书失败: " + ex.getMessage());
        }
    }

    private void loadCertFile() {
        try {
            // 选择文件
            String filePath = CompUtil.chooseFile(Boot.frame, "选择证书文件");
            if (filePath == null || filePath.isEmpty()) {
                return;
            }

            byte[] bytes = Files.readAllBytes(Paths.get(filePath));
            lastLoadedBytes = bytes;
            lastLoadedPath = filePath;

            // 尽量友好展示：PEM 直接显示；二进制内容用 Base64 展示（便于复制/粘贴解析）
            String asText = new String(bytes, StandardCharsets.UTF_8);
            if (asText.contains("-----BEGIN")) {
                tabCert.getViewForm().getCertInputTextArea().setText(asText);
            } else {
                String b64 = java.util.Base64.getMimeEncoder(64, new byte[] { '\n' }).encodeToString(bytes);
                tabCert.getViewForm().getCertInputTextArea().setText(b64);
                CompUtil.showMsg(Boot.frame, "提示", "已加载二进制文件，已以 BASE64 形式显示（点击“解析证书”即可自动识别）");
            }

        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, "加载证书文件失败: " + ex.getMessage());
        }
    }

    private void parseCert() {
        try {
            String text = tabCert.getViewForm().getCertInputTextArea().getText();
            byte[] bytes = null;
            boolean hasText = text != null && !text.trim().isEmpty();
            if (!hasText) {
                if (lastLoadedBytes == null || lastLoadedBytes.length == 0) {
                    throw new IllegalArgumentException("证书内容不能为空");
                }
                bytes = lastLoadedBytes;
            }

            StringBuilder sb = new StringBuilder();
            sb.append("=== X.509 工具箱解析结果 ===\n");
            if (lastLoadedPath != null && !lastLoadedPath.trim().isEmpty()) {
                sb.append("来源文件：").append(lastLoadedPath).append("\n");
            }

            if (hasText && text.trim().startsWith("-----BEGIN")) {
                // PEM：可能包含多段（CERTIFICATE/CSR/PKCS7/PRIVATE KEY 等）
                sb.append("输入类型：PEM\n\n");
                java.util.List<Object> objs = X509Toolbox.parsePemObjects(text);
                if (objs.isEmpty()) {
                    throw new IllegalArgumentException("未识别到任何 PEM 块（请确认包含 -----BEGIN/END-----）");
                }

                int idx = 0;
                for (Object o : objs) {
                    sb.append("## 块 ").append(idx++).append("：").append(o.getClass().getSimpleName()).append("\n");
                    if (o instanceof org.bouncycastle.cert.X509CertificateHolder) {
                        X509Certificate cert = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                                .setProvider(org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME)
                                .getCertificate((org.bouncycastle.cert.X509CertificateHolder) o);
                        sb.append(X509Toolbox.describeCertificate(cert)).append("\n");
                        sb.append("PEM：\n").append(X509Toolbox.toPem(cert)).append("\n");
                    } else if (o instanceof PKCS10CertificationRequest) {
                        PKCS10CertificationRequest csr = (PKCS10CertificationRequest) o;
                        sb.append(X509Toolbox.describeCsr(csr)).append("\n");
                        sb.append("PEM：\n").append(GmCert.getPemFmtStr(csr)).append("\n");
                    } else {
                        // 其它类型先不强行格式化，至少让用户看到识别结果
                        sb.append(String.valueOf(o)).append("\n\n");
                    }
                }
            } else {
                if (bytes == null) {
                    bytes = X509Toolbox.decodeTextToBytesBestEffort(text);
                }
                sb.append("输入类型：DER/BASE64/HEX/二进制（自动识别）\n");
                sb.append("输入字节数：").append(bytes.length).append("\n\n");

                // 1) PKCS#7
                java.util.List<X509Certificate> pkcs7Certs = X509Toolbox.parsePkcs7Certificates(bytes);
                if (!pkcs7Certs.isEmpty()) {
                    sb.append("检测到：PKCS#7/CMS SignedData\n");
                    sb.append("证书数量：").append(pkcs7Certs.size()).append("\n\n");
                    for (int i = 0; i < pkcs7Certs.size(); i++) {
                        sb.append("## Certificate[").append(i).append("]\n");
                        sb.append(X509Toolbox.describeCertificate(pkcs7Certs.get(i))).append("\n");
                    }
                    tabCert.getViewForm().getCertInfoTextArea().setText(sb.toString());
                    return;
                }

                // 2) X.509 证书（单证或多证）
                java.util.List<X509Certificate> certs = X509Toolbox.parseCertificatesWithJca(bytes);
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
                    tabCert.getViewForm().getCertInfoTextArea().setText(sb.toString());
                    return;
                }

                // 3) CSR
                PKCS10CertificationRequest csr = X509Toolbox.tryParseCsr(bytes);
                if (csr != null) {
                    sb.append("检测到：CSR (PKCS#10)\n\n");
                    sb.append(X509Toolbox.describeCsr(csr)).append("\n");
                    sb.append("PEM：\n").append(GmCert.getPemFmtStr(csr)).append("\n");
                    tabCert.getViewForm().getCertInfoTextArea().setText(sb.toString());
                    return;
                }

                // 4) PKCS#12（必要时提示密码）
                boolean maybeP12 = (lastLoadedPath != null)
                        && lastLoadedPath.toLowerCase(Locale.ROOT).matches(".*\\.(p12|pfx)$");
                if (maybeP12) {
                    char[] presetPwd = readP12Password();
                    KeyStore ks = (presetPwd == null) ? X509Toolbox.tryLoadPkcs12(bytes, new char[0])
                            : X509Toolbox.tryLoadPkcs12(bytes, presetPwd);
                    if (ks == null) {
                        char[] pwd = promptPassword("请输入 PKCS#12 口令（p12/pfx）：");
                        if (pwd != null)
                            ks = X509Toolbox.tryLoadPkcs12(bytes, pwd);
                    }
                    if (ks != null) {
                        sb.append(X509Toolbox.describeKeyStorePkcs12(ks)).append("\n");
                        tabCert.getViewForm().getCertInfoTextArea().setText(sb.toString());
                        return;
                    }
                }

                sb.append("未识别输入内容：目前支持 X.509/CSR/PKCS#7（p7b）以及通过文件扩展名识别 PKCS#12（p12/pfx）。\n");
                sb.append("建议：如果是 p12/pfx，请使用“加载文件”导入；如果是 DER，请尝试先转为 BASE64 再粘贴。\n");
            }

            tabCert.getViewForm().getCertInfoTextArea().setText(sb.toString());

        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, "解析证书失败: " + ex.getMessage());
        }
    }

    private void certToPem() {
        try {
            ParsedInput in = parseInputBestEffort();
            if (in.certs != null && !in.certs.isEmpty()) {
                StringBuilder out = new StringBuilder();
                for (X509Certificate c : in.certs) {
                    out.append(X509Toolbox.toPem(c)).append("\n");
                }
                tabCert.getViewForm().getCertInputTextArea().setText(out.toString());
                CompUtil.showMsg(Boot.frame, "已转换为 PEM（证书可多张）");
                return;
            }
            if (in.csr != null) {
                String csrPem = GmCert.getPemFmtStr(in.csr);
                tabCert.getViewForm().getCertInputTextArea().setText(csrPem);
                CompUtil.showMsg(Boot.frame, "已转换为 CSR PEM");
                return;
            }
            throw new IllegalArgumentException("未识别到证书/CSR，无法转换为 PEM");
        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, "转换失败: " + ex.getMessage());
        }
    }

    private void certToDerBase64() {
        try {
            ParsedInput in = parseInputBestEffort();
            byte[] der = pickFirstDer(in);
            String b64 = java.util.Base64.getMimeEncoder(64, new byte[] { '\n' }).encodeToString(der);
            tabCert.getViewForm().getCertInputTextArea().setText(b64);
            CompUtil.showMsg(Boot.frame, "已输出 DER(Base64)");
        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, "转换失败: " + ex.getMessage());
        }
    }

    private void certToDerHex() {
        try {
            ParsedInput in = parseInputBestEffort();
            byte[] der = pickFirstDer(in);
            tabCert.getViewForm().getCertInputTextArea().setText(org.bouncycastle.util.encoders.Hex.toHexString(der));
            CompUtil.showMsg(Boot.frame, "已输出 DER(HEX)");
        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, "转换失败: " + ex.getMessage());
        }
    }

    private void certSplitPem() {
        try {
            String text = tabCert.getViewForm().getCertInputTextArea().getText();
            if (text == null || text.trim().isEmpty())
                throw new IllegalArgumentException("输入不能为空");
            if (!text.trim().startsWith("-----BEGIN")) {
                // 非 PEM：先解析成证书并输出 pem bundle
                ParsedInput in = parseInputBestEffort();
                if (in.certs == null || in.certs.isEmpty())
                    throw new IllegalArgumentException("未识别到证书，无法拆分");
                StringBuilder out = new StringBuilder();
                for (X509Certificate c : in.certs)
                    out.append(X509Toolbox.toPem(c)).append("\n");
                tabCert.getViewForm().getCertInputTextArea().setText(out.toString());
                return;
            }
            List<Object> objs = X509Toolbox.parsePemObjects(text);
            StringBuilder out = new StringBuilder();
            int idx = 0;
            for (Object o : objs) {
                if (o instanceof org.bouncycastle.cert.X509CertificateHolder) {
                    X509Certificate cert = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                            .setProvider(org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME)
                            .getCertificate((org.bouncycastle.cert.X509CertificateHolder) o);
                    out.append("# Certificate[").append(idx++).append("]\n");
                    out.append(X509Toolbox.toPem(cert)).append("\n");
                }
            }
            if (idx == 0)
                throw new IllegalArgumentException("未找到 CERTIFICATE PEM 块");
            tabCert.getViewForm().getCertInputTextArea().setText(out.toString());
            CompUtil.showMsg(Boot.frame, "已拆分 PEM（仅提取 CERTIFICATE 块）");
        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, "拆分失败: " + ex.getMessage());
        }
    }

    private void certVerifyChain() {
        try {
            ParsedInput in = parseInputBestEffort();
            if (in.certs == null || in.certs.isEmpty()) {
                throw new IllegalArgumentException("请先在输入区提供待验证的证书（leaf 或链）");
            }
            List<X509Certificate> trust = parseTrustCertificates();
            if (trust.isEmpty()) {
                throw new IllegalArgumentException("请在“信任根/中间证书(PEM)”中提供至少一张根证书（TrustAnchor）");
            }

            X509Certificate leaf = pickLeaf(in.certs);
            List<TrustAnchor> anchors = new ArrayList<>();
            for (X509Certificate c : trust)
                anchors.add(new TrustAnchor(c, null));

            // 可用证书池：输入证书 + trust（中间也可放这里）
            List<X509Certificate> pool = new ArrayList<>(in.certs);
            pool.addAll(trust);
            CertStore store = CertStore.getInstance("Collection", new CollectionCertStoreParameters(pool));

            X509CertSelector selector = new X509CertSelector();
            selector.setCertificate(leaf);
            PKIXBuilderParameters params = new PKIXBuilderParameters(new java.util.HashSet<>(anchors), selector);
            params.addCertStore(store);
            params.setRevocationEnabled(false);

            CertPathBuilder builder = CertPathBuilder.getInstance("PKIX");
            PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) builder.build(params);

            StringBuilder sb = new StringBuilder();
            sb.append("链验证：通过\n");
            sb.append("TrustAnchor：")
                    .append(result.getTrustAnchor().getTrustedCert().getSubjectX500Principal().getName()).append("\n");
            sb.append("路径：\n");
            int i = 0;
            for (Certificate c : result.getCertPath().getCertificates()) {
                if (c instanceof X509Certificate) {
                    sb.append("  [").append(i++).append("] ")
                            .append(((X509Certificate) c).getSubjectX500Principal().getName()).append("\n");
                }
            }
            tabCert.getViewForm().getCertInfoTextArea().setText(sb.toString());
            CompUtil.showMsg(Boot.frame, "链验证通过");
        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, "链验证失败: " + ex.getMessage());
        }
    }

    private void certSaveInfo() {
        try {
            String path = CompUtil.saveFile(Boot.frame, "保存输出");
            if (path == null || path.trim().isEmpty())
                return;
            String content = tabCert.getViewForm().getCertInfoTextArea().getText();
            if (content == null)
                content = "";
            Files.write(Paths.get(path), content.getBytes(StandardCharsets.UTF_8));
            CompUtil.showMsg(Boot.frame, "已保存到: " + path);
        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, "保存失败: " + ex.getMessage());
        }
    }

    private void certExportPemFile() {
        try {
            ParsedInput in = parseInputBestEffort();
            if (in.certs == null || in.certs.isEmpty()) {
                throw new IllegalArgumentException("未识别到证书（建议先解析/加载文件）");
            }
            String path = CompUtil.saveFile(Boot.frame, "导出 PEM（证书链）");
            if (path == null || path.trim().isEmpty())
                return;
            StringBuilder pem = new StringBuilder();
            for (X509Certificate c : in.certs) {
                pem.append(X509Toolbox.toPem(c)).append("\n");
            }
            Files.write(Paths.get(path), pem.toString().getBytes(StandardCharsets.UTF_8));
            CompUtil.showMsg(Boot.frame, "已导出 PEM 到: " + path);
        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, "导出失败: " + ex.getMessage());
        }
    }

    private void certExportDerFile() {
        try {
            ParsedInput in = parseInputBestEffort();
            if (in.certs == null || in.certs.isEmpty()) {
                throw new IllegalArgumentException("未识别到证书（DER 导出仅支持单张证书）");
            }
            String path = CompUtil.saveFile(Boot.frame, "导出 DER（单证书）");
            if (path == null || path.trim().isEmpty())
                return;
            byte[] der = in.certs.get(0).getEncoded();
            Files.write(Paths.get(path), der);
            CompUtil.showMsg(Boot.frame, "已导出 DER 到: " + path);
        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, "导出失败: " + ex.getMessage());
        }
    }

    private void certBuildChain() {
        try {
            ParsedInput in = parseInputBestEffort();
            if (in.certs == null || in.certs.isEmpty()) {
                throw new IllegalArgumentException("请先在输入区提供待构建的证书集合（可乱序、多张）");
            }
            List<X509Certificate> trust = parseTrustCertificates();
            List<X509Certificate> pool = new ArrayList<>(in.certs);
            pool.addAll(trust);

            List<X509Certificate> chain = buildBestEffortChain(pool);
            if (chain.isEmpty())
                throw new IllegalArgumentException("无法从当前证书集合构建链（可能缺少上级证书）");

            StringBuilder pem = new StringBuilder();
            for (X509Certificate c : chain)
                pem.append(X509Toolbox.toPem(c)).append("\n");
            tabCert.getViewForm().getCertInputTextArea().setText(pem.toString());

            StringBuilder info = new StringBuilder();
            info.append("构建链（leaf → root）：\n");
            for (int i = 0; i < chain.size(); i++) {
                X509Certificate c = chain.get(i);
                info.append("  [").append(i).append("] ").append(c.getSubjectX500Principal().getName()).append("\n");
            }
            tabCert.getViewForm().getCertInfoTextArea().setText(info.toString());
            CompUtil.showMsg(Boot.frame, "已构建并排序证书链（已回填到输入框）");
        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, "构建链失败: " + ex.getMessage());
        }
    }

    private List<X509Certificate> buildBestEffortChain(List<X509Certificate> certs) {
        // subject->cert（同 subject 可能多张：取第一张）
        java.util.Map<String, X509Certificate> bySubject = new java.util.LinkedHashMap<>();
        java.util.Set<String> allIssuers = new java.util.HashSet<>();
        for (X509Certificate c : certs) {
            if (c == null)
                continue;
            String subj = c.getSubjectX500Principal().getName();
            String iss = c.getIssuerX500Principal().getName();
            allIssuers.add(iss);
            bySubject.putIfAbsent(subj, c);
        }
        if (bySubject.isEmpty())
            return new ArrayList<>();

        // leaf：subject 不作为任何人的 issuer，优先；否则随便选一个非 CA；再否则任意
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
        if (leaf == null)
            leaf = bySubject.values().iterator().next();

        List<X509Certificate> chain = new ArrayList<>();
        java.util.Set<String> seen = new java.util.HashSet<>();
        X509Certificate cur = leaf;
        while (cur != null) {
            String subj = cur.getSubjectX500Principal().getName();
            if (!seen.add(subj))
                break;
            chain.add(cur);
            if (isSelfSigned(cur))
                break;
            String issuer = cur.getIssuerX500Principal().getName();
            cur = bySubject.get(issuer);
        }
        return chain;
    }

    private boolean isSelfSigned(X509Certificate cert) {
        try {
            if (cert == null)
                return false;
            return cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
        } catch (Exception ignored) {
            return false;
        }
    }

    private static class ParsedInput {
        List<X509Certificate> certs;
        PKCS10CertificationRequest csr;
    }

    private ParsedInput parseInputBestEffort() throws Exception {
        ParsedInput out = new ParsedInput();
        String text = tabCert.getViewForm().getCertInputTextArea().getText();
        boolean hasText = text != null && !text.trim().isEmpty();

        if (hasText && text.trim().startsWith("-----BEGIN")) {
            List<Object> objs = X509Toolbox.parsePemObjects(text);
            List<X509Certificate> certs = new ArrayList<>();
            for (Object o : objs) {
                if (o instanceof org.bouncycastle.cert.X509CertificateHolder) {
                    X509Certificate cert = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                            .setProvider(org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME)
                            .getCertificate((org.bouncycastle.cert.X509CertificateHolder) o);
                    certs.add(cert);
                } else if (o instanceof PKCS10CertificationRequest) {
                    out.csr = (PKCS10CertificationRequest) o;
                }
            }
            out.certs = certs;
            return out;
        }

        byte[] bytes = null;
        if (!hasText) {
            bytes = lastLoadedBytes;
        } else {
            bytes = X509Toolbox.decodeTextToBytesBestEffort(text);
        }
        if (bytes == null || bytes.length == 0)
            throw new IllegalArgumentException("输入不能为空");

        // PKCS#7
        List<X509Certificate> pkcs7 = X509Toolbox.parsePkcs7Certificates(bytes);
        if (!pkcs7.isEmpty()) {
            out.certs = pkcs7;
            return out;
        }

        // X.509
        List<X509Certificate> certs = X509Toolbox.parseCertificatesWithJca(bytes);
        if (!certs.isEmpty()) {
            out.certs = certs;
            return out;
        }

        // CSR
        PKCS10CertificationRequest csr = X509Toolbox.tryParseCsr(bytes);
        if (csr != null) {
            out.csr = csr;
            return out;
        }

        // PKCS#12（仅在文件扩展名匹配时尝试）
        boolean maybeP12 = (lastLoadedPath != null)
                && lastLoadedPath.toLowerCase(Locale.ROOT).matches(".*\\.(p12|pfx)$");
        if (maybeP12) {
            char[] preset = readP12Password();
            KeyStore ks = (preset == null) ? X509Toolbox.tryLoadPkcs12(bytes, new char[0])
                    : X509Toolbox.tryLoadPkcs12(bytes, preset);
            if (ks == null) {
                char[] pwd = promptPassword("请输入 PKCS#12 口令（p12/pfx）：");
                if (pwd != null)
                    ks = X509Toolbox.tryLoadPkcs12(bytes, pwd);
            }
            if (ks != null) {
                // 尽量从 keystore 抽证书
                List<X509Certificate> ksCerts = new ArrayList<>();
                java.util.Enumeration<String> aliases = ks.aliases();
                while (aliases.hasMoreElements()) {
                    String a = aliases.nextElement();
                    Certificate c = ks.getCertificate(a);
                    if (c instanceof X509Certificate)
                        ksCerts.add((X509Certificate) c);
                    Certificate[] chain = ks.getCertificateChain(a);
                    if (chain != null) {
                        for (Certificate cc : chain) {
                            if (cc instanceof X509Certificate)
                                ksCerts.add((X509Certificate) cc);
                        }
                    }
                }
                out.certs = ksCerts;
                return out;
            }
        }

        throw new IllegalArgumentException("未识别输入内容（当前支持 X.509/CSR/PKCS#7/PKCS#12）");
    }

    private byte[] pickFirstDer(ParsedInput in) throws Exception {
        if (in.certs != null && !in.certs.isEmpty()) {
            return in.certs.get(0).getEncoded();
        }
        if (in.csr != null) {
            return in.csr.getEncoded();
        }
        throw new IllegalArgumentException("未识别到证书/CSR");
    }

    private char[] readP12Password() {
        try {
            if (tabCert.getViewForm().getP12PasswordField() == null)
                return null;
            char[] pwd = tabCert.getViewForm().getP12PasswordField().getPassword();
            if (pwd == null || pwd.length == 0)
                return null;
            return pwd;
        } catch (Exception ignored) {
            return null;
        }
    }

    private List<X509Certificate> parseTrustCertificates() throws Exception {
        String trustText = tabCert.getViewForm().getTrustPemTextArea().getText();
        if (trustText == null || trustText.trim().isEmpty())
            return new ArrayList<>();
        byte[] bytes = X509Toolbox.decodeTextToBytesBestEffort(trustText);
        List<X509Certificate> certs = X509Toolbox.parseCertificatesWithJca(bytes);
        if (!certs.isEmpty())
            return certs;
        // 如果是 PEM 多段，用 PEMParser 抽证书
        if (trustText.trim().startsWith("-----BEGIN")) {
            List<Object> objs = X509Toolbox.parsePemObjects(trustText);
            List<X509Certificate> out = new ArrayList<>();
            for (Object o : objs) {
                if (o instanceof org.bouncycastle.cert.X509CertificateHolder) {
                    X509Certificate cert = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                            .setProvider(org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME)
                            .getCertificate((org.bouncycastle.cert.X509CertificateHolder) o);
                    out.add(cert);
                }
            }
            return out;
        }
        return new ArrayList<>();
    }

    private X509Certificate pickLeaf(List<X509Certificate> certs) {
        for (X509Certificate c : certs) {
            if (c.getBasicConstraints() == -1)
                return c;
        }
        return certs.get(0);
    }

    private static String normalizeDn(String subjectInput) {
        String s = subjectInput == null ? "" : subjectInput.trim();
        if (s.isEmpty())
            return "CN=Test";
        // 用户可能输入：example.com（当作 CN）；也可能输入：CN=xxx,O=...（完整 DN）
        if (s.contains("="))
            return s;
        return "CN=" + s;
    }

    private static char[] promptPassword(String title) {
        try {
            javax.swing.JPasswordField pf = new javax.swing.JPasswordField();
            int ok = javax.swing.JOptionPane.showConfirmDialog(Boot.frame, pf, title,
                    javax.swing.JOptionPane.OK_CANCEL_OPTION, javax.swing.JOptionPane.PLAIN_MESSAGE);
            if (ok != javax.swing.JOptionPane.OK_OPTION)
                return null;
            return pf.getPassword();
        } catch (Exception ignored) {
            return null;
        }
    }

    private void resetForm() {
        if (tabCert.getGenerateForm().$$$getRootComponent$$$().isShowing()) {
            tabCert.getGenerateForm().getPubKeyTextArea().setText("");
            tabCert.getGenerateForm().getPrvKeyTextArea().setText("");
            tabCert.getGenerateForm().getSubjectTextField().setText("test.example.com");
            tabCert.getGenerateForm().getResultTextArea().setText("");
        } else if (tabCert.getViewForm().$$$getRootComponent$$$().isShowing()) {
            tabCert.getViewForm().getCertInputTextArea().setText("");
            tabCert.getViewForm().getCertInfoTextArea().setText("");
        }
    }
}
