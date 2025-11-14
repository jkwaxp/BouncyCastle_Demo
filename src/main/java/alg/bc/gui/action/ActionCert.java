package alg.bc.gui.action;

import alg.bc.gui.Boot;
import alg.bc.gui.util.ByteUtil;
import alg.bc.gui.util.CompUtil;
import alg.bc.gui.view.TabCert;
import alg.bc.nation.GmCert;
import alg.bc.nation.SM2;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Hex;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;

public class ActionCert implements ActionListener {
    TabCert tabCert;

    public ActionCert(TabCert tabCert) {
        this.tabCert = tabCert;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        String cmd = e.getActionCommand();
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
            case "resetForm":
                resetForm();
                break;
            default:
                break;
        }
    }

    private void generateCsr() {
        try {
            // 获取参数
            String pubKeyHex = tabCert.getGenerateForm().getPubKeyTextArea().getText();
            String prvKeyHex = tabCert.getGenerateForm().getPrvKeyTextArea().getText();
            String subject = tabCert.getGenerateForm().getSubjectTextField().getText();

            // 转换密钥
            byte[] pubKeyBytes = Hex.decode(pubKeyHex);
            byte[] prvKeyBytes = Hex.decode(prvKeyHex);
            PublicKey publicKey = SM2.bytesToPubKey(pubKeyBytes);
            PrivateKey privateKey = SM2.bytesToPrvKey(prvKeyBytes);

            // 生成CSR
            PKCS10CertificationRequest csr = GmCert.generateCsr(publicKey, privateKey, subject);

            // 转换为PEM格式
            String csrPem = GmCert.getPemFmtStr(csr);

            // 显示结果
            tabCert.getGenerateForm().getResultTextArea().setText(csrPem);

        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, "生成CSR失败: " + ex.getMessage());
        }
    }

    private void generateSelfSigned() {
        try {
            // 获取参数
            String pubKeyHex = tabCert.getGenerateForm().getPubKeyTextArea().getText();
            String prvKeyHex = tabCert.getGenerateForm().getPrvKeyTextArea().getText();
            String subject = tabCert.getGenerateForm().getSubjectTextField().getText();

            // 转换密钥
            byte[] pubKeyBytes = Hex.decode(pubKeyHex);
            byte[] prvKeyBytes = Hex.decode(prvKeyHex);
            PublicKey publicKey = SM2.bytesToPubKey(pubKeyBytes);
            PrivateKey privateKey = SM2.bytesToPrvKey(prvKeyBytes);

            // 先生成CSR
            PKCS10CertificationRequest csr = GmCert.generateCsr(publicKey, privateKey, subject);
            String csrPem = GmCert.getPemFmtStr(csr);

            // 生成自签证书（使用根CA签名）
            X509Certificate cert = GmCert.generateCert(GmCert.CertLevel.EndEntity, csrPem);

            // 转换为PEM格式（暂时返回CSR作为示例）
            String certPem = "生成的证书：\n" + cert.toString();

            // 显示结果
            tabCert.getGenerateForm().getResultTextArea().setText(certPem);

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

            // 读取文件内容
            String content = new String(Files.readAllBytes(Paths.get(filePath)));

            // 显示到输入框
            tabCert.getViewForm().getCertInputTextArea().setText(content);

        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, "加载证书文件失败: " + ex.getMessage());
        }
    }

    private void parseCert() {
        try {
            // 获取证书PEM
            String certPem = tabCert.getViewForm().getCertInputTextArea().getText();

            // TODO: 需要实现PEM到X509的转换方法
            // 暂时显示原始PEM内容
            tabCert.getViewForm().getCertInfoTextArea().setText("证书内容：\n" + certPem + "\n\n证书解析功能待完善");

        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, "解析证书失败: " + ex.getMessage());
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
