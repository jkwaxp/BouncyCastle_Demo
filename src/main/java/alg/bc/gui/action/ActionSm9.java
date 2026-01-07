package alg.bc.gui.action;

import alg.bc.gui.Boot;
import alg.bc.gui.util.ByteUtil;
import alg.bc.gui.util.CompUtil;
import alg.bc.gui.util.Logger;
import alg.bc.gui.util.Validate;
import alg.bc.gui.view.TabSm9;
import alg.bc.nation.sm9.Sm9;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

/**
 * SM9（JNI）动作处理。
 *
 * 注意：若 sm9jni.dll 不存在/未加载，会给出明确提示。
 */
public class ActionSm9 implements ActionListener {

    private final TabSm9 tab;

    public ActionSm9(TabSm9 tab) {
        this.tab = tab;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        String cmd = e.getActionCommand();
        Logger.logAction(cmd, "ActionSm9");
        try {
            switch (cmd) {
                case "sm9GenEncMaster":
                    genMaster(Sm9.PURPOSE_ENC);
                    break;
                case "sm9GenSignMaster":
                    genMaster(Sm9.PURPOSE_SIGN);
                    break;
                case "sm9DeriveEncSk":
                    deriveUserSk(Sm9.PURPOSE_ENC);
                    break;
                case "sm9DeriveSignSk":
                    deriveUserSk(Sm9.PURPOSE_SIGN);
                    break;
                case "sm9Encrypt":
                    doEncrypt();
                    break;
                case "sm9Decrypt":
                    doDecrypt();
                    break;
                case "sm9Sign":
                    doSign();
                    break;
                case "sm9Verify":
                    doVerify();
                    break;
                default:
                    break;
            }
        } catch (Exception ex) {
            Logger.logActionError(cmd, "ActionSm9", ex);
            throw ex;
        }
    }

    private void genMaster(int purpose) {
        byte[][] kp = Sm9.kgcGenerateMasterKeyPair(purpose);
        if (kp == null || kp.length < 2) {
            throw new IllegalStateException("KGC 返回主密钥对为空");
        }
        byte[] msk = kp[0];
        byte[] mpk = kp[1];

        String enc = String.valueOf(tab.getKeyEncodeComboBox().getSelectedItem());
        String mskStr = ByteUtil.bytes2Str(msk, enc);
        String mpkStr = ByteUtil.bytes2Str(mpk, enc);

        if (purpose == Sm9.PURPOSE_ENC) {
            tab.getMskEncTextArea().setText(mskStr);
            tab.getMpkEncTextArea().setText(mpkStr);
        } else {
            tab.getMskSignTextArea().setText(mskStr);
            tab.getMpkSignTextArea().setText(mpkStr);
        }
    }

    private void deriveUserSk(int purpose) {
        String enc = String.valueOf(tab.getKeyEncodeComboBox().getSelectedItem());
        String userId = Validate.requireNotBlank(tab.getKgcUserIdTextField().getText(), "用户ID");

        byte[] msk;
        if (purpose == Sm9.PURPOSE_ENC) {
            msk = Validate.requireBytes(tab.getMskEncTextArea().getText(), enc, "加密主密钥(mskEnc)");
        } else {
            msk = Validate.requireBytes(tab.getMskSignTextArea().getText(), enc, "签名主密钥(mskSign)");
        }

        byte[] sk = Sm9.kgcDeriveUserPrivateKey(purpose, msk, userId);
        String skStr = ByteUtil.bytes2Str(sk, enc);
        if (purpose == Sm9.PURPOSE_ENC) {
            tab.getSkEncTextArea().setText(skStr);
        } else {
            tab.getSkSignTextArea().setText(skStr);
        }
    }

    private void doEncrypt() {
        String keyEnc = String.valueOf(tab.getKeyEncodeComboBox().getSelectedItem());
        byte[] mpkEnc = Validate.requireBytes(tab.getEncryptMpkEncTextArea().getText(), keyEnc, "加密主公钥(mpkEnc)");
        String recvId = Validate.requireNotBlank(tab.getCipherUserIdTextField().getText(), "接收方ID");

        String inEnc = String.valueOf(tab.getPlainEncodeComboBox().getSelectedItem());
        byte[] plain = Validate.requireBytes(tab.getPlainTextArea().getText(), inEnc, "明文");

        byte[] ct = Sm9.encrypt(mpkEnc, recvId, plain);
        String outEnc = String.valueOf(tab.getCipherEncodeComboBox().getSelectedItem());
        tab.getCipherTextArea().setText(ByteUtil.bytes2Str(ct, outEnc));
    }

    private void doDecrypt() {
        String keyEnc = String.valueOf(tab.getKeyEncodeComboBox().getSelectedItem());
        byte[] skEnc = Validate.requireBytes(tab.getDecryptSkEncTextArea().getText(), keyEnc, "用户加密私钥(skEnc)");
        String recvId = Validate.requireNotBlank(tab.getCipherUserIdTextField().getText(), "接收方ID");

        String ctEnc = String.valueOf(tab.getCipherEncodeComboBox().getSelectedItem());
        byte[] ct = Validate.requireBytes(tab.getCipherTextArea().getText(), ctEnc, "密文");

        byte[] pt = Sm9.decrypt(skEnc, recvId, ct);
        String outEnc = String.valueOf(tab.getPlainEncodeComboBox().getSelectedItem());
        tab.getPlainTextArea().setText(ByteUtil.bytes2Str(pt, outEnc));
    }

    private void doSign() {
        String keyEnc = String.valueOf(tab.getKeyEncodeComboBox().getSelectedItem());
        byte[] skSign = Validate.requireBytes(tab.getSignSkSignTextArea().getText(), keyEnc, "用户签名私钥(skSign)");
        String signerId = Validate.requireNotBlank(tab.getSignUserIdTextField().getText(), "签名者ID");

        String msgEnc = String.valueOf(tab.getMsgEncodeComboBox().getSelectedItem());
        byte[] msg = Validate.requireBytes(tab.getMsgTextArea().getText(), msgEnc, "待签名数据");

        byte[] sig = Sm9.sign(skSign, signerId, msg);
        String sigEnc = String.valueOf(tab.getSigEncodeComboBox().getSelectedItem());
        tab.getSigTextArea().setText(ByteUtil.bytes2Str(sig, sigEnc));
    }

    private void doVerify() {
        String keyEnc = String.valueOf(tab.getKeyEncodeComboBox().getSelectedItem());
        byte[] mpkSign = Validate.requireBytes(tab.getVerifyMpkSignTextArea().getText(), keyEnc, "签名主公钥(mpkSign)");
        String signerId = Validate.requireNotBlank(tab.getSignUserIdTextField().getText(), "签名者ID");

        String msgEnc = String.valueOf(tab.getMsgEncodeComboBox().getSelectedItem());
        byte[] msg = Validate.requireBytes(tab.getMsgTextArea().getText(), msgEnc, "待验签数据");

        String sigEnc = String.valueOf(tab.getSigEncodeComboBox().getSelectedItem());
        byte[] sig = Validate.requireBytes(tab.getSigTextArea().getText(), sigEnc, "签名值");

        boolean ok = Sm9.verify(mpkSign, signerId, msg, sig);
        CompUtil.showMsg(Boot.frame, "验签结果", ok ? "通过" : "不通过");
    }
}
