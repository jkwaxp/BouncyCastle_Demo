package alg.bc.gui.action.international;

import alg.bc.gui.util.ByteUtil;
import alg.bc.gui.util.Logger;
import alg.bc.gui.util.Validate;
import alg.bc.internation.Des3;

public class IntlDes3Actions {
    private final InternationalViewProvider ui;

    public IntlDes3Actions(InternationalViewProvider ui) {
        this.ui = ui;
    }

    public void des3GenerateKey() throws Exception {
        try {
            Logger.logAction("des3GenerateKey", "IntlDes3Actions");
            int keySize = (Integer) ui.getIntDes3Form().getKeySizeComboBox().getSelectedItem();
            byte[] key = Des3.generateKey(keySize);
            ui.getIntDes3Form().getKeyTextArea().setText(ByteUtil.bytes2Str(key, ui.getIntDes3Form().getKeyEncodeComboBox().getSelectedItem().toString()));
        } catch (Exception ex) {
            Logger.logActionError("des3GenerateKey", "IntlDes3Actions", ex);
            throw ex;
        }
    }

    public void des3GenerateIv() {
        try {
            Logger.logAction("des3GenerateIv", "IntlDes3Actions");
            byte[] iv = new byte[8];
            new java.security.SecureRandom().nextBytes(iv);
            ui.getIntDes3Form().getIvTextArea().setText(ByteUtil.bytes2Str(iv, ui.getIntDes3Form().getIvEncodeComboBox().getSelectedItem().toString()));
        } catch (Exception ex) {
            Logger.logActionError("des3GenerateIv", "IntlDes3Actions", ex);
            throw ex;
        }
    }

    public void des3Encrypt() throws Exception {
        try {
            Logger.logAction("des3Encrypt", "IntlDes3Actions");
            byte[] key = Validate.requireBytes(ui.getIntDes3Form().getKeyTextArea().getText(), ui.getIntDes3Form().getKeyEncodeComboBox().getSelectedItem().toString(), "密钥");
            requireDes3KeyLen(key);
            byte[] input = Validate.requireBytes(ui.getIntDes3Form().getInputTextArea().getText(), ui.getIntDes3Form().getInputEncodeComboBox().getSelectedItem().toString(), "明文");
            String mode = ui.getIntDes3Form().getModeComboBox().getSelectedItem().toString(); // ECB/CBC
            byte[] out;
            if ("ECB".equals(mode)) {
                out = Des3.ecbEncPkcs7(key, input);
            } else {
                byte[] iv = Validate.requireBytes(ui.getIntDes3Form().getIvTextArea().getText(), ui.getIntDes3Form().getIvEncodeComboBox().getSelectedItem().toString(), "IV");
                Validate.requireExactLength(iv, 8, "IV");
                out = Des3.cbcEncPkcs7(key, iv, input);
            }
            ui.getIntDes3Form().getOutputTextArea().setText(ByteUtil.bytes2Str(out, ui.getIntDes3Form().getOutputEncodeComboBox().getSelectedItem().toString()));
        } catch (Exception ex) {
            Logger.logActionError("des3Encrypt", "IntlDes3Actions", ex);
            throw ex;
        }
    }

    public void des3Decrypt() throws Exception {
        try {
            Logger.logAction("des3Decrypt", "IntlDes3Actions");
            byte[] key = Validate.requireBytes(ui.getIntDes3Form().getKeyTextArea().getText(), ui.getIntDes3Form().getKeyEncodeComboBox().getSelectedItem().toString(), "密钥");
            requireDes3KeyLen(key);
            byte[] input = Validate.requireBytes(ui.getIntDes3Form().getInputTextArea().getText(), ui.getIntDes3Form().getInputEncodeComboBox().getSelectedItem().toString(), "密文");
            String mode = ui.getIntDes3Form().getModeComboBox().getSelectedItem().toString();
            byte[] out;
            if ("ECB".equals(mode)) {
                out = Des3.ecbDecPkcs7(key, input);
            } else {
                byte[] iv = Validate.requireBytes(ui.getIntDes3Form().getIvTextArea().getText(), ui.getIntDes3Form().getIvEncodeComboBox().getSelectedItem().toString(), "IV");
                Validate.requireExactLength(iv, 8, "IV");
                out = Des3.cbcDecPkcs7(key, iv, input);
            }
            ui.getIntDes3Form().getOutputTextArea().setText(ByteUtil.bytes2Str(out, ui.getIntDes3Form().getOutputEncodeComboBox().getSelectedItem().toString()));
        } catch (Exception ex) {
            Logger.logActionError("des3Decrypt", "IntlDes3Actions", ex);
            throw ex;
        }
    }

    private void requireDes3KeyLen(byte[] key) {
        if (key == null) throw new IllegalArgumentException("密钥不能为空");
        if (!(key.length == 16 || key.length == 24)) {
            throw new IllegalArgumentException("3DES 密钥长度通常为 16 或 24 字节（当前 " + key.length + " 字节）");
        }
    }
}


