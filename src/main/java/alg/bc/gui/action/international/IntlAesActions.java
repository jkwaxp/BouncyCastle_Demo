package alg.bc.gui.action.international;

import alg.bc.gui.util.ByteUtil;
import alg.bc.gui.util.Logger;
import alg.bc.gui.util.Validate;
import alg.bc.internation.AES;

public class IntlAesActions {
    private final InternationalViewProvider ui;

    public IntlAesActions(InternationalViewProvider ui) {
        this.ui = ui;
    }

    public void aesGenerateKey() throws Exception {
        try {
            Logger.logAction("aesGenerateKey", "IntlAesActions");
            int keySize = (Integer) ui.getIntAesForm().getKeySizeComboBox().getSelectedItem();
            byte[] key = AES.generateKey(keySize);
            ui.getIntAesForm().getKeyTextArea().setText(ByteUtil.bytes2Str(key, ui.getIntAesForm().getKeyEncodeComboBox().getSelectedItem().toString()));
        } catch (Exception ex) {
            Logger.logActionError("aesGenerateKey", "IntlAesActions", ex);
            throw ex;
        }
    }

    public void aesGenerateIv() {
        try {
            Logger.logAction("aesGenerateIv", "IntlAesActions");
            byte[] iv = new byte[16];
            new java.security.SecureRandom().nextBytes(iv);
            ui.getIntAesForm().getIvTextArea().setText(ByteUtil.bytes2Str(iv, ui.getIntAesForm().getIvEncodeComboBox().getSelectedItem().toString()));
        } catch (Exception ex) {
            Logger.logActionError("aesGenerateIv", "IntlAesActions", ex);
            throw ex;
        }
    }

    public void aesEncrypt() throws Exception {
        try {
            Logger.logAction("aesEncrypt", "IntlAesActions");
            byte[] key = Validate.requireBytes(ui.getIntAesForm().getKeyTextArea().getText(), ui.getIntAesForm().getKeyEncodeComboBox().getSelectedItem().toString(), "密钥");
            requireAesKeyLen(key);
            byte[] input = Validate.requireBytes(ui.getIntAesForm().getInputTextArea().getText(), ui.getIntAesForm().getInputEncodeComboBox().getSelectedItem().toString(), "明文");
            String mode = ui.getIntAesForm().getModeComboBox().getSelectedItem().toString();
            String padding = ui.getIntAesForm().getPaddingComboBox().getSelectedItem().toString();
            byte[] iv = null;
            if ("CBC".equals(mode)) {
                iv = Validate.requireBytes(ui.getIntAesForm().getIvTextArea().getText(), ui.getIntAesForm().getIvEncodeComboBox().getSelectedItem().toString(), "IV");
                Validate.requireExactLength(iv, 16, "IV");
            }
            if ("NoPadding".equals(padding)) {
                Validate.requireBlockMultiple(input, 16, "明文（NoPadding）");
            }
            String trans = "AES/" + mode + "/" + (padding.equals("PKCS7") ? "PKCS7Padding" : "NoPadding");
            byte[] out = AES.encrypt(trans, key, iv, input);
            ui.getIntAesForm().getOutputTextArea().setText(ByteUtil.bytes2Str(out, ui.getIntAesForm().getOutputEncodeComboBox().getSelectedItem().toString()));
        } catch (Exception ex) {
            Logger.logActionError("aesEncrypt", "IntlAesActions", ex);
            throw ex;
        }
    }

    public void aesDecrypt() throws Exception {
        try {
            Logger.logAction("aesDecrypt", "IntlAesActions");
            byte[] key = Validate.requireBytes(ui.getIntAesForm().getKeyTextArea().getText(), ui.getIntAesForm().getKeyEncodeComboBox().getSelectedItem().toString(), "密钥");
            requireAesKeyLen(key);
            byte[] input = Validate.requireBytes(ui.getIntAesForm().getInputTextArea().getText(), ui.getIntAesForm().getInputEncodeComboBox().getSelectedItem().toString(), "密文");
            String mode = ui.getIntAesForm().getModeComboBox().getSelectedItem().toString();
            String padding = ui.getIntAesForm().getPaddingComboBox().getSelectedItem().toString();
            byte[] iv = null;
            if ("CBC".equals(mode)) {
                iv = Validate.requireBytes(ui.getIntAesForm().getIvTextArea().getText(), ui.getIntAesForm().getIvEncodeComboBox().getSelectedItem().toString(), "IV");
                Validate.requireExactLength(iv, 16, "IV");
            }
            if ("NoPadding".equals(padding)) {
                Validate.requireBlockMultiple(input, 16, "密文（NoPadding）");
            }
            String trans = "AES/" + mode + "/" + (padding.equals("PKCS7") ? "PKCS7Padding" : "NoPadding");
            byte[] out = AES.decrypt(trans, key, iv, input);
            ui.getIntAesForm().getOutputTextArea().setText(ByteUtil.bytes2Str(out, ui.getIntAesForm().getOutputEncodeComboBox().getSelectedItem().toString()));
        } catch (Exception ex) {
            Logger.logActionError("aesDecrypt", "IntlAesActions", ex);
            throw ex;
        }
    }

    private void requireAesKeyLen(byte[] key) {
        if (key == null) throw new IllegalArgumentException("密钥不能为空");
        if (!(key.length == 16 || key.length == 24 || key.length == 32)) {
            throw new IllegalArgumentException("AES 密钥长度必须为 16/24/32 字节（当前 " + key.length + " 字节）");
        }
    }
}


