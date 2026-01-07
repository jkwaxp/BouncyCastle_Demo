package alg.bc.gui.action.international;

import alg.bc.gui.Boot;
import alg.bc.gui.util.ByteUtil;
import alg.bc.gui.util.CompUtil;
import alg.bc.gui.util.Logger;
import alg.bc.gui.util.Validate;
import alg.bc.internation.Rsa;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class IntlRsaActions {
    private final InternationalViewProvider ui;

    public IntlRsaActions(InternationalViewProvider ui) {
        this.ui = ui;
    }

    public void rsaGenerateKeyPair() throws Exception {
        try {
            Logger.logAction("rsaGenerateKeyPair", "IntlRsaActions");
            Integer sizeObj = (Integer) ui.getIntRsaForm().getKeySizeComboBox().getSelectedItem();
            if (sizeObj == null) {
                throw new IllegalArgumentException("KeySize 未选择，无法生成密钥对");
            }
            Object encObj = ui.getIntRsaForm().getKeyEncodeComboBox().getSelectedItem();
            if (encObj == null) {
                throw new IllegalArgumentException("密钥编码未选择，无法生成密钥对");
            }
            int size = sizeObj;
            KeyPair kp = Rsa.generateKeyPair(size);
            String enc = encObj.toString();
            ui.getIntRsaForm().getPubKeyTextArea().setText(ByteUtil.bytes2Str(kp.getPublic().getEncoded(), enc));
            ui.getIntRsaForm().getPrvKeyTextArea().setText(ByteUtil.bytes2Str(kp.getPrivate().getEncoded(), enc));
        } catch (Exception ex) {
            Logger.logActionError("rsaGenerateKeyPair", "IntlRsaActions", ex);
            throw ex;
        }
    }

    public void rsaEncrypt() throws Exception {
        try {
            Logger.logAction("rsaEncrypt", "IntlRsaActions");
            String keyType = ui.getIntRsaForm().getEncryptKeyTypeComboBox().getSelectedItem().toString();
            String enc = ui.getIntRsaForm().getKeyEncodeComboBox().getSelectedItem().toString();
            byte[] keyBytes = Validate.requireBytes(ui.getIntRsaForm().getEncryptKeyTextArea().getText(), enc, keyType);
            byte[] input = Validate.requireBytes(ui.getIntRsaForm().getCipherInputTextArea().getText(), ui.getIntRsaForm().getCipherInputEncodeComboBox().getSelectedItem().toString(), "数据");
            byte[] out;
            if ("公钥".equals(keyType)) {
                PublicKey pk = Rsa.bytes2PubKey(keyBytes);
                out = Rsa.encrypt(pk, input);
            } else {
                PrivateKey sk = Rsa.bytes2PrvKey(keyBytes);
                out = Rsa.encrypt(sk, input);
            }
            ui.getIntRsaForm().getCipherOutputTextArea().setText(ByteUtil.bytes2Str(out, ui.getIntRsaForm().getCipherOutputEncodeComboBox().getSelectedItem().toString()));
        } catch (Exception ex) {
            Logger.logActionError("rsaEncrypt", "IntlRsaActions", ex);
            throw ex;
        }
    }

    public void rsaDecrypt() throws Exception {
        try {
            Logger.logAction("rsaDecrypt", "IntlRsaActions");
            String keyType = ui.getIntRsaForm().getDecryptKeyTypeComboBox().getSelectedItem().toString();
            String enc = ui.getIntRsaForm().getKeyEncodeComboBox().getSelectedItem().toString();
            byte[] keyBytes = Validate.requireBytes(ui.getIntRsaForm().getDecryptKeyTextArea().getText(), enc, keyType);
            byte[] input = Validate.requireBytes(ui.getIntRsaForm().getCipherInputTextArea().getText(), ui.getIntRsaForm().getCipherInputEncodeComboBox().getSelectedItem().toString(), "数据");
            byte[] out;
            if ("私钥".equals(keyType)) {
                PrivateKey sk = Rsa.bytes2PrvKey(keyBytes);
                out = Rsa.decrypt(sk, input);
            } else {
                PublicKey pk = Rsa.bytes2PubKey(keyBytes);
                out = Rsa.decrypt(pk, input);
            }
            ui.getIntRsaForm().getCipherOutputTextArea().setText(ByteUtil.bytes2Str(out, ui.getIntRsaForm().getCipherOutputEncodeComboBox().getSelectedItem().toString()));
        } catch (Exception ex) {
            Logger.logActionError("rsaDecrypt", "IntlRsaActions", ex);
            throw ex;
        }
    }

    public void rsaSign() throws Exception {
        try {
            Logger.logAction("rsaSign", "IntlRsaActions");
            String enc = ui.getIntRsaForm().getKeyEncodeComboBox().getSelectedItem().toString();
            byte[] prv = Validate.requireBytes(ui.getIntRsaForm().getSignPrvKeyTextArea().getText(), enc, "私钥");
            PrivateKey sk = Rsa.bytes2PrvKey(prv);
            byte[] msg = Validate.requireBytes(ui.getIntRsaForm().getSignMsgTextArea().getText(), ui.getIntRsaForm().getSignMsgEncodeComboBox().getSelectedItem().toString(), "待签名数据");
            byte[] sig = Rsa.sign(sk, msg);
            ui.getIntRsaForm().getSignOutTextArea().setText(ByteUtil.bytes2Str(sig, ui.getIntRsaForm().getSignOutEncodeComboBox().getSelectedItem().toString()));
        } catch (Exception ex) {
            Logger.logActionError("rsaSign", "IntlRsaActions", ex);
            throw ex;
        }
    }

    public void rsaVerify() throws Exception {
        try {
            Logger.logAction("rsaVerify", "IntlRsaActions");
            String enc = ui.getIntRsaForm().getKeyEncodeComboBox().getSelectedItem().toString();
            byte[] pub = Validate.requireBytes(ui.getIntRsaForm().getVerifyPubKeyTextArea().getText(), enc, "公钥");
            PublicKey pk = Rsa.bytes2PubKey(pub);
            byte[] msg = Validate.requireBytes(ui.getIntRsaForm().getVerifyMsgTextArea().getText(), ui.getIntRsaForm().getVerifyMsgEncodeComboBox().getSelectedItem().toString(), "待验签数据");
            byte[] sig = Validate.requireBytes(ui.getIntRsaForm().getVerifySigTextArea().getText(), ui.getIntRsaForm().getVerifySigEncodeComboBox().getSelectedItem().toString(), "签名值");
            boolean ok = Rsa.verify(pk, msg, sig);
            CompUtil.showMsg(Boot.frame, "验签结果", ok ? "通过" : "不通过");
        } catch (Exception ex) {
            Logger.logActionError("rsaVerify", "IntlRsaActions", ex);
            throw ex;
        }
    }
}


