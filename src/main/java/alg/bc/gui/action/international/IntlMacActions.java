package alg.bc.gui.action.international;

import alg.bc.gui.util.ByteUtil;
import alg.bc.gui.util.Validate;
import alg.bc.internation.MAC;

public class IntlMacActions {
    private final InternationalViewProvider ui;

    public IntlMacActions(InternationalViewProvider ui) {
        this.ui = ui;
    }

    public void macDo() throws Exception {
        String alg = ui.getIntMacForm().getAlgComboBox().getSelectedItem().toString();
        byte[] msg = Validate.requireBytes(ui.getIntMacForm().getMsgTextArea().getText(), ui.getIntMacForm().getMsgEncodeComboBox().getSelectedItem().toString(), "消息");
        byte[] key = Validate.requireBytes(ui.getIntMacForm().getKeyTextArea().getText(), ui.getIntMacForm().getKeyEncodeComboBox().getSelectedItem().toString(), "密钥");
        byte[] out;
        switch (alg) {
            case "HMAC-MD5":
                out = MAC.md5HMac(msg, key);
                break;
            case "HMAC-SHA256":
                out = MAC.sha256HMac(msg, key);
                break;
            case "AES-CMAC":
                requireAesKeyLen(key);
                out = MAC.aesCMac(msg, key);
                break;
            case "DES-CMAC":
                if (key.length != 8) {
                    throw new IllegalArgumentException("DES-CMAC 密钥长度必须为 8 字节（当前 " + key.length + " 字节）");
                }
                out = MAC.desCMac(msg, key);
                break;
            default:
                throw new IllegalArgumentException("不支持的 MAC 算法: " + alg);
        }
        ui.getIntMacForm().getOutTextArea().setText(ByteUtil.bytes2Str(out, ui.getIntMacForm().getOutEncodeComboBox().getSelectedItem().toString()));
    }

    private void requireAesKeyLen(byte[] key) {
        if (key == null) throw new IllegalArgumentException("密钥不能为空");
        if (!(key.length == 16 || key.length == 24 || key.length == 32)) {
            throw new IllegalArgumentException("AES 密钥长度必须为 16/24/32 字节（当前 " + key.length + " 字节）");
        }
    }
}


