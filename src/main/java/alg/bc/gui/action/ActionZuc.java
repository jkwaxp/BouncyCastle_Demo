package alg.bc.gui.action;

import alg.bc.gui.Boot;
import alg.bc.gui.util.ByteUtil;
import alg.bc.gui.util.CompUtil;
import alg.bc.gui.util.Logger;
import alg.bc.gui.util.Validate;
import alg.bc.gui.view.TabZuc;
import alg.bc.nation.Zuc;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.SecureRandom;

public class ActionZuc implements ActionListener {
    TabZuc tabZuc;

    public ActionZuc(TabZuc tabZuc) {
        this.tabZuc = tabZuc;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        String cmd = e.getActionCommand();
        Logger.logAction(cmd, "ActionZuc");
        try {
            switch (cmd) {
                case "generateZucKey":
                    generateZucKey();
                    break;
                case "generateZucIv":
                    generateZucIv();
                    break;
                case "zucCipher":
                    zucCipher();
                    break;
                case "zucMac":
                    zucMac();
                    break;
                case "resetForm":
                    resetForm();
                    break;
                default:
                    break;
            }
        } catch (Exception ex) {
            Logger.logActionError(cmd, "ActionZuc", ex);
            throw ex;
        }
    }

    private void generateZucKey() {
        try {
            boolean isZuc128;
            int keyLength;

            // 确定当前在哪个表单以及选择的版本
            if (tabZuc.getCipherForm().$$$getRootComponent$$$().isShowing()) {
                isZuc128 = tabZuc.getCipherForm().getZuc128RadioButton().isSelected();
                keyLength = isZuc128 ? 128 : 256;
                byte[] key = Zuc.generateKey(keyLength);
                String keyEncode = tabZuc.getCipherForm().getKeyEncodeComboBox().getSelectedItem().toString();
                tabZuc.getCipherForm().getKeyTextArea().setText(ByteUtil.bytes2Str(key, keyEncode));
            } else if (tabZuc.getMacForm().$$$getRootComponent$$$().isShowing()) {
                isZuc128 = tabZuc.getMacForm().getZuc128RadioButton().isSelected();
                keyLength = isZuc128 ? 128 : 256;
                byte[] key = Zuc.generateKey(keyLength);
                String keyEncode = tabZuc.getMacForm().getKeyEncodeComboBox().getSelectedItem().toString();
                tabZuc.getMacForm().getKeyTextArea().setText(ByteUtil.bytes2Str(key, keyEncode));
            }
        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, ex.getMessage());
        }
    }

    private void generateZucIv() {
        try {
            boolean isZuc128;
            int ivLength;

            // 确定当前在哪个表单以及选择的版本
            if (tabZuc.getCipherForm().$$$getRootComponent$$$().isShowing()) {
                isZuc128 = tabZuc.getCipherForm().getZuc128RadioButton().isSelected();
                ivLength = isZuc128 ? 16 : 25;  // ZUC-128: 16字节, ZUC-256: 25字节
                byte[] iv = new byte[ivLength];
                new SecureRandom().nextBytes(iv);
                String ivEncode = tabZuc.getCipherForm().getIvEncodeComboBox().getSelectedItem().toString();
                tabZuc.getCipherForm().getIvTextArea().setText(ByteUtil.bytes2Str(iv, ivEncode));
            } else if (tabZuc.getMacForm().$$$getRootComponent$$$().isShowing()) {
                isZuc128 = tabZuc.getMacForm().getZuc128RadioButton().isSelected();
                ivLength = isZuc128 ? 16 : 25;
                byte[] iv = new byte[ivLength];
                new SecureRandom().nextBytes(iv);
                String ivEncode = tabZuc.getMacForm().getIvEncodeComboBox().getSelectedItem().toString();
                tabZuc.getMacForm().getIvTextArea().setText(ByteUtil.bytes2Str(iv, ivEncode));
            }
        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, ex.getMessage());
        }
    }

    private void zucCipher() {
        try {
            // 获取参数
            boolean isZuc128 = tabZuc.getCipherForm().getZuc128RadioButton().isSelected();
            String keyStr = tabZuc.getCipherForm().getKeyTextArea().getText();
            String keyEncode = tabZuc.getCipherForm().getKeyEncodeComboBox().getSelectedItem().toString();
            String ivStr = tabZuc.getCipherForm().getIvTextArea().getText();
            String ivEncode = tabZuc.getCipherForm().getIvEncodeComboBox().getSelectedItem().toString();
            String inputStr = tabZuc.getCipherForm().getInputTextArea().getText();
            String inputEncode = tabZuc.getCipherForm().getInputEncodeComboBox().getSelectedItem().toString();

            byte[] key = Validate.requireBytes(keyStr, keyEncode, "密钥");
            byte[] iv = Validate.requireBytes(ivStr, ivEncode, "IV");
            byte[] input = Validate.requireBytes(inputStr, inputEncode, "输入数据");
            if (isZuc128) {
                Validate.requireExactLength(key, 16, "密钥（ZUC-128）");
                Validate.requireExactLength(iv, 16, "IV（ZUC-128）");
            } else {
                Validate.requireExactLength(key, 32, "密钥（ZUC-256）");
                Validate.requireExactLength(iv, 25, "IV（ZUC-256）");
            }
            byte[] output;

            // 调用对应版本的加密/解密方法（ZUC流密码，加密和解密是同一个操作）
            if (isZuc128) {
                output = Zuc.cipher128(key, iv, input);
            } else {
                output = Zuc.cipher256(key, iv, input);
            }

            // 显示结果
            String outputEncode = tabZuc.getCipherForm().getOutputEncodeComboBox().getSelectedItem().toString();
            tabZuc.getCipherForm().getOutputTextArea().setText(ByteUtil.bytes2Str(output, outputEncode));

        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, ex.getMessage());
        }
    }

    private void zucMac() {
        try {
            // 获取参数
            boolean isZuc128 = tabZuc.getMacForm().getZuc128RadioButton().isSelected();
            String keyStr = tabZuc.getMacForm().getKeyTextArea().getText();
            String keyEncode = tabZuc.getMacForm().getKeyEncodeComboBox().getSelectedItem().toString();
            String ivStr = tabZuc.getMacForm().getIvTextArea().getText();
            String ivEncode = tabZuc.getMacForm().getIvEncodeComboBox().getSelectedItem().toString();
            String dataStr = tabZuc.getMacForm().getDataTextArea().getText();
            String dataEncode = tabZuc.getMacForm().getDataEncodeComboBox().getSelectedItem().toString();

            byte[] key = Validate.requireBytes(keyStr, keyEncode, "密钥");
            byte[] iv = Validate.requireBytes(ivStr, ivEncode, "IV");
            byte[] data = Validate.requireBytes(dataStr, dataEncode, "数据");
            if (isZuc128) {
                Validate.requireExactLength(key, 16, "密钥（ZUC-128）");
                Validate.requireExactLength(iv, 16, "IV（ZUC-128）");
            } else {
                Validate.requireExactLength(key, 32, "密钥（ZUC-256）");
                Validate.requireExactLength(iv, 25, "IV（ZUC-256）");
            }
            byte[] mac;

            // 调用对应版本的MAC方法
            if (isZuc128) {
                mac = Zuc.mac128(key, iv, data);
            } else {
                mac = Zuc.mac256(key, iv, data);
            }

            // 显示结果
            String macEncode = tabZuc.getMacForm().getMacEncodeComboBox().getSelectedItem().toString();
            tabZuc.getMacForm().getMacTextArea().setText(ByteUtil.bytes2Str(mac, macEncode));

        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, ex.getMessage());
        }
    }

    private void resetForm() {
        if (tabZuc.getCipherForm().$$$getRootComponent$$$().isShowing()) {
            tabZuc.getCipherForm().getKeyTextArea().setText("");
            tabZuc.getCipherForm().getIvTextArea().setText("");
            tabZuc.getCipherForm().getInputTextArea().setText("");
            tabZuc.getCipherForm().getOutputTextArea().setText("");
        } else if (tabZuc.getMacForm().$$$getRootComponent$$$().isShowing()) {
            tabZuc.getMacForm().getKeyTextArea().setText("");
            tabZuc.getMacForm().getIvTextArea().setText("");
            tabZuc.getMacForm().getDataTextArea().setText("");
            tabZuc.getMacForm().getMacTextArea().setText("");
        }
    }
}
