package alg.bc.gui.action;

import alg.bc.gui.Boot;
import alg.bc.gui.util.ByteUtil;
import alg.bc.gui.util.CompUtil;
import alg.bc.gui.view.TabSm4;
import alg.bc.nation.SM4;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.SecureRandom;

public class ActionSm4 implements ActionListener {
    TabSm4 tabSm4;

    public ActionSm4(TabSm4 tabSm4){
        this.tabSm4 = tabSm4;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        String cmd = e.getActionCommand();
        switch (cmd) {
            case "generateSm4Key":
                generateSm4Key();
                break;
            case "generateSm4Iv":
                generateSm4Iv();
                break;
            case "sm4Encrypt":
                sm4Encrypt();
                break;
            case "sm4Decrypt":
                sm4Decrypt();
                break;
            case "sm4Cmac":
                sm4Cmac();
                break;
            case "resetForm":
                resetForm();
                break;
            default:
                break;
        }
    }

    private void generateSm4Key() {
        try {
            byte[] key = SM4.generateKey();
            String keyEncode;

            // 确定显示在哪个表单
            if(tabSm4.getEncryptForm().$$$getRootComponent$$$().isShowing()){
                keyEncode = tabSm4.getEncryptForm().getKeyEncodeComboBox().getSelectedItem().toString();
                tabSm4.getEncryptForm().getKeyTextArea().setText(ByteUtil.bytes2Str(key, keyEncode));
            }else if(tabSm4.getCmacForm().$$$getRootComponent$$$().isShowing()){
                keyEncode = tabSm4.getCmacForm().getKeyEncodeComboBox().getSelectedItem().toString();
                tabSm4.getCmacForm().getKeyTextArea().setText(ByteUtil.bytes2Str(key, keyEncode));
            }
        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, ex.getMessage());
        }
    }

    private void generateSm4Iv() {
        try {
            // 生成16字节随机IV
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);

            if(tabSm4.getEncryptForm().$$$getRootComponent$$$().isShowing()){
                String ivEncode = tabSm4.getEncryptForm().getIvEncodeComboBox().getSelectedItem().toString();
                tabSm4.getEncryptForm().getIvTextArea().setText(ByteUtil.bytes2Str(iv, ivEncode));
            }
        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, ex.getMessage());
        }
    }

    private void sm4Encrypt() {
        try {
            // 获取参数
            String keyStr = tabSm4.getEncryptForm().getKeyTextArea().getText();
            String keyEncode = tabSm4.getEncryptForm().getKeyEncodeComboBox().getSelectedItem().toString();
            String dataStr = tabSm4.getEncryptForm().getDataTextArea().getText();
            String dataEncode = tabSm4.getEncryptForm().getDataEncodeComboBox().getSelectedItem().toString();
            String mode = tabSm4.getEncryptForm().getModeComboBox().getSelectedItem().toString();
            String padding = tabSm4.getEncryptForm().getPaddingComboBox().getSelectedItem().toString();

            byte[] key = ByteUtil.str2Bytes(keyStr, keyEncode);
            byte[] data = ByteUtil.str2Bytes(dataStr, dataEncode);
            byte[] cipher;

            // 根据模式和填充调用对应的加密方法
            if ("ECB".equals(mode)) {
                if ("PKCS7".equals(padding)) {
                    cipher = SM4.ecbEncPkcs7(key, data);
                } else {
                    cipher = SM4.ecbEncNoPadding(key, data);
                }
            } else {
                // 其他模式需要IV
                String ivStr = tabSm4.getEncryptForm().getIvTextArea().getText();
                String ivEncode = tabSm4.getEncryptForm().getIvEncodeComboBox().getSelectedItem().toString();
                byte[] iv = ByteUtil.str2Bytes(ivStr, ivEncode);

                if ("CBC".equals(mode)) {
                    if ("PKCS7".equals(padding)) {
                        cipher = SM4.cbcEncPkcs7(key, iv, data);
                    } else {
                        cipher = SM4.cbcEncNoPadding(key, iv, data);
                    }
                } else if ("CFB".equals(mode)) {
                    if ("PKCS7".equals(padding)) {
                        cipher = SM4.cfbEncPkcs7(key, iv, data);
                    } else {
                        cipher = SM4.cfbEncNoPadding(key, iv, data);
                    }
                } else if ("OFB".equals(mode)) {
                    if ("PKCS7".equals(padding)) {
                        cipher = SM4.ofbEncPkcs7(key, iv, data);
                    } else {
                        cipher = SM4.ofbEncNoPadding(key, iv, data);
                    }
                } else if ("GCM".equals(mode)) {
                    cipher = SM4.gcmEnc(key, iv, data);
                } else {
                    throw new IllegalArgumentException("不支持的加密模式: " + mode + " (仅支持ECB/CBC/CFB/OFB/GCM)");
                }
            }

            // 显示结果
            String cipherEncode = tabSm4.getEncryptForm().getCipherEncodeComboBox().getSelectedItem().toString();
            tabSm4.getEncryptForm().getCipherTextArea().setText(ByteUtil.bytes2Str(cipher, cipherEncode));

        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, ex.getMessage());
        }
    }

    private void sm4Decrypt() {
        try {
            // 获取参数
            String keyStr = tabSm4.getDecryptForm().getKeyTextArea().getText();
            String keyEncode = tabSm4.getDecryptForm().getKeyEncodeComboBox().getSelectedItem().toString();
            String cipherStr = tabSm4.getDecryptForm().getCipherTextArea().getText();
            String cipherEncode = tabSm4.getDecryptForm().getCipherEncodeComboBox().getSelectedItem().toString();
            String mode = tabSm4.getDecryptForm().getModeComboBox().getSelectedItem().toString();
            String padding = tabSm4.getDecryptForm().getPaddingComboBox().getSelectedItem().toString();

            byte[] key = ByteUtil.str2Bytes(keyStr, keyEncode);
            byte[] cipher = ByteUtil.str2Bytes(cipherStr, cipherEncode);
            byte[] data;

            // 根据模式和填充调用对应的解密方法
            if ("ECB".equals(mode)) {
                if ("PKCS7".equals(padding)) {
                    data = SM4.ecbDecPkcs7(key, cipher);
                } else {
                    data = SM4.ecbDecNoPadding(key, cipher);
                }
            } else {
                // 其他模式需要IV
                String ivStr = tabSm4.getDecryptForm().getIvTextArea().getText();
                String ivEncode = tabSm4.getDecryptForm().getIvEncodeComboBox().getSelectedItem().toString();
                byte[] iv = ByteUtil.str2Bytes(ivStr, ivEncode);

                if ("CBC".equals(mode)) {
                    if ("PKCS7".equals(padding)) {
                        data = SM4.cbcDecPkcs7(key, iv, cipher);
                    } else {
                        data = SM4.cbcDecNoPadding(key, iv, cipher);
                    }
                } else if ("CFB".equals(mode)) {
                    if ("PKCS7".equals(padding)) {
                        data = SM4.cfbDecPkcs7(key, iv, cipher);
                    } else {
                        data = SM4.cfbDecNoPadding(key, iv, cipher);
                    }
                } else if ("OFB".equals(mode)) {
                    if ("PKCS7".equals(padding)) {
                        data = SM4.ofbDecPkcs7(key, iv, cipher);
                    } else {
                        data = SM4.ofbDecNoPadding(key, iv, cipher);
                    }
                } else if ("GCM".equals(mode)) {
                    data = SM4.gcmDec(key, iv, cipher);
                } else {
                    throw new IllegalArgumentException("不支持的解密模式: " + mode + " (仅支持ECB/CBC/CFB/OFB/GCM)");
                }
            }

            // 显示结果
            String dataEncode = tabSm4.getDecryptForm().getDataEncodeComboBox().getSelectedItem().toString();
            tabSm4.getDecryptForm().getDataTextArea().setText(ByteUtil.bytes2Str(data, dataEncode));

        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, ex.getMessage());
        }
    }

    private void sm4Cmac() {
        try {
            // 获取参数
            String keyStr = tabSm4.getCmacForm().getKeyTextArea().getText();
            String keyEncode = tabSm4.getCmacForm().getKeyEncodeComboBox().getSelectedItem().toString();
            String dataStr = tabSm4.getCmacForm().getDataTextArea().getText();
            String dataEncode = tabSm4.getCmacForm().getDataEncodeComboBox().getSelectedItem().toString();

            byte[] key = ByteUtil.str2Bytes(keyStr, keyEncode);
            byte[] data = ByteUtil.str2Bytes(dataStr, dataEncode);

            // 计算CMAC
            byte[] mac = SM4.cmac(key, data);

            // 显示结果
            String macEncode = tabSm4.getCmacForm().getMacEncodeComboBox().getSelectedItem().toString();
            tabSm4.getCmacForm().getMacTextArea().setText(ByteUtil.bytes2Str(mac, macEncode));

        } catch (Exception ex) {
            CompUtil.showErr(Boot.frame, ex.getMessage());
        }
    }

    private void resetForm() {
        if(tabSm4.getEncryptForm().$$$getRootComponent$$$().isShowing()){
            tabSm4.getEncryptForm().getKeyTextArea().setText("");
            tabSm4.getEncryptForm().getDataTextArea().setText("");
            tabSm4.getEncryptForm().getIvTextArea().setText("");
            tabSm4.getEncryptForm().getCipherTextArea().setText("");
        }else if(tabSm4.getDecryptForm().$$$getRootComponent$$$().isShowing()){
            tabSm4.getDecryptForm().getKeyTextArea().setText("");
            tabSm4.getDecryptForm().getCipherTextArea().setText("");
            tabSm4.getDecryptForm().getIvTextArea().setText("");
            tabSm4.getDecryptForm().getDataTextArea().setText("");
        }else if(tabSm4.getCmacForm().$$$getRootComponent$$$().isShowing()){
            tabSm4.getCmacForm().getKeyTextArea().setText("");
            tabSm4.getCmacForm().getDataTextArea().setText("");
            tabSm4.getCmacForm().getMacTextArea().setText("");
        }
    }
}
