package alg.bc.gui.action;

import alg.bc.gui.Boot;
import alg.bc.gui.util.ByteUtil;
import alg.bc.gui.util.CompUtil;
import alg.bc.gui.util.Validate;
import alg.bc.gui.view.TabSm2;
import alg.bc.nation.SM2;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.KeyPair;

public class ActionSm2 implements ActionListener {
    TabSm2 tabSm2;

    public ActionSm2(TabSm2 formSm2) {
        this.tabSm2 = formSm2;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        String cmd = e.getActionCommand();
        switch (cmd){
            case "generateSm2Key":
                generateSm2Key();
                break;
            case "sm2Encrypt":
                sm2Encrypt();
                break;
            case "sm2Decrypt":
                sm2Decrypt();
                break;
            case "sm2Sign":
                sm2Sign();
                break;
            case "sm2Verify":
                sm2Verify();
                break;
            case "sm2Compress":
                sm2Compress();
                break;
            case "sm2Uncompress":
                sm2Uncompress();
                break;
            case "resetForm":
                resetForm();
            default:
                break;
        }
    }

    private void generateSm2Key(){
        try{
            KeyPair keyPair = SM2.generateKeyPair();
            byte[] pub = SM2.pubKeyToBytes(keyPair.getPublic());
            byte[] prv = SM2.prvKeyToBytes(keyPair.getPrivate());
            if(tabSm2.getGenerateKeyForm().getBase64RadioButton().isSelected()){
                tabSm2.getGenerateKeyForm().getPubKeyArea().setText(Base64.toBase64String(pub));
                tabSm2.getGenerateKeyForm().getPrvKeyArea().setText(Base64.toBase64String(prv));
            }else{
                tabSm2.getGenerateKeyForm().getPubKeyArea().setText(Hex.toHexString(pub));
                tabSm2.getGenerateKeyForm().getPrvKeyArea().setText(Hex.toHexString(prv));
            }
        }catch (Exception e){
            CompUtil.showErr(Boot.frame, e.getMessage());
        }
    }

    private void sm2Encrypt(){
        try{
            String pubKey = tabSm2.getEncryptForm().getPubKeyArea().getText();
            String pubKeyEncode = tabSm2.getEncryptForm().getPubKeyTypeComboBox().getSelectedItem().toString();
            String data = tabSm2.getEncryptForm().getDataArea().getText();
            String dataEncode = tabSm2.getEncryptForm().getDataTypeComboBox().getSelectedItem().toString();
            SM2Engine.Mode mode = SM2Engine.Mode.C1C3C2;
            if(tabSm2.getEncryptForm().getC1C2C3RadioButton().isSelected()){
                mode = SM2Engine.Mode.C1C2C3;
            }
            byte[] pubBytes = Validate.requireSm2PublicKey(pubKey, pubKeyEncode, "公钥");
            byte[] dataBytes = Validate.requireBytes(data, dataEncode, "明文数据");
            byte[] ret = SM2.encrypt(pubBytes, dataBytes, mode);
            String cipherDataEncode = tabSm2.getEncryptForm().getCipherDatacomboBox().getSelectedItem().toString();
            tabSm2.getEncryptForm().getCipherDataArea().setText(ByteUtil.bytes2Str(ret, cipherDataEncode));
        }catch (Exception e){
            CompUtil.showErr(Boot.frame, e.getMessage());
        }
    }

    private void sm2Decrypt(){
        try{
            String prvKey = tabSm2.getDecryptForm().getPrvKeyTextArea().getText();
            String prvKeyEncode = tabSm2.getDecryptForm().getPrvKeyEncodeComboBox().getSelectedItem().toString();
            String cipherData = tabSm2.getDecryptForm().getCipherDataTextArea().getText();
            String cipherDataEncode = tabSm2.getDecryptForm().getCipherTpeComboBox().getSelectedItem().toString();
            SM2Engine.Mode mode = SM2Engine.Mode.C1C3C2;
            if(tabSm2.getDecryptForm().getC1C2C3RadioButton().isSelected()){
                mode = SM2Engine.Mode.C1C2C3;
            }
            byte[] prvBytes = Validate.requireSm2PrivateKey(prvKey, prvKeyEncode, "私钥");
            byte[] cipherBytes = Validate.requireBytes(cipherData, cipherDataEncode, "密文数据");
            byte[] ret = SM2.decrypt(prvBytes, cipherBytes, mode);
            String dataEncode = tabSm2.getDecryptForm().getDataTypeComboBox().getSelectedItem().toString();
            tabSm2.getDecryptForm().getDataTextArea().setText(ByteUtil.bytes2Str(ret, dataEncode));
        }catch (Exception e){
            CompUtil.showErr(Boot.frame, e.getMessage());
        }
    }

    private void sm2Sign(){
        try{
            String prvKey = tabSm2.getSignForm().getPrvKeyTextArea().getText();
            String prvKeyEncode = tabSm2.getSignForm().getPrvKeyTypeComboBox().getSelectedItem().toString();
            String data = tabSm2.getSignForm().getDataTextArea().getText();
            String dataEncode = tabSm2.getSignForm().getDataTypeComboBox().getSelectedItem().toString();

            byte[] prvBytes = Validate.requireSm2PrivateKey(prvKey, prvKeyEncode, "私钥");
            byte[] dataBytes = Validate.requireBytes(data, dataEncode, "待签名数据");
            byte[] ret = SM2.sign(prvBytes, dataBytes);
            if (tabSm2.getSignForm().getSignEncodeAsn1().isSelected()) {
                ret = SM2.rsToAns1(ret);
            }
            String signEncode = tabSm2.getSignForm().getSignTypeComboBox().getSelectedItem().toString();
            tabSm2.getSignForm().getSignTextArea().setText(ByteUtil.bytes2Str(ret, signEncode));
        }catch (Exception e){
            CompUtil.showErr(Boot.frame, e.getMessage());
        }
    }
    private void sm2Verify(){
        try{
            String pubKey = tabSm2.getVerifyForm().getPubKeyTextArea().getText();
            String pubKeyEncode = tabSm2.getVerifyForm().getPubkeyEncodeComboBox().getSelectedItem().toString();
            String data = tabSm2.getVerifyForm().getDataTextArea().getText();
            String dataEncode = tabSm2.getVerifyForm().getDataTypeComboBox().getSelectedItem().toString();
            String sign = tabSm2.getVerifyForm().getSignTextArea().getText();
            String signEncode = tabSm2.getVerifyForm().getSignEncodeComboBox().getSelectedItem().toString();
            boolean sigAsn1 = tabSm2.getVerifyForm().getSignEncodeAsn1RadioButton().isSelected();

            byte[] pubBytes = Validate.requireSm2PublicKey(pubKey, pubKeyEncode, "公钥");
            byte[] dataBytes = Validate.requireBytes(data, dataEncode, "待验签数据");
            byte[] sigBytes;
            if (sigAsn1) {
                sigBytes = Validate.requireBytes(sign, signEncode, "签名值");
                sigBytes = SM2.ans1ToRs(sigBytes);
            } else {
                sigBytes = Validate.requireSm2SignaturePlain(sign, signEncode, "签名值");
            }
            boolean ret = SM2.verify(pubBytes, dataBytes, sigBytes);
            CompUtil.showMsg(Boot.frame, "验签结果", ret ? "通过" : "不通过");
        }catch (Exception e){
            CompUtil.showErr(Boot.frame, e.getMessage());
        }
    }
    private void sm2Compress(){
        try{
            String pubKey = tabSm2.getCompressForm().getPubKeyTextArea().getText();
            String pubKeyEncode = tabSm2.getCompressForm().getPubTypeComboBox().getSelectedItem().toString();

            byte[] pubBytes = Validate.requireSm2PublicKey(pubKey, pubKeyEncode, "公钥");
            byte[] compressedKey = SM2.compress(pubBytes);

            String dataEncode = tabSm2.getCompressForm().getResultTypeComboBox().getSelectedItem().toString();
            tabSm2.getCompressForm().getResultTextArea().setText(ByteUtil.bytes2Str(compressedKey, dataEncode));
        }catch (Exception e){
            CompUtil.showErr(Boot.frame, e.getMessage());
        }
    }
    private void sm2Uncompress(){
        try{
            String pubKey = tabSm2.getCompressForm().getPubKeyTextArea().getText();
            String pubKeyEncode = tabSm2.getCompressForm().getPubTypeComboBox().getSelectedItem().toString();

            byte[] pubBytes = Validate.requireSm2PublicKey(pubKey, pubKeyEncode, "公钥");
            byte[] decompressedKey = SM2.decompress(pubBytes);

            String dataEncode = tabSm2.getCompressForm().getResultTypeComboBox().getSelectedItem().toString();
            tabSm2.getCompressForm().getResultTextArea().setText(ByteUtil.bytes2Str(decompressedKey, dataEncode));
        }catch (Exception e){
            CompUtil.showErr(Boot.frame, e.getMessage());
        }
    }

    private void resetForm() {
        if(tabSm2.getEncryptForm().$$$getRootComponent$$$().isShowing()){
            tabSm2.getEncryptForm().getPubKeyArea().setText("");
            tabSm2.getEncryptForm().getDataArea().setText("");
            tabSm2.getEncryptForm().getCipherDataArea().setText("");
        }else if(tabSm2.getDecryptForm().$$$getRootComponent$$$().isShowing()){
            tabSm2.getDecryptForm().getPrvKeyTextArea().setText("");
            tabSm2.getDecryptForm().getCipherDataTextArea().setText("");
            tabSm2.getDecryptForm().getDataTextArea().setText("");
        }else if(tabSm2.getSignForm().$$$getRootComponent$$$().isShowing()){
            tabSm2.getSignForm().getPrvKeyTextArea().setText("");
            tabSm2.getSignForm().getDataTextArea().setText("");
            tabSm2.getSignForm().getSignTextArea().setText("");
        }else if(tabSm2.getVerifyForm().$$$getRootComponent$$$().isShowing()){
            tabSm2.getVerifyForm().getPubKeyTextArea().setText("");
            tabSm2.getVerifyForm().getSignTextArea().setText("");
        }else if(tabSm2.getCompressForm().$$$getRootComponent$$$().isShowing()){
            tabSm2.getCompressForm().getPubKeyTextArea().setText("");
            tabSm2.getCompressForm().getResultTextArea().setText("");
        }
    }
}
