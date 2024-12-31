package alg.bc.gui.action;

import alg.bc.gui.Boot;
import alg.bc.gui.util.ByteUtil;
import alg.bc.gui.util.CompUtil;
import alg.bc.gui.view.TabSm3;
import alg.bc.nation.SM3;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;


public class ActionSm3 implements ActionListener {

    TabSm3 tabSm3;

    public ActionSm3(TabSm3 tabSm3){
        this.tabSm3 = tabSm3;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        String cmd = e.getActionCommand();
        switch (cmd){
            case "hash":
                hash();
                break;
            case "hmac":
                hmac();
                break;
            case "chooseFile":
                chooseFile();
                break;
            case "reset":
                reset();
                break;
        }
    }

    private void hash() {
        try{
            boolean isTxt = tabSm3.getViewSm3Hash().getTxtRadioButton().isSelected();
            byte[] input;
            if(isTxt) {
                String txt = tabSm3.getViewSm3Hash().getInputTextArea().getText();
                String txtEncode = tabSm3.getViewSm3Hash().getDataEncodeComboBox().getSelectedItem().toString();
                input = ByteUtil.str2Bytes(txt, txtEncode);
            }else{
                String filePath = tabSm3.getViewSm3Hash().getFileTextField().getText();
                if("".equals(filePath)){
                    CompUtil.showMsg(Boot.frame, "请选择文件");
                    return ;
                }
                input = ByteUtil.readFile(filePath);
            }
            byte[] hash = SM3.hash(input);
            String resultEncode = tabSm3.getViewSm3Hash().getResultEncodeComboBox().getSelectedItem().toString();
            tabSm3.getViewSm3Hash().getResultTextArea().setText(ByteUtil.bytes2Str(hash, resultEncode));
        }catch (Exception e){
            CompUtil.showErr(Boot.frame, e.getMessage());
        }
    }

    private void hmac() {
        try{
            boolean isTxt = tabSm3.getViewSm3Hmac().getTxtRadioButton().isSelected();
            byte[] input;
            if(isTxt) {
                String txt = tabSm3.getViewSm3Hmac().getInputTextArea().getText();
                String txtEncode = tabSm3.getViewSm3Hmac().getDataEncodeComboBox().getSelectedItem().toString();
                input = ByteUtil.str2Bytes(txt, txtEncode);
            }else{
                String filePath = tabSm3.getViewSm3Hmac().getFileTextField().getText();
                if("".equals(filePath)){
                    CompUtil.showMsg(Boot.frame, "请选择文件");
                    return ;
                }
                input = ByteUtil.readFile(filePath);
            }
            String key = tabSm3.getViewSm3Hmac().getKeyTextArea().getText();
            String keyEncode = tabSm3.getViewSm3Hmac().getKeyEncodeComboBox().getSelectedItem().toString();
            byte[] hmac = SM3.hmac(ByteUtil.str2Bytes(key, keyEncode), input);
            String resultEncode = tabSm3.getViewSm3Hmac().getResultEncodeComboBox().getSelectedItem().toString();
            tabSm3.getViewSm3Hmac().getResultTextArea().setText(ByteUtil.bytes2Str(hmac, resultEncode));
        }catch (Exception e){
            CompUtil.showErr(Boot.frame, e.getMessage());
        }
    }

    private void chooseFile() {
        String path = CompUtil.chooseFile(Boot.frame, "选择目标文件");
        if(tabSm3.getViewSm3Hash().$$$getRootComponent$$$().isShowing()){
            tabSm3.getViewSm3Hash().getFileTextField().setText(path);
        }else if(tabSm3.getViewSm3Hmac().$$$getRootComponent$$$().isShowing()){
            tabSm3.getViewSm3Hmac().getFileTextField().setText(path);
        }
    }

    private void reset() {
        if(tabSm3.getViewSm3Hash().$$$getRootComponent$$$().isShowing()){
            tabSm3.getViewSm3Hash().getTxtRadioButton().setSelected(true);
            tabSm3.getViewSm3Hash().getInputTextArea().setText("");
            tabSm3.getViewSm3Hash().getFileTextField().setText("");
            tabSm3.getViewSm3Hash().getResultTextArea().setText("");
        }else if(tabSm3.getViewSm3Hmac().$$$getRootComponent$$$().isShowing()){
            tabSm3.getViewSm3Hmac().getTxtRadioButton().setSelected(true);
            tabSm3.getViewSm3Hmac().getInputTextArea().setText("");
            tabSm3.getViewSm3Hmac().getFileTextField().setText("");
            tabSm3.getViewSm3Hmac().getResultTextArea().setText("");
            tabSm3.getViewSm3Hmac().getKeyTextArea().setText("");
        }
    }
}
