package alg.bc.gui.action.international;

import alg.bc.gui.util.ByteUtil;
import alg.bc.gui.util.Logger;
import alg.bc.gui.util.Validate;
import alg.bc.internation.Digest;

public class IntlHashActions {
    private final InternationalViewProvider ui;

    public IntlHashActions(InternationalViewProvider ui) {
        this.ui = ui;
    }

    public void hashDigest() throws Exception {
        try {
            Logger.logAction("hashDigest", "IntlHashActions");
            String alg = ui.getIntHashForm().getAlgComboBox().getSelectedItem().toString();
            byte[] input = Validate.requireBytes(ui.getIntHashForm().getInputTextArea().getText(), ui.getIntHashForm().getInputEncodeComboBox().getSelectedItem().toString(), "输入数据");
            byte[] out;
            switch (alg) {
                case "MD5":
                    out = Digest.md5(input);
                    break;
                case "SHA-1":
                    out = Digest.sha1(input);
                    break;
                case "SHA-256":
                    out = Digest.sha256(input);
                    break;
                case "SHA-512":
                    out = Digest.sha512(input);
                    break;
                default:
                    out = Digest.doDigest(alg, input);
            }
            ui.getIntHashForm().getOutputTextArea().setText(ByteUtil.bytes2Str(out, ui.getIntHashForm().getOutputEncodeComboBox().getSelectedItem().toString()));
        } catch (Exception ex) {
            Logger.logActionError("hashDigest", "IntlHashActions", ex);
            throw ex;
        }
    }
}


