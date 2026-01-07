package alg.bc.gui.action;

import alg.bc.gui.Boot;
import alg.bc.gui.action.international.CommandHandler;
import alg.bc.gui.action.international.InternationalViewProvider;
import alg.bc.gui.action.international.IntlAesActions;
import alg.bc.gui.action.international.IntlCertActions;
import alg.bc.gui.action.international.IntlDes3Actions;
import alg.bc.gui.action.international.IntlHashActions;
import alg.bc.gui.action.international.IntlMacActions;
import alg.bc.gui.action.international.IntlRsaActions;
import alg.bc.gui.util.CompUtil;
import alg.bc.gui.util.Logger;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.HashMap;
import java.util.Map;

/**
 * 国际算法动作入口：只负责 command → handler 分发。
 * 具体实现按模块拆分到 alg.bc.gui.action.international.*
 */
public class ActionInternational implements ActionListener {
    private final Map<String, CommandHandler> handlers = new HashMap<>();

    public ActionInternational(InternationalViewProvider ui) {
        IntlAesActions aes = new IntlAesActions(ui);
        IntlDes3Actions des3 = new IntlDes3Actions(ui);
        IntlRsaActions rsa = new IntlRsaActions(ui);
        IntlHashActions hash = new IntlHashActions(ui);
        IntlMacActions mac = new IntlMacActions(ui);
        IntlCertActions cert = new IntlCertActions(ui);

        // AES
        handlers.put("aesGenerateKey", aes::aesGenerateKey);
        handlers.put("aesGenerateIv", aes::aesGenerateIv);
        handlers.put("aesEncrypt", aes::aesEncrypt);
        handlers.put("aesDecrypt", aes::aesDecrypt);

        // 3DES
        handlers.put("des3GenerateKey", des3::des3GenerateKey);
        handlers.put("des3GenerateIv", des3::des3GenerateIv);
        handlers.put("des3Encrypt", des3::des3Encrypt);
        handlers.put("des3Decrypt", des3::des3Decrypt);

        // RSA
        handlers.put("rsaGenerateKeyPair", rsa::rsaGenerateKeyPair);
        handlers.put("rsaEncrypt", rsa::rsaEncrypt);
        handlers.put("rsaDecrypt", rsa::rsaDecrypt);
        handlers.put("rsaSign", rsa::rsaSign);
        handlers.put("rsaVerify", rsa::rsaVerify);

        // HASH
        handlers.put("hashDigest", hash::hashDigest);

        // MAC
        handlers.put("macDo", mac::macDo);

        // Cert（国际）
        handlers.put("intRsaCertGenerateKeyPair", cert::intRsaCertGenerateKeyPair);
        handlers.put("intRsaCertGenerateCsr", cert::intRsaCertGenerateCsr);
        handlers.put("intRsaCertGenerateSelfSigned", cert::intRsaCertGenerateSelfSigned);
        handlers.put("intRsaCertParse", cert::intRsaCertParse);
        handlers.put("intRsaCertLoadFile", cert::intRsaCertLoadFile);
        handlers.put("intRsaCertToPem", cert::intRsaCertToPem);
        handlers.put("intRsaCertToDerBase64", cert::intRsaCertToDerBase64);
        handlers.put("intRsaCertToDerHex", cert::intRsaCertToDerHex);
        handlers.put("intRsaCertSplitPem", cert::intRsaCertSplitPem);
        handlers.put("intRsaCertVerifyChain", cert::intRsaCertVerifyChain);
        handlers.put("intRsaCertSaveInfo", cert::intRsaCertSaveInfo);
        handlers.put("intRsaCertExportPemFile", cert::intRsaCertExportPemFile);
        handlers.put("intRsaCertExportDerFile", cert::intRsaCertExportDerFile);
        handlers.put("intRsaCertBuildChain", cert::intRsaCertBuildChain);
        handlers.put("intRsaCertReset", cert::intRsaCertReset);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        String cmd = e.getActionCommand();
        Logger.logAction(cmd, "ActionInternational");
        CommandHandler h = handlers.get(cmd);
        if (h == null) {
            Logger.debug("未知的命令: " + cmd);
            return;
        }
        try {
            h.handle();
        } catch (Exception ex) {
            Logger.logActionError(cmd, "ActionInternational", ex);
            CompUtil.showErr(Boot.frame, ex.getMessage());
        }
    }
}


