package alg.bc.gui.action.international;

import alg.bc.gui.view.viewInternational.ViewIntAes;
import alg.bc.gui.view.viewInternational.ViewIntCert;
import alg.bc.gui.view.viewInternational.ViewIntDes3;
import alg.bc.gui.view.viewInternational.ViewIntHash;
import alg.bc.gui.view.viewInternational.ViewIntMac;
import alg.bc.gui.view.viewInternational.ViewIntRsa;

/**
 * 国际算法 UI 访问接口：让 action 层不依赖某个“TabInternational UI 容器类”，
 * 只依赖这些 view 的 getter。
 */
public interface InternationalViewProvider {
    ViewIntAes getIntAesForm();

    ViewIntDes3 getIntDes3Form();

    ViewIntRsa getIntRsaForm();

    ViewIntHash getIntHashForm();

    ViewIntMac getIntMacForm();

    ViewIntCert getIntCertForm();
}


