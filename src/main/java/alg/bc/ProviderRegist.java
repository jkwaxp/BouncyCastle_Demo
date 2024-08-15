package alg.bc;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class ProviderRegist {
    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
}
