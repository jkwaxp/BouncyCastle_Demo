package alg.bc.nation.sm9;

import java.nio.charset.StandardCharsets;

/**
 * SM9 Java 封装（JNI 驱动）。
 *
 * 注意：
 * - 本类只负责：加载 DLL、参数转换、统一错误提示。
 * - 真实 SM9 算法由 sm9jni.dll 实现（可对接 GmSSL 或自研 C 库）。
 */
public final class Sm9 {

    public static final int PURPOSE_ENC = 1;
    public static final int PURPOSE_SIGN = 2;

    private Sm9() {
    }

    public static boolean available() {
        Sm9JniLoader.loadIfPossible();
        return Sm9JniLoader.isLoaded();
    }

    public static byte[][] kgcGenerateMasterKeyPair(int purpose) {
        ensureAvailable();
        return Sm9Native.kgcGenerateMasterKeyPair(purpose);
    }

    public static byte[] kgcDeriveUserPrivateKey(int purpose, byte[] masterSecret, String userId) {
        ensureAvailable();
        if (masterSecret == null || masterSecret.length == 0) {
            throw new IllegalArgumentException("主密钥(msk)不能为空");
        }
        if (userId == null || userId.trim().isEmpty()) {
            throw new IllegalArgumentException("用户ID不能为空");
        }
        return Sm9Native.kgcDeriveUserPrivateKey(purpose, masterSecret, userId.trim().getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] encrypt(byte[] masterPublicEnc, String userId, byte[] plaintext) {
        ensureAvailable();
        if (masterPublicEnc == null || masterPublicEnc.length == 0) {
            throw new IllegalArgumentException("加密主公钥(mpkEnc)不能为空");
        }
        if (userId == null || userId.trim().isEmpty()) {
            throw new IllegalArgumentException("接收方ID不能为空");
        }
        if (plaintext == null || plaintext.length == 0) {
            throw new IllegalArgumentException("明文不能为空");
        }
        return Sm9Native.encrypt(masterPublicEnc, userId.trim().getBytes(StandardCharsets.UTF_8), plaintext);
    }

    public static byte[] decrypt(byte[] userPrivateEnc, String userId, byte[] ciphertext) {
        ensureAvailable();
        if (userPrivateEnc == null || userPrivateEnc.length == 0) {
            throw new IllegalArgumentException("用户加密私钥(skEnc)不能为空");
        }
        if (userId == null || userId.trim().isEmpty()) {
            throw new IllegalArgumentException("接收方ID不能为空");
        }
        if (ciphertext == null || ciphertext.length == 0) {
            throw new IllegalArgumentException("密文不能为空");
        }
        return Sm9Native.decrypt(userPrivateEnc, userId.trim().getBytes(StandardCharsets.UTF_8), ciphertext);
    }

    public static byte[] sign(byte[] userPrivateSign, String userId, byte[] message) {
        ensureAvailable();
        if (userPrivateSign == null || userPrivateSign.length == 0) {
            throw new IllegalArgumentException("用户签名私钥(skSign)不能为空");
        }
        if (userId == null || userId.trim().isEmpty()) {
            throw new IllegalArgumentException("签名者ID不能为空");
        }
        if (message == null || message.length == 0) {
            throw new IllegalArgumentException("待签名数据不能为空");
        }
        return Sm9Native.sign(userPrivateSign, userId.trim().getBytes(StandardCharsets.UTF_8), message);
    }

    public static boolean verify(byte[] masterPublicSign, String userId, byte[] message, byte[] signature) {
        ensureAvailable();
        if (masterPublicSign == null || masterPublicSign.length == 0) {
            throw new IllegalArgumentException("签名主公钥(mpkSign)不能为空");
        }
        if (userId == null || userId.trim().isEmpty()) {
            throw new IllegalArgumentException("签名者ID不能为空");
        }
        if (message == null || message.length == 0) {
            throw new IllegalArgumentException("待验签数据不能为空");
        }
        if (signature == null || signature.length == 0) {
            throw new IllegalArgumentException("签名值不能为空");
        }
        return Sm9Native.verify(masterPublicSign, userId.trim().getBytes(StandardCharsets.UTF_8), message, signature);
    }

    private static void ensureAvailable() {
        if (!available()) {
            throw new IllegalStateException(Sm9JniLoader.candidateHint());
        }
    }
}
