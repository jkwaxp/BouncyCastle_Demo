package alg.bc.nation.sm9;

/**
 * SM9 JNI 接口（由 sm9jni.dll 提供实现）。
 *
 * 说明：
 * - 这里采用“纯 byte[]”协议，便于 GUI 的 HEX/BASE64/UTF-8 切换与 native-image 传递。
 * - 具体编码格式由 sm9jni.dll 定义（建议使用 DER 或固定二进制结构）。
 */
public final class Sm9Native {

    private Sm9Native() {
    }

    /**
     * @param purpose 1=ENC（加密），2=SIGN（签名）
     * @return [0]=msk（主私钥/主密钥）, [1]=mpk（主公钥）
     */
    public static native byte[][] kgcGenerateMasterKeyPair(int purpose);

    /**
     * @param purpose      1=ENC（加密），2=SIGN（签名）
     * @param masterSecret msk
     * @param userIdBytes  userId（UTF-8 bytes）
     * @return userPrivateKey bytes
     */
    public static native byte[] kgcDeriveUserPrivateKey(int purpose, byte[] masterSecret, byte[] userIdBytes);

    /**
     * IBE 加密：使用主公钥 + userId
     */
    public static native byte[] encrypt(byte[] masterPublicEnc, byte[] userIdBytes, byte[] plaintext);

    /**
     * IBE 解密：使用用户私钥 + userId
     */
    public static native byte[] decrypt(byte[] userPrivateEnc, byte[] userIdBytes, byte[] ciphertext);

    /**
     * IBS 签名：使用用户签名私钥 + userId
     */
    public static native byte[] sign(byte[] userPrivateSign, byte[] userIdBytes, byte[] message);

    /**
     * IBS 验签：使用主签名公钥 + userId
     */
    public static native boolean verify(byte[] masterPublicSign, byte[] userIdBytes, byte[] message, byte[] signature);
}
