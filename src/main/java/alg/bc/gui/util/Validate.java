package alg.bc.gui.util;

import java.io.File;
import java.util.Arrays;

/**
 * GUI 参数校验工具：
 * - 统一处理空值、编码解码、长度约束
 * - 失败时抛出 IllegalArgumentException，供 Action 捕获并弹窗提示
 */
public final class Validate {

    private Validate() {
    }

    public static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }

    public static String requireNotBlank(String s, String fieldName) {
        if (isBlank(s)) {
            throw new IllegalArgumentException(fieldName + "不能为空");
        }
        return s;
    }

    /**
     * 对 HEX/BASE64：自动去掉所有空白字符（方便粘贴带换行的数据）
     * 对 UTF-8：保留原始内容（仅用于判断是否为空白）
     */
    public static byte[] requireBytes(String raw, String encode, String fieldName) {
        requireNotBlank(raw, fieldName);
        String normalized = raw;
        if ("HEX".equalsIgnoreCase(encode) || "BASE64".equalsIgnoreCase(encode)) {
            normalized = raw.replaceAll("\\s+", "");
            if (normalized.isEmpty()) {
                throw new IllegalArgumentException(fieldName + "不能为空");
            }
        }
        try {
            return ByteUtil.str2Bytes(normalized, encode);
        } catch (Exception ex) {
            String enc = encode == null ? "" : encode.toUpperCase();
            throw new IllegalArgumentException(fieldName + "格式不正确（期望 " + enc + "）");
        }
    }

    public static void requireExactLength(byte[] data, int len, String fieldName) {
        if (data == null) {
            throw new IllegalArgumentException(fieldName + "不能为空");
        }
        if (data.length != len) {
            throw new IllegalArgumentException(fieldName + "长度必须为 " + len + " 字节（当前 " + data.length + " 字节）");
        }
    }

    public static void requireLengthIn(byte[] data, int[] lens, String fieldName) {
        if (data == null) {
            throw new IllegalArgumentException(fieldName + "不能为空");
        }
        for (int l : lens) {
            if (data.length == l) return;
        }
        throw new IllegalArgumentException(fieldName + "长度必须为 " + Arrays.toString(lens) + " 字节（当前 " + data.length + " 字节）");
    }

    public static void requireBlockMultiple(byte[] data, int blockSize, String fieldName) {
        if (data == null) {
            throw new IllegalArgumentException(fieldName + "不能为空");
        }
        if (blockSize <= 0) return;
        if ((data.length % blockSize) != 0) {
            throw new IllegalArgumentException(fieldName + "长度必须是 " + blockSize + " 字节的整数倍（当前 " + data.length + " 字节）");
        }
    }

    public static void requireFileExists(String path, String fieldName) {
        requireNotBlank(path, fieldName);
        File f = new File(path);
        if (!f.exists() || !f.isFile()) {
            throw new IllegalArgumentException(fieldName + "不存在或不是文件: " + path);
        }
    }

    // ----------------- 国密专项校验 -----------------

    /**
     * SM2 公钥允许：33(压缩)/64(裸XY)/65(未压缩带04前缀)
     */
    public static byte[] requireSm2PublicKey(String raw, String encode, String fieldName) {
        byte[] pub = requireBytes(raw, encode, fieldName);
        requireLengthIn(pub, new int[]{33, 64, 65}, fieldName);
        if (pub.length == 33) {
            int b0 = pub[0] & 0xFF;
            if (b0 != 0x02 && b0 != 0x03) {
                throw new IllegalArgumentException(fieldName + "为33字节时必须是压缩公钥（首字节应为 02/03）");
            }
        }
        if (pub.length == 65) {
            int b0 = pub[0] & 0xFF;
            if (b0 != 0x04) {
                throw new IllegalArgumentException(fieldName + "为65字节时必须是未压缩公钥（首字节应为 04）");
            }
        }
        return pub;
    }

    /**
     * SM2 私钥通常为 32 字节；为了兼容前导 0 被省略的情况，允许 1..32 字节。
     */
    public static byte[] requireSm2PrivateKey(String raw, String encode, String fieldName) {
        byte[] prv = requireBytes(raw, encode, fieldName);
        if (prv.length < 1 || prv.length > 32) {
            throw new IllegalArgumentException(fieldName + "长度应在 1..32 字节（当前 " + prv.length + " 字节）");
        }
        return prv;
    }

    /**
     * SM2 标准签名（PlainDSAEncoding）为 64 字节 R||S。
     */
    public static byte[] requireSm2SignaturePlain(String raw, String encode, String fieldName) {
        byte[] sig = requireBytes(raw, encode, fieldName);
        requireExactLength(sig, 64, fieldName);
        return sig;
    }
}


