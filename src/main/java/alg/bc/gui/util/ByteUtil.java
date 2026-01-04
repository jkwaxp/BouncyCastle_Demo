package alg.bc.gui.util;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;

public class ByteUtil {

    public static byte[] str2Bytes(String str, String encode){
        switch (encode){
            case "UTF-8":
                return str.getBytes(StandardCharsets.UTF_8);
            case "HEX":
                return Hex.decode(str);
            case "BASE64":
                return Base64.decode(str);
            default:
                throw new RuntimeException("未知的数据编码类型:" + encode);
        }
    }

    public static String bytes2Str(byte[] data, String encode){
        switch (encode){
            case "UTF-8":
                return new String(data, StandardCharsets.UTF_8);
            case "HEX":
                return Hex.toHexString(data);
            case "BASE64":
                return Base64.toBase64String(data);
            default:
                throw new RuntimeException("未知的数据编码类型:" + encode);
        }
    }

    public static byte[] readFile(String path){
        try(FileInputStream is = new FileInputStream(path);
            ByteArrayOutputStream os = new ByteArrayOutputStream()){
            byte[] buf = new byte[512];
            int i = 0;
            while((i = is.read(buf)) > 0){
                os.write(buf, 0 , i);
            }
            return os.toByteArray();
        }catch (Exception e){
            throw new RuntimeException("文件读取失败:" + e.getMessage());
        }
    }
}
