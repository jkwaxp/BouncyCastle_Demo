package util;

import java.io.*;

public class FileUtil {

    public static String readResource(String fileName){
        File file = new File(FileUtil.class.getClassLoader().getResource(fileName).getFile());

        try(FileInputStream is = new FileInputStream(file);
            ByteArrayOutputStream os = new ByteArrayOutputStream()){
            byte[] buf = new byte[512];
            int i = 0;
            while((i = is.read(buf)) > 0){
                os.write(buf, 0 , i);
            }
            return os.toString("UTF-8");
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }
}
