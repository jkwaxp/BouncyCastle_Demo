package alg.bc.nation.sm9;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * 负责加载 SM9 JNI 动态库（Windows: sm9jni.dll）。
 *
 * 约定：
 * - 开发/运行：可放在工作目录下：./sm9jni.dll
 * - 发布：可放在 ./lib/sm9jni.dll（与 bc-tool.exe 同级的 lib 目录）
 */
public final class Sm9JniLoader {

    private static volatile boolean loaded = false;
    private static volatile String lastError = null;

    private Sm9JniLoader() {
    }

    public static boolean isLoaded() {
        return loaded;
    }

    public static String getLastError(){
        return lastError;
    }

    public static synchronized void loadIfPossible() {
        if (loaded)
            return;
        lastError = null;

        // 1) 先尝试系统库路径（PATH / java.library.path）
        try {
            System.loadLibrary("sm9jni");
            loaded = true;
            return;
        } catch (Throwable ignored) {
            lastError = ignored.toString();
        }

        // 2) 再尝试从常见发布目录加载
        for (File dir : candidateDirs()) {
            // sm9jni.dll 依赖 gmssl.dll：很多 Windows 环境不会自动从“同目录”解析依赖
            // 先显式加载 gmssl.dll，再加载 sm9jni.dll
            tryLoadFromDir(dir, "gmssl.dll");
            if (tryLoadFromDir(dir, "sm9jni.dll")) {
                loaded = true;
                return;
            }
        }
    }

    public static String candidateHint() {
        StringBuilder sb = new StringBuilder();
        sb.append("未加载 SM9 JNI 动态库 sm9jni.dll。\n\n");
        if (lastError != null) {
            sb.append("最后一次加载失败原因：").append(lastError).append("\n\n");
        }
        sb.append("请将 sm9jni.dll 和 gmssl.dll 放到以下任一目录，然后重启应用：\n");
        for (File d : candidateDirs()) {
            sb.append("- ").append(d.getAbsolutePath()).append("\n");
        }
        sb.append("\n或确保 sm9jni.dll 在 PATH / java.library.path 中可被找到。\n");
        return sb.toString();
    }

    private static boolean tryLoadFromDir(File dir, String dllName) {
        if (dir == null)
            return false;
        try {
            File f = new File(dir, dllName);
            if (f.isFile()) {
                System.load(f.getAbsolutePath());
                return true;
            }
        } catch (Throwable t) {
            lastError = t.toString();
        }
        return false;
    }

    private static List<File> candidateDirs() {
        String dir = System.getProperty("user.dir");
        if (dir == null || dir.trim().isEmpty())
            dir = ".";
        File base = new File(dir);
        List<File> out = new ArrayList<>();
        out.add(base);
        out.add(new File(base, "lib"));
        out.add(new File(base, "bin"));
        out.add(new File(base, "dist"));
        out.add(new File(new File(base, "dist"), "bin"));
        out.add(new File(new File(base, "dist"), "lib"));
        return out;
    }
}
