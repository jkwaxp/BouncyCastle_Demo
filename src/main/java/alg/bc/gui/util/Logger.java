package alg.bc.gui.util;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * 简单的日志工具类，用于Native Image运行时的错误诊断
 * 日志会同时输出到控制台和文件
 */
public class Logger {
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final boolean DEBUG = Boolean.getBoolean("bc.debug") || "true".equals(System.getenv("BC_DEBUG"));
    private static final String LOG_FILE;
    private static FileWriter fileWriter;

    static {
        // 在程序当前目录下创建日志文件
        String logPath = "bc-tool.log";
        try {
            logPath = Paths.get(System.getProperty("user.dir"), "bc-tool.log").toString();
        } catch (Exception e) {
            // 使用默认路径
        }
        LOG_FILE = logPath;

        // 初始化文件写入器
        try {
            fileWriter = new FileWriter(LOG_FILE, false); // false = 覆盖原有日志
            fileWriter.write("========== BC-Tool 日志 ==========\n");
            fileWriter.write("启动时间: " + LocalDateTime.now().format(formatter) + "\n");
            fileWriter.write("==================================\n\n");
            fileWriter.flush();
        } catch (Exception e) {
            System.err.println("无法创建日志文件: " + LOG_FILE);
            e.printStackTrace();
        }
    }

    public static void info(String message) {
        log("INFO", message, null);
    }

    public static void error(String message) {
        log("ERROR", message, null);
    }

    public static void error(String message, Throwable t) {
        log("ERROR", message, t);
    }

    public static void debug(String message) {
        log("DEBUG", message, null);
    }

    private static void log(String level, String message, Throwable t) {
        try {
            String timestamp = LocalDateTime.now().format(formatter);
            String logMessage = String.format("[%s] [%s] %s%n", timestamp, level, message);

            // 1. 输出到控制台
            System.err.print(logMessage);

            // 2. 输出到文件
            if (fileWriter != null) {
                synchronized (fileWriter) {
                    fileWriter.write(logMessage);

                    if (t != null) {
                        StringWriter sw = new StringWriter();
                        PrintWriter pw = new PrintWriter(sw);
                        t.printStackTrace(pw);
                        fileWriter.write(sw.toString());
                        fileWriter.write("\n");
                    }

                    fileWriter.flush();
                }
            }

            // 3. 输出异常到控制台
            if (t != null) {
                t.printStackTrace(System.err);
            }

            System.err.flush();
        } catch (Exception e) {
            System.err.println("Logger error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }

    /**
     * 记录ActionListener事件执行
     */
    public static void logAction(String actionCommand, String component) {
        info("Action执行: " + actionCommand + " (组件: " + component + ")");
    }

    /**
     * 记录ActionListener异常
     */
    public static void logActionError(String actionCommand, String component, Throwable t) {
        error("Action执行失败: " + actionCommand + " (组件: " + component + ")", t);
    }

    /**
     * 获取日志文件路径
     */
    public static String getLogFilePath() {
        return LOG_FILE;
    }
}
