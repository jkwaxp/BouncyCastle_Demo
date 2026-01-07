package alg.bc.gui.util;

/**
 * AWT事件线程异常处理器
 * 用于捕获Swing/AWT事件分发线程中的异常
 */
public class AwtExceptionHandler {
    public void handle(Throwable t) {
        Logger.error("AWT事件线程异常", t);
    }
}
