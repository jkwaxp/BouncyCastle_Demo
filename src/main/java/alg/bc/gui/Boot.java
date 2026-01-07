package alg.bc.gui;

import alg.bc.gui.util.CompUtil;
import alg.bc.gui.util.Logger;
import alg.bc.gui.view.MainWindow;
import alg.bc.nation.sm9.Sm9JniLoader;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.swing.*;
import javax.swing.plaf.FontUIResource;
import java.awt.Component;
import java.awt.Container;
import java.awt.Font;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.Security;

public class Boot {
    public static JFrame frame = null;

    // GraalVM native-image: some AWT Windows native code uses JNI FindClass for
    // these types.
    // Keep them reachable so they are not removed by closed-world analysis.
    @SuppressWarnings("unused")
    private static final Class<?>[] NATIVE_AWT_KEEPALIVE = new Class<?>[] {
            java.awt.event.MouseWheelEvent.class,
            java.awt.event.MouseWheelListener.class
    };

    public static void main(String[] args) {
        // 必须在最开始注册BouncyCastle Provider
        Security.addProvider(new BouncyCastleProvider());

        // 设置全局异常处理器，捕获所有未处理的异常
        Thread.setDefaultUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler() {
            @Override
            public void uncaughtException(Thread t, Throwable e) {
                Logger.error("未捕获的异常 (线程: " + t.getName() + ")", e);
            }
        });

        // 设置AWT事件线程的异常处理
        System.setProperty("sun.awt.exception.handler", "alg.bc.gui.util.AwtExceptionHandler");

        Logger.info("应用程序启动...");
        Logger.info("Native Image模式: " + isNativeImage());

        // Native-image 下需要 java.home 才能找到 fontconfig.*（否则会直接抛错）
        if (isNativeImage()) {
            setupNativeImageUiScaleAndDpi();
            setupNativeImageFonts();
            // 让部分 AWT/Swing 在 Windows 下通过 JNI 调用的构造器保持可达（必须在字体系统初始化之后）
            ensureNativeJniKeepalive();
        }

        // jar/jpackage 运行：优先系统 LAF；native-image：强制 Metal（Windows LAF 依赖大量内部
        // JNI/字段，native-image 下不稳定）
        try {
            if (isNativeImage()) {
                UIManager.setLookAndFeel("javax.swing.plaf.metal.MetalLookAndFeel");
            } else {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            }
        } catch (Exception ignored) {
        }

        // 避免某些环境下 invokeLater 里的 UI 任务还没跑，main 就结束导致 JVM 直接退出
        try {
            java.awt.Toolkit.getDefaultToolkit();
        } catch (Throwable ignored) {
        }

        // Native-image 下：尽量显式设置可用的 CJK 字体，避免字体度量异常导致布局坍缩
        if (isNativeImage()) {
            try {
                FontUIResource font = new FontUIResource(selectNativeCjkFont(14));
                applyFontToUiDefaults(font);
            } catch (Throwable ignored) {
            }
        }

        // 尝试预加载 SM9 JNI（不强依赖；失败也不影响启动）
        try {
            Sm9JniLoader.loadIfPossible();
        } catch (Throwable ignored) {
        }

        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                try {
                    frame = new JFrame("算法工具");
                    MainWindow mainWindow = new MainWindow(frame);
                    JComponent root = mainWindow.getMainPanel();

                    if (isNativeImage()) {
                        // native-image 下 TAB 非 TOP 时在部分 Windows 环境会出现渲染问题：强制 TOP
                        forceTopTabs(root);
                    }

                    frame.setContentPane(root);
                    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

                    // 优先 pack()；如果 native-image 下仍出现字体度量异常，则回退固定尺寸
                    try {
                        frame.pack();
                    } catch (Throwable ignored) {
                        frame.setSize(900, 700);
                    }

                    CompUtil.centerInScreen(frame);
                    frame.setVisible(true);

                    if (isNativeImage()) {
                        // native-image 下不要调用 updateComponentTreeUI：它会把我们覆盖的字体 defaults 重置回 LAF 默认值
                        SwingUtilities.invokeLater(new Runnable() {
                            @Override
                            public void run() {
                                try {
                                    Font f = selectNativeCjkFont(14);
                                    // 1) 覆盖 defaults（给后续 UI delegate/组件）
                                    applyFontToUiDefaults(new FontUIResource(f));
                                    // 2) 直接递归 setFont（给已创建组件）
                                    applyFontRecursively(frame, f);
                                    frame.invalidate();
                                    frame.validate();
                                    frame.repaint();
                                } catch (Throwable ignored) {
                                }
                            }
                        });
                    }
                } catch (Throwable t) {
                    // IDEA / jar 运行时不要吞异常，否则会“启动即退出”且无任何提示
                    if (!isNativeImage()) {
                        try {
                            t.printStackTrace();
                        } catch (Throwable ignored) {
                        }
                        try {
                            JOptionPane.showMessageDialog(null, "启动失败：\n" + t, "错误", JOptionPane.ERROR_MESSAGE);
                        } catch (Throwable ignored) {
                        }
                    }
                }
            }
        });
    }

    public static boolean isNativeImage() {
        return System.getProperty("org.graalvm.nativeimage.imagecode") != null;
    }

    private static void setupNativeImageUiScaleAndDpi() {
        System.setProperty("sun.java2d.dpiaware", "true");
        // 不强行关闭渲染管线：某些环境下会导致字体度量/渲染异常
        // （native-image 默认值更接近 jar 运行行为）

        // Windows 下强制用 Win32 字体管理器，并告知字体目录（对某些 native-image 版本有帮助）
        try {
            String os = System.getProperty("os.name", "");
            if (os.toLowerCase().contains("win")) {
                System.setProperty("sun.font.fontmanager", "sun.awt.Win32FontManager");
                String windir = System.getenv("WINDIR");
                if (windir != null && !windir.trim().isEmpty()) {
                    System.setProperty("sun.java2d.fontpath", windir + "\\Fonts");
                    // 额外提示 AWT 字体扫描目录（不会替代 fontpath，但能在某些环境下触发额外加载）
                    System.setProperty("java.awt.fonts", windir + "\\Fonts");
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private static void setupNativeImageFonts() {
        try {
            // native-image 下 java.home 可能为空：用 user.dir 作为伪 java.home，给 fontconfig 找路径
            String javaHome = System.getProperty("java.home");
            if (javaHome == null || javaHome.trim().isEmpty()) {
                javaHome = System.getProperty("user.dir");
                System.setProperty("java.home", javaHome);
            }
            Path libDir = new File(javaHome, "lib").toPath();
            if (!Files.exists(libDir)) {
                Files.createDirectories(libDir);
            }
            extractResourceToFile("/fontconfig.bfc", new File(libDir.toFile(), "fontconfig.bfc"));
            extractResourceToFile("/fontconfig.properties", new File(libDir.toFile(), "fontconfig.properties"));
        } catch (Exception e) {
            // ignore
        }
    }

    private static Font selectNativeCjkFont(int size) {
        // 优先这些字体（命中任一即可）；找不到就回退 Dialog
        String[] preferred = new String[] {
                "Microsoft YaHei", "微软雅黑",
                "SimSun", "宋体",
                "SimHei", "黑体",
                "Microsoft JhengHei UI", "Microsoft JhengHei"
        };
        try {
            String[] families = java.awt.GraphicsEnvironment.getLocalGraphicsEnvironment()
                    .getAvailableFontFamilyNames();
            for (String want : preferred) {
                for (String fam : families) {
                    if (fam.equalsIgnoreCase(want)) {
                        return new java.awt.Font(fam, java.awt.Font.PLAIN, size);
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return new java.awt.Font(java.awt.Font.DIALOG, java.awt.Font.PLAIN, size);
    }

    private static void applyFontToUiDefaults(FontUIResource font) {
        // 注意：在 Windows/Metal 下，Toolkit 初始化后可能会重新装载 LAF defaults。
        // 所以需要同时覆盖 getDefaults() 与 getLookAndFeelDefaults()，并显式覆盖核心键。
        UIDefaults[] targets = new UIDefaults[] {
                UIManager.getDefaults(),
                UIManager.getLookAndFeelDefaults()
        };
        for (UIDefaults defaults : targets) {
            if (defaults == null)
                continue;
            Object[] keys = defaults.keySet().toArray();
            for (Object key : keys) {
                if (key instanceof String && ((String) key).endsWith(".font")) {
                    defaults.put(key, font);
                }
            }
        }

        // 显式覆盖常用键，避免 keySet() union / MultiUIDefaults 的边界情况
        try {
            UIManager.put("Label.font", font);
            UIManager.put("Button.font", font);
            UIManager.put("ToggleButton.font", font);
            UIManager.put("RadioButton.font", font);
            UIManager.put("CheckBox.font", font);
            UIManager.put("ComboBox.font", font);
            UIManager.put("TextField.font", font);
            UIManager.put("TextArea.font", font);
            UIManager.put("TextPane.font", font);
            UIManager.put("EditorPane.font", font);
            UIManager.put("PasswordField.font", font);
            UIManager.put("TabbedPane.font", font);
            UIManager.put("Table.font", font);
            UIManager.put("Tree.font", font);
            UIManager.put("Menu.font", font);
            UIManager.put("MenuItem.font", font);
            UIManager.put("PopupMenu.font", font);
            UIManager.put("OptionPane.messageFont", font);
            UIManager.put("OptionPane.buttonFont", font);
        } catch (Throwable ignored) {
        }
    }

    private static void applyFontRecursively(Component component, Font font) {
        if (component == null || font == null)
            return;
        try {
            component.setFont(font);
        } catch (Throwable ignored) {
        }
        if (component instanceof Container) {
            Component[] children;
            try {
                children = ((Container) component).getComponents();
            } catch (Throwable t) {
                return;
            }
            if (children != null) {
                for (Component child : children) {
                    applyFontRecursively(child, font);
                }
            }
        }
    }

    private static void forceTopTabs(Component component) {
        if (component instanceof JTabbedPane) {
            ((JTabbedPane) component).setTabPlacement(JTabbedPane.TOP);
        }
        if (component instanceof Container) {
            Component[] children;
            try {
                children = ((Container) component).getComponents();
            } catch (Throwable t) {
                return;
            }
            if (children != null) {
                for (Component child : children) {
                    forceTopTabs(child);
                }
            }
        }
    }

    private static void extractResourceToFile(String resourcePath, File targetFile) throws IOException {
        try (InputStream is = Boot.class.getResourceAsStream(resourcePath)) {
            if (is != null) {
                Files.copy(is, targetFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
            }
        }
    }

    private static void ensureNativeJniKeepalive() {
        try {
            // Windows ThemeReader 会通过 JNI 调用 Color(int,int,int)；显式创建一次避免被裁剪
            new java.awt.Color(0, 0, 0);
        } catch (Throwable ignored) {
        }
    }
}
