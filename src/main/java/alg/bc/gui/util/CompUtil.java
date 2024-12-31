package alg.bc.gui.util;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EtchedBorder;
import java.awt.*;
import java.io.File;

/**
 *
 */
public class CompUtil {

    public static void addCircleBoard(JComponent comp, String text){
        Border oldBorder = comp.getBorder();
        Border newBorder = BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(EtchedBorder.RAISED), text);
        comp.setBorder(oldBorder == null ? newBorder : new CompoundBorder(newBorder, oldBorder));
    }
    public static void centerInScreen(JFrame win) {
        Dimension sz = win.getPreferredSize();
        Toolkit tk = Toolkit.getDefaultToolkit();
        if (tk == null) {
            win.setLocation(20, 20);
            return;
        }
        Dimension ssz = tk.getScreenSize();
        win.setLocation(ssz.width / 2 - sz.width / 2, ssz.height / 2 - sz.height / 2);
    }

    public static void centerInScreen(JFrame win, int width, int height) {
        Dimension sz = new Dimension(width, height);
        win.setSize(sz);
        Toolkit tk = Toolkit.getDefaultToolkit();
        if (tk == null) {
            win.setLocation(20, 20);
            return;
        }
        Dimension ssz = tk.getScreenSize();
        win.setLocation(ssz.width / 2 - sz.width / 2, ssz.height / 2 - sz.height / 2);
    }

    public static String chooseFile(JFrame win, String title){
        FileDialog fwin = new FileDialog(win, title, FileDialog.LOAD);
        fwin.setVisible(true);
        String parentStr = fwin.getDirectory();
        String dirStr = fwin.getFile();
        if (parentStr == null || dirStr == null) return "";
        return parentStr + File.separator + dirStr;
    }

    public static String saveFile(JFrame win, String title){
        FileDialog fwin = new FileDialog(win, title, FileDialog.SAVE);
        fwin.setVisible(true);
        String parentStr = fwin.getDirectory();
        String dirStr = fwin.getFile();
        if (parentStr == null || dirStr == null) return null;
        return parentStr + File.separator + dirStr;
    }

    public static void showSingleLineMsg(JFrame win, String title, String content){
        JTextArea textArea = new JTextArea(1, 30);
        textArea.setText(content);
        textArea.setEditable(false);
        textArea.setWrapStyleWord(true);
        textArea.setLineWrap(true);
        textArea.setCaretPosition(0);
        JScrollPane scrollPane = new JScrollPane(textArea);
        scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        JOptionPane.showMessageDialog(win, scrollPane, title == null ? "INFO" : title, JOptionPane.PLAIN_MESSAGE);
    }
    public static void showMsg(JFrame win, String content){
        JOptionPane.showMessageDialog(win, content, "INFO", JOptionPane.PLAIN_MESSAGE);
    }
    public static void showMsg(JFrame win, String title, String content){
        JOptionPane.showMessageDialog(win, content, title == null ? "INFO" : title, JOptionPane.PLAIN_MESSAGE);
    }
    public static void showErr(JFrame win, String content){
        JOptionPane.showMessageDialog(win, content, "ERROR", JOptionPane.ERROR_MESSAGE);
    }

    public static void showErr(JFrame win, String title, String content){
        JOptionPane.showMessageDialog(win, content, title == null ? "ERROR" : title, JOptionPane.ERROR_MESSAGE);
    }

    public static int showConfirm(JFrame win, String title, String content){
        return JOptionPane.showConfirmDialog(win, content, title == null ? "INFO" : title, JOptionPane.PLAIN_MESSAGE);
    }
}
