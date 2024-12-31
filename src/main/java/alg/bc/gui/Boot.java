package alg.bc.gui;

import alg.bc.gui.util.CompUtil;
import alg.bc.gui.view.MainWindow;

import javax.swing.*;

public class Boot {
    public static JFrame frame = null;
    public static void main(String[] args) {
        frame = new JFrame("算法库工具");
        frame.setContentPane(new MainWindow(frame).getMainPanel());
        CompUtil.centerInScreen(frame);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.pack();
        frame.setVisible(true);
    }
}
