package alg.bc.gui.action;

import alg.bc.gui.view.TabSm4;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class ActionSm4 implements ActionListener {
    TabSm4 tabSm4;

    public ActionSm4(TabSm4 tabSm4){
        this.tabSm4 = tabSm4;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        String cmd = e.getActionCommand();
        switch (cmd) {
            case "generateSm4Key":
                generateSm4Key();
                break;
            default:
                break;
        }
    }

    private void generateSm4Key() {

    }
}
