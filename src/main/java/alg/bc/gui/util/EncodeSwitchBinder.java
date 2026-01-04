package alg.bc.gui.util;

import alg.bc.gui.Boot;

import javax.swing.*;
import javax.swing.text.JTextComponent;
import java.awt.event.ItemEvent;

/**
 * 编码下拉框/单选框切换时，把对应文本框内容按新编码重新编码回填。
 *
 * 规则：
 * - 记录“旧编码”，切换时：旧编码解码 -> 新编码编码
 * - 内容为空：不处理
 * - 解码失败：弹窗提示并回退到旧选项
 */
public final class EncodeSwitchBinder {

    private static final String PROP_PREV_ENCODE = "bc.prevEncode";
    private static final String PROP_GUARD = "bc.encodeSwitch.guard";

    private EncodeSwitchBinder() {
    }

    public static void bind(JComboBox<?> encodeComboBox, JTextComponent textComponent, String fieldName) {
        if (encodeComboBox == null || textComponent == null) return;
        Object init = encodeComboBox.getSelectedItem();
        if (init != null) {
            encodeComboBox.putClientProperty(PROP_PREV_ENCODE, init.toString());
        }

        encodeComboBox.addItemListener(e -> {
            if (e.getStateChange() != ItemEvent.SELECTED) return;
            if (Boolean.TRUE.equals(encodeComboBox.getClientProperty(PROP_GUARD))) return;

            Object newSel = encodeComboBox.getSelectedItem();
            if (newSel == null) return;
            String newEnc = newSel.toString();

            String oldEnc = (String) encodeComboBox.getClientProperty(PROP_PREV_ENCODE);
            if (oldEnc == null) {
                encodeComboBox.putClientProperty(PROP_PREV_ENCODE, newEnc);
                return;
            }
            if (oldEnc.equalsIgnoreCase(newEnc)) return;

            String raw = textComponent.getText();
            if (raw == null || raw.trim().isEmpty()) {
                encodeComboBox.putClientProperty(PROP_PREV_ENCODE, newEnc);
                return;
            }

            try {
                String normalized = raw;
                if ("HEX".equalsIgnoreCase(oldEnc) || "BASE64".equalsIgnoreCase(oldEnc)) {
                    normalized = raw.replaceAll("\\s+", "");
                }
                byte[] bytes = ByteUtil.str2Bytes(normalized, oldEnc);
                String converted = ByteUtil.bytes2Str(bytes, newEnc);
                textComponent.setText(converted);
                encodeComboBox.putClientProperty(PROP_PREV_ENCODE, newEnc);
            } catch (Exception ex) {
                // 回退到旧选项
                encodeComboBox.putClientProperty(PROP_GUARD, Boolean.TRUE);
                try {
                    encodeComboBox.setSelectedItem(oldEnc);
                } finally {
                    encodeComboBox.putClientProperty(PROP_GUARD, Boolean.FALSE);
                }
                CompUtil.showErr(Boot.frame, (fieldName == null ? "内容" : fieldName) + "无法按当前编码(" + oldEnc + ")解析，不能切换到 " + newEnc);
            }
        });
    }

    public static void bindHexBase64(JRadioButton hexRadioButton, JRadioButton base64RadioButton, JTextComponent[] targets, String fieldName) {
        if (hexRadioButton == null || base64RadioButton == null || targets == null) return;
        final String[] prev = new String[]{hexRadioButton.isSelected() ? "HEX" : "BASE64"};
        final boolean[] guard = new boolean[]{false};

        Runnable onChange = () -> {
            if (guard[0]) return;
            String newEnc = hexRadioButton.isSelected() ? "HEX" : "BASE64";
            String oldEnc = prev[0];
            if (oldEnc.equalsIgnoreCase(newEnc)) return;

            // 全部都能转换才提交；任何一个失败就整体回退
            String[] newTexts = new String[targets.length];
            try {
                for (int i = 0; i < targets.length; i++) {
                    JTextComponent t = targets[i];
                    if (t == null) continue;
                    String raw = t.getText();
                    if (raw == null || raw.trim().isEmpty()) {
                        newTexts[i] = raw;
                        continue;
                    }
                    String normalized = raw.replaceAll("\\s+", "");
                    byte[] bytes = ByteUtil.str2Bytes(normalized, oldEnc);
                    newTexts[i] = ByteUtil.bytes2Str(bytes, newEnc);
                }
            } catch (Exception ex) {
                guard[0] = true;
                try {
                    if ("HEX".equalsIgnoreCase(oldEnc)) {
                        hexRadioButton.setSelected(true);
                    } else {
                        base64RadioButton.setSelected(true);
                    }
                } finally {
                    guard[0] = false;
                }
                CompUtil.showErr(Boot.frame, (fieldName == null ? "内容" : fieldName) + "无法按当前编码(" + oldEnc + ")解析，不能切换到 " + newEnc);
                return;
            }

            for (int i = 0; i < targets.length; i++) {
                if (targets[i] != null && newTexts[i] != null) {
                    targets[i].setText(newTexts[i]);
                }
            }
            prev[0] = newEnc;
        };

        hexRadioButton.addActionListener(e -> onChange.run());
        base64RadioButton.addActionListener(e -> onChange.run());
    }
}


