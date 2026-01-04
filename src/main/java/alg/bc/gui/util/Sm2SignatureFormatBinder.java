package alg.bc.gui.util;

import alg.bc.gui.Boot;
import alg.bc.nation.SM2;

import javax.swing.*;
import javax.swing.text.JTextComponent;
import java.awt.event.ItemEvent;

/**
 * 绑定 SM2 签名 RAW/ASN1 编码切换，并在切换时同步转换已有内容。
 */
public final class Sm2SignatureFormatBinder {

    private static final String PROP_PREV_FORMAT = "sm2.sign.prevFormat";
    private static final String PROP_SWITCH_GUARD = "sm2.sign.switchGuard";

    private Sm2SignatureFormatBinder() {
    }

    public static void bind(JRadioButton rawButton, JRadioButton asn1Button,
                            JComboBox<?> encodeComboBox, JTextComponent textComponent, String fieldName) {
        if (rawButton == null || asn1Button == null) {
            return;
        }
        ButtonGroup group = new ButtonGroup();
        group.add(rawButton);
        group.add(asn1Button);
        if (!rawButton.isSelected() && !asn1Button.isSelected()) {
            rawButton.setSelected(true);
        }
        String initFormat = rawButton.isSelected() ? "RAW" : "ASN1";
        rawButton.putClientProperty(PROP_PREV_FORMAT, initFormat);
        asn1Button.putClientProperty(PROP_PREV_FORMAT, initFormat);

        java.awt.event.ItemListener listener = e -> {
            if (e.getStateChange() != ItemEvent.SELECTED) {
                return;
            }
            handleSwitch(rawButton, asn1Button, encodeComboBox, textComponent, fieldName);
        };
        rawButton.addItemListener(listener);
        asn1Button.addItemListener(listener);
    }

    private static void handleSwitch(JRadioButton rawButton, JRadioButton asn1Button,
                                     JComboBox<?> encodeComboBox, JTextComponent textComponent, String fieldName) {
        if (Boolean.TRUE.equals(rawButton.getClientProperty(PROP_SWITCH_GUARD))) {
            return;
        }
        String prevFormat = (String) rawButton.getClientProperty(PROP_PREV_FORMAT);
        if (prevFormat == null) {
            prevFormat = rawButton.isSelected() ? "RAW" : "ASN1";
        }
        String newFormat = rawButton.isSelected() ? "RAW" : "ASN1";
        if (prevFormat.equalsIgnoreCase(newFormat)) {
            return;
        }

        String text = textComponent == null ? null : textComponent.getText();
        if (text == null || text.trim().isEmpty()) {
            rawButton.putClientProperty(PROP_PREV_FORMAT, newFormat);
            asn1Button.putClientProperty(PROP_PREV_FORMAT, newFormat);
            return;
        }

        String encode = "HEX";
        if (encodeComboBox != null && encodeComboBox.getSelectedItem() != null) {
            encode = encodeComboBox.getSelectedItem().toString();
        }

        try {
            String normalized = text;
            if ("HEX".equalsIgnoreCase(encode) || "BASE64".equalsIgnoreCase(encode)) {
                normalized = text.replaceAll("\\s+", "");
            }
            byte[] bytes = ByteUtil.str2Bytes(normalized, encode);
            byte[] converted;
            if ("RAW".equalsIgnoreCase(prevFormat) && "ASN1".equalsIgnoreCase(newFormat)) {
                converted = SM2.rsToAns1(bytes);
            } else {
                converted = SM2.ans1ToRs(bytes);
            }
            if (textComponent != null) {
                textComponent.setText(ByteUtil.bytes2Str(converted, encode));
            }
            rawButton.putClientProperty(PROP_PREV_FORMAT, newFormat);
            asn1Button.putClientProperty(PROP_PREV_FORMAT, newFormat);
        } catch (Exception ex) {
            rawButton.putClientProperty(PROP_SWITCH_GUARD, Boolean.TRUE);
            try {
                if ("RAW".equalsIgnoreCase(prevFormat)) {
                    rawButton.setSelected(true);
                } else {
                    asn1Button.setSelected(true);
                }
            } finally {
                rawButton.putClientProperty(PROP_SWITCH_GUARD, Boolean.FALSE);
            }
            String name = fieldName == null ? "签名值" : fieldName;
            String msg = ex.getMessage();
            if (msg == null || msg.trim().isEmpty()) {
                msg = ex.getClass().getSimpleName();
            }
            CompUtil.showErr(Boot.frame, name + "无法按 " + prevFormat + " 格式解析，不能切换到 " + newFormat + "：\n" + msg);
        }
    }
}

