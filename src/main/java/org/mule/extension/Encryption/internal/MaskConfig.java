package org.mule.extension.Encryption.internal;

import org.mule.runtime.extension.api.annotation.param.display.DisplayName;

public class MaskConfig {

    private String field;
    private int startIndex;
    private int endIndex;
    private String maskChar;

    public MaskConfig() {}

    public MaskConfig(String field, int startIndex, int endIndex, String maskChar) {
        this.field = field;
        this.startIndex = startIndex;
        this.endIndex = endIndex;
        this.maskChar = maskChar;
    }

    @DisplayName("Field Name")
    public String getField() {
        return field;
    }

    public void setField(String field) {
        this.field = field;
    }

    @DisplayName("Start Index")
    public int getStartIndex() {
        return startIndex;
    }

    public void setStartIndex(int startIndex) {
        this.startIndex = startIndex;
    }

    @DisplayName("End Index")
    public int getEndIndex() {
        return endIndex;
    }

    public void setEndIndex(int endIndex) {
        this.endIndex = endIndex;
    }

    @DisplayName("Mask Character")
    public String getMaskChar() {
        return maskChar;
    }

    public void setMaskChar(String maskChar) {
        this.maskChar = maskChar;
    }
}