
package com.example.blehidfido2.ctap;

public enum CtapHidCmd {
    MSG(0x03),
    CBOR(0x10),
    INIT(0x06),
    PING(0x01),
    CANCEL(0x11),
    ERROR(0x3f),
    KEEP_ALIVE(0x3b),
    WINK(0x08),
    LOCK(0x04);

    private final int value;

    CtapHidCmd(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    @Override
    public String toString() {
        return name();
    }
}