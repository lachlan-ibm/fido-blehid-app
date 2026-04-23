/*
 * Copyright IBM 2025, 2026
 */

package com.isfs.blekey.ctap;

public enum CtapHidCmd {
    ERR(0x00),
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
    
    /**
     * Looks up a CtapHidCmd enum by its integer value.
     *
     * @param value The integer value to look up
     * @return The corresponding CtapHidCmd enum value
     * @throws IllegalArgumentException if no matching enum value is found
     */
    public static CtapHidCmd fromValue(int value) {
        for (CtapHidCmd cmd : CtapHidCmd.values()) {
            if (cmd.getValue() == value) {
                return cmd;
            }
        }
        throw new IllegalArgumentException("Unknown command value: " + value);
    }

    @Override
    public String toString() {
        return name();
    }
}