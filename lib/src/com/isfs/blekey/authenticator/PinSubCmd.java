/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator;

import java.util.stream.Collectors;
import java.util.function.Function;
import java.util.Map;
import java.util.Arrays;

public enum PinSubCmd {
    ERR(0x00),
    GETRETRY(0x01),
    GETKEY(0x02),
    SETPIN(0x03),
    CHANGEPIN(0x04),
    GETTKN(0x05),
    GETTKNUV(0x06),
    GETUVRETRY(0x07);

    private final int value;

    PinSubCmd(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    @Override
    public String toString() {
        return name();
    }

    private static Map<Integer, PinSubCmd> reverseLookup = 
            Arrays.stream(PinSubCmd.values())
                  .collect(Collectors.toMap(PinSubCmd::getValue, Function.identity()));

    public static PinSubCmd fromInt(final int id) {
        return reverseLookup.getOrDefault(id, ERR);
    }
}
