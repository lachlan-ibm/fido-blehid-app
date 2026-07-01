/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator;

import java.util.stream.Collectors;
import java.util.function.Function;
import java.util.Map;
import java.util.Arrays;

public enum AuthenticatorCmd {
    ERR(0x00),
    MKCRED(0x01),
    NXTAST(0x02),
    GETINF(0x04),
    ATHPIN(0x06),
    SELECTION(0x0B);

    private final int value;

    AuthenticatorCmd(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    @Override
    public String toString() {
        return name();
    }

    private static Map<Integer, AuthenticatorCmd> reverseLookup = 
            Arrays.stream(AuthenticatorCmd.values()).collect(Collectors.toMap(AuthenticatorCmd::getValue, Function.identity()));

    public static AuthenticatorCmd fromInt(final int id) {
        return reverseLookup.getOrDefault(id, ERR);
    }
}
