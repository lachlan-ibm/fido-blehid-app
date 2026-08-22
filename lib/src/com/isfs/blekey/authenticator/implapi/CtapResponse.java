/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator.implapi;

import com.isfs.blekey.ctap.Ctap2StatusCode;
import java.nio.ByteBuffer;

/**
 * Static response-building helpers shared by all CTAP command handlers.
 * Eliminates the identical {@code error()} / {@code success()} one-liners
 * duplicated across {@code GetAssertionHandler}, {@code MakeCredentialHandler},
 * and {@code PinFlowHandler}.
 */
public final class CtapResponse {

    private CtapResponse() {}

    /** Builds a single-byte CTAP error response. */
    public static byte[] error(Ctap2StatusCode code) {
        return new byte[]{ (byte) code.getCode() };
    }

    /** Prepends the SUCCESS status byte to {@code payload}. */
    public static byte[] success(byte[] payload) {
        ByteBuffer bb = ByteBuffer.allocate(payload.length + 1);
        bb.put((byte) Ctap2StatusCode.SUCCESS.getCode());
        bb.put(payload);
        return bb.array();
    }
}
