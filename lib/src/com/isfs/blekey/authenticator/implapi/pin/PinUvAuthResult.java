/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator.implapi.pin;

import com.isfs.blekey.ctap.Ctap2StatusCode;

/**
 * Result of PIN/UV authentication processing.
 */
public class PinUvAuthResult {
    public final boolean userVerified;
    public final Ctap2StatusCode errorCode;

    public static final PinUvAuthResult NO_VERIFICATION = new PinUvAuthResult(false, null);

    public PinUvAuthResult(boolean userVerified, Ctap2StatusCode errorCode) {
        this.userVerified = userVerified;
        this.errorCode = errorCode;
    }
}
