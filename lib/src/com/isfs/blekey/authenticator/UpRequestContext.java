/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator;

import com.isfs.blekey.ctap.CtapTxn;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Immutable context object describing a pending user-presence request.
 *
 * <p>Created exclusively by {@link AuthenticatorAPI} and passed to the registered
 * {@link AuthenticatorAPI.UserPresenceCallback}.  The app layer calls
 * {@link #buildResponse(Outcome)} exactly once when the user acts; subsequent
 * calls are silently ignored (idempotency guard via {@link AtomicBoolean}).</p>
 */
public final class UpRequestContext {

    /** The outcome chosen by the user (or system). */
    public enum Outcome {
        /** Full CTAP2 approval: advertises PIN/UV protocol, sets UP flag on txn. */
        APPROVED,
        /** CTAP1-compat approval: omits PIN/UV, adds U2F_V2, does NOT set UP flag. */
        APPROVED_CTAP1_COMPAT,
        /** Denial: returns OPERATION_DENIED error. */
        DENIED
    }

    private final String  rpId;
    private final CtapTxn txn;
    private final boolean isGetInfo;
    private final AtomicBoolean delivered = new AtomicBoolean(false);

    /**
     * Package-private — only {@link AuthenticatorAPI} creates instances.
     *
     * @param rpId      Relying-party identifier (null for getInfo).
     * @param txn       The live {@link CtapTxn} for this channel.
     * @param isGetInfo {@code true} when this context was created for a getInfo ceremony.
     */
    UpRequestContext(String rpId, CtapTxn txn, boolean isGetInfo) {
        this.rpId      = rpId;
        this.txn       = txn;
        this.isGetInfo = isGetInfo;
    }

    /** Returns the relying-party identifier, or {@code null} for getInfo. */
    public String  getRpId()    { return rpId;      }

    /** Returns the live transaction associated with this request. */
    public CtapTxn getTxn()     { return txn;       }

    /** Returns {@code true} when this context was created for a getInfo ceremony. */
    public boolean isGetInfo()  { return isGetInfo; }

    /**
     * Builds the CTAP wire bytes appropriate for the given {@code outcome}.
     *
     * <p>This method is idempotent: the first call builds and returns the response;
     * any subsequent call returns {@code null} without re-building or re-sending.</p>
     *
     * @param outcome The user's decision.
     * @return The response bytes to pass to
     *         {@code HIDPasskey.sendDeferredResponse}, or {@code null} if already delivered.
     */
    public byte[] buildResponse(Outcome outcome) {
        if (!delivered.compareAndSet(false, true)) return null;
        switch (outcome) {
            case APPROVED:
                return AuthenticatorAPI.buildGetInfoCtap2Response();
            case APPROVED_CTAP1_COMPAT:
                return AuthenticatorAPI.buildGetInfoCtap1CompatResponse();
            default:
                return AuthenticatorAPI.buildDeniedResponse();
        }
    }
}
