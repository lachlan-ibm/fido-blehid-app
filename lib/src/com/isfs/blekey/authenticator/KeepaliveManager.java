/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator;

import com.isfs.blekey.ctap.CtapTxn;

/**
 * Contract between the authenticator protocol layer and the transport layer for
 * CTAP keepalive signalling.
 *
 * <p>Status constants live here — the only place in the codebase that must know
 * their values.  {@link com.isfs.blekey.authenticator.implapi.UpUvGate} calls
 * these methods; the app layer implements them.</p>
 *
 * <p>Status codes per CTAP spec §11.2.9.1.4:</p>
 * <ul>
 *   <li>{@link #STATUS_PROCESSING} (0x01) — authenticator is working on the request</li>
 *   <li>{@link #STATUS_UP_NEEDED}  (0x02) — user presence / interaction required</li>
 * </ul>
 */
public interface KeepaliveManager {

    /** Keepalive status: authenticator is processing. */
    byte STATUS_PROCESSING = (byte) 0x01;
    /** Keepalive status: user presence required. */
    byte STATUS_UP_NEEDED  = (byte) 0x02;

    /**
     * Starts sending keepalive frames for the given transaction at the
     * spec-required 100 ms interval.
     *
     * <p>Any previously active session for the same transaction is stopped first.</p>
     *
     * @param txn    the live CTAP transaction (used as the session key)
     * @param status initial status byte ({@link #STATUS_PROCESSING} or {@link #STATUS_UP_NEEDED})
     */
    void startKeepalive(CtapTxn txn, byte status);

    /**
     * Stops sending keepalive frames for the given transaction.
     *
     * @param txn the live CTAP transaction
     */
    void stopKeepalive(CtapTxn txn);
}
