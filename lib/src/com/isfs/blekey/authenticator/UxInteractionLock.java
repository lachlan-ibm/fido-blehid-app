/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator;

import java.util.Arrays;

/**
 * CID-exclusive mutex for UP and UV ceremonies (15-second window).
 *
 * <p>A single global instance ({@link #get()}) serialises user-interaction
 * ceremonies across all CTAP channels.  Only the channel that acquired the
 * lock may run a ceremony; any other channel receives
 * {@code CTAP2_ERR_CHANNEL_BUSY} until the lock expires or is released.</p>
 *
 * <p>A {@code null} CID is treated as a non-participant: {@link #tryAcquire}
 * returns {@code true} without claiming ownership, so callers that run
 * outside of a CTAP channel context are never blocked.</p>
 */
public final class UxInteractionLock {

    static final long LOCK_TIMEOUT_MS = 15_000L;

    private static final UxInteractionLock INSTANCE = new UxInteractionLock();

    private byte[] ownerCid    = null;
    private long   expiresAtMs = 0L;

    private UxInteractionLock() {}

    public static UxInteractionLock get() { return INSTANCE; }

    public synchronized boolean tryAcquire(byte[] cid) {
        // A null CID means no CTAP channel is established; treat as non-participant —
        // the call passes through without claiming the lock.
        if (cid == null) return true;
        long now = System.currentTimeMillis();
        if (ownerCid != null && now < expiresAtMs && !Arrays.equals(ownerCid, cid)) {
            return false;
        }
        ownerCid    = cid.clone();
        expiresAtMs = now + LOCK_TIMEOUT_MS;
        return true;
    }

    public synchronized void release(byte[] cid) {
        if (Arrays.equals(ownerCid, cid)) {
            ownerCid    = null;
            expiresAtMs = 0L;
        }
    }

    public synchronized boolean isOwner(byte[] cid) {
        return ownerCid != null
            && Arrays.equals(ownerCid, cid)
            && System.currentTimeMillis() < expiresAtMs;
    }
}

// Made with Bob
