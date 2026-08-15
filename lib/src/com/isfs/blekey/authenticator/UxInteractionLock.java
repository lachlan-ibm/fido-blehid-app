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
 *
 * <p>In addition to the CID mutex, this class also owns the app-global
 * biometric grant.  Once a biometric is cleared the derived ECDH IKM is
 * cached here and is available to any CID within the fixed grant window.
 * The window is set once at bio-success time and never extended.</p>
 */
public final class UxInteractionLock {

    public static final long LOCK_TIMEOUT_MS = 15_000L;

    private static final UxInteractionLock INSTANCE = new UxInteractionLock();

    // -------------------------------------------------------------------------
    // CID mutex fields (unchanged)
    // -------------------------------------------------------------------------

    private byte[] ownerCid    = null;
    private long   expiresAtMs = 0L;

    // -------------------------------------------------------------------------
    // App-global bio grant fields
    // -------------------------------------------------------------------------

    /** App-global cached ECDH IKM. Written after bio success; read by any CID. */
    private volatile byte[] cachedIkm = null;

    /** Monotonic wall-clock ms at which the current bio grant expires. 0 = no grant. */
    private volatile long grantExpiresAtMs = 0L;

    private UxInteractionLock() {}

    public static UxInteractionLock get() { return INSTANCE; }

    // -------------------------------------------------------------------------
    // CID mutex methods (unchanged)
    // -------------------------------------------------------------------------

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

    // -------------------------------------------------------------------------
    // App-global bio grant methods
    // -------------------------------------------------------------------------

    /**
     * Records a successful biometric approval app-globally.
     * Called by HIDForegroundService immediately after the Keystore bio callback fires.
     *
     * @param ikm       the ECDH IKM just derived (defensively copied)
     * @param windowMs  Keystore biometric validity period in ms
     */
    public synchronized void recordBioGrant(byte[] ikm, long windowMs) {
        this.cachedIkm        = ikm.clone();
        this.grantExpiresAtMs = System.currentTimeMillis() + windowMs;
    }

    /** Returns true when the IKM grant is currently active. */
    public boolean isGrantActive() {
        return cachedIkm != null && System.currentTimeMillis() < grantExpiresAtMs;
    }

    /** Returns the cached IKM (defensive copy), or null if grant is not active. */
    public synchronized byte[] getCachedIkm() {
        if (!isGrantActive()) return null;
        return cachedIkm.clone();
    }

    /** Revokes the grant. Call on explicit deny or CID inactivity expiry. */
    public synchronized void revokeGrant() {
        cachedIkm        = null;
        grantExpiresAtMs = 0L;
    }
}

// Made with Bob
