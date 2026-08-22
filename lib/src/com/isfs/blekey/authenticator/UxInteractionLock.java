/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

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

    /**
     * Tracks the out-of-band UX collection state for this CID.
     * Written by the app thread; read by the CTAP/BT callback thread.
     * Volatile provides the single-writer/single-reader happens-before guarantee.
     */
    public enum UxState {
        /** No UX has been started recently. */
        IDLE,
        /** UX collection is in progress (Allow/Deny dialog or biometric pending). */
        IN_PROGRESS,
        /** User approved and IKM is cached. Protected commands may run immediately. */
        APPROVED,
        /** User denied or timed out. Protected commands return OPERATION_DENIED. */
        DENIED
    }


    public static final long LOCK_TIMEOUT_MS = 15_000L;

    private static final UxInteractionLock INSTANCE = new UxInteractionLock();

    // -------------------------------------------------------------------------
    // App-global bio grant fields
    // -------------------------------------------------------------------------

    /** App-global cached ECDH IKM. Written after bio success; read by any CID. */
    private volatile byte[] cachedIkm = null;
    private volatile long   expiresAtMs = 0L;
    private UxState uxState = UxState.IDLE;

    // -------------------------------------------------------------------------
    // Latch — armed when IN_PROGRESS, released on approve/deny/timeout/reset
    // -------------------------------------------------------------------------

    /** Latch armed when state transitions to IN_PROGRESS; released on approve/deny/timeout. */
    private volatile CountDownLatch uxLatch = null;

    // -------------------------------------------------------------------------
    // Self-resetting timer
    // -------------------------------------------------------------------------

    private final ScheduledExecutorService scheduler =
        Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "ux-lock-reset-timer");
            t.setDaemon(true);
            return t;
        });
    private ScheduledFuture<?> resetFuture = null;

    private UxInteractionLock() {}

    public static UxInteractionLock get() { return INSTANCE; }

    public synchronized void reset() {
        cancelResetTimer();
        releaseLatch();
        expiresAtMs = 0L;
        cachedIkm = null;
        uxState = UxState.IDLE;
        uxLatch = null;
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
        this.expiresAtMs = System.currentTimeMillis() + windowMs;
    }

    /** Returns true when the IKM grant is currently active. */
    public synchronized boolean isGrantActive() {
        return cachedIkm != null && System.currentTimeMillis() < expiresAtMs;
    }

    /** Return true if Ux has recently been denied */
    public synchronized boolean isUserDenied() {
        return this.uxState == UxState.DENIED && System.currentTimeMillis() < expiresAtMs;
    }

    public synchronized void setUserDenied(long windowMs) {
        cancelResetTimer();
        this.uxState = UxState.DENIED;
        this.expiresAtMs = System.currentTimeMillis() + windowMs;
        scheduleReset(windowMs);
    }

    /** Returns the cached IKM (defensive copy), or null if grant is not active. */
    public synchronized byte[] getCachedIkm() {
        if (!isGrantActive()) return null;
        return cachedIkm.clone();
    }

    /** Returns the current UX state for this CID. */
    public synchronized UxState getUxState() { return uxState; }

    /** Sets the UX state. */
    public synchronized void setUxState(UxState s) { this.uxState = s; }

    // -------------------------------------------------------------------------
    // Latch API
    // -------------------------------------------------------------------------

    /**
     * Allocates a fresh {@link CountDownLatch}(1). Call immediately before
     * {@code onUpUvRequired} so Branch 3 callers have a latch to block on.
     */
    public synchronized void armLatch() {
        uxLatch = new CountDownLatch(1);
    }

    /**
     * Counts down the latch. Safe to call if the latch is null or already fired.
     */
    public synchronized void releaseLatch() {
        CountDownLatch l = uxLatch;
        if (l != null) l.countDown();
    }

    /**
     * Blocks the calling thread until the latch fires or {@code timeoutMs} elapses.
     *
     * @param timeoutMs maximum wait in milliseconds
     * @return {@code true} if the latch fired before the timeout; {@code false} on timeout
     */
    public boolean awaitLatch(long timeoutMs) {
        CountDownLatch l;
        synchronized (this) { l = uxLatch; }
        if (l == null) return false;
        try {
            return l.await(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    /**
     * Convenience: sets state to {@link UxState#IN_PROGRESS} and arms the latch atomically.
     * Call at every site that calls {@code cb.onUpUvRequired()}.
     */
    public synchronized void setStateInProgress() {
        uxState = UxState.IN_PROGRESS;
        armLatch();
    }

    // -------------------------------------------------------------------------
    // Self-resetting timer
    // -------------------------------------------------------------------------

    /**
     * Arms the internal reset timer. After {@code windowMs} the lock automatically
     * transitions back to IDLE. Safe to call from any thread.
     */
    public synchronized void scheduleReset(long windowMs) {
        cancelResetTimer();
        resetFuture = scheduler.schedule(this::resetInternal, windowMs,
            TimeUnit.MILLISECONDS);
    }

    private synchronized void resetInternal() {
        resetFuture = null;
        releaseLatch();
        uxState = UxState.IDLE;
        cachedIkm = null;
        expiresAtMs = 0L;
        uxLatch = null;
    }

    private synchronized void cancelResetTimer() {
        if (resetFuture != null) {
            resetFuture.cancel(false);
            resetFuture = null;
        }
    }
}

// Made with Bob
