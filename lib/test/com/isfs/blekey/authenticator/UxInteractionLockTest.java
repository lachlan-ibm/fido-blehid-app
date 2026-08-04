/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link UxInteractionLock}.
 *
 * <p>The class is package-private; tests are in the same package and access
 * the singleton via reflection to reset state between tests.
 *
 * <p>Covers:
 * <ul>
 *   <li>Same CID can re-acquire the lock.</li>
 *   <li>Different CID is blocked while lock is held.</li>
 *   <li>Release allows another CID to acquire.</li>
 *   <li>Lock auto-expires after the timeout.</li>
 * </ul>
 */
public class UxInteractionLockTest {

    private static final byte[] CID_A = {0x01, 0x02, 0x03, 0x04};
    private static final byte[] CID_B = {0x0A, 0x0B, 0x0C, 0x0D};

    /** The singleton lock instance obtained via reflection. */
    private Object lock;

    private Method tryAcquire;
    private Method release;
    private Method isOwner;

    @BeforeEach
    void setUp() throws Exception {
        Class<?> lockClass = Class.forName(
            "com.isfs.blekey.authenticator.UxInteractionLock");

        Method getInstance = lockClass.getDeclaredMethod("get");
        getInstance.setAccessible(true);
        lock = getInstance.invoke(null);

        tryAcquire = lockClass.getDeclaredMethod("tryAcquire", byte[].class);
        tryAcquire.setAccessible(true);

        release = lockClass.getDeclaredMethod("release", byte[].class);
        release.setAccessible(true);

        isOwner = lockClass.getDeclaredMethod("isOwner", byte[].class);
        isOwner.setAccessible(true);

        // Always start and end each test with a clean lock state.
        resetLock();
    }

    @AfterEach
    void tearDown() throws Exception {
        resetLock();
    }

    private void resetLock() throws Exception {
        Field ownerCidField = lock.getClass().getDeclaredField("ownerCid");
        ownerCidField.setAccessible(true);
        ownerCidField.set(lock, null);
        Field expiresField = lock.getClass().getDeclaredField("expiresAtMs");
        expiresField.setAccessible(true);
        expiresField.set(lock, 0L);
    }

    /**
     * The same CID can re-acquire an already-held lock (idempotent / refreshes the window).
     */
    @Test
    void sameCidCanReacquire() throws Exception {
        assertTrue((boolean) tryAcquire.invoke(lock, (Object) CID_A),
            "First tryAcquire(CID_A) should succeed");
        assertTrue((boolean) tryAcquire.invoke(lock, (Object) CID_A),
            "Second tryAcquire(CID_A) should also succeed (same owner)");
    }

    /**
     * A different CID is blocked while the lock is held by CID_A.
     */
    @Test
    void differentCidBlockedWhileLockHeld() throws Exception {
        assertTrue((boolean) tryAcquire.invoke(lock, (Object) CID_A),
            "CID_A acquires the lock");
        assertFalse((boolean) tryAcquire.invoke(lock, (Object) CID_B),
            "CID_B should be blocked while CID_A holds the lock");
    }

    /**
     * After CID_A releases, CID_B can acquire.
     */
    @Test
    void releaseAllowsOtherCid() throws Exception {
        assertTrue((boolean) tryAcquire.invoke(lock, (Object) CID_A));
        release.invoke(lock, (Object) CID_A);
        assertTrue((boolean) tryAcquire.invoke(lock, (Object) CID_B),
            "CID_B should acquire after CID_A releases");
    }

    /**
     * isOwner returns true only for the holder and false for others.
     */
    @Test
    void isOwnerReflectsCurrentHolder() throws Exception {
        tryAcquire.invoke(lock, (Object) CID_A);
        assertTrue((boolean) isOwner.invoke(lock, (Object) CID_A),
            "CID_A is the owner after acquiring");
        assertFalse((boolean) isOwner.invoke(lock, (Object) CID_B),
            "CID_B is not the owner");
    }

    /**
     * Lock auto-expires: after the timeout elapses, another CID can acquire.
     *
     * <p>We shorten the timeout to 50 ms via reflection to avoid a 15-second sleep.
     */
    @Test
    void lockExpiresAfterTimeout() throws Exception {
        Class<?> lockClass = lock.getClass();

        // On Java 17+ changing static-final fields is blocked; instead we directly
        // set expiresAtMs to an already-expired value to simulate lock expiry.
        Field expiresAtMs = lockClass.getDeclaredField("expiresAtMs");
        expiresAtMs.setAccessible(true);
        Field ownerCid = lockClass.getDeclaredField("ownerCid");
        ownerCid.setAccessible(true);

        // Simulate: CID_A acquired the lock but its window expired 1 second ago.
        ownerCid.set(lock, CID_A.clone());
        expiresAtMs.set(lock, System.currentTimeMillis() - 1_000L);

        // isOwner should now return false because the lock expired.
        assertFalse((boolean) isOwner.invoke(lock, (Object) CID_A),
            "isOwner should be false for expired lock");

        // CID_B should now be able to acquire.
        assertTrue((boolean) tryAcquire.invoke(lock, (Object) CID_B),
            "CID_B should acquire after CID_A's lock expired");
    }

    /**
     * releaseUpLock public shim delegates to the lock correctly.
     * After the shim releases, another CID can acquire via reflection.
     */
    @Test
    void releaseUpLockShimWorks() throws Exception {
        assertTrue((boolean) tryAcquire.invoke(lock, (Object) CID_A));
        AuthenticatorAPI.releaseUpLock(CID_A);
        assertTrue((boolean) tryAcquire.invoke(lock, (Object) CID_B),
            "CID_B should acquire after public releaseUpLock(CID_A) is called");
    }
}
