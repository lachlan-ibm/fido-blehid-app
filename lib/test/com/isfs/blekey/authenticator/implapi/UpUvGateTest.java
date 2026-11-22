/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator.implapi;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;

import com.isfs.blekey.authenticator.AuthenticatorAPI;
import com.isfs.blekey.authenticator.KeepaliveManager;
import com.isfs.blekey.authenticator.UpUvRequestCtx;
import com.isfs.blekey.authenticator.UpUvRequestCtx.CeremonyType;
import com.isfs.blekey.authenticator.UxInteractionLock;
import com.isfs.blekey.authenticator.implapi.UpUvGate.LatchStrategy;
import com.isfs.blekey.ctap.Ctap2StatusCode;
import com.isfs.blekey.ctap.CtapTxn;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Branch tests for {@link UpUvGate}.
 *
 * <p>Every test either never blocks or releases / never arms the
 * {@link UxInteractionLock} latch itself, so the 25 s production wait is never
 * reached. {@code @Timeout} caps any accidental hang.</p>
 */
@Timeout(value = 10, unit = TimeUnit.SECONDS)
public class UpUvGateTest {

    /** Upper bound for any cross-thread wait in this class. */
    private static final long WAIT_MS = 2_000L;

    private static final byte[] OK = new byte[] { 0x00, 0x01 };

    private CtapTxn txn;
    private KeepaliveManager km;
    private final AtomicReference<byte[]> sent = new AtomicReference<>();
    private final AtomicReference<CtapTxn> sentTxn = new AtomicReference<>();
    private CountDownLatch sentLatch;
    private final AtomicInteger sendCount = new AtomicInteger();

    @BeforeEach
    public void setUp() {
        resetState();
        txn = new CtapTxn();
        km = mock(KeepaliveManager.class);
        sentLatch = new CountDownLatch(1);
        sendCount.set(0);
        AuthenticatorAPI.setKeepaliveManager(km);
        AuthenticatorAPI.setDeferredResponseSender((t, r) -> {
            sentTxn.set(t);
            sent.set(r);
            sendCount.incrementAndGet();
            sentLatch.countDown();
        });
    }

    @AfterEach
    public void tearDown() {
        resetState();
    }

    private static void resetState() {
        AuthenticatorAPI.setUpUvCallback(null);
        AuthenticatorAPI.setKeepaliveManager(null);
        AuthenticatorAPI.setDeferredResponseSender(null);
        UxInteractionLock.get().reset();
    }

    private static byte[] err(Ctap2StatusCode c) {
        return CtapResponse.error(c);
    }

    private void awaitSent() throws InterruptedException {
        assertTrue(sentLatch.await(WAIT_MS, TimeUnit.MILLISECONDS), "deferred response not sent");
    }

    /** Captures the context passed to onUpUvRequired. */
    private CountDownLatch captureCtx(AtomicReference<UpUvRequestCtx> ref) {
        CountDownLatch l = new CountDownLatch(1);
        AuthenticatorAPI.setUpUvCallback(ctx -> { ref.set(ctx); l.countDown(); });
        return l;
    }

    // -------------------------------------------------------------------------
    // Branch 1 — grant active
    // -------------------------------------------------------------------------

    @Test
    public void await_grantActive_executesImmediately() {
        UxInteractionLock.get().recordBioGrant(new byte[32], 60_000L);
        byte[] r = UpUvGate.await(txn, "t", "rp", LatchStrategy.SYNC,
                CeremonyType.GET_ASSERTION, () -> OK);
        assertArrayEquals(OK, r);
    }

    @Test
    public void await_grantActive_actionThrows_returnsOther() {
        UxInteractionLock.get().recordBioGrant(new byte[32], 60_000L);
        byte[] r = UpUvGate.await(txn, "t", "rp", LatchStrategy.SYNC,
                CeremonyType.MAKE_CREDENTIAL, () -> { throw new IllegalStateException("boom"); });
        assertArrayEquals(err(Ctap2StatusCode.OTHER), r);
    }

    @Test
    public void await_grantActive_checkedExceptionThrows_returnsOther() {
        UxInteractionLock.get().recordBioGrant(new byte[32], 60_000L);
        byte[] r = UpUvGate.await(txn, "t", "rp", LatchStrategy.SYNC,
                CeremonyType.GET_ASSERTION, () -> { throw new java.io.IOException("io"); });
        assertArrayEquals(err(Ctap2StatusCode.OTHER), r);
    }

    @Test
    public void await_grantActive_getTknUv_skipsFastPath_firesCallback() {
        UxInteractionLock.get().recordBioGrant(new byte[32], 60_000L);
        AtomicReference<UpUvRequestCtx> ref = new AtomicReference<>();
        captureCtx(ref);
        byte[] r = UpUvGate.await(txn, "t", null, LatchStrategy.ASYNC,
                CeremonyType.GET_TKN_UV, () -> OK);
        assertNull(r);
        assertNotNull(ref.get());
        assertEquals(CeremonyType.GET_TKN_UV, ref.get().getCeremonyType());
    }

    // -------------------------------------------------------------------------
    // Branch 2 — denied
    // -------------------------------------------------------------------------

    @Test
    public void await_denied_returnsOperationDenied() {
        UxInteractionLock.get().setUserDenied(60_000L);
        byte[] r = UpUvGate.await(txn, "t", "rp", LatchStrategy.SYNC,
                CeremonyType.GET_ASSERTION, () -> OK);
        assertArrayEquals(err(Ctap2StatusCode.OPERATION_DENIED), r);
    }

    // -------------------------------------------------------------------------
    // Branch 3 SYNC — latch wait
    // -------------------------------------------------------------------------

    @Test
    public void await_sync_latchAlreadyReleased_executesAction() {
        UxInteractionLock lock = UxInteractionLock.get();
        lock.setStateInProgress();
        lock.releaseLatch();
        byte[] r = UpUvGate.await(txn, "t", "rp", LatchStrategy.SYNC,
                CeremonyType.GET_ASSERTION, () -> OK);
        assertArrayEquals(OK, r);
    }

    @Test
    public void await_sync_noLatchArmed_timesOutImmediately() {
        // IN_PROGRESS without an armed latch: awaitLatch returns false without blocking.
        UxInteractionLock.get().setUxState(UxInteractionLock.UxState.IN_PROGRESS);
        byte[] r = UpUvGate.await(txn, "t", "rp", LatchStrategy.SYNC,
                CeremonyType.MAKE_CREDENTIAL, () -> OK);
        assertArrayEquals(err(Ctap2StatusCode.OPERATION_DENIED), r);
    }

    @Test
    public void await_sync_latchFiresThenDenied_returnsOperationDenied() throws Exception {
        UxInteractionLock lock = UxInteractionLock.get();
        lock.setStateInProgress();
        AtomicReference<byte[]> result = new AtomicReference<>();
        Thread t = new Thread(() -> result.set(UpUvGate.await(txn, "t", "rp",
                LatchStrategy.SYNC, CeremonyType.GET_ASSERTION, () -> OK)));
        t.setDaemon(true);
        t.start();
        waitUntilParked(t);
        lock.setUserDenied(60_000L);
        lock.releaseLatch();
        t.join(WAIT_MS);
        assertFalse(t.isAlive());
        assertArrayEquals(err(Ctap2StatusCode.OPERATION_DENIED), result.get());
    }

    private static void waitUntilParked(Thread t) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(WAIT_MS);
        while (t.getState() != Thread.State.TIMED_WAITING && System.nanoTime() < deadline) {
            Thread.sleep(1);
        }
        assertEquals(Thread.State.TIMED_WAITING, t.getState(), "thread never reached latch wait");
    }

    // -------------------------------------------------------------------------
    // Branch 3 ASYNC — background latch waiter
    // -------------------------------------------------------------------------

    @Test
    public void await_async_approved_dispatchesAndSetsUserPresent() throws Exception {
        UxInteractionLock lock = UxInteractionLock.get();
        lock.setStateInProgress();
        byte[] r = UpUvGate.await(txn, "t", "rp", LatchStrategy.ASYNC,
                CeremonyType.GET_ASSERTION, () -> OK);
        assertNull(r);
        verify(km).startKeepalive(txn, KeepaliveManager.STATUS_UP_NEEDED);
        lock.releaseLatch();
        awaitSent();
        assertArrayEquals(OK, sent.get());
        assertSame(txn, sentTxn.get());
        assertTrue(txn.isUserPresent());
    }

    @Test
    public void await_async_approved_actionThrows_sendsOther() throws Exception {
        UxInteractionLock lock = UxInteractionLock.get();
        lock.setStateInProgress();
        assertNull(UpUvGate.await(txn, "t", "rp", LatchStrategy.ASYNC,
                CeremonyType.MAKE_CREDENTIAL, () -> { throw new RuntimeException("x"); }));
        lock.releaseLatch();
        awaitSent();
        assertArrayEquals(err(Ctap2StatusCode.OTHER), sent.get());
    }

    @Test
    public void await_async_timeout_sendsDeniedAndStopsKeepalive() throws Exception {
        UxInteractionLock.get().setUxState(UxInteractionLock.UxState.IN_PROGRESS); // no latch → immediate false
        assertNull(UpUvGate.await(txn, "t", "rp", LatchStrategy.ASYNC,
                CeremonyType.GET_ASSERTION, () -> OK));
        awaitSent();
        assertArrayEquals(err(Ctap2StatusCode.OPERATION_DENIED), sent.get());
        verify(km, timeout(WAIT_MS)).stopKeepalive(txn);
    }

    @Test
    public void await_async_timeout_noKeepaliveManager_noNpe() throws Exception {
        AuthenticatorAPI.setKeepaliveManager(null);
        UxInteractionLock.get().setUxState(UxInteractionLock.UxState.IN_PROGRESS);
        assertNull(UpUvGate.await(txn, "t", "rp", LatchStrategy.ASYNC,
                CeremonyType.GET_ASSERTION, () -> OK));
        awaitSent();
        assertArrayEquals(err(Ctap2StatusCode.OPERATION_DENIED), sent.get());
    }

    @Test
    public void await_async_latchFiresThenDenied_sendsDenied() throws Exception {
        UxInteractionLock lock = UxInteractionLock.get();
        lock.setStateInProgress();
        assertNull(UpUvGate.await(txn, "t", "rp", LatchStrategy.ASYNC,
                CeremonyType.GET_ASSERTION, () -> OK));
        lock.setUserDenied(60_000L);
        lock.releaseLatch();
        awaitSent();
        assertArrayEquals(err(Ctap2StatusCode.OPERATION_DENIED), sent.get());
        verify(km, timeout(WAIT_MS)).stopKeepalive(txn);
    }

    @Test
    public void await_async_getTknUv_approved_refiresCallbackWithoutBiometric() throws Exception {
        UxInteractionLock lock = UxInteractionLock.get();
        lock.setStateInProgress();
        AtomicReference<UpUvRequestCtx> ref = new AtomicReference<>();
        CountDownLatch cbLatch = captureCtx(ref);
        assertNull(UpUvGate.await(txn, "t", null, LatchStrategy.ASYNC,
                CeremonyType.GET_TKN_UV, () -> OK));
        verify(km).startKeepalive(txn, KeepaliveManager.STATUS_PROCESSING);
        lock.releaseLatch();
        assertTrue(cbLatch.await(WAIT_MS, TimeUnit.MILLISECONDS));
        assertFalse(ref.get().requiresBiometric());
        assertEquals(CeremonyType.GET_TKN_UV, ref.get().getCeremonyType());
        assertEquals(0, sendCount.get(), "nothing sent until PIN collected");
    }

    @Test
    public void await_async_getTknUv_approved_noCallback_sendsDenied() throws Exception {
        UxInteractionLock lock = UxInteractionLock.get();
        lock.setStateInProgress();
        assertNull(UpUvGate.await(txn, "t", null, LatchStrategy.ASYNC,
                CeremonyType.GET_TKN_UV, () -> OK));
        lock.releaseLatch();
        awaitSent();
        assertArrayEquals(err(Ctap2StatusCode.OPERATION_DENIED), sent.get());
    }

    // -------------------------------------------------------------------------
    // Branch 4 — fireUpUvRequired
    // -------------------------------------------------------------------------

    @Test
    public void await_idle_noCallback_returnsOperationDenied() {
        byte[] r = UpUvGate.await(txn, "t", "rp", LatchStrategy.SYNC,
                CeremonyType.GET_ASSERTION, () -> OK);
        assertArrayEquals(err(Ctap2StatusCode.OPERATION_DENIED), r);
        assertEquals(UxInteractionLock.UxState.IDLE, UxInteractionLock.get().getUxState());
        verify(km, never()).startKeepalive(any(), org.mockito.ArgumentMatchers.anyByte());
    }

    @Test
    public void await_idle_callback_deferredWithBiometricAndKeepalive() {
        AtomicReference<UpUvRequestCtx> ref = new AtomicReference<>();
        captureCtx(ref);
        byte[] r = UpUvGate.await(txn, "t", "example.com", LatchStrategy.SYNC,
                CeremonyType.MAKE_CREDENTIAL, () -> OK);
        assertNull(r);
        assertEquals(UxInteractionLock.UxState.IN_PROGRESS, UxInteractionLock.get().getUxState());
        UpUvRequestCtx ctx = ref.get();
        assertEquals("example.com", ctx.getRpId());
        assertSame(txn, ctx.getTxn());
        assertTrue(ctx.requiresBiometric());
        assertEquals(CeremonyType.MAKE_CREDENTIAL, ctx.getCeremonyType());
        verify(km).startKeepalive(txn, KeepaliveManager.STATUS_UP_NEEDED);
    }

    @Test
    public void await_idle_getTknUv_noBiometricAndProcessingKeepalive() {
        AtomicReference<UpUvRequestCtx> ref = new AtomicReference<>();
        captureCtx(ref);
        assertNull(UpUvGate.await(txn, "t", null, LatchStrategy.ASYNC,
                CeremonyType.GET_TKN_UV, () -> OK));
        assertFalse(ref.get().requiresBiometric());
        verify(km).startKeepalive(txn, KeepaliveManager.STATUS_PROCESSING);
    }

    @Test
    public void await_idle_callback_noKeepaliveManager_noNpe() {
        AuthenticatorAPI.setKeepaliveManager(null);
        AtomicReference<UpUvRequestCtx> ref = new AtomicReference<>();
        captureCtx(ref);
        assertNull(UpUvGate.await(txn, "t", "rp", LatchStrategy.SYNC,
                CeremonyType.GET_ASSERTION, () -> OK));
        assertNotNull(ref.get());
    }

    @Test
    public void await_idle_chainApproved_runsActionAndSendsResponse() throws Exception {
        AtomicReference<UpUvRequestCtx> ref = new AtomicReference<>();
        captureCtx(ref);
        UpUvGate.await(txn, "t", "rp", LatchStrategy.SYNC, CeremonyType.GET_ASSERTION, () -> OK);

        AtomicReference<byte[]> chainResult = new AtomicReference<>(new byte[] { 9 });
        AtomicInteger done = new AtomicInteger();
        ref.get().buildResponse(UpUvRequestCtx.Outcome.APPROVED, e -> {
            chainResult.set(e);
            done.incrementAndGet();
        });
        assertTrue(done.get() >= 1, "chain terminal callback must fire");
        assertNull(chainResult.get());
        assertArrayEquals(OK, sent.get());
        assertEquals(1, sendCount.get(), "action must run and send exactly once");
        assertTrue(txn.isUserPresent());
    }

    @Test
    public void await_idle_chainApproved_actionThrows_sendsOther() {
        AtomicReference<UpUvRequestCtx> ref = new AtomicReference<>();
        captureCtx(ref);
        UpUvGate.await(txn, "t", "rp", LatchStrategy.SYNC, CeremonyType.GET_ASSERTION,
                () -> { throw new RuntimeException("x"); });
        ref.get().buildResponse(UpUvRequestCtx.Outcome.APPROVED, e -> {});
        assertArrayEquals(err(Ctap2StatusCode.OTHER), sent.get());
    }

    // -------------------------------------------------------------------------
    // dispatchApproved
    // -------------------------------------------------------------------------

    @Test
    public void dispatchApproved_nullTxn_stillSendsAndCompletesChain() {
        AtomicReference<byte[]> chain = new AtomicReference<>(new byte[] { 1 });
        AtomicInteger done = new AtomicInteger();
        UpUvGate.dispatchApproved(e -> { chain.set(e); done.incrementAndGet(); }, null, "t", () -> OK);
        assertEquals(1, done.get());
        assertNull(chain.get());
        assertArrayEquals(OK, sent.get());
        assertNull(sentTxn.get());
    }

    @Test
    public void dispatchApproved_noSender_dropsResponseAndCompletesChain() {
        AuthenticatorAPI.setDeferredResponseSender(null);
        AtomicInteger done = new AtomicInteger();
        UpUvGate.dispatchApproved(e -> done.incrementAndGet(), txn, "t", () -> OK);
        assertEquals(1, done.get());
        assertEquals(0, sendCount.get());
        assertTrue(txn.isUserPresent());
    }

    // -------------------------------------------------------------------------
    // fireIfIdle
    // -------------------------------------------------------------------------

    private UpUvRequestCtx ctx() {
        return new UpUvRequestCtx("rp", txn, java.util.Collections.emptyList());
    }

    @Test
    public void fireIfIdle_grantActive_returnsFalse() {
        UxInteractionLock.get().recordBioGrant(new byte[32], 60_000L);
        AtomicInteger built = new AtomicInteger();
        assertFalse(UpUvGate.fireIfIdle(txn, () -> { built.incrementAndGet(); return ctx(); }));
        assertEquals(0, built.get());
    }

    @Test
    public void fireIfIdle_denied_returnsFalse() {
        UxInteractionLock.get().setUserDenied(60_000L);
        assertFalse(UpUvGate.fireIfIdle(txn, this::ctx));
    }

    @Test
    public void fireIfIdle_inProgress_returnsFalse() {
        UxInteractionLock.get().setStateInProgress();
        AtomicReference<UpUvRequestCtx> ref = new AtomicReference<>();
        captureCtx(ref);
        assertFalse(UpUvGate.fireIfIdle(txn, this::ctx));
        assertNull(ref.get());
    }

    @Test
    public void fireIfIdle_noCallback_returnsFalse() {
        assertFalse(UpUvGate.fireIfIdle(txn, this::ctx));
        assertEquals(UxInteractionLock.UxState.IDLE, UxInteractionLock.get().getUxState());
    }

    @Test
    public void fireIfIdle_idleWithCallback_firesAndSetsInProgress() {
        AtomicReference<UpUvRequestCtx> ref = new AtomicReference<>();
        captureCtx(ref);
        UpUvRequestCtx built = ctx();
        assertTrue(UpUvGate.fireIfIdle(txn, () -> built));
        assertSame(built, ref.get());
        assertEquals(UxInteractionLock.UxState.IN_PROGRESS, UxInteractionLock.get().getUxState());
    }
}
