/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator.implapi;

import com.isfs.blekey.authenticator.AuthenticatorAPI;
import com.isfs.blekey.authenticator.UpUvRequestCtx;
import com.isfs.blekey.authenticator.UxInteractionLock;
import com.isfs.blekey.authenticator.implapi.pin.PinFlowHandler;
import com.isfs.blekey.ctap.Ctap2StatusCode;
import com.isfs.blekey.ctap.CtapTxn;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.function.Supplier;

/**
 * Shared four-branch UP/UV gate used by {@link GetAssertionHandler},
 * {@link MakeCredentialHandler}, and {@link PinFlowHandler#getTkn}.
 *
 * <p>Branch order:
 * <ol>
 *   <li><b>Fast-path</b>   — app-global bio grant active → execute immediately.</li>
 *   <li><b>Denied-path</b> — CID was already denied → {@code OPERATION_DENIED}.</li>
 *   <li><b>Latch-wait</b>  — getInfo/getKey already started UX → wait on latch.
 *       Blocking (SYNC) for MKCRED/GETASSERT; background thread (ASYNC) for GETTKN.</li>
 *   <li><b>Legacy-deferred</b> — no prior UX started → {@code tryAcquire} →
 *       {@code onUpUvRequired} → return {@code null} (deferred).</li>
 * </ol>
 * </p>
 */
public final class UpUvGate {

    private static final Logger logger = LoggerFactory.getLogger(UpUvGate.class);
    private static final long   UP_WAIT_TIMEOUT_MS = 25_000L;

    private UpUvGate() {}

    /**
     * Whether the latch-wait branch should block the calling thread (SYNC) or
     * hand off to a background thread (ASYNC).
     *
     * <p>Use SYNC for MKCRED and GETASSERT whose callers are already on a
     * disposable worker thread. Use ASYNC for GETTKN whose caller is on the
     * BLE packet-handler thread and must not block.</p>
     */
    public enum LatchStrategy { SYNC, ASYNC }

    /**
     * Functional interface for the command-specific execute action.
     * Implementations may throw any checked exception.
     */
    @FunctionalInterface
    public interface ExecuteAction {
        byte[] execute() throws Exception;
    }

    /**
     * Runs the four-branch UP/UV gate.
     *
     * @param txn           the live CTAP transaction
     * @param cmdLabel      short name for log messages (e.g. {@code "getAssertion"})
     * @param rpId          relying-party identifier (may be {@code null} for PIN ceremonies)
     * @param latchStrategy {@link LatchStrategy#SYNC} or {@link LatchStrategy#ASYNC}
     * @param ceremonyType  identifies the ceremony for dialog text selection
     * @param action        the command-specific execution logic
     * @return response bytes, {@code null} (deferred / async), or an error
     */
    public static byte[] await(
            CtapTxn txn,
            String cmdLabel,
            String rpId,
            LatchStrategy latchStrategy,
            UpUvRequestCtx.CeremonyType ceremonyType,
            ExecuteAction action) {

        // Branch 1 — UPUV session active.
        if (UxInteractionLock.get().isGrantActive()) {
            logger.debug("{}: grant active, no UP prompt", cmdLabel);
            try {
                return action.execute();
            } catch (Exception e) {
                logger.error("{} fast-path failed", cmdLabel, e);
                return CtapResponse.error(Ctap2StatusCode.OTHER);
            }
        }
        UxInteractionLock lock = UxInteractionLock.get();
        // Branch 2 — UPUV session denied.
        if (lock.isUserDenied()) {
            logger.warn("{}: CID denied — OPERATION_DENIED", cmdLabel);
            return CtapResponse.error(Ctap2StatusCode.OPERATION_DENIED);
        }

        // Branch 3 — UX already in progress (started by getInfo/getKey); wait for the result
        if (lock.getUxState() == UxInteractionLock.UxState.IN_PROGRESS) {
            if (latchStrategy == LatchStrategy.SYNC) {
                logger.debug("{}: UX in progress — waiting on latch (max {}ms)",
                        cmdLabel, UP_WAIT_TIMEOUT_MS);
                boolean completed = UxInteractionLock.get().awaitLatch(UP_WAIT_TIMEOUT_MS);
                if (!completed || UxInteractionLock.get().isUserDenied()) {
                    logger.warn("{}: UX latch timeout or denied — OPERATION_DENIED", cmdLabel);
                    return CtapResponse.error(Ctap2StatusCode.OPERATION_DENIED);
                }
                logger.debug("{}: latch-wait path — latch fired, UX APPROVED", cmdLabel);
                try {
                    return action.execute();
                } catch (Exception e) {
                    logger.error("{} post-latch failed", cmdLabel, e);
                    return CtapResponse.error(Ctap2StatusCode.OTHER);
                }
            } else {
                // ASYNC — spawn a background thread so the BLE handler thread is not blocked.
                logger.debug("{}: UX in progress — registering deferred latch listener", cmdLabel);
                Thread latchWaiter = new Thread(() -> {
                    boolean completed = UxInteractionLock.get().awaitLatch(UP_WAIT_TIMEOUT_MS);
                    byte[] response;
                    if (!completed || UxInteractionLock.get().isUserDenied()) {
                        logger.warn("{}: latch timeout or denied — OPERATION_DENIED", cmdLabel);
                        response = CtapResponse.error(Ctap2StatusCode.OPERATION_DENIED);
                    } else {
                        logger.debug("{}: latch fired APPROVED — processing", cmdLabel);
                        try {
                            response = action.execute();
                        } catch (Exception e) {
                            logger.error("{} async latch-wait execute failed", cmdLabel, e);
                            response = CtapResponse.error(Ctap2StatusCode.OTHER);
                        }
                    }
                    AuthenticatorAPI.DeferredResponseSender sender =
                        AuthenticatorAPI.getDeferredResponseSender();
                    if (sender != null) {
                        sender.send(txn, response);
                    } else {
                        logger.error("{}: no DeferredResponseSender — response dropped", cmdLabel);
                    }
                }, cmdLabel + "-latch-waiter");
                latchWaiter.setDaemon(true);
                latchWaiter.start();
                return null; // deferred
            }
        }

        // Branch 4 — no prior UX started (platform skipped getInfo/getKey)
        AuthenticatorAPI.UpUvCallback cb = AuthenticatorAPI.getUpUvCallback();
        if (cb == null) {
            logger.warn("{}: no UpUvCallback — OPERATION_DENIED", cmdLabel);
            return CtapResponse.error(Ctap2StatusCode.OPERATION_DENIED);
        }
        UxInteractionLock.get().setStateInProgress();
        cb.onUpUvRequired(
            new UpUvRequestCtx(rpId, txn,
                List.of((chainCb) -> dispatchApproved(chainCb, txn, cmdLabel, action)),
                true,  // requiresBiometric
                ceremonyType
            )
        );
        return null; // deferred
    }

    /**
     * Common "on-approved" deferred-send helper.
     *
     * <p>Sets {@code txn.userPresent = true}, runs {@code action}, and delivers
     * the result via {@link AuthenticatorAPI#getDeferredResponseSender()}.  On
     * any exception the error response is sent instead.  Always calls
     * {@code chainCb.done(null)} to close the chain.</p>
     */
    public static void dispatchApproved(
            UpUvRequestCtx.ChainCallback chainCb,
            CtapTxn txn,
            String cmdLabel,
            ExecuteAction action) {
        if (txn != null) txn.setUserPresent(true);
        byte[] response;
        try {
            response = action.execute();
        } catch (Exception e) {
            logger.error("{} chain action failed", cmdLabel, e);
            response = CtapResponse.error(Ctap2StatusCode.OTHER);
        }
        AuthenticatorAPI.DeferredResponseSender sender =
            AuthenticatorAPI.getDeferredResponseSender();
        if (sender != null) sender.send(txn, response);
        chainCb.done(null);
    }



    /**
     * Acquires the {@link UxInteractionLock}, transitions to
     * {@link UxInteractionLock.UxState#IN_PROGRESS}, arms the latch, and fires
     * {@link AuthenticatorAPI.UpUvCallback#onUpUvRequired}.
     *
     * <p>Does nothing if the CID is {@code null}, the UxState is not IDLE,
     * the CID has already been denied, the app-global grant is active,
     * or the lock cannot be acquired.</p>
     *
     * @param txn        the live CTAP transaction
     * @param ctxBuilder supplier of the {@link UpUvRequestCtx} to pass to the callback
     * @return {@code true} if the callback was fired; {@code false} if skipped
     */
    public static boolean fireIfIdle(CtapTxn txn,
                                     Supplier<UpUvRequestCtx> ctxBuilder) {
        if (UxInteractionLock.get().isGrantActive()) return false;
        if (UxInteractionLock.get().isUserDenied()) return false;
        if (UxInteractionLock.get().getUxState() == UxInteractionLock.UxState.IN_PROGRESS) return false;

        AuthenticatorAPI.UpUvCallback cb = AuthenticatorAPI.getUpUvCallback();
        if (cb != null) {
            logger.debug("UxTrigger: firing onUpUvRequired for CID {}", txn.getCid());
            UxInteractionLock.get().setStateInProgress();
            cb.onUpUvRequired(ctxBuilder.get());
            return true;
        } else {
            return false;
        }
    }
}
