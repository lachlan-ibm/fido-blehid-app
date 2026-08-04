/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator;

import com.isfs.blekey.ctap.CtapTxn;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Immutable context object describing a pending UP/UV request.
 *
 * <p>Created exclusively by {@link AuthenticatorAPI} and passed to the registered
 * {@link AuthenticatorAPI.UpUvCallback}.  The app layer calls
 * {@link #buildResponse(Outcome, ChainCallback)} exactly once when the user acts;
 * subsequent calls are silently ignored (idempotency guard via {@link AtomicBoolean}).</p>
 *
 * <p>Every context that reaches {@code onUpUvRequired} is either a
 * {@code getInfo}, {@code getKey} / {@code getTkn} PIN ceremony, or a
 * {@code makeCredential} / {@code getAssertion} ceremony.  The service layer
 * must always show a biometric prompt before running the ChainAction; the
 * Android Keystore enforces this at the hardware level for the platform key.</p>
 */
public final class UpUvRequestCtx {

    /** Keepalive status: background work in progress (no physical interaction needed yet). */
    public static final byte KEEPALIVE_PROCESSING = (byte) 0x01;

    /** Keepalive status: waiting for a physical user-presence button press. */
    public static final byte KEEPALIVE_UP_NEEDED  = (byte) 0x02;

    /** The outcome chosen by the user (or system). */
    public enum Outcome {
        /** Approval: grants the pending CTAP operation. */
        APPROVED,
        /** Denial: returns OPERATION_DENIED error. */
        DENIED
    }

    /**
     * A single step in the post-approval action chain.
     * The implementation must call exactly one of {@link ChainCallback#done(byte[])}:
     * {@code done(null)} on success, {@code done(errorBytes)} on failure.
     */
    public interface ChainAction {
        void run(ChainCallback cb);
    }

    /**
     * Completion signal from a {@link ChainAction}.
     * {@code errorBytes} is {@code null} on success, non-null on failure.
     */
    public interface ChainCallback {
        void done(byte[] errorBytes);
    }

    // -------------------------------------------------------------------------

    private final String            rpId;
    private final CtapTxn           txn;
    private final List<ChainAction> actions;
    private final AtomicBoolean     delivered = new AtomicBoolean(false);
    private final byte              keepaliveStatus;
    private final boolean           requiresBiometric;

    /**
     * Creates a minimal context with no chain actions.
     *
     * @param rpId Relying-party identifier.
     * @param txn  The live {@link CtapTxn} for this channel.
     */
    public UpUvRequestCtx(String rpId, CtapTxn txn) {
        this(rpId, txn, Collections.emptyList());
    }

    /**
     * Creates a context with a post-approval action chain.
     *
     * @param rpId    Relying-party identifier.
     * @param txn     The live {@link CtapTxn} for this channel.
     * @param actions Ordered list of actions to run after approval (empty = none).
     */
    public UpUvRequestCtx(String rpId, CtapTxn txn, List<ChainAction> actions) {
        this(rpId, txn, actions, KEEPALIVE_UP_NEEDED);
    }

    /**
     * Creates a context with a specified keepalive status.
     *
     * @param rpId            Relying-party identifier.
     * @param txn             The live {@link CtapTxn} for this channel.
     * @param actions         Ordered list of actions to run after approval (empty = none).
     * @param keepaliveStatus {@link #KEEPALIVE_PROCESSING} or {@link #KEEPALIVE_UP_NEEDED}.
     */
    public UpUvRequestCtx(String rpId, CtapTxn txn, List<ChainAction> actions, byte keepaliveStatus) {
        this(rpId, txn, actions, keepaliveStatus, false);
    }

    /**
     * Full constructor.
     *
     * @param rpId              Relying-party identifier.
     * @param txn               The live {@link CtapTxn} for this channel.
     * @param actions           Ordered list of actions to run after approval (empty = none).
     * @param keepaliveStatus   {@link #KEEPALIVE_PROCESSING} or {@link #KEEPALIVE_UP_NEEDED}.
     * @param requiresBiometric {@code true} when the app layer must show a biometric prompt
     *                          before running the chain (getTkn / makeCredential / getAssertion
     *                          slow paths); {@code false} for UP-only ceremonies (getInfo /
     *                          getKey) where Allow/Deny is sufficient.
     */
    public UpUvRequestCtx(String rpId, CtapTxn txn, List<ChainAction> actions, byte keepaliveStatus,
                     boolean requiresBiometric) {
        this.rpId              = rpId;
        this.txn               = txn;
        this.actions           = actions;
        this.keepaliveStatus   = keepaliveStatus;
        this.requiresBiometric = requiresBiometric;
    }

    /** Returns the relying-party identifier. */
    public String  getRpId() { return rpId; }

    /** Returns the live transaction associated with this request. */
    public CtapTxn getTxn()  { return txn;  }

    /**
     * Returns the keepalive status that should be sent while waiting for this ceremony.
     * {@link #KEEPALIVE_PROCESSING} for GETKEY / GETTKN; {@link #KEEPALIVE_UP_NEEDED} for
     * makeCredential / getAssertion.
     */
    public byte getKeepaliveStatus() { return keepaliveStatus; }

    /**
     * Returns {@code true} when the app layer must present a biometric prompt before
     * running the chain actions.  {@code false} for UP-only ceremonies (getInfo / getKey)
     * where an Allow/Deny tap is sufficient.
     */
    public boolean requiresBiometric() { return requiresBiometric; }

    /**
     * Builds the CTAP wire response for the given {@code outcome} and delivers it via
     * {@code cb}, running any chained actions on the approved path.
     *
     * <ul>
     *   <li>On {@code DENIED} the chain is skipped and {@code cb.done(deniedBytes)} is
     *       called immediately.</li>
     *   <li>On {@code APPROVED} each action in {@link #actions} is run in order.
     *       The first action that calls {@code done(errorBytes)} with non-null bytes
     *       stops the chain and that error is delivered.  When all actions succeed,
     *       {@code cb.done(null)} is called (the actual CTAP response is sent by the
     *       deferred lambda inside makeCredential / getAssertion via
     *       {@code DeferredResponseSender.send}).</li>
     * </ul>
     *
     * <p>Idempotent: a second call invokes {@code cb.done(null)} without re-running
     * anything.</p>
     *
     * @param outcome The user's decision.
     * @param cb      Callback that receives the final response (or {@code null} on a
     *                duplicate call).
     */
    public void buildResponse(Outcome outcome, ChainCallback cb) {
        if (!delivered.compareAndSet(false, true)) { cb.done(null); return; }
        if (outcome != Outcome.APPROVED) {
            cb.done(AuthenticatorAPI.buildDeniedResponse());
            return;
        }
        // successResponse is null: makeCredential/getAssertion send their own response
        // via DeferredResponseSender after the biometric gate completes.
        new ChainRunner(actions, null, cb).run();
    }

    // -------------------------------------------------------------------------

    /**
     * Iterates the action list without recursion.
     *
     * <p>On the async path (bio prompt) the action stores the callback and returns;
     * {@link #run()} exits.  The bio callback thread later calls
     * {@link ChainCallback#done}, which re-enters {@link #run()} on that thread.
     * On the fast path the action calls {@link ChainCallback#done} synchronously before
     * returning; {@link #run()} sees {@code resultReady == true} and advances the loop
     * without re-entering itself.</p>
     */
    private static final class ChainRunner {
        private final List<ChainAction> actions;
        private final byte[]            successResponse;
        private final ChainCallback     terminal;
        private int              index       = 0;
        private volatile boolean resultReady = false;
        private volatile byte[]  result      = null;

        ChainRunner(List<ChainAction> actions, byte[] successResponse, ChainCallback terminal) {
            this.actions         = actions;
            this.successResponse = successResponse;
            this.terminal        = terminal;
        }

        void run() {
            while (index < actions.size()) {
                resultReady = false;
                actions.get(index++).run(errorBytes -> {
                    result      = errorBytes;
                    resultReady = true;
                    if (resultReady && result != null) { terminal.done(result); }
                    else if (resultReady) { run(); }
                });
                if (!resultReady) return;   // async — bio callback will re-enter run()
                if (result != null) return; // error already delivered above
            }
            terminal.done(successResponse);
        }
    }
}
