/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator;

import com.isfs.blekey.ctap.CtapTxn;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Immutable context object describing a pending user-presence request.
 *
 * <p>Created exclusively by {@link AuthenticatorAPI} and passed to the registered
 * {@link AuthenticatorAPI.UserPresenceCallback}.  The app layer calls
 * {@link #buildResponse(Outcome, ChainCallback)} exactly once when the user acts;
 * subsequent calls are silently ignored (idempotency guard via {@link AtomicBoolean}).</p>
 *
 * <p>{@code getInfo} no longer creates a UP context — it returns synchronously,
 * driven by {@code AppConfig.isCtap1CompatMode()}.  Every context that reaches
 * {@code onUserPresenceRequired} is therefore a {@code makeCredential} or
 * {@code getAssertion} ceremony.</p>
 */
public final class UpRequestContext {

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

    /**
     * Package-private — only {@link AuthenticatorAPI} creates instances.
     *
     * @param rpId Relying-party identifier.
     * @param txn  The live {@link CtapTxn} for this channel.
     */
    UpRequestContext(String rpId, CtapTxn txn) {
        this(rpId, txn, Collections.emptyList());
    }

    /**
     * Package-private overload that allows {@link AuthenticatorAPI} to supply a chain of
     * post-approval actions.
     *
     * @param rpId    Relying-party identifier.
     * @param txn     The live {@link CtapTxn} for this channel.
     * @param actions Ordered list of actions to run after approval (empty = none).
     */
    UpRequestContext(String rpId, CtapTxn txn, List<ChainAction> actions) {
        this.rpId    = rpId;
        this.txn     = txn;
        this.actions = actions;
    }

    /** Returns the relying-party identifier. */
    public String  getRpId() { return rpId; }

    /** Returns the live transaction associated with this request. */
    public CtapTxn getTxn()  { return txn;  }

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
