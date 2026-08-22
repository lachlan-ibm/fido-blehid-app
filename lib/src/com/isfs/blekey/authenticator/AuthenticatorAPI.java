/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator;

import com.isfs.blekey.authenticator.UxInteractionLock.UxState;
import com.isfs.blekey.authenticator.implapi.CtapResponse;
import com.isfs.blekey.authenticator.implapi.GetAssertionHandler;
import com.isfs.blekey.authenticator.implapi.MakeCredentialHandler;
import com.isfs.blekey.authenticator.implapi.UpUvGate;
import com.isfs.blekey.authenticator.implapi.pin.PinFlowHandler;
import com.isfs.blekey.authenticator.implapi.pin.PinSessionRegistry;
import com.isfs.blekey.ctap.Ctap2StatusCode;
import com.isfs.blekey.ctap.CtapTxn;
import com.isfs.blekey.data.AppConfig;
import com.isfs.blekey.util.Cbor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Public entry point for the FIDO2 / CTAP2 authenticator.
 *
 * <p>This class owns only the public API surface and the shared static fields
 * ({@code upUvCallback}, {@code deferredResponseSender}, {@code appConfig}).
 * All command implementations have been extracted to cohesive handler classes
 * in the {@code authenticator.pin}, {@code authenticator.credential}, and
 * {@code authenticator} (flat) packages per the refactor plan.</p>
 *
 * <ul>
 *   <li>{@link MakeCredentialHandler}   — CTAP 0x01 makeCredential</li>
 *   <li>{@link GetAssertionHandler}     — CTAP 0x02/0x08 getAssertion / getNextAssertion</li>
 *   <li>{@link PinFlowHandler}          — CTAP 0x06 clientPIN (getKey / getTkn / getRetries)</li>
 *   <li>{@link U2fHandler}              — CTAP1 / U2F registration, authentication</li>
 * </ul>
 */
public class AuthenticatorAPI {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticatorAPI.class);

    // -------------------------------------------------------------------------
    // UpUvCallback
    // -------------------------------------------------------------------------

    /**
     * Callback invoked when user-presence/user-verification evidence must be collected.
     * Implemented by the App layer; the lib layer has no OS/Platform dependencies.
     */
    public interface UpUvCallback {
        /**
         * Called on the CTAP processing thread when user presence / verification is needed.
         * The implementation must post to the UI thread before showing any dialog.
         *
         * @param context  Immutable context; call {@link UpUvRequestCtx#buildResponse}
         *                 once the user acts.
         */
        void onUpUvRequired(UpUvRequestCtx context);
    }

    /** Shared callback — volatile so background threads see updates immediately. */
    private static volatile UpUvCallback upUvCallback = null;

    public static void setUpUvCallback(UpUvCallback cb) {
        upUvCallback = cb;
    }

    /** Returns the current UP/UV callback; accessible to sub-package handlers. */
    public static UpUvCallback getUpUvCallback() {
        return upUvCallback;
    }

    // -------------------------------------------------------------------------
    // DeferredResponseSender
    // -------------------------------------------------------------------------

    /**
     * Thin send-back shim passed into every deferred CTAP operation.
     * Implemented by HIDForegroundService; keep lib free of any
     * reference to Android APIs or app layer.
     */
    public interface DeferredResponseSender {
        void send(CtapTxn txn, byte[] response);
    }

    private static volatile DeferredResponseSender deferredResponseSender = null;

    public static void setDeferredResponseSender(DeferredResponseSender sender) {
        deferredResponseSender = sender;
    }

    /** Returns the current deferred-response sender; accessible to sub-package handlers. */
    public static DeferredResponseSender getDeferredResponseSender() {
        return deferredResponseSender;
    }

    // -------------------------------------------------------------------------
    // App configuration
    // -------------------------------------------------------------------------

    /** App configuration used for all credential key derivation. Thread-safe via volatile. */
    private static volatile AppConfig appConfig = AppConfig.getDefault();

    /**
     * Sets the App configuration. Call from the app layer before any CTAP ceremony begins,
     * typically in {@code HIDForegroundService.onCreate()} after loading SharedPreferences.
     *
     * @param config non-null config; passing null resets to the built-in default.
     */
    public static void setAppConfig(AppConfig config) {
        appConfig = (config != null) ? config : AppConfig.getDefault();
    }

    /** Returns the active App configuration. */
    public static AppConfig getAppConfig() {
        return appConfig;
    }

    // -------------------------------------------------------------------------
    // PIN retry accessors (delegated to PinSessionRegistry)
    // -------------------------------------------------------------------------

    /** Returns the number of PIN retry attempts remaining before lockout. */
    public static int getPinRetries() {
        return PinSessionRegistry.getPinRetries();
    }

    /** Returns the maximum number of PIN attempts allowed before lockout. */
    public static int getMaxPinRetries() {
        return PinSessionRegistry.MAX_PIN_RETRIES;
    }

    /**
     * Resets the PIN retry counter to the maximum value.
     * Call only from an operator-authenticated UI gesture.
     */
    public static void resetPinRetries() {
        PinSessionRegistry.resetPinRetries();
    }

    // -------------------------------------------------------------------------
    // UP interaction lock
    // -------------------------------------------------------------------------

    /**
     * The Ux lock been denied recently; don't ask again.
     * 
     */
    public static void setUxLockDenied(long windowMs) {
        UxInteractionLock.get().setUserDenied(windowMs);
    }

    /**
     * Releases the UP interaction lock held by the given CID.
     * Called by HIDForegroundService on denial or timeout.
     */
    public static void resetUpLock() {
        UxInteractionLock.get().reset();
    }

    // -------------------------------------------------------------------------
    // Public error/response helpers
    // -------------------------------------------------------------------------

    /**
     * Builds a CTAP2 error response byte array.
     * Used by the Android layer when it needs to build an error response
     * without having visibility into the private {@code error()} method.
     */
    public static byte[] buildErrorResponse(Ctap2StatusCode code) {
        return CtapResponse.error(code);
    }

    // -------------------------------------------------------------------------
    // Package-private response builders — called only by UpUvRequestCtx
    // -------------------------------------------------------------------------

    /**
     * Builds the full CTAP2 getInfo response.
     * Advertises FIDO_2_1 and FIDO_2_0, includes PIN/UV Auth Protocol 1 and clientPin.
     */
    static byte[] buildGetInfoCtap2Response() {
        LinkedHashMap<String, Boolean> capabilities = new LinkedHashMap<>();
        capabilities.put("rk", true);
        capabilities.put("plat", true);
        capabilities.put("clientPin", true);
        LinkedHashMap<Integer, Object> info = new LinkedHashMap<>();
        info.put(0x01, new String[]{"FIDO_2_1", "FIDO_2_0"});
        info.put(0x02, new String[]{"hmac-secret"});
        info.put(0x03, new byte[16]);
        info.put(0x04, capabilities);
        info.put(0x05, 4096);
        info.put(0x06, new int[]{1}); // PIN/UV Auth Protocol 1
        return success(Cbor.encode(info));
    }

    /**
     * Builds the CTAP1-compat getInfo response.
     * Omits {@code pinUvAuthProtocols} and the {@code clientPin} option;
     * adds {@code "U2F_V2"} to the versions array.
     */
    static byte[] buildGetInfoCtap1CompatResponse() {
        LinkedHashMap<String, Boolean> capabilities = new LinkedHashMap<>();
        capabilities.put("rk", true);
        capabilities.put("plat", true);
        LinkedHashMap<Integer, Object> info = new LinkedHashMap<>();
        info.put(0x01, new String[]{"FIDO_2_0", "U2F_V2"});
        info.put(0x02, new String[]{"hmac-secret"});
        info.put(0x03, new byte[16]);
        info.put(0x04, capabilities);
        info.put(0x05, 4096);
        return success(Cbor.encode(info));
    }

    /** Builds the single-byte OPERATION_DENIED error response. */
    static byte[] buildDeniedResponse() {
        return new byte[]{ (byte) Ctap2StatusCode.OPERATION_DENIED.getCode() };
    }

    private static byte[] success(byte[] rsp) {
        ByteBuffer bb = ByteBuffer.allocate(rsp.length + 1);
        bb.put((byte) Ctap2StatusCode.SUCCESS.getCode());
        bb.put(rsp);
        return bb.array();
    }

    // -------------------------------------------------------------------------
    // process() — main command router
    // -------------------------------------------------------------------------

    /**
     * Main entry point for processing CTAP2 commands.
     * Routes the request to the appropriate handler based on the command type.
     *
     * @param txn     the CTAP transaction
     * @param api     the CTAP2 command identifier
     * @param request the request parameters
     * @return a byte array containing the response
     */
    public static byte[] process(CtapTxn txn, int api, Map<Integer, Object> request) {
        AuthenticatorCmd cmd = AuthenticatorCmd.fromInt(api);
        switch (cmd) {
            case MKCRED:
                return MakeCredentialHandler.makeCredential(txn, request);
            case NXTAST:
                return GetAssertionHandler.getAssertion(txn, request);
            case GETNXTAST:
                return GetAssertionHandler.getNextAssertion(txn, request);
            case GETINF:
                return getInfo(txn, request);
            case ATHPIN:
                return PinFlowHandler.pinRequest(txn, request);
            case SELECTION:
                return authenticatorSelection(txn);
            default:
                return new byte[]{ (byte) Ctap2StatusCode.INVALID_COMMAND.getCode() };
        }
    }

    // -------------------------------------------------------------------------
    // getInfo (CTAP 0x04)
    // -------------------------------------------------------------------------

    /**
     * Processes a getInfo request (CTAP2 authenticatorGetInfo command).
     *
     * <p>If the CID is idle and the UX lock is free, the response is <em>deferred</em>:
     * the pre-built CBOR bytes are stashed inside the {@link UpUvRequestCtx} as
     * {@code inlineResponse} and {@code null} is returned.  {@code CtapHid.cbor()}
     * then takes the deferred path (sets {@code deferredCmd}, returns without sending).
     * When the user taps Allow, {@code HIDForegroundService.deliverUpApproved()} calls
     * {@code buildResponse(APPROVED, cb)}, which routes {@code inlineResponse} through
     * {@link UpUvRequestCtx.ChainRunner} → {@code cb.done(responseBytes)} →
     * {@code sendDeferred(txn, responseBytes)} — putting the bytes on the wire only
     * after the user has consented.  The biometric prompt follows immediately after.</p>
     *
     * <p>Will only return if Ux is being attempted or has been approved
     * (test / offline path).</p>
     */
    protected static byte[] getInfo(CtapTxn txn, Map<Integer, Object> req) {
        boolean ctap1 = appConfig.isCtap1CompatMode();
        byte[] responseBytes = ctap1 ? buildGetInfoCtap1CompatResponse()
                                     : buildGetInfoCtap2Response();
        if (UxInteractionLock.get().isGrantActive()) {
            logger.debug("getInfo: grant active; UP set, ctap1CompatMode={}", ctap1);
            return responseBytes;
        }

        boolean fired = UpUvGate.fireIfIdle(txn, () -> new UpUvRequestCtx(
            null,
            txn,
            responseBytes, //Send response once approved; do not wait for bio auth
            true,
            UpUvRequestCtx.CeremonyType.GET_INFO
        ));
        if (fired) {
            logger.debug("[{}]:getInfo: requesting UPUV session from idle lock", Arrays.toString(txn.getCid()));
            return null;
        }
        UxState state = UxInteractionLock.get().getUxState(); 
        logger.debug("getInfo: UxState [{}], ctap1CompatMode={}", state, ctap1);
        return (!UxState.DENIED.equals(state)) ? //Approved should have active grant; in-progress is above
                responseBytes : new byte[]{ (byte) Ctap2StatusCode.OPERATION_DENIED.getCode() };
    }

    // -------------------------------------------------------------------------
    // authenticatorSelection (CTAP 0x0B)
    // -------------------------------------------------------------------------

    /**
     * Processes an authenticatorSelection request (CTAP2.1 command 0x0B).
     * UP determined by state of ux lock; approved == ok to reply
     */
    private static byte[] authenticatorSelection(CtapTxn txn) {
        if (!UxState.DENIED.equals(UxInteractionLock.get().getUxState())) {
            logger.debug("authenticatorSelection: grant active; UP set");
            return new byte[]{ (byte) Ctap2StatusCode.SUCCESS.getCode() };
        }
        logger.debug("authenticatorSelection: UP denied returning denied");
        return new byte[]{ (byte) Ctap2StatusCode.OPERATION_DENIED.getCode() };
    }

    // -------------------------------------------------------------------------
    // CTAP1 / U2F entry points — delegated to U2fHandler
    // -------------------------------------------------------------------------

    public static byte[] u2fRegister(CtapTxn txn, byte[] challengeParam, byte[] appParam) {
        return U2fHandler.u2fRegister(txn, challengeParam, appParam);
    }

    public static boolean u2fCheckKeyHandle(CtapTxn txn, byte[] appParam, byte[] keyHandle) {
        return U2fHandler.u2fCheckKeyHandle(txn, appParam, keyHandle);
    }

    public static byte[] u2fAuthenticate(CtapTxn txn, byte[] challengeParam, byte[] appParam,
                                          byte[] keyHandle, boolean requireUP) {
        return U2fHandler.u2fAuthenticate(txn, challengeParam, appParam, keyHandle, requireUP);
    }
}
