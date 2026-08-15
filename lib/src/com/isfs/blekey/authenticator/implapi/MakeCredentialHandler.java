/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator.implapi;

import com.isfs.blekey.authenticator.AuthenticatorAPI;
import com.isfs.blekey.authenticator.CredentialType;
import com.isfs.blekey.authenticator.Fido2Authenticator;
import com.isfs.blekey.authenticator.UpUvRequestCtx;
import com.isfs.blekey.authenticator.UxInteractionLock;
import com.isfs.blekey.authenticator.implapi.pin.PinSessionRegistry;
import com.isfs.blekey.authenticator.implapi.pin.PinUvAuthResult;
import com.isfs.blekey.authenticator.implapi.pin.PinVerifier;
import com.isfs.blekey.ctap.Ctap2StatusCode;
import com.isfs.blekey.ctap.CtapTxn;
import com.isfs.blekey.ctap.CtapTxn.CidUxState;
import com.isfs.blekey.data.AppConfig;
import com.isfs.blekey.util.KeyUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

/**
 * Handles the {@code makeCredential} CTAP command (0x01).
 *
 * <p>Owns {@code makeCredential()}, {@code executeMakeCredential()}, and
 * {@code handleResidentCredentialStorage()}.  Result type
 * {@link CredentialCreationResult} lives as a package-private top-level class at the
 * bottom of this file (§6g).</p>
 */
public class MakeCredentialHandler {

    private static final Logger logger = LoggerFactory.getLogger(MakeCredentialHandler.class);

    /** Maximum ms to wait for the out-of-band UX latch before timing out (§5.3). */
    private static final long UP_WAIT_TIMEOUT_MS = 25_000L;

    private MakeCredentialHandler() {}

    /**
     * Entry point for the {@code makeCredential} command (CTAP 0x01).
     * Defers behind a UP/UV prompt if user presence has not yet been collected.
     *
     * @return response bytes, {@code null} (deferred), or an error
     */
    public static byte[] makeCredential(CtapTxn txn, Map<Integer, Object> req) {
        logger.info("makeCredential: starting credential creation");

        if (!PinSessionRegistry.loadAuthenticatedSession(txn)) {
            logger.debug("makeCredential: no PIN session for CID — using platform key");
            txn.setPasskey(null);
        }

        CredentialValidationResult validation =
            CredentialValidator.canMakeCredential(req, txn.getPasskey());
        if (!validation.isValid()) {
            logger.error("Credential validation failed: {}", validation.errorCode);
            return error(validation.errorCode);
        }
        logger.debug("Creating credential of type: {}", validation.type);

        // Fast path: app-global bio grant active — covers any CID, not just the one that
        // collected UP. A fresh CtapTxn always has isUserPresent=false, so the old guard
        // of txn.isUserPresent() && isGrantActive() was never true on a new session.
        if (UxInteractionLock.get().isGrantActive()) {
            logger.debug("makeCredential: grant active — fast path, no UP prompt");
            try {
                return executeMakeCredential(validation, txn, req);
            } catch (Exception e) {
                logger.error("makeCredential fast-path failed", e);
                return error(Ctap2StatusCode.OTHER);
            }
        }

        // Denied path: CID was already denied this session.
        if (txn.getUxState() == CidUxState.DENIED || txn.isUserDenied()) {
            logger.warn("makeCredential: CID denied — OPERATION_DENIED");
            return error(Ctap2StatusCode.OPERATION_DENIED);
        }

        // Latch-wait path: getInfo already started the UX; wait for it to complete.
        if (txn.getUxState() == CidUxState.IN_PROGRESS) {
            logger.debug("makeCredential: UX in progress — waiting on latch (max {}ms)", UP_WAIT_TIMEOUT_MS);
            boolean completed = txn.awaitUxLatch(UP_WAIT_TIMEOUT_MS);
            if (!completed || txn.getUxState() != CidUxState.APPROVED) {
                logger.warn("makeCredential: UX latch timeout or denied — OPERATION_DENIED");
                return error(Ctap2StatusCode.OPERATION_DENIED);
            }
            logger.debug("makeCredential: latch-wait path — latch fired, UX APPROVED");
            try {
                return executeMakeCredential(validation, txn, req);
            } catch (Exception e) {
                logger.error("makeCredential post-latch failed", e);
                return error(Ctap2StatusCode.OTHER);
            }
        }

        // Legacy deferred path: getInfo was not called first (platform skipped it),
        // or lock held by another CID. Preserve existing behaviour unchanged.
        AuthenticatorAPI.UpUvCallback cb = AuthenticatorAPI.getUpUvCallback();
        if (cb == null) {
            logger.warn("makeCredential: no UpUvCallback — OPERATION_DENIED");
            return error(Ctap2StatusCode.OPERATION_DENIED);
        }

        @SuppressWarnings("unchecked")
        String rpIdStr = (String) ((Map<String, Object>) req.get(0x02)).get("id");
        final CredentialValidationResult valFinal = validation;
        final Map<Integer, Object> reqFinal = req;

        if (!UxInteractionLock.get().tryAcquire(txn.getCid())) {
            logger.warn("makeCredential: CID does not own UP lock — CHANNEL_BUSY");
            return error(Ctap2StatusCode.CHANNEL_BUSY);
        }
        cb.onUpUvRequired(
            new UpUvRequestCtx(rpIdStr, txn,
                List.of((chainCb) ->
                    onMakeCredentialUpApproved(chainCb, txn, valFinal, reqFinal)),
                UpUvRequestCtx.KEEPALIVE_UP_NEEDED,
                true,  // requiresBiometric
                UpUvRequestCtx.CeremonyType.MAKE_CREDENTIAL
            )
        );
        return null; // deferred (legacy path)
    }

    private static void onMakeCredentialUpApproved(
            UpUvRequestCtx.ChainCallback chainCb,
            CtapTxn txn,
            CredentialValidationResult val,
            Map<Integer, Object> req) {
        txn.setUserPresent(true);
        try {
            byte[] response = executeMakeCredential(val, txn, req);
            AuthenticatorAPI.DeferredResponseSender sender =
                AuthenticatorAPI.getDeferredResponseSender();
            if (sender != null) sender.send(txn, response);
        } catch (Exception e) {
            logger.error("makeCredential chain action failed", e);
            AuthenticatorAPI.DeferredResponseSender sender =
                AuthenticatorAPI.getDeferredResponseSender();
            if (sender != null) sender.send(txn, error(Ctap2StatusCode.OTHER));
        }
        chainCb.done(null);
    }

    // -------------------------------------------------------------------------
    // executeMakeCredential
    // -------------------------------------------------------------------------

    static byte[] executeMakeCredential(
            CredentialValidationResult validation,
            CtapTxn txn,
            Map<Integer, Object> req) throws Exception {

        CredentialOptions options = CredentialValidator.parseOptions(req);
        PinUvAuthResult pinUvResult;
        if (options.uv || req.containsKey(0x08 /* PIN_UV_AUTH_PARAM */)) {
            pinUvResult = PinVerifier.verify(req, txn);
            if (pinUvResult.errorCode != null) return error(pinUvResult.errorCode);
        } else {
            pinUvResult = PinUvAuthResult.NO_VERIFICATION;
        }
        logger.info("executeMakeCredential: req.uv={}; user verified={}",
                    options.uv, pinUvResult.userVerified);

        AttestationMaterial attestation =
            AttestationBuilder.loadAttestationMaterial(validation.type, txn);
        Fido2Authenticator authenticator = validateAndCreateAuthenticator(txn, req);
        if (authenticator == null) return error(Ctap2StatusCode.OTHER);

        CredentialCreationResult credentialResult =
            AttestationBuilder.buildCredentialData(req, authenticator, attestation);
        if (!credentialResult.isSuccess()) return error(credentialResult.errorCode);

        Ctap2StatusCode storeError = handleResidentCredentialStorage(
            validation.type, req, authenticator, txn);
        if (storeError != null) return error(storeError);

        return AttestationBuilder.buildMakeCredentialResponse(
            credentialResult.authenticatorData,
            credentialResult.attestationStatement
        );
    }

    private static Fido2Authenticator validateAndCreateAuthenticator(
            CtapTxn txn, Map<Integer, Object> req) {
        try {
            Fido2Authenticator a = new Fido2Authenticator();
            byte[] rpIdBytes = CredentialSeedDeriver.extractRpIdBytes(req.get(0x02));
            AppConfig appConfig = AuthenticatorAPI.getAppConfig();

            if (txn.getPasskey() != null) {
                CredentialSeedDeriver.configureCredentialAnchor(
                    a, txn.getPasskey().getPrivateKey(), rpIdBytes, appConfig);
            } else {
                a.setSymKeys(KeyUtils.getPasskeySeed(rpIdBytes,
                    UxInteractionLock.get().getCachedIkm(), appConfig));
            }
            return a;
        } catch (IllegalArgumentException | IllegalStateException e) {
            logger.error("Authenticator creation failed: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            logger.error("Unexpected error creating authenticator", e);
            throw new RuntimeException("Failed to create authenticator: " + e.getMessage(), e);
        }
    }

    static Ctap2StatusCode handleResidentCredentialStorage(
            CredentialType type,
            Map<Integer, Object> req,
            Fido2Authenticator authenticator,
            CtapTxn txn) {
        if (type != CredentialType.RESIDENT) return null;
        Ctap2StatusCode storeResult = ResidentCredentialStore.storeResidentCredential(
            req, authenticator.getCredId(), txn.getPasskey(), txn);
        if (storeResult != null && storeResult != Ctap2StatusCode.SUCCESS) return storeResult;
        return null;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static byte[] error(Ctap2StatusCode code) {
        return new byte[]{ (byte) code.getCode() };
    }
}

// ---------------------------------------------------------------------------
// Result type co-located with MakeCredentialHandler (§6g)
// ---------------------------------------------------------------------------

/** Holds the built authenticator data + attestation statement, or an error code. */
class CredentialCreationResult {
    final byte[] authenticatorData;
    final Map<String, Object> attestationStatement;
    final Ctap2StatusCode errorCode;

    CredentialCreationResult(byte[] authenticatorData, Map<String, Object> attestationStatement) {
        this.authenticatorData = authenticatorData;
        this.attestationStatement = attestationStatement;
        this.errorCode = null;
    }

    CredentialCreationResult(Ctap2StatusCode errorCode) {
        this.authenticatorData = null;
        this.attestationStatement = null;
        this.errorCode = errorCode;
    }

    boolean isSuccess() { return errorCode == null; }
}
