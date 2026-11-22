/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator.implapi.pin;

import com.isfs.blekey.authenticator.AuthenticatorAPI;
import com.isfs.blekey.authenticator.UpUvRequestCtx;
import com.isfs.blekey.authenticator.UxInteractionLock;
import com.isfs.blekey.authenticator.implapi.CtapResponse;
import com.isfs.blekey.authenticator.implapi.UpUvGate;
import com.isfs.blekey.ctap.Ctap2StatusCode;
import com.isfs.blekey.ctap.CtapTxn;
import com.isfs.blekey.data.Passkey;
import com.isfs.blekey.util.ByteUtils;
import com.isfs.blekey.util.Cbor;
import com.isfs.blekey.util.FileUtils;
import com.isfs.blekey.util.KeyUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import javax.crypto.NoSuchPaddingException;

/**
 * Handles the full PIN ceremony flow:
 * {@code pinRequest()}, {@code getKey()}, {@code getTkn()}, {@code pinRty()},
 * and all supporting helpers.
 *
 * <p>Deferred responses are dispatched via
 * {@link AuthenticatorAPI#getDeferredResponseSender()}.</p>
 */
public class PinFlowHandler {

    private static final Logger logger = LoggerFactory.getLogger(PinFlowHandler.class);

    /** id of pinUvAuthProtocol in clientPin requests. */
    private static final int KEY_PIN_UV_AUTH_PROTOCOL = 0x01;

    /** PIN token size in bytes (CTAP2 spec). */
    private static final int PIN_TOKEN_SIZE = 32;

    /** CBOR map key for encrypted PIN hash in clientPin requests. */
    private static final int KEY_PIN_HASH_ENC = 0x06;

    /** CBOR map key for platform key agreement key in clientPin requests. */
    private static final int KEY_PLATFORM_KEY_AGREEMENT = 0x03;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private PinFlowHandler() {}

    // -------------------------------------------------------------------------
    // Public entry points
    // -------------------------------------------------------------------------

    /**
     * Routes a clientPIN request to the correct sub-command handler.
     *
     * @param txn live CTAP transaction
     * @param req CTAP2 request map
     * @return response bytes, {@code null} (deferred), or an error
     */
    public static byte[] pinRequest(CtapTxn txn, Map<Integer, Object> req) {
        logger.debug("PinFlowHandler: === pinRequest START ===");
        PinSubCmd cmd = PinSubCmd.fromInt((int) req.getOrDefault(2, 0));
        logger.debug("PinFlowHandler: PIN subcommand: {}", cmd);
        logger.debug("PinFlowHandler: Request parameters: {}", req.keySet());

        switch (cmd) {
            case GETRETRY:
                logger.debug("PinFlowHandler: Processing GETRETRY");
                return pinRty(txn, req);
            case GETKEY:
                logger.debug("PinFlowHandler: Processing GETKEY");
                return getKey(txn, req);
            case GETTKN:
                logger.debug("PinFlowHandler: Processing GETTKN");
                return getTkn(txn, req);
            case GETTKNUV:
                logger.debug("PinFlowHandler: Processing GETTKNUV");
                return getTknBuiltIn(txn, req);
            case GETUVRETRY:
                logger.debug("PinFlowHandler: Processing GETUVRETRY");
                return uvRty(txn, req);
            case GETTKNPIN_PERMS:
                logger.debug("PinFlowHandler: Processing GETTKNPIN_PERMS");
                return getTknWithPinPermissions(txn, req);
            case GETTKNUV_PERMS:
                logger.debug("PinFlowHandler: Processing GETTKNUV_PERMS");
                return getTknBuiltInWithPermissions(txn, req);
            default:
                logger.debug("PinFlowHandler: Invalid PIN subcommand: {}", cmd);
                return CtapResponse.error(Ctap2StatusCode.INVALID_COMMAND);
        }
    }

    // -------------------------------------------------------------------------
    // pin auth protocol helpers
    // -------------------------------------------------------------------------

    private static PinUvAuthProtocol resolveProtocol(Map<Integer, ?> req) {
        return PinUvAuthProtocol.forId(req.get(KEY_PIN_UV_AUTH_PROTOCOL));
    }

    private static Ctap2StatusCode protocolError(Map<Integer, ?> req) {
        return req.get(KEY_PIN_UV_AUTH_PROTOCOL) == null
            ? Ctap2StatusCode.MISSING_PARAMETER
            : Ctap2StatusCode.INVALID_PARAMETER;
    }

    // -------------------------------------------------------------------------
    // getKey
    // -------------------------------------------------------------------------

    /**
     * Handles the getKeyAgreement PIN sub-command.
     */
    private static byte[] getKey(CtapTxn txn, Map<Integer, Object> req) {
        logger.debug("entry getKey");
        if (resolveProtocol(req) == null) {
            logger.warn("pinUvAuthProtocol missing/unsupported");
            return CtapResponse.error(protocolError(req));
        }
        return executeGetKey(txn);
    }

    /**
     * Generates the ephemeral ECDH key pair, stores it on the txn, and returns
     * the COSE key response.
     */
    public static byte[] executeGetKey(CtapTxn txn) {
        
        // Attempt to start out-of-band UX collection for this CID if it is idle.
        // DO NOT PROMPT FOR UPUV IF A GRANT IS ACTIVE — the bio gate is already in
        // progress or complete; do not start another one. UxTrigger.fireIfIdle()
        // guards all of these conditions internally.
        UpUvGate.fireIfIdle(txn, () -> new UpUvRequestCtx(
            null,
            txn,
            Collections.emptyList(),
            true   // requiresBiometric: platform key is needed
        ));

        KeyPair ecdhPair;
        try {
            ecdhPair = KeyUtils.generateKeyPair("EC", 256);
        } catch (Exception e) {
            logger.error("getKey: failed to generate ephemeral ECDH key pair", e);
            return CtapResponse.error(Ctap2StatusCode.OTHER);
        }
        if (txn != null) {
            txn.setEcdhKeyPair(ecdhPair);
            logger.debug("getKey: stored ephemeral ECDH key pair on CID transaction");
        }
        Map<Integer, Object> coseKey = KeyUtils.toCoseKey(ecdhPair.getPublic(), -25);
        Map<Integer, Object> rsp = Map.of(0x01, coseKey);
        byte[] keyBytes = Cbor.encode(rsp);
        logger.debug("getKey: CBOR-encoded response hex dump:");
        logger.debug("{}", ByteUtils.hexDump(keyBytes, "GETKEY Response"));
        return CtapResponse.success(keyBytes);
    }

    // -------------------------------------------------------------------------
    // getTkn
    // -------------------------------------------------------------------------

    /**
     * Handles the getPINToken PIN sub-command.
     * Always requires UV (biometric). Runs synchronously if lock is owned + IKM cached;
     * otherwise defers behind UP + biometric dialog.
     */
    private static byte[] getTkn(CtapTxn txn, Map<Integer, ?> req) {
        if (txn == null) {
            logger.warn("getTkn: null txn — OPERATION_DENIED");
            return CtapResponse.error(Ctap2StatusCode.OPERATION_DENIED);
        }
        if (resolveProtocol(req) == null) {
            logger.warn("pinUvAuthProtocol missing/unsupported");
            return CtapResponse.error(protocolError(req));
        }
        // Grant fast-path: bio done app-wide — no dialog or notification needed.
        // IKM is owned by UxInteractionLock; CredentialSeedDeriver reads from it directly.
        // The fast-path sets userPresent before calling processTkn to match prior behaviour.
        if (UxInteractionLock.get().isGrantActive()) {
            logger.debug("getTkn: grant active — processing synchronously, no notification");
            txn.setUserPresent(true);
            return processTkn(txn, req);
        }

        return UpUvGate.await(
            txn,
            "getTkn",
            null,                              // rpId not applicable for PIN
            UpUvGate.LatchStrategy.ASYNC,      // must not block BLE handler thread
            UpUvRequestCtx.CeremonyType.GET_TKN,
            () -> processTkn(txn, req)
        );
    }

    // -------------------------------------------------------------------------
    // getTknBuiltIn — GETTKNUV (0x06): built-in UV via in-app PIN Activity
    // -------------------------------------------------------------------------

    /**
     * Handles {@code getPinUvAuthTokenUsingUvWithPermissions} (subCommand 0x06).
     * If a prior ceremony is {@code IN_PROGRESS}, waits on the latch (ASYNC) before
     * triggering the in-app PIN Activity.
     */
    private static byte[] getTknBuiltIn(CtapTxn txn, Map<Integer, Object> req) {
        if (txn == null) {
            logger.warn("getTknBuiltIn: null txn — OPERATION_DENIED");
            return CtapResponse.error(Ctap2StatusCode.OPERATION_DENIED);
        }
        if (resolveProtocol(req) == null) {
            logger.warn("pinUvAuthProtocol missing/unsupported");
            return CtapResponse.error(protocolError(req));
        }
        if (PinSessionRegistry.getUvRetries() == 0) {
            logger.warn("getTknBuiltIn: uvRetries exhausted — UV_BLOCKED");
            return CtapResponse.error(Ctap2StatusCode.UV_BLOCKED);
        }

        logger.debug("getTknBuiltIn: req keys={} passkey={} pinHash={} ecdhKeyPair={}",
                req.keySet(),
                txn.getPasskey() != null ? txn.getPasskey().getFileName() : "null",
                txn.getPinHash() != null ? txn.getPinHash().length + "bytes" : "null",
                txn.getEcdhKeyPair() != null ? "present" : "null");

        byte[] result = UpUvGate.await(
            txn,
            "getTknBuiltIn",
            null,
            UpUvGate.LatchStrategy.ASYNC,
            UpUvRequestCtx.CeremonyType.GET_TKN_UV,
            () -> generateUvToken(txn, req)
        );
        logger.debug("getTknBuiltIn: UpUvGate.await returned {}", result == null ? "null (deferred)" : result.length + "bytes, status=0x" + String.format("%02x", result[0]));
        return result;
    }

    /**
     * Generates the UV token: ECDH + random 32-byte nonce encrypted with the shared
     * secret, committed to the CID session via
     * {@link PinSessionRegistry#updateAuthenticationState}.
     *
     * <p>Requires that {@code GETKEY} has already been called on this CID so that
     * {@code txn.getEcdhKeyPair()} is non-null.</p>
     */
    static byte[] generateUvToken(CtapTxn txn, Map<Integer, ?> req) {
        logger.debug("generateUvToken: passkey={} pinHash={} ecdhKeyPair={}",
                txn.getPasskey() != null ? txn.getPasskey().getFileName() : "null",
                txn.getPinHash() != null ? txn.getPinHash().length + "bytes" : "null",
                txn.getEcdhKeyPair() != null ? "present" : "null");
        PinUvAuthProtocol protocol = resolveProtocol(req);
        PublicKey clientKey = extractClientPublicKey(req);
        if (clientKey == null) {
            logger.warn("generateUvToken: clientKey null — MISSING_PARAMETER");
            return CtapResponse.error(Ctap2StatusCode.MISSING_PARAMETER);
        }
        byte[] sharedSecret = performEcdhKeyAgreement(protocol, clientKey, txn);
        if (sharedSecret == null) {
            logger.warn("generateUvToken: sharedSecret null — OTHER");
            return CtapResponse.error(Ctap2StatusCode.OTHER);
        }
        try {
            byte[] uvToken = new byte[PIN_TOKEN_SIZE];
            SECURE_RANDOM.nextBytes(uvToken);
            byte[] encryptedUvToken = protocol.encrypt(sharedSecret, uvToken);
            // mc|ga permissions for GETTKNUV.
            txn.setPinUvAuthProtocol(protocol.id());
            PinSessionRegistry.updateAuthenticationState(txn, txn.getPasskey(), uvToken,
                txn.getPinHash(), 0x03);
            PinSessionRegistry.resetUvRetries();
            byte[] response = new PinTokenResponseBuilder().withPinToken(encryptedUvToken).build();
            logger.debug("generateUvToken: sending {} bytes, status=0x{}", response.length, String.format("%02x", response[0]));
            return response;
        } catch (GeneralSecurityException e) {
            int remaining = PinSessionRegistry.decrementUvRetries();
            logger.error("generateUvToken: crypto failure, uvRetries remaining: {}", remaining, e);
            return handleCryptographicException(e);
        }
    }

    /**
     * Generates a UV token with requestor-supplied permissions.
     */
    static byte[] generateUvTokenWithPermissions(CtapTxn txn, Map<Integer, ?> req, int permissions) {
        logger.debug("generateUvTokenWithPermissions: permissions=0x{} passkey={} ecdhKeyPair={}",
                Integer.toHexString(permissions),
                txn.getPasskey() != null ? txn.getPasskey().getFileName() : "null",
                txn.getEcdhKeyPair() != null ? "present" : "null");
        PinUvAuthProtocol protocol = resolveProtocol(req);
        PublicKey clientKey = extractClientPublicKey(req);
        if (clientKey == null) {
            logger.warn("generateUvTokenWithPermissions: clientKey null — MISSING_PARAMETER");
            return CtapResponse.error(Ctap2StatusCode.MISSING_PARAMETER);
        }
        byte[] sharedSecret = performEcdhKeyAgreement(protocol, clientKey, txn);
        if (sharedSecret == null) {
            logger.warn("generateUvTokenWithPermissions: sharedSecret null — OTHER");
            return CtapResponse.error(Ctap2StatusCode.OTHER);
        }
        try {
            byte[] uvToken = new byte[PIN_TOKEN_SIZE];
            SECURE_RANDOM.nextBytes(uvToken);
            byte[] encryptedUvToken = protocol.encrypt(sharedSecret, uvToken);
            txn.setPinUvAuthProtocol(protocol.id());
            PinSessionRegistry.updateAuthenticationState(txn, txn.getPasskey(), uvToken,
                txn.getPinHash(), permissions);
            PinSessionRegistry.resetUvRetries();
            byte[] response = new PinTokenResponseBuilder().withPinToken(encryptedUvToken).build();
            logger.debug("generateUvTokenWithPermissions: sending {} bytes, status=0x{}",
                response.length, String.format("%02x", response[0]));
            return response;
        } catch (GeneralSecurityException e) {
            int remaining = PinSessionRegistry.decrementUvRetries();
            logger.error("generateUvTokenWithPermissions: crypto failure, uvRetries remaining: {}", remaining, e);
            return handleCryptographicException(e);
        }
    }

    // -------------------------------------------------------------------------
    // pinRty
    // -------------------------------------------------------------------------

    private static byte[] pinRty(CtapTxn txn, Map<Integer, Object> req) {
        Map<Integer, Object> rsp = Map.of(0x03, PinSessionRegistry.getPinRetries());
        return CtapResponse.success(Cbor.encode(rsp));
    }

    // -------------------------------------------------------------------------
    // uvRty — GETUVRETRY (0x07)
    // -------------------------------------------------------------------------

    /**
     * Returns the number of built-in UV retries remaining (CBOR map key {@code 0x05}).
     * Does not decrement — the counter decrements only on a failed UV attempt.
     */
    private static byte[] uvRty(CtapTxn txn, Map<Integer, Object> req) {
        Map<Integer, Object> rsp = Map.of(0x05, PinSessionRegistry.getUvRetries());
        return CtapResponse.success(Cbor.encode(rsp));
    }

    // -------------------------------------------------------------------------
    // processTkn helpers
    // -------------------------------------------------------------------------

    /**
     * Core PIN-token logic getPinToken: validates the PIN hash, performs ECDH,
     * generates the token with permissions mc|ga (0x03) per CTAP 2.3 §6.5.5.7.1.
     */
    public static byte[] processTkn(CtapTxn txn, Map<Integer, ?> req) {
        PinUvAuthProtocol protocol = resolveProtocol(req);
        PinHashValidationResult validation = validateAndExtractPinHash(req);
        if (!validation.isValid()) {
            return CtapResponse.error(validation.getErrorCode());
        }
        PublicKey clientKey = extractClientPublicKey(req);
        if (clientKey == null) {
            return CtapResponse.error(Ctap2StatusCode.INVALID_PARAMETER);
        }
        byte[] sharedSecret = performEcdhKeyAgreement(protocol, clientKey, txn);
        if (sharedSecret == null) {
            return CtapResponse.error(Ctap2StatusCode.OTHER);
        }
        return processPinVerificationAndGenerateToken(protocol, txn, validation.getPinHashEnc(), sharedSecret,
                0x03 /* mc | ga */);
    }

    /**
     * Handles {@code getPinUvAuthTokenUsingPinWithPermissions} (sub-command 0x09).
     * Reads the {@code permissions} field (CBOR key 0x09) from the request and issues a
     * token scoped to those permissions only. CTAP 2.3 §6.5.5.7.2.
     */
    private static byte[] getTknWithPinPermissions(CtapTxn txn, Map<Integer, Object> req) {
        if (txn == null) {
            logger.warn("getTknWithPinPermissions: null txn — OPERATION_DENIED");
            return CtapResponse.error(Ctap2StatusCode.OPERATION_DENIED);
        }
        if (resolveProtocol(req) == null) {
            logger.warn("pinUvAuthProtocol missing/unsupported");
            return CtapResponse.error(protocolError(req));
        }
        Object permObj = req.get(0x09);
        if (!(permObj instanceof Integer)) {
            logger.error("getTknWithPinPermissions: missing or invalid permissions parameter");
            return CtapResponse.error(Ctap2StatusCode.MISSING_PARAMETER);
        }
        int permissions = (Integer) permObj;
        if (permissions == 0) {
            logger.error("getTknWithPinPermissions: permissions value is 0 — INVALID_PARAMETER");
            return CtapResponse.error(Ctap2StatusCode.INVALID_PARAMETER);
        }

        if (UxInteractionLock.get().isGrantActive()) {
            logger.debug("getTknWithPinPermissions: grant active — processing synchronously");
            txn.setUserPresent(true);
            return processTknWithPermissions(txn, req, permissions);
        }

        return UpUvGate.await(
            txn,
            "getTknWithPinPermissions",
            null,
            UpUvGate.LatchStrategy.ASYNC,
            UpUvRequestCtx.CeremonyType.GET_TKN,
            () -> processTknWithPermissions(txn, req, permissions)
        );
    }

    /**
     * Core PIN-token logic for {@code getPinUvAuthTokenUsingPinWithPermissions}.
     * Identical to {@link #processTkn} except uses the caller-supplied permissions bitmask.
     */
    static byte[] processTknWithPermissions(CtapTxn txn, Map<Integer, ?> req, int permissions) {
        PinUvAuthProtocol protocol = resolveProtocol(req);
        PinHashValidationResult validation = validateAndExtractPinHash(req);
        if (!validation.isValid()) {
            return CtapResponse.error(validation.getErrorCode());
        }
        PublicKey clientKey = extractClientPublicKey(req);
        if (clientKey == null) {
            return CtapResponse.error(Ctap2StatusCode.INVALID_PARAMETER);
        }
        byte[] sharedSecret = performEcdhKeyAgreement(protocol, clientKey, txn);
        if (sharedSecret == null) {
            return CtapResponse.error(Ctap2StatusCode.OTHER);
        }
        return processPinVerificationAndGenerateToken(protocol, txn, validation.getPinHashEnc(), sharedSecret,
                permissions);
    }

    /**
     * Handles {@code getPinUvAuthTokenUsingUvWithPermissions} via sub-command 0x0A.
     * Reads the {@code permissions} field (CBOR key 0x09) from the request and issues a
     * UV token scoped to those permissions. Falls back to mc|ga (0x03) if absent.
     * CTAP 2.3 §6.5.5.7.3.
     */
    private static byte[] getTknBuiltInWithPermissions(CtapTxn txn, Map<Integer, Object> req) {
        if (txn == null) {
            logger.warn("getTknBuiltInWithPermissions: null txn — OPERATION_DENIED");
            return CtapResponse.error(Ctap2StatusCode.OPERATION_DENIED);
        }
        if (resolveProtocol(req) == null) {
            logger.warn("pinUvAuthProtocol missing/unsupported");
            return CtapResponse.error(protocolError(req));
        }
        if (PinSessionRegistry.getUvRetries() == 0) {
            logger.warn("getTknBuiltInWithPermissions: uvRetries exhausted — UV_BLOCKED");
            return CtapResponse.error(Ctap2StatusCode.UV_BLOCKED);
        }

        Object permObj = req.get(0x09 /* permissions */);
        if (!(permObj instanceof Integer)) {
            logger.error("getTknBuiltInWithPermissions: missing or invalid permissions parameter");
            return CtapResponse.error(Ctap2StatusCode.MISSING_PARAMETER);
        }
        int permissions = (Integer) permObj;
        if (permissions == 0) {
            logger.error("getTknBuiltInWithPermissions: permissions value is 0 — INVALID_PARAMETER");
            return CtapResponse.error(Ctap2StatusCode.INVALID_PARAMETER);
        }

        return UpUvGate.await(
            txn,
            "getTknBuiltInWithPermissions",
            null,
            UpUvGate.LatchStrategy.ASYNC,
            UpUvRequestCtx.CeremonyType.GET_TKN_UV,
            () -> generateUvTokenWithPermissions(txn, req, permissions)
        );
    }

    private static PinHashValidationResult validateAndExtractPinHash(Map<Integer, ?> req) {
        Object pinHashEncObj = req.get(KEY_PIN_HASH_ENC);
        if (pinHashEncObj == null) {
            logger.error("Missing encrypted PIN hash (0x06) in request");
            return PinHashValidationResult.failure(Ctap2StatusCode.MISSING_PARAMETER);
        }
        if (!(pinHashEncObj instanceof byte[])) {
            logger.error("Invalid type for encrypted PIN hash, expected byte[]");
            return PinHashValidationResult.failure(Ctap2StatusCode.INVALID_PARAMETER);
        }
        return PinHashValidationResult.success((byte[]) pinHashEncObj);
    }

    private static PublicKey extractClientPublicKey(Map<Integer, ?> req) {
        @SuppressWarnings("unchecked")
        Map<Integer, Object> clientCoseKey = (Map<Integer, Object>) req.get(KEY_PLATFORM_KEY_AGREEMENT);
        if (clientCoseKey == null) {
            logger.error("Missing client COSE key (0x03) in request");
            return null;
        }
        PublicKey clientKey = KeyUtils.fromCoseKey(clientCoseKey);
        if (clientKey == null) {
            logger.error("Failed to parse client public key from COSE format");
        } else {
            logger.debug("Successfully parsed client public key from COSE structure");
        }
        return clientKey;
    }

    private static byte[] performEcdhKeyAgreement(PinUvAuthProtocol protocol, PublicKey clientKey, CtapTxn txn) {
        if (txn == null || txn.getEcdhKeyPair() == null) {
            logger.error("performEcdhKeyAgreement: no ECDH key pair on transaction — "
                         + "GETKEY must precede GETTKN on the same CID");
            return null;
        }
        byte[] sharedSecret;
        try {
            sharedSecret = protocol.decapsulate(clientKey, txn.getEcdhKeyPair().getPrivate());
        } catch (GeneralSecurityException | RuntimeException e) {
            logger.error("ECDH key agreement failed", e);
            sharedSecret = null;
        } finally {
            txn.setEcdhKeyPair(null); // erase from memory
        }
        if (sharedSecret != null) {
            logger.debug("ECDH key agreement successful, shared secret size: {} bytes",
                         sharedSecret.length);
        } else {
            logger.error("ECDH key agreement failed to generate shared secret");
        }
        return sharedSecret;
    }

    private static byte[] processPinVerificationAndGenerateToken(PinUvAuthProtocol protocol,
                                                                   CtapTxn txn,
                                                                   byte[] pinHashEnc,
                                                                   byte[] sharedSecret,
                                                                   int permissions) {
        try {
            PinVerificationResult pinVerification = decryptAndVerifyPin(protocol, pinHashEnc, sharedSecret);
            if (!pinVerification.isValid()) {
                return CtapResponse.error(pinVerification.getErrorCode());
            }

            byte[] pinHash = pinVerification.getPinHash(); // 16 bytes
            byte[] fullPinHash = reconstructFullPinHash(pinHash, pinVerification.getPasskey());

            byte[] pinToken = new byte[PIN_TOKEN_SIZE];
            SECURE_RANDOM.nextBytes(pinToken);
            byte[] encryptedPinToken = protocol.encrypt(sharedSecret, pinToken);
            logger.debug("Encrypted token: {}", Arrays.toString(encryptedPinToken));
            txn.setPinUvAuthProtocol(protocol.id());
            PinSessionRegistry.updateAuthenticationState(txn, pinVerification.getPasskey(),
                pinToken, fullPinHash != null ? fullPinHash : pinHash, permissions);
            return new PinTokenResponseBuilder().withPinToken(encryptedPinToken).build();

        } catch (GeneralSecurityException e) {
            return handleCryptographicException(e);
        }
    }

    private static PinVerificationResult decryptAndVerifyPin(PinUvAuthProtocol protocol,
                                                              byte[] pinHashEnc,
                                                              byte[] sharedSecret)
            throws GeneralSecurityException {
        byte[] pinHash = protocol.decrypt(sharedSecret, pinHashEnc);
        if (pinHash.length != 16) {
            return PinVerificationResult.failure(Ctap2StatusCode.PIN_AUTH_INVALID);
        }
        Passkey pkeyFile = verifyPinAndOpenPasskey(pinHash);
        if (pkeyFile == null) {
            Ctap2StatusCode errorCode = (PinSessionRegistry.getPinRetries() == 0)
                ? Ctap2StatusCode.PIN_BLOCKED
                : Ctap2StatusCode.PIN_AUTH_INVALID;
            if (PinSessionRegistry.getPinRetries() == 0) {
                logger.error("PIN blocked due to too many failed attempts");
            }
            return PinVerificationResult.failure(errorCode);
        }
        return PinVerificationResult.success(pkeyFile, pinHash);
    }

    private static Passkey verifyPinAndOpenPasskey(byte[] pinHash) {
        Passkey pkeyFile = Passkey.openKey(pinHash);
        if (pkeyFile == null) {
            int remaining = PinSessionRegistry.decrementRetries();
            logger.error("Failed to open passkey file. Retries remaining: {}", remaining);
        } else {
            logger.debug("Passkey file opened successfully");
        }
        return pkeyFile;
    }

    private static byte[] reconstructFullPinHash(byte[] lowerHash, Passkey passkey) {
        if (lowerHash == null || lowerHash.length != 16 || passkey == null) return null;
        try {
            java.io.File pkFile = new java.io.File(
                FileUtils.getFido2Home(), passkey.getFileName());
            byte[] upperHashEnc = FileUtils.readFileBytes(FileUtils.getStashFile(pkFile));
            byte[] upperHash = KeyUtils.getStashCipher().decrypt(upperHashEnc);
            if (upperHash == null || upperHash.length != 16) return null;
            byte[] fullHash = new byte[32];
            System.arraycopy(lowerHash, 0, fullHash,  0, 16);
            System.arraycopy(upperHash,  0, fullHash, 16, 16);
            return fullHash;
        } catch (Exception e) {
            logger.warn("reconstructFullPinHash: failed", e);
            return null;
        }
    }

    private static byte[] handleCryptographicException(Exception e) {
        if (e instanceof NoSuchAlgorithmException || e instanceof NoSuchPaddingException) {
            logger.error("Cryptographic algorithm not available", e);
            return CtapResponse.error(Ctap2StatusCode.OTHER);
        }
        if (e instanceof InvalidKeyException
                || e instanceof InvalidAlgorithmParameterException) {
            logger.error("Invalid cryptographic parameters", e);
            return CtapResponse.error(Ctap2StatusCode.INVALID_PARAMETER);
        }
        if (e instanceof GeneralSecurityException) {
            logger.error("Cryptographic operation failed", e);
            return CtapResponse.error(Ctap2StatusCode.PIN_AUTH_INVALID);
        }
        logger.error("Unexpected exception during PIN token generation", e);
        return CtapResponse.error(Ctap2StatusCode.OTHER);
    }
}
