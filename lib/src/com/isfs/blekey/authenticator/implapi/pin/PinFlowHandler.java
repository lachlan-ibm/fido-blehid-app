/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator.implapi.pin;

import com.isfs.blekey.authenticator.AuthenticatorAPI;
import com.isfs.blekey.authenticator.AuthenticatorAPI.UpUvCallback;
import com.isfs.blekey.authenticator.UpUvRequestCtx;
import com.isfs.blekey.authenticator.UxInteractionLock;
import com.isfs.blekey.ctap.Ctap2StatusCode;
import com.isfs.blekey.ctap.CtapTxn;
import com.isfs.blekey.ctap.CtapTxn.CidUxState;
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
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

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

    /** PIN token size in bytes (CTAP2 spec). */
    private static final int PIN_TOKEN_SIZE = 32;

    /** AES block size in bytes. */
    private static final int AES_BLOCK_SIZE = 16;

    /** CBOR map key for encrypted PIN hash in clientPin requests. */
    private static final int KEY_PIN_HASH_ENC = 0x06;

    /** CBOR map key for platform key agreement key in clientPin requests. */
    private static final int KEY_PLATFORM_KEY_AGREEMENT = 0x03;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /** ThreadLocal AES-CBC cipher (NoPadding). */
    private static final ThreadLocal<Cipher> AES_CBC_CIPHER =
        ThreadLocal.withInitial(() -> {
            try {
                return Cipher.getInstance("AES/CBC/NoPadding");
            } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                throw new RuntimeException("AES/CBC/NoPadding cipher not available", e);
            }
        });

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
            default:
                logger.debug("PinFlowHandler: Invalid PIN subcommand: {}", cmd);
                return error(Ctap2StatusCode.INVALID_COMMAND);
        }
    }

    // -------------------------------------------------------------------------
    // getKey
    // -------------------------------------------------------------------------

    /**
     * Handles the getKeyAgreement PIN sub-command.
     * Returns synchronously — no UP/UV prompt, no lock claimed (plan §4.2 / G3).
     */
    private static byte[] getKey(CtapTxn txn, Map<Integer, Object> req) {
        logger.debug("getKey: synchronous");
        return executeGetKey(txn);
    }

    /**
     * Generates the ephemeral ECDH key pair, stores it on the txn, and returns
     * the COSE key response.
     */
    public static byte[] executeGetKey(CtapTxn txn) {
        // Attempt to start out-of-band UX collection for this CID.
        // Guard: only when txn exists, uxState is IDLE, and the lock is free.
        // If another CID holds the lock, uxState stays IDLE and protected commands
        // will return CHANNEL_BUSY via the existing legacy path (unchanged).
        //DO NOT PROMPT FOR UPUV IF A GRANT IS ACTIVE THE BIO GATE IS ALREADY IN PROGRESS OR COMPLETE
        //DO NOT START ANOTHER ONE
        if (!UxInteractionLock.get().isGrantActive()
                && txn.getCid() != null
                && txn.getUxState() == CidUxState.IDLE
                && UxInteractionLock.get().tryAcquire(txn.getCid())) {
            txn.setUxState(CidUxState.IN_PROGRESS);
            txn.armUxLatch();
            UpUvCallback cb = AuthenticatorAPI.getUpUvCallback();
            if (cb != null) {
                logger.debug("getKey: starting out-of-band UX for CID {}", Arrays.toString(txn.getCid()));
                cb.onUpUvRequired(new UpUvRequestCtx(
                    null,
                    txn,
                    java.util.Collections.emptyList(),
                    UpUvRequestCtx.KEEPALIVE_PROCESSING,
                    true   // requiresBiometric: platform key is needed
                ));
            } else {
                // No callback registered — release lock and reset state.
                UxInteractionLock.get().release(txn.getCid());
                txn.setUxState(CidUxState.IDLE);
            }
        }
        KeyPair ecdhPair;
        try {
            ecdhPair = KeyUtils.generateKeyPair("EC", 256);
        } catch (Exception e) {
            logger.error("getKey: failed to generate ephemeral ECDH key pair", e);
            return error(Ctap2StatusCode.OTHER);
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
        return success(keyBytes);
    }

    // -------------------------------------------------------------------------
    // getTkn
    // -------------------------------------------------------------------------

    /**
     * Handles the getPINToken PIN sub-command.
     * Always requires UV (biometric). Runs synchronously if lock is owned + IKM cached;
     * otherwise defers behind UP + biometric dialog.
     */
    /** Maximum ms to wait for the out-of-band UX latch before timing out (§5.4). */
    private static final long UP_WAIT_TIMEOUT_MS = 25_000L;

    private static byte[] getTkn(CtapTxn txn, Map<Integer, ?> req) {
        // Grant fast-path: bio done app-wide — no dialog or notification needed.
        // IKM is owned by UxInteractionLock; CredentialSeedDeriver reads from it directly.
        if (txn != null && UxInteractionLock.get().isGrantActive()) {
            logger.debug("getTkn: grant active — processing synchronously, no notification");
            txn.setUserPresent(true);
            return processTkn(txn, req);
        }

        // Denied path: CID was already denied this session.
        if (txn != null && (txn.getUxState() == CidUxState.DENIED || txn.isUserDenied())) {
            logger.warn("getTkn: CID denied — OPERATION_DENIED");
            return error(Ctap2StatusCode.OPERATION_DENIED);
        }

        // Latch-wait path: GETKEY already started the UX; wait off-thread to avoid ANR.
        if (txn != null && txn.getUxState() == CidUxState.IN_PROGRESS) {
            logger.debug("getTkn: UX in progress — registering deferred latch listener");
            final Map<Integer, ?> reqSnapshot = req;
            Thread latchWaiter = new Thread(() -> {
                boolean completed = txn.awaitUxLatch(UP_WAIT_TIMEOUT_MS);
                byte[] response;
                if (!completed || txn.getUxState() != CidUxState.APPROVED) {
                    logger.warn("getTkn: latch timeout or denied — OPERATION_DENIED");
                    response = error(Ctap2StatusCode.OPERATION_DENIED);
                } else {
                    logger.debug("getTkn: latch fired APPROVED — processing token");
                    response = processTkn(txn, reqSnapshot);
                }
                AuthenticatorAPI.DeferredResponseSender sender =
                    AuthenticatorAPI.getDeferredResponseSender();
                if (sender != null) {
                    sender.send(txn, response);
                } else {
                    logger.error("getTkn: no DeferredResponseSender — response dropped");
                }
            }, "getTkn-latch-waiter");
            latchWaiter.setDaemon(true);
            latchWaiter.start();
            return null; // deferred
        }

        // Legacy deferred path: getInfo was not called first (platform skipped it),
        // or lock held by another CID. Preserve existing behaviour unchanged.
        AuthenticatorAPI.UpUvCallback cb = AuthenticatorAPI.getUpUvCallback();
        if (cb == null) {
            logger.warn("getTkn: no UpUvCallback — OPERATION_DENIED");
            return error(Ctap2StatusCode.OPERATION_DENIED);
        }

        final Map<Integer, ?> reqFinal = req;

        if (!UxInteractionLock.get().tryAcquire(txn.getCid())) {
            logger.warn("getTkn: CID does not own UP lock — CHANNEL_BUSY");
            return error(Ctap2StatusCode.CHANNEL_BUSY);
        }
        cb.onUpUvRequired(
            new UpUvRequestCtx(null, txn,
                java.util.List.of((chainCb) -> onGetTknUpApproved(chainCb, txn, reqFinal)),
                UpUvRequestCtx.KEEPALIVE_PROCESSING,
                true,  // requiresBiometric: UV always required for getTkn
                UpUvRequestCtx.CeremonyType.GET_TKN
            )
        );
        return null; // deferred (legacy path)
    }

    private static void onGetTknUpApproved(UpUvRequestCtx.ChainCallback chainCb,
                                            CtapTxn txn,
                                            Map<Integer, ?> req) {
        if (txn != null) txn.setUserPresent(true);
        byte[] response = processTkn(txn, req);
        AuthenticatorAPI.DeferredResponseSender sender = AuthenticatorAPI.getDeferredResponseSender();
        if (sender != null) sender.send(txn, response);
        chainCb.done(null);
    }

    // -------------------------------------------------------------------------
    // pinRty
    // -------------------------------------------------------------------------

    private static byte[] pinRty(CtapTxn txn, Map<Integer, Object> req) {
        Map<Integer, Object> rsp = Map.of(0x03, PinSessionRegistry.getPinRetries());
        PinSessionRegistry.decrementRetries();
        return success(Cbor.encode(rsp));
    }

    // -------------------------------------------------------------------------
    // processTkn helpers
    // -------------------------------------------------------------------------

    /**
     * Core PIN-token logic: validates the PIN hash, performs ECDH, generates the token.
     */
    public static byte[] processTkn(CtapTxn txn, Map<Integer, ?> req) {
        PinHashValidationResult validation = validateAndExtractPinHash(req);
        if (!validation.isValid()) {
            return error(validation.getErrorCode());
        }
        PublicKey clientKey = extractClientPublicKey(req);
        if (clientKey == null) {
            return error(Ctap2StatusCode.INVALID_PARAMETER);
        }
        byte[] sharedSecret = performEcdhKeyAgreement(clientKey, txn);
        if (sharedSecret == null) {
            return error(Ctap2StatusCode.OTHER);
        }
        return processPinVerificationAndGenerateToken(txn, validation.getPinHashEnc(), sharedSecret);
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

    private static byte[] performEcdhKeyAgreement(PublicKey clientKey, CtapTxn txn) {
        if (txn == null || txn.getEcdhKeyPair() == null) {
            logger.error("performEcdhKeyAgreement: no ECDH key pair on transaction — "
                         + "GETKEY must precede GETTKN on the same CID");
            return null;
        }
        java.security.PrivateKey priv = txn.getEcdhKeyPair().getPrivate();
        byte[] sharedSecret = KeyUtils.decapsulate(clientKey, priv);
        txn.setEcdhKeyPair(null); // erase from memory
        if (sharedSecret != null) {
            logger.debug("ECDH key agreement successful, shared secret size: {} bytes",
                         sharedSecret.length);
        } else {
            logger.error("ECDH key agreement failed to generate shared secret");
        }
        return sharedSecret;
    }

    private static byte[] processPinVerificationAndGenerateToken(CtapTxn txn,
                                                                   byte[] pinHashEnc,
                                                                   byte[] sharedSecret) {
        try {
            PinVerificationResult pinVerification = decryptAndVerifyPin(pinHashEnc, sharedSecret);
            if (!pinVerification.isValid()) {
                return error(pinVerification.getErrorCode());
            }

            byte[] pinHash = pinVerification.getPinHash(); // 16 bytes
            byte[] fullPinHash = reconstructFullPinHash(pinHash, pinVerification.getPasskey());

            byte[] pinToken = new byte[PIN_TOKEN_SIZE];
            SECURE_RANDOM.nextBytes(pinToken);
            byte[] encryptedPinToken = performAesCbc(Cipher.ENCRYPT_MODE, pinToken, sharedSecret);
            logger.debug("Encrypted token: {}", encryptedPinToken);
            PinSessionRegistry.updateAuthenticationState(txn, pinVerification.getPasskey(),
                pinToken, fullPinHash != null ? fullPinHash : pinHash);
            return new PinTokenResponseBuilder().withPinToken(encryptedPinToken).build();

        } catch (GeneralSecurityException e) {
            return handleCryptographicException(e);
        }
    }

    private static PinVerificationResult decryptAndVerifyPin(byte[] pinHashEnc,
                                                              byte[] sharedSecret)
            throws GeneralSecurityException {
        byte[] pinHash = performAesCbc(Cipher.DECRYPT_MODE, pinHashEnc, sharedSecret);
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

    private static byte[] performAesCbc(int mode, byte[] data, byte[] sharedSecret)
            throws GeneralSecurityException {
        SecretKeySpec keySpec = new SecretKeySpec(sharedSecret, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[AES_BLOCK_SIZE]);
        Cipher cipher = AES_CBC_CIPHER.get();
        cipher.init(mode, keySpec, ivSpec);
        return cipher.doFinal(data);
    }

    private static byte[] handleCryptographicException(Exception e) {
        if (e instanceof NoSuchAlgorithmException || e instanceof NoSuchPaddingException) {
            logger.error("Cryptographic algorithm not available", e);
            return error(Ctap2StatusCode.OTHER);
        }
        if (e instanceof InvalidKeyException
                || e instanceof InvalidAlgorithmParameterException) {
            logger.error("Invalid cryptographic parameters", e);
            return error(Ctap2StatusCode.INVALID_PARAMETER);
        }
        if (e instanceof GeneralSecurityException) {
            logger.error("Cryptographic operation failed", e);
            return error(Ctap2StatusCode.PIN_AUTH_INVALID);
        }
        logger.error("Unexpected exception during PIN token generation", e);
        return error(Ctap2StatusCode.OTHER);
    }

    // -------------------------------------------------------------------------
    // Response helpers
    // -------------------------------------------------------------------------

    private static byte[] success(byte[] rsp) {
        byte[] out = new byte[rsp.length + 1];
        out[0] = (byte) Ctap2StatusCode.SUCCESS.getCode();
        System.arraycopy(rsp, 0, out, 1, rsp.length);
        return out;
    }

    private static byte[] error(Ctap2StatusCode code) {
        return new byte[]{ (byte) code.getCode() };
    }
}
