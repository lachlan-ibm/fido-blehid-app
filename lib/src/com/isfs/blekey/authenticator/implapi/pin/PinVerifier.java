/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator.implapi.pin;

import com.isfs.blekey.ctap.Ctap2StatusCode;
import com.isfs.blekey.ctap.CtapTxn;
import com.isfs.blekey.util.Cbor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * PIN/UV authentication verification — the flattened 2-method form (§6b).
 *
 * <p>Replaces the original six-method chain
 * ({@code verifyPinUvAuth → handleMissingPinUvAuthParam → verifyToken →
 * verifyTokenWithParams → retrievePinAuthToken → verifyPinAuthToken}) and
 * eliminates {@code PinAuthException}.  All error propagation is done via the
 * {@link PinUvAuthResult} return type.</p>
 *
 * <p>Result types {@link PinUvAuthResult}, {@link PinHashValidationResult},
 * {@link PinVerificationResult}, and {@link PinTokenResponseBuilder} live as
 * package-private top-level classes at the bottom of this file.</p>
 */
public class PinVerifier {

    private static final Logger logger = LoggerFactory.getLogger(PinVerifier.class);

    /** Supported PIN/UV auth protocol version (CTAP 2.3). */
    private static final int SUPPORTED_PIN_UV_AUTH_PROTOCOL = 1;

    /** ThreadLocal HmacSHA256 — one instance per thread, no synchronisation needed. */
    private static final ThreadLocal<Mac> HMAC_SHA256 =
        ThreadLocal.withInitial(() -> {
            try {
                return Mac.getInstance("HmacSHA256");
            } catch (java.security.NoSuchAlgorithmException e) {
                throw new RuntimeException("HmacSHA256 algorithm not available", e);
            }
        });

    private PinVerifier() {}

    /**
     * Entry point for PIN/UV authentication (flattened §6b).
     *
     * <p>Handles the null-param case inline, validates the protocol version,
     * then delegates to {@link #verifyHmac} for the pure crypto check.</p>
     *
     * @param req CTAP2 request map (keys 0x08 pinUvAuthParam, 0x09 protocol, 0x01 cdh)
     * @param txn the CTAP transaction holding the pinAuthToken
     * @return {@link PinUvAuthResult} with verification status or error code
     */
    public static PinUvAuthResult verify(Map<Integer, Object> req, CtapTxn txn) {
        logger.debug("Starting PIN/UV auth verification");
        PinUvAuthParams params = PinUvAuthParams.parse(req);
        if (!params.isValid()) {
            return new PinUvAuthResult(false, params.errorCode);
        }

        // No pinUvAuthParam — proceed without UV unless UV was explicitly requested.
        if (params.pinUvAuthParam == null) {
            if (params.uvRequested) {
                logger.error("User verification required but no PIN/UV auth token provided");
                return new PinUvAuthResult(false, Ctap2StatusCode.PIN_REQUIRED);
            }
            logger.debug("No PIN/UV auth param provided, proceeding without user verification");
            return PinUvAuthResult.NO_VERIFICATION;
        }

        // Validate protocol version.
        if (params.pinUvAuthProtocol == null) {
            logger.error("PIN/UV auth protocol not specified");
            return new PinUvAuthResult(false, Ctap2StatusCode.PIN_AUTH_INVALID);
        }
        if (params.pinUvAuthProtocol != SUPPORTED_PIN_UV_AUTH_PROTOCOL) {
            logger.error("Unsupported PIN/UV auth protocol: {}", params.pinUvAuthProtocol);
            return new PinUvAuthResult(false, Ctap2StatusCode.PIN_AUTH_INVALID);
        }

        byte[] clientDataHash = (byte[]) req.get(0x01);
        if (clientDataHash == null) {
            logger.error("Missing clientDataHash for PIN/UV auth verification");
            return new PinUvAuthResult(false, Ctap2StatusCode.MISSING_PARAMETER);
        }

        // Inline token retrieval — no checked exception needed.
        byte[] pinAuthToken = txn.getPinAuthTkn();
        logger.debug("Retrieving PIN token from transaction: {}",
                     pinAuthToken != null ? pinAuthToken.length + " bytes" : "null");
        if (pinAuthToken == null) {
            logger.error("No PIN auth token in transaction");
            return new PinUvAuthResult(false, Ctap2StatusCode.PIN_AUTH_INVALID);
        }

        PinUvAuthResult result = verifyHmac(pinAuthToken, params.pinUvAuthParam, clientDataHash);
        if (result.errorCode == null) {
            logger.debug("PIN/UV auth verification completed successfully");
        }
        return result;
    }

    /**
     * Pure HMAC-SHA-256 check: verifies that
     * {@code pinUvAuthParam == HMAC-SHA-256(pinAuthToken, clientDataHash)[0:16]}.
     * No checked exception declared.
     *
     * @param pinAuthToken    symmetric key (full token from transaction)
     * @param pinUvAuthParam  first 16 bytes of the expected HMAC
     * @param clientDataHash  the message (32-byte SHA-256 of client data)
     * @return {@link PinUvAuthResult} — {@code userVerified=true} on success
     */
    public static PinUvAuthResult verifyHmac(byte[] pinAuthToken, byte[] pinUvAuthParam,
                                              byte[] clientDataHash) {
        logger.debug("Verifying PIN/UV auth token HMAC");
        try {
            Mac mac = HMAC_SHA256.get();
            mac.init(new SecretKeySpec(pinAuthToken, "HmacSHA256"));
            byte[] expected16 = Arrays.copyOf(mac.doFinal(clientDataHash), 16);
            if (!MessageDigest.isEqual(pinUvAuthParam, expected16)) {
                logger.error("PIN/UV auth token verification failed: HMAC mismatch");
                return new PinUvAuthResult(false, Ctap2StatusCode.PIN_AUTH_INVALID);
            }
            return new PinUvAuthResult(true, null);
        } catch (InvalidKeyException e) {
            logger.error("Invalid key during PIN/UV auth token verification", e);
            return new PinUvAuthResult(false, Ctap2StatusCode.PIN_AUTH_INVALID);
        }
    }
}

// ---------------------------------------------------------------------------
// Result types co-located with their owning handler (§6g)
// ---------------------------------------------------------------------------
// PinUvAuthResult is in its own file (public class requirement).

/**
 * Result of PIN hash validation — either the extracted encrypted hash or an error code.
 */
class PinHashValidationResult {
    private final byte[] pinHashEnc;
    private final Ctap2StatusCode errorCode;

    private PinHashValidationResult(byte[] pinHashEnc, Ctap2StatusCode errorCode) {
        this.pinHashEnc = pinHashEnc;
        this.errorCode = errorCode;
    }

    static PinHashValidationResult success(byte[] pinHashEnc) {
        return new PinHashValidationResult(pinHashEnc, null);
    }

    static PinHashValidationResult failure(Ctap2StatusCode errorCode) {
        return new PinHashValidationResult(null, errorCode);
    }

    boolean isValid() { return pinHashEnc != null; }
    byte[] getPinHashEnc() { return pinHashEnc; }
    Ctap2StatusCode getErrorCode() { return errorCode; }
}

/**
 * Result of PIN verification — either the opened passkey + PIN hash or an error code.
 */
class PinVerificationResult {
    private final com.isfs.blekey.data.Passkey passkey;
    private final byte[] pinHash;
    private final Ctap2StatusCode errorCode;

    private PinVerificationResult(com.isfs.blekey.data.Passkey passkey, byte[] pinHash,
                                   Ctap2StatusCode errorCode) {
        this.passkey = passkey;
        this.pinHash = pinHash;
        this.errorCode = errorCode;
    }

    static PinVerificationResult success(com.isfs.blekey.data.Passkey passkey, byte[] pinHash) {
        return new PinVerificationResult(passkey, pinHash, null);
    }

    static PinVerificationResult failure(Ctap2StatusCode errorCode) {
        return new PinVerificationResult(null, null, errorCode);
    }

    boolean isValid() { return passkey != null; }
    com.isfs.blekey.data.Passkey getPasskey() { return passkey; }
    byte[] getPinHash() { return pinHash; }
    Ctap2StatusCode getErrorCode() { return errorCode; }
}

/**
 * Builder for PIN token CBOR responses.
 */
class PinTokenResponseBuilder {
    private final Map<Integer, Object> response = new HashMap<>();

    PinTokenResponseBuilder withPinToken(byte[] pinToken) {
        response.put(0x02 /* KEY_PIN_TOKEN */, pinToken);
        return this;
    }

    byte[] build() {
        byte[] encoded = Cbor.encode(response);
        byte[] out = new byte[encoded.length + 1];
        out[0] = (byte) com.isfs.blekey.ctap.Ctap2StatusCode.SUCCESS.getCode();
        System.arraycopy(encoded, 0, out, 1, encoded.length);
        return out;
    }
}
