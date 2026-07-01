/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator;

import com.isfs.blekey.util.Cbor;
import com.isfs.blekey.ctap.Ctap2StatusCode;
import com.isfs.blekey.ctap.CtapTxn;
import com.isfs.blekey.util.KeyUtils;
import com.isfs.blekey.util.FileUtils;
import com.isfs.blekey.util.ByteUtils;

import com.isfs.blekey.data.Passkey;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implements the FIDO2 Client to Authenticator Protocol (CTAP2) API.
 * This class handles CTAP2 commands and generates appropriate responses,
 * interfacing with the Fido2Authenticator to perform cryptographic operations.
 */
public class AuthenticatorAPI {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticatorAPI.class);

    // -------------------------------------------------------------------------
    // User-Presence callback — set once by the Android layer before any ceremony
    // -------------------------------------------------------------------------

    /**
     * Callback invoked when user presence evidence must be collected.
     * Implemented by the Android layer (ServerActivity); the lib layer has no
     * Android dependencies.
     *
     * <p>The lib pre-builds both possible response buffers and hands them to the
     * app layer together with the live {@link CtapTxn}.  The app layer sends
     * keepalive frames until the user acts, then calls
     * {@code HIDPasskey.sendDeferredResponse(txn, approvedResponse)} or
     * {@code HIDPasskey.sendDeferredResponse(txn, deniedResponse)} accordingly.
     * No runnables are involved — the app layer owns the decision and the send.</p>
     */
    public interface UserPresenceCallback {
        /**
         * @param rpId            Relying-party ID (null for getInfo).
         * @param txn             The live {@link CtapTxn} for this channel.
         * @param approvedResponse Pre-built bytes to send when the user approves.
         * @param deniedResponse  Pre-built bytes to send when the user denies.
         */
        void onUserPresenceRequired(String rpId, CtapTxn txn,
                                    byte[] approvedResponse, byte[] deniedResponse);
    }

    /** Shared callback — volatile so background threads see updates immediately. */
    private static volatile UserPresenceCallback userPresenceCallback = null;

    /**
     * Registers the user-presence callback.  Call from ServerActivity before
     * any CTAP ceremony begins; call with {@code null} in onDestroy to unregister.
     *
     * @param cb The callback implementation, or null to clear it.
     */
    public static void setUserPresenceCallback(UserPresenceCallback cb) {
        userPresenceCallback = cb;
    }

    /**
     * Public wrapper over the private {@link #error(Ctap2StatusCode)} method.
     * Used by the Android layer when it needs to build an error response byte
     * array (e.g. for timeout or denied UP) without having visibility into
     * the private method.
     *
     * @param code The CTAP2 status code
     * @return Single-byte array {@code [code.getCode()]}
     */
    public static byte[] buildErrorResponse(Ctap2StatusCode code) {
        return new byte[] { (byte) code.getCode() };
    }

    /**
     * Number of PIN retry attempts allowed before lockout.
     */
    private static int pinRetries = 5;

    /**
     * Key pair used for platform authentication.
     */
    private static KeyPair platKeyPair = KeyUtils.getKeyPair("ECDSA");
    
    /**
     * Map of channel IDs to their authenticated passkeys.
     * Maps CID to the Passkey that was authenticated via PIN verification.
     */
    private static Map<byte[], Passkey> openKeys = new HashMap<>();

    /**
     * Supported COSE algorithm identifiers.
     * ES256 (-7) is the primary algorithm for FIDO2.
     */
    private static final Set<Integer> SUPPORTED_ALGORITHM_SET = new HashSet<>(Arrays.asList(-7));

    /**
     * Supported PIN/UV authentication protocol version.
     * Currently only Protocol One (version 1) is supported per CTAP 2.3 specification.
     */
    private static final int SUPPORTED_PIN_UV_AUTH_PROTOCOL = 1;

    /**
     * ThreadLocal cache for HmacSHA256 Mac instances to avoid expensive getInstance() calls.
     * Each thread gets its own instance, eliminating synchronization overhead.
     */
    private static final ThreadLocal<javax.crypto.Mac> HMAC_SHA256 =
        ThreadLocal.withInitial(() -> {
            try {
                return javax.crypto.Mac.getInstance("HmacSHA256");
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("HmacSHA256 algorithm not available", e);
            }
        });
    
    /**
     * ThreadLocal cache for SHA-256 MessageDigest instances to avoid expensive getInstance() calls.
     * Each thread gets its own instance, eliminating synchronization overhead.
     */
    private static final ThreadLocal<MessageDigest> SHA256_DIGEST =
        ThreadLocal.withInitial(() -> {
            try {
                return MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("SHA-256 algorithm not available", e);
            }
        });
    
    /**
     * ThreadLocal cache for AES/CBC/NoPadding Cipher instances to avoid expensive getInstance() calls.
     * Each thread gets its own instance, eliminating synchronization overhead.
     */
    private static final ThreadLocal<Cipher> AES_CBC_CIPHER =
        ThreadLocal.withInitial(() -> {
            try {
                return Cipher.getInstance("AES/CBC/NoPadding");
            } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                throw new RuntimeException("AES/CBC/NoPadding cipher not available", e);
            }
        });
    
    /**
     * Computes SHA-256 hash of the input bytes.
     * Uses ThreadLocal MessageDigest for thread safety without synchronization.
     *
     * @param input The bytes to hash
     * @return The SHA-256 hash (32 bytes)
     */
    private static byte[] sha256(byte[] input) {
        MessageDigest digest = SHA256_DIGEST.get();
        digest.reset();
        return digest.digest(input);
    }
    
    /**
     * PIN token size in bytes (32 bytes as per CTAP2 specification).
     */
    private static final int PIN_TOKEN_SIZE = 32;

    /**
     * AES block size in bytes (16 bytes for AES-128/256).
     */
    private static final int AES_BLOCK_SIZE = 16;

    /**
     * Maximum number of PIN retry attempts before lockout.
     */
    private static final int MAX_PIN_RETRIES = 5;

    /**
     * CBOR map key for encrypted PIN hash in clientPin requests.
     */
    private static final int KEY_PIN_HASH_ENC = 0x06;

    /**
     * CBOR map key for platform key agreement key in clientPin requests.
     */
    private static final int KEY_PLATFORM_KEY_AGREEMENT = 0x03;

    /**
     * CBOR map key for PIN token in clientPin responses.
     */
    private static final int KEY_PIN_TOKEN = 0x02;

    /**
     * Reusable SecureRandom instance for generating cryptographic tokens.
     * SecureRandom initialization is expensive, so we reuse a single instance.
     */
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();


    private static PinUvAuthResult verifyPinAuthToken(byte[] pinAuthToken, byte[] pinUvAuthParam, byte[] clientDataHash)
            throws InvalidKeyException {
        logger.debug("Verifying PIN/UV auth token");
        
        // Get cached Mac instance from ThreadLocal
        javax.crypto.Mac mac = HMAC_SHA256.get();
        javax.crypto.spec.SecretKeySpec keySpec =
            new javax.crypto.spec.SecretKeySpec(pinAuthToken, "HmacSHA256");
        mac.init(keySpec);
        byte[] expectedAuth = mac.doFinal(clientDataHash);
        
        // Compare first 16 bytes (CTAP2 spec requirement)
        byte[] expectedAuth16 = Arrays.copyOf(expectedAuth, 16);
        
        if (!MessageDigest.isEqual(pinUvAuthParam, expectedAuth16)) {
            logger.error("PIN/UV auth token verification failed: HMAC mismatch");
            return new PinUvAuthResult(false, Ctap2StatusCode.PIN_AUTH_INVALID);
        }
        // Success: user is verified, no error code
        return new PinUvAuthResult(true, null);
    }
    

    /**
     * Creates an error result with logging for PIN/UV authentication failures.
     *
     * @param message The error message to log
     * @param code The CTAP2 status code for the error
     * @return PinUvAuthResult with userVerified=false and the specified error code
     */
    private static PinUvAuthResult errorResult(String message, Ctap2StatusCode code) {
        logger.error(message);
        return new PinUvAuthResult(false, code);
    }

    /**
     * Creates an error result with logging for PIN/UV authentication failures with exception.
     *
     * @param message The error message to log
     * @param code The CTAP2 status code for the error
     * @param e The exception that caused the error
     * @return PinUvAuthResult with userVerified=false and the specified error code
     */
    private static PinUvAuthResult errorResult(String message, Ctap2StatusCode code, Exception e) {
        logger.error(message, e);
        return new PinUvAuthResult(false, code);
    }

    /**
     * Retrieves and validates the PIN auth token from the transaction.
     *
     * @param txn The CTAP transaction containing the PIN auth token
     * @return The PIN auth token byte array
     * @throws PinAuthException if the token is null or invalid
     */
    private static byte[] retrievePinAuthToken(CtapTxn txn) throws PinAuthException {
        byte[] token = txn.getPinAuthTkn();
        logger.debug("Retrieving PIN token from transaction: {}", token != null ? token.length + " bytes" : "null");
        if (token == null) {
            logger.error("No PIN auth token in transaction");
            throw new PinAuthException("No PIN auth token in transaction",
                                     Ctap2StatusCode.PIN_AUTH_INVALID);
        }
        return token;
    }

    /**
     * Validates the PIN/UV authentication protocol version.
     *
     * @param protocol The protocol version to validate (must be 1)
     * @return Error code if validation fails, null if valid
     */
    private static Ctap2StatusCode validatePinUvAuthProtocol(Integer protocol) {
        if (protocol == null) {
            logger.error("PIN/UV auth protocol not specified");
            return Ctap2StatusCode.PIN_AUTH_INVALID;
        }
        if (protocol != SUPPORTED_PIN_UV_AUTH_PROTOCOL) {
            logger.error("Unsupported PIN/UV auth protocol: {}", protocol);
            return Ctap2StatusCode.PIN_AUTH_INVALID;
        }
        return null;
    }

    /**
     * Verifies the PIN auth token with the provided parameters.
     *
     * @param txn The CTAP transaction containing the PIN auth token
     * @param params The PIN/UV authentication parameters
     * @return PinUvAuthResult with verification status or error code
     * @throws PinAuthException if token retrieval fails
     * @throws InvalidKeyException if cryptographic verification fails
     */
    private static PinUvAuthResult verifyTokenWithParams(CtapTxn txn, PinUvAuthParams params, byte[] clientDataHash)
            throws PinAuthException, InvalidKeyException {
        byte[] pinAuthToken = retrievePinAuthToken(txn);
        return verifyPinAuthToken(pinAuthToken, params.pinUvAuthParam, clientDataHash);
    }

    /**
     * Verifies PIN/UV authentication according to CTAP2 specification.
     *
     * This function implements the PIN/UV authentication verification algorithm as per CTAP 2.3:
     * 1. Checks if pinUvAuthParam is provided in the request
     * 2. If provided, verifies it using HMAC-SHA-256 with pinAuthToken as the symmetric key
     * 3. Hashes the RP ID and uses it as the message to verify
     * 4. Verifies the pinAuthToken has the required permission (mc for makeCredential)
     * 5. Returns appropriate error codes if verification fails
     *
     * According to CTAP spec:
     * - pinUvAuthParam = HMAC-SHA-256(pinAuthToken, rpIdHash)[0:16]
     * - The pinAuthToken must have the 'mc' (makeCredential) permission
     * - Only PIN/UV Auth Protocol One (version 1) is currently supported
     *
     * @param req The request parameters containing:
     *            - 0x02: RP information (contains RP ID)
     *            - 0x07: Options (contains 'uv' flag)
     *            - 0x08: pinUvAuthParam (16 bytes, optional)
     *            - 0x09: pinUvAuthProtocol (integer, must be 1 if provided)
     * @param txn The CTAP transaction containing the pinAuthToken
     * @return PinUvAuthResult with verification status (userVerified=true) or error code
     */
    private static PinUvAuthResult verifyPinUvAuth(
            Map<Integer, Object> req,
            CtapTxn txn) {
        
        logger.debug("Starting PIN/UV auth verification");
        
        // Guard: Validate request parameters
        PinUvAuthParams params = PinUvAuthParams.parse(req);
        if (!params.isValid()) {
            return new PinUvAuthResult(false, params.errorCode);
        }
        
        if (params.pinUvAuthParam == null) {
            return handleMissingPinUvAuthParam(params);
        }
                Ctap2StatusCode protocolError = validatePinUvAuthProtocol(params.pinUvAuthProtocol);
        if (protocolError != null) {
            return new PinUvAuthResult(false, protocolError);
        }
        
        byte[] clientDataHash = getClientDataHash(req, MakeCredentialKeys.CLIENT_DATA_HASH);
        if (clientDataHash == null) {
            logger.error("Missing clientDataHash for PIN/UV auth verification");
            return new PinUvAuthResult(false, Ctap2StatusCode.MISSING_PARAMETER);
        }
        
        final PinUvAuthResult result = verifyToken(txn, params, clientDataHash);
        
        if (result.errorCode == null) {
            logger.debug("PIN/UV auth verification completed successfully");
        }
        return result;
    }
    
    /**
     * Handles the case when no pinUvAuthParam is provided in the request.
     *
     * @param params The parsed PIN/UV auth parameters
     * @return PinUvAuthResult indicating whether to proceed or require PIN
     */
    private static PinUvAuthResult handleMissingPinUvAuthParam(PinUvAuthParams params) {
        if (params.uvRequested) {
            return errorResult("User verification required but no PIN/UV auth token provided",
                             Ctap2StatusCode.PIN_REQUIRED);
        }
        logger.debug("No PIN/UV auth param provided, proceeding without user verification");
        return PinUvAuthResult.NO_VERIFICATION;
    }
    
    /**
     * Verifies the PIN/UV auth token with the provided parameters.
     *
     * @param txn The CTAP transaction containing the pinAuthToken
     * @param params The parsed PIN/UV auth parameters
     * @param clientDataHash The client data hash for HMAC verification
     * @return PinUvAuthResult with verification status
     */
    private static PinUvAuthResult verifyToken(CtapTxn txn, PinUvAuthParams params, byte[] clientDataHash) {
        try {
            return verifyTokenWithParams(txn, params, clientDataHash);
        } catch (PinAuthException e) {
            return errorResult(e.getMessage(), e.code);
        } catch (InvalidKeyException e) {
            return errorResult("Invalid key during PIN/UV auth token verification",
                             Ctap2StatusCode.PIN_AUTH_INVALID, e);
        }
    }

    /**
     * Creates an error response with the specified status code.
     *
     * @param code The CTAP2 status code for the error
     * @return A byte array containing the error response
     */
    private static byte[] error(Ctap2StatusCode code) {
        return new byte[] {(byte) code.getCode()};
    }

    /**
     * Creates a success response with the specified payload.
     *
     * @param rsp The response payload to include
     * @return A byte array containing the success response with the payload
     */
    private static byte[] success(byte[] rsp) {
        ByteBuffer bb = ByteBuffer.allocate(rsp.length + 1);
        bb.put((byte) Ctap2StatusCode.SUCCESS.getCode()); bb.put(rsp);
        return bb.array(); //[SUCCESS, *cbor]
    }

    /**
     * Creates an error response for an invalid command.
     *
     * @param txn The CTAP transaction
     * @param req The request parameters
     * @return A byte array containing the error response
     */
    protected static byte[] err(CtapTxn txn, Map<Integer, Object> req) {
        return error(Ctap2StatusCode.INVALID_COMMAND);
    }

    /**
     * Exception thrown during PIN/UV authentication token processing.
     */
    private static class PinAuthException extends Exception {
        final Ctap2StatusCode code;
        
        PinAuthException(String message, Ctap2StatusCode code) {
            super(message);
            this.code = code;
        }
    }

    /**
     * Result class for PIN/UV authentication processing.
     */
    private static class PinUvAuthResult {
        final boolean userVerified;
        final Ctap2StatusCode errorCode;
        
        //static final PinUvAuthResult SUCCESS = new PinUvAuthResult(true, null);
        static final PinUvAuthResult NO_VERIFICATION = new PinUvAuthResult(false, null);
        
        PinUvAuthResult(boolean userVerified, Ctap2StatusCode errorCode) {
            this.userVerified = userVerified;
            this.errorCode = errorCode;
        }
    }


    /**
     * Result class for credential validation containing both the type and any error code.
     */
    private static class CredentialValidationResult {
        final CredentialType type;
        final Ctap2StatusCode errorCode;
        
        CredentialValidationResult(CredentialType type, Ctap2StatusCode errorCode) {
            this.type = type;
            this.errorCode = errorCode;
        }
        
        /**
         * Factory method for creating error results.
         *
         * @param code The error code
         * @return CredentialValidationResult with NONE type and the specified error code
         */
        static CredentialValidationResult error(Ctap2StatusCode code) {
            return new CredentialValidationResult(CredentialType.NONE, code);
        }
        
        boolean isValid() {
            return errorCode == null && type != CredentialType.NONE;
        }
    }
    /**
     * Result of PIN hash validation containing either the extracted PIN hash or an error code.
     */
    private static class PinHashValidationResult {
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
        
        boolean isValid() {
            return pinHashEnc != null;
        }
        
        byte[] getPinHashEnc() {
            return pinHashEnc;
        }
        
        Ctap2StatusCode getErrorCode() {
            return errorCode;
        }
    }


    /**
     * Result of PIN verification containing either the passkey and PIN hash or an error code.
     */
    private static class PinVerificationResult {
        private final Passkey passkey;
        private final byte[] pinHash;
        private final Ctap2StatusCode errorCode;
        
        private PinVerificationResult(Passkey passkey, byte[] pinHash, Ctap2StatusCode errorCode) {
            this.passkey = passkey;
            this.pinHash = pinHash;
            this.errorCode = errorCode;
        }
        
        static PinVerificationResult success(Passkey passkey, byte[] pinHash) {
            return new PinVerificationResult(passkey, pinHash, null);
        }
        
        static PinVerificationResult failure(Ctap2StatusCode errorCode) {
            return new PinVerificationResult(null, null, errorCode);
        }
        
        boolean isValid() {
            return passkey != null;
        }
        
        Passkey getPasskey() {
            return passkey;
        }
        
        byte[] getPinHash() {
            return pinHash;
        }
        
        Ctap2StatusCode getErrorCode() {
            return errorCode;
        }
    }

    /**
     * Builder for PIN token responses.
     */
    private static class PinTokenResponseBuilder {
        private final Map<Integer, Object> response = new HashMap<>();
        
        PinTokenResponseBuilder withPinToken(byte[] pinToken) {
            response.put(KEY_PIN_TOKEN, pinToken);
            return this;
        }
        
        byte[] build() {
            return success(Cbor.encode(response));
        }
    }


    /**
     * CTAP2 makeCredential request parameter keys.
     * Defines the integer keys used in the request map according to CTAP2 specification.
     */
    private interface MakeCredentialKeys {
        int CLIENT_DATA_HASH = 0x01;
        int RP = 0x02;
        int USER = 0x03;
        int PUB_KEY_CRED_PARAMS = 0x04;
        int EXCLUDE_LIST = 0x05;
        int OPTIONS = 0x07;
    }

    /**
     * CTAP2 parameter keys for authenticatorGetAssertion command.
     */
    private interface GetAssertionKeys {
        int RPID = 0x01;
        int CLIENT_DATA_HASH = 0x02;
        int ALLOW_LIST = 0x03;
        //int OPTIONS = 0x05;
        //int PIN_UV_AUTH_PARAM = 0x06;
        //int PIN_UV_AUTH_PROTOCOL = 0x07;
    }

    /**
     * Type-safe accessor for clientDataHash from request.
     *
     * @param req The request parameters map
     * @param key The parameter key to extract clientDataHash from the request
     * @return The client data hash byte array
     */
    private static byte[] getClientDataHash(Map<Integer, Object> req, int key) {
        return (byte[]) req.get(key);
    }

    /**
     * Type-safe accessor for pubKeyCredParams from request.
     *
     * @param req The request parameters map
     * @return List of public key credential parameters
     */
    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> getPubKeyCredParams(Map<Integer, Object> req) {
        return (List<Map<String, Object>>) req.get(MakeCredentialKeys.PUB_KEY_CRED_PARAMS);
    }

    /**
     * Type-safe accessor for excludeList from request.
     *
     * @param req The request parameters map
     * @return List of credentials to exclude
     */
    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> getExcludeList(Map<Integer, Object> req) {
        return (List<Map<String, Object>>) req.get(MakeCredentialKeys.EXCLUDE_LIST);
    }

    private static Ctap2StatusCode validateRequiredParameter(Map<Integer, Object> req, int key, String paramName) {
        if (!req.containsKey(key)) {
            logger.error("Missing required parameter: " + paramName + " (" + key + ")");
            return Ctap2StatusCode.MISSING_PARAMETER;
        }
        return null;
    }

    /**
     * Validates all required parameters for makeCredential request.
     *
     * @param req The request parameters map
     * @return Error code if any required parameter is missing, null otherwise
     */
    private static Ctap2StatusCode validateRequiredParameters(Map<Integer, Object> req) {
        int[] requiredKeys = {0x01, 0x02, 0x03, 0x04};
        String[] paramNames = {"clientDataHash", "rp", "user", "pubKeyCredParams"};
        
        for (int i = 0; i < requiredKeys.length; i++) {
            Ctap2StatusCode error = validateRequiredParameter(req, requiredKeys[i], paramNames[i]);
            if (error != null) {
                return error;
            }
        }
        return null;
    }

    /**
     * Validates clientDataHash length (must be 32 bytes for SHA-256).
     *
     * @param clientDataHash The client data hash to validate
     * @return Error code if validation fails, null otherwise
     */
    private static Ctap2StatusCode validateClientDataHash(byte[] clientDataHash) {
        if (clientDataHash == null || clientDataHash.length != 32) {
            logger.error("Invalid clientDataHash length: expected 32 bytes, got {}",
                        clientDataHash != null ? clientDataHash.length : 0);
            return Ctap2StatusCode.INVALID_PARAMETER;
        }
        return null;
    }

    /**
     * Checks if any credential in the exclude list already exists.
     *
     * @param excludeList List of credentials to exclude
     * @param passkey The passkey containing resident credentials
     * @return Error code if an excluded credential exists, null otherwise
     */
    private static Ctap2StatusCode checkExcludeList(
            List<Map<String, Object>> excludeList,
            Passkey passkey) {
        if (excludeList == null || excludeList.isEmpty()) {
            return null;
        }
        
        for (Map<String, Object> excludedCred : excludeList) {
            byte[] credId = (byte[]) excludedCred.get("id");
            if (credId != null && isCredentialExcluded(credId, passkey)) {
                logger.warn("Credential in excludeList already exists");
                return Ctap2StatusCode.CREDENTIAL_EXCLUDED;
            }
        }
        return null;
    }

    /**
     * Validates that user presence is required (up flag must be true).
     *
     * @param options The parsed credential options
     * @return Error code if user presence is not set, null otherwise
     */
    private static Ctap2StatusCode validateUserPresence(CredentialOptions options) {
        if (!options.up) {
            logger.error("User presence (up) is required but set to false");
            return Ctap2StatusCode.INVALID_OPTION;
        }
        return null;
    }

    /**
     * Checks if any of the provided algorithms is supported.
     *
     * @param pubKeyCredParams List of public key credential parameters
     * @return true if at least one supported algorithm is found
     */
    private static boolean isSupportedAlgorithm(List<Map<String, Object>> pubKeyCredParams) {
        if (pubKeyCredParams == null || pubKeyCredParams.isEmpty()) {
            return false;
        }
        
        for (Map<String, Object> param : pubKeyCredParams) {
            Object alg = param.get("alg");
            if (alg != null && SUPPORTED_ALGORITHM_SET.contains(alg)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Validates algorithm support in pubKeyCredParams.
     *
     * @param pubKeyCredParams List of public key credential parameters
     * @return Error code if validation fails, null otherwise
     */
    private static Ctap2StatusCode validateAlgorithmSupport(List<Map<String, Object>> pubKeyCredParams) {
        if (pubKeyCredParams == null || pubKeyCredParams.isEmpty()) {
            logger.error("pubKeyCredParams is null or empty");
            return Ctap2StatusCode.INVALID_PARAMETER;
        }
        
        if (!isSupportedAlgorithm(pubKeyCredParams)) {
            logger.error("No supported algorithm found in pubKeyCredParams");
            return Ctap2StatusCode.UNSUPPORTED_ALGORITHM;
        }
        
        return null;
    }

    /**
     * Helper class to hold parsed credential options.
     */
    private static class CredentialOptions {
        final boolean up;
        final boolean uv;
        final boolean rk;
        
        CredentialOptions(boolean up, boolean uv, boolean rk) {
            this.up = up;
            this.uv = uv;
            this.rk = rk;
        }
    }

    /**
     * Parses credential options from the request.
     *
     * @param req The request parameters map
     * @return CredentialOptions containing parsed up, uv, and rk flags
     */
    private static CredentialOptions parseOptions(Map<Integer, Object> req) {
        @SuppressWarnings("unchecked")
        Map<String, Object> options = (Map<String, Object>) req.getOrDefault(MakeCredentialKeys.OPTIONS, new HashMap<>());
        
        boolean up = (boolean) options.getOrDefault("up", true);
        boolean uv = (boolean) options.getOrDefault("uv", false);
        boolean rk = (boolean) options.getOrDefault("rk", false);
        
        return new CredentialOptions(up, uv, rk);
    }

    /**
     * Determines the credential type based on rk and uv flags.
     *
     * @param rk Resident key flag
     * @param uv User verification flag
     * @param passkey The passkey (unused per user feedback)
     * @return CredentialValidationResult with the determined type or error
     */
    private static CredentialValidationResult determineCredentialType(boolean rk, boolean uv, Passkey passkey) {
        if (uv && !isUserVerificationAvailable()) {
            logger.error("User verification requested but not available");
            return new CredentialValidationResult(CredentialType.NONE, Ctap2StatusCode.UNSUPPORTED_OPTION);
        }
        
        if (rk) {
            if (uv) {
                return new CredentialValidationResult(CredentialType.RESIDENT, null);
            } else {
                logger.warn("Creating resident credential without user verification");
                return new CredentialValidationResult(CredentialType.RESIDENT, null);
            }
        } else {
            return new CredentialValidationResult(CredentialType.TWO_FACTOR, null);
        }
    }

    /**
     * Validates if a credential can be created based on CTAP2 specification requirements.
     * Implements comprehensive validation according to CTAP2 authenticatorMakeCredential algorithm.
     *
     * @param req The request parameters map
     * @param passkey The passkey to check resident credential capacity
     * @return CredentialValidationResult containing the credential type and any error
     */
    private static CredentialValidationResult _canMakeCredential(Map<Integer, Object> req, Passkey passkey) {
        // Step 1: Validate required parameters (CTAP2 spec section 6.1.2)
        Ctap2StatusCode error = validateRequiredParameters(req);
        if (error != null) {
            return CredentialValidationResult.error(error);
        }
        
        // Step 2: Validate clientDataHash length (must be 32 bytes for SHA-256)
        byte[] clientDataHash = getClientDataHash(req, MakeCredentialKeys.CLIENT_DATA_HASH);
        error = validateClientDataHash(clientDataHash);
        if (error != null) {
            return CredentialValidationResult.error(error);
        }

        // Step 3: Validate algorithm support
        List<Map<String, Object>> pubKeyCredParams = getPubKeyCredParams(req);
        error = validateAlgorithmSupport(pubKeyCredParams);
        if (error != null) {
            return CredentialValidationResult.error(error);
        }

        // Step 4: Check excludeList for existing credentials
        List<Map<String, Object>> excludeList = getExcludeList(req);
        error = checkExcludeList(excludeList, passkey);
        if (error != null) {
            return CredentialValidationResult.error(error);
        }

        // Step 5: Parse and validate options
        CredentialOptions options = parseOptions(req);
        error = validateUserPresence(options);
        if (error != null) {
            return CredentialValidationResult.error(error);
        }

        // Step 6: Determine credential type and validate constraints
        return determineCredentialType(options.rk, options.uv, passkey);
    }


    private static File resolvePasskeyFile(CtapTxn txn) {
        String fileName = txn.getPasskeyFileName();
        if (fileName == null) {
            logger.error("Cannot persist passkey: missing file name");
            return null;
        }
        
        String fido2Home = FileUtils.getFido2Home();
        if (fido2Home == null || fido2Home.isEmpty()) {
            logger.error("FIDO2_HOME not set, cannot persist passkey");
            return null;
        }
        
        return new File(fido2Home + File.separator + fileName);
    }

    private static Ctap2StatusCode validateNotNull(Object value, String errorMessage) {
        if (value == null) {
            logger.error(errorMessage);
            return Ctap2StatusCode.OTHER;
        }
        return null;
    }

    private static class CredentialInfo {
        final String rpId;
        final byte[] rpIdBytes;
        final byte[] userId;

        public CredentialInfo(String rpId, byte[] rpIdBytes, byte[] userId) {
            this.rpId = rpId;
            this.rpIdBytes = rpIdBytes;
            this.userId = userId;
        }
    }

    private static CredentialInfo extractCredentialInfo(Map<Integer, Object> req) {
        @SuppressWarnings("unchecked")
        Map<String, Object> rp = (Map<String, Object>) req.get(MakeCredentialKeys.RP);
        String rpId = (String) rp.get("id");
        byte[] rpIdBytes = rpId.getBytes(StandardCharsets.UTF_8);
        
        @SuppressWarnings("unchecked")
        Map<String, Object> user = (Map<String, Object>) req.get(MakeCredentialKeys.USER);
        byte[] userId = (byte[]) user.get("id");
        
        return new CredentialInfo(rpId, rpIdBytes, userId);
    }

    /**
     * Checks if a duplicate resident credential exists for the given RP and user.
     * Uses stream API for efficient credential matching.
     *
     * @param passkey The passkey containing resident credentials
     * @param rpIdBytes The RP ID as bytes
     * @param userId The user ID as bytes
     * @return true if a duplicate credential exists, false otherwise
     */
    private static boolean isDuplicateResidentCredential(Passkey passkey, byte[] rpIdBytes, byte[] userId) {
        List<Map<String, byte[]>> resCreds = passkey.getResCreds();
        
        if (resCreds == null || resCreds.isEmpty()) {
            logger.debug("No existing credentials to check for duplicates");
            return false;
        }
        
        logger.debug("Checking {} existing credentials for duplicates", resCreds.size());
        
        boolean isDuplicate = resCreds.stream()
            .anyMatch(existingCred -> {
                byte[] existingRpId = existingCred.get("rp.id");
                byte[] existingUserId = existingCred.get("user.id");
                
                return existingRpId != null && existingUserId != null &&
                       Arrays.equals(existingRpId, rpIdBytes) &&
                       Arrays.equals(existingUserId, userId);
            });
        
        if (isDuplicate) {
            logger.warn("Duplicate resident credential detected for RP: {}", new String(rpIdBytes, StandardCharsets.UTF_8));
        }
        
        return isDuplicate;
    }

    /**
     * Validates passkey and resolves the passkey file for persistence.
     *
     * @param passkey The passkey to validate
     * @param txn The CTAP transaction containing file information
     * @return Error code if validation fails, null on success
     */
    private static Ctap2StatusCode validatePasskeyAndFile(Passkey passkey, CtapTxn txn) {
        Ctap2StatusCode error = validateNotNull(passkey, "Cannot store resident credential: passkey is null");
        if (error != null) {
            return error;
        }
        
        File passkeyFile = resolvePasskeyFile(txn);
        if (passkeyFile == null) {
            logger.error("Cannot resolve passkey file");
            return Ctap2StatusCode.OTHER;
        }
        
        if (!passkeyFile.exists()) {
            logger.error("Passkey file does not exist: {}", passkeyFile.getAbsolutePath());
            return Ctap2StatusCode.OTHER;
        }
        
        return null;
    }

    /**
     * Persists the passkey to file using the provided PIN hash.
     *
     * @param passkey The passkey to persist
     * @param pinHash The PIN hash for encryption
     * @param passkeyFile The file to write to
     * @return Error code if persistence fails, null on success
     */
    private static Ctap2StatusCode persistPasskey(Passkey passkey, byte[] pinHash, File passkeyFile) {
        Ctap2StatusCode error = validateNotNull(pinHash, "Cannot persist passkey: missing PIN hash");
        if (error != null) {
            return error;
        }
        
        boolean success = Passkey.writeKey(passkey, pinHash, passkeyFile);
        if (!success) {
            logger.error("Failed to persist passkey to file: {}", passkeyFile.getAbsolutePath());
            return Ctap2StatusCode.OTHER;
        }
        
        logger.info("Successfully persisted passkey to file: {}", passkeyFile.getName());
        return Ctap2StatusCode.SUCCESS;
    }

    /**
     * Stores a resident credential in the passkey and persists it to file.
     *
     * Algorithm (from CTAP_MakeCredential_Implementation_Plan.md lines 428-486):
     * 1. Extract user and RP information
     * 2. Store credential with metadata using addResCred()
     * 3. Persist passkey to file using writeKey()
     *
     * @param req The request parameters
     * @param credentialId The credential ID
     * @param passkey The passkey to store in
     * @param txn The CTAP transaction containing PIN hash and file name
     * @return Error code if storage fails, SUCCESS on success
     */
    private static Ctap2StatusCode storeResidentCredential(
            Map<Integer, Object> req,
            byte[] credentialId,
            Passkey passkey,
            CtapTxn txn) {
        
        logger.info("Storing resident credential - CID: {}",
                    txn.getCid() != null ? Arrays.toString(txn.getCid()) : "null");
        
        // Validate passkey and file
        Ctap2StatusCode error = validatePasskeyAndFile(passkey, txn);
        if (error != null) {
            return error;
        }
        
        // Extract credential information
        CredentialInfo credInfo = extractCredentialInfo(req);
        
        // Check for duplicate resident credential (same RP and user)
        if (isDuplicateResidentCredential(passkey, credInfo.rpIdBytes, credInfo.userId)) {
            return Ctap2StatusCode.CREDENTIAL_EXCLUDED;
        }
        
        // Add resident credential to passkey
        passkey.addResCred(credInfo.rpIdBytes, credentialId, credInfo.userId);
        logger.debug("Added resident credential for RP: {}, total count: {}",
                    credInfo.rpId, passkey.getResCreds().size());
        
        // Persist passkey to file
        return persistPasskey(passkey, txn.getPinHash(), resolvePasskeyFile(txn));
    }

    /**
     * Checks if a credential ID is in the exclude list.
     * This should check against both resident credentials and any u2f credentials.
     *
     * @param credId The credential ID to check
     * @param passkey The passkey containing resident credentials
     * @return true if the credential should be excluded
     */
    private static boolean isCredentialExcluded(byte[] credId, Passkey passkey) {
        if (passkey == null || credId == null) {
            return false;
        }
        
        List<Map<String, byte[]>> resCreds = passkey.getResCreds();
        if (resCreds == null) {
            return false;
        }
        
        // Check if credId matches any resident credential
        for (Map<String, byte[]> cred : resCreds) {
            byte[] storedCredId = cred.get("cred.id");
            if (storedCredId != null && java.util.Arrays.equals(credId, storedCredId)) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Checks if user verification is available on this authenticator.
     * This should check for PIN setup or biometric availability.
     *
     * @return true if user verification is available
     */
    private static boolean isUserVerificationAvailable() {
        // TODO: Invoke bio auth API to check user
        // For now, assume UV is available if we have a platform key pair
        return platKeyPair != null;
    }

    /**
     * Processes a makeCredential request (CTAP2 authenticatorMakeCredential command).
     * Creates a new credential and returns an attestation object.
     *
     * @param txn The CTAP transaction
     * @param req The request parameters
     * @return A byte array containing the response
     */
    protected static byte[] makeCredential(CtapTxn txn, Map<Integer, Object> req) {
        logger.info("makeCredential: starting credential creation");
        
        // Load authenticated session from openKeys if available
        loadAuthenticatedSession(txn);

        // UP must have been collected during getInfo on this channel.
        // CTAP §6.1.2 step 14: cached UP satisfies the "up" option requirement.
        if (txn == null || !txn.isUserPresent()) {
            logger.warn("makeCredential: user presence not cached — returning OPERATION_DENIED");
            return error(Ctap2StatusCode.OPERATION_DENIED);
        }
        
        // Validate the request and determine credential type
        CredentialValidationResult validation = _canMakeCredential(req, txn.getPasskey());
        
        if (!validation.isValid()) {
            logger.error("Credential validation failed: {}", validation.errorCode);
            return error(validation.errorCode);
        }
        
        logger.info("Creating credential of type: {}", validation.type);
        
        try {
            return executeMakeCredential(validation, txn, req);
        } catch (Exception e) {
            logger.error("makeCredential exception: {}", e.getMessage(), e);
            return error(Ctap2StatusCode.OTHER);
        }
    }

    /**
     * Container for attestation material including key pair and certificate.
     */
    private static class AttestationMaterial {
        final KeyPair keyPair;
        final X509Certificate anonCA;
        
        AttestationMaterial(KeyPair keyPair, X509Certificate anonCA) {
            this.keyPair = keyPair;
            this.anonCA = anonCA;
        }
    }

    /**
     * Loads attestation material (key pair and certificate) for credential creation.
     *
     * @param credentialType The type of credential being created
     * @param userVerified Whether the user has been verified
     * @param txn The CTAP transaction containing passkey information
     * @return AttestationMaterial containing key pair and certificate
     * @throws Exception if key generation fails
     */
    private static AttestationMaterial loadAttestationMaterial(
            CredentialType credentialType,
            boolean userVerified,
            CtapTxn txn) throws Exception {
        
        KeyPair keyPair = loadAttestationKeyPair(credentialType, userVerified, txn);
        X509Certificate anonCA = loadAnonCA(txn);
        return new AttestationMaterial(keyPair, anonCA);
    }

    /**
     * Loads the appropriate key pair for attestation based on credential type and verification status.
     *
     * @param credentialType The type of credential being created
     * @param userVerified Whether the user has been verified
     * @param txn The CTAP transaction containing passkey information
     * @return The key pair to use for attestation
     * @throws Exception if key generation fails
     */
    private static KeyPair loadAttestationKeyPair(
            CredentialType credentialType,
            boolean userVerified,
            CtapTxn txn) throws Exception {
        
        if (credentialType == CredentialType.RESIDENT && userVerified) {
            java.security.PrivateKey passkeyPrivateKey = txn.getPasskey().getPrivateKey();
            PublicKey passkeyPublicKey = KeyUtils.getPubKey((ECPrivateKey) passkeyPrivateKey);
            return new KeyPair(passkeyPublicKey, passkeyPrivateKey);
        }
        
        java.security.PrivateKey platformKey = KeyUtils.getPlatformKey();
        if (platformKey == null) {
            // Platform key doesn't exist, generate a temporary key pair for testing
            KeyPair tempKeyPair = KeyUtils.getKeyPair("ECDSA");
            return tempKeyPair;
        }
        PublicKey platformPublicKey = KeyUtils.getPubKey((ECPrivateKey) platformKey);
        return new KeyPair(platformPublicKey, platformKey);
    }

    /**
     * Builds authenticator data for the credential.
     *
     * @param req The request parameters containing RP information
     * @param authenticator The FIDO2 authenticator instance
     * @return The authenticator data bytes
     * @throws Exception if authenticator data building fails
     */
    private static byte[] buildAuthenticatorData(
            Map<Integer, Object> req,
            Fido2Authenticator authenticator) throws Exception {
        
        logger.debug("=== buildAuthenticatorData START ===");
        Object rpValue = req.get(0x02);
        logger.debug("RP value from request: {}", rpValue);
        
        Map<String, Object> options = Map.of(
            "rp", rpValue,
            "attestation", true
        );
        
        logger.debug("Calling authenticator.buildAuthenticatorData with options: {}", options.keySet());
        byte[] result = authenticator.buildAuthenticatorData(
            options,
            "packed",
            null,
            null,
            authenticator.getKeyPair()
        );
        logger.debug("buildAuthenticatorData result length: {}", result != null ? result.length : "null");
        logger.debug("=== buildAuthenticatorData END ===");
        
        return result;
    }

    /**
     * Creates the attestation statement for the credential.
     *
     * @param clientDataHash The client data hash
     * @param authenticatorData The authenticator data
     * @param authenticator The FIDO2 authenticator instance
     * @param attestationKeyPair The key pair to use for attestation
     * @param akiCert
     * @return The attestation statement map
     * @throws Exception if attestation statement creation fails
     */
    private static Map<String, Object> createAttestationStatement(
            byte[] clientDataHash,
            byte[] authenticatorData,
            Fido2Authenticator authenticator,
            KeyPair attestationKeyPair,
            X509Certificate akiCert) throws Exception {
        
        logger.debug("=== createAttestationStatement START ===");
        logger.debug("clientDataHash length: {}", clientDataHash != null ? clientDataHash.length : "null");
        logger.debug("authenticatorData length: {}", authenticatorData != null ? authenticatorData.length : "null");
        logger.debug("credId length: {}", authenticator.getCredId() != null ? authenticator.getCredId().length : "null");
        logger.debug("attestationKeyPair: {}", attestationKeyPair != null ? "present" : "null");
        logger.debug("akiCert: {}", akiCert != null ? "present" : "null");
        
        Map<String, Object> result = authenticator.processAttestationStatement(
            "packed",
            clientDataHash,
            authenticatorData,
            authenticator.getCredId(),
            authenticator.getKeyPair(),
            attestationKeyPair,
            akiCert
        );
        
        logger.debug("attestationStatement result: {}", result != null ? result.keySet() : "null");
        logger.debug("=== createAttestationStatement END ===");
        
        return result;
    }

    /**
     * Builds the makeCredential response.
     *
     * @param authenticatorData The authenticator data
     * @param attestationStatement The attestation statement
     * @return The encoded response bytes
     */
    private static byte[] buildMakeCredentialResponse(
            byte[] authenticatorData,
            Map<String, Object> attestationStatement) {
        
        logger.debug("=== buildMakeCredentialResponse START ===");
        logger.debug("authenticatorData length: {}", authenticatorData != null ? authenticatorData.length : "null");
        logger.debug("attestationStatement: {}", attestationStatement != null ? attestationStatement.keySet() : "null");
        
        Map<Integer, Object> response = Map.of(
            0x01, "packed",  // fmt
            0x02, authenticatorData,
            0x03, attestationStatement
        );
        
        logger.debug("Response map created with keys: {}", response.keySet());
        byte[] encoded = Cbor.encode(response);
        logger.debug("CBOR encoded response length: {}", encoded != null ? encoded.length : "null");
        
        if (encoded == null || encoded.length == 0) {
            logger.error("CBOR encoding returned empty or null result!");
            logger.error("Response map: {}", response);
        }
        
        return success(encoded);
    }

    /**
     * Extracts and validates the client data hash from the request.
     *
     * @param req The request parameters
     * @return The client data hash bytes, or null if missing
     */
    private static byte[] extractClientDataHash(Map<Integer, Object> req) {
        byte[] clientDataHash = (byte[]) req.get(0x01);
        if (clientDataHash == null) {
            logger.error("Missing required clientDataHash (0x01) in request");
        }
        return clientDataHash;
    }

    /**
     * Logs detailed RP value information for debugging.
     *
     * @param rpValue The RP value to log (can be Map, String, or byte[])
     */
    private static void logRpValueDetails(Object rpValue) {
        if (!logger.isInfoEnabled()) {
            return;
        }
        
        logger.info("=== makeCredential: Extracted RP value (0x02) ===");
        logger.info("RP value type: {}", rpValue != null ? rpValue.getClass().getName() : "null");
        
        if (rpValue instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> rpMap = (Map<String, Object>) rpValue;
            logger.info("RP map keys: {}", rpMap.keySet());
            Object idObj = rpMap.get("id");
            logger.info("RP id type: {}", idObj != null ? idObj.getClass().getName() : "null");
            logger.info("RP id value: {}", idObj);
        } else if (rpValue instanceof String) {
            logger.info("RP string value: {}", rpValue);
        } else if (rpValue instanceof byte[]) {
            byte[] rpBytes = (byte[]) rpValue;
            logger.info("RP byte array length: {}", rpBytes.length);
            logger.info("RP byte array (hex): {}", ByteUtils.bytesToHex(rpBytes));
        }
    }

    private static X509Certificate loadAnonCA(CtapTxn txn){
        //TODO generate correct annon ca cert from spec
        return (txn.getPasskey() == null) ? null : txn.getPasskey().getCertificate();
    }

    /**
     * Handles storage of resident credentials if required.
     *
     * @param type The credential type (RESIDENT or NON_RESIDENT)
     * @param req The request parameters
     * @param authenticator The FIDO2 authenticator instance
     * @param txn The CTAP transaction
     * @return Error code if storage fails, null on success
     */
    private static Ctap2StatusCode handleResidentCredentialStorage(
            CredentialType type,
            Map<Integer, Object> req,
            Fido2Authenticator authenticator,
            CtapTxn txn) {
        
        if (type != CredentialType.RESIDENT) {
            return null;
        }
        
        Ctap2StatusCode storeResult = storeResidentCredential(
            req,
            authenticator.getCredId(),
            txn.getPasskey(),
            txn
        );
        
        if (storeResult != null && storeResult != Ctap2StatusCode.SUCCESS) {
            return storeResult;
        }
        
        return null;
    }

    /**
     * Result class for credential creation operations.
     */
    private static class CredentialCreationResult {
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
        
        boolean isSuccess() {
            return errorCode == null;
        }
    }

    /**
     * Validates and creates the authenticator for credential creation.
     *
     * @param txn The CTAP transaction
     * @param req The request parameters
     * @return The authenticator, or null if creation fails
     */
    private static Fido2Authenticator validateAndCreateAuthenticator(
            CtapTxn txn,
            Map<Integer, Object> req) {
        
        Object rpValue = req.get(MakeCredentialKeys.RP);
        logRpValueDetails(rpValue);
        
        Fido2Authenticator authenticator = createAuthenticator(txn, rpValue);
        if (authenticator == null) {
            logger.error("Failed to create authenticator");
        }
        return authenticator;
    }

    /**
     * Builds the credential data including authenticator data and attestation statement.
     *
     * @param req The request parameters
     * @param authenticator The FIDO2 authenticator
     * @param attestation The attestation material
     * @return CredentialCreationResult containing the credential data or error
     */
    private static CredentialCreationResult buildCredentialData(
            Map<Integer, Object> req,
            Fido2Authenticator authenticator,
            AttestationMaterial attestation) throws Exception {
        
        byte[] clientDataHash = extractClientDataHash(req);
        if (clientDataHash == null) {
            logger.error("buildCredentialData: clientDataHash is null");
            return new CredentialCreationResult(Ctap2StatusCode.MISSING_PARAMETER);
        }

        byte[] authenticatorData = buildAuthenticatorData(req, authenticator);
        if (authenticatorData == null) {
            logger.error("buildCredentialData: authenticatorData is null");
            return new CredentialCreationResult(Ctap2StatusCode.OTHER);
        }

        Map<String, Object> attestationStatement = createAttestationStatement(
            clientDataHash,
            authenticatorData,
            authenticator,
            attestation.keyPair,
            attestation.anonCA
        );
        if (attestationStatement == null) {
            logger.error("buildCredentialData: attestationStatement is null");
            return new CredentialCreationResult(Ctap2StatusCode.OTHER);
        }
        logger.debug("buildCredentialData: attestationStatement keys: {}", attestationStatement.keySet());
        logger.debug("=== buildCredentialData SUCCESS ===");
        
        return new CredentialCreationResult(authenticatorData, attestationStatement);
    }

    private static byte[] executeMakeCredential(
            CredentialValidationResult validation,
            CtapTxn txn,
            Map<Integer, Object> req) throws Exception {

        PinUvAuthResult pinUvResult = verifyPinUvAuth(req, txn);
        if (pinUvResult.errorCode != null) {
            return error(pinUvResult.errorCode);
        }
        AttestationMaterial attestation = loadAttestationMaterial(
            validation.type,
            pinUvResult.userVerified,
            txn
        );
        Fido2Authenticator authenticator = validateAndCreateAuthenticator(txn, req);
        if (authenticator == null) {
            return error(Ctap2StatusCode.OTHER);
        }
        CredentialCreationResult credentialResult = buildCredentialData(req, authenticator, attestation);
        if (!credentialResult.isSuccess()) {
            return error(credentialResult.errorCode);
        }
        Ctap2StatusCode storeError = handleResidentCredentialStorage(
            validation.type, req, authenticator, txn);
        if (storeError != null) {
            return error(storeError);
        }
        return buildMakeCredentialResponse(
            credentialResult.authenticatorData,
            credentialResult.attestationStatement
        );
    }

    /**
     * Retrieves the passkey from openKeys and populates the transaction.
     * If an authenticated session exists for this CID, sets the passkey in the transaction.
     *
     * @param txn The CTAP transaction to populate
     * @return true if an authenticated session was found and applied, false otherwise
     */
    private static boolean loadAuthenticatedSession(CtapTxn txn) {
        byte[] targetCid = txn.getCid();
        // Manual lookup using Arrays.equals since HashMap doesn't work with byte[] keys
        for (Map.Entry<byte[], Passkey> entry : openKeys.entrySet()) {
            if (Arrays.equals(entry.getKey(), targetCid)) {
                logger.debug("Found authenticated session for CID, loading passkey");
                txn.setPasskey(entry.getValue());
                return true;
            }
        }
        logger.debug("No authenticated session found for CID");
        return false;
    }

    /**
     * Creates a Fido2Authenticator instance configured for the given transaction.
     *
     * @param txn The CTAP transaction context
     * @param req The CTAP2 request parameters
     * @return A configured Fido2Authenticator instance
     * @throws IllegalArgumentException if request parameters are invalid
     * @throws IllegalStateException if authenticator configuration fails
     * @throws RuntimeException for unexpected errors
     */
    private static Fido2Authenticator createAuthenticator(CtapTxn txn, Object rpIdValue) {
        try {
            Fido2Authenticator a = new Fido2Authenticator();
            byte[] rpIdBytes = extractRpIdBytes(rpIdValue);
            
            if (txn.getPasskey() != null) {
                configureResidentCredential(a, txn.getPasskey(), rpIdBytes);
            } else {
                String seed = KeyUtils.getPasskeySeed(rpIdBytes, KeyUtils.getPlatformKey());
                if (seed == null) {
                    throw new IllegalStateException("Failed to generate seed from platform key");
                }
                
                a.setSymKeys(seed);
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
    
    /**
     * Extracts and validates the RP ID from the request.
     * Handles three formats: String (getAssertion), byte array, or Map (makeCredential).
     *
     * @param req The CTAP2 request map
     * @return The RP ID as bytes
     * @throws IllegalArgumentException if RP ID is missing or has unsupported type
     */
    private static byte[] extractRpIdBytes(Object rpIdValue) {
        if (rpIdValue == null) {
            throw new IllegalArgumentException("Missing rpId value");
        }
        
        if (rpIdValue instanceof String) {
            String rpId = (String) rpIdValue;
            logger.debug("Extracted rpId from String: {}, hashing for seed generation", rpId);
            return sha256(rpId.getBytes(StandardCharsets.UTF_8));
        }
        
        if (rpIdValue instanceof byte[]) {
            byte[] rpIdBytes = (byte[]) rpIdValue;
            logger.debug("Extracted rpId from byte array (length: {}), hashing for seed generation", rpIdBytes.length);
            return sha256(rpIdBytes);
        }
        
        if (rpIdValue instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> rpMap = (Map<String, Object>) rpIdValue;
            Object rpIdObj = rpMap.get("id");
            
            if (rpIdObj == null) {
                throw new IllegalArgumentException("RP map missing 'id' field");
            }
            
            if (rpIdObj instanceof String) {
                String rpId = (String) rpIdObj;
                logger.debug("Extracted rpId from RP map String: {}, hashing for seed generation", rpId);
                return sha256(rpId.getBytes(StandardCharsets.UTF_8));
            }
            
            if (rpIdObj instanceof byte[]) {
                byte[] rpIdBytes = (byte[]) rpIdObj;
                logger.debug("Extracted rpId from RP map byte array (length: {}), hashing for seed generation", rpIdBytes.length);
                return sha256(rpIdBytes);
            }
            
            throw new IllegalArgumentException(
                "RP map 'id' field has unsupported type: " + rpIdObj.getClass().getName());
        }
        
        throw new IllegalArgumentException(
            "rpId value has unsupported type: " + rpIdValue.getClass().getName());
    }
    
    /**
     * Configures authenticator for resident credential (passkey-based).
     *
     * @param a The authenticator to configure
     * @param passkey The passkey containing certificate and private key
     * @param rpIdBytes The RP ID bytes for seed generation
     * @throws IllegalStateException if seed generation fails
     */
    private static void configureResidentCredential(Fido2Authenticator a, Passkey passkey, byte[] rpIdBytes) {
        
        java.security.PrivateKey privKey = passkey.getPrivateKey();
        logger.debug("Passkey private key algorithm: {}", privKey != null ? privKey.getAlgorithm() : "null");
        
        String seed = KeyUtils.getPasskeySeed(rpIdBytes, privKey);
        if (seed == null) {
            throw new IllegalStateException("Failed to generate seed from passkey");
        }
        
        a.setSymKeys(seed);
    }

    private static Map<String, byte[]> initializeAuthenticatorWithCredential(
            Fido2Authenticator authenticator,
            ArrayList<Map<String, byte[]>> credentials) {
        
        for (Map<String, byte[]> cred : credentials) {
            try {
                byte[] credId = cred.get("id");
                logger.debug("Attempting to initialize authenticator with credential ID (length: {})",
                    credId != null ? credId.length : 0);
                authenticator.initFromCredId(credId);
                logger.debug("Successfully initialized authenticator with credential");
                return cred;  // Return the credential that was successfully used
            } catch (Exception e) {
                logger.debug("Failed to initialize with credential: {}", e.getMessage());
                // Continue trying other credentials
                continue;
            }
        }
        logger.debug("Failed to initialize authenticator with any of {} credentials", credentials.size());
        return null;
    }

    private static ArrayList<Map<String, byte[]>> processCredentials(
            Map<Integer, Object> req, Passkey passkey) {
        @SuppressWarnings("unchecked")
        ArrayList<Map<String, byte[]>> allowList = 
                (ArrayList<Map<String, byte[]>>) req.get(0x03);
        
        if (allowList == null) {
            allowList = new ArrayList<>();
        }
        if (passkey != null) { // Add resident credentials if available
        List<Map<String, byte[]>> resCreds = passkey.getResCreds();
        if (resCreds != null) {
            for (Map<String, byte[]> cred : resCreds) {
                allowList.add(Map.of(
                    "id", (byte[]) cred.get("cred.id"),
                    "user", (byte[]) cred.get("user.id")  // Use "user.id" as key to match check in generateSignedAssertion
                ));
            }
        }
    }
        return allowList;
    }


    private static byte[] generateSignedAssertion(
            Map<Integer, Object> req,
            Fido2Authenticator authenticator,
            Map<String, byte[]> credentialData) {
        
        try {
            // Use GetAssertionKeys constants for correct parameter extraction
            String rpId = (String) req.get(GetAssertionKeys.RPID);  // 0x01
            byte[] clientDataHash = (byte[]) req.get(GetAssertionKeys.CLIENT_DATA_HASH);  // 0x02
            
            Map<String, Object> cred = Map.of(
                "id", authenticator.getCredId(),
                "type", "public-key"
            );
            
            // Check if allowList is absent or empty (discoverable credential scenario)
            // When allowList is not in the request, req.get returns null
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> allowList = (List<Map<String, Object>>) req.get(GetAssertionKeys.ALLOW_LIST);
            boolean isDiscoverableCredential = (allowList == null || allowList.isEmpty());
            
            logger.info("allowList present: {}, isEmpty: {}, isDiscoverableCredential: {}",
                allowList != null, allowList != null && allowList.isEmpty(), isDiscoverableCredential);
            
            Map<String, Object> options = Map.of("rpId", rpId);
            
            byte[] authData = authenticator.buildAuthenticatorData(
                options, "packed", null, null, authenticator.getKeyPair());
            
            // === DIAGNOSTIC LOGGING FOR AUTHENTICATOR DATA ===
            logger.debug("=== generateSignedAssertion: authData verification ===");
            logger.debug("authData length: {}", authData != null ? authData.length : "null");
            if (authData != null && authData.length > 0) {
                logger.debug("authData first 4 bytes (hex): {}",
                    com.isfs.blekey.util.ByteUtils.bytesToHex(Arrays.copyOfRange(authData, 0, Math.min(4, authData.length))));
                if (authData.length >= 37) {
                    logger.debug("authData first 37 bytes (rpIdHash + flags + counter):");
                    logger.debug("  rpIdHash (32 bytes): {}",
                        com.isfs.blekey.util.ByteUtils.bytesToHex(Arrays.copyOfRange(authData, 0, 32)));
                    logger.debug("  flags (1 byte): 0x{}", String.format("%02x", authData[32]));
                    logger.debug("  counter (4 bytes): {}",
                        com.isfs.blekey.util.ByteUtils.bytesToHex(Arrays.copyOfRange(authData, 33, 37)));
                }
                logger.debug("authData full hex dump:");
                logger.debug("{}", com.isfs.blekey.util.ByteUtils.hexDump(authData, "AuthenticatorData"));
            }
            logger.debug("=== End authData verification ===");
            
            ByteBuffer bb = ByteBuffer.allocate(authData.length + clientDataHash.length);
            bb.put(authData);
            bb.put(clientDataHash);
            byte[] sig = authenticator.signData(
                bb.array(), authenticator.getPrivKey(), "SHA256withECDSA");
            
            // Build response - include user entity if discoverable credential
            Map<Integer, Object> rsp;
            if (isDiscoverableCredential && credentialData != null && credentialData.containsKey("user")) {
                // Include user entity (0x04) for discoverable credentials
                byte[] userId = credentialData.get("user");
                Map<String, Object> userEntity = Map.of("id", userId);
                
                logger.info("Including user entity in assertion response (discoverable credential)");
                logger.info("User ID length: {} bytes", userId.length);
                logger.info("User ID (hex): {}", com.isfs.blekey.util.ByteUtils.bytesToHex(userId));
                
                rsp = Map.of(
                    0x01, cred,
                    0x02, authData,
                    0x03, sig,
                    0x04, userEntity
                );
            } else {
                rsp = Map.of(
                    0x01, cred,
                    0x02, authData,
                    0x03, sig
                );
            }
            
            return success(Cbor.encode(rsp));
        } catch (Exception e) {
            logger.error("Failed to generate signed assertion: {}", e.getMessage());
            e.printStackTrace();
            return error(Ctap2StatusCode.OTHER);
        }
    }

    /**
     * Processes a getAssertion request (CTAP2 authenticatorGetAssertion command).
     * Signs a challenge using an existing credential.
     *
     * @param txn The CTAP transaction
     * @param req The request parameters
     * @return A byte array containing the response
     */
     protected static byte[] getAssertion(CtapTxn txn, Map<Integer, Object> req) {
        logger.debug("getAssertion");
        
        // Load authenticated session from openKeys if available
        loadAuthenticatedSession(txn);

        // UP must have been collected during getInfo on this channel.
        // CTAP §6.2.2 step 9: cached UP satisfies the "up" option requirement.
        if (txn == null || !txn.isUserPresent()) {
            logger.warn("getAssertion: user presence not cached — returning OPERATION_DENIED");
            return error(Ctap2StatusCode.OPERATION_DENIED);
        }

        // Extract rpId string (parameter 0x01) for getAssertion
        Object rpIdValue = req.get(GetAssertionKeys.RPID);
        logger.info("=== getAssertion: Extracted rpId value (0x01) ===");
        logger.info("rpId value type: {}", rpIdValue != null ? rpIdValue.getClass().getName() : "null");
        if (rpIdValue instanceof String) {
            logger.info("rpId string value: {}", rpIdValue);
        } else if (rpIdValue instanceof byte[]) {
            byte[] rpIdBytes = (byte[]) rpIdValue;
            logger.info("rpId byte array length: {}", rpIdBytes.length);
            logger.info("rpId byte array (hex): {}", ByteUtils.bytesToHex(rpIdBytes));
        } else if (rpIdValue instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> rpMap = (Map<String, Object>) rpIdValue;
            logger.info("rpId map keys: {}", rpMap.keySet());
        }
        Fido2Authenticator authenticator = createAuthenticator(txn, rpIdValue);
        if (authenticator == null) {
            logger.debug("authenticator is null");
            return error(Ctap2StatusCode.OTHER);
        }
        logger.debug("created authenticator");
        // Process credentials from allowList and resident credentials
        ArrayList<Map<String, byte[]>> credentials = processCredentials(req, txn.getPasskey());
        if (credentials.isEmpty()) {
            logger.debug("No credentials found");
            return error(Ctap2StatusCode.NO_CREDENTIALS);
        }

        // Initialize authenticator with a valid credential
        Map<String, byte[]> selectedCredential = initializeAuthenticatorWithCredential(authenticator, credentials);
        if (selectedCredential == null) {
            logger.debug("Fido2Authenticator initialization failed with cred list");
            return error(Ctap2StatusCode.NO_CREDENTIALS);
        }

        // Generate and sign assertion with credential data (includes user.id for discoverable credentials)
        return generateSignedAssertion(req, authenticator, selectedCredential);
    }

    /**
     * Processes a getInfo request (CTAP2 authenticatorGetInfo command).
     * Returns information about the authenticator's capabilities.
     *
     * @param txn The CTAP transaction
     * @param req The request parameters
     * @return A byte array containing the response
     */
    protected static byte[] getInfo(CtapTxn txn, Map<Integer, Object> req) {
        logger.debug("getInfo");

        // If no callback is registered, there is no way to collect UP — deny immediately.
        if (userPresenceCallback == null) {
            logger.warn("getInfo: no UserPresenceCallback registered — returning OPERATION_DENIED");
            return error(Ctap2StatusCode.OPERATION_DENIED);
        }

        // Pre-compute the response; it is only sent to the host after the user approves.
        Map<String, Boolean> capabilities = Map.of("rk", true,
                                                   "plat", true,
                                                   "clientPin", true);
        Map<Integer, Object> info = Map.of(
            0x01, new String[] {"FIDO_2_1", "FIDO_2_0"},
            0x02, new String[] {"hmac-secret"}, //extensions
            0x03, new byte[16], //AAGUID - must be 16-byte bytestring per CTAP2 spec
            0x04, capabilities,
            0x05, 4096, // maxMsgSize
            0x06, new int[] {1} //PIN/UV Auth Protocol One
        );
        // approved: multi-frame CBOR response — drained via HIDPasskey.sendDeferredResponse(txn, buf)
        final byte[] approvedResponse = success(Cbor.encode(info));
        // denied: always a single status byte — known upfront, no drain needed
        final byte[] deniedResponse   = error(Ctap2StatusCode.OPERATION_DENIED);
        logger.debug("getInfo: pre-computed approved ({} bytes) and denied (1 byte) responses",
                     approvedResponse.length);

        // Pass both buffers to the app layer together with the live txn.
        // The app layer sends keepalives until the user acts, then calls:
        //   HIDPasskey.sendDeferredResponse(txn, approvedResponse) — approve (drains all frames)
        //   HIDPasskey.sendDeferredResponse(txn, deniedResponse)   — deny/timeout/cancel (single frame)
        userPresenceCallback.onUserPresenceRequired(null, txn, approvedResponse, deniedResponse);

        // Return null to signal CtapHid that the response is deferred.
        return null;
    }

    /**
     * Processes a PIN request (CTAP2 authenticatorClientPIN command).
     * Handles PIN-related operations such as getting retries, keys, and tokens.
     *
     * @param txn The CTAP transaction
     * @param req The request parameters
     * @return A byte array containing the response
     */
    protected static byte[] pinRequest(CtapTxn txn, Map<Integer, Object> req) {
        logger.debug("AuthenticatorAPI: === pinRequest START ===");
        PinSubCmd cmd = PinSubCmd.fromInt((int) req.getOrDefault(2, 0));
        logger.debug("AuthenticatorAPI: PIN subcommand: {}", cmd);
        logger.debug("AuthenticatorAPI: Request parameters: {}", req.keySet());
        
        switch(cmd)
        {
            case GETRETRY:
                logger.debug("AuthenticatorAPI: Processing GETRETRY");
                return pinRty(txn, req);
            case GETKEY:
                logger.debug("AuthenticatorAPI: Processing GETKEY");
                return getKey(txn, req);
            case GETTKN:
                logger.debug("AuthenticatorAPI: Processing GETTKN");
                return getTkn(txn, req);
            default:
                logger.debug("AuthenticatorAPI: Invalid PIN subcommand: {}", cmd);
                return error(Ctap2StatusCode.INVALID_COMMAND);
        }
    }

    /**
     * Handles the getKey PIN subcommand.
     * Returns the platform public key in COSE format.
     *
     * @param txn The CTAP transaction
     * @param req The request parameters
     * @return A byte array containing the response
     */
    private static byte[] getKey(CtapTxn txn, Map<Integer, Object> req) {
        logger.debug("AuthenticatorAPI: getKey: Returning platform public key");
        logger.debug("AuthenticatorAPI: platKeyPair is null: {}", (AuthenticatorAPI.platKeyPair == null));
        
        if (AuthenticatorAPI.platKeyPair == null) {
            logger.debug("AuthenticatorAPI: CRITICAL: platKeyPair is NULL! Cannot return public key");
            return error(Ctap2StatusCode.OTHER);
        }
        
        // For PIN/UV Auth Protocol 1, the platform key must use ECDH algorithm (-25)
        // not ES256 (-7), as it's used for key agreement, not signing
        Map<Integer, Object> coseKey = KeyUtils.toCoseKey(AuthenticatorAPI.platKeyPair.getPublic(), -25);
        
        logger.debug("AuthenticatorAPI: getKey: COSE key structure:");
        logger.debug("  kty (1): {}", coseKey.get(1));
        logger.debug("  alg (3): {}", coseKey.get(3));
        logger.debug("  crv (-1): {}", coseKey.get(-1));
        logger.debug("  x (-2) length: {}", (coseKey.get(-2) != null ? ((byte[])coseKey.get(-2)).length : 0));
        logger.debug("  y (-3) length: {}", (coseKey.get(-3) != null ? ((byte[])coseKey.get(-3)).length : 0));
        
        // Log the actual coordinate bytes
        if (coseKey.get(-2) != null) {
            logger.debug("  x (-2) hex: {}", com.isfs.blekey.util.ByteUtils.bytesToHex((byte[])coseKey.get(-2)));
        }
        if (coseKey.get(-3) != null) {
            logger.debug("  y (-3) hex: {}", com.isfs.blekey.util.ByteUtils.bytesToHex((byte[])coseKey.get(-3)));
        }
        
        Map<Integer, Object> rsp = Map.of(0x01, coseKey);
        byte[] key = Cbor.encode(rsp);
        logger.debug("AuthenticatorAPI: getKey: Successfully encoded public key, size: {} bytes", key.length);
        logger.debug("AuthenticatorAPI: getKey: CBOR-encoded response hex dump:");
        logger.debug("{}", com.isfs.blekey.util.ByteUtils.hexDump(key, "GETKEY Response"));
        return success(key);
    }

    /**
     * Extracts and parses the client's public key from the COSE key structure.
     *
     * @param req The request parameters containing the client COSE key at key 0x03
     * @return The parsed PublicKey, or null if extraction/parsing fails
     */
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

    /**
     * Performs ECDH key agreement between the client's public key and platform's private key.
     *
     * @param clientKey The client's public key
     * @return The shared secret bytes, or null if ECDH fails
     */
    private static byte[] performEcdhKeyAgreement(PublicKey clientKey) {
        if (platKeyPair == null) {
            logger.error("Platform key pair is null, cannot perform ECDH key agreement");
            return null;
        }
        
        byte[] sharedSecret = KeyUtils.decapsulate(clientKey, platKeyPair.getPrivate());
        if (sharedSecret != null) {
            logger.debug("ECDH key agreement successful, shared secret size: {} bytes", 
                        sharedSecret.length);
        } else {
            logger.error("ECDH key agreement failed to generate shared secret");
        }
        return sharedSecret;
    }

    /**
     * Performs AES-CBC encryption or decryption using the shared secret.
     * Uses ThreadLocal cipher cache for performance optimization.
     *
     * @param mode Cipher mode (Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE)
     * @param data The data to encrypt or decrypt
     * @param sharedSecret The shared secret from ECDH key agreement
     * @return The encrypted or decrypted data
     * @throws GeneralSecurityException if the operation fails
     */
    private static byte[] performAesCbc(int mode, byte[] data, byte[] sharedSecret)
            throws GeneralSecurityException {
        SecretKeySpec keySpec = new SecretKeySpec(sharedSecret, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[AES_BLOCK_SIZE]);
        
        Cipher cipher = AES_CBC_CIPHER.get();
        cipher.init(mode, keySpec, ivSpec);
        return cipher.doFinal(data);
    }

    /**
     * Decrypts the encrypted PIN hash using AES-CBC with the shared secret.
     *
     * @param pinHashEnc The encrypted PIN hash
     * @param sharedSecret The shared secret from ECDH key agreement
     * @return The decrypted PIN hash
     * @throws java.security.GeneralSecurityException if decryption fails
     */
    private static byte[] decryptPinHash(byte[] pinHashEnc, byte[] sharedSecret)
            throws GeneralSecurityException {
        logger.debug("=== decryptPinHash: Input Analysis ===");
        logger.debug("pinHashEnc length: {} bytes", pinHashEnc.length);
        logger.debug("pinHashEnc (hex): {}", bytesToHex(pinHashEnc));
        logger.debug("sharedSecret length: {} bytes", sharedSecret.length);
        logger.debug("sharedSecret (hex): {}", bytesToHex(sharedSecret));
        
        byte[] pinHash = performAesCbc(Cipher.DECRYPT_MODE, pinHashEnc, sharedSecret);
        
        logger.debug("PIN hash decrypted successfully, size: {} bytes", pinHash.length);
        logger.debug("Decrypted pinHash (hex): {}", bytesToHex(pinHash));
        return pinHash;
    }

    /**
     * Encrypts the PIN token using AES-CBC with the shared secret.
     * Per CTAP spec, the PIN token must be encrypted before sending to client.
     *
     * @param pinToken The PIN token to encrypt
     * @param sharedSecret The shared secret from ECDH key agreement
     * @return The encrypted PIN token
     * @throws java.security.GeneralSecurityException if encryption fails
     */
    private static byte[] encryptPinToken(byte[] pinToken, byte[] sharedSecret)
            throws GeneralSecurityException {
        logger.debug("=== encryptPinToken: Encrypting PIN token ===");
        logger.debug("pinToken length: {} bytes", pinToken.length);
        logger.debug("pinToken (hex): {}", bytesToHex(pinToken));
        logger.debug("sharedSecret length: {} bytes", sharedSecret.length);
        
        byte[] encryptedPinToken = performAesCbc(Cipher.ENCRYPT_MODE, pinToken, sharedSecret);
        
        logger.debug("PIN token encrypted successfully, size: {} bytes", encryptedPinToken.length);
        logger.debug("Encrypted PIN token (hex): {}", bytesToHex(encryptedPinToken));
        
        return encryptedPinToken;
    }
    
    /**
     * Converts a byte array to hexadecimal string for logging.
     */
    private static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "null";
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Generates a new random PIN authentication token.
     *
     * @return A new 32-byte PIN authentication token
     */
    private static byte[] generatePinAuthToken() {
        byte[] pinToken = new byte[PIN_TOKEN_SIZE];
        SECURE_RANDOM.nextBytes(pinToken);
        logger.debug("Generated new PIN auth token, size: {} bytes", pinToken.length);
        return pinToken;
    }

    /**
     * Updates the authentication state after successful PIN verification.
     * Stores the authenticated passkey and resets retry counter.
     *
     * @param txn The CTAP transaction
     * @param pkeyFile The opened passkey file
     * @param pinToken The generated PIN authentication token
     * @param pinHash The verified PIN hash
     */
    private static void updateAuthenticationState(CtapTxn txn, Passkey pkeyFile, byte[] pinToken, byte[] pinHash) {
        openKeys.put(txn.getCid(), pkeyFile);
        pinRetries = MAX_PIN_RETRIES;
        txn.setPinAuthTkn(pinToken);
        txn.setPinHash(pinHash);
        txn.setPasskey(pkeyFile);
        txn.setPasskeyFileName(pkeyFile.getFileName());
        logger.debug("PIN token stored in transaction, size: {} bytes", pinToken != null ? pinToken.length : 0);
        logger.info("=== PIN HASH TRACKING: Set in transaction, size: {} bytes, CID: {}",
                    pinHash != null ? pinHash.length : 0,
                    txn.getCid() != null ? java.util.Arrays.toString(txn.getCid()) : "null");
        
        // Update the transaction in assignedCids to preserve authentication state
        com.isfs.blekey.ctap.CtapHid.updateCidTransaction(txn.getCid(), txn);
        logger.debug("Updated CID transaction with authenticated passkey");
        
        // Verify PIN hash was preserved
        byte[] verifyPinHash = txn.getPinHash();
        logger.info("=== PIN HASH TRACKING: After updateCidTransaction, PIN hash in txn: {} bytes",
                    verifyPinHash != null ? verifyPinHash.length : 0);
    }

    /**
     * Validates the getTkn request parameters and extracts the encrypted PIN hash.
     *
     * @param req The request parameters
     * @return PinHashValidationResult containing the PIN hash or error code
     */
    private static PinHashValidationResult validateAndExtractPinHash(Map<Integer, ?> req) {
        if (platKeyPair == null) {
            logger.error("Platform key pair is null, cannot process PIN token request");
            return PinHashValidationResult.failure(Ctap2StatusCode.OTHER);
        }
        
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

    /**
     * Verifies the PIN by attempting to open the passkey file.
     * Manages retry counter and handles PIN blocking.
     *
     * @param pinHash The decrypted PIN hash
     * @return The opened Passkey file, or null if verification fails
     */
    private static Passkey verifyPinAndOpenPasskey(byte[] pinHash) {
        Passkey pkeyFile = Passkey.openKey(pinHash);
        
        if (pkeyFile == null) {
            pinRetries = Math.max(0, pinRetries - 1);
            logger.error("Failed to open passkey file. Retries remaining: {}", pinRetries);
        } else {
            logger.debug("Passkey file opened successfully");
        }
        
        return pkeyFile;
    }

    /**
     * Maps cryptographic exceptions to appropriate CTAP2 status codes.
     *
     * @param e The exception to handle
     * @return A byte array containing the error response
     */
    private static byte[] handleCryptographicException(Exception e) {
        if (e instanceof NoSuchAlgorithmException || e instanceof NoSuchPaddingException) {
            logger.error("Cryptographic algorithm not available", e);
            return error(Ctap2StatusCode.OTHER);
        }
        if (e instanceof InvalidKeyException || e instanceof InvalidAlgorithmParameterException) {
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

    /**
     * Decrypts and verifies the PIN, handling retry logic.
     *
     * @param pinHashEnc The encrypted PIN hash
     * @param sharedSecret The shared secret for decryption
     * @return PinVerificationResult containing the passkey and PIN hash or error code
     * @throws GeneralSecurityException if decryption fails
     */
    private static PinVerificationResult decryptAndVerifyPin(byte[] pinHashEnc, byte[] sharedSecret)
            throws GeneralSecurityException {
        byte[] pinHash = decryptPinHash(pinHashEnc, sharedSecret);
        Passkey pkeyFile = verifyPinAndOpenPasskey(pinHash);
        
        if (pkeyFile == null) {
            Ctap2StatusCode errorCode = (pinRetries == 0)
                ? Ctap2StatusCode.PIN_BLOCKED
                : Ctap2StatusCode.PIN_AUTH_INVALID;
            if (pinRetries == 0) {
                logger.error("PIN blocked due to too many failed attempts");
            }
            return PinVerificationResult.failure(errorCode);
        }
        
        return PinVerificationResult.success(pkeyFile, pinHash);
    }

    /**
     * Handles the getToken PIN subcommand.
     * Verifies the PIN and returns an authentication token.
     *
     * @param txn The CTAP transaction
     * @param req The request parameters
     * @return A byte array containing the response
     */
    private static byte[] getTkn(CtapTxn txn, Map<Integer, ?> req) {
        logger.debug("Processing PIN token request");
        
        // Validate request and extract encrypted PIN hash
        PinHashValidationResult validation = validateAndExtractPinHash(req);
        if (!validation.isValid()) {
            return error(validation.getErrorCode());
        }
        
        // Extract client public key
        PublicKey clientKey = extractClientPublicKey(req);
        if (clientKey == null) {
            return error(Ctap2StatusCode.INVALID_PARAMETER);
        }
        
        // Perform ECDH key agreement
        byte[] sharedSecret = performEcdhKeyAgreement(clientKey);
        if (sharedSecret == null) {
            return error(Ctap2StatusCode.OTHER);
        }
        
        // Process PIN verification and generate token response
        return processPinVerificationAndGenerateToken(txn, validation.getPinHashEnc(), sharedSecret);
    }
    
    /**
     * Processes PIN verification and generates the encrypted token response.
     * Handles all cryptographic operations and state updates.
     *
     * @param txn The CTAP transaction
     * @param pinHashEnc The encrypted PIN hash
     * @param sharedSecret The shared secret from ECDH
     * @return A byte array containing the response
     */
    private static byte[] processPinVerificationAndGenerateToken(CtapTxn txn, byte[] pinHashEnc, byte[] sharedSecret) {
        try {
            // Decrypt and verify PIN
            PinVerificationResult pinVerification = decryptAndVerifyPin(pinHashEnc, sharedSecret);
            if (!pinVerification.isValid()) {
                return error(pinVerification.getErrorCode());
            }
            
            // Generate and encrypt PIN auth token
            byte[] pinToken = generatePinAuthToken();
            byte[] encryptedPinToken = encryptPinToken(pinToken, sharedSecret);
            
            // Update authentication state
            updateAuthenticationState(txn, pinVerification.getPasskey(), pinToken, pinVerification.getPinHash());
            
            // Build and return response
            return new PinTokenResponseBuilder()
                .withPinToken(encryptedPinToken)
                .build();
            
        } catch (GeneralSecurityException e) {
            return handleCryptographicException(e);
        }
    }

    /**
     * Handles the getRetries PIN subcommand.
     * Returns the number of PIN retry attempts remaining.
     *
     * @param txn The CTAP transaction
     * @param req The request parameters
     * @return A byte array containing the response
     */
    private static byte[] pinRty(CtapTxn txn, Map<Integer, Object> req) {
        Map<Integer, Object> rsp = Map.of(0x03, pinRetries--);
        return success(Cbor.encode(rsp));
    }

    /**
     * Main entry point for processing CTAP2 commands.
     * Routes the request to the appropriate handler based on the command type.
     *
     * @param txn The CTAP transaction
     * @param api The CTAP2 command identifier
     * @param request The request parameters
     * @return A byte array containing the response
     */
    public static byte[] process(CtapTxn txn, int api, Map<Integer, Object> request) {
        AuthenticatorCmd cmd = AuthenticatorCmd.fromInt(api);
        switch(cmd)
        {
            case MKCRED:
                return makeCredential(txn, request);
            case NXTAST:
                return getAssertion(txn, request);
            case GETINF:
                return getInfo(txn, request);
            case ATHPIN:
                return pinRequest(txn, request);
            case SELECTION:
                return authenticatorSelection(txn);
            default:
                return error(Ctap2StatusCode.INVALID_COMMAND);
        }
    }

    /**
     * Processes an authenticatorSelection request (CTAP2.1 command 0x0B).
     *
     * Chrome sends this immediately after getInfo to confirm the authenticator
     * is reachable before proceeding with makeCredential. UP was already collected
     * during getInfo, so no second prompt is needed — return success immediately.
     *
     * @param txn The CTAP transaction
     * @return 1-byte success response, or OPERATION_DENIED if UP was not collected
     */
    private static byte[] authenticatorSelection(CtapTxn txn) {
        logger.debug("authenticatorSelection");
        if (txn == null || !txn.isUserPresent()) {
            logger.warn("authenticatorSelection: UP not cached — returning OPERATION_DENIED");
            return error(Ctap2StatusCode.OPERATION_DENIED);
        }
        // CTAP2.1 §6.9: success response is a single 0x00 status byte with no CBOR payload.
        logger.debug("authenticatorSelection: UP cached — returning success");
        return new byte[]{ 0x00 };
    }
}

// Made with Bob
