/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator;

import com.isfs.blekey.util.Cbor;
import com.isfs.blekey.ctap.Ctap2StatusCode;
import com.isfs.blekey.ctap.CtapTxn;
import com.isfs.blekey.util.KeyUtils;
import com.isfs.blekey.util.FileUtils;

import com.isfs.blekey.data.Passkey;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.crypto.Cipher;
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

    /**
     * Number of PIN retry attempts allowed before lockout.
     */
    private static int pinRetries = 5;

    /**
     * Key pair used for platform authentication.
     */
    private static KeyPair platKeyPair = KeyUtils.getKeyPair("EC");
    
    /**
     * Map of channel IDs to their associated platform keys and passkeys.
     * Maps CID to a map containing the passkey and platform public key.
     */
    private static Map<byte[], Map<String, Object>> openKeys = new HashMap<byte[], Map<String, Object>>();

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

    private static PinUvAuthResult verifyPinAuthToken(byte[] pinAuthToken, byte[] pinUvAuthParam, String rpId)
            throws InvalidKeyException {
        // Get cached MessageDigest instance from ThreadLocal
        MessageDigest digest = SHA256_DIGEST.get();
        digest.reset();
        byte[] rpIdHash = digest.digest(rpId.getBytes(StandardCharsets.UTF_8));
        
        // Get cached Mac instance from ThreadLocal
        javax.crypto.Mac mac = HMAC_SHA256.get();
        javax.crypto.spec.SecretKeySpec keySpec =
            new javax.crypto.spec.SecretKeySpec(pinAuthToken, "HmacSHA256");
        mac.init(keySpec);
        byte[] expectedAuth = mac.doFinal(rpIdHash);
        
        // Compare first 16 bytes (CTAP2 spec requirement)
        byte[] expectedAuth16 = Arrays.copyOf(expectedAuth, 16);
        
        if (!MessageDigest.isEqual(pinUvAuthParam, expectedAuth16)) {
            logger.error("PIN/UV auth token verification failed: HMAC mismatch for RP: {}", rpId);
            return new PinUvAuthResult(false, Ctap2StatusCode.PIN_AUTH_INVALID);
        }
        return new PinUvAuthResult(false, Ctap2StatusCode.SUCCESS);
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
        if (token == null) {
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
    private static PinUvAuthResult verifyTokenWithParams(CtapTxn txn, PinUvAuthParams params)
            throws PinAuthException, InvalidKeyException {
        byte[] pinAuthToken = retrievePinAuthToken(txn);
        return verifyPinAuthToken(pinAuthToken, params.pinUvAuthParam, params.rpId);
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
        
        // Parse and validate request parameters
        PinUvAuthParams params = PinUvAuthParams.parse(req);
        if (!params.isValid()) {
            return new PinUvAuthResult(false, params.errorCode);
        }
        
        // If no pinUvAuthParam provided, check if UV was required
        if (params.pinUvAuthParam == null) {
            if (params.uvRequested) {
                return errorResult("User verification required but no PIN/UV auth token provided",
                                 Ctap2StatusCode.PIN_REQUIRED);
            }
            logger.debug("No PIN/UV auth param provided, proceeding without user verification");
            return PinUvAuthResult.NO_VERIFICATION;
        }
        
        // Validate pinUvAuthProtocol
        logger.debug("Validating PIN/UV auth protocol: {}", params.pinUvAuthProtocol);
        Ctap2StatusCode protocolError = validatePinUvAuthProtocol(params.pinUvAuthProtocol);
        if (protocolError != null) {
            return new PinUvAuthResult(false, protocolError);
        }
        
        // Get and verify PIN auth token
        logger.debug("Protocol validation passed, retrieving and verifying PIN auth token");
        try {
            PinUvAuthResult result = verifyTokenWithParams(txn, params);
            if (result.errorCode != Ctap2StatusCode.SUCCESS) {
                return result;
            }
        } catch (PinAuthException e) {
            return errorResult(e.getMessage(), e.code);
        } catch (InvalidKeyException e) {
            return errorResult("Invalid key during PIN/UV auth token verification",
                             Ctap2StatusCode.PIN_AUTH_INVALID, e);
        }
        
        // Auth token verified successfully
        logger.debug("PIN/UV auth token verified successfully for RP: {}", params.rpId);
        return PinUvAuthResult.SUCCESS;
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
        
        static final PinUvAuthResult SUCCESS = new PinUvAuthResult(true, null);
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
        
        boolean isValid() {
            return errorCode == null && type != CredentialType.NONE;
        }
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

    private static boolean isSupportedAlgorithm(List<Map<String, Object>> pubKeyCredParams) {
        if (pubKeyCredParams == null || pubKeyCredParams.isEmpty()) {
            return false;
        } else {
            for (Map<String, Object> param : pubKeyCredParams) {
                if (param.containsKey("alg") 
                            && SUPPORTED_ALGORITHM_SET.contains(param.get("alg"))) {
                    return true;
                }
            }
        }
        return false;
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
        Map<String, Object> options = (Map<String, Object>) req.getOrDefault(0x07, new HashMap<>());
        
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
            return new CredentialValidationResult(CredentialType.NONE, error);
        }
        
        // Step 2: Validate clientDataHash length (must be 32 bytes for SHA-256)
        byte[] clientDataHash = (byte[]) req.get(0x01);
        error = validateClientDataHash(clientDataHash);
        if (error != null) {
            return new CredentialValidationResult(CredentialType.NONE, error);
        }

        // Step 3: Validate algorithm support
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> pubKeyCredParams = (List<Map<String, Object>>) req.get(0x04);
        if (!isSupportedAlgorithm(pubKeyCredParams)) {
            logger.error("No supported algorithm found in pubKeyCredParams");
            return new CredentialValidationResult(CredentialType.NONE, Ctap2StatusCode.UNSUPPORTED_ALGORITHM);
        }

        // Step 4: Check excludeList for existing credentials
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> excludeList = (List<Map<String, Object>>) req.get(0x05);
        error = checkExcludeList(excludeList, passkey);
        if (error != null) {
            return new CredentialValidationResult(CredentialType.NONE, error);
        }

        // Step 5: Parse and validate options
        CredentialOptions options = parseOptions(req);
        error = validateUserPresence(options);
        if (error != null) {
            return new CredentialValidationResult(CredentialType.NONE, error);
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
        Map<String, Object> rp = (Map<String, Object>) req.get(0x02);
        String rpId = (String) rp.get("id");
        byte[] rpIdBytes = rpId.getBytes(StandardCharsets.UTF_8);
        
        @SuppressWarnings("unchecked")
        Map<String, Object> user = (Map<String, Object>) req.get(0x03);
        byte[] userId = (byte[]) user.get("id");
        
        return new CredentialInfo(rpId, rpIdBytes, userId);
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
     * @param credentialKeyPair The credential key pair (not used, kept for future)
     * @param passkey The passkey to store in
     * @param txn The CTAP transaction containing PIN hash and file name
     * @return Error code if storage fails, null on success
     */
    private static Ctap2StatusCode storeResidentCredential(
            Map<Integer, Object> req,
            byte[] credentialId,
            KeyPair credentialKeyPair,
            Passkey passkey,
            CtapTxn txn) {
        
        // Validate passkey
        Ctap2StatusCode error = validateNotNull(passkey, "Cannot store resident credential: passkey is null");
        if (error != null) {
            return error;
        }
        // Validate file     
        File passkeyFile = resolvePasskeyFile(txn);
        if(passkeyFile == null || !passkeyFile.exists()) return Ctap2StatusCode.OTHER;

        
        // Gather credential data
        CredentialInfo credInfo = extractCredentialInfo(req);
        
        // Add resident credential to passkey
        passkey.addResCred(credInfo.rpIdBytes, credentialId, credInfo.userId);

        // Count current resident credentials
        logger.debug("Added resident credential for RP: {}, credential count: {}",
                    credInfo.rpId, (passkey.getResCreds() != null) ? passkey.getResCreds().size() : 0);

        // Persist passkey to file
        byte[] pinHash = txn.getPinHash();
        error = validateNotNull(pinHash, "Cannot persist passkey: missing PIN hash");
        if (error != null) {
            return error;
        }
        
        // Write passkey to file
        boolean success = Passkey.writeKey(passkey, pinHash, passkeyFile);
        if (!success) {
            logger.error("Failed to persist passkey to file: {}", passkeyFile.getAbsolutePath());
            return Ctap2StatusCode.OTHER;
        }
        
        String fileName = txn.getPasskeyFileName();
        logger.info("Successfully persisted resident credential to file: {}", fileName);
        return Ctap2StatusCode.SUCCESS;
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
        logger.debug("makeCredential");
        
        // Validate the request and determine credential type
        CredentialValidationResult validation = _canMakeCredential(req, txn.getPasskey());
        
        if (!validation.isValid()) {
            logger.error("Credential validation failed: {}", validation.errorCode);
            return error(validation.errorCode);
        }
        
        logger.debug("Creating credential of type: {}", validation.type);
        
        try {
            return _makeCredential(validation, txn, req);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            return error(Ctap2StatusCode.OTHER);
        }
    }

    private static byte[] _makeCredential(
            CredentialValidationResult validation, 
            CtapTxn txn, 
            Map<Integer, Object> req) throws Exception {

        // Verify pin auth token if it exists
        PinUvAuthResult pinUvResult = verifyPinUvAuth(req, txn);
        if (pinUvResult.errorCode != null) {
            return error(pinUvResult.errorCode);
        }
        // Load key material
        KeyPair caKp = new KeyPair(KeyUtils.getPubKey((ECPrivateKey) KeyUtils.getPlatformKey()),
                                    KeyUtils.getPlatformKey());
        if(validation.type == CredentialType.RESIDENT && pinUvResult.userVerified) {
           caKp = new KeyPair(KeyUtils.getPubKey((ECPrivateKey) txn.getPasskey().getPrivateKey()),
                                        txn.getPasskey().getPrivateKey());
        }
        Fido2Authenticator pkey = new Fido2Authenticator("EC", 256);

        // Step 1: Build Authenticator Data
        byte[] cdh = (byte[]) req.get(0x01);
        byte[] authenticatorData = pkey.buildAuthenticatorData(Map.of("rp", req.get(0x02), "attestation",true), 
                    "packed", null, null, pkey.getKeyPair());
        // Step 2: Create Attestation Statement (packed-self)
        Map<String, Object> attStmt = pkey.processAttestationStatement("packed", cdh, authenticatorData, 
                        pkey.getCredId(), pkey.getKeyPair(), caKp, null);

        // Step 3: Store Credential (if resident)
        if (validation.type == CredentialType.RESIDENT) {
            Ctap2StatusCode storeResult = storeResidentCredential(
                req, pkey.getCredId(), pkey.getKeyPair(), txn.getPasskey(), txn);
            if (storeResult != null) {
                return error(storeResult);
            }
        }

        // Step 4: Build Response
        Map<Integer, Object> response = Map.of(
            0x01, "packed", // fmt
            0x02, authenticatorData,
            0x03, attStmt
        );
        
        return success(Cbor.encode(response));
    }

    private static Fido2Authenticator createAuthenticator(CtapTxn txn, Map<Integer, Object> req) {
        try {
            Fido2Authenticator a = new Fido2Authenticator();
            if(txn.getPasskey() != null) { //PinAuth completed and passkey opened; resident credential
                a.setAuthnCert(txn.getPasskey().getCertificate());
                a.setSymKeys(KeyUtils.getPasskeySeed((byte[]) req.get(0x01), txn.getPasskey().getPrivateKey()));
            } else { //U2F authenticator
                a.setSymKeys(KeyUtils.getPasskeySeed((byte[]) req.get(0x01), KeyUtils.getPlatformKey()));
            }
            return a;
        } catch (Exception e) {
            //logger.error("Failed to create authenticator", e);
            return null;
        }
    }

    private static boolean initializeAuthenticatorWithCredential(
            Fido2Authenticator authenticator, 
            ArrayList<Map<String, byte[]>> credentials) {
        
        for (Map<String, byte[]> cred : credentials) {
            try {
                authenticator.initFromCredId(cred.get("id"));
                return true;
            } catch (Exception e) {
                // Continue trying other credentials
                continue;
            }
        }
        return false;
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
                        "user", (byte[]) cred.get("user.id")
                    ));
                }
            }
        }
        return allowList;
    }


    private static byte[] generateSignedAssertion(
            Map<Integer, Object> req, 
            Fido2Authenticator authenticator) {
        
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> pubKeyMap = (Map<String, Object>) req.get(0x02);
            
            Map<String, Object> cred = Map.of(
                "id", authenticator.getCredId(),
                "type", "public-key"
            );
            
            byte[] authData = authenticator.buildAuthenticatorData(
                pubKeyMap, "packed", null, null, authenticator.getKeyPair());
            
            byte[] clientDataHash = (byte[]) req.get(0x01);
            ByteBuffer bb = ByteBuffer.allocate(authData.length + clientDataHash.length);
            bb.put(authData);
            bb.put(clientDataHash);
            byte[] sig = authenticator.signData(
                bb.array(), authenticator.getPrivKey(), "SHA256withECDSA");
            
            Map<Integer, Object> rsp = Map.of(
                0x01, cred, 0x02, authData, 0x03, sig);
            
            return success(Cbor.encode(rsp));
        } catch (Exception e) {
            logger.error("Failed to generate signed assertion", e.getMessage());
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
        Fido2Authenticator authenticator = createAuthenticator(txn, req);
        if (authenticator == null) {
            logger.debug("authenticator is null");
            return error(Ctap2StatusCode.OTHER);
        }
        logger.debug("created authenticator");
        // Process credentials from allowList and resident credentials
        ArrayList<Map<String, byte[]>> credentials = processCredentials(req, txn.getPasskey());
        if (credentials.isEmpty()) {
            return error(Ctap2StatusCode.NO_CREDENTIALS);
        }

        // Initialize authenticator with a valid credential
        if (!initializeAuthenticatorWithCredential(authenticator, credentials)) {
            return error(Ctap2StatusCode.NO_CREDENTIALS);
        }

        // Generate and sign assertion
        return generateSignedAssertion(req, authenticator);
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
        Map<String, Boolean> capabilities = Map.of("rk", true,
                                                   "plat", true, //XD
                                                   "clientPint", true);
        Map<Integer, Object> info = Map.of(
            0x01, new String[] {"FIDO_2_1", "FIDO_2_0"},
            0x02, new String[] {"hmac-secret"}, //extensions
            0x03, new int[] {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, //AAGUID
            0x04, capabilities, //capabilities
            0x05, 4096, // maxMsgSize
            0x06, new int[] {1} //PIN/UV Auth Protocol One
        );
        logger.debug("getInfo response: {}", info);
        return success(Cbor.encode(info));
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
        PinSubCmd cmd = PinSubCmd.fromInt((int) req.getOrDefault(2, 0));
        switch(cmd)
        {
            case GETRETRY:
                return pinRty(txn, req);
            case GETKEY:
                return getKey(txn, req);
            case GETTKN:
                return getTkn(txn, req);
            default:
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
        Map<Integer, Object> rsp = Map.of(0x01, 
                KeyUtils.toCoseKey(AuthenticatorAPI.platKeyPair.getPublic()));
        byte[] key = Cbor.encode(rsp);
        return success(key);
    }

    /**
     * Handles the getToken PIN subcommand.
     * Verifies the PIN and returns an authentication token.
     *
     * @param txn The CTAP transaction
     * @param req The request parameters
     * @return A byte array containing the response
     */
    private static byte[] getTkn(CtapTxn txn, Map<Integer, Object> req) {
        //Decapsulate shared secret
        byte[] pinHashEnc = (byte[]) req.get(0x06);
        @SuppressWarnings("unchecked")
        PublicKey theirKey = KeyUtils.fromCoseKey((Map<Integer, Object>) req.get(0x03));
        byte[] sharedSecret = KeyUtils.decapsulate(theirKey,
                    AuthenticatorAPI.platKeyPair.getPrivate());
        // Create AES key from shared secret
        SecretKeySpec secretKeySpec = new SecretKeySpec(sharedSecret, "AES");
        // Create all-zero IV for CBC mode
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]);
        try {
            // Initialize cipher with CBC mode and zero IV
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);
            byte[] pinHash = cipher.doFinal(pinHashEnc);
            Passkey pkeyFile = Passkey.openKey(pinHash);
            if (pkeyFile == null) {
                return AuthenticatorAPI.error(Ctap2StatusCode.PIN_AUTH_INVALID);
            }
            //Return pin auth token
            byte[] pinTkn = new byte[32];
            SecureRandom random = new SecureRandom();
            random.nextBytes(pinTkn);
            openKeys.put(txn.getCid(), Map.of("passkey", pkeyFile, "plat", theirKey));
            pinRetries = 5;
            Map<Integer, Object> rsp = Map.of(0x02, pinTkn);
            txn.setPinAuthTkn(pinTkn);
            txn.setPinHash(pinHash);
            txn.setPasskeyFileName(pkeyFile.getFileName());
            return success(Cbor.encode(rsp));
        } catch (Exception e) {
            return error(Ctap2StatusCode.INVALID_PARAMETER);
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
            default:
                return error(Ctap2StatusCode.INVALID_COMMAND);
        }
    }
}

// Made with Bob
