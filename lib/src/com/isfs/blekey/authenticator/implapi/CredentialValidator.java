/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator.implapi;

import com.isfs.blekey.authenticator.CredentialType;
import com.isfs.blekey.ctap.Ctap2StatusCode;
import com.isfs.blekey.data.Passkey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Validates whether a {@code makeCredential} request can proceed, determines the
 * credential type, and checks the exclude-list.
 *
 * <p>Result types {@link CredentialValidationResult} and {@link CredentialOptions}
 * live as package-accessible top-level classes at the bottom of this file (§6g).</p>
 */
public class CredentialValidator {

    private static final Logger logger = LoggerFactory.getLogger(CredentialValidator.class);

    /** Supported COSE algorithm identifiers. ES256 (-7) is the primary FIDO2 algorithm. */
    private static final Set<Integer> SUPPORTED_ALGORITHM_SET =
        new HashSet<>(Arrays.asList(-7));

    /** makeCredential request parameter keys. */
    private static final int KEY_CLIENT_DATA_HASH  = 0x01;
    private static final int KEY_RP                = 0x02;
    private static final int KEY_USER              = 0x03;
    private static final int KEY_PUB_KEY_CRED_PARAMS = 0x04;
    private static final int KEY_EXCLUDE_LIST      = 0x05;
    private static final int KEY_OPTIONS           = 0x07;
    private static final int KEY_PIN_UV_AUTH_PARAM = 0x08;

    private CredentialValidator() {}

    /**
     * Validates the request and determines the credential type.
     *
     * @param req     CTAP2 makeCredential request map
     * @param passkey authenticated passkey for this CID (may be null)
     * @return result containing the credential type or an error code
     */
    public static CredentialValidationResult canMakeCredential(
            Map<Integer, Object> req, Passkey passkey) {

        Ctap2StatusCode error = validateRequiredParameters(req);
        if (error != null) return CredentialValidationResult.error(error);

        error = validateClientDataHash(getClientDataHash(req));
        if (error != null) return CredentialValidationResult.error(error);

        error = validateAlgorithmSupport(getPubKeyCredParams(req));
        if (error != null) return CredentialValidationResult.error(error);

        error = checkExcludeList(getExcludeList(req), passkey);
        if (error != null) return CredentialValidationResult.error(error);

        CredentialOptions options = parseOptions(req);
        return determineCredentialType(
            options.rk,
            options.uv || req.containsKey(KEY_PIN_UV_AUTH_PARAM),
            passkey);
    }

    // -------------------------------------------------------------------------
    // Individual validators (package-accessible for direct testing)
    // -------------------------------------------------------------------------

    static Ctap2StatusCode validateRequiredParameters(Map<Integer, Object> req) {
        int[] requiredKeys = {KEY_CLIENT_DATA_HASH, KEY_RP, KEY_USER, KEY_PUB_KEY_CRED_PARAMS};
        String[] paramNames = {"clientDataHash", "rp", "user", "pubKeyCredParams"};
        for (int i = 0; i < requiredKeys.length; i++) {
            if (!req.containsKey(requiredKeys[i])) {
                logger.error("Missing required parameter: {} ({})", paramNames[i], requiredKeys[i]);
                return Ctap2StatusCode.MISSING_PARAMETER;
            }
        }
        return null;
    }

    static Ctap2StatusCode validateClientDataHash(byte[] clientDataHash) {
        if (clientDataHash == null || clientDataHash.length != 32) {
            logger.error("Invalid clientDataHash length: expected 32 bytes, got {}",
                         clientDataHash != null ? clientDataHash.length : 0);
            return Ctap2StatusCode.INVALID_PARAMETER;
        }
        return null;
    }

    /** Returns {@code true} if at least one supported algorithm is found. */
    public static boolean isSupportedAlgorithm(List<Map<String, Object>> pubKeyCredParams) {
        if (pubKeyCredParams == null || pubKeyCredParams.isEmpty()) return false;
        for (Map<String, Object> param : pubKeyCredParams) {
            Object alg = param.get("alg");
            if (alg != null && SUPPORTED_ALGORITHM_SET.contains(alg)) return true;
        }
        return false;
    }

    static Ctap2StatusCode validateAlgorithmSupport(
            List<Map<String, Object>> pubKeyCredParams) {
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
     * Checks if any credential in the exclude list already exists in the passkey.
     */
    public static Ctap2StatusCode checkExcludeList(
            List<Map<String, Object>> excludeList, Passkey passkey) {
        if (excludeList == null || excludeList.isEmpty()) return null;
        for (Map<String, Object> excludedCred : excludeList) {
            byte[] credId = (byte[]) excludedCred.get("id");
            if (credId != null && ResidentCredentialStore.isCredentialExcluded(credId, passkey)) {
                logger.warn("Credential in excludeList already exists");
                return Ctap2StatusCode.CREDENTIAL_EXCLUDED;
            }
        }
        return null;
    }

    /**
     * Determines the credential type based on rk and uv flags.
     */
    public static CredentialValidationResult determineCredentialType(
            boolean rk, boolean uv, Passkey passkey) {
        if (uv && passkey == null) {
            logger.error("User verification requested but no pin auth ceremony completed...");
            return new CredentialValidationResult(CredentialType.NONE, Ctap2StatusCode.PIN_REQUIRED);
        }
        if (rk) {
            if (uv) return new CredentialValidationResult(CredentialType.RESIDENT, null);
            logger.error("Creating resident credential without user verification is not allowed");
            return new CredentialValidationResult(CredentialType.NONE, Ctap2StatusCode.PIN_REQUIRED);
        } else if (uv) {
            return new CredentialValidationResult(CredentialType.PASSKEY, null);
        } else {
            return new CredentialValidationResult(CredentialType.TWO_FACTOR, null);
        }
    }

    /**
     * Parses the {@code options} map from the request.
     */
    public static CredentialOptions parseOptions(Map<Integer, Object> req) {
        @SuppressWarnings("unchecked")
        Map<String, Object> options = (Map<String, Object>)
            req.getOrDefault(KEY_OPTIONS, new HashMap<>());
        boolean uv = (boolean) options.getOrDefault("uv", false);
        boolean rk = (boolean) options.getOrDefault("rk", false);
        return new CredentialOptions(uv, rk);
    }

    // -------------------------------------------------------------------------
    // Accessors for request fields
    // -------------------------------------------------------------------------

    static byte[] getClientDataHash(Map<Integer, Object> req) {
        return (byte[]) req.get(KEY_CLIENT_DATA_HASH);
    }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> getPubKeyCredParams(Map<Integer, Object> req) {
        return (List<Map<String, Object>>) req.get(KEY_PUB_KEY_CRED_PARAMS);
    }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> getExcludeList(Map<Integer, Object> req) {
        return (List<Map<String, Object>>) req.get(KEY_EXCLUDE_LIST);
    }
}

// ---------------------------------------------------------------------------
// Result types co-located with CredentialValidator (§6g)
// ---------------------------------------------------------------------------

/**
 * Result of credential validation: contains the determined credential type or an error code.
 */
class CredentialValidationResult {
    final CredentialType type;
    final Ctap2StatusCode errorCode;

    CredentialValidationResult(CredentialType type, Ctap2StatusCode errorCode) {
        this.type = type;
        this.errorCode = errorCode;
    }

    static CredentialValidationResult error(Ctap2StatusCode code) {
        return new CredentialValidationResult(CredentialType.NONE, code);
    }

    public boolean isValid() {
        return errorCode == null && type != CredentialType.NONE;
    }
}

/**
 * Parsed credential options (rk and uv flags).
 */
class CredentialOptions {
    final boolean uv;
    final boolean rk;

    CredentialOptions(boolean uv, boolean rk) {
        this.uv = uv;
        this.rk = rk;
    }
}
