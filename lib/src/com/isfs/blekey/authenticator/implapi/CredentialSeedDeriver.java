/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator.implapi;

import com.isfs.blekey.authenticator.Fido2Authenticator;
import com.isfs.blekey.authenticator.UxInteractionLock;
import com.isfs.blekey.data.AppConfig;
import com.isfs.blekey.ctap.CtapTxn;
import com.isfs.blekey.util.KeyUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Map;

/**
 * Derives the HKDF passkey seed from the platform key (§6c).
 *
 * <p>Owns {@code derivePasskeySeed()}, {@code configureCredentialAnchor()},
 * {@code extractRpIdBytes()}, and the private {@code extractRpIdFromMap()} helper
 * that reduces top-level branch count (§6d).</p>
 */
public class CredentialSeedDeriver {

    private static final Logger logger = LoggerFactory.getLogger(CredentialSeedDeriver.class);

    /** ThreadLocal SHA-256 digest. */
    private static final ThreadLocal<MessageDigest> SHA256_DIGEST =
        ThreadLocal.withInitial(() -> {
            try {
                return MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("SHA-256 algorithm not available", e);
            }
        });

    private CredentialSeedDeriver() {}

    // -------------------------------------------------------------------------
    // derivePasskeySeed
    // -------------------------------------------------------------------------

    /**
     * Derives the HKDF passkey seed synchronously from the platform key.
     *
     * <p>If {@code txn} already has a cached IKM the seed is computed immediately.
     * Otherwise performs a fresh ECDH self-agreement, caches the resulting IKM on
     * {@code txn}, and returns the HKDF-derived seed string.</p>
     *
     * @param txn        CTAP transaction (may be null); IKM is cached here on success
     * @param privKey    platform private key
     * @param rpIdBytes  SHA-256 of the RP ID
     * @param appConfig  application configuration for seed derivation
     * @return the seed string, or {@code null} on any error
     */
    public static String derivePasskeySeed(
            CtapTxn txn,
            PrivateKey privKey,
            byte[] rpIdBytes,
            AppConfig appConfig) {

        // Fast path: app-global bio grant is active — IKM already derived this session.
        if (UxInteractionLock.get().isGrantActive()) {
            byte[] cachedIkm = UxInteractionLock.get().getCachedIkm();
            if (cachedIkm != null) {
                logger.debug("derivePasskeySeed: using cached IKM from global grant");
                try {
                    return KeyUtils.getPasskeySeed(rpIdBytes, cachedIkm, appConfig);
                } catch (Exception e) {
                    logger.warn("derivePasskeySeed: cached-IKM seed derivation failed — retrying", e);
                    // Fall through to fresh derivation
                }
            }
        }

        java.security.PublicKey pubKey;
        try {
            pubKey = KeyUtils.getKeystoreManager().getEC256PublicKey();
        } catch (Exception e) {
            logger.error("derivePasskeySeed: failed to retrieve platform public key", e);
            return null;
        }

        try {
            javax.crypto.KeyAgreement ka = javax.crypto.KeyAgreement.getInstance("ECDH");
            ka.init(privKey);
            ka.doPhase(pubKey, true);
            byte[] ikm = ka.generateSecret();

            // IKM is now owned by UxInteractionLock — do not cache on txn.
            return KeyUtils.getPasskeySeed(rpIdBytes, ikm, appConfig);
        } catch (Exception e) {
            logger.error("derivePasskeySeed: ECDH self-agreement failed", e);
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // configureCredentialAnchor
    // -------------------------------------------------------------------------

    /**
     * Configures the authenticator to recover keys from credential IDs using the
     * passkey's private key as the HKDF IKM.
     */
    public static void configureCredentialAnchor(
            Fido2Authenticator a,
            PrivateKey privKey,
            byte[] rpIdBytes,
            AppConfig appConfig) {
        logger.debug("Passkey private key: {}", privKey != null ? privKey.getAlgorithm() : "null");
        byte[] ikm = privKey != null ? privKey.getEncoded() : null;
        String seed = KeyUtils.getPasskeySeed(rpIdBytes, ikm, appConfig);
        if (seed == null) {
            throw new IllegalStateException("Failed to generate seed from passkey");
        }
        a.setSymKeys(seed);
    }

    // -------------------------------------------------------------------------
    // extractRpIdBytes (§6d: Map branch extracted to sub-method)
    // -------------------------------------------------------------------------

    /**
     * Extracts the RP ID from an arbitrary value and returns its SHA-256 hash.
     *
     * <p>Accepts three formats: {@code String}, {@code byte[]}, or {@code Map}
     * (makeCredential RP object).  The Map branch is handled by
     * {@link #extractRpIdFromMap(Map)} to keep this method to three flat cases.</p>
     *
     * @param rpIdValue the raw value from the CTAP2 request (key 0x01 or 0x02)
     * @return SHA-256 hash of the RP ID
     * @throws IllegalArgumentException if the value is null or has an unsupported type
     */
    public static byte[] extractRpIdBytes(Object rpIdValue) {
        if (rpIdValue == null) {
            throw new IllegalArgumentException("Missing rpId value");
        }
        if (rpIdValue instanceof String) {
            String rpId = (String) rpIdValue;
            logger.debug("Extracted rpId from String: {}, hashing", rpId);
            return sha256(rpId.getBytes(StandardCharsets.UTF_8));
        }
        if (rpIdValue instanceof byte[]) {
            byte[] rpIdBytes = (byte[]) rpIdValue;
            logger.debug("Extracted rpId from byte array (length: {}), hashing", rpIdBytes.length);
            return sha256(rpIdBytes);
        }
        if (rpIdValue instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> rpMap = (Map<String, Object>) rpIdValue;
            return extractRpIdFromMap(rpMap);
        }
        throw new IllegalArgumentException(
            "rpId value has unsupported type: " + rpIdValue.getClass().getName());
    }

    /**
     * Extracts the RP ID from the {@code rp} map (makeCredential format) and hashes it.
     * Handles both {@code String} and {@code byte[]} forms of {@code rp.id}.
     */
    private static byte[] extractRpIdFromMap(Map<String, Object> rp) {
        Object rpIdObj = rp.get("id");
        if (rpIdObj == null) {
            throw new IllegalArgumentException("RP map missing 'id' field");
        }
        if (rpIdObj instanceof String) {
            String rpId = (String) rpIdObj;
            logger.debug("Extracted rpId from RP map String: {}, hashing", rpId);
            return sha256(rpId.getBytes(StandardCharsets.UTF_8));
        }
        if (rpIdObj instanceof byte[]) {
            byte[] rpIdBytes = (byte[]) rpIdObj;
            logger.debug("Extracted rpId from RP map byte array (length: {}), hashing",
                         rpIdBytes.length);
            return sha256(rpIdBytes);
        }
        throw new IllegalArgumentException(
            "RP map 'id' field has unsupported type: " + rpIdObj.getClass().getName());
    }

    private static byte[] sha256(byte[] input) {
        MessageDigest digest = SHA256_DIGEST.get();
        digest.reset();
        return digest.digest(input);
    }
}
