/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.util;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * Manages holder binding keys for digital credentials using a master key + seed derivation approach.
 * 
 * Architecture:
 * - Single master key stored in hardware-backed keystore (Android Keystore/iOS Keychain)
 * - Per-credential seeds stored with passkey data
 * - Binding keys derived on-demand using HKDF with master key signature
 * 
 * Security Properties:
 * - Master key requires biometric authentication for each use
 * - Master key never leaves hardware security module
 * - Derived keys are cryptographically independent
 * - Seeds alone are useless without master key access
 * 
 * Key Derivation:
 * 1. Master key signs the credential seed (requires biometric auth)
 * 2. Salt = SHA-256(credential_id || issuer_id)
 * 3. Info = "AYE BLE KEY DIGITAL CREDENTIAL MASTER SEED" || credential_type
 * 4. Binding key = HKDF-Expand(HKDF-Extract(Salt, master_key_signature), Info, 32)
 */
public class HolderBindingKeyManager {
    
    private static final Logger logger = LoggerFactory.getLogger(HolderBindingKeyManager.class);
    
    private static final int SEED_LENGTH = 32;
    private static final int KEY_LENGTH = 32;
    private static final String HKDF_INFO_PREFIX = "AYE BLE KEY DIGITAL CREDENTIAL MASTER SEED";
    private static final byte[] HKDF_INFO_PREFIX_BYTES = HKDF_INFO_PREFIX.getBytes(StandardCharsets.UTF_8);
    
    /**
     * Platform-specific keystore manager for master key operations.
     * Must be set during application initialization.
     */
    private static KeystoreManager keystoreManager;
    
    /**
     * Sets the platform-specific keystore manager.
     * This must be called during application initialization.
     * 
     * @param manager The KeystoreManager implementation
     */
    public static void setKeystoreManager(KeystoreManager manager) {
        keystoreManager = manager;
        logger.info("HolderBindingKeyManager: KeystoreManager set");
    }
    
    /**
     * Gets the current keystore manager.
     * 
     * @return The KeystoreManager instance, or null if not set
     */
    public static KeystoreManager getKeystoreManager() {
        return keystoreManager;
    }
    
    /**
     * Generates a new random seed for a credential.
     * This seed should be stored with the credential data.
     * 
     * @return 32-byte random seed
     * @throws RuntimeException if secure random generation fails
     */
    public static byte[] generateSeed() {
        try {
            SecureRandom random = SecureRandom.getInstanceStrong();
            byte[] seed = new byte[SEED_LENGTH];
            random.nextBytes(seed);
            logger.debug("Generated new credential seed");
            return seed;
        } catch (Exception e) {
            logger.error("Failed to generate credential seed", e);
            throw new RuntimeException("Failed to generate credential seed", e);
        }
    }
    
    /**
     * Derives a holder binding EC key pair from the master key and credential seed.
     *
     * This method:
     * 1. Validates inputs
     * 2. Computes salt from credential ID and issuer ID
     * 3. Signs the seed with master key (requires biometric auth)
     * 4. Derives key material using HKDF
     * 5. Generates EC P-256 key pair from derived material
     *
     * @param seed The credential seed (32 bytes)
     * @param credentialId The credential identifier
     * @param issuerId The issuer identifier (DID or URL)
     * @param credentialType The credential type
     * @param masterKey The master private key (from hardware keystore)
     * @return Derived EC key pair (P-256 curve)
     * @throws IllegalArgumentException if inputs are invalid
     * @throws RuntimeException if key derivation fails
     */
    public static KeyPair deriveBindingKey(byte[] seed, String credentialId, String issuerId,
                                          String credentialType, PrivateKey masterKey) {
        validateDerivationInputs(seed, credentialId, issuerId, credentialType, masterKey);
        
        try {
            byte[] salt = computeSalt(credentialId, issuerId);
            byte[] masterKeyDerivedMaterial = deriveMasterKeyMaterial(masterKey, seed);
            byte[] infoBytes = buildHkdfInfo(credentialType);
            byte[] keyMaterial = KeyUtils.hkdf(masterKeyDerivedMaterial, salt, infoBytes, KEY_LENGTH);
            KeyPair keyPair = generateECKeyPairFromSeed(keyMaterial);
            
            logger.debug("Derived EC binding key pair for credential {} (issuer: {})",
                        credentialId, issuerId);
            return keyPair;
        } catch (Exception e) {
            logger.error("Failed to derive binding key", e);
            throw new RuntimeException("Failed to derive binding key", e);
        }
    }
    
    /**
     * Validates all inputs for key derivation.
     *
     * @param seed The credential seed
     * @param credentialId The credential identifier
     * @param issuerId The issuer identifier
     * @param credentialType The credential type
     * @param masterKey The master private key
     * @throws IllegalArgumentException if any input is invalid
     */
    private static void validateDerivationInputs(byte[] seed, String credentialId,
                                                 String issuerId, String credentialType,
                                                 PrivateKey masterKey) {
        if (seed == null || seed.length != SEED_LENGTH) {
            throw new IllegalArgumentException("Seed must be " + SEED_LENGTH + " bytes");
        }
        if (credentialId == null || credentialId.isEmpty()) {
            throw new IllegalArgumentException("Credential ID cannot be null or empty");
        }
        if (issuerId == null || issuerId.isEmpty()) {
            throw new IllegalArgumentException("Issuer ID cannot be null or empty");
        }
        if (credentialType == null || credentialType.isEmpty()) {
            throw new IllegalArgumentException("Credential type cannot be null or empty");
        }
        if (masterKey == null) {
            throw new IllegalArgumentException("Master key cannot be null");
        }
    }
    
    /**
     * Derives deterministic key material from master key and seed using HMAC-SHA256.
     * This is deterministic unlike signing which uses random k-values in ECDSA.
     *
     * @param masterKey The master private key
     * @param seed The credential seed
     * @return Derived key material (32 bytes)
     * @throws Exception if HMAC derivation fails
     */
    private static byte[] deriveMasterKeyMaterial(PrivateKey masterKey, byte[] seed)
            throws Exception {
        byte[] masterKeyBytes = masterKey.getEncoded();
        if (masterKeyBytes == null) {
            throw new IllegalStateException("Master key encoding not available");
        }
        
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        javax.crypto.spec.SecretKeySpec keySpec =
            new javax.crypto.spec.SecretKeySpec(masterKeyBytes, "HmacSHA256");
        mac.init(keySpec);
        return mac.doFinal(seed);
    }
    
    /**
     * Builds the HKDF info parameter by concatenating the prefix with credential type.
     * Uses pre-computed prefix bytes for efficiency.
     *
     * @param credentialType The credential type
     * @return HKDF info bytes
     */
    private static byte[] buildHkdfInfo(String credentialType) {
        byte[] credentialTypeBytes = credentialType.getBytes(StandardCharsets.UTF_8);
        byte[] infoBytes = new byte[HKDF_INFO_PREFIX_BYTES.length + credentialTypeBytes.length];
        System.arraycopy(HKDF_INFO_PREFIX_BYTES, 0, infoBytes, 0, HKDF_INFO_PREFIX_BYTES.length);
        System.arraycopy(credentialTypeBytes, 0, infoBytes, HKDF_INFO_PREFIX_BYTES.length,
                        credentialTypeBytes.length);
        return infoBytes;
    }
    
    /**
     * Generates an EC P-256 key pair from seed material using BouncyCastle.
     * Uses the seed as the private key scalar and derives the public key via EC point multiplication.
     *
     * @param seed 32-byte seed material for private key
     * @return EC key pair on P-256 curve
     */
    private static KeyPair generateECKeyPairFromSeed(byte[] seed) {
        try {
            // Ensure BouncyCastle provider is available
            KeyUtils.ensureBouncyCastleProvider();
            
            // Get P-256 curve parameters from BouncyCastle
            ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
            
            // Convert seed to BigInteger for private key scalar
            BigInteger privateKeyScalar = new BigInteger(1, seed);
            
            // Ensure private key is within valid range [1, n-1] where n is the curve order
            BigInteger curveOrder = ecSpec.getN();
            privateKeyScalar = privateKeyScalar.mod(curveOrder);
            if (privateKeyScalar.equals(BigInteger.ZERO)) {
                privateKeyScalar = BigInteger.ONE;
            }
            
            // Derive public key by multiplying generator point by private key scalar
            // Public key = private_key * G (generator point)
            ECPoint publicPoint = ecSpec.getG().multiply(privateKeyScalar).normalize();
            
            // Create key specs
            ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(privateKeyScalar, ecSpec);
            ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(publicPoint, ecSpec);
            
            // Generate keys
            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
            
            return new KeyPair(publicKey, privateKey);
            
        } catch (Exception e) {
            logger.error("Failed to generate EC key pair from seed", e);
            throw new RuntimeException("Failed to generate EC key pair from seed", e);
        }
    }
    
    /**
     * Computes the salt for HKDF key derivation.
     * Salt = SHA-256(credential_id || issuer_id)
     * 
     * @param credentialId The credential identifier
     * @param issuerId The issuer identifier
     * @return 32-byte salt
     */
    private static byte[] computeSalt(String credentialId, String issuerId) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(credentialId.getBytes(StandardCharsets.UTF_8));
            digest.update(issuerId.getBytes(StandardCharsets.UTF_8));
            return digest.digest();
        } catch (Exception e) {
            logger.error("Failed to compute salt", e);
            throw new RuntimeException("Failed to compute salt", e);
        }
    }
    
    /**
     * Validates that a seed can be used for key derivation.
     * 
     * @param seed The seed to validate
     * @return true if seed is valid, false otherwise
     */
    public static boolean validateSeed(byte[] seed) {
        return seed != null && seed.length == SEED_LENGTH;
    }
    
    /**
     * Checks if the holder binding key manager is properly initialized.
     * 
     * @return true if keystore manager is set, false otherwise
     */
    public static boolean isInitialized() {
        return keystoreManager != null;
    }
    
    /**
     * Gets the expected seed length in bytes.
     * 
     * @return Seed length (32 bytes)
     */
    public static int getSeedLength() {
        return SEED_LENGTH;
    }
    
    /**
     * Gets the derived key length in bytes.
     * 
     * @return Key length (32 bytes)
     */
    public static int getKeyLength() {
        return KEY_LENGTH;
    }
}

// Made with Bob
