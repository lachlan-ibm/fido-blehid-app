/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.util;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;
import android.util.Log;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;

/**
 * Android-specific implementation of holder binding key management.
 * 
 * This class manages the master key in Android Keystore with the following properties:
 * - Hardware-backed (StrongBox if available, otherwise TEE)
 * - Requires biometric authentication for each use
 * - Never leaves the secure hardware
 * - Used to sign credential seeds for HKDF key derivation
 * 
 * The master key is a P-256 EC key with signing capability, protected by
 * biometric authentication that must be provided for each operation.
 */
public class AndroidHolderBindingKeyManager {
    
    private static final String TAG = "AndroidHolderBindingKeyManager";
    private static final String MASTER_KEY_ALIAS = "platform_key";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    
    /**
     * Generates or retrieves the master key from Android Keystore.
     * 
     * The key is generated with the following properties:
     * - Algorithm: EC (P-256 curve)
     * - Purpose: Sign and verify
     * - Digest: SHA-256 and SHA-512
     * - User authentication: Required for each use (timeout = 0)
     * - Authentication type: Biometric (strong)
     * - StrongBox backed: If available on device
     * 
     * @return The master private key
     * @throws RuntimeException if key generation or retrieval fails
     */
    public static PrivateKey getMasterKey() {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);
            
            // Check if key already exists
            if (keyStore.containsAlias(MASTER_KEY_ALIAS)) {
                Log.d(TAG, "Master key already exists, retrieving from keystore");
                return (PrivateKey) keyStore.getKey(MASTER_KEY_ALIAS, null);
            }
            
            // Generate new master key
            Log.i(TAG, "Generating new master key in Android Keystore");
            return generateMasterKey();
        } catch (Exception e) {
            Log.e(TAG, "Failed to get master key", e);
            throw new RuntimeException("Failed to get master key", e);
        }
    }
    
    /**
     * Generates a new master key in Android Keystore.
     * 
     * @return The generated private key
     * @throws Exception if key generation fails
     */
    private static PrivateKey generateMasterKey() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            ANDROID_KEYSTORE
        );
        
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
            MASTER_KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY
        )
        .setDigests(
            KeyProperties.DIGEST_SHA256,
            KeyProperties.DIGEST_SHA512
        )
        .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
        .setUserAuthenticationRequired(true);
        
        // Set biometric authentication requirement
        // Auth valid for this operation only (timeout = 0)
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(
                0,  // Auth valid for this operation only
                KeyProperties.AUTH_BIOMETRIC_STRONG
            );
        } else {
            throw new IllegalStateException(
                "Biometric authentication requires Android R (API 30) or higher. " +
                "Current API level: " + android.os.Build.VERSION.SDK_INT
            );
        }
        
        try {
            builder.setIsStrongBoxBacked(true);
            keyPairGenerator.initialize(builder.build());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            Log.i(TAG, "Master key generated successfully using StrongBox");
            return keyPair.getPrivate();
        } catch (StrongBoxUnavailableException e) {
            Log.w(TAG, "StrongBox not available, falling back to TEE", e);
            // Rebuild without StrongBox
            builder = new KeyGenParameterSpec.Builder(
                MASTER_KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN
            )
            .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true);
            
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
                builder.setUserAuthenticationParameters(
                    0,
                    KeyProperties.AUTH_BIOMETRIC_STRONG
                );
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate master key with StrongBox", e);
        }
        keyPairGenerator.initialize(builder.build());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        
        Log.i(TAG, "Master key generated successfully using TEE");
        return keyPair.getPrivate();
    }
    
    /**
     * Checks if the master key exists in the keystore.
     * 
     * @return true if master key exists, false otherwise
     */
    public static boolean masterKeyExists() {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);
            return keyStore.containsAlias(MASTER_KEY_ALIAS);
        } catch (Exception e) {
            Log.e(TAG, "Failed to check master key existence", e);
            return false;
        }
    }
    
    /**
     * Deletes the master key from the keystore.
     * WARNING: This will make all credentials using this master key unusable.
     * 
     * @return true if deletion was successful, false otherwise
     */
    public static boolean deleteMasterKey() {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);
            
            if (keyStore.containsAlias(MASTER_KEY_ALIAS)) {
                keyStore.deleteEntry(MASTER_KEY_ALIAS);
                Log.i(TAG, "Master key deleted");
                return true;
            }
            
            Log.w(TAG, "Master key does not exist");
            return false;
        } catch (Exception e) {
            Log.e(TAG, "Failed to delete master key", e);
            return false;
        }
    }
    
    /**
     * Gets information about the master key's security properties.
     * 
     * @return String describing the key's security properties
     */
    public static String getMasterKeyInfo() {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);
            
            if (!keyStore.containsAlias(MASTER_KEY_ALIAS)) {
                return "Master key does not exist";
            }
            
            StringBuilder info = new StringBuilder();
            info.append("Master Key Information:\n");
            info.append("- Alias: ").append(MASTER_KEY_ALIAS).append("\n");
            info.append("- Algorithm: EC (P-256)\n");
            info.append("- Purpose: Sign/Verify\n");
            info.append("- Authentication: Biometric (required per use)\n");
            
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                info.append("- Hardware: StrongBox or TEE\n");
            } else {
                info.append("- Hardware: TEE\n");
            }
            
            return info.toString();
        } catch (Exception e) {
            Log.e(TAG, "Failed to get master key info", e);
            return "Error retrieving master key info: " + e.getMessage();
        }
    }
    
    /**
     * Derives a holder binding key for a credential using the master key.
     * This is a convenience wrapper around HolderBindingKeyManager.deriveBindingKey()
     * that automatically retrieves the master key from Android Keystore.
     *
     * @param seed The credential seed (32 bytes)
     * @param salt The salt for key derivation (32 bytes) - not used in current implementation
     * @param issuerId The issuer identifier (DID or URL)
     * @param credentialType The credential type
     * @return Derived holder binding private key
     * @throws RuntimeException if key derivation fails
     */
    public static PrivateKey deriveHolderBindingKey(byte[] seed, byte[] salt,
                                                    String issuerId, String credentialType) {
        try {
            PrivateKey masterKey = getMasterKey();
            
            String credentialId = java.util.UUID.randomUUID().toString();
            
            KeyPair keyPair = HolderBindingKeyManager.deriveBindingKey(
                seed,
                credentialId,
                issuerId,
                credentialType,
                masterKey
            );
            
            return keyPair.getPrivate();
        } catch (Exception e) {
            Log.e(TAG, "Failed to derive holder binding key", e);
            throw new RuntimeException("Failed to derive holder binding key", e);
        }
    }
}

// Made with Bob
