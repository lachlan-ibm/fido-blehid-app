/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.util;

import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.SecretKey;

/**
 * Platform-agnostic interface for secure key storage and encryption operations.
 * This interface allows different implementations for Android Keystore, Apple Keychain,
 * or other platform-specific secure storage mechanisms.
 *
 * Implementations should provide hardware-backed encryption when available,
 * with fallback to software-based encryption if necessary.
 */
public interface KeystoreManager {
    
    /**
     * Retrieves or creates the application's master encryption key.
     * This key is used to encrypt sensitive data like PIN hash components.
     *
     * @return The application's master SecretKey
     * @throws Exception if key generation or retrieval fails
     */
    SecretKey getOrCreateAppKey() throws Exception;
    
    /**
     * Retrieves or creates an EC256 (secp256r1/P-256) key pair for ECDH operations.
     * Returns the public key component.
     *
     * @return The EC256 public key
     * @throws Exception if key generation or retrieval fails
     */
    PublicKey getEC256PublicKey() throws Exception;
    
    /**
     * Retrieves or creates an EC256 (secp256r1/P-256) key pair for ECDH operations.
     * Returns the private key component.
     *
     * @return The EC256 private key
     * @throws Exception if key generation or retrieval fails
     */
    PrivateKey getEC256PrivateKey() throws Exception;
    
    /**
     * Checks if the keystore is available and functional on this platform.
     * 
     * @return true if the keystore is available, false otherwise
     */
    boolean isKeystoreAvailable();
    
    /**
     * Deletes the application's master key from the keystore.
     * This should be used with caution as it will make all encrypted data unrecoverable.
     *
     * @return true if the key was successfully deleted, false otherwise
     */
    boolean deleteAppKey();

    /**
     * Returns the biometric auth validity period in ms.
     * Implementations should return the value used when creating the EC256 key
     * (setUserAuthenticationValidityDurationSeconds × 1000).
     * Default is 15 000 ms (matches LOCK_TIMEOUT_MS) for non-Android environments.
     */
    default long getBiometricValidityMs() {
        return 15_000L;
    }
}

// Made with Bob
