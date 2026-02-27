/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.util;

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
     * Encrypts data using the application's master key.
     * The encryption should use authenticated encryption (e.g., AES-GCM)
     * to ensure both confidentiality and integrity.
     * 
     * @param data The plaintext data to encrypt
     * @return The encrypted data, including any necessary metadata (IV, tag, etc.)
     * @throws Exception if encryption fails
     */
    byte[] encryptWithAppKey(byte[] data) throws Exception;
    
    /**
     * Decrypts data that was encrypted with the application's master key.
     * 
     * @param encryptedData The encrypted data to decrypt
     * @return The decrypted plaintext data
     * @throws Exception if decryption fails (wrong key, corrupted data, etc.)
     */
    byte[] decryptWithAppKey(byte[] encryptedData) throws Exception;
    
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
}

// Made with Bob
