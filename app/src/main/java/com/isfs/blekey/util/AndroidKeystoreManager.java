/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.util;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.security.KeyStore;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Android implementation of KeystoreManager using Android Keystore System.
 * Provides secure storage and encryption using hardware-backed keys when available.
 */
public class AndroidKeystoreManager implements KeystoreManager {
    
    private static final Logger logger = LoggerFactory.getLogger(AndroidKeystoreManager.class);
    
    private static final String KEYSTORE_ALIAS = "fido2_app_key";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    
    /**
     * Gets or creates the app key from Android Keystore.
     * This key is used to encrypt U2F credential keys and cache PIN hash.
     *
     * The key is hardware-backed on supported devices, providing additional security.
     * On devices without hardware keystore, it falls back to software implementation.
     *
     * @return The app key from Android Keystore
     * @throws Exception if key generation or retrieval fails
     */
    @Override
    public SecretKey getOrCreateAppKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);
        
        if (!keyStore.containsAlias(KEYSTORE_ALIAS)) {
            logger.info("App key not found, generating new key in Android Keystore");
            
            // Generate new AES-256 key
            KeyGenerator keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE);
            
            KeyGenParameterSpec keySpec = new KeyGenParameterSpec.Builder(
                KEYSTORE_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(false) // App key doesn't require user auth
                .setRandomizedEncryptionRequired(true) // Use random IV for each encryption
                .build();
            
            keyGenerator.init(keySpec);
            keyGenerator.generateKey();
            
            logger.info("Successfully generated new app key in Android Keystore");
        } else {
            logger.debug("Using existing app key from Android Keystore");
        }
        
        return (SecretKey) keyStore.getKey(KEYSTORE_ALIAS, null);
    }
    
    /**
     * Encrypts data using the app key with AES-GCM.
     * The IV is prepended to the encrypted data for later decryption.
     * 
     * Format: [12-byte IV][encrypted data with 16-byte auth tag]
     *
     * @param data The plaintext data to encrypt
     * @return The encrypted data with IV prepended
     * @throws Exception if encryption fails
     */
    @Override
    public byte[] encryptWithAppKey(byte[] data) throws Exception {
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Data to encrypt cannot be null or empty");
        }
        
        SecretKey key = getOrCreateAppKey();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        
        byte[] iv = cipher.getIV();
        byte[] encrypted = cipher.doFinal(data);
        
        // Prepend IV to encrypted data
        byte[] result = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
        
        logger.debug("Encrypted {} bytes to {} bytes (including IV)", data.length, result.length);
        return result;
    }
    
    /**
     * Decrypts data using the app key with AES-GCM.
     * Expects the IV to be prepended to the encrypted data.
     *
     * @param encryptedData The encrypted data with IV prepended
     * @return The decrypted plaintext data
     * @throws Exception if decryption fails or data is invalid
     */
    @Override
    public byte[] decryptWithAppKey(byte[] encryptedData) throws Exception {
        if (encryptedData == null || encryptedData.length <= GCM_IV_LENGTH) {
            throw new IllegalArgumentException("Encrypted data is invalid or too short");
        }
        
        SecretKey key = getOrCreateAppKey();
        
        // Extract IV (first 12 bytes for GCM)
        byte[] iv = new byte[GCM_IV_LENGTH];
        byte[] encrypted = new byte[encryptedData.length - GCM_IV_LENGTH];
        System.arraycopy(encryptedData, 0, iv, 0, GCM_IV_LENGTH);
        System.arraycopy(encryptedData, GCM_IV_LENGTH, encrypted, 0, encrypted.length);
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
        
        byte[] decrypted = cipher.doFinal(encrypted);
        logger.debug("Decrypted {} bytes to {} bytes", encryptedData.length, decrypted.length);
        
        return decrypted;
    }
    
    /**
     * Checks if the Android Keystore is available and functional.
     * This can be used to determine if hardware-backed security is available.
     *
     * @return true if Android Keystore is available
     */
    @Override
    public boolean isKeystoreAvailable() {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);
            return true;
        } catch (Exception e) {
            logger.warn("Android Keystore not available: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * Deletes the app key from Android Keystore.
     * This should only be used during testing or when resetting the authenticator.
     *
     * @return true if the key was deleted or didn't exist
     */
    @Override
    public boolean deleteAppKey() {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);
            
            if (keyStore.containsAlias(KEYSTORE_ALIAS)) {
                keyStore.deleteEntry(KEYSTORE_ALIAS);
                logger.info("Deleted app key from Android Keystore");
                return true;
            }
            
            logger.debug("App key not found in Android Keystore");
            return true;
        } catch (Exception e) {
            logger.error("Failed to delete app key: {}", e.getMessage(), e);
            return false;
        }
    }
}

// Made with Bob