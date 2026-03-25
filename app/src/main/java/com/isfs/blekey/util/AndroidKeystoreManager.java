/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.util;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.security.KeyStore;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Android implementation of KeystoreManager using Android Keystore System.
 * Uses EC256 (ECDSA P-256) keys for FIDO2 compatibility and ECDH for encryption.
 */
public class AndroidKeystoreManager implements KeystoreManager {
    
    private static final Logger logger = LoggerFactory.getLogger(AndroidKeystoreManager.class);
    
    private static final String EC_KEYSTORE_ALIAS = "fido2_platform_key";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";

    /**
     * Gets or creates an EC256 key pair from Android Keystore.
     * This uses ECDSA with P-256 curve, which is compatible with FIDO2.
     *
     * @return The EC256 key pair from Android Keystore
     * @throws Exception if key generation or retrieval fails
     */
    public KeyPair getOrCreateEC256KeyPair() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);
        
        if (!keyStore.containsAlias(EC_KEYSTORE_ALIAS)) {
            logger.info("EC256 key not found, generating new key pair in Android Keystore");
            
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE);
            
            KeyGenParameterSpec keySpec = new KeyGenParameterSpec.Builder(
                EC_KEYSTORE_ALIAS,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY | KeyProperties.PURPOSE_AGREE_KEY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1")) // P-256 curve
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setUserAuthenticationRequired(false)
                .build();
            
            keyPairGenerator.initialize(keySpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            
            logger.info("Successfully generated new EC256 key pair in Android Keystore");
            return keyPair;
        } else {
            logger.debug("Using existing EC256 key pair from Android Keystore");
        }
        
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(EC_KEYSTORE_ALIAS, null);
        PublicKey publicKey = keyStore.getCertificate(EC_KEYSTORE_ALIAS).getPublicKey();
        
        return new KeyPair(publicKey, privateKey);
    }
    
    /**
     * Gets the public key from the EC256 key pair.
     *
     * @return The EC256 public key
     * @throws Exception if key retrieval fails
     */
    public PublicKey getEC256PublicKey() throws Exception {
        return getOrCreateEC256KeyPair().getPublic();
    }
    
    /**
     * Gets the private key from the EC256 key pair.
     *
     * @return The EC256 private key
     * @throws Exception if key retrieval fails
     */
    public PrivateKey getEC256PrivateKey() throws Exception {
        return getOrCreateEC256KeyPair().getPrivate();
    }
    
    /**
     * Legacy method for compatibility - not used with EC keys.
     * @deprecated Use getOrCreateEC256KeyPair() instead
     */
    @Override
    @Deprecated
    public javax.crypto.SecretKey getOrCreateAppKey() throws Exception {
        throw new UnsupportedOperationException("Use EC256 key pair methods instead");
    }
    
    /**
     * Checks if the Android Keystore is available and functional.
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
     * Deletes the EC256 key pair from Android Keystore.
     *
     * @return true if the key was deleted or didn't exist
     */
    @Override
    public boolean deleteAppKey() {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);
            
            if (keyStore.containsAlias(EC_KEYSTORE_ALIAS)) {
                keyStore.deleteEntry(EC_KEYSTORE_ALIAS);
                logger.info("Deleted EC256 key pair from Android Keystore");
                return true;
            }
            
            logger.debug("EC256 key pair not found in Android Keystore");
            return true;
        } catch (Exception e) {
            logger.error("Failed to delete EC256 key pair: {}", e.getMessage(), e);
            return false;
        }
    }
}

// Made with Bob