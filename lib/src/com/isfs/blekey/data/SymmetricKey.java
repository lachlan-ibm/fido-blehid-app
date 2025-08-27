/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.data;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;

/**
 * Custom implementation of symmetric encryption with AES-GCM.
 * This replaces the dependency on Fernet with a custom implementation.
 *
 * This implementation provides authenticated encryption that guarantees a message
 * cannot be manipulated or read without the key.
 * 
 * It has also replaced the Fernet schema AES-CBC-HMAC-SHA256 with AES-GCM.
 * 
 * The ciphertext is encrypted using AES-GCM with a 128-bit key.
 * The authentication tag is appended to the ciphertext.
 * The timestamp is used to prevent replay attacks.
 * The nonce is used to prevent identical ciphertexts from being generated.
 * 
 * The token is encoded as Base64.
 */
public class SymmetricKey {
    
    // Version byte for our GCM-based tokens (different from standard Fernet)
    private static final byte VERSION = (byte) 0x81;  // Using 0x81 to distinguish from standard Fernet's 0x80
    
    // Constants for token structure
    private static final int GCM_TAG_SIZE = 16;  // GCM authentication tag size in bytes
    private static final int GCM_NONCE_SIZE = 12;  // Recommended nonce size for GCM
    private static final int TS_SIZE = 8;  // Timestamp size in bytes
    
    // Minimum token size: Version (1) + Timestamp (8) + Nonce (12) + Tag (16) + min ciphertext (1)
    private static final int MIN_TOKEN_SIZE = 38;
    
    // Crypto parameters
    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_AUTH_TAG_LENGTH = 128;  // Authentication tag length in bits
    
    // The encryption key
    private final byte[] key;
    
    /**
     * Initialize with a symmetric key.
     *
     * @param key A 32-byte key or a URL-safe base64-encoded 32-byte key.
     *           Used for both encryption and authentication in GCM mode.
     * @throws IllegalArgumentException if the key is not 32 bytes
     */
    public SymmetricKey(String key) {
        byte[] decodedKey;
        
        try {
            decodedKey = Base64.getUrlDecoder().decode(key);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid key: base64 decoding failed", e);
        }
        
        if (decodedKey.length != 32) {
            throw new IllegalArgumentException(
                "Symmetric key must be 32 bytes (URL-safe base64-encoded)."
            );
        }
        
        this.key = decodedKey;
    }
    
    /**
     * Initialize with a raw byte array key.
     *
     * @param key A 32-byte key.
     * @throws IllegalArgumentException if the key is not 32 bytes
     */
    public SymmetricKey(byte[] key) {
        if (key.length != 32) {
            throw new IllegalArgumentException(
                "Symmetric key must be 32 bytes."
            );
        }
        
        this.key = Arrays.copyOf(key, key.length);
    }
    
    /**
     * Generates a new symmetric key.
     *
     * @return A URL-safe base64-encoded 32-byte key.
     */
    public static String generateKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(key);
    }
    
    /**
     * Encrypts data using AES-GCM.
     *
     * @param data The data to encrypt.
     * @return The encrypted token as a URL-safe base64-encoded string.
     * @throws IllegalArgumentException if data is null
     * @throws RuntimeException if encryption fails
     */
    public String encrypt(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Data must not be null.");
        }
        
        try {
            // Current time in seconds since the epoch
            long currentTime = Instant.now().getEpochSecond();
            byte[] timestampBytes = ByteBuffer.allocate(TS_SIZE).putLong(currentTime).array();
            
            // Generate a random 96-bit nonce (recommended size for GCM)
            byte[] nonce = new byte[GCM_NONCE_SIZE];
            new SecureRandom().nextBytes(nonce);
            
            // Initialize cipher with AES-GCM
            SecretKey secretKey = new SecretKeySpec(key, ENCRYPTION_ALGORITHM);
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_AUTH_TAG_LENGTH, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
            
            // Include timestamp in the associated data for authentication
            cipher.updateAAD(timestampBytes);
            
            // Encrypt the data (no padding needed with GCM)
            byte[] ciphertext = cipher.doFinal(data);
            
            // Format: Version (0x81) || Timestamp (8 bytes) || Nonce (12 bytes) || Ciphertext+Tag
            // Note: In Java, the GCM tag is appended to the ciphertext by the cipher.doFinal() method
            ByteBuffer tokenBuffer = ByteBuffer.allocate(1 + TS_SIZE + GCM_NONCE_SIZE + ciphertext.length);
            tokenBuffer.put(VERSION);
            tokenBuffer.put(timestampBytes);
            tokenBuffer.put(nonce);
            tokenBuffer.put(ciphertext);
            
            // Return URL-safe base64 encoded token
            return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBuffer.array());
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    /**
     * Parse a token into its components.
     *
     * @param tokenBytes Raw bytes of the token after base64 decoding
     * @return TokenComponents object containing the parsed components
     * @throws IllegalArgumentException if the token format is invalid
     */
    private TokenComponents parseToken(byte[] tokenBytes) {
        if (tokenBytes.length < MIN_TOKEN_SIZE) {
            throw new IllegalArgumentException(
                "Token too short: " + tokenBytes.length + " bytes, minimum is " + MIN_TOKEN_SIZE
            );
        }
        
        // Extract parts
        byte version = tokenBytes[0];
        byte[] timestampBytes = Arrays.copyOfRange(tokenBytes, 1, 1 + TS_SIZE);
        byte[] nonce = Arrays.copyOfRange(tokenBytes, 1 + TS_SIZE, 1 + TS_SIZE + GCM_NONCE_SIZE);
        byte[] ciphertext = Arrays.copyOfRange(tokenBytes, 1 + TS_SIZE + GCM_NONCE_SIZE, tokenBytes.length);
        
        // Verify version
        if (version != VERSION) {
            throw new IllegalArgumentException(
                "Invalid token version: " + version + ", expected " + VERSION
            );
        }
        
        return new TokenComponents(version, timestampBytes, nonce, ciphertext);
    }
    
    /**
     * Verify that a token's timestamp is within the TTL.
     *
     * @param timestampBytes 8-byte timestamp from the token
     * @param ttl Time-to-live in seconds
     * @throws SecurityException if the token has expired
     */
    private void verifyTimestamp(byte[] timestampBytes, Long ttl) {
        if (ttl == null) {
            return;
        }
        
        long timestamp = ByteBuffer.wrap(timestampBytes).getLong();
        long currentTime = Instant.now().getEpochSecond();
        
        if (currentTime - timestamp > ttl) {
            long age = currentTime - timestamp;
            throw new SecurityException("Token expired: token is " + age + 
                " seconds old, but TTL is " + ttl);
        }
    }

    /**
     * Decrypts a token.
     *
     * @param token The token to decrypt.
     * @param ttl Time-to-live in seconds. If the token is older than this, decryption will fail.
     *            If null, no TTL check is performed.
     * @return The decrypted data.
     * @throws IllegalArgumentException if the token is invalid
     * @throws SecurityException if the token is expired or cannot be authenticated
     * @throws RuntimeException if decryption fails
     */
    public byte[] decrypt(String token, Long ttl) {
        if (token == null) {
            throw new IllegalArgumentException("Token must not be null.");
        }
        return decrypt(Base64.getUrlDecoder().decode(token), ttl);
    }

    public byte[] decrypt(byte[] data, Long ttl) {
        try {
            // Parse the token into its components
            TokenComponents components = parseToken(data);
            
            // Verify timestamp if TTL is provided
            verifyTimestamp(components.timestampBytes, ttl);
            
            // Decrypt the ciphertext with AES-GCM
            try {
                SecretKey secretKey = new SecretKeySpec(key, ENCRYPTION_ALGORITHM);
                Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
                GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_AUTH_TAG_LENGTH, components.nonce);
                cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
                
                // Include timestamp in the associated data for authentication
                cipher.updateAAD(components.timestampBytes);
                
                // Decrypt and verify the ciphertext
                return cipher.doFinal(components.ciphertext);
            } catch (Exception e) {
                throw new SecurityException("Decryption failed: " + e.getMessage(), e);
            }
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid token: base64 decoding failed", e);
        }
    }
    
    /**
     * Decrypts a token with no TTL check.
     *
     * @param token The token to decrypt.
     * @return The decrypted data.
     * @throws IllegalArgumentException if the token is invalid
     * @throws SecurityException if the token cannot be authenticated
     * @throws RuntimeException if decryption fails
     */
    public byte[] decrypt(String token) {
        return decrypt(token, null);
    }
    
    /**
     * Helper class to hold token components
     */
    private static class TokenComponents {
        final byte version;
        final byte[] timestampBytes;
        final byte[] nonce;
        final byte[] ciphertext;
        
        TokenComponents(byte version, byte[] timestampBytes, byte[] nonce, byte[] ciphertext) {
            this.version = version;
            this.timestampBytes = timestampBytes;
            this.nonce = nonce;
            this.ciphertext = ciphertext;
        }
    }
}

// Made with Bob