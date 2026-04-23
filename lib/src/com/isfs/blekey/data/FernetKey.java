/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.data;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;

public class FernetKey {
    
    private static final byte VERSION = (byte) 0x80;
    private static final int HMAC_SIZE = 32;
    private static final int IV_SIZE = 16;
    private static final int TS_SIZE = 8;
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final long TOKEN_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days in seconds
    
    /**
     * Generate a new Fernet key (256 bits: 128 for signing, 128 for encryption)
     * 
     * @return Base64-encoded Fernet key
     */
    public static String generateSeed() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(key);
    }
    
    /**
     * Encrypt data using Fernet
     * 
     * @param keyString Base64-encoded Fernet key
     * @param data Data to encrypt
     * @return Base64-encoded Fernet token
     */
    public static String encrypt(String keyString, byte[] data) throws Exception {
        // Decode the key
        byte[] key = Base64.getUrlDecoder().decode(keyString);
        KeyComponents keyComponents = splitKey(key);
        
        // Generate IV
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        
        // Get current timestamp
        long timestamp = Instant.now().getEpochSecond();
        byte[] timestampBytes = ByteBuffer.allocate(TS_SIZE).putLong(timestamp).array();
        
        // Encrypt the data
        SecretKeySpec secretKey = new SecretKeySpec(keyComponents.encryptionKey, ENCRYPTION_ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
        byte[] ciphertext = cipher.doFinal(data);
        
        // Construct the token without HMAC
        ByteBuffer tokenBuffer = ByteBuffer.allocate(1 + TS_SIZE + IV_SIZE + ciphertext.length);
        tokenBuffer.put(VERSION);
        tokenBuffer.put(timestampBytes);
        tokenBuffer.put(iv);
        tokenBuffer.put(ciphertext);
        byte[] tokenWithoutHmac = tokenBuffer.array();
        
        // Calculate HMAC
        Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
        hmac.init(new SecretKeySpec(keyComponents.signingKey, HMAC_ALGORITHM));
        byte[] calculatedHmac = hmac.doFinal(tokenWithoutHmac);
        
        // Construct the final token
        ByteBuffer finalTokenBuffer = ByteBuffer.allocate(tokenWithoutHmac.length + HMAC_SIZE);
        finalTokenBuffer.put(tokenWithoutHmac);
        finalTokenBuffer.put(calculatedHmac);
        byte[] finalToken = finalTokenBuffer.array();
        
        // Encode to Base64
        return Base64.getUrlEncoder().withoutPadding().encodeToString(finalToken);
    }
    
    /**
     * Decrypt data using Fernet
     * 
     * @param keyString Base64-encoded Fernet key
     * @param tokenString Base64-encoded Fernet token
     * @return Decrypted data
     * @throws SecurityException if the token is invalid or expired
     * @throws IllegalArgumentException if inputs are malformed
     * @throws Exception if decryption fails
     */
    public static byte[] decrypt(String keyString, String tokenString) throws Exception {
        // Decode the key and token
        byte[] key = Base64.getUrlDecoder().decode(keyString);
        byte[] token = Base64.getUrlDecoder().decode(tokenString);
        
        // Split the key and extract token components
        KeyComponents keyComponents = splitKey(key);
        TokenComponents tokenComponents = extractTokenComponents(token);
        
        // Verify HMAC
        verifyHmac(keyComponents.signingKey, tokenComponents.tokenWithoutHmac, tokenComponents.hmac);
        
        // Validate timestamp
        validateTokenTimestamp(tokenComponents.timestampBytes);
        
        // Decrypt the data
        SecretKeySpec secretKey = new SecretKeySpec(keyComponents.encryptionKey, ENCRYPTION_ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(tokenComponents.iv));
        return cipher.doFinal(tokenComponents.ciphertext);
    }
    
    /**
     * Verify the HMAC signature of a token
     */
    private static void verifyHmac(byte[] signingKey, byte[] tokenWithoutHmac, byte[] providedHmac) throws Exception {
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(new SecretKeySpec(signingKey, HMAC_ALGORITHM));
        byte[] calculatedHmac = mac.doFinal(tokenWithoutHmac);
        
        if (!Arrays.equals(providedHmac, calculatedHmac)) {
            throw new SecurityException("Invalid HMAC signature");
        }
    }
    
    /**
     * Validate token timestamp is not expired
     */
    private static void validateTokenTimestamp(byte[] timestampBytes) {
        long timestamp = ByteBuffer.wrap(timestampBytes).getLong();
        long now = Instant.now().getEpochSecond();
        
        if (now - timestamp > TOKEN_TTL_SECONDS) {
            throw new SecurityException("Token expired");
        }
    }
    
    /**
     * Extract components from a Fernet token
     */
    private static TokenComponents extractTokenComponents(byte[] token) {
        if (token.length < 1 + TS_SIZE + IV_SIZE + HMAC_SIZE) {
            throw new IllegalArgumentException("Token too short");
        }
        
        // Check version
        if (token[0] != VERSION) {
            throw new IllegalArgumentException("Invalid token version");
        }
        
        // Extract HMAC
        byte[] hmac = Arrays.copyOfRange(token, token.length - HMAC_SIZE, token.length);
        byte[] tokenWithoutHmac = Arrays.copyOfRange(token, 0, token.length - HMAC_SIZE);
        
        // Extract timestamp, IV, and ciphertext
        byte[] timestampBytes = Arrays.copyOfRange(token, 1, 1 + TS_SIZE);
        byte[] iv = Arrays.copyOfRange(token, 1 + TS_SIZE, 1 + TS_SIZE + IV_SIZE);
        byte[] ciphertext = Arrays.copyOfRange(token, 1 + TS_SIZE + IV_SIZE, token.length - HMAC_SIZE);
        
        return new TokenComponents(hmac, tokenWithoutHmac, timestampBytes, iv, ciphertext);
    }
    
    /**
     * Split a Fernet key into signing and encryption keys
     */
    private static KeyComponents splitKey(byte[] key) {
        if (key.length != 32) {
            throw new IllegalArgumentException("Invalid key length");
        }
        
        byte[] signingKey = Arrays.copyOfRange(key, 0, 16);
        byte[] encryptionKey = Arrays.copyOfRange(key, 16, 32);
        
        return new KeyComponents(signingKey, encryptionKey);
    }
    
    /**
     * Helper class to hold token components
     */
    private static class TokenComponents {
        final byte[] hmac;
        final byte[] tokenWithoutHmac;
        final byte[] timestampBytes;
        final byte[] iv;
        final byte[] ciphertext;
        
        TokenComponents(byte[] hmac, byte[] tokenWithoutHmac, byte[] timestampBytes, byte[] iv, byte[] ciphertext) {
            this.hmac = hmac;
            this.tokenWithoutHmac = tokenWithoutHmac;
            this.timestampBytes = timestampBytes;
            this.iv = iv;
            this.ciphertext = ciphertext;
        }
    }
    
    /**
     * Helper class to hold key components
     */
    private static class KeyComponents {
        final byte[] signingKey;
        final byte[] encryptionKey;
        
        KeyComponents(byte[] signingKey, byte[] encryptionKey) {
            this.signingKey = signingKey;
            this.encryptionKey = encryptionKey;
        }
    }
}

// Made with Bob
