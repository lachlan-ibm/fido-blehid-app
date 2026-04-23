/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.data;

import org.junit.Test;
import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;

/**
 * Test for the SymmetricKey class
 */
public class SymmetricKeyTest {

    @Test
    public void testEncryptDecrypt() {
        // Generate a key
        String key = SymmetricKey.generateKey();
        SymmetricKey symmetricKey = new SymmetricKey(key);
        
        // Test data
        String originalMessage = "Hello, this is a test message!";
        byte[] originalData = originalMessage.getBytes(StandardCharsets.UTF_8);
        
        // Encrypt
        String token = symmetricKey.encrypt(originalData);
        assertNotNull("Token should not be null", token);
        
        // Decrypt
        byte[] decryptedData = symmetricKey.decrypt(token);
        assertNotNull("Decrypted data should not be null", decryptedData);
        
        // Verify
        String decryptedMessage = new String(decryptedData, StandardCharsets.UTF_8);
        assertEquals("Decrypted message should match original", originalMessage, decryptedMessage);
    }
    
    @Test
    public void testTTL() {
        // Generate a key
        String key = SymmetricKey.generateKey();
        SymmetricKey symmetricKey = new SymmetricKey(key);
        
        // Test data
        byte[] data = "TTL test".getBytes(StandardCharsets.UTF_8);
        
        // Encrypt
        String token = symmetricKey.encrypt(data);
        
        // Should decrypt with no TTL
        byte[] decrypted1 = symmetricKey.decrypt(token);
        assertNotNull(decrypted1);
        
        // Should decrypt with a large TTL
        byte[] decrypted2 = symmetricKey.decrypt(token, 3600L); // 1 hour
        assertNotNull(decrypted2);
        
        try {
            // Should fail with a very small TTL (0 seconds)
            symmetricKey.decrypt(token, 0L);
            fail("Should have thrown SecurityException for expired token");
        } catch (SecurityException e) {
            // Expected
            assertTrue(e.getMessage().contains("Token expired"));
        }
        //Should pass if this test takes > 1s
        assertNotNull(symmetricKey.decrypt(token, 1L));
    }
    
    @Test
    public void testInvalidToken() {
        // Generate a key
        String key = SymmetricKey.generateKey();
        SymmetricKey symmetricKey = new SymmetricKey(key);
        
        try {
            // Try to decrypt an invalid token
            symmetricKey.decrypt("invalidToken");
            fail("Should have thrown IllegalArgumentException for invalid token");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue(e.getMessage().contains("Invalid token"));
        }
    }
    
    @Test
    public void testWrongKey() {
        // Generate two different keys
        String key1 = SymmetricKey.generateKey();
        String key2 = SymmetricKey.generateKey();
        
        SymmetricKey symmetricKey1 = new SymmetricKey(key1);
        SymmetricKey symmetricKey2 = new SymmetricKey(key2);
        
        // Encrypt with key1
        byte[] data = "Secret message".getBytes(StandardCharsets.UTF_8);
        String token = symmetricKey1.encrypt(data);
        
        try {
            // Try to decrypt with key2
            symmetricKey2.decrypt(token);
            fail("Should have thrown SecurityException for authentication failure");
        } catch (SecurityException e) {
            // Expected
            assertTrue(e.getMessage().contains("Decryption failed"));
        }
    }
    
    @Test
    public void testKeyGeneration() {
        // Generate multiple keys and ensure they're different
        String key1 = SymmetricKey.generateKey();
        String key2 = SymmetricKey.generateKey();
        
        assertNotEquals("Generated keys should be different", key1, key2);
        
        // Decode and check length
        byte[] decodedKey = java.util.Base64.getUrlDecoder().decode(key1);
        assertEquals("Key should be 32 bytes", 32, decodedKey.length);
    }
}

// Made with Bob
