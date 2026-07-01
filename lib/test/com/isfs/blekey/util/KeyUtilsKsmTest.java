/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.util;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Test suite for KeystoreManager integration methods in KeyUtils.
 * Tests ksmEncrypt and ksmDecrypt methods with mocked KeystoreManager.
 */
public class KeyUtilsKsmTest {

    @Mock
    private KeystoreManager mockKsm;
    
    private KeyPair testKeyPair;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        // Generate a test EC key pair
        testKeyPair = KeyUtils.generateKeyPair("EC", 256);
    }

    // ========== ksmEncrypt Tests ==========

    @Test
    public void testKsmEncrypt() throws Exception {
        byte[] plaintext = "sensitive data".getBytes(StandardCharsets.UTF_8);
        
        when(mockKsm.isKeystoreAvailable()).thenReturn(true);
        when(mockKsm.getEC256PublicKey()).thenReturn(testKeyPair.getPublic());
        
        byte[] result = KeyUtils.ksmEncrypt(plaintext, mockKsm);
        
        assertNotNull("Encrypted result should not be null", result);
        assertTrue("Encrypted data should be longer than plaintext", result.length > plaintext.length);
        verify(mockKsm).isKeystoreAvailable();
        verify(mockKsm).getEC256PublicKey();
    }

    @Test(expected = IOException.class)
    public void testKsmEncryptNullKeystoreManager() throws Exception {
        byte[] data = "test".getBytes(StandardCharsets.UTF_8);
        KeyUtils.ksmEncrypt(data, null);
    }

    @Test(expected = IOException.class)
    public void testKsmEncryptKeystoreNotAvailable() throws Exception {
        byte[] data = "test".getBytes(StandardCharsets.UTF_8);
        
        when(mockKsm.isKeystoreAvailable()).thenReturn(false);
        
        KeyUtils.ksmEncrypt(data, mockKsm);
    }

    @Test(expected = IOException.class)
    public void testKsmEncryptPublicKeyRetrievalFails() throws Exception {
        byte[] data = "test".getBytes(StandardCharsets.UTF_8);
        
        when(mockKsm.isKeystoreAvailable()).thenReturn(true);
        when(mockKsm.getEC256PublicKey()).thenThrow(new RuntimeException("Key retrieval failed"));
        
        KeyUtils.ksmEncrypt(data, mockKsm);
    }

    @Test
    public void testKsmEncryptEmptyData() throws Exception {
        byte[] emptyData = new byte[0];
        
        when(mockKsm.isKeystoreAvailable()).thenReturn(true);
        when(mockKsm.getEC256PublicKey()).thenReturn(testKeyPair.getPublic());
        
        byte[] result = KeyUtils.ksmEncrypt(emptyData, mockKsm);
        
        assertNotNull("Result should not be null even for empty data", result);
    }

    @Test
    public void testKsmEncryptLargeData() throws Exception {
        byte[] largeData = new byte[10000];
        for (int i = 0; i < largeData.length; i++) {
            largeData[i] = (byte) (i % 256);
        }
        
        when(mockKsm.isKeystoreAvailable()).thenReturn(true);
        when(mockKsm.getEC256PublicKey()).thenReturn(testKeyPair.getPublic());
        
        byte[] result = KeyUtils.ksmEncrypt(largeData, mockKsm);
        
        assertNotNull("Encrypted result should not be null", result);
        assertTrue("Encrypted data should be present", result.length > 0);
    }

    // ========== ksmDecrypt Tests ==========

    @Test
    public void testKsmDecrypt() throws Exception {
        byte[] plaintext = "decrypted data".getBytes(StandardCharsets.UTF_8);
        
        // First encrypt the data
        when(mockKsm.isKeystoreAvailable()).thenReturn(true);
        when(mockKsm.getEC256PublicKey()).thenReturn(testKeyPair.getPublic());
        byte[] ciphertext = KeyUtils.ksmEncrypt(plaintext, mockKsm);
        
        // Now decrypt it
        when(mockKsm.getEC256PrivateKey()).thenReturn(testKeyPair.getPrivate());
        
        byte[] result = KeyUtils.ksmDecrypt(ciphertext, mockKsm);
        
        assertNotNull("Decrypted result should not be null", result);
        assertArrayEquals("Decrypted data should match original plaintext", plaintext, result);
        verify(mockKsm, atLeastOnce()).isKeystoreAvailable();
        verify(mockKsm).getEC256PrivateKey();
    }

    @Test
    public void testKsmDecryptNullKeystoreManager() throws Exception {
        byte[] data = new byte[]{1, 2, 3};
        
        byte[] result = KeyUtils.ksmDecrypt(data, null);
        
        assertNull("Result should be null when KeystoreManager is null", result);
    }

    @Test
    public void testKsmDecryptKeystoreNotAvailable() throws Exception {
        byte[] data = new byte[]{1, 2, 3};
        
        when(mockKsm.isKeystoreAvailable()).thenReturn(false);
        
        byte[] result = KeyUtils.ksmDecrypt(data, mockKsm);
        
        assertNull("Result should be null when keystore is not available", result);
    }

    @Test
    public void testKsmDecryptPrivateKeyRetrievalFails() throws Exception {
        byte[] data = new byte[]{1, 2, 3};
        
        when(mockKsm.isKeystoreAvailable()).thenReturn(true);
        when(mockKsm.getEC256PrivateKey()).thenThrow(new RuntimeException("Key retrieval failed"));
        
        byte[] result = KeyUtils.ksmDecrypt(data, mockKsm);
        
        assertNull("Result should be null when private key retrieval fails", result);
    }

    @Test
    public void testKsmDecryptInvalidCiphertext() throws Exception {
        byte[] invalidCiphertext = new byte[]{1, 2, 3, 4, 5};
        
        when(mockKsm.isKeystoreAvailable()).thenReturn(true);
        when(mockKsm.getEC256PrivateKey()).thenReturn(testKeyPair.getPrivate());
        
        byte[] result = KeyUtils.ksmDecrypt(invalidCiphertext, mockKsm);
        
        assertNull("Result should be null for invalid ciphertext", result);
    }

    @Test
    public void testKsmEncryptDecryptRoundTrip() throws Exception {
        byte[] originalData = "Round trip test data".getBytes(StandardCharsets.UTF_8);
        
        // Encrypt
        when(mockKsm.isKeystoreAvailable()).thenReturn(true);
        when(mockKsm.getEC256PublicKey()).thenReturn(testKeyPair.getPublic());
        byte[] encrypted = KeyUtils.ksmEncrypt(originalData, mockKsm);
        
        // Decrypt
        when(mockKsm.getEC256PrivateKey()).thenReturn(testKeyPair.getPrivate());
        byte[] decrypted = KeyUtils.ksmDecrypt(encrypted, mockKsm);
        
        assertNotNull("Decrypted data should not be null", decrypted);
        assertArrayEquals("Round trip should preserve data", originalData, decrypted);
    }

    @Test
    public void testKsmEncryptDifferentDataProducesDifferentCiphertext() throws Exception {
        byte[] data1 = "data one".getBytes(StandardCharsets.UTF_8);
        byte[] data2 = "data two".getBytes(StandardCharsets.UTF_8);
        
        when(mockKsm.isKeystoreAvailable()).thenReturn(true);
        when(mockKsm.getEC256PublicKey()).thenReturn(testKeyPair.getPublic());
        
        byte[] encrypted1 = KeyUtils.ksmEncrypt(data1, mockKsm);
        byte[] encrypted2 = KeyUtils.ksmEncrypt(data2, mockKsm);
        
        assertFalse("Different plaintexts should produce different ciphertexts",
                    java.util.Arrays.equals(encrypted1, encrypted2));
    }

    @Test
    public void testKsmEncryptSameDataProducesDifferentCiphertext() throws Exception {
        byte[] data = "same data".getBytes(StandardCharsets.UTF_8);
        
        when(mockKsm.isKeystoreAvailable()).thenReturn(true);
        when(mockKsm.getEC256PublicKey()).thenReturn(testKeyPair.getPublic());
        
        byte[] encrypted1 = KeyUtils.ksmEncrypt(data, mockKsm);
        byte[] encrypted2 = KeyUtils.ksmEncrypt(data, mockKsm);
        
        assertFalse("Same plaintext should produce different ciphertexts due to random IV",
                    java.util.Arrays.equals(encrypted1, encrypted2));
    }
}

// Made with Bob
