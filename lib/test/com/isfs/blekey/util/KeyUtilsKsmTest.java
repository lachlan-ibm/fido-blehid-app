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

import com.isfs.blekey.data.StashCipher;

/**
 * Test suite for KSM-backed stash encryption via StashCipher.
 *
 * The ksmEncrypt/ksmDecrypt methods were removed from KeyUtils during refactoring;
 * the equivalent logic now lives in StashCipher (TeeStashCipher path), which is
 * obtained via StashCipher.create(ksm, null, null) when the KSM is available.
 */
public class KeyUtilsKsmTest {

    @Mock
    private KeystoreManager mockKsm;

    private KeyPair testKeyPair;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        testKeyPair = KeyUtils.generateKeyPair("EC", 256);
    }

    // ========== encrypt Tests ==========

    @Test
    public void testKsmEncrypt() throws Exception {
        byte[] plaintext = "sensitive data".getBytes(StandardCharsets.UTF_8);

        when(mockKsm.isKeystoreAvailable()).thenReturn(true);
        when(mockKsm.getEC256PublicKey()).thenReturn(testKeyPair.getPublic());

        StashCipher cipher = StashCipher.create(mockKsm, null, null);
        byte[] result = cipher.encrypt(plaintext);

        assertNotNull("Encrypted result should not be null", result);
        assertTrue("Encrypted data should be longer than plaintext", result.length > plaintext.length);
        verify(mockKsm).isKeystoreAvailable();
        verify(mockKsm).getEC256PublicKey();
    }

    @Test(expected = IOException.class)
    public void testKsmEncryptPublicKeyRetrievalFails() throws Exception {
        byte[] data = "test".getBytes(StandardCharsets.UTF_8);

        when(mockKsm.isKeystoreAvailable()).thenReturn(true);
        when(mockKsm.getEC256PublicKey()).thenThrow(new RuntimeException("Key retrieval failed"));

        StashCipher cipher = StashCipher.create(mockKsm, null, null);
        cipher.encrypt(data);
    }

    @Test
    public void testKsmEncryptEmptyData() throws Exception {
        byte[] emptyData = new byte[0];

        when(mockKsm.isKeystoreAvailable()).thenReturn(true);
        when(mockKsm.getEC256PublicKey()).thenReturn(testKeyPair.getPublic());

        StashCipher cipher = StashCipher.create(mockKsm, null, null);
        byte[] result = cipher.encrypt(emptyData);

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

        StashCipher cipher = StashCipher.create(mockKsm, null, null);
        byte[] result = cipher.encrypt(largeData);

        assertNotNull("Encrypted result should not be null", result);
        assertTrue("Encrypted data should be present", result.length > 0);
    }

    // ========== decrypt Tests ==========

    @Test
    public void testKsmDecrypt() throws Exception {
        byte[] plaintext = "decrypted data".getBytes(StandardCharsets.UTF_8);

        // Encrypt first
        when(mockKsm.isKeystoreAvailable()).thenReturn(true);
        when(mockKsm.getEC256PublicKey()).thenReturn(testKeyPair.getPublic());
        StashCipher cipher = StashCipher.create(mockKsm, null, null);
        byte[] ciphertext = cipher.encrypt(plaintext);

        // Now decrypt
        when(mockKsm.getEC256PrivateKey()).thenReturn(testKeyPair.getPrivate());
        byte[] result = cipher.decrypt(ciphertext);

        assertNotNull("Decrypted result should not be null", result);
        assertArrayEquals("Decrypted data should match original plaintext", plaintext, result);
        verify(mockKsm, atLeastOnce()).isKeystoreAvailable();
        verify(mockKsm).getEC256PrivateKey();
    }

    @Test
    public void testKsmDecryptPrivateKeyRetrievalFails() throws Exception {
        byte[] data = new byte[]{1, 2, 3};

        when(mockKsm.isKeystoreAvailable()).thenReturn(true);
        when(mockKsm.getEC256PrivateKey()).thenThrow(new RuntimeException("Key retrieval failed"));

        StashCipher cipher = StashCipher.create(mockKsm, null, null);
        try {
            cipher.decrypt(data);
            fail("Expected exception when private key retrieval fails");
        } catch (Exception e) {
            // expected
        }
    }

    @Test
    public void testKsmDecryptInvalidCiphertext() throws Exception {
        byte[] invalidCiphertext = new byte[]{1, 2, 3, 4, 5};

        when(mockKsm.isKeystoreAvailable()).thenReturn(true);
        when(mockKsm.getEC256PrivateKey()).thenReturn(testKeyPair.getPrivate());

        StashCipher cipher = StashCipher.create(mockKsm, null, null);
        try {
            cipher.decrypt(invalidCiphertext);
            fail("Expected exception for invalid ciphertext");
        } catch (Exception e) {
            // expected
        }
    }

    @Test
    public void testKsmEncryptDecryptRoundTrip() throws Exception {
        byte[] originalData = "Round trip test data".getBytes(StandardCharsets.UTF_8);

        when(mockKsm.isKeystoreAvailable()).thenReturn(true);
        when(mockKsm.getEC256PublicKey()).thenReturn(testKeyPair.getPublic());
        when(mockKsm.getEC256PrivateKey()).thenReturn(testKeyPair.getPrivate());

        StashCipher cipher = StashCipher.create(mockKsm, null, null);
        byte[] encrypted = cipher.encrypt(originalData);
        byte[] decrypted = cipher.decrypt(encrypted);

        assertNotNull("Decrypted data should not be null", decrypted);
        assertArrayEquals("Round trip should preserve data", originalData, decrypted);
    }

    @Test
    public void testKsmEncryptDifferentDataProducesDifferentCiphertext() throws Exception {
        byte[] data1 = "data one".getBytes(StandardCharsets.UTF_8);
        byte[] data2 = "data two".getBytes(StandardCharsets.UTF_8);

        when(mockKsm.isKeystoreAvailable()).thenReturn(true);
        when(mockKsm.getEC256PublicKey()).thenReturn(testKeyPair.getPublic());

        StashCipher cipher = StashCipher.create(mockKsm, null, null);
        byte[] encrypted1 = cipher.encrypt(data1);
        byte[] encrypted2 = cipher.encrypt(data2);

        assertFalse("Different plaintexts should produce different ciphertexts",
                java.util.Arrays.equals(encrypted1, encrypted2));
    }

    @Test
    public void testKsmEncryptSameDataProducesDifferentCiphertext() throws Exception {
        byte[] data = "same data".getBytes(StandardCharsets.UTF_8);

        when(mockKsm.isKeystoreAvailable()).thenReturn(true);
        when(mockKsm.getEC256PublicKey()).thenReturn(testKeyPair.getPublic());

        StashCipher cipher = StashCipher.create(mockKsm, null, null);
        byte[] encrypted1 = cipher.encrypt(data);
        byte[] encrypted2 = cipher.encrypt(data);

        assertFalse("Same plaintext should produce different ciphertexts due to random IV",
                java.util.Arrays.equals(encrypted1, encrypted2));
    }
}

// Made with Bob
