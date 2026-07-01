/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.util;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Signature;

/**
 * Test suite for signature operations in KeyUtils.
 * Tests the sign() method with different key types and error conditions.
 */
public class KeyUtilsSignatureTest {

    private KeyPair ecKeyPair;
    private KeyPair rsaKeyPair;
    private KeyPair ed25519KeyPair;
    private byte[] testData;

    @Before
    public void setUp() throws Exception {
        ecKeyPair = KeyUtils.generateKeyPair("EC", 256);
        rsaKeyPair = KeyUtils.generateKeyPair("RSA", 2048);
        ed25519KeyPair = KeyUtils.generateKeyPair("Ed25519", 256);
        testData = "data to sign".getBytes(StandardCharsets.UTF_8);
    }

    // ========== Basic Signing Tests ==========

    @Test
    public void testSignWithECKey() throws Exception {
        byte[] signature = KeyUtils.sign(testData, ecKeyPair.getPrivate());
        
        assertNotNull("Signature should not be null", signature);
        assertTrue("Signature should have content", signature.length > 0);
        
        // Verify the signature
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(ecKeyPair.getPublic());
        verifier.update(testData);
        assertTrue("Signature should be valid", verifier.verify(signature));
    }

    @Test
    public void testSignWithRSAKey() throws Exception {
        byte[] signature = KeyUtils.sign(testData, rsaKeyPair.getPrivate());
        
        assertNotNull("Signature should not be null", signature);
        assertTrue("Signature should have content", signature.length > 0);
        
        // Verify the signature
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(rsaKeyPair.getPublic());
        verifier.update(testData);
        assertTrue("Signature should be valid", verifier.verify(signature));
    }

    @Test
    public void testSignWithEd25519Key() throws Exception {
        // Ed25519 is not currently supported by the sign() method
        // This test verifies that it throws an appropriate exception
        try {
            KeyUtils.sign(testData, ed25519KeyPair.getPrivate());
            fail("Should throw exception for Ed25519 key");
        } catch (RuntimeException e) {
            // Expected - Ed25519 not supported in sign() method
            assertTrue("Exception message should indicate signing failed",
                      e.getMessage().contains("Signing failed"));
        }
    }

    // ========== Null Input Tests ==========

    @Test(expected = IllegalArgumentException.class)
    public void testSignNullData() throws Exception {
        KeyUtils.sign(null, ecKeyPair.getPrivate());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSignEmptyData() throws Exception {
        byte[] emptyData = new byte[0];
        KeyUtils.sign(emptyData, ecKeyPair.getPrivate());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSignNullKey() throws Exception {
        KeyUtils.sign(testData, null);
    }

    // ========== Different Data Sizes ==========

    @Test
    public void testSignSmallData() throws Exception {
        byte[] smallData = new byte[]{0x01};
        
        byte[] signature = KeyUtils.sign(smallData, ecKeyPair.getPrivate());
        
        assertNotNull("Signature should not be null", signature);
        assertTrue("Signature should have content", signature.length > 0);
    }

    @Test
    public void testSignLargeData() throws Exception {
        byte[] largeData = new byte[10000];
        for (int i = 0; i < largeData.length; i++) {
            largeData[i] = (byte) (i % 256);
        }
        
        byte[] signature = KeyUtils.sign(largeData, ecKeyPair.getPrivate());
        
        assertNotNull("Signature should not be null", signature);
        assertTrue("Signature should have content", signature.length > 0);
    }

    // ========== Signature Uniqueness ==========

    @Test
    public void testSignDifferentDataProducesDifferentSignatures() throws Exception {
        byte[] data1 = "data one".getBytes(StandardCharsets.UTF_8);
        byte[] data2 = "data two".getBytes(StandardCharsets.UTF_8);
        
        byte[] signature1 = KeyUtils.sign(data1, ecKeyPair.getPrivate());
        byte[] signature2 = KeyUtils.sign(data2, ecKeyPair.getPrivate());
        
        assertFalse("Different data should produce different signatures",
                    java.util.Arrays.equals(signature1, signature2));
    }

    @Test
    public void testSignDifferentKeysProduceDifferentSignatures() throws Exception {
        KeyPair anotherEcKeyPair = KeyUtils.generateKeyPair("EC", 256);
        
        byte[] signature1 = KeyUtils.sign(testData, ecKeyPair.getPrivate());
        byte[] signature2 = KeyUtils.sign(testData, anotherEcKeyPair.getPrivate());
        
        assertFalse("Different keys should produce different signatures",
                    java.util.Arrays.equals(signature1, signature2));
    }

    // ========== Signature Verification ==========

    @Test
    public void testSignatureVerificationWithCorrectKey() throws Exception {
        byte[] signature = KeyUtils.sign(testData, ecKeyPair.getPrivate());
        
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(ecKeyPair.getPublic());
        verifier.update(testData);
        
        assertTrue("Signature should verify with correct public key", verifier.verify(signature));
    }

    @Test
    public void testSignatureVerificationWithWrongKey() throws Exception {
        KeyPair wrongKeyPair = KeyUtils.generateKeyPair("EC", 256);
        byte[] signature = KeyUtils.sign(testData, ecKeyPair.getPrivate());
        
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(wrongKeyPair.getPublic());
        verifier.update(testData);
        
        assertFalse("Signature should not verify with wrong public key", verifier.verify(signature));
    }

    @Test
    public void testSignatureVerificationWithModifiedData() throws Exception {
        byte[] signature = KeyUtils.sign(testData, ecKeyPair.getPrivate());
        byte[] modifiedData = "modified data".getBytes(StandardCharsets.UTF_8);
        
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(ecKeyPair.getPublic());
        verifier.update(modifiedData);
        
        assertFalse("Signature should not verify with modified data", verifier.verify(signature));
    }

    // ========== Unsupported Algorithm Test ==========

    @Test(expected = RuntimeException.class)
    public void testSignUnsupportedAlgorithm() throws Exception {
        PrivateKey mockKey = mock(PrivateKey.class);
        when(mockKey.getAlgorithm()).thenReturn("UNSUPPORTED");
        
        KeyUtils.sign(testData, mockKey);
    }

    // ========== Determinism Tests ==========

    @Test
    public void testSignDeterministicForECDSA() throws Exception {
        // Note: ECDSA signatures include randomness, so same data/key produces different signatures
        byte[] signature1 = KeyUtils.sign(testData, ecKeyPair.getPrivate());
        byte[] signature2 = KeyUtils.sign(testData, ecKeyPair.getPrivate());
        
        // Both should be valid even if different
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        
        verifier.initVerify(ecKeyPair.getPublic());
        verifier.update(testData);
        assertTrue("First signature should be valid", verifier.verify(signature1));
        
        verifier.initVerify(ecKeyPair.getPublic());
        verifier.update(testData);
        assertTrue("Second signature should be valid", verifier.verify(signature2));
    }

    // ========== Cross-Algorithm Tests ==========

    @Test
    public void testSignWithMultipleAlgorithms() throws Exception {
        byte[] ecSignature = KeyUtils.sign(testData, ecKeyPair.getPrivate());
        byte[] rsaSignature = KeyUtils.sign(testData, rsaKeyPair.getPrivate());
        
        assertNotNull("EC signature should not be null", ecSignature);
        assertNotNull("RSA signature should not be null", rsaSignature);
        
        // Signatures should be different due to different algorithms
        assertFalse("Different algorithms should produce different signatures",
                    java.util.Arrays.equals(ecSignature, rsaSignature));
    }

    // ========== Special Characters in Data ==========

    @Test
    public void testSignWithSpecialCharacters() throws Exception {
        byte[] specialData = new byte[]{0x00, 0x01, (byte) 0xFF, (byte) 0xFE, 0x7F, (byte) 0x80};
        
        byte[] signature = KeyUtils.sign(specialData, ecKeyPair.getPrivate());
        
        assertNotNull("Signature should not be null", signature);
        
        // Verify the signature
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(ecKeyPair.getPublic());
        verifier.update(specialData);
        assertTrue("Signature should be valid", verifier.verify(signature));
    }

    @Test
    public void testSignWithUTF8Data() throws Exception {
        byte[] utf8Data = "Hello 世界 🌍".getBytes(StandardCharsets.UTF_8);
        
        byte[] signature = KeyUtils.sign(utf8Data, ecKeyPair.getPrivate());
        
        assertNotNull("Signature should not be null", signature);
        
        // Verify the signature
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(ecKeyPair.getPublic());
        verifier.update(utf8Data);
        assertTrue("Signature should be valid", verifier.verify(signature));
    }
}

// Made with Bob
