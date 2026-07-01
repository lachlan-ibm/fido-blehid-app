/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.util;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Test suite for input validation and provider management in KeyUtils.
 * Tests verifyDecryptInputs, getECKeyPair, ensureBouncyCastleProvider, and related methods.
 */
public class KeyUtilsValidationTest {

    private KeyPair ecKeyPair;
    private KeyPair rsaKeyPair;

    @Before
    public void setUp() throws Exception {
        // Ensure BouncyCastle provider is properly set up for tests
        KeyUtils.ensureBouncyCastleProvider();
        ecKeyPair = KeyUtils.generateKeyPair("EC", 256);
        rsaKeyPair = KeyUtils.generateKeyPair("RSA", 2048);
    }

    // ========== ecdhDecrypt Input Validation Tests ==========
    // Testing input validation through ecdhDecrypt which calls verifyDecryptInputs

    @Test(expected = Exception.class)
    public void testEcdhDecryptNullData() throws Exception {
        KeyUtils.ecdhDecrypt(null, ecKeyPair.getPrivate());
    }

    @Test(expected = Exception.class)
    public void testEcdhDecryptNullKey() throws Exception {
        byte[] data = new byte[250];
        KeyUtils.ecdhDecrypt(data, null);
    }

    @Test(expected = Exception.class)
    public void testEcdhDecryptInvalidDataLength() throws Exception {
        byte[] shortData = new byte[10]; // Too short
        KeyUtils.ecdhDecrypt(shortData, ecKeyPair.getPrivate());
    }

    @Test(expected = Exception.class)
    public void testEcdhDecryptWrongKeyType() throws Exception {
        byte[] data = new byte[250];
        KeyUtils.ecdhDecrypt(data, rsaKeyPair.getPrivate());
    }

    @Test
    public void testEcdhDecryptValidData() throws Exception {
        // Create valid encrypted data using ecdhEncrypt
        byte[] plaintext = "test data".getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = KeyUtils.ecdhEncrypt(plaintext, ecKeyPair.getPublic());
        
        // Should successfully decrypt
        byte[] decrypted = KeyUtils.ecdhDecrypt(encrypted, ecKeyPair.getPrivate());
        assertArrayEquals("Decrypted data should match original", plaintext, decrypted);
    }

    @Test(expected = Exception.class)
    public void testEcdhDecryptEmptyData() throws Exception {
        byte[] emptyData = new byte[0];
        KeyUtils.ecdhDecrypt(emptyData, ecKeyPair.getPrivate());
    }

    // ========== getECKeyPair Tests ==========

    @Test
    public void testGetECKeyPair() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair("EC", 256);
        
        assertNotNull("Key pair should not be null", keyPair);
        assertNotNull("Private key should not be null", keyPair.getPrivate());
        assertNotNull("Public key should not be null", keyPair.getPublic());
        
        assertTrue("Private key should be EC private key",
                   keyPair.getPrivate().getAlgorithm().equals("EC") ||
                   keyPair.getPrivate().getAlgorithm().equals("ECDSA"));
        assertTrue("Public key should be EC public key",
                   keyPair.getPublic().getAlgorithm().equals("EC") ||
                   keyPair.getPublic().getAlgorithm().equals("ECDSA"));
    }

    @Test
    public void testGetECKeyPairMultipleCalls() throws Exception {
        KeyPair keyPair1 = KeyUtils.generateKeyPair("EC", 256);
        KeyPair keyPair2 = KeyUtils.generateKeyPair("EC", 256);
        
        assertNotNull("First key pair should not be null", keyPair1);
        assertNotNull("Second key pair should not be null", keyPair2);
        
        // Different calls should generate different keys
        assertFalse("Different calls should generate different private keys",
                    Arrays.equals(keyPair1.getPrivate().getEncoded(),
                                keyPair2.getPrivate().getEncoded()));
        assertFalse("Different calls should generate different public keys",
                    Arrays.equals(keyPair1.getPublic().getEncoded(),
                                keyPair2.getPublic().getEncoded()));
    }

    @Test
    public void testGetECKeyPairKeySize() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair("EC", 256);
        
        // Verify key is usable for ECDH
        byte[] testData = "test".getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = KeyUtils.ecdhEncrypt(testData, keyPair.getPublic());
        byte[] decrypted = KeyUtils.ecdhDecrypt(encrypted, keyPair.getPrivate());
        
        assertArrayEquals("Key pair should be usable for ECDH", testData, decrypted);
    }

    // ========== ensureBouncyCastleProvider Tests ==========

    @Test
    public void testEnsureBouncyCastleProvider() {
        // Call the method
        KeyUtils.ensureBouncyCastleProvider();
        
        // Verify BC provider is registered
        Provider bcProvider = Security.getProvider("BC");
        assertNotNull("BouncyCastle provider should be registered", bcProvider);
        
        // Verify it's a BouncyCastle provider
        assertTrue("Should be BouncyCastle provider instance",
                   bcProvider instanceof BouncyCastleProvider ||
                   bcProvider.getClass().getName().contains("BouncyCastle"));
    }

    @Test
    public void testEnsureBouncyCastleProviderPriority() {
        KeyUtils.ensureBouncyCastleProvider();
        
        // Verify BC is at position 1 (highest priority)
        Provider[] providers = Security.getProviders();
        assertEquals("BC should be at position 1", "BC", providers[0].getName());
    }

    @Test
    public void testEnsureBouncyCastleProviderIdempotent() {
        KeyUtils.ensureBouncyCastleProvider();
        Provider bcProvider1 = Security.getProvider("BC");
        
        KeyUtils.ensureBouncyCastleProvider();
        Provider bcProvider2 = Security.getProvider("BC");
        
        assertSame("Multiple calls should not change provider instance",
                   bcProvider1, bcProvider2);
    }

    @Test
    public void testBouncyCastleProviderRegistered() {
        Provider bcProvider = Security.getProvider("BC");
        assertNotNull("BouncyCastle provider should be registered", bcProvider);
        assertTrue("Should be BouncyCastle provider",
                   bcProvider instanceof BouncyCastleProvider ||
                   bcProvider.getClass().getName().contains("BouncyCastle"));
    }

    @Test
    public void testBouncyCastleProviderPriority() {
        // Ensure BC is set up before checking priority
        KeyUtils.ensureBouncyCastleProvider();
        Provider[] providers = Security.getProviders();
        assertEquals("BC should be first provider", "BC", providers[0].getName());
    }

    // ========== getPublic(byte[], String) Tests ==========

    @Test
    public void testGetPublicFromBytesEC() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair("EC", 256);
        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
        
        java.security.PublicKey reconstructed = KeyUtils.getPublic(publicKeyBytes, "EC");
        
        assertNotNull("Reconstructed key should not be null", reconstructed);
        assertArrayEquals("Reconstructed key should match original",
                         keyPair.getPublic().getEncoded(),
                         reconstructed.getEncoded());
    }

    @Test
    public void testGetPublicFromBytesRSA() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair("RSA", 2048);
        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
        
        java.security.PublicKey reconstructed = KeyUtils.getPublic(publicKeyBytes, "RSA");
        
        assertNotNull("Reconstructed key should not be null", reconstructed);
        assertTrue("Reconstructed key should be RSA public key",
                   reconstructed instanceof java.security.interfaces.RSAPublicKey);
    }

    @Test(expected = Exception.class)
    public void testGetPublicInvalidBytes() throws Exception {
        byte[] invalidBytes = new byte[]{1, 2, 3, 4, 5};
        KeyUtils.getPublic(invalidBytes, "EC");
    }

    @Test(expected = Exception.class)
    public void testGetPublicWrongAlgorithm() throws Exception {
        KeyPair ecKeyPair = KeyUtils.generateKeyPair("EC", 256);
        byte[] ecPublicKeyBytes = ecKeyPair.getPublic().getEncoded();
        
        // Try to interpret EC key as RSA
        KeyUtils.getPublic(ecPublicKeyBytes, "RSA");
    }

    @Test(expected = Exception.class)
    public void testGetPublicNullBytes() throws Exception {
        KeyUtils.getPublic(null, "EC");
    }

    @Test(expected = Exception.class)
    public void testGetPublicEmptyBytes() throws Exception {
        KeyUtils.getPublic(new byte[0], "EC");
    }

    // ========== getPinHash Tests ==========

    @Test
    public void testGetPinHash() {
        String pin = "123456";
        byte[] hash = KeyUtils.getPinHash(pin);
        
        assertNotNull("Hash should not be null", hash);
        assertEquals("Hash should be 32 bytes (SHA-256)", 32, hash.length);
    }

    @Test
    public void testGetPinHashDeterministic() {
        String pin = "123456";
        byte[] hash1 = KeyUtils.getPinHash(pin);
        byte[] hash2 = KeyUtils.getPinHash(pin);
        
        assertArrayEquals("Same PIN should produce same hash", hash1, hash2);
    }

    @Test
    public void testGetPinHashDifferentPins() {
        String pin1 = "123456";
        String pin2 = "654321";
        
        byte[] hash1 = KeyUtils.getPinHash(pin1);
        byte[] hash2 = KeyUtils.getPinHash(pin2);
        
        assertFalse("Different PINs should produce different hashes",
                    Arrays.equals(hash1, hash2));
    }

    @Test(expected = Exception.class)
    public void testGetPinHashNull() {
        KeyUtils.getPinHash(null);
    }

    @Test
    public void testGetPinHashEmpty() {
        String emptyPin = "";
        byte[] hash = KeyUtils.getPinHash(emptyPin);
        
        assertNotNull("Hash should not be null even for empty PIN", hash);
        assertEquals("Hash should be 32 bytes", 32, hash.length);
    }

    @Test
    public void testGetPinHashSpecialCharacters() {
        String pin = "!@#$%^&*()";
        byte[] hash = KeyUtils.getPinHash(pin);
        
        assertNotNull("Hash should not be null", hash);
        assertEquals("Hash should be 32 bytes", 32, hash.length);
    }

    @Test
    public void testGetPinHashUnicode() {
        String pin = "密码123";
        byte[] hash = KeyUtils.getPinHash(pin);
        
        assertNotNull("Hash should not be null", hash);
        assertEquals("Hash should be 32 bytes", 32, hash.length);
    }

    // ========== getLowerPinHash Tests ==========

    @Test
    public void testGetLowerPinHash() {
        String pin = "123456";
        byte[] lowerHash = KeyUtils.getLowerPinHash(pin);
        
        assertNotNull("Lower hash should not be null", lowerHash);
        assertEquals("Lower hash should be 16 bytes", 16, lowerHash.length);
    }

    @Test
    public void testGetLowerPinHashMatchesFirstHalf() {
        String pin = "123456";
        byte[] fullHash = KeyUtils.getPinHash(pin);
        byte[] lowerHash = KeyUtils.getLowerPinHash(pin);
        
        byte[] expectedLowerHash = Arrays.copyOfRange(fullHash, 0, 16);
        assertArrayEquals("Lower hash should match first 16 bytes of full hash",
                         expectedLowerHash, lowerHash);
    }

    @Test
    public void testGetLowerPinHashDeterministic() {
        String pin = "123456";
        byte[] lowerHash1 = KeyUtils.getLowerPinHash(pin);
        byte[] lowerHash2 = KeyUtils.getLowerPinHash(pin);
        
        assertArrayEquals("Same PIN should produce same lower hash", lowerHash1, lowerHash2);
    }
}

// Made with Bob
