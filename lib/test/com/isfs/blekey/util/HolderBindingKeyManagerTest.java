/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.util;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.security.KeyPair;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for HolderBindingKeyManager.
 * Tests HKDF key derivation, seed management, and EC key pair generation.
 */
public class HolderBindingKeyManagerTest {
    
    private static KeyPair masterKeyPair;
    
    @BeforeAll
    public static void setUp() throws Exception {
        // Ensure BouncyCastle provider is available
        KeyUtils.ensureBouncyCastleProvider();
        
        // Generate a test master key pair (EC P-256)
        masterKeyPair = KeyUtils.generateKeyPair("EC", 256);
        assertNotNull(masterKeyPair, "Master key pair should be generated");
    }
    
    @Test
    @DisplayName("Generate seed produces 32-byte random seed")
    public void testGenerateSeed() {
        byte[] seed1 = HolderBindingKeyManager.generateSeed();
        byte[] seed2 = HolderBindingKeyManager.generateSeed();
        
        assertNotNull(seed1, "Seed should not be null");
        assertEquals(32, seed1.length, "Seed should be 32 bytes");
        
        assertNotNull(seed2, "Second seed should not be null");
        assertEquals(32, seed2.length, "Second seed should be 32 bytes");
        
        assertFalse(Arrays.equals(seed1, seed2), "Seeds should be random and different");
    }
    
    @Test
    @DisplayName("Validate seed accepts valid 32-byte seeds")
    public void testValidateSeed() {
        byte[] validSeed = new byte[32];
        assertTrue(HolderBindingKeyManager.validateSeed(validSeed), "32-byte seed should be valid");
        
        byte[] invalidSeed = new byte[16];
        assertFalse(HolderBindingKeyManager.validateSeed(invalidSeed), "16-byte seed should be invalid");
        
        assertFalse(HolderBindingKeyManager.validateSeed(null), "Null seed should be invalid");
    }
    
    @Test
    @DisplayName("Derive binding key produces valid EC key pair")
    public void testDeriveBindingKey() {
        byte[] seed = HolderBindingKeyManager.generateSeed();
        String credentialId = "credential-123";
        String issuerId = "https://issuer.example.com";
        String credentialType = "VerifiableCredential";
        
        KeyPair keyPair = HolderBindingKeyManager.deriveBindingKey(
            seed, credentialId, issuerId, credentialType, masterKeyPair.getPrivate());
        
        assertNotNull(keyPair, "Key pair should not be null");
        assertNotNull(keyPair.getPrivate(), "Private key should not be null");
        assertNotNull(keyPair.getPublic(), "Public key should not be null");
        
        assertEquals("EC", keyPair.getPrivate().getAlgorithm(), "Private key should be EC");
        assertEquals("EC", keyPair.getPublic().getAlgorithm(), "Public key should be EC");
    }
    
    @Test
    @DisplayName("Derive binding key is deterministic for same inputs")
    public void testDeriveBindingKeyDeterministic() {
        byte[] seed = HolderBindingKeyManager.generateSeed();
        String credentialId = "credential-456";
        String issuerId = "https://issuer.example.com";
        String credentialType = "DriverLicense";
        
        KeyPair keyPair1 = HolderBindingKeyManager.deriveBindingKey(
            seed, credentialId, issuerId, credentialType, masterKeyPair.getPrivate());
        
        KeyPair keyPair2 = HolderBindingKeyManager.deriveBindingKey(
            seed, credentialId, issuerId, credentialType, masterKeyPair.getPrivate());
        
        // Compare EC key coordinates instead of encoded bytes
        // EC key encoding can vary even for the same mathematical point
        java.security.interfaces.ECPublicKey pub1 = (java.security.interfaces.ECPublicKey) keyPair1.getPublic();
        java.security.interfaces.ECPublicKey pub2 = (java.security.interfaces.ECPublicKey) keyPair2.getPublic();
        
        assertEquals(
            pub1.getW().getAffineX(),
            pub2.getW().getAffineX(),
            "Same inputs should produce same public key X coordinate"
        );
        
        assertEquals(
            pub1.getW().getAffineY(),
            pub2.getW().getAffineY(),
            "Same inputs should produce same public key Y coordinate"
        );
        
        // For private keys, compare the S value (private key scalar)
        java.security.interfaces.ECPrivateKey priv1 = (java.security.interfaces.ECPrivateKey) keyPair1.getPrivate();
        java.security.interfaces.ECPrivateKey priv2 = (java.security.interfaces.ECPrivateKey) keyPair2.getPrivate();
        
        assertEquals(
            priv1.getS(),
            priv2.getS(),
            "Same inputs should produce same private key scalar"
        );
    }
    
    @Test
    @DisplayName("Derive binding key produces different keys for different seeds")
    public void testDeriveBindingKeyDifferentSeeds() {
        byte[] seed1 = HolderBindingKeyManager.generateSeed();
        byte[] seed2 = HolderBindingKeyManager.generateSeed();
        String credentialId = "credential-789";
        String issuerId = "https://issuer.example.com";
        String credentialType = "UniversityDegree";
        
        KeyPair keyPair1 = HolderBindingKeyManager.deriveBindingKey(
            seed1, credentialId, issuerId, credentialType, masterKeyPair.getPrivate());
        
        KeyPair keyPair2 = HolderBindingKeyManager.deriveBindingKey(
            seed2, credentialId, issuerId, credentialType, masterKeyPair.getPrivate());
        
        assertFalse(
            Arrays.equals(keyPair1.getPublic().getEncoded(), keyPair2.getPublic().getEncoded()),
            "Different seeds should produce different public keys"
        );
        
        assertFalse(
            Arrays.equals(keyPair1.getPrivate().getEncoded(), keyPair2.getPrivate().getEncoded()),
            "Different seeds should produce different private keys"
        );
    }
    
    @Test
    @DisplayName("Derive binding key produces different keys for different credential IDs")
    public void testDeriveBindingKeyDifferentCredentialIds() {
        byte[] seed = HolderBindingKeyManager.generateSeed();
        String issuerId = "https://issuer.example.com";
        String credentialType = "VerifiableCredential";
        
        KeyPair keyPair1 = HolderBindingKeyManager.deriveBindingKey(
            seed, "credential-001", issuerId, credentialType, masterKeyPair.getPrivate());
        
        KeyPair keyPair2 = HolderBindingKeyManager.deriveBindingKey(
            seed, "credential-002", issuerId, credentialType, masterKeyPair.getPrivate());
        
        assertFalse(
            Arrays.equals(keyPair1.getPublic().getEncoded(), keyPair2.getPublic().getEncoded()),
            "Different credential IDs should produce different keys (due to salt)"
        );
    }
    
    @Test
    @DisplayName("Derive binding key produces different keys for different issuer IDs")
    public void testDeriveBindingKeyDifferentIssuerIds() {
        byte[] seed = HolderBindingKeyManager.generateSeed();
        String credentialId = "credential-abc";
        String credentialType = "VerifiableCredential";
        
        KeyPair keyPair1 = HolderBindingKeyManager.deriveBindingKey(
            seed, credentialId, "https://issuer1.example.com", credentialType, masterKeyPair.getPrivate());
        
        KeyPair keyPair2 = HolderBindingKeyManager.deriveBindingKey(
            seed, credentialId, "https://issuer2.example.com", credentialType, masterKeyPair.getPrivate());
        
        assertFalse(
            Arrays.equals(keyPair1.getPublic().getEncoded(), keyPair2.getPublic().getEncoded()),
            "Different issuer IDs should produce different keys (due to salt)"
        );
    }
    
    @Test
    @DisplayName("Derive binding key produces different keys for different credential types")
    public void testDeriveBindingKeyDifferentCredentialTypes() {
        byte[] seed = HolderBindingKeyManager.generateSeed();
        String credentialId = "credential-xyz";
        String issuerId = "https://issuer.example.com";
        
        KeyPair keyPair1 = HolderBindingKeyManager.deriveBindingKey(
            seed, credentialId, issuerId, "DriverLicense", masterKeyPair.getPrivate());
        
        KeyPair keyPair2 = HolderBindingKeyManager.deriveBindingKey(
            seed, credentialId, issuerId, "UniversityDegree", masterKeyPair.getPrivate());
        
        assertFalse(
            Arrays.equals(keyPair1.getPublic().getEncoded(), keyPair2.getPublic().getEncoded()),
            "Different credential types should produce different keys (due to info)"
        );
    }
    
    @Test
    @DisplayName("Derive binding key rejects invalid seed length")
    public void testDeriveBindingKeyInvalidSeedLength() {
        byte[] invalidSeed = new byte[16]; // Wrong length
        String credentialId = "credential-123";
        String issuerId = "https://issuer.example.com";
        String credentialType = "VerifiableCredential";
        
        assertThrows(IllegalArgumentException.class, () -> {
            HolderBindingKeyManager.deriveBindingKey(
                invalidSeed, credentialId, issuerId, credentialType, masterKeyPair.getPrivate());
        }, "Should reject seed with invalid length");
    }
    
    @Test
    @DisplayName("Derive binding key rejects null seed")
    public void testDeriveBindingKeyNullSeed() {
        String credentialId = "credential-123";
        String issuerId = "https://issuer.example.com";
        String credentialType = "VerifiableCredential";
        
        assertThrows(IllegalArgumentException.class, () -> {
            HolderBindingKeyManager.deriveBindingKey(
                null, credentialId, issuerId, credentialType, masterKeyPair.getPrivate());
        }, "Should reject null seed");
    }
    
    @Test
    @DisplayName("Derive binding key rejects null or empty credential ID")
    public void testDeriveBindingKeyInvalidCredentialId() {
        byte[] seed = HolderBindingKeyManager.generateSeed();
        String issuerId = "https://issuer.example.com";
        String credentialType = "VerifiableCredential";
        
        assertThrows(IllegalArgumentException.class, () -> {
            HolderBindingKeyManager.deriveBindingKey(
                seed, null, issuerId, credentialType, masterKeyPair.getPrivate());
        }, "Should reject null credential ID");
        
        assertThrows(IllegalArgumentException.class, () -> {
            HolderBindingKeyManager.deriveBindingKey(
                seed, "", issuerId, credentialType, masterKeyPair.getPrivate());
        }, "Should reject empty credential ID");
    }
    
    @Test
    @DisplayName("Derive binding key rejects null or empty issuer ID")
    public void testDeriveBindingKeyInvalidIssuerId() {
        byte[] seed = HolderBindingKeyManager.generateSeed();
        String credentialId = "credential-123";
        String credentialType = "VerifiableCredential";
        
        assertThrows(IllegalArgumentException.class, () -> {
            HolderBindingKeyManager.deriveBindingKey(
                seed, credentialId, null, credentialType, masterKeyPair.getPrivate());
        }, "Should reject null issuer ID");
        
        assertThrows(IllegalArgumentException.class, () -> {
            HolderBindingKeyManager.deriveBindingKey(
                seed, credentialId, "", credentialType, masterKeyPair.getPrivate());
        }, "Should reject empty issuer ID");
    }
    
    @Test
    @DisplayName("Derive binding key rejects null or empty credential type")
    public void testDeriveBindingKeyInvalidCredentialType() {
        byte[] seed = HolderBindingKeyManager.generateSeed();
        String credentialId = "credential-123";
        String issuerId = "https://issuer.example.com";
        
        assertThrows(IllegalArgumentException.class, () -> {
            HolderBindingKeyManager.deriveBindingKey(
                seed, credentialId, issuerId, null, masterKeyPair.getPrivate());
        }, "Should reject null credential type");
        
        assertThrows(IllegalArgumentException.class, () -> {
            HolderBindingKeyManager.deriveBindingKey(
                seed, credentialId, issuerId, "", masterKeyPair.getPrivate());
        }, "Should reject empty credential type");
    }
    
    @Test
    @DisplayName("Derive binding key rejects null master key")
    public void testDeriveBindingKeyNullMasterKey() {
        byte[] seed = HolderBindingKeyManager.generateSeed();
        String credentialId = "credential-123";
        String issuerId = "https://issuer.example.com";
        String credentialType = "VerifiableCredential";
        
        assertThrows(IllegalArgumentException.class, () -> {
            HolderBindingKeyManager.deriveBindingKey(
                seed, credentialId, issuerId, credentialType, null);
        }, "Should reject null master key");
    }
    
    @Test
    @DisplayName("Get seed length returns 32")
    public void testGetSeedLength() {
        assertEquals(32, HolderBindingKeyManager.getSeedLength(), "Seed length should be 32 bytes");
    }
    
    @Test
    @DisplayName("Get key length returns 32")
    public void testGetKeyLength() {
        assertEquals(32, HolderBindingKeyManager.getKeyLength(), "Key length should be 32 bytes");
    }
    
    @Test
    @DisplayName("Derived key can be used for signing")
    public void testDerivedKeyCanSign() throws Exception {
        byte[] seed = HolderBindingKeyManager.generateSeed();
        String credentialId = "credential-sign-test";
        String issuerId = "https://issuer.example.com";
        String credentialType = "VerifiableCredential";
        
        KeyPair keyPair = HolderBindingKeyManager.deriveBindingKey(
            seed, credentialId, issuerId, credentialType, masterKeyPair.getPrivate());
        
        // Test that the derived key can be used for signing
        byte[] testData = "Test data to sign".getBytes();
        byte[] signature = KeyUtils.sign(testData, keyPair.getPrivate());
        
        assertNotNull(signature, "Signature should not be null");
        assertTrue(signature.length > 0, "Signature should not be empty");
        
        // Verify signature using Java Signature API
        java.security.Signature verifier = java.security.Signature.getInstance("SHA256withECDSA", "BC");
        verifier.initVerify(keyPair.getPublic());
        verifier.update(testData);
        boolean verified = verifier.verify(signature);
        assertTrue(verified, "Signature should verify with derived public key");
    }
    
    @Test
    @DisplayName("Key isolation - different credentials have independent keys")
    public void testKeyIsolation() throws Exception {
        byte[] seed1 = HolderBindingKeyManager.generateSeed();
        byte[] seed2 = HolderBindingKeyManager.generateSeed();
        
        KeyPair keyPair1 = HolderBindingKeyManager.deriveBindingKey(
            seed1, "cred-1", "issuer-1", "Type1", masterKeyPair.getPrivate());
        
        KeyPair keyPair2 = HolderBindingKeyManager.deriveBindingKey(
            seed2, "cred-2", "issuer-2", "Type2", masterKeyPair.getPrivate());
        
        // Keys should be completely independent
        assertFalse(
            Arrays.equals(keyPair1.getPublic().getEncoded(), keyPair2.getPublic().getEncoded()),
            "Keys for different credentials should be independent"
        );
        
        // Signature from one key should not verify with another key
        byte[] testData = "Test data".getBytes();
        byte[] signature1 = KeyUtils.sign(testData, keyPair1.getPrivate());
        
        // Try to verify with wrong key
        java.security.Signature verifier = java.security.Signature.getInstance("SHA256withECDSA", "BC");
        verifier.initVerify(keyPair2.getPublic());
        verifier.update(testData);
        boolean crossVerify = verifier.verify(signature1);
        assertFalse(crossVerify, "Signature from one credential should not verify with another's key");
    }
}

// Made with Bob