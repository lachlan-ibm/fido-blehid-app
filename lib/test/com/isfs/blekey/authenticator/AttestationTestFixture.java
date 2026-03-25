/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;

import com.isfs.blekey.util.CertUtils;
import com.isfs.blekey.util.KeyUtils;

/**
 * Test fixture providing reusable PKI infrastructure for attestation tests.
 * This class generates and caches certificate authorities and key pairs
 * that can be reused across multiple test cases for Apple, Android, TPM,
 * and FIDO U2F attestations.
 */
public class AttestationTestFixture {
    
    // Cached PKI components
    private KeyPair rootCaKeyPair;
    private X509Certificate rootCaCert;
    private KeyPair ecCaKeyPair;
    private X509Certificate ecCaCert;
    private KeyPair rsaCaKeyPair;
    private X509Certificate rsaCaCert;
    
    // Cached authenticator key pairs
    private KeyPair ecAuthenticatorKeyPair;
    private KeyPair rsaAuthenticatorKeyPair;
    
    // Test data
    private byte[] testAuthData;
    private byte[] testClientDataHash;
    private byte[] testCredId;
    
    /**
     * Initializes the test fixture with all necessary PKI components.
     * This method should be called once before running attestation tests.
     * 
     * @throws Exception if initialization fails
     */
    public void initialize() throws Exception {
        // Generate root CA (RSA) for general use
        rootCaKeyPair = KeyUtils.generateKeyPair("RSA", 2048);
        rootCaCert = CertUtils.generateCaCert("CN=Test Root CA", rootCaKeyPair, 365, true);
        
        // Generate EC CA for EC-based attestations (Apple, FIDO U2F)
        ecCaKeyPair = generateEcKeyPair();
        ecCaCert = CertUtils.generateCaCert("CN=Test EC CA", ecCaKeyPair, 365, true);
        
        // Generate RSA CA for RSA-based attestations (Android, TPM)
        rsaCaKeyPair = KeyUtils.generateKeyPair("RSA", 2048);
        rsaCaCert = CertUtils.generateCaCert("CN=Test RSA CA", rsaCaKeyPair, 365, true);
        
        // Generate authenticator key pairs
        ecAuthenticatorKeyPair = generateEcKeyPair();
        rsaAuthenticatorKeyPair = KeyUtils.generateKeyPair("RSA", 2048);
        
        // Generate test data
        testAuthData = generateTestAuthData();
        testClientDataHash = generateTestClientDataHash();
        testCredId = generateTestCredId();
    }
    
    /**
     * Generates an EC key pair using P-256 curve.
     * 
     * @return A new EC key pair
     * @throws Exception if key generation fails
     */
    private KeyPair generateEcKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256); // P-256 curve
        return keyGen.generateKeyPair();
    }
    
    /**
     * Generates test authenticator data (37 bytes minimum).
     * Format: rpIdHash (32 bytes) + flags (1 byte) + signCount (4 bytes)
     * 
     * @return Test authenticator data
     * @throws Exception if generation fails
     */
    private byte[] generateTestAuthData() throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] rpIdHash = digest.digest("example.com".getBytes());
        byte[] authData = new byte[37];
        System.arraycopy(rpIdHash, 0, authData, 0, 32);
        authData[32] = 0x45; // flags: UP=1, UV=0, AT=1, ED=0
        // signCount = 0 (bytes 33-36)
        return authData;
    }
    
    /**
     * Generates test client data hash (32 bytes).
     * 
     * @return Test client data hash
     * @throws Exception if generation fails
     */
    private byte[] generateTestClientDataHash() throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest("test-client-data".getBytes());
    }
    
    /**
     * Generates test credential ID (16 bytes).
     * 
     * @return Test credential ID
     */
    private byte[] generateTestCredId() {
        byte[] credId = new byte[16];
        for (int i = 0; i < credId.length; i++) {
            credId[i] = (byte) i;
        }
        return credId;
    }
    
    // Getters for PKI components
    
    public KeyPair getRootCaKeyPair() {
        return rootCaKeyPair;
    }
    
    public X509Certificate getRootCaCert() {
        return rootCaCert;
    }
    
    public KeyPair getEcCaKeyPair() {
        return ecCaKeyPair;
    }
    
    public X509Certificate getEcCaCert() {
        return ecCaCert;
    }
    
    public KeyPair getRsaCaKeyPair() {
        return rsaCaKeyPair;
    }
    
    public X509Certificate getRsaCaCert() {
        return rsaCaCert;
    }
    
    public KeyPair getEcAuthenticatorKeyPair() {
        return ecAuthenticatorKeyPair;
    }
    
    public KeyPair getRsaAuthenticatorKeyPair() {
        return rsaAuthenticatorKeyPair;
    }
    
    // Getters for test data
    
    public byte[] getTestAuthData() {
        return testAuthData;
    }
    
    public byte[] getTestClientDataHash() {
        return testClientDataHash;
    }
    
    public byte[] getTestCredId() {
        return testCredId;
    }
    
    /**
     * Creates a fresh EC authenticator key pair for tests that need unique keys.
     * 
     * @return A new EC key pair
     * @throws Exception if key generation fails
     */
    public KeyPair createFreshEcKeyPair() throws Exception {
        return generateEcKeyPair();
    }
    
    /**
     * Creates a fresh RSA authenticator key pair for tests that need unique keys.
     * 
     * @return A new RSA key pair
     * @throws Exception if key generation fails
     */
    public KeyPair createFreshRsaKeyPair() throws Exception {
        return KeyUtils.generateKeyPair("RSA", 2048);
    }
}

// Made with Bob
