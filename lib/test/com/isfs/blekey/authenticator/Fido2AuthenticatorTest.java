/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.authenticator;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.isfs.blekey.data.Passkey;
import com.isfs.blekey.util.KeyUtils;

import jakarta.json.Json;
import jakarta.json.JsonObject;

/**
 * Unit tests for the Fido2Authenticator class.
 */
@ExtendWith(MockitoExtension.class)
public class Fido2AuthenticatorTest {

    private Fido2Authenticator authenticator;
    
    @Mock
    private Passkey mockPasskey;
    
    @BeforeEach
    public void setUp() {
        authenticator = new Fido2Authenticator();
    }
    
    /**
     * Test the default constructor creates an EC key pair.
     */
    @Test
    public void testDefaultConstructor() {
        assertNotNull(authenticator.getKeyPair());
        assertEquals("EC", authenticator.getKeyPair().getPublic().getAlgorithm());
    }
    
    /**
     * Test constructor with algorithm parameter.
     */
    @Test
    public void testConstructorWithAlgorithm() throws Exception {
        Fido2Authenticator rsaAuth = new Fido2Authenticator("RSA");
        assertNotNull(rsaAuth.getKeyPair());
        assertEquals("RSA", rsaAuth.getKeyPair().getPublic().getAlgorithm());
    }
    
    /**
     * Test constructor with algorithm and key size parameters.
     */
    @Test
    public void testConstructorWithAlgorithmAndKeySize() throws NoSuchAlgorithmException {
        Fido2Authenticator rsaAuth = new Fido2Authenticator("RSA", 2048);
        assertNotNull(rsaAuth.getKeyPair());
        assertEquals("RSA", rsaAuth.getKeyPair().getPublic().getAlgorithm());
    }
    
    /**
     * Test the fromPasskey static factory method.
     */
    @Test
    public void testFromPasskey() throws Exception {
        // Mock the Passkey behavior
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        KeyPair keyPair = keyGen.generateKeyPair();
        
        when(mockPasskey.getPrivateKey()).thenReturn(keyPair.getPrivate());
        when(mockPasskey.getCertificate()).thenReturn(mock(X509Certificate.class));
        when(mockPasskey.getSeed()).thenReturn(new byte[32]); // 32-byte seed for Key
        
        Fido2Authenticator auth = Fido2Authenticator.fromPasskey(mockPasskey);
        
        assertNotNull(auth);
        assertNotNull(auth.getCaCert());
        assertNotNull(auth.getCaKeyPair());
    }
    
    /**
     * Test the getCredIdBytes method.
     */
    @Test
    public void testGetCredIdBytes() throws Exception {
        byte[] credIdBytes = authenticator.getCredIdBytes();
        assertNotNull(credIdBytes);
        assertTrue(credIdBytes.length > 0);
    }
    
    /**
     * Test the counter functionality.
     */
    @Test
    public void testCounter() {
        long initialCounter = authenticator.getCounter();
        assertEquals(0, initialCounter);
        
        authenticator.setCounter(42);
        assertEquals(42, authenticator.getCounter());
    }
    
    /**
     * Test the setKeyPair method.
     */
    @Test
    public void testSetKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        KeyPair newKeyPair = keyGen.generateKeyPair();
        
        authenticator.setKeyPair(newKeyPair);
        
        assertSame(newKeyPair, authenticator.getKeyPair());
        assertEquals("RSA", authenticator.getKeyPair().getPublic().getAlgorithm());
    }
    
    /**
     * Test the buildClientDataJson method.
     */
    @Test
    public void testBuildClientDataJsonForAssertion() {
        // Setup for assertion (webauthn.get)
        Map<String, Object> publicKey = new HashMap<>();
        publicKey.put("rpId", "example.com");
        publicKey.put("challenge", "challenge123".getBytes());
        
        JsonObject clientData = authenticator.buildClientDataJson(publicKey);
        
        assertNotNull(clientData);
        assertEquals("https://example.com", clientData.getString("origin"));
        assertEquals("webauthn.get", clientData.getString("type"));
        assertTrue(clientData.getString("challenge").length() > 0);
    }
    
    /**
     * Test the buildClientDataJson method for credential creation.
     */
    @Test
    public void testBuildClientDataJsonForCreation() {
        // Setup for credential creation (webauthn.create)
        Map<String, Object> publicKey = new HashMap<>();
        Map<String, Object> rp = new HashMap<>();
        rp.put("id", "example.com");
        publicKey.put("rp", rp);
        publicKey.put("challenge", "challenge123".getBytes());
        
        JsonObject clientData = authenticator.buildClientDataJson(publicKey);
        
        assertNotNull(clientData);
        assertEquals("https://example.com", clientData.getString("origin"));
        assertEquals("webauthn.create", clientData.getString("type"));
        assertTrue(clientData.getString("challenge").length() > 0);
    }
    
    /**
     * Test the buildClientDataJson method with custom origin.
     */
    @Test
    public void testBuildClientDataJsonWithCustomOrigin() {
        // Setup with custom origin
        Map<String, Object> publicKey = new HashMap<>();
        publicKey.put("rpId", "example.com");
        publicKey.put("origin", "https://app.example.com");
        publicKey.put("challenge", "challenge123".getBytes());
        
        JsonObject clientData = authenticator.buildClientDataJson(publicKey);
        
        assertNotNull(clientData);
        assertEquals("https://app.example.com", clientData.getString("origin"));
    }
    
    /**
     * Test the buildAuthenticatorData method for assertion.
     */
    @Test
    public void testBuildAuthenticatorDataForAssertion() throws Exception {
        // Setup for assertion
        Map<String, Object> publicKey = new HashMap<>();
        publicKey.put("rpId", "example.com");
        publicKey.put("challenge", "challenge123".getBytes());
        
        JsonObject clientDataJSON = Json.createObjectBuilder()
                .add("origin", "https://example.com")
                .add("challenge", Base64.getUrlEncoder().encodeToString("challenge123".getBytes()))
                .add("type", "webauthn.get")
                .build();
        
        byte[] authData = authenticator.buildAuthenticatorData(
                clientDataJSON, 
                publicKey, 
                null, // No attestation for assertion
                null, 
                null, 
                authenticator.getKeyPair());
        
        assertNotNull(authData);
        assertTrue(authData.length > 0);
        
        // First 32 bytes should be rpIdHash
        byte[] rpIdHash = new byte[32];
        System.arraycopy(authData, 0, rpIdHash, 0, 32);
        assertNotNull(rpIdHash);
        
        // Byte 32 should contain flags
        int flags = authData[32] & 0xFF;
        assertTrue((flags & 0x01) != 0); // UP flag should be set
    }
    
    /**
     * Test the buildAuthenticatorData method for credential creation.
     */
    @Test
    public void testBuildAuthenticatorDataForCredentialCreation() throws Exception {
        // Setup for credential creation
        Map<String, Object> publicKey = new HashMap<>();
        Map<String, Object> rp = new HashMap<>();
        rp.put("id", "example.com");
        publicKey.put("rp", rp);
        publicKey.put("attestation", "none");
        publicKey.put("challenge", "challenge123".getBytes());
        
        JsonObject clientDataJSON = Json.createObjectBuilder()
                .add("origin", "https://example.com")
                .add("challenge", Base64.getUrlEncoder().encodeToString("challenge123".getBytes()))
                .add("type", "webauthn.create")
                .build();
        
        byte[] authData = authenticator.buildAuthenticatorData(
                clientDataJSON, 
                publicKey, 
                "none", // Attestation type
                null, 
                null, 
                authenticator.getKeyPair());
        
        assertNotNull(authData);
        assertTrue(authData.length > 0);
        
        // First 32 bytes should be rpIdHash
        byte[] rpIdHash = new byte[32];
        System.arraycopy(authData, 0, rpIdHash, 0, 32);
        assertNotNull(rpIdHash);
        
        // Byte 32 should contain flags
        int flags = authData[32] & 0xFF;
        assertTrue((flags & 0x01) != 0); // UP flag should be set
        assertTrue((flags & 0x40) != 0); // AT flag should be set for attestation
    }
}

// Made with Bob
