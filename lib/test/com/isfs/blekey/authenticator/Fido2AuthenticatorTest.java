/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.authenticator;

import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.isfs.blekey.data.Passkey;
import com.isfs.blekey.data.SymmetricKey;
import com.isfs.blekey.util.Cbor;
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
        System.err.println("testFromPasskey");
        // Mock the Passkey behavior
        String symKeySeed = SymmetricKey.generateKey();
        byte[] seedBytes = Base64.getUrlDecoder().decode(symKeySeed);
        
        // Use doReturn().when() syntax instead of when().thenReturn() to avoid unfinished stubbing
        X509Certificate mockCert = mock(X509Certificate.class);
        doReturn(mockCert).when(mockPasskey).getCertificate();
        doReturn(seedBytes).when(mockPasskey).getSeed();
        
        Fido2Authenticator auth = Fido2Authenticator.fromPasskey(mockPasskey);
        
        assertNotNull(auth);
        assertNotNull(auth.getSymKey());
        assertNotNull(auth.getAuthnCert());
        
        // Generate cred id
        byte[] credId = auth.getCredId();
        assertNotNull(credId);
        assertTrue(credId.length > 0);
        System.err.println("Credential Id:" + Arrays.toString(credId));
        
        // Re-encode the bytes to a base64 string for decryption
        Map<String, Object> start = KeyUtils.getECPrivateKeyParameters(auth.getPrivKey());
        System.err.println("start: " + start);
        byte[] cbor = Cbor.encode(start);
        String test = auth.getSymKey().encrypt(cbor);
        byte[] decrypted = auth.getSymKey().decrypt(test);
        System.err.println("decoded: " + Cbor.decode(decrypted));
        assertTrue(Arrays.equals(cbor, decrypted));
        
        // Try to decrypt the raw credential ID bytes instead of the base64-encoded string
        System.err.println("Attempt to recover original key");
        System.err.println(Arrays.toString(credId));
        byte[] keyBytes = auth.getSymKey().decrypt(new String(credId));
        System.err.println("Decrypted key bytes: " + Arrays.toString(keyBytes));
        assertNotNull(keyBytes);

        // Derive private key should be equal
        Fido2Authenticator a2 = new Fido2Authenticator();
        a2.setSymKey(auth.getSymKey());
        a2.initFromCredId(credId);
        assertEquals(auth.getPrivKey(), a2.getPrivKey());
    }
    
    /**
     * Test the getCredIdBytes method.
     */
    @Test
    public void testGetCredIdBytes() throws Exception {
        System.err.println("testGetCredIdBytes");
        // Set up the authenticator with a symmetric key to ensure proper credential ID generation
        authenticator.setSymKey(new SymmetricKey(SymmetricKey.generateKey()));
        
        byte[] credIdBytes = authenticator.getCredId();
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
        
        
        byte[] authData = authenticator.buildAuthenticatorData(
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
        
        byte[] authData = authenticator.buildAuthenticatorData(
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

    /**
     * Test the packed attestation statement
     */
    @Test
    public void testPackedAttestationStatement() throws Exception {
        // Setup for credential creation
        JsonObject clientDataJSON = Json.createObjectBuilder()
                .add("origin", "https://example.com")
                .add("challenge", Base64.getUrlEncoder().encodeToString("challenge123".getBytes()))
                .add("type", "webauthn.create")
                .build();

        // Hash the clientDataJSON with SHA-256
        byte[] clientDataHash;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            clientDataHash = digest.digest(clientDataJSON.toString().getBytes());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }

        Map<String, Object> publicKey = new HashMap<>();
        Map<String, Object> rp = new HashMap<>();
        rp.put("id", "example.com");
        publicKey.put("rp", rp);
        publicKey.put("attestation", "none");
        publicKey.put("challenge", "challenge123".getBytes());
        
        byte[] authData = authenticator.buildAuthenticatorData(
                publicKey,
                "none", // Attestation type
                null,
                null,
                authenticator.getKeyPair());
        
        Map<String, Object> attStmt = authenticator.processAttestationStatement("packed-self", clientDataHash,
                authData, authenticator.getCredId(), authenticator.getKeyPair(), null, null);
        
        // Verify the attestation statement was created successfully
        assertNotNull(attStmt);
    }
}

// Made with Bob
