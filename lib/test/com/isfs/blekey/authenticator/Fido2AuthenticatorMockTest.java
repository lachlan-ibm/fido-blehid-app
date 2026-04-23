/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import com.isfs.blekey.data.Passkey;
import com.isfs.blekey.data.SymmetricKey;
import com.isfs.blekey.util.Cbor;
import com.isfs.blekey.util.CertUtils;
import com.isfs.blekey.util.KeyUtils;
import com.isfs.blekey.util.JsonUtils;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;

/**
 * Mock-based unit tests for the Fido2Authenticator class.
 * These tests use mocking to isolate the Fido2Authenticator class from its dependencies.
 */
@SuppressWarnings("unchecked")
@ExtendWith(MockitoExtension.class)
public class Fido2AuthenticatorMockTest {

    // KeyPair is a final class and cannot be mocked directly, create a real KeyPair instance instead
    private KeyPair keyPair;
    
    @Mock
    private PublicKey mockPublicKey;
    
    @Mock
    private PrivateKey mockPrivateKey;
    
    @Mock
    private X509Certificate mockCertificate;
    
    @Mock
    private Passkey mockPasskey;
    
    @Mock
    private JsonReader mockJsonReader;
    
    @Mock
    private JsonObject mockJsonObject;
    
    private Fido2Authenticator authenticator;
    
    @BeforeEach
    public void setUp() throws Exception {
        // Create a real KeyPair with mocked public and private keys
        keyPair = new KeyPair(mockPublicKey, mockPrivateKey);
        
        // Setup mock keys with lenient stubbing to avoid UnnecessaryStubbingException
        lenient().when(mockPublicKey.getAlgorithm()).thenReturn("EC");
        lenient().when(mockPublicKey.getEncoded()).thenReturn("mockPublicKeyEncoded".getBytes());
        
        // Create authenticator with the key pair
        authenticator = new Fido2Authenticator();
        authenticator.setKeyPair(keyPair);
    }
    
    /**
     * Test the getCredIdBytes method with and without a symmetric key.
     */
    @Test
    public void testGetCredIdBytes() throws Exception {
        Fido2Authenticator a = new Fido2Authenticator();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(a.getKeyPair().getPublic().getEncoded());
        byte[] expected = digest.digest();
        byte[] cid = a.getCredId();
        assertNotNull(cid);
        assertTrue(cid.length == 32); //SHA-256 block size
        assertTrue(Arrays.equals(expected, cid));
        
        // Generate a proper seed for the Passkey
        String seed = SymmetricKey.generateKey();
        // Create the authenitcator
        Fido2Authenticator a2 = new Fido2Authenticator();
        a2.setSymKeys(seed);
        byte[] cid2 = a2.getCredId();
        System.err.println("original cred id :" + Arrays.toString(cid2));
        assertNotNull(cid2);

        // Create authenticator from the passkey
        Fido2Authenticator a3 = new Fido2Authenticator();
        a3.setSymKeys(seed);
        a3.initFromCredId(cid2);
        assertEquals(a2.getCredId(), a3.getCredId());
        assertEquals(a2.getPrivKey(), a3.getPrivKey());
    }
    
    /**
     * Test the credentialCreate method with mocked dependencies.
     */
    
    @Test
    public void testCredentialCreate() throws Exception {
        // Setup mocks
        String jsonOptions = "{\"rp\":{\"id\":\"example.com\"},\"user\":{\"id\":\"dGVzdHVzZXIK\"},\"challenge\":\"Zmlkb05vbmNlQ2hhbGxlbmdlCg\",\"attestation\":\"direct\"}";
        Map<String, Object> mockResult = new HashMap<>();
        mockResult.put("id", "credentialId");   
            
        // Create a spy to mock the internal method
        Fido2Authenticator a = new Fido2Authenticator();
        
        // Test the method
        String result = a.credentialCreate(jsonOptions, "packed-self");
        Map<String, Object> rMap = (Map<String, Object>) JsonUtils.decode(result, HashMap.class);
        // Verify
        assertNotNull(result);
        Map<String, Object> response = (Map<String, Object>) rMap.get("response");
        assertTrue(response.containsKey("clientDataJSON"));
        assertTrue(response.containsKey("attestationObject"));
        assertTrue(Arrays.equals(a.getCredId(), Base64.getUrlDecoder().decode((String) rMap.get("id"))));
        Map<String, Object> cdj = (Map<String, Object>) JsonUtils.decode(
                new String (Base64.getUrlDecoder().decode((String) response.get("clientDataJSON"))), HashMap.class);
        assertEquals("webauthn.create", (String) cdj.get("type"));
        byte[] aObjBytes = Base64.getUrlDecoder().decode((String) response.get("attestationObject"));
        Map<String, Object> aObj = (Map<String, Object>) Cbor.decode(aObjBytes);
        assertTrue(aObj.containsKey("authData"));
        assertTrue(aObj.containsKey("attStmt"));
        assertTrue(aObj.containsKey("fmt"));
        assertEquals("packed", aObj.get("fmt"));

        Map<String, Object> attStmt = (Map<String, Object>) aObj.get("attStmt");
        assertTrue(attStmt.containsKey("sig"));
        assertEquals(attStmt.get("alg"), -7);
    }
    
    /**
     * Test the credentialRequest method with mocked dependencies.
     */
    @Test
    public void testCredentialRequest() throws Exception {
        // Use a real implementation approach
        // Create a properly formatted JSON string with all required fields
        String jsonOptions = "{\"challenge\":\"Y2hhbGxlbmdl\",\"rpId\":\"example.com\"}";
        
        // Create a real Fido2Authenticator instance
        Fido2Authenticator realAuth = new Fido2Authenticator();
        
        // Test the method with minimal mocking
        try (MockedStatic<JsonUtils> jsonUtilsMock = mockStatic(JsonUtils.class)) {
            // Create a properly structured options map with required fields
            Map<String, Object> mockOptions = new HashMap<>();
            mockOptions.put("challenge", "Y2hhbGxlbmdl");
            mockOptions.put("rpId", "example.com");
            
            // Only mock the JSON encoding/decoding
            jsonUtilsMock.when(() -> JsonUtils.decode(anyString(), any())).thenReturn(mockOptions);
            jsonUtilsMock.when(() -> JsonUtils.encode(any())).thenReturn("{\"id\":\"test-credential\"}");
            
            // Test the method
            String result = realAuth.credentialRequest(jsonOptions);
            
            // Verify
            assertNotNull(result);
            assertEquals("{\"id\":\"test-credential\"}", result);
        }
    }
    
    /**
     * Test the buildClientDataJson method with mocked dependencies.
     */
    @Test
    public void testBuildClientDataJson() {
        System.err.println("testBuildClientDataJson");
        // Setup mocks
        Map<String, Object> publicKey = new HashMap<>();
        publicKey.put("rpId", "example.com");
        publicKey.put("challenge", "challenge123".getBytes());
        
        JsonObject mockClientData = mock(JsonObject.class);
        
        try (MockedStatic<Json> jsonMock = mockStatic(Json.class)) {
            // Mock JSON builder using jakarta.json.JsonObjectBuilder
            jakarta.json.JsonObjectBuilder mockBuilder = mock(jakarta.json.JsonObjectBuilder.class);
            
            jsonMock.when(() -> Json.createObjectBuilder()).thenReturn(mockBuilder);
            when(mockBuilder.add(eq("origin"), anyString())).thenReturn(mockBuilder);
            when(mockBuilder.add(eq("challenge"), anyString())).thenReturn(mockBuilder);
            when(mockBuilder.add(eq("type"), anyString())).thenReturn(mockBuilder);
            when(mockBuilder.build()).thenReturn(mockClientData);
            
            // Test the method
            JsonObject result = authenticator.buildClientDataJson(publicKey);
            
            // Verify
            assertNotNull(result);
            assertSame(mockClientData, result);
            
            // Instead of checking that the objects are the same instance,
            // we should verify that the mock was called with the correct parameters
            verify(mockBuilder).add(eq("origin"), anyString());
            verify(mockBuilder).add(eq("challenge"), anyString());
            verify(mockBuilder).add(eq("type"), eq("webauthn.get"));
        }
    }
    
    /**
     * Test the buildAuthenticatorData method with mocked dependencies.
     */
    @Test
    public void testBuildAuthenticatorData() throws Exception {
        // Setup mocks
        Map<String, Object> publicKey = new HashMap<>();
        publicKey.put("rpId", "example.com");
        
        try (MockedStatic<MessageDigest> digestMock = mockStatic(MessageDigest.class)) {
            MessageDigest mockDigest = mock(MessageDigest.class, RETURNS_DEEP_STUBS);
            // Use lenient() to avoid UnnecessaryStubbingException
            lenient().when(mockDigest.digest()).thenReturn(new byte[32]);
            lenient().when(mockDigest.digest(any(byte[].class))).thenReturn(new byte[32]);
            digestMock.when(() -> MessageDigest.getInstance(anyString())).thenReturn(mockDigest);
            
            // Test the method with correct parameters
            byte[] result = authenticator.buildAuthenticatorData(
                    publicKey, null, null, null, keyPair);
            
            // Verify
            assertNotNull(result);
            assertTrue(result.length > 0);
            //TODO
        }
    }
    
    /**
     * Test the processAttestationStatement method with mocked dependencies.
     */
    @Test
    public void testProcessAttestationStatement() throws Exception {
        byte[] clientDataHash = "clientDataHash".getBytes();
        byte[] authData = new byte[37]; // Minimum size for auth data
        byte[] credId = "credentialId123".getBytes();
        
        // Generate real EC key pairs using KeyUtils.generateKeyPair
        KeyPair realKeyPair = KeyUtils.generateKeyPair("EC", 256);
        KeyPair realCaKeyPair = KeyUtils.generateKeyPair("EC", 256);
        
        // Generate a real X509Certificate using CertUtils
        X509Certificate realCertificate = CertUtils.generateCaCert("CN=Test CA", realCaKeyPair, 365, true);
        
        // Create a new local Fido2Authenticator instance specifically for this test
        Fido2Authenticator localAuthenticator = new Fido2Authenticator();
        localAuthenticator.setKeyPair(realKeyPair);
        
        // Test with "none" attestation using real key pair
        Map<String, Object> noneResult = localAuthenticator.processAttestationStatement(
                "none", clientDataHash, authData, credId, realKeyPair, null, null);
        
        assertNotNull(noneResult);
        assertTrue(noneResult.isEmpty()); // "none" attestation should be empty
        
        // Test with "packed" attestation using real key pairs and certificate
        Map<String, Object> packedResult = localAuthenticator.processAttestationStatement(
                "packed", clientDataHash, authData, credId, realKeyPair, realCaKeyPair, realCertificate);
        
        assertNotNull(packedResult);
        assertFalse(packedResult.isEmpty());
    }

}

// Made with Bob
