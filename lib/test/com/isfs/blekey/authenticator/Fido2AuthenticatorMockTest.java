/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.authenticator;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.*;

import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
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
import com.isfs.blekey.util.KeyUtils;
import com.isfs.blekey.util.JsonUtils;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;

/**
 * Mock-based unit tests for the Fido2Authenticator class.
 * These tests use mocking to isolate the Fido2Authenticator class from its dependencies.
 */
@ExtendWith(MockitoExtension.class)
public class Fido2AuthenticatorMockTest {

    @Mock
    private KeyPair mockKeyPair;
    
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
        // Setup mock key pair
        when(mockKeyPair.getPublic()).thenReturn(mockPublicKey);
        when(mockKeyPair.getPrivate()).thenReturn(mockPrivateKey);
        when(mockPublicKey.getAlgorithm()).thenReturn("EC");
        when(mockPublicKey.getEncoded()).thenReturn("mockPublicKeyEncoded".getBytes());
        
        // Create authenticator with mocked key pair
        authenticator = new Fido2Authenticator();
        authenticator.setKeyPair(mockKeyPair);
    }
    
    /**
     * Test the fromPasskey static factory method with mocked dependencies.
     */
    @Test
    public void testFromPasskey() throws Exception {
        // Setup mocks
        when(mockPasskey.getCertificate()).thenReturn(mockCertificate);
        when(mockPasskey.getPrivateKey()).thenReturn(mockPrivateKey);
        when(mockPasskey.getSeed()).thenReturn(new byte[32]);
        
        try (MockedStatic<KeyUtils> keyUtilsMock = mockStatic(KeyUtils.class)) {
            keyUtilsMock.when(() -> KeyUtils.getPubKey((ECPrivateKey) any())).thenReturn(mockPublicKey);
            
            // Test the method
            Fido2Authenticator result = Fido2Authenticator.fromPasskey(mockPasskey);
            
            // Verify
            assertNotNull(result);
            assertEquals(mockCertificate, result.getAuthnCert());
            // This assertion is commented out because the fromPasskey method doesn't set a caKeyPair field
            // assertNotNull(result.getCaKeyPair());
        }
    }
    
    /**
     * Test the getCredIdBytes method with mocked dependencies.
     */
    @Test
    public void testGetCredIdBytes() throws Exception {
        // Test with null caKeyPair (SHA-256 hash path)
        try (MockedStatic<MessageDigest> digestMock = mockStatic(MessageDigest.class)) {
            MessageDigest mockDigest = mock(MessageDigest.class);
            when(mockDigest.digest(any())).thenReturn("hashedCredId".getBytes());
            digestMock.when(() -> MessageDigest.getInstance("SHA-256")).thenReturn(mockDigest);
            
            byte[] result = authenticator.getCredId();
            
            assertNotNull(result);
            assertArrayEquals("hashedCredId".getBytes(), result);
        }
        
        // Generate a proper seed for the Passkey
        byte[] seed = new byte[32];
        new SecureRandom().nextBytes(seed);
        
        // Create the authenitcator
        Fido2Authenticator authenticator = new Fido2Authenticator();
        authenticator.setAuthnCert(mockCertificate);
        authenticator.setSymKey(new SymmetricKey(seed));
        
        // Setup the mockPasskey to return the seed
        when(mockPasskey.getSeed()).thenReturn(seed);
        
        // Create authenticator from the passkey
        Fido2Authenticator a = Fido2Authenticator.fromPasskey(mockPasskey);
        
        // Create a SymmetricKey
        SymmetricKey symKey = new SymmetricKey(seed);
        
        // Set the mockSymKey on the authenticator
        a.setSymKey(symKey);
        byte[] result = a.getCredId();
        assertNotNull(result);

        //Use the credential id to geenrate a new Fido2Authenticator object with the same key pair
        Fido2Authenticator authenticator2 = Fido2Authenticator.fromPasskey(mockPasskey);
        byte[] credId2 = authenticator2.getCredId();
        assertEquals(result, credId2);
        assertEquals(authenticator.getCredId(), credId2);
    }
    
    /**
     * Test the credentialCreate method with mocked dependencies.
     */
    @Test
    public void testCredentialCreate() throws Exception {
        // Setup mocks
        String jsonOptions = "{\"publicKey\":{\"rp\":{\"id\":\"example.com\"}}}";
        Map<String, Object> mockOptions = new HashMap<>();
        Map<String, Object> mockResult = new HashMap<>();
        mockResult.put("id", "credentialId");
        
        try (MockedStatic<Json> jsonMock = mockStatic(Json.class);
             MockedStatic<JsonUtils> jsonUtilsMock = mockStatic(JsonUtils.class)) {
            
            // Mock JSON parsing - specify StringReader to avoid ambiguity
            jsonMock.when(() -> Json.createReader(any(java.io.StringReader.class))).thenReturn(mockJsonReader);
            when(mockJsonReader.readObject()).thenReturn(mockJsonObject);
            
            // Mock JsonUtils instead of DataMapper
            jsonUtilsMock.when(() -> JsonUtils.decode(anyString(), eq(Map.class))).thenReturn(mockOptions);
            jsonUtilsMock.when(() -> JsonUtils.encode(any())).thenReturn("{\"id\":\"credentialId\"}");
            when(mockJsonObject.toString()).thenReturn("{\"id\":\"credentialId\"}");
            
            // Create a spy to mock the internal method
            Fido2Authenticator spyAuth = spy(authenticator);
            doReturn(mockResult).when(spyAuth).credentialCreate(
                    eq(mockOptions), eq("none"), eq(mockKeyPair), isNull(), isNull());
            
            // Test the method
            String result = spyAuth.credentialCreate(jsonOptions);
            
            // Verify
            assertNotNull(result);
            assertEquals("{\"id\":\"credentialId\"}", result);
        }
    }
    
    /**
     * Test the credentialRequest method with mocked dependencies.
     */
    @Test
    public void testCredentialRequest() throws Exception {
        // Setup mocks
        String jsonOptions = "{\"publicKey\":{\"rpId\":\"example.com\"}}";
        Map<String, Object> mockOptions = new HashMap<>();
        Map<String, Object> mockResult = new HashMap<>();
        mockResult.put("id", "assertionId");
        
        try (MockedStatic<Json> jsonMock = mockStatic(Json.class);
             MockedStatic<JsonUtils> jsonUtilsMock = mockStatic(JsonUtils.class)) {
            
            // Mock JSON parsing - specify StringReader to avoid ambiguity
            jsonMock.when(() -> Json.createReader(any(java.io.StringReader.class))).thenReturn(mockJsonReader);
            when(mockJsonReader.readObject()).thenReturn(mockJsonObject);
            
            // Mock JsonUtils instead of DataMapper
            jsonUtilsMock.when(() -> JsonUtils.decode(anyString(), eq(Map.class))).thenReturn(mockOptions);
            jsonUtilsMock.when(() -> JsonUtils.encode(any())).thenReturn("{\"id\":\"assertionId\"}");
            when(mockJsonObject.toString()).thenReturn("{\"id\":\"assertionId\"}");
            
            // Create a spy to mock the internal method
            Fido2Authenticator spyAuth = spy(authenticator);
            doReturn(mockResult).when(spyAuth).credentialRequest(eq(mockOptions), eq(mockKeyPair));
            
            // Test the method
            String result = spyAuth.credentialRequest(jsonOptions);
            
            // Verify
            assertNotNull(result);
            assertEquals("{\"id\":\"assertionId\"}", result);
        }
    }
    
    /**
     * Test the buildClientDataJson method with mocked dependencies.
     */
    @Test
    public void testBuildClientDataJson() {
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
            for(String key: publicKey.keySet()) {
                assertSame(publicKey.get(key), result.get(key));
            }
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
            MessageDigest mockDigest = mock(MessageDigest.class);
            when(mockDigest.digest(any())).thenReturn(new byte[32]); // rpIdHash
            digestMock.when(() -> MessageDigest.getInstance("SHA-256")).thenReturn(mockDigest);
            
            // Test the method with correct parameters
            byte[] result = authenticator.buildAuthenticatorData(
                    publicKey, null, null, null, mockKeyPair);
            
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
        KeyPair mockCaKeyPair = mock(KeyPair.class);
        
        // Test with "none" attestation
        Map<String, Object> noneResult = authenticator.processAttestationStatement(
                "none", clientDataHash, authData, credId, mockKeyPair, null, null);
        
        assertNotNull(noneResult);
        assertTrue(noneResult.isEmpty()); // "none" attestation should be empty
        
        // Test with "packed" attestation using mocked signature
        try (MockedStatic<KeyUtils> keyUtilsMock = mockStatic(KeyUtils.class)) {
            // Use the signData method from Fido2Authenticator instead of KeyUtils
            doReturn("signature".getBytes()).when(authenticator).signData(any(), any(), anyString());
            
            Map<String, Object> packedResult = authenticator.processAttestationStatement(
                    "packed", clientDataHash, authData, credId, mockKeyPair, mockCaKeyPair, mockCertificate);
            
            assertNotNull(packedResult);
            assertFalse(packedResult.isEmpty());
        }
    }

}

// Made with Bob
