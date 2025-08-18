package com.isfs.blekey.authenticator;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import com.isfs.blekey.data.Passkey;
import com.isfs.blekey.util.Cbor;
import com.isfs.blekey.util.CertUtils;
import com.isfs.blekey.util.DataMapper;
import com.isfs.blekey.util.KeyUtils;
import com.macasaet.fernet.Key;
import com.macasaet.fernet.Token;

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
            keyUtilsMock.when(() -> KeyUtils.getPubKey(any())).thenReturn(mockPublicKey);
            
            // Test the method
            Fido2Authenticator result = Fido2Authenticator.fromPasskey(mockPasskey);
            
            // Verify
            assertNotNull(result);
            assertEquals(mockCertificate, result.getCaCert());
            assertNotNull(result.getCaKeyPair());
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
            
            byte[] result = authenticator.getCredIdBytes();
            
            assertNotNull(result);
            assertArrayEquals("hashedCredId".getBytes(), result);
        }
        
        // Test with non-null caKeyPair (Token path)
        KeyPair mockCaKeyPair = mock(KeyPair.class);
        authenticator.setCaKeyPair(mockCaKeyPair);
        Key mockKey = mock(Key.class);
        authenticator.setFKey(mockKey);
        
        try (MockedStatic<Token> tokenMock = mockStatic(Token.class)) {
            Token mockToken = mock(Token.class);
            when(mockToken.toString()).thenReturn("mockToken");
            tokenMock.when(() -> Token.generate(eq(mockKey), any())).thenReturn(mockToken);
            
            byte[] result = authenticator.getCredIdBytes();
            
            assertNotNull(result);
        }
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
             MockedStatic<DataMapper> mapperMock = mockStatic(DataMapper.class)) {
            
            // Mock JSON parsing
            jsonMock.when(() -> Json.createReader(any())).thenReturn(mockJsonReader);
            when(mockJsonReader.readObject()).thenReturn(mockJsonObject);
            
            // Mock DataMapper
            mapperMock.when(() -> DataMapper.jsonToMap(mockJsonObject)).thenReturn(mockOptions);
            mapperMock.when(() -> DataMapper.objectToJson(any())).thenReturn(mockJsonObject);
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
             MockedStatic<DataMapper> mapperMock = mockStatic(DataMapper.class)) {
            
            // Mock JSON parsing
            jsonMock.when(() -> Json.createReader(any())).thenReturn(mockJsonReader);
            when(mockJsonReader.readObject()).thenReturn(mockJsonObject);
            
            // Mock DataMapper
            mapperMock.when(() -> DataMapper.jsonToMap(mockJsonObject)).thenReturn(mockOptions);
            mapperMock.when(() -> DataMapper.objectToJson(any())).thenReturn(mockJsonObject);
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
            // Mock JSON builder
            Json.JsonObjectBuilder mockBuilder = mock(Json.JsonObjectBuilder.class);
            Json.JsonObjectBuilder mockNestedBuilder = mock(Json.JsonObjectBuilder.class);
            
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
        }
    }
    
    /**
     * Test the buildAuthenticatorData method with mocked dependencies.
     */
    @Test
    public void testBuildAuthenticatorData() throws Exception {
        // Setup mocks
        JsonObject mockClientData = mock(JsonObject.class);
        Map<String, Object> publicKey = new HashMap<>();
        publicKey.put("rpId", "example.com");
        
        try (MockedStatic<MessageDigest> digestMock = mockStatic(MessageDigest.class)) {
            MessageDigest mockDigest = mock(MessageDigest.class);
            when(mockDigest.digest(any())).thenReturn(new byte[32]); // rpIdHash
            digestMock.when(() -> MessageDigest.getInstance("SHA-256")).thenReturn(mockDigest);
            
            // Test the method
            byte[] result = authenticator.buildAuthenticatorData(
                    mockClientData, publicKey, null, null, null, mockKeyPair);
            
            // Verify
            assertNotNull(result);
            assertTrue(result.length > 0);
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
            keyUtilsMock.when(() -> KeyUtils.signData(any(), any(), any())).thenReturn("signature".getBytes());
            
            Map<String, Object> packedResult = authenticator.processAttestationStatement(
                    "packed", clientDataHash, authData, credId, mockKeyPair, mockCaKeyPair, mockCertificate);
            
            assertNotNull(packedResult);
            assertFalse(packedResult.isEmpty());
        }
    }
    
    /**
     * Helper method to set the CA key pair and certificate in the authenticator.
     */
    private void setCaKeyPair(KeyPair caKeyPair, X509Certificate caCert) {
        try {
            java.lang.reflect.Field caKeyPairField = Fido2Authenticator.class.getDeclaredField("caKeyPair");
            caKeyPairField.setAccessible(true);
            caKeyPairField.set(authenticator, caKeyPair);
            
            java.lang.reflect.Field caCertField = Fido2Authenticator.class.getDeclaredField("caCert");
            caCertField.setAccessible(true);
            caCertField.set(authenticator, caCert);
        } catch (Exception e) {
            fail("Failed to set CA key pair: " + e.getMessage());
        }
    }
    
    /**
     * Helper method to set the fKey in the authenticator.
     */
    private void setFKey(Key fKey) {
        try {
            java.lang.reflect.Field fKeyField = Fido2Authenticator.class.getDeclaredField("fKey");
            fKeyField.setAccessible(true);
            fKeyField.set(authenticator, fKey);
        } catch (Exception e) {
            fail("Failed to set fKey: " + e.getMessage());
        }
    }
}

// Made with Bob
