/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.oidc;

import com.isfs.blekey.credential.VerifiableCredential;
import com.isfs.blekey.credential.DigitalCredentialMetadata;
import com.isfs.blekey.util.HolderBindingKeyManager;
import com.isfs.blekey.util.http.HttpClient;
import com.isfs.blekey.util.http.HttpResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for Oidc4VpHandler.
 * Tests presentation flow, selective disclosure, and VP token creation.
 */
public class Oidc4VpHandlerTest {
    
    private HttpClient mockHttpClient;
    private Oidc4VpHandler handler;
    private PrivateKey masterKey;
    private VerifiableCredential testCredential;
    
    @BeforeEach
    public void setUp() throws Exception {
        mockHttpClient = mock(HttpClient.class);
        handler = new Oidc4VpHandler(mockHttpClient);
        
        // Generate test master key
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        KeyPair keyPair = keyGen.generateKeyPair();
        masterKey = keyPair.getPrivate();
        
        // Create test credential
        testCredential = createTestCredential();
    }
    
    private VerifiableCredential createTestCredential() {
        VerifiableCredential credential = new VerifiableCredential();
        credential.setId("test-cred-123");
        
        // Set holder binding key seed
        byte[] seed = HolderBindingKeyManager.generateSeed();
        credential.setHolderBindingKeySeed(seed);
        
        // Set metadata
        DigitalCredentialMetadata metadata = credential.getMetadata();
        metadata.setIssuerDid("did:example:issuer");
        metadata.setCredentialType("UniversityDegree");
        
        // Set SD-JWT data (issuer JWT + disclosures)
        String sdJwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZTppc3N1ZXIifQ.sig~" +
                      "WyJzYWx0MSIsIm5hbWUiLCJKb2huIERvZSJd~" +
                      "WyJzYWx0MiIsImRlZ3JlZSIsIkJhY2hlbG9yIl0";
        credential.setEncryptedData(sdJwt.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        
        return credential;
    }
    
    @Test
    public void testPresentCredential_Success() throws Exception {
        String authRequest = "openid://?client_id=verifier123&" +
            "response_uri=https://verifier.example.com/response&" +
            "nonce=test-nonce&" +
            "state=test-state&" +
            "presentation_definition=" + java.net.URLEncoder.encode(
                "{\"id\":\"pd-1\",\"input_descriptors\":[{\"id\":\"input-1\"}]}", "UTF-8");
        
        Set<String> selectedClaims = new HashSet<>(Arrays.asList("name", "degree"));
        
        when(mockHttpClient.postWithRetry(anyString(), anyString(), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), "{\"status\":\"ok\"}"));
        
        String response = handler.presentCredential(authRequest, testCredential, selectedClaims, masterKey);
        
        assertNotNull(response);
        assertEquals("{\"status\":\"ok\"}", response);
        verify(mockHttpClient).postWithRetry(anyString(), anyString(), any(), any());
    }
    
    @Test
    public void testPresentCredential_MissingPresentationDefinition() {
        String authRequest = "openid://?client_id=verifier123&" +
            "response_uri=https://verifier.example.com/response&" +
            "nonce=test-nonce";
        
        Set<String> selectedClaims = new HashSet<>(Arrays.asList("name"));
        
        OidcException exception = assertThrows(OidcException.class, () -> {
            handler.presentCredential(authRequest, testCredential, selectedClaims, masterKey);
        });
        
        assertTrue(exception.getMessage().contains("Presentation definition not found"));
    }
    
    @Test
    public void testPresentCredential_WithRequestUri() throws Exception {
        String authRequest = "openid://?request_uri=https://verifier.example.com/request/123";
        
        // Mock request object fetch
        String requestObject = "eyJhbGciOiJFUzI1NiJ9." +
            java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
                ("{\"client_id\":\"verifier123\"," +
                 "\"response_uri\":\"https://verifier.example.com/response\"," +
                 "\"nonce\":\"nonce123\"," +
                 "\"presentation_definition\":{\"id\":\"pd-1\",\"input_descriptors\":[{\"id\":\"input-1\"}]}}").getBytes()
            ) + ".sig";
        
        when(mockHttpClient.get("https://verifier.example.com/request/123"))
            .thenReturn(new HttpResponse(200, Map.of(), requestObject));
        
        when(mockHttpClient.postWithRetry(anyString(), anyString(), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), "{}"));
        
        Set<String> selectedClaims = new HashSet<>(Arrays.asList("name"));
        
        String response = handler.presentCredential(authRequest, testCredential, selectedClaims, masterKey);
        
        assertNotNull(response);
        verify(mockHttpClient).get("https://verifier.example.com/request/123");
    }
    
    @Test
    public void testCreatePresentation_Success() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256); // P-256 curve
        KeyPair holderKey = keyGen.generateKeyPair();
        
        PresentationDefinition presentationDef = PresentationDefinition.fromJson(
            "{\"id\":\"pd-1\",\"input_descriptors\":[{\"id\":\"input-1\"}]}");
        
        List<String> disclosedClaims = Arrays.asList("name", "degree");
        
        String vpToken = handler.createPresentation(
            testCredential,
            holderKey.getPrivate(),
            presentationDef,
            disclosedClaims
        );
        
        assertNotNull(vpToken);
        assertTrue(vpToken.contains("~")); // SD-JWT format with separators
        
        // Verify it contains issuer JWT and key binding JWT
        String[] parts = vpToken.split("~");
        assertTrue(parts.length >= 2); // At least issuer JWT and KB-JWT
    }
    
    @Test
    public void testCreatePresentation_EmptyDisclosures() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256); // P-256 curve
        KeyPair holderKey = keyGen.generateKeyPair();
        
        PresentationDefinition presentationDef = PresentationDefinition.fromJson(
            "{\"id\":\"pd-1\",\"input_descriptors\":[{\"id\":\"input-1\"}]}");
        
        List<String> disclosedClaims = Collections.emptyList();
        
        String vpToken = handler.createPresentation(
            testCredential,
            holderKey.getPrivate(),
            presentationDef,
            disclosedClaims
        );
        
        assertNotNull(vpToken);
        assertTrue(vpToken.contains("~"));
    }
    
    @Test
    public void testSubmitPresentation_Success() throws Exception {
        String responseUri = "https://verifier.example.com/response";
        String vpToken = "issuer.jwt~disclosure1~kb.jwt";
        
        when(mockHttpClient.postWithRetry(eq(responseUri), anyString(), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), "{\"status\":\"verified\"}"));
        
        boolean result = handler.submitPresentation(responseUri, vpToken);
        
        assertTrue(result);
        verify(mockHttpClient).postWithRetry(eq(responseUri), anyString(), any(), any());
    }
    
    @Test
    public void testSubmitPresentation_Failure() throws Exception {
        String responseUri = "https://verifier.example.com/response";
        String vpToken = "issuer.jwt~kb.jwt";
        
        when(mockHttpClient.postWithRetry(eq(responseUri), anyString(), any(), any()))
            .thenReturn(new HttpResponse(400, Map.of(), "{\"error\":\"invalid_presentation\"}"));
        
        OidcException exception = assertThrows(OidcException.class, () -> {
            handler.submitPresentation(responseUri, vpToken);
        });
        
        assertTrue(exception.getMessage().contains("Presentation submission failed"));
    }
    
    @Test
    public void testBindingKeyCache_HitAndMiss() throws Exception {
        assertEquals(0, handler.getCacheSize());
        
        String authRequest = "openid://?client_id=verifier&" +
            "response_uri=https://verifier.example.com/response&" +
            "nonce=nonce&" +
            "presentation_definition=" + java.net.URLEncoder.encode(
                "{\"id\":\"pd-1\",\"input_descriptors\":[{\"id\":\"input-1\"}]}", "UTF-8");
        
        when(mockHttpClient.postWithRetry(anyString(), anyString(), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), "{}"));
        
        Set<String> claims = new HashSet<>(Arrays.asList("name"));
        
        // First call - cache miss
        handler.presentCredential(authRequest, testCredential, claims, masterKey);
        assertEquals(1, handler.getCacheSize());
        
        // Second call - cache hit
        handler.presentCredential(authRequest, testCredential, claims, masterKey);
        assertEquals(1, handler.getCacheSize());
    }
    
    @Test
    public void testClearBindingKeyCache() throws Exception {
        String authRequest = "openid://?client_id=verifier&" +
            "response_uri=https://verifier.example.com/response&" +
            "nonce=nonce&" +
            "presentation_definition=" + java.net.URLEncoder.encode(
                "{\"id\":\"pd-1\",\"input_descriptors\":[{\"id\":\"input-1\"}]}", "UTF-8");
        
        when(mockHttpClient.postWithRetry(anyString(), anyString(), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), "{}"));
        
        Set<String> claims = new HashSet<>(Arrays.asList("name"));
        
        handler.presentCredential(authRequest, testCredential, claims, masterKey);
        assertEquals(1, handler.getCacheSize());
        
        handler.clearBindingKeyCache();
        assertEquals(0, handler.getCacheSize());
    }
    
    @Test
    public void testEvictBindingKey() throws Exception {
        String authRequest = "openid://?client_id=verifier&" +
            "response_uri=https://verifier.example.com/response&" +
            "nonce=nonce&" +
            "presentation_definition=" + java.net.URLEncoder.encode(
                "{\"id\":\"pd-1\",\"input_descriptors\":[{\"id\":\"input-1\"}]}", "UTF-8");
        
        when(mockHttpClient.postWithRetry(anyString(), anyString(), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), "{}"));
        
        Set<String> claims = new HashSet<>(Arrays.asList("name"));
        
        handler.presentCredential(authRequest, testCredential, claims, masterKey);
        assertEquals(1, handler.getCacheSize());
        
        handler.evictBindingKey(testCredential);
        assertEquals(0, handler.getCacheSize());
    }
    
    @Test
    public void testCleanupExpiredKeys() throws Exception {
        // This test would require manipulating time or waiting for expiration
        // For now, test that cleanup doesn't fail on empty cache
        int removed = handler.cleanupExpiredKeys();
        assertEquals(0, removed);
    }
    
    @Test
    public void testConstructor_DefaultHttpClient() {
        Oidc4VpHandler defaultHandler = new Oidc4VpHandler();
        assertNotNull(defaultHandler);
        assertEquals(0, defaultHandler.getCacheSize());
    }
    
    @Test
    public void testConstructor_CustomHttpClient() {
        HttpClient customClient = new HttpClient();
        Oidc4VpHandler customHandler = new Oidc4VpHandler(customClient);
        assertNotNull(customHandler);
        assertEquals(0, customHandler.getCacheSize());
    }
    
    @Test
    public void testPresentCredential_NoCredentialData() throws Exception {
        VerifiableCredential emptyCredential = new VerifiableCredential();
        emptyCredential.setId("empty-cred");
        emptyCredential.setHolderBindingKeySeed(HolderBindingKeyManager.generateSeed());
        
        DigitalCredentialMetadata metadata = emptyCredential.getMetadata();
        metadata.setIssuerDid("did:example:issuer");
        metadata.setCredentialType("TestCredential");
        
        String authRequest = "openid://?client_id=verifier&" +
            "response_uri=https://verifier.example.com/response&" +
            "nonce=nonce&" +
            "presentation_definition=" + java.net.URLEncoder.encode(
                "{\"id\":\"pd-1\",\"input_descriptors\":[{\"id\":\"input-1\"}]}", "UTF-8");
        
        Set<String> claims = new HashSet<>(Arrays.asList("name"));
        
        assertThrows(Exception.class, () -> {
            handler.presentCredential(authRequest, emptyCredential, claims, masterKey);
        });
    }
}

// Made with Bob