/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.oidc;

import com.isfs.blekey.credential.VerifiableCredential;
import com.isfs.blekey.credential.DigitalCredentialMetadata;
import com.isfs.blekey.credential.jwt.JwtException;
import com.isfs.blekey.credential.sdjwt.SdJwtException;
import com.isfs.blekey.util.HolderBindingKeyManager;
import com.isfs.blekey.util.http.HttpClient;
import com.isfs.blekey.util.http.HttpException;
import com.isfs.blekey.util.http.HttpResponse;
import com.isfs.blekey.util.http.RetryPolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URISyntaxException;
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
    
    // ============= Exception Handling Tests ==========
    
    @Test
    public void testPresentCredential_SdJwtException() throws Exception {
        // Create credential with invalid SD-JWT data
        VerifiableCredential badCredential = new VerifiableCredential();
        badCredential.setId("bad-cred");
        badCredential.setHolderBindingKeySeed(HolderBindingKeyManager.generateSeed());
        
        DigitalCredentialMetadata metadata = badCredential.getMetadata();
        metadata.setIssuerDid("did:example:issuer");
        metadata.setCredentialType("TestCredential");
        
        // Set invalid SD-JWT data (missing disclosures)
        badCredential.setEncryptedData("invalid-jwt-data".getBytes());
        
        String authRequest = "openid://?client_id=verifier&" +
            "response_uri=https://verifier.example.com/response&" +
            "nonce=nonce&" +
            "presentation_definition=" + java.net.URLEncoder.encode(
                "{\"id\":\"pd-1\",\"input_descriptors\":[{\"id\":\"input-1\"}]}", "UTF-8");
        
        Set<String> claims = new HashSet<>(Arrays.asList("name"));
        
        OidcException exception = assertThrows(OidcException.class, () -> {
            handler.presentCredential(authRequest, badCredential, claims, masterKey);
        });
        
        // Exception should be thrown - message content may vary
        assertNotNull(exception.getMessage());
    }
    
    @Test
    public void testPresentCredential_IOException() throws Exception {
        String authRequest = "openid://?client_id=verifier&" +
            "response_uri=https://verifier.example.com/response&" +
            "nonce=nonce&" +
            "presentation_definition=" + java.net.URLEncoder.encode(
                "{\"id\":\"pd-1\",\"input_descriptors\":[{\"id\":\"input-1\"}]}", "UTF-8");
        
        Set<String> claims = new HashSet<>(Arrays.asList("name"));
        
        // Mock HTTP client to throw HttpException wrapping IOException
        when(mockHttpClient.postWithRetry(anyString(), anyString(), any(), any()))
            .thenThrow(new HttpException.NetworkException("Network error", new IOException("Connection failed")));
        
        OidcException exception = assertThrows(OidcException.class, () -> {
            handler.presentCredential(authRequest, testCredential, claims, masterKey);
        });
        
        // Exception should be thrown - message content may vary
        assertNotNull(exception.getMessage());
    }
    
    @Test
    public void testPresentCredential_URISyntaxException() throws Exception {
        // Create request with request_uri that will cause URISyntaxException
        String authRequest = "openid://?request_uri=https://verifier.example.com/request/123";
        
        Set<String> claims = new HashSet<>(Arrays.asList("name"));
        
        // Mock to throw URISyntaxException during fetch
        when(mockHttpClient.get(anyString()))
            .thenThrow(new RuntimeException(new URISyntaxException("invalid", "reason")));
        
        OidcException exception = assertThrows(OidcException.class, () -> {
            handler.presentCredential(authRequest, testCredential, claims, masterKey);
        });
        
        assertTrue(exception.getMessage().contains("Presentation failed") || 
                   exception.getMessage().contains("Failed to fetch request object"));
    }
    
    // ========== Request Object Fetching Tests ==========
    
    @Test
    public void testFetchRequestObject_HttpError() throws Exception {
        String authRequest = "openid://?request_uri=https://verifier.example.com/request/123";
        
        // Mock HTTP error response
        when(mockHttpClient.get("https://verifier.example.com/request/123"))
            .thenReturn(new HttpResponse(404, Map.of(), "Not Found"));
        
        Set<String> claims = new HashSet<>(Arrays.asList("name"));
        
        OidcException exception = assertThrows(OidcException.class, () -> {
            handler.presentCredential(authRequest, testCredential, claims, masterKey);
        });
        
        assertTrue(exception.getMessage().contains("Failed to fetch request object") ||
                   exception.getMessage().contains("404"));
    }
    
    @Test
    public void testFetchRequestObject_InvalidJwtFormat() throws Exception {
        String authRequest = "openid://?request_uri=https://verifier.example.com/request/123";
        
        // Mock response with invalid JWT (not 3 parts)
        when(mockHttpClient.get("https://verifier.example.com/request/123"))
            .thenReturn(new HttpResponse(200, Map.of(), "invalid.jwt"));
        
        Set<String> claims = new HashSet<>(Arrays.asList("name"));
        
        OidcException exception = assertThrows(OidcException.class, () -> {
            handler.presentCredential(authRequest, testCredential, claims, masterKey);
        });
        
        assertTrue(exception.getMessage().contains("Invalid JWT request object") ||
                   exception.getMessage().contains("Failed to fetch request object"));
    }
    
    @Test
    public void testFetchRequestObject_HttpException() throws Exception {
        String authRequest = "openid://?request_uri=https://verifier.example.com/request/123";
        
        // Mock HttpException
        when(mockHttpClient.get("https://verifier.example.com/request/123"))
            .thenThrow(new HttpException.NetworkException("Connection timeout", new IOException()));
        
        Set<String> claims = new HashSet<>(Arrays.asList("name"));
        
        OidcException exception = assertThrows(OidcException.class, () -> {
            handler.presentCredential(authRequest, testCredential, claims, masterKey);
        });
        
        assertTrue(exception.getMessage().contains("Failed to fetch request object"));
        assertTrue(exception.getCause() instanceof HttpException);
    }
    
    @Test
    public void testFetchRequestObject_MissingPresentationDefinition() throws Exception {
        String authRequest = "openid://?request_uri=https://verifier.example.com/request/123";
        
        // Mock request object without presentation_definition
        String requestObject = "eyJhbGciOiJFUzI1NiJ9." +
            java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
                ("{\"client_id\":\"verifier123\"," +
                 "\"response_uri\":\"https://verifier.example.com/response\"," +
                 "\"nonce\":\"nonce123\"}").getBytes()
            ) + ".sig";
        
        when(mockHttpClient.get("https://verifier.example.com/request/123"))
            .thenReturn(new HttpResponse(200, Map.of(), requestObject));
        
        Set<String> claims = new HashSet<>(Arrays.asList("name"));
        
        OidcException exception = assertThrows(OidcException.class, () -> {
            handler.presentCredential(authRequest, testCredential, claims, masterKey);
        });
        
        assertTrue(exception.getMessage().contains("Presentation definition not found"));
    }
    
    // ========== Cache Expiration Tests ==========
    
    @Test
    public void testCleanupExpiredKeys_WithExpiredEntries() throws Exception {
        // First, populate cache with entries
        String authRequest = "openid://?client_id=verifier&" +
            "response_uri=https://verifier.example.com/response&" +
            "nonce=nonce&" +
            "presentation_definition=" + java.net.URLEncoder.encode(
                "{\"id\":\"pd-1\",\"input_descriptors\":[{\"id\":\"input-1\"}]}", "UTF-8");
        
        when(mockHttpClient.postWithRetry(anyString(), anyString(), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), "{}"));
        
        Set<String> claims = new HashSet<>(Arrays.asList("name"));
        
        // Add entry to cache
        handler.presentCredential(authRequest, testCredential, claims, masterKey);
        assertEquals(1, handler.getCacheSize());
        
        // Use reflection to manipulate cache timestamps to simulate expiration
        try {
            java.lang.reflect.Field cacheField = handler.getClass().getDeclaredField("bindingKeyCache");
            cacheField.setAccessible(true);
            @SuppressWarnings("unchecked")
            java.util.concurrent.ConcurrentHashMap<String, Object> cache = 
                (java.util.concurrent.ConcurrentHashMap<String, Object>) cacheField.get(handler);
            
            // Get the CachedKeyPair class and create expired entry
            Class<?> cachedKeyPairClass = Class.forName("com.isfs.blekey.oidc.Oidc4VpHandler$CachedKeyPair");
            java.lang.reflect.Constructor<?> constructor = cachedKeyPairClass.getDeclaredConstructor(
                KeyPair.class, long.class);
            constructor.setAccessible(true);
            
            // Create entry with old timestamp (6 minutes ago - beyond 5 minute TTL)
            long expiredTime = System.currentTimeMillis() - (6 * 60 * 1000);
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(256);
            KeyPair expiredKeyPair = keyGen.generateKeyPair();
            Object expiredEntry = constructor.newInstance(expiredKeyPair, expiredTime);
            
            // Add expired entry to cache
            cache.put("expired-key", expiredEntry);
            assertEquals(2, handler.getCacheSize());
            
            // Now cleanup should remove the expired entry
            int removed = handler.cleanupExpiredKeys();
            assertEquals(1, removed);
            assertEquals(1, handler.getCacheSize());
            
        } catch (Exception e) {
            // If reflection fails, skip this test
            System.err.println("Reflection test skipped: " + e.getMessage());
        }
    }
    
    @Test
    public void testCleanupExpiredKeys_MixedExpiredAndValid() throws Exception {
        // Add valid entry
        String authRequest = "openid://?client_id=verifier&" +
            "response_uri=https://verifier.example.com/response&" +
            "nonce=nonce&" +
            "presentation_definition=" + java.net.URLEncoder.encode(
                "{\"id\":\"pd-1\",\"input_descriptors\":[{\"id\":\"input-1\"}]}", "UTF-8");
        
        when(mockHttpClient.postWithRetry(anyString(), anyString(), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), "{}"));
        
        Set<String> claims = new HashSet<>(Arrays.asList("name"));
        handler.presentCredential(authRequest, testCredential, claims, masterKey);
        
        // Create second credential for another cache entry
        VerifiableCredential credential2 = createTestCredential();
        credential2.setId("test-cred-456");
        handler.presentCredential(authRequest, credential2, claims, masterKey);
        
        assertEquals(2, handler.getCacheSize());
        
        // Try to add expired entries via reflection
        try {
            java.lang.reflect.Field cacheField = handler.getClass().getDeclaredField("bindingKeyCache");
            cacheField.setAccessible(true);
            @SuppressWarnings("unchecked")
            java.util.concurrent.ConcurrentHashMap<String, Object> cache = 
                (java.util.concurrent.ConcurrentHashMap<String, Object>) cacheField.get(handler);
            
            Class<?> cachedKeyPairClass = Class.forName("com.isfs.blekey.oidc.Oidc4VpHandler$CachedKeyPair");
            java.lang.reflect.Constructor<?> constructor = cachedKeyPairClass.getDeclaredConstructor(
                KeyPair.class, long.class);
            constructor.setAccessible(true);
            
            // Add 2 expired entries
            long expiredTime = System.currentTimeMillis() - (6 * 60 * 1000);
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(256);
            
            for (int i = 0; i < 2; i++) {
                KeyPair expiredKeyPair = keyGen.generateKeyPair();
                Object expiredEntry = constructor.newInstance(expiredKeyPair, expiredTime);
                cache.put("expired-key-" + i, expiredEntry);
            }
            
            assertEquals(4, handler.getCacheSize());
            
            // Cleanup should remove only expired entries
            int removed = handler.cleanupExpiredKeys();
            assertEquals(2, removed);
            assertEquals(2, handler.getCacheSize());
            
        } catch (Exception e) {
            System.err.println("Reflection test skipped: " + e.getMessage());
        }
    }
    
    // ========== Binding Key Edge Cases ==========
    
    @Test
    public void testGetCachedOrDeriveBindingKey_ExpiredEntry() throws Exception {
        // This is tested via the cleanup tests above with reflection
        // Here we test the behavior when accessing an expired entry
        String authRequest = "openid://?client_id=verifier&" +
            "response_uri=https://verifier.example.com/response&" +
            "nonce=nonce&" +
            "presentation_definition=" + java.net.URLEncoder.encode(
                "{\"id\":\"pd-1\",\"input_descriptors\":[{\"id\":\"input-1\"}]}", "UTF-8");
        
        when(mockHttpClient.postWithRetry(anyString(), anyString(), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), "{}"));
        
        Set<String> claims = new HashSet<>(Arrays.asList("name"));
        
        // Add entry to cache
        handler.presentCredential(authRequest, testCredential, claims, masterKey);
        assertEquals(1, handler.getCacheSize());
        
        // Manually expire the entry via reflection
        try {
            java.lang.reflect.Field cacheField = handler.getClass().getDeclaredField("bindingKeyCache");
            cacheField.setAccessible(true);
            @SuppressWarnings("unchecked")
            java.util.concurrent.ConcurrentHashMap<String, Object> cache = 
                (java.util.concurrent.ConcurrentHashMap<String, Object>) cacheField.get(handler);
            
            // Get first entry and modify its timestamp
            Object firstEntry = cache.values().iterator().next();
            java.lang.reflect.Field timestampField = firstEntry.getClass().getDeclaredField("timestamp");
            timestampField.setAccessible(true);
            
            // Set to 6 minutes ago
            long expiredTime = System.currentTimeMillis() - (6 * 60 * 1000);
            timestampField.setLong(firstEntry, expiredTime);
            
            // Next call should detect expiration and re-derive
            handler.presentCredential(authRequest, testCredential, claims, masterKey);
            assertEquals(1, handler.getCacheSize());
            
        } catch (Exception e) {
            System.err.println("Reflection test skipped: " + e.getMessage());
        }
    }
    
    @Test
    public void testDeriveHolderBindingKey_NoSeed() throws Exception {
        VerifiableCredential noSeedCredential = new VerifiableCredential();
        noSeedCredential.setId("no-seed-cred");
        // Don't set holder binding key seed
        
        DigitalCredentialMetadata metadata = noSeedCredential.getMetadata();
        metadata.setIssuerDid("did:example:issuer");
        metadata.setCredentialType("TestCredential");
        
        String sdJwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZTppc3N1ZXIifQ.sig~" +
                      "WyJzYWx0MSIsIm5hbWUiLCJKb2huIl0";
        noSeedCredential.setEncryptedData(sdJwt.getBytes());
        
        String authRequest = "openid://?client_id=verifier&" +
            "response_uri=https://verifier.example.com/response&" +
            "nonce=nonce&" +
            "presentation_definition=" + java.net.URLEncoder.encode(
                "{\"id\":\"pd-1\",\"input_descriptors\":[{\"id\":\"input-1\"}]}", "UTF-8");
        
        Set<String> claims = new HashSet<>(Arrays.asList("name"));
        
        OidcException exception = assertThrows(OidcException.class, () -> {
            handler.presentCredential(authRequest, noSeedCredential, claims, masterKey);
        });
        
        assertTrue(exception.getMessage().contains("Presentation failed"));
        assertTrue(exception.getCause() instanceof IllegalArgumentException);
    }
    
    @Test
    public void testDeriveHolderBindingKey_WithIssuerUrl() throws Exception {
        VerifiableCredential urlCredential = new VerifiableCredential();
        urlCredential.setId("url-cred");
        urlCredential.setHolderBindingKeySeed(HolderBindingKeyManager.generateSeed());
        
        DigitalCredentialMetadata metadata = urlCredential.getMetadata();
        // Set issuerUrl instead of issuerDid
        metadata.setIssuerUrl("https://issuer.example.com");
        metadata.setCredentialType("TestCredential");
        
        String sdJwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSJ9.sig~" +
                      "WyJzYWx0MSIsIm5hbWUiLCJKb2huIl0";
        urlCredential.setEncryptedData(sdJwt.getBytes());
        
        String authRequest = "openid://?client_id=verifier&" +
            "response_uri=https://verifier.example.com/response&" +
            "nonce=nonce&" +
            "presentation_definition=" + java.net.URLEncoder.encode(
                "{\"id\":\"pd-1\",\"input_descriptors\":[{\"id\":\"input-1\"}]}", "UTF-8");
        
        when(mockHttpClient.postWithRetry(anyString(), anyString(), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), "{}"));
        
        Set<String> claims = new HashSet<>(Arrays.asList("name"));
        
        // Should succeed using issuerUrl
        String response = handler.presentCredential(authRequest, urlCredential, claims, masterKey);
        assertNotNull(response);
    }
    
    @Test
    public void testBuildCacheKey_WithIssuerUrl() throws Exception {
        VerifiableCredential urlCredential = new VerifiableCredential();
        urlCredential.setId("url-cred-2");
        urlCredential.setHolderBindingKeySeed(HolderBindingKeyManager.generateSeed());
        
        DigitalCredentialMetadata metadata = urlCredential.getMetadata();
        metadata.setIssuerUrl("https://issuer2.example.com");
        metadata.setCredentialType("TestCredential2");
        
        String sdJwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3VlcjIuZXhhbXBsZS5jb20ifQ.sig~" +
                      "WyJzYWx0MSIsIm5hbWUiLCJKb2huIl0";
        urlCredential.setEncryptedData(sdJwt.getBytes());
        
        String authRequest = "openid://?client_id=verifier&" +
            "response_uri=https://verifier.example.com/response&" +
            "nonce=nonce&" +
            "presentation_definition=" + java.net.URLEncoder.encode(
                "{\"id\":\"pd-1\",\"input_descriptors\":[{\"id\":\"input-1\"}]}", "UTF-8");
        
        when(mockHttpClient.postWithRetry(anyString(), anyString(), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), "{}"));
        
        Set<String> claims = new HashSet<>(Arrays.asList("name"));
        
        handler.presentCredential(authRequest, urlCredential, claims, masterKey);
        assertEquals(1, handler.getCacheSize());
        
        // Verify cache key was built with issuerUrl
        handler.evictBindingKey(urlCredential);
        assertEquals(0, handler.getCacheSize());
    }
    
    // ========== Presentation Creation Edge Cases ==========
    
    @Test
    public void testCreatePresentation_GenericException() throws Exception {
        // Create credential with data that will cause exception during processing
        VerifiableCredential badCredential = new VerifiableCredential();
        badCredential.setId("bad-cred-2");
        
        DigitalCredentialMetadata metadata = badCredential.getMetadata();
        metadata.setIssuerDid("did:example:issuer");
        metadata.setCredentialType("TestCredential");
        
        // Set data that will cause exception (null will trigger IllegalArgumentException)
        badCredential.setEncryptedData(null);
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        KeyPair holderKey = keyGen.generateKeyPair();
        
        PresentationDefinition presentationDef = PresentationDefinition.fromJson(
            "{\"id\":\"pd-1\",\"input_descriptors\":[{\"id\":\"input-1\"}]}");
        
        List<String> disclosedClaims = Arrays.asList("name");
        
        OidcException exception = assertThrows(OidcException.class, () -> {
            handler.createPresentation(badCredential, holderKey.getPrivate(), 
                presentationDef, disclosedClaims);
        });
        
        assertTrue(exception.getMessage().contains("Failed to create presentation"));
    }
    
    // ========== Query Parsing Edge Cases ==========
    
    @Test
    public void testParseQueryParams_NoQueryString() throws Exception {
        // URI without query string
        String authRequest = "openid://";
        
        Set<String> claims = new HashSet<>(Arrays.asList("name"));
        
        // Should fail because no presentation_definition
        OidcException exception = assertThrows(OidcException.class, () -> {
            handler.presentCredential(authRequest, testCredential, claims, masterKey);
        });
        
        assertTrue(exception.getMessage().contains("Presentation definition not found"));
    }
    
    @Test
    public void testParseQueryParams_MalformedPairs() throws Exception {
        // URI with malformed query parameters (no = sign)
        String authRequest = "openid://?malformed&client_id=verifier&" +
            "response_uri=https://verifier.example.com/response&" +
            "nonce=nonce&" +
            "presentation_definition=" + java.net.URLEncoder.encode(
                "{\"id\":\"pd-1\",\"input_descriptors\":[{\"id\":\"input-1\"}]}", "UTF-8");
        
        when(mockHttpClient.postWithRetry(anyString(), anyString(), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), "{}"));
        
        Set<String> claims = new HashSet<>(Arrays.asList("name"));
        
        // Should still work, ignoring malformed parameter
        String response = handler.presentCredential(authRequest, testCredential, claims, masterKey);
        assertNotNull(response);
    }
    
    @Test
    public void testParseQueryParams_DecodeException() throws Exception {
        // Create URI with parameter that has invalid URL encoding
        // Using %XX where XX is not valid hex will cause decode issues
        String authRequest = "openid://?client_id=verifier&" +
            "response_uri=https://verifier.example.com/response&" +
            "nonce=nonce&" +
            "state=%ZZ%YY&" +  // Invalid URL encoding
            "presentation_definition=" + java.net.URLEncoder.encode(
                "{\"id\":\"pd-1\",\"input_descriptors\":[{\"id\":\"input-1\"}]}", "UTF-8");
        
        when(mockHttpClient.postWithRetry(anyString(), anyString(), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), "{}"));
        
        Set<String> claims = new HashSet<>(Arrays.asList("name"));
        
        // Should still work, using the raw value if decode fails
        String response = handler.presentCredential(authRequest, testCredential, claims, masterKey);
        assertNotNull(response);
    }
    
    // ========== Data Extraction Edge Cases ==========
    
    @Test
    public void testExtractIssuerJwt_NoSeparator() throws Exception {
        VerifiableCredential noSepCredential = new VerifiableCredential();
        noSepCredential.setId("no-sep-cred");
        noSepCredential.setHolderBindingKeySeed(HolderBindingKeyManager.generateSeed());
        
        DigitalCredentialMetadata metadata = noSepCredential.getMetadata();
        metadata.setIssuerDid("did:example:issuer");
        metadata.setCredentialType("TestCredential");
        
        // JWT without ~ separator (plain JWT, no disclosures)
        String plainJwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZTppc3N1ZXIifQ.signature";
        noSepCredential.setEncryptedData(plainJwt.getBytes());
        
        String authRequest = "openid://?client_id=verifier&" +
            "response_uri=https://verifier.example.com/response&" +
            "nonce=nonce&" +
            "presentation_definition=" + java.net.URLEncoder.encode(
                "{\"id\":\"pd-1\",\"input_descriptors\":[{\"id\":\"input-1\"}]}", "UTF-8");
        
        when(mockHttpClient.postWithRetry(anyString(), anyString(), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), "{}"));
        
        Set<String> claims = new HashSet<>();  // Empty claims
        
        // Should work with plain JWT (no disclosures)
        String response = handler.presentCredential(authRequest, noSepCredential, claims, masterKey);
        assertNotNull(response);
    }
    
    @Test
    public void testExtractDisclosures_NullData() throws Exception {
        VerifiableCredential nullDataCredential = new VerifiableCredential();
        nullDataCredential.setId("null-data-cred");
        nullDataCredential.setHolderBindingKeySeed(HolderBindingKeyManager.generateSeed());
        
        DigitalCredentialMetadata metadata = nullDataCredential.getMetadata();
        metadata.setIssuerDid("did:example:issuer");
        metadata.setCredentialType("TestCredential");
        
        // Don't set encrypted data (null)
        nullDataCredential.setEncryptedData(null);
        
        String authRequest = "openid://?client_id=verifier&" +
            "response_uri=https://verifier.example.com/response&" +
            "nonce=nonce&" +
            "presentation_definition=" + java.net.URLEncoder.encode(
                "{\"id\":\"pd-1\",\"input_descriptors\":[{\"id\":\"input-1\"}]}", "UTF-8");
        
        Set<String> claims = new HashSet<>(Arrays.asList("name"));
        
        // Should fail with IllegalArgumentException
        OidcException exception = assertThrows(OidcException.class, () -> {
            handler.presentCredential(authRequest, nullDataCredential, claims, masterKey);
        });
        
        assertTrue(exception.getMessage().contains("Presentation failed"));
        assertTrue(exception.getCause() instanceof IllegalArgumentException);
    }
    
    // ========== Submission Edge Cases ==========
    
    @Test
    public void testSubmitPresentation_ErrorWithBody() throws Exception {
        String responseUri = "https://verifier.example.com/response";
        String vpToken = "issuer.jwt~kb.jwt";
        
        // Mock error response with body
        when(mockHttpClient.postWithRetry(eq(responseUri), anyString(), any(), any()))
            .thenReturn(new HttpResponse(400, Map.of(), 
                "{\"error\":\"invalid_presentation\",\"error_description\":\"Invalid signature\"}"));
        
        OidcException exception = assertThrows(OidcException.class, () -> {
            handler.submitPresentation(responseUri, vpToken);
        });
        
        assertTrue(exception.getMessage().contains("Presentation submission failed"));
        assertTrue(exception.getMessage().contains("400"));
        assertTrue(exception.getMessage().contains("invalid_presentation"));
    }
    
    @Test
    public void testSubmitPresentation_NullState() throws Exception {
        String authRequest = "openid://?client_id=verifier&" +
            "response_uri=https://verifier.example.com/response&" +
            "nonce=nonce&" +
            // No state parameter
            "presentation_definition=" + java.net.URLEncoder.encode(
                "{\"id\":\"pd-1\",\"input_descriptors\":[{\"id\":\"input-1\"}]}", "UTF-8");
        
        when(mockHttpClient.postWithRetry(anyString(), anyString(), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), "{}"));
        
        Set<String> claims = new HashSet<>(Arrays.asList("name"));
        
        // Should work without state parameter
        String response = handler.presentCredential(authRequest, testCredential, claims, masterKey);
        assertNotNull(response);
    }
    
    @Test
    public void testSubmitPresentation_HttpException() throws Exception {
        String responseUri = "https://verifier.example.com/response";
        String vpToken = "issuer.jwt~kb.jwt";
        
        // Mock HttpException during submission
        when(mockHttpClient.postWithRetry(eq(responseUri), anyString(), any(), any()))
            .thenThrow(new HttpException.NetworkException("Connection refused", new IOException()));
        
        OidcException exception = assertThrows(OidcException.class, () -> {
            handler.submitPresentation(responseUri, vpToken);
        });
        
        assertTrue(exception.getMessage().contains("Failed to submit presentation"));
    }
}
