/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.oidc;

import com.isfs.blekey.credential.DigitalCredentialFormat;
import com.isfs.blekey.util.JsonUtils;
import com.isfs.blekey.util.http.HttpClient;
import com.isfs.blekey.util.http.HttpResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.mockito.ArgumentCaptor;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for JSON-LD credential request construction in Oidc4VciClient.
 * Tests Phase 2B.2: JSON-LD OIDC4VCI - Credential Request
 */
@DisplayName("OIDC4VCI Client JSON-LD Request Tests")
class Oidc4VciClientJsonLdRequestTest {
    
    private HttpClient mockHttpClient;
    private Oidc4VciClient client;
    private Method requestCredentialMethod;
    private IssuerMetadata mockMetadata;
    private Method extractContextsFromMetadataMethod;
    
    @BeforeEach
    void setUp() throws Exception {
        mockHttpClient = mock(HttpClient.class);
        client = new Oidc4VciClient(mockHttpClient);
        
        // Access private method via reflection for testing
        requestCredentialMethod = Oidc4VciClient.class.getDeclaredMethod(
            "requestCredential", String.class, String.class, String.class, String.class,
            DigitalCredentialFormat.class, IssuerMetadata.class);
        requestCredentialMethod.setAccessible(true);

        extractContextsFromMetadataMethod = Oidc4VciClient.class.getDeclaredMethod(
            "extractContextsFromMetadata", IssuerMetadata.class, String.class);
        extractContextsFromMetadataMethod.setAccessible(true);
        
        // Create mock metadata with JSON-LD credential configuration
        mockMetadata = createMockMetadata();
    }
    
    /**
     * Creates a mock IssuerMetadata with JSON-LD credential configuration.
     */
    private IssuerMetadata createMockMetadata() {
        Map<String, Object> credConfig = new HashMap<>();
        credConfig.put("format", "ldp_vc");
        
        Map<String, Object> credDef = new HashMap<>();
        List<String> contexts = new ArrayList<>();
        contexts.add("https://www.w3.org/2018/credentials/v1");
        contexts.add("https://www.w3.org/2018/credentials/examples/v1");
        credDef.put("@context", contexts);
        credConfig.put("credential_definition", credDef);
        
        List<Map<String, Object>> credentialsSupported = new ArrayList<>();
        credentialsSupported.add(credConfig);
        
        // Create metadata using reflection or a test constructor
        // For simplicity, we'll create a minimal mock
        IssuerMetadata metadata = mock(IssuerMetadata.class);
        when(metadata.getCredentialsSupported()).thenReturn(credentialsSupported);
        
        return metadata;
    }
    
    @Test
    @DisplayName("Should construct JSON-LD credential request with ldp_vc format")
    void testJsonLdRequestConstruction() throws Exception {
        // Setup mock response
        Map<String, Object> responseMap = Map.of("credential", "mock-credential-jwt");
        String responseJson = JsonUtils.encode(responseMap);
        HttpResponse mockResponse = new HttpResponse(200, Map.of(), responseJson);
        when(mockHttpClient.postWithRetry(anyString(), anyString(), anyMap(), any()))
            .thenReturn(mockResponse);
        
        // Invoke request method
        String endpoint = "https://issuer.example.com/credential";
        String accessToken = "test-access-token";
        String credentialType = "UniversityDegree";
        String keyProofJwt = "test-proof-jwt";
        
        requestCredentialMethod.invoke(client, endpoint, accessToken, credentialType,
                                       keyProofJwt, DigitalCredentialFormat.JSON_LD, mockMetadata);
        
        // Capture the request body
        ArgumentCaptor<String> requestBodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockHttpClient).postWithRetry(eq(endpoint), requestBodyCaptor.capture(), anyMap(), any());
        
        // Parse and verify request structure
        @SuppressWarnings("unchecked")
        Map<String, Object> request = (Map<String, Object>) JsonUtils.decode(requestBodyCaptor.getValue(), Map.class);
        
        // Verify format
        assertEquals("ldp_vc", request.get("format"), "Format should be ldp_vc");
        
        // Verify credential_definition
        assertTrue(request.containsKey("credential_definition"), "Should contain credential_definition");
        @SuppressWarnings("unchecked")
        Map<String, Object> credDef = (Map<String, Object>) request.get("credential_definition");
        
        // Verify type
        assertTrue(credDef.containsKey("type"), "credential_definition should contain type");
        @SuppressWarnings("unchecked")
        List<String> types = (List<String>) credDef.get("type");
        assertTrue(types.contains("VerifiableCredential"), "Should include VerifiableCredential type");
        assertTrue(types.contains(credentialType), "Should include credential type");
        
        // Verify @context
        assertTrue(credDef.containsKey("@context"), "credential_definition should contain @context");
        @SuppressWarnings("unchecked")
        List<String> contexts = (List<String>) credDef.get("@context");
        assertTrue(contexts.contains("https://www.w3.org/2018/credentials/v1"), 
                  "Should include W3C credentials context");
        
        // Verify proof
        assertTrue(request.containsKey("proof"), "Should contain proof");
        @SuppressWarnings("unchecked")
        Map<String, Object> proof = (Map<String, Object>) request.get("proof");
        assertEquals("jwt", proof.get("proof_type"), "Proof type should be jwt");
        assertEquals(keyProofJwt, proof.get("jwt"), "Should include proof JWT");
    }
    
    @Test
    @DisplayName("Should construct SD-JWT-VC credential request")
    void testSdJwtVcRequestConstruction() throws Exception {
        // Setup mock response
        Map<String, Object> responseMap = Map.of("credential", "mock-credential-jwt");
        String responseJson = JsonUtils.encode(responseMap);
        HttpResponse mockResponse = new HttpResponse(200, Map.of(), responseJson);
        when(mockHttpClient.postWithRetry(anyString(), anyString(), anyMap(), any()))
            .thenReturn(mockResponse);
        
        // Invoke request method
        String endpoint = "https://issuer.example.com/credential";
        String accessToken = "test-access-token";
        String credentialType = "UniversityDegree";
        String keyProofJwt = "test-proof-jwt";
        
        requestCredentialMethod.invoke(client, endpoint, accessToken, credentialType,
                                       keyProofJwt, DigitalCredentialFormat.SD_JWT_VC, mockMetadata);
        
        // Capture the request body
        ArgumentCaptor<String> requestBodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockHttpClient).postWithRetry(eq(endpoint), requestBodyCaptor.capture(), anyMap(), any());
        
        // Parse and verify request structure
        @SuppressWarnings("unchecked")
        Map<String, Object> request = (Map<String, Object>) JsonUtils.decode(requestBodyCaptor.getValue(), Map.class);
        
        // Verify format
        assertEquals("jwt_vc_json", request.get("format"), "Format should be jwt_vc_json");
        
        // Verify types
        assertTrue(request.containsKey("types"), "Should contain types");
        @SuppressWarnings("unchecked")
        List<String> types = (List<String>) request.get("types");
        assertEquals(2, types.size(), "Should have 2 types");
        assertEquals("VerifiableCredential", types.get(0), "First type should be VerifiableCredential");
        assertEquals(credentialType, types.get(1), "Second type should be credential type");
    }
    
    @Test
    @DisplayName("Should construct ISO mDL credential request")
    void testMdlRequestConstruction() throws Exception {
        // Setup mock response with base64-encoded CBOR
        Map<String, Object> responseMap = Map.of("credential", "bW9jay1jYm9yLWRhdGE=");
        String responseJson = JsonUtils.encode(responseMap);
        HttpResponse mockResponse = new HttpResponse(200, Map.of(), responseJson);
        when(mockHttpClient.postWithRetry(anyString(), anyString(), anyMap(), any()))
            .thenReturn(mockResponse);
        
        // Invoke request method
        String endpoint = "https://issuer.example.com/credential";
        String accessToken = "test-access-token";
        String docType = "org.iso.18013.5.1.mDL";
        String keyProofJwt = "test-proof-jwt";
        
        requestCredentialMethod.invoke(client, endpoint, accessToken, docType,
                                       keyProofJwt, DigitalCredentialFormat.ISO_MDOC, mockMetadata);
        
        // Capture the request body
        ArgumentCaptor<String> requestBodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockHttpClient).postWithRetry(eq(endpoint), requestBodyCaptor.capture(), anyMap(), any());
        
        // Parse and verify request structure
        @SuppressWarnings("unchecked")
        Map<String, Object> request = (Map<String, Object>) JsonUtils.decode(requestBodyCaptor.getValue(), Map.class);
        
        // Verify format
        assertEquals("mso_mdoc", request.get("format"), "Format should be mso_mdoc");
        
        // Verify doctype
        assertEquals(docType, request.get("doctype"), "Should include doctype");
    }
    
    @Test
    @DisplayName("Should include authorization header in request")
    void testAuthorizationHeader() throws Exception {
        // Setup mock response
        Map<String, Object> responseMap = Map.of("credential", "mock-credential");
        String responseJson = JsonUtils.encode(responseMap);
        HttpResponse mockResponse = new HttpResponse(200, Map.of(), responseJson);
        when(mockHttpClient.postWithRetry(anyString(), anyString(), anyMap(), any()))
            .thenReturn(mockResponse);
        
        // Invoke request method
        String accessToken = "test-access-token-123";
        requestCredentialMethod.invoke(client, "https://issuer.example.com/credential",
                                       accessToken, "UniversityDegree", "proof-jwt",
                                       DigitalCredentialFormat.JSON_LD, mockMetadata);
        
        // Capture the headers
        ArgumentCaptor<Map<String, String>> headersCaptor = ArgumentCaptor.forClass(Map.class);
        verify(mockHttpClient).postWithRetry(anyString(), anyString(), headersCaptor.capture(), any());
        
        Map<String, String> headers = headersCaptor.getValue();
        assertEquals("Bearer " + accessToken, headers.get("Authorization"), 
                    "Should include Bearer token in Authorization header");
        assertEquals("application/json", headers.get("Content-Type"), 
                    "Should set Content-Type to application/json");
        assertEquals("application/json", headers.get("Accept"), 
                    "Should set Accept to application/json");
    }
    
    @Test
    @DisplayName("Should handle HTTP error responses")
    void testHttpErrorHandling() throws Exception {
        // Setup mock error response
        HttpResponse mockResponse = new HttpResponse(400, Map.of(), "{\"error\":\"invalid_request\"}");
        when(mockHttpClient.postWithRetry(anyString(), anyString(), anyMap(), any()))
            .thenReturn(mockResponse);
        
        // Invoke request method and expect exception
        Exception exception = assertThrows(Exception.class, () -> {
            requestCredentialMethod.invoke(client, "https://issuer.example.com/credential",
                                          "token", "UniversityDegree", "proof",
                                          DigitalCredentialFormat.JSON_LD, mockMetadata);
        });
        
        // Verify it's an OidcException wrapped in InvocationTargetException
        assertTrue(exception.getCause() instanceof OidcException, 
                  "Should throw OidcException for HTTP errors");
        assertTrue(exception.getCause().getMessage().contains("400"), 
                  "Error message should include status code");
    }
    
    @Test
    @DisplayName("Should handle missing credential in response")
    void testMissingCredentialInResponse() throws Exception {
        // Setup mock response without credential field
        Map<String, Object> responseMap = Map.of("status", "success");
        String responseJson = JsonUtils.encode(responseMap);
        HttpResponse mockResponse = new HttpResponse(200, Map.of(), responseJson);
        when(mockHttpClient.postWithRetry(anyString(), anyString(), anyMap(), any()))
            .thenReturn(mockResponse);
        
        // Invoke request method and expect exception
        Exception exception = assertThrows(Exception.class, () -> {
            requestCredentialMethod.invoke(client, "https://issuer.example.com/credential",
                                          "token", "UniversityDegree", "proof",
                                          DigitalCredentialFormat.JSON_LD, mockMetadata);
        });
        
        // Verify it's an OidcException
        assertTrue(exception.getCause() instanceof OidcException, 
                  "Should throw OidcException for missing credential");
        assertTrue(exception.getCause().getMessage().contains("Credential not found"), 
                  "Error message should indicate missing credential");
    }
    
    @Test
    @DisplayName("Should return credential string for JSON-LD format")
    void testJsonLdCredentialReturn() throws Exception {
        // Setup mock response
        String expectedCredential = "eyJhbGciOiJFUzI1NiJ9.eyJ2YyI6e319.signature";
        Map<String, Object> responseMap = Map.of("credential", expectedCredential);
        String responseJson = JsonUtils.encode(responseMap);
        HttpResponse mockResponse = new HttpResponse(200, Map.of(), responseJson);
        when(mockHttpClient.postWithRetry(anyString(), anyString(), anyMap(), any()))
            .thenReturn(mockResponse);
        
        // Invoke request method
        Object result = requestCredentialMethod.invoke(client, "https://issuer.example.com/credential",
                                                      "token", "UniversityDegree", "proof",
                                                      DigitalCredentialFormat.JSON_LD, mockMetadata);
        
        // Verify result
        assertTrue(result instanceof String, "Should return String for JSON-LD credential");
        assertEquals(expectedCredential, result, "Should return the credential from response");
    }
    
    @Test
    @DisplayName("Should return byte array for ISO mDL format")
    void testMdlCredentialReturn() throws Exception {
        // Setup mock response with base64-encoded CBOR
        String base64Cbor = "bW9jay1jYm9yLWRhdGE=";
        Map<String, Object> responseMap = Map.of("credential", base64Cbor);
        String responseJson = JsonUtils.encode(responseMap);
        HttpResponse mockResponse = new HttpResponse(200, Map.of(), responseJson);
        when(mockHttpClient.postWithRetry(anyString(), anyString(), anyMap(), any()))
            .thenReturn(mockResponse);
        
        // Invoke request method
        Object result = requestCredentialMethod.invoke(client, "https://issuer.example.com/credential",
                                                      "token", "org.iso.18013.5.1.mDL", "proof",
                                                      DigitalCredentialFormat.ISO_MDOC, mockMetadata);
        
        // Verify result
        assertTrue(result instanceof byte[], "Should return byte[] for mDL credential");
        assertArrayEquals("mock-cbor-data".getBytes(), (byte[]) result, 
                         "Should decode base64 CBOR data");
    }
    @Test
    @DisplayName("Should extract contexts from string metadata context")
    void testExtractContextsFromMetadata_StringContext() throws Exception {
        IssuerMetadata metadata = mock(IssuerMetadata.class);

        Map<String, Object> credDef = new HashMap<>();
        credDef.put("@context", "https://example.com/credentials/university/v1");

        Map<String, Object> credConfig = new HashMap<>();
        credConfig.put("format", "ldp_vc");
        credConfig.put("credential_definition", credDef);

        when(metadata.getCredentialsSupported()).thenReturn(List.of(credConfig));

        @SuppressWarnings("unchecked")
        List<String> contexts = (List<String>) extractContextsFromMetadataMethod.invoke(
            client, metadata, "UniversityDegree");

        assertEquals(2, contexts.size());
        assertEquals("https://www.w3.org/2018/credentials/v1", contexts.get(0));
        assertEquals("https://example.com/credentials/university/v1", contexts.get(1));
    }

    @Test
    @DisplayName("Should add default examples context when metadata has no usable context")
    void testExtractContextsFromMetadata_DefaultExamplesFallback() throws Exception {
        IssuerMetadata metadata = mock(IssuerMetadata.class);

        Map<String, Object> credConfig = new HashMap<>();
        credConfig.put("format", "ldp_vc");
        credConfig.put("credential_definition", Map.of());

        when(metadata.getCredentialsSupported()).thenReturn(List.of(credConfig));

        @SuppressWarnings("unchecked")
        List<String> contexts = (List<String>) extractContextsFromMetadataMethod.invoke(
            client, metadata, "UniversityDegree");

        assertEquals(2, contexts.size());
        assertEquals("https://www.w3.org/2018/credentials/v1", contexts.get(0));
        assertEquals("https://www.w3.org/2018/credentials/examples/v1", contexts.get(1));
    }

    @Test
    @DisplayName("Should ignore non-ldp_vc entries and duplicate W3C context values")
    void testExtractContextsFromMetadata_IgnoresNonJsonLdAndDuplicates() throws Exception {
        IssuerMetadata metadata = mock(IssuerMetadata.class);

        Map<String, Object> nonJsonLdConfig = new HashMap<>();
        nonJsonLdConfig.put("format", "jwt_vc_json");
        nonJsonLdConfig.put("credential_definition", Map.of(
            "@context", List.of("https://example.com/ignored/v1")
        ));

        Map<String, Object> jsonLdCredDef = new HashMap<>();
        jsonLdCredDef.put("@context", List.of(
            "https://www.w3.org/2018/credentials/v1",
            "https://example.com/credentials/common/v1",
            "https://example.com/credentials/common/v1"
        ));

        Map<String, Object> jsonLdConfig = new HashMap<>();
        jsonLdConfig.put("format", "ldp_vc");
        jsonLdConfig.put("credential_definition", jsonLdCredDef);

        when(metadata.getCredentialsSupported()).thenReturn(List.of(nonJsonLdConfig, jsonLdConfig));

        @SuppressWarnings("unchecked")
        List<String> contexts = (List<String>) extractContextsFromMetadataMethod.invoke(
            client, metadata, "UniversityDegree");

        assertEquals(2, contexts.size());
        assertEquals("https://www.w3.org/2018/credentials/v1", contexts.get(0));
        assertEquals("https://example.com/credentials/common/v1", contexts.get(1));
    }
}

// Made with Bob