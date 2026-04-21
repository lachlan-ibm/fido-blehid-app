/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.oidc;

import com.isfs.blekey.credential.VerifiableCredential;
import com.isfs.blekey.util.http.HttpClient;
import com.isfs.blekey.util.http.HttpException;
import com.isfs.blekey.util.http.HttpResponse;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for Oidc4VciClient.
 * Tests credential issuance flow, token exchange, and key proof JWT creation.
 */
public class Oidc4VciClientTest {
    
    private MockWebServer mockServer;
    private HttpClient mockHttpClient;
    private Oidc4VciClient client;
    private String baseUrl;
    private PrivateKey masterKey;
    
    @BeforeEach
    public void setUp() throws Exception {
        mockServer = new MockWebServer();
        mockServer.start();
        baseUrl = mockServer.url("/").toString().replaceAll("/$", "");
        
        mockHttpClient = mock(HttpClient.class);
        client = new Oidc4VciClient(mockHttpClient);
        
        // Generate test master key
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        KeyPair keyPair = keyGen.generateKeyPair();
        masterKey = keyPair.getPrivate();
    }
    
    @AfterEach
    public void tearDown() throws Exception {
        mockServer.shutdown();
    }
    
    @Test
    public void testIssueCredential_Success() throws Exception {
        // Setup credential offer URI
        String offerJson = String.format("{" +
            "\"credential_issuer\":\"%s\"," +
            "\"credentials\":[\"UniversityDegree\"]," +
            "\"grants\":{" +
                "\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{" +
                    "\"pre-authorized_code\":\"test-code-123\"" +
                "}" +
            "}" +
        "}", baseUrl);
        
        String credentialOfferUri = "openid-credential-offer://?credential_offer=" + 
            java.net.URLEncoder.encode(offerJson, "UTF-8");
        
        // Mock issuer metadata response
        String metadataJson = String.format("{" +
            "\"credential_issuer\":\"%s\"," +
            "\"credential_endpoint\":\"%s/credential\"," +
            "\"token_endpoint\":\"%s/token\"" +
        "}", baseUrl, baseUrl, baseUrl);
        
        when(mockHttpClient.getWithRetry(contains("/.well-known/"), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), metadataJson));
        
        // Mock token response
        String tokenJson = "{" +
            "\"access_token\":\"test-access-token\"," +
            "\"token_type\":\"Bearer\"," +
            "\"expires_in\":3600," +
            "\"c_nonce\":\"test-nonce\"" +
        "}";
        
        when(mockHttpClient.postWithRetry(eq(baseUrl + "/token"), anyString(), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), tokenJson));
        
        // Mock credential response
        String credentialJwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsInZjIjp7InR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJVbml2ZXJzaXR5RGVncmVlIl19fQ.signature";
        String credentialResponseJson = "{\"credential\":\"" + credentialJwt + "\"}";
        
        when(mockHttpClient.postWithRetry(eq(baseUrl + "/credential"), anyString(), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), credentialResponseJson));
        
        // Execute
        VerifiableCredential credential = client.issueCredential(
            credentialOfferUri,
            "cred-123",
            baseUrl,
            "UniversityDegree",
            masterKey
        );
        
        // Verify
        assertNotNull(credential);
        assertNotNull(credential.getHolderBindingKeySeed());
        assertNotNull(credential.getEncryptedData());
        
        // Verify HTTP calls were made
        verify(mockHttpClient).getWithRetry(contains("/.well-known/"), any(), any());
        verify(mockHttpClient).postWithRetry(eq(baseUrl + "/token"), anyString(), any(), any());
        verify(mockHttpClient).postWithRetry(eq(baseUrl + "/credential"), anyString(), any(), any());
    }
    
    @Test
    public void testIssueCredential_MissingTokenEndpoint() throws Exception {
        String offerJson = String.format("{" +
            "\"credential_issuer\":\"%s\"," +
            "\"credentials\":[\"UniversityDegree\"]," +
            "\"grants\":{" +
                "\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{" +
                    "\"pre-authorized_code\":\"test-code\"" +
                "}" +
            "}" +
        "}", baseUrl);
        
        String credentialOfferUri = "openid-credential-offer://?credential_offer=" + 
            java.net.URLEncoder.encode(offerJson, "UTF-8");
        
        // Mock metadata without token endpoint
        String metadataJson = String.format("{" +
            "\"credential_issuer\":\"%s\"," +
            "\"credential_endpoint\":\"%s/credential\"" +
        "}", baseUrl, baseUrl);
        
        when(mockHttpClient.getWithRetry(contains("/.well-known/"), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), metadataJson));
        
        // Execute and verify exception
        OidcException exception = assertThrows(OidcException.class, () -> {
            client.issueCredential(credentialOfferUri, "cred-123", baseUrl, "UniversityDegree", masterKey);
        });
        
        assertTrue(exception.getMessage().contains("Token endpoint not found"));
    }
    
    @Test
    public void testIssueCredential_NoPreAuthorizedCode() throws Exception {
        String offerJson = String.format("{" +
            "\"credential_issuer\":\"%s\"," +
            "\"credentials\":[\"UniversityDegree\"]," +
            "\"grants\":{}" +
        "}", baseUrl);
        
        String credentialOfferUri = "openid-credential-offer://?credential_offer=" + 
            java.net.URLEncoder.encode(offerJson, "UTF-8");
        
        String metadataJson = String.format("{" +
            "\"credential_issuer\":\"%s\"," +
            "\"credential_endpoint\":\"%s/credential\"," +
            "\"token_endpoint\":\"%s/token\"" +
        "}", baseUrl, baseUrl, baseUrl);
        
        when(mockHttpClient.getWithRetry(contains("/.well-known/"), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), metadataJson));
        
        OidcException exception = assertThrows(OidcException.class, () -> {
            client.issueCredential(credentialOfferUri, "cred-123", baseUrl, "UniversityDegree", masterKey);
        });
        
        assertTrue(exception.getMessage().contains("Pre-authorized code grant not found"));
    }
    
    @Test
    public void testIssueCredential_CredentialRequestFails() throws Exception {
        String offerJson = String.format("{" +
            "\"credential_issuer\":\"%s\"," +
            "\"credentials\":[\"UniversityDegree\"]," +
            "\"grants\":{" +
                "\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{" +
                    "\"pre-authorized_code\":\"test-code\"" +
                "}" +
            "}" +
        "}", baseUrl);
        
        String credentialOfferUri = "openid-credential-offer://?credential_offer=" + 
            java.net.URLEncoder.encode(offerJson, "UTF-8");
        
        String metadataJson = String.format("{" +
            "\"credential_issuer\":\"%s\"," +
            "\"credential_endpoint\":\"%s/credential\"," +
            "\"token_endpoint\":\"%s/token\"" +
        "}", baseUrl, baseUrl, baseUrl);
        
        when(mockHttpClient.getWithRetry(contains("/.well-known/"), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), metadataJson));
        
        String tokenJson = "{" +
            "\"access_token\":\"test-token\"," +
            "\"token_type\":\"Bearer\"," +
            "\"c_nonce\":\"nonce\"" +
        "}";
        
        when(mockHttpClient.postWithRetry(eq(baseUrl + "/token"), anyString(), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), tokenJson));
        
        // Credential request fails
        when(mockHttpClient.postWithRetry(eq(baseUrl + "/credential"), anyString(), any(), any()))
            .thenReturn(new HttpResponse(400, Map.of(), "{\"error\":\"invalid_request\"}"));
        
        OidcException exception = assertThrows(OidcException.class, () -> {
            client.issueCredential(credentialOfferUri, "cred-123", baseUrl, "UniversityDegree", masterKey);
        });
        
        assertTrue(exception.getMessage().contains("Credential request failed"));
    }
    
    @Test
    public void testIssueCredential_MissingCredentialInResponse() throws Exception {
        String offerJson = String.format("{" +
            "\"credential_issuer\":\"%s\"," +
            "\"credentials\":[\"UniversityDegree\"]," +
            "\"grants\":{" +
                "\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{" +
                    "\"pre-authorized_code\":\"test-code\"" +
                "}" +
            "}" +
        "}", baseUrl);
        
        String credentialOfferUri = "openid-credential-offer://?credential_offer=" + 
            java.net.URLEncoder.encode(offerJson, "UTF-8");
        
        String metadataJson = String.format("{" +
            "\"credential_issuer\":\"%s\"," +
            "\"credential_endpoint\":\"%s/credential\"," +
            "\"token_endpoint\":\"%s/token\"" +
        "}", baseUrl, baseUrl, baseUrl);
        
        when(mockHttpClient.getWithRetry(contains("/.well-known/"), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), metadataJson));
        
        String tokenJson = "{" +
            "\"access_token\":\"test-token\"," +
            "\"token_type\":\"Bearer\"," +
            "\"c_nonce\":\"nonce\"" +
        "}";
        
        when(mockHttpClient.postWithRetry(eq(baseUrl + "/token"), anyString(), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), tokenJson));
        
        // Response without credential field
        when(mockHttpClient.postWithRetry(eq(baseUrl + "/credential"), anyString(), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), "{}"));
        
        OidcException exception = assertThrows(OidcException.class, () -> {
            client.issueCredential(credentialOfferUri, "cred-123", baseUrl, "UniversityDegree", masterKey);
        });
        
        assertTrue(exception.getMessage().contains("Credential not found in response"));
    }
    
    @Test
    public void testIssueCredential_NetworkError() throws Exception {
        String offerJson = String.format("{" +
            "\"credential_issuer\":\"%s\"," +
            "\"credentials\":[\"UniversityDegree\"]," +
            "\"grants\":{" +
                "\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{" +
                    "\"pre-authorized_code\":\"test-code\"" +
                "}" +
            "}" +
        "}", baseUrl);
        
        String credentialOfferUri = "openid-credential-offer://?credential_offer=" + 
            java.net.URLEncoder.encode(offerJson, "UTF-8");
        
        when(mockHttpClient.getWithRetry(contains("/.well-known/"), any(), any()))
            .thenThrow(new HttpException.NetworkException("Network error", new java.io.IOException("Network error")));
        
        OidcException exception = assertThrows(OidcException.class, () -> {
            client.issueCredential(credentialOfferUri, "cred-123", baseUrl, "UniversityDegree", masterKey);
        });
        
        assertTrue(exception.getMessage().contains("Credential issuance failed"));
    }
    
    @Test
    public void testIssueCredential_KeyProofWithNonce() throws Exception {
        String offerJson = String.format("{" +
            "\"credential_issuer\":\"%s\"," +
            "\"credentials\":[\"UniversityDegree\"]," +
            "\"grants\":{" +
                "\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{" +
                    "\"pre-authorized_code\":\"test-code\"" +
                "}" +
            "}" +
        "}", baseUrl);
        
        String credentialOfferUri = "openid-credential-offer://?credential_offer=" + 
            java.net.URLEncoder.encode(offerJson, "UTF-8");
        
        String metadataJson = String.format("{" +
            "\"credential_issuer\":\"%s\"," +
            "\"credential_endpoint\":\"%s/credential\"," +
            "\"token_endpoint\":\"%s/token\"" +
        "}", baseUrl, baseUrl, baseUrl);
        
        when(mockHttpClient.getWithRetry(contains("/.well-known/"), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), metadataJson));
        
        String tokenJson = "{" +
            "\"access_token\":\"test-token\"," +
            "\"token_type\":\"Bearer\"," +
            "\"c_nonce\":\"test-nonce-value\"," +
            "\"c_nonce_expires_in\":300" +
        "}";
        
        when(mockHttpClient.postWithRetry(eq(baseUrl + "/token"), anyString(), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), tokenJson));
        
        String credentialJwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsInZjIjp7InR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXX19.sig";
        String credentialResponseJson = "{\"credential\":\"" + credentialJwt + "\"}";
        
        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        when(mockHttpClient.postWithRetry(eq(baseUrl + "/credential"), bodyCaptor.capture(), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), credentialResponseJson));
        
        VerifiableCredential credential = client.issueCredential(
            credentialOfferUri, "cred-123", baseUrl, "UniversityDegree", masterKey);
        
        assertNotNull(credential);
        
        // Verify the credential request body contains proof with JWT
        String requestBody = bodyCaptor.getValue();
        assertTrue(requestBody.contains("proof"));
        assertTrue(requestBody.contains("jwt"));
    }
    
    @Test
    public void testConstructor_DefaultHttpClient() {
        Oidc4VciClient defaultClient = new Oidc4VciClient();
        assertNotNull(defaultClient);
    }
    
    @Test
    public void testConstructor_CustomHttpClient() {
        HttpClient customClient = new HttpClient();
        Oidc4VciClient clientWithCustom = new Oidc4VciClient(customClient);
        assertNotNull(clientWithCustom);
    }
}

// Made with Bob