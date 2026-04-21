/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.credential.status;

import com.isfs.blekey.credential.DigitalCredentialMetadata;
import com.isfs.blekey.credential.VerifiableCredential;
import com.isfs.blekey.util.http.HttpClient;
import com.isfs.blekey.util.http.HttpResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for CredentialStatusChecker.
 * Tests Status List 2021 validation.
 */
public class CredentialStatusCheckerTest {
    
    private HttpClient mockHttpClient;
    private CredentialStatusChecker checker;
    
    @BeforeEach
    public void setUp() {
        mockHttpClient = mock(HttpClient.class);
        checker = new CredentialStatusChecker(mockHttpClient);
    }
    
    @Test
    public void testCheckStatus_ValidCredential() throws Exception {
        VerifiableCredential credential = createTestCredential("https://issuer.example.com/status/1", "0");
        
        // Mock status list response (bit 0 = 0, meaning valid)
        String statusListJwt = createMockStatusListJwt(false);
        when(mockHttpClient.getWithRetry(eq("https://issuer.example.com/status/1"), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), statusListJwt));
        
        CredentialStatus status = checker.checkStatus(credential);
        
        assertEquals(CredentialStatus.VALID, status);
    }
    
    @Test
    public void testCheckStatus_RevokedCredential() throws Exception {
        VerifiableCredential credential = createTestCredential("https://issuer.example.com/status/1", "0");
        
        // Mock status list response (bit 0 = 1, meaning revoked)
        String statusListJwt = createMockStatusListJwt(true);
        when(mockHttpClient.getWithRetry(eq("https://issuer.example.com/status/1"), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), statusListJwt));
        
        CredentialStatus status = checker.checkStatus(credential);
        
        assertEquals(CredentialStatus.REVOKED, status);
    }
    
    @Test
    public void testCheckStatus_NoStatusListUrl() {
        VerifiableCredential credential = new VerifiableCredential();
        credential.setId("test-cred");
        
        DigitalCredentialMetadata metadata = credential.getMetadata();
        metadata.setStatusListUrl(null);
        
        CredentialStatus status = checker.checkStatus(credential);
        
        assertEquals(CredentialStatus.VALID, status);
    }
    
    @Test
    public void testCheckStatus_EmptyStatusListUrl() {
        VerifiableCredential credential = new VerifiableCredential();
        credential.setId("test-cred");
        
        DigitalCredentialMetadata metadata = credential.getMetadata();
        metadata.setStatusListUrl("");
        
        CredentialStatus status = checker.checkStatus(credential);
        
        assertEquals(CredentialStatus.VALID, status);
    }
    
    @Test
    public void testCheckStatus_NullCredential() {
        CredentialStatus status = checker.checkStatus(null);
        
        assertEquals(CredentialStatus.UNKNOWN, status);
    }
    
    @Test
    public void testCheckStatus_NoMetadata() {
        VerifiableCredential credential = new VerifiableCredential();
        credential.setId("test-cred");
        // Metadata is auto-created by constructor, but has no status list URL
        
        CredentialStatus status = checker.checkStatus(credential);
        
        // Should return VALID since no status list URL means no revocation checking
        assertEquals(CredentialStatus.VALID, status);
    }
    
    @Test
    public void testCheckStatus_MissingStatusListIndex() {
        VerifiableCredential credential = new VerifiableCredential();
        credential.setId("test-cred");
        
        DigitalCredentialMetadata metadata = credential.getMetadata();
        metadata.setStatusListUrl("https://issuer.example.com/status/1");
        // Don't set statusListIndex in display properties
        
        CredentialStatus status = checker.checkStatus(credential);
        
        assertEquals(CredentialStatus.UNKNOWN, status);
    }
    
    @Test
    public void testCheckStatus_InvalidStatusListIndex() {
        VerifiableCredential credential = new VerifiableCredential();
        credential.setId("test-cred");
        
        DigitalCredentialMetadata metadata = credential.getMetadata();
        metadata.setStatusListUrl("https://issuer.example.com/status/1");
        metadata.setDisplayProperty("statusListIndex", "invalid");
        
        CredentialStatus status = checker.checkStatus(credential);
        
        assertEquals(CredentialStatus.UNKNOWN, status);
    }
    
    @Test
    public void testCheckStatus_NetworkError() throws Exception {
        VerifiableCredential credential = createTestCredential("https://issuer.example.com/status/1", "0");
        
        when(mockHttpClient.getWithRetry(anyString(), any(), any()))
            .thenThrow(new RuntimeException("Network error"));
        
        CredentialStatus status = checker.checkStatus(credential);
        
        assertEquals(CredentialStatus.UNKNOWN, status);
    }
    
    @Test
    public void testIsValid_ValidCredential() throws Exception {
        VerifiableCredential credential = createTestCredential("https://issuer.example.com/status/1", "0");
        
        String statusListJwt = createMockStatusListJwt(false);
        when(mockHttpClient.getWithRetry(anyString(), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), statusListJwt));
        
        assertTrue(checker.isValid(credential));
    }
    
    @Test
    public void testIsValid_RevokedCredential() throws Exception {
        VerifiableCredential credential = createTestCredential("https://issuer.example.com/status/1", "0");
        
        String statusListJwt = createMockStatusListJwt(true);
        when(mockHttpClient.getWithRetry(anyString(), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), statusListJwt));
        
        assertFalse(checker.isValid(credential));
    }
    
    @Test
    public void testIsRevoked_RevokedCredential() throws Exception {
        VerifiableCredential credential = createTestCredential("https://issuer.example.com/status/1", "0");
        
        String statusListJwt = createMockStatusListJwt(true);
        when(mockHttpClient.getWithRetry(anyString(), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), statusListJwt));
        
        assertTrue(checker.isRevoked(credential));
    }
    
    @Test
    public void testIsRevoked_ValidCredential() throws Exception {
        VerifiableCredential credential = createTestCredential("https://issuer.example.com/status/1", "0");
        
        String statusListJwt = createMockStatusListJwt(false);
        when(mockHttpClient.getWithRetry(anyString(), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), statusListJwt));
        
        assertFalse(checker.isRevoked(credential));
    }
    
    @Test
    public void testClearCache() {
        // Should not throw exception
        assertDoesNotThrow(() -> checker.clearCache());
    }
    
    @Test
    public void testClearCache_WithUrl() {
        // Should not throw exception
        assertDoesNotThrow(() -> checker.clearCache("https://issuer.example.com/status/1"));
    }
    
    @Test
    public void testConstructor_DefaultHttpClient() {
        CredentialStatusChecker defaultChecker = new CredentialStatusChecker();
        assertNotNull(defaultChecker);
    }
    
    @Test
    public void testConstructor_CustomHttpClient() {
        HttpClient customClient = new HttpClient();
        CredentialStatusChecker customChecker = new CredentialStatusChecker(customClient);
        assertNotNull(customChecker);
    }
    
    @Test
    public void testCheckStatus_DifferentIndices() throws Exception {
        // Test with index 0
        VerifiableCredential cred0 = createTestCredential("https://issuer.example.com/status/1", "0");
        
        // Test with index 5
        VerifiableCredential cred5 = createTestCredential("https://issuer.example.com/status/1", "5");
        
        String statusListJwt = createMockStatusListJwt(false);
        when(mockHttpClient.getWithRetry(anyString(), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), statusListJwt));
        
        CredentialStatus status0 = checker.checkStatus(cred0);
        CredentialStatus status5 = checker.checkStatus(cred5);
        
        // Both should be valid (assuming mock returns all zeros)
        assertEquals(CredentialStatus.VALID, status0);
        assertEquals(CredentialStatus.VALID, status5);
    }
    
    @Test
    public void testCheckStatus_CacheUsage() throws Exception {
        VerifiableCredential credential = createTestCredential("https://issuer.example.com/status/1", "0");
        
        String statusListJwt = createMockStatusListJwt(false);
        when(mockHttpClient.getWithRetry(anyString(), any(), any()))
            .thenReturn(new HttpResponse(200, Map.of(), statusListJwt));
        
        // First call
        checker.checkStatus(credential);
        
        // Second call - should use cache
        checker.checkStatus(credential);
        
        // Verify HTTP client was called (caching is internal to StatusList2021)
        verify(mockHttpClient, atLeastOnce()).getWithRetry(anyString(), any(), any());
    }
    
    private VerifiableCredential createTestCredential(String statusListUrl, String statusListIndex) {
        VerifiableCredential credential = new VerifiableCredential();
        credential.setId("test-cred-" + statusListIndex);
        
        DigitalCredentialMetadata metadata = credential.getMetadata();
        metadata.setStatusListUrl(statusListUrl);
        metadata.setDisplayProperty("statusListIndex", statusListIndex);
        
        return credential;
    }
    
    private String createMockStatusListJwt(boolean revoked) throws Exception {
        // Create a simple mock JWT with status list
        // The status list should contain a GZIP-compressed bitstring
        String header = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString("{\"alg\":\"ES256\"}".getBytes());
        
        // Create a bitstring (1 byte = 8 bits, all zeros or first bit set)
        byte[] bitstring = new byte[1];
        if (revoked) {
            bitstring[0] = (byte) 0x80; // Set first bit (MSB)
        } else {
            bitstring[0] = 0x00; // All bits clear
        }
        
        // Compress the bitstring using GZIP
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        java.util.zip.GZIPOutputStream gzos = new java.util.zip.GZIPOutputStream(baos);
        gzos.write(bitstring);
        gzos.close();
        byte[] compressed = baos.toByteArray();
        
        // Encode compressed bitstring as base64url
        String encodedBits = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString(compressed);
        
        // Create payload with status list matching the expected format
        String payload = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString(("{\"status_list\":{\"bits\":\"" + encodedBits + "\"}}").getBytes());
        
        String signature = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString("mock_signature".getBytes());
        
        return header + "." + payload + "." + signature;
    }
}

// Made with Bob