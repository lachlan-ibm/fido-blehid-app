/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.oidc;

import com.isfs.blekey.credential.DigitalCredentialFormat;
import com.isfs.blekey.credential.VerifiableCredential;
import com.isfs.blekey.credential.mdl.IssuerAuth;
import com.isfs.blekey.credential.mdl.IssuerSigned;
import com.isfs.blekey.credential.mdl.IssuerSignedItem;
import com.isfs.blekey.credential.mdl.MdlCredential;
import com.isfs.blekey.credential.mdl.MobileDocument;
import com.isfs.blekey.credential.mdl.MobileSecurityObject;
import com.isfs.blekey.util.http.HttpClient;
import com.isfs.blekey.util.http.HttpResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for mDL issuance in Oidc4VciClient.
 */
class Oidc4VciClientMdlTest {
    
    private Oidc4VciClient client;
    private HttpClient mockHttpClient;
    private KeyPair holderKeyPair;
    private KeyPair issuerKeyPair;
    
    @BeforeEach
    void setUp() throws Exception {
        mockHttpClient = mock(HttpClient.class);
        client = new Oidc4VciClient(mockHttpClient);
        
        // Generate test key pairs
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        holderKeyPair = keyGen.generateKeyPair();
        issuerKeyPair = keyGen.generateKeyPair();
    }
    
    @Test
    void testIssueMdlCredential() throws Exception {
        // Setup mock responses
        setupMockMdlIssuanceFlow();
        
        // Issue mDL credential with proper credential offer URL including pre-authorized code
        String credentialOfferUrl = "openid-credential-offer://?credential_offer=" +
            "%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.example.com%22%2C" +
            "%22credentials%22%3A%5B%22org.iso.18013.5.1.mDL%22%5D%2C" +
            "%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B" +
            "%22pre-authorized_code%22%3A%22test-code-123%22%7D%7D%7D";
        
        VerifiableCredential credential = client.issueCredential(
            credentialOfferUrl,
            "test-credential-id",
            "https://issuer.example.com",
            "org.iso.18013.5.1.mDL",
            holderKeyPair.getPrivate(),
            DigitalCredentialFormat.ISO_MDOC
        );
        
        // Verify credential
        assertNotNull(credential);
        assertTrue(credential instanceof MdlCredential);
        
        MdlCredential mdlCredential = (MdlCredential) credential;
        assertEquals("org.iso.18013.5.1.mDL", mdlCredential.getDocType());
        assertNotNull(mdlCredential.getIssuerSigned());
        assertNotNull(mdlCredential.getHolderBindingKeySeed());
    }
    
    @Test
    void testMdlCredentialValidation() throws Exception {
        // Create a test mDL
        MdlCredential testMdl = createTestMdlCredential();
        byte[] mdlCbor = testMdl.toMdlCbor();
        
        // Setup mock to return the mDL
        setupMockMdlIssuanceFlowWithCredential(mdlCbor);
        
        // Issue and validate with proper credential offer URL including pre-authorized code
        String credentialOfferUrl = "openid-credential-offer://?credential_offer=" +
            "%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.example.com%22%2C" +
            "%22credentials%22%3A%5B%22org.iso.18013.5.1.mDL%22%5D%2C" +
            "%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B" +
            "%22pre-authorized_code%22%3A%22test-code-123%22%7D%7D%7D";
        
        VerifiableCredential credential = client.issueCredential(
            credentialOfferUrl,
            "test-credential-id",
            "https://issuer.example.com",
            "org.iso.18013.5.1.mDL",
            holderKeyPair.getPrivate(),
            DigitalCredentialFormat.ISO_MDOC
        );
        
        assertNotNull(credential);
        assertTrue(credential instanceof MdlCredential);
        
        MdlCredential mdl = (MdlCredential) credential;
        assertEquals("org.iso.18013.5.1.mDL", mdl.getMetadata().getCredentialType());
        assertNotNull(mdl.getMetadata().getIssuedAt());
        assertNotNull(mdl.getMetadata().getExpiresAt());
    }
    
    @Test
    void testMdlCredentialRequestFormat() throws Exception {
        setupMockMdlIssuanceFlow();
        
        String credentialOfferUrl = "openid-credential-offer://?credential_offer=" +
            "%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.example.com%22%2C" +
            "%22credentials%22%3A%5B%22org.iso.18013.5.1.mDL%22%5D%2C" +
            "%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B" +
            "%22pre-authorized_code%22%3A%22test-code-123%22%7D%7D%7D";
        
        client.issueCredential(
            credentialOfferUrl,
            "test-credential-id",
            "https://issuer.example.com",
            "org.iso.18013.5.1.mDL",
            holderKeyPair.getPrivate(),
            DigitalCredentialFormat.ISO_MDOC
        );
        
        // Verify credential request format
        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockHttpClient, atLeastOnce()).postWithRetry(
            contains("/credential"),
            bodyCaptor.capture(),
            anyMap(),
            any()
        );
        
        String requestBody = bodyCaptor.getValue();
        assertTrue(requestBody.contains("mso_mdoc"), "Request should specify mso_mdoc format");
        assertTrue(requestBody.contains("doctype"), "Request should include doctype");
    }
    
    @Test
    void testMdlCredentialWithInvalidMso() throws Exception {
        // Create mDL with expired MSO
        MdlCredential expiredMdl = createExpiredMdlCredential();
        byte[] mdlCbor = expiredMdl.toMdlCbor();
        
        setupMockMdlIssuanceFlowWithCredential(mdlCbor);
        
        // Should throw exception for expired MSO
        String credentialOfferUrl = "openid-credential-offer://?credential_offer=" +
            "%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.example.com%22%2C" +
            "%22credentials%22%3A%5B%22org.iso.18013.5.1.mDL%22%5D%2C" +
            "%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B" +
            "%22pre-authorized_code%22%3A%22test-code-123%22%7D%7D%7D";
        
        assertThrows(OidcException.class, () -> {
            client.issueCredential(
                credentialOfferUrl,
                "test-credential-id",
                "https://issuer.example.com",
                "org.iso.18013.5.1.mDL",
                holderKeyPair.getPrivate(),
                DigitalCredentialFormat.ISO_MDOC
            );
        });
    }
    
    @Test
    void testMdlCredentialStorage() throws Exception {
        setupMockMdlIssuanceFlow();
        
        String credentialOfferUrl = "openid-credential-offer://?credential_offer=" +
            "%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.example.com%22%2C" +
            "%22credentials%22%3A%5B%22org.iso.18013.5.1.mDL%22%5D%2C" +
            "%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B" +
            "%22pre-authorized_code%22%3A%22test-code-123%22%7D%7D%7D";
        
        VerifiableCredential credential = client.issueCredential(
            credentialOfferUrl,
            "test-credential-id",
            "https://issuer.example.com",
            "org.iso.18013.5.1.mDL",
            holderKeyPair.getPrivate(),
            DigitalCredentialFormat.ISO_MDOC
        );
        
        // Verify credential has encrypted data
        assertNotNull(credential.getEncryptedData());
        assertTrue(credential.getEncryptedData().length > 0);
        
        // Verify holder binding key seed is stored
        assertNotNull(credential.getHolderBindingKeySeed());
        assertEquals(32, credential.getHolderBindingKeySeed().length);
    }
    
    // Helper methods
    
    private void setupMockMdlIssuanceFlow() throws Exception {
        MdlCredential testMdl = createTestMdlCredential();
        setupMockMdlIssuanceFlowWithCredential(testMdl.toMdlCbor());
    }
    
    private void setupMockMdlIssuanceFlowWithCredential(byte[] mdlCbor) throws Exception {
        // Mock credential offer response
        when(mockHttpClient.getWithRetry(contains("/.well-known/openid-credential-issuer"), anyMap(), any()))
            .thenReturn(new HttpResponse(200, null, createIssuerMetadataJson()));
        
        // Mock token response
        when(mockHttpClient.postWithRetry(
            contains("/token"),
            anyString(),
            anyMap(),
            any()
        )).thenReturn(new HttpResponse(200, null, createTokenResponseJson()));
        
        // Mock credential response with mDL
        String credentialResponseJson = createMdlCredentialResponseJson(mdlCbor);
        when(mockHttpClient.postWithRetry(
            contains("/credential"),
            anyString(),
            anyMap(),
            any()
        )).thenReturn(new HttpResponse(200, null, credentialResponseJson));
    }
    
    private MdlCredential createTestMdlCredential() throws Exception {
        // Create MSO
        Map<String, Map<Integer, byte[]>> valueDigests = new HashMap<>();
        Map<Integer, byte[]> mdlDigests = new HashMap<>();
        mdlDigests.put(0, new byte[32]); // Dummy digest
        valueDigests.put("org.iso.18013.5.1", mdlDigests);
        
        Map<String, Object> deviceKeyInfo = new HashMap<>();
        deviceKeyInfo.put("deviceKey", holderKeyPair.getPublic().getEncoded());
        
        MobileSecurityObject mso = new MobileSecurityObject(
            "1.0",
            "SHA-256",
            valueDigests,
            deviceKeyInfo,
            "org.iso.18013.5.1.mDL",
            Instant.now(),
            Instant.now(),
            Instant.now().plusSeconds(86400 * 365) // Valid for 1 year
        );
        
        // Create IssuerAuth
        IssuerAuth issuerAuth = IssuerAuth.create(mso, issuerKeyPair.getPrivate(), null);
        
        // Create IssuerSigned
        Map<String, List<IssuerSignedItem>> nameSpaces = new HashMap<>();
        List<IssuerSignedItem> items = new ArrayList<>();
        items.add(new IssuerSignedItem(0, new byte[16], "family_name", "Doe"));
        nameSpaces.put("org.iso.18013.5.1", items);
        
        IssuerSigned issuerSigned = new IssuerSigned(nameSpaces, issuerAuth.toCbor());
        
        // Create MdlCredential
        MdlCredential mdl = new MdlCredential();
        mdl.setDocType("org.iso.18013.5.1.mDL");
        mdl.setIssuerSigned(issuerSigned);
        
        return mdl;
    }
    
    private MdlCredential createExpiredMdlCredential() throws Exception {
        // Create MSO with past expiration
        Map<String, Map<Integer, byte[]>> valueDigests = new HashMap<>();
        Map<Integer, byte[]> mdlDigests = new HashMap<>();
        mdlDigests.put(0, new byte[32]);
        valueDigests.put("org.iso.18013.5.1", mdlDigests);
        
        Map<String, Object> deviceKeyInfo = new HashMap<>();
        deviceKeyInfo.put("deviceKey", holderKeyPair.getPublic().getEncoded());
        
        MobileSecurityObject mso = new MobileSecurityObject(
            "1.0",
            "SHA-256",
            valueDigests,
            deviceKeyInfo,
            "org.iso.18013.5.1.mDL",
            Instant.now().minusSeconds(86400 * 400), // Signed 400 days ago
            Instant.now().minusSeconds(86400 * 400),
            Instant.now().minusSeconds(86400 * 30) // Expired 30 days ago
        );
        
        IssuerAuth issuerAuth = IssuerAuth.create(mso, issuerKeyPair.getPrivate(), null);
        
        Map<String, List<IssuerSignedItem>> nameSpaces = new HashMap<>();
        List<IssuerSignedItem> items = new ArrayList<>();
        items.add(new IssuerSignedItem(0, new byte[16], "family_name", "Doe"));
        nameSpaces.put("org.iso.18013.5.1", items);
        
        IssuerSigned issuerSigned = new IssuerSigned(nameSpaces, issuerAuth.toCbor());
        
        MdlCredential mdl = new MdlCredential();
        mdl.setDocType("org.iso.18013.5.1.mDL");
        mdl.setIssuerSigned(issuerSigned);
        
        return mdl;
    }
    
    private String createIssuerMetadataJson() {
        return "{"
            + "\"credential_issuer\":\"https://issuer.example.com\","
            + "\"token_endpoint\":\"https://issuer.example.com/token\","
            + "\"credential_endpoint\":\"https://issuer.example.com/credential\""
            + "}";
    }
    
    private String createTokenResponseJson() {
        return "{"
            + "\"access_token\":\"test-access-token\","
            + "\"token_type\":\"Bearer\","
            + "\"expires_in\":3600,"
            + "\"c_nonce\":\"test-nonce\""
            + "}";
    }
    
    private String createMdlCredentialResponseJson(byte[] mdlCbor) {
        String base64Mdl = Base64.getEncoder().encodeToString(mdlCbor);
        return "{\"credential\":\"" + base64Mdl + "\"}";
    }
}

// Made with Bob