/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.authenticator;

import static org.junit.jupiter.api.Assertions.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import com.isfs.blekey.util.CertUtils;
import com.isfs.blekey.util.KeyUtils;

import jakarta.json.Json;

/**
 * Integration tests for the Fido2Authenticator class.
 * These tests focus on the end-to-end credential creation and assertion flows.
 */
@ExtendWith(MockitoExtension.class)
public class Fido2AuthenticatorIntegrationTest {

    private Fido2Authenticator authenticator;
    private KeyPair caKeyPair;
    private X509Certificate caCert;
    
    @BeforeEach
    public void setUp() throws Exception {
        authenticator = new Fido2Authenticator();
        
        // Generate CA key pair and certificate for attestation tests
        caKeyPair = KeyUtils.getKeyPair("EC");
        caCert = CertUtils.generateCaCert( "CN=Test CA", caKeyPair, 365, true);
    }
    
    /**
     * Helper method to create a JSON string with credential creation options.
     */
    private String createCredentialCreationOptionsJson() {
        return Json.createObjectBuilder()
                .add("publicKey", Json.createObjectBuilder()
                    .add("rp", Json.createObjectBuilder()
                        .add("id", "example.com")
                        .add("name", "Example RP"))
                    .add("user", Json.createObjectBuilder()
                        .add("id", Base64.getEncoder().encodeToString("user123".getBytes()))
                        .add("name", "testuser@example.com")
                        .add("displayName", "Test User"))
                    .add("challenge", Base64.getEncoder().encodeToString("challenge123".getBytes()))
                    .add("pubKeyCredParams", Json.createArrayBuilder()
                        .add(Json.createObjectBuilder()
                            .add("type", "public-key")
                            .add("alg", -7))) // ES256
                    .add("timeout", 60000)
                    .add("attestation", "direct"))
                .build().toString();
    }
    
    /**
     * Helper method to create a JSON string with assertion options.
     */
    private String createAssertionOptionsJson() {
        return Json.createObjectBuilder()
                .add("publicKey", Json.createObjectBuilder()
                    .add("rpId", "example.com")
                    .add("challenge", Base64.getEncoder().encodeToString("challenge123".getBytes()))
                    .add("timeout", 60000)
                    .add("allowCredentials", Json.createArrayBuilder()
                        .add(Json.createObjectBuilder()
                            .add("type", "public-key")
                            .add("id", Base64.getEncoder().encodeToString("credentialId123".getBytes())))))
                .build().toString();
    }
    
    /**
     * Test credential creation with "none" attestation.
     */
    @Test
    public void testCredentialCreateWithNoneAttestation() throws Exception {
        String jsonOptions = createCredentialCreationOptionsJson();
        String response = authenticator.credentialCreate(jsonOptions, "none");
        
        assertNotNull(response);
        assertTrue(response.contains("attestationObject"));
        assertTrue(response.contains("clientDataJSON"));
    }
    
    /**
     * Test credential creation with "packed" attestation.
     */
    @Test
    public void testCredentialCreateWithPackedAttestation() throws Exception {
        String jsonOptions = createCredentialCreationOptionsJson();
        String response = authenticator.credentialCreate(jsonOptions, "packed", authenticator.getKeyPair(), caKeyPair, caCert);
        
        assertNotNull(response);
        assertTrue(response.contains("attestationObject"));
        assertTrue(response.contains("clientDataJSON"));
        // Packed attestation should include a signature
        assertTrue(response.contains("sig"));
    }
    
    /**
     * Test assertion generation.
     */
    @Test
    public void testCredentialRequest() throws Exception {
        // First create a credential
        String createOptions = createCredentialCreationOptionsJson();
        String createResponse = authenticator.credentialCreate(createOptions, "none");
        assertNotNull(createResponse);
        
        // Then use it for assertion
        String assertOptions = createAssertionOptionsJson();
        String assertResponse = authenticator.credentialRequest(assertOptions);
        
        assertNotNull(assertResponse);
        assertTrue(assertResponse.contains("authenticatorData"));
        assertTrue(assertResponse.contains("clientDataJSON"));
        assertTrue(assertResponse.contains("signature"));
    }
    
    /**
     * Test the full credential creation and assertion flow with a custom key pair.
     */
    @Test
    public void testFullCredentialFlowWithCustomKeyPair() throws Exception {
        // Generate a custom key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        KeyPair customKeyPair = keyGen.generateKeyPair();
        
        // Create credential with custom key pair
        String createOptions = createCredentialCreationOptionsJson();
        String createResponse = authenticator.credentialCreate(createOptions, "none", customKeyPair);
        assertNotNull(createResponse);
        
        // Use the same key pair for assertion
        String assertOptions = createAssertionOptionsJson();
        String assertResponse = authenticator.credentialRequest(assertOptions, customKeyPair);
        
        assertNotNull(assertResponse);
        assertTrue(assertResponse.contains("authenticatorData"));
        assertTrue(assertResponse.contains("signature"));
    }
    
    /**
     * Test credential creation with extensions.
     */
    @Test
    public void testCredentialCreateWithExtensions() throws Exception {
        // Create options with extensions
        String jsonOptions = Json.createObjectBuilder()
                .add("publicKey", Json.createObjectBuilder()
                    .add("rp", Json.createObjectBuilder()
                        .add("id", "example.com")
                        .add("name", "Example RP"))
                    .add("user", Json.createObjectBuilder()
                        .add("id", Base64.getEncoder().encodeToString("user123".getBytes()))
                        .add("name", "testuser@example.com")
                        .add("displayName", "Test User"))
                    .add("challenge", Base64.getEncoder().encodeToString("challenge123".getBytes()))
                    .add("pubKeyCredParams", Json.createArrayBuilder()
                        .add(Json.createObjectBuilder()
                            .add("type", "public-key")
                            .add("alg", -7))) // ES256
                    .add("timeout", 60000)
                    .add("attestation", "direct")
                    .add("extensions", Json.createObjectBuilder()
                        .add("txAuthSimple", "Please verify this transaction")))
                .build().toString();
        
        String response = authenticator.credentialCreate(jsonOptions, "none");
        
        assertNotNull(response);
        assertTrue(response.contains("attestationObject"));
        assertTrue(response.contains("clientDataJSON"));
    }
    
    /**
     * Test assertion with extensions.
     */
    @Test
    public void testCredentialRequestWithExtensions() throws Exception {
        // Create assertion options with extensions
        String jsonOptions = Json.createObjectBuilder()
                .add("publicKey", Json.createObjectBuilder()
                    .add("rpId", "example.com")
                    .add("challenge", Base64.getEncoder().encodeToString("challenge123".getBytes()))
                    .add("timeout", 60000)
                    .add("allowCredentials", Json.createArrayBuilder()
                        .add(Json.createObjectBuilder()
                            .add("type", "public-key")
                            .add("id", Base64.getEncoder().encodeToString("credentialId123".getBytes()))))
                    .add("extensions", Json.createObjectBuilder()
                        .add("txAuthSimple", "Please verify this transaction")))
                .build().toString();
        
        String response = authenticator.credentialRequest(jsonOptions);
        
        assertNotNull(response);
        assertTrue(response.contains("authenticatorData"));
        assertTrue(response.contains("signature"));
    }
    
    /**
     * Test the processAttestationStatement method with different attestation types.
     */
    @Test
    public void testProcessAttestationStatement() throws Exception {
        byte[] clientDataHash = "clientDataHash".getBytes();
        byte[] authData = new byte[37]; // Minimum size for auth data
        byte[] credId = "credentialId123".getBytes();
        
        // Test with "none" attestation
        Map<String, Object> noneAttStmt = authenticator.processAttestationStatement(
                "none", clientDataHash, authData, credId, 
                authenticator.getKeyPair(), null, null);
        
        assertNotNull(noneAttStmt);
        assertTrue(noneAttStmt.isEmpty()); // "none" attestation should be empty
        
        // Test with "packed" attestation
        Map<String, Object> packedAttStmt = authenticator.processAttestationStatement(
                "packed", clientDataHash, authData, credId, 
                authenticator.getKeyPair(), caKeyPair, caCert);
        
        assertNotNull(packedAttStmt);
        assertFalse(packedAttStmt.isEmpty());
        assertTrue(packedAttStmt.containsKey("alg"));
        assertTrue(packedAttStmt.containsKey("sig"));
    }
}

// Made with Bob
