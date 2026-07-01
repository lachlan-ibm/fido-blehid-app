/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.oidc;

import com.isfs.blekey.credential.DigitalCredentialMetadata;
import com.isfs.blekey.credential.VerifiableCredential;
import com.isfs.blekey.credential.jsonld.JsonLdCredential;
import com.isfs.blekey.credential.jsonld.JsonLdException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for JSON-LD credential response parsing in Oidc4VciClient.
 * 
 * Tests Phase 2B.3: JSON-LD Response Parsing
 * - Parse JSON-LD credential from response
 * - Validate credential structure
 * - Extract metadata
 * - Handle errors gracefully
 */
class Oidc4VciClientJsonLdResponseTest {
    
    private Oidc4VciClient client;
    private PublicKey holderPublicKey;
    
    @BeforeEach
    void setUp() throws Exception {
        client = new Oidc4VciClient();
        
        // Generate a test key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        KeyPair keyPair = keyGen.generateKeyPair();
        holderPublicKey = keyPair.getPublic();
    }
    
    /**
     * Helper method to invoke private validateJsonLdCredential method via reflection.
     * Unwraps InvocationTargetException to get the actual exception.
     */
    private VerifiableCredential invokeValidateJsonLdCredential(String credentialJson, PublicKey publicKey)
            throws Exception {
        Method method = Oidc4VciClient.class.getDeclaredMethod(
            "validateJsonLdCredential", String.class, PublicKey.class);
        method.setAccessible(true);
        try {
            return (VerifiableCredential) method.invoke(client, credentialJson, publicKey);
        } catch (java.lang.reflect.InvocationTargetException e) {
            // Unwrap the actual exception
            Throwable cause = e.getCause();
            if (cause instanceof Exception) {
                throw (Exception) cause;
            }
            throw e;
        }
    }
    
    @Test
    void testValidateJsonLdCredential_ValidCredential() throws Exception {
        // Given: A valid JSON-LD credential
        String credentialJson = """
            {
              "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
              ],
              "id": "http://example.edu/credentials/3732",
              "type": ["VerifiableCredential", "UniversityDegreeCredential"],
              "issuer": "did:example:issuer123",
              "issuanceDate": "2024-01-01T00:00:00Z",
              "expirationDate": "2025-01-01T00:00:00Z",
              "credentialSubject": {
                "id": "did:example:student456",
                "degree": {
                  "type": "BachelorDegree",
                  "name": "Bachelor of Science"
                }
              },
              "proof": {
                "type": "JsonWebSignature2020",
                "created": "2024-01-01T00:00:00Z",
                "verificationMethod": "did:example:issuer123#key-1",
                "proofPurpose": "assertionMethod",
                "jws": "eyJhbGciOiJFUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..test"
              }
            }
            """;
        
        // When: Validating the credential
        VerifiableCredential result = invokeValidateJsonLdCredential(credentialJson, holderPublicKey);
        
        // Then: Credential is parsed and validated
        assertNotNull(result);
        assertNotNull(result.getEncryptedData());
        
        DigitalCredentialMetadata metadata = result.getMetadata();
        assertNotNull(metadata);
        assertEquals("UniversityDegreeCredential", metadata.getCredentialType());
        assertEquals("did:example:issuer123", metadata.getIssuerDid());
        assertNotNull(metadata.getIssuedAt());
        assertNotNull(metadata.getExpiresAt());
        
        // Check JSON-LD specific metadata
        assertNotNull(metadata.getTypes());
        assertTrue(metadata.getTypes().contains("VerifiableCredential"));
        assertTrue(metadata.getTypes().contains("UniversityDegreeCredential"));
        
        assertNotNull(metadata.getContexts());
        assertTrue(metadata.getContexts().contains("https://www.w3.org/2018/credentials/v1"));
        
        assertEquals("JsonWebSignature2020", metadata.getProofType());
        assertNotNull(metadata.getCredentialSubject());
    }
    
    @Test
    void testValidateJsonLdCredential_MinimalCredential() throws Exception {
        // Given: A minimal valid JSON-LD credential (no proof, no expiration)
        String credentialJson = """
            {
              "@context": "https://www.w3.org/2018/credentials/v1",
              "type": "VerifiableCredential",
              "issuer": "https://example.com/issuer",
              "issuanceDate": "2024-01-01T00:00:00Z",
              "credentialSubject": {
                "id": "did:example:subject"
              }
            }
            """;
        
        // When: Validating the credential
        VerifiableCredential result = invokeValidateJsonLdCredential(credentialJson, holderPublicKey);
        
        // Then: Credential is parsed successfully
        assertNotNull(result);
        
        DigitalCredentialMetadata metadata = result.getMetadata();
        assertNotNull(metadata);
        assertNull(metadata.getCredentialType());
        assertNull(metadata.getIssuerDid()); // URL issuer, not DID
        assertEquals("https://example.com/issuer", metadata.getIssuerUrl());
        assertNotNull(metadata.getIssuedAt());
        assertNull(metadata.getExpiresAt());
        assertNull(metadata.getProofType());
        
        // But the types list should contain VerifiableCredential
        assertNotNull(metadata.getTypes());
        assertTrue(metadata.getTypes().contains("VerifiableCredential"));
    }
    
    @Test
    void testValidateJsonLdCredential_MultipleTypes() throws Exception {
        // Given: A credential with multiple types
        String credentialJson = """
            {
              "@context": "https://www.w3.org/2018/credentials/v1",
              "type": ["VerifiableCredential", "EmployeeCredential", "SecurityClearance"],
              "issuer": "did:example:company",
              "issuanceDate": "2024-01-01T00:00:00Z",
              "credentialSubject": {
                "id": "did:example:employee"
              }
            }
            """;
        
        // When: Validating the credential
        VerifiableCredential result = invokeValidateJsonLdCredential(credentialJson, holderPublicKey);
        
        // Then: Most specific type (last non-VerifiableCredential) is used
        DigitalCredentialMetadata metadata = result.getMetadata();
        assertEquals("SecurityClearance", metadata.getCredentialType());
        
        // All types are preserved in metadata
        assertEquals(3, metadata.getTypes().size());
        assertTrue(metadata.getTypes().contains("VerifiableCredential"));
        assertTrue(metadata.getTypes().contains("EmployeeCredential"));
        assertTrue(metadata.getTypes().contains("SecurityClearance"));
    }
    
    @Test
    void testValidateJsonLdCredential_MultipleContexts() throws Exception {
        // Given: A credential with multiple contexts
        String credentialJson = """
            {
              "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1",
                "https://example.com/contexts/custom/v1"
              ],
              "type": "VerifiableCredential",
              "issuer": "did:example:issuer",
              "issuanceDate": "2024-01-01T00:00:00Z",
              "credentialSubject": {
                "id": "did:example:subject"
              }
            }
            """;
        
        // When: Validating the credential
        VerifiableCredential result = invokeValidateJsonLdCredential(credentialJson, holderPublicKey);
        
        // Then: All contexts are preserved
        DigitalCredentialMetadata metadata = result.getMetadata();
        assertEquals(3, metadata.getContexts().size());
        assertTrue(metadata.getContexts().contains("https://www.w3.org/2018/credentials/v1"));
        assertTrue(metadata.getContexts().contains("https://www.w3.org/2018/credentials/examples/v1"));
        assertTrue(metadata.getContexts().contains("https://example.com/contexts/custom/v1"));
    }
    
    @Test
    void testValidateJsonLdCredential_InvalidJson() {
        // Given: Invalid JSON
        String credentialJson = "{ invalid json }";
        
        // When/Then: Validation throws OidcException
        OidcException exception = assertThrows(OidcException.class, () -> {
            invokeValidateJsonLdCredential(credentialJson, holderPublicKey);
        });
        
        assertTrue(exception.getMessage().contains("JSON-LD validation failed"));
    }
    
    @Test
    void testValidateJsonLdCredential_MissingRequiredFields() {
        // Given: JSON-LD credential missing required fields (no issuer)
        String credentialJson = """
            {
              "@context": "https://www.w3.org/2018/credentials/v1",
              "type": "VerifiableCredential",
              "issuanceDate": "2024-01-01T00:00:00Z",
              "credentialSubject": {
                "id": "did:example:subject"
              }
            }
            """;
        
        // When/Then: Validation throws OidcException
        OidcException exception = assertThrows(OidcException.class, () -> {
            invokeValidateJsonLdCredential(credentialJson, holderPublicKey);
        });
        
        assertTrue(exception.getMessage().contains("JSON-LD validation failed"));
    }
    
    // Note: JsonLdCredential.fromJson() provides defaults for missing @context and type,
    // so these fields are not strictly required during parsing. The validation happens
    // after parsing and will catch truly invalid credentials.
    
    @Test
    void testValidateJsonLdCredential_MissingCredentialSubject() {
        // Given: JSON-LD credential missing credentialSubject
        String credentialJson = """
            {
              "@context": "https://www.w3.org/2018/credentials/v1",
              "type": "VerifiableCredential",
              "issuer": "did:example:issuer",
              "issuanceDate": "2024-01-01T00:00:00Z"
            }
            """;
        
        // When/Then: Validation throws OidcException
        OidcException exception = assertThrows(OidcException.class, () -> {
            invokeValidateJsonLdCredential(credentialJson, holderPublicKey);
        });
        
        assertTrue(exception.getMessage().contains("JSON-LD validation failed"));
    }
    
    @Test
    void testValidateJsonLdCredential_InvalidIssuanceDate() {
        // Given: JSON-LD credential with invalid issuanceDate format
        String credentialJson = """
            {
              "@context": "https://www.w3.org/2018/credentials/v1",
              "type": "VerifiableCredential",
              "issuer": "did:example:issuer",
              "issuanceDate": "not-a-date",
              "credentialSubject": {
                "id": "did:example:subject"
              }
            }
            """;
        
        // When/Then: Validation throws OidcException
        OidcException exception = assertThrows(OidcException.class, () -> {
            invokeValidateJsonLdCredential(credentialJson, holderPublicKey);
        });
        
        assertTrue(exception.getMessage().contains("JSON-LD validation failed"));
    }
    
    @Test
    void testValidateJsonLdCredential_WithProof() throws Exception {
        // Given: A credential with a proof
        String credentialJson = """
            {
              "@context": "https://www.w3.org/2018/credentials/v1",
              "type": "VerifiableCredential",
              "issuer": "did:example:issuer",
              "issuanceDate": "2024-01-01T00:00:00Z",
              "credentialSubject": {
                "id": "did:example:subject"
              },
              "proof": {
                "type": "JsonWebSignature2020",
                "created": "2024-01-01T00:00:00Z",
                "verificationMethod": "did:example:issuer#key-1",
                "proofPurpose": "assertionMethod",
                "jws": "eyJhbGciOiJFUzI1NiJ9..test"
              }
            }
            """;
        
        // When: Validating the credential
        VerifiableCredential result = invokeValidateJsonLdCredential(credentialJson, holderPublicKey);
        
        // Then: Proof type is extracted
        DigitalCredentialMetadata metadata = result.getMetadata();
        assertEquals("JsonWebSignature2020", metadata.getProofType());
    }
    
    @Test
    void testValidateJsonLdCredential_NullCredentialJson() {
        // Given: Null credential JSON
        String credentialJson = null;
        
        // When/Then: Validation throws OidcException
        OidcException exception = assertThrows(OidcException.class, () -> {
            invokeValidateJsonLdCredential(credentialJson, holderPublicKey);
        });
        
        assertTrue(exception.getMessage().contains("JSON-LD validation failed"));
    }
    
    @Test
    void testValidateJsonLdCredential_EmptyCredentialJson() {
        // Given: Empty credential JSON
        String credentialJson = "";
        
        // When/Then: Validation throws OidcException
        OidcException exception = assertThrows(OidcException.class, () -> {
            invokeValidateJsonLdCredential(credentialJson, holderPublicKey);
        });
        
        assertTrue(exception.getMessage().contains("JSON-LD validation failed"));
    }
    
    @Test
    void testValidateJsonLdCredential_CredentialDataIsStored() throws Exception {
        // Given: A valid JSON-LD credential
        String credentialJson = """
            {
              "@context": "https://www.w3.org/2018/credentials/v1",
              "type": "VerifiableCredential",
              "issuer": "did:example:issuer",
              "issuanceDate": "2024-01-01T00:00:00Z",
              "credentialSubject": {
                "id": "did:example:subject"
              }
            }
            """;
        
        // When: Validating the credential
        VerifiableCredential result = invokeValidateJsonLdCredential(credentialJson, holderPublicKey);
        
        // Then: Raw JSON is stored as encrypted data
        assertNotNull(result.getEncryptedData());
        assertTrue(result.getEncryptedData().length > 0);
        
        // Verify the stored data matches the input
        String storedJson = new String(result.getEncryptedData(), java.nio.charset.StandardCharsets.UTF_8);
        assertNotNull(storedJson);
        assertTrue(storedJson.contains("VerifiableCredential"));
    }
}

// Made with Bob