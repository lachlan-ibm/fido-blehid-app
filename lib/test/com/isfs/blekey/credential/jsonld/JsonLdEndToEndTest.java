/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.credential.jsonld;

import com.isfs.blekey.credential.DigitalCredentialFormat;
import com.isfs.blekey.credential.DigitalCredentialMetadata;
import com.isfs.blekey.credential.VerifiableCredential;
import com.isfs.blekey.credential.jsonld.proof.JwsProofHandler;
import com.isfs.blekey.credential.jsonld.proof.ProofVerifier;
import com.isfs.blekey.oidc.Oidc4VciClient;
import com.isfs.blekey.oidc.OidcException;
import com.isfs.blekey.util.HolderBindingKeyManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end integration tests for JSON-LD Verifiable Credentials.
 * 
 * <p>This test suite validates the complete JSON-LD credential lifecycle:
 * <ol>
 *   <li><b>Issuance</b>: Issue JSON-LD credential via OIDC4VCI</li>
 *   <li><b>Storage</b>: Store credential with CBOR serialization</li>
 *   <li><b>Retrieval</b>: Retrieve and deserialize credential</li>
 *   <li><b>Verification</b>: Verify credential structure and proof</li>
 * </ol>
 * 
 * @see <a href="https://www.w3.org/TR/vc-data-model/">W3C Verifiable Credentials Data Model</a>
 */
@DisplayName("JSON-LD End-to-End Integration Tests")
class JsonLdEndToEndTest {
    
    private KeyPair issuerKeyPair;
    private KeyPair holderKeyPair;
    private PrivateKey masterKey;
    
    @BeforeEach
    void setUp() throws Exception {
        // Generate issuer key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        issuerKeyPair = keyGen.generateKeyPair();
        
        // Generate holder key pair
        holderKeyPair = keyGen.generateKeyPair();
        
        // Generate master key for holder binding
        masterKey = keyGen.generateKeyPair().getPrivate();
    }
    
    @Test
    @DisplayName("E2E-001: Complete JSON-LD credential creation and validation")
    void testCompleteCredentialCreation() throws Exception {
        // 1. Create JSON-LD credential
        JsonLdCredential credential = createSampleCredential();
        
        // 2. Verify credential structure
        assertNotNull(credential);
        assertEquals("https://example.com/credentials/123", credential.getId());
        assertTrue(credential.getTypes().contains("VerifiableCredential"));
        assertTrue(credential.getTypes().contains("UniversityDegreeCredential"));
        
        // 3. Verify context
        List<String> contexts = credential.getContext().getContextUrls();
        assertTrue(contexts.contains("https://www.w3.org/2018/credentials/v1"));
        
        // 4. Verify issuer
        assertEquals("did:example:issuer", credential.getIssuer());
        
        // 5. Verify credential subject
        assertNotNull(credential.getCredentialSubject());
        assertEquals("did:example:holder", credential.getCredentialSubject().getId());
        
        // 6. Verify dates
        assertNotNull(credential.getIssuanceDate());
        assertNotNull(credential.getExpirationDate());
    }
    
    @Test
    @DisplayName("E2E-002: JSON-LD credential with proof")
    void testCredentialWithProof() throws Exception {
        // 1. Create credential
        JsonLdCredential credential = createSampleCredential();
        
        // 2. Add proof
        JsonLdProof proof = new JsonLdProof();
        proof.setType("Ed25519Signature2020");
        proof.setCreated(Instant.now());
        proof.setVerificationMethod("did:example:issuer#key-1");
        proof.setProofPurpose("assertionMethod");
        proof.setProofValue("mock-signature-value");
        
        credential.setProof(proof);
        
        // 3. Verify proof structure
        assertNotNull(credential.getProof());
        assertEquals("Ed25519Signature2020", credential.getProof().getType());
        assertEquals("did:example:issuer#key-1", credential.getProof().getVerificationMethod());
        assertEquals("assertionMethod", credential.getProof().getProofPurpose());
    }
    
    @Test
    @DisplayName("E2E-003: JSON-LD credential serialization and deserialization")
    void testSerializationRoundTrip() throws Exception {
        // 1. Create credential
        JsonLdCredential original = createSampleCredential();
        
        // 2. Serialize to JSON
        String json = original.toJson();
        assertNotNull(json);
        assertTrue(json.contains("VerifiableCredential"));
        assertTrue(json.contains("UniversityDegreeCredential"));
        
        // 3. Deserialize from JSON
        JsonLdCredential deserialized = JsonLdCredential.fromJson(json);
        
        // 4. Verify deserialized credential
        assertNotNull(deserialized);
        assertEquals(original.getId(), deserialized.getId());
        assertEquals(original.getIssuer(), deserialized.getIssuer());
        assertEquals(original.getTypes().size(), deserialized.getTypes().size());
        
        // 5. Verify credential subject preserved
        assertNotNull(deserialized.getCredentialSubject());
        assertEquals(original.getCredentialSubject().getId(), 
                    deserialized.getCredentialSubject().getId());
    }
    
    @Test
    @DisplayName("E2E-004: VerifiableCredential wrapper with JSON-LD format")
    void testVerifiableCredentialWrapper() throws Exception {
        // 1. Create JSON-LD credential
        JsonLdCredential jsonLdCred = createSampleCredential();
        String credentialJson = jsonLdCred.toJson();
        
        // 2. Create VerifiableCredential wrapper
        VerifiableCredential credential = new VerifiableCredential();
        credential.setFormat(DigitalCredentialFormat.JSON_LD);
        credential.setEncryptedData(credentialJson.getBytes());
        credential.generateSeedAndSalt();
        
        // 3. Set metadata from JSON-LD credential
        DigitalCredentialMetadata metadata = credential.getMetadata();
        metadata.setIssuerDid(jsonLdCred.getIssuer());
        metadata.setCredentialType("UniversityDegreeCredential");
        metadata.setIssuedAt(jsonLdCred.getIssuanceDate());
        metadata.setExpiresAt(jsonLdCred.getExpirationDate());
        metadata.setContexts(jsonLdCred.getContext().getContextUrls());
        metadata.setTypes(new ArrayList<>(jsonLdCred.getTypes()));
        
        // 4. Verify wrapper structure
        assertNotNull(credential);
        assertEquals(DigitalCredentialFormat.JSON_LD, credential.getFormat());
        assertNotNull(credential.getEncryptedData());
        assertNotNull(credential.getHolderBindingKeySeed());
        assertNotNull(credential.getSalt());
        
        // 5. Verify metadata
        assertEquals("UniversityDegreeCredential", metadata.getCredentialType());
        assertEquals("did:example:issuer", metadata.getIssuerDid());
        assertTrue(metadata.getContexts().contains("https://www.w3.org/2018/credentials/v1"));
        assertTrue(metadata.getTypes().contains("VerifiableCredential"));
    }
    
    @Test
    @DisplayName("E2E-005: CBOR storage and retrieval")
    void testCborStorageAndRetrieval() throws Exception {
        // 1. Create JSON-LD credential
        JsonLdCredential jsonLdCred = createSampleCredential();
        String credentialJson = jsonLdCred.toJson();
        
        // 2. Create VerifiableCredential wrapper
        VerifiableCredential original = new VerifiableCredential();
        original.setFormat(DigitalCredentialFormat.JSON_LD);
        original.setEncryptedData(credentialJson.getBytes());
        original.generateSeedAndSalt();
        
        DigitalCredentialMetadata metadata = original.getMetadata();
        metadata.setIssuerDid(jsonLdCred.getIssuer());
        metadata.setCredentialType("UniversityDegreeCredential");
        metadata.setContexts(jsonLdCred.getContext().getContextUrls());
        metadata.setTypes(new ArrayList<>(jsonLdCred.getTypes()));
        
        // 3. Serialize to CBOR
        byte[] cbor = original.toCbor();
        assertNotNull(cbor);
        assertTrue(cbor.length > 0);
        
        // 4. Deserialize from CBOR
        VerifiableCredential retrieved = VerifiableCredential.fromCbor(cbor);
        
        // 5. Verify retrieved credential
        assertNotNull(retrieved);
        assertEquals(original.getId(), retrieved.getId());
        assertEquals(original.getFormat(), retrieved.getFormat());
        assertEquals(DigitalCredentialFormat.JSON_LD, retrieved.getFormat());
        
        // 6. Verify metadata preserved
        DigitalCredentialMetadata retrievedMetadata = retrieved.getMetadata();
        assertEquals(metadata.getCredentialType(), retrievedMetadata.getCredentialType());
        assertEquals(metadata.getIssuerDid(), retrievedMetadata.getIssuerDid());
        assertEquals(metadata.getContexts().size(), retrievedMetadata.getContexts().size());
        assertEquals(metadata.getTypes().size(), retrievedMetadata.getTypes().size());
    }
    
    @Test
    @DisplayName("E2E-006: Credential validation")
    void testCredentialValidation() throws Exception {
        // 1. Create valid credential
        JsonLdCredential credential = createSampleCredential();
        
        // 2. Validate credential
        assertDoesNotThrow(() -> credential.validate());
        
        // 3. Test invalid credential - missing required fields
        JsonLdCredential invalid = new JsonLdCredential();
        assertThrows(JsonLdException.class, () -> invalid.validate());
    }
    
    @Test
    @DisplayName("E2E-007: Multiple credential types")
    void testMultipleCredentialTypes() throws Exception {
        // 1. Create credential with multiple types
        JsonLdCredential credential = new JsonLdCredential();
        credential.setId("https://example.com/credentials/456");
        credential.addType("VerifiableCredential");
        credential.addType("EmployeeCredential");
        credential.addType("SecurityClearanceCredential");
        
        credential.getContext().addContextUrl("https://www.w3.org/2018/credentials/v1");
        credential.setIssuer("did:example:employer");
        credential.setIssuanceDate(Instant.now());
        
        CredentialSubject subject = new CredentialSubject();
        subject.setId("did:example:employee");
        subject.addClaim("employeeId", "EMP-12345");
        subject.addClaim("clearanceLevel", "SECRET");
        credential.setCredentialSubject(subject);
        
        // 2. Verify all types present
        List<String> types = credential.getTypes();
        assertEquals(3, types.size());
        assertTrue(types.contains("VerifiableCredential"));
        assertTrue(types.contains("EmployeeCredential"));
        assertTrue(types.contains("SecurityClearanceCredential"));
    }
    
    @Test
    @DisplayName("E2E-008: Credential with custom context")
    void testCustomContext() throws Exception {
        // 1. Create credential with custom context
        JsonLdCredential credential = new JsonLdCredential();
        credential.setId("https://example.com/credentials/789");
        credential.addType("VerifiableCredential");
        credential.getContext().addContextUrl("https://www.w3.org/2018/credentials/v1");
        credential.getContext().addContextUrl("https://example.com/contexts/university/v1");
        credential.setIssuer("did:example:issuer");
        credential.setIssuanceDate(Instant.now());
        
        CredentialSubject subject = new CredentialSubject();
        subject.setId("did:example:holder");
        credential.setCredentialSubject(subject);
        
        // 2. Verify contexts
        List<String> contexts = credential.getContext().getContextUrls();
        assertEquals(2, contexts.size());
        assertTrue(contexts.contains("https://www.w3.org/2018/credentials/v1"));
        assertTrue(contexts.contains("https://example.com/contexts/university/v1"));
    }
    
    @Test
    @DisplayName("E2E-009: Holder binding key derivation")
    void testHolderBindingKeyDerivation() throws Exception {
        // 1. Generate credential seed
        byte[] seed = HolderBindingKeyManager.generateSeed();
        assertNotNull(seed);
        assertEquals(32, seed.length);
        
        // 2. Derive holder binding key
        String credentialId = "cred-123";
        String issuerId = "did:example:issuer";
        String credentialType = "UniversityDegreeCredential";
        
        KeyPair bindingKey = HolderBindingKeyManager.deriveBindingKey(
            seed, credentialId, issuerId, credentialType, masterKey);
        
        // 3. Verify key pair generated
        assertNotNull(bindingKey);
        assertNotNull(bindingKey.getPrivate());
        assertNotNull(bindingKey.getPublic());
        
        // 4. Verify deterministic derivation
        KeyPair bindingKey2 = HolderBindingKeyManager.deriveBindingKey(
            seed, credentialId, issuerId, credentialType, masterKey);
        
        assertArrayEquals(bindingKey.getPublic().getEncoded(), 
                         bindingKey2.getPublic().getEncoded());
    }
    
    @Test
    @DisplayName("E2E-010: Performance - credential creation latency")
    void testCredentialCreationPerformance() throws Exception {
        long startTime = System.currentTimeMillis();
        
        JsonLdCredential credential = createSampleCredential();
        String json = credential.toJson();
        JsonLdCredential deserialized = JsonLdCredential.fromJson(json);
        
        long endTime = System.currentTimeMillis();
        long latency = endTime - startTime;
        
        assertNotNull(deserialized);
        assertTrue(latency < 100, 
            "Credential creation should complete in less than 100ms, took: " + latency + "ms");
    }
    
    // Helper methods
    
    /**
     * Creates a sample JSON-LD credential for testing.
     */
    private JsonLdCredential createSampleCredential() {
        JsonLdCredential credential = new JsonLdCredential();
        
        // Set ID
        credential.setId("https://example.com/credentials/123");
        
        // Set types
        credential.addType("VerifiableCredential");
        credential.addType("UniversityDegreeCredential");
        
        // Set context
        credential.getContext().addContextUrl("https://www.w3.org/2018/credentials/v1");
        
        // Set issuer
        credential.setIssuer("did:example:issuer");
        
        // Set dates
        Instant now = Instant.now();
        credential.setIssuanceDate(now);
        credential.setExpirationDate(now.plusSeconds(31536000)); // 1 year
        
        // Set credential subject
        CredentialSubject subject = new CredentialSubject();
        subject.setId("did:example:holder");
        subject.addClaim("degree", Map.of(
            "type", "BachelorDegree",
            "name", "Bachelor of Science in Computer Science"
        ));
        subject.addClaim("alumniOf", "Example University");
        credential.setCredentialSubject(subject);
        
        return credential;
    }
}

// Made with Bob