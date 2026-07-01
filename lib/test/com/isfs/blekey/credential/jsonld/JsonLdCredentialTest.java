/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.jsonld;

import com.google.gson.JsonObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive unit tests for {@link JsonLdCredential}.
 * Tests serialization, deserialization, validation, and all credential operations.
 */
class JsonLdCredentialTest {
    
    private JsonLdCredential credential;
    private Instant testIssuanceDate;
    private Instant testExpirationDate;
    
    @BeforeEach
    void setUp() {
        credential = new JsonLdCredential();
        // Add required W3C VC context and type (no longer added automatically)
        credential.getContext().addContextUrl(JsonLdContext.W3C_VC_CONTEXT);
        credential.addType("VerifiableCredential");
        
        testIssuanceDate = Instant.parse("2024-01-15T10:30:00Z");
        testExpirationDate = Instant.parse("2025-01-15T10:30:00Z");
    }
    
    @Test
    void testDefaultConstructor() {
        // Test that constructor creates empty credential (no automatic defaults)
        JsonLdCredential emptyCred = new JsonLdCredential();
        assertNotNull(emptyCred.getContext());
        assertTrue(emptyCred.getContext().isEmpty());
        assertEquals(0, emptyCred.getTypes().size());
        assertNull(emptyCred.getId());
        assertNull(emptyCred.getIssuer());
        assertNull(emptyCred.getIssuanceDate());
        assertNull(emptyCred.getExpirationDate());
        assertNull(emptyCred.getCredentialSubject());
        assertNull(emptyCred.getProof());
    }
    
    @Test
    void testDefaultContextIncludesW3CVC() {
        // After setUp, credential should have W3C VC context
        assertTrue(credential.getContext().getContextUrls().contains(JsonLdContext.W3C_VC_CONTEXT));
    }
    
    @Test
    void testSetId() {
        credential.setId("http://example.edu/credentials/3732");
        assertEquals("http://example.edu/credentials/3732", credential.getId());
    }
    
    @Test
    void testSetContext() {
        JsonLdContext context = new JsonLdContext();
        context.addContextUrl(JsonLdContext.W3C_VC_CONTEXT);
        context.addContextUrl("https://www.w3.org/2018/credentials/examples/v1");
        
        credential.setContext(context);
        assertEquals(context, credential.getContext());
    }
    
    @Test
    void testAddType() {
        credential.addType("UniversityDegreeCredential");
        
        assertEquals(2, credential.getTypes().size());
        assertTrue(credential.getTypes().contains("VerifiableCredential"));
        assertTrue(credential.getTypes().contains("UniversityDegreeCredential"));
    }
    
    @Test
    void testAddMultipleTypes() {
        credential.addType("UniversityDegreeCredential");
        credential.addType("BachelorDegree");
        
        assertEquals(3, credential.getTypes().size());
    }
    
    @Test
    void testAddDuplicateType() {
        credential.addType("UniversityDegreeCredential");
        credential.addType("UniversityDegreeCredential");
        
        assertEquals(2, credential.getTypes().size());
    }
    
    @Test
    void testAddNullType() {
        credential.addType(null);
        assertEquals(1, credential.getTypes().size());
    }
    
    @Test
    void testAddEmptyType() {
        credential.addType("");
        assertEquals(1, credential.getTypes().size());
    }
    
    @Test
    void testRemoveType() {
        credential.addType("UniversityDegreeCredential");
        credential.removeType("UniversityDegreeCredential");
        
        assertEquals(1, credential.getTypes().size());
        assertFalse(credential.getTypes().contains("UniversityDegreeCredential"));
    }
    
    @Test
    void testSetIssuer() {
        credential.setIssuer("did:example:issuer");
        assertEquals("did:example:issuer", credential.getIssuer());
    }
    
    @Test
    void testSetIssuanceDate() {
        credential.setIssuanceDate(testIssuanceDate);
        assertEquals(testIssuanceDate, credential.getIssuanceDate());
    }
    
    @Test
    void testSetExpirationDate() {
        credential.setExpirationDate(testExpirationDate);
        assertEquals(testExpirationDate, credential.getExpirationDate());
    }
    
    @Test
    void testSetCredentialSubject() {
        CredentialSubject subject = new CredentialSubject("did:example:student");
        subject.addClaim("degree", "Bachelor of Science");
        
        credential.setCredentialSubject(subject);
        assertEquals(subject, credential.getCredentialSubject());
    }
    
    @Test
    void testSetProof() {
        JsonLdProof proof = new JsonLdProof(JsonLdProof.TYPE_JWS_2020);
        proof.setVerificationMethod("did:example:issuer#key-1");
        proof.setProofPurpose(JsonLdProof.PURPOSE_ASSERTION);
        proof.setJws("eyJhbGciOiJFZERTQSJ9..signature");
        
        credential.setProof(proof);
        assertEquals(proof, credential.getProof());
    }
    
    @Test
    void testValidateSuccess() throws JsonLdException {
        setupValidCredential();
        assertDoesNotThrow(() -> credential.validate());
    }
    
    @Test
    void testValidateMissingContext() {
        credential.setContext(new JsonLdContext()); // Empty context
        credential.setIssuer("did:example:issuer");
        credential.setIssuanceDate(testIssuanceDate);
        credential.setCredentialSubject(new CredentialSubject("did:example:student"));
        
        JsonLdException ex = assertThrows(JsonLdException.class, () -> credential.validate());
        assertTrue(ex.getMessage().contains("@context"));
    }
    
    @Test
    void testValidateMissingVerifiableCredentialType() {
        credential.removeType("VerifiableCredential");
        credential.setIssuer("did:example:issuer");
        credential.setIssuanceDate(testIssuanceDate);
        credential.setCredentialSubject(new CredentialSubject("did:example:student"));
        
        JsonLdException ex = assertThrows(JsonLdException.class, () -> credential.validate());
        assertTrue(ex.getMessage().toLowerCase().contains("verifiablecredential") ||
                   ex.getMessage().toLowerCase().contains("type"));
    }
    
    @Test
    void testValidateMissingIssuer() {
        credential.setIssuanceDate(testIssuanceDate);
        credential.setCredentialSubject(new CredentialSubject("did:example:student"));
        
        JsonLdException ex = assertThrows(JsonLdException.class, () -> credential.validate());
        assertTrue(ex.getMessage().contains("Issuer"));
    }
    
    @Test
    void testValidateMissingIssuanceDate() {
        credential.setIssuer("did:example:issuer");
        credential.setCredentialSubject(new CredentialSubject("did:example:student"));
        
        JsonLdException ex = assertThrows(JsonLdException.class, () -> credential.validate());
        assertTrue(ex.getMessage().contains("Issuance date"));
    }
    
    @Test
    void testValidateMissingCredentialSubject() {
        credential.setIssuer("did:example:issuer");
        credential.setIssuanceDate(testIssuanceDate);
        
        JsonLdException ex = assertThrows(JsonLdException.class, () -> credential.validate());
        assertTrue(ex.getMessage().contains("Credential subject"));
    }
    
    @Test
    void testValidateInvalidProof() {
        setupValidCredential();
        
        // Add invalid proof (missing required fields)
        JsonLdProof proof = new JsonLdProof();
        proof.setType(JsonLdProof.TYPE_JWS_2020);
        credential.setProof(proof);
        
        assertThrows(JsonLdException.class, () -> credential.validate());
    }
    
    @Test
    void testToJsonComplete() {
        setupCompleteCredential();
        
        String json = credential.toJson();
        
        assertNotNull(json);
        assertTrue(json.contains("@context"));
        assertTrue(json.contains("id"));
        assertTrue(json.contains("type"));
        assertTrue(json.contains("issuer"));
        assertTrue(json.contains("issuanceDate"));
        assertTrue(json.contains("expirationDate"));
        assertTrue(json.contains("credentialSubject"));
        assertTrue(json.contains("proof"));
    }
    
    @Test
    void testToJsonMinimal() {
        setupValidCredential();
        
        String json = credential.toJson();
        
        assertNotNull(json);
        assertTrue(json.contains("@context"));
        assertTrue(json.contains("type"));
        assertTrue(json.contains("issuer"));
        assertTrue(json.contains("issuanceDate"));
        assertTrue(json.contains("credentialSubject"));
        // Check that credential itself has no id (but credentialSubject may have one)
        JsonObject jsonObj = credential.toJsonObject();
        assertFalse(jsonObj.has("id")); // Credential has no id field
        assertFalse(json.contains("expirationDate"));
        assertFalse(json.contains("proof"));
    }
    
    @Test
    void testToJsonObjectSingleType() {
        credential.setIssuer("did:example:issuer");
        
        JsonObject json = credential.toJsonObject();
        
        assertTrue(json.get("type").isJsonPrimitive());
        assertEquals("VerifiableCredential", json.get("type").getAsString());
    }
    
    @Test
    void testToJsonObjectMultipleTypes() {
        credential.addType("UniversityDegreeCredential");
        credential.setIssuer("did:example:issuer");
        
        JsonObject json = credential.toJsonObject();
        
        assertTrue(json.get("type").isJsonArray());
        assertEquals(2, json.get("type").getAsJsonArray().size());
    }
    
    @Test
    void testFromJsonComplete() throws JsonLdException {
        setupCompleteCredential();
        String json = credential.toJson();
        
        JsonLdCredential restored = JsonLdCredential.fromJson(json);
        
        assertNotNull(restored);
        assertEquals(credential.getId(), restored.getId());
        assertEquals(credential.getIssuer(), restored.getIssuer());
        assertEquals(credential.getIssuanceDate(), restored.getIssuanceDate());
        assertEquals(credential.getExpirationDate(), restored.getExpirationDate());
        assertNotNull(restored.getCredentialSubject());
        assertNotNull(restored.getProof());
    }
    
    @Test
    void testFromJsonMinimal() throws JsonLdException {
        setupValidCredential();
        String json = credential.toJson();
        
        JsonLdCredential restored = JsonLdCredential.fromJson(json);
        
        assertNotNull(restored);
        assertEquals(credential.getIssuer(), restored.getIssuer());
        assertEquals(credential.getIssuanceDate(), restored.getIssuanceDate());
        assertNull(restored.getId());
        assertNull(restored.getExpirationDate());
        assertNull(restored.getProof());
    }
    
    @Test
    void testFromJsonNull() {
        assertThrows(JsonLdException.class, () -> {
            JsonLdCredential.fromJson((String) null);
        });
    }
    
    @Test
    void testFromJsonEmpty() {
        assertThrows(JsonLdException.class, () -> {
            JsonLdCredential.fromJson("");
        });
    }
    
    @Test
    void testFromJsonInvalidJson() {
        assertThrows(JsonLdException.class, () -> {
            JsonLdCredential.fromJson("not valid json");
        });
    }
    
    @Test
    void testFromJsonObjectWithIssuerObject() throws JsonLdException {
        JsonObject json = new JsonObject();
        json.addProperty("@context", JsonLdContext.W3C_VC_CONTEXT);
        json.addProperty("type", "VerifiableCredential");
        
        JsonObject issuerObj = new JsonObject();
        issuerObj.addProperty("id", "did:example:issuer");
        issuerObj.addProperty("name", "Example University");
        json.add("issuer", issuerObj);
        
        json.addProperty("issuanceDate", testIssuanceDate.toString());
        
        JsonObject subject = new JsonObject();
        subject.addProperty("id", "did:example:student");
        json.add("credentialSubject", subject);
        
        JsonLdCredential cred = JsonLdCredential.fromJsonObject(json);
        
        assertEquals("did:example:issuer", cred.getIssuer());
    }
    
    @Test
    void testRoundTripComplete() throws JsonLdException {
        setupCompleteCredential();
        
        String json = credential.toJson();
        JsonLdCredential restored = JsonLdCredential.fromJson(json);
        
        assertEquals(credential, restored);
    }
    
    @Test
    void testRoundTripMinimal() throws JsonLdException {
        setupValidCredential();
        
        String json = credential.toJson();
        JsonLdCredential restored = JsonLdCredential.fromJson(json);
        
        assertEquals(credential, restored);
    }
    
    @Test
    void testEquals() {
        JsonLdCredential cred1 = new JsonLdCredential();
        cred1.setId("http://example.edu/credentials/3732");
        cred1.setIssuer("did:example:issuer");
        cred1.setIssuanceDate(testIssuanceDate);
        cred1.setCredentialSubject(new CredentialSubject("did:example:student"));
        
        JsonLdCredential cred2 = new JsonLdCredential();
        cred2.setId("http://example.edu/credentials/3732");
        cred2.setIssuer("did:example:issuer");
        cred2.setIssuanceDate(testIssuanceDate);
        cred2.setCredentialSubject(new CredentialSubject("did:example:student"));
        
        assertEquals(cred1, cred2);
        assertEquals(cred1.hashCode(), cred2.hashCode());
    }
    
    @Test
    void testNotEqualsDifferentId() {
        JsonLdCredential cred1 = new JsonLdCredential();
        cred1.setId("http://example.edu/credentials/3732");
        cred1.setIssuer("did:example:issuer");
        
        JsonLdCredential cred2 = new JsonLdCredential();
        cred2.setId("http://example.edu/credentials/9999");
        cred2.setIssuer("did:example:issuer");
        
        assertNotEquals(cred1, cred2);
    }
    
    @Test
    void testNotEqualsDifferentIssuer() {
        JsonLdCredential cred1 = new JsonLdCredential();
        cred1.setIssuer("did:example:issuer1");
        
        JsonLdCredential cred2 = new JsonLdCredential();
        cred2.setIssuer("did:example:issuer2");
        
        assertNotEquals(cred1, cred2);
    }
    
    @Test
    void testToString() {
        setupCompleteCredential();
        
        String str = credential.toString();
        assertTrue(str.contains("JsonLdCredential"));
        assertTrue(str.contains(credential.getId()));
        assertTrue(str.contains(credential.getIssuer()));
        assertTrue(str.contains("hasSubject=true"));
        assertTrue(str.contains("hasProof=true"));
    }
    
    @Test
    void testMethodChaining() {
        CredentialSubject subject = new CredentialSubject("did:example:student");
        JsonLdProof proof = new JsonLdProof(JsonLdProof.TYPE_JWS_2020);
        
        JsonLdCredential cred = new JsonLdCredential()
            .setId("http://example.edu/credentials/3732")
            .addType("VerifiableCredential")  // Add required base type
            .addType("UniversityDegreeCredential")
            .setIssuer("did:example:issuer")
            .setIssuanceDate(testIssuanceDate)
            .setExpirationDate(testExpirationDate)
            .setCredentialSubject(subject)
            .setProof(proof);
        
        // Also add required W3C VC context
        cred.getContext().addContextUrl(JsonLdContext.W3C_VC_CONTEXT);
        
        assertEquals("http://example.edu/credentials/3732", cred.getId());
        assertEquals(2, cred.getTypes().size());
        assertEquals("did:example:issuer", cred.getIssuer());
        assertEquals(testIssuanceDate, cred.getIssuanceDate());
        assertEquals(testExpirationDate, cred.getExpirationDate());
        assertEquals(subject, cred.getCredentialSubject());
        assertEquals(proof, cred.getProof());
    }
    
    @Test
    void testCompleteCredentialExample() throws JsonLdException {
        // Create a complete university degree credential
        JsonLdCredential cred = new JsonLdCredential();
        cred.setId("http://example.edu/credentials/3732");
        
        // Add required W3C VC context and type
        cred.getContext().addContextUrl(JsonLdContext.W3C_VC_CONTEXT);
        cred.addType("VerifiableCredential");
        cred.addType("UniversityDegreeCredential");
        
        cred.setIssuer("did:example:university");
        cred.setIssuanceDate(testIssuanceDate);
        cred.setExpirationDate(testExpirationDate);
        
        // Add additional context
        cred.getContext().addContextUrl("https://www.w3.org/2018/credentials/examples/v1");
        
        // Add credential subject
        CredentialSubject subject = new CredentialSubject("did:example:student123");
        subject.addClaim("degree", "Bachelor of Science");
        subject.addClaim("degreeType", "BachelorDegree");
        subject.addClaim("name", "Alice Smith");
        cred.setCredentialSubject(subject);
        
        // Add proof
        JsonLdProof proof = new JsonLdProof(JsonLdProof.TYPE_JWS_2020);
        proof.setVerificationMethod("did:example:university#key-1");
        proof.setProofPurpose(JsonLdProof.PURPOSE_ASSERTION);
        proof.setCreated(testIssuanceDate);
        proof.setJws("eyJhbGciOiJFZERTQSJ9..signature");
        cred.setProof(proof);
        
        // Validate
        assertDoesNotThrow(() -> cred.validate());
        
        // Serialize and deserialize
        String json = cred.toJson();
        JsonLdCredential restored = JsonLdCredential.fromJson(json);
        
        assertEquals(cred, restored);
        assertEquals("Alice Smith", restored.getCredentialSubject().getClaimAsString("name"));
    }
    
    // Helper methods
    
    private void setupValidCredential() {
        credential.setIssuer("did:example:issuer");
        credential.setIssuanceDate(testIssuanceDate);
        
        CredentialSubject subject = new CredentialSubject("did:example:student");
        subject.addClaim("name", "Alice Smith");
        credential.setCredentialSubject(subject);
    }
    
    private void setupCompleteCredential() {
        credential.setId("http://example.edu/credentials/3732");
        credential.addType("UniversityDegreeCredential");
        credential.setIssuer("did:example:issuer");
        credential.setIssuanceDate(testIssuanceDate);
        credential.setExpirationDate(testExpirationDate);
        
        credential.getContext().addContextUrl("https://www.w3.org/2018/credentials/examples/v1");
        
        CredentialSubject subject = new CredentialSubject("did:example:student");
        subject.addClaim("degree", "Bachelor of Science");
        subject.addClaim("name", "Alice Smith");
        credential.setCredentialSubject(subject);
        
        JsonLdProof proof = new JsonLdProof(JsonLdProof.TYPE_JWS_2020);
        proof.setVerificationMethod("did:example:issuer#key-1");
        proof.setProofPurpose(JsonLdProof.PURPOSE_ASSERTION);
        proof.setCreated(testIssuanceDate);
        proof.setJws("eyJhbGciOiJFZERTQSJ9..signature");
        credential.setProof(proof);
    }
}

// Made with Bob