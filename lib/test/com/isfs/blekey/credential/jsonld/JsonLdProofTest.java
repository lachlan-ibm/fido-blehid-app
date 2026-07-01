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
 * Unit tests for {@link JsonLdProof}.
 */
class JsonLdProofTest {
    
    private JsonLdProof proof;
    private Instant testTime;
    
    @BeforeEach
    void setUp() {
        proof = new JsonLdProof();
        testTime = Instant.parse("2024-01-15T10:30:00Z");
    }
    
    @Test
    void testEmptyProof() {
        assertNull(proof.getType());
        assertNull(proof.getVerificationMethod());
        assertNull(proof.getProofPurpose());
        assertNull(proof.getCreated());
        assertNull(proof.getJws());
        assertNull(proof.getProofValue());
    }
    
    @Test
    void testConstructorWithType() {
        JsonLdProof p = new JsonLdProof(JsonLdProof.TYPE_JWS_2020);
        assertEquals(JsonLdProof.TYPE_JWS_2020, p.getType());
    }
    
    @Test
    void testSetType() {
        proof.setType(JsonLdProof.TYPE_JWS_2020);
        assertEquals(JsonLdProof.TYPE_JWS_2020, proof.getType());
    }
    
    @Test
    void testSetVerificationMethod() {
        proof.setVerificationMethod("did:example:issuer#key-1");
        assertEquals("did:example:issuer#key-1", proof.getVerificationMethod());
    }
    
    @Test
    void testSetProofPurpose() {
        proof.setProofPurpose(JsonLdProof.PURPOSE_ASSERTION);
        assertEquals(JsonLdProof.PURPOSE_ASSERTION, proof.getProofPurpose());
    }
    
    @Test
    void testSetCreated() {
        proof.setCreated(testTime);
        assertEquals(testTime, proof.getCreated());
    }
    
    @Test
    void testSetJws() {
        String jws = "eyJhbGciOiJFZERTQSJ9..signature";
        proof.setJws(jws);
        assertEquals(jws, proof.getJws());
    }
    
    @Test
    void testSetProofValue() {
        String proofValue = "base64url-encoded-signature";
        proof.setProofValue(proofValue);
        assertEquals(proofValue, proof.getProofValue());
    }
    
    @Test
    void testAddProperty() {
        proof.addProperty("challenge", "abc123");
        proof.addProperty("domain", "example.com");
        
        assertEquals("abc123", proof.getProperty("challenge"));
        assertEquals("example.com", proof.getProperty("domain"));
    }
    
    @Test
    void testAddNullProperty() {
        proof.addProperty(null, "value");
        proof.addProperty("", "value");
        proof.addProperty("key", null);
        
        assertTrue(proof.getAdditionalProperties().isEmpty());
    }
    
    @Test
    void testGetNonExistentProperty() {
        assertNull(proof.getProperty("nonexistent"));
    }
    
    @Test
    void testGetAdditionalProperties() {
        proof.addProperty("challenge", "abc123");
        proof.addProperty("domain", "example.com");
        
        var props = proof.getAdditionalProperties();
        assertEquals(2, props.size());
        assertEquals("abc123", props.get("challenge"));
        assertEquals("example.com", props.get("domain"));
    }
    
    @Test
    void testToJson() {
        proof.setType(JsonLdProof.TYPE_JWS_2020);
        proof.setVerificationMethod("did:example:issuer#key-1");
        proof.setProofPurpose(JsonLdProof.PURPOSE_ASSERTION);
        proof.setCreated(testTime);
        proof.setJws("eyJhbGciOiJFZERTQSJ9..signature");
        proof.addProperty("challenge", "abc123");
        
        JsonObject json = proof.toJson();
        
        assertEquals(JsonLdProof.TYPE_JWS_2020, json.get("type").getAsString());
        assertEquals("did:example:issuer#key-1", json.get("verificationMethod").getAsString());
        assertEquals(JsonLdProof.PURPOSE_ASSERTION, json.get("proofPurpose").getAsString());
        assertEquals(testTime.toString(), json.get("created").getAsString());
        assertEquals("eyJhbGciOiJFZERTQSJ9..signature", json.get("jws").getAsString());
        assertEquals("abc123", json.get("challenge").getAsString());
    }
    
    @Test
    void testToJsonMinimal() {
        proof.setType(JsonLdProof.TYPE_JWS_2020);
        proof.setVerificationMethod("did:example:issuer#key-1");
        proof.setProofPurpose(JsonLdProof.PURPOSE_ASSERTION);
        proof.setJws("eyJhbGciOiJFZERTQSJ9..signature");
        
        JsonObject json = proof.toJson();
        
        assertTrue(json.has("type"));
        assertTrue(json.has("verificationMethod"));
        assertTrue(json.has("proofPurpose"));
        assertTrue(json.has("jws"));
        assertFalse(json.has("created"));
        assertFalse(json.has("proofValue"));
    }
    
    @Test
    void testToJsonWithProofValue() {
        proof.setType(JsonLdProof.TYPE_ED25519_2020);
        proof.setVerificationMethod("did:example:issuer#key-1");
        proof.setProofPurpose(JsonLdProof.PURPOSE_ASSERTION);
        proof.setProofValue("base64url-signature");
        
        JsonObject json = proof.toJson();
        
        assertTrue(json.has("proofValue"));
        assertFalse(json.has("jws"));
    }
    
    @Test
    void testFromJson() throws JsonLdException {
        JsonObject json = new JsonObject();
        json.addProperty("type", JsonLdProof.TYPE_JWS_2020);
        json.addProperty("verificationMethod", "did:example:issuer#key-1");
        json.addProperty("proofPurpose", JsonLdProof.PURPOSE_ASSERTION);
        json.addProperty("created", testTime.toString());
        json.addProperty("jws", "eyJhbGciOiJFZERTQSJ9..signature");
        json.addProperty("challenge", "abc123");
        
        JsonLdProof p = JsonLdProof.fromJson(json);
        
        assertEquals(JsonLdProof.TYPE_JWS_2020, p.getType());
        assertEquals("did:example:issuer#key-1", p.getVerificationMethod());
        assertEquals(JsonLdProof.PURPOSE_ASSERTION, p.getProofPurpose());
        assertEquals(testTime, p.getCreated());
        assertEquals("eyJhbGciOiJFZERTQSJ9..signature", p.getJws());
        assertEquals("abc123", p.getProperty("challenge"));
    }
    
    @Test
    void testFromJsonMinimal() throws JsonLdException {
        JsonObject json = new JsonObject();
        json.addProperty("type", JsonLdProof.TYPE_JWS_2020);
        json.addProperty("verificationMethod", "did:example:issuer#key-1");
        json.addProperty("proofPurpose", JsonLdProof.PURPOSE_ASSERTION);
        json.addProperty("jws", "eyJhbGciOiJFZERTQSJ9..signature");
        
        JsonLdProof p = JsonLdProof.fromJson(json);
        
        assertEquals(JsonLdProof.TYPE_JWS_2020, p.getType());
        assertNull(p.getCreated());
    }
    
    @Test
    void testFromJsonNull() {
        assertThrows(JsonLdException.class, () -> {
            JsonLdProof.fromJson(null);
        });
    }
    
    @Test
    void testFromJsonInvalidCreated() {
        JsonObject json = new JsonObject();
        json.addProperty("type", JsonLdProof.TYPE_JWS_2020);
        json.addProperty("verificationMethod", "did:example:issuer#key-1");
        json.addProperty("proofPurpose", JsonLdProof.PURPOSE_ASSERTION);
        json.addProperty("created", "invalid-timestamp");
        json.addProperty("jws", "eyJhbGciOiJFZERTQSJ9..signature");
        
        assertThrows(JsonLdException.class, () -> {
            JsonLdProof.fromJson(json);
        });
    }
    
    @Test
    void testValidateSuccess() throws JsonLdException {
        proof.setType(JsonLdProof.TYPE_JWS_2020);
        proof.setVerificationMethod("did:example:issuer#key-1");
        proof.setProofPurpose(JsonLdProof.PURPOSE_ASSERTION);
        proof.setJws("eyJhbGciOiJFZERTQSJ9..signature");
        
        assertDoesNotThrow(() -> proof.validate());
    }
    
    @Test
    void testValidateMissingType() {
        proof.setVerificationMethod("did:example:issuer#key-1");
        proof.setProofPurpose(JsonLdProof.PURPOSE_ASSERTION);
        proof.setJws("eyJhbGciOiJFZERTQSJ9..signature");
        
        JsonLdException ex = assertThrows(JsonLdException.class, () -> proof.validate());
        assertTrue(ex.getMessage().contains("type"));
    }
    
    @Test
    void testValidateMissingVerificationMethod() {
        proof.setType(JsonLdProof.TYPE_JWS_2020);
        proof.setProofPurpose(JsonLdProof.PURPOSE_ASSERTION);
        proof.setJws("eyJhbGciOiJFZERTQSJ9..signature");
        
        JsonLdException ex = assertThrows(JsonLdException.class, () -> proof.validate());
        assertTrue(ex.getMessage().toLowerCase().contains("verification"));
    }
    
    @Test
    void testValidateMissingProofPurpose() {
        proof.setType(JsonLdProof.TYPE_JWS_2020);
        proof.setVerificationMethod("did:example:issuer#key-1");
        proof.setJws("eyJhbGciOiJFZERTQSJ9..signature");
        
        JsonLdException ex = assertThrows(JsonLdException.class, () -> proof.validate());
        assertTrue(ex.getMessage().toLowerCase().contains("purpose"));
    }
    
    @Test
    void testValidateMissingSignature() {
        proof.setType(JsonLdProof.TYPE_JWS_2020);
        proof.setVerificationMethod("did:example:issuer#key-1");
        proof.setProofPurpose(JsonLdProof.PURPOSE_ASSERTION);
        
        JsonLdException ex = assertThrows(JsonLdException.class, () -> proof.validate());
        assertTrue(ex.getMessage().contains("jws") || ex.getMessage().contains("proofValue"));
    }
    
    @Test
    void testValidateWithProofValue() throws JsonLdException {
        proof.setType(JsonLdProof.TYPE_ED25519_2020);
        proof.setVerificationMethod("did:example:issuer#key-1");
        proof.setProofPurpose(JsonLdProof.PURPOSE_ASSERTION);
        proof.setProofValue("base64url-signature");
        
        assertDoesNotThrow(() -> proof.validate());
    }
    
    @Test
    void testRoundTrip() throws JsonLdException {
        proof.setType(JsonLdProof.TYPE_JWS_2020);
        proof.setVerificationMethod("did:example:issuer#key-1");
        proof.setProofPurpose(JsonLdProof.PURPOSE_ASSERTION);
        proof.setCreated(testTime);
        proof.setJws("eyJhbGciOiJFZERTQSJ9..signature");
        proof.addProperty("challenge", "abc123");
        proof.addProperty("domain", "example.com");
        
        JsonObject json = proof.toJson();
        JsonLdProof restored = JsonLdProof.fromJson(json);
        
        assertEquals(proof, restored);
    }
    
    @Test
    void testEquals() {
        JsonLdProof p1 = new JsonLdProof(JsonLdProof.TYPE_JWS_2020);
        p1.setVerificationMethod("did:example:issuer#key-1");
        p1.setProofPurpose(JsonLdProof.PURPOSE_ASSERTION);
        p1.setCreated(testTime);
        p1.setJws("eyJhbGciOiJFZERTQSJ9..signature");
        
        JsonLdProof p2 = new JsonLdProof(JsonLdProof.TYPE_JWS_2020);
        p2.setVerificationMethod("did:example:issuer#key-1");
        p2.setProofPurpose(JsonLdProof.PURPOSE_ASSERTION);
        p2.setCreated(testTime);
        p2.setJws("eyJhbGciOiJFZERTQSJ9..signature");
        
        assertEquals(p1, p2);
        assertEquals(p1.hashCode(), p2.hashCode());
    }
    
    @Test
    void testNotEqualsDifferentType() {
        JsonLdProof p1 = new JsonLdProof(JsonLdProof.TYPE_JWS_2020);
        p1.setVerificationMethod("did:example:issuer#key-1");
        p1.setProofPurpose(JsonLdProof.PURPOSE_ASSERTION);
        p1.setJws("signature");
        
        JsonLdProof p2 = new JsonLdProof(JsonLdProof.TYPE_ED25519_2020);
        p2.setVerificationMethod("did:example:issuer#key-1");
        p2.setProofPurpose(JsonLdProof.PURPOSE_ASSERTION);
        p2.setProofValue("signature");
        
        assertNotEquals(p1, p2);
    }
    
    @Test
    void testNotEqualsDifferentSignature() {
        JsonLdProof p1 = new JsonLdProof(JsonLdProof.TYPE_JWS_2020);
        p1.setVerificationMethod("did:example:issuer#key-1");
        p1.setProofPurpose(JsonLdProof.PURPOSE_ASSERTION);
        p1.setJws("signature1");
        
        JsonLdProof p2 = new JsonLdProof(JsonLdProof.TYPE_JWS_2020);
        p2.setVerificationMethod("did:example:issuer#key-1");
        p2.setProofPurpose(JsonLdProof.PURPOSE_ASSERTION);
        p2.setJws("signature2");
        
        assertNotEquals(p1, p2);
    }
    
    @Test
    void testToString() {
        proof.setType(JsonLdProof.TYPE_JWS_2020);
        proof.setVerificationMethod("did:example:issuer#key-1");
        proof.setProofPurpose(JsonLdProof.PURPOSE_ASSERTION);
        proof.setCreated(testTime);
        
        String str = proof.toString();
        assertTrue(str.contains("JsonLdProof"));
        assertTrue(str.contains(JsonLdProof.TYPE_JWS_2020));
        assertTrue(str.contains("did:example:issuer#key-1"));
        assertTrue(str.contains(JsonLdProof.PURPOSE_ASSERTION));
    }
    
    @Test
    void testMethodChaining() {
        JsonLdProof p = new JsonLdProof()
            .setType(JsonLdProof.TYPE_JWS_2020)
            .setVerificationMethod("did:example:issuer#key-1")
            .setProofPurpose(JsonLdProof.PURPOSE_ASSERTION)
            .setCreated(testTime)
            .setJws("eyJhbGciOiJFZERTQSJ9..signature")
            .addProperty("challenge", "abc123");
        
        assertEquals(JsonLdProof.TYPE_JWS_2020, p.getType());
        assertEquals("did:example:issuer#key-1", p.getVerificationMethod());
        assertEquals("abc123", p.getProperty("challenge"));
    }
    
    @Test
    void testProofTypeConstants() {
        assertEquals("JsonWebSignature2020", JsonLdProof.TYPE_JWS_2020);
        assertEquals("Ed25519Signature2020", JsonLdProof.TYPE_ED25519_2020);
        assertEquals("EcdsaSecp256k1Signature2019", JsonLdProof.TYPE_ECDSA_SECP256K1_2019);
    }
    
    @Test
    void testProofPurposeConstants() {
        assertEquals("assertionMethod", JsonLdProof.PURPOSE_ASSERTION);
        assertEquals("authentication", JsonLdProof.PURPOSE_AUTHENTICATION);
        assertEquals("keyAgreement", JsonLdProof.PURPOSE_KEY_AGREEMENT);
    }
}

// Made with Bob