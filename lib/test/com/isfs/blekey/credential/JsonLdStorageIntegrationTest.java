/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.credential;

import com.isfs.blekey.credential.jsonld.JsonLdException;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for JSON-LD credential storage.
 * Tests Phase 2A: JSON-LD Storage Integration
 * 
 * Verifies:
 * - JSON-LD credentials can be serialized to CBOR
 * - JSON-LD credentials can be deserialized from CBOR
 * - JSON-LD metadata fields are preserved
 * - SD-JWT credentials still work (backward compatibility)
 */
public class JsonLdStorageIntegrationTest {
    
    @Test
    public void testJsonLdCredentialSerialization() {
        // Create a JSON-LD credential
        VerifiableCredential credential = new VerifiableCredential();
        credential.setFormat(DigitalCredentialFormat.JSON_LD);
        credential.setId("http://example.edu/credentials/3732");
        
        // Set up metadata with JSON-LD specific fields
        DigitalCredentialMetadata metadata = new DigitalCredentialMetadata();
        metadata.setIssuerDid("did:example:issuer123");
        metadata.setIssuerUrl("https://example.edu");
        metadata.setCredentialType("UniversityDegreeCredential");
        metadata.setIssuedAt(Instant.parse("2024-01-01T00:00:00Z"));
        metadata.setExpiresAt(Instant.parse("2025-01-01T00:00:00Z"));
        
        // Add JSON-LD specific fields
        metadata.addContext("https://www.w3.org/2018/credentials/v1");
        metadata.addContext("https://www.w3.org/2018/credentials/examples/v1");
        metadata.addType("VerifiableCredential");
        metadata.addType("UniversityDegreeCredential");
        metadata.setCredentialSubject("{\"id\":\"did:example:student\",\"degree\":\"Bachelor\"}");
        metadata.setProofType("JsonWebSignature2020");
        
        credential.setMetadata(metadata);
        credential.generateSeedAndSalt();
        credential.setEncryptedData(new byte[]{1, 2, 3, 4, 5});
        
        // Serialize to CBOR
        byte[] cbor = credential.toCbor();
        assertNotNull(cbor);
        assertTrue(cbor.length > 0);
        
        // Deserialize from CBOR
        VerifiableCredential deserialized = VerifiableCredential.fromCbor(cbor);
        
        // Verify basic fields
        assertEquals(credential.getId(), deserialized.getId());
        assertEquals(DigitalCredentialFormat.JSON_LD, deserialized.getFormat());
        assertArrayEquals(credential.getEncryptedData(), deserialized.getEncryptedData());
        assertArrayEquals(credential.getHolderBindingKeySeed(), deserialized.getHolderBindingKeySeed());
        assertArrayEquals(credential.getSalt(), deserialized.getSalt());
        
        // Verify metadata
        DigitalCredentialMetadata deserializedMeta = deserialized.getMetadata();
        assertNotNull(deserializedMeta);
        assertEquals(metadata.getIssuerDid(), deserializedMeta.getIssuerDid());
        assertEquals(metadata.getIssuerUrl(), deserializedMeta.getIssuerUrl());
        assertEquals(metadata.getCredentialType(), deserializedMeta.getCredentialType());
        assertEquals(metadata.getIssuedAt(), deserializedMeta.getIssuedAt());
        assertEquals(metadata.getExpiresAt(), deserializedMeta.getExpiresAt());
        
        // Verify JSON-LD specific fields
        assertNotNull(deserializedMeta.getContexts());
        assertEquals(2, deserializedMeta.getContexts().size());
        assertTrue(deserializedMeta.getContexts().contains("https://www.w3.org/2018/credentials/v1"));
        assertTrue(deserializedMeta.getContexts().contains("https://www.w3.org/2018/credentials/examples/v1"));
        
        assertNotNull(deserializedMeta.getTypes());
        assertEquals(2, deserializedMeta.getTypes().size());
        assertTrue(deserializedMeta.getTypes().contains("VerifiableCredential"));
        assertTrue(deserializedMeta.getTypes().contains("UniversityDegreeCredential"));
        
        assertEquals(metadata.getCredentialSubject(), deserializedMeta.getCredentialSubject());
        assertEquals(metadata.getProofType(), deserializedMeta.getProofType());
    }
    
    @Test
    public void testSdJwtCredentialBackwardCompatibility() {
        // Create an SD-JWT credential (existing format)
        VerifiableCredential credential = new VerifiableCredential();
        credential.setFormat(DigitalCredentialFormat.SD_JWT_VC);
        credential.setId("credential-123");
        
        // Set up metadata without JSON-LD fields
        DigitalCredentialMetadata metadata = new DigitalCredentialMetadata();
        metadata.setIssuerDid("did:example:issuer456");
        metadata.setIssuerUrl("https://issuer.example.com");
        metadata.setCredentialType("IdentityCredential");
        metadata.setIssuedAt(Instant.parse("2024-06-01T00:00:00Z"));
        metadata.setDisplayProperty("title", "Identity Credential");
        metadata.setDisplayProperty("backgroundColor", "#0066cc");
        
        credential.setMetadata(metadata);
        credential.generateSeedAndSalt();
        credential.setEncryptedData(new byte[]{10, 20, 30, 40, 50});
        
        // Serialize to CBOR
        byte[] cbor = credential.toCbor();
        assertNotNull(cbor);
        
        // Deserialize from CBOR
        VerifiableCredential deserialized = VerifiableCredential.fromCbor(cbor);
        
        // Verify SD-JWT credential still works
        assertEquals(credential.getId(), deserialized.getId());
        assertEquals(DigitalCredentialFormat.SD_JWT_VC, deserialized.getFormat());
        assertArrayEquals(credential.getEncryptedData(), deserialized.getEncryptedData());
        
        // Verify metadata
        DigitalCredentialMetadata deserializedMeta = deserialized.getMetadata();
        assertNotNull(deserializedMeta);
        assertEquals(metadata.getIssuerDid(), deserializedMeta.getIssuerDid());
        assertEquals(metadata.getIssuerUrl(), deserializedMeta.getIssuerUrl());
        assertEquals(metadata.getCredentialType(), deserializedMeta.getCredentialType());
        assertEquals(metadata.getIssuedAt(), deserializedMeta.getIssuedAt());
        assertEquals("Identity Credential", deserializedMeta.getDisplayProperty("title"));
        assertEquals("#0066cc", deserializedMeta.getDisplayProperty("backgroundColor"));
        
        // Verify JSON-LD fields are null (not set for SD-JWT)
        assertNull(deserializedMeta.getContexts());
        assertNull(deserializedMeta.getTypes());
        assertNull(deserializedMeta.getCredentialSubject());
        assertNull(deserializedMeta.getProofType());
    }
    
    @Test
    public void testJsonLdFormatIsSupported() {
        assertTrue(DigitalCredentialFormat.JSON_LD.isSupported());
    }
    
    @Test
    public void testSerializeJsonLd_ValidCredential() throws JsonLdException {
        // Create a JSON-LD credential with metadata
        VerifiableCredential credential = new VerifiableCredential();
        credential.setFormat(DigitalCredentialFormat.JSON_LD);
        credential.setId("http://example.edu/credentials/9999");
        
        DigitalCredentialMetadata metadata = new DigitalCredentialMetadata();
        metadata.setIssuerDid("did:example:issuer789");
        metadata.setIssuedAt(Instant.parse("2024-03-15T10:30:00Z"));
        metadata.setExpiresAt(Instant.parse("2025-03-15T10:30:00Z"));
        metadata.addContext("https://www.w3.org/2018/credentials/v1");
        metadata.addType("VerifiableCredential");
        
        credential.setMetadata(metadata);
        
        // Serialize to JSON-LD
        String json = credential.serializeJsonLd();
        assertNotNull(json);
        assertTrue(json.contains("@context"));
        assertTrue(json.contains("VerifiableCredential"));
        assertTrue(json.contains("did:example:issuer789"));
    }
    
    @Test
    public void testSerializeJsonLd_WrongFormat() {
        // Create an SD-JWT credential
        VerifiableCredential credential = new VerifiableCredential();
        credential.setFormat(DigitalCredentialFormat.SD_JWT_VC);
        
        // Should throw exception when trying to serialize as JSON-LD
        assertThrows(IllegalStateException.class, () -> {
            credential.serializeJsonLd();
        });
    }
    
    @Test
    public void testSerializeJsonLd_NullMetadata() {
        // Create a JSON-LD credential without metadata
        VerifiableCredential credential = new VerifiableCredential();
        credential.setFormat(DigitalCredentialFormat.JSON_LD);
        credential.setMetadata(null);
        
        // Should throw exception
        assertThrows(JsonLdException.class, () -> {
            credential.serializeJsonLd();
        });
    }
    
    @Test
    public void testMixedCredentialStorage() {
        // Test that we can store both SD-JWT and JSON-LD credentials
        
        // Create SD-JWT credential
        VerifiableCredential sdJwt = new VerifiableCredential();
        sdJwt.setFormat(DigitalCredentialFormat.SD_JWT_VC);
        DigitalCredentialMetadata sdJwtMeta = new DigitalCredentialMetadata();
        sdJwtMeta.setIssuerDid("did:example:sd-jwt-issuer");
        sdJwtMeta.setCredentialType("DriverLicense");
        sdJwt.setMetadata(sdJwtMeta);
        sdJwt.generateSeedAndSalt();
        
        // Create JSON-LD credential
        VerifiableCredential jsonLd = new VerifiableCredential();
        jsonLd.setFormat(DigitalCredentialFormat.JSON_LD);
        DigitalCredentialMetadata jsonLdMeta = new DigitalCredentialMetadata();
        jsonLdMeta.setIssuerDid("did:example:jsonld-issuer");
        jsonLdMeta.setCredentialType("UniversityDegree");
        jsonLdMeta.addContext("https://www.w3.org/2018/credentials/v1");
        jsonLdMeta.addType("VerifiableCredential");
        jsonLd.setMetadata(jsonLdMeta);
        jsonLd.generateSeedAndSalt();
        
        // Serialize both
        byte[] sdJwtCbor = sdJwt.toCbor();
        byte[] jsonLdCbor = jsonLd.toCbor();
        
        // Deserialize both
        VerifiableCredential sdJwtDeserialized = VerifiableCredential.fromCbor(sdJwtCbor);
        VerifiableCredential jsonLdDeserialized = VerifiableCredential.fromCbor(jsonLdCbor);
        
        // Verify formats are preserved
        assertEquals(DigitalCredentialFormat.SD_JWT_VC, sdJwtDeserialized.getFormat());
        assertEquals(DigitalCredentialFormat.JSON_LD, jsonLdDeserialized.getFormat());
        
        // Verify metadata
        assertEquals("did:example:sd-jwt-issuer", sdJwtDeserialized.getMetadata().getIssuerDid());
        assertEquals("did:example:jsonld-issuer", jsonLdDeserialized.getMetadata().getIssuerDid());
        
        // Verify JSON-LD specific fields only exist in JSON-LD credential
        assertNull(sdJwtDeserialized.getMetadata().getContexts());
        assertNotNull(jsonLdDeserialized.getMetadata().getContexts());
    }
}

// Made with Bob