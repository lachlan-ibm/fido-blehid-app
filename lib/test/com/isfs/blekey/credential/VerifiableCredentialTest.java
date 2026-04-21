/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.credential;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.time.Instant;

public class VerifiableCredentialTest {
    
    @Test
    public void testCborSerializationDeserialization() {
        DigitalCredentialMetadata metadata = new DigitalCredentialMetadata();
        metadata.setIssuerDid("did:example:issuer123");
        metadata.setIssuerUrl("https://issuer.example.com");
        metadata.setCredentialType("VerifiableCredential");
        metadata.setIssuedAt(Instant.now());
        metadata.setExpiresAt(Instant.now().plusSeconds(86400));
        metadata.setStatusListUrl("https://issuer.example.com/status");
        metadata.setDisplayProperty("name", "Test Credential");
        
        VerifiableCredential original = new VerifiableCredential(
            DigitalCredentialFormat.SD_JWT_VC,
            metadata,
            new byte[]{1, 2, 3, 4, 5}
        );
        
        byte[] cbor = original.toCbor();
        assertNotNull(cbor);
        
        VerifiableCredential deserialized = VerifiableCredential.fromCbor(cbor);
        
        assertEquals(original.getId(), deserialized.getId());
        assertEquals(original.getFormat(), deserialized.getFormat());
        assertEquals(original.getMetadata().getIssuerDid(), deserialized.getMetadata().getIssuerDid());
        assertEquals(original.getMetadata().getCredentialType(), deserialized.getMetadata().getCredentialType());
        assertArrayEquals(original.getEncryptedData(), deserialized.getEncryptedData());
        assertArrayEquals(original.getHolderBindingKeySeed(), deserialized.getHolderBindingKeySeed());
        assertArrayEquals(original.getSalt(), deserialized.getSalt());
    }
    
    @Test
    public void testInvalidCborThrowsException() {
        byte[] invalidCbor = new byte[]{1, 2, 3};
        
        assertThrows(IllegalArgumentException.class, () -> {
            VerifiableCredential.fromCbor(invalidCbor);
        });
    }
    
    @Test
    public void testEmptyCredential() {
        VerifiableCredential credential = new VerifiableCredential();
        
        assertNotNull(credential.getId());
        assertEquals(DigitalCredentialFormat.SD_JWT_VC, credential.getFormat());
        assertNotNull(credential.getMetadata());
    }
}

// Made with Bob
