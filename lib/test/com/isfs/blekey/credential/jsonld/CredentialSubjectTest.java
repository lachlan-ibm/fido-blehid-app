/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.jsonld;

import com.google.gson.JsonObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link CredentialSubject}.
 */
class CredentialSubjectTest {
    
    private CredentialSubject subject;
    
    @BeforeEach
    void setUp() {
        subject = new CredentialSubject();
    }
    
    @Test
    void testEmptySubject() {
        assertNull(subject.getId());
        assertTrue(subject.isEmpty());
        assertEquals(0, subject.size());
    }
    
    @Test
    void testConstructorWithId() {
        CredentialSubject sub = new CredentialSubject("did:example:123");
        
        assertEquals("did:example:123", sub.getId());
        assertTrue(sub.isEmpty()); // No claims yet
    }
    
    @Test
    void testSetId() {
        subject.setId("did:example:123");
        assertEquals("did:example:123", subject.getId());
    }
    
    @Test
    void testAddStringClaim() {
        subject.addClaim("name", "Alice Smith");
        
        assertFalse(subject.isEmpty());
        assertEquals(1, subject.size());
        assertEquals("Alice Smith", subject.getClaim("name"));
        assertEquals("Alice Smith", subject.getClaimAsString("name"));
    }
    
    @Test
    void testAddNumberClaim() {
        subject.addClaim("age", 30);
        
        assertEquals(30, subject.getClaim("age"));
        assertEquals(30, subject.getClaimAsInteger("age"));
    }
    
    @Test
    void testAddBooleanClaim() {
        subject.addClaim("verified", true);
        
        assertEquals(true, subject.getClaim("verified"));
        assertEquals(true, subject.getClaimAsBoolean("verified"));
    }
    
    @Test
    void testAddMultipleClaims() {
        subject.addClaim("name", "Alice Smith");
        subject.addClaim("email", "alice@example.com");
        subject.addClaim("age", 30);
        
        assertEquals(3, subject.size());
        assertTrue(subject.hasClaim("name"));
        assertTrue(subject.hasClaim("email"));
        assertTrue(subject.hasClaim("age"));
    }
    
    @Test
    void testAddNullClaimName() {
        assertThrows(IllegalArgumentException.class, () -> {
            subject.addClaim(null, "value");
        });
    }
    
    @Test
    void testAddEmptyClaimName() {
        assertThrows(IllegalArgumentException.class, () -> {
            subject.addClaim("", "value");
        });
    }
    
    @Test
    void testAddNullClaimValue() {
        subject.addClaim("name", null);
        assertFalse(subject.hasClaim("name"));
    }
    
    @Test
    void testGetNonExistentClaim() {
        assertNull(subject.getClaim("nonexistent"));
        assertNull(subject.getClaimAsString("nonexistent"));
        assertNull(subject.getClaimAsInteger("nonexistent"));
        assertNull(subject.getClaimAsBoolean("nonexistent"));
    }
    
    @Test
    void testGetClaimAsWrongType() {
        subject.addClaim("name", "Alice");
        
        assertNull(subject.getClaimAsInteger("name"));
        assertNull(subject.getClaimAsBoolean("name"));
    }
    
    @Test
    void testRemoveClaim() {
        subject.addClaim("name", "Alice");
        subject.addClaim("email", "alice@example.com");
        
        assertEquals(2, subject.size());
        
        Object removed = subject.removeClaim("name");
        assertEquals("Alice", removed);
        assertEquals(1, subject.size());
        assertFalse(subject.hasClaim("name"));
        assertTrue(subject.hasClaim("email"));
    }
    
    @Test
    void testRemoveNonExistentClaim() {
        assertNull(subject.removeClaim("nonexistent"));
    }
    
    @Test
    void testGetClaimNames() {
        subject.addClaim("name", "Alice");
        subject.addClaim("email", "alice@example.com");
        subject.addClaim("age", 30);
        
        assertEquals(3, subject.getClaimNames().size());
        assertTrue(subject.getClaimNames().contains("name"));
        assertTrue(subject.getClaimNames().contains("email"));
        assertTrue(subject.getClaimNames().contains("age"));
    }
    
    @Test
    void testGetClaims() {
        subject.addClaim("name", "Alice");
        subject.addClaim("email", "alice@example.com");
        
        var claims = subject.getClaims();
        assertEquals(2, claims.size());
        assertEquals("Alice", claims.get("name"));
        assertEquals("alice@example.com", claims.get("email"));
    }
    
    @Test
    void testToJson() {
        subject.setId("did:example:123");
        subject.addClaim("name", "Alice Smith");
        subject.addClaim("email", "alice@example.com");
        subject.addClaim("age", 30);
        subject.addClaim("verified", true);
        
        JsonObject json = subject.toJson();
        
        assertEquals("did:example:123", json.get("id").getAsString());
        assertEquals("Alice Smith", json.get("name").getAsString());
        assertEquals("alice@example.com", json.get("email").getAsString());
        assertEquals(30, json.get("age").getAsInt());
        assertTrue(json.get("verified").getAsBoolean());
    }
    
    @Test
    void testToJsonWithoutId() {
        subject.addClaim("name", "Alice");
        
        JsonObject json = subject.toJson();
        
        assertFalse(json.has("id"));
        assertEquals("Alice", json.get("name").getAsString());
    }
    
    @Test
    void testToJsonEmpty() {
        JsonObject json = subject.toJson();
        
        assertFalse(json.has("id"));
        assertEquals(0, json.size());
    }
    
    @Test
    void testFromJson() throws JsonLdException {
        JsonObject json = new JsonObject();
        json.addProperty("id", "did:example:123");
        json.addProperty("name", "Alice Smith");
        json.addProperty("email", "alice@example.com");
        json.addProperty("age", 30);
        json.addProperty("verified", true);
        
        CredentialSubject sub = CredentialSubject.fromJson(json);
        
        assertEquals("did:example:123", sub.getId());
        assertEquals("Alice Smith", sub.getClaimAsString("name"));
        assertEquals("alice@example.com", sub.getClaimAsString("email"));
        assertEquals(30, sub.getClaimAsInteger("age"));
        assertEquals(true, sub.getClaimAsBoolean("verified"));
    }
    
    @Test
    void testFromJsonWithoutId() throws JsonLdException {
        JsonObject json = new JsonObject();
        json.addProperty("name", "Alice");
        
        CredentialSubject sub = CredentialSubject.fromJson(json);
        
        assertNull(sub.getId());
        assertEquals("Alice", sub.getClaimAsString("name"));
    }
    
    @Test
    void testFromJsonNull() {
        assertThrows(JsonLdException.class, () -> {
            CredentialSubject.fromJson(null);
        });
    }
    
    @Test
    void testRoundTrip() throws JsonLdException {
        subject.setId("did:example:123");
        subject.addClaim("name", "Alice Smith");
        subject.addClaim("email", "alice@example.com");
        subject.addClaim("age", 30);
        subject.addClaim("verified", true);
        
        JsonObject json = subject.toJson();
        CredentialSubject restored = CredentialSubject.fromJson(json);
        
        assertEquals(subject, restored);
    }
    
    @Test
    void testEquals() {
        CredentialSubject sub1 = new CredentialSubject("did:example:123");
        sub1.addClaim("name", "Alice");
        sub1.addClaim("email", "alice@example.com");
        
        CredentialSubject sub2 = new CredentialSubject("did:example:123");
        sub2.addClaim("name", "Alice");
        sub2.addClaim("email", "alice@example.com");
        
        assertEquals(sub1, sub2);
        assertEquals(sub1.hashCode(), sub2.hashCode());
    }
    
    @Test
    void testNotEqualsDifferentId() {
        CredentialSubject sub1 = new CredentialSubject("did:example:123");
        sub1.addClaim("name", "Alice");
        
        CredentialSubject sub2 = new CredentialSubject("did:example:456");
        sub2.addClaim("name", "Alice");
        
        assertNotEquals(sub1, sub2);
    }
    
    @Test
    void testNotEqualsDifferentClaims() {
        CredentialSubject sub1 = new CredentialSubject("did:example:123");
        sub1.addClaim("name", "Alice");
        
        CredentialSubject sub2 = new CredentialSubject("did:example:123");
        sub2.addClaim("name", "Bob");
        
        assertNotEquals(sub1, sub2);
    }
    
    @Test
    void testToString() {
        subject.setId("did:example:123");
        subject.addClaim("name", "Alice");
        subject.addClaim("email", "alice@example.com");
        
        String str = subject.toString();
        assertTrue(str.contains("CredentialSubject"));
        assertTrue(str.contains("did:example:123"));
        assertTrue(str.contains("name"));
        assertTrue(str.contains("email"));
    }
    
    @Test
    void testMethodChaining() {
        CredentialSubject sub = new CredentialSubject()
            .setId("did:example:123")
            .addClaim("name", "Alice")
            .addClaim("email", "alice@example.com")
            .addClaim("age", 30);
        
        assertEquals("did:example:123", sub.getId());
        assertEquals(3, sub.size());
    }
    
    @Test
    void testNumberConversion() {
        subject.addClaim("count", 42L);
        
        assertEquals(42, subject.getClaimAsInteger("count"));
    }
    
    @Test
    void testDoubleValue() {
        subject.addClaim("score", 95.5);
        
        assertEquals(95.5, subject.getClaim("score"));
        assertEquals(95, subject.getClaimAsInteger("score")); // Truncates
    }
}

// Made with Bob