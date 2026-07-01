/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.oidc;

import org.junit.Test;
import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Tests for CredentialOffer getter methods.
 * Targets uncovered lines: 220, 228, 293
 */
public class CredentialOfferGetterTest {
    
    @Test
    public void testGetGrants() throws OidcException {
        Map<String, Object> offer = createOfferWithGrants();
        CredentialOffer credOffer = new CredentialOffer(offer);
        
        Map<String, Object> grants = credOffer.getGrants();
        assertNotNull(grants);
        assertFalse(grants.isEmpty());
        assertTrue(grants.containsKey("urn:ietf:params:oauth:grant-type:pre-authorized_code"));
        
        // Verify it returns a copy
        grants.clear();
        assertFalse("Should return a copy", credOffer.getGrants().isEmpty());
    }
    
    @Test
    public void testGetGrantsWhenEmpty() throws OidcException {
        Map<String, Object> offer = createBasicOffer();
        offer.remove("grants");
        CredentialOffer credOffer = new CredentialOffer(offer);
        
        Map<String, Object> grants = credOffer.getGrants();
        assertNotNull(grants);
        assertTrue(grants.isEmpty());
    }
    
    @Test
    public void testGetRawOffer() throws OidcException {
        Map<String, Object> offer = createBasicOffer();
        CredentialOffer credOffer = new CredentialOffer(offer);
        
        Map<String, Object> rawOffer = credOffer.getRawOffer();
        assertNotNull(rawOffer);
        assertEquals(offer.get("credential_issuer"), rawOffer.get("credential_issuer"));
    }
    
    @Test
    public void testGetReceivedAtMillis() throws OidcException {
        long timestamp = System.currentTimeMillis();
        Map<String, Object> offer = createBasicOffer();
        CredentialOffer credOffer = new CredentialOffer(offer, timestamp);
        
        assertEquals(timestamp, credOffer.getReceivedAtMillis());
    }
    
    @Test
    public void testGetRemainingSecondsNoArg() throws OidcException {
        Map<String, Object> offer = createBasicOffer();
        offer.put("expires_in", 300);
        CredentialOffer credOffer = new CredentialOffer(offer);
        
        Long remaining = credOffer.getRemainingSeconds();
        assertNotNull(remaining);
        assertTrue("Should be close to 300 seconds", remaining >= 299 && remaining <= 300);
    }
    
    @Test
    public void testGetRemainingSecondsWhenDefaultExpiration() throws OidcException {
        Map<String, Object> offer = createBasicOffer();
        // Don't set expires_in, should use default
        CredentialOffer credOffer = new CredentialOffer(offer);
        
        Long remaining = credOffer.getRemainingSeconds();
        assertNotNull(remaining);
        assertTrue("Should be close to default 300 seconds", remaining >= 299 && remaining <= 300);
    }
    
    private Map<String, Object> createBasicOffer() {
        Map<String, Object> offer = new HashMap<>();
        offer.put("credential_issuer", "https://issuer.example.com");
        offer.put("credentials", List.of("UniversityDegree"));
        return offer;
    }
    
    private Map<String, Object> createOfferWithGrants() {
        Map<String, Object> offer = createBasicOffer();
        
        Map<String, Object> grants = new HashMap<>();
        Map<String, Object> preAuthGrant = new HashMap<>();
        preAuthGrant.put("pre-authorized_code", "test-code");
        preAuthGrant.put("user_pin_required", false);
        grants.put("urn:ietf:params:oauth:grant-type:pre-authorized_code", preAuthGrant);
        offer.put("grants", grants);
        
        return offer;
    }
}

// Made with Bob