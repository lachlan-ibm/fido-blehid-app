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
 * Tests for CredentialOffer expiration functionality.
 */
public class CredentialOfferExpirationTest {
    
    @Test
    public void testOfferWithExpiresIn() throws OidcException {
        Map<String, Object> offerMap = createBasicOffer();
        offerMap.put("expires_in", 300); // 5 minutes
        
        CredentialOffer offer = new CredentialOffer(offerMap);
        
        assertNotNull(offer.getExpiresIn());
        assertEquals(Long.valueOf(300), offer.getExpiresIn());
        assertFalse("Offer should not be expired immediately", offer.isExpired());
    }
    
    @Test
    public void testOfferWithoutExpiresIn() throws OidcException {
        Map<String, Object> offerMap = createBasicOffer();
        
        CredentialOffer offer = new CredentialOffer(offerMap);
        
        assertNotNull("Should have default expiration", offer.getExpiresIn());
        assertEquals("Should use default 300 seconds", Long.valueOf(300), offer.getExpiresIn());
    }
    
    @Test
    public void testOfferExpiration() throws OidcException {
        Map<String, Object> offerMap = createBasicOffer();
        offerMap.put("expires_in", 1); // 1 second
        
        long now = System.currentTimeMillis();
        CredentialOffer offer = new CredentialOffer(offerMap, now);
        
        assertFalse("Should not be expired at creation", offer.isExpired(now));
        assertFalse("Should not be expired after 500ms", offer.isExpired(now + 500));
        assertTrue("Should be expired after 1.5 seconds", offer.isExpired(now + 1500));
    }
    
    @Test
    public void testRemainingSeconds() throws OidcException {
        Map<String, Object> offerMap = createBasicOffer();
        offerMap.put("expires_in", 300); // 5 minutes
        
        long now = System.currentTimeMillis();
        CredentialOffer offer = new CredentialOffer(offerMap, now);
        
        Long remaining = offer.getRemainingSeconds(now);
        assertNotNull(remaining);
        assertEquals(Long.valueOf(300), remaining);
        
        remaining = offer.getRemainingSeconds(now + 60000); // 1 minute later
        assertNotNull(remaining);
        assertEquals(Long.valueOf(240), remaining);
        
        remaining = offer.getRemainingSeconds(now + 300000); // 5 minutes later
        assertNotNull(remaining);
        assertEquals(Long.valueOf(0), remaining);
        
        remaining = offer.getRemainingSeconds(now + 400000); // 6.67 minutes later
        assertNotNull(remaining);
        assertEquals(Long.valueOf(0), remaining);
    }
    
    @Test
    public void testExpirationTimeMillis() throws OidcException {
        Map<String, Object> offerMap = createBasicOffer();
        offerMap.put("expires_in", 300);
        
        long now = System.currentTimeMillis();
        CredentialOffer offer = new CredentialOffer(offerMap, now);
        
        Long expirationTime = offer.getExpirationTimeMillis();
        assertNotNull(expirationTime);
        assertEquals(Long.valueOf(now + 300000), expirationTime);
    }
    
    @Test
    public void testOfferToString() throws OidcException {
        Map<String, Object> offerMap = createBasicOffer();
        offerMap.put("expires_in", 300);
        
        CredentialOffer offer = new CredentialOffer(offerMap);
        String str = offer.toString();
        
        assertTrue("Should contain expiration info", str.contains("expiresIn=300s"));
        assertTrue("Should contain expiration status", str.contains("isExpired="));
    }
    
    @Test
    public void testOfferFromUri() throws OidcException {
        String offerJson = "{" +
            "\"credential_issuer\":\"https://issuer.example.com\"," +
            "\"credentials\":[\"UniversityDegree\"]," +
            "\"expires_in\":180" +
            "}";
        
        String encodedOffer = java.net.URLEncoder.encode(offerJson, java.nio.charset.StandardCharsets.UTF_8);
        String uri = "openid-credential-offer://?credential_offer=" + encodedOffer;
        
        CredentialOffer offer = CredentialOffer.fromUri(uri);
        
        assertNotNull(offer);
        assertEquals(Long.valueOf(180), offer.getExpiresIn());
        assertFalse(offer.isExpired());
    }
    
    private Map<String, Object> createBasicOffer() {
        Map<String, Object> offer = new HashMap<>();
        offer.put("credential_issuer", "https://issuer.example.com");
        offer.put("credentials", List.of("UniversityDegree"));
        
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