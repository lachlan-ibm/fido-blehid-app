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
 * Tests for CredentialOffer grant handling edge cases.
 * Targets uncovered lines: 245, 249, 255
 */
public class CredentialOfferGrantTest {
    
    @Test
    public void testGetPreAuthorizedCodeWhenNoGrant() throws OidcException {
        Map<String, Object> offer = createBasicOffer();
        // No grants at all
        CredentialOffer credOffer = new CredentialOffer(offer);
        
        assertFalse(credOffer.hasPreAuthorizedCodeGrant());
        assertNull("Should return null when no grant", credOffer.getPreAuthorizedCode());
    }
    
    @Test
    public void testGetPreAuthorizedCodeWhenGrantIsNotMap() throws OidcException {
        Map<String, Object> offer = createBasicOffer();
        Map<String, Object> grants = new HashMap<>();
        grants.put("urn:ietf:params:oauth:grant-type:pre-authorized_code", "not-a-map");
        offer.put("grants", grants);
        
        CredentialOffer credOffer = new CredentialOffer(offer);
        assertTrue(credOffer.hasPreAuthorizedCodeGrant());
        assertNull("Should return null when grant is not a Map", credOffer.getPreAuthorizedCode());
    }
    
    @Test
    public void testGetPreAuthorizedCodeWhenCodeMissing() throws OidcException {
        Map<String, Object> offer = createBasicOffer();
        Map<String, Object> grants = new HashMap<>();
        Map<String, Object> preAuthGrant = new HashMap<>();
        preAuthGrant.put("user_pin_required", true);
        // Missing "pre-authorized_code" key
        grants.put("urn:ietf:params:oauth:grant-type:pre-authorized_code", preAuthGrant);
        offer.put("grants", grants);
        
        CredentialOffer credOffer = new CredentialOffer(offer);
        assertNull("Should return null when code is missing", credOffer.getPreAuthorizedCode());
    }
    
    @Test
    public void testGetPreAuthorizedCodeWhenValid() throws OidcException {
        Map<String, Object> offer = createBasicOffer();
        Map<String, Object> grants = new HashMap<>();
        Map<String, Object> preAuthGrant = new HashMap<>();
        preAuthGrant.put("pre-authorized_code", "code123");
        grants.put("urn:ietf:params:oauth:grant-type:pre-authorized_code", preAuthGrant);
        offer.put("grants", grants);
        
        CredentialOffer credOffer = new CredentialOffer(offer);
        assertEquals("code123", credOffer.getPreAuthorizedCode());
    }
    
    @Test
    public void testIsUserPinRequiredWhenGrantIsNotMap() throws OidcException {
        Map<String, Object> offer = createBasicOffer();
        Map<String, Object> grants = new HashMap<>();
        grants.put("urn:ietf:params:oauth:grant-type:pre-authorized_code", "not-a-map");
        offer.put("grants", grants);
        
        CredentialOffer credOffer = new CredentialOffer(offer);
        assertFalse("Should return false when grant is not a Map", credOffer.isUserPinRequired());
    }
    
    @Test
    public void testIsUserPinRequiredWhenNotBoolean() throws OidcException {
        Map<String, Object> offer = createBasicOffer();
        Map<String, Object> grants = new HashMap<>();
        Map<String, Object> preAuthGrant = new HashMap<>();
        preAuthGrant.put("pre-authorized_code", "code123");
        preAuthGrant.put("user_pin_required", "true"); // String instead of Boolean
        grants.put("urn:ietf:params:oauth:grant-type:pre-authorized_code", preAuthGrant);
        offer.put("grants", grants);
        
        CredentialOffer credOffer = new CredentialOffer(offer);
        assertFalse("Should return false when not a Boolean", credOffer.isUserPinRequired());
    }
    
    @Test
    public void testIsUserPinRequiredWhenMissing() throws OidcException {
        Map<String, Object> offer = createBasicOffer();
        Map<String, Object> grants = new HashMap<>();
        Map<String, Object> preAuthGrant = new HashMap<>();
        preAuthGrant.put("pre-authorized_code", "code123");
        // Missing "user_pin_required" key
        grants.put("urn:ietf:params:oauth:grant-type:pre-authorized_code", preAuthGrant);
        offer.put("grants", grants);
        
        CredentialOffer credOffer = new CredentialOffer(offer);
        assertFalse("Should return false when missing", credOffer.isUserPinRequired());
    }
    
    @Test
    public void testIsUserPinRequiredWhenTrue() throws OidcException {
        Map<String, Object> offer = createBasicOffer();
        Map<String, Object> grants = new HashMap<>();
        Map<String, Object> preAuthGrant = new HashMap<>();
        preAuthGrant.put("pre-authorized_code", "code123");
        preAuthGrant.put("user_pin_required", true);
        grants.put("urn:ietf:params:oauth:grant-type:pre-authorized_code", preAuthGrant);
        offer.put("grants", grants);
        
        CredentialOffer credOffer = new CredentialOffer(offer);
        assertTrue("Should return true", credOffer.isUserPinRequired());
    }
    
    @Test
    public void testIsUserPinRequiredWhenFalse() throws OidcException {
        Map<String, Object> offer = createBasicOffer();
        Map<String, Object> grants = new HashMap<>();
        Map<String, Object> preAuthGrant = new HashMap<>();
        preAuthGrant.put("pre-authorized_code", "code123");
        preAuthGrant.put("user_pin_required", false);
        grants.put("urn:ietf:params:oauth:grant-type:pre-authorized_code", preAuthGrant);
        offer.put("grants", grants);
        
        CredentialOffer credOffer = new CredentialOffer(offer);
        assertFalse("Should return false", credOffer.isUserPinRequired());
    }
    
    private Map<String, Object> createBasicOffer() {
        Map<String, Object> offer = new HashMap<>();
        offer.put("credential_issuer", "https://issuer.example.com");
        offer.put("credentials", List.of("UniversityDegree"));
        return offer;
    }
}

// Made with Bob