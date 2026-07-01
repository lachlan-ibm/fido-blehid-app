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
 * Tests for CredentialOffer constructor validation and error handling.
 * Targets uncovered lines: 72, 81, 87, 97-105, 110, 120
 */
public class CredentialOfferConstructorTest {
    
    // Line 72: null offer check
    @Test(expected = OidcException.class)
    public void testConstructorWithNullOffer() throws OidcException {
        new CredentialOffer(null);
    }
    
    // Line 81: null/empty credential_issuer check
    @Test(expected = OidcException.class)
    public void testConstructorWithNullCredentialIssuer() throws OidcException {
        Map<String, Object> offer = new HashMap<>();
        offer.put("credentials", List.of("UniversityDegree"));
        new CredentialOffer(offer);
    }
    
    @Test(expected = OidcException.class)
    public void testConstructorWithEmptyCredentialIssuer() throws OidcException {
        Map<String, Object> offer = new HashMap<>();
        offer.put("credential_issuer", "");
        offer.put("credentials", List.of("UniversityDegree"));
        new CredentialOffer(offer);
    }
    
    // Line 87: null credentials check
    @Test(expected = OidcException.class)
    public void testConstructorWithNullCredentials() throws OidcException {
        Map<String, Object> offer = new HashMap<>();
        offer.put("credential_issuer", "https://issuer.example.com");
        new CredentialOffer(offer);
    }
    
    // Line 110: empty credentials list check
    @Test(expected = OidcException.class)
    public void testConstructorWithEmptyCredentials() throws OidcException {
        Map<String, Object> offer = new HashMap<>();
        offer.put("credential_issuer", "https://issuer.example.com");
        offer.put("credentials", List.of());
        new CredentialOffer(offer);
    }
    
    // Lines 97-105: credential as Map (format extraction)
    @Test
    public void testConstructorWithCredentialMapObjects() throws OidcException {
        Map<String, Object> offer = new HashMap<>();
        offer.put("credential_issuer", "https://issuer.example.com");
        
        Map<String, Object> credConfig = new HashMap<>();
        credConfig.put("format", "jwt_vc_json");
        credConfig.put("types", List.of("VerifiableCredential", "UniversityDegree"));
        
        offer.put("credentials", List.of(credConfig));
        
        CredentialOffer credOffer = new CredentialOffer(offer);
        assertEquals(1, credOffer.getCredentials().size());
        assertEquals("jwt_vc_json", credOffer.getCredentials().get(0));
    }
    
    @Test
    public void testConstructorWithCredentialMapWithoutFormat() throws OidcException {
        Map<String, Object> offer = new HashMap<>();
        offer.put("credential_issuer", "https://issuer.example.com");
        
        Map<String, Object> credConfig = new HashMap<>();
        credConfig.put("types", List.of("VerifiableCredential"));
        // Missing "format" key - should be skipped
        
        // Add a valid credential so we don't hit the empty credentials error
        offer.put("credentials", List.of("UniversityDegree", credConfig));
        
        CredentialOffer credOffer = new CredentialOffer(offer);
        assertEquals(1, credOffer.getCredentials().size());
        assertEquals("UniversityDegree", credOffer.getCredentials().get(0));
    }
    
    // Line 97: credential that is neither String nor Map (else branch)
    @Test
    public void testConstructorWithInvalidCredentialType() throws OidcException {
        Map<String, Object> offer = new HashMap<>();
        offer.put("credential_issuer", "https://issuer.example.com");
        // Mix valid and invalid types - use ArrayList to allow mixed types
        List<Object> credList = new java.util.ArrayList<>();
        credList.add("UniversityDegree");
        credList.add(123);
        credList.add(null);
        offer.put("credentials", credList);
        
        CredentialOffer credOffer = new CredentialOffer(offer);
        assertEquals(1, credOffer.getCredentials().size());
        assertEquals("UniversityDegree", credOffer.getCredentials().get(0));
    }
    
    @Test(expected = OidcException.class)
    public void testConstructorWithOnlyInvalidCredentials() throws OidcException {
        Map<String, Object> offer = new HashMap<>();
        offer.put("credential_issuer", "https://issuer.example.com");
        // All invalid types - use ArrayList to allow mixed types
        List<Object> credList = new java.util.ArrayList<>();
        credList.add(123);
        credList.add(456);
        credList.add(null);
        offer.put("credentials", credList);
        
        // Should throw because no valid credentials remain
        new CredentialOffer(offer);
    }
    
    // Line 120: grants not a Map (else branch)
    @Test
    public void testConstructorWithNonMapGrants() throws OidcException {
        Map<String, Object> offer = new HashMap<>();
        offer.put("credential_issuer", "https://issuer.example.com");
        offer.put("credentials", List.of("UniversityDegree"));
        offer.put("grants", "invalid"); // Not a Map
        
        CredentialOffer credOffer = new CredentialOffer(offer);
        assertTrue("Should default to empty grants", credOffer.getGrants().isEmpty());
    }
    
    @Test
    public void testConstructorWithNullGrants() throws OidcException {
        Map<String, Object> offer = new HashMap<>();
        offer.put("credential_issuer", "https://issuer.example.com");
        offer.put("credentials", List.of("UniversityDegree"));
        offer.put("grants", null);
        
        CredentialOffer credOffer = new CredentialOffer(offer);
        assertTrue("Should default to empty grants", credOffer.getGrants().isEmpty());
    }
    
    // Test with valid grants for completeness
    @Test
    public void testConstructorWithValidGrants() throws OidcException {
        Map<String, Object> offer = new HashMap<>();
        offer.put("credential_issuer", "https://issuer.example.com");
        offer.put("credentials", List.of("UniversityDegree"));
        
        Map<String, Object> grants = new HashMap<>();
        Map<String, Object> preAuthGrant = new HashMap<>();
        preAuthGrant.put("pre-authorized_code", "code123");
        grants.put("urn:ietf:params:oauth:grant-type:pre-authorized_code", preAuthGrant);
        offer.put("grants", grants);
        
        CredentialOffer credOffer = new CredentialOffer(offer);
        assertFalse("Should have grants", credOffer.getGrants().isEmpty());
    }
    
    // Test expires_in variations
    @Test
    public void testConstructorWithNonNumberExpiresIn() throws OidcException {
        Map<String, Object> offer = new HashMap<>();
        offer.put("credential_issuer", "https://issuer.example.com");
        offer.put("credentials", List.of("UniversityDegree"));
        offer.put("expires_in", "300"); // String instead of Number
        
        CredentialOffer credOffer = new CredentialOffer(offer);
        assertEquals("Should use default expiration", Long.valueOf(300), credOffer.getExpiresIn());
    }
    
    @Test
    public void testConstructorWithIntegerExpiresIn() throws OidcException {
        Map<String, Object> offer = new HashMap<>();
        offer.put("credential_issuer", "https://issuer.example.com");
        offer.put("credentials", List.of("UniversityDegree"));
        offer.put("expires_in", 600);
        
        CredentialOffer credOffer = new CredentialOffer(offer);
        assertEquals(Long.valueOf(600), credOffer.getExpiresIn());
    }
    
    @Test
    public void testConstructorWithTimestamp() throws OidcException {
        Map<String, Object> offer = new HashMap<>();
        offer.put("credential_issuer", "https://issuer.example.com");
        offer.put("credentials", List.of("UniversityDegree"));
        
        long timestamp = 1234567890000L;
        CredentialOffer credOffer = new CredentialOffer(offer, timestamp);
        
        assertEquals(timestamp, credOffer.getReceivedAtMillis());
    }
}

// Made with Bob