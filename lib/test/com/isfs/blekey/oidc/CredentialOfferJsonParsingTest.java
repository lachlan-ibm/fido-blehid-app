/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.oidc;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Tests for CredentialOffer JSON parsing functionality.
 * Targets uncovered lines: 190, 193-195
 */
public class CredentialOfferJsonParsingTest {
    
    @Test(expected = OidcException.class)
    public void testFromJsonWithNull() throws OidcException {
        CredentialOffer.fromJson(null);
    }
    
    @Test(expected = OidcException.class)
    public void testFromJsonWithInvalidSyntax() throws OidcException {
        String invalidJson = "{invalid json syntax";
        CredentialOffer.fromJson(invalidJson);
    }
    
    @Test(expected = OidcException.class)
    public void testFromJsonWithEmptyString() throws OidcException {
        CredentialOffer.fromJson("");
    }
    
    @Test
    public void testFromJsonWithValidOffer() throws OidcException {
        String json = "{" +
            "\"credential_issuer\":\"https://issuer.example.com\"," +
            "\"credentials\":[\"UniversityDegree\"]" +
            "}";
        
        CredentialOffer offer = CredentialOffer.fromJson(json);
        assertNotNull(offer);
        assertEquals("https://issuer.example.com", offer.getCredentialIssuer());
    }
    
    @Test
    public void testFromJsonWithComplexOffer() throws OidcException {
        String json = "{" +
            "\"credential_issuer\":\"https://issuer.example.com\"," +
            "\"credentials\":[" +
            "  \"UniversityDegree\"," +
            "  {\"format\":\"jwt_vc_json\",\"types\":[\"VerifiableCredential\"]}" +
            "]," +
            "\"grants\":{" +
            "  \"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{" +
            "    \"pre-authorized_code\":\"code123\"," +
            "    \"user_pin_required\":true" +
            "  }" +
            "}," +
            "\"expires_in\":600" +
            "}";
        
        CredentialOffer offer = CredentialOffer.fromJson(json);
        assertNotNull(offer);
        assertEquals(2, offer.getCredentials().size());
        assertTrue(offer.hasPreAuthorizedCodeGrant());
        assertTrue(offer.isUserPinRequired());
        assertEquals(Long.valueOf(600), offer.getExpiresIn());
    }
    
    @Test(expected = OidcException.class)
    public void testFromJsonWithMissingCredentialIssuer() throws OidcException {
        String json = "{\"credentials\":[\"UniversityDegree\"]}";
        CredentialOffer.fromJson(json);
    }
    
    @Test(expected = OidcException.class)
    public void testFromJsonWithMissingCredentials() throws OidcException {
        String json = "{\"credential_issuer\":\"https://issuer.example.com\"}";
        CredentialOffer.fromJson(json);
    }
}

// Made with Bob