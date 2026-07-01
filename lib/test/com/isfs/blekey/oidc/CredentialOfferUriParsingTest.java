/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.oidc;

import org.junit.Test;
import static org.junit.Assert.*;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Tests for CredentialOffer URI parsing functionality.
 * Targets uncovered lines: 148, 154, 167, 170, 172-174
 */
public class CredentialOfferUriParsingTest {
    
    // Line 148: Invalid scheme check
    @Test(expected = OidcException.class)
    public void testFromUriWithInvalidScheme() throws OidcException {
        String uri = "https://example.com?credential_offer={}";
        CredentialOffer.fromUri(uri);
    }
    
    @Test(expected = OidcException.class)
    public void testFromUriWithHttpScheme() throws OidcException {
        String uri = "http://example.com?credential_offer={}";
        CredentialOffer.fromUri(uri);
    }
    
    // Line 154: Missing/empty query check
    @Test(expected = OidcException.class)
    public void testFromUriWithMissingQuery() throws OidcException {
        String uri = "openid-credential-offer://";
        CredentialOffer.fromUri(uri);
    }
    
    @Test(expected = OidcException.class)
    public void testFromUriWithEmptyQuery() throws OidcException {
        String uri = "openid-credential-offer://?";
        CredentialOffer.fromUri(uri);
    }
    
    // Line 167: credential_offer_uri (by reference) - not supported
    @Test(expected = OidcException.class)
    public void testFromUriWithCredentialOfferUri() throws OidcException {
        String uri = "openid-credential-offer://?credential_offer_uri=https://issuer.example.com/offers/123";
        CredentialOffer.fromUri(uri);
    }
    
    // Line 170: Missing both parameters
    @Test(expected = OidcException.class)
    public void testFromUriWithMissingBothParameters() throws OidcException {
        String uri = "openid-credential-offer://?other_param=value";
        CredentialOffer.fromUri(uri);
    }
    
    @Test(expected = OidcException.class)
    public void testFromUriWithOnlyUnrelatedParams() throws OidcException {
        String uri = "openid-credential-offer://?foo=bar&baz=qux";
        CredentialOffer.fromUri(uri);
    }
    
    // Lines 172-174: Exception handling (malformed URI, etc.)
    @Test(expected = OidcException.class)
    public void testFromUriWithMalformedUri() throws OidcException {
        String uri = "not a valid uri at all ://???";
        CredentialOffer.fromUri(uri);
    }
    
    @Test(expected = OidcException.class)
    public void testFromUriWithInvalidJson() throws OidcException {
        String invalidJson = "{invalid json syntax";
        String encodedOffer = URLEncoder.encode(invalidJson, StandardCharsets.UTF_8);
        String uri = "openid-credential-offer://?credential_offer=" + encodedOffer;
        CredentialOffer.fromUri(uri);
    }
    
    // Valid cases for completeness
    @Test
    public void testFromUriWithValidCredentialOffer() throws OidcException {
        String offerJson = "{" +
            "\"credential_issuer\":\"https://issuer.example.com\"," +
            "\"credentials\":[\"UniversityDegree\"]" +
            "}";
        String encodedOffer = URLEncoder.encode(offerJson, StandardCharsets.UTF_8);
        String uri = "openid-credential-offer://?credential_offer=" + encodedOffer;
        
        CredentialOffer offer = CredentialOffer.fromUri(uri);
        assertNotNull(offer);
        assertEquals("https://issuer.example.com", offer.getCredentialIssuer());
        assertEquals(1, offer.getCredentials().size());
        assertEquals("UniversityDegree", offer.getCredentials().get(0));
    }
    
    @Test
    public void testFromUriWithSpecialCharacters() throws OidcException {
        String offerJson = "{" +
            "\"credential_issuer\":\"https://issuer.example.com/path\"," +
            "\"credentials\":[\"University Degree\"]" +
            "}";
        String encodedOffer = URLEncoder.encode(offerJson, StandardCharsets.UTF_8);
        String uri = "openid-credential-offer://?credential_offer=" + encodedOffer;
        
        CredentialOffer offer = CredentialOffer.fromUri(uri);
        assertNotNull(offer);
        assertEquals("https://issuer.example.com/path", offer.getCredentialIssuer());
        assertEquals(1, offer.getCredentials().size());
        assertEquals("University Degree", offer.getCredentials().get(0));
    }
    
    @Test
    public void testFromUriWithComplexOffer() throws OidcException {
        String offerJson = "{" +
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
        String encodedOffer = URLEncoder.encode(offerJson, StandardCharsets.UTF_8);
        String uri = "openid-credential-offer://?credential_offer=" + encodedOffer;
        
        CredentialOffer offer = CredentialOffer.fromUri(uri);
        assertNotNull(offer);
        assertEquals(2, offer.getCredentials().size());
        assertTrue(offer.hasPreAuthorizedCodeGrant());
        assertTrue(offer.isUserPinRequired());
        assertEquals(Long.valueOf(600), offer.getExpiresIn());
    }
    
    @Test
    public void testFromUriWithAdditionalParameters() throws OidcException {
        String offerJson = "{" +
            "\"credential_issuer\":\"https://issuer.example.com\"," +
            "\"credentials\":[\"UniversityDegree\"]" +
            "}";
        String encodedOffer = URLEncoder.encode(offerJson, StandardCharsets.UTF_8);
        // Additional parameters should be ignored
        String uri = "openid-credential-offer://?credential_offer=" + encodedOffer + 
                     "&other_param=value&another=123";
        
        CredentialOffer offer = CredentialOffer.fromUri(uri);
        assertNotNull(offer);
    }
}

// Made with Bob