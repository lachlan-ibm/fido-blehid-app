/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.oidc;

import com.isfs.blekey.credential.DigitalCredentialFormat;
import com.isfs.blekey.util.http.HttpClient;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for JSON-LD format detection in Oidc4VciClient.
 * Tests Phase 2B.1: JSON-LD OIDC4VCI - Format Detection
 */
@DisplayName("OIDC4VCI Client Format Detection Tests")
class Oidc4VciClientFormatDetectionTest {
    
    private Oidc4VciClient client;
    private Method detectFormatMethod;
    private Method mapFormatStringMethod;
    
    @BeforeEach
    void setUp() throws Exception {
        client = new Oidc4VciClient();
        
        // Access private methods via reflection for testing
        detectFormatMethod = Oidc4VciClient.class.getDeclaredMethod(
            "detectCredentialFormat", CredentialOffer.class, IssuerMetadata.class);
        detectFormatMethod.setAccessible(true);
        
        mapFormatStringMethod = Oidc4VciClient.class.getDeclaredMethod(
            "mapFormatString", String.class);
        mapFormatStringMethod.setAccessible(true);
    }
    
    @Test
    @DisplayName("Should detect ldp_vc format as JSON_LD")
    void testDetectLdpVcFormat() throws Exception {
        // Create offer with ldp_vc format
        Map<String, Object> offerMap = createOfferMap("UniversityDegree");
        CredentialOffer offer = new CredentialOffer(offerMap);
        
        // Create metadata with ldp_vc format
        Map<String, Object> metadataMap = createMetadataMap("ldp_vc");
        IssuerMetadata metadata = new IssuerMetadata(metadataMap, new HttpClient());
        
        // Detect format
        DigitalCredentialFormat format = (DigitalCredentialFormat) 
            detectFormatMethod.invoke(client, offer, metadata);
        
        assertEquals(DigitalCredentialFormat.JSON_LD, format,
            "ldp_vc format should be detected as JSON_LD");
    }
    
    @Test
    @DisplayName("Should detect jwt_vc_json-ld format as JSON_LD")
    void testDetectJwtVcJsonLdFormat() throws Exception {
        // Create offer
        Map<String, Object> offerMap = createOfferMap("UniversityDegree");
        CredentialOffer offer = new CredentialOffer(offerMap);
        
        // Create metadata with jwt_vc_json-ld format
        Map<String, Object> metadataMap = createMetadataMap("jwt_vc_json-ld");
        IssuerMetadata metadata = new IssuerMetadata(metadataMap, new HttpClient());
        
        // Detect format
        DigitalCredentialFormat format = (DigitalCredentialFormat) 
            detectFormatMethod.invoke(client, offer, metadata);
        
        assertEquals(DigitalCredentialFormat.JSON_LD, format,
            "jwt_vc_json-ld format should be detected as JSON_LD");
    }
    
    @Test
    @DisplayName("Should detect mso_mdoc format as ISO_MDOC")
    void testDetectMsoMdocFormat() throws Exception {
        // Create offer
        Map<String, Object> offerMap = createOfferMap("org.iso.18013.5.1.mDL");
        CredentialOffer offer = new CredentialOffer(offerMap);
        
        // Create metadata with mso_mdoc format
        Map<String, Object> metadataMap = createMetadataMap("mso_mdoc");
        IssuerMetadata metadata = new IssuerMetadata(metadataMap, new HttpClient());
        
        // Detect format
        DigitalCredentialFormat format = (DigitalCredentialFormat) 
            detectFormatMethod.invoke(client, offer, metadata);
        
        assertEquals(DigitalCredentialFormat.ISO_MDOC, format,
            "mso_mdoc format should be detected as ISO_MDOC");
    }
    
    @Test
    @DisplayName("Should detect jwt_vc_json format as SD_JWT_VC")
    void testDetectJwtVcJsonFormat() throws Exception {
        // Create offer
        Map<String, Object> offerMap = createOfferMap("UniversityDegree");
        CredentialOffer offer = new CredentialOffer(offerMap);
        
        // Create metadata with jwt_vc_json format
        Map<String, Object> metadataMap = createMetadataMap("jwt_vc_json");
        IssuerMetadata metadata = new IssuerMetadata(metadataMap, new HttpClient());
        
        // Detect format
        DigitalCredentialFormat format = (DigitalCredentialFormat) 
            detectFormatMethod.invoke(client, offer, metadata);
        
        assertEquals(DigitalCredentialFormat.SD_JWT_VC, format,
            "jwt_vc_json format should be detected as SD_JWT_VC");
    }
    
    @Test
    @DisplayName("Should detect vc+sd-jwt format as SD_JWT_VC")
    void testDetectVcSdJwtFormat() throws Exception {
        // Create offer
        Map<String, Object> offerMap = createOfferMap("UniversityDegree");
        CredentialOffer offer = new CredentialOffer(offerMap);
        
        // Create metadata with vc+sd-jwt format
        Map<String, Object> metadataMap = createMetadataMap("vc+sd-jwt");
        IssuerMetadata metadata = new IssuerMetadata(metadataMap, new HttpClient());
        
        // Detect format
        DigitalCredentialFormat format = (DigitalCredentialFormat) 
            detectFormatMethod.invoke(client, offer, metadata);
        
        assertEquals(DigitalCredentialFormat.SD_JWT_VC, format,
            "vc+sd-jwt format should be detected as SD_JWT_VC");
    }
    
    @Test
    @DisplayName("Should default to SD_JWT_VC for unknown format")
    void testDefaultToSdJwtVc() throws Exception {
        // Create offer
        Map<String, Object> offerMap = createOfferMap("UniversityDegree");
        CredentialOffer offer = new CredentialOffer(offerMap);
        
        // Create metadata with unknown format
        Map<String, Object> metadataMap = createMetadataMap("unknown_format");
        IssuerMetadata metadata = new IssuerMetadata(metadataMap, new HttpClient());
        
        // Detect format
        DigitalCredentialFormat format = (DigitalCredentialFormat) 
            detectFormatMethod.invoke(client, offer, metadata);
        
        assertEquals(DigitalCredentialFormat.SD_JWT_VC, format,
            "Unknown format should default to SD_JWT_VC");
    }
    
    @Test
    @DisplayName("Should default to SD_JWT_VC when no format in metadata")
    void testDefaultWhenNoFormat() throws Exception {
        // Create offer
        Map<String, Object> offerMap = createOfferMap("UniversityDegree");
        CredentialOffer offer = new CredentialOffer(offerMap);
        
        // Create metadata with no credentials_supported
        Map<String, Object> metadataMap = new HashMap<>();
        metadataMap.put("credential_issuer", "https://issuer.example.com");
        metadataMap.put("credential_endpoint", "https://issuer.example.com/credential");
        metadataMap.put("token_endpoint", "https://issuer.example.com/token");
        IssuerMetadata metadata = new IssuerMetadata(metadataMap, new HttpClient());
        
        // Detect format
        DigitalCredentialFormat format = (DigitalCredentialFormat) 
            detectFormatMethod.invoke(client, offer, metadata);
        
        assertEquals(DigitalCredentialFormat.SD_JWT_VC, format,
            "Should default to SD_JWT_VC when no format in metadata");
    }
    
    @Test
    @DisplayName("Should handle multiple formats and select first")
    void testMultipleFormats() throws Exception {
        // Create offer
        Map<String, Object> offerMap = createOfferMap("UniversityDegree");
        CredentialOffer offer = new CredentialOffer(offerMap);
        
        // Create metadata with multiple formats
        Map<String, Object> metadataMap = new HashMap<>();
        metadataMap.put("credential_issuer", "https://issuer.example.com");
        metadataMap.put("credential_endpoint", "https://issuer.example.com/credential");
        metadataMap.put("token_endpoint", "https://issuer.example.com/token");
        
        List<Map<String, Object>> credentialsSupported = new ArrayList<>();
        
        // First credential: ldp_vc
        Map<String, Object> cred1 = new HashMap<>();
        cred1.put("format", "ldp_vc");
        cred1.put("types", List.of("VerifiableCredential", "UniversityDegree"));
        credentialsSupported.add(cred1);
        
        // Second credential: jwt_vc_json
        Map<String, Object> cred2 = new HashMap<>();
        cred2.put("format", "jwt_vc_json");
        cred2.put("types", List.of("VerifiableCredential", "DriverLicense"));
        credentialsSupported.add(cred2);
        
        metadataMap.put("credentials_supported", credentialsSupported);
        IssuerMetadata metadata = new IssuerMetadata(metadataMap, new HttpClient());
        
        // Detect format - should select first one
        DigitalCredentialFormat format = (DigitalCredentialFormat) 
            detectFormatMethod.invoke(client, offer, metadata);
        
        assertEquals(DigitalCredentialFormat.JSON_LD, format,
            "Should select first format when multiple are available");
    }
    
    @Test
    @DisplayName("mapFormatString should handle case insensitivity")
    void testMapFormatStringCaseInsensitive() throws Exception {
        // Test uppercase
        DigitalCredentialFormat format1 = (DigitalCredentialFormat) 
            mapFormatStringMethod.invoke(client, "LDP_VC");
        assertEquals(DigitalCredentialFormat.JSON_LD, format1);
        
        // Test mixed case
        DigitalCredentialFormat format2 = (DigitalCredentialFormat) 
            mapFormatStringMethod.invoke(client, "Ldp_Vc");
        assertEquals(DigitalCredentialFormat.JSON_LD, format2);
        
        // Test with spaces
        DigitalCredentialFormat format3 = (DigitalCredentialFormat) 
            mapFormatStringMethod.invoke(client, "  ldp_vc  ");
        assertEquals(DigitalCredentialFormat.JSON_LD, format3);
    }
    
    @Test
    @DisplayName("mapFormatString should return null for null input")
    void testMapFormatStringNull() throws Exception {
        DigitalCredentialFormat format = (DigitalCredentialFormat) 
            mapFormatStringMethod.invoke(client, new Object[]{null});
        assertNull(format, "Should return null for null input");
    }
    
    @Test
    @DisplayName("mapFormatString should return null for empty string")
    void testMapFormatStringEmpty() throws Exception {
        DigitalCredentialFormat format = (DigitalCredentialFormat) 
            mapFormatStringMethod.invoke(client, "");
        assertNull(format, "Should return null for empty string");
    }
    
    @Test
    @DisplayName("mapFormatString should return null for unknown format")
    void testMapFormatStringUnknown() throws Exception {
        DigitalCredentialFormat format = (DigitalCredentialFormat) 
            mapFormatStringMethod.invoke(client, "unknown_format_xyz");
        assertNull(format, "Should return null for unknown format");
    }
    
    // Helper methods
    
    private Map<String, Object> createOfferMap(String credentialType) {
        Map<String, Object> offerMap = new HashMap<>();
        offerMap.put("credential_issuer", "https://issuer.example.com");
        offerMap.put("credentials", List.of(credentialType));
        
        Map<String, Object> grants = new HashMap<>();
        Map<String, Object> preAuthGrant = new HashMap<>();
        preAuthGrant.put("pre-authorized_code", "test-code-123");
        preAuthGrant.put("user_pin_required", false);
        grants.put("urn:ietf:params:oauth:grant-type:pre-authorized_code", preAuthGrant);
        offerMap.put("grants", grants);
        
        return offerMap;
    }
    
    private Map<String, Object> createMetadataMap(String format) {
        Map<String, Object> metadataMap = new HashMap<>();
        metadataMap.put("credential_issuer", "https://issuer.example.com");
        metadataMap.put("credential_endpoint", "https://issuer.example.com/credential");
        metadataMap.put("token_endpoint", "https://issuer.example.com/token");
        
        List<Map<String, Object>> credentialsSupported = new ArrayList<>();
        Map<String, Object> credConfig = new HashMap<>();
        credConfig.put("format", format);
        credConfig.put("types", List.of("VerifiableCredential", "UniversityDegree"));
        credConfig.put("cryptographic_binding_methods_supported", List.of("jwk"));
        credConfig.put("cryptographic_suites_supported", List.of("ES256"));
        credentialsSupported.add(credConfig);
        
        metadataMap.put("credentials_supported", credentialsSupported);
        
        return metadataMap;
    }
}

// Made with Bob