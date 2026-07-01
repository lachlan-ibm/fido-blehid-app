/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.oidc;

import com.isfs.blekey.credential.VerifiableCredential;
import com.isfs.blekey.credential.jwt.JwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive tests for validateCredential() method in Oidc4VciClient.
 * Critical Path Coverage - JWT Credential Validation
 * 
 */
@DisplayName("OIDC4VCI Client - JWT Credential Validation Tests")
class Oidc4VciClientValidationTest {
    
    private Oidc4VciClient client;
    private PublicKey holderPublicKey;
    private Method validateCredentialMethod;
    
    @BeforeEach
    void setUp() throws Exception {
        client = new Oidc4VciClient();
        
        // Generate test key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        KeyPair keyPair = keyGen.generateKeyPair();
        holderPublicKey = keyPair.getPublic();
        
        // Access private method via reflection
        validateCredentialMethod = Oidc4VciClient.class.getDeclaredMethod(
            "validateCredential", String.class, PublicKey.class);
        validateCredentialMethod.setAccessible(true);
    }
    
    /**
     * Helper to invoke validateCredential and unwrap exceptions
     */
    private VerifiableCredential invokeValidateCredential(String jwt, PublicKey publicKey) throws Exception {
        try {
            return (VerifiableCredential) validateCredentialMethod.invoke(client, jwt, publicKey);
        } catch (java.lang.reflect.InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception) {
                throw (Exception) cause;
            }
            throw e;
        }
    }
    
    /**
     * Helper to create a minimal valid JWT with vc claim
     */
    private String createValidJwt(String issuer, String credentialType) {
        // Create JWT parts
        String header = Base64.getUrlEncoder().withoutPadding()
            .encodeToString("{\"alg\":\"ES256\",\"typ\":\"JWT\"}".getBytes());
        
        String payload = String.format(
            "{\"iss\":\"%s\",\"iat\":1640000000,\"exp\":1740000000,\"vc\":{\"type\":[\"%s\"]}}",
            issuer, credentialType
        );
        String encodedPayload = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(payload.getBytes());
        
        String signature = Base64.getUrlEncoder().withoutPadding()
            .encodeToString("fake-signature".getBytes());
        
        return header + "." + encodedPayload + "." + signature;
    }
    
    @Nested
    @DisplayName("Valid Credential Tests")
    class ValidCredentialTests {
        
        @Test
        @DisplayName("Should validate credential with DID issuer")
        void testValidateCredential_DidIssuerExtraction() throws Exception {
            String jwt = createValidJwt("did:example:issuer123", "UniversityDegree");
            
            VerifiableCredential credential = invokeValidateCredential(jwt, holderPublicKey);
            
            assertNotNull(credential);
            assertNotNull(credential.getEncryptedData());
            assertEquals("did:example:issuer123", credential.getMetadata().getIssuerDid());
            assertNull(credential.getMetadata().getIssuerUrl());
        }
        
        @Test
        @DisplayName("Should validate credential with URL issuer")
        void testValidateCredential_UrlIssuerExtraction() throws Exception {
            String jwt = createValidJwt("https://issuer.example.com", "UniversityDegree");
            
            VerifiableCredential credential = invokeValidateCredential(jwt, holderPublicKey);
            
            assertNotNull(credential);
            assertEquals("https://issuer.example.com", credential.getMetadata().getIssuerUrl());
            assertNull(credential.getMetadata().getIssuerDid());
        }
        
        @Test
        @DisplayName("Should extract credential type from vc object")
        void testValidateCredential_CredentialTypeExtraction() throws Exception {
            String jwt = createValidJwt("did:example:issuer", "DriverLicense");
            
            VerifiableCredential credential = invokeValidateCredential(jwt, holderPublicKey);
            
            assertEquals("DriverLicense", credential.getMetadata().getCredentialType());
        }
        
        @Test
        @DisplayName("Should handle complex type array")
        void testValidateCredential_ComplexTypeArray() throws Exception {
            String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"ES256\"}".getBytes());
            
            String payload = "{\"iss\":\"did:example:issuer\",\"iat\":1640000000,\"exp\":1740000000," +
                "\"vc\":{\"type\":[\"VerifiableCredential\",\"EmployeeCredential\",\"SecurityClearance\"]}}";
            String encodedPayload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payload.getBytes());
            
            String jwt = header + "." + encodedPayload + ".signature";
            
            VerifiableCredential credential = invokeValidateCredential(jwt, holderPublicKey);
            
            // Should use the last type in the array
            assertEquals("SecurityClearance", credential.getMetadata().getCredentialType());
        }
        
        @Test
        @DisplayName("Should extract timestamps from JWT claims")
        void testValidateCredential_TimestampExtraction() throws Exception {
            String jwt = createValidJwt("did:example:issuer", "UniversityDegree");
            
            VerifiableCredential credential = invokeValidateCredential(jwt, holderPublicKey);
            
            assertNotNull(credential.getMetadata().getIssuedAt());
            assertNotNull(credential.getMetadata().getExpiresAt());
        }
    }
    
    @Nested
    @DisplayName("Missing VC Claim Tests")
    class MissingVcClaimTests {
        
        @Test
        @DisplayName("Should throw exception when vc claim is missing")
        void testValidateCredential_MissingVcClaim() throws Exception {
            String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"ES256\"}".getBytes());
            
            String payload = "{\"iss\":\"did:example:issuer\",\"iat\":1640000000}";
            String encodedPayload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payload.getBytes());
            
            String jwt = header + "." + encodedPayload + ".signature";
            
            OidcException exception = assertThrows(OidcException.class, () -> {
                invokeValidateCredential(jwt, holderPublicKey);
            });
            
            assertTrue(exception.getMessage().contains("Verifiable credential not found in JWT"));
        }
        
        @Test
        @DisplayName("Should throw exception when vc object is null")
        void testValidateCredential_NullVcObject() throws Exception {
            String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"ES256\"}".getBytes());
            
            String payload = "{\"iss\":\"did:example:issuer\",\"vc\":null}";
            String encodedPayload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payload.getBytes());
            
            String jwt = header + "." + encodedPayload + ".signature";
            
            OidcException exception = assertThrows(OidcException.class, () -> {
                invokeValidateCredential(jwt, holderPublicKey);
            });
            
            assertTrue(exception.getMessage().contains("Verifiable credential not found in JWT"));
        }
    }
    
    @Nested
    @DisplayName("Invalid VC Structure Tests")
    class InvalidVcStructureTests {
        
        @Test
        @DisplayName("Should handle vc with missing type")
        void testValidateCredential_MissingTypeInVc() throws Exception {
            String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"ES256\"}".getBytes());
            
            String payload = "{\"iss\":\"did:example:issuer\",\"iat\":1640000000,\"vc\":{}}";
            String encodedPayload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payload.getBytes());
            
            String jwt = header + "." + encodedPayload + ".signature";
            
            VerifiableCredential credential = invokeValidateCredential(jwt, holderPublicKey);
            
            // Should not throw, but credential type will be null
            assertNotNull(credential);
            assertNull(credential.getMetadata().getCredentialType());
        }
        
        @Test
        @DisplayName("Should handle vc with empty type list")
        void testValidateCredential_EmptyTypeList() throws Exception {
            String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"ES256\"}".getBytes());
            
            String payload = "{\"iss\":\"did:example:issuer\",\"iat\":1640000000,\"vc\":{\"type\":[]}}";
            String encodedPayload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payload.getBytes());
            
            String jwt = header + "." + encodedPayload + ".signature";
            
            VerifiableCredential credential = invokeValidateCredential(jwt, holderPublicKey);
            
            // Should not throw, but credential type will be null
            assertNotNull(credential);
            assertNull(credential.getMetadata().getCredentialType());
        }
        
        @Test
        @DisplayName("Should handle vc as non-Map object")
        void testValidateCredential_InvalidVcStructure() throws Exception {
            String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"ES256\"}".getBytes());
            
            String payload = "{\"iss\":\"did:example:issuer\",\"iat\":1640000000,\"vc\":\"string-value\"}";
            String encodedPayload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payload.getBytes());
            
            String jwt = header + "." + encodedPayload + ".signature";
            
            VerifiableCredential credential = invokeValidateCredential(jwt, holderPublicKey);
            
            // Should not throw, but won't extract type
            assertNotNull(credential);
            assertNull(credential.getMetadata().getCredentialType());
        }
    }
    
    @Nested
    @DisplayName("Issuer Field Tests")
    class IssuerFieldTests {
        
        @Test
        @DisplayName("Should handle null issuer")
        void testValidateCredential_NullIssuer() throws Exception {
            String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"ES256\"}".getBytes());
            
            String payload = "{\"iat\":1640000000,\"vc\":{\"type\":[\"UniversityDegree\"]}}";
            String encodedPayload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payload.getBytes());
            
            String jwt = header + "." + encodedPayload + ".signature";
            
            VerifiableCredential credential = invokeValidateCredential(jwt, holderPublicKey);
            
            assertNotNull(credential);
            assertNull(credential.getMetadata().getIssuerDid());
            assertNull(credential.getMetadata().getIssuerUrl());
        }
        
        @Test
        @DisplayName("Should handle invalid issuer format")
        void testValidateCredential_InvalidIssuerFormat() throws Exception {
            String jwt = createValidJwt("", "UniversityDegree");
            
            VerifiableCredential credential = invokeValidateCredential(jwt, holderPublicKey);
            
            assertNotNull(credential);
            // Empty issuer should be treated as URL
            assertEquals("", credential.getMetadata().getIssuerUrl());
        }
    }
    
    @Nested
    @DisplayName("Timestamp Tests")
    class TimestampTests {
        
        @Test
        @DisplayName("Should handle missing timestamps")
        void testValidateCredential_MissingTimestamps() throws Exception {
            String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"ES256\"}".getBytes());
            
            String payload = "{\"iss\":\"did:example:issuer\",\"vc\":{\"type\":[\"UniversityDegree\"]}}";
            String encodedPayload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payload.getBytes());
            
            String jwt = header + "." + encodedPayload + ".signature";
            
            VerifiableCredential credential = invokeValidateCredential(jwt, holderPublicKey);
            
            assertNotNull(credential);
            assertNull(credential.getMetadata().getIssuedAt());
            assertNull(credential.getMetadata().getExpiresAt());
        }
        
        @Test
        @DisplayName("Should handle null issuedAt")
        void testValidateCredential_NullIssuedAt() throws Exception {
            String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"ES256\"}".getBytes());
            
            String payload = "{\"iss\":\"did:example:issuer\",\"exp\":1740000000,\"vc\":{\"type\":[\"UniversityDegree\"]}}";
            String encodedPayload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payload.getBytes());
            
            String jwt = header + "." + encodedPayload + ".signature";
            
            VerifiableCredential credential = invokeValidateCredential(jwt, holderPublicKey);
            
            assertNotNull(credential);
            assertNull(credential.getMetadata().getIssuedAt());
            assertNotNull(credential.getMetadata().getExpiresAt());
        }
        
        @Test
        @DisplayName("Should handle null expirationTime")
        void testValidateCredential_NullExpirationTime() throws Exception {
            String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"ES256\"}".getBytes());
            
            String payload = "{\"iss\":\"did:example:issuer\",\"iat\":1640000000,\"vc\":{\"type\":[\"UniversityDegree\"]}}";
            String encodedPayload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payload.getBytes());
            
            String jwt = header + "." + encodedPayload + ".signature";
            
            VerifiableCredential credential = invokeValidateCredential(jwt, holderPublicKey);
            
            assertNotNull(credential);
            assertNotNull(credential.getMetadata().getIssuedAt());
            assertNull(credential.getMetadata().getExpiresAt());
        }
    }
    
    @Nested
    @DisplayName("JWT Parsing Exception Tests")
    class JwtParsingExceptionTests {
        
        @Test
        @DisplayName("Should throw exception for invalid JWT format")
        void testValidateCredential_JwtParsingException() {
            String invalidJwt = "not.a.valid.jwt.format";
            
            OidcException exception = assertThrows(OidcException.class, () -> {
                invokeValidateCredential(invalidJwt, holderPublicKey);
            });
            
            assertTrue(exception.getMessage().contains("Credential validation failed"));
        }
        
        @Test
        @DisplayName("Should throw exception for malformed JWT")
        void testValidateCredential_MalformedJwt() {
            String malformedJwt = "header.payload";  // Missing signature
            
            OidcException exception = assertThrows(OidcException.class, () -> {
                invokeValidateCredential(malformedJwt, holderPublicKey);
            });
            
            assertTrue(exception.getMessage().contains("Credential validation failed"));
        }
        
        @Test
        @DisplayName("Should throw exception for invalid base64 in JWT")
        void testValidateCredential_InvalidBase64() {
            String invalidJwt = "not-base64.not-base64.not-base64";
            
            OidcException exception = assertThrows(OidcException.class, () -> {
                invokeValidateCredential(invalidJwt, holderPublicKey);
            });
            
            assertTrue(exception.getMessage().contains("Credential validation failed"));
        }
        
        @Test
        @DisplayName("Should throw exception for invalid JSON in payload")
        void testValidateCredential_InvalidJsonPayload() {
            String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"ES256\"}".getBytes());
            
            String invalidPayload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{invalid json}".getBytes());
            
            String jwt = header + "." + invalidPayload + ".signature";
            
            OidcException exception = assertThrows(OidcException.class, () -> {
                invokeValidateCredential(jwt, holderPublicKey);
            });
            
            assertTrue(exception.getMessage().contains("Credential validation failed"));
        }
    }
    
    @Nested
    @DisplayName("Unexpected Exception Tests")
    class UnexpectedExceptionTests {
        
        @Test
        @DisplayName("Should handle null JWT")
        void testValidateCredential_NullJwt() {
            OidcException exception = assertThrows(OidcException.class, () -> {
                invokeValidateCredential(null, holderPublicKey);
            });
            
            assertTrue(exception.getMessage().contains("Credential validation failed"));
        }
        
        @Test
        @DisplayName("Should handle empty JWT")
        void testValidateCredential_EmptyJwt() {
            OidcException exception = assertThrows(OidcException.class, () -> {
                invokeValidateCredential("", holderPublicKey);
            });
            
            assertTrue(exception.getMessage().contains("Credential validation failed"));
        }
    }
    
    @Nested
    @DisplayName("Data Storage Tests")
    class DataStorageTests {
        
        @Test
        @DisplayName("Should store JWT as encrypted data")
        void testValidateCredential_DataStorage() throws Exception {
            String jwt = createValidJwt("did:example:issuer", "UniversityDegree");
            
            VerifiableCredential credential = invokeValidateCredential(jwt, holderPublicKey);
            
            assertNotNull(credential.getEncryptedData());
            assertTrue(credential.getEncryptedData().length > 0);
            
            // Verify stored data matches input
            String storedJwt = new String(credential.getEncryptedData(), 
                java.nio.charset.StandardCharsets.UTF_8);
            assertEquals(jwt, storedJwt);
        }
    }
}

// Made with Bob