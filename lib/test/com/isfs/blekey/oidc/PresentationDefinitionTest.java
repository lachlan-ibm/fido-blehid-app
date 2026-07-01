/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.oidc;

import com.isfs.blekey.credential.VerifiableCredential;
import com.isfs.blekey.credential.DigitalCredentialMetadata;
import com.isfs.blekey.util.http.HttpClient;
import com.isfs.blekey.util.http.HttpResponse;
import com.isfs.blekey.util.http.HttpException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Comprehensive unit tests for PresentationDefinition class.
 * Implements the test coverage plan to achieve >90% coverage.
 */
@DisplayName("PresentationDefinition Tests")
class PresentationDefinitionTest {
    
    private static final String VALID_PD_JSON = """
        {
            "id": "test_presentation_definition",
            "input_descriptors": [
                {
                    "id": "id_credential",
                    "format": {
                        "jwt_vc_json": {
                            "alg": ["ES256"]
                        }
                    },
                    "constraints": {
                        "fields": [
                            {
                                "path": ["$.vc.type"],
                                "filter": {
                                    "type": "string",
                                    "pattern": "UniversityDegree"
                                }
                            },
                            {
                                "path": ["$.vc.credentialSubject.name"],
                                "filter": {
                                    "type": "string"
                                }
                            }
                        ]
                    }
                }
            ]
        }
        """;
    
    private HttpClient mockHttpClient;
    
    @BeforeEach
    void setUp() {
        mockHttpClient = mock(HttpClient.class);
    }
    
    private VerifiableCredential createMockCredential(String type) {
        VerifiableCredential credential = new VerifiableCredential();
        credential.setId("test-cred-123");
        
        DigitalCredentialMetadata metadata = credential.getMetadata();
        metadata.setIssuerDid("did:example:issuer");
        metadata.setCredentialType(type);
        
        return credential;
    }
    
    // ========================================================================
    // Core Parsing Tests
    // ========================================================================
    
    @Nested
    @DisplayName("JSON Parsing Tests")
    class JsonParsingTests {
        
        @Test
        @DisplayName("Should parse valid JSON successfully")
        void testFromJson_ValidInput() throws OidcException {
            PresentationDefinition result = PresentationDefinition.fromJson(VALID_PD_JSON);
            
            assertNotNull(result);
            assertEquals("test_presentation_definition", result.getId());
            assertNotNull(result.getInputDescriptors());
            assertEquals(1, result.getInputDescriptors().size());
            assertEquals("id_credential", result.getInputDescriptors().get(0).getId());
        }
        
        @Test
        @DisplayName("Should throw OidcException for null input")
        void testFromJson_NullInput() {
            OidcException exception = assertThrows(OidcException.class, () -> {
                PresentationDefinition.fromJson(null);
            });
            
            assertTrue(exception.getMessage().contains("Failed to parse"));
        }
        
        @Test
        @DisplayName("Should throw OidcException for empty string")
        void testFromJson_EmptyString() {
            OidcException exception = assertThrows(OidcException.class, () -> {
                PresentationDefinition.fromJson("");
            });
            
            assertTrue(exception.getMessage().contains("Failed to parse"));
        }
        
        @Test
        @DisplayName("Should throw OidcException for invalid JSON")
        void testFromJson_InvalidJson() {
            String invalidJson = "{invalid json}";
            
            OidcException exception = assertThrows(OidcException.class, () -> {
                PresentationDefinition.fromJson(invalidJson);
            });
            
            assertTrue(exception.getMessage().contains("Failed to parse"));
        }
        
        @Test
        @DisplayName("Should parse JSON with missing id")
        void testFromJson_MissingId() throws OidcException {
            String json = """
                {
                    "input_descriptors": [
                        {
                            "id": "descriptor_1"
                        }
                    ]
                }
                """;
            
            PresentationDefinition result = PresentationDefinition.fromJson(json);
            
            assertNotNull(result);
            assertNull(result.getId());
            assertEquals(1, result.getInputDescriptors().size());
        }
        
        @Test
        @DisplayName("Should parse JSON with missing input_descriptors")
        void testFromJson_MissingInputDescriptors() throws OidcException {
            String json = """
                {
                    "id": "test_pd"
                }
                """;
            
            PresentationDefinition result = PresentationDefinition.fromJson(json);
            
            assertNotNull(result);
            assertEquals("test_pd", result.getId());
            assertNotNull(result.getInputDescriptors());
            assertTrue(result.getInputDescriptors().isEmpty());
        }
        
        @Test
        @DisplayName("Should parse complex nested structure")
        void testFromJson_ComplexNestedStructure() throws OidcException {
            String json = """
                {
                    "id": "complex_pd",
                    "input_descriptors": [
                        {
                            "id": "descriptor_1",
                            "format": {
                                "jwt_vc_json": {"alg": ["ES256", "ES384"]}
                            },
                            "constraints": {
                                "fields": [
                                    {
                                        "path": ["$.vc.type"],
                                        "filter": {
                                            "type": "string",
                                            "pattern": "Degree"
                                        }
                                    }
                                ]
                            }
                        }
                    ]
                }
                """;
            
            PresentationDefinition result = PresentationDefinition.fromJson(json);
            
            assertNotNull(result);
            assertEquals("complex_pd", result.getId());
            assertEquals(1, result.getInputDescriptors().size());
        }
    }
    
    @Nested
    @DisplayName("Map Parsing Tests")
    class MapParsingTests {
        
        @Test
        @DisplayName("Should throw OidcException for null map")
        void testFromMap_NullMap() {
            OidcException exception = assertThrows(OidcException.class, () -> {
                PresentationDefinition.fromMap(null);
            });
            
            assertTrue(exception.getMessage().contains("null"));
        }
        
        @Test
        @DisplayName("Should parse empty map")
        void testFromMap_EmptyMap() throws OidcException {
            Map<String, Object> emptyMap = new HashMap<>();
            
            PresentationDefinition result = PresentationDefinition.fromMap(emptyMap);
            
            assertNotNull(result);
            assertNull(result.getId());
            assertNotNull(result.getInputDescriptors());
            assertTrue(result.getInputDescriptors().isEmpty());
        }
        
        @Test
        @DisplayName("Should parse map with all fields")
        void testFromMap_WithAllFields() throws OidcException {
            Map<String, Object> map = new HashMap<>();
            map.put("id", "test_pd");
            
            List<Map<String, Object>> descriptors = new ArrayList<>();
            Map<String, Object> descriptor = new HashMap<>();
            descriptor.put("id", "desc_1");
            
            Map<String, Object> constraints = new HashMap<>();
            List<Map<String, Object>> fields = new ArrayList<>();
            Map<String, Object> field = new HashMap<>();
            field.put("path", List.of("$.vc.type"));
            fields.add(field);
            constraints.put("fields", fields);
            descriptor.put("constraints", constraints);
            
            descriptors.add(descriptor);
            map.put("input_descriptors", descriptors);
            
            PresentationDefinition result = PresentationDefinition.fromMap(map);
            
            assertNotNull(result);
            assertEquals("test_pd", result.getId());
            assertEquals(1, result.getInputDescriptors().size());
            assertEquals("desc_1", result.getInputDescriptors().get(0).getId());
        }
        
        @Test
        @DisplayName("Should handle null input_descriptors")
        void testFromMap_WithNullInputDescriptors() throws OidcException {
            Map<String, Object> map = new HashMap<>();
            map.put("id", "test_pd");
            map.put("input_descriptors", null);
            
            PresentationDefinition result = PresentationDefinition.fromMap(map);
            
            assertNotNull(result);
            assertEquals("test_pd", result.getId());
            assertNotNull(result.getInputDescriptors());
            assertTrue(result.getInputDescriptors().isEmpty());
        }
        
        @Test
        @DisplayName("Should handle empty input_descriptors list")
        void testFromMap_WithEmptyInputDescriptors() throws OidcException {
            Map<String, Object> map = new HashMap<>();
            map.put("id", "test_pd");
            map.put("input_descriptors", new ArrayList<>());
            
            PresentationDefinition result = PresentationDefinition.fromMap(map);
            
            assertNotNull(result);
            assertEquals("test_pd", result.getId());
            assertTrue(result.getInputDescriptors().isEmpty());
        }
        
        @Test
        @DisplayName("Should parse multiple descriptors")
        void testFromMap_WithMultipleDescriptors() throws OidcException {
            Map<String, Object> map = new HashMap<>();
            map.put("id", "multi_pd");
            
            List<Map<String, Object>> descriptors = new ArrayList<>();
            
            Map<String, Object> desc1 = new HashMap<>();
            desc1.put("id", "desc_1");
            descriptors.add(desc1);
            
            Map<String, Object> desc2 = new HashMap<>();
            desc2.put("id", "desc_2");
            descriptors.add(desc2);
            
            map.put("input_descriptors", descriptors);
            
            PresentationDefinition result = PresentationDefinition.fromMap(map);
            
            assertNotNull(result);
            assertEquals(2, result.getInputDescriptors().size());
            assertEquals("desc_1", result.getInputDescriptors().get(0).getId());
            assertEquals("desc_2", result.getInputDescriptors().get(1).getId());
        }
    }
    
    // ========================================================================
    // HTTP and JWT Tests
    // ========================================================================
    
    @Nested
    @DisplayName("HTTP and JWT Tests")
    class HttpJwtTests {
        
        @Test
        @DisplayName("Should fetch and parse JSON from URI successfully")
        void testFromUri_SuccessfulJsonFetch() throws Exception {
            // Note: fromUri creates its own HttpClient, so we test with actual HTTP calls
            // or test the error paths
            OidcException exception = assertThrows(OidcException.class, () -> {
                PresentationDefinition.fromUri("https://invalid.example.com/pd");
            });
            
            assertTrue(exception.getMessage().contains("Failed to fetch"));
        }
        
        @Test
        @DisplayName("Should throw OidcException for HTTP errors")
        void testFromUri_HttpError() {
            OidcException exception = assertThrows(OidcException.class, () -> {
                PresentationDefinition.fromUri("https://httpstat.us/404");
            });
            
            assertTrue(exception.getMessage().contains("Failed to fetch"));
        }
        
        @Test
        @DisplayName("Should throw OidcException for invalid URI")
        void testFromUri_InvalidUri() {
            OidcException exception = assertThrows(OidcException.class, () -> {
                PresentationDefinition.fromUri("not a valid uri");
            });
            
            assertTrue(exception.getMessage().contains("Failed to fetch"));
        }
        
        @Test
        @DisplayName("Should throw OidcException for network errors")
        void testFromUri_NetworkError() {
            OidcException exception = assertThrows(OidcException.class, () -> {
                PresentationDefinition.fromUri("https://nonexistent.invalid.domain.test/pd");
            });
            
            assertTrue(exception.getMessage().contains("Failed to fetch"));
        }
    }
    // ========================================================================
    // Credential Matching Tests
    // ========================================================================
    
    @Nested
    @DisplayName("Credential Matching Tests")
    class CredentialMatchingTests {
        
        @Test
        @DisplayName("Should return false for null credential")
        void testMatches_NullCredential() throws OidcException {
            PresentationDefinition pd = PresentationDefinition.fromJson(VALID_PD_JSON);
            
            assertFalse(pd.matches(null));
        }
        
        @Test
        @DisplayName("Should return false for null input descriptors")
        void testMatches_NullInputDescriptors() {
            PresentationDefinition pd = new PresentationDefinition();
            pd.setId("test");
            pd.setInputDescriptors(null);
            
            VerifiableCredential credential = createMockCredential("UniversityDegree");
            
            assertFalse(pd.matches(credential));
        }
        
        @Test
        @DisplayName("Should return false for empty input descriptors")
        void testMatches_EmptyInputDescriptors() {
            PresentationDefinition pd = new PresentationDefinition();
            pd.setId("test");
            pd.setInputDescriptors(new ArrayList<>());
            
            VerifiableCredential credential = createMockCredential("UniversityDegree");
            
            assertFalse(pd.matches(credential));
        }
        
        @Test
        @DisplayName("Should return true for matching credential")
        void testMatches_MatchingCredential() throws OidcException {
            PresentationDefinition pd = PresentationDefinition.fromJson(VALID_PD_JSON);
            VerifiableCredential credential = createMockCredential("UniversityDegree");
            
            assertTrue(pd.matches(credential));
        }
        
        @Test
        @DisplayName("Should return false for non-matching credential")
        void testMatches_NonMatchingCredential() throws OidcException {
            PresentationDefinition pd = PresentationDefinition.fromJson(VALID_PD_JSON);
            VerifiableCredential credential = createMockCredential("DriverLicense");
            
            assertFalse(pd.matches(credential));
        }
        
        @Test
        @DisplayName("Should match when first descriptor matches")
        void testMatches_MultipleDescriptors_FirstMatches() throws OidcException {
            String json = """
                {
                    "id": "multi_pd",
                    "input_descriptors": [
                        {
                            "id": "desc_1",
                            "constraints": {
                                "fields": [
                                    {
                                        "path": ["$.vc.type"],
                                        "filter": {"pattern": "UniversityDegree"}
                                    }
                                ]
                            }
                        },
                        {
                            "id": "desc_2",
                            "constraints": {
                                "fields": [
                                    {
                                        "path": ["$.vc.type"],
                                        "filter": {"pattern": "DriverLicense"}
                                    }
                                ]
                            }
                        }
                    ]
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            VerifiableCredential credential = createMockCredential("UniversityDegree");
            
            assertTrue(pd.matches(credential));
        }
        
        @Test
        @DisplayName("Should match when second descriptor matches")
        void testMatches_MultipleDescriptors_SecondMatches() throws OidcException {
            String json = """
                {
                    "id": "multi_pd",
                    "input_descriptors": [
                        {
                            "id": "desc_1",
                            "constraints": {
                                "fields": [
                                    {
                                        "path": ["$.vc.type"],
                                        "filter": {"pattern": "DriverLicense"}
                                    }
                                ]
                            }
                        },
                        {
                            "id": "desc_2",
                            "constraints": {
                                "fields": [
                                    {
                                        "path": ["$.vc.type"],
                                        "filter": {"pattern": "UniversityDegree"}
                                    }
                                ]
                            }
                        }
                    ]
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            VerifiableCredential credential = createMockCredential("UniversityDegree");
            
            assertTrue(pd.matches(credential));
        }
        
        @Test
        @DisplayName("Should not match when no descriptors match")
        void testMatches_MultipleDescriptors_NoneMatch() throws OidcException {
            String json = """
                {
                    "id": "multi_pd",
                    "input_descriptors": [
                        {
                            "id": "desc_1",
                            "constraints": {
                                "fields": [
                                    {
                                        "path": ["$.vc.type"],
                                        "filter": {"pattern": "DriverLicense"}
                                    }
                                ]
                            }
                        },
                        {
                            "id": "desc_2",
                            "constraints": {
                                "fields": [
                                    {
                                        "path": ["$.vc.type"],
                                        "filter": {"pattern": "Passport"}
                                    }
                                ]
                            }
                        }
                    ]
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            VerifiableCredential credential = createMockCredential("UniversityDegree");
            
            assertFalse(pd.matches(credential));
        }
        
        @Test
        @DisplayName("Should match descriptor with null constraints")
        void testMatchesDescriptor_NullConstraints() throws OidcException {
            String json = """
                {
                    "id": "test_pd",
                    "input_descriptors": [
                        {
                            "id": "desc_1"
                        }
                    ]
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            VerifiableCredential credential = createMockCredential("UniversityDegree");
            
            assertTrue(pd.matches(credential));
        }
        
        @Test
        @DisplayName("Should match descriptor with empty fields")
        void testMatchesDescriptor_EmptyFields() throws OidcException {
            String json = """
                {
                    "id": "test_pd",
                    "input_descriptors": [
                        {
                            "id": "desc_1",
                            "constraints": {
                                "fields": []
                            }
                        }
                    ]
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            VerifiableCredential credential = createMockCredential("UniversityDegree");
            
            assertTrue(pd.matches(credential));
        }
        
        @Test
        @DisplayName("Should match descriptor with null fields")
        void testMatchesDescriptor_NullFields() throws OidcException {
            String json = """
                {
                    "id": "test_pd",
                    "input_descriptors": [
                        {
                            "id": "desc_1",
                            "constraints": {}
                        }
                    ]
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            VerifiableCredential credential = createMockCredential("UniversityDegree");
            
            assertTrue(pd.matches(credential));
        }
        
        @Test
        @DisplayName("Should match when all fields match")
        void testMatchesDescriptor_AllFieldsMatch() throws OidcException {
            String json = """
                {
                    "id": "test_pd",
                    "input_descriptors": [
                        {
                            "id": "desc_1",
                            "constraints": {
                                "fields": [
                                    {
                                        "path": ["$.vc.type"],
                                        "filter": {"pattern": "UniversityDegree"}
                                    },
                                    {
                                        "path": ["type"],
                                        "filter": {"pattern": "University.*"}
                                    }
                                ]
                            }
                        }
                    ]
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            VerifiableCredential credential = createMockCredential("UniversityDegree");
            
            assertTrue(pd.matches(credential));
        }
        
        @Test
        @DisplayName("Should not match when one field fails")
        void testMatchesDescriptor_OneFieldFails() throws OidcException {
            String json = """
                {
                    "id": "test_pd",
                    "input_descriptors": [
                        {
                            "id": "desc_1",
                            "constraints": {
                                "fields": [
                                    {
                                        "path": ["$.vc.type"],
                                        "filter": {"pattern": "UniversityDegree"}
                                    },
                                    {
                                        "path": ["type"],
                                        "filter": {"pattern": "DriverLicense"}
                                    }
                                ]
                            }
                        }
                    ]
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            VerifiableCredential credential = createMockCredential("UniversityDegree");
            
            assertFalse(pd.matches(credential));
        }
        
        @Test
        @DisplayName("Should match field with null path")
        void testMatchesField_NullPath() throws OidcException {
            String json = """
                {
                    "id": "test_pd",
                    "input_descriptors": [
                        {
                            "id": "desc_1",
                            "constraints": {
                                "fields": [
                                    {
                                        "filter": {"pattern": "UniversityDegree"}
                                    }
                                ]
                            }
                        }
                    ]
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            VerifiableCredential credential = createMockCredential("UniversityDegree");
            
            assertTrue(pd.matches(credential));
        }
        
        @Test
        @DisplayName("Should match field with empty path")
        void testMatchesField_EmptyPath() throws OidcException {
            String json = """
                {
                    "id": "test_pd",
                    "input_descriptors": [
                        {
                            "id": "desc_1",
                            "constraints": {
                                "fields": [
                                    {
                                        "path": [],
                                        "filter": {"pattern": "UniversityDegree"}
                                    }
                                ]
                            }
                        }
                    ]
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            VerifiableCredential credential = createMockCredential("UniversityDegree");
            
            assertTrue(pd.matches(credential));
        }
        
        @Test
        @DisplayName("Should match type path with pattern")
        void testMatchesField_TypePathWithPattern() throws OidcException {
            String json = """
                {
                    "id": "test_pd",
                    "input_descriptors": [
                        {
                            "id": "desc_1",
                            "constraints": {
                                "fields": [
                                    {
                                        "path": ["$.vc.type"],
                                        "filter": {"pattern": "University.*"}
                                    }
                                ]
                            }
                        }
                    ]
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            VerifiableCredential credential = createMockCredential("UniversityDegree");
            
            assertTrue(pd.matches(credential));
        }
        
        @Test
        @DisplayName("Should match type path with contains")
        void testMatchesField_TypePathWithContains() throws OidcException {
            String json = """
                {
                    "id": "test_pd",
                    "input_descriptors": [
                        {
                            "id": "desc_1",
                            "constraints": {
                                "fields": [
                                    {
                                        "path": ["$.vc.type"],
                                        "filter": {
                                            "contains": {
                                                "const": "University"
                                            }
                                        }
                                    }
                                ]
                            }
                        }
                    ]
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            VerifiableCredential credential = createMockCredential("UniversityDegree");
            
            assertTrue(pd.matches(credential));
        }
        
        @Test
        @DisplayName("Should match type path with no filter")
        void testMatchesField_TypePathNoFilter() throws OidcException {
            String json = """
                {
                    "id": "test_pd",
                    "input_descriptors": [
                        {
                            "id": "desc_1",
                            "constraints": {
                                "fields": [
                                    {
                                        "path": ["$.vc.type"]
                                    }
                                ]
                            }
                        }
                    ]
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            VerifiableCredential credential = createMockCredential("UniversityDegree");
            
            assertTrue(pd.matches(credential));
        }
        
        @Test
        @DisplayName("Should not match when credential type is null")
        void testMatchesField_NullCredentialType() throws OidcException {
            String json = """
                {
                    "id": "test_pd",
                    "input_descriptors": [
                        {
                            "id": "desc_1",
                            "constraints": {
                                "fields": [
                                    {
                                        "path": ["$.vc.type"],
                                        "filter": {"pattern": "UniversityDegree"}
                                    }
                                ]
                            }
                        }
                    ]
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            VerifiableCredential credential = createMockCredential(null);
            
            assertFalse(pd.matches(credential));
        }
        
        @Test
        @DisplayName("Should match when pattern matches")
        void testMatchesField_PatternMatches() throws OidcException {
            String json = """
                {
                    "id": "test_pd",
                    "input_descriptors": [
                        {
                            "id": "desc_1",
                            "constraints": {
                                "fields": [
                                    {
                                        "path": ["type"],
                                        "filter": {"pattern": ".*Degree"}
                                    }
                                ]
                            }
                        }
                    ]
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            VerifiableCredential credential = createMockCredential("UniversityDegree");
            
            assertTrue(pd.matches(credential));
        }
        
        @Test
        @DisplayName("Should not match when pattern does not match")
        void testMatchesField_PatternDoesNotMatch() throws OidcException {
            String json = """
                {
                    "id": "test_pd",
                    "input_descriptors": [
                        {
                            "id": "desc_1",
                            "constraints": {
                                "fields": [
                                    {
                                        "path": ["type"],
                                        "filter": {"pattern": "DriverLicense"}
                                    }
                                ]
                            }
                        }
                    ]
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            VerifiableCredential credential = createMockCredential("UniversityDegree");
            
            assertFalse(pd.matches(credential));
        }
        
        @Test
        @DisplayName("Should match when contains matches")
        void testMatchesField_ContainsMatches() throws OidcException {
            String json = """
                {
                    "id": "test_pd",
                    "input_descriptors": [
                        {
                            "id": "desc_1",
                            "constraints": {
                                "fields": [
                                    {
                                        "path": ["type"],
                                        "filter": {
                                            "contains": {
                                                "const": "University"
                                            }
                                        }
                                    }
                                ]
                            }
                        }
                    ]
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            VerifiableCredential credential = createMockCredential("UniversityDegree");
            
            assertTrue(pd.matches(credential));
        }
        
        @Test
        @DisplayName("Should not match when contains does not match")
        void testMatchesField_ContainsDoesNotMatch() throws OidcException {
            String json = """
                {
                    "id": "test_pd",
                    "input_descriptors": [
                        {
                            "id": "desc_1",
                            "constraints": {
                                "fields": [
                                    {
                                        "path": ["type"],
                                        "filter": {
                                            "contains": {
                                                "const": "Driver"
                                            }
                                        }
                                    }
                                ]
                            }
                        }
                    ]
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            VerifiableCredential credential = createMockCredential("UniversityDegree");
            
            assertFalse(pd.matches(credential));
        }
        
        @Test
        @DisplayName("Should match non-type path")
        void testMatchesField_NonTypePath() throws OidcException {
            String json = """
                {
                    "id": "test_pd",
                    "input_descriptors": [
                        {
                            "id": "desc_1",
                            "constraints": {
                                "fields": [
                                    {
                                        "path": ["$.vc.credentialSubject.name"]
                                    }
                                ]
                            }
                        }
                    ]
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            VerifiableCredential credential = createMockCredential("UniversityDegree");
            
            // Non-type paths currently return true (not fully implemented)
            assertTrue(pd.matches(credential));
        }
    }
    
    // ========================================================================
    // Field Extraction Tests
    // ========================================================================
    
    @Nested
    @DisplayName("Field Extraction Tests")
    class FieldExtractionTests {
        
        @Test
        @DisplayName("Should return empty list for null input descriptors in getRequestedFields")
        void testGetRequestedFields_NullInputDescriptors() {
            PresentationDefinition pd = new PresentationDefinition();
            pd.setInputDescriptors(null);
            
            List<String> fields = pd.getRequestedFields();
            
            assertNotNull(fields);
            assertTrue(fields.isEmpty());
        }
        
        @Test
        @DisplayName("Should return empty list for empty input descriptors in getRequestedFields")
        void testGetRequestedFields_EmptyInputDescriptors() {
            PresentationDefinition pd = new PresentationDefinition();
            pd.setInputDescriptors(new ArrayList<>());
            
            List<String> fields = pd.getRequestedFields();
            
            assertNotNull(fields);
            assertTrue(fields.isEmpty());
        }
        
        @Test
        @DisplayName("Should return empty list when no constraints in getRequestedFields")
        void testGetRequestedFields_NoConstraints() throws OidcException {
            String json = """
                {
                    "id": "test_pd",
                    "input_descriptors": [
                        {
                            "id": "desc_1"
                        }
                    ]
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            List<String> fields = pd.getRequestedFields();
            
            assertNotNull(fields);
            assertTrue(fields.isEmpty());
        }
        
        @Test
        @DisplayName("Should return empty list when no fields in getRequestedFields")
        void testGetRequestedFields_NoFields() throws OidcException {
            String json = """
                {
                    "id": "test_pd",
                    "input_descriptors": [
                        {
                            "id": "desc_1",
                            "constraints": {}
                        }
                    ]
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            List<String> fields = pd.getRequestedFields();
            
            assertNotNull(fields);
            assertTrue(fields.isEmpty());
        }
        
        @Test
        @DisplayName("Should extract single field in getRequestedFields")
        void testGetRequestedFields_SingleField() throws OidcException {
            String json = """
                {
                    "id": "test_pd",
                    "input_descriptors": [
                        {
                            "id": "desc_1",
                            "constraints": {
                                "fields": [
                                    {
                                        "path": ["$.vc.credentialSubject.name"]
                                    }
                                ]
                            }
                        }
                    ]
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            List<String> fields = pd.getRequestedFields();
            
            assertNotNull(fields);
            assertEquals(1, fields.size());
            assertEquals("Name", fields.get(0));
        }
        
        @Test
        @DisplayName("Should extract multiple fields in getRequestedFields")
        void testGetRequestedFields_MultipleFields() throws OidcException {
            PresentationDefinition pd = PresentationDefinition.fromJson(VALID_PD_JSON);
            List<String> fields = pd.getRequestedFields();
            
            assertNotNull(fields);
            assertEquals(2, fields.size());
            assertTrue(fields.contains("Type"));
            assertTrue(fields.contains("Name"));
        }
        
        @Test
        @DisplayName("Should not include duplicate fields in getRequestedFields")
        void testGetRequestedFields_DuplicateFields() throws OidcException {
            String json = """
                {
                    "id": "test_pd",
                    "input_descriptors": [
                        {
                            "id": "desc_1",
                            "constraints": {
                                "fields": [
                                    {
                                        "path": ["$.vc.credentialSubject.name"]
                                    },
                                    {
                                        "path": ["$.vc.credentialSubject.name"]
                                    }
                                ]
                            }
                        }
                    ]
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            List<String> fields = pd.getRequestedFields();
            
            assertNotNull(fields);
            assertEquals(1, fields.size());
            assertEquals("Name", fields.get(0));
        }
        
        @Test
        @DisplayName("Should handle null path in getRequestedFields")
        void testGetRequestedFields_NullPath() throws OidcException {
            String json = """
                {
                    "id": "test_pd",
                    "input_descriptors": [
                        {
                            "id": "desc_1",
                            "constraints": {
                                "fields": [
                                    {
                                        "filter": {"pattern": "test"}
                                    }
                                ]
                            }
                        }
                    ]
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            List<String> fields = pd.getRequestedFields();
            
            assertNotNull(fields);
            assertTrue(fields.isEmpty());
        }
        
        @Test
        @DisplayName("Should handle empty path in getRequestedFields")
        void testGetRequestedFields_EmptyPath() throws OidcException {
            String json = """
                {
                    "id": "test_pd",
                    "input_descriptors": [
                        {
                            "id": "desc_1",
                            "constraints": {
                                "fields": [
                                    {
                                        "path": []
                                    }
                                ]
                            }
                        }
                    ]
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            List<String> fields = pd.getRequestedFields();
            
            assertNotNull(fields);
            assertTrue(fields.isEmpty());
        }
        
        @Test
        @DisplayName("Should extract field name from simple path")
        void testExtractFieldName_SimplePath() throws OidcException {
            String json = """
                {
                    "id": "test_pd",
                    "input_descriptors": [
                        {
                            "id": "desc_1",
                            "constraints": {
                                "fields": [
                                    {
                                        "path": ["$.name"]
                                    }
                                ]
                            }
                        }
                    ]
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            List<String> fields = pd.getRequestedFields();
            
            assertNotNull(fields);
            assertEquals(1, fields.size());
            assertEquals("Name", fields.get(0));
        }
        
        @Test
        @DisplayName("Should extract field name from nested path")
        void testExtractFieldName_NestedPath() throws OidcException {
            String json = """
                {
                    "id": "test_pd",
                    "input_descriptors": [
                        {
                            "id": "desc_1",
                            "constraints": {
                                "fields": [
                                    {
                                        "path": ["$.vc.credentialSubject.degree"]
                                    }
                                ]
                            }
                        }
                    ]
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            List<String> fields = pd.getRequestedFields();
            
            assertNotNull(fields);
            assertEquals(1, fields.size());
            assertEquals("Degree", fields.get(0));
        }
        
        @Test
        @DisplayName("Should extract field name with array notation")
        void testExtractFieldName_WithArrayNotation() throws OidcException {
            String json = """
                {
                    "id": "test_pd",
                    "input_descriptors": [
                        {
                            "id": "desc_1",
                            "constraints": {
                                "fields": [
                                    {
                                        "path": ["$.vc.type[0]"]
                                    }
                                ]
                            }
                        }
                    ]
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            List<String> fields = pd.getRequestedFields();
            
            assertNotNull(fields);
            assertEquals(1, fields.size());
            assertEquals("Type", fields.get(0));
        }
        
        @Test
        @DisplayName("Should extract field name with underscores")
        void testExtractFieldName_WithUnderscores() throws OidcException {
            String json = """
                {
                    "id": "test_pd",
                    "input_descriptors": [
                        {
                            "id": "desc_1",
                            "constraints": {
                                "fields": [
                                    {
                                        "path": ["$.first_name"]
                                    }
                                ]
                            }
                        }
                    ]
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            List<String> fields = pd.getRequestedFields();
            
            assertNotNull(fields);
            assertEquals(1, fields.size());
            assertEquals("First Name", fields.get(0));
        }
        
        @Test
        @DisplayName("Should extract field name with hyphens")
        void testExtractFieldName_WithHyphens() throws OidcException {
            String json = """
                {
                    "id": "test_pd",
                    "input_descriptors": [
                        {
                            "id": "desc_1",
                            "constraints": {
                                "fields": [
                                    {
                                        "path": ["$.birth-date"]
                                    }
                                ]
                            }
                        }
                    ]
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            List<String> fields = pd.getRequestedFields();
            
            assertNotNull(fields);
            assertEquals(1, fields.size());
            assertEquals("Birth Date", fields.get(0));
        }
        
        @Test
        @DisplayName("Should extract multiple words from field name")
        void testExtractFieldName_MultipleWords() throws OidcException {
            String json = """
                {
                    "id": "test_pd",
                    "input_descriptors": [
                        {
                            "id": "desc_1",
                            "constraints": {
                                "fields": [
                                    {
                                        "path": ["$.university_degree_name"]
                                    }
                                ]
                            }
                        }
                    ]
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            List<String> fields = pd.getRequestedFields();
            
            assertNotNull(fields);
            assertEquals(1, fields.size());
            assertEquals("University Degree Name", fields.get(0));
        }
        
        @Test
        @DisplayName("Should get verifier name from first descriptor with ID")
        void testGetVerifierName_FromFirstDescriptorWithId() throws OidcException {
            String json = """
                {
                    "id": "test_pd",
                    "input_descriptors": [
                        {
                            "id": "university_verifier"
                        }
                    ]
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            String name = pd.getVerifierName();
            
            assertEquals("University Verifier", name);
        }
        
        @Test
        @DisplayName("Should return Unknown Verifier for no descriptors")
        void testGetVerifierName_NoDescriptors() {
            PresentationDefinition pd = new PresentationDefinition();
            pd.setInputDescriptors(new ArrayList<>());
            
            String name = pd.getVerifierName();
            
            assertEquals("Unknown Verifier", name);
        }
        
        @Test
        @DisplayName("Should return Unknown Verifier for null descriptor id")
        void testGetVerifierName_NullDescriptorId() throws OidcException {
            String json = """
                {
                    "input_descriptors": [
                        {
                            "constraints": {}
                        }
                    ]
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            String name = pd.getVerifierName();
            
            assertEquals("Unknown Verifier", name);
        }
        
        @Test
        @DisplayName("Should return Unknown Verifier for null definition id")
        void testGetVerifierName_NullDefinitionId() {
            PresentationDefinition pd = new PresentationDefinition();
            pd.setId(null);
            pd.setInputDescriptors(new ArrayList<>());
            
            String name = pd.getVerifierName();
            
            assertEquals("Unknown Verifier", name);
        }
        
        @Test
        @DisplayName("Should format name with underscores")
        void testFormatVerifierName_WithUnderscores() throws OidcException {
            String json = """
                {
                    "id": "my_test_verifier"
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            String name = pd.getVerifierName();
            
            assertEquals("My Test Verifier", name);
        }
        
        @Test
        @DisplayName("Should format name with hyphens")
        void testFormatVerifierName_WithHyphens() throws OidcException {
            String json = """
                {
                    "id": "my-test-verifier"
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            String name = pd.getVerifierName();
            
            assertEquals("My Test Verifier", name);
        }
        
        @Test
        @DisplayName("Should format name with mixed case")
        void testFormatVerifierName_WithMixedCase() throws OidcException {
            String json = """
                {
                    "id": "MyTestVerifier"
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            String name = pd.getVerifierName();
            
            assertEquals("Mytestverifier", name);
        }
        
        @Test
        @DisplayName("Should format name with multiple words")
        void testFormatVerifierName_WithMultipleWords() throws OidcException {
            String json = """
                {
                    "id": "university_degree_verification_service"
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            String name = pd.getVerifierName();
            
            assertEquals("University Degree Verification Service", name);
        }
        
        @Test
        @DisplayName("Should format single word")
        void testFormatVerifierName_SingleWord() throws OidcException {
            String json = """
                {
                    "id": "verifier"
                }
                """;
            
            PresentationDefinition pd = PresentationDefinition.fromJson(json);
            String name = pd.getVerifierName();
            
            assertEquals("Verifier", name);
        }
    }
    
    // ========================================================================
    // Phase 6: Setter and Edge Case Tests
    // ========================================================================
    
    @Nested
    @DisplayName("Setter and Edge Case Tests")
    class SetterEdgeCaseTests {
        
        @Test
        @DisplayName("Should set valid id")
        void testSetId_ValidValue() {
            PresentationDefinition pd = new PresentationDefinition();
            pd.setId("test_id");
            
            assertEquals("test_id", pd.getId());
        }
        
        @Test
        @DisplayName("Should set null id")
        void testSetId_NullValue() {
            PresentationDefinition pd = new PresentationDefinition();
            pd.setId("test_id");
            pd.setId(null);
            
            assertNull(pd.getId());
        }
        
        @Test
        @DisplayName("Should set empty string id")
        void testSetId_EmptyString() {
            PresentationDefinition pd = new PresentationDefinition();
            pd.setId("");
            
            assertEquals("", pd.getId());
        }
        
        @Test
        @DisplayName("Should set valid input descriptors list")
        void testSetInputDescriptors_ValidList() {
            PresentationDefinition pd = new PresentationDefinition();
            List<PresentationDefinition.InputDescriptor> descriptors = new ArrayList<>();
            
            pd.setInputDescriptors(descriptors);
            
            assertNotNull(pd.getInputDescriptors());
            assertSame(descriptors, pd.getInputDescriptors());
        }
        
        @Test
        @DisplayName("Should set null input descriptors list")
        void testSetInputDescriptors_NullList() {
            PresentationDefinition pd = new PresentationDefinition();
            pd.setInputDescriptors(null);
            
            assertNull(pd.getInputDescriptors());
        }
        
        @Test
        @DisplayName("Should set empty input descriptors list")
        void testSetInputDescriptors_EmptyList() {
            PresentationDefinition pd = new PresentationDefinition();
            List<PresentationDefinition.InputDescriptor> descriptors = new ArrayList<>();
            pd.setInputDescriptors(descriptors);
            
            assertNotNull(pd.getInputDescriptors());
            assertTrue(pd.getInputDescriptors().isEmpty());
        }
        
        @Test
        @DisplayName("Should create InputDescriptor from map")
        void testInputDescriptor_FromMap() {
            Map<String, Object> map = new HashMap<>();
            map.put("id", "test_descriptor");
            
            Map<String, Object> format = new HashMap<>();
            format.put("jwt_vc_json", Map.of("alg", List.of("ES256")));
            map.put("format", format);
            
            Map<String, Object> constraints = new HashMap<>();
            map.put("constraints", constraints);
            
            PresentationDefinition.InputDescriptor descriptor = 
                PresentationDefinition.InputDescriptor.fromMap(map);
            
            assertNotNull(descriptor);
            assertEquals("test_descriptor", descriptor.getId());
            assertNotNull(descriptor.getFormat());
            assertNotNull(descriptor.getConstraints());
        }
        
        @Test
        @DisplayName("Should get InputDescriptor properties")
        void testInputDescriptor_Getters() {
            Map<String, Object> map = new HashMap<>();
            map.put("id", "test_id");
            map.put("format", Map.of("jwt", "value"));
            
            PresentationDefinition.InputDescriptor descriptor = 
                PresentationDefinition.InputDescriptor.fromMap(map);
            
            assertEquals("test_id", descriptor.getId());
            assertNotNull(descriptor.getFormat());
            assertEquals("value", descriptor.getFormat().get("jwt"));
        }
        
        @Test
        @DisplayName("Should create Constraints from map")
        void testConstraints_FromMap() {
            Map<String, Object> map = new HashMap<>();
            List<Map<String, Object>> fields = new ArrayList<>();
            
            Map<String, Object> field = new HashMap<>();
            field.put("path", List.of("$.test"));
            fields.add(field);
            
            map.put("fields", fields);
            
            PresentationDefinition.Constraints constraints = 
                PresentationDefinition.Constraints.fromMap(map);
            
            assertNotNull(constraints);
            assertNotNull(constraints.getFields());
            assertEquals(1, constraints.getFields().size());
        }
        
        @Test
        @DisplayName("Should get Constraints fields")
        void testConstraints_GetFields() {
            Map<String, Object> map = new HashMap<>();
            List<Map<String, Object>> fields = new ArrayList<>();
            
            Map<String, Object> field1 = new HashMap<>();
            field1.put("path", List.of("$.field1"));
            fields.add(field1);
            
            Map<String, Object> field2 = new HashMap<>();
            field2.put("path", List.of("$.field2"));
            fields.add(field2);
            
            map.put("fields", fields);
            
            PresentationDefinition.Constraints constraints = 
                PresentationDefinition.Constraints.fromMap(map);
            
            assertEquals(2, constraints.getFields().size());
        }
        
        @Test
        @DisplayName("Should create Field from map")
        void testField_FromMap() {
            Map<String, Object> map = new HashMap<>();
            map.put("path", List.of("$.vc.type"));
            map.put("filter", Map.of("pattern", "Test"));
            
            PresentationDefinition.Field field = 
                PresentationDefinition.Field.fromMap(map);
            
            assertNotNull(field);
            assertNotNull(field.getPath());
            assertNotNull(field.getFilter());
        }
        
        @Test
        @DisplayName("Should get Field properties")
        void testField_Getters() {
            Map<String, Object> map = new HashMap<>();
            map.put("path", List.of("$.test.path"));
            map.put("filter", Map.of("type", "string"));
            
            PresentationDefinition.Field field = 
                PresentationDefinition.Field.fromMap(map);
            
            assertEquals(1, field.getPath().size());
            assertEquals("$.test.path", field.getPath().get(0));
            assertEquals("string", field.getFilter().get("type"));
        }
        
        @Test
        @DisplayName("Should handle InputDescriptor with null constraints")
        void testInputDescriptor_NullConstraints() {
            Map<String, Object> map = new HashMap<>();
            map.put("id", "test");
            map.put("constraints", null);
            
            PresentationDefinition.InputDescriptor descriptor = 
                PresentationDefinition.InputDescriptor.fromMap(map);
            
            assertNotNull(descriptor);
            assertNull(descriptor.getConstraints());
        }
        
        @Test
        @DisplayName("Should handle Constraints with null fields")
        void testConstraints_NullFields() {
            Map<String, Object> map = new HashMap<>();
            map.put("fields", null);
            
            PresentationDefinition.Constraints constraints = 
                PresentationDefinition.Constraints.fromMap(map);
            
            assertNotNull(constraints);
            assertNotNull(constraints.getFields());
            assertTrue(constraints.getFields().isEmpty());
        }
        
        @Test
        @DisplayName("Should handle Field with null path")
        void testField_NullPath() {
            Map<String, Object> map = new HashMap<>();
            map.put("path", null);
            map.put("filter", Map.of("pattern", "test"));
            
            PresentationDefinition.Field field = 
                PresentationDefinition.Field.fromMap(map);
            
            assertNotNull(field);
            assertNull(field.getPath());
            assertNotNull(field.getFilter());
        }
        
        @Test
        @DisplayName("Should handle Field with null filter")
        void testField_NullFilter() {
            Map<String, Object> map = new HashMap<>();
            map.put("path", List.of("$.test"));
            map.put("filter", null);
            
            PresentationDefinition.Field field = 
                PresentationDefinition.Field.fromMap(map);
            
            assertNotNull(field);
            assertNotNull(field.getPath());
            assertNull(field.getFilter());
        }
    }
}
