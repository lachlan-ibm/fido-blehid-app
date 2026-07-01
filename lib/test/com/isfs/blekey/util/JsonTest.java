/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.apicatalog.jsonld.JsonLdError;

import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.stream.JsonParsingException;

/**
 * Test cases for the Json utility class.
 */
public class JsonTest {

    @Test
    public void testEncodeMap() {
        Map<String, Object> testMap = new HashMap<>();
        testMap.put("name", "John Doe");
        testMap.put("age", 30);
        testMap.put("isActive", true);
        
        String json = JsonUtils.encode(testMap);
        System.err.println("serialized: " + json);
        
        // Verify the JSON string contains the expected values
        assertTrue(json.contains("\"name\":\"John Doe\""));
        assertTrue(json.contains("\"age\":30"));
        assertTrue(json.contains("\"isActive\":true"));
    }
    
    @Test
    public void testEncodeNestedMap() {
        Map<String, Object> addressMap = new HashMap<>();
        addressMap.put("street", "123 Main St");
        addressMap.put("city", "Anytown");
        
        Map<String, Object> testMap = new HashMap<>();
        testMap.put("name", "Jane Smith");
        testMap.put("address", addressMap);
        
        String json = JsonUtils.encode(testMap);
        
        // Verify the JSON string contains the expected values
        assertTrue(json.contains("\"name\":\"Jane Smith\""));
        assertTrue(json.contains("\"street\":\"123 Main St\""));
        assertTrue(json.contains("\"city\":\"Anytown\""));
    }
    
    @Test
    public void testDecodeSimpleJson() {
        String json = "{\"name\":\"John Doe\",\"age\":30,\"isActive\":true}";
        
        Object result = JsonUtils.decode(json, HashMap.class);
        
        assertNotNull(result);
        assertTrue(result instanceof Map);
        
        @SuppressWarnings("unchecked")
        Map<String, Object> resultMap = (Map<String, Object>) result;
        
        assertEquals("John Doe", resultMap.get("name"));
        assertEquals(30, resultMap.get("age"));
        assertEquals(true, resultMap.get("isActive"));
    }
    
    @Test
    public void testDecodeNestedJson() {
        String json = "{\"name\":\"Jane Smith\",\"address\":{\"street\":\"123 Main St\",\"city\":\"Anytown\"}}";
        
        Object result = JsonUtils.decode(json, HashMap.class);
        
        assertNotNull(result);
        assertTrue(result instanceof Map);
        
        @SuppressWarnings("unchecked")
        Map<String, Object> resultMap = (Map<String, Object>) result;
        
        assertEquals("Jane Smith", resultMap.get("name"));
        
        @SuppressWarnings("unchecked")
        Map<String, Object> addressMap = (Map<String, Object>) resultMap.get("address");
        
        assertNotNull(addressMap);
        assertEquals("123 Main St", addressMap.get("street"));
        assertEquals("Anytown", addressMap.get("city"));
    }
    
    @Test
    public void testEncodeNull() {
        String json = JsonUtils.encode(null);
        assertEquals(null, json);
    }
    
    @Test
    public void testDecodeNull() {
        Object result = JsonUtils.decode(null, Object.class);
        assertEquals(null, result);
    }
    
    @Test
    public void testDecodeEmptyString() {
        Object result = JsonUtils.decode("", String.class);
        assertEquals(null, result);
    }
    
    // ========== JSON-LD Tests ==========
    
    @Test
    public void testExpandJsonLd() throws JsonLdError {
        // Test JSON-LD expansion with a simple credential
        String jsonLd = "{"
            + "\"@context\": \"https://www.w3.org/2018/credentials/v1\","
            + "\"type\": \"VerifiableCredential\","
            + "\"issuer\": \"did:example:123\","
            + "\"credentialSubject\": {"
            + "  \"id\": \"did:example:456\","
            + "  \"name\": \"Alice\""
            + "}"
            + "}";
        
        Object expanded = JsonUtils.expandJsonLd(jsonLd);
        
        assertNotNull(expanded);
        assertTrue(expanded instanceof List);
        
        @SuppressWarnings("unchecked")
        List<Object> expandedList = (List<Object>) expanded;
        assertTrue(expandedList.size() > 0);
        
        System.err.println("Expanded JSON-LD: " + JsonUtils.encode(expanded));
    }
    
    @Test
    public void testExpandJsonLdWithNull() throws JsonLdError {
        Object result = JsonUtils.expandJsonLd(null);
        assertNull(result);
    }
    
    @Test
    public void testExpandJsonLdWithEmptyString() throws JsonLdError {
        Object result = JsonUtils.expandJsonLd("");
        assertNull(result);
    }
    
    @Test
    public void testExpandJsonLdWithInvalidJson() {
        String invalidJson = "{invalid json}";
        
        // Invalid JSON throws JsonParsingException before JSON-LD processing
        assertThrows(JsonParsingException.class, () -> {
            JsonUtils.expandJsonLd(invalidJson);
        });
    }
    
    @Test
    public void testCompactJsonLd() throws JsonLdError {
        // Test JSON-LD compaction with expanded form
        String expandedJsonLd = "["
            + "{"
            + "  \"http://www.w3.org/1999/02/22-rdf-syntax-ns#type\": ["
            + "    {\"@id\": \"https://www.w3.org/2018/credentials#VerifiableCredential\"}"
            + "  ],"
            + "  \"https://www.w3.org/2018/credentials#issuer\": ["
            + "    {\"@id\": \"did:example:123\"}"
            + "  ]"
            + "}"
            + "]";
        
        String context = "{"
            + "\"@context\": {"
            + "  \"@vocab\": \"https://www.w3.org/2018/credentials#\","
            + "  \"type\": \"@type\","
            + "  \"id\": \"@id\""
            + "}"
            + "}";
        
        Object compacted = JsonUtils.compactJsonLd(expandedJsonLd, context);
        
        assertNotNull(compacted);
        assertTrue(compacted instanceof Map);
        
        System.err.println("Compacted JSON-LD: " + JsonUtils.encode(compacted));
    }
    
    @Test
    public void testCompactJsonLdWithNull() throws JsonLdError {
        Object result = JsonUtils.compactJsonLd(null, "{}");
        assertNull(result);
    }
    
    @Test
    public void testCompactJsonLdWithEmptyString() throws JsonLdError {
        Object result = JsonUtils.compactJsonLd("", "{}");
        assertNull(result);
    }
    
    @Test
    public void testCompactJsonLdWithNullContext() throws JsonLdError {
        String jsonLd = "[{\"@id\": \"did:example:123\"}]";
        
        Object compacted = JsonUtils.compactJsonLd(jsonLd, null);
        
        assertNotNull(compacted);
        System.err.println("Compacted with null context: " + JsonUtils.encode(compacted));
    }
    
    @Test
    public void testCompactJsonLdWithInvalidJson() {
        String invalidJson = "{invalid json}";
        
        // Invalid JSON throws JsonParsingException before JSON-LD processing
        assertThrows(JsonParsingException.class, () -> {
            JsonUtils.compactJsonLd(invalidJson, "{}");
        });
    }
    
    @Test
    public void testNormalizeJsonLd() throws JsonLdError {
        // Test JSON-LD normalization (URDNA2015 canonicalization)
        String jsonLd = "{"
            + "\"@context\": \"https://www.w3.org/2018/credentials/v1\","
            + "\"type\": \"VerifiableCredential\","
            + "\"issuer\": \"did:example:123\","
            + "\"credentialSubject\": {"
            + "  \"id\": \"did:example:456\","
            + "  \"name\": \"Alice\""
            + "}"
            + "}";
        
        JsonArray normalized = JsonUtils.normalizeJsonLd(jsonLd);
        
        assertNotNull(normalized);
        assertTrue(normalized instanceof JsonArray);
        // Normalized output is in expanded form
        assertTrue(normalized.size() > 0);
        
        System.err.println("Normalized JSON-LD (expanded form):");
        System.err.println(JsonUtils.toJsonString(normalized));
    }
    
    @Test
    public void testNormalizeJsonLdWithNull() throws JsonLdError {
        JsonArray result = JsonUtils.normalizeJsonLd(null);
        assertNull(result);
    }
    
    @Test
    public void testNormalizeJsonLdWithEmptyString() throws JsonLdError {
        JsonArray result = JsonUtils.normalizeJsonLd("");
        assertNull(result);
    }
    
    @Test
    public void testNormalizeJsonLdWithInvalidJson() {
        String invalidJson = "{invalid json}";
        
        // Invalid JSON throws JsonParsingException before JSON-LD processing
        assertThrows(JsonParsingException.class, () -> {
            JsonUtils.normalizeJsonLd(invalidJson);
        });
    }
    
    @Test
    public void testJsonLdRoundTrip() throws JsonLdError {
        // Test expand -> compact round trip
        String originalJsonLd = "{"
            + "\"@context\": \"https://www.w3.org/2018/credentials/v1\","
            + "\"type\": \"VerifiableCredential\","
            + "\"issuer\": \"did:example:123\""
            + "}";
        
        // Expand
        JsonArray expanded = JsonUtils.expandJsonLd(originalJsonLd);
        assertNotNull(expanded);
        
        // Convert expanded to JSON string for compaction
        String expandedJson = JsonUtils.toJsonString(expanded);
        
        // Compact back
        String context = "{\"@context\": \"https://www.w3.org/2018/credentials/v1\"}";
        JsonObject compacted = JsonUtils.compactJsonLd(expandedJson, context);
        
        assertNotNull(compacted);
        assertTrue(compacted instanceof JsonObject);
        
        // Verify the type is preserved
        assertTrue(compacted.containsKey("type") || compacted.containsKey("@type"));
        
        System.err.println("Round-trip result: " + JsonUtils.toJsonString(compacted));
    }
}

// Made with Bob
