/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

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
}

// Made with Bob
