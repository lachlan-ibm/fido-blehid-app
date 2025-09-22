/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.util;

import java.io.IOException;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Utility class for JSON encoding and decoding operations.
 * Uses Jackson for JSON processing.
 */
public class JsonUtils {
    
    // Shared ObjectMapper instance with pretty printing enabled
    private static final ObjectMapper mapper = new ObjectMapper();
    
    /**
     * Encodes an object to a JSON string.
     * 
     * @param o The object to encode (can be a Map, POJO, or other compatible types)
     * @return A JSON string representation of the object, or empty string if encoding fails
     */
    public static String encode(Object o) {
        if (o == null) {
            return null;
        }
        
        try {
            return mapper.writeValueAsString(o);
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * Decodes a JSON string into an object.
     * 
     * @param s The JSON string to decode
     * @param clazz The expected class of the decoded object (Map, List, POJO, etc.)
     * @return The decoded object (typically a Map or List), or null if decoding fails
     */
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public static Object decode(String s, Class clazz) {
        if (s == null || s.isEmpty()) {
            return null;
        }
        
        try {
            return mapper.readValue(s, clazz);
        } catch (IOException e) {
            return null;
        }
    }
}

// Made with Bob
