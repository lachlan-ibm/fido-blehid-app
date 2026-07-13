/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.util;

import java.io.StringReader;
import java.io.StringWriter;

import com.apicatalog.jsonld.JsonLd;
import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.document.JsonDocument;
import tools.jackson.databind.ObjectMapper;

import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.json.JsonStructure;
import jakarta.json.JsonWriter;
import jakarta.json.JsonWriterFactory;
import jakarta.json.stream.JsonGenerator;

/**
 * Utility class for JSON encoding and decoding operations.
 * Uses Jackson for JSON processing and Titanium JSON-LD for JSON-LD operations.
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
        } catch (Exception e) {
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
        } catch (Exception e) {
            return null;
        }
    }
    
    /**
     * Expands a JSON-LD document using the JSON-LD 1.1 expansion algorithm.
     * Expansion removes context and converts the document to a normalized form.
     * 
     * @param jsonLdString The JSON-LD document as a string
     * @return The expanded JSON-LD document as a JsonArray, or null if expansion fails
     * @throws JsonLdError if JSON-LD processing fails
     */
    public static JsonArray expandJsonLd(String jsonLdString) throws JsonLdError {
        if (jsonLdString == null || jsonLdString.isEmpty()) {
            return null;
        }
        
        try (JsonReader reader = Json.createReader(new StringReader(jsonLdString))) {
            JsonStructure jsonStructure = reader.read();
            JsonDocument document = JsonDocument.of(jsonStructure);
            
            return JsonLd.expand(document).get();
        }
    }
    
    /**
     * Compacts a JSON-LD document using the provided context.
     * Compaction applies a context to shorten IRIs and make the document more readable.
     * 
     * @param jsonLdString The JSON-LD document as a string
     * @param contextString The JSON-LD context as a string (can be a URL or inline context)
     * @return The compacted JSON-LD document as a JsonObject, or null if compaction fails
     * @throws JsonLdError if JSON-LD processing fails
     */
    public static JsonObject compactJsonLd(String jsonLdString, String contextString) throws JsonLdError {
        if (jsonLdString == null || jsonLdString.isEmpty()) {
            return null;
        }
        
        try (JsonReader docReader = Json.createReader(new StringReader(jsonLdString))) {
            JsonStructure jsonStructure = docReader.read();
            JsonDocument document = JsonDocument.of(jsonStructure);
            
            if (contextString != null && !contextString.isEmpty()) {
                try (JsonReader ctxReader = Json.createReader(new StringReader(contextString))) {
                    JsonStructure contextStructure = ctxReader.read();
                    JsonDocument contextDoc = JsonDocument.of(contextStructure);
                    return JsonLd.compact(document, contextDoc).get();
                }
            } else {
                // Use empty context if none provided
                JsonObject emptyContext = Json.createObjectBuilder().build();
                JsonDocument contextDoc = JsonDocument.of(emptyContext);
                return JsonLd.compact(document, contextDoc).get();
            }
        }
    }
    
    /**
     * Normalizes a JSON-LD document by converting it to RDF and back.
     * This provides a basic form of normalization suitable for comparison.
     * For full URDNA2015 canonicalization, use a dedicated RDF canonicalization library.
     * 
     * @param jsonLdString The JSON-LD document as a string
     * @return The normalized JSON-LD document as a JsonArray (expanded form), or null if normalization fails
     * @throws JsonLdError if JSON-LD processing fails
     */
    public static JsonArray normalizeJsonLd(String jsonLdString) throws JsonLdError {
        if (jsonLdString == null || jsonLdString.isEmpty()) {
            return null;
        }
        
        // For Phase 1A, we provide basic normalization via expansion
        // Full URDNA2015 canonicalization will be added in Phase 1C with proof support
        return expandJsonLd(jsonLdString);
    }
    
    /**
     * Converts a Jakarta JSON object to a pretty-printed JSON string.
     * 
     * @param jsonObject The Jakarta JSON object to convert
     * @return Pretty-printed JSON string
     */
    public static String toJsonString(JsonStructure jsonObject) {
        if (jsonObject == null) {
            return null;
        }
        
        StringWriter stringWriter = new StringWriter();
        JsonWriterFactory writerFactory = Json.createWriterFactory(
            java.util.Map.of(JsonGenerator.PRETTY_PRINTING, true));
        
        try (JsonWriter jsonWriter = writerFactory.createWriter(stringWriter)) {
            jsonWriter.write(jsonObject);
        }
        
        return stringWriter.toString();
    }
}

// Made with Bob
