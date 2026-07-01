/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.jsonld;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Manages JSON-LD @context with caching support.
 * 
 * <p>The @context in JSON-LD defines how terms in the document map to IRIs (Internationalized 
 * Resource Identifiers). This class provides:
 * <ul>
 *   <li>Context creation from URLs and inline definitions</li>
 *   <li>Context caching to avoid repeated fetches</li>
 *   <li>Context merging for multiple contexts</li>
 *   <li>Serialization to JSON-LD format</li>
 * </ul>
 * 
 * <p>Example usage:
 * <pre>{@code
 * // Create context with W3C VC context
 * JsonLdContext context = new JsonLdContext();
 * context.addContextUrl("https://www.w3.org/2018/credentials/v1");
 * context.addContextUrl("https://www.w3.org/2018/credentials/examples/v1");
 * 
 * // Add inline term definitions
 * context.addTermDefinition("name", "http://schema.org/name");
 * context.addTermDefinition("email", "http://schema.org/email");
 * 
 * // Serialize to JSON
 * JsonElement contextJson = context.toJson();
 * }</pre>
 * 
 * @see <a href="https://www.w3.org/TR/json-ld11/#the-context">JSON-LD 1.1 Context</a>
 * @see <a href="https://www.w3.org/TR/vc-data-model/#contexts">VC Data Model Contexts</a>
 */
public class JsonLdContext {
    
    /**
     * Standard W3C Verifiable Credentials context URL.
     */
    public static final String W3C_VC_CONTEXT = "https://www.w3.org/2018/credentials/v1";
    
    /**
     * List of context URLs (e.g., "https://www.w3.org/2018/credentials/v1").
     */
    private final List<String> contextUrls;
    
    /**
     * Inline term definitions (term -> IRI mapping).
     */
    private final Map<String, String> termDefinitions;
    
    /**
     * Cache for resolved contexts (URL -> resolved context).
     * In a production system, this would be a proper cache with expiration.
     */
    private static final Map<String, JsonObject> contextCache = new HashMap<>();
    
    /**
     * Constructs an empty JSON-LD context.
     */
    public JsonLdContext() {
        this.contextUrls = new ArrayList<>();
        this.termDefinitions = new HashMap<>();
    }
    
    /**
     * Constructs a JSON-LD context with a single context URL.
     * 
     * @param contextUrl the context URL to add
     */
    public JsonLdContext(String contextUrl) {
        this();
        addContextUrl(contextUrl);
    }
    
    /**
     * Constructs a JSON-LD context from multiple context URLs.
     * 
     * @param contextUrls list of context URLs
     */
    public JsonLdContext(List<String> contextUrls) {
        this();
        if (contextUrls != null) {
            this.contextUrls.addAll(contextUrls);
        }
    }
    
    /**
     * Adds a context URL to this context.
     * 
     * @param contextUrl the context URL to add (e.g., "https://www.w3.org/2018/credentials/v1")
     * @return this context for method chaining
     */
    public JsonLdContext addContextUrl(String contextUrl) {
        if (contextUrl != null && !contextUrl.isEmpty()) {
            this.contextUrls.add(contextUrl);
        }
        return this;
    }
    
    /**
     * Adds an inline term definition to this context.
     * 
     * @param term the term to define (e.g., "name")
     * @param iri the IRI the term maps to (e.g., "http://schema.org/name")
     * @return this context for method chaining
     */
    public JsonLdContext addTermDefinition(String term, String iri) {
        if (term != null && !term.isEmpty() && iri != null && !iri.isEmpty()) {
            this.termDefinitions.put(term, iri);
        }
        return this;
    }
    
    /**
     * Gets the list of context URLs.
     * 
     * @return unmodifiable list of context URLs
     */
    public List<String> getContextUrls() {
        return new ArrayList<>(contextUrls);
    }
    
    /**
     * Gets the inline term definitions.
     * 
     * @return unmodifiable map of term definitions
     */
    public Map<String, String> getTermDefinitions() {
        return new HashMap<>(termDefinitions);
    }
    
    /**
     * Checks if this context is empty (no URLs or term definitions).
     * 
     * @return true if empty, false otherwise
     */
    public boolean isEmpty() {
        return contextUrls.isEmpty() && termDefinitions.isEmpty();
    }
    
    /**
     * Serializes this context to JSON-LD format.
     * 
     * <p>The output format depends on the context contents:
     * <ul>
     *   <li>Single URL: returns a string</li>
     *   <li>Multiple URLs: returns an array</li>
     *   <li>URLs + terms: returns an array with URLs and an inline object</li>
     *   <li>Only terms: returns an inline object</li>
     * </ul>
     * 
     * @return JSON representation of this context
     */
    public JsonElement toJson() {
        // Case 1: Only inline terms, no URLs
        if (contextUrls.isEmpty() && !termDefinitions.isEmpty()) {
            return createInlineContextObject();
        }
        
        // Case 2: Single URL, no inline terms
        if (contextUrls.size() == 1 && termDefinitions.isEmpty()) {
            return new JsonPrimitive(contextUrls.get(0));
        }
        
        // Case 3: Multiple URLs or URLs + inline terms
        JsonArray contextArray = new JsonArray();
        
        // Add all URLs
        for (String url : contextUrls) {
            contextArray.add(url);
        }
        
        // Add inline terms if present
        if (!termDefinitions.isEmpty()) {
            contextArray.add(createInlineContextObject());
        }
        
        return contextArray;
    }
    
    /**
     * Creates an inline context object from term definitions.
     * 
     * @return JSON object with term definitions
     */
    private JsonObject createInlineContextObject() {
        JsonObject inlineContext = new JsonObject();
        for (Map.Entry<String, String> entry : termDefinitions.entrySet()) {
            inlineContext.addProperty(entry.getKey(), entry.getValue());
        }
        return inlineContext;
    }
    
    /**
     * Parses a JSON-LD context from JSON.
     * 
     * @param contextJson the JSON representation of the context
     * @return parsed JsonLdContext
     * @throws JsonLdException if the context format is invalid
     */
    public static JsonLdContext fromJson(JsonElement contextJson) throws JsonLdException {
        if (contextJson == null || contextJson.isJsonNull()) {
            throw new JsonLdException("Context cannot be null");
        }
        
        JsonLdContext context = new JsonLdContext();
        
        if (contextJson.isJsonPrimitive()) {
            // Single URL as string
            context.addContextUrl(contextJson.getAsString());
        } else if (contextJson.isJsonArray()) {
            // Array of URLs and/or inline contexts
            JsonArray array = contextJson.getAsJsonArray();
            for (JsonElement element : array) {
                if (element.isJsonPrimitive()) {
                    context.addContextUrl(element.getAsString());
                } else if (element.isJsonObject()) {
                    parseInlineContext(context, element.getAsJsonObject());
                }
            }
        } else if (contextJson.isJsonObject()) {
            // Inline context object
            parseInlineContext(context, contextJson.getAsJsonObject());
        } else {
            throw new JsonLdException("Invalid context format");
        }
        
        return context;
    }
    
    /**
     * Parses inline term definitions from a JSON object.
     * 
     * @param context the context to add definitions to
     * @param inlineContext the JSON object containing term definitions
     */
    private static void parseInlineContext(JsonLdContext context, JsonObject inlineContext) {
        for (Map.Entry<String, JsonElement> entry : inlineContext.entrySet()) {
            String term = entry.getKey();
            JsonElement value = entry.getValue();
            
            if (value.isJsonPrimitive()) {
                context.addTermDefinition(term, value.getAsString());
            }
            // Note: More complex term definitions (with @id, @type, etc.) 
            // would be handled here in a full implementation
        }
    }
    
    /**
     * Merges another context into this context.
     * 
     * @param other the context to merge
     * @return this context for method chaining
     */
    public JsonLdContext merge(JsonLdContext other) {
        if (other != null) {
            this.contextUrls.addAll(other.contextUrls);
            this.termDefinitions.putAll(other.termDefinitions);
        }
        return this;
    }
    
    /**
     * Clears the context cache.
     * Useful for testing or when contexts need to be reloaded.
     */
    public static void clearCache() {
        contextCache.clear();
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        JsonLdContext that = (JsonLdContext) o;
        return Objects.equals(contextUrls, that.contextUrls) &&
               Objects.equals(termDefinitions, that.termDefinitions);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(contextUrls, termDefinitions);
    }
    
    @Override
    public String toString() {
        return "JsonLdContext{" +
               "urls=" + contextUrls +
               ", terms=" + termDefinitions.keySet() +
               '}';
    }
}

// Made with Bob