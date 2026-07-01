/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.jsonld;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Represents the credentialSubject of a Verifiable Credential.
 * 
 * <p>The credentialSubject contains claims about the subject of the credential.
 * This class provides a flexible container for arbitrary claims while ensuring
 * proper JSON-LD serialization.
 * 
 * <p>Example usage:
 * <pre>{@code
 * // Create credential subject with claims
 * CredentialSubject subject = new CredentialSubject("did:example:123");
 * subject.addClaim("name", "Alice Smith");
 * subject.addClaim("email", "alice@example.com");
 * subject.addClaim("age", 30);
 * 
 * // Serialize to JSON
 * JsonObject subjectJson = subject.toJson();
 * }</pre>
 * 
 * @see <a href="https://www.w3.org/TR/vc-data-model/#credential-subject">VC Data Model - Credential Subject</a>
 */
public class CredentialSubject {
    
    /**
     * The identifier of the subject (typically a DID).
     * This is the "id" field in the credentialSubject.
     */
    private String id;
    
    /**
     * Claims about the subject.
     * Maps claim names to their values.
     */
    private final Map<String, Object> claims;
    
    /**
     * Constructs an empty credential subject.
     */
    public CredentialSubject() {
        this.claims = new HashMap<>();
    }
    
    /**
     * Constructs a credential subject with the specified ID.
     * 
     * @param id the subject identifier (typically a DID like "did:example:123")
     */
    public CredentialSubject(String id) {
        this();
        this.id = id;
    }
    
    /**
     * Gets the subject identifier.
     * 
     * @return the subject ID, or null if not set
     */
    public String getId() {
        return id;
    }
    
    /**
     * Sets the subject identifier.
     * 
     * @param id the subject identifier (typically a DID)
     * @return this subject for method chaining
     */
    public CredentialSubject setId(String id) {
        this.id = id;
        return this;
    }
    
    /**
     * Adds a claim about the subject.
     * 
     * @param name the claim name (e.g., "name", "email")
     * @param value the claim value (String, Number, Boolean, or JsonElement)
     * @return this subject for method chaining
     * @throws IllegalArgumentException if name is null or empty
     */
    public CredentialSubject addClaim(String name, Object value) {
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("Claim name cannot be null or empty");
        }
        if (value != null) {
            claims.put(name, value);
        }
        return this;
    }
    
    /**
     * Gets a claim value.
     * 
     * @param name the claim name
     * @return the claim value, or null if not present
     */
    public Object getClaim(String name) {
        return claims.get(name);
    }
    
    /**
     * Gets a claim value as a String.
     * 
     * @param name the claim name
     * @return the claim value as String, or null if not present or not a String
     */
    public String getClaimAsString(String name) {
        Object value = claims.get(name);
        return value instanceof String ? (String) value : null;
    }
    
    /**
     * Gets a claim value as an Integer.
     * 
     * @param name the claim name
     * @return the claim value as Integer, or null if not present or not a Number
     */
    public Integer getClaimAsInteger(String name) {
        Object value = claims.get(name);
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        return null;
    }
    
    /**
     * Gets a claim value as a Boolean.
     * 
     * @param name the claim name
     * @return the claim value as Boolean, or null if not present or not a Boolean
     */
    public Boolean getClaimAsBoolean(String name) {
        Object value = claims.get(name);
        return value instanceof Boolean ? (Boolean) value : null;
    }
    
    /**
     * Checks if a claim exists.
     * 
     * @param name the claim name
     * @return true if the claim exists, false otherwise
     */
    public boolean hasClaim(String name) {
        return claims.containsKey(name);
    }
    
    /**
     * Removes a claim.
     * 
     * @param name the claim name to remove
     * @return the previous value associated with the claim, or null
     */
    public Object removeClaim(String name) {
        return claims.remove(name);
    }
    
    /**
     * Gets all claim names.
     * 
     * @return set of claim names
     */
    public Set<String> getClaimNames() {
        return claims.keySet();
    }
    
    /**
     * Gets all claims.
     * 
     * @return unmodifiable map of claims
     */
    public Map<String, Object> getClaims() {
        return new HashMap<>(claims);
    }
    
    /**
     * Checks if this subject has no claims (excluding the id).
     * 
     * @return true if no claims are present, false otherwise
     */
    public boolean isEmpty() {
        return claims.isEmpty();
    }
    
    /**
     * Gets the number of claims (excluding the id).
     * 
     * @return the number of claims
     */
    public int size() {
        return claims.size();
    }
    
    /**
     * Serializes this credential subject to JSON.
     * 
     * @return JSON object representation
     */
    public JsonObject toJson() {
        JsonObject json = new JsonObject();
        
        // Add id if present
        if (id != null && !id.isEmpty()) {
            json.addProperty("id", id);
        }
        
        // Add all claims
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            String name = entry.getKey();
            Object value = entry.getValue();
            
            if (value instanceof String) {
                json.addProperty(name, (String) value);
            } else if (value instanceof Number) {
                json.addProperty(name, (Number) value);
            } else if (value instanceof Boolean) {
                json.addProperty(name, (Boolean) value);
            } else if (value instanceof JsonElement) {
                json.add(name, (JsonElement) value);
            } else if (value != null) {
                // Fallback: convert to string
                json.addProperty(name, value.toString());
            }
        }
        
        return json;
    }
    
    /**
     * Parses a credential subject from JSON.
     * 
     * @param json the JSON object
     * @return parsed CredentialSubject
     * @throws JsonLdException if the JSON format is invalid
     */
    public static CredentialSubject fromJson(JsonObject json) throws JsonLdException {
        if (json == null) {
            throw new JsonLdException("Credential subject JSON cannot be null");
        }
        
        CredentialSubject subject = new CredentialSubject();
        
        // Extract id if present
        if (json.has("id")) {
            JsonElement idElement = json.get("id");
            if (idElement.isJsonPrimitive()) {
                subject.setId(idElement.getAsString());
            }
        }
        
        // Extract all other properties as claims
        for (Map.Entry<String, JsonElement> entry : json.entrySet()) {
            String name = entry.getKey();
            
            // Skip "id" as it's already handled
            if ("id".equals(name)) {
                continue;
            }
            
            JsonElement value = entry.getValue();
            
            if (value.isJsonPrimitive()) {
                JsonPrimitive primitive = value.getAsJsonPrimitive();
                if (primitive.isString()) {
                    subject.addClaim(name, primitive.getAsString());
                } else if (primitive.isNumber()) {
                    subject.addClaim(name, primitive.getAsNumber());
                } else if (primitive.isBoolean()) {
                    subject.addClaim(name, primitive.getAsBoolean());
                }
            } else {
                // Store complex values as JsonElement
                subject.addClaim(name, value);
            }
        }
        
        return subject;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CredentialSubject that = (CredentialSubject) o;
        return Objects.equals(id, that.id) &&
               Objects.equals(claims, that.claims);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(id, claims);
    }
    
    @Override
    public String toString() {
        return "CredentialSubject{" +
               "id='" + id + '\'' +
               ", claims=" + claims.keySet() +
               '}';
    }
}

// Made with Bob