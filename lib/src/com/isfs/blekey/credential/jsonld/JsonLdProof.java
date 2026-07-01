/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.jsonld;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Represents a cryptographic proof in a JSON-LD Verifiable Credential.
 * 
 * <p>A proof provides evidence that the credential is authentic and has not been tampered with.
 * This class supports various proof types including:
 * <ul>
 *   <li>JsonWebSignature2020 - JWS-based proof</li>
 *   <li>Ed25519Signature2020 - EdDSA signature</li>
 *   <li>EcdsaSecp256k1Signature2019 - ECDSA signature</li>
 * </ul>
 * 
 * <p>Example usage:
 * <pre>{@code
 * // Create a JWS proof
 * JsonLdProof proof = new JsonLdProof("JsonWebSignature2020");
 * proof.setVerificationMethod("did:example:issuer#key-1");
 * proof.setProofPurpose("assertionMethod");
 * proof.setCreated(Instant.now());
 * proof.setJws("eyJhbGc...");
 * 
 * // Serialize to JSON
 * JsonObject proofJson = proof.toJson();
 * }</pre>
 * 
 * @see <a href="https://www.w3.org/TR/vc-data-model/#proofs-signatures">VC Data Model - Proofs</a>
 * @see <a href="https://w3c-ccg.github.io/ld-proofs/">Linked Data Proofs</a>
 */
public class JsonLdProof {
    
    /**
     * Common proof types.
     */
    public static final String TYPE_JWS_2020 = "JsonWebSignature2020";
    public static final String TYPE_ED25519_2020 = "Ed25519Signature2020";
    public static final String TYPE_ECDSA_SECP256K1_2019 = "EcdsaSecp256k1Signature2019";
    
    /**
     * Common proof purposes.
     */
    public static final String PURPOSE_ASSERTION = "assertionMethod";
    public static final String PURPOSE_AUTHENTICATION = "authentication";
    public static final String PURPOSE_KEY_AGREEMENT = "keyAgreement";
    
    /**
     * The type of proof (e.g., "JsonWebSignature2020").
     */
    private String type;
    
    /**
     * The verification method used to verify the proof.
     * Typically a DID URL like "did:example:issuer#key-1".
     */
    private String verificationMethod;
    
    /**
     * The purpose of the proof (e.g., "assertionMethod").
     */
    private String proofPurpose;
    
    /**
     * When the proof was created (ISO 8601 timestamp).
     */
    private Instant created;
    
    /**
     * The JWS (JSON Web Signature) value for JWS-based proofs.
     */
    private String jws;
    
    /**
     * The signature value for non-JWS proofs (base64url encoded).
     */
    private String proofValue;
    
    /**
     * Additional proof properties.
     */
    private final Map<String, Object> additionalProperties;
    
    /**
     * Constructs an empty proof.
     */
    public JsonLdProof() {
        this.additionalProperties = new HashMap<>();
    }
    
    /**
     * Constructs a proof with the specified type.
     * 
     * @param type the proof type (e.g., "JsonWebSignature2020")
     */
    public JsonLdProof(String type) {
        this();
        this.type = type;
    }
    
    /**
     * Gets the proof type.
     * 
     * @return the proof type
     */
    public String getType() {
        return type;
    }
    
    /**
     * Sets the proof type.
     * 
     * @param type the proof type (e.g., "JsonWebSignature2020")
     * @return this proof for method chaining
     */
    public JsonLdProof setType(String type) {
        this.type = type;
        return this;
    }
    
    /**
     * Gets the verification method.
     * 
     * @return the verification method (DID URL)
     */
    public String getVerificationMethod() {
        return verificationMethod;
    }
    
    /**
     * Sets the verification method.
     * 
     * @param verificationMethod the verification method (e.g., "did:example:issuer#key-1")
     * @return this proof for method chaining
     */
    public JsonLdProof setVerificationMethod(String verificationMethod) {
        this.verificationMethod = verificationMethod;
        return this;
    }
    
    /**
     * Gets the proof purpose.
     * 
     * @return the proof purpose
     */
    public String getProofPurpose() {
        return proofPurpose;
    }
    
    /**
     * Sets the proof purpose.
     * 
     * @param proofPurpose the proof purpose (e.g., "assertionMethod")
     * @return this proof for method chaining
     */
    public JsonLdProof setProofPurpose(String proofPurpose) {
        this.proofPurpose = proofPurpose;
        return this;
    }
    
    /**
     * Gets the creation timestamp.
     * 
     * @return the creation timestamp
     */
    public Instant getCreated() {
        return created;
    }
    
    /**
     * Sets the creation timestamp.
     * 
     * @param created the creation timestamp
     * @return this proof for method chaining
     */
    public JsonLdProof setCreated(Instant created) {
        this.created = created;
        return this;
    }
    
    /**
     * Gets the JWS value.
     * 
     * @return the JWS value, or null if not set
     */
    public String getJws() {
        return jws;
    }
    
    /**
     * Sets the JWS value (for JsonWebSignature2020 proofs).
     * 
     * @param jws the JWS value
     * @return this proof for method chaining
     */
    public JsonLdProof setJws(String jws) {
        this.jws = jws;
        return this;
    }
    
    /**
     * Gets the proof value.
     * 
     * @return the proof value, or null if not set
     */
    public String getProofValue() {
        return proofValue;
    }
    
    /**
     * Sets the proof value (for non-JWS proofs).
     * 
     * @param proofValue the proof value (base64url encoded)
     * @return this proof for method chaining
     */
    public JsonLdProof setProofValue(String proofValue) {
        this.proofValue = proofValue;
        return this;
    }
    
    /**
     * Adds an additional property to the proof.
     * 
     * @param name the property name
     * @param value the property value
     * @return this proof for method chaining
     */
    public JsonLdProof addProperty(String name, Object value) {
        if (name != null && !name.isEmpty() && value != null) {
            additionalProperties.put(name, value);
        }
        return this;
    }
    
    /**
     * Gets an additional property.
     * 
     * @param name the property name
     * @return the property value, or null if not present
     */
    public Object getProperty(String name) {
        return additionalProperties.get(name);
    }
    
    /**
     * Gets all additional properties.
     * 
     * @return map of additional properties
     */
    public Map<String, Object> getAdditionalProperties() {
        return new HashMap<>(additionalProperties);
    }
    
    /**
     * Serializes this proof to JSON.
     * 
     * @return JSON object representation
     */
    public JsonObject toJson() {
        JsonObject json = new JsonObject();
        
        // Required fields
        if (type != null) {
            json.addProperty("type", type);
        }
        if (verificationMethod != null) {
            json.addProperty("verificationMethod", verificationMethod);
        }
        if (proofPurpose != null) {
            json.addProperty("proofPurpose", proofPurpose);
        }
        
        // Optional fields
        if (created != null) {
            json.addProperty("created", created.toString());
        }
        if (jws != null) {
            json.addProperty("jws", jws);
        }
        if (proofValue != null) {
            json.addProperty("proofValue", proofValue);
        }
        
        // Additional properties
        for (Map.Entry<String, Object> entry : additionalProperties.entrySet()) {
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
            }
        }
        
        return json;
    }
    
    /**
     * Parses a proof from JSON.
     * 
     * @param json the JSON object
     * @return parsed JsonLdProof
     * @throws JsonLdException if the JSON format is invalid
     */
    public static JsonLdProof fromJson(JsonObject json) throws JsonLdException {
        if (json == null) {
            throw new JsonLdException("Proof JSON cannot be null");
        }
        
        JsonLdProof proof = new JsonLdProof();
        
        // Extract standard fields
        if (json.has("type")) {
            proof.setType(json.get("type").getAsString());
        }
        if (json.has("verificationMethod")) {
            proof.setVerificationMethod(json.get("verificationMethod").getAsString());
        }
        if (json.has("proofPurpose")) {
            proof.setProofPurpose(json.get("proofPurpose").getAsString());
        }
        if (json.has("created")) {
            try {
                proof.setCreated(Instant.parse(json.get("created").getAsString()));
            } catch (Exception e) {
                throw new JsonLdException("Invalid created timestamp", e);
            }
        }
        if (json.has("jws")) {
            proof.setJws(json.get("jws").getAsString());
        }
        if (json.has("proofValue")) {
            proof.setProofValue(json.get("proofValue").getAsString());
        }
        
        // Extract additional properties
        for (Map.Entry<String, JsonElement> entry : json.entrySet()) {
            String name = entry.getKey();
            
            // Skip standard fields
            if ("type".equals(name) || "verificationMethod".equals(name) || 
                "proofPurpose".equals(name) || "created".equals(name) || 
                "jws".equals(name) || "proofValue".equals(name)) {
                continue;
            }
            
            JsonElement value = entry.getValue();
            if (value.isJsonPrimitive()) {
                if (value.getAsJsonPrimitive().isString()) {
                    proof.addProperty(name, value.getAsString());
                } else if (value.getAsJsonPrimitive().isNumber()) {
                    proof.addProperty(name, value.getAsNumber());
                } else if (value.getAsJsonPrimitive().isBoolean()) {
                    proof.addProperty(name, value.getAsBoolean());
                }
            } else {
                proof.addProperty(name, value);
            }
        }
        
        return proof;
    }
    
    /**
     * Validates that this proof has all required fields.
     * 
     * @throws JsonLdException if validation fails
     */
    public void validate() throws JsonLdException {
        if (type == null || type.isEmpty()) {
            throw new JsonLdException("Proof type is required");
        }
        if (verificationMethod == null || verificationMethod.isEmpty()) {
            throw new JsonLdException("Verification method is required");
        }
        if (proofPurpose == null || proofPurpose.isEmpty()) {
            throw new JsonLdException("Proof purpose is required");
        }
        
        // At least one of jws or proofValue must be present
        if ((jws == null || jws.isEmpty()) && (proofValue == null || proofValue.isEmpty())) {
            throw new JsonLdException("Either jws or proofValue must be present");
        }
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        JsonLdProof that = (JsonLdProof) o;
        return Objects.equals(type, that.type) &&
               Objects.equals(verificationMethod, that.verificationMethod) &&
               Objects.equals(proofPurpose, that.proofPurpose) &&
               Objects.equals(created, that.created) &&
               Objects.equals(jws, that.jws) &&
               Objects.equals(proofValue, that.proofValue) &&
               Objects.equals(additionalProperties, that.additionalProperties);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(type, verificationMethod, proofPurpose, created, jws, proofValue, additionalProperties);
    }
    
    @Override
    public String toString() {
        return "JsonLdProof{" +
               "type='" + type + '\'' +
               ", verificationMethod='" + verificationMethod + '\'' +
               ", proofPurpose='" + proofPurpose + '\'' +
               ", created=" + created +
               '}';
    }
}

// Made with Bob