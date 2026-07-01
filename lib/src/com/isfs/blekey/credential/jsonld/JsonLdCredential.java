/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.jsonld;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Represents a JSON-LD Verifiable Credential.
 * 
 * <p>This class implements the W3C Verifiable Credentials Data Model using JSON-LD format.
 * It provides a complete container for JSON-LD credentials with support for:
 * <ul>
 *   <li>Multiple @context definitions</li>
 *   <li>Credential types</li>
 *   <li>Issuer identification (DID)</li>
 *   <li>Issuance and expiration dates</li>
 *   <li>Credential subject with claims</li>
 *   <li>Cryptographic proofs</li>
 *   <li>JSON serialization/deserialization</li>
 * </ul>
 * 
 * <p>Example usage:
 * <pre>{@code
 * // Create a JSON-LD credential
 * JsonLdCredential credential = new JsonLdCredential();
 * credential.setId("http://example.edu/credentials/3732");
 * credential.addType("VerifiableCredential");
 * credential.addType("UniversityDegreeCredential");
 * credential.setIssuer("did:example:issuer");
 * credential.setIssuanceDate(Instant.now());
 * 
 * // Add context
 * credential.getContext().addContextUrl(JsonLdContext.W3C_VC_CONTEXT);
 * credential.getContext().addContextUrl("https://www.w3.org/2018/credentials/examples/v1");
 * 
 * // Add credential subject
 * CredentialSubject subject = new CredentialSubject("did:example:student");
 * subject.addClaim("degree", "Bachelor of Science");
 * subject.addClaim("degreeType", "BachelorDegree");
 * credential.setCredentialSubject(subject);
 * 
 * // Add proof
 * JsonLdProof proof = new JsonLdProof("JsonWebSignature2020");
 * proof.setVerificationMethod("did:example:issuer#key-1");
 * proof.setProofPurpose("assertionMethod");
 * proof.setCreated(Instant.now());
 * proof.setJws("eyJhbGc...");
 * credential.setProof(proof);
 * 
 * // Serialize to JSON
 * String json = credential.toJson();
 * }</pre>
 * 
 * @see <a href="https://www.w3.org/TR/vc-data-model/">Verifiable Credentials Data Model</a>
 * @see <a href="https://www.w3.org/TR/json-ld11/">JSON-LD 1.1</a>
 */
public class JsonLdCredential {
    
    /**
     * The @context defines the JSON-LD context for this credential.
     */
    private JsonLdContext context;
    
    /**
     * The credential identifier (URI).
     */
    private String id;
    
    /**
     * The types of this credential (e.g., ["VerifiableCredential", "UniversityDegreeCredential"]).
     */
    private final List<String> types;
    
    /**
     * The issuer of this credential (typically a DID).
     */
    private String issuer;
    
    /**
     * When the credential was issued.
     */
    private Instant issuanceDate;
    
    /**
     * When the credential expires (optional).
     */
    private Instant expirationDate;
    
    /**
     * The credential subject containing claims.
     */
    private CredentialSubject credentialSubject;
    
    /**
     * The cryptographic proof.
     */
    private JsonLdProof proof;
    
    /**
     * Gson instance for JSON serialization.
     */
    private static final Gson gson = new GsonBuilder()
            .setPrettyPrinting()
            .create();
    
    /**
     * Constructs an empty JSON-LD credential.
     *
     * <p>Note: The W3C VC context and "VerifiableCredential" type are NOT automatically added.
     * They must be explicitly set based on the credential offer or issuer metadata.
     * The validate() method will ensure these required elements are present.
     */
    public JsonLdCredential() {
        this.context = new JsonLdContext();
        this.types = new ArrayList<>();
    }
    
    /**
     * Gets the @context.
     * 
     * @return the JSON-LD context
     */
    public JsonLdContext getContext() {
        return context;
    }
    
    /**
     * Sets the @context.
     * 
     * @param context the JSON-LD context
     * @return this credential for method chaining
     */
    public JsonLdCredential setContext(JsonLdContext context) {
        this.context = context;
        return this;
    }
    
    /**
     * Gets the credential ID.
     * 
     * @return the credential ID (URI)
     */
    public String getId() {
        return id;
    }
    
    /**
     * Sets the credential ID.
     * 
     * @param id the credential ID (URI)
     * @return this credential for method chaining
     */
    public JsonLdCredential setId(String id) {
        this.id = id;
        return this;
    }
    
    /**
     * Gets the credential types.
     * 
     * @return list of credential types
     */
    public List<String> getTypes() {
        return new ArrayList<>(types);
    }
    
    /**
     * Adds a credential type.
     * 
     * @param type the type to add
     * @return this credential for method chaining
     */
    public JsonLdCredential addType(String type) {
        if (type != null && !type.isEmpty() && !types.contains(type)) {
            types.add(type);
        }
        return this;
    }
    
    /**
     * Removes a credential type.
     * 
     * @param type the type to remove
     * @return this credential for method chaining
     */
    public JsonLdCredential removeType(String type) {
        types.remove(type);
        return this;
    }
    
    /**
     * Gets the issuer.
     * 
     * @return the issuer (typically a DID)
     */
    public String getIssuer() {
        return issuer;
    }
    
    /**
     * Sets the issuer.
     * 
     * @param issuer the issuer (typically a DID like "did:example:issuer")
     * @return this credential for method chaining
     */
    public JsonLdCredential setIssuer(String issuer) {
        this.issuer = issuer;
        return this;
    }
    
    /**
     * Gets the issuance date.
     * 
     * @return the issuance date
     */
    public Instant getIssuanceDate() {
        return issuanceDate;
    }
    
    /**
     * Sets the issuance date.
     * 
     * @param issuanceDate the issuance date
     * @return this credential for method chaining
     */
    public JsonLdCredential setIssuanceDate(Instant issuanceDate) {
        this.issuanceDate = issuanceDate;
        return this;
    }
    
    /**
     * Gets the expiration date.
     * 
     * @return the expiration date, or null if not set
     */
    public Instant getExpirationDate() {
        return expirationDate;
    }
    
    /**
     * Sets the expiration date.
     * 
     * @param expirationDate the expiration date
     * @return this credential for method chaining
     */
    public JsonLdCredential setExpirationDate(Instant expirationDate) {
        this.expirationDate = expirationDate;
        return this;
    }
    
    /**
     * Gets the credential subject.
     * 
     * @return the credential subject
     */
    public CredentialSubject getCredentialSubject() {
        return credentialSubject;
    }
    
    /**
     * Sets the credential subject.
     * 
     * @param credentialSubject the credential subject
     * @return this credential for method chaining
     */
    public JsonLdCredential setCredentialSubject(CredentialSubject credentialSubject) {
        this.credentialSubject = credentialSubject;
        return this;
    }
    
    /**
     * Gets the proof.
     * 
     * @return the proof, or null if not set
     */
    public JsonLdProof getProof() {
        return proof;
    }
    
    /**
     * Sets the proof.
     * 
     * @param proof the cryptographic proof
     * @return this credential for method chaining
     */
    public JsonLdCredential setProof(JsonLdProof proof) {
        this.proof = proof;
        return this;
    }
    
    /**
     * Validates that this credential has all required fields per W3C VC spec.
     *
     * @throws JsonLdException if validation fails
     */
    public void validate() throws JsonLdException {
        // Validate @context
        if (context == null || context.isEmpty()) {
            throw new JsonLdException("@context is required");
        }
        
        // Validate required contexts
        List<String> contextUrls = context.getContextUrls();
        if (!contextUrls.contains(JsonLdContext.W3C_VC_CONTEXT)) {
            throw new JsonLdException("@context must include W3C VC context: " + JsonLdContext.W3C_VC_CONTEXT);
        }
        if (!contextUrls.isEmpty() && !JsonLdContext.W3C_VC_CONTEXT.equals(contextUrls.get(0))) {
            throw new JsonLdException("W3C VC context must be the first context in @context array");
        }
        if (types.isEmpty()) {
            throw new JsonLdException("At least one type is required");
        }
        if (!types.contains("VerifiableCredential")) {
            throw new JsonLdException("Type must include 'VerifiableCredential'");
        }
        if (issuer == null || issuer.isEmpty()) {
            throw new JsonLdException("Issuer is required");
        }
        if (issuanceDate == null) {
            throw new JsonLdException("Issuance date is required");
        }
        if (credentialSubject == null) {
            throw new JsonLdException("Credential subject is required");
        }
        
        // Validate proof if present
        if (proof != null) {
            proof.validate();
        }
    }
    
    /**
     * Serializes this credential to JSON string.
     * 
     * @return JSON string representation
     */
    public String toJson() {
        return gson.toJson(toJsonObject());
    }
    
    /**
     * Serializes this credential to a JsonObject.
     * 
     * @return JsonObject representation
     */
    public JsonObject toJsonObject() {
        JsonObject json = new JsonObject();
        
        // Add @context
        if (context != null) {
            json.add("@context", context.toJson());
        }
        
        // Add id
        if (id != null && !id.isEmpty()) {
            json.addProperty("id", id);
        }
        
        // Add type(s)
        if (types.size() == 1) {
            json.addProperty("type", types.get(0));
        } else if (types.size() > 1) {
            JsonArray typeArray = new JsonArray();
            for (String type : types) {
                typeArray.add(type);
            }
            json.add("type", typeArray);
        }
        
        // Add issuer
        if (issuer != null && !issuer.isEmpty()) {
            json.addProperty("issuer", issuer);
        }
        
        // Add issuanceDate
        if (issuanceDate != null) {
            json.addProperty("issuanceDate", issuanceDate.toString());
        }
        
        // Add expirationDate
        if (expirationDate != null) {
            json.addProperty("expirationDate", expirationDate.toString());
        }
        
        // Add credentialSubject
        if (credentialSubject != null) {
            json.add("credentialSubject", credentialSubject.toJson());
        }
        
        // Add proof
        if (proof != null) {
            json.add("proof", proof.toJson());
        }
        
        return json;
    }
    
    /**
     * Parses a JSON-LD credential from JSON string.
     * 
     * @param json the JSON string
     * @return parsed JsonLdCredential
     * @throws JsonLdException if parsing fails
     */
    public static JsonLdCredential fromJson(String json) throws JsonLdException {
        if (json == null || json.isEmpty()) {
            throw new JsonLdException("JSON string cannot be null or empty");
        }
        
        try {
            JsonElement element = JsonParser.parseString(json);
            if (!element.isJsonObject()) {
                throw new JsonLdException("JSON must be an object");
            }
            return fromJsonObject(element.getAsJsonObject());
        } catch (Exception e) {
            throw new JsonLdException("Failed to parse JSON", e);
        }
    }
    
    /**
     * Parses a JSON-LD credential from JsonObject.
     * 
     * @param json the JsonObject
     * @return parsed JsonLdCredential
     * @throws JsonLdException if parsing fails
     */
    public static JsonLdCredential fromJsonObject(JsonObject json) throws JsonLdException {
        if (json == null) {
            throw new JsonLdException("JSON object cannot be null");
        }
        
        JsonLdCredential credential = new JsonLdCredential();
        
        // Parse @context
        if (json.has("@context")) {
            credential.context = JsonLdContext.fromJson(json.get("@context"));
        }
        
        // Parse id
        if (json.has("id")) {
            credential.id = json.get("id").getAsString();
        }
        
        // Parse type(s)
        if (json.has("type")) {
            credential.types.clear(); // Remove default "VerifiableCredential"
            JsonElement typeElement = json.get("type");
            if (typeElement.isJsonPrimitive()) {
                credential.addType(typeElement.getAsString());
            } else if (typeElement.isJsonArray()) {
                JsonArray typeArray = typeElement.getAsJsonArray();
                for (JsonElement type : typeArray) {
                    credential.addType(type.getAsString());
                }
            }
        }
        
        // Parse issuer
        if (json.has("issuer")) {
            JsonElement issuerElement = json.get("issuer");
            if (issuerElement.isJsonPrimitive()) {
                credential.issuer = issuerElement.getAsString();
            } else if (issuerElement.isJsonObject()) {
                // Issuer can be an object with "id" field
                JsonObject issuerObj = issuerElement.getAsJsonObject();
                if (issuerObj.has("id")) {
                    credential.issuer = issuerObj.get("id").getAsString();
                }
            }
        }
        
        // Parse issuanceDate
        if (json.has("issuanceDate")) {
            try {
                credential.issuanceDate = Instant.parse(json.get("issuanceDate").getAsString());
            } catch (Exception e) {
                throw new JsonLdException("Invalid issuanceDate format", e);
            }
        }
        
        // Parse expirationDate
        if (json.has("expirationDate")) {
            try {
                credential.expirationDate = Instant.parse(json.get("expirationDate").getAsString());
            } catch (Exception e) {
                throw new JsonLdException("Invalid expirationDate format", e);
            }
        }
        
        // Parse credentialSubject
        if (json.has("credentialSubject")) {
            JsonElement subjectElement = json.get("credentialSubject");
            if (subjectElement.isJsonObject()) {
                credential.credentialSubject = CredentialSubject.fromJson(subjectElement.getAsJsonObject());
            }
        }
        
        // Parse proof
        if (json.has("proof")) {
            JsonElement proofElement = json.get("proof");
            if (proofElement.isJsonObject()) {
                credential.proof = JsonLdProof.fromJson(proofElement.getAsJsonObject());
            }
        }
        
        return credential;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        JsonLdCredential that = (JsonLdCredential) o;
        return Objects.equals(context, that.context) &&
               Objects.equals(id, that.id) &&
               Objects.equals(types, that.types) &&
               Objects.equals(issuer, that.issuer) &&
               Objects.equals(issuanceDate, that.issuanceDate) &&
               Objects.equals(expirationDate, that.expirationDate) &&
               Objects.equals(credentialSubject, that.credentialSubject) &&
               Objects.equals(proof, that.proof);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(context, id, types, issuer, issuanceDate, expirationDate, credentialSubject, proof);
    }
    
    @Override
    public String toString() {
        return "JsonLdCredential{" +
               "id='" + id + '\'' +
               ", types=" + types +
               ", issuer='" + issuer + '\'' +
               ", issuanceDate=" + issuanceDate +
               ", hasSubject=" + (credentialSubject != null) +
               ", hasProof=" + (proof != null) +
               '}';
    }
}

// Made with Bob