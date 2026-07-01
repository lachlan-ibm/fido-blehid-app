/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Metadata associated with a digital credential.
 * Contains issuer information, credential type, validity dates, and display properties.
 *
 * <p>For JSON-LD credentials, additional fields are available:
 * <ul>
 *   <li>contexts - List of @context URLs</li>
 *   <li>types - List of credential types</li>
 *   <li>credentialSubject - Subject claims as JSON string</li>
 *   <li>proofType - Type of cryptographic proof</li>
 * </ul>
 */
public class DigitalCredentialMetadata {
    
    private String issuerDid;
    private String issuerUrl;
    private String credentialType;
    private Instant issuedAt;
    private Instant expiresAt;
    private String statusListUrl;
    private Map<String, String> displayProperties;
    
    // JSON-LD specific fields
    private List<String> contexts;
    private List<String> types;
    private String credentialSubject;
    private String proofType;
    
    /**
     * Creates a new credential metadata instance.
     */
    public DigitalCredentialMetadata() {
        this.displayProperties = new HashMap<>();
    }
    
    /**
     * Creates a new credential metadata instance with specified values.
     * 
     * @param issuerDid DID of the credential issuer
     * @param issuerUrl URL of the credential issuer
     * @param credentialType Type of the credential (e.g., "VerifiableCredential")
     * @param issuedAt Timestamp when credential was issued
     * @param expiresAt Timestamp when credential expires (null if no expiration)
     */
    public DigitalCredentialMetadata(String issuerDid, String issuerUrl, 
                                     String credentialType, Instant issuedAt, 
                                     Instant expiresAt) {
        this.issuerDid = issuerDid;
        this.issuerUrl = issuerUrl;
        this.credentialType = credentialType;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
        this.displayProperties = new HashMap<>();
    }
    
    /**
     * Gets the issuer's Decentralized Identifier (DID).
     * @return Issuer DID
     */
    public String getIssuerDid() {
        return issuerDid;
    }
    
    /**
     * Sets the issuer's Decentralized Identifier (DID).
     * @param issuerDid Issuer DID
     */
    public void setIssuerDid(String issuerDid) {
        this.issuerDid = issuerDid;
    }
    
    /**
     * Gets the issuer's URL.
     * @return Issuer URL
     */
    public String getIssuerUrl() {
        return issuerUrl;
    }
    
    /**
     * Sets the issuer's URL.
     * @param issuerUrl Issuer URL
     */
    public void setIssuerUrl(String issuerUrl) {
        this.issuerUrl = issuerUrl;
    }
    
    /**
     * Gets the credential type.
     * @return Credential type (e.g., "VerifiableCredential", "UniversityDegree")
     */
    public String getCredentialType() {
        return credentialType;
    }
    
    /**
     * Sets the credential type.
     * @param credentialType Credential type
     */
    public void setCredentialType(String credentialType) {
        this.credentialType = credentialType;
    }
    
    /**
     * Gets the issuance timestamp.
     * @return Timestamp when credential was issued
     */
    public Instant getIssuedAt() {
        return issuedAt;
    }
    
    /**
     * Sets the issuance timestamp.
     * @param issuedAt Timestamp when credential was issued
     */
    public void setIssuedAt(Instant issuedAt) {
        this.issuedAt = issuedAt;
    }
    
    /**
     * Gets the expiration timestamp.
     * @return Timestamp when credential expires, or null if no expiration
     */
    public Instant getExpiresAt() {
        return expiresAt;
    }
    
    /**
     * Sets the expiration timestamp.
     * @param expiresAt Timestamp when credential expires, or null if no expiration
     */
    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }
    
    /**
     * Gets the status list URL for checking credential revocation.
     * @return Status list URL, or null if not applicable
     */
    public String getStatusListUrl() {
        return statusListUrl;
    }
    
    /**
     * Sets the status list URL for checking credential revocation.
     * @param statusListUrl Status list URL
     */
    public void setStatusListUrl(String statusListUrl) {
        this.statusListUrl = statusListUrl;
    }
    
    /**
     * Gets the display properties map.
     * Display properties contain UI-related information like title, description, colors, etc.
     * @return Mutable map of display properties
     */
    public Map<String, String> getDisplayProperties() {
        return displayProperties;
    }
    
    /**
     * Sets a display property.
     * @param key Property key (e.g., "title", "description", "backgroundColor")
     * @param value Property value
     */
    public void setDisplayProperty(String key, String value) {
        this.displayProperties.put(key, value);
    }
    
    /**
     * Gets a display property value.
     * @param key Property key
     * @return Property value, or null if not set
     */
    public String getDisplayProperty(String key) {
        return this.displayProperties.get(key);
    }
    
    /**
     * Checks if the credential is currently valid (not expired).
     * @return true if credential is valid, false if expired
     */
    public boolean isValid() {
        if (expiresAt == null) {
            return true;
        }
        return Instant.now().isBefore(expiresAt);
    }
    
    /**
     * Checks if the credential has been issued (issuedAt is in the past).
     * @return true if credential has been issued, false if issuance is in the future
     */
    public boolean isIssued() {
        if (issuedAt == null) {
            return false;
        }
        return Instant.now().isAfter(issuedAt);
    }
    
    // JSON-LD specific getters and setters
    
    /**
     * Gets the list of @context URLs for JSON-LD credentials.
     * @return List of context URLs, or null if not a JSON-LD credential
     */
    public List<String> getContexts() {
        return contexts;
    }
    
    /**
     * Sets the list of @context URLs for JSON-LD credentials.
     * @param contexts List of context URLs
     */
    public void setContexts(List<String> contexts) {
        this.contexts = contexts;
    }
    
    /**
     * Adds a context URL to the list.
     * @param contextUrl Context URL to add
     */
    public void addContext(String contextUrl) {
        if (this.contexts == null) {
            this.contexts = new ArrayList<>();
        }
        if (!this.contexts.contains(contextUrl)) {
            this.contexts.add(contextUrl);
        }
    }
    
    /**
     * Gets the list of credential types for JSON-LD credentials.
     * @return List of types, or null if not a JSON-LD credential
     */
    public List<String> getTypes() {
        return types;
    }
    
    /**
     * Sets the list of credential types for JSON-LD credentials.
     * @param types List of credential types
     */
    public void setTypes(List<String> types) {
        this.types = types;
    }
    
    /**
     * Adds a type to the list.
     * @param type Type to add
     */
    public void addType(String type) {
        if (this.types == null) {
            this.types = new ArrayList<>();
        }
        if (!this.types.contains(type)) {
            this.types.add(type);
        }
    }
    
    /**
     * Gets the credential subject as JSON string for JSON-LD credentials.
     * @return Credential subject JSON, or null if not a JSON-LD credential
     */
    public String getCredentialSubject() {
        return credentialSubject;
    }
    
    /**
     * Sets the credential subject as JSON string for JSON-LD credentials.
     * @param credentialSubject Credential subject JSON
     */
    public void setCredentialSubject(String credentialSubject) {
        this.credentialSubject = credentialSubject;
    }
    
    /**
     * Gets the proof type for JSON-LD credentials.
     * @return Proof type (e.g., "JsonWebSignature2020"), or null if not a JSON-LD credential
     */
    public String getProofType() {
        return proofType;
    }
    
    /**
     * Sets the proof type for JSON-LD credentials.
     * @param proofType Proof type
     */
    public void setProofType(String proofType) {
        this.proofType = proofType;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DigitalCredentialMetadata that = (DigitalCredentialMetadata) o;
        return Objects.equals(issuerDid, that.issuerDid) &&
               Objects.equals(issuerUrl, that.issuerUrl) &&
               Objects.equals(credentialType, that.credentialType) &&
               Objects.equals(issuedAt, that.issuedAt) &&
               Objects.equals(expiresAt, that.expiresAt) &&
               Objects.equals(statusListUrl, that.statusListUrl) &&
               Objects.equals(contexts, that.contexts) &&
               Objects.equals(types, that.types) &&
               Objects.equals(credentialSubject, that.credentialSubject) &&
               Objects.equals(proofType, that.proofType);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(issuerDid, issuerUrl, credentialType, issuedAt, expiresAt,
                           statusListUrl, contexts, types, credentialSubject, proofType);
    }
    
    @Override
    public String toString() {
        return "DigitalCredentialMetadata{" +
               "issuerDid='" + issuerDid + '\'' +
               ", issuerUrl='" + issuerUrl + '\'' +
               ", credentialType='" + credentialType + '\'' +
               ", issuedAt=" + issuedAt +
               ", expiresAt=" + expiresAt +
               ", statusListUrl='" + statusListUrl + '\'' +
               ", displayProperties=" + displayProperties +
               ", contexts=" + contexts +
               ", types=" + types +
               ", hasCredentialSubject=" + (credentialSubject != null) +
               ", proofType='" + proofType + '\'' +
               '}';
    }
}

// Made with Bob
