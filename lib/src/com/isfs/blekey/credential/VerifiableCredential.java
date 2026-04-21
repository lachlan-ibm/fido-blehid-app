/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential;

import com.isfs.blekey.util.Cbor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Represents a Verifiable Credential with secure storage capabilities.
 * 
 * This class encapsulates a digital credential in SD-JWT format (MVP scope),
 * with support for holder binding keys derived from a master key and per-credential seed.
 * 
 * Storage Structure:
 * - Credential ID: Unique identifier for this credential
 * - Format: Credential format (SD-JWT-VC for MVP)
 * - Metadata: Issuer info, type, dates, display properties
 * - Holder Binding Key Seed: Random seed for HKDF key derivation
 * - Encrypted Data: The actual credential data (SD-JWT)
 * - Salt: Salt used for HKDF key derivation
 * 
 * Security Model:
 * - Holder binding keys are derived on-demand using HKDF with:
 *   - Master key signature of the seed (requires biometric auth)
 *   - Salt derived from credential ID and issuer ID
 *   - Info string containing credential type
 * - Credential data is encrypted with derived key
 * - Seeds are stored encrypted with passkey's existing encryption
 */
public class VerifiableCredential {
    
    private static final Logger logger = LoggerFactory.getLogger(VerifiableCredential.class);
    
    private static final int SEED_LENGTH = 32;
    private static final int SALT_LENGTH = 32;
    
    private String id;
    private DigitalCredentialFormat format;
    private DigitalCredentialMetadata metadata;
    private byte[] holderBindingKeySeed;
    private byte[] encryptedData;
    private byte[] salt;
    
    /**
     * Creates a new empty VerifiableCredential.
     */
    public VerifiableCredential() {
        this.id = UUID.randomUUID().toString();
        this.format = DigitalCredentialFormat.SD_JWT_VC;
        this.metadata = new DigitalCredentialMetadata();
    }
    
    /**
     * Creates a new VerifiableCredential with specified parameters.
     * 
     * @param format Credential format
     * @param metadata Credential metadata
     * @param encryptedData Encrypted credential data
     */
    public VerifiableCredential(DigitalCredentialFormat format, 
                                DigitalCredentialMetadata metadata,
                                byte[] encryptedData) {
        this.id = UUID.randomUUID().toString();
        this.format = format;
        this.metadata = metadata;
        this.encryptedData = encryptedData != null ? encryptedData.clone() : null;
        generateSeedAndSalt();
    }
    
    /**
     * Generates a new random seed and salt for this credential.
     * Should be called when creating a new credential.
     */
    public void generateSeedAndSalt() {
        try {
            SecureRandom random = SecureRandom.getInstanceStrong();
            
            this.holderBindingKeySeed = new byte[SEED_LENGTH];
            random.nextBytes(this.holderBindingKeySeed);
            
            this.salt = new byte[SALT_LENGTH];
            random.nextBytes(this.salt);
            
            logger.debug("Generated new seed and salt for credential {}", id);
        } catch (Exception e) {
            logger.error("Failed to generate seed and salt", e);
            throw new RuntimeException("Failed to generate cryptographic material", e);
        }
    }
    
    /**
     * Gets the unique credential identifier.
     * @return Credential ID
     */
    public String getId() {
        return id;
    }
    
    /**
     * Sets the credential identifier.
     * @param id Credential ID
     */
    public void setId(String id) {
        this.id = id;
    }
    
    /**
     * Gets the credential format.
     * @return Credential format
     */
    public DigitalCredentialFormat getFormat() {
        return format;
    }
    
    /**
     * Sets the credential format.
     * @param format Credential format
     */
    public void setFormat(DigitalCredentialFormat format) {
        this.format = format;
    }
    
    /**
     * Gets the credential metadata.
     * @return Credential metadata
     */
    public DigitalCredentialMetadata getMetadata() {
        return metadata;
    }
    
    /**
     * Sets the credential metadata.
     * @param metadata Credential metadata
     */
    public void setMetadata(DigitalCredentialMetadata metadata) {
        this.metadata = metadata;
    }
    
    /**
     * Gets the holder binding key seed.
     * This seed is used with the master key to derive the actual binding key.
     * @return Holder binding key seed (32 bytes)
     */
    public byte[] getHolderBindingKeySeed() {
        return holderBindingKeySeed != null ? holderBindingKeySeed.clone() : null;
    }
    
    /**
     * Sets the holder binding key seed.
     * @param holderBindingKeySeed Holder binding key seed (must be 32 bytes)
     */
    public void setHolderBindingKeySeed(byte[] holderBindingKeySeed) {
        if (holderBindingKeySeed != null && holderBindingKeySeed.length != SEED_LENGTH) {
            throw new IllegalArgumentException("Seed must be " + SEED_LENGTH + " bytes");
        }
        this.holderBindingKeySeed = holderBindingKeySeed != null ? holderBindingKeySeed.clone() : null;
    }
    
    /**
     * Gets the encrypted credential data.
     * @return Encrypted credential data
     */
    public byte[] getEncryptedData() {
        return encryptedData != null ? encryptedData.clone() : null;
    }
    
    /**
     * Sets the encrypted credential data.
     * @param encryptedData Encrypted credential data
     */
    public void setEncryptedData(byte[] encryptedData) {
        this.encryptedData = encryptedData != null ? encryptedData.clone() : null;
    }
    
    /**
     * Gets the salt used for key derivation.
     * @return Salt (32 bytes)
     */
    public byte[] getSalt() {
        return salt != null ? salt.clone() : null;
    }
    
    /**
     * Sets the salt used for key derivation.
     * @param salt Salt (must be 32 bytes)
     */
    public void setSalt(byte[] salt) {
        if (salt != null && salt.length != SALT_LENGTH) {
            throw new IllegalArgumentException("Salt must be " + SALT_LENGTH + " bytes");
        }
        this.salt = salt != null ? salt.clone() : null;
    }
    
    /**
     * Serializes this credential to CBOR format for storage.
     * 
     * CBOR Structure:
     * {
     *   1: id (string),
     *   2: format (string),
     *   3: metadata (map),
     *   4: holderBindingKeySeed (bytes),
     *   5: encryptedData (bytes),
     *   6: salt (bytes)
     * }
     * 
     * @return CBOR-encoded credential data
     */
    public byte[] toCbor() {
        Map<Integer, Object> cborMap = new HashMap<>();
        
        cborMap.put(1, id);
        cborMap.put(2, format.getIdentifier());
        cborMap.put(3, serializeMetadata());
        
        if (holderBindingKeySeed != null) {
            cborMap.put(4, holderBindingKeySeed);
        }
        
        if (encryptedData != null) {
            cborMap.put(5, encryptedData);
        }
        
        if (salt != null) {
            cborMap.put(6, salt);
        }
        
        return Cbor.encode(cborMap);
    }
    
    /**
     * Safely casts an object to the specified type with validation.
     *
     * @param obj The object to cast
     * @param type The target class type
     * @param fieldName The field name for error messages
     * @return The cast object
     * @throws IllegalArgumentException if the object is not of the expected type
     */
    private static <T> T castOrThrow(Object obj, Class<T> type, String fieldName) {
        if (obj == null) {
            return null;
        }
        if (!type.isInstance(obj)) {
            throw new IllegalArgumentException(
                fieldName + " must be a " + type.getSimpleName() + ", but was " + obj.getClass().getSimpleName()
            );
        }
        return type.cast(obj);
    }
    
    /**
     * Retrieves and casts a required value from a map.
     *
     * @param map The source map
     * @param key The key to retrieve
     * @param type The expected type
     * @param fieldName The field name for error messages
     * @return The cast value
     * @throws IllegalArgumentException if the key is missing or value has wrong type
     */
    private static <T> T getRequired(Map<Integer, Object> map, Integer key, Class<T> type, String fieldName) {
        Object value = map.get(key);
        if (value == null) {
            throw new IllegalArgumentException("Required field " + fieldName + " is missing");
        }
        return castOrThrow(value, type, fieldName);
    }
    
    /**
     * Retrieves and casts an optional value from a map.
     *
     * @param map The source map
     * @param key The key to retrieve
     * @param type The expected type
     * @param fieldName The field name for error messages
     * @return The cast value or null if not present
     * @throws IllegalArgumentException if value has wrong type
     */
    private static <T> T getOptional(Map<Integer, Object> map, Integer key, Class<T> type, String fieldName) {
        if (!map.containsKey(key)) {
            return null;
        }
        return castOrThrow(map.get(key), type, fieldName);
    }
    
    /**
     * Deserializes a credential from CBOR format.
     *
     * @param cborData CBOR-encoded credential data
     * @return Deserialized VerifiableCredential
     * @throws IllegalArgumentException if CBOR data is invalid
     */
    public static VerifiableCredential fromCbor(byte[] cborData) {
        try {
            Object decoded = Cbor.decode(cborData);
            @SuppressWarnings("unchecked")
            Map<Integer, Object> cborMap = castOrThrow(decoded, Map.class, "CBOR root");
            
            VerifiableCredential credential = new VerifiableCredential();
            
            credential.id = getRequired(cborMap, 1, String.class, "credential ID");
            
            String formatId = getRequired(cborMap, 2, String.class, "credential format");
            credential.format = DigitalCredentialFormat.fromIdentifier(formatId);
            
            @SuppressWarnings("unchecked")
            Map<Integer, Object> metadataMap = getOptional(cborMap, 3, Map.class, "metadata");
            credential.metadata = deserializeMetadata(metadataMap);
            
            credential.holderBindingKeySeed = getOptional(cborMap, 4, byte[].class, "holder binding key seed");
            credential.encryptedData = getOptional(cborMap, 5, byte[].class, "encrypted data");
            credential.salt = getOptional(cborMap, 6, byte[].class, "salt");
            
            return credential;
        } catch (ClassCastException e) {
            logger.error("Type mismatch while deserializing credential from CBOR", e);
            throw new IllegalArgumentException("Invalid CBOR credential data: type mismatch", e);
        } catch (Exception e) {
            logger.error("Failed to deserialize credential from CBOR", e);
            throw new IllegalArgumentException("Invalid CBOR credential data", e);
        }
    }
    
    /**
     * Serializes metadata to CBOR map format.
     */
    private Map<Integer, Object> serializeMetadata() {
        Map<Integer, Object> metaMap = new HashMap<>();
        
        if (metadata.getIssuerDid() != null) {
            metaMap.put(1, metadata.getIssuerDid());
        }
        if (metadata.getIssuerUrl() != null) {
            metaMap.put(2, metadata.getIssuerUrl());
        }
        if (metadata.getCredentialType() != null) {
            metaMap.put(3, metadata.getCredentialType());
        }
        if (metadata.getIssuedAt() != null) {
            metaMap.put(4, metadata.getIssuedAt().getEpochSecond());
        }
        if (metadata.getExpiresAt() != null) {
            metaMap.put(5, metadata.getExpiresAt().getEpochSecond());
        }
        if (metadata.getStatusListUrl() != null) {
            metaMap.put(6, metadata.getStatusListUrl());
        }
        if (!metadata.getDisplayProperties().isEmpty()) {
            metaMap.put(7, metadata.getDisplayProperties());
        }
        
        return metaMap;
    }
    
    /**
     * Deserializes metadata from CBOR map format.
     */
    private static DigitalCredentialMetadata deserializeMetadata(Map<Integer, Object> metaMap) {
        if (metaMap == null) {
            return new DigitalCredentialMetadata();
        }
        
        DigitalCredentialMetadata metadata = new DigitalCredentialMetadata();
        
        String issuerDid = getOptional(metaMap, 1, String.class, "issuer DID");
        if (issuerDid != null) {
            metadata.setIssuerDid(issuerDid);
        }
        
        String issuerUrl = getOptional(metaMap, 2, String.class, "issuer URL");
        if (issuerUrl != null) {
            metadata.setIssuerUrl(issuerUrl);
        }
        
        String credentialType = getOptional(metaMap, 3, String.class, "credential type");
        if (credentialType != null) {
            metadata.setCredentialType(credentialType);
        }
        
        Number issuedAt = getOptional(metaMap, 4, Number.class, "issued at timestamp");
        if (issuedAt != null) {
            metadata.setIssuedAt(java.time.Instant.ofEpochSecond(issuedAt.longValue()));
        }
        
        Number expiresAt = getOptional(metaMap, 5, Number.class, "expires at timestamp");
        if (expiresAt != null) {
            metadata.setExpiresAt(java.time.Instant.ofEpochSecond(expiresAt.longValue()));
        }
        
        String statusListUrl = getOptional(metaMap, 6, String.class, "status list URL");
        if (statusListUrl != null) {
            metadata.setStatusListUrl(statusListUrl);
        }
        
        @SuppressWarnings("unchecked")
        Map<String, String> displayProps = getOptional(metaMap, 7, Map.class, "display properties");
        if (displayProps != null) {
            displayProps.forEach(metadata::setDisplayProperty);
        }
        
        return metadata;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        VerifiableCredential that = (VerifiableCredential) o;
        return Objects.equals(id, that.id) &&
               format == that.format &&
               Objects.equals(metadata, that.metadata) &&
               Arrays.equals(holderBindingKeySeed, that.holderBindingKeySeed) &&
               Arrays.equals(encryptedData, that.encryptedData) &&
               Arrays.equals(salt, that.salt);
    }
    
    @Override
    public int hashCode() {
        int result = Objects.hash(id, format, metadata);
        result = 31 * result + Arrays.hashCode(holderBindingKeySeed);
        result = 31 * result + Arrays.hashCode(encryptedData);
        result = 31 * result + Arrays.hashCode(salt);
        return result;
    }
    
    @Override
    public String toString() {
        return "VerifiableCredential{" +
               "id='" + id + '\'' +
               ", format=" + format +
               ", metadata=" + metadata +
               ", hasSeed=" + (holderBindingKeySeed != null) +
               ", hasEncryptedData=" + (encryptedData != null) +
               ", hasSalt=" + (salt != null) +
               '}';
    }
}

// Made with Bob
