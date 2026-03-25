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
     * Deserializes a credential from CBOR format.
     * 
     * @param cborData CBOR-encoded credential data
     * @return Deserialized VerifiableCredential
     * @throws IllegalArgumentException if CBOR data is invalid
     */
    public static VerifiableCredential fromCbor(byte[] cborData) {
        try {
            Map<Integer, Object> cborMap = (Map<Integer, Object>) Cbor.decode(cborData);
            
            VerifiableCredential credential = new VerifiableCredential();
            
            credential.id = (String) cborMap.get(1);
            credential.format = DigitalCredentialFormat.fromIdentifier((String) cborMap.get(2));
            credential.metadata = deserializeMetadata((Map<Integer, Object>) cborMap.get(3));
            
            if (cborMap.containsKey(4)) {
                credential.holderBindingKeySeed = (byte[]) cborMap.get(4);
            }
            
            if (cborMap.containsKey(5)) {
                credential.encryptedData = (byte[]) cborMap.get(5);
            }
            
            if (cborMap.containsKey(6)) {
                credential.salt = (byte[]) cborMap.get(6);
            }
            
            return credential;
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
        
        if (metaMap.containsKey(1)) {
            metadata.setIssuerDid((String) metaMap.get(1));
        }
        if (metaMap.containsKey(2)) {
            metadata.setIssuerUrl((String) metaMap.get(2));
        }
        if (metaMap.containsKey(3)) {
            metadata.setCredentialType((String) metaMap.get(3));
        }
        if (metaMap.containsKey(4)) {
            metadata.setIssuedAt(java.time.Instant.ofEpochSecond(((Number) metaMap.get(4)).longValue()));
        }
        if (metaMap.containsKey(5)) {
            metadata.setExpiresAt(java.time.Instant.ofEpochSecond(((Number) metaMap.get(5)).longValue()));
        }
        if (metaMap.containsKey(6)) {
            metadata.setStatusListUrl((String) metaMap.get(6));
        }
        if (metaMap.containsKey(7)) {
            @SuppressWarnings("unchecked")
            Map<String, String> displayProps = (Map<String, String>) metaMap.get(7);
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
