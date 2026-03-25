/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.credential.sdjwt;

import java.util.Objects;

/**
 * Represents a parsed SD-JWT disclosure.
 * 
 * A disclosure contains:
 * - Salt: Random value for privacy
 * - Claim name: The name of the disclosed claim
 * - Claim value: The value of the disclosed claim
 * - Original base64url encoding: For hash verification
 * 
 * According to IETF draft-ietf-oauth-selective-disclosure-jwt-08,
 * disclosures are base64url-encoded JSON arrays: [salt, claim_name, claim_value]
 */
public class Disclosure {
    
    private final String salt;
    private final String claimName;
    private final Object claimValue;
    private final String base64urlEncoded;
    
    /**
     * Creates a new Disclosure.
     * 
     * @param salt The salt value
     * @param claimName The claim name
     * @param claimValue The claim value
     * @param base64urlEncoded The original base64url-encoded disclosure
     */
    public Disclosure(String salt, String claimName, Object claimValue, String base64urlEncoded) {
        this.salt = salt;
        this.claimName = claimName;
        this.claimValue = claimValue;
        this.base64urlEncoded = base64urlEncoded;
    }
    
    /**
     * Gets the salt value.
     * @return Salt
     */
    public String getSalt() {
        return salt;
    }
    
    /**
     * Gets the claim name.
     * @return Claim name
     */
    public String getClaimName() {
        return claimName;
    }
    
    /**
     * Gets the claim value.
     * @return Claim value
     */
    public Object getClaimValue() {
        return claimValue;
    }
    
    /**
     * Gets the original base64url-encoded disclosure.
     * This is needed for hash verification.
     * @return Base64url-encoded disclosure
     */
    public String getBase64urlEncoded() {
        return base64urlEncoded;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Disclosure that = (Disclosure) o;
        return Objects.equals(salt, that.salt) &&
               Objects.equals(claimName, that.claimName) &&
               Objects.equals(claimValue, that.claimValue) &&
               Objects.equals(base64urlEncoded, that.base64urlEncoded);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(salt, claimName, claimValue, base64urlEncoded);
    }
    
    @Override
    public String toString() {
        return "Disclosure{" +
               "claimName='" + claimName + '\'' +
               ", hasSalt=" + (salt != null) +
               ", hasValue=" + (claimValue != null) +
               '}';
    }
}

// Made with Bob