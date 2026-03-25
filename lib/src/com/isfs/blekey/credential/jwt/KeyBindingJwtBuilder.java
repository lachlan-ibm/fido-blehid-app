/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.credential.jwt;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Base64;

/**
 * Builder for creating Key Binding JWTs (KB-JWT) for holder binding in SD-JWT credentials.
 * KB-JWT proves possession of the private key corresponding to the holder binding key.
 */
public class KeyBindingJwtBuilder {
    private final JwtBuilder jwtBuilder;
    private String sdHash;

    public KeyBindingJwtBuilder() {
        this.jwtBuilder = new JwtBuilder();
    }

    /**
     * Set the audience (verifier) for the KB-JWT.
     */
    public KeyBindingJwtBuilder setAudience(String audience) {
        jwtBuilder.setAudience(audience);
        return this;
    }

    /**
     * Set the nonce provided by the verifier.
     */
    public KeyBindingJwtBuilder setNonce(String nonce) {
        jwtBuilder.setClaim("nonce", nonce);
        return this;
    }

    /**
     * Set the issued at time (current time).
     */
    public KeyBindingJwtBuilder setIssuedAtNow() {
        jwtBuilder.setIssuedAt(System.currentTimeMillis() / 1000);
        return this;
    }

    /**
     * Set the expiration time.
     */
    public KeyBindingJwtBuilder setExpirationTime(long expirationTimeSeconds) {
        jwtBuilder.setExpirationTime(expirationTimeSeconds);
        return this;
    }

    /**
     * Set the expiration time relative to now (in seconds from now).
     */
    public KeyBindingJwtBuilder setExpirationTimeFromNow(long secondsFromNow) {
        long now = System.currentTimeMillis() / 1000;
        jwtBuilder.setExpirationTime(now + secondsFromNow);
        return this;
    }

    /**
     * Set the SD-JWT hash for integrity protection.
     * This is the SHA-256 hash of the concatenated disclosures.
     * 
     * @param disclosures The selected disclosures to include in the presentation
     */
    public KeyBindingJwtBuilder setSdHash(String... disclosures) throws JwtException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            
            StringBuilder concatenated = new StringBuilder();
            for (String disclosure : disclosures) {
                concatenated.append(disclosure);
            }
            
            byte[] hashBytes = digest.digest(concatenated.toString().getBytes(StandardCharsets.US_ASCII));
            this.sdHash = Base64.getUrlEncoder().withoutPadding().encodeToString(hashBytes);
            jwtBuilder.setClaim("sd_hash", this.sdHash);
            
            return this;
        } catch (NoSuchAlgorithmException e) {
            throw new JwtException("SHA-256 algorithm not available", e);
        }
    }

    /**
     * Set a custom claim.
     */
    public KeyBindingJwtBuilder setClaim(String name, Object value) {
        jwtBuilder.setClaim(name, value);
        return this;
    }

    /**
     * Set the holder binding private key for signing.
     */
    public KeyBindingJwtBuilder setSigningKey(PrivateKey holderBindingKey) {
        jwtBuilder.setSigningKey(holderBindingKey);
        return this;
    }

    /**
     * Build and sign the KB-JWT.
     * 
     * @return The compact serialized KB-JWT string
     * @throws JwtException if JWT creation or signing fails
     */
    public String build() throws JwtException {
        return jwtBuilder.build();
    }

    /**
     * Get the computed SD hash value.
     */
    public String getSdHash() {
        return sdHash;
    }
}

// Made with Bob
