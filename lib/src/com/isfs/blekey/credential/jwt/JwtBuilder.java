/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.credential.jwt;

import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.lang.JoseException;

import java.security.PrivateKey;
import java.util.Map;

/**
 * Builder for creating and signing JWTs using ES256 algorithm.
 */
public class JwtBuilder {
    private final JwtClaims claims;
    private PrivateKey signingKey;

    public JwtBuilder() {
        this.claims = new JwtClaims();
    }

    /**
     * Set the issuer (iss) claim.
     */
    public JwtBuilder setIssuer(String issuer) {
        claims.setIssuer(issuer);
        return this;
    }

    /**
     * Set the subject (sub) claim.
     */
    public JwtBuilder setSubject(String subject) {
        claims.setSubject(subject);
        return this;
    }

    /**
     * Set the audience (aud) claim.
     */
    public JwtBuilder setAudience(String audience) {
        claims.setAudience(audience);
        return this;
    }

    /**
     * Set the expiration time (exp) claim.
     */
    public JwtBuilder setExpirationTime(long expirationTimeSeconds) {
        claims.setExpirationTime(NumericDate.fromSeconds(expirationTimeSeconds));
        return this;
    }

    /**
     * Set the not before (nbf) claim.
     */
    public JwtBuilder setNotBefore(long notBeforeSeconds) {
        claims.setNotBefore(NumericDate.fromSeconds(notBeforeSeconds));
        return this;
    }

    /**
     * Set the issued at (iat) claim.
     */
    public JwtBuilder setIssuedAt(long issuedAtSeconds) {
        claims.setIssuedAt(NumericDate.fromSeconds(issuedAtSeconds));
        return this;
    }

    /**
     * Set the JWT ID (jti) claim.
     */
    public JwtBuilder setJwtId(String jwtId) {
        claims.setJwtId(jwtId);
        return this;
    }

    /**
     * Set a custom claim.
     */
    public JwtBuilder setClaim(String name, Object value) {
        claims.setClaim(name, value);
        return this;
    }

    /**
     * Set multiple custom claims.
     */
    public JwtBuilder setClaims(Map<String, Object> customClaims) {
        for (Map.Entry<String, Object> entry : customClaims.entrySet()) {
            claims.setClaim(entry.getKey(), entry.getValue());
        }
        return this;
    }

    /**
     * Set the private key for signing.
     */
    public JwtBuilder setSigningKey(PrivateKey signingKey) {
        this.signingKey = signingKey;
        return this;
    }

    /**
     * Build and sign the JWT.
     * 
     * @return The compact serialized JWT string
     * @throws JwtException if JWT creation or signing fails
     */
    public String build() throws JwtException {
        if (signingKey == null) {
            throw new JwtException("Signing key is required");
        }

        try {
            JsonWebSignature jws = new JsonWebSignature();
            jws.setPayload(claims.toJson());
            jws.setKey(signingKey);
            jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
            
            return jws.getCompactSerialization();
        } catch (JoseException e) {
            throw new JwtException("Failed to build JWT", e);
        }
    }

    /**
     * Get the claims for inspection before building.
     */
    public JwtClaims getClaims() {
        return claims;
    }
}

// Made with Bob
