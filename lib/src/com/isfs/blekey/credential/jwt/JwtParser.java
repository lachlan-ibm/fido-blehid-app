/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.credential.jwt;

import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.VerificationKeyResolver;

import java.security.PublicKey;

/**
 * Parser for validating and extracting claims from JWTs.
 */
public class JwtParser {
    private final JwtConsumer jwtConsumer;

    /**
     * Create a JWT parser with a single verification key.
     */
    public JwtParser(PublicKey verificationKey) {
        this.jwtConsumer = new JwtConsumerBuilder()
            .setVerificationKey(verificationKey)
            .setRequireExpirationTime()
            .setAllowedClockSkewInSeconds(30)
            .build();
    }

    /**
     * Create a JWT parser with a custom key resolver.
     */
    public JwtParser(VerificationKeyResolver keyResolver) {
        this.jwtConsumer = new JwtConsumerBuilder()
            .setVerificationKeyResolver(keyResolver)
            .setRequireExpirationTime()
            .setAllowedClockSkewInSeconds(30)
            .build();
    }

    /**
     * Create a JWT parser with custom configuration.
     */
    public JwtParser(JwtConsumer jwtConsumer) {
        this.jwtConsumer = jwtConsumer;
    }

    /**
     * Parse and validate a JWT, returning the claims.
     * 
     * @param jwt The compact serialized JWT string
     * @return The validated JWT claims
     * @throws JwtException if JWT validation fails
     */
    public JwtClaims parse(String jwt) throws JwtException {
        try {
            return jwtConsumer.processToClaims(jwt);
        } catch (InvalidJwtException e) {
            throw new JwtException("Failed to parse JWT: " + e.getMessage(), e);
        }
    }

    /**
     * Parse a JWT without signature verification (use with caution).
     * This is useful for extracting claims from self-issued tokens.
     * 
     * @param jwt The compact serialized JWT string
     * @return The JWT claims (unverified)
     * @throws JwtException if JWT parsing fails
     */
    public static JwtClaims parseUnsecured(String jwt) throws JwtException {
        try {
            JwtConsumer consumer = new JwtConsumerBuilder()
                .setSkipSignatureVerification()
                .setSkipAllValidators()
                .build();
            return consumer.processToClaims(jwt);
        } catch (InvalidJwtException e) {
            throw new JwtException("Failed to parse unsecured JWT: " + e.getMessage(), e);
        }
    }

    /**
     * Extract a specific claim from a JWT.
     * 
     * @param jwt The compact serialized JWT string
     * @param claimName The name of the claim to extract
     * @return The claim value, or null if not present
     * @throws JwtException if JWT validation fails
     */
    public Object getClaim(String jwt, String claimName) throws JwtException {
        JwtClaims claims = parse(jwt);
        return claims.getClaimValue(claimName);
    }

    /**
     * Verify a JWT signature without processing claims.
     * 
     * @param jwt The compact serialized JWT string
     * @return true if signature is valid, false otherwise
     */
    public boolean verifySignature(String jwt) {
        try {
            jwtConsumer.processToClaims(jwt);
            return true;
        } catch (InvalidJwtException e) {
            return false;
        }
    }
}

// Made with Bob
