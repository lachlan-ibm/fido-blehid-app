/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.credential.sdjwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

/**
 * Computes and verifies SHA-256 hashes of SD-JWT disclosures.
 * 
 * According to IETF draft-ietf-oauth-selective-disclosure-jwt-08:
 * - Hash = SHA-256(disclosure_base64url_string)
 * - The hash is embedded in the JWT's _sd array
 * - Verifier recomputes hashes to verify disclosed claims
 */
public class DisclosureHasher {
    
    private static final Logger logger = LoggerFactory.getLogger(DisclosureHasher.class);
    private static final String DEFAULT_HASH_ALGORITHM = "SHA-256";
    
    /**
     * Computes the SHA-256 hash of a disclosure.
     * 
     * @param disclosure The base64url-encoded disclosure string
     * @return The SHA-256 hash bytes
     * @throws SdJwtException if hashing fails
     */
    public static byte[] computeHash(String disclosure) throws SdJwtException {
        return computeHash(disclosure, DEFAULT_HASH_ALGORITHM);
    }
    
    /**
     * Computes the hash of a disclosure using the specified algorithm.
     * 
     * @param disclosure The base64url-encoded disclosure string
     * @param algorithm The hash algorithm (e.g., "SHA-256", "SHA-512")
     * @return The hash bytes
     * @throws SdJwtException if hashing fails
     */
    public static byte[] computeHash(String disclosure, String algorithm) throws SdJwtException {
        if (disclosure == null || disclosure.isEmpty()) {
            throw new SdJwtException("Disclosure cannot be null or empty");
        }
        
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            byte[] disclosureBytes = disclosure.getBytes(StandardCharsets.US_ASCII);
            return digest.digest(disclosureBytes);
        } catch (NoSuchAlgorithmException e) {
            logger.error("Hash algorithm not available: {}", algorithm, e);
            throw new SdJwtException("Hash algorithm not available: " + algorithm, e);
        }
    }
    
    /**
     * Computes the base64url-encoded hash of a disclosure.
     * This is the format used in JWT _sd arrays.
     * 
     * @param disclosure The base64url-encoded disclosure string
     * @return The base64url-encoded hash
     * @throws SdJwtException if hashing fails
     */
    public static String computeHashBase64url(String disclosure) throws SdJwtException {
        byte[] hash = computeHash(disclosure);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }
    
    /**
     * Verifies that a disclosure matches an expected hash.
     * 
     * @param disclosure The base64url-encoded disclosure string
     * @param expectedHash The expected hash bytes
     * @return true if hash matches, false otherwise
     */
    public static boolean verifyHash(String disclosure, byte[] expectedHash) {
        try {
            byte[] actualHash = computeHash(disclosure);
            boolean matches = Arrays.equals(actualHash, expectedHash);
            
            if (!matches) {
                logger.warn("Disclosure hash mismatch");
            }
            
            return matches;
        } catch (SdJwtException e) {
            logger.error("Failed to verify disclosure hash", e);
            return false;
        }
    }
    
    /**
     * Verifies that a disclosure matches an expected base64url-encoded hash.
     * 
     * @param disclosure The base64url-encoded disclosure string
     * @param expectedHashBase64url The expected base64url-encoded hash
     * @return true if hash matches, false otherwise
     */
    public static boolean verifyHashBase64url(String disclosure, String expectedHashBase64url) {
        try {
            byte[] expectedHash = Base64.getUrlDecoder().decode(expectedHashBase64url);
            return verifyHash(disclosure, expectedHash);
        } catch (IllegalArgumentException e) {
            logger.error("Invalid base64url hash", e);
            return false;
        }
    }
    
    /**
     * Computes hashes for multiple disclosures.
     * 
     * @param disclosures Array of base64url-encoded disclosure strings
     * @return Array of hash bytes
     * @throws SdJwtException if hashing fails
     */
    public static byte[][] computeHashes(String[] disclosures) throws SdJwtException {
        if (disclosures == null) {
            return new byte[0][];
        }
        
        byte[][] hashes = new byte[disclosures.length][];
        for (int i = 0; i < disclosures.length; i++) {
            hashes[i] = computeHash(disclosures[i]);
        }
        
        return hashes;
    }
    
    /**
     * Computes base64url-encoded hashes for multiple disclosures.
     * 
     * @param disclosures Array of base64url-encoded disclosure strings
     * @return Array of base64url-encoded hashes
     * @throws SdJwtException if hashing fails
     */
    public static String[] computeHashesBase64url(String[] disclosures) throws SdJwtException {
        if (disclosures == null) {
            return new String[0];
        }
        
        String[] hashes = new String[disclosures.length];
        for (int i = 0; i < disclosures.length; i++) {
            hashes[i] = computeHashBase64url(disclosures[i]);
        }
        
        return hashes;
    }
    
    /**
     * Gets the default hash algorithm used for disclosures.
     * 
     * @return The default hash algorithm ("SHA-256")
     */
    public static String getDefaultHashAlgorithm() {
        return DEFAULT_HASH_ALGORITHM;
    }
}

// Made with Bob