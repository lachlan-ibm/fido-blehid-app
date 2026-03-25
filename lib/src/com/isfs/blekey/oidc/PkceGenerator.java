/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.oidc;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Generates PKCE (Proof Key for Code Exchange) parameters for OAuth 2.0 authorization code flow.
 * Implements RFC 7636 for enhanced security in public clients.
 * 
 * PKCE Flow:
 * 1. Generate random code_verifier (43-128 characters)
 * 2. Compute code_challenge = BASE64URL(SHA256(code_verifier))
 * 3. Send code_challenge with authorization request
 * 4. Send code_verifier with token request
 * 5. Server verifies: SHA256(code_verifier) == code_challenge
 */
public class PkceGenerator {
    
    private static final int CODE_VERIFIER_LENGTH = 64; // 64 bytes = 86 base64url chars (within 43-128 range)
    private static final String CODE_CHALLENGE_METHOD = "S256"; // SHA-256
    
    private final String codeVerifier;
    private final String codeChallenge;
    
    /**
     * Generates a new PKCE parameter pair.
     * 
     * @throws OidcException if PKCE generation fails
     */
    public PkceGenerator() throws OidcException {
        this.codeVerifier = generateCodeVerifier();
        this.codeChallenge = generateCodeChallenge(this.codeVerifier);
    }
    
    /**
     * Creates a PKCE generator with a specific code verifier (for testing).
     * 
     * @param codeVerifier The code verifier to use
     * @throws OidcException if code challenge generation fails
     */
    public PkceGenerator(String codeVerifier) throws OidcException {
        if (codeVerifier == null || codeVerifier.length() < 43 || codeVerifier.length() > 128) {
            throw new OidcException("Code verifier must be between 43 and 128 characters");
        }
        this.codeVerifier = codeVerifier;
        this.codeChallenge = generateCodeChallenge(this.codeVerifier);
    }
    
    /**
     * Gets the code verifier.
     * This should be sent with the token request.
     * 
     * @return The code verifier string
     */
    public String getCodeVerifier() {
        return codeVerifier;
    }
    
    /**
     * Gets the code challenge.
     * This should be sent with the authorization request.
     * 
     * @return The code challenge string
     */
    public String getCodeChallenge() {
        return codeChallenge;
    }
    
    /**
     * Gets the code challenge method.
     * Always returns "S256" (SHA-256).
     * 
     * @return The code challenge method
     */
    public String getCodeChallengeMethod() {
        return CODE_CHALLENGE_METHOD;
    }
    
    /**
     * Generates a cryptographically random code verifier.
     * 
     * @return Base64url-encoded random string (86 characters)
     * @throws OidcException if random generation fails
     */
    private String generateCodeVerifier() throws OidcException {
        try {
            SecureRandom random = SecureRandom.getInstanceStrong();
            byte[] randomBytes = new byte[CODE_VERIFIER_LENGTH];
            random.nextBytes(randomBytes);
            
            // Base64url encode without padding
            return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new OidcException("Failed to generate code verifier", e);
        }
    }
    
    /**
     * Generates the code challenge from the code verifier.
     * code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
     * 
     * @param codeVerifier The code verifier
     * @return The code challenge
     * @throws OidcException if SHA-256 is not available
     */
    private String generateCodeChallenge(String codeVerifier) throws OidcException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            
            // Base64url encode without padding
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new OidcException("SHA-256 algorithm not available", e);
        }
    }
    
    /**
     * Verifies that a code verifier matches a code challenge.
     * Used for testing and validation.
     * 
     * @param codeVerifier The code verifier to verify
     * @param codeChallenge The expected code challenge
     * @return true if the verifier matches the challenge, false otherwise
     */
    public static boolean verify(String codeVerifier, String codeChallenge) {
        try {
            PkceGenerator generator = new PkceGenerator(codeVerifier);
            return generator.getCodeChallenge().equals(codeChallenge);
        } catch (OidcException e) {
            return false;
        }
    }
    
    @Override
    public String toString() {
        return "PkceGenerator{" +
               "codeVerifierLength=" + codeVerifier.length() +
               ", codeChallengeMethod=" + CODE_CHALLENGE_METHOD +
               '}';
    }
}

// Made with Bob