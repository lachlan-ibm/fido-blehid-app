/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.credential.sdjwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;

/**
 * Builds SD-JWT presentations with selective disclosure.
 * 
 * SD-JWT Presentation Format:
 * <issuer_jwt>~<disclosure_1>~<disclosure_2>~...~<kb_jwt>
 * 
 * This builder:
 * 1. Filters disclosures based on user-selected claims
 * 2. Assembles the presentation in the correct format
 * 3. Computes sd_hash for key binding JWT
 */
public class SelectiveDisclosureBuilder {
    
    private static final Logger logger = LoggerFactory.getLogger(SelectiveDisclosureBuilder.class);
    private static final String SEPARATOR = "~";
    
    /**
     * Builds an SD-JWT presentation with selected disclosures.
     * 
     * @param issuerJwt The issuer-signed JWT (without disclosures)
     * @param allDisclosures All available disclosures from the credential
     * @param selectedClaimNames Set of claim names to include in presentation
     * @return SD-JWT presentation string (without KB-JWT)
     * @throws SdJwtException if building fails
     */
    public static String buildPresentation(String issuerJwt,
                                          String[] allDisclosures,
                                          Set<String> selectedClaimNames) throws SdJwtException {
        
        if (issuerJwt == null || issuerJwt.isEmpty()) {
            throw new SdJwtException("Issuer JWT cannot be null or empty");
        }
        
        if (allDisclosures == null || allDisclosures.length == 0) {
            logger.debug("No disclosures available, returning issuer JWT only");
            return issuerJwt;
        }
        
        if (selectedClaimNames == null || selectedClaimNames.isEmpty()) {
            logger.debug("No claims selected, returning issuer JWT only");
            return issuerJwt;
        }
        
        try {
            // Parse all disclosures to filter by claim name
            List<String> selectedDisclosures = new ArrayList<>();
            
            for (String disclosure : allDisclosures) {
                Disclosure parsed = DisclosureParser.parse(disclosure);
                
                if (selectedClaimNames.contains(parsed.getClaimName())) {
                    selectedDisclosures.add(disclosure);
                    logger.debug("Including disclosure for claim: {}", parsed.getClaimName());
                }
            }
            
            // Build presentation: issuer_jwt~disclosure1~disclosure2~...
            StringBuilder presentation = new StringBuilder(issuerJwt);
            
            for (String disclosure : selectedDisclosures) {
                presentation.append(SEPARATOR).append(disclosure);
            }
            
            logger.info("Built SD-JWT presentation with {} disclosures", selectedDisclosures.size());
            return presentation.toString();
            
        } catch (SdJwtException e) {
            logger.error("Failed to build presentation", e);
            throw e;
        }
    }
    
    /**
     * Builds a complete SD-JWT presentation including key binding JWT.
     * 
     * @param issuerJwt The issuer-signed JWT
     * @param allDisclosures All available disclosures
     * @param selectedClaimNames Set of claim names to include
     * @param keyBindingJwt The key binding JWT
     * @return Complete SD-JWT presentation string
     * @throws SdJwtException if building fails
     */
    public static String buildPresentationWithKeyBinding(String issuerJwt,
                                                        String[] allDisclosures,
                                                        Set<String> selectedClaimNames,
                                                        String keyBindingJwt) throws SdJwtException {
        
        String presentation = buildPresentation(issuerJwt, allDisclosures, selectedClaimNames);
        
        if (keyBindingJwt == null || keyBindingJwt.isEmpty()) {
            logger.warn("No key binding JWT provided");
            return presentation;
        }
        
        // Append key binding JWT: presentation~kb_jwt
        return presentation + SEPARATOR + keyBindingJwt;
    }
    
    /**
     * Computes the sd_hash for key binding JWT.
     * 
     * The sd_hash is the base64url-encoded SHA-256 hash of the concatenated
     * disclosures (without separators), used for integrity protection.
     * 
     * @param selectedDisclosures Array of selected disclosure strings
     * @return Base64url-encoded sd_hash
     * @throws SdJwtException if hash computation fails
     */
    public static String computeSdHash(String[] selectedDisclosures) throws SdJwtException {
        if (selectedDisclosures == null || selectedDisclosures.length == 0) {
            logger.debug("No disclosures for sd_hash, returning empty string");
            return "";
        }
        
        try {
            // Concatenate all disclosures
            StringBuilder concatenated = new StringBuilder();
            for (String disclosure : selectedDisclosures) {
                concatenated.append(disclosure);
            }
            
            // Compute SHA-256 hash
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(concatenated.toString().getBytes(StandardCharsets.US_ASCII));
            
            // Base64url encode
            String sdHash = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
            
            logger.debug("Computed sd_hash for {} disclosures", selectedDisclosures.length);
            return sdHash;
            
        } catch (Exception e) {
            logger.error("Failed to compute sd_hash", e);
            throw new SdJwtException("Failed to compute sd_hash: " + e.getMessage(), e);
        }
    }
    
    /**
     * Extracts disclosures from an SD-JWT presentation.
     * 
     * @param presentation The SD-JWT presentation string
     * @return Array of disclosure strings (excluding issuer JWT and KB-JWT)
     */
    public static String[] extractDisclosures(String presentation) {
        if (presentation == null || presentation.isEmpty()) {
            return new String[0];
        }
        
        String[] parts = presentation.split(SEPARATOR);
        
        if (parts.length <= 1) {
            // Only issuer JWT, no disclosures
            return new String[0];
        }
        
        // First part is issuer JWT, last part might be KB-JWT
        // Middle parts are disclosures
        List<String> disclosures = new ArrayList<>();
        
        for (int i = 1; i < parts.length; i++) {
            String part = parts[i];
            
            // Simple heuristic: disclosures are base64url without dots
            // JWTs have dots (header.payload.signature)
            if (!part.contains(".")) {
                disclosures.add(part);
            }
        }
        
        return disclosures.toArray(new String[0]);
    }
    
    /**
     * Validates an SD-JWT presentation format.
     * 
     * @param presentation The presentation to validate
     * @return true if format is valid, false otherwise
     */
    public static boolean isValidPresentation(String presentation) {
        if (presentation == null || presentation.isEmpty()) {
            return false;
        }
        
        String[] parts = presentation.split(SEPARATOR);
        
        // Must have at least issuer JWT
        if (parts.length < 1) {
            return false;
        }
        
        // First part should be a JWT (has dots)
        if (!parts[0].contains(".")) {
            return false;
        }
        
        return true;
    }
}

// Made with Bob