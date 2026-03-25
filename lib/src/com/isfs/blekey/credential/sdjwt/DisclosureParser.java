/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.credential.sdjwt;

import com.isfs.blekey.util.JsonUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

/**
 * Parser for SD-JWT disclosures.
 * 
 * Disclosures are base64url-encoded JSON arrays containing [salt, claim_name, claim_value].
 * This parser extracts and validates disclosure components according to IETF 
 * draft-ietf-oauth-selective-disclosure-jwt-08.
 * 
 * Example disclosure:
 * Base64url([
 *   "2GLC42sKQveCfGfryNRN9w",  // salt
 *   "given_name",               // claim name
 *   "John"                      // claim value
 * ])
 */
public class DisclosureParser {
    
    private static final Logger logger = LoggerFactory.getLogger(DisclosureParser.class);
    
    /**
     * Parses a base64url-encoded disclosure string.
     * 
     * @param base64urlDisclosure The base64url-encoded disclosure
     * @return Parsed Disclosure object
     * @throws SdJwtException if disclosure format is invalid
     */
    public static Disclosure parse(String base64urlDisclosure) throws SdJwtException {
        if (base64urlDisclosure == null || base64urlDisclosure.isEmpty()) {
            throw new SdJwtException("Disclosure cannot be null or empty");
        }
        
        try {
            // Base64url decode
            byte[] decodedBytes = Base64.getUrlDecoder().decode(base64urlDisclosure);
            String decodedJson = new String(decodedBytes, StandardCharsets.UTF_8);
            
            // Parse JSON array
            @SuppressWarnings("unchecked")
            List<Object> array = (List<Object>) JsonUtils.decode(decodedJson, List.class);
            
            // Validate array structure
            if (array == null || array.size() != 3) {
                throw new SdJwtException("Disclosure must be a JSON array with exactly 3 elements");
            }
            
            // Extract components
            String salt = (String) array.get(0);
            String claimName = (String) array.get(1);
            Object claimValue = array.get(2);
            
            // Validate components
            if (salt == null || salt.isEmpty()) {
                throw new SdJwtException("Disclosure salt cannot be null or empty");
            }
            if (claimName == null || claimName.isEmpty()) {
                throw new SdJwtException("Disclosure claim name cannot be null or empty");
            }
            
            logger.debug("Parsed disclosure: claimName={}, hasSalt={}, hasValue={}", 
                        claimName, true, claimValue != null);
            
            return new Disclosure(salt, claimName, claimValue, base64urlDisclosure);
            
        } catch (IllegalArgumentException e) {
            logger.error("Failed to decode base64url disclosure", e);
            throw new SdJwtException("Invalid base64url encoding in disclosure", e);
        } catch (ClassCastException e) {
            logger.error("Invalid disclosure structure", e);
            throw new SdJwtException("Disclosure has invalid structure", e);
        } catch (Exception e) {
            logger.error("Failed to parse disclosure", e);
            throw new SdJwtException("Failed to parse disclosure: " + e.getMessage(), e);
        }
    }
    
    /**
     * Parses multiple disclosures from an array of base64url-encoded strings.
     * 
     * @param base64urlDisclosures Array of base64url-encoded disclosures
     * @return Array of parsed Disclosure objects
     * @throws SdJwtException if any disclosure is invalid
     */
    public static Disclosure[] parseMultiple(String[] base64urlDisclosures) throws SdJwtException {
        if (base64urlDisclosures == null) {
            return new Disclosure[0];
        }
        
        Disclosure[] disclosures = new Disclosure[base64urlDisclosures.length];
        for (int i = 0; i < base64urlDisclosures.length; i++) {
            disclosures[i] = parse(base64urlDisclosures[i]);
        }
        
        return disclosures;
    }
    
    /**
     * Validates that a string is a valid base64url-encoded disclosure.
     * 
     * @param base64urlDisclosure The disclosure to validate
     * @return true if valid, false otherwise
     */
    public static boolean isValid(String base64urlDisclosure) {
        try {
            parse(base64urlDisclosure);
            return true;
        } catch (SdJwtException e) {
            return false;
        }
    }
}

// Made with Bob