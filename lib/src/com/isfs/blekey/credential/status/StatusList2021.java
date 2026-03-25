/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.credential.status;

import com.isfs.blekey.credential.jwt.JwtParser;
import com.isfs.blekey.util.http.HttpClient;
import com.isfs.blekey.util.http.HttpException;
import com.isfs.blekey.util.http.HttpResponse;
import com.isfs.blekey.util.http.RetryPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Implementation of Status List 2021 (RFC 9102) for credential revocation checking.
 * 
 * Status List 2021 uses a compressed bitstring where each bit represents the status
 * of a credential. The bitstring is published as a JWT and can be cached.
 * 
 * Bit values:
 * - 0: Valid
 * - 1: Revoked (or Suspended, depending on purpose)
 */
public class StatusList2021 {
    
    private static final Logger logger = LoggerFactory.getLogger(StatusList2021.class);
    private static final long DEFAULT_CACHE_TTL_MS = 3600000; // 1 hour
    
    private final HttpClient httpClient;
    private final Map<String, CachedStatusList> cache;
    
    public StatusList2021() {
        this.httpClient = new HttpClient();
        this.cache = new HashMap<>();
    }
    
    public StatusList2021(HttpClient httpClient) {
        this.httpClient = httpClient;
        this.cache = new HashMap<>();
    }
    
    /**
     * Checks the status of a credential.
     * 
     * @param statusListUrl URL to the status list JWT
     * @param statusListIndex Bit position in the status list
     * @return Credential status
     * @throws StatusListException if status check fails
     */
    public CredentialStatus checkStatus(String statusListUrl, int statusListIndex) 
            throws StatusListException {
        
        if (statusListUrl == null || statusListUrl.isEmpty()) {
            throw new StatusListException("Status list URL cannot be null or empty");
        }
        
        if (statusListIndex < 0) {
            throw new StatusListException("Status list index must be non-negative");
        }
        
        try {
            // Get status list (from cache or fetch)
            byte[] bitstring = getStatusListBitstring(statusListUrl);
            
            // Check bit at index
            boolean isRevoked = checkBit(bitstring, statusListIndex);
            
            logger.debug("Status check for index {}: {}", statusListIndex, 
                        isRevoked ? "REVOKED" : "VALID");
            
            return isRevoked ? CredentialStatus.REVOKED : CredentialStatus.VALID;
            
        } catch (Exception e) {
            logger.error("Failed to check credential status", e);
            return CredentialStatus.UNKNOWN;
        }
    }
    
    /**
     * Gets the status list bitstring, using cache if available.
     */
    private byte[] getStatusListBitstring(String statusListUrl) throws StatusListException {
        // Check cache
        CachedStatusList cached = cache.get(statusListUrl);
        if (cached != null && !cached.isExpired()) {
            logger.debug("Using cached status list for: {}", statusListUrl);
            return cached.bitstring;
        }
        
        // Fetch fresh status list
        logger.debug("Fetching status list from: {}", statusListUrl);
        byte[] bitstring = fetchStatusList(statusListUrl);
        
        // Cache it
        cache.put(statusListUrl, new CachedStatusList(bitstring, DEFAULT_CACHE_TTL_MS));
        
        return bitstring;
    }
    
    /**
     * Fetches and parses a status list from URL.
     */
    private byte[] fetchStatusList(String statusListUrl) throws StatusListException {
        try {
            // Fetch status list JWT
            HttpResponse response = httpClient.getWithRetry(
                statusListUrl,
                null,
                RetryPolicy.STATUS_CHECK
            );
            
            if (!response.isSuccessful()) {
                throw new StatusListException("Failed to fetch status list: " + response.getStatusCode());
            }
            
            String statusListJwt = response.getBody();
            if (statusListJwt == null || statusListJwt.isEmpty()) {
                throw new StatusListException("Empty status list response");
            }
            
            // Parse JWT (simplified - should verify signature in production)
            var claims = JwtParser.parseUnsecured(statusListJwt);
            
            // Extract status list from claims
            Object statusListObj = claims.getClaimValue("status_list");
            if (statusListObj == null) {
                throw new StatusListException("Status list not found in JWT");
            }
            
            @SuppressWarnings("unchecked")
            Map<String, Object> statusListMap = (Map<String, Object>) statusListObj;
            
            // Get compressed bitstring
            String encodedBits = (String) statusListMap.get("bits");
            if (encodedBits == null) {
                throw new StatusListException("Bitstring not found in status list");
            }
            
            // Decode base64url
            byte[] compressedBits = Base64.getUrlDecoder().decode(encodedBits);
            
            // Decompress (GZIP)
            byte[] bitstring = decompress(compressedBits);
            
            logger.info("Fetched status list: {} bits", bitstring.length * 8);
            return bitstring;
            
        } catch (HttpException e) {
            logger.error("HTTP error fetching status list", e);
            throw new StatusListException("Failed to fetch status list: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error("Failed to parse status list", e);
            throw new StatusListException("Failed to parse status list: " + e.getMessage(), e);
        }
    }
    
    /**
     * Checks if a bit is set at the given index.
     */
    private boolean checkBit(byte[] bitstring, int index) {
        int byteIndex = index / 8;
        int bitIndex = index % 8;
        
        if (byteIndex >= bitstring.length) {
            logger.warn("Status list index {} out of bounds", index);
            return false;
        }
        
        byte b = bitstring[byteIndex];
        int mask = 1 << (7 - bitIndex); // MSB first
        
        return (b & mask) != 0;
    }
    
    /**
     * Decompresses GZIP-compressed data.
     */
    private byte[] decompress(byte[] compressed) throws StatusListException {
        try {
            java.io.ByteArrayInputStream bais = new java.io.ByteArrayInputStream(compressed);
            java.util.zip.GZIPInputStream gzis = new java.util.zip.GZIPInputStream(bais);
            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
            
            byte[] buffer = new byte[1024];
            int len;
            while ((len = gzis.read(buffer)) > 0) {
                baos.write(buffer, 0, len);
            }
            
            gzis.close();
            return baos.toByteArray();
            
        } catch (Exception e) {
            logger.error("Failed to decompress status list", e);
            throw new StatusListException("Failed to decompress status list", e);
        }
    }
    
    /**
     * Clears the status list cache.
     */
    public void clearCache() {
        cache.clear();
        logger.debug("Status list cache cleared");
    }
    
    /**
     * Clears a specific status list from cache.
     */
    public void clearCache(String statusListUrl) {
        cache.remove(statusListUrl);
        logger.debug("Cleared cache for: {}", statusListUrl);
    }
    
    /**
     * Cached status list with expiry.
     */
    private static class CachedStatusList {
        final byte[] bitstring;
        final long expiryTime;
        
        CachedStatusList(byte[] bitstring, long ttlMs) {
            this.bitstring = bitstring;
            this.expiryTime = System.currentTimeMillis() + ttlMs;
        }
        
        boolean isExpired() {
            return System.currentTimeMillis() > expiryTime;
        }
    }
}

// Made with Bob