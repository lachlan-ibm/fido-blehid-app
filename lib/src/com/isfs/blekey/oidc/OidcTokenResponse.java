/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.oidc;

import com.isfs.blekey.util.JsonUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * Represents an OAuth 2.0 / OIDC token response.
 * Parses and provides access to tokens returned from the token endpoint.
 * 
 * Standard fields per RFC 6749:
 * - access_token: The access token issued by the authorization server
 * - token_type: The type of token (usually "Bearer")
 * - expires_in: Lifetime in seconds of the access token
 * - refresh_token: (optional) Token for obtaining new access tokens
 * - scope: (optional) Scope of the access token
 * 
 * OIDC extensions:
 * - id_token: (optional) JWT containing user identity claims
 * - c_nonce: (optional) Nonce for credential issuance proof
 * - c_nonce_expires_in: (optional) Lifetime of c_nonce
 */
public class OidcTokenResponse {
    
    private static final Logger logger = LoggerFactory.getLogger(OidcTokenResponse.class);
    
    private final String accessToken;
    private final String tokenType;
    private final Long expiresIn;
    private final String refreshToken;
    private final String scope;
    private final String idToken;
    private final String cNonce;
    private final Long cNonceExpiresIn;
    private final Map<String, Object> rawResponse;
    
    /**
     * Creates a token response from parsed JSON.
     * 
     * @param responseMap The parsed JSON response from token endpoint
     * @throws OidcException if required fields are missing
     */
    public OidcTokenResponse(Map<String, Object> responseMap) throws OidcException {
        if (responseMap == null) {
            throw new OidcException("Token response cannot be null");
        }
        
        this.rawResponse = responseMap;
        
        // Required fields
        this.accessToken = (String) responseMap.get("access_token");
        if (this.accessToken == null || this.accessToken.isEmpty()) {
            throw new OidcException("access_token is required in token response");
        }
        
        this.tokenType = (String) responseMap.get("token_type");
        if (this.tokenType == null || this.tokenType.isEmpty()) {
            throw new OidcException("token_type is required in token response");
        }
        
        // Optional fields
        this.expiresIn = getLongValue(responseMap, "expires_in");
        this.refreshToken = (String) responseMap.get("refresh_token");
        this.scope = (String) responseMap.get("scope");
        this.idToken = (String) responseMap.get("id_token");
        
        // OIDC4VCI specific fields
        this.cNonce = (String) responseMap.get("c_nonce");
        this.cNonceExpiresIn = getLongValue(responseMap, "c_nonce_expires_in");
        
        logger.debug("Parsed token response: tokenType={}, expiresIn={}, hasRefreshToken={}, hasCNonce={}",
                    tokenType, expiresIn, refreshToken != null, cNonce != null);
    }
    
    /**
     * Parses a token response from JSON string.
     * 
     * @param jsonResponse The JSON response string
     * @return Parsed token response
     * @throws OidcException if parsing fails or required fields are missing
     */
    public static OidcTokenResponse fromJson(String jsonResponse) throws OidcException {
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> responseMap = (Map<String, Object>) JsonUtils.decode(jsonResponse, Map.class);
            if (responseMap == null) {
                throw new OidcException("Failed to parse JSON response");
            }
            return new OidcTokenResponse(responseMap);
        } catch (Exception e) {
            logger.error("Failed to parse token response", e);
            throw new OidcException("Failed to parse token response: " + e.getMessage(), e);
        }
    }
    
    /**
     * Gets the access token.
     * @return The access token
     */
    public String getAccessToken() {
        return accessToken;
    }
    
    /**
     * Gets the token type (usually "Bearer").
     * @return The token type
     */
    public String getTokenType() {
        return tokenType;
    }
    
    /**
     * Gets the token expiration time in seconds.
     * @return Expiration time in seconds, or null if not provided
     */
    public Long getExpiresIn() {
        return expiresIn;
    }
    
    /**
     * Gets the refresh token.
     * @return The refresh token, or null if not provided
     */
    public String getRefreshToken() {
        return refreshToken;
    }
    
    /**
     * Gets the scope of the access token.
     * @return The scope, or null if not provided
     */
    public String getScope() {
        return scope;
    }
    
    /**
     * Gets the ID token (OIDC).
     * @return The ID token JWT, or null if not provided
     */
    public String getIdToken() {
        return idToken;
    }
    
    /**
     * Gets the c_nonce for credential issuance proof (OIDC4VCI).
     * @return The c_nonce, or null if not provided
     */
    public String getCNonce() {
        return cNonce;
    }
    
    /**
     * Gets the c_nonce expiration time in seconds (OIDC4VCI).
     * @return Expiration time in seconds, or null if not provided
     */
    public Long getCNonceExpiresIn() {
        return cNonceExpiresIn;
    }
    
    /**
     * Gets the raw response map for accessing custom fields.
     * @return The raw response map
     */
    public Map<String, Object> getRawResponse() {
        return rawResponse;
    }
    
    /**
     * Checks if the token response has a refresh token.
     * @return true if refresh token is present, false otherwise
     */
    public boolean hasRefreshToken() {
        return refreshToken != null && !refreshToken.isEmpty();
    }
    
    /**
     * Checks if the token response has an ID token.
     * @return true if ID token is present, false otherwise
     */
    public boolean hasIdToken() {
        return idToken != null && !idToken.isEmpty();
    }
    
    /**
     * Checks if the token response has a c_nonce.
     * @return true if c_nonce is present, false otherwise
     */
    public boolean hasCNonce() {
        return cNonce != null && !cNonce.isEmpty();
    }
    
    /**
     * Helper method to safely extract Long values from response map.
     */
    private Long getLongValue(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value == null) {
            return null;
        }
        if (value instanceof Number) {
            return ((Number) value).longValue();
        }
        try {
            return Long.parseLong(value.toString());
        } catch (NumberFormatException e) {
            logger.warn("Failed to parse {} as Long: {}", key, value);
            return null;
        }
    }
    
    @Override
    public String toString() {
        return "OidcTokenResponse{" +
               "tokenType='" + tokenType + '\'' +
               ", expiresIn=" + expiresIn +
               ", hasRefreshToken=" + hasRefreshToken() +
               ", hasIdToken=" + hasIdToken() +
               ", hasCNonce=" + hasCNonce() +
               '}';
    }
}

// Made with Bob