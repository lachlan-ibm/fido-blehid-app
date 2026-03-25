/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.oidc;

import com.isfs.blekey.util.JsonUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents an OIDC4VCI Credential Offer.
 * Parses credential offers from URIs and provides access to offer details.
 * 
 * Credential Offer URI formats:
 * 1. By value: openid-credential-offer://?credential_offer={json}
 * 2. By reference: openid-credential-offer://?credential_offer_uri={url}
 * 
 * Credential Offer structure:
 * {
 *   "credential_issuer": "https://issuer.example.com",
 *   "credentials": ["UniversityDegree", "DriverLicense"],
 *   "grants": {
 *     "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
 *       "pre-authorized_code": "code123",
 *       "user_pin_required": false
 *     }
 *   }
 * }
 */
public class CredentialOffer {
    
    private static final Logger logger = LoggerFactory.getLogger(CredentialOffer.class);
    private static final String SCHEME = "openid-credential-offer";
    private static final String PRE_AUTHORIZED_CODE_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
    
    private final String credentialIssuer;
    private final List<String> credentials;
    private final Map<String, Object> grants;
    private final Map<String, Object> rawOffer;
    
    /**
     * Creates a credential offer from parsed JSON.
     * 
     * @param offerMap The parsed credential offer JSON
     * @throws OidcException if required fields are missing
     */
    public CredentialOffer(Map<String, Object> offerMap) throws OidcException {
        if (offerMap == null) {
            throw new OidcException("Credential offer cannot be null");
        }
        
        this.rawOffer = offerMap;
        
        // Required: credential_issuer
        this.credentialIssuer = (String) offerMap.get("credential_issuer");
        if (this.credentialIssuer == null || this.credentialIssuer.isEmpty()) {
            throw new OidcException("credential_issuer is required in credential offer");
        }
        
        // Required: credentials (array of credential types)
        Object credentialsObj = offerMap.get("credentials");
        if (credentialsObj == null) {
            throw new OidcException("credentials is required in credential offer");
        }
        
        this.credentials = new ArrayList<>();
        if (credentialsObj instanceof List) {
            @SuppressWarnings("unchecked")
            List<Object> credList = (List<Object>) credentialsObj;
            for (Object cred : credList) {
                if (cred instanceof String) {
                    this.credentials.add((String) cred);
                } else if (cred instanceof Map) {
                    // Handle credential configuration object
                    @SuppressWarnings("unchecked")
                    Map<String, Object> credMap = (Map<String, Object>) cred;
                    String format = (String) credMap.get("format");
                    if (format != null) {
                        this.credentials.add(format);
                    }
                }
            }
        }
        
        if (this.credentials.isEmpty()) {
            throw new OidcException("At least one credential must be offered");
        }
        
        // Optional: grants
        Object grantsObj = offerMap.get("grants");
        if (grantsObj instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> grantsMap = (Map<String, Object>) grantsObj;
            this.grants = grantsMap;
        } else {
            this.grants = new HashMap<>();
        }
        
        logger.debug("Parsed credential offer: issuer={}, credentials={}, grants={}",
                    credentialIssuer, credentials, grants.keySet());
    }
    
    /**
     * Parses a credential offer from a URI.
     * 
     * @param uri The credential offer URI
     * @return Parsed credential offer
     * @throws OidcException if parsing fails
     */
    public static CredentialOffer fromUri(String uri) throws OidcException {
        try {
            URI parsedUri = URI.create(uri);
            
            // Validate scheme
            if (!SCHEME.equals(parsedUri.getScheme())) {
                throw new OidcException("Invalid credential offer URI scheme: " + parsedUri.getScheme());
            }
            
            // Parse query parameters
            String query = parsedUri.getQuery();
            if (query == null || query.isEmpty()) {
                throw new OidcException("Credential offer URI must contain query parameters");
            }
            
            Map<String, String> params = parseQueryString(query);
            
            // Check for credential_offer (by value)
            if (params.containsKey("credential_offer")) {
                String offerJson = params.get("credential_offer");
                return fromJson(offerJson);
            }
            
            // Check for credential_offer_uri (by reference)
            if (params.containsKey("credential_offer_uri")) {
                throw new OidcException("Credential offer by reference not yet supported");
            }
            
            throw new OidcException("Credential offer URI must contain credential_offer or credential_offer_uri");
            
        } catch (Exception e) {
            logger.error("Failed to parse credential offer URI", e);
            throw new OidcException("Failed to parse credential offer URI: " + e.getMessage(), e);
        }
    }
    
    /**
     * Parses a credential offer from JSON string.
     * 
     * @param json The credential offer JSON
     * @return Parsed credential offer
     * @throws OidcException if parsing fails
     */
    public static CredentialOffer fromJson(String json) throws OidcException {
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> offerMap = (Map<String, Object>) JsonUtils.decode(json, Map.class);
            if (offerMap == null) {
                throw new OidcException("Failed to parse credential offer JSON");
            }
            return new CredentialOffer(offerMap);
        } catch (Exception e) {
            logger.error("Failed to parse credential offer JSON", e);
            throw new OidcException("Failed to parse credential offer JSON: " + e.getMessage(), e);
        }
    }
    
    /**
     * Gets the credential issuer URL.
     * @return The credential issuer URL
     */
    public String getCredentialIssuer() {
        return credentialIssuer;
    }
    
    /**
     * Gets the list of offered credential types.
     * @return List of credential types
     */
    public List<String> getCredentials() {
        return new ArrayList<>(credentials);
    }
    
    /**
     * Gets the grants map.
     * @return Map of grant types to grant details
     */
    public Map<String, Object> getGrants() {
        return new HashMap<>(grants);
    }
    
    /**
     * Gets the raw credential offer map.
     * @return The raw offer map
     */
    public Map<String, Object> getRawOffer() {
        return rawOffer;
    }
    
    /**
     * Checks if the offer includes a pre-authorized code grant.
     * @return true if pre-authorized code grant is present
     */
    public boolean hasPreAuthorizedCodeGrant() {
        return grants.containsKey(PRE_AUTHORIZED_CODE_GRANT);
    }
    
    /**
     * Gets the pre-authorized code from the grant.
     * @return The pre-authorized code, or null if not present
     */
    public String getPreAuthorizedCode() {
        if (!hasPreAuthorizedCodeGrant()) {
            return null;
        }
        
        Object grantObj = grants.get(PRE_AUTHORIZED_CODE_GRANT);
        if (grantObj instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> grantMap = (Map<String, Object>) grantObj;
            return (String) grantMap.get("pre-authorized_code");
        }
        
        return null;
    }
    
    /**
     * Checks if user PIN is required for the pre-authorized code grant.
     * @return true if user PIN is required
     */
    public boolean isUserPinRequired() {
        if (!hasPreAuthorizedCodeGrant()) {
            return false;
        }
        
        Object grantObj = grants.get(PRE_AUTHORIZED_CODE_GRANT);
        if (grantObj instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> grantMap = (Map<String, Object>) grantObj;
            Object pinRequired = grantMap.get("user_pin_required");
            if (pinRequired instanceof Boolean) {
                return (Boolean) pinRequired;
            }
        }
        
        return false;
    }
    
    /**
     * Parses a query string into a map of parameters.
     */
    private static Map<String, String> parseQueryString(String query) throws UnsupportedEncodingException {
        Map<String, String> params = new HashMap<>();
        String[] pairs = query.split("&");
        
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            if (idx > 0) {
                String key = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8.name());
                String value = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8.name());
                params.put(key, value);
            }
        }
        
        return params;
    }
    
    @Override
    public String toString() {
        return "CredentialOffer{" +
               "credentialIssuer='" + credentialIssuer + '\'' +
               ", credentials=" + credentials +
               ", hasPreAuthorizedCode=" + hasPreAuthorizedCodeGrant() +
               ", userPinRequired=" + isUserPinRequired() +
               '}';
    }
}

// Made with Bob