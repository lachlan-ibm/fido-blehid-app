/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.oidc;

import com.isfs.blekey.util.JsonUtils;
import com.isfs.blekey.util.http.HttpClient;
import com.isfs.blekey.util.http.HttpException;
import com.isfs.blekey.util.http.HttpResponse;
import com.isfs.blekey.util.http.RetryPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents OIDC4VCI Issuer Metadata.
 * Fetches and parses issuer metadata from the credential issuer's well-known endpoint.
 * 
 * Metadata endpoint: {credential_issuer}/.well-known/openid-credential-issuer
 * 
 * Example metadata:
 * {
 *   "credential_issuer": "https://issuer.example.com",
 *   "credential_endpoint": "https://issuer.example.com/credential",
 *   "token_endpoint": "https://issuer.example.com/token",
 *   "credentials_supported": [
 *     {
 *       "format": "jwt_vc_json",
 *       "types": ["VerifiableCredential", "UniversityDegree"],
 *       "cryptographic_binding_methods_supported": ["jwk"],
 *       "cryptographic_suites_supported": ["ES256"]
 *     }
 *   ]
 * }
 */
public class IssuerMetadata {
    
    private static final Logger logger = LoggerFactory.getLogger(IssuerMetadata.class);
    private static final String WELL_KNOWN_PATH = "/.well-known/openid-credential-issuer";
    
    private final String credentialIssuer;
    private final String credentialEndpoint;
    private String tokenEndpoint;
    private final List<Map<String, Object>> authorization_servers;
    private final List<Map<String, Object>> credentialsSupported;
    private final Map<String, Object> rawMetadata;
    
    /**
     * Creates issuer metadata from parsed JSON.
     * 
     * @param metadataMap The parsed issuer metadata JSON
     * @throws OidcException if required fields are missing
     */
    public IssuerMetadata(Map<String, Object> metadataMap, HttpClient httpClient) throws OidcException {
        if (metadataMap == null) {
            throw new OidcException("Issuer metadata cannot be null");
        }
        
        this.rawMetadata = metadataMap;
        
        // Required: credential_issuer
        this.credentialIssuer = (String) metadataMap.get("credential_issuer");
        if (this.credentialIssuer == null || this.credentialIssuer.isEmpty()) {
            throw new OidcException("credential_issuer is required in issuer metadata");
        }
        
        // Required: credential_endpoint
        this.credentialEndpoint = (String) metadataMap.get("credential_endpoint");
        if (this.credentialEndpoint == null || this.credentialEndpoint.isEmpty()) {
            throw new OidcException("credential_endpoint is required in issuer metadata");
        }
        
        // Optional but commonly present: token_endpoint
        this.tokenEndpoint = (String) metadataMap.get("token_endpoint");
        
        // Optional: credentials_supported
        Object credsSupportedObj = metadataMap.get("credentials_supported");
        if (credsSupportedObj instanceof List) {
            @SuppressWarnings("unchecked")
            List<Object> credsList = (List<Object>) credsSupportedObj;
            this.credentialsSupported = new ArrayList<>();
            for (Object cred : credsList) {
                if (cred instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> credMap = (Map<String, Object>) cred;
                    this.credentialsSupported.add(credMap);
                }
            }
        } else {
            this.credentialsSupported = new ArrayList<>();
        }

        this.authorization_servers = new ArrayList<>();
        Object authServers = metadataMap.get("authorization_servers");
        if (authServers instanceof List) {
            for (Object svrObj : (List<Object>) authServers) {
                Map<String, Object> asMetadata = fetchAuthServerMetadata((String) svrObj, httpClient);
                if (asMetadata != null) {
                    this.authorization_servers.add(asMetadata);
                }
            }
        }

        if (this.tokenEndpoint == null) {
            for (Map<String, Object> asDoc : this.authorization_servers) {
                if (asDoc.get("token_endpoint") instanceof String) {
                    this.tokenEndpoint = (String) asDoc.get("token_endpoint");
                    break;
                }
            }
        }
        
        logger.debug("Parsed issuer metadata: issuer={}, credentialEndpoint={}, tokenEndpoint={}, credentialsSupported={}",
                    credentialIssuer, credentialEndpoint, tokenEndpoint, credentialsSupported.size());
    }


    private static Map<String, Object> fetchAuthServerMetadata(String authServerUrl, HttpClient httpClient) {
        String base = authServerUrl.endsWith("/") ? authServerUrl.substring(0, authServerUrl.length() - 1) : authServerUrl;
        for (String path : new String[]{
                "/.well-known/oauth-authorization-server",
                "/.well-known/openid-configuration"}) {
            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Accept", "application/json");
                HttpResponse r = httpClient.getWithRetry(base + path, headers, RetryPolicy.ISSUANCE);
                if (r.isSuccessful()) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> asDoc = (Map<String, Object>) JsonUtils.decode(r.getBody(), Map.class);
                    if (asDoc != null) {
                        return asDoc;
                    }
                }
            } catch (Exception e) {
                logger.warn("Failed to fetch AS metadata from {}{}: {}", base, path, e.getMessage());
            }
        }
        return null;
    }
    
    /**
     * Fetches issuer metadata from the credential issuer's well-known endpoint.
     * 
     * @param credentialIssuerUrl The credential issuer URL
     * @return Parsed issuer metadata
     * @throws OidcException if fetching or parsing fails
     */
    public static IssuerMetadata fetch(String credentialIssuerUrl) throws OidcException {
        return fetch(credentialIssuerUrl, new HttpClient());
    }
    
    /**
     * Fetches issuer metadata using a custom HTTP client.
     * 
     * @param credentialIssuerUrl The credential issuer URL
     * @param httpClient The HTTP client to use
     * @return Parsed issuer metadata
     * @throws OidcException if fetching or parsing fails
     */
    public static IssuerMetadata fetch(String credentialIssuerUrl, HttpClient httpClient) throws OidcException {
        try {
            // Construct well-known URL
            String wellKnownUrl = credentialIssuerUrl;
            if (wellKnownUrl.endsWith("/")) {
                wellKnownUrl = wellKnownUrl.substring(0, wellKnownUrl.length() - 1);
            }
            wellKnownUrl += WELL_KNOWN_PATH;
            
            logger.debug("Fetching issuer metadata from: {}", wellKnownUrl);
            
            // Fetch metadata with retry
            Map<String, String> headers = new HashMap<>();
            headers.put("Accept", "application/json");
            
            HttpResponse response = httpClient.getWithRetry(wellKnownUrl, headers, RetryPolicy.ISSUANCE);
            
            if (!response.isSuccessful()) {
                throw new OidcException("Failed to fetch issuer metadata: HTTP " + response.getStatusCode());
            }
            
            // Parse metadata to JSON and process
            return new IssuerMetadata(
                (Map<String, Object>) JsonUtils.decode(response.getBody(), Map.class),
                httpClient);
            
        } catch (HttpException e) {
            logger.error("HTTP error fetching issuer metadata", e);
            throw new OidcException("Failed to fetch issuer metadata: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error("Unexpected error fetching issuer metadata", e);
            throw new OidcException("Failed to fetch issuer metadata: " + e.getMessage(), e);
        }
    }
    
    /**
     * Parses issuer metadata from JSON string.
     * 
     * @param json The issuer metadata JSON
     * @return Parsed issuer metadata
     * @throws OidcException if parsing fails
     */
    public static IssuerMetadata fromJson(String json) throws OidcException {
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> metadataMap = (Map<String, Object>) JsonUtils.decode(json, Map.class);
            if (metadataMap == null) {
                throw new OidcException("Failed to parse issuer metadata JSON");
            }
            return new IssuerMetadata(metadataMap, null);
        } catch (Exception e) {
            logger.error("Failed to parse issuer metadata JSON", e);
            throw new OidcException("Failed to parse issuer metadata JSON: " + e.getMessage(), e);
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
     * Gets the credential endpoint URL.
     * @return The credential endpoint URL
     */
    public String getCredentialEndpoint() {
        return credentialEndpoint;
    }
    
    /**
     * Gets the token endpoint URL.
     * @return The token endpoint URL, or null if not provided
     */
    public String getTokenEndpoint() {
        return tokenEndpoint;
    }
    
    /**
     * Gets the list of supported credentials.
     * @return List of credential configurations
     */
    public List<Map<String, Object>> getCredentialsSupported() {
        return new ArrayList<>(credentialsSupported);
    }
    
    /**
     * Gets the raw metadata map.
     * @return The raw metadata map
     */
    public Map<String, Object> getRawMetadata() {
        return rawMetadata;
    }
    
    /**
     * Checks if a specific credential format is supported.
     * 
     * @param format The credential format (e.g., "jwt_vc_json", "ldp_vc")
     * @return true if format is supported
     */
    public boolean supportsFormat(String format) {
        for (Map<String, Object> cred : credentialsSupported) {
            String credFormat = (String) cred.get("format");
            if (format.equals(credFormat)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Checks if a specific cryptographic suite is supported.
     * 
     * @param suite The cryptographic suite (e.g., "ES256", "EdDSA")
     * @return true if suite is supported
     */
    public boolean supportsCryptographicSuite(String suite) {
        for (Map<String, Object> cred : credentialsSupported) {
            Object suitesObj = cred.get("cryptographic_suites_supported");
            if (suitesObj instanceof List) {
                @SuppressWarnings("unchecked")
                List<String> suites = (List<String>) suitesObj;
                if (suites.contains(suite)) {
                    return true;
                }
            }
        }
        return false;
    }
    
    /**
     * Gets supported proof types for credential issuance.
     * 
     * @return List of supported proof types (e.g., "jwt", "cwt")
     */
    public List<String> getSupportedProofTypes() {
        List<String> proofTypes = new ArrayList<>();
        Object proofTypesObj = rawMetadata.get("proof_types_supported");
        
        if (proofTypesObj instanceof List) {
            @SuppressWarnings("unchecked")
            List<String> types = (List<String>) proofTypesObj;
            proofTypes.addAll(types);
        } else {
            // Default to JWT if not specified
            proofTypes.add("jwt");
        }
        
        return proofTypes;
    }
    
    @Override
    public String toString() {
        return "IssuerMetadata{" +
               "credentialIssuer='" + credentialIssuer + '\'' +
               ", credentialEndpoint='" + credentialEndpoint + '\'' +
               ", tokenEndpoint='" + tokenEndpoint + '\'' +
               ", credentialsSupported=" + credentialsSupported.size() +
               '}';
    }
}

// Made with Bob