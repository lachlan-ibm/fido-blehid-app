/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.oidc;

import com.isfs.blekey.credential.VerifiableCredential;
import com.isfs.blekey.credential.jwt.JwtException;
import com.isfs.blekey.credential.jwt.KeyBindingJwtBuilder;
import com.isfs.blekey.credential.sdjwt.SelectiveDisclosureBuilder;
import com.isfs.blekey.credential.sdjwt.SdJwtException;
import com.isfs.blekey.util.HolderBindingKeyManager;
import com.isfs.blekey.util.JsonUtils;
import com.isfs.blekey.util.http.HttpClient;
import com.isfs.blekey.util.http.HttpException;
import com.isfs.blekey.util.http.HttpResponse;
import com.isfs.blekey.util.http.RetryPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * OIDC4VP Handler for credential presentation.
 * Implements the OpenID for Verifiable Presentations (OIDC4VP) protocol.
 * 
 * Presentation Flow:
 * 1. Parse authorization request
 * 2. Fetch request object (if by reference)
 * 3. Parse presentation definition
 * 4. Match stored credentials
 * 5. Get user consent for disclosure
 * 6. Authenticate user (biometric/PIN)
 * 7. Create selective disclosure
 * 8. Create key binding JWT
 * 9. Assemble VP token
 * 10. Submit to verifier
 */
public class Oidc4VpHandler {
    
    private static final Logger logger = LoggerFactory.getLogger(Oidc4VpHandler.class);
    
    private final HttpClient httpClient;
    
    /**
     * Cache for derived holder binding keys with time-based expiration.
     * Key: credentialId + issuerId + credentialType
     * Value: CachedKeyPair with timestamp
     * Thread-safe for concurrent access.
     * Keys expire after 5 minutes to minimize memory exfiltration risk.
     */
    private final ConcurrentHashMap<String, CachedKeyPair> bindingKeyCache;
    
    /**
     * Cache entry TTL in milliseconds (5 minutes).
     * After this time, cached keys are considered expired and will be re-derived.
     */
    private static final long CACHE_TTL_MS = 5 * 60 * 1000;
    
    public Oidc4VpHandler() {
        this.httpClient = new HttpClient();
        this.bindingKeyCache = new ConcurrentHashMap<>();
    }
    
    public Oidc4VpHandler(HttpClient httpClient) {
        this.httpClient = httpClient;
        this.bindingKeyCache = new ConcurrentHashMap<>();
    }
    
    /**
     * Presents a credential to a verifier using OIDC4VP protocol.
     *
     * @param authorizationRequest The authorization request URI
     * @param credential The credential to present
     * @param selectedClaims Set of claim names to disclose
     * @param masterKey The master private key for deriving holder binding key
     * @return Response from verifier
     * @throws OidcException if presentation fails
     */
    public String presentCredential(String authorizationRequest,
                                   VerifiableCredential credential,
                                   Set<String> selectedClaims,
                                   PrivateKey masterKey) throws OidcException {
        try {
            logger.info("Starting credential presentation flow");
            
            AuthorizationRequest authReq = parseRequest(authorizationRequest);
            PresentationDefinition presentationDef = validatePresentationDefinition(authReq);
            String sdJwtPresentation = buildSelectiveDisclosure(credential, selectedClaims);
            String keyBindingJwt = buildKeyBindingJwt(credential, masterKey, authReq, sdJwtPresentation);
            String vpToken = assembleVpToken(sdJwtPresentation, keyBindingJwt);
            String response = submitPresentation(authReq, presentationDef, vpToken);
            
            logger.info("Credential presentation completed successfully");
            return response;
            
        } catch (SdJwtException e) {
            logger.error("SD-JWT operation failed", e);
            throw new OidcException("Presentation failed: " + e.getMessage(), e);
        } catch (JwtException e) {
            logger.error("JWT operation failed", e);
            throw new OidcException("Presentation failed: " + e.getMessage(), e);
        } catch (IOException e) {
            logger.error("Network operation failed", e);
            throw new OidcException("Presentation failed: " + e.getMessage(), e);
        } catch (URISyntaxException e) {
            logger.error("Invalid URI in request", e);
            throw new OidcException("Presentation failed: " + e.getMessage(), e);
        } catch (IllegalArgumentException e) {
            logger.error("Invalid argument", e);
            throw new OidcException("Presentation failed: " + e.getMessage(), e);
        }
    }
    
    /**
     * Parses and fetches the authorization request.
     */
    private AuthorizationRequest parseRequest(String authorizationRequest) throws OidcException, IOException, URISyntaxException {
        logger.debug("Parsing authorization request");
        AuthorizationRequest authReq = parseAuthorizationRequest(authorizationRequest);
        logger.info("Authorization request parsed: responseUri={}", authReq.getResponseUri());
        
        if (authReq.getRequestUri() != null) {
            logger.debug("Fetching request object by reference");
            authReq = fetchRequestObject(authReq.getRequestUri());
        }
        
        return authReq;
    }
    
    /**
     * Validates and extracts the presentation definition from the request.
     */
    private PresentationDefinition validatePresentationDefinition(AuthorizationRequest authReq) throws OidcException {
        logger.debug("Validating presentation definition");
        PresentationDefinition presentationDef = authReq.getPresentationDefinition();
        if (presentationDef == null) {
            throw new OidcException("Presentation definition not found in request");
        }
        return presentationDef;
    }
    
    /**
     * Builds selective disclosure presentation from credential.
     */
    private String buildSelectiveDisclosure(VerifiableCredential credential, Set<String> selectedClaims) throws SdJwtException {
        logger.debug("Creating selective disclosure");
        String issuerJwt = extractIssuerJwt(credential);
        String[] allDisclosures = extractDisclosures(credential);
        
        return SelectiveDisclosureBuilder.buildPresentation(issuerJwt, allDisclosures, selectedClaims);
    }
    
    /**
     * Builds key binding JWT for the presentation.
     */
    private String buildKeyBindingJwt(VerifiableCredential credential, PrivateKey masterKey,
                                     AuthorizationRequest authReq, String sdJwtPresentation) throws SdJwtException, JwtException {
        logger.debug("Creating key binding JWT");
        KeyPair holderBindingKey = getCachedOrDeriveBindingKey(credential, masterKey);
        String[] selectedDisclosures = SelectiveDisclosureBuilder.extractDisclosures(sdJwtPresentation);
        
        return new KeyBindingJwtBuilder()
            .setSigningKey(holderBindingKey.getPrivate())
            .setAudience(authReq.getClientId())
            .setNonce(authReq.getNonce())
            .setIssuedAtNow()
            .setExpirationTimeFromNow(300)
            .setSdHash(selectedDisclosures)
            .build();
    }
    
    /**
     * Assembles the VP token from SD-JWT presentation and key binding JWT.
     */
    private String assembleVpToken(String sdJwtPresentation, String keyBindingJwt) {
        logger.debug("Assembling VP token");
        return sdJwtPresentation + "~" + keyBindingJwt;
    }
    
    /**
     * Submits the presentation to the verifier.
     */
    private String submitPresentation(AuthorizationRequest authReq, PresentationDefinition presentationDef,
                                     String vpToken) throws OidcException, IOException {
        logger.debug("Submitting presentation");
        PresentationSubmission submission = PresentationSubmission.createSingle(
            presentationDef.getId(),
            presentationDef.getInputDescriptors().get(0).getId(),
            "jwt_vc_json"
        );
        
        return submitPresentation(authReq.getResponseUri(), vpToken, submission, authReq.getState());
    }
    
    /**
     * Creates a presentation (VP token) from a credential with selective disclosure.
     *
     * @param credential The credential to present
     * @param holderBindingKey The holder's private key for signing
     * @param presentationDefinition The presentation definition
     * @param disclosedClaims List of claim names to disclose
     * @return VP token string (SD-JWT with key binding)
     * @throws OidcException if presentation creation fails
     */
    public String createPresentation(VerifiableCredential credential,
                                    PrivateKey holderBindingKey,
                                    PresentationDefinition presentationDefinition,
                                    List<String> disclosedClaims) throws OidcException {
        try {
            logger.debug("Creating presentation for credential {}", credential.getId());
            
            String issuerJwt = extractIssuerJwt(credential);
            String[] allDisclosures = extractDisclosures(credential);
            
            java.util.Set<String> claimsSet = new java.util.HashSet<>(disclosedClaims);
            String sdJwtPresentation = SelectiveDisclosureBuilder.buildPresentation(
                issuerJwt, allDisclosures, claimsSet);
            
            String[] selectedDisclosures = SelectiveDisclosureBuilder.extractDisclosures(sdJwtPresentation);
            
            String keyBindingJwt = new KeyBindingJwtBuilder()
                .setSigningKey(holderBindingKey)
                .setAudience(presentationDefinition.getId())
                .setIssuedAtNow()
                .setExpirationTimeFromNow(300)
                .setSdHash(selectedDisclosures)
                .build();
            
            String vpToken = sdJwtPresentation + "~" + keyBindingJwt;
            
            logger.debug("Created VP token with {} disclosures", selectedDisclosures.length);
            return vpToken;
            
        } catch (SdJwtException e) {
            logger.error("SD-JWT operation failed", e);
            throw new OidcException("Failed to create presentation: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error("Failed to create presentation", e);
            throw new OidcException("Failed to create presentation: " + e.getMessage(), e);
        }
    }
    
    /**
     * Submits a presentation to the verifier (simplified signature).
     *
     * @param responseUri The verifier's response URI
     * @param vpToken The VP token to submit
     * @return true if submission was successful
     * @throws OidcException if submission fails
     */
    public boolean submitPresentation(String responseUri, String vpToken) throws OidcException {
        try {
            PresentationSubmission submission = PresentationSubmission.createSingle(
                "presentation_" + System.currentTimeMillis(),
                "credential_input",
                "jwt_vc_json"
            );
            
            String response = submitPresentation(responseUri, vpToken, submission, null);
            
            return response != null;
        } catch (Exception e) {
            logger.error("Failed to submit presentation", e);
            throw new OidcException("Failed to submit presentation: " + e.getMessage(), e);
        }
    }
    
    /**
     * Parses an authorization request URI.
     */
    private AuthorizationRequest parseAuthorizationRequest(String uri) throws OidcException {
        try {
            // Parse query parameters from URI
            Map<String, String> params = parseQueryParams(uri);
            
            AuthorizationRequest request = new AuthorizationRequest();
            request.setClientId(params.get("client_id"));
            request.setResponseUri(params.get("response_uri"));
            request.setNonce(params.get("nonce"));
            request.setState(params.get("state"));
            request.setRequestUri(params.get("request_uri"));
            
            // Parse presentation definition if inline
            String presentationDefJson = params.get("presentation_definition");
            if (presentationDefJson != null) {
                request.setPresentationDefinition(
                    PresentationDefinition.fromJson(presentationDefJson));
            }
            
            return request;
        } catch (Exception e) {
            logger.error("Failed to parse authorization request", e);
            throw new OidcException("Failed to parse authorization request: " + e.getMessage(), e);
        }
    }
    
    /**
     * Fetches a request object by reference.
     */
    private AuthorizationRequest fetchRequestObject(String requestUri) throws OidcException {
        try {
            HttpResponse response = httpClient.get(requestUri);
            
            if (!response.isSuccessful()) {
                throw new OidcException("Failed to fetch request object: " + response.getStatusCode());
            }
            
            // Parse JWT request object (simplified - should verify signature)
            String[] parts = response.getBody().split("\\.");
            if (parts.length != 3) {
                throw new OidcException("Invalid JWT request object");
            }
            
            // Decode payload
            String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
            @SuppressWarnings("unchecked")
            Map<String, Object> claims = (Map<String, Object>) JsonUtils.decode(payload, Map.class);
            
            AuthorizationRequest request = new AuthorizationRequest();
            request.setClientId((String) claims.get("client_id"));
            request.setResponseUri((String) claims.get("response_uri"));
            request.setNonce((String) claims.get("nonce"));
            request.setState((String) claims.get("state"));
            
            @SuppressWarnings("unchecked")
            Map<String, Object> presentationDefMap = (Map<String, Object>) claims.get("presentation_definition");
            if (presentationDefMap != null) {
                request.setPresentationDefinition(
                    PresentationDefinition.fromMap(presentationDefMap));
            }
            
            return request;
        } catch (HttpException e) {
            logger.error("HTTP error fetching request object", e);
            throw new OidcException("Failed to fetch request object: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error("Failed to fetch request object", e);
            throw new OidcException("Failed to fetch request object: " + e.getMessage(), e);
        }
    }
    
    /**
     * Submits the presentation to the verifier.
     */
    private String submitPresentation(String responseUri,
                                     String vpToken,
                                     PresentationSubmission submission,
                                     String state) throws OidcException {
        try {
            Map<String, Object> requestBody = new HashMap<>();
            requestBody.put("vp_token", vpToken);
            requestBody.put("presentation_submission", submission.toMap());
            if (state != null) {
                requestBody.put("state", state);
            }
            
            String jsonBody = JsonUtils.encode(requestBody);
            
            Map<String, String> headers = new HashMap<>();
            headers.put("Content-Type", "application/json");
            headers.put("Accept", "application/json");
            
            logger.debug("Submitting presentation to: {}", responseUri);
            
            HttpResponse response = httpClient.postWithRetry(
                responseUri,
                jsonBody,
                headers,
                RetryPolicy.PRESENTATION
            );
            
            if (!response.isSuccessful()) {
                String errorMsg = "Presentation submission failed with status " + response.getStatusCode();
                if (response.getBody() != null) {
                    errorMsg += ": " + response.getBody();
                }
                throw new OidcException(errorMsg);
            }
            
            return response.getBody();
            
        } catch (HttpException e) {
            logger.error("HTTP error during presentation submission", e);
            throw new OidcException("Presentation submission failed: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error("Unexpected error during presentation submission", e);
            throw new OidcException("Presentation submission failed: " + e.getMessage(), e);
        }
    }
    
    /**
     * Extracts the issuer JWT from a credential.
     */
    private String extractIssuerJwt(VerifiableCredential credential) {
        // For MVP, the encrypted data contains the full SD-JWT
        byte[] encryptedData = credential.getEncryptedData();
        if (encryptedData == null) {
            throw new IllegalArgumentException("Credential has no data");
        }
        
        String fullSdJwt = new String(encryptedData, java.nio.charset.StandardCharsets.UTF_8);
        
        // Extract issuer JWT (first part before ~)
        int separatorIndex = fullSdJwt.indexOf('~');
        if (separatorIndex > 0) {
            return fullSdJwt.substring(0, separatorIndex);
        }
        
        return fullSdJwt;
    }
    
    /**
     * Extracts disclosures from a credential.
     */
    private String[] extractDisclosures(VerifiableCredential credential) {
        byte[] encryptedData = credential.getEncryptedData();
        if (encryptedData == null) {
            return new String[0];
        }
        
        String fullSdJwt = new String(encryptedData, java.nio.charset.StandardCharsets.UTF_8);
        return SelectiveDisclosureBuilder.extractDisclosures(fullSdJwt);
    }
    
    /**
     * Gets cached or derives the holder binding key for a credential.
     * Uses a cache with time-based expiration to avoid redundant cryptographic derivation.
     * Expired entries are automatically removed and re-derived.
     */
    private KeyPair getCachedOrDeriveBindingKey(VerifiableCredential credential, PrivateKey masterKey) {
        String cacheKey = buildCacheKey(credential);
        long currentTime = System.currentTimeMillis();
        
        CachedKeyPair cached = bindingKeyCache.get(cacheKey);
        
        if (cached != null && !cached.isExpired(currentTime)) {
            logger.debug("Cache hit for binding key, credential {}", credential.getId());
            return cached.keyPair;
        }
        
        if (cached != null) {
            logger.debug("Cache entry expired for credential {}, re-deriving", credential.getId());
            bindingKeyCache.remove(cacheKey);
        } else {
            logger.debug("Cache miss for binding key, deriving new key for credential {}", credential.getId());
        }
        
        KeyPair newKeyPair = deriveHolderBindingKey(credential, masterKey);
        bindingKeyCache.put(cacheKey, new CachedKeyPair(newKeyPair, currentTime));
        
        return newKeyPair;
    }
    
    /**
     * Builds a cache key for a credential's binding key.
     */
    private String buildCacheKey(VerifiableCredential credential) {
        String issuerId = credential.getMetadata().getIssuerDid() != null ?
            credential.getMetadata().getIssuerDid() :
            credential.getMetadata().getIssuerUrl();
        
        return credential.getId() + "|" + issuerId + "|" + credential.getMetadata().getCredentialType();
    }
    
    /**
     * Derives the holder binding key for a credential.
     */
    private KeyPair deriveHolderBindingKey(VerifiableCredential credential, PrivateKey masterKey) {
        byte[] seed = credential.getHolderBindingKeySeed();
        if (seed == null) {
            throw new IllegalArgumentException("Credential has no holder binding key seed");
        }
        
        return HolderBindingKeyManager.deriveBindingKey(
            seed,
            credential.getId(),
            credential.getMetadata().getIssuerDid() != null ?
                credential.getMetadata().getIssuerDid() :
                credential.getMetadata().getIssuerUrl(),
            credential.getMetadata().getCredentialType(),
            masterKey
        );
    }
    
    /**
     * Clears the binding key cache.
     * Should be called when credentials are deleted or on application shutdown.
     */
    public void clearBindingKeyCache() {
        bindingKeyCache.clear();
        logger.debug("Binding key cache cleared");
    }
    
    /**
     * Removes a specific credential's binding key from the cache.
     * Should be called when a credential is deleted or updated.
     */
    public void evictBindingKey(VerifiableCredential credential) {
        String cacheKey = buildCacheKey(credential);
        bindingKeyCache.remove(cacheKey);
        logger.debug("Evicted binding key for credential {}", credential.getId());
    }
    
    /**
     * Removes expired entries from the cache.
     * This method should be called periodically (e.g., every minute) to proactively
     * clean up expired keys and minimize memory exposure.
     *
     * @return Number of expired entries removed
     */
    public int cleanupExpiredKeys() {
        long currentTime = System.currentTimeMillis();
        AtomicInteger removedCount = new AtomicInteger(0);
        
        bindingKeyCache.entrySet().removeIf(entry -> {
            if (entry.getValue().isExpired(currentTime)) {
                removedCount.incrementAndGet();
                return true;
            }
            return false;
        });
        
        int count = removedCount.get();
        if (count > 0) {
            logger.debug("Cleaned up {} expired binding keys from cache", count);
        }
        
        return count;
    }
    
    /**
     * Gets the current cache size.
     * Useful for monitoring and testing.
     *
     * @return Number of entries in the cache
     */
    public int getCacheSize() {
        return bindingKeyCache.size();
    }
    
    /**
     * Parses query parameters from a URI.
     */
    private Map<String, String> parseQueryParams(String uri) {
        Map<String, String> params = new HashMap<>();
        
        int queryStart = uri.indexOf('?');
        if (queryStart < 0) {
            return params;
        }
        
        String query = uri.substring(queryStart + 1);
        String[] pairs = query.split("&");
        
        for (String pair : pairs) {
            int eqIndex = pair.indexOf('=');
            if (eqIndex > 0) {
                String key = pair.substring(0, eqIndex);
                String value = pair.substring(eqIndex + 1);
                try {
                    value = java.net.URLDecoder.decode(value, "UTF-8");
                } catch (Exception e) {
                    logger.warn("Failed to decode parameter value", e);
                }
                params.put(key, value);
            }
        }
        
        return params;
    }
    
    /**
     * Cache entry for a KeyPair with timestamp for expiration.
     */
    private static class CachedKeyPair {
        final KeyPair keyPair;
        final long timestamp;
        
        CachedKeyPair(KeyPair keyPair, long timestamp) {
            this.keyPair = keyPair;
            this.timestamp = timestamp;
        }
        
        boolean isExpired(long currentTime) {
            return (currentTime - timestamp) > CACHE_TTL_MS;
        }
    }
    
    /**
     * Represents a parsed authorization request.
     */
    private static class AuthorizationRequest {
        private String clientId;
        private String responseUri;
        private String nonce;
        private String state;
        private String requestUri;
        private PresentationDefinition presentationDefinition;
        
        public String getClientId() { return clientId; }
        public void setClientId(String clientId) { this.clientId = clientId; }
        
        public String getResponseUri() { return responseUri; }
        public void setResponseUri(String responseUri) { this.responseUri = responseUri; }
        
        public String getNonce() { return nonce; }
        public void setNonce(String nonce) { this.nonce = nonce; }
        
        public String getState() { return state; }
        public void setState(String state) { this.state = state; }
        
        public String getRequestUri() { return requestUri; }
        public void setRequestUri(String requestUri) { this.requestUri = requestUri; }
        
        public PresentationDefinition getPresentationDefinition() { return presentationDefinition; }
        public void setPresentationDefinition(PresentationDefinition presentationDefinition) { 
            this.presentationDefinition = presentationDefinition; 
        }
    }
}

// Made with Bob