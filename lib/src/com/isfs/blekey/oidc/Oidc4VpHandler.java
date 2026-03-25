/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.oidc;

import com.isfs.blekey.credential.VerifiableCredential;
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

import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
    private static final String CLIENT_ID = "aye-ble-key-wallet";
    
    private final HttpClient httpClient;
    
    public Oidc4VpHandler() {
        this.httpClient = new HttpClient();
    }
    
    public Oidc4VpHandler(HttpClient httpClient) {
        this.httpClient = httpClient;
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
            
            // Step 1: Parse authorization request
            logger.debug("Step 1: Parsing authorization request");
            AuthorizationRequest authReq = parseAuthorizationRequest(authorizationRequest);
            logger.info("Authorization request parsed: responseUri={}", authReq.getResponseUri());
            
            // Step 2: Fetch request object if by reference
            if (authReq.getRequestUri() != null) {
                logger.debug("Step 2: Fetching request object by reference");
                authReq = fetchRequestObject(authReq.getRequestUri());
            }
            
            // Step 3: Parse presentation definition
            logger.debug("Step 3: Parsing presentation definition");
            PresentationDefinition presentationDef = authReq.getPresentationDefinition();
            if (presentationDef == null) {
                throw new OidcException("Presentation definition not found in request");
            }
            
            // Step 4-6: User consent and authentication handled by caller
            
            // Step 7: Create selective disclosure
            logger.debug("Step 7: Creating selective disclosure");
            String issuerJwt = extractIssuerJwt(credential);
            String[] allDisclosures = extractDisclosures(credential);
            
            String sdJwtPresentation = SelectiveDisclosureBuilder.buildPresentation(
                issuerJwt, allDisclosures, selectedClaims);
            
            // Step 8: Create key binding JWT
            logger.debug("Step 8: Creating key binding JWT");
            KeyPair holderBindingKey = deriveHolderBindingKey(credential, masterKey);
            
            String[] selectedDisclosures = SelectiveDisclosureBuilder.extractDisclosures(sdJwtPresentation);
            String sdHash = SelectiveDisclosureBuilder.computeSdHash(selectedDisclosures);
            
            String keyBindingJwt = new KeyBindingJwtBuilder()
                .setSigningKey(holderBindingKey.getPrivate())
                .setAudience(authReq.getClientId())
                .setNonce(authReq.getNonce())
                .setIssuedAtNow()
                .setExpirationTimeFromNow(300)
                .setSdHash(selectedDisclosures)
                .build();
            
            // Step 9: Assemble VP token
            logger.debug("Step 9: Assembling VP token");
            String vpToken = sdJwtPresentation + "~" + keyBindingJwt;
            
            // Create presentation submission
            PresentationSubmission submission = PresentationSubmission.createSingle(
                presentationDef.getId(),
                presentationDef.getInputDescriptors().get(0).getId(),
                "jwt_vc_json"
            );
            
            // Step 10: Submit to verifier
            logger.debug("Step 10: Submitting presentation");
            String response = submitPresentation(
                authReq.getResponseUri(),
                vpToken,
                submission,
                authReq.getState()
            );
            
            logger.info("Credential presentation completed successfully");
            return response;
            
        } catch (SdJwtException e) {
            logger.error("SD-JWT operation failed", e);
            throw new OidcException("Presentation failed: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error("Credential presentation failed", e);
            throw new OidcException("Presentation failed: " + e.getMessage(), e);
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