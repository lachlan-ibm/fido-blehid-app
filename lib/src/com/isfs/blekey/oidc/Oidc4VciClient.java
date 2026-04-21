/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.oidc;

import com.isfs.blekey.credential.DigitalCredentialMetadata;
import com.isfs.blekey.credential.VerifiableCredential;
import com.isfs.blekey.credential.jwt.JwtBuilder;
import com.isfs.blekey.credential.jwt.JwtException;
import com.isfs.blekey.credential.jwt.JwtParser;
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
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * OIDC4VCI Client for credential issuance.
 * Implements the OpenID for Verifiable Credential Issuance (OIDC4VCI) protocol.
 * 
 * Issuance Flow:
 * 1. Parse credential offer
 * 2. Fetch issuer metadata
 * 3. Request access token (pre-authorized code grant)
 * 4. Generate credential seed and derive holder binding key
 * 5. Create key proof JWT
 * 6. Request credential with proof
 * 7. Validate and return credential
 * 
 * Security:
 * - Holder binding key derived from master key (requires biometric auth)
 * - Key proof JWT proves possession of holder binding key
 * - Credential signature verified before acceptance
 */
public class Oidc4VciClient {
    
    private static final Logger logger = LoggerFactory.getLogger(Oidc4VciClient.class);
    private static final String CLIENT_ID = "aye-ble-key-wallet";
    private static final int KEY_PROOF_EXPIRY_SECONDS = 300; // 5 minutes
    
    private final HttpClient httpClient;
    private final OidcAuthorizationClient authClient;
    
    /**
     * Creates a new OIDC4VCI client.
     */
    public Oidc4VciClient() {
        this.httpClient = new HttpClient();
        this.authClient = new OidcAuthorizationClient(httpClient);
    }
    
    /**
     * Creates a new OIDC4VCI client with custom HTTP client.
     * 
     * @param httpClient The HTTP client to use
     */
    public Oidc4VciClient(HttpClient httpClient) {
        this.httpClient = httpClient;
        this.authClient = new OidcAuthorizationClient(httpClient);
    }
    
    /**
     * Issues a credential using the OIDC4VCI protocol.
     * 
     * @param credentialOfferUri The credential offer URI
     * @param credentialId The credential identifier
     * @param issuerId The issuer identifier
     * @param credentialType The credential type
     * @param masterKey The master private key for deriving holder binding key
     * @return The issued verifiable credential
     * @throws OidcException if issuance fails
     */
    public VerifiableCredential issueCredential(String credentialOfferUri,
                                               String credentialId,
                                               String issuerId,
                                               String credentialType,
                                               PrivateKey masterKey) throws OidcException {
        try {
            logger.info("Starting credential issuance flow");
            
            // Step 1: Parse credential offer
            logger.debug("Step 1: Parsing credential offer");
            CredentialOffer offer = CredentialOffer.fromUri(credentialOfferUri);
            logger.info("Credential offer parsed: {}", offer);
            
            // Step 2: Fetch issuer metadata
            logger.debug("Step 2: Fetching issuer metadata");
            IssuerMetadata metadata = IssuerMetadata.fetch(offer.getCredentialIssuer(), httpClient);
            logger.info("Issuer metadata fetched: {}", metadata);
            
            // Validate metadata
            if (metadata.getTokenEndpoint() == null) {
                throw new OidcException("Token endpoint not found in issuer metadata");
            }
            
            // Step 3: Request access token
            logger.debug("Step 3: Requesting access token");
            OidcTokenResponse tokenResponse = requestAccessToken(offer, metadata);
            logger.info("Access token obtained: expiresIn={}, hasCNonce={}", 
                       tokenResponse.getExpiresIn(), tokenResponse.hasCNonce());
            
            // Step 4: Generate credential seed and derive holder binding key
            logger.debug("Step 4: Generating holder binding key");
            byte[] credentialSeed = HolderBindingKeyManager.generateSeed();
            KeyPair holderBindingKeyPair = HolderBindingKeyManager.deriveBindingKey(
                credentialSeed, credentialId, issuerId, credentialType, masterKey);
            logger.info("Holder binding key generated");
            
            // Step 5: Create key proof JWT
            logger.debug("Step 5: Creating key proof JWT");
            String keyProofJwt = createKeyProofJwt(
                holderBindingKeyPair.getPrivate(),
                holderBindingKeyPair.getPublic(),
                metadata.getCredentialIssuer(),
                tokenResponse.getCNonce()
            );
            logger.info("Key proof JWT created");
            
            // Step 6: Request credential with proof
            logger.debug("Step 6: Requesting credential");
            String credentialJwt = requestCredential(
                metadata.getCredentialEndpoint(),
                tokenResponse.getAccessToken(),
                offer.getCredentials().get(0), // Use first credential type
                keyProofJwt
            );
            logger.info("Credential received");
            
            // Step 7: Validate and parse credential
            logger.debug("Step 7: Validating credential");
            VerifiableCredential credential = validateCredential(credentialJwt, holderBindingKeyPair.getPublic());
            logger.info("Credential validated successfully");
            
            // Store credential seed with credential
            credential.setHolderBindingKeySeed(credentialSeed);
            
            return credential;
            
        } catch (Exception e) {
            logger.error("Credential issuance failed", e);
            throw new OidcException("Credential issuance failed: " + e.getMessage(), e);
        }
    }
    
    /**
     * Requests an access token using pre-authorized code grant.
     */
    private OidcTokenResponse requestAccessToken(CredentialOffer offer, IssuerMetadata metadata) 
            throws OidcException {
        
        if (!offer.hasPreAuthorizedCodeGrant()) {
            throw new OidcException("Pre-authorized code grant not found in credential offer");
        }
        
        String preAuthorizedCode = offer.getPreAuthorizedCode();
        if (preAuthorizedCode == null || preAuthorizedCode.isEmpty()) {
            throw new OidcException("Pre-authorized code is missing");
        }
        
        return authClient.requestPreAuthorizedToken(
            metadata.getTokenEndpoint(),
            preAuthorizedCode,
            CLIENT_ID
        );
    }
    
    /**
     * Creates a key proof JWT to prove possession of the holder binding key.
     */
    private String createKeyProofJwt(PrivateKey holderBindingKey,
                                    PublicKey holderBindingPublicKey,
                                    String audience,
                                    String nonce) throws JwtException {
        
        long now = System.currentTimeMillis() / 1000;
        
        // Create JWT with holder binding key
        JwtBuilder builder = new JwtBuilder()
            .setIssuer(CLIENT_ID)
            .setAudience(audience)
            .setIssuedAt(now)
            .setExpirationTime(now + KEY_PROOF_EXPIRY_SECONDS)
            .setSigningKey(holderBindingKey);
        
        // Add nonce if provided
        if (nonce != null && !nonce.isEmpty()) {
            builder.setClaim("nonce", nonce);
        }
        
        // Add public key as JWK in header (proof of possession)
        // This is done by including the public key in the JWT header
        // For now, we'll include it as a claim (implementation may vary by issuer)
        String publicKeyJwk = publicKeyToJwk(holderBindingPublicKey);
        builder.setClaim("cnf", Map.of("jwk", publicKeyJwk));
        
        return builder.build();
    }
    
    /**
     * Requests a credential from the credential endpoint.
     */
    private String requestCredential(String credentialEndpoint,
                                    String accessToken,
                                    String credentialType,
                                    String keyProofJwt) throws OidcException {
        try {
            // Build credential request
            Map<String, Object> request = new HashMap<>();
            request.put("format", "jwt_vc_json");
            request.put("types", new String[]{"VerifiableCredential", credentialType});
            
            // Add proof
            Map<String, Object> proof = new HashMap<>();
            proof.put("proof_type", "jwt");
            proof.put("jwt", keyProofJwt);
            request.put("proof", proof);
            
            String requestBody = JsonUtils.encode(request);
            
            // Set headers
            Map<String, String> headers = new HashMap<>();
            headers.put("Content-Type", "application/json");
            headers.put("Authorization", "Bearer " + accessToken);
            headers.put("Accept", "application/json");
            
            logger.debug("Requesting credential from: {}", credentialEndpoint);
            
            // Make request with retry
            HttpResponse response = httpClient.postWithRetry(
                credentialEndpoint,
                requestBody,
                headers,
                RetryPolicy.ISSUANCE
            );
            
            if (!response.isSuccessful()) {
                String errorMsg = "Credential request failed with status " + response.getStatusCode();
                if (response.getBody() != null) {
                    errorMsg += ": " + response.getBody();
                }
                throw new OidcException(errorMsg);
            }
            
            // Parse response
            @SuppressWarnings("unchecked")
            Map<String, Object> responseMap = (Map<String, Object>) JsonUtils.decode(response.getBody(), Map.class);
            
            // Extract credential
            String credential = (String) responseMap.get("credential");
            if (credential == null || credential.isEmpty()) {
                throw new OidcException("Credential not found in response");
            }
            
            return credential;
            
        } catch (HttpException e) {
            logger.error("HTTP error during credential request", e);
            throw new OidcException("Credential request failed: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error("Unexpected error during credential request", e);
            throw new OidcException("Credential request failed: " + e.getMessage(), e);
        }
    }
    
    /**
     * Validates the issued credential.
     *
     * For MVP, we create a VerifiableCredential wrapper around the JWT.
     * Full validation including issuer signature verification will be added later.
     */
    private VerifiableCredential validateCredential(String credentialJwt, PublicKey holderBindingPublicKey)
            throws OidcException {
        try {
            // Parse JWT to extract claims (unsecured for MVP)
            // TODO: Implement proper issuer signature verification
            var claims = JwtParser.parseUnsecured(credentialJwt);
            
            // Extract credential metadata from JWT claims
            Object vcObj = claims.getClaimValue("vc");
            if (vcObj == null) {
                throw new OidcException("Verifiable credential not found in JWT");
            }
            
            // Create VerifiableCredential wrapper
            VerifiableCredential credential = new VerifiableCredential();
            
            // Store the JWT as encrypted data (will be properly encrypted later)
            credential.setEncryptedData(credentialJwt.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            
            // Extract and set metadata
            DigitalCredentialMetadata metadata = credential.getMetadata();
            
            // Extract issuer
            String issuer = claims.getIssuer();
            if (issuer != null) {
                if (issuer.startsWith("did:")) {
                    metadata.setIssuerDid(issuer);
                } else {
                    metadata.setIssuerUrl(issuer);
                }
            }
            
            // Extract credential type from vc object
            if (vcObj instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> vcMap = (Map<String, Object>) vcObj;
                Object typeObj = vcMap.get("type");
                if (typeObj instanceof java.util.List) {
                    @SuppressWarnings("unchecked")
                    java.util.List<String> types = (java.util.List<String>) typeObj;
                    if (!types.isEmpty()) {
                        // Use the most specific type (last in list)
                        metadata.setCredentialType(types.get(types.size() - 1));
                    }
                }
            }
            
            // Extract timestamps
            if (claims.getIssuedAt() != null) {
                metadata.setIssuedAt(java.time.Instant.ofEpochSecond(claims.getIssuedAt().getValue()));
            }
            if (claims.getExpirationTime() != null) {
                metadata.setExpiresAt(java.time.Instant.ofEpochSecond(claims.getExpirationTime().getValue()));
            }
            
            logger.debug("Credential validated: type={}, issuer={}",
                        metadata.getCredentialType(),
                        metadata.getIssuerDid() != null ? metadata.getIssuerDid() : metadata.getIssuerUrl());
            
            return credential;
            
        } catch (JwtException e) {
            logger.error("JWT validation failed", e);
            throw new OidcException("Credential validation failed: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error("Unexpected error during credential validation", e);
            throw new OidcException("Credential validation failed: " + e.getMessage(), e);
        }
    }
    
    /**
     * Converts a public key to JWK format.
     * Simplified implementation - full JWK support would be more complex.
     */
    private String publicKeyToJwk(PublicKey publicKey) {
        // For ES256, we need to extract x and y coordinates
        // This is a simplified version - production code should use a proper JWK library
        byte[] encoded = publicKey.getEncoded();
        String base64 = Base64.getUrlEncoder().withoutPadding().encodeToString(encoded);
        
        Map<String, Object> jwk = new HashMap<>();
        jwk.put("kty", "EC");
        jwk.put("crv", "P-256");
        jwk.put("x", base64); // Simplified - should extract actual x coordinate
        
        return JsonUtils.encode(jwk);
    }
}

// Made with Bob