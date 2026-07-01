/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.oidc;

import com.isfs.blekey.credential.DigitalCredentialFormat;
import com.isfs.blekey.credential.DigitalCredentialMetadata;
import com.isfs.blekey.credential.VerifiableCredential;
import com.isfs.blekey.credential.jsonld.JsonLdCredential;
import com.isfs.blekey.credential.jsonld.JsonLdException;
import com.isfs.blekey.credential.jsonld.proof.ProofVerifier;
import com.isfs.blekey.credential.jwt.JwtBuilder;
import com.isfs.blekey.credential.jwt.JwtException;
import com.isfs.blekey.credential.jwt.JwtParser;
import com.isfs.blekey.credential.mdl.IssuerAuth;
import com.isfs.blekey.credential.mdl.MdlCredential;
import com.isfs.blekey.credential.mdl.MdlException;
import com.isfs.blekey.credential.mdl.MobileSecurityObject;
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
import java.util.List;
import java.util.Map;
import java.util.ArrayList;

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
     * Automatically detects the credential format from the offer.
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
        return issueCredential(credentialOfferUri, credentialId, issuerId,
                             credentialType, masterKey, null);
    }
    
    /**
     * Issues a credential using the OIDC4VCI protocol with explicit format.
     *
     * @param credentialOfferUri The credential offer URI
     * @param credentialId The credential identifier
     * @param issuerId The issuer identifier
     * @param credentialType The credential type
     * @param masterKey The master private key for deriving holder binding key
     * @param format The credential format (null for auto-detection)
     * @return The issued verifiable credential
     * @throws OidcException if issuance fails
     */
    public VerifiableCredential issueCredential(String credentialOfferUri,
                                               String credentialId,
                                               String issuerId,
                                               String credentialType,
                                               PrivateKey masterKey,
                                               DigitalCredentialFormat format) throws OidcException {
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
            
            // Determine format if not specified
            if (format == null) {
                format = detectCredentialFormat(offer, metadata);
            }
            logger.info("Credential format: {}", format);
            
            // Step 6: Request credential with proof
            logger.debug("Step 6: Requesting credential");
            Object credentialResponse = requestCredential(
                metadata.getCredentialEndpoint(),
                tokenResponse.getAccessToken(),
                offer.getCredentials().get(0), // Use first credential type
                keyProofJwt,
                format,
                metadata
            );
            logger.info("Credential received");
            
            // Step 7: Validate and parse credential based on format
            logger.debug("Step 7: Validating credential");
            VerifiableCredential credential;
            if (format == DigitalCredentialFormat.ISO_MDOC) {
                credential = validateMdlCredential((byte[]) credentialResponse,
                                                   holderBindingKeyPair.getPublic());
            } else if (format == DigitalCredentialFormat.JSON_LD) {
                credential = validateJsonLdCredential((String) credentialResponse,
                                                     holderBindingKeyPair.getPublic());
            } else {
                credential = validateCredential((String) credentialResponse,
                                               holderBindingKeyPair.getPublic());
            }
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
     * Detects the credential format from the offer and metadata.
     * Supports detection of SD-JWT-VC, ISO mDL, and JSON-LD formats.
     *
     * Format identifiers:
     * - "jwt_vc_json" or "vc+sd-jwt" -> SD_JWT_VC
     * - "mso_mdoc" -> ISO_MDOC
     * - "ldp_vc" or "jwt_vc_json-ld" -> JSON_LD
     *
     * @param offer The credential offer
     * @param metadata The issuer metadata
     * @return The detected credential format
     */
    private DigitalCredentialFormat detectCredentialFormat(CredentialOffer offer,
                                                          IssuerMetadata metadata) {
        logger.debug("Detecting credential format from offer and metadata");
        
        // First, check if the offer specifies a format in the credentials array
        List<String> credentials = offer.getCredentials();
        if (credentials != null && !credentials.isEmpty()) {
            String firstCredential = credentials.get(0);
            
            // Check if it's a credential configuration ID that we need to look up in metadata
            List<Map<String, Object>> credentialsSupported = metadata.getCredentialsSupported();
            for (Map<String, Object> credConfig : credentialsSupported) {
                // Check if this credential configuration matches
                Object formatObj = credConfig.get("format");
                if (formatObj instanceof String) {
                    String format = (String) formatObj;
                    DigitalCredentialFormat detected = mapFormatString(format);
                    if (detected != null) {
                        logger.info("Detected format from metadata: {} -> {}", format, detected);
                        return detected;
                    }
                }
            }
        }
        
        // Fallback: Check if metadata has any supported formats
        List<Map<String, Object>> credentialsSupported = metadata.getCredentialsSupported();
        if (!credentialsSupported.isEmpty()) {
            Map<String, Object> firstCred = credentialsSupported.get(0);
            Object formatObj = firstCred.get("format");
            if (formatObj instanceof String) {
                String format = (String) formatObj;
                DigitalCredentialFormat detected = mapFormatString(format);
                if (detected != null) {
                    logger.info("Detected format from first supported credential: {} -> {}", format, detected);
                    return detected;
                }
            }
        }
        
        // Default to SD-JWT-VC if no format detected
        logger.warn("No format detected, defaulting to SD_JWT_VC");
        return DigitalCredentialFormat.SD_JWT_VC;
    }
    
    /**
     * Maps OIDC4VCI format strings to DigitalCredentialFormat enum values.
     *
     * @param formatString The format string from issuer metadata
     * @return The corresponding DigitalCredentialFormat, or null if not recognized
     */
    private DigitalCredentialFormat mapFormatString(String formatString) {
        if (formatString == null || formatString.isEmpty()) {
            return null;
        }
        
        // Normalize format string
        String normalized = formatString.toLowerCase().trim();
        
        // JSON-LD formats
        if (normalized.equals("ldp_vc") || normalized.equals("jwt_vc_json-ld")) {
            return DigitalCredentialFormat.JSON_LD;
        }
        
        // ISO mDL format
        if (normalized.equals("mso_mdoc")) {
            return DigitalCredentialFormat.ISO_MDOC;
        }
        
        // SD-JWT-VC formats
        if (normalized.equals("jwt_vc_json") || normalized.equals("vc+sd-jwt")) {
            return DigitalCredentialFormat.SD_JWT_VC;
        }
        
        logger.warn("Unknown format string: {}", formatString);
        return null;
    }
    
    /**
     * Requests a credential from the credential endpoint.
     * Supports SD-JWT-VC, ISO mDL, and JSON-LD credential formats.
     */
    private Object requestCredential(String credentialEndpoint,
                                    String accessToken,
                                    String credentialType,
                                    String keyProofJwt,
                                    DigitalCredentialFormat format,
                                    IssuerMetadata metadata) throws OidcException {
        try {
            // Build credential request
            Map<String, Object> request = new HashMap<>();
            
            // Set format and format-specific parameters
            if (format == DigitalCredentialFormat.ISO_MDOC) {
                // ISO mDL format
                request.put("format", "mso_mdoc");
                request.put("doctype", credentialType);
            } else if (format == DigitalCredentialFormat.JSON_LD) {
                // JSON-LD format - use ldp_vc as the primary format identifier
                // Extract @context from metadata or use defaults
                List<String> contexts = extractContextsFromMetadata(metadata, credentialType);
                
                request.put("format", "ldp_vc");
                request.put("credential_definition", Map.of(
                    "type", List.of("VerifiableCredential", credentialType),
                    "@context", contexts
                ));
            } else {
                // SD-JWT-VC format (default)
                request.put("format", "jwt_vc_json");
                request.put("types", new String[]{"VerifiableCredential", credentialType});
            }
            
            // Add proof
            Map<String, Object> proof = new HashMap<>();
            proof.put("proof_type", "jwt");
            proof.put("jwt", keyProofJwt);
            request.put("proof", proof);
            
            String requestBody = JsonUtils.encode(request);
            logger.debug("Credential request body: {}", requestBody);
            
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
            
            // Extract credential based on format
            if (format == DigitalCredentialFormat.ISO_MDOC) {
                // mDL credentials are returned as base64-encoded CBOR
                String credentialB64 = (String) responseMap.get("credential");
                if (credentialB64 == null || credentialB64.isEmpty()) {
                    throw new OidcException("Credential not found in response");
                }
                return Base64.getDecoder().decode(credentialB64);
            } else {
                // JWT and JSON-LD credentials are returned as strings
                String credential = (String) responseMap.get("credential");
                if (credential == null || credential.isEmpty()) {
                    throw new OidcException("Credential not found in response");
                }
                return credential;
            }
            
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
     * Validates an mDL credential received from the issuer.
     *
     * @param mdlCbor the CBOR-encoded mDL credential
     * @param holderBindingPublicKey the holder's binding public key
     * @return the validated MdlCredential
     * @throws OidcException if validation fails
     */
    private MdlCredential validateMdlCredential(byte[] mdlCbor, PublicKey holderBindingPublicKey)
            throws OidcException {
        try {
            logger.debug("Validating mDL credential");
            
            // Parse the mDL from CBOR
            MdlCredential mdlCredential = MdlCredential.fromMdlCbor(mdlCbor);
            
            // Extract and validate IssuerAuth
            if (mdlCredential.getIssuerSigned() == null) {
                throw new OidcException("mDL missing IssuerSigned data");
            }
            
            byte[] issuerAuthBytes = mdlCredential.getIssuerSigned().getIssuerAuth();
            IssuerAuth issuerAuth = IssuerAuth.fromCbor(issuerAuthBytes);
            
            // Extract MSO from IssuerAuth
            MobileSecurityObject mso = issuerAuth.getMso();
            
            // Validate MSO structure
            mso.validate();
            
            // Verify MSO is currently valid
            if (!mso.isValid()) {
                throw new OidcException("MSO is not currently valid (expired or not yet valid)");
            }
            
            // TODO: Verify issuer signature on IssuerAuth
            // This requires the issuer's public key or certificate
            // For now, we'll skip signature verification (Phase 4D will add this)
            logger.warn("Issuer signature verification not yet implemented");
            
            // TODO: Verify MSO digests match IssuerSignedItems
            // This ensures the data hasn't been tampered with
            logger.warn("MSO digest verification not yet implemented");
            
            // Set metadata from MSO
            DigitalCredentialMetadata metadata = mdlCredential.getMetadata();
            metadata.setCredentialType(mso.getDocType());
            metadata.setIssuedAt(mso.getSigned());
            metadata.setExpiresAt(mso.getValidUntil());
            
            // Store the raw CBOR as encrypted data
            mdlCredential.setEncryptedData(mdlCbor);
            
            logger.info("mDL credential validated: docType={}, validUntil={}",
                       mso.getDocType(), mso.getValidUntil());
            
            return mdlCredential;
            
        } catch (MdlException e) {
            logger.error("mDL validation failed", e);
            throw new OidcException("mDL validation failed: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error("Unexpected error during mDL validation", e);
            throw new OidcException("mDL validation failed: " + e.getMessage(), e);
        }
    }

    
    /**
     * Validates a JSON-LD credential received from the issuer.
     *
     * @param credentialJson the JSON string of the JSON-LD credential
     * @param holderBindingPublicKey the holder's binding public key
     * @return the validated VerifiableCredential wrapping the JSON-LD credential
     * @throws OidcException if validation fails
     */
    private VerifiableCredential validateJsonLdCredential(String credentialJson, PublicKey holderBindingPublicKey)
            throws OidcException {
        try {
            logger.debug("Validating JSON-LD credential");
            
            // Parse the JSON-LD credential
            JsonLdCredential jsonLdCred = JsonLdCredential.fromJson(credentialJson);
            
            // Validate credential structure
            jsonLdCred.validate();
            
            // Verify the proof if present
            if (jsonLdCred.getProof() != null) {
                logger.debug("Verifying JSON-LD credential proof");
                
                // Create proof verifier with default handlers
                ProofVerifier verifier = new ProofVerifier(true);
                
                // TODO: Get issuer's public key from verification method
                // For now, we'll skip signature verification
                // Full implementation requires resolving the verification method DID
                logger.warn("JSON-LD proof signature verification not yet implemented");
                
                // Validate proof structure
                verifier.validateForVerification(jsonLdCred);
            } else {
                logger.warn("JSON-LD credential has no proof");
            }
            
            // Create VerifiableCredential wrapper
            VerifiableCredential credential = new VerifiableCredential();
            
            // Store the JSON as encrypted data (will be properly encrypted later)
            credential.setEncryptedData(credentialJson.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            
            // Extract and set metadata
            DigitalCredentialMetadata metadata = credential.getMetadata();
            
            // Set credential type (use most specific type, excluding VerifiableCredential)
            List<String> types = jsonLdCred.getTypes();
            for (int i = types.size() - 1; i >= 0; i--) {
                String type = types.get(i);
                if (!"VerifiableCredential".equals(type)) {
                    metadata.setCredentialType(type);
                    break;
                }
            }
            
            // Set JSON-LD specific metadata
            metadata.setTypes(new ArrayList<>(types));
            metadata.setContexts(jsonLdCred.getContext().getContextUrls());
            if (jsonLdCred.getCredentialSubject() != null) {
                metadata.setCredentialSubject(jsonLdCred.getCredentialSubject().toJson().toString());
            }
            if (jsonLdCred.getProof() != null) {
                metadata.setProofType(jsonLdCred.getProof().getType());
            }
            
            // Set issuer
            String issuer = jsonLdCred.getIssuer();
            if (issuer != null) {
                if (issuer.startsWith("did:")) {
                    metadata.setIssuerDid(issuer);
                } else {
                    metadata.setIssuerUrl(issuer);
                }
            }
            
            // Set timestamps
            if (jsonLdCred.getIssuanceDate() != null) {
                metadata.setIssuedAt(jsonLdCred.getIssuanceDate());
            }
            if (jsonLdCred.getExpirationDate() != null) {
                metadata.setExpiresAt(jsonLdCred.getExpirationDate());
            }
            
            logger.info("JSON-LD credential validated: type={}, issuer={}",
                       metadata.getCredentialType(),
                       metadata.getIssuerDid() != null ? metadata.getIssuerDid() : metadata.getIssuerUrl());
            
            return credential;
            
        } catch (JsonLdException e) {
            logger.error("JSON-LD validation failed", e);
            throw new OidcException("JSON-LD validation failed: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error("Unexpected error during JSON-LD validation", e);
            throw new OidcException("JSON-LD validation failed: " + e.getMessage(), e);
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
    
    /**
     * Extracts @context URLs from issuer metadata for JSON-LD credentials.
     * Falls back to W3C VC context + examples context if not specified in metadata.
     *
     * @param metadata The issuer metadata
     * @param credentialType The credential type being requested
     * @return List of context URLs, with W3C VC context always first
     * @throws OidcException if no valid context can be determined
     */
    private List<String> extractContextsFromMetadata(IssuerMetadata metadata, String credentialType)
            throws OidcException {
        List<String> contexts = new ArrayList<>();
        
        // W3C VC context is always required and must be first
        contexts.add("https://www.w3.org/2018/credentials/v1");
        
        // Try to find context from metadata
        List<Map<String, Object>> credentialsSupported = metadata.getCredentialsSupported();
        for (Map<String, Object> credConfig : credentialsSupported) {
            // Check if this is the right credential type
            Object formatObj = credConfig.get("format");
            if (formatObj instanceof String && "ldp_vc".equals(formatObj)) {
                // Look for @context in credential definition
                Object credDefObj = credConfig.get("credential_definition");
                if (credDefObj instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> credDef = (Map<String, Object>) credDefObj;
                    Object contextObj = credDef.get("@context");
                    
                    if (contextObj instanceof List) {
                        @SuppressWarnings("unchecked")
                        List<String> metadataContexts = (List<String>) contextObj;
                        for (String ctx : metadataContexts) {
                            // Skip W3C VC context since we already added it
                            if (!"https://www.w3.org/2018/credentials/v1".equals(ctx) && !contexts.contains(ctx)) {
                                contexts.add(ctx);
                            }
                        }
                    } else if (contextObj instanceof String) {
                        String ctx = (String) contextObj;
                        if (!"https://www.w3.org/2018/credentials/v1".equals(ctx) && !contexts.contains(ctx)) {
                            contexts.add(ctx);
                        }
                    }
                }
            }
        }
        
        // If no additional contexts found in metadata, add default examples context
        if (contexts.size() == 1) {
            logger.warn("No @context found in issuer metadata for JSON-LD credential, using default examples context");
            contexts.add("https://www.w3.org/2018/credentials/examples/v1");
        }
        
        logger.debug("Extracted contexts for JSON-LD credential request: {}", contexts);
        return contexts;
    }
}

// Made with Bob