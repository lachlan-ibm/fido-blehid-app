/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.oidc;

import com.isfs.blekey.util.http.HttpClient;
import com.isfs.blekey.util.http.HttpException;
import com.isfs.blekey.util.http.HttpResponse;
import com.isfs.blekey.util.http.RetryPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Common OAuth 2.0 authorization code flow implementation with PKCE support.
 * Used by both OIDC4VCI and OIDC4VP for obtaining access tokens.
 * 
 * Implements:
 * - RFC 6749: OAuth 2.0 Authorization Framework
 * - RFC 7636: Proof Key for Code Exchange (PKCE)
 * - RFC 8252: OAuth 2.0 for Native Apps
 * 
 * Flow:
 * 1. Generate PKCE parameters (code_verifier, code_challenge)
 * 2. Build authorization URL with code_challenge
 * 3. User authenticates and authorizes (handled externally)
 * 4. Exchange authorization code for access token with code_verifier
 * 5. Optionally refresh access token using refresh_token
 */
public class OidcAuthorizationClient {
    
    private static final Logger logger = LoggerFactory.getLogger(OidcAuthorizationClient.class);
    private static final int STATE_LENGTH = 32;
    private static final int NONCE_LENGTH = 32;
    
    private final HttpClient httpClient;
    
    /**
     * Creates a new OIDC authorization client.
     */
    public OidcAuthorizationClient() {
        this.httpClient = new HttpClient();
    }
    
    /**
     * Creates a new OIDC authorization client with a custom HTTP client.
     * 
     * @param httpClient The HTTP client to use
     */
    public OidcAuthorizationClient(HttpClient httpClient) {
        this.httpClient = httpClient;
    }
    
    /**
     * Builds an authorization request URL with PKCE.
     * 
     * @param authorizationEndpoint The authorization endpoint URL
     * @param clientId The client identifier
     * @param redirectUri The redirect URI
     * @param scope The requested scope (space-separated)
     * @param state The state parameter for CSRF protection
     * @param codeChallenge The PKCE code challenge
     * @param codeChallengeMethod The PKCE code challenge method (usually "S256")
     * @return The complete authorization URL
     * @throws OidcException if URL building fails
     */
    public String buildAuthorizationUrl(String authorizationEndpoint,
                                       String clientId,
                                       String redirectUri,
                                       String scope,
                                       String state,
                                       String codeChallenge,
                                       String codeChallengeMethod) throws OidcException {
        try {
            StringBuilder url = new StringBuilder(authorizationEndpoint);
            url.append("?response_type=code");
            url.append("&client_id=").append(urlEncode(clientId));
            url.append("&redirect_uri=").append(urlEncode(redirectUri));
            
            if (scope != null && !scope.isEmpty()) {
                url.append("&scope=").append(urlEncode(scope));
            }
            
            if (state != null && !state.isEmpty()) {
                url.append("&state=").append(urlEncode(state));
            }
            
            // PKCE parameters
            url.append("&code_challenge=").append(urlEncode(codeChallenge));
            url.append("&code_challenge_method=").append(urlEncode(codeChallengeMethod));
            
            logger.debug("Built authorization URL for client: {}", clientId);
            return url.toString();
        } catch (Exception e) {
            throw new OidcException("Failed to build authorization URL", e);
        }
    }
    
    /**
     * Builds an authorization request URL with PKCE using a PkceGenerator.
     * 
     * @param authorizationEndpoint The authorization endpoint URL
     * @param clientId The client identifier
     * @param redirectUri The redirect URI
     * @param scope The requested scope (space-separated)
     * @param state The state parameter for CSRF protection
     * @param pkce The PKCE generator containing code challenge
     * @return The complete authorization URL
     * @throws OidcException if URL building fails
     */
    public String buildAuthorizationUrl(String authorizationEndpoint,
                                       String clientId,
                                       String redirectUri,
                                       String scope,
                                       String state,
                                       PkceGenerator pkce) throws OidcException {
        return buildAuthorizationUrl(authorizationEndpoint, clientId, redirectUri, scope, state,
                                    pkce.getCodeChallenge(), pkce.getCodeChallengeMethod());
    }
    
    /**
     * Exchanges an authorization code for an access token.
     * 
     * @param tokenEndpoint The token endpoint URL
     * @param authorizationCode The authorization code received from authorization endpoint
     * @param codeVerifier The PKCE code verifier
     * @param redirectUri The redirect URI (must match the one used in authorization request)
     * @param clientId The client identifier
     * @return The token response containing access_token and optionally refresh_token
     * @throws OidcException if token exchange fails
     */
    public OidcTokenResponse exchangeCodeForToken(String tokenEndpoint,
                                                  String authorizationCode,
                                                  String codeVerifier,
                                                  String redirectUri,
                                                  String clientId) throws OidcException {
        Map<String, String> params = new HashMap<>();
        params.put("grant_type", "authorization_code");
        params.put("code", authorizationCode);
        params.put("redirect_uri", redirectUri);
        params.put("client_id", clientId);
        params.put("code_verifier", codeVerifier);
        
        return requestToken(tokenEndpoint, params);
    }
    
    /**
     * Refreshes an access token using a refresh token.
     * 
     * @param tokenEndpoint The token endpoint URL
     * @param refreshToken The refresh token
     * @param clientId The client identifier
     * @return The token response with new access_token
     * @throws OidcException if token refresh fails
     */
    public OidcTokenResponse refreshToken(String tokenEndpoint,
                                         String refreshToken,
                                         String clientId) throws OidcException {
        Map<String, String> params = new HashMap<>();
        params.put("grant_type", "refresh_token");
        params.put("refresh_token", refreshToken);
        params.put("client_id", clientId);
        
        return requestToken(tokenEndpoint, params);
    }
    
    /**
     * Requests a token using pre-authorized code grant (OIDC4VCI).
     * 
     * @param tokenEndpoint The token endpoint URL
     * @param preAuthorizedCode The pre-authorized code from credential offer
     * @param clientId The client identifier
     * @return The token response
     * @throws OidcException if token request fails
     */
    public OidcTokenResponse requestPreAuthorizedToken(String tokenEndpoint,
                                                      String preAuthorizedCode,
                                                      String clientId) throws OidcException {
        Map<String, String> params = new HashMap<>();
        params.put("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code");
        params.put("pre-authorized_code", preAuthorizedCode);
        params.put("client_id", clientId);
        
        return requestToken(tokenEndpoint, params);
    }
    
    /**
     * Makes a token request to the token endpoint.
     * 
     * @param tokenEndpoint The token endpoint URL
     * @param params The request parameters
     * @return The token response
     * @throws OidcException if request fails
     */
    private OidcTokenResponse requestToken(String tokenEndpoint, Map<String, String> params) throws OidcException {
        try {
            // Build form-urlencoded body
            String body = buildFormBody(params);
            
            // Set headers
            Map<String, String> headers = new HashMap<>();
            headers.put("Content-Type", "application/x-www-form-urlencoded");
            headers.put("Accept", "application/json");
            
            logger.debug("Requesting token from: {}", tokenEndpoint);
            
            // Make request with retry policy
            HttpResponse response = httpClient.postWithRetry(
                tokenEndpoint,
                body,
                headers,
                RetryPolicy.ISSUANCE
            );
            
            if (!response.isSuccessful()) {
                String errorMsg = "Token request failed with status " + response.getStatusCode();
                if (response.getBody() != null) {
                    errorMsg += ": " + response.getBody();
                }
                throw new OidcException(errorMsg);
            }
            
            // Parse token response
            return OidcTokenResponse.fromJson(response.getBody());
            
        } catch (HttpException e) {
            logger.error("HTTP error during token request", e);
            throw new OidcException("Token request failed: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error("Unexpected error during token request", e);
            throw new OidcException("Token request failed: " + e.getMessage(), e);
        }
    }
    
    /**
     * Generates a cryptographically random state parameter.
     * 
     * @return Base64url-encoded random state
     * @throws OidcException if random generation fails
     */
    public static String generateState() throws OidcException {
        return generateRandomString(STATE_LENGTH);
    }
    
    /**
     * Generates a cryptographically random nonce parameter.
     * 
     * @return Base64url-encoded random nonce
     * @throws OidcException if random generation fails
     */
    public static String generateNonce() throws OidcException {
        return generateRandomString(NONCE_LENGTH);
    }
    
    /**
     * Generates a cryptographically random string.
     * 
     * @param length The length in bytes
     * @return Base64url-encoded random string
     * @throws OidcException if random generation fails
     */
    private static String generateRandomString(int length) throws OidcException {
        try {
            SecureRandom random = SecureRandom.getInstanceStrong();
            byte[] randomBytes = new byte[length];
            random.nextBytes(randomBytes);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        } catch (Exception e) {
            throw new OidcException("Failed to generate random string", e);
        }
    }
    
    /**
     * Builds a form-urlencoded request body from parameters.
     * 
     * @param params The parameters
     * @return The form-urlencoded body
     */
    private String buildFormBody(Map<String, String> params) {
        StringBuilder body = new StringBuilder();
        boolean first = true;
        
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (!first) {
                body.append("&");
            }
            body.append(urlEncode(entry.getKey()));
            body.append("=");
            body.append(urlEncode(entry.getValue()));
            first = false;
        }
        
        return body.toString();
    }
    
    /**
     * URL-encodes a string.
     * 
     * @param value The value to encode
     * @return The URL-encoded value
     */
    private String urlEncode(String value) {
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            // UTF-8 is always supported
            throw new RuntimeException("UTF-8 encoding not supported", e);
        }
    }
}

// Made with Bob