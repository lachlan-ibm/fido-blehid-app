/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.oidc;

import com.isfs.blekey.util.http.HttpClient;
import com.isfs.blekey.util.http.HttpException;
import com.isfs.blekey.util.http.HttpResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Comprehensive unit tests for OidcAuthorizationClient.
 * Tests OAuth 2.0 authorization code flow with PKCE support.
 * 
 * Coverage targets:
 * - Authorization URL building (all parameter combinations)
 * - Token exchange (authorization code grant)
 * - Token refresh
 * - Error handling (HTTP errors, invalid responses)
 * - Utility methods (state/nonce generation, URL encoding)
 * - Constructors
 */
public class OidcAuthorizationClientTest {
    
    private HttpClient mockHttpClient;
    private OidcAuthorizationClient client;
    
    // Test constants
    private static final String TEST_AUTH_ENDPOINT = "https://auth.example.com/authorize";
    private static final String TEST_TOKEN_ENDPOINT = "https://auth.example.com/token";
    private static final String TEST_CLIENT_ID = "test-client-123";
    private static final String TEST_REDIRECT_URI = "app://callback";
    private static final String TEST_SCOPE = "openid profile email";
    private static final String TEST_STATE = "test-state-xyz";
    private static final String TEST_CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static final String TEST_CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String TEST_CODE_CHALLENGE_METHOD = "S256";
    private static final String TEST_AUTH_CODE = "SplxlOBeZQQYbYS6WxSbIA";
    private static final String TEST_ACCESS_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test";
    private static final String TEST_REFRESH_TOKEN = "8xLOxBtZp8";
    
    @BeforeEach
    public void setUp() {
        mockHttpClient = mock(HttpClient.class);
        client = new OidcAuthorizationClient(mockHttpClient);
    }
    
    // ========================================================================
    // Phase 1: Core Authorization Flow Tests
    // ========================================================================
    
    /**
     * Test 1.1: Build authorization URL with all parameters
     * Coverage: Lines 82-100, all branches
     */
    @Test
    public void testBuildAuthorizationUrl_AllParameters() throws OidcException {
        String url = client.buildAuthorizationUrl(
            TEST_AUTH_ENDPOINT,
            TEST_CLIENT_ID,
            TEST_REDIRECT_URI,
            TEST_SCOPE,
            TEST_STATE,
            TEST_CODE_CHALLENGE,
            TEST_CODE_CHALLENGE_METHOD
        );
        
        assertNotNull(url);
        assertTrue(url.startsWith(TEST_AUTH_ENDPOINT + "?"));
        assertTrue(url.contains("response_type=code"));
        assertTrue(url.contains("client_id=" + TEST_CLIENT_ID));
        assertTrue(url.contains("redirect_uri=app%3A%2F%2Fcallback")); // URL encoded
        assertTrue(url.contains("scope=openid+profile+email")); // URL encoded spaces
        assertTrue(url.contains("state=" + TEST_STATE));
        assertTrue(url.contains("code_challenge=" + TEST_CODE_CHALLENGE));
        assertTrue(url.contains("code_challenge_method=" + TEST_CODE_CHALLENGE_METHOD));
    }
    
    /**
     * Test 1.2: Build authorization URL with minimal parameters (no scope, no state)
     * Coverage: Lines 82-100, branches at lines 87, 91 (false paths)
     */
    @Test
    public void testBuildAuthorizationUrl_MinimalParameters() throws OidcException {
        String url = client.buildAuthorizationUrl(
            TEST_AUTH_ENDPOINT,
            TEST_CLIENT_ID,
            TEST_REDIRECT_URI,
            null, // no scope
            null, // no state
            TEST_CODE_CHALLENGE,
            TEST_CODE_CHALLENGE_METHOD
        );
        
        assertNotNull(url);
        assertTrue(url.startsWith(TEST_AUTH_ENDPOINT + "?"));
        assertTrue(url.contains("response_type=code"));
        assertTrue(url.contains("client_id=" + TEST_CLIENT_ID));
        assertTrue(url.contains("redirect_uri=app%3A%2F%2Fcallback"));
        assertFalse(url.contains("scope="));
        assertFalse(url.contains("state="));
        assertTrue(url.contains("code_challenge=" + TEST_CODE_CHALLENGE));
        assertTrue(url.contains("code_challenge_method=" + TEST_CODE_CHALLENGE_METHOD));
    }
    
    /**
     * Test 1.3: Build authorization URL with empty scope
     * Coverage: Branch at line 87 (empty string check)
     */
    @Test
    public void testBuildAuthorizationUrl_EmptyScope() throws OidcException {
        String url = client.buildAuthorizationUrl(
            TEST_AUTH_ENDPOINT,
            TEST_CLIENT_ID,
            TEST_REDIRECT_URI,
            "", // empty scope
            TEST_STATE,
            TEST_CODE_CHALLENGE,
            TEST_CODE_CHALLENGE_METHOD
        );
        
        assertNotNull(url);
        assertFalse(url.contains("scope="));
        assertTrue(url.contains("state=" + TEST_STATE));
    }
    
    /**
     * Test 1.4: Build authorization URL with empty state
     * Coverage: Branch at line 91 (empty string check)
     */
    @Test
    public void testBuildAuthorizationUrl_EmptyState() throws OidcException {
        String url = client.buildAuthorizationUrl(
            TEST_AUTH_ENDPOINT,
            TEST_CLIENT_ID,
            TEST_REDIRECT_URI,
            TEST_SCOPE,
            "", // empty state
            TEST_CODE_CHALLENGE,
            TEST_CODE_CHALLENGE_METHOD
        );
        
        assertNotNull(url);
        assertTrue(url.contains("scope=openid+profile+email"));
        assertFalse(url.contains("state="));
    }
    
    /**
     * Test 1.5: Build authorization URL with PkceGenerator
     * Coverage: Lines 124-125 (overloaded method)
     */
    @Test
    public void testBuildAuthorizationUrl_WithPkceGenerator() throws OidcException {
        PkceGenerator pkce = new PkceGenerator(TEST_CODE_VERIFIER);
        
        String url = client.buildAuthorizationUrl(
            TEST_AUTH_ENDPOINT,
            TEST_CLIENT_ID,
            TEST_REDIRECT_URI,
            TEST_SCOPE,
            TEST_STATE,
            pkce
        );
        
        assertNotNull(url);
        assertTrue(url.contains("code_challenge=" + pkce.getCodeChallenge()));
        assertTrue(url.contains("code_challenge_method=" + pkce.getCodeChallengeMethod()));
    }
    
    /**
     * Test 1.6: Build authorization URL with special characters
     * Coverage: URL encoding functionality (lines 84-97, urlEncode method)
     */
    @Test
    public void testBuildAuthorizationUrl_SpecialCharacters() throws OidcException {
        String specialClientId = "client&id=test";
        String specialRedirectUri = "app://callback?param=value&other=test";
        String specialScope = "openid profile:read email@domain";
        String specialState = "state with spaces & special=chars";
        
        String url = client.buildAuthorizationUrl(
            TEST_AUTH_ENDPOINT,
            specialClientId,
            specialRedirectUri,
            specialScope,
            specialState,
            TEST_CODE_CHALLENGE,
            TEST_CODE_CHALLENGE_METHOD
        );
        
        assertNotNull(url);
        // Verify special characters are encoded
        assertTrue(url.contains("client_id=client%26id%3Dtest"));
        assertTrue(url.contains("redirect_uri=app%3A%2F%2Fcallback%3Fparam%3Dvalue%26other%3Dtest"));
        assertTrue(url.contains("scope=openid+profile%3Aread+email%40domain"));
        assertTrue(url.contains("state=state+with+spaces+%26+special%3Dchars"));
    }
    
    /**
     * Test 1.7: Build authorization URL exception handling
     * Coverage: Lines 101-103 (exception wrapping)
     * Note: This is difficult to trigger naturally since urlEncode catches UnsupportedEncodingException
     * and wraps it in RuntimeException. We test the outer try-catch by passing null values.
     */
    @Test
    public void testBuildAuthorizationUrl_ExceptionHandling() {
        // Passing null should cause NullPointerException which gets wrapped
        assertThrows(OidcException.class, () -> {
            client.buildAuthorizationUrl(
                null, // null endpoint
                TEST_CLIENT_ID,
                TEST_REDIRECT_URI,
                TEST_SCOPE,
                TEST_STATE,
                TEST_CODE_CHALLENGE,
                TEST_CODE_CHALLENGE_METHOD
            );
        });
    }
    
    /**
     * Test 1.8: Exchange authorization code for token - success
     * Coverage: Lines 144-151 (exchangeCodeForToken method)
     */
    @Test
    public void testExchangeCodeForToken_Success() throws Exception {
        // Mock successful token response
        String tokenResponseJson = String.format(
            "{\"access_token\":\"%s\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"refresh_token\":\"%s\"}",
            TEST_ACCESS_TOKEN, TEST_REFRESH_TOKEN
        );
        HttpResponse mockResponse = new HttpResponse(200, new HashMap<>(), tokenResponseJson);
        when(mockHttpClient.postWithRetry(anyString(), anyString(), anyMap(), any()))
            .thenReturn(mockResponse);
        
        OidcTokenResponse tokenResponse = client.exchangeCodeForToken(
            TEST_TOKEN_ENDPOINT,
            TEST_AUTH_CODE,
            TEST_CODE_VERIFIER,
            TEST_REDIRECT_URI,
            TEST_CLIENT_ID
        );
        
        assertNotNull(tokenResponse);
        assertEquals(TEST_ACCESS_TOKEN, tokenResponse.getAccessToken());
        assertEquals("Bearer", tokenResponse.getTokenType());
        assertEquals(TEST_REFRESH_TOKEN, tokenResponse.getRefreshToken());
        
        // Verify request parameters
        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockHttpClient).postWithRetry(
            eq(TEST_TOKEN_ENDPOINT),
            bodyCaptor.capture(),
            anyMap(),
            any()
        );
        
        String requestBody = bodyCaptor.getValue();
        assertTrue(requestBody.contains("grant_type=authorization_code"));
        assertTrue(requestBody.contains("code=" + TEST_AUTH_CODE));
        assertTrue(requestBody.contains("redirect_uri=app%3A%2F%2Fcallback"));
        assertTrue(requestBody.contains("client_id=" + TEST_CLIENT_ID));
        assertTrue(requestBody.contains("code_verifier=" + TEST_CODE_VERIFIER));
    }
    
    /**
     * Test 1.9: Exchange authorization code - verify all parameters
     * Coverage: Lines 144-151 (parameter mapping)
     */
    @Test
    public void testExchangeCodeForToken_AllParameters() throws Exception {
        String tokenResponseJson = String.format(
            "{\"access_token\":\"%s\",\"token_type\":\"Bearer\"}",
            TEST_ACCESS_TOKEN
        );
        HttpResponse mockResponse = new HttpResponse(200, new HashMap<>(), tokenResponseJson);
        when(mockHttpClient.postWithRetry(anyString(), anyString(), anyMap(), any()))
            .thenReturn(mockResponse);
        
        client.exchangeCodeForToken(
            TEST_TOKEN_ENDPOINT,
            TEST_AUTH_CODE,
            TEST_CODE_VERIFIER,
            TEST_REDIRECT_URI,
            TEST_CLIENT_ID
        );
        
        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Map<String, String>> headersCaptor = ArgumentCaptor.forClass(Map.class);
        verify(mockHttpClient).postWithRetry(
            eq(TEST_TOKEN_ENDPOINT),
            bodyCaptor.capture(),
            headersCaptor.capture(),
            any()
        );
        
        // Verify headers
        Map<String, String> headers = headersCaptor.getValue();
        assertEquals("application/x-www-form-urlencoded", headers.get("Content-Type"));
        assertEquals("application/json", headers.get("Accept"));
        
        // Verify all required parameters are present
        String body = bodyCaptor.getValue();
        assertTrue(body.contains("grant_type="));
        assertTrue(body.contains("code="));
        assertTrue(body.contains("redirect_uri="));
        assertTrue(body.contains("client_id="));
        assertTrue(body.contains("code_verifier="));
    }
    
    /**
     * Test 1.10: Refresh token - success
     * Coverage: Lines 166-171 (refreshToken method)
     */
    @Test
    public void testRefreshToken_Success() throws Exception {
        String newAccessToken = "new-access-token-xyz";
        String tokenResponseJson = String.format(
            "{\"access_token\":\"%s\",\"token_type\":\"Bearer\",\"expires_in\":3600}",
            newAccessToken
        );
        HttpResponse mockResponse = new HttpResponse(200, new HashMap<>(), tokenResponseJson);
        when(mockHttpClient.postWithRetry(anyString(), anyString(), anyMap(), any()))
            .thenReturn(mockResponse);
        
        OidcTokenResponse tokenResponse = client.refreshToken(
            TEST_TOKEN_ENDPOINT,
            TEST_REFRESH_TOKEN,
            TEST_CLIENT_ID
        );
        
        assertNotNull(tokenResponse);
        assertEquals(newAccessToken, tokenResponse.getAccessToken());
        assertEquals("Bearer", tokenResponse.getTokenType());
        
        // Verify request parameters
        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockHttpClient).postWithRetry(
            eq(TEST_TOKEN_ENDPOINT),
            bodyCaptor.capture(),
            anyMap(),
            any()
        );
        
        String requestBody = bodyCaptor.getValue();
        assertTrue(requestBody.contains("grant_type=refresh_token"));
        assertTrue(requestBody.contains("refresh_token=" + TEST_REFRESH_TOKEN));
        assertTrue(requestBody.contains("client_id=" + TEST_CLIENT_ID));
    }
    
    /**
     * Test 1.11: Refresh token - verify new access token
     * Coverage: Lines 166-171 (token refresh flow)
     */
    @Test
    public void testRefreshToken_WithNewAccessToken() throws Exception {
        String newAccessToken = "refreshed-token-abc";
        String newRefreshToken = "new-refresh-token-def";
        String tokenResponseJson = String.format(
            "{\"access_token\":\"%s\",\"token_type\":\"Bearer\",\"refresh_token\":\"%s\"}",
            newAccessToken, newRefreshToken
        );
        HttpResponse mockResponse = new HttpResponse(200, new HashMap<>(), tokenResponseJson);
        when(mockHttpClient.postWithRetry(anyString(), anyString(), anyMap(), any()))
            .thenReturn(mockResponse);
        
        OidcTokenResponse tokenResponse = client.refreshToken(
            TEST_TOKEN_ENDPOINT,
            TEST_REFRESH_TOKEN,
            TEST_CLIENT_ID
        );
        
        assertNotNull(tokenResponse);
        assertEquals(newAccessToken, tokenResponse.getAccessToken());
        assertEquals(newRefreshToken, tokenResponse.getRefreshToken());
        assertTrue(tokenResponse.hasRefreshToken());
    }
    
    // ========================================================================
    // Phase 2: Error Handling Tests
    // ========================================================================
    
    /**
     * Test 2.1: Request token - HTTP error
     * Coverage: Lines 233-235 (HttpException catch block)
     */
    @Test
    public void testRequestToken_HttpError() throws Exception {
        HttpException httpException = new HttpException("Connection timeout", null);
        when(mockHttpClient.postWithRetry(anyString(), anyString(), anyMap(), any()))
            .thenThrow(httpException);
        
        OidcException exception = assertThrows(OidcException.class, () -> {
            client.exchangeCodeForToken(
                TEST_TOKEN_ENDPOINT,
                TEST_AUTH_CODE,
                TEST_CODE_VERIFIER,
                TEST_REDIRECT_URI,
                TEST_CLIENT_ID
            );
        });
        
        assertTrue(exception.getMessage().contains("Token request failed"));
        assertTrue(exception.getMessage().contains("Connection timeout"));
        assertEquals(httpException, exception.getCause());
    }
    
    /**
     * Test 2.2: Request token - generic exception
     * Coverage: Lines 236-238 (generic Exception catch block)
     */
    @Test
    public void testRequestToken_GenericException() throws Exception {
        RuntimeException genericException = new RuntimeException("Unexpected error");
        when(mockHttpClient.postWithRetry(anyString(), anyString(), anyMap(), any()))
            .thenThrow(genericException);
        
        OidcException exception = assertThrows(OidcException.class, () -> {
            client.refreshToken(
                TEST_TOKEN_ENDPOINT,
                TEST_REFRESH_TOKEN,
                TEST_CLIENT_ID
            );
        });
        
        assertTrue(exception.getMessage().contains("Token request failed"));
        assertTrue(exception.getMessage().contains("Unexpected error"));
        assertEquals(genericException, exception.getCause());
    }
    
    /**
     * Test 2.3: Request token - unsuccessful response (status != 200)
     * Coverage: Lines 222-228 (error response handling)
     */
    @Test
    public void testRequestToken_UnsuccessfulResponse() throws Exception {
        HttpResponse errorResponse = new HttpResponse(401, new HashMap<>(), null);
        when(mockHttpClient.postWithRetry(anyString(), anyString(), anyMap(), any()))
            .thenReturn(errorResponse);
        
        OidcException exception = assertThrows(OidcException.class, () -> {
            client.exchangeCodeForToken(
                TEST_TOKEN_ENDPOINT,
                TEST_AUTH_CODE,
                TEST_CODE_VERIFIER,
                TEST_REDIRECT_URI,
                TEST_CLIENT_ID
            );
        });
        
        assertTrue(exception.getMessage().contains("Token request failed"));
        assertTrue(exception.getMessage().contains("401"));
    }
    
    /**
     * Test 2.4: Request token - unsuccessful response with error body
     * Coverage: Lines 224-226 (error message with body)
     */
    @Test
    public void testRequestToken_UnsuccessfulResponseWithBody() throws Exception {
        String errorBody = "{\"error\":\"invalid_grant\",\"error_description\":\"Authorization code expired\"}";
        HttpResponse errorResponse = new HttpResponse(400, new HashMap<>(), errorBody);
        when(mockHttpClient.postWithRetry(anyString(), anyString(), anyMap(), any()))
            .thenReturn(errorResponse);
        
        OidcException exception = assertThrows(OidcException.class, () -> {
            client.exchangeCodeForToken(
                TEST_TOKEN_ENDPOINT,
                TEST_AUTH_CODE,
                TEST_CODE_VERIFIER,
                TEST_REDIRECT_URI,
                TEST_CLIENT_ID
            );
        });
        
        assertTrue(exception.getMessage().contains("400"));
        assertTrue(exception.getMessage().contains("invalid_grant"));
        assertTrue(exception.getMessage().contains("Authorization code expired"));
    }
    
    /**
     * Test 2.5: Request token - unsuccessful response without body
     * Coverage: Lines 222-228 (error without body)
     */
    @Test
    public void testRequestToken_UnsuccessfulResponseWithoutBody() throws Exception {
        HttpResponse errorResponse = new HttpResponse(500, new HashMap<>(), null);
        when(mockHttpClient.postWithRetry(anyString(), anyString(), anyMap(), any()))
            .thenReturn(errorResponse);
        
        OidcException exception = assertThrows(OidcException.class, () -> {
            client.refreshToken(
                TEST_TOKEN_ENDPOINT,
                TEST_REFRESH_TOKEN,
                TEST_CLIENT_ID
            );
        });
        
        assertTrue(exception.getMessage().contains("Token request failed"));
        assertTrue(exception.getMessage().contains("500"));
        assertFalse(exception.getMessage().contains("null")); // Should not include null body
    }
    
    // ========================================================================
    // Phase 3: Utility Method Tests
    // ========================================================================
    
    /**
     * Test 3.1: Generate state - success
     * Coverage: Lines 248-249 (generateState method)
     */
    @Test
    public void testGenerateState_Success() throws OidcException {
        String state = OidcAuthorizationClient.generateState();
        
        assertNotNull(state);
        assertFalse(state.isEmpty());
        // Base64url encoded 32 bytes should be ~43 characters
        assertTrue(state.length() >= 40);
        // Should not contain padding
        assertFalse(state.contains("="));
        // Should be URL-safe (no +, /, =)
        assertFalse(state.contains("+"));
        assertFalse(state.contains("/"));
    }
    
    /**
     * Test 3.2: Generate nonce - success
     * Coverage: Lines 258-259 (generateNonce method)
     */
    @Test
    public void testGenerateNonce_Success() throws OidcException {
        String nonce = OidcAuthorizationClient.generateNonce();
        
        assertNotNull(nonce);
        assertFalse(nonce.isEmpty());
        // Base64url encoded 32 bytes should be ~43 characters
        assertTrue(nonce.length() >= 40);
        // Should not contain padding
        assertFalse(nonce.contains("="));
        // Should be URL-safe
        assertFalse(nonce.contains("+"));
        assertFalse(nonce.contains("/"));
    }
    
    /**
     * Test 3.3: Generate random string - success
     * Coverage: Lines 271-274 (generateRandomString method)
     * Note: This is a private method, tested indirectly through generateState/generateNonce
     */
    @Test
    public void testGenerateRandomString_Success() throws OidcException {
        // Test through public methods
        String state1 = OidcAuthorizationClient.generateState();
        String state2 = OidcAuthorizationClient.generateState();
        
        assertNotNull(state1);
        assertNotNull(state2);
        // Should be different (cryptographically random)
        assertNotEquals(state1, state2);
    }
    
    /**
     * Test 3.4: Generate state - uniqueness
     * Coverage: Lines 248-249 (collision resistance)
     */
    @Test
    public void testGenerateState_Uniqueness() throws OidcException {
        // Generate multiple states and verify uniqueness
        java.util.Set<String> states = new java.util.HashSet<>();
        for (int i = 0; i < 100; i++) {
            String state = OidcAuthorizationClient.generateState();
            assertTrue(states.add(state), "Generated duplicate state: " + state);
        }
        assertEquals(100, states.size());
    }
    
    /**
     * Test 3.5: Generate nonce - uniqueness
     * Coverage: Lines 258-259 (collision resistance)
     */
    @Test
    public void testGenerateNonce_Uniqueness() throws OidcException {
        // Generate multiple nonces and verify uniqueness
        java.util.Set<String> nonces = new java.util.HashSet<>();
        for (int i = 0; i < 100; i++) {
            String nonce = OidcAuthorizationClient.generateNonce();
            assertTrue(nonces.add(nonce), "Generated duplicate nonce: " + nonce);
        }
        assertEquals(100, nonces.size());
    }
    
    /**
     * Test 3.6: URL encode - special characters
     * Coverage: Line 311 (urlEncode method)
     * Note: This is a private method, tested indirectly through buildAuthorizationUrl
     */
    @Test
    public void testUrlEncode_SpecialCharacters() throws OidcException {
        // Test through buildAuthorizationUrl which uses urlEncode
        String url = client.buildAuthorizationUrl(
            TEST_AUTH_ENDPOINT,
            "client&id",
            "app://callback?test=1",
            "scope with spaces",
            "state=value",
            TEST_CODE_CHALLENGE,
            TEST_CODE_CHALLENGE_METHOD
        );
        
        // Verify encoding
        assertTrue(url.contains("client%26id")); // & encoded
        assertTrue(url.contains("app%3A%2F%2Fcallback%3Ftest%3D1")); // :, /, ? encoded
        assertTrue(url.contains("scope+with+spaces")); // spaces as +
        assertTrue(url.contains("state%3Dvalue")); // = encoded
    }
    
    /**
     * Test 3.7: Build form body - success
     * Coverage: Lines 286-301 (buildFormBody method)
     * Note: This is a private method, tested indirectly through token requests
     */
    @Test
    public void testBuildFormBody_Success() throws Exception {
        String tokenResponseJson = String.format(
            "{\"access_token\":\"%s\",\"token_type\":\"Bearer\"}",
            TEST_ACCESS_TOKEN
        );
        HttpResponse mockResponse = new HttpResponse(200, new HashMap<>(), tokenResponseJson);
        when(mockHttpClient.postWithRetry(anyString(), anyString(), anyMap(), any()))
            .thenReturn(mockResponse);
        
        client.exchangeCodeForToken(
            TEST_TOKEN_ENDPOINT,
            TEST_AUTH_CODE,
            TEST_CODE_VERIFIER,
            TEST_REDIRECT_URI,
            TEST_CLIENT_ID
        );
        
        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockHttpClient).postWithRetry(anyString(), bodyCaptor.capture(), anyMap(), any());
        
        String body = bodyCaptor.getValue();
        // Verify form-urlencoded format
        assertTrue(body.contains("&")); // Parameters separated by &
        assertTrue(body.contains("=")); // Key=value pairs
        assertFalse(body.startsWith("&")); // Should not start with &
    }
    
    /**
     * Test 3.8: Build form body - parameter order
     * Coverage: Lines 286-301 (parameter iteration)
     */
    @Test
    public void testBuildFormBody_ParameterOrder() throws Exception {
        String tokenResponseJson = String.format(
            "{\"access_token\":\"%s\",\"token_type\":\"Bearer\"}",
            TEST_ACCESS_TOKEN
        );
        HttpResponse mockResponse = new HttpResponse(200, new HashMap<>(), tokenResponseJson);
        when(mockHttpClient.postWithRetry(anyString(), anyString(), anyMap(), any()))
            .thenReturn(mockResponse);
        
        client.refreshToken(TEST_TOKEN_ENDPOINT, TEST_REFRESH_TOKEN, TEST_CLIENT_ID);
        
        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockHttpClient).postWithRetry(anyString(), bodyCaptor.capture(), anyMap(), any());
        
        String body = bodyCaptor.getValue();
        // All parameters should be present
        assertTrue(body.contains("grant_type="));
        assertTrue(body.contains("refresh_token="));
        assertTrue(body.contains("client_id="));
        // Should not have trailing or leading &
        assertFalse(body.endsWith("&"));
        assertFalse(body.startsWith("&"));
    }
    
    // ========================================================================
    // Phase 4: Constructor Tests
    // ========================================================================
    
    /**
     * Test 4.1: Default constructor
     * Coverage: Lines 48-49 (default constructor)
     */
    @Test
    public void testDefaultConstructor() {
        OidcAuthorizationClient defaultClient = new OidcAuthorizationClient();
        
        assertNotNull(defaultClient);
        // Verify it can be used (HttpClient is initialized)
        assertDoesNotThrow(() -> {
            defaultClient.buildAuthorizationUrl(
                TEST_AUTH_ENDPOINT,
                TEST_CLIENT_ID,
                TEST_REDIRECT_URI,
                TEST_SCOPE,
                TEST_STATE,
                TEST_CODE_CHALLENGE,
                TEST_CODE_CHALLENGE_METHOD
            );
        });
    }
    
    /**
     * Test 4.2: Constructor with HttpClient
     * Coverage: Lines 57-58 (parameterized constructor)
     * Already covered in setUp() and all other tests
     */
    @Test
    public void testConstructorWithHttpClient() {
        HttpClient customHttpClient = mock(HttpClient.class);
        OidcAuthorizationClient customClient = new OidcAuthorizationClient(customHttpClient);
        
        assertNotNull(customClient);
        // The custom client should use the provided HttpClient
        // This is implicitly tested in all other tests via mockHttpClient
    }
    
    // ========================================================================
    // Additional Coverage Tests
    // ========================================================================
    
    /**
     * Test: Pre-authorized token request (already covered in existing tests)
     * Coverage: Lines 183-192 (requestPreAuthorizedToken method)
     * This method is already tested in Oidc4VciClientTest, but we verify it here too
     */
    @Test
    public void testRequestPreAuthorizedToken_Success() throws Exception {
        String preAuthCode = "pre-auth-code-123";
        String tokenResponseJson = String.format(
            "{\"access_token\":\"%s\",\"token_type\":\"Bearer\",\"c_nonce\":\"test-nonce\"}",
            TEST_ACCESS_TOKEN
        );
        HttpResponse mockResponse = new HttpResponse(200, new HashMap<>(), tokenResponseJson);
        when(mockHttpClient.postWithRetry(anyString(), anyString(), anyMap(), any()))
            .thenReturn(mockResponse);
        
        OidcTokenResponse tokenResponse = client.requestPreAuthorizedToken(
            TEST_TOKEN_ENDPOINT,
            preAuthCode,
            TEST_CLIENT_ID
        );
        
        assertNotNull(tokenResponse);
        assertEquals(TEST_ACCESS_TOKEN, tokenResponse.getAccessToken());
        assertTrue(tokenResponse.hasCNonce());
        
        // Verify request parameters
        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockHttpClient).postWithRetry(
            eq(TEST_TOKEN_ENDPOINT),
            bodyCaptor.capture(),
            anyMap(),
            any()
        );
        
        String requestBody = bodyCaptor.getValue();
        assertTrue(requestBody.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code"));
        assertTrue(requestBody.contains("pre-authorized_code=" + preAuthCode));
        assertTrue(requestBody.contains("client_id=" + TEST_CLIENT_ID));
    }

    // ========================================================================
    // Integration-Style Flow Tests
    // ========================================================================

    /**
     * Complete authorization flow using the same client instance.
     * Verifies URL building, code exchange, and refresh token flow together.
     */
    @Test
    public void testCompleteAuthorizationFlow() throws Exception {
        String authorizationUrl = client.buildAuthorizationUrl(
            TEST_AUTH_ENDPOINT,
            TEST_CLIENT_ID,
            TEST_REDIRECT_URI,
            TEST_SCOPE,
            TEST_STATE,
            TEST_CODE_CHALLENGE,
            TEST_CODE_CHALLENGE_METHOD
        );

        assertNotNull(authorizationUrl);
        assertTrue(authorizationUrl.contains("client_id=" + TEST_CLIENT_ID));
        assertTrue(authorizationUrl.contains("state=" + TEST_STATE));
        assertTrue(authorizationUrl.contains("code_challenge=" + TEST_CODE_CHALLENGE));

        HttpResponse exchangeResponse = new HttpResponse(
            200,
            new HashMap<>(),
            "{\"access_token\":\"initial-access-token\",\"token_type\":\"Bearer\",\"refresh_token\":\"" + TEST_REFRESH_TOKEN + "\"}"
        );
        HttpResponse refreshResponse = new HttpResponse(
            200,
            new HashMap<>(),
            "{\"access_token\":\"refreshed-access-token\",\"token_type\":\"Bearer\",\"refresh_token\":\"rotated-refresh-token\"}"
        );

        when(mockHttpClient.postWithRetry(anyString(), anyString(), anyMap(), any()))
            .thenReturn(exchangeResponse)
            .thenReturn(refreshResponse);

        OidcTokenResponse exchanged = client.exchangeCodeForToken(
            TEST_TOKEN_ENDPOINT,
            TEST_AUTH_CODE,
            TEST_CODE_VERIFIER,
            TEST_REDIRECT_URI,
            TEST_CLIENT_ID
        );
        OidcTokenResponse refreshed = client.refreshToken(
            TEST_TOKEN_ENDPOINT,
            exchanged.getRefreshToken(),
            TEST_CLIENT_ID
        );

        assertEquals("initial-access-token", exchanged.getAccessToken());
        assertEquals(TEST_REFRESH_TOKEN, exchanged.getRefreshToken());
        assertEquals("refreshed-access-token", refreshed.getAccessToken());
        assertEquals("rotated-refresh-token", refreshed.getRefreshToken());

        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockHttpClient, times(2)).postWithRetry(
            eq(TEST_TOKEN_ENDPOINT),
            bodyCaptor.capture(),
            anyMap(),
            any()
        );

        assertTrue(bodyCaptor.getAllValues().get(0).contains("grant_type=authorization_code"));
        assertTrue(bodyCaptor.getAllValues().get(0).contains("code=" + TEST_AUTH_CODE));
        assertTrue(bodyCaptor.getAllValues().get(1).contains("grant_type=refresh_token"));
        assertTrue(bodyCaptor.getAllValues().get(1).contains("refresh_token=" + TEST_REFRESH_TOKEN));
    }

    /**
     * PKCE flow using PkceGenerator for authorization URL and verifier for token exchange.
     */
    @Test
    public void testPkceFlow() throws Exception {
        PkceGenerator pkce = new PkceGenerator(TEST_CODE_VERIFIER);

        String authorizationUrl = client.buildAuthorizationUrl(
            TEST_AUTH_ENDPOINT,
            TEST_CLIENT_ID,
            TEST_REDIRECT_URI,
            TEST_SCOPE,
            TEST_STATE,
            pkce
        );

        assertNotNull(authorizationUrl);
        assertTrue(authorizationUrl.contains("code_challenge=" + pkce.getCodeChallenge()));
        assertTrue(authorizationUrl.contains("code_challenge_method=" + pkce.getCodeChallengeMethod()));

        HttpResponse tokenResponse = new HttpResponse(
            200,
            new HashMap<>(),
            "{\"access_token\":\"pkce-access-token\",\"token_type\":\"Bearer\"}"
        );
        when(mockHttpClient.postWithRetry(anyString(), anyString(), anyMap(), any()))
            .thenReturn(tokenResponse);

        OidcTokenResponse exchanged = client.exchangeCodeForToken(
            TEST_TOKEN_ENDPOINT,
            TEST_AUTH_CODE,
            pkce.getCodeVerifier(),
            TEST_REDIRECT_URI,
            TEST_CLIENT_ID
        );

        assertEquals("pkce-access-token", exchanged.getAccessToken());

        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockHttpClient).postWithRetry(
            eq(TEST_TOKEN_ENDPOINT),
            bodyCaptor.capture(),
            anyMap(),
            any()
        );

        String requestBody = bodyCaptor.getValue();
        assertTrue(requestBody.contains("grant_type=authorization_code"));
        assertTrue(requestBody.contains("code_verifier=" + pkce.getCodeVerifier()));
    }
}

// Made with Bob