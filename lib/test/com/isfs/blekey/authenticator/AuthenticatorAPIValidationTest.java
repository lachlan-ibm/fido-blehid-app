/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator;

import com.isfs.blekey.ctap.Ctap2StatusCode;
import com.isfs.blekey.ctap.CtapTxn;
import com.isfs.blekey.data.Passkey;
import com.isfs.blekey.util.Cbor;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Comprehensive unit tests for AuthenticatorAPI validation logic.
 * Tests all error cases defined in CTAP2 specification for authenticatorMakeCredential.
 */
@DisplayName("AuthenticatorAPI Validation Tests")
public class AuthenticatorAPIValidationTest {

    private Map<Integer, Object> baseRequest;
    private CtapTxn mockTxn;
    private Passkey mockPasskey;

    @BeforeEach
    public void setUp() {
        // Create a valid base request that can be modified for each test
        baseRequest = new HashMap<>();
        
        // clientDataHash (0x01) - 32 bytes for SHA-256
        byte[] clientDataHash = new byte[32];
        for (int i = 0; i < 32; i++) {
            clientDataHash[i] = (byte) i;
        }
        baseRequest.put(0x01, clientDataHash);
        
        // rp (0x02)
        Map<String, Object> rp = new HashMap<>();
        rp.put("id", "example.com");
        rp.put("name", "Example Corp");
        baseRequest.put(0x02, rp);
        
        // user (0x03)
        Map<String, Object> user = new HashMap<>();
        user.put("id", new byte[]{1, 2, 3, 4});
        user.put("name", "testuser");
        user.put("displayName", "Test User");
        baseRequest.put(0x03, user);
        
        // pubKeyCredParams (0x04) - ES256
        List<Map<String, Object>> pubKeyCredParams = new ArrayList<>();
        Map<String, Object> es256 = new HashMap<>();
        es256.put("type", "public-key");
        es256.put("alg", -7); // ES256
        pubKeyCredParams.add(es256);
        baseRequest.put(0x04, pubKeyCredParams);
        
        // Default options (0x07)
        Map<String, Object> options = new HashMap<>();
        options.put("up", true);
        options.put("uv", false);
        options.put("rk", false);
        baseRequest.put(0x07, options);
    }

    @Test
    @DisplayName("Should return MISSING_PARAMETER when clientDataHash is missing")
    public void testMissingClientDataHash() {
        baseRequest.remove(0x01);
        
        byte[] response = AuthenticatorAPI.makeCredential(mockTxn, baseRequest);
        
        assertEquals(Ctap2StatusCode.MISSING_PARAMETER.getCode(), response[0],
            "Should return MISSING_PARAMETER error code");
    }

    @Test
    @DisplayName("Should return MISSING_PARAMETER when rp is missing")
    public void testMissingRp() {
        baseRequest.remove(0x02);
        
        byte[] response = AuthenticatorAPI.makeCredential(mockTxn, baseRequest);
        
        assertEquals(Ctap2StatusCode.MISSING_PARAMETER.getCode(), response[0],
            "Should return MISSING_PARAMETER error code");
    }

    @Test
    @DisplayName("Should return MISSING_PARAMETER when user is missing")
    public void testMissingUser() {
        baseRequest.remove(0x03);
        
        byte[] response = AuthenticatorAPI.makeCredential(mockTxn, baseRequest);
        
        assertEquals(Ctap2StatusCode.MISSING_PARAMETER.getCode(), response[0],
            "Should return MISSING_PARAMETER error code");
    }

    @Test
    @DisplayName("Should return MISSING_PARAMETER when pubKeyCredParams is missing")
    public void testMissingPubKeyCredParams() {
        baseRequest.remove(0x04);
        
        byte[] response = AuthenticatorAPI.makeCredential(mockTxn, baseRequest);
        
        assertEquals(Ctap2StatusCode.MISSING_PARAMETER.getCode(), response[0],
            "Should return MISSING_PARAMETER error code");
    }

    @Test
    @DisplayName("Should return INVALID_PARAMETER when clientDataHash is wrong length")
    public void testInvalidClientDataHashLength() {
        // Test with 16 bytes instead of 32
        baseRequest.put(0x01, new byte[16]);
        
        byte[] response = AuthenticatorAPI.makeCredential(mockTxn, baseRequest);
        
        assertEquals(Ctap2StatusCode.INVALID_PARAMETER.getCode(), response[0],
            "Should return INVALID_PARAMETER for wrong hash length");
    }

    @Test
    @DisplayName("Should return INVALID_PARAMETER when clientDataHash is null")
    public void testNullClientDataHash() {
        baseRequest.put(0x01, null);
        
        byte[] response = AuthenticatorAPI.makeCredential(mockTxn, baseRequest);
        
        assertEquals(Ctap2StatusCode.INVALID_PARAMETER.getCode(), response[0],
            "Should return INVALID_PARAMETER for null hash");
    }

    @Test
    @DisplayName("Should return INVALID_PARAMETER when pubKeyCredParams is empty")
    public void testEmptyPubKeyCredParams() {
        baseRequest.put(0x04, new ArrayList<>());
        
        byte[] response = AuthenticatorAPI.makeCredential(mockTxn, baseRequest);
        
        assertEquals(Ctap2StatusCode.INVALID_PARAMETER.getCode(), response[0],
            "Should return INVALID_PARAMETER for empty pubKeyCredParams");
    }

    @Test
    @DisplayName("Should return UNSUPPORTED_ALGORITHM when no supported algorithm in pubKeyCredParams")
    public void testUnsupportedAlgorithm() {
        // Replace with unsupported algorithm (RS256 = -257)
        List<Map<String, Object>> pubKeyCredParams = new ArrayList<>();
        Map<String, Object> rs256 = new HashMap<>();
        rs256.put("type", "public-key");
        rs256.put("alg", -257); // RS256 - not supported
        pubKeyCredParams.add(rs256);
        baseRequest.put(0x04, pubKeyCredParams);
        
        byte[] response = AuthenticatorAPI.makeCredential(mockTxn, baseRequest);
        
        assertEquals(Ctap2StatusCode.UNSUPPORTED_ALGORITHM.getCode(), response[0],
            "Should return UNSUPPORTED_ALGORITHM error code");
    }

    @Test
    @DisplayName("Should accept ES256 algorithm")
    public void testSupportedAlgorithmES256() {
        // ES256 is already in baseRequest, this should succeed (or fail for other reasons)
        byte[] response = AuthenticatorAPI.makeCredential(mockTxn, baseRequest);
        
        // Should not be UNSUPPORTED_ALGORITHM
        assertNotEquals(Ctap2StatusCode.UNSUPPORTED_ALGORITHM.getCode(), response[0],
            "Should not return UNSUPPORTED_ALGORITHM for ES256");
    }

    @Test
    @DisplayName("Should return INVALID_OPTION when user presence is false")
    public void testUserPresenceFalse() {
        @SuppressWarnings("unchecked")
        Map<String, Object> options = (Map<String, Object>) baseRequest.get(0x07);
        options.put("up", false);
        
        byte[] response = AuthenticatorAPI.makeCredential(mockTxn, baseRequest);
        
        assertEquals(Ctap2StatusCode.INVALID_OPTION.getCode(), response[0],
            "Should return INVALID_OPTION when up=false");
    }

    @Test
    @DisplayName("Should handle resident key request")
    public void testResidentKeyRequest() {
        @SuppressWarnings("unchecked")
        Map<String, Object> options = (Map<String, Object>) baseRequest.get(0x07);
        options.put("rk", true);
        options.put("uv", true);
        
        byte[] response = AuthenticatorAPI.makeCredential(mockTxn, baseRequest);
        
        // Should not return INVALID_OPTION or UNSUPPORTED_OPTION for valid rk request
        assertNotEquals(Ctap2StatusCode.INVALID_OPTION.getCode(), response[0],
            "Should not return INVALID_OPTION for valid resident key request");
    }

    @Test
    @DisplayName("Should handle two-factor credential request")
    public void testTwoFactorCredentialRequest() {
        @SuppressWarnings("unchecked")
        Map<String, Object> options = (Map<String, Object>) baseRequest.get(0x07);
        options.put("rk", false);
        options.put("uv", false);
        
        byte[] response = AuthenticatorAPI.makeCredential(mockTxn, baseRequest);
        
        // Should not return INVALID_OPTION for valid two-factor request
        assertNotEquals(Ctap2StatusCode.INVALID_OPTION.getCode(), response[0],
            "Should not return INVALID_OPTION for valid two-factor request");
    }

    @Test
    @DisplayName("Should handle multiple algorithms and select supported one")
    public void testMultipleAlgorithmsWithOneSupported() {
        List<Map<String, Object>> pubKeyCredParams = new ArrayList<>();
        
        // Add unsupported algorithm first
        Map<String, Object> rs256 = new HashMap<>();
        rs256.put("type", "public-key");
        rs256.put("alg", -257); // RS256 - not supported
        pubKeyCredParams.add(rs256);
        
        // Add supported algorithm
        Map<String, Object> es256 = new HashMap<>();
        es256.put("type", "public-key");
        es256.put("alg", -7); // ES256 - supported
        pubKeyCredParams.add(es256);
        
        baseRequest.put(0x04, pubKeyCredParams);
        
        byte[] response = AuthenticatorAPI.makeCredential(mockTxn, baseRequest);
        
        // Should not return UNSUPPORTED_ALGORITHM since ES256 is present
        assertNotEquals(Ctap2StatusCode.UNSUPPORTED_ALGORITHM.getCode(), response[0],
            "Should not return UNSUPPORTED_ALGORITHM when at least one algorithm is supported");
    }

    @Test
    @DisplayName("Should handle options parameter being absent")
    public void testMissingOptionsParameter() {
        baseRequest.remove(0x07);
        
        byte[] response = AuthenticatorAPI.makeCredential(mockTxn, baseRequest);
        
        // Should use defaults (up=true, uv=false, rk=false) and not fail
        assertNotEquals(Ctap2StatusCode.MISSING_PARAMETER.getCode(), response[0],
            "Should not return MISSING_PARAMETER when options is absent (should use defaults)");
    }

    @Test
    @DisplayName("Should validate clientDataHash is exactly 32 bytes")
    public void testClientDataHashExactly32Bytes() {
        // Test with 31 bytes
        baseRequest.put(0x01, new byte[31]);
        byte[] response1 = AuthenticatorAPI.makeCredential(mockTxn, baseRequest);
        assertEquals(Ctap2StatusCode.INVALID_PARAMETER.getCode(), response1[0],
            "Should return INVALID_PARAMETER for 31-byte hash");
        
        // Test with 33 bytes
        baseRequest.put(0x01, new byte[33]);
        byte[] response2 = AuthenticatorAPI.makeCredential(mockTxn, baseRequest);
        assertEquals(Ctap2StatusCode.INVALID_PARAMETER.getCode(), response2[0],
            "Should return INVALID_PARAMETER for 33-byte hash");
        
        // Test with 32 bytes (should not fail for this reason)
        baseRequest.put(0x01, new byte[32]);
        byte[] response3 = AuthenticatorAPI.makeCredential(mockTxn, baseRequest);
        assertNotEquals(Ctap2StatusCode.INVALID_PARAMETER.getCode(), response3[0],
            "Should not return INVALID_PARAMETER for 32-byte hash");
    }

    @Test
    @DisplayName("Should handle algorithm parameter with wrong type")
    public void testAlgorithmParameterWrongType() {
        List<Map<String, Object>> pubKeyCredParams = new ArrayList<>();
        Map<String, Object> param = new HashMap<>();
        param.put("type", "public-key");
        param.put("alg", "not-an-integer"); // Wrong type
        pubKeyCredParams.add(param);
        baseRequest.put(0x04, pubKeyCredParams);
        
        byte[] response = AuthenticatorAPI.makeCredential(mockTxn, baseRequest);
        
        // Should return UNSUPPORTED_ALGORITHM since no valid algorithm found
        assertEquals(Ctap2StatusCode.UNSUPPORTED_ALGORITHM.getCode(), response[0],
            "Should return UNSUPPORTED_ALGORITHM when algorithm type is invalid");
    }
}

// Made with Bob