/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator;

import static org.junit.Assert.*;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import com.isfs.blekey.ctap.Ctap2StatusCode;

/**
 * Tests for AuthenticatorAPI validation methods including algorithm support,
 * credential type determination, protocol validation, and error handling.
 *
 * Covers:
 * - isSupportedAlgorithm() - Algorithm validation with various edge cases
 * - determineCredentialType() - Credential type logic for different rk/uv combinations
 * - validatePinUvAuthProtocol() - PIN/UV protocol version validation
 * - errorResult() - Error response generation with various inputs
 */
public class AuthenticatorAPIValidationTest {

    /**
     * Test isSupportedAlgorithm() with multiple algorithms including unsupported ones.
     * Covers branch where algorithm is not in SUPPORTED_ALGORITHM_SET.
     */
    @Test
    public void testIsSupportedAlgorithm_MixedAlgorithms() throws Exception {
        Method method = AuthenticatorAPI.class.getDeclaredMethod("isSupportedAlgorithm", List.class);
        method.setAccessible(true);
        
        List<Map<String, Object>> params = new ArrayList<>();
        
        // Add unsupported algorithm first
        Map<String, Object> param1 = new HashMap<>();
        param1.put("alg", -257); // RS256 - unsupported
        param1.put("type", "public-key");
        params.add(param1);
        
        // Add supported algorithm
        Map<String, Object> param2 = new HashMap<>();
        param2.put("alg", -7); // ES256 - supported
        param2.put("type", "public-key");
        params.add(param2);
        
        Boolean result = (Boolean) method.invoke(null, params);
        
        assertTrue("Should return true when at least one supported algorithm exists", result);
    }
    
    /**
     * Test isSupportedAlgorithm() with only unsupported algorithms.
     * Covers the false return branch.
     */
    @Test
    public void testIsSupportedAlgorithm_OnlyUnsupported() throws Exception {
        Method method = AuthenticatorAPI.class.getDeclaredMethod("isSupportedAlgorithm", List.class);
        method.setAccessible(true);
        
        List<Map<String, Object>> params = new ArrayList<>();
        
        Map<String, Object> param1 = new HashMap<>();
        param1.put("alg", -257); // RS256
        param1.put("type", "public-key");
        params.add(param1);
        
        Map<String, Object> param2 = new HashMap<>();
        param2.put("alg", -258); // RS384
        param2.put("type", "public-key");
        params.add(param2);
        
        Boolean result = (Boolean) method.invoke(null, params);
        
        assertFalse("Should return false when no supported algorithms exist", result);
    }
    
    /**
     * Test isSupportedAlgorithm() with parameter missing 'alg' field.
     * Covers branch where param.get("alg") returns null.
     */
    @Test
    public void testIsSupportedAlgorithm_MissingAlgField() throws Exception {
        Method method = AuthenticatorAPI.class.getDeclaredMethod("isSupportedAlgorithm", List.class);
        method.setAccessible(true);
        
        List<Map<String, Object>> params = new ArrayList<>();
        
        Map<String, Object> param = new HashMap<>();
        param.put("type", "public-key");
        // Missing "alg" field
        params.add(param);
        
        Boolean result = (Boolean) method.invoke(null, params);
        
        assertFalse("Should return false when alg field is missing", result);
    }
    
    /**
     * Test isSupportedAlgorithm() with non-integer alg value.
     * Covers branch where alg is not an Integer.
     */
    @Test
    public void testIsSupportedAlgorithm_NonIntegerAlg() throws Exception {
        Method method = AuthenticatorAPI.class.getDeclaredMethod("isSupportedAlgorithm", List.class);
        method.setAccessible(true);
        
        List<Map<String, Object>> params = new ArrayList<>();
        
        Map<String, Object> param = new HashMap<>();
        param.put("alg", "not-an-integer");
        param.put("type", "public-key");
        params.add(param);
        
        Boolean result = (Boolean) method.invoke(null, params);
        
        assertFalse("Should return false when alg is not an integer", result);
    }
    
    /**
     * Test determineCredentialType() with rk=false, uv=false.
     * Covers the TWO_FACTOR credential branch.
     */
    @Test
    public void testDetermineCredentialType_TwoFactor() throws Exception {
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "determineCredentialType", boolean.class, boolean.class,
            com.isfs.blekey.data.Passkey.class);
        method.setAccessible(true);
        
        Object result = method.invoke(null, false, false, null);
        
        assertNotNull("Should return a result", result);
    }
    
    /**
     * Test determineCredentialType() with rk=true, uv=false.
     * Covers the RESIDENT credential branch.
     */
    @Test
    public void testDetermineCredentialType_Resident() throws Exception {
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "determineCredentialType", boolean.class, boolean.class,
            com.isfs.blekey.data.Passkey.class);
        method.setAccessible(true);
        
        Object result = method.invoke(null, true, false, null);
        
        assertNotNull("Should return a result", result);
    }
    
    /**
     * Test determineCredentialType() with rk=true, uv=true.
     * Covers the user verification branch.
     */
    @Test
    public void testDetermineCredentialType_UserVerified() throws Exception {
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "determineCredentialType", boolean.class, boolean.class,
            com.isfs.blekey.data.Passkey.class);
        method.setAccessible(true);
        
        Object result = method.invoke(null, true, true, null);
        
        assertNotNull("Should return a result", result);
    }
    
    /**
     * Test determineCredentialType() with rk=false, uv=true.
     * Covers the UV without RK branch.
     */
    @Test
    public void testDetermineCredentialType_UvWithoutRk() throws Exception {
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "determineCredentialType", boolean.class, boolean.class,
            com.isfs.blekey.data.Passkey.class);
        method.setAccessible(true);
        
        Object result = method.invoke(null, false, true, null);
        
        assertNotNull("Should return a result", result);
    }
    
    /**
     * Test validatePinUvAuthProtocol() with protocol version 0.
     * Covers the unsupported protocol branch.
     */
    @Test
    public void testValidatePinUvAuthProtocol_Version0() throws Exception {
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "validatePinUvAuthProtocol", Integer.class);
        method.setAccessible(true);
        
        Ctap2StatusCode result = (Ctap2StatusCode) method.invoke(null, 0);
        
        assertEquals("Protocol version 0 should be invalid", 
            Ctap2StatusCode.PIN_AUTH_INVALID, result);
    }
    
    /**
     * Test validatePinUvAuthProtocol() with protocol version 3.
     * Covers the unsupported protocol branch.
     */
    @Test
    public void testValidatePinUvAuthProtocol_Version3() throws Exception {
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "validatePinUvAuthProtocol", Integer.class);
        method.setAccessible(true);
        
        Ctap2StatusCode result = (Ctap2StatusCode) method.invoke(null, 3);
        
        assertEquals("Protocol version 3 should be invalid", 
            Ctap2StatusCode.PIN_AUTH_INVALID, result);
    }
    
    /**
     * Test validatePinUvAuthProtocol() with negative protocol version.
     * Covers the invalid protocol branch.
     */
    @Test
    public void testValidatePinUvAuthProtocol_NegativeVersion() throws Exception {
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "validatePinUvAuthProtocol", Integer.class);
        method.setAccessible(true);
        
        Ctap2StatusCode result = (Ctap2StatusCode) method.invoke(null, -1);
        
        assertEquals("Negative protocol version should be invalid", 
            Ctap2StatusCode.PIN_AUTH_INVALID, result);
    }
    
    /**
     * Test errorResult() with null message.
     * Covers the null message branch.
     */
    @Test
    public void testErrorResult_NullMessage() throws Exception {
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "errorResult", String.class, Ctap2StatusCode.class);
        method.setAccessible(true);
        
        Object result = method.invoke(null, null, Ctap2StatusCode.PIN_AUTH_INVALID);
        
        assertNotNull("Should return result even with null message", result);
    }
    
    /**
     * Test errorResult() with empty message.
     * Covers the empty string branch.
     */
    @Test
    public void testErrorResult_EmptyMessage() throws Exception {
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "errorResult", String.class, Ctap2StatusCode.class);
        method.setAccessible(true);
        
        Object result = method.invoke(null, "", Ctap2StatusCode.PIN_AUTH_INVALID);
        
        assertNotNull("Should return result with empty message", result);
    }
    
    /**
     * Test errorResult() with exception parameter and null message.
     * Covers the exception handling branch with null message.
     */
    @Test
    public void testErrorResult_WithExceptionNullMessage() throws Exception {
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "errorResult", String.class, Ctap2StatusCode.class, Exception.class);
        method.setAccessible(true);
        
        Exception testException = new RuntimeException("Test exception");
        Object result = method.invoke(null, null, Ctap2StatusCode.PIN_AUTH_INVALID, testException);
        
        assertNotNull("Should return result with exception and null message", result);
    }
    
    /**
     * Test errorResult() with exception parameter and non-null message.
     * Covers the exception handling branch with message.
     */
    @Test
    public void testErrorResult_WithExceptionAndMessage() throws Exception {
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "errorResult", String.class, Ctap2StatusCode.class, Exception.class);
        method.setAccessible(true);
        
        Exception testException = new RuntimeException("Test exception");
        Object result = method.invoke(null, "Error occurred", Ctap2StatusCode.PIN_AUTH_INVALID, testException);
        
        assertNotNull("Should return result with exception and message", result);
    }
    
    /**
     * Test errorResult() with null exception.
     * Covers the null exception branch.
     */
    @Test
    public void testErrorResult_NullException() throws Exception {
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "errorResult", String.class, Ctap2StatusCode.class, Exception.class);
        method.setAccessible(true);
        
        Object result = method.invoke(null, "Error message", Ctap2StatusCode.PIN_AUTH_INVALID, null);
        
        assertNotNull("Should return result with null exception", result);
    }
}

// Made with Bob
