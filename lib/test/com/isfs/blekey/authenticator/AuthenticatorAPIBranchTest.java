/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import com.isfs.blekey.ctap.Ctap2StatusCode;

/**
 * Branch coverage tests for AuthenticatorAPI.
 * Targets high-impact branches identified in Phase 2 of coverage improvement plan.
 * 
 * Focus areas (from CODE_COVERAGE_IMPROVE_PLAN.md lines 126-152):
 * - validatePinUvAuthProtocol() with unsupported protocol versions (lines 218, 219)
 * - isSupportedAlgorithm() with edge cases (lines 485, 486, 487)
 * - determineCredentialType() with rk/uv combinations (lines 536, 541, 542)
 * - PinAuthException and AuthenticationContext inner classes (lines 348-351, 378-381)
 */
@ExtendWith(MockitoExtension.class)
public class AuthenticatorAPIBranchTest {

    @BeforeEach
    public void setUp() throws Exception {
    }

    // ========== High-Impact Branch Tests for validatePinUvAuthProtocol() ==========

    /**
     * Test validatePinUvAuthProtocol() with null protocol (line 214-216)
     */
    @Test
    public void testValidatePinUvAuthProtocolWithNull() throws Exception {
        java.lang.reflect.Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "validatePinUvAuthProtocol", Integer.class);
        method.setAccessible(true);
        
        Ctap2StatusCode result = (Ctap2StatusCode) method.invoke(null, (Integer) null);
        
        assertEquals(Ctap2StatusCode.PIN_AUTH_INVALID, result);
    }

    /**
     * Test validatePinUvAuthProtocol() with unsupported protocol version (lines 218-220)
     */
    @Test
    public void testValidatePinUvAuthProtocolWithUnsupportedVersion() throws Exception {
        java.lang.reflect.Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "validatePinUvAuthProtocol", Integer.class);
        method.setAccessible(true);
        
        // Test with protocol version 2 (unsupported)
        Ctap2StatusCode result = (Ctap2StatusCode) method.invoke(null, 2);
        
        assertEquals(Ctap2StatusCode.PIN_AUTH_INVALID, result);
    }

    /**
     * Test validatePinUvAuthProtocol() with supported protocol version
     */
    @Test
    public void testValidatePinUvAuthProtocolWithSupportedVersion() throws Exception {
        java.lang.reflect.Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "validatePinUvAuthProtocol", Integer.class);
        method.setAccessible(true);
        
        // Test with protocol version 1 (supported)
        Ctap2StatusCode result = (Ctap2StatusCode) method.invoke(null, 1);
        
        assertNull(result, "Should return null for supported protocol version");
    }


    // ========== Tests for errorResult() Methods ==========

    /**
     * Test errorResult() with message and code (line 173-176)
     */
    @Test
    public void testErrorResultWithMessageAndCode() throws Exception {
        java.lang.reflect.Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "errorResult", String.class, Ctap2StatusCode.class);
        method.setAccessible(true);
        
        Object result = method.invoke(null, "Test error", Ctap2StatusCode.PIN_AUTH_INVALID);
        
        assertNotNull(result);
        // Verify it's a PinUvAuthResult
        assertTrue(result.getClass().getSimpleName().contains("PinUvAuthResult"));
    }

    /**
     * Test errorResult() with message, code, and exception (line 186-189)
     */
    @Test
    public void testErrorResultWithException() throws Exception {
        java.lang.reflect.Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "errorResult", String.class, Ctap2StatusCode.class, Exception.class);
        method.setAccessible(true);
        
        Exception testException = new Exception("Test exception");
        Object result = method.invoke(null, "Test error", Ctap2StatusCode.PIN_AUTH_INVALID, testException);
        
        assertNotNull(result);
        assertTrue(result.getClass().getSimpleName().contains("PinUvAuthResult"));
    }

    /**
     * Test errorResult() with different error codes
     */
    @Test
    public void testErrorResultWithDifferentCodes() throws Exception {
        java.lang.reflect.Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "errorResult", String.class, Ctap2StatusCode.class);
        method.setAccessible(true);
        
        Ctap2StatusCode[] codes = {
            Ctap2StatusCode.PIN_AUTH_INVALID,
            Ctap2StatusCode.PIN_REQUIRED,
            Ctap2StatusCode.PIN_INVALID,
            Ctap2StatusCode.PIN_BLOCKED
        };
        
        for (Ctap2StatusCode code : codes) {
            Object result = method.invoke(null, "Test error", code);
            assertNotNull(result);
        }
    }

    // ========== Tests for PinAuthException Inner Class ==========

    /**
     * Test PinAuthException constructor and fields (lines 348-351)
     */
    @Test
    public void testPinAuthExceptionConstructor() throws Exception {
        String message = "Test PIN auth error";
        Ctap2StatusCode code = Ctap2StatusCode.PIN_AUTH_INVALID;
        
        // Access the inner class
        Class<?> exceptionClass = Class.forName("com.isfs.blekey.authenticator.AuthenticatorAPI$PinAuthException");
        java.lang.reflect.Constructor<?> constructor = exceptionClass.getDeclaredConstructor(String.class, Ctap2StatusCode.class);
        constructor.setAccessible(true);
        
        Object exception = constructor.newInstance(message, code);
        
        assertNotNull(exception);
        assertTrue(exception instanceof Exception);
        assertEquals(message, ((Exception) exception).getMessage());
        
        // Verify code field
        java.lang.reflect.Field codeField = exceptionClass.getDeclaredField("code");
        codeField.setAccessible(true);
        assertEquals(code, codeField.get(exception));
    }

    /**
     * Test PinAuthException with different status codes
     */
    @Test
    public void testPinAuthExceptionWithDifferentCodes() throws Exception {
        Class<?> exceptionClass = Class.forName("com.isfs.blekey.authenticator.AuthenticatorAPI$PinAuthException");
        java.lang.reflect.Constructor<?> constructor = exceptionClass.getDeclaredConstructor(String.class, Ctap2StatusCode.class);
        constructor.setAccessible(true);
        
        Ctap2StatusCode[] codes = {
            Ctap2StatusCode.PIN_AUTH_INVALID,
            Ctap2StatusCode.PIN_REQUIRED,
            Ctap2StatusCode.PIN_INVALID,
            Ctap2StatusCode.PIN_BLOCKED
        };
        
        for (Ctap2StatusCode code : codes) {
            Object exception = constructor.newInstance("Test", code);
            
            java.lang.reflect.Field codeField = exceptionClass.getDeclaredField("code");
            codeField.setAccessible(true);
            assertEquals(code, codeField.get(exception));
        }
    }


}
