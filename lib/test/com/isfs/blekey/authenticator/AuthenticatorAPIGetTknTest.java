/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator;

import static org.junit.Assert.*;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import com.isfs.blekey.ctap.Ctap2StatusCode;
import com.isfs.blekey.ctap.CtapTxn;

/**
 * Tests targeting missed branches in getTkn() and related methods.
 * Based on JaCoCo coverage report showing getTkn with 30% instruction, 35% branch coverage.
 * 
 * Key branches to cover:
 * - Line 1425: pinHashEnc == null check
 * - Line 1426: platKeyPair == null check  
 * - Line 1429: req.get(KEY_PIN_HASH_ENC) == null check
 * - Line 1437: clientKey == null check
 * - Line 1443: sharedSecret == null check
 * - Line 1453: pkeyFile == null check
 * - Line 1454: pinRetries == 0 check
 * - Exception handling branches (lines 1472-1481)
 */
public class AuthenticatorAPIGetTknTest {

    @Mock
    private CtapTxn mockTxn;
    
    private static final int KEY_PIN_HASH_ENC = 0x06;
    private static final int KEY_PLATFORM_KEY_AGREEMENT = 0x03;
    
    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
    }
    
    /**
     * Test getTkn() with null pinHashEnc and null platKeyPair.
     * Covers line 1426-1428: platKeyPair == null branch
     */
    @Test
    public void testGetTkn_NullPlatKeyPair() throws Exception {
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "getTkn", CtapTxn.class, Map.class);
        method.setAccessible(true);
        
        Map<Integer, Object> req = new HashMap<>();
        req.put(KEY_PIN_HASH_ENC, new byte[16]);
        
        // Set platKeyPair to null via reflection
        java.lang.reflect.Field field = AuthenticatorAPI.class.getDeclaredField("platKeyPair");
        field.setAccessible(true);
        Object originalValue = field.get(null);
        field.set(null, null);
        
        try {
            byte[] result = (byte[]) method.invoke(null, mockTxn, req);
            
            assertNotNull("Should return error response", result);
            assertEquals("Should return OTHER error", Ctap2StatusCode.OTHER.getCode(), result[0] & 0xFF);
        } finally {
            // Restore original value
            field.set(null, originalValue);
        }
    }
    
    /**
     * Test getTkn() with missing KEY_PIN_HASH_ENC parameter.
     * Covers line 1429-1431: req.get(KEY_PIN_HASH_ENC) == null branch
     */
    @Test
    public void testGetTkn_MissingPinHashEnc() throws Exception {
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "getTkn", CtapTxn.class, Map.class);
        method.setAccessible(true);
        
        Map<Integer, Object> req = new HashMap<>();
        // Missing KEY_PIN_HASH_ENC
        req.put(KEY_PLATFORM_KEY_AGREEMENT, new HashMap<>());
        
        byte[] result = (byte[]) method.invoke(null, mockTxn, req);
        
        assertNotNull("Should return error response", result);
        assertEquals("Should return MISSING_PARAMETER error", 
            Ctap2StatusCode.MISSING_PARAMETER.getCode(), result[0] & 0xFF);
    }
    
    /**
     * Test getTkn() with invalid pinHashEnc (wrong type).
     * Covers line 1432: return error(INVALID_PARAMETER) branch
     */
    @Test
    public void testGetTkn_InvalidPinHashEncType() throws Exception {
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "getTkn", CtapTxn.class, Map.class);
        method.setAccessible(true);
        
        Map<Integer, Object> req = new HashMap<>();
        req.put(KEY_PIN_HASH_ENC, "not-a-byte-array"); // Wrong type
        req.put(KEY_PLATFORM_KEY_AGREEMENT, new HashMap<>());
        
        byte[] result = (byte[]) method.invoke(null, mockTxn, req);
        
        assertNotNull("Should return error response", result);
        assertEquals("Should return INVALID_PARAMETER error", 
            Ctap2StatusCode.INVALID_PARAMETER.getCode(), result[0] & 0xFF);
    }
    
    /**
     * Test getTkn() with null client key.
     * Covers line 1437-1439: clientKey == null branch
     */
    @Test
    public void testGetTkn_NullClientKey() throws Exception {
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "getTkn", CtapTxn.class, Map.class);
        method.setAccessible(true);
        
        Map<Integer, Object> req = new HashMap<>();
        req.put(KEY_PIN_HASH_ENC, new byte[16]);
        // Missing or invalid KEY_PLATFORM_KEY_AGREEMENT will result in null clientKey
        
        byte[] result = (byte[]) method.invoke(null, mockTxn, req);
        
        assertNotNull("Should return error response", result);
        // Will hit clientKey == null check
    }
    
    /**
     * Test validateAndExtractPinHash() with null request.
     * Covers null check branch - method throws NullPointerException.
     */
    @Test(expected = java.lang.reflect.InvocationTargetException.class)
    public void testValidateAndExtractPinHash_NullRequest() throws Exception {
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "validateAndExtractPinHash", Map.class);
        method.setAccessible(true);
        
        method.invoke(null, (Map<Integer, Object>) null);
    }
    
    /**
     * Test validateAndExtractPinHash() with missing parameter.
     * Covers missing parameter branch.
     */
    @Test
    public void testValidateAndExtractPinHash_MissingParameter() throws Exception {
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "validateAndExtractPinHash", Map.class);
        method.setAccessible(true);
        
        Map<Integer, Object> req = new HashMap<>();
        // Missing KEY_PIN_HASH_ENC
        
        Object result = method.invoke(null, req);
        
        assertNotNull("Should return PinHashValidationResult", result);
        // Use reflection to check isValid() method
        Method isValidMethod = result.getClass().getDeclaredMethod("isValid");
        isValidMethod.setAccessible(true);
        boolean isValid = (boolean) isValidMethod.invoke(result);
        assertFalse("Should return invalid result for missing parameter", isValid);
    }
    
    /**
     * Test validateAndExtractPinHash() with wrong type.
     * Covers type validation branch.
     */
    @Test
    public void testValidateAndExtractPinHash_WrongType() throws Exception {
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "validateAndExtractPinHash", Map.class);
        method.setAccessible(true);
        
        Map<Integer, Object> req = new HashMap<>();
        req.put(KEY_PIN_HASH_ENC, "not-a-byte-array");
        
        Object result = method.invoke(null, req);
        
        assertNotNull("Should return PinHashValidationResult", result);
        // Use reflection to check isValid() method
        Method isValidMethod = result.getClass().getDeclaredMethod("isValid");
        isValidMethod.setAccessible(true);
        boolean isValid = (boolean) isValidMethod.invoke(result);
        assertFalse("Should return invalid result for wrong type", isValid);
    }
    
    /**
     * Test extractClientPublicKey() with null request.
     * Covers null check branch - method throws NullPointerException.
     */
    @Test(expected = java.lang.reflect.InvocationTargetException.class)
    public void testExtractClientPublicKey_NullRequest() throws Exception {
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "extractClientPublicKey", Map.class);
        method.setAccessible(true);
        
        method.invoke(null, (Map<Integer, Object>) null);
    }
    
    /**
     * Test extractClientPublicKey() with missing key agreement.
     * Covers missing parameter branch.
     */
    @Test
    public void testExtractClientPublicKey_MissingKeyAgreement() throws Exception {
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "extractClientPublicKey", Map.class);
        method.setAccessible(true);
        
        Map<Integer, Object> req = new HashMap<>();
        // Missing KEY_PLATFORM_KEY_AGREEMENT
        
        Object result = method.invoke(null, req);
        
        assertNull("Should return null for missing key agreement", result);
    }
    
    /**
     * Test extractClientPublicKey() with invalid key agreement type.
     * Covers type validation branch - method throws ClassCastException.
     */
    @Test(expected = java.lang.reflect.InvocationTargetException.class)
    public void testExtractClientPublicKey_InvalidType() throws Exception {
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "extractClientPublicKey", Map.class);
        method.setAccessible(true);
        
        Map<Integer, Object> req = new HashMap<>();
        req.put(KEY_PLATFORM_KEY_AGREEMENT, "not-a-map");
        
        method.invoke(null, req);
    }
    
    /**
     * Test performEcdhKeyAgreement() with null client key.
     * Covers null check branch - method throws IllegalArgumentException.
     */
    @Test(expected = java.lang.reflect.InvocationTargetException.class)
    public void testPerformEcdhKeyAgreement_NullClientKey() throws Exception {
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "performEcdhKeyAgreement", java.security.PublicKey.class);
        method.setAccessible(true);
        
        method.invoke(null, (java.security.PublicKey) null);
    }

}

// Made with Bob
