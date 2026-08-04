/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.isfs.blekey.authenticator.implapi.CredentialValidator;
import com.isfs.blekey.ctap.Ctap2StatusCode;
import com.isfs.blekey.data.Passkey;

/**
 * Tests for AuthenticatorAPI algorithm validation and credential type detection.
 * Focuses on isSupportedAlgorithm(), determineCredentialType(), and checkExcludeList() methods.
 *
 * Coverage areas:
 * - Algorithm validation with various COSE algorithm IDs
 * - Credential type determination based on rk/uv flags
 * - Exclude list validation with edge cases
 *
 * Tests private methods using reflection to match existing test patterns.
 */
@ExtendWith(MockitoExtension.class)
public class AuthenticatorAPIAlgorithmValidationTest {

    @Mock
    private Passkey mockPasskey;

    @BeforeEach
    public void setUp() throws Exception {
    }

    // ========================================================================
    // Algorithm Selection Tests - isSupportedAlgorithm()
    // Lines 481-493: Tests for algorithm validation with pubKeyCredParams list
    // ========================================================================

    /**
     * Test isSupportedAlgorithm() with ES256 (COSE alg -7) - the primary supported algorithm
     * Expected: true
     */
    @Test
    public void testIsSupportedAlgorithm_ES256() throws Exception {
        Method method = CredentialValidator.class.getDeclaredMethod(
            "isSupportedAlgorithm", List.class);
        method.setAccessible(true);
        
        List<Map<String, Object>> pubKeyCredParams = new ArrayList<>();
        Map<String, Object> param = new HashMap<>();
        param.put("alg", -7);  // ES256
        param.put("type", "public-key");
        pubKeyCredParams.add(param);
        
        Boolean result = (Boolean) method.invoke(null, pubKeyCredParams);
        assertTrue(result, "ES256 (-7) should be supported");
    }

    /**
     * Test isSupportedAlgorithm() with unsupported algorithm RS256 (COSE alg -257)
     * Expected: false (only ES256 is in SUPPORTED_ALGORITHM_SET)
     */
    @Test
    public void testIsSupportedAlgorithm_RS256_Unsupported() throws Exception {
        Method method = CredentialValidator.class.getDeclaredMethod(
            "isSupportedAlgorithm", List.class);
        method.setAccessible(true);
        
        List<Map<String, Object>> pubKeyCredParams = new ArrayList<>();
        Map<String, Object> param = new HashMap<>();
        param.put("alg", -257);  // RS256 - not supported
        param.put("type", "public-key");
        pubKeyCredParams.add(param);
        
        Boolean result = (Boolean) method.invoke(null, pubKeyCredParams);
        assertFalse(result, "RS256 (-257) should not be supported");
    }

    /**
     * Test isSupportedAlgorithm() with null list
     * Expected: false (line 482)
     */
    @Test
    public void testIsSupportedAlgorithm_NullList() throws Exception {
        Method method = CredentialValidator.class.getDeclaredMethod(
            "isSupportedAlgorithm", List.class);
        method.setAccessible(true);
        
        Boolean result = (Boolean) method.invoke(null, (List<?>) null);
        assertFalse(result, "Null list should return false");
    }

    /**
     * Test isSupportedAlgorithm() with empty list
     * Expected: false (line 482)
     */
    @Test
    public void testIsSupportedAlgorithm_EmptyList() throws Exception {
        Method method = CredentialValidator.class.getDeclaredMethod(
            "isSupportedAlgorithm", List.class);
        method.setAccessible(true);
        
        List<Map<String, Object>> pubKeyCredParams = new ArrayList<>();
        
        Boolean result = (Boolean) method.invoke(null, pubKeyCredParams);
        assertFalse(result, "Empty list should return false");
    }

    /**
     * Test isSupportedAlgorithm() with multiple algorithms including ES256
     * Expected: true (should find ES256 in the list)
     */
    @Test
    public void testIsSupportedAlgorithm_MultipleWithSupported() throws Exception {
        Method method = CredentialValidator.class.getDeclaredMethod(
            "isSupportedAlgorithm", List.class);
        method.setAccessible(true);
        
        List<Map<String, Object>> pubKeyCredParams = new ArrayList<>();
        
        // Add unsupported algorithm first
        Map<String, Object> param1 = new HashMap<>();
        param1.put("alg", -257);  // RS256 - not supported
        pubKeyCredParams.add(param1);
        
        // Add supported algorithm
        Map<String, Object> param2 = new HashMap<>();
        param2.put("alg", -7);  // ES256 - supported
        pubKeyCredParams.add(param2);
        
        Boolean result = (Boolean) method.invoke(null, pubKeyCredParams);
        assertTrue(result, "Should return true when ES256 is in the list");
    }

    /**
     * Test isSupportedAlgorithm() with parameter missing 'alg' key
     * Expected: false (line 486 - containsKey check)
     */
    @Test
    public void testIsSupportedAlgorithm_MissingAlgKey() throws Exception {
        Method method = CredentialValidator.class.getDeclaredMethod(
            "isSupportedAlgorithm", List.class);
        method.setAccessible(true);
        
        List<Map<String, Object>> pubKeyCredParams = new ArrayList<>();
        Map<String, Object> param = new HashMap<>();
        param.put("type", "public-key");  // No "alg" key
        pubKeyCredParams.add(param);
        
        Boolean result = (Boolean) method.invoke(null, pubKeyCredParams);
        assertFalse(result, "Should return false when alg key is missing");
    }

    /**
     * Test isSupportedAlgorithm() with all unsupported algorithms
     * Expected: false (line 492)
     */
    @Test
    public void testIsSupportedAlgorithm_AllUnsupported() throws Exception {
        Method method = CredentialValidator.class.getDeclaredMethod(
            "isSupportedAlgorithm", List.class);
        method.setAccessible(true);
        
        List<Map<String, Object>> pubKeyCredParams = new ArrayList<>();
        
        int[] unsupportedAlgs = {-257, -258, -259, -8, -37, 999};
        for (int alg : unsupportedAlgs) {
            Map<String, Object> param = new HashMap<>();
            param.put("alg", alg);
            pubKeyCredParams.add(param);
        }
        
        Boolean result = (Boolean) method.invoke(null, pubKeyCredParams);
        assertFalse(result, "Should return false when no supported algorithms present");
    }

    // ========================================================================
    // Credential Type Detection Tests - determineCredentialType()
    // Lines 535-550: Tests for credential type based on rk/uv flags
    // ========================================================================

    /**
     * Test determineCredentialType() with rk=true, uv=true (resident credential with UV)
     * Expected: CredentialType.RESIDENT (line 543)
     */
    @Test
    public void testDetermineCredentialType_ResidentWithUV() throws Exception {
        Method method = CredentialValidator.class.getDeclaredMethod(
            "determineCredentialType", boolean.class, boolean.class, Passkey.class);
        method.setAccessible(true);
        
        Object result = method.invoke(null, true, true, mockPasskey);
        
        assertNotNull(result);
        // Result is CredentialValidationResult, access type field directly
        Class<?> resultClass = result.getClass();
        java.lang.reflect.Field typeField = resultClass.getDeclaredField("type");
        typeField.setAccessible(true);
        Object credType = typeField.get(result);
        
        assertEquals("RESIDENT", credType.toString(),
                     "Should return RESIDENT for rk=true, uv=true");
    }

    /**
     * Test determineCredentialType() with rk=true, uv=false (resident without UV)
     * Expected: CredentialType.RESIDENT with warning (line 546)
     */
    @Test
    public void testDetermineCredentialType_ResidentWithoutUV() throws Exception {
        Method method = CredentialValidator.class.getDeclaredMethod(
            "determineCredentialType", boolean.class, boolean.class, Passkey.class);
        method.setAccessible(true);
        
        Object result = method.invoke(null, true, false, mockPasskey);
        
        assertNotNull(result);
        Class<?> resultClass = result.getClass();
        java.lang.reflect.Field typeField = resultClass.getDeclaredField("type");
        typeField.setAccessible(true);
        java.lang.reflect.Field errorField = resultClass.getDeclaredField("errorCode");
        errorField.setAccessible(true);
        Object credType = typeField.get(result);
        Object errorCode = errorField.get(result);
        assertEquals("NONE", credType.toString(),
                     "Should return NONE for rk=true, uv=false");
        assertEquals(errorCode, Ctap2StatusCode.PIN_REQUIRED, "Must request UV to request RK");
    }

    /**
     * Test determineCredentialType() with rk=false, uv=false (two-factor)
     * Expected: CredentialType.TWO_FACTOR (line 549)
     */
    @Test
    public void testDetermineCredentialType_TwoFactor() throws Exception {
        Method method = CredentialValidator.class.getDeclaredMethod(
            "determineCredentialType", boolean.class, boolean.class, Passkey.class);
        method.setAccessible(true);
        
        Object result = method.invoke(null, false, false, mockPasskey);
        
        assertNotNull(result);
        Class<?> resultClass = result.getClass();
        java.lang.reflect.Field typeField = resultClass.getDeclaredField("type");
        typeField.setAccessible(true);
        Object credType = typeField.get(result);
        
        assertEquals("TWO_FACTOR", credType.toString(),
                     "Should return TWO_FACTOR for rk=false");
    }

    /**
     * Test determineCredentialType() with rk=false, uv=true (two-factor with UV)
     * Expected: CredentialType.TWO_FACTOR (line 549)
     */
    @Test
    public void testDetermineCredentialType_TwoFactorWithUV() throws Exception {
        Method method = CredentialValidator.class.getDeclaredMethod(
            "determineCredentialType", boolean.class, boolean.class, Passkey.class);
        method.setAccessible(true);
        
        Object result = method.invoke(null, false, true, mockPasskey);
        
        assertNotNull(result);
        Class<?> resultClass = result.getClass();
        java.lang.reflect.Field typeField = resultClass.getDeclaredField("type");
        typeField.setAccessible(true);
        Object credType = typeField.get(result);
        
        assertEquals("PASSKEY", credType.toString(),
                     "Should return PASSKEY for rk=false, uv=true");
    }

    // ========================================================================
    // Exclude List Validation Tests - checkExcludeList()
    // Lines 450-465: Tests for credential exclusion checking
    // ========================================================================

    /**
     * Test checkExcludeList() with null exclude list
     * Expected: null (no error, line 453-454)
     */
    @Test
    public void testCheckExcludeList_NullList() throws Exception {
        Method method = CredentialValidator.class.getDeclaredMethod(
            "checkExcludeList", List.class, Passkey.class);
        method.setAccessible(true);
        
        Ctap2StatusCode result = (Ctap2StatusCode) method.invoke(null, null, mockPasskey);
        assertNull(result, "Should return null for null exclude list");
    }

    /**
     * Test checkExcludeList() with empty exclude list
     * Expected: null (no error, line 453-454)
     */
    @Test
    public void testCheckExcludeList_EmptyList() throws Exception {
        Method method = CredentialValidator.class.getDeclaredMethod(
            "checkExcludeList", List.class, Passkey.class);
        method.setAccessible(true);
        
        List<Map<String, Object>> excludeList = new ArrayList<>();
        
        Ctap2StatusCode result = (Ctap2StatusCode) method.invoke(null, excludeList, mockPasskey);
        assertNull(result, "Should return null for empty exclude list");
    }

    /**
     * Test checkExcludeList() with credential having null ID
     * Expected: null (no error, line 458-459 null check)
     */
    @Test
    public void testCheckExcludeList_NullCredentialId() throws Exception {
        Method method = CredentialValidator.class.getDeclaredMethod(
            "checkExcludeList", List.class, Passkey.class);
        method.setAccessible(true);
        
        List<Map<String, Object>> excludeList = new ArrayList<>();
        Map<String, Object> credential = new HashMap<>();
        credential.put("id", null);
        excludeList.add(credential);
        
        Ctap2StatusCode result = (Ctap2StatusCode) method.invoke(null, excludeList, mockPasskey);
        assertNull(result, "Should return null when credential ID is null");
    }

    /**
     * Test checkExcludeList() with credential missing ID key
     * Expected: null (no error, line 458 - get returns null)
     */
    @Test
    public void testCheckExcludeList_MissingIdKey() throws Exception {
        Method method = CredentialValidator.class.getDeclaredMethod(
            "checkExcludeList", List.class, Passkey.class);
        method.setAccessible(true);
        
        List<Map<String, Object>> excludeList = new ArrayList<>();
        Map<String, Object> credential = new HashMap<>();
        credential.put("type", "public-key");  // No "id" key
        excludeList.add(credential);
        
        Ctap2StatusCode result = (Ctap2StatusCode) method.invoke(null, excludeList, mockPasskey);
        assertNull(result, "Should return null when credential ID key is missing");
    }

    /**
     * Test checkExcludeList() with multiple credentials, none excluded
     * Expected: null (no error, completes loop without finding match)
     */
    @Test
    public void testCheckExcludeList_MultipleNonExcluded() throws Exception {
        Method method = CredentialValidator.class.getDeclaredMethod(
            "checkExcludeList", List.class, Passkey.class);
        method.setAccessible(true);
        
        List<Map<String, Object>> excludeList = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            Map<String, Object> credential = new HashMap<>();
            credential.put("id", new byte[]{(byte)i, (byte)(i+1), (byte)(i+2)});
            excludeList.add(credential);
        }
        
        Ctap2StatusCode result = (Ctap2StatusCode) method.invoke(null, excludeList, mockPasskey);
        assertNull(result, "Should return null when no credentials are excluded");
    }
}

// Made with Bob
