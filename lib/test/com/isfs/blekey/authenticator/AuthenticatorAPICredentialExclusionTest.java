/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.isfs.blekey.ctap.Ctap2StatusCode;
import com.isfs.blekey.data.Passkey;

/**
 * Tests for AuthenticatorAPI credential exclusion and user verification validation.
 * Focuses on previously untested branches in credential validation logic.
 *
 * Coverage areas:
 * - determineCredentialType() with UV unavailable error path
 * - checkExcludeList() with actual excluded credentials
 * - validateUserPresence() validation logic
 * - isCredentialExcluded() helper method with all edge cases
 *
 * These tests target critical error paths and validation logic that were
 * identified as high-priority coverage gaps in the coverage improvement plan.
 */
@ExtendWith(MockitoExtension.class)
public class AuthenticatorAPICredentialExclusionTest {

    @Mock
    private Passkey mockPasskey;

    private KeyPair originalPlatKeyPair;

    @BeforeEach
    public void setUp() throws Exception {
        // Save original platKeyPair for restoration
        Field platKeyPairField = AuthenticatorAPI.class.getDeclaredField("platKeyPair");
        platKeyPairField.setAccessible(true);
        originalPlatKeyPair = (KeyPair) platKeyPairField.get(null);
    }

    @AfterEach
    public void tearDown() throws Exception {
        // Restore original platKeyPair
        Field platKeyPairField = AuthenticatorAPI.class.getDeclaredField("platKeyPair");
        platKeyPairField.setAccessible(true);
        platKeyPairField.set(null, originalPlatKeyPair);
    }

    // ========================================================================
    // determineCredentialType() - Missing UV Unavailable Branch
    // Line 536-538: Test when UV is requested but not available
    // ========================================================================

    /**
     * Test determineCredentialType() when UV is requested but not available.
     * This tests the critical branch at line 536-538 that returns UNSUPPORTED_OPTION.
     * 
     * QUICK WIN: This branch is currently untested and represents a key error path.
     */
    @Test
    public void testDetermineCredentialType_UVRequestedButUnavailable() throws Exception {
        // Set platKeyPair to null to make UV unavailable
        Field platKeyPairField = AuthenticatorAPI.class.getDeclaredField("platKeyPair");
        platKeyPairField.setAccessible(true);
        platKeyPairField.set(null, null);

        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "determineCredentialType", boolean.class, boolean.class, Passkey.class);
        method.setAccessible(true);
        
        // Request UV when it's not available
        Object result = method.invoke(null, false, true, mockPasskey);
        
        assertNotNull(result);
        Class<?> resultClass = result.getClass();
        
        // Verify error code is UNSUPPORTED_OPTION
        Field errorField = resultClass.getDeclaredField("errorCode");
        errorField.setAccessible(true);
        Ctap2StatusCode error = (Ctap2StatusCode) errorField.get(result);
        
        assertEquals(Ctap2StatusCode.UNSUPPORTED_OPTION, error,
                     "Should return UNSUPPORTED_OPTION when UV requested but unavailable");
        
        // Verify type is NONE
        Field typeField = resultClass.getDeclaredField("type");
        typeField.setAccessible(true);
        Object credType = typeField.get(result);
        
        assertEquals("NONE", credType.toString(),
                     "Should return NONE credential type when UV unavailable");
    }

    /**
     * Test determineCredentialType() when UV is requested with resident key but UV unavailable.
     * Tests line 536 branch with rk=true, uv=true, but UV not available.
     */
    @Test
    public void testDetermineCredentialType_ResidentUVRequestedButUnavailable() throws Exception {
        // Set platKeyPair to null to make UV unavailable
        Field platKeyPairField = AuthenticatorAPI.class.getDeclaredField("platKeyPair");
        platKeyPairField.setAccessible(true);
        platKeyPairField.set(null, null);

        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "determineCredentialType", boolean.class, boolean.class, Passkey.class);
        method.setAccessible(true);
        
        // Request resident credential with UV when UV is not available
        Object result = method.invoke(null, true, true, mockPasskey);
        
        assertNotNull(result);
        Class<?> resultClass = result.getClass();
        
        Field errorField = resultClass.getDeclaredField("errorCode");
        errorField.setAccessible(true);
        Ctap2StatusCode error = (Ctap2StatusCode) errorField.get(result);
        
        assertEquals(Ctap2StatusCode.UNSUPPORTED_OPTION, error,
                     "Should return UNSUPPORTED_OPTION for resident+UV when UV unavailable");
    }

    // ========================================================================
    // checkExcludeList() - Missing Excluded Credential Branch
    // Line 459-462: Test when credential is actually in exclude list
    // ========================================================================

    /**
     * Test checkExcludeList() when a credential IS in the exclude list.
     * This tests the critical branch at line 459-462 that returns CREDENTIAL_EXCLUDED.
     * 
     * QUICK WIN: This is the main success path for exclude list validation.
     */
    @Test
    public void testCheckExcludeList_CredentialExcluded() throws Exception {
        byte[] excludedCredId = new byte[]{1, 2, 3, 4, 5};
        
        // Mock passkey with resident credentials
        List<Map<String, byte[]>> resCreds = new ArrayList<>();
        Map<String, byte[]> cred = new HashMap<>();
        cred.put("cred.id", excludedCredId);
        resCreds.add(cred);
        
        when(mockPasskey.getResCreds()).thenReturn(resCreds);
        
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "checkExcludeList", List.class, Passkey.class);
        method.setAccessible(true);
        
        List<Map<String, Object>> excludeList = new ArrayList<>();
        Map<String, Object> excludedCred = new HashMap<>();
        excludedCred.put("id", excludedCredId);
        excludeList.add(excludedCred);
        
        Ctap2StatusCode result = (Ctap2StatusCode) method.invoke(null, excludeList, mockPasskey);
        
        assertEquals(Ctap2StatusCode.CREDENTIAL_EXCLUDED, result,
                     "Should return CREDENTIAL_EXCLUDED when credential is in exclude list");
    }

    /**
     * Test checkExcludeList() with multiple credentials, one excluded.
     * Tests that the method correctly identifies an excluded credential among many.
     */
    @Test
    public void testCheckExcludeList_MultipleCredentialsOneExcluded() throws Exception {
        byte[] excludedCredId = new byte[]{5, 6, 7, 8};
        byte[] otherCredId1 = new byte[]{1, 2, 3, 4};
        byte[] otherCredId2 = new byte[]{9, 10, 11, 12};
        
        // Mock passkey with multiple resident credentials
        List<Map<String, byte[]>> resCreds = new ArrayList<>();
        Map<String, byte[]> cred1 = new HashMap<>();
        cred1.put("cred.id", otherCredId1);
        Map<String, byte[]> cred2 = new HashMap<>();
        cred2.put("cred.id", excludedCredId);  // This one matches
        Map<String, byte[]> cred3 = new HashMap<>();
        cred3.put("cred.id", otherCredId2);
        resCreds.add(cred1);
        resCreds.add(cred2);
        resCreds.add(cred3);
        
        when(mockPasskey.getResCreds()).thenReturn(resCreds);
        
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "checkExcludeList", List.class, Passkey.class);
        method.setAccessible(true);
        
        List<Map<String, Object>> excludeList = new ArrayList<>();
        Map<String, Object> excludedCred = new HashMap<>();
        excludedCred.put("id", excludedCredId);
        excludeList.add(excludedCred);
        
        Ctap2StatusCode result = (Ctap2StatusCode) method.invoke(null, excludeList, mockPasskey);
        
        assertEquals(Ctap2StatusCode.CREDENTIAL_EXCLUDED, result,
                     "Should find excluded credential among multiple resident credentials");
    }

    // ========================================================================
    // validateUserPresence() - Completely Untested Method
    // Line 473-478: Test user presence validation
    // ========================================================================

    /**
     * Test validateUserPresence() when UP is true (valid).
     * Tests line 474-475 branch (happy path).
     * 
     * QUICK WIN: This method has 0% coverage currently.
     */
    @Test
    public void testValidateUserPresence_Valid() throws Exception {
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "validateUserPresence", Class.forName("com.isfs.blekey.authenticator.AuthenticatorAPI$CredentialOptions"));
        method.setAccessible(true);
        
        // Create CredentialOptions with up=true using constructor
        Class<?> optionsClass = Class.forName("com.isfs.blekey.authenticator.AuthenticatorAPI$CredentialOptions");
        java.lang.reflect.Constructor<?> constructor = optionsClass.getDeclaredConstructor(
            boolean.class, boolean.class, boolean.class);
        constructor.setAccessible(true);
        Object options = constructor.newInstance(true, false, false);
        
        Ctap2StatusCode result = (Ctap2StatusCode) method.invoke(null, options);
        
        assertNull(result, "Should return null when user presence is true");
    }

    /**
     * Test validateUserPresence() when UP is false (invalid).
     * Tests line 474-476 branch (error path).
     * 
     * QUICK WIN: Critical validation that must return INVALID_OPTION.
     */
    @Test
    public void testValidateUserPresence_Invalid() throws Exception {
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "validateUserPresence", Class.forName("com.isfs.blekey.authenticator.AuthenticatorAPI$CredentialOptions"));
        method.setAccessible(true);
        
        // Create CredentialOptions with up=false using constructor
        Class<?> optionsClass = Class.forName("com.isfs.blekey.authenticator.AuthenticatorAPI$CredentialOptions");
        java.lang.reflect.Constructor<?> constructor = optionsClass.getDeclaredConstructor(
            boolean.class, boolean.class, boolean.class);
        constructor.setAccessible(true);
        Object options = constructor.newInstance(false, false, false);
        
        Ctap2StatusCode result = (Ctap2StatusCode) method.invoke(null, options);
        
        assertEquals(Ctap2StatusCode.INVALID_OPTION, result,
                     "Should return INVALID_OPTION when user presence is false");
    }

    // ========================================================================
    // isCredentialExcluded() - Helper Method Branch Coverage
    // Lines 726-743: Test all branches of credential exclusion logic
    // ========================================================================

    /**
     * Test isCredentialExcluded() with null passkey.
     * Tests line 726-728 branch.
     */
    @Test
    public void testIsCredentialExcluded_NullPasskey() throws Exception {
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "isCredentialExcluded", byte[].class, Passkey.class);
        method.setAccessible(true);
        
        byte[] credId = new byte[]{1, 2, 3};
        Boolean result = (Boolean) method.invoke(null, credId, null);
        
        assertFalse(result, "Should return false when passkey is null");
    }

    /**
     * Test isCredentialExcluded() with null credId.
     * Tests line 726-728 branch.
     */
    @Test
    public void testIsCredentialExcluded_NullCredId() throws Exception {
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "isCredentialExcluded", byte[].class, Passkey.class);
        method.setAccessible(true);
        
        Boolean result = (Boolean) method.invoke(null, null, mockPasskey);
        
        assertFalse(result, "Should return false when credId is null");
    }

    /**
     * Test isCredentialExcluded() with null resident credentials list.
     * Tests line 731-733 branch.
     */
    @Test
    public void testIsCredentialExcluded_NullResCreds() throws Exception {
        when(mockPasskey.getResCreds()).thenReturn(null);
        
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "isCredentialExcluded", byte[].class, Passkey.class);
        method.setAccessible(true);
        
        byte[] credId = new byte[]{1, 2, 3};
        Boolean result = (Boolean) method.invoke(null, credId, mockPasskey);
        
        assertFalse(result, "Should return false when resident credentials list is null");
    }

    /**
     * Test isCredentialExcluded() with matching credential.
     * Tests line 738-740 branch (found match).
     */
    @Test
    public void testIsCredentialExcluded_MatchFound() throws Exception {
        byte[] credId = new byte[]{1, 2, 3, 4, 5};
        
        List<Map<String, byte[]>> resCreds = new ArrayList<>();
        Map<String, byte[]> cred = new HashMap<>();
        cred.put("cred.id", credId);
        resCreds.add(cred);
        
        when(mockPasskey.getResCreds()).thenReturn(resCreds);
        
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "isCredentialExcluded", byte[].class, Passkey.class);
        method.setAccessible(true);
        
        Boolean result = (Boolean) method.invoke(null, credId, mockPasskey);
        
        assertTrue(result, "Should return true when credential ID matches");
    }

    /**
     * Test isCredentialExcluded() with no matching credential.
     * Tests line 743 branch (no match found).
     */
    @Test
    public void testIsCredentialExcluded_NoMatch() throws Exception {
        byte[] credId = new byte[]{1, 2, 3, 4, 5};
        byte[] differentCredId = new byte[]{6, 7, 8, 9, 10};
        
        List<Map<String, byte[]>> resCreds = new ArrayList<>();
        Map<String, byte[]> cred = new HashMap<>();
        cred.put("cred.id", differentCredId);
        resCreds.add(cred);
        
        when(mockPasskey.getResCreds()).thenReturn(resCreds);
        
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "isCredentialExcluded", byte[].class, Passkey.class);
        method.setAccessible(true);
        
        Boolean result = (Boolean) method.invoke(null, credId, mockPasskey);
        
        assertFalse(result, "Should return false when credential ID does not match");
    }

    /**
     * Test isCredentialExcluded() with credential entry having null cred.id.
     * Tests line 738 null check branch.
     */
    @Test
    public void testIsCredentialExcluded_NullStoredCredId() throws Exception {
        byte[] credId = new byte[]{1, 2, 3, 4, 5};
        
        List<Map<String, byte[]>> resCreds = new ArrayList<>();
        Map<String, byte[]> cred = new HashMap<>();
        cred.put("cred.id", null);  // Null stored credential ID
        resCreds.add(cred);
        
        when(mockPasskey.getResCreds()).thenReturn(resCreds);
        
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "isCredentialExcluded", byte[].class, Passkey.class);
        method.setAccessible(true);
        
        Boolean result = (Boolean) method.invoke(null, credId, mockPasskey);
        
        assertFalse(result, "Should return false when stored credential ID is null");
    }

    /**
     * Test isCredentialExcluded() with multiple credentials, checking each branch.
     * Tests the loop iteration through multiple credentials (line 736-741).
     */
    @Test
    public void testIsCredentialExcluded_MultipleCredentialsNoMatch() throws Exception {
        byte[] credId = new byte[]{1, 2, 3, 4, 5};
        
        List<Map<String, byte[]>> resCreds = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            Map<String, byte[]> cred = new HashMap<>();
            cred.put("cred.id", new byte[]{(byte)(i+10), (byte)(i+11), (byte)(i+12)});
            resCreds.add(cred);
        }
        
        when(mockPasskey.getResCreds()).thenReturn(resCreds);
        
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "isCredentialExcluded", byte[].class, Passkey.class);
        method.setAccessible(true);
        
        Boolean result = (Boolean) method.invoke(null, credId, mockPasskey);
        
        assertFalse(result, "Should return false after checking all credentials with no match");
    }
}

// Made with Bob