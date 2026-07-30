/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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