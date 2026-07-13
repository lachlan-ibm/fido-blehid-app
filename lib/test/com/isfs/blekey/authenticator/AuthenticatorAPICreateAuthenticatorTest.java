/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.isfs.blekey.ctap.CtapTxn;
import com.isfs.blekey.data.Passkey;

/**
 * Branch coverage tests for AuthenticatorAPI.createAuthenticator() method.
 * 
 */
@ExtendWith(MockitoExtension.class)
public class AuthenticatorAPICreateAuthenticatorTest {

    @Mock
    private CtapTxn mockTxn;
    
    @Mock
    private Passkey mockPasskey;
    
    private KeyPair testKeyPair;
    private X509Certificate testCert;
    private PrivateKey testPrivateKey;
    
    @BeforeEach
    public void setUp() throws Exception {
        // Point FIDO2_HOME at a temp dir that has no platform.key file,
        // so KeyUtils.getPlatformKey() reliably returns null in all tests.
        System.setProperty("FIDO2_HOME", System.getProperty("java.io.tmpdir"));

        // Create test key pair and certificate
        testKeyPair = TestHelper.createTestKeyPair("EC");
        testPrivateKey = testKeyPair.getPrivate();
        
        Object[] caData = TestHelper.createTestCA();
        testCert = (X509Certificate) caData[1];
    }

    @AfterEach
    public void tearDown() {
        System.clearProperty("FIDO2_HOME");
    }

    // ========== Branch: rpObj instanceof String (line 1008) ==========
    
    /**
     * Test createAuthenticator with rpId as String (getAssertion scenario).
     * Covers branch at line 1008: rpObj instanceof String
     * Note: Without platform key setup, KeyUtils.getPasskeySeed() may return null,
     * causing authenticator creation to fail and throw IllegalStateException.
     */
    @Test
    public void testCreateAuthenticator_RpIdAsString() throws Exception {
        // Setup request with rpId as String (0x02 parameter)
        Map<Integer, Object> req = new HashMap<>();
        req.put(0x02, "example.com");
        req.put(0x01, "clientDataHash".getBytes(StandardCharsets.UTF_8));
        
        // Mock transaction without passkey (U2F path)
        when(mockTxn.getPasskey()).thenReturn(null);
        
        // Invoke private method using reflection
        java.lang.reflect.Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "createAuthenticator", CtapTxn.class, Object.class);
        method.setAccessible(true);
        
        // Expect IllegalStateException when platform key is not available
        Exception exception = assertThrows(java.lang.reflect.InvocationTargetException.class, () -> {
            method.invoke(null, mockTxn, req.get(0x02));
        });
        
        // Verify the cause is IllegalStateException
        assertTrue(exception.getCause() instanceof IllegalStateException,
            "Expected IllegalStateException when seed generation fails");
        String message = exception.getCause().getMessage();
        assertTrue(message != null && message.contains("Failed to generate seed"),
            "Exception message should indicate seed generation failure");
    }

    // ========== Branch: rpObj instanceof byte[] (line 1012) ==========
    
    /**
     * Test createAuthenticator with rpId as byte array.
     * Covers branch at line 1012: rpObj instanceof byte[]
     */
    @Test
    public void testCreateAuthenticator_RpIdAsByteArray() throws Exception {
        // Setup request with rpId as byte array
        Map<Integer, Object> req = new HashMap<>();
        req.put(0x02, "example.com".getBytes(StandardCharsets.UTF_8));
        req.put(0x01, "clientDataHash".getBytes(StandardCharsets.UTF_8));
        
        when(mockTxn.getPasskey()).thenReturn(null);
        
        java.lang.reflect.Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "createAuthenticator", CtapTxn.class, Object.class);
        method.setAccessible(true);
        
        // Expect IllegalStateException when platform key is not available
        Exception exception = assertThrows(java.lang.reflect.InvocationTargetException.class, () -> {
            method.invoke(null, mockTxn, req.get(0x02));
        });
        
        assertTrue(exception.getCause() instanceof IllegalStateException,
            "Expected IllegalStateException when seed generation fails");
    }

    // ========== Branch: rpObj instanceof Map with String id (lines 1016, 1022) ==========
    
    /**
     * Test createAuthenticator with RP entity map containing String id (makeCredential scenario).
     * Covers branches at lines 1016 and 1022: rpObj instanceof Map, rpIdObj instanceof String
     */
    @Test
    public void testCreateAuthenticator_RpMapWithStringId() throws Exception {
        // Setup request with RP entity map (makeCredential)
        Map<String, Object> rpMap = new HashMap<>();
        rpMap.put("id", "example.com");
        rpMap.put("name", "Example RP");
        
        Map<Integer, Object> req = new HashMap<>();
        req.put(0x02, rpMap);
        req.put(0x01, "clientDataHash".getBytes(StandardCharsets.UTF_8));
        
        when(mockTxn.getPasskey()).thenReturn(null);
        
        java.lang.reflect.Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "createAuthenticator", CtapTxn.class, Object.class);
        method.setAccessible(true);
        
        // Expect IllegalStateException when platform key is not available
        Exception exception = assertThrows(java.lang.reflect.InvocationTargetException.class, () -> {
            method.invoke(null, mockTxn, req.get(0x02));
        });
        
        assertTrue(exception.getCause() instanceof IllegalStateException,
            "Expected IllegalStateException when seed generation fails");
    }

    // ========== Branch: rpObj instanceof Map with byte[] id (lines 1016, 1025) ==========
    
    /**
     * Test createAuthenticator with RP entity map containing byte[] id.
     * Covers branches at lines 1016 and 1025: rpObj instanceof Map, rpIdObj instanceof byte[]
     */
    @Test
    public void testCreateAuthenticator_RpMapWithByteArrayId() throws Exception {
        // Setup request with RP map containing byte[] id
        Map<String, Object> rpMap = new HashMap<>();
        rpMap.put("id", "example.com".getBytes(StandardCharsets.UTF_8));
        rpMap.put("name", "Example RP");
        
        Map<Integer, Object> req = new HashMap<>();
        req.put(0x02, rpMap);
        req.put(0x01, "clientDataHash".getBytes(StandardCharsets.UTF_8));
        
        
        java.lang.reflect.Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "createAuthenticator", CtapTxn.class, Object.class);
        method.setAccessible(true);
        
        // Expect IllegalStateException when platform key is not available
        Exception exception = assertThrows(java.lang.reflect.InvocationTargetException.class, () -> {
            method.invoke(null, mockTxn, req.get(0x02));
        });
        
        assertTrue(exception.getCause() instanceof IllegalStateException,
            "Expected IllegalStateException when seed generation fails");
    }

    // ========== Branch: rpIdBytes == null fallback (line 1032) ==========
    
    /**
     * Test createAuthenticator with missing rpId (fallback to clientDataHash).
     * Covers branch at line 1032: rpIdBytes == null
     */
    @Test
    public void testCreateAuthenticator_MissingRpIdFallbackToClientDataHash() throws Exception {
        // Setup request without rpId (0x02 parameter)
        Map<Integer, Object> req = new HashMap<>();
        req.put(0x01, "clientDataHash".getBytes(StandardCharsets.UTF_8));
                
        java.lang.reflect.Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "createAuthenticator", CtapTxn.class, Object.class);
        method.setAccessible(true);
        
        // Expect IllegalArgumentException for missing RP parameter
        Exception exception = assertThrows(java.lang.reflect.InvocationTargetException.class, () -> {
            method.invoke(null, mockTxn, req.get(0x02));
        });
        
        assertTrue(exception.getCause() instanceof IllegalArgumentException,
            "Expected IllegalArgumentException for missing RP parameter");
        String message = exception.getCause().getMessage();
        assertTrue(message != null && message.contains("Missing rpId"),
            "Exception message should indicate missing rpId value");
    }

    /**
     * Test createAuthenticator with RP map but missing id field (fallback to clientDataHash).
     * Covers branch at line 1032: rpIdBytes == null after checking map
     */
    @Test
    public void testCreateAuthenticator_RpMapWithoutIdFallback() throws Exception {
        // Setup request with RP map but no "id" field
        Map<String, Object> rpMap = new HashMap<>();
        rpMap.put("name", "Example RP");
        // No "id" field - rpIdObj will be null
        
        Map<Integer, Object> req = new HashMap<>();
        req.put(0x02, rpMap);
        req.put(0x01, "clientDataHash".getBytes(StandardCharsets.UTF_8));
        
        
        java.lang.reflect.Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "createAuthenticator", CtapTxn.class, Object.class);
        method.setAccessible(true);
        
        // Expect IllegalArgumentException for missing id field in RP map
        Exception exception = assertThrows(java.lang.reflect.InvocationTargetException.class, () -> {
            method.invoke(null, mockTxn, req.get(0x02));
        });
        
        assertTrue(exception.getCause() instanceof IllegalArgumentException,
            "Expected IllegalArgumentException for missing id field");
        assertTrue(exception.getCause().getMessage().contains("RP map missing 'id' field"),
            "Exception message should indicate missing id field");
    }

    // ========== Branch: txn.getPasskey() != null (line 1037) ==========
    
    /**
     * Test createAuthenticator with passkey (resident credential path).
     * Covers branch at line 1037: txn.getPasskey() != null
     */
    @Test
    public void testCreateAuthenticator_WithPasskey_ResidentCredential() throws Exception {
        // Setup request
        Map<Integer, Object> req = new HashMap<>();
        req.put(0x02, "example.com");
        req.put(0x01, "clientDataHash".getBytes(StandardCharsets.UTF_8));
        
        // Mock passkey with private key only (certificate not needed for this path)
        when(mockPasskey.getPrivateKey()).thenReturn(testPrivateKey);
        when(mockTxn.getPasskey()).thenReturn(mockPasskey);
        
        java.lang.reflect.Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "createAuthenticator", CtapTxn.class, Object.class);
        method.setAccessible(true);
        
        Fido2Authenticator result = (Fido2Authenticator) method.invoke(null, mockTxn, req.get(0x02));
        
        assertNotNull(result, "Should create authenticator with passkey for resident credential");
    }

    // ========== Branch: else (U2F authenticator) (line 1046) ==========
    
    /**
     * Test createAuthenticator without passkey (U2F authenticator path).
     * Covers branch at line 1046: else (U2F authenticator)
     */
    @Test
    public void testCreateAuthenticator_WithoutPasskey_U2FAuthenticator() throws Exception {
        // Setup request
        Map<Integer, Object> req = new HashMap<>();
        req.put(0x02, "example.com");
        req.put(0x01, "clientDataHash".getBytes(StandardCharsets.UTF_8));
        
        // Mock transaction without passkey
        when(mockTxn.getPasskey()).thenReturn(null);
        
        java.lang.reflect.Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "createAuthenticator", CtapTxn.class, Object.class);
        method.setAccessible(true);
        
        // Expect IllegalStateException when platform key is not available
        Exception exception = assertThrows(java.lang.reflect.InvocationTargetException.class, () -> {
            method.invoke(null, mockTxn, req.get(0x02));
        });
        
        assertTrue(exception.getCause() instanceof IllegalStateException,
            "Expected IllegalStateException when seed generation fails");
    }

    // ========== Branch: Exception handling (line 1050) ==========
    
    /**
     * Test createAuthenticator exception handling.
     * Covers branch at line 1050: catch (Exception e)
     * Now throws RuntimeException instead of returning null.
     */
    @Test
    public void testCreateAuthenticator_ExceptionHandling() throws Exception {
        // Setup request that will cause an exception (null request map)
        Map<Integer, Object> req = null;
        
        // Don't stub mockTxn.getPasskey() - let it return null naturally
        
        java.lang.reflect.Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "createAuthenticator", CtapTxn.class, Object.class);
        method.setAccessible(true);
        
        // Expect IllegalArgumentException for null rpIdValue
        Exception exception = assertThrows(java.lang.reflect.InvocationTargetException.class, () -> {
            method.invoke(null, mockTxn, null);
        });
        
        assertTrue(exception.getCause() instanceof IllegalArgumentException,
            "Expected IllegalArgumentException for null rpIdValue");
        String message = exception.getCause().getMessage();
        assertTrue(message != null && message.contains("Missing rpId"),
            "Exception message should indicate missing rpId value");
    }

    /**
     * Test createAuthenticator with exception during key generation.
     * Covers exception path when KeyUtils.getPasskeySeed returns null
     * Now throws IllegalStateException instead of returning null.
     */
    @Test
    public void testCreateAuthenticator_ExceptionDuringKeyGeneration() throws Exception {
        // Setup request with invalid data that might cause KeyUtils to fail
        Map<Integer, Object> req = new HashMap<>();
        req.put(0x02, "example.com");
        req.put(0x01, "clientDataHash".getBytes(StandardCharsets.UTF_8));
        
        // Mock passkey with null private key to trigger exception
        when(mockPasskey.getPrivateKey()).thenReturn(null);
        when(mockTxn.getPasskey()).thenReturn(mockPasskey);
        
        java.lang.reflect.Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "createAuthenticator", CtapTxn.class, Object.class);
        method.setAccessible(true);
        
        // Expect IllegalStateException when seed generation fails
        Exception exception = assertThrows(java.lang.reflect.InvocationTargetException.class, () -> {
            method.invoke(null, mockTxn, req.get(0x02));
        });
        
        assertTrue(exception.getCause() instanceof IllegalStateException,
            "Expected IllegalStateException when seed generation fails");
        String message = exception.getCause().getMessage();
        assertTrue(message != null && message.contains("Failed to generate seed"),
            "Exception message should indicate seed generation failure");
    }

    // ========== Additional edge case tests ==========
    
    /**
     * Test createAuthenticator with unsupported rpObj type.
     * Tests the implicit else case when rpObj is neither String, byte[], nor Map
     * Now throws IllegalArgumentException instead of falling back.
     */
    @Test
    public void testCreateAuthenticator_UnsupportedRpObjType() throws Exception {
        // Setup request with unsupported type (Integer)
        Map<Integer, Object> req = new HashMap<>();
        req.put(0x02, Integer.valueOf(12345)); // Unsupported type
        req.put(0x01, "clientDataHash".getBytes(StandardCharsets.UTF_8));
        
        
        java.lang.reflect.Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "createAuthenticator", CtapTxn.class, Object.class);
        method.setAccessible(true);
        
        // Expect IllegalArgumentException for unsupported RP type
        Exception exception = assertThrows(java.lang.reflect.InvocationTargetException.class, () -> {
            method.invoke(null, mockTxn, req.get(0x02));
        });
        
        assertTrue(exception.getCause() instanceof IllegalArgumentException,
            "Expected IllegalArgumentException for unsupported RP type");
        String message = exception.getCause().getMessage();
        assertTrue(message != null && message.contains("unsupported type"),
            "Exception message should indicate unsupported type");
    }

    /**
     * Test createAuthenticator with RP map containing unsupported id type.
     * Tests the implicit else case when rpIdObj is neither String nor byte[]
     * Now throws IllegalArgumentException instead of falling back.
     */
    @Test
    public void testCreateAuthenticator_RpMapWithUnsupportedIdType() throws Exception {
        // Setup request with RP map containing unsupported id type
        Map<String, Object> rpMap = new HashMap<>();
        rpMap.put("id", Integer.valueOf(12345)); // Unsupported type
        rpMap.put("name", "Example RP");
        
        Map<Integer, Object> req = new HashMap<>();
        req.put(0x02, rpMap);
        req.put(0x01, "clientDataHash".getBytes(StandardCharsets.UTF_8));
        
        
        java.lang.reflect.Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "createAuthenticator", CtapTxn.class, Object.class);
        method.setAccessible(true);
        
        // Expect IllegalArgumentException for unsupported id type
        Exception exception = assertThrows(java.lang.reflect.InvocationTargetException.class, () -> {
            method.invoke(null, mockTxn, req.get(0x02));
        });
        
        assertTrue(exception.getCause() instanceof IllegalArgumentException,
            "Expected IllegalArgumentException for unsupported id type");
        assertTrue(exception.getCause().getMessage().contains("RP map 'id' field has unsupported type"),
            "Exception message should indicate unsupported id type");
    }

    /**
     * Test createAuthenticator with all branch combinations for comprehensive coverage.
     * This test verifies the method works correctly with various input combinations.
     * Updated to expect exceptions when platform key is unavailable.
     */
    @Test
    public void testCreateAuthenticator_ComprehensiveBranchCoverage() throws Exception {
        java.lang.reflect.Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "createAuthenticator", CtapTxn.class, Object.class);
        method.setAccessible(true);
        
        // Test 1: String rpId + no passkey (will throw exception without platform key)
        Map<Integer, Object> req1 = new HashMap<>();
        req1.put(0x02, "example.com");
        req1.put(0x01, "hash1".getBytes());
        when(mockTxn.getPasskey()).thenReturn(null);
        assertThrows(java.lang.reflect.InvocationTargetException.class, () -> {
            method.invoke(null, mockTxn, req1.get(0x02));
        }, "String rpId without platform key should throw exception");
        
        // Test 2: byte[] rpId + with passkey
        Map<Integer, Object> req2 = new HashMap<>();
        req2.put(0x02, "example.com".getBytes());
        req2.put(0x01, "hash2".getBytes());
        when(mockPasskey.getPrivateKey()).thenReturn(testPrivateKey);
        when(mockTxn.getPasskey()).thenReturn(mockPasskey);
        Object result2 = method.invoke(null, mockTxn, req2.get(0x02));
        assertNotNull(result2, "byte[] rpId + passkey should succeed");
        
        // Test 3: Map with String id + no passkey (will throw exception without platform key)
        Map<String, Object> rpMap3 = new HashMap<>();
        rpMap3.put("id", "example.com");
        Map<Integer, Object> req3 = new HashMap<>();
        req3.put(0x02, rpMap3);
        req3.put(0x01, "hash3".getBytes());
        when(mockTxn.getPasskey()).thenReturn(null);
        assertThrows(java.lang.reflect.InvocationTargetException.class, () -> {
            method.invoke(null, mockTxn, req3.get(0x02));
        }, "Map with String id without platform key should throw exception");
        
        // Test 4: Map with byte[] id + with passkey
        Map<String, Object> rpMap4 = new HashMap<>();
        rpMap4.put("id", "example.com".getBytes());
        Map<Integer, Object> req4 = new HashMap<>();
        req4.put(0x02, rpMap4);
        req4.put(0x01, "hash4".getBytes());
        when(mockTxn.getPasskey()).thenReturn(mockPasskey);
        Object result4 = method.invoke(null, mockTxn, req4.get(0x02));
        assertNotNull(result4, "Map with byte[] id + passkey should succeed");
    }
}

// Made with Bob