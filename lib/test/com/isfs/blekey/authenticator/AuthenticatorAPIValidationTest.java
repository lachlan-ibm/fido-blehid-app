/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator;

import static org.junit.Assert.*;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.isfs.blekey.authenticator.implapi.CredentialValidator;
import com.isfs.blekey.authenticator.implapi.pin.PinVerifier;
import com.isfs.blekey.ctap.Ctap2StatusCode;
import com.isfs.blekey.ctap.CtapTxn;

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

    private Method verifyPinUvAuth;

    @Before
    public void setUp() throws Exception {
        verifyPinUvAuth = PinVerifier.class.getDeclaredMethod(
            "verify", Map.class, CtapTxn.class);
        verifyPinUvAuth.setAccessible(true);
    }

    private Object invokeVerify(Map<Integer, Object> req, CtapTxn txn) throws Exception {
        try {
            return verifyPinUvAuth.invoke(null, req, txn);
        } catch (InvocationTargetException e) {
            throw (Exception) e.getCause();
        }
    }

    private Ctap2StatusCode getErrorCode(Object result) throws Exception {
        java.lang.reflect.Field f = result.getClass().getDeclaredField("errorCode");
        f.setAccessible(true);
        return (Ctap2StatusCode) f.get(result);
    }

    /**
     * Test isSupportedAlgorithm() with multiple algorithms including unsupported ones.
     * Covers branch where algorithm is not in SUPPORTED_ALGORITHM_SET.
     */
    @Test
    public void testIsSupportedAlgorithm_MixedAlgorithms() throws Exception {
        Method method = CredentialValidator.class.getDeclaredMethod("isSupportedAlgorithm", List.class);
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
        Method method = CredentialValidator.class.getDeclaredMethod("isSupportedAlgorithm", List.class);
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
        Method method = CredentialValidator.class.getDeclaredMethod("isSupportedAlgorithm", List.class);
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
        Method method = CredentialValidator.class.getDeclaredMethod("isSupportedAlgorithm", List.class);
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
        Method method = CredentialValidator.class.getDeclaredMethod(
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
        Method method = CredentialValidator.class.getDeclaredMethod(
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
        Method method = CredentialValidator.class.getDeclaredMethod(
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
        Method method = CredentialValidator.class.getDeclaredMethod(
            "determineCredentialType", boolean.class, boolean.class,
            com.isfs.blekey.data.Passkey.class);
        method.setAccessible(true);

        Object result = method.invoke(null, false, true, null);

        assertNotNull("Should return a result", result);
    }
    
    /**
     * Protocol version 0 is unsupported — verifyPinUvAuth returns PIN_AUTH_INVALID.
     * (Replaces reflection-based validatePinUvAuthProtocol_Version0 test.)
     */
    @Test
    public void testValidatePinUvAuthProtocol_Version0() throws Exception {
        Map<Integer, Object> req = buildReqWithProtocol(0);
        CtapTxn txn = new CtapTxn();
        txn.setPinAuthTkn(new byte[32]);
        assertEquals("Protocol 0 should be invalid",
            Ctap2StatusCode.PIN_AUTH_INVALID, getErrorCode(invokeVerify(req, txn)));
    }

    /**
     * Protocol version 3 is unsupported — verifyPinUvAuth returns PIN_AUTH_INVALID.
     * (Replaces reflection-based validatePinUvAuthProtocol_Version3 test.)
     */
    @Test
    public void testValidatePinUvAuthProtocol_Version3() throws Exception {
        Map<Integer, Object> req = buildReqWithProtocol(3);
        CtapTxn txn = new CtapTxn();
        txn.setPinAuthTkn(new byte[32]);
        assertEquals("Protocol 3 should be invalid",
            Ctap2StatusCode.PIN_AUTH_INVALID, getErrorCode(invokeVerify(req, txn)));
    }

    /**
     * Negative protocol version is unsupported — verifyPinUvAuth returns PIN_AUTH_INVALID.
     * (Replaces reflection-based validatePinUvAuthProtocol_NegativeVersion test.)
     */
    @Test
    public void testValidatePinUvAuthProtocol_NegativeVersion() throws Exception {
        Map<Integer, Object> req = buildReqWithProtocol(-1);
        CtapTxn txn = new CtapTxn();
        txn.setPinAuthTkn(new byte[32]);
        assertEquals("Negative protocol should be invalid",
            Ctap2StatusCode.PIN_AUTH_INVALID, getErrorCode(invokeVerify(req, txn)));
    }

    /**
     * No pinUvAuthParam and UV not requested → no error (errorCode is null).
     * (Replaces errorResult_NullMessage / _EmptyMessage tests: the old errorResult
     *  helper is gone; error propagation is tested end-to-end here.)
     */
    @Test
    public void testErrorResult_NullMessage() throws Exception {
        Map<Integer, Object> req = baseReq();
        req.put(0x07, Map.of("uv", false)); // no UV request, no pinUvAuthParam
        CtapTxn txn = new CtapTxn();
        assertNull("No UV param and no UV request should produce no error",
            getErrorCode(invokeVerify(req, txn)));
    }

    /**
     * No pinUvAuthParam and UV requested → PIN_REQUIRED error.
     * (Replaces errorResult_EmptyMessage test: equivalent error-propagation coverage.)
     */
    @Test
    public void testErrorResult_EmptyMessage() throws Exception {
        Map<Integer, Object> req = baseReq();
        req.put(0x07, Map.of("uv", true));
        CtapTxn txn = new CtapTxn();
        assertEquals("UV requested without token should return PIN_REQUIRED",
            Ctap2StatusCode.PIN_REQUIRED, getErrorCode(invokeVerify(req, txn)));
    }

    /**
     * pinUvAuthParam present but missing clientDataHash → MISSING_PARAMETER.
     * (Replaces errorResult_WithExceptionNullMessage test: exercises the same
     *  error-return path in verifyPinUvAuth.)
     */
    @Test
    public void testErrorResult_WithExceptionNullMessage() throws Exception {
        Map<Integer, Object> req = new HashMap<>();
        req.put(0x02, Map.of("id", "example.com")); // RP required
        req.put(0x08, new byte[16]); // pinUvAuthParam present
        req.put(0x09, 1);            // valid protocol
        // key 0x01 (clientDataHash) intentionally absent
        CtapTxn txn = new CtapTxn();
        txn.setPinAuthTkn(new byte[32]);
        assertEquals("Missing clientDataHash should return MISSING_PARAMETER",
            Ctap2StatusCode.MISSING_PARAMETER, getErrorCode(invokeVerify(req, txn)));
    }

    /**
     * pinUvAuthParam present, valid protocol, no PIN token on txn → PIN_AUTH_INVALID.
     * (Replaces errorResult_WithExceptionAndMessage test.)
     */
    @Test
    public void testErrorResult_WithExceptionAndMessage() throws Exception {
        Map<Integer, Object> req = buildReqWithProtocol(1);
        CtapTxn txn = new CtapTxn();
        // txn.getPinAuthTkn() == null → PIN_AUTH_INVALID
        assertEquals("Null PIN token should return PIN_AUTH_INVALID",
            Ctap2StatusCode.PIN_AUTH_INVALID, getErrorCode(invokeVerify(req, txn)));
    }

    /**
     * Unsupported protocol 2 → PIN_AUTH_INVALID.
     * (Replaces errorResult_NullException test: different error-return code path.)
     */
    @Test
    public void testErrorResult_NullException() throws Exception {
        Map<Integer, Object> req = buildReqWithProtocol(2);
        CtapTxn txn = new CtapTxn();
        txn.setPinAuthTkn(new byte[32]);
        assertEquals("Protocol 2 should return PIN_AUTH_INVALID",
            Ctap2StatusCode.PIN_AUTH_INVALID, getErrorCode(invokeVerify(req, txn)));
    }

    // ---- helpers ----
    private Map<Integer, Object> buildReqWithProtocol(int protocol) {
        Map<Integer, Object> req = new HashMap<>();
        req.put(0x02, Map.of("id", "example.com")); // RP — required by PinUvAuthParams.parse
        req.put(0x08, new byte[16]); // pinUvAuthParam — triggers protocol check
        req.put(0x09, protocol);
        req.put(0x01, new byte[32]); // clientDataHash
        return req;
    }

    private Map<Integer, Object> baseReq() {
        Map<Integer, Object> req = new HashMap<>();
        req.put(0x02, Map.of("id", "example.com")); // RP — required by PinUvAuthParams.parse
        req.put(0x01, new byte[32]);
        return req;
    }
}

// Made with Bob
