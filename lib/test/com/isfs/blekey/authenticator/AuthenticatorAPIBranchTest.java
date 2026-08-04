/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import com.isfs.blekey.authenticator.implapi.pin.PinVerifier;
import com.isfs.blekey.ctap.Ctap2StatusCode;
import com.isfs.blekey.ctap.CtapTxn;

/**
 * Branch coverage tests for AuthenticatorAPI.
 *
 * Covers PIN/UV authentication protocol-validation branches that are now inlined
 * inside {@code verifyPinUvAuth()} after the §6b flattening refactor.
 * PinAuthException and the standalone helper methods were removed; behaviour is
 * verified end-to-end through {@code verifyPinUvAuth}.
 */
@ExtendWith(MockitoExtension.class)
public class AuthenticatorAPIBranchTest {

    private Method verifyPinUvAuth;

    @BeforeEach
    public void setUp() throws Exception {
        verifyPinUvAuth = PinVerifier.class.getDeclaredMethod(
            "verify", Map.class, CtapTxn.class);
        verifyPinUvAuth.setAccessible(true);
    }

    // ========== Protocol-validation branches now inlined in verifyPinUvAuth() ==========

    /** Null protocol (pinUvAuthProtocol key absent) → PIN_AUTH_INVALID. */
    @Test
    public void testVerifyPinUvAuth_NullProtocol_ReturnsPinAuthInvalid() throws Exception {
        // Build a request with a pinUvAuthParam (16 bytes) but no protocol key.
        Map<Integer, Object> req = baseReq();
        req.put(0x08, new byte[16]);   // pinUvAuthParam present
        // key 0x09 (pinUvAuthProtocol) intentionally absent → null protocol

        CtapTxn txn = new CtapTxn();
        txn.setPinAuthTkn(new byte[32]);

        Object result = invokeVerify(req, txn);
        assertPinAuthInvalid(result);
    }

    /** Unsupported protocol version 2 → PIN_AUTH_INVALID. */
    @Test
    public void testVerifyPinUvAuth_UnsupportedProtocol2_ReturnsPinAuthInvalid() throws Exception {
        Map<Integer, Object> req = baseReq();
        req.put(0x08, new byte[16]);
        req.put(0x09, 2);             // version 2 — unsupported

        CtapTxn txn = new CtapTxn();
        txn.setPinAuthTkn(new byte[32]);

        Object result = invokeVerify(req, txn);
        assertPinAuthInvalid(result);
    }

    /** Unsupported protocol version 0 → PIN_AUTH_INVALID. */
    @Test
    public void testVerifyPinUvAuth_UnsupportedProtocol0_ReturnsPinAuthInvalid() throws Exception {
        Map<Integer, Object> req = baseReq();
        req.put(0x08, new byte[16]);
        req.put(0x09, 0);

        CtapTxn txn = new CtapTxn();
        txn.setPinAuthTkn(new byte[32]);

        Object result = invokeVerify(req, txn);
        assertPinAuthInvalid(result);
    }

    /** Unsupported negative protocol version → PIN_AUTH_INVALID. */
    @Test
    public void testVerifyPinUvAuth_NegativeProtocol_ReturnsPinAuthInvalid() throws Exception {
        Map<Integer, Object> req = baseReq();
        req.put(0x08, new byte[16]);
        req.put(0x09, -1);

        CtapTxn txn = new CtapTxn();
        txn.setPinAuthTkn(new byte[32]);

        Object result = invokeVerify(req, txn);
        assertPinAuthInvalid(result);
    }

    /** No pinUvAuthParam and UV not requested → NO_VERIFICATION (errorCode null). */
    @Test
    public void testVerifyPinUvAuth_NoParam_NoUvRequest_ReturnsNoVerification() throws Exception {
        Map<Integer, Object> req = baseReq();
        // No key 0x08 (pinUvAuthParam)
        req.put(0x07, Map.of("uv", false)); // uv=false

        CtapTxn txn = new CtapTxn();

        Object result = invokeVerify(req, txn);
        assertErrorCodeNull(result);
    }

    /** No pinUvAuthParam but UV was requested → PIN_REQUIRED. */
    @Test
    public void testVerifyPinUvAuth_NoParam_UvRequested_ReturnsPinRequired() throws Exception {
        Map<Integer, Object> req = baseReq();
        // No key 0x08
        req.put(0x07, Map.of("uv", true)); // uv=true

        CtapTxn txn = new CtapTxn();

        Object result = invokeVerify(req, txn);
        assertErrorCode(result, Ctap2StatusCode.PIN_REQUIRED);
    }

    // ========== helpers ==========

    /** Minimum valid request: RP map with "id" + clientDataHash (key 0x01). */
    private Map<Integer, Object> baseReq() {
        Map<Integer, Object> req = new HashMap<>();
        req.put(0x02, Map.of("id", "example.com")); // RP — required by PinUvAuthParams.parse
        req.put(0x01, new byte[32]);                 // clientDataHash
        return req;
    }


    private Object invokeVerify(Map<Integer, Object> req, CtapTxn txn) throws Exception {
        try {
            return verifyPinUvAuth.invoke(null, req, txn);
        } catch (InvocationTargetException e) {
            throw (Exception) e.getCause();
        }
    }

    private void assertErrorCode(Object result, Ctap2StatusCode expected) throws Exception {
        java.lang.reflect.Field f = result.getClass().getDeclaredField("errorCode");
        f.setAccessible(true);
        assertEquals(expected, f.get(result));
    }

    private void assertPinAuthInvalid(Object result) throws Exception {
        assertErrorCode(result, Ctap2StatusCode.PIN_AUTH_INVALID);
    }

    private void assertErrorCodeNull(Object result) throws Exception {
        java.lang.reflect.Field f = result.getClass().getDeclaredField("errorCode");
        f.setAccessible(true);
        assertNull(f.get(result));
    }
}

// Made with Bob
