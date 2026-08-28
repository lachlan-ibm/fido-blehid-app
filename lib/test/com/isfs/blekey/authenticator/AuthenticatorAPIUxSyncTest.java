/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import com.isfs.blekey.ctap.Ctap2StatusCode;
import com.isfs.blekey.ctap.CtapTxn;
import com.isfs.blekey.data.AppConfig;
import com.isfs.blekey.util.FileUtils;
import com.isfs.blekey.util.KeyUtils;

/**
 * Acceptance tests for the getInfo synchronous refactor (plan §4.1 / G1, G2)
 * and getAssertion / getNextAssertion UP-gate and lock-gate paths (G4, G5).
 *
 * <p>Tests marked PRE-REFACTOR FAIL are the acceptance criteria for the source
 * changes in plan §4.1 and §4.2; all others are regression guards.</p>
 *
 * <p>getInfo is package-protected — this test is in the same package so no
 * reflection is needed to call it directly.</p>
 */
@ExtendWith(MockitoExtension.class)
public class AuthenticatorAPIUxSyncTest {

    private java.io.File tempDir;
    private final AtomicReference<byte[]> capturedResponse = new AtomicReference<>();

    @BeforeEach
    public void setUp() throws Exception {
        tempDir = Files.createTempDirectory("fido2-uxsync-test-").toFile();
        tempDir.deleteOnExit();
        System.setProperty("FIDO2_HOME", tempDir.getAbsolutePath());

        KeyPair platformKeyPair = KeyUtils.generateKeyPair("EC", 256);
        FileUtils.writePrivatePEM(platformKeyPair.getPrivate(),
                new java.io.File(tempDir, "platform.key"));

        AuthenticatorAPI.setUpUvCallback(null);
        AuthenticatorAPI.setDeferredResponseSender(null);
        capturedResponse.set(null);
        resetUpLock();
    }

    @AfterEach
    public void tearDown() throws Exception {
        AuthenticatorAPI.setUpUvCallback(null);
        AuthenticatorAPI.setDeferredResponseSender(null);
        AuthenticatorAPI.setAppConfig(null); // reset to default (CTAP2 mode)
        System.clearProperty("FIDO2_HOME");
        resetUpLock();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static void resetUpLock() throws Exception {
        UxInteractionLock.get().reset();
    }


    // -------------------------------------------------------------------------
    // getInfo tests (G1, G2)
    // -------------------------------------------------------------------------

    /**
     * POST-REFACTOR (plan §4.1): getInfo must return SUCCESS with no UpUvCallback.
     * PRE-REFACTOR: returns OPERATION_DENIED (0x27).
     */
    @Test
    public void testGetInfo_NoCallback_ReturnsSuccess() {
        AuthenticatorAPI.setUpUvCallback(null);
        CtapTxn txn = new CtapTxn();
        txn.setCid(new byte[]{0x01, 0x02, 0x03, 0x04});

        byte[] response = AuthenticatorAPI.getInfo(txn, new HashMap<>());

        assertNotNull(response, "getInfo must never return null after refactor");
        assertEquals(0x00, response[0] & 0xFF,
                "getInfo must return SUCCESS (0x00) with no callback after §4.1 refactor");
    }

    /**
     * POST-REFACTOR (plan §4.1): getInfo must return SUCCESS when another CID holds the lock.
     * PRE-REFACTOR: returns CHANNEL_BUSY (0x06).
     */
    @Test
    public void testGetInfo_OtherCidHoldsLock_ReturnsSuccess() throws Exception {
        byte[] MY_CID = {0x01, 0x02, 0x03, 0x04};

        // Simulate another CID already holding the UX lock (IN_PROGRESS).
        // fireIfIdle skips when state != IDLE, so getInfo falls through to the
        // non-null return at line 305 of AuthenticatorAPI.getInfo().
        UxInteractionLock.get().setStateInProgress();

        AuthenticatorAPI.setUpUvCallback(ctx -> {}); // stub — must not be called

        CtapTxn txn = new CtapTxn();
        txn.setCid(MY_CID);

        byte[] response = AuthenticatorAPI.getInfo(txn, new HashMap<>());

        assertNotNull(response, "getInfo must not return null when lock is IN_PROGRESS");
        assertEquals(0x00, response[0] & 0xFF,
                "getInfo must return SUCCESS regardless of lock state after §4.1 refactor");
    }

    /**
     * getInfo ctap2 mode response must contain FIDO_2_1 and not U2F_V2 (G2).
     * Green before and after the refactor.
     */
    @Test
    public void testGetInfo_Ctap2Mode_ResponseContainsFido21() throws Exception {
        AuthenticatorAPI.setAppConfig(new AppConfig(null, false));
        // The getInfo deferred path delivers responseBytes through ChainRunner.terminal.done()
        // (not through DeferredResponseSender), so capture it from the ChainCallback.
        AuthenticatorAPI.setUpUvCallback(ctx ->
            ctx.buildResponse(UpUvRequestCtx.Outcome.APPROVED, rsp -> capturedResponse.set(rsp)));

        CtapTxn txn = new CtapTxn();
        txn.setCid(new byte[]{0x01, 0x02, 0x03, 0x04});

        byte[] response = AuthenticatorAPI.getInfo(txn, new HashMap<>());
        if (response == null) response = capturedResponse.get();

        assertNotNull(response, "Must have a response");
        assertEquals(0x00, response[0] & 0xFF, "Status byte must be SUCCESS");

        byte[] cborBody = java.util.Arrays.copyOfRange(response, 1, response.length);
        @SuppressWarnings("unchecked")
        java.util.Map<Integer, Object> info =
            (java.util.Map<Integer, Object>) com.isfs.blekey.util.Cbor.decode(cborBody);
        @SuppressWarnings("unchecked")
        java.util.List<Object> vList = (java.util.List<Object>) info.get(0x01);
        assertTrue(vList.contains("FIDO_2_1"),
            "ctap2 mode getInfo response must advertise FIDO_2_1");
        assertFalse(vList.contains("U2F_V2"),
            "ctap2 mode getInfo response must NOT advertise U2F_V2");
    }

    /**
     * getInfo ctap1 compat mode response must contain U2F_V2 and not FIDO_2_1 (G2).
     * Green before and after the refactor.
     */
    @Test
    public void testGetInfo_Ctap1CompatMode_ResponseContainsU2fV2() throws Exception {
        AuthenticatorAPI.setAppConfig(new AppConfig(null, true));
        // Same as ctap2 test: getInfo delivers via ChainCallback, not DeferredResponseSender.
        AuthenticatorAPI.setUpUvCallback(ctx ->
            ctx.buildResponse(UpUvRequestCtx.Outcome.APPROVED, rsp -> capturedResponse.set(rsp)));

        CtapTxn txn = new CtapTxn();
        txn.setCid(new byte[]{0x01, 0x02, 0x03, 0x04});

        byte[] response = AuthenticatorAPI.getInfo(txn, new HashMap<>());
        if (response == null) response = capturedResponse.get();

        assertNotNull(response, "Must have a response");
        assertEquals(0x00, response[0] & 0xFF, "Status byte must be SUCCESS");

        byte[] cborBody = java.util.Arrays.copyOfRange(response, 1, response.length);
        @SuppressWarnings("unchecked")
        java.util.Map<Integer, Object> info =
            (java.util.Map<Integer, Object>) com.isfs.blekey.util.Cbor.decode(cborBody);
        @SuppressWarnings("unchecked")
        java.util.List<Object> vList = (java.util.List<Object>) info.get(0x01);
        assertTrue(vList.contains("U2F_V2"),
            "ctap1-compat mode getInfo response must advertise U2F_V2");
        assertFalse(vList.contains("FIDO_2_1"),
            "ctap1-compat mode getInfo response must NOT advertise FIDO_2_1");
    }

    // -------------------------------------------------------------------------
    // getAssertion / getNextAssertion tests (G4, G5)
    // -------------------------------------------------------------------------

    /**
     * getAssertion with no callback and UP not set returns OPERATION_DENIED (G5).
     */
    @Test
    public void testGetAssertion_NoCallback_UpNotSet_ReturnsOperationDenied() {
        AuthenticatorAPI.setUpUvCallback(null);

        CtapTxn txn = new CtapTxn();
        txn.setCid(new byte[]{0x01, 0x02, 0x03, 0x04});

        Map<Integer, Object> req = new HashMap<>();
        req.put(0x01, "example.com");

        byte[] response = com.isfs.blekey.authenticator.implapi.GetAssertionHandler
                .getAssertion(txn, req);

        assertNotNull(response, "Must return OPERATION_DENIED, not null");
        assertEquals(Ctap2StatusCode.OPERATION_DENIED.getCode(), response[0] & 0xFF,
            "Must return OPERATION_DENIED when no callback and UP not set");
    }

    /**
     * getNextAssertion with no lock ownership returns OPERATION_DENIED (G4).
     */
    @Test
    public void testGetNextAssertion_NoLockOwnership_ReturnsOperationDenied() {
        CtapTxn txn = new CtapTxn();
        txn.setCid(new byte[]{0x01, 0x02, 0x03, 0x04});

        Map<Integer, Object> req = new HashMap<>();
        req.put(0x01, "example.com");

        byte[] response = com.isfs.blekey.authenticator.implapi.GetAssertionHandler
                .getNextAssertion(txn, req);

        assertNotNull(response, "Must return OPERATION_DENIED, not null");
        assertEquals(Ctap2StatusCode.OPERATION_DENIED.getCode(), response[0] & 0xFF,
            "getNextAssertion must return OPERATION_DENIED when CID does not own the lock");
    }
}
