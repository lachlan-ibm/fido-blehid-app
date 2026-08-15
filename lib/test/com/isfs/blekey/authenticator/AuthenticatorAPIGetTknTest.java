/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import com.isfs.blekey.authenticator.implapi.pin.PinFlowHandler;
import com.isfs.blekey.ctap.Ctap2StatusCode;
import com.isfs.blekey.ctap.CtapTxn;
import com.isfs.blekey.util.FileUtils;
import com.isfs.blekey.util.KeyUtils;

/**
 * Unit tests for {@link AuthenticatorAPI#getTkn} (via reflection).
 *
 * <p>After the UPUV-split refactor, {@code getTkn} has three paths:
 * <ul>
 *   <li><b>Fast path</b> — UP lock owned + IKM cached → synchronous {@code processTkn}.</li>
 *   <li><b>Blocked path</b> — another CID holds the lock → immediate {@code OPERATION_DENIED}.</li>
 *   <li><b>Slow path</b> — lock not owned / IKM absent, but callback registered → deferred.</li>
 * </ul>
 *
 * <p>Validation-error tests exercise the fast path so that
 * {@code processTkn} is reached and the specific error code from
 * {@code validateAndExtractPinHash} / {@code extractClientPublicKey} is returned.
 */
@ExtendWith(MockitoExtension.class)
public class AuthenticatorAPIGetTknTest {

    private static final byte[] TEST_CID = {0x01, 0x02, 0x03, 0x04};

    private java.io.File tempDir;
    private Method getTknMethod;

    @BeforeEach
    public void setUp() throws Exception {
        // Minimal FIDO2_HOME so KeyUtils static initialisation does not fail.
        tempDir = Files.createTempDirectory("fido2-getTkn-test-").toFile();
        tempDir.deleteOnExit();
        System.setProperty("FIDO2_HOME", tempDir.getAbsolutePath());

        // Write a platform.key so KeyUtils.getPlatformKey() (file-based path) works.
        KeyPair platformKeyPair = KeyUtils.generateKeyPair("EC", 256);
        FileUtils.writePrivatePEM(platformKeyPair.getPrivate(),
                new java.io.File(tempDir, "platform.key"));

        // No UpUvCallback registered — slow path returns OPERATION_DENIED.
        AuthenticatorAPI.setUpUvCallback(null);
        AuthenticatorAPI.setDeferredResponseSender(null);

        // Obtain private getTkn(CtapTxn, Map) via reflection.
        getTknMethod = PinFlowHandler.class.getDeclaredMethod(
                "getTkn", CtapTxn.class, Map.class);
        getTknMethod.setAccessible(true);

        // Always start with a clean UP lock.
        resetUpLock();
    }

    @AfterEach
    public void tearDown() throws Exception {
        AuthenticatorAPI.setUpUvCallback(null);
        AuthenticatorAPI.setDeferredResponseSender(null);
        System.clearProperty("FIDO2_HOME");
        resetUpLock();
    }

    // -------------------------------------------------------------------------
    // Fast-path helper
    // -------------------------------------------------------------------------

    /**
     * Acquires the UP lock for {@code cid} and marks IKM as cached on {@code txn} so
     * that the fast path inside {@code getTkn} is taken.
     */
    private void setupFastPath(CtapTxn txn, byte[] cid) throws Exception {
        Class<?> lockClass = Class.forName(
            "com.isfs.blekey.authenticator.UxInteractionLock");
        Method get = lockClass.getDeclaredMethod("get");
        get.setAccessible(true);
        Object lock = get.invoke(null);
        Method tryAcquire = lockClass.getDeclaredMethod("tryAcquire", byte[].class);
        tryAcquire.setAccessible(true);
        // Cast to Object to avoid Java treating byte[] as a varargs array.
        tryAcquire.invoke(lock, (Object) cid);

        // Arm the app-global bio grant so getTkn's isGrantActive() fast-path is taken.
        Method recordBioGrant = lockClass.getDeclaredMethod(
                "recordBioGrant", byte[].class, long.class);
        recordBioGrant.setAccessible(true);
        recordBioGrant.invoke(lock, new byte[32], 15_000L);
    }

    /**
     * Resets the UxInteractionLock singleton to a clean state between tests.
     */
    private static void resetUpLock() throws Exception {
        Class<?> lockClass = Class.forName(
            "com.isfs.blekey.authenticator.UxInteractionLock");
        Method get = lockClass.getDeclaredMethod("get");
        get.setAccessible(true);
        Object lock = get.invoke(null);

        Field ownerCid = lockClass.getDeclaredField("ownerCid");
        ownerCid.setAccessible(true);
        ownerCid.set(lock, null);

        Field expiresAtMs = lockClass.getDeclaredField("expiresAtMs");
        expiresAtMs.setAccessible(true);
        expiresAtMs.set(lock, 0L);

        Field cachedIkm = lockClass.getDeclaredField("cachedIkm");
        cachedIkm.setAccessible(true);
        cachedIkm.set(lock, null);

        Field grantExpiresAtMs = lockClass.getDeclaredField("grantExpiresAtMs");
        grantExpiresAtMs.setAccessible(true);
        grantExpiresAtMs.set(lock, 0L);
    }

    /**
     * Extracts the CTAP2 status byte from the response array (byte[0] after the
     * 7-byte HID-packet framing that the unit test returns directly from the method).
     * The raw response from {@code getTkn} starts with the status byte at index 0.
     */
    private static int statusByte(byte[] response) {
        assertNotNull(response, "Response must not be null");
        // getTkn returns the raw CBOR response (status byte at offset 0).
        return response[0] & 0xFF;
    }

    // -------------------------------------------------------------------------
    // Fast-path validation tests
    // -------------------------------------------------------------------------

    /**
     * Missing pinHashEnc field (key 0x06) → MISSING_PARAMETER.
     * Fast path is set up so processTkn is entered and the validation error is returned.
     */
    @Test
    public void testGetTkn_MissingPinHashEnc() throws Exception {
        CtapTxn txn = new CtapTxn();
        txn.setCid(TEST_CID);
        setupFastPath(txn, TEST_CID);

        Map<Integer, Object> req = new HashMap<>();
        req.put(0x01, 1); // pinProtocol — no pinHashEnc (0x06)

        byte[] response = (byte[]) getTknMethod.invoke(null, txn, req);
        assertNotNull(response, "Should return MISSING_PARAMETER error, not null");
        assertEquals(Ctap2StatusCode.MISSING_PARAMETER.getCode(), statusByte(response),
                "Expected MISSING_PARAMETER status");
    }

    /**
     * pinHashEnc present but wrong type (Integer instead of byte[]) → INVALID_PARAMETER.
     */
    @Test
    public void testGetTkn_InvalidPinHashEncType() throws Exception {
        CtapTxn txn = new CtapTxn();
        txn.setCid(TEST_CID);
        setupFastPath(txn, TEST_CID);

        Map<Integer, Object> req = new HashMap<>();
        req.put(0x06, Integer.valueOf(42)); // wrong type

        byte[] response = (byte[]) getTknMethod.invoke(null, txn, req);
        assertNotNull(response, "Should return INVALID_PARAMETER error, not null");
        assertEquals(Ctap2StatusCode.INVALID_PARAMETER.getCode(), statusByte(response),
                "Expected INVALID_PARAMETER status");
    }

    /**
     * pinHashEnc is valid bytes but client key (0x03) is absent → INVALID_PARAMETER.
     */
    @Test
    public void testGetTkn_NullClientKey() throws Exception {
        CtapTxn txn = new CtapTxn();
        txn.setCid(TEST_CID);
        setupFastPath(txn, TEST_CID);

        Map<Integer, Object> req = new HashMap<>();
        req.put(0x06, new byte[16]); // valid byte[] pinHashEnc
        // 0x03 (keyAgreement) deliberately absent

        byte[] response = (byte[]) getTknMethod.invoke(null, txn, req);
        // extractClientPublicKey returns null → INVALID_PARAMETER
        assertNotNull(response, "Expected a non-null error response");
        assertEquals(Ctap2StatusCode.INVALID_PARAMETER.getCode(), statusByte(response),
                "Expected INVALID_PARAMETER when client key is absent");
    }

    /**
     * Valid pinHashEnc + valid client COSE key but txn has no ECDH key pair (no prior
     * GETKEY) → OTHER from performEcdhKeyAgreement (sharedSecret is null).
     */
    @Test
    public void testGetTkn_NoEcdhKeyPairOnTxn() throws Exception {
        CtapTxn txn = new CtapTxn();
        txn.setCid(TEST_CID);
        setupFastPath(txn, TEST_CID);
        // Intentionally do NOT set an ECDH key pair on txn.

        // Build a minimal valid client COSE key (EC P-256).
        KeyPair clientKp = KeyUtils.generateKeyPair("EC", 256);
        Map<Integer, Object> clientCoseKey = KeyUtils.toCoseKey(clientKp.getPublic());

        Map<Integer, Object> req = new HashMap<>();
        req.put(0x06, new byte[16]);          // pinHashEnc
        req.put(0x03, clientCoseKey);          // keyAgreement

        byte[] response = (byte[]) getTknMethod.invoke(null, txn, req);
        // performEcdhKeyAgreement: txn has no ECDH key pair → returns null → OTHER
        assertNotNull(response, "Expected a non-null error response");
        assertEquals(Ctap2StatusCode.OTHER.getCode(), statusByte(response),
                "Expected OTHER when ECDH key pair is missing from txn");
    }

    // -------------------------------------------------------------------------
    // Slow-path tests (no lock, no callback)
    // -------------------------------------------------------------------------

    /**
     * When the CID does not own the UP lock and no UpUvCallback is registered,
     * getTkn returns OPERATION_DENIED (slow path short-circuit).
     */
    @Test
    public void testGetTkn_NullCallback_ReturnsOperationDenied() throws Exception {
        // No fast-path setup — lock is free, IKM is not cached.
        CtapTxn txn = new CtapTxn();
        txn.setCid(TEST_CID);

        Map<Integer, Object> req = new HashMap<>();
        req.put(0x06, new byte[16]);

        // userPresenceCallback is null (set in setUp)
        byte[] response = (byte[]) getTknMethod.invoke(null, txn, req);
        assertNotNull(response, "Should return OPERATION_DENIED, not null");
        assertEquals(Ctap2StatusCode.OPERATION_DENIED.getCode(), statusByte(response),
                "Expected OPERATION_DENIED when no callback is registered");
    }

    // -------------------------------------------------------------------------
    // New tests — plan §10.1
    // -------------------------------------------------------------------------

    /**
     * When another CID owns the UxInteractionLock and a callback is registered,
     * getTkn for a different CID must return CHANNEL_BUSY immediately — not deferred.
     * Regression guard for G4.
     */
    @Test
    public void testGetTkn_OtherCidHoldsLock_ReturnsChannelBusy() throws Exception {
        byte[] OTHER_CID = {0x0A, 0x0B, 0x0C, 0x0D};

        Class<?> lockClass = Class.forName("com.isfs.blekey.authenticator.UxInteractionLock");
        Method getLock = lockClass.getDeclaredMethod("get");
        getLock.setAccessible(true);
        Object lock = getLock.invoke(null);
        Method tryAcquire = lockClass.getDeclaredMethod("tryAcquire", byte[].class);
        tryAcquire.setAccessible(true);
        tryAcquire.invoke(lock, (Object) OTHER_CID);

        // Register a no-op callback so the null-callback guard is not hit first.
        AuthenticatorAPI.setUpUvCallback(ctx -> {});

        CtapTxn txn = new CtapTxn();
        txn.setCid(TEST_CID);
        // grant not active → fast-path skipped → falls through to tryAcquire → CHANNEL_BUSY

        Map<Integer, Object> req = new HashMap<>();
        req.put(0x06, new byte[16]);

        byte[] response = (byte[]) getTknMethod.invoke(null, txn, req);
        assertNotNull(response, "Must return CHANNEL_BUSY, not null");
        assertEquals(Ctap2StatusCode.CHANNEL_BUSY.getCode(), statusByte(response),
                "Expected CHANNEL_BUSY when another CID owns the lock");
    }

    /**
     * POST-REFACTOR (plan §4.2): getKey must return SUCCESS with no UpUvCallback registered.
     * PRE-REFACTOR: returns OPERATION_DENIED — this test is the acceptance criterion for §4.2.
     */
    @Test
    public void testGetKey_NoCallback_PostRefactor_ReturnsSuccess() throws Exception {
        // upUvCallback is null from setUp.
        CtapTxn txn = new CtapTxn();
        txn.setCid(TEST_CID);

        Method pinRequest = PinFlowHandler.class
                .getDeclaredMethod("pinRequest", CtapTxn.class, Map.class);
        pinRequest.setAccessible(true);

        Map<Integer, Object> req = new HashMap<>();
        req.put(2, 0x02); // subCommand = GETKEY

        byte[] response = (byte[]) pinRequest.invoke(null, txn, req);
        assertNotNull(response, "getKey must return a response synchronously after refactor");
        assertEquals(0x00, statusByte(response),
                "getKey must return SUCCESS (0x00) after §4.2 refactor");
    }

    /**
     * POST-REFACTOR (plan §4.2): getKey must return SUCCESS even when another CID holds
     * the UxInteractionLock. PRE-REFACTOR: returns CHANNEL_BUSY.
     */
    @Test
    public void testGetKey_OtherCidHoldsLock_PostRefactor_ReturnsSuccess() throws Exception {
        byte[] OTHER_CID = {0x0A, 0x0B, 0x0C, 0x0D};

        Class<?> lockClass = Class.forName("com.isfs.blekey.authenticator.UxInteractionLock");
        Method getLock = lockClass.getDeclaredMethod("get");
        getLock.setAccessible(true);
        Object lock = getLock.invoke(null);
        Method tryAcquire = lockClass.getDeclaredMethod("tryAcquire", byte[].class);
        tryAcquire.setAccessible(true);
        tryAcquire.invoke(lock, (Object) OTHER_CID);

        AuthenticatorAPI.setUpUvCallback(ctx -> {}); // stub so pre-refactor null-guard is not hit

        CtapTxn txn = new CtapTxn();
        txn.setCid(TEST_CID);

        Method pinRequest = PinFlowHandler.class
                .getDeclaredMethod("pinRequest", CtapTxn.class, Map.class);
        pinRequest.setAccessible(true);

        Map<Integer, Object> req = new HashMap<>();
        req.put(2, 0x02); // GETKEY

        byte[] response = (byte[]) pinRequest.invoke(null, txn, req);
        assertNotNull(response, "getKey must not return null when lock held by another CID after refactor");
        assertEquals(0x00, statusByte(response),
                "getKey must return SUCCESS regardless of lock state after §4.2 refactor");
    }

    /**
     * executeGetKey(txn) must store the ephemeral ECDH key pair on the txn and return
     * a SUCCESS response whose CBOR body contains a COSE key at map key 0x01.
     */
    @Test
    public void testExecuteGetKey_StoresEcdhKeyPairAndReturnsCoseKey() throws Exception {
        CtapTxn txn = new CtapTxn();

        byte[] response = PinFlowHandler.executeGetKey(txn);

        assertNotNull(response, "executeGetKey must return a non-null response");
        assertEquals(0x00, response[0] & 0xFF, "executeGetKey must return status byte 0x00");
        assertNotNull(txn.getEcdhKeyPair(),
                "executeGetKey must store the ephemeral ECDH key pair on txn");

        byte[] cborBody = java.util.Arrays.copyOfRange(response, 1, response.length);
        @SuppressWarnings("unchecked")
        java.util.Map<Integer, Object> decoded =
                (java.util.Map<Integer, Object>) com.isfs.blekey.util.Cbor.decode(cborBody);
        assertNotNull(decoded, "Response CBOR must decode to a map");
        assertTrue(decoded.containsKey(0x01),
                "CBOR map must contain key 0x01 (keyAgreement)");
        assertTrue(decoded.get(0x01) instanceof java.util.Map,
                "keyAgreement value must itself be a COSE key map");
    }
}
