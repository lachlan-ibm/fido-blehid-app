/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.authenticator.implapi.pin;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import com.isfs.blekey.authenticator.AuthenticatorAPI;
import com.isfs.blekey.authenticator.UpUvRequestCtx;
import com.isfs.blekey.authenticator.UxInteractionLock;
import com.isfs.blekey.ctap.Ctap2StatusCode;
import com.isfs.blekey.ctap.CtapTxn;
import com.isfs.blekey.data.Passkey;
import com.isfs.blekey.util.Cbor;
import com.isfs.blekey.util.KeyUtils;
import com.isfs.blekey.util.KeystoreManager;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import javax.crypto.NoSuchPaddingException;

/**
 * End-to-end and branch tests for {@link PinFlowHandler}, exercising the PIN/UV
 * token ceremonies with both PIN/UV auth protocol 1 (CTAP 2.3 §6.5.6) and
 * protocol 2 (§6.5.7).
 *
 * <p>The "platform" side of each exchange is played by {@link PinClient}, which uses
 * the protocol implementation to derive the shared secret, encrypt the PIN hash and
 * decrypt the returned token.</p>
 */
public class PinFlowHandlerTest {

    private static final int SUB_GETRETRY = 0x01;
    private static final int SUB_GETKEY = 0x02;
    private static final int SUB_GETTKN = 0x05;
    private static final int SUB_GETTKNUV = 0x06;
    private static final int SUB_GETUVRETRY = 0x07;
    private static final int SUB_GETTKNPIN_PERMS = 0x09;
    private static final int SUB_GETTKNUV_PERMS = 0x0A;

    private static final int PERMS_MC_GA = 0x03;
    private static final int PERMS_CUSTOM = 0x0C; // be | cm

    private static final AtomicInteger CID_SEQ = new AtomicInteger(0x1000);

    private File home;
    private byte[] pinHash;      // 32 bytes
    private byte[] lowerHash;    // 16 bytes — what the platform sends encrypted
    private KeystoreManager prevKsm;
    private PublicKey prevRootPub;
    private PrivateKey prevRootPriv;

    // -------------------------------------------------------------------------
    // Fixture
    // -------------------------------------------------------------------------

    @BeforeEach
    public void setUp() throws Exception {
        home = Files.createTempDirectory("pinflow-test-").toFile();
        home.deleteOnExit();
        System.setProperty("FIDO2_HOME", home.getAbsolutePath());

        prevKsm = KeyUtils.getKeystoreManager();
        prevRootPub = (PublicKey) getRootField("rootPublicKey");
        prevRootPriv = (PrivateKey) getRootField("rootPrivateKey");

        KeystoreManager ksm = mock(KeystoreManager.class);
        when(ksm.isKeystoreAvailable()).thenReturn(false);
        KeyUtils.setKeystoreManager(ksm);   // also invalidates the cached StashCipher
        KeyPair root = KeyUtils.generateKeyPair("EC", 256);
        setRootField("rootPublicKey", root.getPublic());
        setRootField("rootPrivateKey", root.getPrivate());

        pinHash = new byte[32];
        new SecureRandom().nextBytes(pinHash);
        lowerHash = Arrays.copyOf(pinHash, 16);
        File pk = new File(home, "pinflow.passkey");
        pk.deleteOnExit();
        new File(home, "pinflow.stash").deleteOnExit();
        assertNotNull(Passkey.generatePasskey(pinHash, pk), "test passkey must be created");

        resetState();
    }

    @AfterEach
    public void tearDown() throws Exception {
        resetState();
        System.clearProperty("FIDO2_HOME");
        setRootField("rootPublicKey", prevRootPub);
        setRootField("rootPrivateKey", prevRootPriv);
        KeyUtils.setKeystoreManager(prevKsm);
    }

    private static void resetState() {
        AuthenticatorAPI.setUpUvCallback(null);
        AuthenticatorAPI.setDeferredResponseSender(null);
        UxInteractionLock.get().reset();
        PinSessionRegistry.resetPinRetries();
    }

    private static Object getRootField(String name) throws Exception {
        Field f = KeyUtils.class.getDeclaredField(name);
        f.setAccessible(true);
        return f.get(null);
    }

    private static void setRootField(String name, Object v) throws Exception {
        Field f = KeyUtils.class.getDeclaredField(name);
        f.setAccessible(true);
        f.set(null, v);
    }

    /** Unique CID per call: PinSessionRegistry keys its maps by byte[] identity. */
    private static CtapTxn newTxn() {
        int n = CID_SEQ.incrementAndGet();
        CtapTxn txn = new CtapTxn();
        txn.setCid(new byte[] {0x7E, (byte) (n >> 16), (byte) (n >> 8), (byte) n});
        return txn;
    }

    private static void armGrant() {
        UxInteractionLock.get().recordBioGrant(new byte[32], 30_000L);
    }

    private static int status(byte[] rsp) {
        assertNotNull(rsp, "response must not be null");
        return rsp[0] & 0xFF;
    }

    private static void assertStatus(Ctap2StatusCode expected, byte[] rsp) {
        assertEquals(expected.getCode(), status(rsp), "expected " + expected);
    }

    @SuppressWarnings("unchecked")
    private static Map<Integer, Object> decodeBody(byte[] rsp) {
        assertEquals(0, status(rsp), "expected SUCCESS");
        return (Map<Integer, Object>) Cbor.decode(Arrays.copyOfRange(rsp, 1, rsp.length));
    }

    /** Platform-side view of a PIN/UV auth protocol exchange. */
    private static final class PinClient {
        final int protocolId;
        final PinUvAuthProtocol proto;
        final KeyPair keyPair;
        byte[] sharedSecret;

        PinClient(int protocolId) throws Exception {
            this.protocolId = protocolId;
            this.proto = PinUvAuthProtocol.forId(protocolId);
            this.keyPair = KeyUtils.generateKeyPair("EC", 256);
        }

        void agree(CtapTxn txn) throws Exception {
            sharedSecret = proto.decapsulate(txn.getEcdhKeyPair().getPublic(), keyPair.getPrivate());
        }

        Map<Integer, Object> request(int sub, byte[] pinHashEnc, Integer permissions) {
            Map<Integer, Object> req = new HashMap<>();
            req.put(0x01, protocolId);
            req.put(0x02, sub);
            req.put(0x03, KeyUtils.toCoseKey(keyPair.getPublic(), -25));
            if (pinHashEnc != null) req.put(0x06, pinHashEnc);
            if (permissions != null) req.put(0x09, permissions);
            return req;
        }

        byte[] encryptedPinHash(byte[] hash) throws Exception {
            return proto.encrypt(sharedSecret, hash);
        }

        byte[] decryptToken(byte[] rsp) throws Exception {
            byte[] enc = (byte[]) decodeBody(rsp).get(0x02);
            assertNotNull(enc, "pinUvAuthToken (0x02) missing");
            assertEquals(protocolId == 1 ? 32 : 48, enc.length,
                "protocol " + protocolId + " ciphertext length");
            byte[] token = proto.decrypt(sharedSecret, enc);
            assertEquals(32, token.length);
            return token;
        }
    }

    /** Issues GETKEY through pinRequest and derives the platform-side shared secret. */
    private PinClient handshake(CtapTxn txn, int protocolId) throws Exception {
        Map<Integer, Object> keyReq = new HashMap<>();
        keyReq.put(0x01, protocolId);
        keyReq.put(0x02, SUB_GETKEY);
        assertEquals(0, status(PinFlowHandler.pinRequest(txn, keyReq)));
        assertNotNull(txn.getEcdhKeyPair());
        PinClient c = new PinClient(protocolId);
        c.agree(txn);
        return c;
    }

    /** Runs {@code call} with a callback that approves and a sender that captures the response. */
    private static byte[] runDeferred(Supplier<byte[]> call) {
        AtomicReference<byte[]> deferred = new AtomicReference<>();
        AuthenticatorAPI.setDeferredResponseSender((t, r) -> deferred.set(r));
        AuthenticatorAPI.setUpUvCallback(
            ctx -> ctx.buildResponse(UpUvRequestCtx.Outcome.APPROVED, e -> {}));
        assertNull(call.get(), "call must defer");
        return deferred.get();
    }

    private static Object invokePrivate(String name, Class<?>[] types, Object[] args) throws Exception {
        Method m = PinFlowHandler.class.getDeclaredMethod(name, types);
        m.setAccessible(true);
        try {
            return m.invoke(null, args);
        } catch (InvocationTargetException e) {
            throw (Exception) e.getCause();
        }
    }

    // -------------------------------------------------------------------------
    // Successful token issuance — protocol 1 and protocol 2
    // -------------------------------------------------------------------------

    private void assertPinTokenIssued(int protocolId, int sub, Integer perms, int expectedPerms)
            throws Exception {
        armGrant();
        CtapTxn txn = newTxn();
        PinClient c = handshake(txn, protocolId);

        byte[] rsp = PinFlowHandler.pinRequest(txn,
            c.request(sub, c.encryptedPinHash(lowerHash), perms));

        byte[] token = c.decryptToken(rsp);
        assertArrayEquals(token, txn.getPinAuthTkn());
        assertEquals(protocolId, txn.getPinUvAuthProtocol());
        assertArrayEquals(pinHash, txn.getPinHash(), "full 32-byte PIN hash reconstructed");
        assertEquals(expectedPerms, PinSessionRegistry.getPermissions(txn.getCid()));
        assertNull(txn.getEcdhKeyPair(), "ECDH key pair must be erased after use");
        assertEquals(PinSessionRegistry.MAX_PIN_RETRIES, PinSessionRegistry.getPinRetries());
    }

    @Test
    public void getTkn_protocol1_issuesTokenWithMcGa() throws Exception {
        assertPinTokenIssued(1, SUB_GETTKN, null, PERMS_MC_GA);
    }

    @Test
    public void getTkn_protocol2_issuesTokenWithMcGa() throws Exception {
        assertPinTokenIssued(2, SUB_GETTKN, null, PERMS_MC_GA);
    }

    @Test
    public void getTknWithPinPermissions_protocol1_issuesTokenWithRequestedPerms() throws Exception {
        assertPinTokenIssued(1, SUB_GETTKNPIN_PERMS, PERMS_CUSTOM, PERMS_CUSTOM);
    }

    @Test
    public void getTknWithPinPermissions_protocol2_issuesTokenWithRequestedPerms() throws Exception {
        assertPinTokenIssued(2, SUB_GETTKNPIN_PERMS, PERMS_CUSTOM, PERMS_CUSTOM);
    }

    private void assertDeferredPinToken(int protocolId, int sub, Integer perms, int expectedPerms)
            throws Exception {
        CtapTxn txn = newTxn();
        PinClient c = handshake(txn, protocolId);           // no callback yet: GETKEY fires nothing
        Map<Integer, Object> req = c.request(sub, c.encryptedPinHash(lowerHash), perms);

        byte[] rsp = runDeferred(() -> PinFlowHandler.pinRequest(txn, req));

        byte[] token = c.decryptToken(rsp);
        assertArrayEquals(token, txn.getPinAuthTkn());
        assertEquals(expectedPerms, PinSessionRegistry.getPermissions(txn.getCid()));
        assertTrue(txn.isUserPresent());
    }

    @Test
    public void getTkn_noGrant_protocol1_deferredThroughUpUvGate() throws Exception {
        assertDeferredPinToken(1, SUB_GETTKN, null, PERMS_MC_GA);
    }

    @Test
    public void getTkn_noGrant_protocol2_deferredThroughUpUvGate() throws Exception {
        assertDeferredPinToken(2, SUB_GETTKN, null, PERMS_MC_GA);
    }

    @Test
    public void getTknWithPinPermissions_noGrant_protocol1_deferredThroughUpUvGate() throws Exception {
        assertDeferredPinToken(1, SUB_GETTKNPIN_PERMS, PERMS_CUSTOM, PERMS_CUSTOM);
    }

    @Test
    public void getTknWithPinPermissions_noGrant_protocol2_deferredThroughUpUvGate() throws Exception {
        assertDeferredPinToken(2, SUB_GETTKNPIN_PERMS, PERMS_CUSTOM, PERMS_CUSTOM);
    }

    private void assertUvTokenIssued(int protocolId, int sub, Integer perms, int expectedPerms)
            throws Exception {
        CtapTxn txn = newTxn();
        PinClient c = handshake(txn, protocolId);
        Map<Integer, Object> req = c.request(sub, null, perms);
        PinSessionRegistry.decrementUvRetries();            // must be reset by a successful UV

        byte[] rsp = runDeferred(() -> PinFlowHandler.pinRequest(txn, req));

        byte[] token = c.decryptToken(rsp);
        assertArrayEquals(token, txn.getPinAuthTkn());
        assertEquals(protocolId, txn.getPinUvAuthProtocol());
        assertEquals(expectedPerms, PinSessionRegistry.getPermissions(txn.getCid()));
        assertEquals(PinSessionRegistry.MAX_UV_RETRIES, PinSessionRegistry.getUvRetries());
        assertNull(txn.getEcdhKeyPair());
    }

    @Test
    public void getTknBuiltIn_protocol1_issuesUvTokenWithMcGa() throws Exception {
        assertUvTokenIssued(1, SUB_GETTKNUV, null, PERMS_MC_GA);
    }

    @Test
    public void getTknBuiltIn_protocol2_issuesUvTokenWithMcGa() throws Exception {
        assertUvTokenIssued(2, SUB_GETTKNUV, null, PERMS_MC_GA);
    }

    @Test
    public void getTknBuiltInWithPermissions_protocol1_issuesUvTokenWithRequestedPerms() throws Exception {
        assertUvTokenIssued(1, SUB_GETTKNUV_PERMS, PERMS_CUSTOM, PERMS_CUSTOM);
    }

    @Test
    public void getTknBuiltInWithPermissions_protocol2_issuesUvTokenWithRequestedPerms() throws Exception {
        assertUvTokenIssued(2, SUB_GETTKNUV_PERMS, PERMS_CUSTOM, PERMS_CUSTOM);
    }

    @Test
    public void protocol1AndProtocol2Tokens_differInFormat() throws Exception {
        armGrant();
        for (int p = 1; p <= 2; p++) {
            CtapTxn txn = newTxn();
            PinClient c = handshake(txn, p);
            byte[] rsp = PinFlowHandler.pinRequest(txn,
                c.request(SUB_GETTKN, c.encryptedPinHash(lowerHash), null));
            byte[] enc = (byte[]) decodeBody(rsp).get(0x02);
            assertEquals(p == 1 ? 32 : 48, enc.length);     // p2 carries a 16-byte IV prefix
        }
    }

    // -------------------------------------------------------------------------
    // PIN verification failures — protocol 1 and protocol 2
    // -------------------------------------------------------------------------

    private void assertWrongPin(int protocolId) throws Exception {
        armGrant();
        CtapTxn txn = newTxn();
        PinClient c = handshake(txn, protocolId);

        byte[] rsp = PinFlowHandler.pinRequest(txn,
            c.request(SUB_GETTKN, c.encryptedPinHash(new byte[16]), null));

        assertStatus(Ctap2StatusCode.PIN_AUTH_INVALID, rsp);
        assertEquals(PinSessionRegistry.MAX_PIN_RETRIES - 1, PinSessionRegistry.getPinRetries());
        assertNull(txn.getPinAuthTkn());
    }

    @Test
    public void getTkn_wrongPin_protocol1_decrementsRetries() throws Exception {
        assertWrongPin(1);
    }

    @Test
    public void getTkn_wrongPin_protocol2_decrementsRetries() throws Exception {
        assertWrongPin(2);
    }

    private void assertWrongPinLastRetry(int protocolId) throws Exception {
        armGrant();
        for (int i = 0; i < PinSessionRegistry.MAX_PIN_RETRIES - 1; i++) {
            PinSessionRegistry.decrementRetries();
        }
        CtapTxn txn = newTxn();
        PinClient c = handshake(txn, protocolId);

        byte[] rsp = PinFlowHandler.pinRequest(txn,
            c.request(SUB_GETTKN, c.encryptedPinHash(new byte[16]), null));

        assertStatus(Ctap2StatusCode.PIN_BLOCKED, rsp);
        assertEquals(0, PinSessionRegistry.getPinRetries());
    }

    @Test
    public void getTkn_wrongPinOnLastRetry_protocol1_returnsPinBlocked() throws Exception {
        assertWrongPinLastRetry(1);
    }

    @Test
    public void getTkn_wrongPinOnLastRetry_protocol2_returnsPinBlocked() throws Exception {
        assertWrongPinLastRetry(2);
    }

    private void assertPinHashWrongLength(int protocolId) throws Exception {
        armGrant();
        CtapTxn txn = newTxn();
        PinClient c = handshake(txn, protocolId);

        byte[] rsp = PinFlowHandler.pinRequest(txn,
            c.request(SUB_GETTKN, c.encryptedPinHash(new byte[32]), null));

        assertStatus(Ctap2StatusCode.PIN_AUTH_INVALID, rsp);
        assertEquals(PinSessionRegistry.MAX_PIN_RETRIES, PinSessionRegistry.getPinRetries(),
            "length mismatch must not consume a retry");
    }

    @Test
    public void getTkn_decryptedPinHashNot16Bytes_protocol1() throws Exception {
        assertPinHashWrongLength(1);
    }

    @Test
    public void getTkn_decryptedPinHashNot16Bytes_protocol2() throws Exception {
        assertPinHashWrongLength(2);
    }

    private void assertMalformedCiphertext(int protocolId) throws Exception {
        armGrant();
        CtapTxn txn = newTxn();
        PinClient c = handshake(txn, protocolId);

        // 15 bytes: not a block multiple (p1) / shorter than the IV (p2)
        byte[] rsp = PinFlowHandler.pinRequest(txn, c.request(SUB_GETTKN, new byte[15], null));

        assertStatus(Ctap2StatusCode.PIN_AUTH_INVALID, rsp);
    }

    @Test
    public void getTkn_malformedPinHashEnc_protocol1() throws Exception {
        assertMalformedCiphertext(1);
    }

    @Test
    public void getTkn_malformedPinHashEnc_protocol2() throws Exception {
        assertMalformedCiphertext(2);
    }

    @Test
    public void getTkn_protocol2PinHashEncUsingProtocol1Format_isRejected() throws Exception {
        // Platform negotiated protocol 2 but sends a protocol-1 (no IV prefix) ciphertext:
        // the first 16 bytes are taken as IV and the remainder is 0 bytes → wrong length.
        armGrant();
        CtapTxn txn = newTxn();
        PinClient c = handshake(txn, 2);
        byte[] p1Style = new byte[16];

        byte[] rsp = PinFlowHandler.pinRequest(txn, c.request(SUB_GETTKN, p1Style, null));

        assertStatus(Ctap2StatusCode.PIN_AUTH_INVALID, rsp);
    }

    // -------------------------------------------------------------------------
    // Request validation — processTkn / processTknWithPermissions
    // -------------------------------------------------------------------------

    private void assertProcessValidation(int protocolId, boolean withPermissions) throws Exception {
        CtapTxn txn = newTxn();
        PinClient c = handshake(txn, protocolId);

        // missing pinHashEnc
        Map<Integer, Object> r = c.request(SUB_GETTKN, null, null);
        assertStatus(Ctap2StatusCode.MISSING_PARAMETER, process(txn, r, withPermissions));

        // wrong type for pinHashEnc
        r = c.request(SUB_GETTKN, null, null);
        r.put(0x06, Integer.valueOf(7));
        assertStatus(Ctap2StatusCode.INVALID_PARAMETER, process(txn, r, withPermissions));

        // missing platform key agreement key
        r = c.request(SUB_GETTKN, new byte[16], null);
        r.remove(0x03);
        assertStatus(Ctap2StatusCode.INVALID_PARAMETER, process(txn, r, withPermissions));

        // no ECDH key pair on the txn (GETKEY not issued)
        CtapTxn bare = newTxn();
        r = c.request(SUB_GETTKN, new byte[16], null);
        assertStatus(Ctap2StatusCode.OTHER, process(bare, r, withPermissions));
    }

    private static byte[] process(CtapTxn txn, Map<Integer, Object> req, boolean withPermissions) {
        return withPermissions
            ? PinFlowHandler.processTknWithPermissions(txn, req, PERMS_CUSTOM)
            : PinFlowHandler.processTkn(txn, req);
    }

    @Test
    public void processTkn_validation_protocol1() throws Exception {
        assertProcessValidation(1, false);
    }

    @Test
    public void processTkn_validation_protocol2() throws Exception {
        assertProcessValidation(2, false);
    }

    @Test
    public void processTknWithPermissions_validation_protocol1() throws Exception {
        assertProcessValidation(1, true);
    }

    @Test
    public void processTknWithPermissions_validation_protocol2() throws Exception {
        assertProcessValidation(2, true);
    }

    // -------------------------------------------------------------------------
    // generateUvToken / generateUvTokenWithPermissions error branches
    // -------------------------------------------------------------------------

    private void assertUvGenerationErrors(int protocolId, boolean withPermissions) throws Exception {
        CtapTxn txn = newTxn();
        PinClient c = handshake(txn, protocolId);

        // missing client key
        Map<Integer, Object> r = c.request(SUB_GETTKNUV, null, null);
        r.remove(0x03);
        assertStatus(Ctap2StatusCode.MISSING_PARAMETER, generateUv(txn, r, withPermissions));
        assertNotNull(txn.getEcdhKeyPair(), "key pair untouched when client key missing");

        // no ECDH key pair
        CtapTxn bare = newTxn();
        r = c.request(SUB_GETTKNUV, null, null);
        assertStatus(Ctap2StatusCode.OTHER, generateUv(bare, r, withPermissions));
    }

    private static byte[] generateUv(CtapTxn txn, Map<Integer, Object> req, boolean withPermissions) {
        return withPermissions
            ? PinFlowHandler.generateUvTokenWithPermissions(txn, req, PERMS_CUSTOM)
            : PinFlowHandler.generateUvToken(txn, req);
    }

    @Test
    public void generateUvToken_errors_protocol1() throws Exception {
        assertUvGenerationErrors(1, false);
    }

    @Test
    public void generateUvToken_errors_protocol2() throws Exception {
        assertUvGenerationErrors(2, false);
    }

    @Test
    public void generateUvTokenWithPermissions_errors_protocol1() throws Exception {
        assertUvGenerationErrors(1, true);
    }

    @Test
    public void generateUvTokenWithPermissions_errors_protocol2() throws Exception {
        assertUvGenerationErrors(2, true);
    }

    private void assertUvCryptoFailure(boolean withPermissions) throws Exception {
        CtapTxn txn = newTxn();
        assertEquals(0, status(PinFlowHandler.executeGetKey(txn)));
        PinClient c = new PinClient(2);
        Map<Integer, Object> req = c.request(SUB_GETTKNUV, null, null);

        PinUvAuthProtocol proto = mock(PinUvAuthProtocol.class);
        when(proto.id()).thenReturn(2);
        when(proto.decapsulate(any(), any())).thenReturn(new byte[64]);
        when(proto.encrypt(any(), any())).thenThrow(new InvalidKeyException("boom"));

        byte[] rsp;
        try (MockedStatic<PinUvAuthProtocol> ms = mockStatic(PinUvAuthProtocol.class)) {
            ms.when(() -> PinUvAuthProtocol.forId(any())).thenReturn(proto);
            rsp = generateUv(txn, req, withPermissions);
        }

        assertStatus(Ctap2StatusCode.INVALID_PARAMETER, rsp);
        assertEquals(PinSessionRegistry.MAX_UV_RETRIES - 1, PinSessionRegistry.getUvRetries(),
            "crypto failure consumes a UV retry");
    }

    @Test
    public void generateUvToken_cryptoFailure_decrementsUvRetries() throws Exception {
        assertUvCryptoFailure(false);
    }

    @Test
    public void generateUvTokenWithPermissions_cryptoFailure_decrementsUvRetries() throws Exception {
        assertUvCryptoFailure(true);
    }

    // -------------------------------------------------------------------------
    // pinRequest routing and parameter validation
    // -------------------------------------------------------------------------

    @Test
    public void pinRequest_getRetry_returnsPinRetries() throws Exception {
        Map<Integer, Object> req = new HashMap<>();
        req.put(0x02, SUB_GETRETRY);

        Map<Integer, Object> body = decodeBody(PinFlowHandler.pinRequest(null, req));
        assertEquals(PinSessionRegistry.MAX_PIN_RETRIES, ((Number) body.get(0x03)).intValue());

        PinSessionRegistry.decrementRetries();
        body = decodeBody(PinFlowHandler.pinRequest(null, req));
        assertEquals(PinSessionRegistry.MAX_PIN_RETRIES - 1, ((Number) body.get(0x03)).intValue());
    }

    @Test
    public void pinRequest_getUvRetry_returnsUvRetries() throws Exception {
        Map<Integer, Object> req = new HashMap<>();
        req.put(0x02, SUB_GETUVRETRY);

        Map<Integer, Object> body = decodeBody(PinFlowHandler.pinRequest(null, req));
        assertEquals(PinSessionRegistry.MAX_UV_RETRIES, ((Number) body.get(0x05)).intValue());

        PinSessionRegistry.decrementUvRetries();
        body = decodeBody(PinFlowHandler.pinRequest(null, req));
        assertEquals(PinSessionRegistry.MAX_UV_RETRIES - 1, ((Number) body.get(0x05)).intValue());
    }

    @Test
    public void pinRequest_unsupportedSubCommands_returnInvalidCommand() {
        for (int sub : new int[] {0x03 /* SETPIN */, 0x04 /* CHANGEPIN */, 0x08, 0xFF}) {
            Map<Integer, Object> req = new HashMap<>();
            req.put(0x02, sub);
            assertStatus(Ctap2StatusCode.INVALID_COMMAND, PinFlowHandler.pinRequest(newTxn(), req));
        }
        assertStatus(Ctap2StatusCode.INVALID_COMMAND,
            PinFlowHandler.pinRequest(newTxn(), new HashMap<>()));  // subcommand absent
    }

    private static final int[] PROTOCOL_CHECKED_SUBS = {
        SUB_GETKEY, SUB_GETTKN, SUB_GETTKNUV, SUB_GETTKNPIN_PERMS, SUB_GETTKNUV_PERMS
    };

    @Test
    public void pinRequest_missingProtocol_returnsMissingParameter() {
        for (int sub : PROTOCOL_CHECKED_SUBS) {
            Map<Integer, Object> req = new HashMap<>();
            req.put(0x02, sub);
            assertStatus(Ctap2StatusCode.MISSING_PARAMETER,
                PinFlowHandler.pinRequest(newTxn(), req));
        }
    }

    @Test
    public void pinRequest_unsupportedProtocol_returnsInvalidParameter() {
        for (int badProtocol : new int[] {0, 3}) {
            for (int sub : PROTOCOL_CHECKED_SUBS) {
                Map<Integer, Object> req = new HashMap<>();
                req.put(0x01, badProtocol);
                req.put(0x02, sub);
                assertStatus(Ctap2StatusCode.INVALID_PARAMETER,
                    PinFlowHandler.pinRequest(newTxn(), req));
            }
        }
    }

    @Test
    public void pinRequest_nonIntegerProtocol_returnsInvalidParameter() {
        Map<Integer, Object> req = new HashMap<>();
        req.put(0x01, "2");
        req.put(0x02, SUB_GETTKN);
        assertStatus(Ctap2StatusCode.INVALID_PARAMETER, PinFlowHandler.pinRequest(newTxn(), req));
    }

    @Test
    public void pinRequest_nullTxn_returnsOperationDenied() {
        for (int protocol = 1; protocol <= 2; protocol++) {
            for (int sub : new int[] {SUB_GETTKN, SUB_GETTKNUV, SUB_GETTKNPIN_PERMS, SUB_GETTKNUV_PERMS}) {
                Map<Integer, Object> req = new HashMap<>();
                req.put(0x01, protocol);
                req.put(0x02, sub);
                assertStatus(Ctap2StatusCode.OPERATION_DENIED, PinFlowHandler.pinRequest(null, req));
            }
        }
    }

    @Test
    public void getTknWithPinPermissions_invalidPermissions() {
        for (int protocol = 1; protocol <= 2; protocol++) {
            Map<Integer, Object> req = new HashMap<>();
            req.put(0x01, protocol);
            req.put(0x02, SUB_GETTKNPIN_PERMS);
            assertStatus(Ctap2StatusCode.MISSING_PARAMETER,
                PinFlowHandler.pinRequest(newTxn(), req));

            req.put(0x09, "mc");
            assertStatus(Ctap2StatusCode.MISSING_PARAMETER,
                PinFlowHandler.pinRequest(newTxn(), req));

            req.put(0x09, 0);
            assertStatus(Ctap2StatusCode.INVALID_PARAMETER,
                PinFlowHandler.pinRequest(newTxn(), req));
        }
    }

    @Test
    public void getTknBuiltInWithPermissions_invalidPermissions() {
        for (int protocol = 1; protocol <= 2; protocol++) {
            Map<Integer, Object> req = new HashMap<>();
            req.put(0x01, protocol);
            req.put(0x02, SUB_GETTKNUV_PERMS);
            assertStatus(Ctap2StatusCode.MISSING_PARAMETER,
                PinFlowHandler.pinRequest(newTxn(), req));

            req.put(0x09, new byte[] {1});
            assertStatus(Ctap2StatusCode.MISSING_PARAMETER,
                PinFlowHandler.pinRequest(newTxn(), req));

            req.put(0x09, 0);
            assertStatus(Ctap2StatusCode.INVALID_PARAMETER,
                PinFlowHandler.pinRequest(newTxn(), req));
        }
    }

    @Test
    public void builtInUv_exhaustedRetries_returnsUvBlocked() {
        for (int i = 0; i < PinSessionRegistry.MAX_UV_RETRIES; i++) {
            PinSessionRegistry.decrementUvRetries();
        }
        for (int protocol = 1; protocol <= 2; protocol++) {
            Map<Integer, Object> req = new HashMap<>();
            req.put(0x01, protocol);
            req.put(0x02, SUB_GETTKNUV);
            assertStatus(Ctap2StatusCode.UV_BLOCKED, PinFlowHandler.pinRequest(newTxn(), req));

            req.put(0x02, SUB_GETTKNUV_PERMS);
            req.put(0x09, PERMS_MC_GA);
            assertStatus(Ctap2StatusCode.UV_BLOCKED, PinFlowHandler.pinRequest(newTxn(), req));
        }
    }

    // -------------------------------------------------------------------------
    // executeGetKey
    // -------------------------------------------------------------------------

    @Test
    public void executeGetKey_nullTxn_returnsCoseKey() {
        Map<Integer, Object> body = decodeBody(PinFlowHandler.executeGetKey(null));
        assertTrue(body.get(0x01) instanceof Map);
    }

    @Test
    public void executeGetKey_keyGenerationFailure_returnsOther() {
        CtapTxn txn = newTxn();
        try (MockedStatic<KeyUtils> ms = mockStatic(KeyUtils.class, CALLS_REAL_METHODS)) {
            ms.when(() -> KeyUtils.generateKeyPair(anyString(), anyInt()))
              .thenThrow(new RuntimeException("no entropy"));
            assertStatus(Ctap2StatusCode.OTHER, PinFlowHandler.executeGetKey(txn));
        }
        assertNull(txn.getEcdhKeyPair());
    }

    @Test
    public void executeGetKey_idleWithCallback_firesUpUvRequest() {
        AtomicReference<UpUvRequestCtx> seen = new AtomicReference<>();
        AuthenticatorAPI.setUpUvCallback(seen::set);
        CtapTxn txn = newTxn();

        assertEquals(0, status(PinFlowHandler.executeGetKey(txn)));

        assertNotNull(seen.get(), "UP/UV callback must fire for an idle lock");
        assertSame(txn, seen.get().getTxn());
        assertTrue(seen.get().requiresBiometric());
        assertEquals(UxInteractionLock.UxState.IN_PROGRESS, UxInteractionLock.get().getUxState());
    }

    @Test
    public void executeGetKey_grantActive_doesNotFireUpUvRequest() {
        armGrant();
        AtomicReference<UpUvRequestCtx> seen = new AtomicReference<>();
        AuthenticatorAPI.setUpUvCallback(seen::set);

        assertEquals(0, status(PinFlowHandler.executeGetKey(newTxn())));

        assertNull(seen.get());
    }

    // -------------------------------------------------------------------------
    // Private helpers (reflection)
    // -------------------------------------------------------------------------

    @Test
    public void handleCryptographicException_mapsExceptionTypes() throws Exception {
        Class<?>[] types = {Exception.class};
        assertStatus(Ctap2StatusCode.OTHER, (byte[]) invokePrivate("handleCryptographicException",
            types, new Object[] {new NoSuchAlgorithmException()}));
        assertStatus(Ctap2StatusCode.OTHER, (byte[]) invokePrivate("handleCryptographicException",
            types, new Object[] {new NoSuchPaddingException()}));
        assertStatus(Ctap2StatusCode.INVALID_PARAMETER, (byte[]) invokePrivate("handleCryptographicException",
            types, new Object[] {new InvalidKeyException()}));
        assertStatus(Ctap2StatusCode.INVALID_PARAMETER, (byte[]) invokePrivate("handleCryptographicException",
            types, new Object[] {new InvalidAlgorithmParameterException()}));
        assertStatus(Ctap2StatusCode.PIN_AUTH_INVALID, (byte[]) invokePrivate("handleCryptographicException",
            types, new Object[] {new GeneralSecurityException()}));
        assertStatus(Ctap2StatusCode.OTHER, (byte[]) invokePrivate("handleCryptographicException",
            types, new Object[] {new IllegalStateException()}));
    }

    @Test
    public void performEcdhKeyAgreement_failures_returnNullAndEraseKeyPair() throws Exception {
        Class<?>[] types = {PinUvAuthProtocol.class, PublicKey.class, CtapTxn.class};
        PublicKey clientKey = KeyUtils.generateKeyPair("EC", 256).getPublic();

        // null txn
        assertNull(invokePrivate("performEcdhKeyAgreement", types,
            new Object[] {PinUvAuthProtocol.forId(1), clientKey, null}));

        // txn without key pair
        assertNull(invokePrivate("performEcdhKeyAgreement", types,
            new Object[] {PinUvAuthProtocol.forId(1), clientKey, newTxn()}));

        // checked failure from decapsulate
        PinUvAuthProtocol checked = mock(PinUvAuthProtocol.class);
        when(checked.decapsulate(any(), any())).thenThrow(new GeneralSecurityException("bad peer"));
        CtapTxn t1 = newTxn();
        t1.setEcdhKeyPair(KeyUtils.generateKeyPair("EC", 256));
        assertNull(invokePrivate("performEcdhKeyAgreement", types, new Object[] {checked, clientKey, t1}));
        assertNull(t1.getEcdhKeyPair());

        // unchecked failure from decapsulate
        PinUvAuthProtocol unchecked = mock(PinUvAuthProtocol.class);
        when(unchecked.decapsulate(any(), any())).thenThrow(new IllegalArgumentException("bad peer"));
        CtapTxn t2 = newTxn();
        t2.setEcdhKeyPair(KeyUtils.generateKeyPair("EC", 256));
        assertNull(invokePrivate("performEcdhKeyAgreement", types, new Object[] {unchecked, clientKey, t2}));
        assertNull(t2.getEcdhKeyPair());
    }

    @Test
    public void processPinVerificationAndGenerateToken_encryptFailure_mapsToStatus() throws Exception {
        Class<?>[] types = {PinUvAuthProtocol.class, CtapTxn.class, byte[].class, byte[].class, int.class};

        PinUvAuthProtocol invalidKey = mock(PinUvAuthProtocol.class);
        when(invalidKey.decrypt(any(), any())).thenReturn(lowerHash);
        when(invalidKey.encrypt(any(), any())).thenThrow(new InvalidKeyException("x"));
        assertStatus(Ctap2StatusCode.INVALID_PARAMETER, (byte[]) invokePrivate(
            "processPinVerificationAndGenerateToken", types,
            new Object[] {invalidKey, newTxn(), new byte[16], new byte[64], PERMS_MC_GA}));

        PinUvAuthProtocol noAlg = mock(PinUvAuthProtocol.class);
        when(noAlg.decrypt(any(), any())).thenReturn(lowerHash);
        when(noAlg.encrypt(any(), any())).thenThrow(new NoSuchAlgorithmException("x"));
        assertStatus(Ctap2StatusCode.OTHER, (byte[]) invokePrivate(
            "processPinVerificationAndGenerateToken", types,
            new Object[] {noAlg, newTxn(), new byte[16], new byte[64], PERMS_MC_GA}));
    }

    @Test
    public void reconstructFullPinHash_returnsNullForBadInputs() throws Exception {
        Class<?>[] types = {byte[].class, Passkey.class};
        Passkey pk = Passkey.openKey(lowerHash);
        assertNotNull(pk);

        assertNull(invokePrivate("reconstructFullPinHash", types, new Object[] {null, pk}));
        assertNull(invokePrivate("reconstructFullPinHash", types, new Object[] {new byte[15], pk}));
        assertNull(invokePrivate("reconstructFullPinHash", types, new Object[] {lowerHash, null}));

        // stash file missing → exception swallowed
        pk.setFileName("does-not-exist.passkey");
        assertNull(invokePrivate("reconstructFullPinHash", types, new Object[] {lowerHash, pk}));

        // happy path
        pk.setFileName("pinflow.passkey");
        assertArrayEquals(pinHash,
            (byte[]) invokePrivate("reconstructFullPinHash", types, new Object[] {lowerHash, pk}));
    }
}
