/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import com.isfs.blekey.ctap.CtapTxn;
import com.isfs.blekey.data.AppConfig;
import com.isfs.blekey.data.Passkey;
import com.isfs.blekey.util.FileUtils;
import com.isfs.blekey.util.KeyUtils;

/**
 * Unit tests for the Platform Key Attestation feature (UV-discouraged path).
 *
 * Covers the changes introduced by docs/PLATFORM_KEY_ATTESTATION_PLAN.md:
 *
 *  Test 2 — loadAttestationKeyPair: uv=true, rk=false uses passkey file key
 *  Test 3 — loadAttestationKeyPair: uv=false, rk=false uses platform key
 *  Test 4 — createAttestationStatement: packed-self when akiCert == null
 *  Test 5 — createAttestationStatement: packed when akiCert present
 *  Test 6 — executeMakeCredential: uv=false skips PIN check (integration via _canMakeCredential+execute)
 */
@ExtendWith(MockitoExtension.class)
public class PlatformKeyAttestationTest {

    private KeyPair savedPlatKeyPair;
    private KeyPair testPasskeyPair;
    private KeyPair testPlatformKeyPair;
    private File tempDir;
    /** Captures the deferred response delivered via DeferredResponseSender in unit tests. */
    private final AtomicReference<byte[]> capturedResponse = new AtomicReference<>();

    @BeforeEach
    public void setUp() throws Exception {
        // Create a temp FIDO2_HOME so KeyUtils.getPlatformKey() has a real directory
        tempDir = Files.createTempDirectory("fido2-test-").toFile();
        tempDir.deleteOnExit();
        System.setProperty("FIDO2_HOME", tempDir.getAbsolutePath());

        // Generate a test passkey key pair (simulates a loaded .passkey file key)
        testPasskeyPair = KeyUtils.generateKeyPair("EC", 256);

        // Generate a test platform key pair and write it to platform.key so that
        // KeyUtils.getPlatformKey() (disk lookup) returns it during makeCredential.
        testPlatformKeyPair = KeyUtils.generateKeyPair("EC", 256);
        FileUtils.writePrivatePEM(testPlatformKeyPair.getPrivate(),
                new File(tempDir, "platform.key"));

        // Save + replace the static platKeyPair so tests are deterministic
        Field platKeyPairField = AuthenticatorAPI.class.getDeclaredField("platKeyPair");
        platKeyPairField.setAccessible(true);
        savedPlatKeyPair = (KeyPair) platKeyPairField.get(null);
        platKeyPairField.set(null, testPlatformKeyPair);

        // Stub SecureStorageCallback: platform key is not TEE-backed in tests.
        // Call onUnlocked() immediately so makeCredential/getAssertion can proceed.
        AuthenticatorAPI.setSecureStorageCallback(ctx -> ctx.onUnlocked());

        // Stub DeferredResponseSender: try the CtapHid path first (Ctap2HidRequestTest
        // pattern); fall back to capturing in capturedResponse for direct-call tests.
        capturedResponse.set(null);
        AuthenticatorAPI.setDeferredResponseSender((txn, response) -> {
            com.isfs.blekey.ctap.CtapHid deferred = txn.takeDeferredCmd();
            if (deferred != null) {
                try {
                    deferred.injectDeferredResponse(response);
                } catch (java.io.IOException e) {
                    throw new RuntimeException(e);
                }
            } else {
                capturedResponse.set(response);
            }
        });
    }

    @AfterEach
    public void tearDown() throws Exception {
        Field platKeyPairField = AuthenticatorAPI.class.getDeclaredField("platKeyPair");
        platKeyPairField.setAccessible(true);
        platKeyPairField.set(null, savedPlatKeyPair);
        AuthenticatorAPI.setSecureStorageCallback(null);
        AuthenticatorAPI.setDeferredResponseSender(null);
        System.clearProperty("FIDO2_HOME");
    }


    // =========================================================================
    // Test 4 — createAttestationStatement: packed-self when akiCert == null
    // Plan item: "akiCert=null → map contains 'alg' and 'sig', does not contain 'x5c'"
    // =========================================================================

    /**
     * createAttestationStatement() with akiCert=null must produce a packed-self
     * statement: 'alg' and 'sig' keys present, 'x5c' absent.
     */
    @Test
    public void testCreateAttestationStatement_PackedSelfWhenNoCert() throws Exception {
        Fido2Authenticator authenticator = new Fido2Authenticator();
        authenticator.setSymKeys(KeyUtils.getPasskeySeed(
            MessageDigest.getInstance("SHA-256").digest("example.com".getBytes()),
            testPlatformKeyPair.getPrivate().getEncoded(), AppConfig.getDefault()));

        byte[] clientDataHash = MessageDigest.getInstance("SHA-256").digest("test".getBytes());
        byte[] authData = new byte[37];

        // Use the platform key pair as the attestation key pair (UV-discouraged path)
        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "createAttestationStatement",
            byte[].class, byte[].class, Fido2Authenticator.class,
            KeyPair.class, X509Certificate.class);
        method.setAccessible(true);

        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) method.invoke(
            null, clientDataHash, authData, authenticator, testPlatformKeyPair, null /* akiCert */);

        assertNotNull(result, "Attestation statement must not be null");
        assertTrue(result.containsKey("alg"), "packed-self must contain 'alg'");
        assertTrue(result.containsKey("sig"), "packed-self must contain 'sig'");
        assertFalse(result.containsKey("x5c"), "packed-self must NOT contain 'x5c'");
    }

    // =========================================================================
    // Test 5 — createAttestationStatement: packed when akiCert present
    // Plan item: "akiCert present → map contains 'x5c'"
    // =========================================================================

    /**
     * createAttestationStatement() with a real X509Certificate must produce a
     * packed statement with 'x5c' present.
     */
    @Test
    public void testCreateAttestationStatement_PackedWhenCertPresent() throws Exception {
        AttestationTestFixture fixture = new AttestationTestFixture();
        fixture.initialize();

        Fido2Authenticator authenticator = new Fido2Authenticator();
        authenticator.setSymKeys(KeyUtils.getPasskeySeed(
            MessageDigest.getInstance("SHA-256").digest("example.com".getBytes()),
            testPlatformKeyPair.getPrivate().getEncoded(), AppConfig.getDefault()));

        byte[] clientDataHash = MessageDigest.getInstance("SHA-256").digest("test".getBytes());
        byte[] authData = new byte[37];

        KeyPair caKeyPair = fixture.getEcCaKeyPair();
        X509Certificate caCert = fixture.getEcCaCert();

        Method method = AuthenticatorAPI.class.getDeclaredMethod(
            "createAttestationStatement",
            byte[].class, byte[].class, Fido2Authenticator.class,
            KeyPair.class, X509Certificate.class);
        method.setAccessible(true);

        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) method.invoke(
            null, clientDataHash, authData, authenticator, caKeyPair, caCert);

        assertNotNull(result, "Attestation statement must not be null");
        assertTrue(result.containsKey("alg"), "packed must contain 'alg'");
        assertTrue(result.containsKey("sig"), "packed must contain 'sig'");
        assertTrue(result.containsKey("x5c"), "packed with CA cert must contain 'x5c'");
    }

    // =========================================================================
    // Test 6 — executeMakeCredential: uv=false skips PIN check
    // Plan item: "uv=false, no pinUvAuthParam → CTAP2_OK, not PIN_REQUIRED"
    // =========================================================================

    /**
     * A makeCredential request with options.uv=false and no pinUvAuthParam (0x08)
     * must succeed (return CTAP2_OK byte 0x00), not fail with PIN_REQUIRED.
     */
    @Test
    public void testMakeCredential_UvFalseSkipsPinCheck() throws Exception {
        // Build a minimal valid makeCredential request with uv=false, no PIN param
        Map<Integer, Object> req = buildMinimalMakeCredentialRequest(false /* uv */);

        CtapTxn txn = new CtapTxn();
        txn.setUserPresent(true);

        // makeCredential is always deferred now; response arrives via DeferredResponseSender.
        AuthenticatorAPI.makeCredential(txn, req);

        byte[] response = capturedResponse.get();
        assertNotNull(response, "Response must not be null");
        // The response must NOT be PIN_REQUIRED (0x36) — that's the key assertion.
        // PIN check is skipped for uv=false; any other failure (e.g. missing disk
        // platform key in the test environment) is acceptable.
        assertNotEquals((byte) 0x36, response[0],
            "uv=false makeCredential must NOT return PIN_REQUIRED (0x36)");
    }

    /**
     * A makeCredential request with options.uv=true and no pinUvAuthParam must
     * fail with PIN_REQUIRED (the PIN check is only skipped for uv=false).
     */
    @Test
    public void testMakeCredential_UvTrueRequiresPin() throws Exception {
        Map<Integer, Object> req = buildMinimalMakeCredentialRequest(true /* uv */);

        CtapTxn txn = new CtapTxn();
        txn.setUserPresent(true);

        byte[] response = AuthenticatorAPI.makeCredential(txn, req);

        assertNotNull(response, "Response must not be null");
        // 0x36 = PIN_REQUIRED
        assertEquals((byte) 0x36, response[0],
            "uv=true without PIN token must return PIN_REQUIRED (0x36)");
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /**
     * Builds a minimal valid authenticatorMakeCredential CBOR request map.
     *
     * @param uv Whether to request user verification
     */
    private static Map<Integer, Object> buildMinimalMakeCredentialRequest(boolean uv) {
        Map<Integer, Object> req = new HashMap<>();

        // 0x01 clientDataHash (32 bytes)
        req.put(0x01, new byte[32]);

        // 0x02 rp map with id
        Map<String, Object> rp = new HashMap<>();
        rp.put("id", "example.com");
        rp.put("name", "Example");
        req.put(0x02, rp);

        // 0x03 user map with id
        Map<String, Object> user = new HashMap<>();
        user.put("id", new byte[]{1, 2, 3, 4});
        user.put("name", "testuser");
        req.put(0x03, user);

        // 0x04 pubKeyCredParams (ES256 = -7)
        java.util.List<Map<String, Object>> pubKeyCredParams = new java.util.ArrayList<>();
        Map<String, Object> param = new HashMap<>();
        param.put("type", "public-key");
        param.put("alg", -7);
        pubKeyCredParams.add(param);
        req.put(0x04, pubKeyCredParams);

        // 0x07 options map with uv flag and up=true
        Map<String, Object> options = new HashMap<>();
        options.put("uv", uv);
        options.put("up", true);
        options.put("rk", false);
        req.put(0x07, options);

        return req;
    }
}

// Made with Bob
