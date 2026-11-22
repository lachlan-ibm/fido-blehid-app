/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.authenticator.implapi;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.isfs.blekey.authenticator.AuthenticatorAPI;
import com.isfs.blekey.authenticator.Fido2Authenticator;
import com.isfs.blekey.data.Passkey;
import com.isfs.blekey.util.Cbor;
import com.isfs.blekey.util.JsonUtils;

/**
 * Unit tests for {@link CredentialManagerAuthenticator}.
 */
@SuppressWarnings("unchecked")
public class CredentialManagerAuthenticatorTest {

    private static final String RP_ID = "example.com";
    private static final byte[] USER_ID = "user123".getBytes(StandardCharsets.UTF_8);
    private static final byte[] LPH = new byte[32];

    @TempDir
    File tempDir;

    private PrivateKey platformKey;
    private Passkey passkey;
    private List<Map<String, byte[]>> resCreds;

    @BeforeEach
    void setUp() throws Exception {
        AuthenticatorAPI.setAppConfig(null);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        platformKey = kpg.generateKeyPair().getPrivate();

        resCreds = new ArrayList<>();
        passkey = mock(Passkey.class);
        when(passkey.getPrivateKey()).thenReturn(platformKey);
        when(passkey.getResCreds()).thenReturn(resCreds);
    }

    // -------------------------------------------------------------------------
    // helpers
    // -------------------------------------------------------------------------

    private static byte[] sha256(String s) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
    }

    private static String b64u(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private static byte[] unb64u(String s) {
        return Base64.getUrlDecoder().decode(s);
    }

    private static Map<String, Object> parse(String json) {
        return (Map<String, Object>) JsonUtils.decode(json, Map.class);
    }

    private String createJson(String rpId, String residentKey, Object pubKeyCredParams) {
        Map<String, Object> req = new HashMap<>();
        Map<String, Object> rp = new HashMap<>();
        if (rpId != null) rp.put("id", rpId);
        rp.put("name", "Example");
        req.put("rp", rp);
        Map<String, Object> user = new HashMap<>();
        user.put("id", b64u(USER_ID));
        user.put("name", "u@example.com");
        user.put("displayName", "U");
        req.put("user", user);
        req.put("challenge", b64u("challenge123".getBytes(StandardCharsets.UTF_8)));
        if (pubKeyCredParams != null) req.put("pubKeyCredParams", pubKeyCredParams);
        req.put("timeout", 60000);
        req.put("attestation", "none");
        if (residentKey != null) {
            Map<String, Object> sel = new HashMap<>();
            sel.put("residentKey", residentKey);
            req.put("authenticatorSelection", sel);
        }
        return JsonUtils.encode(req);
    }

    private static List<Map<String, Object>> es256Params() {
        List<Map<String, Object>> l = new ArrayList<>();
        Map<String, Object> p = new HashMap<>();
        p.put("type", "public-key");
        p.put("alg", -7);
        l.add(p);
        return l;
    }

    private String getJson(String rpId, List<String> allowIds) {
        Map<String, Object> req = new HashMap<>();
        if (rpId != null) req.put("rpId", rpId);
        req.put("challenge", b64u("challenge123".getBytes(StandardCharsets.UTF_8)));
        req.put("timeout", 60000);
        if (allowIds != null) {
            List<Map<String, Object>> allow = new ArrayList<>();
            for (String id : allowIds) {
                Map<String, Object> e = new HashMap<>();
                e.put("type", "public-key");
                e.put("id", id);
                allow.add(e);
            }
            req.put("allowCredentials", allow);
        }
        return JsonUtils.encode(req);
    }

    /** Credential ID the authenticator would produce for this passkey + rpId. */
    private byte[] credIdFor(String rpId) throws Exception {
        Fido2Authenticator a = new Fido2Authenticator();
        CredentialSeedDeriver.configureCredentialAnchor(
                a, platformKey, sha256(rpId), AuthenticatorAPI.getAppConfig());
        return a.getCredId();
    }

    private static Map<String, byte[]> resCred(String rpId, byte[] credId, byte[] userId) {
        Map<String, byte[]> m = new HashMap<>();
        m.put("rp.id", rpId.getBytes(StandardCharsets.UTF_8));
        m.put("cred.id", credId);
        m.put("user.id", userId);
        return m;
    }

    private File existingPasskeyFile() throws Exception {
        File f = new File(tempDir, "test.passkey");
        assertTrue(f.createNewFile());
        return f;
    }

    // -------------------------------------------------------------------------
    // getAssertion
    // -------------------------------------------------------------------------

    @Test
    void getAssertion_nullRequest_throws() {
        assertThrows(IllegalStateException.class,
                () -> CredentialManagerAuthenticator.getAssertion(null, passkey));
    }

    @Test
    void getAssertion_invalidJson_throws() {
        assertThrows(IllegalStateException.class,
                () -> CredentialManagerAuthenticator.getAssertion("not json", passkey));
    }

    @Test
    void getAssertion_missingRpId_throws() {
        assertThrows(IllegalStateException.class,
                () -> CredentialManagerAuthenticator.getAssertion(getJson(null, null), passkey));
    }

    @Test
    void getAssertion_emptyRpId_throws() {
        assertThrows(IllegalStateException.class,
                () -> CredentialManagerAuthenticator.getAssertion(getJson("", null), passkey));
    }

    @Test
    void getAssertion_noCandidates_throws() {
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> CredentialManagerAuthenticator.getAssertion(getJson(RP_ID, null), passkey));
        assertTrue(e.getMessage().contains("No credentials found"));
    }

    @Test
    void getAssertion_nullResCredsAndNoAllowList_throws() {
        when(passkey.getResCreds()).thenReturn(null);
        assertThrows(IllegalStateException.class,
                () -> CredentialManagerAuthenticator.getAssertion(getJson(RP_ID, null), passkey));
    }

    @Test
    void getAssertion_resCredForOtherRp_isIgnored() throws Exception {
        resCreds.add(resCred("other.com", credIdFor("other.com"), USER_ID));
        assertThrows(IllegalStateException.class,
                () -> CredentialManagerAuthenticator.getAssertion(getJson(RP_ID, null), passkey));
    }

    @Test
    void getAssertion_invalidBase64InAllowList_throwsNoCredentials() {
        String json = getJson(RP_ID, List.of("!!!not-base64!!!"));
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> CredentialManagerAuthenticator.getAssertion(json, passkey));
        assertTrue(e.getMessage().contains("No credentials found"));
    }

    @Test
    void getAssertion_undecryptableCandidate_throws() {
        resCreds.add(resCred(RP_ID, new byte[] {1, 2, 3, 4, 5}, USER_ID));
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> CredentialManagerAuthenticator.getAssertion(getJson(RP_ID, null), passkey));
        assertTrue(e.getMessage().contains("No matching credential could be decrypted"));
    }

    @Test
    void getAssertion_nullCredIdInResCreds_isRejectedNotFatal() throws Exception {
        Map<String, byte[]> bad = resCred(RP_ID, null, USER_ID);
        resCreds.add(bad);
        resCreds.add(resCred(RP_ID, credIdFor(RP_ID), USER_ID));
        String out = CredentialManagerAuthenticator.getAssertion(getJson(RP_ID, null), passkey);
        assertNotNull(out);
    }

    @Test
    void getAssertion_residentCredential_returnsNormalisedResponse() throws Exception {
        byte[] credId = credIdFor(RP_ID);
        resCreds.add(resCred(RP_ID, credId, USER_ID));

        String out = CredentialManagerAuthenticator.getAssertion(getJson(RP_ID, null), passkey);
        Map<String, Object> result = parse(out);

        assertEquals(b64u(credId), result.get("id"));
        assertEquals(b64u(credId), result.get("rawId"));
        assertEquals("public-key", result.get("type"));
        assertEquals("platform", result.get("authenticatorAttachment"));
        assertEquals(new HashMap<>(), result.get("clientExtensionResults"));
        assertFalse(result.containsKey("getClientExtensionResults"));

        Map<String, Object> rsp = (Map<String, Object>) result.get("response");
        for (String k : new String[] {"clientDataJSON", "authenticatorData", "signature"}) {
            String v = (String) rsp.get(k);
            assertNotNull(v, k);
            assertFalse(v.contains("="), k + " must not be padded");
        }
        assertEquals(b64u(USER_ID), rsp.get("userHandle"));

        byte[] authData = unb64u((String) rsp.get("authenticatorData"));
        assertArrayEquals(sha256(RP_ID), Arrays.copyOf(authData, 32));

        String clientData = new String(unb64u((String) rsp.get("clientDataJSON")),
                StandardCharsets.UTF_8);
        assertTrue(clientData.contains("webauthn.get"));
        assertTrue(clientData.contains("https://" + RP_ID));
    }

    @Test
    void getAssertion_allowListCredential_hasEmptyUserHandle() throws Exception {
        byte[] credId = credIdFor(RP_ID);
        String out = CredentialManagerAuthenticator.getAssertion(
                getJson(RP_ID, List.of(b64u(credId))), passkey);
        Map<String, Object> result = parse(out);
        Map<String, Object> rsp = (Map<String, Object>) result.get("response");
        assertEquals("", rsp.get("userHandle"));
        assertEquals(b64u(credId), result.get("rawId"));
    }

    @Test
    void getAssertion_nullResCredsWithAllowList_succeeds() throws Exception {
        when(passkey.getResCreds()).thenReturn(null);
        byte[] credId = credIdFor(RP_ID);
        String out = CredentialManagerAuthenticator.getAssertion(
                getJson(RP_ID, List.of(b64u(credId))), passkey);
        Map<String, Object> rsp = (Map<String, Object>) parse(out).get("response");
        assertEquals("", rsp.get("userHandle"));
    }

    @Test
    void getAssertion_badResCredFollowedByGoodAllowListEntry_succeeds() throws Exception {
        resCreds.add(resCred(RP_ID, new byte[] {9, 9, 9, 9, 9}, USER_ID));
        byte[] credId = credIdFor(RP_ID);
        String out = CredentialManagerAuthenticator.getAssertion(
                getJson(RP_ID, List.of(b64u(credId))), passkey);
        assertEquals(b64u(credId), parse(out).get("rawId"));
    }

    @Test
    void getAssertion_resCredWithDifferentCredId_givesEmptyUserHandle() throws Exception {
        byte[] credId = credIdFor(RP_ID);
        resCreds.add(resCred("other.com", new byte[] {1, 2, 3}, USER_ID));
        String out = CredentialManagerAuthenticator.getAssertion(
                getJson(RP_ID, List.of(b64u(credId))), passkey);
        Map<String, Object> rsp = (Map<String, Object>) parse(out).get("response");
        assertEquals("", rsp.get("userHandle"));
    }

    // -------------------------------------------------------------------------
    // makeCredential
    // -------------------------------------------------------------------------

    @Test
    void makeCredential_returnsNormalisedAttestation() throws Exception {
        String json = createJson(RP_ID, "required", es256Params());
        String out = CredentialManagerAuthenticator.makeCredential(
                json, passkey, LPH, existingPasskeyFile());
        Map<String, Object> result = parse(out);

        String id = (String) result.get("id");
        assertNotNull(id);
        assertFalse(id.contains("="));
        assertEquals(id, result.get("rawId"));
        assertEquals("public-key", result.get("type"));
        assertEquals(new HashMap<>(), result.get("clientExtensionResults"));
        assertFalse(result.containsKey("getClientExtensionResults"));

        Map<String, Object> rsp = (Map<String, Object>) result.get("response");
        String attObjB64 = (String) rsp.get("attestationObject");
        assertFalse(attObjB64.contains("="));
        assertFalse(((String) rsp.get("clientDataJSON")).contains("="));
        assertEquals(List.of("internal", "usb"), rsp.get("transports"));
        assertEquals(-7, ((Number) rsp.get("publicKeyAlgorithm")).intValue());

        Map<String, Object> attObj = (Map<String, Object>) Cbor.decode(unb64u(attObjB64));
        byte[] authData = (byte[]) attObj.get("authData");
        assertEquals(b64u(authData), rsp.get("authenticatorData"));
        assertArrayEquals(sha256(RP_ID), Arrays.copyOf(authData, 32));

        // publicKey must be a parseable SubjectPublicKeyInfo EC key
        byte[] spki = unb64u((String) rsp.get("publicKey"));
        assertEquals("EC", KeyFactory.getInstance("EC")
                .generatePublic(new X509EncodedKeySpec(spki)).getAlgorithm());

        String clientData = new String(unb64u((String) rsp.get("clientDataJSON")),
                StandardCharsets.UTF_8);
        assertTrue(clientData.contains("webauthn.create"));
    }

    @Test
    void makeCredential_credentialIdMatchesDerivedAnchor() throws Exception {
        String out = CredentialManagerAuthenticator.makeCredential(
                createJson(RP_ID, "required", es256Params()), passkey, LPH, existingPasskeyFile());
        String id = (String) parse(out).get("id");

        // The created credential must be recoverable from the same passkey + rpId.
        Fido2Authenticator a = new Fido2Authenticator();
        CredentialSeedDeriver.configureCredentialAnchor(
                a, platformKey, sha256(RP_ID), AuthenticatorAPI.getAppConfig());
        a.initFromCredId(unb64u(id));
        assertNotNull(a.getKeyPair());
    }

    @Test
    void makeCredential_thenGetAssertion_roundTrip() throws Exception {
        String created = CredentialManagerAuthenticator.makeCredential(
                createJson(RP_ID, "required", es256Params()), passkey, LPH, existingPasskeyFile());
        String id = (String) parse(created).get("id");

        String out = CredentialManagerAuthenticator.getAssertion(
                getJson(RP_ID, List.of(id)), passkey);
        assertEquals(id, parse(out).get("rawId"));
    }

    @Test
    void makeCredential_residentRequired_storesCredential() throws Exception {
        CredentialManagerAuthenticator.makeCredential(
                createJson(RP_ID, "required", es256Params()), passkey, LPH, existingPasskeyFile());
        verify(passkey).addResCred(
                any(byte[].class), any(byte[].class), any(byte[].class));
    }

    @Test
    void makeCredential_residentPreferred_storesCredential() throws Exception {
        CredentialManagerAuthenticator.makeCredential(
                createJson(RP_ID, "preferred", es256Params()), passkey, LPH, existingPasskeyFile());
        verify(passkey).addResCred(
                any(byte[].class), any(byte[].class), any(byte[].class));
    }

    @Test
    void makeCredential_residentDiscouraged_doesNotStore() throws Exception {
        CredentialManagerAuthenticator.makeCredential(
                createJson(RP_ID, "discouraged", es256Params()), passkey, LPH, existingPasskeyFile());
        verify(passkey, never()).addResCred(
                any(byte[].class), any(byte[].class), any(byte[].class));
    }

    @Test
    void makeCredential_noAuthenticatorSelection_doesNotStore() throws Exception {
        CredentialManagerAuthenticator.makeCredential(
                createJson(RP_ID, null, es256Params()), passkey, LPH, existingPasskeyFile());
        verify(passkey, never()).addResCred(
                any(byte[].class), any(byte[].class), any(byte[].class));
    }

    @Test
    void makeCredential_duplicateResidentCredential_doesNotStoreAgain() throws Exception {
        resCreds.add(resCred(RP_ID, new byte[] {1}, USER_ID));
        CredentialManagerAuthenticator.makeCredential(
                createJson(RP_ID, "required", es256Params()), passkey, LPH, existingPasskeyFile());
        verify(passkey, never()).addResCred(
                any(byte[].class), any(byte[].class), any(byte[].class));
    }

    @Test
    void makeCredential_missingPasskeyFile_doesNotStoreButSucceeds() throws Exception {
        File missing = new File(tempDir, "missing.passkey");
        String out = CredentialManagerAuthenticator.makeCredential(
                createJson(RP_ID, "required", es256Params()), passkey, LPH, missing);
        assertNotNull(parse(out).get("id"));
        verify(passkey, never()).addResCred(
                any(byte[].class), any(byte[].class), any(byte[].class));
    }

    @Test
    void makeCredential_nonEs256Params_stillUsesEcdsa() throws Exception {
        List<Map<String, Object>> params = new ArrayList<>();
        Map<String, Object> p = new HashMap<>();
        p.put("type", "public-key");
        p.put("alg", -257);
        params.add(p);
        String out = CredentialManagerAuthenticator.makeCredential(
                createJson(RP_ID, null, params), passkey, LPH, existingPasskeyFile());
        Map<String, Object> rsp = (Map<String, Object>) parse(out).get("response");
        assertEquals(-7, ((Number) rsp.get("publicKeyAlgorithm")).intValue());
    }

    @Test
    void makeCredential_nullPubKeyCredParams_succeeds() throws Exception {
        String out = CredentialManagerAuthenticator.makeCredential(
                createJson(RP_ID, null, null), passkey, LPH, existingPasskeyFile());
        assertNotNull(parse(out).get("id"));
    }

    @Test
    void makeCredential_nonNumericAlg_stillSucceeds() throws Exception {
        List<Map<String, Object>> params = new ArrayList<>();
        Map<String, Object> p = new HashMap<>();
        p.put("type", "public-key");
        p.put("alg", "-7");
        params.add(p);
        String out = CredentialManagerAuthenticator.makeCredential(
                createJson(RP_ID, null, params), passkey, LPH, existingPasskeyFile());
        assertNotNull(parse(out).get("id"));
    }

    @Test
    void makeCredential_nullRequest_throws() {
        assertThrows(Exception.class, () -> CredentialManagerAuthenticator.makeCredential(
                null, passkey, LPH, new File(tempDir, "x.passkey")));
    }

    @Test
    void makeCredential_missingRpId_throws() {
        assertThrows(Exception.class, () -> CredentialManagerAuthenticator.makeCredential(
                createJson(null, null, es256Params()), passkey, LPH,
                new File(tempDir, "x.passkey")));
    }

    @Test
    void makeCredential_invalidJson_throws() {
        assertThrows(Exception.class, () -> CredentialManagerAuthenticator.makeCredential(
                "not json", passkey, LPH, new File(tempDir, "x.passkey")));
    }
}
