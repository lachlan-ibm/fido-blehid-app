/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator.implapi;

import com.isfs.blekey.authenticator.AuthenticatorAPI;
import com.isfs.blekey.authenticator.Fido2Authenticator;
import com.isfs.blekey.data.Passkey;
import com.isfs.blekey.util.Cbor;
import com.isfs.blekey.util.JsonUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Orchestrates the WebAuthn GET (assertion) and CREATE (make-credential) ceremonies
 * and normalises the raw {@link Fido2Authenticator} response into the wire shape
 * expected by Android Credential Manager.
 *
 * <p>This class is the lib-layer boundary: it contains all CTAP2/WebAuthn logic
 * that was previously duplicated inside {@code CredentialManagerProviderActivity}.
 * It has <strong>zero Android imports</strong>.</p>
 */
public final class CredentialManagerAuthenticator {

    private static final Logger logger =
            LoggerFactory.getLogger(CredentialManagerAuthenticator.class);

    private CredentialManagerAuthenticator() {}

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Performs the FIDO2 GET assertion ceremony and returns a normalised JSON
     * string ready for {@code PublicKeyCredential}.
     *
     * @param requestJson the WebAuthn GET request JSON
     * @param passkey     the decrypted passkey
     * @return normalised assertion response JSON
     * @throws Exception on any CTAP2, crypto, or JSON error
     */
    public static String getAssertion(String requestJson, Passkey passkey) throws Exception {
        String rpId = parseRpIdGet(requestJson);
        if (rpId == null || rpId.isEmpty()) {
            throw new IllegalStateException("Cannot determine rpId from GET request JSON");
        }
        logger.debug("getAssertion: rpId={}", rpId);

        byte[] rpIdBytes = sha256(rpId.getBytes(StandardCharsets.UTF_8));

        Fido2Authenticator authenticator = new Fido2Authenticator();
        CredentialSeedDeriver.configureCredentialAnchor(
                authenticator, passkey.getPrivateKey(), rpIdBytes,
                AuthenticatorAPI.getAppConfig());

        ArrayList<byte[]> candidates = buildCandidateCredIds(passkey, rpId, requestJson);
        if (candidates.isEmpty()) {
            throw new IllegalStateException("No credentials found for rpId: " + rpId);
        }

        initAuthenticatorFromCandidates(authenticator, candidates, rpId);

        String raw = authenticator.credentialRequest(requestJson, authenticator.getKeyPair());
        return normaliseAssertionResponse(raw, passkey.getResCreds());
    }

    /**
     * Performs the FIDO2 CREATE (make-credential) ceremony, stores the resident
     * credential, and returns a normalised JSON string ready for
     * {@code CreatePublicKeyCredentialResponse}.
     *
     * @param requestJson  the WebAuthn CREATE request JSON
     * @param passkey      the decrypted passkey
     * @param lph          16-byte PIN-hash used to re-encrypt the passkey on disk
     * @param passkeyFile  file to persist the updated passkey to
     * @return normalised attestation response JSON
     * @throws Exception on any CTAP2, crypto, or JSON error
     */
    public static String makeCredential(
            String requestJson, Passkey passkey, byte[] lph, File passkeyFile) throws Exception {

        String rpId = parseRpIdCreate(requestJson);
        logger.debug("makeCredential: rpId={}", rpId);

        String jcaAlg = selectJcaAlg(requestJson);
        logger.debug("makeCredential: jcaAlg={}", jcaAlg);

        Fido2Authenticator authenticator = new Fido2Authenticator(jcaAlg);

        if (rpId != null && !rpId.isEmpty()) {
            byte[] rpIdBytes = sha256(rpId.getBytes(StandardCharsets.UTF_8));
            CredentialSeedDeriver.configureCredentialAnchor(
                    authenticator, passkey.getPrivateKey(), rpIdBytes,
                    AuthenticatorAPI.getAppConfig());
        }

        String raw = authenticator.credentialCreate(requestJson, "packed-self");
        ResidentCredentialStore.storeResidentCredential(
                requestJson, authenticator.getCredId(), passkey, lph, passkeyFile);

        return normaliseAttestationResponse(raw,
                authenticator.getKeyPair().getPublic().getEncoded());
    }

    // -------------------------------------------------------------------------
    // Private — orchestration helpers
    // -------------------------------------------------------------------------

    private static ArrayList<byte[]> buildCandidateCredIds(
            Passkey passkey, String rpId, String requestJson) {

        ArrayList<byte[]> candidates = new ArrayList<>();

        List<Map<String, byte[]>> resCreds = passkey.getResCreds();
        if (resCreds != null) {
            byte[] rpIdUtf8 = rpId.getBytes(StandardCharsets.UTF_8);
            for (Map<String, byte[]> cred : resCreds) {
                byte[] storedRpId = cred.get("rp.id");
                if (storedRpId != null && Arrays.equals(storedRpId, rpIdUtf8)) {
                    candidates.add(cred.get("cred.id"));
                }
            }
        }

        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> req = (Map<String, Object>) JsonUtils.decode(requestJson, Map.class);
            if (req != null) {
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> allowList =
                        (List<Map<String, Object>>) req.get("allowCredentials");
                if (allowList != null) {
                    for (Map<String, Object> entry : allowList) {
                        String b64id = (String) entry.get("id");
                        if (b64id != null) {
                            candidates.add(Base64.getUrlDecoder().decode(b64id));
                        }
                    }
                }
            }
        } catch (Exception e) {
            logger.warn("buildCandidateCredIds: failed to parse allowCredentials", e);
        }

        logger.debug("buildCandidateCredIds: {} candidate(s) for rpId={}", candidates.size(), rpId);
        return candidates;
    }

    private static void initAuthenticatorFromCandidates(
            Fido2Authenticator authenticator,
            ArrayList<byte[]> candidates,
            String rpId) throws Exception {

        for (byte[] credId : candidates) {
            try {
                authenticator.initFromCredId(credId);
                logger.debug("initAuthenticatorFromCandidates: matched credential for rpId={}", rpId);
                return;
            } catch (Exception e) {
                logger.debug("initAuthenticatorFromCandidates: candidate rejected — {}", e.getMessage());
            }
        }
        throw new IllegalStateException(
                "No matching credential could be decrypted for rpId: " + rpId);
    }

    // -------------------------------------------------------------------------
    // Private — response normalisers
    // -------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private static String normaliseAssertionResponse(
            String json, List<Map<String, byte[]>> resCreds) throws Exception {

        Map<String, Object> result =
                (Map<String, Object>) JsonUtils.decode(json, Map.class);

        result.put("id", stripPadding((String) result.get("id")));
        result.put("rawId", stripPadding((String) result.get("rawId")));

        byte[] rawId = Base64.getUrlDecoder().decode((String) result.get("rawId"));

        Map<String, Object> rsp = (Map<String, Object>) result.get("response");
        rsp.put("clientDataJSON",   stripPadding((String) rsp.get("clientDataJSON")));
        rsp.put("authenticatorData", stripPadding((String) rsp.get("authenticatorData")));
        rsp.put("signature",        stripPadding((String) rsp.get("signature")));

        String userHandle = "";
        if (resCreds != null) {
            for (Map<String, byte[]> cred : resCreds) {
                if (Arrays.equals(cred.get("cred.id"), rawId)) {
                    userHandle = Base64.getUrlEncoder().withoutPadding()
                            .encodeToString(cred.get("user.id"));
                    break;
                }
            }
        }
        rsp.put("userHandle", userHandle);

        result.put("clientExtensionResults", new HashMap<>());
        result.remove("getClientExtensionResults");
        result.put("authenticatorAttachment", "platform");

        return JsonUtils.encode(result);
    }

    @SuppressWarnings("unchecked")
    private static String normaliseAttestationResponse(
            String json, byte[] subjectPublicKeyInfoDer) throws Exception {

        Map<String, Object> result =
                (Map<String, Object>) JsonUtils.decode(json, Map.class);

        result.put("id",    stripPadding((String) result.get("id")));
        result.put("rawId", stripPadding((String) result.get("rawId")));

        Map<String, Object> rsp = (Map<String, Object>) result.get("response");

        String strippedAttestation = stripPadding((String) rsp.get("attestationObject"));
        rsp.put("attestationObject", strippedAttestation);
        rsp.put("clientDataJSON",    stripPadding((String) rsp.get("clientDataJSON")));

        Map<String, Object> attObj = (Map<String, Object>) Cbor.decode(
                Base64.getUrlDecoder().decode((String) rsp.get("attestationObject")));
        String authData = Base64.getUrlEncoder().withoutPadding()
                .encodeToString((byte[]) attObj.get("authData"));
        rsp.put("authenticatorData", authData);

        List<String> transports = new ArrayList<>();
        transports.add("internal");
        transports.add("usb");
        rsp.put("transports", transports);

        if (subjectPublicKeyInfoDer != null) {
            rsp.put("publicKey", Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(subjectPublicKeyInfoDer));
        }
        rsp.put("publicKeyAlgorithm", -7);

        result.put("clientExtensionResults", new HashMap<>());
        result.remove("getClientExtensionResults");

        return JsonUtils.encode(result);
    }

    // -------------------------------------------------------------------------
    // Private — JSON parsing helpers
    // -------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private static String parseRpIdGet(String json) {
        if (json == null) return null;
        try {
            Map<String, Object> obj = (Map<String, Object>) JsonUtils.decode(json, Map.class);
            return obj != null ? (String) obj.get("rpId") : null;
        } catch (Exception e) {
            logger.warn("parseRpIdGet failed", e);
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private static String parseRpIdCreate(String json) {
        if (json == null) return null;
        try {
            Map<String, Object> obj = (Map<String, Object>) JsonUtils.decode(json, Map.class);
            if (obj == null) return null;
            Map<String, Object> rp = (Map<String, Object>) obj.get("rp");
            return rp != null ? (String) rp.get("id") : null;
        } catch (Exception e) {
            logger.warn("parseRpIdCreate failed", e);
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private static String selectJcaAlg(String json) {
        final int COSE_ES256 = -7;
        if (json != null) {
            try {
                Map<String, Object> obj = (Map<String, Object>) JsonUtils.decode(json, Map.class);
                if (obj != null) {
                    List<Map<String, Object>> params =
                            (List<Map<String, Object>>) obj.get("pubKeyCredParams");
                    if (params != null) {
                        for (Map<String, Object> p : params) {
                            Object alg = p.get("alg");
                            if (alg instanceof Number
                                    && ((Number) alg).intValue() == COSE_ES256) {
                                return "ECDSA";
                            }
                        }
                    }
                }
            } catch (Exception e) {
                logger.warn("selectJcaAlg: failed to parse pubKeyCredParams", e);
            }
        }
        return "ECDSA";
    }

    // -------------------------------------------------------------------------
    // Private — primitives
    // -------------------------------------------------------------------------

    private static String stripPadding(String s) {
        return s == null ? null : s.replace("=", "");
    }

    private static byte[] sha256(byte[] input) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(input);
    }
}
