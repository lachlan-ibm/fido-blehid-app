/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator.implapi;

import com.isfs.blekey.authenticator.AuthenticatorAPI;
import com.isfs.blekey.authenticator.Fido2Authenticator;
import com.isfs.blekey.authenticator.UpUvRequestCtx;
import com.isfs.blekey.authenticator.UxInteractionLock;
import com.isfs.blekey.authenticator.implapi.pin.PinSessionRegistry;
import com.isfs.blekey.ctap.Ctap2StatusCode;
import com.isfs.blekey.ctap.CtapTxn;
import com.isfs.blekey.ctap.CtapTxn.CidUxState;
import com.isfs.blekey.data.Passkey;
import com.isfs.blekey.util.Cbor;
import com.isfs.blekey.util.KeyUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Handles the {@code getAssertion} (0x02) and {@code getNextAssertion} (0x08) CTAP commands.
 *
 * <p>The cross-CID key-leak security fix (§2b) is maintained here: only the CID's own
 * passkey key and the platform seed are consulted — the {@code openKeys} loop that
 * could allow another CID's PIN session to satisfy this CID's {@code getAssertion} has
 * been removed.</p>
 */
public class GetAssertionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GetAssertionHandler.class);

    /** Maximum ms to wait for the out-of-band UX latch before timing out (§5.2). */
    private static final long UP_WAIT_TIMEOUT_MS = 25_000L;

    private GetAssertionHandler() {}

    // -------------------------------------------------------------------------
    // getAssertion (CTAP 0x02)
    // -------------------------------------------------------------------------

    /**
     * Entry point for the {@code authenticatorGetAssertion} command.
     */
    public static byte[] getAssertion(CtapTxn txn, Map<Integer, Object> req) {
        logger.debug("getAssertion");

        if (!PinSessionRegistry.loadAuthenticatedSession(txn)) {
            logger.debug("getAssertion: no PIN session for CID — clearing stale passkey");
            txn.setPasskey(null);
        }

        // Fast path: app-global bio grant active — covers any CID, not just the one that
        // collected UP. A fresh CtapTxn always has isUserPresent=false, so the old guard
        // of txn.isUserPresent() && isGrantActive() was never true on a new session.
        if (UxInteractionLock.get().isGrantActive()) {
            logger.debug("getAssertion: grant active — fast path, no UP prompt");
            try {
                return executeGetAssertion(txn, req);
            } catch (Exception e) {
                logger.error("getAssertion fast-path failed", e);
                return error(Ctap2StatusCode.OTHER);
            }
        }

        // Denied path: CID was already denied this session.
        if (txn.getUxState() == CidUxState.DENIED || txn.isUserDenied()) {
            logger.warn("getAssertion: CID denied — OPERATION_DENIED");
            return error(Ctap2StatusCode.OPERATION_DENIED);
        }

        // Latch-wait path: getInfo already started the UX; wait for it to complete.
        if (txn.getUxState() == CidUxState.IN_PROGRESS) {
            logger.debug("getAssertion: UX in progress — waiting on latch (max {}ms)", UP_WAIT_TIMEOUT_MS);
            boolean completed = txn.awaitUxLatch(UP_WAIT_TIMEOUT_MS);
            if (!completed || txn.getUxState() != CidUxState.APPROVED) {
                logger.warn("getAssertion: UX latch timeout or denied — OPERATION_DENIED");
                return error(Ctap2StatusCode.OPERATION_DENIED);
            }
            logger.debug("getAssertion: latch-wait path — latch fired, UX APPROVED");
            try {
                return executeGetAssertion(txn, req);
            } catch (Exception e) {
                logger.error("getAssertion post-latch failed", e);
                return error(Ctap2StatusCode.OTHER);
            }
        }

        // Legacy deferred path: getInfo was not called first (platform skipped it),
        // or lock held by another CID. Preserve existing behaviour unchanged.
        AuthenticatorAPI.UpUvCallback cb = AuthenticatorAPI.getUpUvCallback();
        if (cb == null) {
            logger.warn("getAssertion: no UpUvCallback — OPERATION_DENIED");
            return error(Ctap2StatusCode.OPERATION_DENIED);
        }

        Object rpIdValue = req.get(0x01 /* RPID */);
        String rpIdStr = (rpIdValue instanceof String) ? (String) rpIdValue : null;
        final Map<Integer, Object> reqFinal = req;

        if (!UxInteractionLock.get().tryAcquire(txn.getCid())) {
            logger.warn("getAssertion: CID does not own UP lock — CHANNEL_BUSY");
            return error(Ctap2StatusCode.CHANNEL_BUSY);
        }
        cb.onUpUvRequired(
            new UpUvRequestCtx(rpIdStr, txn,
                java.util.List.of((chainCb) ->
                    onGetAssertionUpApproved(chainCb, txn, reqFinal)),
                UpUvRequestCtx.KEEPALIVE_UP_NEEDED,
                true,  // requiresBiometric
                UpUvRequestCtx.CeremonyType.GET_ASSERTION
            )
        );
        return null; // deferred (legacy path)
    }

    private static void onGetAssertionUpApproved(
            UpUvRequestCtx.ChainCallback chainCb,
            CtapTxn txn,
            Map<Integer, Object> req) {
        txn.setUserPresent(true);
        try {
            byte[] response = executeGetAssertion(txn, req);
            AuthenticatorAPI.DeferredResponseSender sender =
                AuthenticatorAPI.getDeferredResponseSender();
            if (sender != null) sender.send(txn, response);
        } catch (Exception e) {
            logger.error("getAssertion chain action failed", e);
            AuthenticatorAPI.DeferredResponseSender sender =
                AuthenticatorAPI.getDeferredResponseSender();
            if (sender != null) sender.send(txn, error(Ctap2StatusCode.OTHER));
        }
        chainCb.done(null);
    }

    // -------------------------------------------------------------------------
    // getNextAssertion (CTAP 0x08)
    // -------------------------------------------------------------------------

    /**
     * Reuses the UP approval cached in the {@link UxInteractionLock} from a prior
     * {@code getAssertion} on the same CID — no new UP dialog is shown.
     */
    public static byte[] getNextAssertion(CtapTxn txn, Map<Integer, Object> req) {
        logger.debug("getNextAssertion");
        if (!UxInteractionLock.get().isOwner(txn.getCid())) {
            logger.warn("getNextAssertion: CID does not own UP lock — OPERATION_DENIED");
            return error(Ctap2StatusCode.OPERATION_DENIED);
        }
        if (!PinSessionRegistry.loadAuthenticatedSession(txn)) {
            logger.debug("getNextAssertion: no PIN session for CID — using platform key");
            txn.setPasskey(null);
        }
        try {
            return executeGetAssertion(txn, req);
        } catch (Exception e) {
            logger.error("getNextAssertion failed", e);
            return error(Ctap2StatusCode.OTHER);
        }
    }

    // -------------------------------------------------------------------------
    // executeGetAssertion (§2b: openKeys cross-CID loop removed)
    // -------------------------------------------------------------------------

    static byte[] executeGetAssertion(CtapTxn txn, Map<Integer, Object> req) throws Exception {
        PrivateKey platformKey = KeyUtils.getPlatformKey();
        if (platformKey == null) return error(Ctap2StatusCode.OTHER);

        Object rpIdValue = req.get(0x01 /* RPID */);
        byte[] rpIdBytes = CredentialSeedDeriver.extractRpIdBytes(rpIdValue);
        String seed = CredentialSeedDeriver.derivePasskeySeed(
            txn, platformKey, rpIdBytes, AuthenticatorAPI.getAppConfig());
        if (seed == null) return error(Ctap2StatusCode.OTHER);

        Passkey passkeySnap = txn.getPasskey();
        Fido2Authenticator authenticator = new Fido2Authenticator();
        authenticator.setSymKeys(seed);

        // Try passkey key first if available (§2b: only this CID's passkey is consulted).
        if (passkeySnap != null) {
            CredentialSeedDeriver.configureCredentialAnchor(
                authenticator, passkeySnap.getPrivateKey(), rpIdBytes,
                AuthenticatorAPI.getAppConfig());
        }

        ArrayList<Map<String, byte[]>> credentials = processCredentials(req, passkeySnap);
        if (credentials.isEmpty()) return error(Ctap2StatusCode.NO_CREDENTIALS);

        Map<String, byte[]> selectedCredential =
            initializeAuthenticatorWithCredential(authenticator, credentials);

        if (selectedCredential == null) {
            // passkey key exhausted — fall back to platform seed only.
            // Other CID sessions must NEVER be consulted (cross-CID key leak).
            logger.debug("getAssertion: passkey key exhausted — retrying with platform seed");
            authenticator.setSymKeys(seed);
            selectedCredential = initializeAuthenticatorWithCredential(authenticator, credentials);
        }

        if (selectedCredential == null) {
            logger.debug("getAssertion: all keys exhausted");
            return error(Ctap2StatusCode.NO_CREDENTIALS);
        }

        return generateSignedAssertion(req, authenticator, selectedCredential);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static ArrayList<Map<String, byte[]>> processCredentials(
            Map<Integer, Object> req, Passkey passkey) {
        @SuppressWarnings("unchecked")
        ArrayList<Map<String, byte[]>> allowList =
            (ArrayList<Map<String, byte[]>>) req.get(0x03 /* ALLOW_LIST */);
        if (allowList == null) allowList = new ArrayList<>();
        if (passkey != null) {
            List<Map<String, byte[]>> resCreds = passkey.getResCreds();
            if (resCreds != null) {
                for (Map<String, byte[]> cred : resCreds) {
                    allowList.add(Map.of(
                        "id",   (byte[]) cred.get("cred.id"),
                        "user", (byte[]) cred.get("user.id")
                    ));
                }
            }
        }
        return allowList;
    }

    private static Map<String, byte[]> initializeAuthenticatorWithCredential(
            Fido2Authenticator authenticator,
            ArrayList<Map<String, byte[]>> credentials) {
        for (Map<String, byte[]> cred : credentials) {
            try {
                byte[] credId = cred.get("id");
                logger.debug("Attempting to initialize authenticator with credential ID (length: {})",
                    credId != null ? credId.length : 0);
                authenticator.initFromCredId(credId);
                logger.debug("Successfully initialized authenticator with credential");
                return cred;
            } catch (Exception e) {
                logger.debug("Failed to initialize with credential: {}", e.getMessage());
            }
        }
        logger.debug("Failed to initialize authenticator with any of {} credentials",
                     credentials.size());
        return null;
    }

    private static byte[] generateSignedAssertion(
            Map<Integer, Object> req,
            Fido2Authenticator authenticator,
            Map<String, byte[]> credentialData) {
        try {
            String rpId = (String) req.get(0x01 /* RPID */);
            byte[] clientDataHash = (byte[]) req.get(0x02 /* CLIENT_DATA_HASH */);

            Map<String, Object> cred = Map.of("id", authenticator.getCredId(), "type", "public-key");
            Map<String, Object> options = Map.of("rpId", rpId);

            byte[] authData = authenticator.buildAuthenticatorData(
                options, "packed", null, null, authenticator.getKeyPair());

            ByteBuffer bb = ByteBuffer.allocate(authData.length + clientDataHash.length);
            bb.put(authData);
            bb.put(clientDataHash);
            byte[] sig = authenticator.signData(
                bb.array(), authenticator.getPrivKey(), "SHA256withECDSA");

            Map<Integer, Object> rsp = new HashMap<>();
            rsp.putAll(Map.of(0x01, cred, 0x02, authData, 0x03, sig));
            if (credentialData != null && credentialData.containsKey("user")) {
                byte[] userId = credentialData.get("user");
                rsp.put(0x04, Map.of("id", userId));
            }

            byte[] encoded = Cbor.encode(rsp);
            byte[] out = new byte[encoded.length + 1];
            out[0] = (byte) Ctap2StatusCode.SUCCESS.getCode();
            System.arraycopy(encoded, 0, out, 1, encoded.length);
            return out;
        } catch (Exception e) {
            logger.error("Failed to generate signed assertion: {}", e.getMessage());
            e.printStackTrace();
            return error(Ctap2StatusCode.OTHER);
        }
    }

    private static byte[] error(Ctap2StatusCode code) {
        return new byte[]{ (byte) code.getCode() };
    }
}
