/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator.implapi;

import com.isfs.blekey.ctap.Ctap2StatusCode;
import com.isfs.blekey.ctap.CtapTxn;
import com.isfs.blekey.data.Passkey;
import com.isfs.blekey.util.FileUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Manages resident credential storage — persisting credentials into the
 * {@link Passkey} object and writing it to disk.
 *
 * <p>Also owns the duplicate-detection and exclude-list helpers that operate
 * on the stored credential list.</p>
 *
 * <p>Result type {@link CredentialInfo} lives as a package-private top-level
 * class at the bottom of this file (§6g).</p>
 */
public class ResidentCredentialStore {

    private static final Logger logger = LoggerFactory.getLogger(ResidentCredentialStore.class);

    private ResidentCredentialStore() {}

    // -------------------------------------------------------------------------
    // Public entry points
    // -------------------------------------------------------------------------

    /**
     * Stores a resident credential into the passkey and persists it to disk.
     */
    public static Ctap2StatusCode storeResidentCredential(
            Map<Integer, Object> req,
            byte[] credentialId,
            Passkey passkey,
            CtapTxn txn) {

        logger.info("Storing resident credential - CID: {}",
                    txn.getCid() != null ? Arrays.toString(txn.getCid()) : "null");

        Ctap2StatusCode error = validatePasskeyAndFile(passkey, txn);
        if (error != null) return error;

        CredentialInfo credInfo = extractCredentialInfo(req);
        if (isDuplicateResidentCredential(passkey, credInfo.rpIdBytes, credInfo.userId)) {
            return Ctap2StatusCode.CREDENTIAL_EXCLUDED;
        }
        passkey.addResCred(credInfo.rpIdBytes, credentialId, credInfo.userId);
        logger.debug("Added resident credential for RP: {}, total count: {}",
                     credInfo.rpId, passkey.getResCreds().size());
        return persistPasskey(passkey, txn.getPinHash(), resolvePasskeyFile(txn));
    }

    /**
     * Returns {@code true} if {@code credId} matches any stored resident credential ID.
     */
    public static boolean isCredentialExcluded(byte[] credId, Passkey passkey) {
        if (passkey == null || credId == null) return false;
        List<Map<String, byte[]>> resCreds = passkey.getResCreds();
        if (resCreds == null) return false;
        for (Map<String, byte[]> cred : resCreds) {
            byte[] stored = cred.get("cred.id");
            if (stored != null && Arrays.equals(credId, stored)) return true;
        }
        return false;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    static boolean isDuplicateResidentCredential(
            Passkey passkey, byte[] rpIdBytes, byte[] userId) {
        List<Map<String, byte[]>> resCreds = passkey.getResCreds();
        if (resCreds == null || resCreds.isEmpty()) {
            logger.debug("No existing credentials to check for duplicates");
            return false;
        }
        logger.debug("Checking {} existing credentials for duplicates", resCreds.size());
        boolean isDuplicate = resCreds.stream().anyMatch(existingCred -> {
            byte[] existingRpId  = existingCred.get("rp.id");
            byte[] existingUser  = existingCred.get("user.id");
            return existingRpId != null && existingUser != null
                && Arrays.equals(existingRpId, rpIdBytes)
                && Arrays.equals(existingUser, userId);
        });
        if (isDuplicate) {
            logger.warn("Duplicate resident credential detected for RP: {}",
                        new String(rpIdBytes, StandardCharsets.UTF_8));
        }
        return isDuplicate;
    }

    private static Ctap2StatusCode validatePasskeyAndFile(Passkey passkey, CtapTxn txn) {
        if (passkey == null) {
            logger.error("Cannot store resident credential: passkey is null");
            return Ctap2StatusCode.OTHER;
        }
        File passkeyFile = resolvePasskeyFile(txn);
        if (passkeyFile == null) {
            logger.error("Cannot resolve passkey file");
            return Ctap2StatusCode.OTHER;
        }
        if (!passkeyFile.exists()) {
            logger.error("Passkey file does not exist: {}", passkeyFile.getAbsolutePath());
            return Ctap2StatusCode.OTHER;
        }
        return null;
    }

    static File resolvePasskeyFile(CtapTxn txn) {
        String fileName = txn.getPasskeyFileName();
        if (fileName == null) {
            logger.error("Cannot persist passkey: missing file name");
            return null;
        }
        String fido2Home = FileUtils.getFido2Home();
        if (fido2Home == null || fido2Home.isEmpty()) {
            logger.error("FIDO2_HOME not set, cannot persist passkey");
            return null;
        }
        return new File(fido2Home + File.separator + fileName);
    }

    private static Ctap2StatusCode persistPasskey(
            Passkey passkey, byte[] pinHash, File passkeyFile) {
        if (pinHash == null) {
            logger.error("Cannot persist passkey: missing PIN hash");
            return Ctap2StatusCode.OTHER;
        }
        boolean success = Passkey.writeKey(passkey, pinHash, passkeyFile);
        if (!success) {
            logger.error("Failed to persist passkey to file: {}", passkeyFile.getAbsolutePath());
            return Ctap2StatusCode.OTHER;
        }
        logger.info("Successfully persisted passkey to file: {}", passkeyFile.getName());
        return Ctap2StatusCode.SUCCESS;
    }

    @SuppressWarnings("unchecked")
    private static CredentialInfo extractCredentialInfo(Map<Integer, Object> req) {
        Map<String, Object> rp = (Map<String, Object>) req.get(0x02);
        String rpId = (String) rp.get("id");
        byte[] rpIdBytes = rpId.getBytes(StandardCharsets.UTF_8);
        Map<String, Object> user = (Map<String, Object>) req.get(0x03);
        byte[] userId = (byte[]) user.get("id");
        return new CredentialInfo(rpId, rpIdBytes, userId);
    }
}

// ---------------------------------------------------------------------------
// Result type co-located with its owner (§6g)
// ---------------------------------------------------------------------------

/** Immutable holder for RP ID and user ID extracted from a makeCredential request. */
class CredentialInfo {
    final String rpId;
    final byte[] rpIdBytes;
    final byte[] userId;

    CredentialInfo(String rpId, byte[] rpIdBytes, byte[] userId) {
        this.rpId = rpId;
        this.rpIdBytes = rpIdBytes;
        this.userId = userId;
    }
}
