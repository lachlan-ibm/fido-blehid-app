/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator.implapi.pin;

import com.isfs.blekey.ctap.CtapHid;
import com.isfs.blekey.ctap.CtapTxn;
import com.isfs.blekey.data.Passkey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Owns the PIN session state: the map of CID → authenticated Passkey ({@code openKeys}),
 * the retry counter, and the {@link #updateAuthenticationState} helper that commits a
 * successful PIN verification into both the session registry and the live transaction.
 */
public class PinSessionRegistry {

    private static final Logger logger = LoggerFactory.getLogger(PinSessionRegistry.class);

    /** Maximum number of attempts (PIN or UV) before lockout. */
    public static final int MAX_PIN_RETRIES = 5;

    /** Alias kept so callers using the UV name compile without change. */
    public static final int MAX_UV_RETRIES = MAX_PIN_RETRIES;

    /** Map of channel IDs to their authenticated passkeys. */
    private static Map<byte[], Passkey> openKeys = new HashMap<>();
    /**
     * Bit values: mc=0x01, ga=0x02, cm=0x04, be=0x08, lbw=0x10, acfg=0x20.
     * CTAP 2.3 §6.5.5.7.
     */
    private static Map<byte[], Integer> tokenPermissions = new HashMap<>();

    /** Single shared retry counter for both PIN and UV attempts. */
    private static int pinRetries = MAX_PIN_RETRIES;

    private PinSessionRegistry() {}

    /** Returns the number of retry attempts remaining. */
    public static int getPinRetries() { return pinRetries; }

    /** Resets the retry counter to the maximum value. */
    public static void resetPinRetries() {
        pinRetries = MAX_PIN_RETRIES;
        logger.debug("Retry counter reset to maximum ({})", MAX_PIN_RETRIES);
    }

    /**
     * Decrements the retry counter (floor 0) on a failed PIN attempt.
     * Returns the remaining count after decrement.
     */
    public static int decrementRetries() {
        pinRetries = Math.max(0, pinRetries - 1);
        return pinRetries;
    }

    // -------------------------------------------------------------------------
    // UV retries — delegated to the single shared counter
    // -------------------------------------------------------------------------

    /** Returns the number of retry attempts remaining (same counter as PIN). */
    public static int getUvRetries() { return pinRetries; }

    /** Resets the shared retry counter (call on successful UV). */
    public static void resetUvRetries() {
        resetPinRetries();
    }

    /**
     * Decrements the shared retry counter (floor 0) on a failed UV attempt.
     * Returns the remaining count after decrement.
     */
    public static int decrementUvRetries() {
        return decrementRetries();
    }

    /**
     * Looks up an authenticated session for the given CID and populates the transaction.
     * Uses linear scan with {@link Arrays#equals} because {@code byte[]} keys do not
     * work correctly with {@link HashMap}.
     *
     * @param txn the transaction to populate
     * @return {@code true} if an authenticated session was found and applied
     */
    public static boolean loadAuthenticatedSession(CtapTxn txn) {
        byte[] targetCid = txn.getCid();
        for (Map.Entry<byte[], Passkey> entry : openKeys.entrySet()) {
            if (Arrays.equals(entry.getKey(), targetCid)) {
                logger.debug("Found authenticated session for CID, loading passkey");
                txn.setPasskey(entry.getValue());
                return true;
            }
        }
        logger.debug("No authenticated session found for CID");
        return false;
    }

    /**
     * Commits a successful PIN verification into the session registry and the live txn.
     * Resets the retry counter, stores the PIN token, hash, and permissions on the txn,
     * marks UP as collected, and propagates the updated txn to {@link CtapHid}.
     *
     */
    public static void updateAuthenticationState(CtapTxn txn, Passkey pkeyFile,
                                                  byte[] pinToken, byte[] pinHash,
                                                  int permissions) {
        openKeys.put(txn.getCid(), pkeyFile);
        tokenPermissions.put(txn.getCid(), permissions);
        resetPinRetries();
        txn.setPinAuthTkn(pinToken);
        txn.setPinHash(pinHash);
        txn.setPasskey(pkeyFile);
        txn.setUserPresent(true);
        logger.debug("PIN token stored in transaction, size: {} bytes, permissions=0x{}",
                     pinToken != null ? pinToken.length : 0,
                     Integer.toHexString(permissions));
        CtapHid.updateCidTransaction(txn.getCid(), txn);
        logger.debug("Updated CID transaction with authenticated passkey");
    }

    /**
     * Returns the permissions bitmask for the active PIN session on the given CID, or
     * {@code 0} if no authenticated session exists for that CID.
     *
     * <p>A return value of {@code 0} means no PIN token was issued on this channel —
     * permission checks should be skipped in that case (platform-key path).</p>
     *
     * @param cid channel identifier
     * @return permissions bitmask (CTAP 2.3 §6.5.5.7), or {@code 0} if none
     */
    public static int getPermissions(byte[] cid) {
        for (Map.Entry<byte[], Integer> entry : tokenPermissions.entrySet()) {
            if (Arrays.equals(entry.getKey(), cid)) return entry.getValue();
        }
        return 0;
    }
}
