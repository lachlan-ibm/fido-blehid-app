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

    /** Maximum number of PIN attempts before lockout. */
    public static final int MAX_PIN_RETRIES = 5;

    /**
     * Maximum number of built-in UV attempts before UV lockout.
     * CTAP2.3 spec §6.5.5.7.3 allows 1–25; we use 8.
     */
    public static final int MAX_UV_RETRIES = 8;

    /** Map of channel IDs to their authenticated passkeys. */
    private static Map<byte[], Passkey> openKeys = new HashMap<>();

    /** Number of PIN retry attempts remaining before lockout. */
    private static int pinRetries = MAX_PIN_RETRIES;

    /** Number of built-in UV (in-app PIN) retry attempts remaining before UV lockout. */
    private static int uvRetries = MAX_UV_RETRIES;

    private PinSessionRegistry() {}

    /** Returns the number of PIN retry attempts remaining. */
    public static int getPinRetries() { return pinRetries; }

    /** Resets the PIN retry counter to the maximum value. */
    public static void resetPinRetries() {
        pinRetries = MAX_PIN_RETRIES;
        logger.info("PIN retry counter reset to maximum ({})", MAX_PIN_RETRIES);
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
    // UV retries (built-in UV / in-app PIN Activity)
    // -------------------------------------------------------------------------

    /** Returns the number of built-in UV retry attempts remaining. */
    public static int getUvRetries() { return uvRetries; }

    /** Resets the UV retry counter to the maximum value (call on successful UV). */
    public static void resetUvRetries() {
        uvRetries = MAX_UV_RETRIES;
        logger.info("UV retry counter reset to maximum ({})", MAX_UV_RETRIES);
    }

    /**
     * Decrements the UV retry counter (floor 0) on a failed built-in UV attempt.
     * Returns the remaining count after decrement.
     */
    public static int decrementUvRetries() {
        uvRetries = Math.max(0, uvRetries - 1);
        return uvRetries;
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
     * Resets the retry counter, stores the PIN token and hash on the txn, marks UP
     * as collected, and propagates the updated txn to {@link CtapHid}.
     */
    public static void updateAuthenticationState(CtapTxn txn, Passkey pkeyFile,
                                                  byte[] pinToken, byte[] pinHash) {
        openKeys.put(txn.getCid(), pkeyFile);
        pinRetries = MAX_PIN_RETRIES;
        txn.setPinAuthTkn(pinToken);
        txn.setPinHash(pinHash);
        txn.setPasskey(pkeyFile);
        txn.setUserPresent(true);
        logger.debug("PIN token stored in transaction, size: {} bytes",
                     pinToken != null ? pinToken.length : 0);
        CtapHid.updateCidTransaction(txn.getCid(), txn);
        logger.debug("Updated CID transaction with authenticated passkey");
    }
}
