/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.fidoble;

import android.os.Handler;
import android.os.HandlerThread;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.isfs.blekey.ctap.CtapBle;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Transport-agnostic keepalive manager for FIDO BLE and BT Classic HID operations.
 * 
 *
 * <p>Per CTAP specification §11.2.9.1.4, the authenticator must send keepalive
 * messages every 100 ms during long operations to prevent timeout.</p>
 *
 * <p>Keepalive Status Codes:</p>
 * <ul>
 *   <li>0x01 — Processing (authenticator is working on the request)</li>
 *   <li>0x02 — Waiting for user presence (user interaction required)</li>
 * </ul>
 *
 * <p>The manager runs on a background thread to avoid blocking the main thread.
 * Sessions are keyed by a caller-supplied {@code String} (CID hex for HID;
 * device MAC address for BLE) so it works identically for both transports.</p>
 */
public class KeepaliveManager {

    private static final String TAG = KeepaliveManager.class.getCanonicalName();

    /** Keepalive interval per CTAP spec (100 ms). */
    private static final long KEEPALIVE_INTERVAL_MS = 100;

    /** Status: authenticator is processing. */
    public static final byte STATUS_PROCESSING = (byte) 0x01;
    /** Status: user presence required. */
    public static final byte STATUS_UP_NEEDED  = (byte) 0x02;

    // -------------------------------------------------------------------------
    // KeepaliveSender — transport abstraction
    // -------------------------------------------------------------------------

    /**
     * Transport-agnostic callback for sending a keepalive frame.
     *
     * <p>The {@code byte[]} argument is the fully-framed keepalive packet:
     * <ul>
     *   <li>BLE: {@code CtapBle.frameResponse(CMD_KEEPALIVE, [status])}</li>
     *   <li>HID: 64-byte HID input report containing the keepalive bytes</li>
     * </ul>
     * </p>
     */
    @FunctionalInterface
    public interface KeepaliveSender {
        /**
         * Sends a keepalive frame to the connected host.
         *
         * @param frame The fully-framed keepalive bytes
         */
        void send(byte[] frame);
    }

    // -------------------------------------------------------------------------
    // Internal state
    // -------------------------------------------------------------------------

    /** Background thread for keepalive operations. */
    private final HandlerThread keepaliveThread;
    private final Handler keepaliveHandler;

    /** Pluggable transport sender. */
    private final KeepaliveSender sender;

    /** Active sessions keyed by caller-supplied String (CID hex or device address). */
    private final Map<String, KeepaliveSession> activeSessions = new ConcurrentHashMap<>();

    // -------------------------------------------------------------------------
    // Session bookkeeping
    // -------------------------------------------------------------------------

    /**
     * Represents an active keepalive session for a single channel / device.
     */
    private static class KeepaliveSession {
        final AtomicBoolean active = new AtomicBoolean(true);
        byte currentStatus;
        final long startTime = System.currentTimeMillis();

        KeepaliveSession(byte initialStatus) {
            this.currentStatus = initialStatus;
        }
    }

    // -------------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------------

    /**
     * Creates a new keepalive manager that sends frames via the supplied {@code sender}.
     *
     * <p>BLE usage:
     * <pre>{@code new KeepaliveManager(frame -> fidoService.sendResponse(device, frame))}</pre>
     * BT Classic HID usage:
     * <pre>{@code new KeepaliveManager(frame -> btHidService.sendInputReport(frame))}</pre>
     * </p>
     *
     * @param sender Transport callback used to deliver each keepalive frame.
     */
    public KeepaliveManager(@NonNull KeepaliveSender sender) {
        this(sender, null);
    }

    /**
     * Test constructor — accepts an externally created {@link Handler} so unit tests
     * can control scheduling without needing a real {@link HandlerThread}.
     *
     * @param sender  Transport callback.
     * @param handler Optional handler; pass {@code null} to create a background thread.
     */
    KeepaliveManager(@NonNull KeepaliveSender sender, @Nullable Handler handler) {
        this.sender = sender;

        if (handler != null) {
            this.keepaliveHandler = handler;
            this.keepaliveThread  = null;
        } else {
            keepaliveThread = new HandlerThread("BLEKeepalive");
            keepaliveThread.start();
            keepaliveHandler = new Handler(keepaliveThread.getLooper());
        }

        Log.d(TAG, "KeepaliveManager initialized");
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Starts sending keepalive frames for the given session key.
     * Any previously active session for the same key is stopped first.
     *
     * @param key    Session key (CID hex string or device MAC address).
     * @param status Initial status byte ({@link #STATUS_PROCESSING} or {@link #STATUS_UP_NEEDED}).
     */
    public void startKeepalive(@NonNull String key, byte status) {
        stopKeepalive(key);

        KeepaliveSession session = new KeepaliveSession(status);
        activeSessions.put(key, session);

        Log.d(TAG, "Starting keepalive for key=" + key +
                   ", status=0x" + String.format("%02X", status));

        scheduleKeepalive(session);
    }

    /**
     * Updates the keepalive status for an active session.
     *
     * @param key    Session key.
     * @param status New status byte.
     */
    public void updateStatus(@NonNull String key, byte status) {
        KeepaliveSession session = activeSessions.get(key);
        if (session != null && session.active.get()) {
            session.currentStatus = status;
            Log.d(TAG, "Updated keepalive status for key=" + key +
                       " to 0x" + String.format("%02X", status));
        }
    }

    /**
     * Stops sending keepalive frames for the given session key.
     *
     * @param key Session key.
     */
    public void stopKeepalive(@NonNull String key) {
        KeepaliveSession session = activeSessions.remove(key);
        if (session != null) {
            session.active.set(false);
            long duration = System.currentTimeMillis() - session.startTime;
            Log.d(TAG, "Stopped keepalive for key=" + key + ", duration=" + duration + "ms");
        }
    }

    /**
     * Returns {@code true} if a keepalive session is currently active for the given key.
     *
     * @param key Session key.
     * @return {@code true} if the session is active.
     */
    public boolean isActive(@NonNull String key) {
        KeepaliveSession session = activeSessions.get(key);
        return session != null && session.active.get();
    }

    /**
     * Returns the number of currently active keepalive sessions.
     *
     * @return Active session count.
     */
    public int getActiveSessionCount() {
        return activeSessions.size();
    }

    /**
     * Stops all keepalive sessions and shuts down the background thread.
     */
    public void shutdown() {
        Log.d(TAG, "Shutting down keepalive manager");

        for (KeepaliveSession session : activeSessions.values()) {
            session.active.set(false);
        }
        activeSessions.clear();

        keepaliveHandler.removeCallbacksAndMessages(null);

        if (keepaliveThread != null) {
            keepaliveThread.quitSafely();
        }

        Log.d(TAG, "Keepalive manager shutdown complete");
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    private void scheduleKeepalive(@NonNull KeepaliveSession session) {
        keepaliveHandler.postDelayed(() -> {
            if (!session.active.get()) return;

            sendKeepalive(session);

            if (session.active.get()) {
                scheduleKeepalive(session);
            }
        }, KEEPALIVE_INTERVAL_MS);
    }

    private void sendKeepalive(@NonNull KeepaliveSession session) {
        try {
            byte[] keepaliveData  = new byte[]{ session.currentStatus };
            byte[] keepaliveFrame = new CtapBle().frameResponse(
                CtapBle.CMD_KEEPALIVE, keepaliveData);

            sender.send(keepaliveFrame);

            Log.v(TAG, "Sent keepalive status=0x" +
                       String.format("%02X", session.currentStatus));
        } catch (Exception e) {
            Log.e(TAG, "Failed to send keepalive: " + e.getMessage(), e);
        }
    }
}

// Made with Bob
