/*
 * Copyright IBM 2025
 */

package com.isfs.blekey.service;

import android.annotation.SuppressLint;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ServiceInfo;
import android.os.BatteryManager;
import android.os.Binder;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.PowerManager;
import android.util.Log;

import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;

import com.isfs.blekey.R;
import com.isfs.blekey.authenticator.AuthenticatorAPI;
import com.isfs.blekey.authenticator.AuthenticatorAPI.UpUvCallback;
import com.isfs.blekey.authenticator.KeepaliveManager;
import com.isfs.blekey.authenticator.UpUvRequestCtx;
import com.isfs.blekey.authenticator.UpUvRequestCtx.Outcome;
import com.isfs.blekey.authenticator.UxInteractionLock;
import com.isfs.blekey.bthid.BTHIDService;
import com.isfs.blekey.bthid.HIDPasskey;
import com.isfs.blekey.ctap.Ctap2StatusCode;
import com.isfs.blekey.ctap.CtapHid;
import com.isfs.blekey.ctap.CtapTxn;
import com.isfs.blekey.fidoble.FIDOBLEService;
import com.isfs.blekey.util.KeyUtils;

import java.security.PrivateKey;
import java.util.Arrays;

import javax.crypto.KeyAgreement;

/**
 * Single Android foreground service that owns the Bluetooth connection lifecycle, the
 * UP/UV ceremony FSM, battery monitoring, and keepalive management.
 *
 * <p>On {@link #onStartCommand} the service attempts to start the Classic-BT HID
 * transport ({@link BTHIDService}).  If the device does not support
 * {@code BluetoothProfile.HID_DEVICE} or the registration fails, it falls back to the
 * FIDO BLE GATT transport ({@link FIDOBLEService}).  Only one transport is active at a
 * time.  If neither transport starts successfully the service stops itself — the
 * {@code ServerFragment} BT-status icon reflects the resulting state.</p>
 *
 * <p>The UP/UV callback is registered <em>before</em> either transport is started so
 * that CTAP requests arriving on the BLE path are automatically routed through the same
 * {@code UpHandler} as the HID path.</p>
 */
public class BluetoothCtapService extends Service {

    private static final String TAG = BluetoothCtapService.class.getCanonicalName();
    private static final int NOTIFICATION_ID = 1001;
    private static final String CHANNEL_ID = "bt_hid_channel";
    private static final int MIN_BATTERY_LEVEL = 15;
    private static final int LOW_BATTERY_LEVEL = 10;

    // -------------------------------------------------------------------------
    // UP constants
    // -------------------------------------------------------------------------

    /** Dedicated notification channel for UP alerts (IMPORTANCE_HIGH for heads-up / lock screen). */
    static final String UP_CHANNEL_ID = "fido_up_channel";
    /** Notification ID for the UP prompt notification. */
    static final int UP_NOTIFICATION_ID = 4200;
    /** Stage 1: user to tap Allow/Deny after the dialog/notification appears. */
    public static final int UP_DIALOG_TIMEOUT_MS = 8_000;
    /** Stage 2: user to meet biometric challenge after Allow. */
    public static final int UP_BIO_TIMEOUT_MS = 12_000;
    /** Stage 0: device is backgrounded/screen-off; waiting for app to foreground. */
    public static final int UP_BACKGROUND_TIMEOUT_MS = 5_000;

    private int getUpDialogTimeoutMs() {
        return getSharedPreferences("HIDServicePrefs", Context.MODE_PRIVATE)
                .getInt("up_dialog_timeout_ms", UP_DIALOG_TIMEOUT_MS);
    }

    private int getUpBioTimeoutMs() {
        return getSharedPreferences("HIDServicePrefs", Context.MODE_PRIVATE)
                .getInt("up_bio_timeout_ms", UP_BIO_TIMEOUT_MS);
    }

    private int getUpBackgroundTimeoutMs() {
        return getSharedPreferences("HIDServicePrefs", Context.MODE_PRIVATE)
                .getInt("up_background_timeout_ms", UP_BACKGROUND_TIMEOUT_MS);
    }

    // -------------------------------------------------------------------------
    // Service-level fields
    // -------------------------------------------------------------------------

    /** Non-null while the HID transport is active. */
    @Nullable private BTHIDService hidService;
    /** Non-null while the BLE GATT transport is active. */
    @Nullable private FIDOBLEService bleService;

    private final IBinder binder = new LocalBinder();
    private BroadcastReceiver batteryReceiver;
    private boolean lowBatteryMode = false;

    // -------------------------------------------------------------------------
    // UP ownership
    // -------------------------------------------------------------------------

    /**
     * Active keepalive manager — {@link HidKeepaliveManager} for HID; the
     * {@link com.isfs.blekey.fidoble.KeepaliveManager} instance for BLE.  Set in
     * {@link #onStartCommand} after the transport is chosen; cleared in
     * {@link #onDestroy}.
     */
    @Nullable private KeepaliveManager keepaliveManager;

    /** Pending context; non-null while a UP ceremony is in progress. */
    private volatile UpUvRequestCtx pendingContext = null;
    /** Pending txn; mirrors pendingContext.getTxn() for convenience. */
    private volatile CtapTxn pendingUpTxn = null;

    private final Handler upHandler = new Handler(Looper.getMainLooper());
    private Runnable timeoutRunnable = null;
    /** Non-null while Stage 0 (background) timeout is running. */
    private Runnable backgroundTimeoutRunnable = null;
    /** Fires 15 s after the last completed lock-owning command to evict the CID (G7). */
    private Runnable cidInactivityRunnable = null;

    private PowerManager.WakeLock upWakeLock = null;

    /**
     * Volatile reference to the currently-bound activity delegate.
     * Null when the activity is not in the foreground / not bound.
     */
    private volatile UpActivityDelegate activityDelegate = null;

    // -------------------------------------------------------------------------
    // UpActivityDelegate — implemented by ServerFragment
    // -------------------------------------------------------------------------

    /**
     * Callback interface implemented by {@code ServerFragment} to show a biometric
     * prompt after the user taps Allow.
     */
    public interface BiometricDelegate {
        void showBiometricPrompt(Runnable onSuccess, Runnable onFailed);
    }

    /**
     * Callback interface for the bound {@code ServerFragment}.
     */
    public interface UpActivityDelegate {
        void showUpDialog(@Nullable String rpId);
    }

    // -------------------------------------------------------------------------
    // Binder
    // -------------------------------------------------------------------------

    public class LocalBinder extends Binder {
        public BluetoothCtapService getService() {
            return BluetoothCtapService.this;
        }
    }

    // -------------------------------------------------------------------------
    // Service lifecycle
    // -------------------------------------------------------------------------

    @Override
    public void onCreate() {
        super.onCreate();
        Log.d(TAG, "onCreate");
        createNotificationChannel();
        createUpNotificationChannel();
        registerBatteryReceiver();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.d(TAG, "onStartCommand");

        Notification notification = createNotification();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE);
        } else {
            startForeground(NOTIFICATION_ID, notification);
        }

        // Register the UP/UV callback BEFORE starting any transport so the BLE path
        // benefits from the same UpHandler as the HID path.
        AuthenticatorAPI.setUpUvCallback(new UpHandler());

        if (hidService == null && bleService == null) {
            if (!startHidTransport()) {
                // HID not available — try BLE GATT.
                if (!startBleTransport()) {
                    Log.e(TAG, "Neither HID nor BLE transport could be started");
                    stopSelf();
                    return START_NOT_STICKY;
                }
            }
        } else {
            Log.d(TAG, "Transport already running");
        }

        AuthenticatorAPI.setDeferredResponseSender(
            (txn, response) -> sendDeferred(txn, response));
        if (keepaliveManager != null) {
            AuthenticatorAPI.setKeepaliveManager(keepaliveManager);
        }

        CtapHid.setOnCancelCallback(() -> upHandler.post(() -> {
            UpActivityDelegate d = activityDelegate;
            if (d instanceof CancelListener) ((CancelListener) d).onUpCancelled();
            cancelCidInactivityTimer();
            stopUpKeepalive();
            releaseUpWakeLock();
            clearPendingUpState();
        }));

        return START_STICKY;
    }

    /**
     * Attempts to start the Classic-BT HID transport.
     *
     * @return {@code true} if the HID service registered successfully.
     */
    private boolean startHidTransport() {
        try {
            Log.d(TAG, "Starting BTHIDService…");
            BTHIDService svc = new BTHIDService(this);
            svc.setDeviceName(getString(R.string.ble_beekey));
            if (!svc.registerHidDevice()) {
                Log.e(TAG, "BTHIDService: registerHidDevice() failed");
                return false;
            }
            hidService = svc;
            keepaliveManager = new HidKeepaliveManager();
            Log.d(TAG, "BTHIDService started (HID transport active)");
            return true;
        } catch (UnsupportedOperationException e) {
            Log.w(TAG, "BTHIDService not supported: " + e.getMessage());
            return false;
        } catch (Exception e) {
            Log.e(TAG, "BTHIDService unexpected error: " + e.getMessage(), e);
            return false;
        }
    }

    /**
     * Attempts to start the FIDO BLE GATT transport.
     *
     * @return {@code true} if the BLE service initialised successfully.
     */
    private boolean startBleTransport() {
        try {
            Log.d(TAG, "Starting FIDOBLEService (BLE GATT transport)…");
            BleKeepaliveManager bm = new BleKeepaliveManager();
            FIDOBLEService svc = new FIDOBLEService(this, bm.inner());
            svc.startAdvertising();
            bleService = svc;
            keepaliveManager = bm;
            Log.d(TAG, "FIDOBLEService started (BLE transport active)");
            return true;
        } catch (UnsupportedOperationException e) {
            Log.w(TAG, "FIDOBLEService not supported: " + e.getMessage());
            return false;
        } catch (Exception e) {
            Log.e(TAG, "FIDOBLEService unexpected error: " + e.getMessage(), e);
            return false;
        }
    }

    @Override
    public void onDestroy() {
        Log.d(TAG, "onDestroy");
        AuthenticatorAPI.setUpUvCallback(null);
        AuthenticatorAPI.setDeferredResponseSender(null);
        AuthenticatorAPI.setKeepaliveManager(null);

        if (keepaliveManager instanceof HidKeepaliveManager) {
            ((HidKeepaliveManager) keepaliveManager).shutdown();
        } else if (keepaliveManager instanceof BleKeepaliveManager) {
            ((BleKeepaliveManager) keepaliveManager).shutdown();
        }
        keepaliveManager = null;

        if (hidService != null) {
            hidService.unregisterHidDevice();
            hidService = null;
        }
        if (bleService != null) {
            bleService.close();
            bleService = null;
        }

        unregisterBatteryReceiver();
        super.onDestroy();
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return binder;
    }

    // -------------------------------------------------------------------------
    // UP delegate wiring
    // -------------------------------------------------------------------------

    public void setActivityDelegate(@Nullable UpActivityDelegate delegate) {
        activityDelegate = delegate;
    }

    // -------------------------------------------------------------------------
    // UP delivery methods (called by ServerFragment button handlers)
    // -------------------------------------------------------------------------

    /** Approve — full CTAP2 path. */
    public void deliverUpApproved() {
        upHandler.post(() -> {
            cancelTimeout();
            cancelUpNotification();
            if (pendingContext == null) {
                finishUpDelivery();
                return;
            }

            CtapTxn txn = pendingUpTxn;

            if (UxInteractionLock.get().isGrantActive()) {
                pendingContext.buildResponse(Outcome.APPROVED, response -> {
                    if (response != null) sendDeferred(txn, response);
                    finishUpDelivery();
                });
                return;
            }

            if (!pendingContext.requiresBiometric()) {
                pendingContext.buildResponse(Outcome.APPROVED, response -> {
                    if (response != null) sendDeferred(txn, response);
                    finishUpDelivery();
                });
                return;
            }

            UpActivityDelegate d = activityDelegate;
            if (!(d instanceof BiometricDelegate)) {
                Log.w(TAG, "deliverUpApproved: no BiometricDelegate — denying");
                deliverUpDenied();
                return;
            }

            if (pendingContext.getCeremonyType() == UpUvRequestCtx.CeremonyType.GET_INFO) {
                pendingContext.buildResponse(Outcome.APPROVED, response -> {
                    if (response != null) sendDeferred(txn, response);
                });
            }

            timeoutRunnable = this::deliverTimeoutInternal;
            upHandler.postDelayed(timeoutRunnable, getUpBioTimeoutMs());

            ((BiometricDelegate) d).showBiometricPrompt(
                /* onSuccess */ () -> upHandler.post(() -> {
                    cancelTimeout();
                    try {
                        PrivateKey platKey = KeyUtils.getPlatformKey();
                        if (platKey != null) {
                            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
                            ka.init(platKey);
                            ka.doPhase(KeyUtils.getKeystoreManager().getEC256PublicKey(), true);
                            byte[] ikm = ka.generateSecret();
                            long validityMs = KeyUtils.getKeystoreManager().getBiometricValidityMs();
                            UxInteractionLock.get().recordBioGrant(ikm, validityMs);
                        }
                    } catch (Exception e) {
                        Log.e(TAG, "deliverUpApproved: IKM derivation failed", e);
                    }
                    txn.setUserPresent(true);
                    UxInteractionLock.get().setUxState(UxInteractionLock.UxState.APPROVED);
                    UxInteractionLock.get().releaseLatch();
                    pendingContext.buildResponse(Outcome.APPROVED, response -> {
                        if (response != null) sendDeferred(txn, response);
                        finishUpDelivery();
                    });
                }),
                /* onFailed  */ () -> deliverUpDenied()
            );
        });
    }

    /** Deny. */
    public void deliverUpDenied() {
        upHandler.post(() -> {
            cancelTimeout();
            cancelCidInactivityTimer();
            cancelUpNotification();
            if (pendingUpTxn != null) {
                UxInteractionLock.get().setUxState(UxInteractionLock.UxState.DENIED);
                UxInteractionLock.get().releaseLatch();
                AuthenticatorAPI.setUxLockDenied(UP_BIO_TIMEOUT_MS);
            }
            if (pendingContext != null) {
                pendingContext.buildResponse(Outcome.DENIED, response -> {
                    if (response != null) sendDeferred(pendingUpTxn, response);
                    finishUpDelivery();
                });
            } else {
                finishUpDelivery();
            }
        });
    }

    /** Returns {@code true} when a UP ceremony is currently in progress. */
    public boolean hasPendingUpRequest() {
        return pendingContext != null;
    }

    /**
     * Returns the transaction associated with the current pending UP ceremony, or
     * {@code null} if none is in progress.
     */
    public CtapTxn getPendingUpTxn() {
        return pendingUpTxn;
    }

    /** Cancels the pending UP notification (called by activity when dialog is visible). */
    public void cancelUpNotification() {
        NotificationManagerCompat.from(this).cancel(UP_NOTIFICATION_ID);
    }

    // -------------------------------------------------------------------------
    // HidKeepaliveManager — BT Classic HID keepalive (HID framing, §8)
    // -------------------------------------------------------------------------

    private final class HidKeepaliveManager implements KeepaliveManager {

        private static final long KEEPALIVE_INTERVAL_MS = 100L;

        private final android.os.HandlerThread keepaliveThread;
        private final android.os.Handler keepaliveHandler;

        private final java.util.Map<String, KeepaliveSession> activeSessions =
                new java.util.concurrent.ConcurrentHashMap<>();

        HidKeepaliveManager() {
            keepaliveThread = new android.os.HandlerThread("HidKeepalive");
            keepaliveThread.start();
            keepaliveHandler = new android.os.Handler(keepaliveThread.getLooper());
        }

        @Override
        public void startKeepalive(CtapTxn txn, byte status) {
            String key = cidHex(txn);
            stopByKey(key);
            KeepaliveSession session = new KeepaliveSession(key, status);
            activeSessions.put(key, session);
            Log.d(TAG, "HidKeepalive start key=" + key);
            schedule(session);
        }

        @Override
        public void stopKeepalive(CtapTxn txn) {
            stopByKey(cidHex(txn));
        }

        private void stopByKey(String key) {
            KeepaliveSession session = activeSessions.remove(key);
            if (session != null) {
                session.active = false;
                keepaliveHandler.removeCallbacksAndMessages(session);
            }
        }

        void shutdown() {
            for (KeepaliveSession s : activeSessions.values()) s.active = false;
            activeSessions.clear();
            keepaliveHandler.removeCallbacksAndMessages(null);
            keepaliveThread.quitSafely();
        }

        private void schedule(KeepaliveSession session) {
            keepaliveHandler.postDelayed(session.runnable, session, KEEPALIVE_INTERVAL_MS);
        }

        private void sendFrame(KeepaliveSession session) {
            if (hidService == null) return;
            byte[] cid = hexToBytes(session.key);
            if (cid == null) return;
            hidService.sendResponse(CtapHid.buildHidKeepaliveFrame(cid, session.status));
        }

        private String cidHex(CtapTxn txn) {
            return bytesToHex(txn.getCid());
        }

        private byte[] hexToBytes(String hex) {
            if (hex == null || hex.length() % 2 != 0) return null;
            byte[] b = new byte[hex.length() / 2];
            for (int i = 0; i < b.length; i++) {
                b[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
            }
            return b;
        }

        private final class KeepaliveSession {
            final String key;
            volatile byte status;
            volatile boolean active = true;

            KeepaliveSession(String key, byte status) {
                this.key = key;
                this.status = status;
            }

            final Runnable runnable = () -> {
                if (!active) return;
                sendFrame(this);
                if (active) schedule(this);
            };
        }
    }

    // -------------------------------------------------------------------------
    // BleKeepaliveManager — FIDO BLE GATT keepalive (BLE framing, §11)
    // -------------------------------------------------------------------------

    /**
     * Implements {@link KeepaliveManager} for the BLE transport.
     * Delegates to {@link com.isfs.blekey.fidoble.KeepaliveManager} which keys
     * sessions by device MAC address string.  On the BLE path the {@link CtapTxn}
     * is constructed with {@code deviceIdentifier = device.getAddress()}, so that
     * value is the natural session key.
     */
    private final class BleKeepaliveManager implements KeepaliveManager {

        private final com.isfs.blekey.fidoble.KeepaliveManager delegate;

        BleKeepaliveManager() {
            delegate = new com.isfs.blekey.fidoble.KeepaliveManager(frame -> {
                FIDOBLEService svc = bleService;
                if (svc != null) svc.sendResponse(frame);
            });
        }

        /** Returns the underlying {@link com.isfs.blekey.fidoble.KeepaliveManager}
         *  for injection into {@link FIDOBLEService}. */
        com.isfs.blekey.fidoble.KeepaliveManager inner() {
            return delegate;
        }

        @Override
        public void startKeepalive(CtapTxn txn, byte status) {
            String key = txn.getDeviceIdentifier();
            if (key == null) key = bytesToHex(txn.getCid());
            delegate.startKeepalive(key, status);
        }

        @Override
        public void stopKeepalive(CtapTxn txn) {
            String key = txn.getDeviceIdentifier();
            if (key == null) key = bytesToHex(txn.getCid());
            delegate.stopKeepalive(key);
        }

        void shutdown() {
            delegate.shutdown();
        }
    }

    // -------------------------------------------------------------------------
    // UpHandler
    // -------------------------------------------------------------------------

    private final class UpHandler implements UpUvCallback {
        @Override
        public void onUpUvRequired(UpUvRequestCtx context) {
            acquireUpWakeLock();

            CtapTxn txn    = context.getTxn();
            byte[]  cid    = txn.getCid();
            String  cidKey = bytesToHex(cid);

            pendingContext = context;
            pendingUpTxn   = txn;

            upHandler.post(() -> {
                if (context.getCeremonyType() == UpUvRequestCtx.CeremonyType.GET_TKN_UV) {
                    Log.d(TAG, "UP: GET_TKN_UV — launching UvPinEntryActivity");
                    startUpTimeout();
                    Intent pinIntent = new Intent(BluetoothCtapService.this,
                            com.isfs.blekey.activity.UvPinEntryActivity.class);
                    pinIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                    startActivity(pinIntent);
                    return;
                }

                if (txn.isUserPresent() && context.requiresBiometric()) {
                    Log.d(TAG, "UP: txn already has UP + requiresBiometric — skipping dialog");
                    deliverUpApproved();
                    return;
                }

                Log.d(TAG, "UP: cidKey=" + cidKey);
                UpActivityDelegate d = activityDelegate;
                if (d != null) {
                    startUpTimeout();
                    d.showUpDialog(context.getRpId());
                } else {
                    startBackgroundTimeout();
                    postUpNotification();
                }
            });
        }
    }

    // -------------------------------------------------------------------------
    // UP internal helpers
    // -------------------------------------------------------------------------

    private void startUpTimeout() {
        timeoutRunnable = this::deliverTimeoutInternal;
        upHandler.postDelayed(timeoutRunnable, getUpDialogTimeoutMs());
    }

    private void cancelTimeout() {
        if (timeoutRunnable != null) {
            upHandler.removeCallbacks(timeoutRunnable);
            timeoutRunnable = null;
        }
        cancelBackgroundTimeout();
    }

    private void startBackgroundTimeout() {
        backgroundTimeoutRunnable = this::deliverTimeoutInternal;
        upHandler.postDelayed(backgroundTimeoutRunnable, getUpBackgroundTimeoutMs());
    }

    private void cancelBackgroundTimeout() {
        if (backgroundTimeoutRunnable != null) {
            upHandler.removeCallbacks(backgroundTimeoutRunnable);
            backgroundTimeoutRunnable = null;
        }
    }

    private void deliverTimeoutInternal() {
        cancelCidInactivityTimer();
        cancelUpNotification();
        UpActivityDelegate d = activityDelegate;
        if (d instanceof TimeoutListener) ((TimeoutListener) d).onUpTimeout();
        if (pendingUpTxn != null) {
            AuthenticatorAPI.setUxLockDenied(UP_BIO_TIMEOUT_MS);
            UxInteractionLock.get().releaseLatch();
        }
        if (pendingContext != null) {
            sendDeferred(pendingUpTxn,
                AuthenticatorAPI.buildErrorResponse(Ctap2StatusCode.USER_ACTION_TIMEOUT));
        }
        finishUpDelivery();
    }

    /**
     * Routes a deferred CTAP response through the active transport's framing layer.
     *
     * <p>For the HID path this calls {@link HIDPasskey#sendDeferredResponse} which applies
     * HID framing.  The BLE path sends responses inline inside
     * {@code FIDOBLEService.processCtapMessage}; there is no deferred BLE path.</p>
     */
    private void sendDeferred(CtapTxn txn, byte[] response) {
        HIDPasskey pk = getHIDPasskey();
        if (pk != null && response != null) pk.sendDeferredResponse(txn, response);
        if (txn != null && txn.getCid() != null) {
            resetCidInactivityTimer(txn.getCid());
        }
    }

    // -------------------------------------------------------------------------
    // CID inactivity timer (G7)
    // -------------------------------------------------------------------------

    private void resetCidInactivityTimer(byte[] cid) {
        if (cidInactivityRunnable != null) {
            upHandler.removeCallbacks(cidInactivityRunnable);
        }
        cidInactivityRunnable = () -> onCidInactivityExpired(cid);
        upHandler.postDelayed(cidInactivityRunnable, UxInteractionLock.LOCK_TIMEOUT_MS);
    }

    private void cancelCidInactivityTimer() {
        if (cidInactivityRunnable != null) {
            upHandler.removeCallbacks(cidInactivityRunnable);
            cidInactivityRunnable = null;
        }
    }

    private void onCidInactivityExpired(byte[] cid) {
        cidInactivityRunnable = null;
        Log.d(TAG, "CID inactivity expired: " + bytesToHex(cid));
        CtapTxn txn = CtapHid.getCidTransaction(cid);
        if (txn != null) {
            UxInteractionLock.get().setUxState(UxInteractionLock.UxState.DENIED);
            UxInteractionLock.get().releaseLatch();
            CtapHid deferredCmd = txn.takeDeferredCmd();
            if (deferredCmd != null) {
                try {
                    deferredCmd.injectDeferredResponse(
                        new byte[]{ (byte) Ctap2StatusCode.KEEPALIVE_CANCEL.getCode() });
                } catch (Exception e) {
                    Log.e(TAG, "onCidInactivityExpired: inject failed", e);
                }
            }
        }
        CtapHid.evictCid(cid);
        if (pendingUpTxn != null && Arrays.equals(pendingUpTxn.getCid(), cid)) {
            finishUpDelivery();
        }
    }

    private void finishUpDelivery() {
        stopUpKeepalive();
        releaseUpWakeLock();
        clearPendingUpState();
    }

    private void stopUpKeepalive() {
        if (pendingUpTxn != null && keepaliveManager != null) {
            keepaliveManager.stopKeepalive(pendingUpTxn);
        }
    }

    private void clearPendingUpState() {
        pendingContext = null;
        pendingUpTxn   = null;
    }

    private void acquireUpWakeLock() {
        if (upWakeLock != null && upWakeLock.isHeld()) return;
        PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
        if (pm == null) return;
        long maxMs = getUpBackgroundTimeoutMs()
                   + getUpDialogTimeoutMs()
                   + getUpBioTimeoutMs()
                   + 2_000L;
        upWakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "blekey:upPrompt");
        upWakeLock.acquire(maxMs);
        Log.d(TAG, "UP wake lock acquired for " + maxMs + " ms");
    }

    private void releaseUpWakeLock() {
        if (upWakeLock != null && upWakeLock.isHeld()) {
            upWakeLock.release();
            Log.d(TAG, "UP wake lock released");
        }
        upWakeLock = null;
    }

    /** Called by {@code ServerFragment.showUpDialog} when the fragment is backgrounded. */
    public void postUpNotificationPublic() {
        postUpNotification();
    }

    /**
     * Called by the fragment when it resumes and a UP ceremony is still in progress.
     * Transitions Stage 0 → Stage 1.  Returns {@code null} if no ceremony is pending.
     */
    @Nullable
    public String transitionToForeground() {
        if (pendingContext == null) return null;
        cancelBackgroundTimeout();
        if (timeoutRunnable == null) startUpTimeout();
        return pendingContext.getRpId();
    }

    @SuppressLint("MissingPermission")
    private void postUpNotification() {
        Intent tapIntent = new Intent(this, com.isfs.blekey.MainActivity.class)
            .addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT
                    | Intent.FLAG_ACTIVITY_SINGLE_TOP
                    | Intent.FLAG_ACTIVITY_NEW_TASK);

        PendingIntent tapPi = PendingIntent.getActivity(this, 0, tapIntent,
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        NotificationCompat.Builder b = new NotificationCompat.Builder(this, UP_CHANNEL_ID)
            .setSmallIcon(R.drawable.bee)
            .setContentTitle(getString(R.string.up_notification_title))
            .setContentText(getString(R.string.up_notification_text))
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setAutoCancel(true)
            .setOngoing(false)
            .setVibrate(new long[]{0, 250, 100, 250})
            .setContentIntent(tapPi);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            if (nm != null && nm.canUseFullScreenIntent()) {
                PendingIntent fsPi = PendingIntent.getActivity(this, 1, tapIntent,
                    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
                b.setFullScreenIntent(fsPi, true);
            } else {
                Log.w(TAG, "USE_FULL_SCREEN_INTENT not granted");
            }
        } else {
            PendingIntent fsPi = PendingIntent.getActivity(this, 1, tapIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
            b.setFullScreenIntent(fsPi, true);
        }

        NotificationManagerCompat.from(this).notify(UP_NOTIFICATION_ID, b.build());
    }

    // -------------------------------------------------------------------------
    // Optional listener mix-ins for ServerFragment
    // -------------------------------------------------------------------------

    public interface CancelListener {
        void onUpCancelled();
    }

    public interface TimeoutListener {
        void onUpTimeout();
    }

    // -------------------------------------------------------------------------
    // Getters
    // -------------------------------------------------------------------------

    /** Returns the BTHIDService instance, or null if the HID transport is not active. */
    @Nullable
    public BTHIDService getHidService() {
        return hidService;
    }

    /**
     * Returns the {@link HIDPasskey} instance owned by {@link BTHIDService}, or null
     * if the HID transport is not active.
     */
    @Nullable
    public HIDPasskey getHIDPasskey() {
        return hidService != null ? hidService.getPasskey() : null;
    }

    /** Returns {@code true} when the HID transport is active. */
    public boolean isRunning() {
        return hidService != null;
    }

    /** Returns whether the service is in low battery mode. */
    public boolean isLowBatteryMode() {
        return lowBatteryMode;
    }

    // -------------------------------------------------------------------------
    // Notification helpers
    // -------------------------------------------------------------------------

    private void createUpNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(
                UP_CHANNEL_ID,
                getString(R.string.up_getinfo_title),
                NotificationManager.IMPORTANCE_HIGH);
            ch.setDescription(getString(R.string.up_getinfo_message));
            ch.enableVibration(true);
            ch.setShowBadge(true);
            NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            if (nm != null) nm.createNotificationChannel(ch);
        }
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                "FIDO Bluetooth Service",
                NotificationManager.IMPORTANCE_MIN);
            channel.setDescription("Keeps FIDO Bluetooth service running");
            channel.setShowBadge(false);
            NotificationManager manager =
                (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
            if (manager != null) manager.createNotificationChannel(channel);
        }
    }

    private Notification createNotification() {
        return new NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Passkey BT Active")
            .setContentText("FIDO Bluetooth service is running")
            .setSmallIcon(R.drawable.bee)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setShowWhen(false)
            .build();
    }

    // -------------------------------------------------------------------------
    // Battery receiver
    // -------------------------------------------------------------------------

    private void registerBatteryReceiver() {
        batteryReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                int level = intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
                int scale = intent.getIntExtra(BatteryManager.EXTRA_SCALE, -1);
                int batteryPct = (int) ((level / (float) scale) * 100);
                Log.d(TAG, "Battery level: " + batteryPct + "%");
                handleBatteryLevel(batteryPct);
            }
        };
        IntentFilter filter = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);
        registerReceiver(batteryReceiver, filter);
    }

    private void unregisterBatteryReceiver() {
        if (batteryReceiver != null) {
            try {
                unregisterReceiver(batteryReceiver);
            } catch (IllegalArgumentException e) {
                Log.w(TAG, "Battery receiver was not registered");
            }
            batteryReceiver = null;
        }
    }

    private void handleBatteryLevel(int batteryPct) {
        if (batteryPct <= LOW_BATTERY_LEVEL && !lowBatteryMode) {
            Log.w(TAG, "Battery critically low (" + batteryPct + "%), stopping service");
            lowBatteryMode = true;
            stopSelf();
        } else if (batteryPct <= MIN_BATTERY_LEVEL && !lowBatteryMode) {
            Log.w(TAG, "Battery low (" + batteryPct + "%), entering low battery mode");
            lowBatteryMode = true;
        } else if (batteryPct > MIN_BATTERY_LEVEL + 5 && lowBatteryMode) {
            Log.d(TAG, "Battery recovered (" + batteryPct + "%), exiting low battery mode");
            lowBatteryMode = false;
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static String bytesToHex(byte[] b) {
        if (b == null) return "";
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}
