/*
 * Copyright IBM 2025
 */

package com.isfs.blekey.hidsvc;

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
import com.isfs.blekey.authenticator.UpUvRequestCtx;
import com.isfs.blekey.authenticator.UpUvRequestCtx.Outcome;
import com.isfs.blekey.authenticator.UxInteractionLock;
import com.isfs.blekey.ctap.Ctap2StatusCode;
import com.isfs.blekey.ctap.CtapHid;
import com.isfs.blekey.ctap.CtapTxn;
import com.isfs.blekey.fidoble.KeepaliveManager;
import com.isfs.blekey.util.KeyUtils;
import java.security.PrivateKey;
import java.util.Arrays;

import javax.crypto.KeyAgreement;

/**
 * Foreground service that keeps the classic Bluetooth HID device service running persistently.
 * This ensures Bluetooth pairing and connections work reliably without
 * requiring the app to be in the foreground.
 *
 * <p>This service also owns the User Presence (UP) callback lifecycle.  Registering
 * the callback here (rather than in {@code ServerActivity}) means that incoming
 * {@code authenticatorGetInfo} / {@code authenticatorGetAssertion} requests are
 * handled correctly even when the activity has been destroyed by the OS.</p>
 */
public class HIDForegroundService extends Service {

    private static final String TAG = HIDForegroundService.class.getCanonicalName();
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
    /** How long to wait for user response before auto-denying. */
    /** Stage 1 :: user to tap Allow/Deny after the dialog/notification appears. */
    public static final int UP_DIALOG_TIMEOUT_MS = 8_000;   // 8 s
    /** Stage 2 :: user to meet biometric challenge after Allow. */
    public static final int UP_BIO_TIMEOUT_MS = 12_000;     // 12 s
    /** Stage 0 :: device is backgrounded/screen-off; waiting for app to foreground. */
    public static final int UP_BACKGROUND_TIMEOUT_MS = 5_000;   // 5 s

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

    private BTHIDService hidService;
    private final IBinder binder = new LocalBinder();
    private BroadcastReceiver batteryReceiver;
    private boolean lowBatteryMode = false;

    // -------------------------------------------------------------------------
    // UP ownership — moved from ServerActivity (Flaw 1 fix)
    // -------------------------------------------------------------------------

    private KeepaliveManager keepaliveManager;

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
    // UpActivityDelegate — implemented by ServerActivity
    // -------------------------------------------------------------------------

    /**
     * Callback interface implemented by {@code ServerActivity} to show a biometric
     * prompt after the user taps Allow.
     *
     * <p>The service calls {@link #showBiometricPrompt} on the UI thread only when the
     * CID does not already own the UP lock (i.e. this is the first ceremony in the
     * 15-second window).  If the CID is already the lock owner the chain runs
     * immediately without a second bio challenge.</p>
     */
    public interface BiometricDelegate {
        /**
         * Show the biometric prompt.  Call {@code onSuccess.run()} when authentication
         * succeeds, {@code onFailed.run()} on failure or cancellation.
         *
         * @param onSuccess Runnable to invoke on biometric success (UI or executor thread).
         * @param onFailed  Runnable to invoke on biometric failure or cancellation.
         */
        void showBiometricPrompt(Runnable onSuccess, Runnable onFailed);
    }

    /**
     * Callback interface for the bound {@code ServerActivity}.
     *
     * <p>The service calls {@link #showUpDialog} on the UI thread when the
     * activity is visible and a UP ceremony begins.  The activity calls back
     * via {@link #deliverUpApproved()} or {@link #deliverUpDenied()} once the
     * user acts.</p>
     *
     * <p>No {@link UpUvRequestCtx} reference is passed across this boundary —
     * the service owns that state exclusively.</p>
     */
    public interface UpActivityDelegate {
        /**
         * Called on the UI thread: show the UP dialog.
         *
         * @param rpId Relying-party identifier (may be null).
         */
        void showUpDialog(@Nullable String rpId);
    }

    // -------------------------------------------------------------------------
    // Binder
    // -------------------------------------------------------------------------

    /**
     * Binder for clients that want to interact with the service.
     */
    public class LocalBinder extends Binder {
        public HIDForegroundService getService() {
            return HIDForegroundService.this;
        }
    }

    // -------------------------------------------------------------------------
    // Service lifecycle
    // -------------------------------------------------------------------------

    @Override
    public void onCreate() {
        super.onCreate();
        Log.d(TAG, "onCreate");
        // applyAppConfig() is deferred: called inside SecureStorageHandler on first
        // bio success, because KeyAgreement.init(platformKey) requires prior bio auth
        // once the key is bio-gated.
        createNotificationChannel();
        createUpNotificationChannel();
        registerBatteryReceiver();

        // Keepalive sender: write frames through BTHIDService once it is initialised.
        // The lambda captures `this` so it always uses the live hidService reference.
        keepaliveManager = new KeepaliveManager(frame -> {
            if (hidService != null) hidService.sendInputReport(frame);
        });
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.d(TAG, "onStartCommand");

        Notification notification = createNotification();
        // Android 14+ (API 34) requires the service type to match the manifest declaration.
        // Omitting it causes MissingForegroundServiceTypeException and an immediate service kill.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE);
        } else {
            startForeground(NOTIFICATION_ID, notification);
        }

        if (hidService == null) {
            try {
                Log.d(TAG, "Creating BTHIDService...");
                hidService = new BTHIDService(this);
                Log.d(TAG, "BTHIDService created successfully");
                hidService.setDeviceName(getString(R.string.ble_beekey));
                if (!hidService.registerHidDevice()) {
                    Log.e(TAG, "Failed to register classic Bluetooth HID device");
                    stopSelf();
                    return START_NOT_STICKY;
                }
                Log.d(TAG, "BTHIDService started and registered");
            } catch (UnsupportedOperationException e) {
                Log.e(TAG, "Failed to start BTHIDService: " + e.getMessage(), e);
                stopSelf();
                return START_NOT_STICKY;
            } catch (Exception e) {
                Log.e(TAG, "Unexpected error starting BTHIDService: " + e.getMessage(), e);
                stopSelf();
                return START_NOT_STICKY;
            }
        } else {
            Log.d(TAG, "BTHIDService already running");
        }

        // Register the UP/UV callback here so it survives activity destruction.
        AuthenticatorAPI.setUpUvCallback(new UpHandler());

        // UPUV_GATE_SIMPLIFICATION: SecureStorageCallback no longer used for CTAP commands.
        // AuthenticatorAPI.setSecureStorageCallback(new SecureStorageHandler());
        AuthenticatorAPI.setDeferredResponseSender(
            (txn, response) -> sendDeferred(txn, response));

        // Cancel hook — CTAP cancel frame injects KEEPALIVE_CANCEL into the deferred CtapHid;
        // we clean up the service-side state and ask the delegate to dismiss its dialog.
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

    @Override
    public void onDestroy() {
        Log.d(TAG, "onDestroy");
        AuthenticatorAPI.setUpUvCallback(null);
        // AuthenticatorAPI.setSecureStorageCallback(null); // UPUV_GATE_SIMPLIFICATION
        AuthenticatorAPI.setDeferredResponseSender(null);
        if (keepaliveManager != null) { keepaliveManager.shutdown(); keepaliveManager = null; }
        unregisterBatteryReceiver();
        if (hidService != null) {
            hidService.unregisterHidDevice();
            hidService = null;
        }
        super.onDestroy();
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return binder;
    }

    // -------------------------------------------------------------------------
    // UP delegate wiring (called by ServerActivity on bind / unbind)
    // -------------------------------------------------------------------------

    /**
     * Called by {@code ServerActivity} once it has bound and is ready to show dialogs.
     * Pass {@code null} when the activity is destroyed / unbound.
     */
    public void setActivityDelegate(@Nullable UpActivityDelegate delegate) {
        activityDelegate = delegate;
    }

    // -------------------------------------------------------------------------
    // UP delivery methods (called by ServerActivity button handlers)
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

            // If the app-global bio grant is active, run the chain directly — no
            // second biometric prompt needed.
            if (UxInteractionLock.get().isGrantActive()) {
                pendingContext.buildResponse(Outcome.APPROVED, response -> {
                    if (response != null) sendDeferred(txn, response);
                    finishUpDelivery();
                });
                return;
            }

            // If the pending ceremony does not require a biometric (getInfo / getKey),
            // run the chain directly after the Allow tap — no fingerprint needed.
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

            // GET_INFO: send the pre-built CBOR response NOW (Allow-tap time) per plan
            // constraint C2. The bio that follows is only for recordBioGrant / Keystore gate.
            // buildResponse marks delivered=true; the bio-success call below is a no-op.
            if (pendingContext.getCeremonyType() == UpUvRequestCtx.CeremonyType.GET_INFO) {
                pendingContext.buildResponse(Outcome.APPROVED, response -> {
                    if (response != null) sendDeferred(txn, response);
                });
            }

            // Stage-2 timeout covering the biometric window.
            timeoutRunnable = this::deliverTimeoutInternal;
            upHandler.postDelayed(timeoutRunnable, getUpBioTimeoutMs());

            ((BiometricDelegate) d).showBiometricPrompt(
                /* onSuccess */ () -> upHandler.post(() -> {
                    cancelTimeout();

                    // ---------------------------------------------------------------
                    // STRICT WRITE ORDER
                    // The CTAP thread may be blocking on awaitUxLatch(). All txn state
                    // must be fully written before releaseUxLatch() fires, because the
                    // CTAP thread reads these values the instant it wakes.
                    //
                    // Record the app-global bio grant NOW while the Keystore auth window
                    // is open. IKM derivation on the CTAP thread (CredentialSeedDeriver)
                    // will fast-path via isGrantActive() the moment it wakes.
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
                    // mark user present.
                    txn.setUserPresent(true);
                    // set APPROVED (volatile write — visible to CTAP thread
                    // immediately after the latch fires via happens-before on countDown).
                    UxInteractionLock.get().setUxState(UxInteractionLock.UxState.APPROVED);
                    // release latch — CTAP thread wakes HERE.
                    UxInteractionLock.get().releaseLatch();
                    // ---------------------------------------------------------------

                    // For the deferred path the chain is non-empty and buildResponse
                    // sends the CTAP response via sendDeferred. For the latch-wait path the
                    // chain is empty (Collections.emptyList()) so buildResponse calls
                    // cb.done(null) → sendDeferred(txn, null) → null-guard no-ops.
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
            // Mark the channel as denied BEFORE sending the response so that any
            // follow-up command arriving on the same CID (e.g. a U2F MSG retry) is
            // rejected immediately without opening a new biometric prompt.
            if (pendingUpTxn != null) {
                UxInteractionLock.get().setUxState(UxInteractionLock.UxState.DENIED);
                UxInteractionLock.get().releaseLatch();   // wake any CTAP thread blocking on latch
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

    /** Cancels the pending UP notification (called by activity when dialog is visible). */
    public void cancelUpNotification() {
        NotificationManagerCompat.from(this).cancel(UP_NOTIFICATION_ID);
    }


    private final class UpHandler implements UpUvCallback {
        @Override
        public void onUpUvRequired(UpUvRequestCtx context) {
            // Acquire wake lock immediately on the CTAP thread so the CPU stays alive
            // while we post to the main thread and build the notification.
            acquireUpWakeLock();

            CtapTxn txn    = context.getTxn();
            byte[]  cid    = txn.getCid();
            String  cidKey = bytesToHex(cid);
            if (context.requiresKeepalive()) {
                stopUpKeepalive();
                keepaliveManager.startKeepalive(cidKey, KeepaliveManager.STATUS_UP_NEEDED);
            }

            // Store pending state on the service before posting to UI thread.
            pendingContext = context;
            pendingUpTxn   = txn;

            upHandler.post(() -> {
                // UP already collected on this txn and the command needs biometric only
                // skip the Allow/Deny dialog and go straight to the biometric prompt.
                if (txn.isUserPresent() && context.requiresBiometric()) {
                    Log.d(TAG, "UP: txn already has UP + requiresBiometric — skipping dialog, delivering approved");
                    deliverUpApproved();
                    return;
                }

                Log.d(TAG, "UP: posting to UI thread for cidKey=" + cidKey);
                UpActivityDelegate d = activityDelegate;
                if (d != null) {
                    // App is in the foreground — arm Stage 1 and show the dialog immediately.
                    startUpTimeout();
                    d.showUpDialog(context.getRpId());
                } else {
                    // App is backgrounded / screen off — arm Stage 0 and post the notification.
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
            UxInteractionLock.get().releaseLatch();   // wake any CTAP thread blocking on latch
        }
        if (pendingContext != null) {
            sendDeferred(pendingUpTxn,
                AuthenticatorAPI.buildErrorResponse(Ctap2StatusCode.USER_ACTION_TIMEOUT));
        }
        finishUpDelivery();
    }

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
        upHandler.postDelayed(cidInactivityRunnable,
            UxInteractionLock.LOCK_TIMEOUT_MS);
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
            // §6.1.4 — wake any CTAP thread that is blocking on awaitUxLatch for this CID.
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
            keepaliveManager.stopKeepalive(bytesToHex(pendingUpTxn.getCid()));
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
        // Worst case: Stage 0 (5s) + Stage 1 (8s) + Stage 2 (12s) + 2s safety margin.
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
     * Transitions Stage 0 → Stage 1 and returns the rpId so the caller can show the dialog.
     * Returns null if no ceremony is pending.
     */
    @Nullable
    public String transitionToForeground() {
        if (pendingContext == null) return null;
        cancelBackgroundTimeout();
        if (timeoutRunnable == null) startUpTimeout();   // arm Stage 1 (guard re-entry)
        return pendingContext.getRpId();
    }

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
                Log.w(TAG, "USE_FULL_SCREEN_INTENT not granted — UP notification will not wake screen");
            }
        } else {
            PendingIntent fsPi = PendingIntent.getActivity(this, 1, tapIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
            b.setFullScreenIntent(fsPi, true);
        }

        NotificationManagerCompat.from(this).notify(UP_NOTIFICATION_ID, b.build());
    }

    // -------------------------------------------------------------------------
    // Optional listener mix-ins for ServerActivity
    // -------------------------------------------------------------------------

    /**
     * Optional extension of {@link UpActivityDelegate}: called when a CTAP cancel
     * frame arrives and the in-progress UP ceremony must be dismissed.
     */
    public interface CancelListener {
        void onUpCancelled();
    }

    /**
     * Optional extension of {@link UpActivityDelegate}: called when the service-side
     * UP timeout fires and the activity should dismiss its dialog and show a toast.
     */
    public interface TimeoutListener {
        void onUpTimeout();
    }

    // -------------------------------------------------------------------------
    // Getters
    // -------------------------------------------------------------------------

    /** Returns the BTHIDService instance, or null if not initialized. */
    @Nullable
    public BTHIDService getHidService() {
        return hidService;
    }

    /**
     * Returns the {@link HIDPasskey} instance owned by the running {@link BTHIDService},
     * or null if the service is not yet initialized.
     */
    @Nullable
    public HIDPasskey getHIDPasskey() {
        return hidService != null ? hidService.getPasskey() : null;
    }

    /** Checks if the service is running with an active BTHIDService. */
    public boolean isRunning() {
        return hidService != null;
    }

    /** Returns whether the service is in low battery mode. */
    public boolean isLowBatteryMode() {
        return lowBatteryMode;
    }

    private void createUpNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(
                UP_CHANNEL_ID,
                "Authentication Request",
                NotificationManager.IMPORTANCE_HIGH);
            ch.setDescription("Prompts for FIDO user presence approval");
            ch.enableVibration(true);
            ch.setShowBadge(true);
            NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            if (nm != null) nm.createNotificationChannel(ch);
        }
    }

    // -------------------------------------------------------------------------
    // Service notification (persistent foreground)
    // -------------------------------------------------------------------------

    /**
     * Creates the notification channel required for Android 8.0+.
     */
    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                "FIDO Classic HID Service",
                NotificationManager.IMPORTANCE_MIN  // silent, no status-bar icon
            );
            channel.setDescription("Keeps FIDO classic Bluetooth HID service running");
            channel.setShowBadge(false);

            NotificationManager manager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
            if (manager != null) {
                manager.createNotificationChannel(channel);
            }
        }
    }

    /**
     * Creates the persistent notification required by startForeground().
     * IMPORTANCE_MIN keeps it silent and out of the status bar.
     */
    private Notification createNotification() {
        return new NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Passkey BT HID Active")
            .setContentText("Classic Bluetooth HID service is running")
            .setSmallIcon(R.drawable.bee)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setShowWhen(false)
            .build();
    }

    // -------------------------------------------------------------------------
    // Battery receiver
    // -------------------------------------------------------------------------

    /**
     * Registers a broadcast receiver to monitor battery level changes.
     */
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
        Log.d(TAG, "Battery receiver registered");
    }

    /**
     * Unregisters the battery broadcast receiver.
     */
    private void unregisterBatteryReceiver() {
        if (batteryReceiver != null) {
            try {
                unregisterReceiver(batteryReceiver);
                Log.d(TAG, "Battery receiver unregistered");
            } catch (IllegalArgumentException e) {
                Log.w(TAG, "Battery receiver was not registered");
            }
            batteryReceiver = null;
        }
    }

    /**
     * Handles battery level changes and stops service if battery is critically low.
     */
    private void handleBatteryLevel(int batteryPct) {
        if (batteryPct <= LOW_BATTERY_LEVEL && !lowBatteryMode) {
            Log.w(TAG, "Battery critically low (" + batteryPct + "%), stopping service");
            lowBatteryMode = true;
            stopSelf();
        } else if (batteryPct <= MIN_BATTERY_LEVEL && !lowBatteryMode) {
            Log.w(TAG, "Battery low (" + batteryPct + "%), entering low battery mode");
            lowBatteryMode = true;
            updateNotificationForLowBattery();
        } else if (batteryPct > MIN_BATTERY_LEVEL + 5 && lowBatteryMode) {
            Log.d(TAG, "Battery recovered (" + batteryPct + "%), exiting low battery mode");
            lowBatteryMode = false;
            updateNotification();
        }
    }

    /** No-op: low-battery state is only logged; no notification update needed. */
    private void updateNotificationForLowBattery() {
        // Intentionally empty — the foreground notification is IMPORTANCE_MIN and not
        // user-visible, so there is nothing meaningful to update.
    }

    /** No-op: normal battery recovery; log already captured in handleBatteryLevel. */
    private void updateNotification() {
        // Intentionally empty — see updateNotificationForLowBattery.
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

// Made with Bob
