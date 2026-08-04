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
import com.isfs.blekey.ctap.Ctap2StatusCode;
import com.isfs.blekey.ctap.CtapHid;
import com.isfs.blekey.ctap.CtapTxn;
import com.isfs.blekey.fidoble.KeepaliveManager;

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

    private int getUpDialogTimeoutMs() {
        return getSharedPreferences("HIDServicePrefs", Context.MODE_PRIVATE)
                .getInt("up_dialog_timeout_ms", UP_DIALOG_TIMEOUT_MS);
    }

    private int getUpBioTimeoutMs() {
        return getSharedPreferences("HIDServicePrefs", Context.MODE_PRIVATE)
                .getInt("up_bio_timeout_ms", UP_BIO_TIMEOUT_MS);
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

            // If the CID already proved biometric in a prior ceremony this session and
            // the platform IKM is cached on the txn, run the chain directly — no
            // second prompt needed.
            if (AuthenticatorAPI.isUpLockOwner(txn.getCid()) && txn.isIkmCached()) {
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

            // Stage-2 timeout covering the biometric window.
            timeoutRunnable = this::deliverTimeoutInternal;
            upHandler.postDelayed(timeoutRunnable, getUpBioTimeoutMs());

            ((BiometricDelegate) d).showBiometricPrompt(
                /* onSuccess */ () -> upHandler.post(() -> {
                    cancelTimeout();
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
            cancelUpNotification();
            // Mark the channel as denied BEFORE sending the response so that any
            // follow-up command arriving on the same CID (e.g. a U2F MSG retry) is
            // rejected immediately without opening a new biometric prompt.
            if (pendingUpTxn != null) {
                pendingUpTxn.setUserDenied(true);
                AuthenticatorAPI.releaseUpLock(pendingUpTxn.getCid());
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

    // -------------------------------------------------------------------------
    // UpHandler — inner class: bridges CTAP thread → service state → UI
    // -------------------------------------------------------------------------

    // UPUV_GATE_SIMPLIFICATION: SecureStorageHandler commented out — no longer needed.
    // Retained here for future reinstatement if the bio-gate path is restored.
    /*
    private final class SecureStorageHandler implements SecureStorageCallback {

        @Override
        public void onPlatformKeyRequired(AuthenticatorAPI.PlatformKeyContext ctx) {
            upHandler.post(() -> {
                UpActivityDelegate d = activityDelegate;
                if (d instanceof BiometricDelegate) {
                    ((BiometricDelegate) d).showBiometricPrompt(
                        new AuthenticatorAPI.PlatformKeyContext(
                            ctx.getSignature(),
                            () -> {
                                // Bio succeeded — auth window is open.
                                if (!appConfigLoaded) {
                                    applyAppConfig(); // safe: ECDH auth gate is now open
                                    appConfigLoaded = true;
                                }
                                ctx.onUnlocked(); // continue the CTAP ceremony
                            },
                            ctx::onFailed
                        )
                    );
                } else {
                    // Activity not visible — cannot show BiometricPrompt from background.
                    ctx.onFailed();
                }
            });
        }
    }
    */

    private final class UpHandler implements UpUvCallback {
        @Override
        public void onUpUvRequired(UpUvRequestCtx context) {
            // Acquire wake lock immediately on the CTAP thread so the CPU stays alive
            // while we post to the main thread and build the notification.
            acquireUpWakeLock();

            CtapTxn txn    = context.getTxn();
            byte[]  cid    = txn.getCid();
            String  cidKey = bytesToHex(cid);
            stopUpKeepalive();
            keepaliveManager.startKeepalive(cidKey, KeepaliveManager.STATUS_PROCESSING);

            // Store pending state on the service before posting to UI thread.
            pendingContext = context;
            pendingUpTxn   = txn;
            startUpTimeout();

            upHandler.post(() -> {
                keepaliveManager.updateStatus(cidKey, context.getKeepaliveStatus());

                // UP already collected on this txn and the command needs biometric only
                // (e.g. getTkn after getInfo) — skip the Allow/Deny dialog and go straight
                // to the biometric prompt.
                if (txn.isUserPresent() && context.requiresBiometric()) {
                    Log.d(TAG, "UP: txn already has UP + requiresBiometric — skipping dialog, delivering approved");
                    deliverUpApproved();
                    return;
                }

                Log.d(TAG, "UP: posting to UI thread for cidKey=" + cidKey);
                UpActivityDelegate d = activityDelegate;
                if (d != null) {
                    d.showUpDialog(context.getRpId());
                } else {
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
    }

    private void deliverTimeoutInternal() {
        cancelUpNotification();
        UpActivityDelegate d = activityDelegate;
        if (d instanceof TimeoutListener) ((TimeoutListener) d).onUpTimeout();
        if (pendingUpTxn != null) AuthenticatorAPI.releaseUpLock(pendingUpTxn.getCid());
        if (pendingContext != null) {
            sendDeferred(pendingUpTxn,
                AuthenticatorAPI.buildErrorResponse(Ctap2StatusCode.USER_ACTION_TIMEOUT));
        }
        finishUpDelivery();
    }

    private void sendDeferred(CtapTxn txn, byte[] response) {
        HIDPasskey pk = getHIDPasskey();
        if (pk != null) pk.sendDeferredResponse(txn, response);
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
        upWakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "blekey:upPrompt");
        upWakeLock.acquire(getUpBioTimeoutMs() + 2_000L);
        Log.d(TAG, "UP wake lock acquired");
    }

    private void releaseUpWakeLock() {
        if (upWakeLock != null && upWakeLock.isHeld()) {
            upWakeLock.release();
            Log.d(TAG, "UP wake lock released");
        }
        upWakeLock = null;
    }

    /** Called by {@code ServerActivity.showUpDialog} when the activity is backgrounded. */
    public void postUpNotificationPublic() {
        postUpNotification();
    }

    private void postUpNotification() {
        Intent tapIntent = new Intent(this, com.isfs.blekey.activity.ServerActivity.class)
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
