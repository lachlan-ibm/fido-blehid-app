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
import android.os.BatteryManager;
import android.os.Binder;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;
import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;
import com.isfs.blekey.MainActivity;
import com.isfs.blekey.R;

/**
 * Foreground service that keeps the HID GATT server running persistently.
 * This ensures Bluetooth pairing and connections work reliably without
 * requiring the app to be in the foreground.
 */
public class HIDForegroundService extends Service {

    private static final String TAG = HIDForegroundService.class.getCanonicalName();
    private static final int NOTIFICATION_ID = 1001;
    private static final String CHANNEL_ID = "fido_ble_hid_channel";
    private static final int MIN_BATTERY_LEVEL = 15;
    private static final int LOW_BATTERY_LEVEL = 10;

    private HIDService hidService;
    private final IBinder binder = new LocalBinder();
    private BroadcastReceiver batteryReceiver;
    private boolean lowBatteryMode = false;

    /**
     * Binder for clients that want to interact with the service.
     */
    public class LocalBinder extends Binder {
        public HIDForegroundService getService() {
            return HIDForegroundService.this;
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        Log.d(TAG, "onCreate");
        createNotificationChannel();
        registerBatteryReceiver();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.d(TAG, "onStartCommand");

        Notification notification = createNotification();
        startForeground(NOTIFICATION_ID, notification);

        if (hidService == null) {
            try {
                Log.d(TAG, "Creating HIDService...");
                hidService = new HIDService(
                    this,
                    true,  // BLUETOOTH_CONNECT permission
                    true   // BLUETOOTH_ADVERTISE permission
                );
                Log.d(TAG, "HIDService created successfully");
                hidService.setDeviceName(getString(R.string.ble_beekey));
                Log.d(TAG, "Device name set, starting advertising...");
                hidService.startAdvertising();
                Log.d(TAG, "HIDService started and advertising");
            } catch (UnsupportedOperationException e) {
                Log.e(TAG, "Failed to start HIDService: " + e.getMessage(), e);
                stopSelf();
                return START_NOT_STICKY;
            } catch (Exception e) {
                Log.e(TAG, "Unexpected error starting HIDService: " + e.getMessage(), e);
                stopSelf();
                return START_NOT_STICKY;
            }
        } else {
            Log.d(TAG, "HIDService already running");
        }

        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        Log.d(TAG, "onDestroy");
        unregisterBatteryReceiver();
        if (hidService != null) {
            hidService.stopAdvertising();
            hidService = null;
        }
        super.onDestroy();
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return binder;
    }

    /**
     * Creates the notification channel required for Android 8.0+.
     */
    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                "FIDO BLE HID Service",
                NotificationManager.IMPORTANCE_LOW
            );
            channel.setDescription("Keeps FIDO BLE HID service running");
            channel.setShowBadge(false);

            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.createNotificationChannel(channel);
            }
        }
    }

    /**
     * Creates the persistent notification shown while the service is running.
     */
    private Notification createNotification() {
        Intent notificationIntent = new Intent(this, MainActivity.class);
        PendingIntent pendingIntent = PendingIntent.getActivity(
            this,
            0,
            notificationIntent,
            PendingIntent.FLAG_IMMUTABLE
        );

        return new NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("FIDO BLE HID Active")
            .setContentText("Bluetooth HID service is running")
            .setSmallIcon(R.drawable.bee)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build();
    }

    /**
     * Returns the HIDService instance, or null if not initialized.
     */
    @Nullable
    public HIDService getHidService() {
        return hidService;
    }

    /**
     * Checks if the service is running with an active HIDService.
     */
    public boolean isRunning() {
        return hidService != null;
    }

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

    /**
     * Updates the notification to indicate low battery mode.
     */
    private void updateNotificationForLowBattery() {
        Intent notificationIntent = new Intent(this, MainActivity.class);
        PendingIntent pendingIntent = PendingIntent.getActivity(
            this,
            0,
            notificationIntent,
            PendingIntent.FLAG_IMMUTABLE
        );

        Notification notification = new NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("FIDO BLE HID Active (Low Battery)")
            .setContentText("Service running in low battery mode")
            .setSmallIcon(R.drawable.bee)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build();

        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager != null) {
            manager.notify(NOTIFICATION_ID, notification);
        }
    }

    /**
     * Updates the notification to normal state.
     */
    private void updateNotification() {
        Notification notification = createNotification();
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager != null) {
            manager.notify(NOTIFICATION_ID, notification);
        }
    }

    /**
     * Returns whether the service is in low battery mode.
     */
    public boolean isLowBatteryMode() {
        return lowBatteryMode;
    }
}

// Made with Bob
