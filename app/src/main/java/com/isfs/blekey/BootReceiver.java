/*
 * Copyright IBM 2025
 */

package com.isfs.blekey;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.BatteryManager;
import android.os.Build;
import android.util.Log;
import com.isfs.blekey.hidsvc.HIDForegroundService;

/**
 * BroadcastReceiver that starts the HID foreground service on device boot.
 * Also checks battery level to avoid starting when battery is low.
 */
public class BootReceiver extends BroadcastReceiver {

    private static final String TAG = BootReceiver.class.getCanonicalName();
    private static final int MIN_BATTERY_LEVEL = 15;
    private static final String PREFS_NAME = "HIDServicePrefs";
    private static final String KEY_AUTO_START = "auto_start_enabled";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null || intent.getAction() == null) {
            return;
        }

        String action = intent.getAction();
        Log.d(TAG, "Received broadcast: " + action);

        if (Intent.ACTION_BOOT_COMPLETED.equals(action)) {
            handleBootCompleted(context);
        } else if (Intent.ACTION_MY_PACKAGE_REPLACED.equals(action)) {
            handlePackageReplaced(context);
        }
    }

    /**
     * Handles device boot completion.
     */
    private void handleBootCompleted(Context context) {
        Log.d(TAG, "Device boot completed, checking if service should start");
        
        if (!isAutoStartEnabled(context)) {
            Log.d(TAG, "Auto-start not enabled, service will not start");
            return;
        }
        
        if (!isBatteryLevelSufficient(context)) {
            Log.w(TAG, "Battery level too low, not starting service");
            return;
        }

        startHIDService(context);
    }

    /**
     * Handles app package replacement (update).
     */
    private void handlePackageReplaced(Context context) {
        Log.d(TAG, "Package replaced, restarting service if needed");
        
        if (!isAutoStartEnabled(context)) {
            Log.d(TAG, "Auto-start not enabled, service will not start");
            return;
        }
        
        if (!isBatteryLevelSufficient(context)) {
            Log.w(TAG, "Battery level too low, not starting service");
            return;
        }

        startHIDService(context);
    }

    /**
     * Checks if battery level is sufficient to start the service.
     */
    private boolean isBatteryLevelSufficient(Context context) {
        try {
            BatteryManager batteryManager = (BatteryManager) context.getSystemService(Context.BATTERY_SERVICE);
            if (batteryManager == null) {
                Log.w(TAG, "BatteryManager not available, assuming sufficient battery");
                return true;
            }

            int batteryLevel = batteryManager.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY);
            Log.d(TAG, "Current battery level: " + batteryLevel + "%");

            return batteryLevel >= MIN_BATTERY_LEVEL;
        } catch (Exception e) {
            Log.e(TAG, "Error checking battery level: " + e.getMessage());
            return true;
        }
    }

    /**
     * Starts the HID foreground service.
     */
    private void startHIDService(Context context) {
        try {
            Intent serviceIntent = new Intent(context, HIDForegroundService.class);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(serviceIntent);
            } else {
                context.startService(serviceIntent);
            }
            Log.d(TAG, "HID foreground service started");
        } catch (Exception e) {
            Log.e(TAG, "Failed to start HID service: " + e.getMessage());
        }
    }

    /**
     * Checks if auto-start is enabled in preferences.
     */
    private boolean isAutoStartEnabled(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        boolean enabled = prefs.getBoolean(KEY_AUTO_START, false);
        Log.d(TAG, "Auto-start enabled: " + enabled);
        return enabled;
    }

    /**
     * Enables auto-start in preferences. Should be called when user manually starts the service.
     */
    public static void enableAutoStart(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        prefs.edit().putBoolean(KEY_AUTO_START, true).apply();
        Log.d(BootReceiver.class.getCanonicalName(), "Auto-start enabled");
    }

    /**
     * Disables auto-start in preferences. Should be called when user manually stops the service.
     */
    public static void disableAutoStart(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        prefs.edit().putBoolean(KEY_AUTO_START, false).apply();
        Log.d(BootReceiver.class.getCanonicalName(), "Auto-start disabled");
    }
}

// Made with Bob
