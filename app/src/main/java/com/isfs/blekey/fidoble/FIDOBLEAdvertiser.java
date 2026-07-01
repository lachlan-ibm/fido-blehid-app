/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.fidoble;

import android.annotation.SuppressLint;
import android.bluetooth.le.AdvertiseCallback;
import android.bluetooth.le.AdvertiseData;
import android.bluetooth.le.AdvertiseSettings;
import android.bluetooth.le.BluetoothLeAdvertiser;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Handler;
import android.os.ParcelUuid;
import android.util.Log;

import androidx.core.content.ContextCompat;

import com.isfs.blekey.util.BleUtils;

/**
 * Manages BLE advertising for the FIDO service (UUID 0xFFFD).
 * 
 * This advertiser broadcasts the FIDO service UUID to allow FIDO clients
 * to discover and connect to this authenticator. It can operate independently
 * or simultaneously with the HID service advertiser.
 * 
 * Per CTAP specification §11.4.4, the FIDO service UUID (0xFFFD) must be
 * included in the advertising data.
 */
public class FIDOBLEAdvertiser {

    private static final String TAG = FIDOBLEAdvertiser.class.getCanonicalName();

    private final Context applicationContext;
    private final Handler handler;
    private final BluetoothLeAdvertiser bluetoothLeAdvertiser;
    private boolean isAdvertising = false;

    /**
     * Callback for advertising events.
     */
    private final AdvertiseCallback advertiseCallback = new AdvertiseCallback() {
        @Override
        public void onStartSuccess(AdvertiseSettings settingsInEffect) {
            isAdvertising = true;
            Log.d(TAG, "FIDO advertising started successfully, mode=" + settingsInEffect.getMode());
        }

        @Override
        public void onStartFailure(int errorCode) {
            isAdvertising = false;
            String errorMessage = getErrorMessage(errorCode);
            Log.e(TAG, "FIDO advertising failed: " + errorMessage + " (code=" + errorCode + ")");
        }
    };

    /**
     * Creates a new FIDO BLE advertiser.
     *
     * @param context Application context
     * @param handler Handler for posting callbacks
     * @param bluetoothLeAdvertiser BLE advertiser instance
     */
    public FIDOBLEAdvertiser(Context context, Handler handler, BluetoothLeAdvertiser bluetoothLeAdvertiser) {
        this.applicationContext = context.getApplicationContext();
        this.handler = handler;
        this.bluetoothLeAdvertiser = bluetoothLeAdvertiser;
    }

    /**
     * Starts advertising the FIDO service.
     */
    @SuppressLint("MissingPermission")
    public void start() {
        if (!hasBluetoothConnectPermission()) {
            Log.e(TAG, "Missing BLUETOOTH_CONNECT permission");
            return;
        }
        
        if (!hasBluetoothAdvertisePermission()) {
            Log.e(TAG, "Missing BLUETOOTH_ADVERTISE permission");
            return;
        }

        if (isAdvertising) {
            Log.d(TAG, "Already advertising FIDO service");
            return;
        }

        handler.post(() -> {
            try {
                // Configure advertising settings
                // Use LOW_LATENCY mode for better responsiveness during authentication
                final AdvertiseSettings settings = new AdvertiseSettings.Builder()
                        .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
                        .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
                        .setConnectable(true)
                        .setTimeout(0)  // Advertise indefinitely
                        .build();

                // Configure advertising data
                // Include only the FIDO service UUID (0xFFFD) to minimize packet size
                // BLE advertising packets have a strict 31-byte limit
                final AdvertiseData advertiseData = new AdvertiseData.Builder()
                        .setIncludeTxPowerLevel(false)
                        .setIncludeDeviceName(false)
                        .addServiceUuid(new ParcelUuid(BleUtils.SERVICE_FIDO))
                        .build();

                // Configure scan response data
                // Include device name in scan response for identification
                final AdvertiseData scanResponse = new AdvertiseData.Builder()
                        .setIncludeDeviceName(true)
                        .build();

                Log.d(TAG, "Starting FIDO advertising with service UUID: " + BleUtils.SERVICE_FIDO);
                Log.d(TAG, "Advertise data: " + advertiseData);
                Log.d(TAG, "Scan response: " + scanResponse);

                bluetoothLeAdvertiser.startAdvertising(
                    settings, 
                    advertiseData, 
                    scanResponse,
                    advertiseCallback
                );
            } catch (Exception e) {
                Log.e(TAG, "Exception starting FIDO advertising: " + e.getMessage(), e);
            }
        });
    }

    /**
     * Stops advertising the FIDO service.
     */
    @SuppressLint("MissingPermission")
    public void stop() {
        if (!isAdvertising) {
            Log.d(TAG, "FIDO advertising not active");
            return;
        }

        handler.post(() -> {
            try {
                bluetoothLeAdvertiser.stopAdvertising(advertiseCallback);
                isAdvertising = false;
                Log.d(TAG, "FIDO advertising stopped");
            } catch (IllegalStateException e) {
                Log.w(TAG, "Bluetooth adapter not enabled: " + e.getMessage());
                isAdvertising = false;
            } catch (Exception e) {
                Log.e(TAG, "Exception stopping FIDO advertising: " + e.getMessage(), e);
            }
        });
    }

    /**
     * Checks if currently advertising.
     */
    public boolean isAdvertising() {
        return isAdvertising;
    }

    /**
     * Checks if BLUETOOTH_CONNECT permission is granted.
     */
    private boolean hasBluetoothConnectPermission() {
        return ContextCompat.checkSelfPermission(
            applicationContext,
            android.Manifest.permission.BLUETOOTH_CONNECT
        ) == PackageManager.PERMISSION_GRANTED;
    }

    /**
     * Checks if BLUETOOTH_ADVERTISE permission is granted.
     */
    private boolean hasBluetoothAdvertisePermission() {
        return ContextCompat.checkSelfPermission(
            applicationContext,
            android.Manifest.permission.BLUETOOTH_ADVERTISE
        ) == PackageManager.PERMISSION_GRANTED;
    }

    /**
     * Converts advertising error code to human-readable message.
     */
    private String getErrorMessage(int errorCode) {
        switch (errorCode) {
            case AdvertiseCallback.ADVERTISE_FAILED_DATA_TOO_LARGE:
                return "Data too large (exceeds 31-byte limit)";
            case AdvertiseCallback.ADVERTISE_FAILED_TOO_MANY_ADVERTISERS:
                return "Too many advertisers";
            case AdvertiseCallback.ADVERTISE_FAILED_ALREADY_STARTED:
                return "Already started";
            case AdvertiseCallback.ADVERTISE_FAILED_INTERNAL_ERROR:
                return "Internal error";
            case AdvertiseCallback.ADVERTISE_FAILED_FEATURE_UNSUPPORTED:
                return "Feature unsupported";
            default:
                return "Unknown error";
        }
    }
}

// Made with Bob
