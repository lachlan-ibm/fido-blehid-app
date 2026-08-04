/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.hidsvc;

import android.annotation.SuppressLint;
import android.bluetooth.le.AdvertiseCallback;
import android.bluetooth.le.AdvertiseData;
import android.bluetooth.le.AdvertiseSettings;
import android.bluetooth.le.BluetoothLeAdvertiser;
import android.content.Context;
import android.content.pm.PackageManager;
import androidx.core.content.ContextCompat;
import android.os.Handler;
import android.os.ParcelUuid;
import android.util.Log;


import com.isfs.blekey.util.BleUtils;

/**
 * Manages BLE advertising for the HID peripheral using the legacy
 * {@link AdvertiseSettings} API.
 *
 * Note: Android does not expose address-type control to third-party apps
 * (requires BLUETOOTH_PRIVILEGED). The device advertises with a Resolvable
 * Private Address (RPA). BlueZ HOGP will resolve the RPA after LE SMP pairing
 * completes and the IRK is stored.
 */
final class HIDBTAdvertiser {

    private static final String TAG = HIDBTAdvertiser.class.getCanonicalName();

    private final Context applicationContext;
    private final Handler handler;
    private final BluetoothLeAdvertiser bluetoothLeAdvertiser;

    private final AdvertiseCallback advertiseCallback = new AdvertiseCallback() {
        @Override
        public void onStartSuccess(AdvertiseSettings settingsInEffect) {
            Log.d(TAG, "Advertising started, mode=" + settingsInEffect.getMode());
        }

        @Override
        public void onStartFailure(int errorCode) {
            Log.e(TAG, "Advertising failed, errorCode=" + errorCode);
        }
    };

    HIDBTAdvertiser(Context context, Handler handler, BluetoothLeAdvertiser bluetoothLeAdvertiser) {
        this.applicationContext    = context.getApplicationContext();
        this.handler               = handler;
        this.bluetoothLeAdvertiser = bluetoothLeAdvertiser;
    }

    @SuppressLint("MissingPermission")
    void start() {
        if (!isPermitBToothConnect()) {
            Log.e(TAG, "Do not have BLUETOOTH_CONNECT permission.");
            return;
        }
        if (!isPermitBToothAdvert()) {
            Log.e(TAG, "Do not have BLUETOOTH_ADVERTISE permission.");
            return;
        }
        handler.post(() -> {
            final AdvertiseSettings settings = new AdvertiseSettings.Builder()
                    .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
                    .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
                    .setConnectable(true)
                    .build();

            // Minimize advertising data — BLE has a strict 31-byte limit.
            // Only include the HID service UUID; 128-bit UUIDs cost 18 bytes each.
            final AdvertiseData advertiseData = new AdvertiseData.Builder()
                    .setIncludeTxPowerLevel(false)
                    .setIncludeDeviceName(false)
                    .addServiceUuid(ParcelUuid.fromString(BleUtils.SERVICE_BLE_HID.toString()))
                    .build();

            // Scan response: device name only.
            // Do NOT add SERVICE_DEVICE_INFORMATION or SERVICE_BATTERY here — each
            // 128-bit UUID consumes 18 bytes, which combined with the device name
            // overflows the 31-byte BLE scan-response packet and causes
            // ADVERTISE_FAILED_DATA_TOO_LARGE, silently preventing HOGP enumeration.
            final AdvertiseData scanResponse = new AdvertiseData.Builder()
                    .setIncludeDeviceName(true)
                    .build();

            Log.d(TAG, "startAdvertising advertiseData=" + advertiseData
                    + " scanResponse=" + scanResponse);
            bluetoothLeAdvertiser.startAdvertising(settings, advertiseData, scanResponse,
                    advertiseCallback);
        });
    }

    @SuppressLint("MissingPermission")
    void stop() {
        handler.post(() -> {
            try {
                bluetoothLeAdvertiser.stopAdvertising(advertiseCallback);
            } catch (IllegalStateException e) {
                Log.d(TAG, "BT Adapter is not turned ON");
            }
        });
    }

    private boolean isPermitBToothConnect() {
        return ContextCompat.checkSelfPermission(applicationContext,
                android.Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED;
    }

    private boolean isPermitBToothAdvert() {
        return ContextCompat.checkSelfPermission(applicationContext,
                android.Manifest.permission.BLUETOOTH_ADVERTISE) == PackageManager.PERMISSION_GRANTED;
    }
}

// Made with Bob
