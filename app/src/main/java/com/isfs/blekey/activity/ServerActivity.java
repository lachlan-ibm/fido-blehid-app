/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.activity;

import com.isfs.blekey.hidsvc.HIDService;
import com.isfs.blekey.R;

import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.content.DialogInterface.OnDismissListener;
import android.os.Bundle;
import android.content.Intent;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AlertDialog.Builder;
import android.widget.Toast;

/**
 * Activity responsible for managing the BLE HID passkey service.
 * This activity checks for Bluetooth availability and compatibility,
 * then initializes and manages the HIDService GATT server for 
 * BLE passkey functionality.
 */
public class ServerActivity extends AppCompatActivity {

    /**
     * The HID service instance that provides passkey functionality over BLE.
     */
    private HIDService passkeyService;
    
    /**
     * Initializes the activity and checks for Bluetooth availability and compatibility.
     * If Bluetooth is not enabled, it requests the user to enable it.
     * If BLE peripheral mode is not supported, it displays an error message and exits.
     * Otherwise, it sets up the passkey peripheral provider.
     *
     * @param savedInstanceState If the activity is being re-initialized after previously
     *                           being shut down, this contains the data it most recently
     *                           supplied in onSaveInstanceState(Bundle).
     */
    @Override
    protected void onCreate(final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        if (!HIDService.isBluetoothEnabled(this)) {
            HIDService.enableBluetooth(this);
            return;
        }

        if (!HIDService.isBleSupported(this) || !HIDService.isBlePeripheralSupported(this)) {
            // display alert and exit
            final AlertDialog alertDialog = new Builder(this).create();
            alertDialog.setTitle(getString(R.string.not_supported));
            alertDialog.setMessage(getString(R.string.ble_perip_not_supported));
            alertDialog.setButton(AlertDialog.BUTTON_NEUTRAL, getString(R.string.ok),
                    new OnClickListener() {
                        @Override
                        public void onClick(final DialogInterface dialog, final int which) {
                            dialog.dismiss();
                        }
                    });
            alertDialog.setOnDismissListener(new OnDismissListener() {
                @Override
                public void onDismiss(final DialogInterface dialog) {
                    finish();
                }
            });
            alertDialog.show();
        } else {
            setupPasskeyPeripheralProvider();
        }
    }
    
    /**
     * Sets up the passkey peripheral provider by initializing the HIDService,
     * setting the device name, and starting BLE advertising.
     */
    public void setupPasskeyPeripheralProvider() {
        // Initialize the HIDService if not already initialized
        if(passkeyService == null) {
            passkeyService = new HIDService(this);
            passkeyService.setDeviceName(getString(R.string.ble_beekey));
        }
        passkeyService.startAdvertising();
    }

    /**
     * Handles the result of activity requests, particularly the Bluetooth enable request.
     * If Bluetooth is enabled successfully, it checks for BLE peripheral support and
     * sets up the passkey peripheral provider if supported.
     *
     * @param requestCode The integer request code originally supplied to startActivityForResult().
     * @param resultCode  The integer result code returned by the child activity.
     * @param data        An Intent, which can return result data to the caller.
     */
    @Override
    protected void onActivityResult(final int requestCode, final int resultCode, final Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if (requestCode == HIDService.REQUEST_CODE_BLUETOOTH_ENABLE) {
            if (!HIDService.isBluetoothEnabled(this)) {
                // User selected NOT to use Bluetooth.
                // do nothing
                Toast.makeText(this, R.string.requires_bl_enabled, Toast.LENGTH_LONG).show();
                return;
            }

            if (!HIDService.isBleSupported(this) || !HIDService.isBlePeripheralSupported(this)) {
                // display alert and exit
                final AlertDialog alertDialog = new Builder(this).create();
                alertDialog.setTitle(getString(R.string.not_supported));
                alertDialog.setMessage(getString(R.string.ble_perip_not_supported));
                alertDialog.setButton(AlertDialog.BUTTON_NEUTRAL, getString(R.string.ok),
                        new OnClickListener() {
                            @Override
                            public void onClick(final DialogInterface dialog, final int which) {
                                dialog.dismiss();
                            }
                        });
                alertDialog.setOnDismissListener(new OnDismissListener() {
                    @Override
                    public void onDismiss(final DialogInterface dialog) {
                        finish();
                    }
                });
                alertDialog.show();
            } else {
                setupPasskeyPeripheralProvider();
            }
        }
    }

    /**
     * Cleans up resources when the activity is destroyed.
     * Stops BLE advertising if the passkey service is active.
     */
    @Override
    protected void onDestroy() {
        super.onDestroy();
        
        if (passkeyService != null) {
            passkeyService.stopAdvertising();
        }
    }
}

// Made with Bob
