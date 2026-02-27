/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.activity;

import com.isfs.blekey.hidsvc.HIDService;

import java.util.ArrayList;
import java.util.List;
import java.io.File;


import com.isfs.blekey.R;

import android.Manifest;
import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.content.DialogInterface.OnDismissListener;
import android.os.Bundle;
import android.util.Log;
import android.content.Intent;
import android.content.pm.PackageManager;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AlertDialog.Builder;
import android.widget.Toast;

import com.isfs.blekey.util.FileUtils;
import com.isfs.blekey.MainActivity;

/**
 * Activity responsible for managing the BLE HID passkey service.
 * This activity checks for Bluetooth availability and compatibility,
 * then initializes and manages the HIDService GATT server for 
 * BLE passkey functionality.
 */
public class ServerActivity extends AppCompatActivity {

    private final String TAG = ServerActivity.class.getCanonicalName();

    /**
     * The HID service instance that provides passkey functionality over BLE.
     */
    private HIDService passkeyService;
    
    /**
     * Flag to track if the Create Passkey button was clicked
     */
    private boolean createPasskeyClicked = false;
    
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
        Log.d(TAG, "onCreate");
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_server);
        
        // Set up back button in toolbar
        findViewById(R.id.backButton).setOnClickListener(view -> {
            // Shut down the Bluetooth GATT server before returning to MainActivity
            if (passkeyService != null) {
                passkeyService.stopAdvertising();
            }
            finish();
        });

        // First check if Bluetooth is supported and was enabled
        if (!HIDService.isBluetoothEnabled(this)) {
            Log.d(TAG, "Did not get bluetooth start permission?");
            showUXForNotPermitted();
            return;
        }

        if (!HIDService.isBleSupported(this) || !HIDService.isBlePeripheralSupported(this)) {
            Log.d(TAG, "Did not get bluetooth LE permission?");
            showUXForNotPermitted();
            return;
        }

        // Update permission flags to check current status
        updatePermissionFlags();
        
        // If we already have permissions, set up the service
        if (CONNECT_GRANTED == true && ADVERTISE_GRANTED == true) {
            Log.d(TAG, "Already have all required permissions, setting up service");
            setupPasskeyPeripheralProvider();
        } else {
            // Otherwise, request permissions and wait for callback
            Log.d(TAG, "Need to request permissions first");
            askForPermissions();
        }
    }

    private void showUXForNotPermitted() {
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
    }
    
    /**
     * Sets up the passkey peripheral provider by initializing the HIDService,
     * setting the device name, and starting BLE advertising.
     */
    public void setupPasskeyPeripheralProvider() {
        // Check if any passkeys exist before starting advertising
        if (noPasskeysExist()) {
            // No passkeys exist, show dialog and redirect to ManageActivity
            showNoPasskeysDialog();
            return;
        }
        
        // Initialize the HIDService if not already initialized
        if(passkeyService == null) {
            passkeyService = new HIDService(this,
                                        (CONNECT_GRANTED == null) ? false: CONNECT_GRANTED,
                                        (ADVERTISE_GRANTED == null) ? false : ADVERTISE_GRANTED);
            passkeyService.setDeviceName(getString(R.string.ble_beekey));
        }
        passkeyService.startAdvertising();
    }
    
    /**
     * Checks if any passkeys exist in the FIDO2_HOME directory.
     *
     * @return true if no passkeys exist, false otherwise
     */
    private boolean noPasskeysExist() {
        // In Android, we should use the app's data directory
        File appDataDir = getFilesDir();
        System.setProperty("FIDO2_HOME", appDataDir.getAbsolutePath());
        
        return FileUtils.listPasskeys() == null || FileUtils.listPasskeys().isEmpty();
    }

    /**
     * Stops the passkey service and navigates back to MainActivity.
     */
    private void stopServiceAndReturnToMain() {
        // Shut down the Bluetooth server gracefully if it has started
        if (passkeyService != null) {
            passkeyService.stopAdvertising();
        }
        passkeyService = null;
        
        // Return to MainActivity
        Intent mainIntent = new Intent(getApplicationContext(), MainActivity.class);
        mainIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(mainIntent);
        finish();
    }

    /**
     * Handles the Create Passkey button click.
     */
    private void onCreatePasskeyClicked(DialogInterface dialog) {
        createPasskeyClicked = true;
        Intent intent = new Intent(ServerActivity.this, ManageActivity.class);
        startActivity(intent);
        dialog.dismiss();
        finish();
    }

    /**
     * Handles the Cancel button click.
     */
    private void onCancelClicked(DialogInterface dialog) {
        Log.d(TAG, "Cancel button clicked, shutting down and returning to main activity");
        dialog.dismiss();
        stopServiceAndReturnToMain();
    }

    /**
     * Handles dialog dismissal when not handled by buttons.
     */
    private void onDialogDismissed(DialogInterface dialog) {
        // Only handle dismissal if it wasn't already handled by a button click
        if (isFinishing() || createPasskeyClicked) {
            Log.d(TAG, "Dialog dismissed but activity is already finishing or create passkey was clicked");
            return;
        }
        
        Log.d(TAG, "Dialog dismissed without button click, shutting down and returning to main activity");
        stopServiceAndReturnToMain();
    }
    
    /**
     * Shows a dialog informing the user that they need to create a passkey
     * before they can start advertising. Provides options to create a passkey
     * or cancel.
     */
    private void showNoPasskeysDialog() {
        final AlertDialog alertDialog = new Builder(this).create();
        alertDialog.setTitle(getString(R.string.no_passkeys));
        alertDialog.setMessage(getString(R.string.create_passkey_first));
        
        // Add button to create a passkey
        alertDialog.setButton(AlertDialog.BUTTON_POSITIVE, getString(R.string.create_passkey),
                (dialog, which) -> onCreatePasskeyClicked(dialog));
        
        // Add button to cancel
        alertDialog.setButton(AlertDialog.BUTTON_NEGATIVE, getString(R.string.cancel),
                (dialog, which) -> onCancelClicked(dialog));
        
        alertDialog.setOnDismissListener(dialog -> onDialogDismissed(dialog));
        
        alertDialog.show();
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
        Log.d(TAG, "onActivityResult");
        super.onActivityResult(requestCode, resultCode, data);

        if (requestCode == REQUEST_CODE_BLUETOOTH_CONNECT) {
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

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        Log.d(TAG, "onRequestPermissionsResult");
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        
        if (requestCode == REQUEST_CODE_BLUETOOTH_CONNECT) {
            processPermissionsResults(permissions, grantResults);
            
            // Only proceed if we have both required permissions
            if (CONNECT_GRANTED == true && ADVERTISE_GRANTED == true) {
                Log.d(TAG, "Got all required permissions, setting up service");
                setupPasskeyPeripheralProvider();
            } else {
                // Permission denied, display alert and exit
                Log.d(TAG, "Permission denied: CONNECT=" + CONNECT_GRANTED + ", ADVERTISE=" + ADVERTISE_GRANTED);
                final AlertDialog alertDialog = new Builder(this).create();
                alertDialog.setTitle(getString(R.string.not_supported));
                alertDialog.setMessage(getString(R.string.ble_not_permitted));
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
            }
        }
    }


    /**
     * Request code for bluetooth connect permission
     */
    public static final int REQUEST_CODE_BLUETOOTH_CONNECT = 0xb1e;

    /**
     * Results of permission checks
     */
    private static Boolean CONNECT_GRANTED = null;
    private static Boolean ADVERTISE_GRANTED = null;
    
    private void processPermissionsResults(String[] permissions, int[] grantResults) {
        for (int i = 0; i < permissions.length; i++) {
            if (permissions[i].equals(Manifest.permission.BLUETOOTH_CONNECT)) {
                if (grantResults[i] == PackageManager.PERMISSION_GRANTED) {
                    Log.d(TAG, "Have BLUETOOTH_CONNECT permission, start it up!");
                    CONNECT_GRANTED = true;
                } else {
                    CONNECT_GRANTED = false;
                }
            }
            else if (permissions[i].equals(Manifest.permission.BLUETOOTH_ADVERTISE)) {
                if (grantResults[i] == PackageManager.PERMISSION_GRANTED) {
                    Log.d(TAG, "Have BLUETOOTH_ADVERTISE permission, start it up!");
                    ADVERTISE_GRANTED = true;
                }
                else {
                    ADVERTISE_GRANTED = false;
                }
            }
        }

    }

    private void updatePermissionFlags() {
        // Check BLUETOOTH_CONNECT permission
        if (ContextCompat.checkSelfPermission(this,
                Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED) {
            Log.d(TAG, "Have BLUETOOTH_CONNECT permission");
            CONNECT_GRANTED = true;
        } else {
            CONNECT_GRANTED = false;
        }
        // Check BLUETOOTH_ADVERTISE permission
        if (ContextCompat.checkSelfPermission(this,
                Manifest.permission.BLUETOOTH_ADVERTISE) == PackageManager.PERMISSION_GRANTED) {
            Log.d(TAG, "Have BLUETOOTH_ADVERTISE permission");
            ADVERTISE_GRANTED = true;
        } else {
            ADVERTISE_GRANTED = false;
        }
    }

    private void askForPermissions() {
        updatePermissionFlags();
        
        // If we have both permissions, we can proceed
        if (CONNECT_GRANTED == true && ADVERTISE_GRANTED == true) {
            Log.d(TAG, "Have all required Bluetooth permissions, start it up!");
            return;
        }
        
        // Check if we should show rationale for CONNECT permission
        if (!CONNECT_GRANTED &&
                ActivityCompat.shouldShowRequestPermissionRationale(this, Manifest.permission.BLUETOOTH_CONNECT)) {
            Log.d(TAG, "Can't do anything without BLUETOOTH_CONNECT permission");
            Toast.makeText(this, getString(R.string.ble_not_permitted), Toast.LENGTH_SHORT).show();
            finish();
            return;
        }
        
        // Request any missing permissions
        try {
            Log.d(TAG, "Asking for Bluetooth permissions");
            List<String> permissionsToRequest = new ArrayList<>();
            
            if (!CONNECT_GRANTED) { // Need CONNECT
                permissionsToRequest.add(Manifest.permission.BLUETOOTH_CONNECT);
            }
            if (!ADVERTISE_GRANTED) { // Need ADVERTISE
                permissionsToRequest.add(Manifest.permission.BLUETOOTH_ADVERTISE);
            }
            
            if (permissionsToRequest.size() > 0) {
                requestPermissions(permissionsToRequest.toArray(new String[0]), REQUEST_CODE_BLUETOOTH_CONNECT);
            }
        } catch (Exception e) {
            Log.e(TAG, "Error asking for Bluetooth permissions", e);
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