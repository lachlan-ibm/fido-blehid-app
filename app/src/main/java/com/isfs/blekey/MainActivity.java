 /*
 * Copyright IBM 2025
 */
package com.isfs.blekey;

import android.os.Bundle;
import android.view.View;
import android.content.Intent;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.app.AlertDialog;
import android.util.Log;
import android.widget.Toast;
import android.widget.Button;

import com.isfs.blekey.activity.ManageActivity;
import com.isfs.blekey.activity.ServerActivity;
import com.isfs.blekey.activity.QRScannerActivity;
import com.isfs.blekey.util.AndroidKeystoreManager;
import com.isfs.blekey.util.KeyUtils;
import com.isfs.blekey.util.CameraPermissionHelper;


/**
 * Main entry point for the BLE HID Passkey application.
 * This activity provides a simple user interface with a toggle button
 * that launches the PasskeyActivity when clicked.
 */
public class MainActivity extends AppCompatActivity {

    private static final String TAG = "MainActivity";
    private static final int CAMERA_PERMISSION_REQUEST_CODE = 1001;

    /**
     * Initializes the activity, sets up the UI and configures the toggle button
     * to launch the PasskeyActivity when clicked.
     *
     * @param savedInstanceState If the activity is being re-initialized after previously
     *                           being shut down, this contains the data it most recently
     *                           supplied in onSaveInstanceState(Bundle).
     */
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        setupToolbar();
        initializeRootKeyPair();
        setupButtons();
    }
    
    /**
     * Configures the toolbar by hiding back and home buttons to center the logo.
     */
    private void setupToolbar() {
        findViewById(R.id.backButton).setVisibility(View.GONE);
        findViewById(R.id.homeButton).setVisibility(View.GONE);
    }
    
    /**
     * Sets up click listeners for all buttons using lambda expressions.
     */
    private void setupButtons() {
        Button serverButton = findViewById(R.id.serverButton);
        serverButton.setOnClickListener(v ->
            startActivity(new Intent(this, ServerActivity.class)));
        
        Button manageButton = findViewById(R.id.manageButton);
        manageButton.setOnClickListener(v ->
            startActivity(new Intent(this, ManageActivity.class)));
        
        Button scanQrButton = findViewById(R.id.scanQrButton);
        scanQrButton.setOnClickListener(v -> {
            if (hasCameraPermission()) {
                startActivity(new Intent(this, QRScannerActivity.class));
            } else {
                requestCameraPermission();
            }
        });
    }
    
    /**
     * Initializes the root key pair needed for passkey operations.
     * This should be done first when the app starts.
     */
    private void initializeRootKeyPair() {
        try {
            // Set FIDO2_HOME to the app's files directory if missing
            String fido2Home = System.getProperty("FIDO2_HOME");
            if (fido2Home == null) {
                fido2Home = getFilesDir().getAbsolutePath();
                System.setProperty("FIDO2_HOME", fido2Home);
                Log.i(TAG, "Set FIDO2_HOME to: " + fido2Home);
            }
            
            AndroidKeystoreManager keystoreManager = new AndroidKeystoreManager();
            KeyUtils.setKeystoreManager(keystoreManager);
            if (!keystoreManager.isKeystoreAvailable()) {
                String platformKeyPath = fido2Home +
                        java.nio.file.FileSystems.getDefault().getSeparator() + "platform.key";
                KeyUtils.ensureRootKeyPair(platformKeyPath, null);
            }

            Log.i(TAG, "Root key pair initialized successfully");

        } catch (Exception e) {
            Log.e(TAG, "Failed to initialize root key pair", e);
            Toast.makeText(this, "Failed to initialize platform key: " + e.getMessage(), Toast.LENGTH_SHORT).show();
        }
    }
    
    
    /**
     * Checks if camera permission is granted.
     *
     * @return true if camera permission is granted, false otherwise
     */
    private boolean hasCameraPermission() {
        return CameraPermissionHelper.checkPermission(this);
    }
    
    /**
     * Requests camera permission from the user.
     * Shows a rationale dialog first if the user has previously denied the permission.
     */
    private void requestCameraPermission() {
        if (CameraPermissionHelper.shouldShowRationale(this)) {
            // Show rationale dialog before requesting permission
            showPermissionRationaleDialog();
        } else {
            // Request permission directly
            CameraPermissionHelper.requestPermission(this, CAMERA_PERMISSION_REQUEST_CODE);
        }
    }
    
    /**
     * Shows a dialog explaining why camera permission is needed.
     * This is shown when the user has previously denied the permission.
     */
    private void showPermissionRationaleDialog() {
        new AlertDialog.Builder(this)
            .setTitle("Camera Permission Required")
            .setMessage(CameraPermissionHelper.getPermissionRationale())
            .setPositiveButton("Grant Permission", (dialog, which) -> {
                CameraPermissionHelper.requestPermission(this, CAMERA_PERMISSION_REQUEST_CODE);
            })
            .setNegativeButton("Cancel", (dialog, which) -> {
                Toast.makeText(this, "Camera permission is required to scan QR codes", Toast.LENGTH_SHORT).show();
            })
            .show();
    }
    
    /**
     * Handles the result of permission requests.
     * Called when the user responds to a permission request dialog.
     */
    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        
        if (requestCode == CAMERA_PERMISSION_REQUEST_CODE) {
            if (CameraPermissionHelper.isPermissionGranted(grantResults)) {
                Log.i(TAG, "Camera permission granted");
                Toast.makeText(this, "Camera permission granted", Toast.LENGTH_SHORT).show();
                startActivity(new Intent(this, QRScannerActivity.class));
            } else {
                Log.w(TAG, "Camera permission denied");
                // Check if user selected "Don't ask again"
                if (!CameraPermissionHelper.shouldShowRationale(this)) {
                    // User selected "Don't ask again" - show message about Settings
                    new AlertDialog.Builder(this)
                        .setTitle("Permission Denied")
                        .setMessage(CameraPermissionHelper.getPermissionDeniedMessage())
                        .setPositiveButton("OK", null)
                        .show();
                } else {
                    Toast.makeText(this, "Camera permission denied", Toast.LENGTH_SHORT).show();
                }
            }
        }
    }
    
}
