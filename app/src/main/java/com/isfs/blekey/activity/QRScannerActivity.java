/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.activity;

import android.content.Context;
import android.content.Intent;
import android.media.ToneGenerator;
import android.media.AudioManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.os.VibratorManager;
import android.util.Log;
import android.view.View;
import android.widget.ImageButton;
import android.widget.Toast;

import androidx.activity.OnBackPressedCallback;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.core.view.WindowCompat;

import com.isfs.blekey.util.InsetsHelper;

import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.ResultPoint;
import com.isfs.blekey.R;
import com.journeyapps.barcodescanner.BarcodeCallback;
import com.journeyapps.barcodescanner.BarcodeResult;
import com.journeyapps.barcodescanner.DecoratedBarcodeView;
import com.journeyapps.barcodescanner.DefaultDecoderFactory;

import java.util.Arrays;
import java.util.List;

/**
 * Activity for scanning QR codes containing credential offers or presentation requests.
 * Uses ZXing library to scan QR codes with custom URI schemes:
 * - openid-credential-offer://
 * - openid4vp://
 *
 * The scanned URI is routed directly to [ManageActivity](app/src/main/java/com/isfs/blekey/activity/ManageActivity.java)
 * for credential handling.
 */
public class QRScannerActivity extends AppCompatActivity {
    private static final String TAG = "QRScannerActivity";
    
    // Result codes
    public static final int RESULT_SCAN_SUCCESS = RESULT_OK;
    public static final int RESULT_SCAN_CANCELLED = RESULT_CANCELED;
    public static final int RESULT_SCAN_ERROR = RESULT_FIRST_USER;
    
    // Intent extra keys
    public static final String EXTRA_SCANNED_URI = "scanned_uri";
    public static final String EXTRA_ERROR_MESSAGE = "error_message";
    
    // UI components
    private DecoratedBarcodeView barcodeView;
    private FloatingActionButton flashlightButton;
    private boolean isFlashlightOn = false;
    private boolean hasScanned = false; // Debounce flag
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        WindowCompat.setDecorFitsSystemWindows(getWindow(), false);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_qr_scanner);

        // Apply bottom inset to root so the flashlight FAB clears the nav bar
        InsetsHelper.applyBottomInset(findViewById(R.id.barcode_scanner).getRootView());

        // Set up toolbar with back button
        setupToolbar();
        
        // Initialize barcode scanner
        initializeBarcodeScanner();
        
        // Set up flashlight toggle
        setupFlashlightToggle();
        
        // Set up modern back press handling
        setupBackPressHandler();
    }
    
    /**
     * Sets up modern back press handling using OnBackPressedCallback.
     */
    private void setupBackPressHandler() {
        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override
            public void handleOnBackPressed() {
                setResult(RESULT_SCAN_CANCELLED);
                finish();
            }
        });
    }
    
    /**
     * Sets up the toolbar with back button and home button functionality.
     */
    private void setupToolbar() {
        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayShowTitleEnabled(false);
        }

        InsetsHelper.applyTopInsetToToolbar(toolbar);

        ImageButton backButton = toolbar.findViewById(R.id.backButton);
        backButton.setOnClickListener(v -> {
            setResult(RESULT_SCAN_CANCELLED);
            finish();
        });
        
        ImageButton homeButton = toolbar.findViewById(R.id.homeButton);
        homeButton.setOnClickListener(v -> {
            Intent intent = new Intent(this, com.isfs.blekey.MainActivity.class);
            intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(intent);
            finish();
        });
    }
    
    /**
     * Initializes the ZXing barcode scanner with QR code format only.
     */
    private void initializeBarcodeScanner() {
        barcodeView = findViewById(R.id.barcode_scanner);
        
        // Configure to scan QR codes only
        barcodeView.getBarcodeView().setDecoderFactory(
            new DefaultDecoderFactory(Arrays.asList(BarcodeFormat.QR_CODE))
        );
        
        // Set up scan callback
        barcodeView.decodeContinuous(new BarcodeCallback() {
            @Override
            public void barcodeResult(BarcodeResult result) {
                if (result != null && result.getText() != null && !hasScanned) {
                    handleScannedCode(result.getText());
                }
            }
            
            @Override
            public void possibleResultPoints(List<ResultPoint> resultPoints) {
                // Optional: Could be used for visual feedback
            }
        });
    }
    
    /**
     * Sets up the flashlight toggle button.
     */
    private void setupFlashlightToggle() {
        flashlightButton = findViewById(R.id.flashlight_button);
        
        // Check if device has flashlight
        if (!hasFlashlight()) {
            flashlightButton.setVisibility(View.GONE);
            return;
        }
        
        flashlightButton.setOnClickListener(v -> toggleFlashlight());
    }
    
    /**
     * Checks if the device has a flashlight/torch.
     */
    private boolean hasFlashlight() {
        return getPackageManager().hasSystemFeature(
            android.content.pm.PackageManager.FEATURE_CAMERA_FLASH
        );
    }
    
    /**
     * Toggles the camera flashlight on/off.
     */
    private void toggleFlashlight() {
        if (isFlashlightOn) {
            barcodeView.setTorchOff();
            isFlashlightOn = false;
            flashlightButton.setContentDescription(getString(R.string.flashlight_off));
        } else {
            barcodeView.setTorchOn();
            isFlashlightOn = true;
            flashlightButton.setContentDescription(getString(R.string.flashlight_on));
        }
    }
    
    /**
     * Handles a scanned QR code by validating the URI scheme and routing valid
     * credential URIs directly to [ManageActivity](app/src/main/java/com/isfs/blekey/activity/ManageActivity.java).
     *
     * @param scannedText The text content of the scanned QR code
     */
    private void handleScannedCode(String scannedText) {
        if (hasScanned) {
            return;
        }
        hasScanned = true;

        Log.i(TAG, "Scanned QR code: " + scannedText);

        if (isValidCredentialUri(scannedText)) {
            vibrateSuccess();
            barcodeView.pause();
            routeToCredentialFlow(scannedText);
        } else {
            hasScanned = false;
            showInvalidQrError(scannedText);
        }
    }

    /**
     * Routes a scanned credential URI directly to [ManageActivity](app/src/main/java/com/isfs/blekey/activity/ManageActivity.java).
     */
    private void routeToCredentialFlow(String uri) {
        Intent intent = new Intent(this, ManageActivity.class);

        if (uri.startsWith("openid-credential-offer://")) {
            intent.setAction("com.isfs.blekey.CREDENTIAL_OFFER");
            intent.putExtra("credential_offer_uri", uri);
            intent.putExtra("flow_type", "issuance");
        } else if (uri.startsWith("openid4vp://")) {
            intent.setAction("com.isfs.blekey.PRESENTATION_REQUEST");
            intent.putExtra("presentation_request_uri", uri);
            intent.putExtra("flow_type", "presentation");
        } else {
            hasScanned = false;
            Toast.makeText(this, "Invalid credential URI", Toast.LENGTH_SHORT).show();
            return;
        }

        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        startActivity(intent);
        finish();
    }
    
    /**
     * Validates if the scanned URI has a supported credential scheme.
     *
     * @param uri The URI to validate
     * @return true if the URI scheme is supported, false otherwise
     */
    private boolean isValidCredentialUri(String uri) {
        return uri != null &&
               !uri.isEmpty() &&
               (uri.startsWith("openid-credential-offer://") ||
                uri.startsWith("openid4vp://"));
    }
    
    /**
     * Shows an error message for invalid QR codes.
     * 
     * @param scannedText The invalid scanned text
     */
    private void showInvalidQrError(String scannedText) {
        runOnUiThread(() -> {
            String errorMessage = getString(R.string.qr_scanner_invalid);
            
            // Log the invalid URI for debugging
            Log.w(TAG, "Invalid QR code scanned: " + scannedText);
            
            // Show toast with error
            Toast.makeText(this, errorMessage, Toast.LENGTH_LONG).show();
            
            // Provide error vibration
            vibrateError();
        });
    }
    
    /**
     * Provides haptic feedback for successful scan.
     */
    private void vibrateSuccess() {
        try {
            Vibrator vibrator = getVibrator();
            if (vibrator != null && vibrator.hasVibrator()) {
                // Single short vibration for success
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    vibrator.vibrate(VibrationEffect.createOneShot(100, VibrationEffect.DEFAULT_AMPLITUDE));
                } else {
                    // Fallback for older devices
                    vibrator.vibrate(100);
                }
            }
            
            // Play success beep sound
            playSuccessBeep();
        } catch (Exception e) {
            Log.w(TAG, "Failed to vibrate", e);
        }
    }
    
    /**
     * Plays a success beep sound when QR code is successfully scanned.
     */
    private void playSuccessBeep() {
        try {
            ToneGenerator toneGenerator = new ToneGenerator(AudioManager.STREAM_NOTIFICATION, 100);
            toneGenerator.startTone(ToneGenerator.TONE_PROP_BEEP, 200);
            
            // Release after a short delay using modern Handler constructor
            new Handler(Looper.getMainLooper()).postDelayed(() -> {
                try {
                    toneGenerator.release();
                } catch (Exception e) {
                    Log.w(TAG, "Failed to release tone generator", e);
                }
            }, 300);
        } catch (Exception e) {
            Log.w(TAG, "Failed to play beep sound", e);
        }
    }
    
    /**
     * Provides haptic feedback for error using modern Vibrator API.
     */
    private void vibrateError() {
        try {
            Vibrator vibrator = getVibrator();
            if (vibrator != null && vibrator.hasVibrator()) {
                // Double short vibration for error
                long[] pattern = {0, 100, 100, 100};
                
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    vibrator.vibrate(VibrationEffect.createWaveform(pattern, -1));
                } else {
                    // Fallback for older devices
                    vibrator.vibrate(pattern, -1);
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "Failed to vibrate", e);
        }
    }
    
    /**
     * Gets the Vibrator instance using the appropriate API for the device's Android version.
     *
     * @return Vibrator instance or null if not available
     */
    private Vibrator getVibrator() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            // Android 12+ (API 31+): Use VibratorManager
            VibratorManager vibratorManager = (VibratorManager) getSystemService(Context.VIBRATOR_MANAGER_SERVICE);
            return vibratorManager != null ? vibratorManager.getDefaultVibrator() : null;
        } else {
            // Older versions: Use deprecated VIBRATOR_SERVICE
            return (Vibrator) getSystemService(VIBRATOR_SERVICE);
        }
    }
    
    @Override
    protected void onResume() {
        super.onResume();
        barcodeView.resume();
    }
    
    @Override
    protected void onPause() {
        super.onPause();
        barcodeView.pause();
        
        // Turn off flashlight when pausing
        if (isFlashlightOn) {
            barcodeView.setTorchOff();
            isFlashlightOn = false;
        }
    }
    
    @Override
    protected void onDestroy() {
        super.onDestroy();
        // Clean up resources
        if (barcodeView != null) {
            barcodeView.pause();
        }
    }
    
}

// Made with Bob