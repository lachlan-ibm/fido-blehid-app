/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.util;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.pm.PackageManager;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

/**
 * Helper class for managing camera permissions.
 * Provides a simplified interface for checking and requesting camera permissions
 * following Android 13+ best practices.
 * 
 * This helper supports:
 * - Permission status checking
 * - Permission rationale detection
 * - Permission request handling
 * - User-friendly status messages
 */
public class CameraPermissionHelper {
    
    private static final String TAG = CameraPermissionHelper.class.getCanonicalName();
    
    /**
     * Checks if camera permission is granted.
     * 
     * @param context Application context
     * @return true if camera permission is granted, false otherwise
     */
    public static boolean checkPermission(@NonNull Context context) {
        int result = ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA);
        boolean granted = result == PackageManager.PERMISSION_GRANTED;
        
        if (granted) {
            Log.d(TAG, "Camera permission is granted");
        } else {
            Log.d(TAG, "Camera permission is not granted");
        }
        
        return granted;
    }
    
    /**
     * Checks if the app should show a rationale for requesting camera permission.
     * This returns true if the user has previously denied the permission.
     * 
     * @param activity The activity context
     * @return true if rationale should be shown, false otherwise
     */
    public static boolean shouldShowRationale(@NonNull Activity activity) {
        boolean shouldShow = ActivityCompat.shouldShowRequestPermissionRationale(
            activity, 
            Manifest.permission.CAMERA
        );
        
        if (shouldShow) {
            Log.d(TAG, "Should show permission rationale");
        }
        
        return shouldShow;
    }
    
    /**
     * Requests camera permission from the user.
     * The result will be delivered to the activity's onRequestPermissionsResult() method.
     * 
     * @param activity The activity context
     * @param requestCode The request code to identify this permission request
     */
    public static void requestPermission(@NonNull Activity activity, int requestCode) {
        Log.d(TAG, "Requesting camera permission with request code: " + requestCode);
        ActivityCompat.requestPermissions(
            activity,
            new String[]{Manifest.permission.CAMERA},
            requestCode
        );
    }
    
    /**
     * Checks if the permission request result indicates that permission was granted.
     * This should be called from the activity's onRequestPermissionsResult() method.
     * 
     * @param grantResults The grant results array from onRequestPermissionsResult
     * @return true if permission was granted, false otherwise
     */
    public static boolean isPermissionGranted(@NonNull int[] grantResults) {
        boolean granted = grantResults.length > 0 && 
                         grantResults[0] == PackageManager.PERMISSION_GRANTED;
        
        if (granted) {
            Log.d(TAG, "Camera permission was granted by user");
        } else {
            Log.d(TAG, "Camera permission was denied by user");
        }
        
        return granted;
    }
    
    /**
     * Gets a user-friendly message for camera permission status.
     * 
     * @param context Application context
     * @return Status message
     */
    public static String getPermissionStatusMessage(@NonNull Context context) {
        if (checkPermission(context)) {
            return "Camera permission granted";
        } else {
            return "Camera permission is required to scan QR codes";
        }
    }
    
    /**
     * Gets a user-friendly rationale message explaining why camera permission is needed.
     * This should be shown to the user before requesting permission.
     * 
     * @return Rationale message
     */
    public static String getPermissionRationale() {
        return "Camera access is required to scan QR codes for credential offers and presentation requests. " +
               "The camera will only be used when you explicitly choose to scan a QR code.";
    }
    
    /**
     * Gets a message to show when permission is permanently denied (user selected "Don't ask again").
     * 
     * @return Message for permanently denied permission
     */
    public static String getPermissionDeniedMessage() {
        return "Camera permission is required to scan QR codes. " +
               "Please enable camera permission in Settings to use this feature.";
    }
}

// Made with Bob