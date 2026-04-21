package com.isfs.blekey.util;

import android.content.Context;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.FragmentActivity;

import java.util.concurrent.Executor;

/**
 * Helper class for biometric authentication using BiometricPrompt API.
 * Provides a simplified interface for authenticating users with fingerprint, face, or device credentials.
 * 
 * This helper supports:
 * - Strong biometric authentication (fingerprint, face)
 * - Fallback to device credentials (PIN, pattern, password)
 * - Configurable authentication prompts
 * - Error handling and status reporting
 */
public class BiometricAuthHelper {
    
    private static final String TAG = BiometricAuthHelper.class.getCanonicalName();
    
    private final FragmentActivity activity;
    private final Executor executor;
    private BiometricPrompt biometricPrompt;
    private AuthenticationCallback currentCallback;
    
    /**
     * Callback interface for authentication results.
     */
    public interface AuthenticationCallback {
        /**
         * Called when authentication succeeds.
         */
        void onAuthenticationSucceeded();
        
        /**
         * Called when authentication fails.
         * @param errorMessage Description of the error
         */
        void onAuthenticationFailed(String errorMessage);
        
        /**
         * Called when authentication is cancelled by the user.
         */
        void onAuthenticationCancelled();
    }
    
    /**
     * Creates a new BiometricAuthHelper.
     * 
     * @param activity The FragmentActivity context
     */
    public BiometricAuthHelper(@NonNull FragmentActivity activity) {
        this.activity = activity;
        this.executor = ContextCompat.getMainExecutor(activity);
        this.biometricPrompt = new BiometricPrompt(activity, executor, new BiometricAuthCallbackImpl());
    }
    
    /**
     * Checks if biometric authentication is available on this device.
     * 
     * @return true if biometric authentication is available, false otherwise
     */
    public boolean isBiometricAvailable() {
        BiometricManager biometricManager = BiometricManager.from(activity);
        int result = biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG |
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
        );
        
        switch (result) {
            case BiometricManager.BIOMETRIC_SUCCESS:
                Log.d(TAG, "Biometric authentication is available");
                return true;
            case BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE:
                Log.w(TAG, "No biometric hardware available");
                return false;
            case BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE:
                Log.w(TAG, "Biometric hardware unavailable");
                return false;
            case BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED:
                Log.w(TAG, "No biometric credentials enrolled");
                return false;
            case BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED:
                Log.w(TAG, "Security update required for biometric authentication");
                return false;
            case BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED:
                Log.w(TAG, "Biometric authentication unsupported");
                return false;
            case BiometricManager.BIOMETRIC_STATUS_UNKNOWN:
                Log.w(TAG, "Biometric status unknown");
                return false;
            default:
                Log.w(TAG, "Unknown biometric status: " + result);
                return false;
        }
    }
    
    /**
     * Authenticates the user with biometric or device credentials.
     * 
     * @param title Title for the authentication prompt
     * @param subtitle Subtitle for the authentication prompt
     * @param callback Callback for authentication results
     */
    public void authenticate(@NonNull String title, 
                           @NonNull String subtitle,
                           @NonNull AuthenticationCallback callback) {
        authenticate(title, subtitle, null, callback);
    }
    
    /**
     * Authenticates the user with biometric or device credentials.
     * 
     * @param title Title for the authentication prompt
     * @param subtitle Subtitle for the authentication prompt
     * @param description Optional description for the authentication prompt
     * @param callback Callback for authentication results
     */
    public void authenticate(@NonNull String title,
                           @NonNull String subtitle,
                           String description,
                           @NonNull AuthenticationCallback callback) {
        if (!isBiometricAvailable()) {
            callback.onAuthenticationFailed("Biometric authentication not available");
            return;
        }
        
        this.currentCallback = callback;
        
        BiometricPrompt.PromptInfo.Builder promptInfoBuilder = new BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_STRONG |
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
            );
        
        if (description != null && !description.isEmpty()) {
            promptInfoBuilder.setDescription(description);
        }
        
        BiometricPrompt.PromptInfo promptInfo = promptInfoBuilder.build();
        biometricPrompt.authenticate(promptInfo);
    }
    
    /**
     * Authenticates for credential issuance with appropriate messaging.
     * 
     * @param callback Callback for authentication results
     */
    public void authenticateForIssuance(@NonNull AuthenticationCallback callback) {
        authenticate(
            "Authenticate to Issue Credential",
            "Verify your identity to receive the credential",
            "This credential will be securely stored on your device",
            callback
        );
    }
    
    /**
     * Authenticates for credential presentation with appropriate messaging.
     * 
     * @param callback Callback for authentication results
     */
    public void authenticateForPresentation(@NonNull AuthenticationCallback callback) {
        authenticate(
            "Authenticate to Share Credential",
            "Verify your identity to share your credential",
            "Your credential will be shared with the requesting party",
            callback
        );
    }
    
    /**
     * Authenticates for credential access with appropriate messaging.
     * 
     * @param callback Callback for authentication results
     */
    public void authenticateForAccess(@NonNull AuthenticationCallback callback) {
        authenticate(
            "Authenticate to Access Credential",
            "Verify your identity to view credential details",
            callback
        );
    }
    
    /**
     * Cancels any ongoing authentication.
     */
    public void cancelAuthentication() {
        if (biometricPrompt != null) {
            biometricPrompt.cancelAuthentication();
        }
    }
    
    /**
     * Gets a user-friendly message for biometric availability status.
     * 
     * @param context Application context
     * @return Status message
     */
    public static String getBiometricStatusMessage(@NonNull Context context) {
        BiometricManager biometricManager = BiometricManager.from(context);
        int result = biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG |
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
        );
        
        switch (result) {
            case BiometricManager.BIOMETRIC_SUCCESS:
                return "Biometric authentication available";
            case BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE:
                return "No biometric hardware available on this device";
            case BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE:
                return "Biometric hardware is currently unavailable";
            case BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED:
                return "No biometric credentials enrolled. Please set up fingerprint or face unlock in Settings";
            case BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED:
                return "Security update required for biometric authentication";
            case BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED:
                return "Biometric authentication is not supported on this device";
            case BiometricManager.BIOMETRIC_STATUS_UNKNOWN:
                return "Biometric status unknown";
            default:
                return "Unknown biometric status";
        }
    }
    
    /**
     * Helper method to determine if an error code represents user cancellation.
     *
     * @param errorCode The BiometricPrompt error code
     * @return true if the error represents user cancellation
     */
    private boolean isUserCancellation(int errorCode) {
        return errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
               errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
               errorCode == BiometricPrompt.ERROR_CANCELED;
    }
    
    /**
     * Private implementation of BiometricPrompt.AuthenticationCallback.
     * Delegates to the current AuthenticationCallback provided by the caller.
     */
    private class BiometricAuthCallbackImpl extends BiometricPrompt.AuthenticationCallback {
        @Override
        public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
            super.onAuthenticationError(errorCode, errString);
            Log.e(TAG, "Authentication error: " + errString + " (code: " + errorCode + ")");
            
            if (currentCallback != null) {
                if (isUserCancellation(errorCode)) {
                    currentCallback.onAuthenticationCancelled();
                } else {
                    currentCallback.onAuthenticationFailed(errString.toString());
                }
            }
        }
        
        @Override
        public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
            super.onAuthenticationSucceeded(result);
            Log.d(TAG, "Authentication succeeded");
            
            if (currentCallback != null) {
                currentCallback.onAuthenticationSucceeded();
            }
        }
        
        @Override
        public void onAuthenticationFailed() {
            super.onAuthenticationFailed();
            Log.w(TAG, "Authentication failed - biometric not recognized");
        }
    }
}

// Made with Bob