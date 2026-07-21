/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.util;

import androidx.annotation.NonNull;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.fragment.app.FragmentActivity;

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

/**
 * Helper that wraps {@link BiometricPrompt} to show biometric challenges.
 *
 * <p>Two overloads of {@code authenticate} are provided:
 * <ul>
 *   <li>Convenience overloads ({@link #authenticateForIssuance},
 *       {@link #authenticateForPresentation}) for credential flows that do not
 *       need a {@link BiometricPrompt.CryptoObject}.</li>
 *   <li>The {@link BiometricPrompt.CryptoObject} overload used by the secure-storage
 *       TEE gate: it binds the prompt to a pre-initialised {@link java.security.Signature}
 *       so that the Android Keystore releases the bio-gated platform key only once the
 *       user authenticates successfully.</li>
 * </ul>
 * <p>
 * NOTE: {@link BiometricPrompt.PromptInfo} built for the {@code CryptoObject} overload must
 * NOT include {@link BiometricManager.Authenticators#DEVICE_CREDENTIAL} — Android throws
 * {@link IllegalArgumentException} if you mix device-credential with a {@code CryptoObject}.
 * </p>
 */
public class BiometricAuthHelper {

    /**
     * Callback for biometric authentication events.
     *
     * <p>{@link #onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult)} receives
     * the full result so callers that bound a {@link BiometricPrompt.CryptoObject} can
     * extract the authenticated {@link java.security.Signature}.  Callers that do not need
     * the result may simply ignore the parameter.</p>
     */
    public interface AuthenticationCallback {
        void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result);
        void onAuthenticationFailed(String errorMessage);
        void onAuthenticationCancelled();
    }

    private final BiometricPrompt biometricPrompt;
    private volatile AuthenticationCallback currentCallback;

    public BiometricAuthHelper(@NonNull FragmentActivity activity) {
        Executor executor = Executors.newSingleThreadExecutor();
        biometricPrompt = new BiometricPrompt(activity, executor,
                new BiometricPrompt.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationSucceeded(
                            @NonNull BiometricPrompt.AuthenticationResult result) {
                        AuthenticationCallback cb = currentCallback;
                        if (cb != null) cb.onAuthenticationSucceeded(result);
                    }

                    @Override
                    public void onAuthenticationError(int errorCode,
                            @NonNull CharSequence errString) {
                        AuthenticationCallback cb = currentCallback;
                        if (cb != null) {
                            if (errorCode == BiometricPrompt.ERROR_USER_CANCELED
                                    || errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON
                                    || errorCode == BiometricPrompt.ERROR_CANCELED) {
                                cb.onAuthenticationCancelled();
                            } else {
                                cb.onAuthenticationFailed(errString.toString());
                            }
                        }
                    }

                    @Override
                    public void onAuthenticationFailed() {
                        // Finger not recognised — prompt stays open.
                    }
                });
    }

    /**
     * Shows a biometric prompt for TEE-gated platform key operations (timeout-based key).
     * No CryptoObject — the TEE auth window opens on success.
     */
    public void authenticate(
            @NonNull String title,
            @NonNull String subtitle,
            @NonNull AuthenticationCallback callback) {

        this.currentCallback = callback;

        BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setSubtitle(subtitle)
                .setNegativeButtonText("Cancel")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .build();

        biometricPrompt.authenticate(promptInfo);
    }

    /** Convenience overload for credential issuance. */
    public void authenticateForIssuance(@NonNull AuthenticationCallback callback) {
        authenticate("Authenticate to Issue Credential",
                "Verify your identity to receive the credential", callback);
    }

    /** Convenience overload for credential presentation. */
    public void authenticateForPresentation(@NonNull AuthenticationCallback callback) {
        authenticate("Authenticate to Share Credential",
                "Verify your identity to share your credential", callback);
    }
}

// Made with Bob
