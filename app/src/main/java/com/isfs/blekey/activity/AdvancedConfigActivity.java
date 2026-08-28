/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.activity;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.SwitchCompat;

import android.widget.TextView;

import com.google.android.material.textfield.TextInputEditText;
import com.google.android.material.textfield.TextInputLayout;
import com.isfs.blekey.MainActivity;
import com.isfs.blekey.R;
import com.isfs.blekey.data.AppConfig;
import com.isfs.blekey.authenticator.AuthenticatorAPI;
import com.isfs.blekey.hidsvc.HIDForegroundService;
import com.isfs.blekey.util.BiometricAuthHelper;
import com.isfs.blekey.util.KeyUtils;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

/**
 * Activity that lets the operator configure the HKDF domain-separation string
 * used during credential key derivation.
 *
 * <p>Persists to {@code SharedPreferences("HIDServicePrefs", "hkdf_info")}.
 * Changing the value invalidates all previously issued credentials; the UI
 * shows a confirmation dialog before saving.</p>
 *
 * <p><b>Platform-key gate</b>: every operation that reads or writes the
 * encrypted HKDF info, or that deletes/regenerates the platform key, requires
 * a fresh strong-biometric event.  This opens the 30-second Android Keystore
 * auth window so that {@link KeyUtils#getPlatformKey()} (ECDH) and
 * {@link KeyUtils#resetPlatformKey()} succeed without
 * {@code UserNotAuthenticatedException}.</p>
 */
public class AdvancedConfigActivity extends AppCompatActivity {

    private static final String TAG = AdvancedConfigActivity.class.getCanonicalName();
    private static final String PREFS_NAME              = "HIDServicePrefs";
    private static final String PREFS_KEY_HKDF_INFO     = "hkdf_info";
    private static final String PREFS_KEY_AUTO_START    = "auto_start_enabled";
    private static final String PREFS_KEY_CTAP1_COMPAT  = "ctap1_compat_mode";
    private static final String PREFS_KEY_UP_DIALOG_TIMEOUT     = "up_dialog_timeout_ms";
    private static final String PREFS_KEY_UP_BIO_TIMEOUT        = "up_bio_timeout_ms";
    private static final String PREFS_KEY_UP_BACKGROUND_TIMEOUT = "up_background_timeout_ms";

    private static final int UP_TIMEOUT_MIN_MS =  1_000;   //  1 s
    private static final int UP_TIMEOUT_MAX_MS = 45_000;   // 45 s

    private TextInputLayout   hkdfInfoLayout;
    private TextInputEditText hkdfInfoEdit;
    private SwitchCompat      autoStartSwitch;
    private SwitchCompat      ctap1CompatSwitch;
    private TextView          pinRetriesValue;
    private TextView          uvRetriesValue;

    private TextInputLayout   upBackgroundTimeoutLayout;
    private TextInputEditText upBackgroundTimeoutEdit;
    private TextInputLayout   upDialogTimeoutLayout;
    private TextInputEditText upDialogTimeoutEdit;
    private TextInputLayout   upBioTimeoutLayout;
    private TextInputEditText upBioTimeoutEdit;

    /** Biometric helper — requires a FragmentActivity, constructed once. */
    private BiometricAuthHelper biometricHelper;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_advanced_config);

        biometricHelper = new BiometricAuthHelper(this);

        hkdfInfoLayout    = findViewById(R.id.hkdfInfoLayout);
        hkdfInfoEdit      = findViewById(R.id.hkdfInfoEdit);
        autoStartSwitch   = findViewById(R.id.autoStartSwitch);
        ctap1CompatSwitch = findViewById(R.id.ctap1CompatSwitch);

        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);

        // The HKDF field shows the default until the operator taps "Load / Decrypt".
        // Decryption is deferred behind a biometric prompt so the platform key's
        // 30-second auth window is open when ECDH runs.
        hkdfInfoEdit.setText(AppConfig.DEFAULT_INFO);
        hkdfInfoEdit.setHint(R.string.adv_config_hkdf_info_hint);

        // Load and wire auto-start toggle — persists immediately on change
        autoStartSwitch.setChecked(prefs.getBoolean(PREFS_KEY_AUTO_START, true));
        autoStartSwitch.setOnCheckedChangeListener((buttonView, isChecked) -> {
            getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                    .edit()
                    .putBoolean(PREFS_KEY_AUTO_START, isChecked)
                    .apply();
            if (isChecked) {
                com.isfs.blekey.BootReceiver.enableAutoStart(this);
            } else {
                com.isfs.blekey.BootReceiver.disableAutoStart(this);
            }
            Log.d(TAG, "Auto-start set to: " + isChecked);
        });

        // Load and wire CTAP1 compat toggle — persists immediately and applies live
        ctap1CompatSwitch.setChecked(
                prefs.getBoolean(PREFS_KEY_CTAP1_COMPAT, AppConfig.DEFAULT_CTAP1_COMPAT));
        ctap1CompatSwitch.setOnCheckedChangeListener((buttonView, isChecked) -> {
            getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                    .edit()
                    .putBoolean(PREFS_KEY_CTAP1_COMPAT, isChecked)
                    .apply();
            AppConfig current1 = AuthenticatorAPI.getAppConfig();
            AuthenticatorAPI.setAppConfig(new AppConfig(current1.getInfo(), isChecked));
            Log.d(TAG, "CTAP1 compat mode set to: " + isChecked);
        });

        findViewById(R.id.backButton).setOnClickListener(v -> finish());

        findViewById(R.id.homeButton).setOnClickListener(v -> {
            Intent intent = new Intent(this, MainActivity.class);
            intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(intent);
            finish();
        });

        upBackgroundTimeoutLayout = findViewById(R.id.upBackgroundTimeoutLayout);
        upBackgroundTimeoutEdit   = findViewById(R.id.upBackgroundTimeoutEdit);
        upDialogTimeoutLayout     = findViewById(R.id.upDialogTimeoutLayout);
        upDialogTimeoutEdit       = findViewById(R.id.upDialogTimeoutEdit);
        upBioTimeoutLayout        = findViewById(R.id.upBioTimeoutLayout);
        upBioTimeoutEdit          = findViewById(R.id.upBioTimeoutEdit);

        int backgroundMs = prefs.getInt(PREFS_KEY_UP_BACKGROUND_TIMEOUT,
                HIDForegroundService.UP_BACKGROUND_TIMEOUT_MS);
        int dialogMs     = prefs.getInt(PREFS_KEY_UP_DIALOG_TIMEOUT,
                HIDForegroundService.UP_DIALOG_TIMEOUT_MS);
        int bioMs        = prefs.getInt(PREFS_KEY_UP_BIO_TIMEOUT,
                HIDForegroundService.UP_BIO_TIMEOUT_MS);
        upBackgroundTimeoutEdit.setText(String.valueOf(backgroundMs));
        upDialogTimeoutEdit.setText(String.valueOf(dialogMs));
        upBioTimeoutEdit.setText(String.valueOf(bioMs));

        // "Load encrypted HKDF value" — bio required to open the platform key.
        findViewById(R.id.loadHkdfButton).setOnClickListener(v -> onLoadHkdfClicked());

        findViewById(R.id.saveConfigButton).setOnClickListener(v -> onSaveClicked());

        findViewById(R.id.resetPlatformKeyButton).setOnClickListener(v -> onResetPlatformKeyClicked());

        pinRetriesValue = findViewById(R.id.pinRetriesValue);
        uvRetriesValue  = findViewById(R.id.uvRetriesValue);
        refreshPinRetriesDisplay();
        findViewById(R.id.resetPinRetriesButton).setOnClickListener(v -> onResetPinRetriesClicked());
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshPinRetriesDisplay();
    }

    // -------------------------------------------------------------------------
    // Load (decrypt) HKDF info — bio gate
    // -------------------------------------------------------------------------

    /**
     * Shows a biometric prompt, then decrypts and populates the HKDF info field.
     * The bio event opens the 30-second Android Keystore auth window so that
     * {@link KeyUtils#getPlatformKey()} succeeds inside {@link #doLoadDecryptedInfo}.
     */
    private void onLoadHkdfClicked() {
        biometricHelper.authenticate(
            getString(R.string.bio_prompt_title),
            getString(R.string.adv_config_bio_subtitle_load),
            new BiometricAuthHelper.AuthenticationCallback() {
                @Override
                public void onAuthenticationSucceeded(
                        androidx.biometric.BiometricPrompt.AuthenticationResult result) {
                    runOnUiThread(() -> doLoadDecryptedInfo());
                }
                @Override
                public void onAuthenticationFailed(String errorMessage) {
                    runOnUiThread(() -> Toast.makeText(AdvancedConfigActivity.this,
                            R.string.authentication_required, Toast.LENGTH_LONG).show());
                }
                @Override
                public void onAuthenticationCancelled() {
                    runOnUiThread(() -> Toast.makeText(AdvancedConfigActivity.this,
                            getString(R.string.cancel), Toast.LENGTH_SHORT).show());
                }
            });
    }

    /**
     * Decrypts and populates the HKDF info field.
     * Must be called while the Android Keystore auth window is open (i.e. within
     * 30 seconds of a successful {@link BiometricAuthHelper#authenticate} call).
     */
    private void doLoadDecryptedInfo() {
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        String stored = prefs.getString(PREFS_KEY_HKDF_INFO, null);
        if (stored == null) {
            hkdfInfoEdit.setText(AppConfig.DEFAULT_INFO);
            return;
        }
        try {
            PrivateKey platformKey = KeyUtils.getPlatformKey();
            if (platformKey == null) {
                Log.e(TAG, "Platform key unavailable; cannot decrypt HKDF info");
                hkdfInfoEdit.setText(AppConfig.DEFAULT_INFO);
                return;
            }
            byte[] ciphertext = Base64.decode(stored, Base64.NO_WRAP);
            byte[] plaintext  = KeyUtils.ecdhDecrypt(ciphertext, platformKey);
            hkdfInfoEdit.setText(new String(plaintext, StandardCharsets.UTF_8));
        } catch (Exception e) {
            Log.e(TAG, "Failed to decrypt HKDF info", e);
            Toast.makeText(this, R.string.adv_config_decrypt_failed, Toast.LENGTH_LONG).show();
            hkdfInfoEdit.setText(AppConfig.DEFAULT_INFO);
        }
    }

    // -------------------------------------------------------------------------
    // Save
    // -------------------------------------------------------------------------

    private void onSaveClicked() {
        // --- HKDF validation ---
        String value = hkdfInfoEdit.getText() != null
                ? hkdfInfoEdit.getText().toString().trim()
                : "";
        if (value.length() < AppConfig.MIN_INFO_LENGTH) {
            hkdfInfoLayout.setError(getString(
                    R.string.adv_config_hkdf_info_too_short, AppConfig.MIN_INFO_LENGTH));
            return;
        }
        hkdfInfoLayout.setError(null);

        // --- timeout validation ---
        Integer backgroundMs = parseTimeout(upBackgroundTimeoutEdit, upBackgroundTimeoutLayout,
                R.string.adv_config_up_timeout_invalid);
        Integer dialogMs     = parseTimeout(upDialogTimeoutEdit, upDialogTimeoutLayout,
                R.string.adv_config_up_timeout_invalid);
        Integer bioMs        = parseTimeout(upBioTimeoutEdit, upBioTimeoutLayout,
                R.string.adv_config_up_timeout_invalid);
        if (backgroundMs == null || dialogMs == null || bioMs == null) return;

        // Persist timeouts immediately (non-destructive, no platform key needed)
        getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .putInt(PREFS_KEY_UP_BACKGROUND_TIMEOUT, backgroundMs)
                .putInt(PREFS_KEY_UP_DIALOG_TIMEOUT,     dialogMs)
                .putInt(PREFS_KEY_UP_BIO_TIMEOUT,        bioMs)
                .apply();

        // HKDF info change is destructive — confirm, then bio-gate the crypto.
        final String valueFinal = value;
        new AlertDialog.Builder(this)
                .setTitle(R.string.adv_config_save_confirm_title)
                .setMessage(R.string.adv_config_save_confirm_message)
                .setPositiveButton(R.string.ok, (dialog, which) ->
                        authenticateThenPersist(valueFinal))
                .setNegativeButton(R.string.cancel, null)
                .show();
    }

    /**
     * Bio gate before re-encrypting and writing the HKDF info.
     * Opens the Android Keystore auth window so {@link KeyUtils#getPlatformKey()} (ECDH) succeeds.
     */
    private void authenticateThenPersist(String value) {
        biometricHelper.authenticate(
            getString(R.string.bio_prompt_title),
            getString(R.string.adv_config_bio_subtitle_save),
            new BiometricAuthHelper.AuthenticationCallback() {
                @Override
                public void onAuthenticationSucceeded(
                        androidx.biometric.BiometricPrompt.AuthenticationResult result) {
                    runOnUiThread(() -> persistAndApply(value));
                }
                @Override
                public void onAuthenticationFailed(String errorMessage) {
                    runOnUiThread(() -> Toast.makeText(AdvancedConfigActivity.this,
                            R.string.authentication_required, Toast.LENGTH_LONG).show());
                }
                @Override
                public void onAuthenticationCancelled() {
                    runOnUiThread(() -> Toast.makeText(AdvancedConfigActivity.this,
                            getString(R.string.cancel), Toast.LENGTH_SHORT).show());
                }
            });
    }

    /**
     * Parses an integer ms value from {@code edit}, validates it is within
     * [{@link #UP_TIMEOUT_MIN_MS}, {@link #UP_TIMEOUT_MAX_MS}], sets an inline error
     * on {@code layout} if invalid, and returns {@code null} on failure.
     */
    private Integer parseTimeout(TextInputEditText edit, TextInputLayout layout, int errorResId) {
        String raw = edit.getText() != null ? edit.getText().toString().trim() : "";
        try {
            int ms = Integer.parseInt(raw);
            if (ms < UP_TIMEOUT_MIN_MS || ms > UP_TIMEOUT_MAX_MS) throw new NumberFormatException();
            layout.setError(null);
            return ms;
        } catch (NumberFormatException e) {
            layout.setError(getString(errorResId, UP_TIMEOUT_MIN_MS, UP_TIMEOUT_MAX_MS));
            return null;
        }
    }

    /**
     * Encrypts {@code value} with the platform public key (ECDH/AES-GCM) and stores the
     * Base64-encoded ciphertext in SharedPreferences, then applies the config live.
     *
     * <p>Must be called while the Android Keystore auth window is open (within 30 seconds
     * of a successful biometric).</p>
     */
    private void persistAndApply(String value) {
        try {
            PrivateKey platformPrivKey = KeyUtils.getPlatformKey();
            if (!(platformPrivKey instanceof ECPrivateKey)) {
                Log.e(TAG, "Platform key missing or not EC; cannot encrypt HKDF info");
                return;
            }
            ECPublicKey platformPubKey =
                    KeyUtils.getPubKey((ECPrivateKey) platformPrivKey);
            byte[] ciphertext = KeyUtils.ecdhEncrypt(
                    value.getBytes(StandardCharsets.UTF_8), platformPubKey);
            String encoded = Base64.encodeToString(ciphertext, Base64.NO_WRAP);

            getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                    .edit()
                    .putString(PREFS_KEY_HKDF_INFO, encoded)
                    .apply();
        } catch (Exception e) {
            Log.e(TAG, "Failed to encrypt HKDF info; not saved", e);
            return;
        }
        AuthenticatorAPI.setAppConfig(new AppConfig(value));
        Log.d(TAG, "HKDF info updated: length=" + value.length());
        finish();
    }

    // -------------------------------------------------------------------------
    // PIN retries
    // -------------------------------------------------------------------------

    private void refreshPinRetriesDisplay() {
        pinRetriesValue.setText(getString(R.string.adv_config_pin_retries_value,
                AuthenticatorAPI.getPinRetries(), AuthenticatorAPI.getMaxPinRetries()));
        uvRetriesValue.setText(getString(R.string.adv_config_uv_retries_value,
                AuthenticatorAPI.getUvRetries(), AuthenticatorAPI.getMaxUvRetries()));
    }

    private void onResetPinRetriesClicked() {
        new AlertDialog.Builder(this)
                .setTitle(R.string.adv_config_pin_retries_reset_confirm_title)
                .setMessage(getString(
                        R.string.adv_config_pin_retries_reset_confirm_message,
                        AuthenticatorAPI.getMaxPinRetries()))
                .setPositiveButton(R.string.ok, (dialog, which) -> {
                    AuthenticatorAPI.resetPinRetries();
                    refreshPinRetriesDisplay();
                    Toast.makeText(this,
                            R.string.adv_config_pin_retries_reset_success,
                            Toast.LENGTH_SHORT).show();
                    Log.i(TAG, "PIN retry counter reset by operator");
                })
                .setNegativeButton(R.string.cancel, null)
                .show();
    }

    // -------------------------------------------------------------------------
    // Platform key reset — bio gate before deletion + re-generation
    // -------------------------------------------------------------------------

    private void onResetPlatformKeyClicked() {
        new AlertDialog.Builder(this)
                .setTitle(R.string.adv_config_reset_confirm_title)
                .setMessage(R.string.adv_config_reset_confirm_message)
                .setPositiveButton(R.string.ok, (dialog, which) ->
                        authenticateThenResetPlatformKey())
                .setNegativeButton(R.string.cancel, null)
                .show();
    }

    /**
     * Bio gate before resetting the platform key.  The biometric opens the auth window
     * so that {@link KeyUtils#resetPlatformKey()} can access/delete the existing key
     * without {@code UserNotAuthenticatedException}.
     */
    private void authenticateThenResetPlatformKey() {
        biometricHelper.authenticate(
            getString(R.string.bio_prompt_title),
            getString(R.string.adv_config_bio_subtitle_reset),
            new BiometricAuthHelper.AuthenticationCallback() {
                @Override
                public void onAuthenticationSucceeded(
                        androidx.biometric.BiometricPrompt.AuthenticationResult result) {
                    runOnUiThread(() -> performPlatformKeyReset());
                }
                @Override
                public void onAuthenticationFailed(String errorMessage) {
                    runOnUiThread(() -> Toast.makeText(AdvancedConfigActivity.this,
                            R.string.authentication_required, Toast.LENGTH_LONG).show());
                }
                @Override
                public void onAuthenticationCancelled() {
                    runOnUiThread(() -> Toast.makeText(AdvancedConfigActivity.this,
                            getString(R.string.cancel), Toast.LENGTH_SHORT).show());
                }
            });
    }

    /**
     * Performs the actual platform key deletion and regeneration.
     * Must be called while the Android Keystore auth window is open.
     */
    private void performPlatformKeyReset() {
        try {
            KeyUtils.resetPlatformKey();

            // The HKDF info pref was encrypted under the old key — remove it so
            // the service falls back cleanly to AppConfig.DEFAULT_INFO on next
            // start rather than logging a decrypt error.
            getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                    .edit()
                    .remove(PREFS_KEY_HKDF_INFO)
                    .apply();

            // Reflect the cleared pref in the UI immediately.
            hkdfInfoEdit.setText(AppConfig.DEFAULT_INFO);

            Toast.makeText(this, R.string.adv_config_reset_success, Toast.LENGTH_LONG).show();
            Log.i(TAG, "Platform key reset successfully");
        } catch (Exception e) {
            Log.e(TAG, "Platform key reset failed", e);
            Toast.makeText(this,
                    getString(R.string.adv_config_reset_failed, e.getMessage()),
                    Toast.LENGTH_LONG).show();
        }
    }
}
