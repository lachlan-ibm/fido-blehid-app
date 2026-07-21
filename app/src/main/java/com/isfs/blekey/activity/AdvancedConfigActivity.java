/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.activity;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.SwitchCompat;

import com.google.android.material.textfield.TextInputEditText;
import com.google.android.material.textfield.TextInputLayout;
import com.isfs.blekey.R;
import com.isfs.blekey.data.AppConfig;
import com.isfs.blekey.authenticator.AuthenticatorAPI;
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
 * shows a confirmation dialog before saving.
 */
public class AdvancedConfigActivity extends AppCompatActivity {

    private static final String TAG = AdvancedConfigActivity.class.getCanonicalName();
    private static final String PREFS_NAME = "HIDServicePrefs";
    private static final String PREFS_KEY_HKDF_INFO = "hkdf_info";
    private static final String PREFS_KEY_AUTO_START = "auto_start_enabled";

    private TextInputLayout hkdfInfoLayout;
    private TextInputEditText hkdfInfoEdit;
    private SwitchCompat autoStartSwitch;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_advanced_config);

        hkdfInfoLayout  = findViewById(R.id.hkdfInfoLayout);
        hkdfInfoEdit    = findViewById(R.id.hkdfInfoEdit);
        autoStartSwitch = findViewById(R.id.autoStartSwitch);

        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);

        // Load and decrypt HKDF info
        String current = loadDecryptedInfo(prefs);
        hkdfInfoEdit.setText(current);

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

        findViewById(R.id.backButton).setOnClickListener(v -> finish());

        findViewById(R.id.saveConfigButton).setOnClickListener(v -> onSaveClicked());
    }

    private void onSaveClicked() {
        String value = hkdfInfoEdit.getText() != null
                ? hkdfInfoEdit.getText().toString().trim()
                : "";

        if (value.length() < AppConfig.MIN_INFO_LENGTH) {
            hkdfInfoLayout.setError(getString(
                    R.string.adv_config_hkdf_info_too_short, AppConfig.MIN_INFO_LENGTH));
            return;
        }
        hkdfInfoLayout.setError(null);

        new AlertDialog.Builder(this)
                .setTitle(R.string.adv_config_save_confirm_title)
                .setMessage(R.string.adv_config_save_confirm_message)
                .setPositiveButton(R.string.ok, (dialog, which) -> persistAndApply(value))
                .setNegativeButton(R.string.cancel, null)
                .show();
    }

    /**
     * Loads and decrypts the HKDF info string from SharedPreferences.
     *
     * <p>The stored value is ECDH-encrypted with the platform key and Base64-encoded.
     * Falls back to {@link AppConfig#DEFAULT_INFO} if no encrypted value is stored or
     * decryption fails.
     */
    private String loadDecryptedInfo(SharedPreferences prefs) {
        String stored = prefs.getString(PREFS_KEY_HKDF_INFO, null);
        if (stored == null) {
            return AppConfig.DEFAULT_INFO;
        }
        try {
            PrivateKey platformKey = KeyUtils.getPlatformKey();
            if (platformKey == null) {
                Log.e(TAG, "Platform key unavailable; cannot decrypt HKDF info");
                return AppConfig.DEFAULT_INFO;
            }
            byte[] ciphertext = Base64.decode(stored, Base64.NO_WRAP);
            byte[] plaintext = KeyUtils.ecdhDecrypt(ciphertext, platformKey);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (Exception e) {
            Log.e(TAG, "Failed to decrypt HKDF info", e);
            return AppConfig.DEFAULT_INFO;
        }
    }

    /**
     * Encrypts {@code value} with the platform public key (ECDH/AES-GCM) and stores the
     * Base64-encoded ciphertext in SharedPreferences, then applies the config live.
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
}
