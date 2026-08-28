/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.activity;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.isfs.blekey.R;
import com.isfs.blekey.authenticator.implapi.pin.PinSessionRegistry;
import com.isfs.blekey.ctap.CtapTxn;
import com.isfs.blekey.data.Passkey;
import com.isfs.blekey.hidsvc.HIDForegroundService;
import com.isfs.blekey.util.KeyUtils;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * PIN-entry Activity for the {@code getPinUvAuthTokenUsingUvWithPermissions} (0x06) ceremony.
 *
 * <p>Shown when {@link HIDForegroundService}'s UP handler receives a
 * {@link com.isfs.blekey.authenticator.UpUvRequestCtx.CeremonyType#GET_TKN_UV} context.
 * The user enters their PIN; we hash it with SHA-256 via {@link KeyUtils#getPinHash},
 * open the {@link Passkey} locally, store it on the pending transaction, and call
 * {@link HIDForegroundService#deliverUpApproved()} to complete the chain.
 * Cancel or wrong-PIN paths call {@link HIDForegroundService#deliverUpDenied()}.</p>
 */
public class UvPinEntryActivity extends AppCompatActivity {

    private static final String TAG = UvPinEntryActivity.class.getSimpleName();

    private EditText  pinInput;
    private TextView  errorText;
    private Button    submitButton;

    private HIDForegroundService hidService;
    private boolean              bound = false;

    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    private final ServiceConnection connection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            hidService = ((HIDForegroundService.LocalBinder) service).getService();
            bound = true;
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            hidService = null;
            bound = false;
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_uv_pin_entry);

        pinInput    = findViewById(R.id.uvPinInput);
        errorText   = findViewById(R.id.uvPinErrorText);
        submitButton = findViewById(R.id.uvPinSubmitButton);

        submitButton.setOnClickListener(v -> onSubmit());
        findViewById(R.id.uvPinCancelButton).setOnClickListener(v -> onCancel());

        Intent svcIntent = new Intent(this, HIDForegroundService.class);
        bindService(svcIntent, connection, Context.BIND_AUTO_CREATE);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (bound) {
            unbindService(connection);
            bound = false;
        }
        executor.shutdown();
    }

    private void onCancel() {
        if (bound && hidService != null) {
            hidService.deliverUpDenied();
        }
        finish();
    }

    private void onSubmit() {
        Log.d(TAG, "UvPinEntryActivity.onSubmit com.isfs.blekey");
        String pin = pinInput.getText().toString();
        if (pin.isEmpty()) {
            showError(getString(R.string.require_password));
            return;
        }

        submitButton.setEnabled(false);
        errorText.setVisibility(View.GONE);

        executor.execute(() -> {
            byte[] pinHash = KeyUtils.getPinHash(pin);
            byte[] lph = new byte[16];
            System.arraycopy(pinHash, 0, lph, 0, 16);
            Passkey passkey = Passkey.openKey(lph);
            Log.d(TAG, String.format("com.isfs.blekey openKey result: %s", 
                    passkey != null ? passkey.getFileName() : "null"));

            runOnUiThread(() -> {
                submitButton.setEnabled(true);
                if (passkey == null) {
                    int remaining = PinSessionRegistry.decrementUvRetries();
                    if (remaining == 0) {
                        showError(getString(R.string.uv_pin_blocked));
                        if (bound && hidService != null) hidService.deliverUpDenied();
                        finish();
                    } else {
                        showError(getString(R.string.incorrect_password));
                        pinInput.setText("");
                    }
                } else {
                    // Store the opened passkey and its hash on the pending txn so that
                    // PinFlowHandler.generateUvToken() can read them via txn.getPasskey()
                    // and txn.getPinHash() when the chain action fires.
                    if (bound && hidService != null) {
                        CtapTxn txn = hidService.getPendingUpTxn();
                        if (txn != null) {
                            txn.setPasskey(passkey);
                            txn.setPinHash(lph);
                        }
                        hidService.deliverUpApproved();
                    }
                    finish();
                }
            });
        });
    }

    private void showError(String message) {
        errorText.setText(message);
        errorText.setVisibility(View.VISIBLE);
    }
}
