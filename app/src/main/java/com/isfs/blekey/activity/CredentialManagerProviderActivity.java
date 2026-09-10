/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.activity;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.view.WindowCompat;
import androidx.credentials.CreatePublicKeyCredentialResponse;
import androidx.credentials.GetCredentialResponse;
import androidx.credentials.PublicKeyCredential;
import androidx.credentials.CreatePublicKeyCredentialRequest;
import androidx.credentials.GetPublicKeyCredentialOption;
import androidx.credentials.provider.PendingIntentHandler;
import androidx.credentials.provider.ProviderCreateCredentialRequest;
import androidx.credentials.provider.ProviderGetCredentialRequest;

import com.isfs.blekey.R;
import com.isfs.blekey.authenticator.implapi.CredentialManagerAuthenticator;
import com.isfs.blekey.credentials.DigitalCredentialProviderService;
import com.isfs.blekey.data.Passkey;
import com.isfs.blekey.util.BiometricAuthHelper;
import com.isfs.blekey.util.InsetsHelper;
import com.isfs.blekey.util.KeyUtils;

import org.json.JSONObject;

import java.io.File;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Handles the selection-phase {@link android.app.PendingIntent} for the passkey
 * Credential Provider.
 *
 * <p>Both the GET (assertion) and CREATE (make-credential) flows land here.
 * The activity reads the flow type and wallet file name from the intent extras set by
 * {@link DigitalCredentialProviderService}, shows a PIN prompt, decrypts the wallet,
 * calls the appropriate {@link Fido2Authenticator} method, and reports the result back
 * to Credential Manager via {@link PendingIntentHandler}.</p>
 */
public class CredentialManagerProviderActivity extends AppCompatActivity {

    private static final String TAG = CredentialManagerProviderActivity.class.getName();

    private EditText   pinInput;
    private TextView   errorText;
    private TextView   rpIdLabel;
    private Button     submitButton;
    private Button     cancelButton;
    private ProgressBar progressBar;

    private String flowType;
    private String walletFileName;
    private String requestJson;

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private BiometricAuthHelper biometricAuthHelper;

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        WindowCompat.setDecorFitsSystemWindows(getWindow(), false);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_credential_manager_provider);
        InsetsHelper.applyBottomInset(findViewById(android.R.id.content));

        pinInput     = findViewById(R.id.cmpPinInput);
        errorText    = findViewById(R.id.cmpErrorText);
        rpIdLabel    = findViewById(R.id.cmpRpIdLabel);
        submitButton = findViewById(R.id.cmpSubmitButton);
        cancelButton = findViewById(R.id.cmpCancelButton);
        progressBar  = findViewById(R.id.cmpProgressBar);

        biometricAuthHelper = new BiometricAuthHelper(this);

        submitButton.setOnClickListener(v -> onSubmit());
        cancelButton.setOnClickListener(v -> onCancel());

        // Ensure FIDO2_HOME is set — this activity may start before MainActivity.
        String fido2Home = System.getProperty("FIDO2_HOME");
        if (fido2Home == null || fido2Home.isEmpty()) {
            System.setProperty("FIDO2_HOME", getFilesDir().getAbsolutePath());
        }

        // Read intent extras.
        flowType       = getIntent().getStringExtra(DigitalCredentialProviderService.EXTRA_FLOW_TYPE);
        walletFileName = getIntent().getStringExtra(DigitalCredentialProviderService.EXTRA_WALLET_FILE);

        if (flowType == null || walletFileName == null) {
            Log.d(TAG, "Missing intent extras — finishing");
            setResult(RESULT_CANCELED);
            finish();
            return;
        }

        // Extract and display the RP ID from the Credential Manager request.
        requestJson = extractRequestJson();
        Log.d(TAG, "onCreate: flowType=" + flowType
                + " requestJson=" + (requestJson == null ? "NULL" : requestJson.substring(0, Math.min(200, requestJson.length()))));
        String rpId = parseRpId(requestJson, flowType);
        if (rpId != null && !rpId.isEmpty()) {
            rpIdLabel.setText("Signing into: " + rpId);
            rpIdLabel.setVisibility(View.VISIBLE);
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        executor.shutdown();
    }

    // -------------------------------------------------------------------------
    // UI actions
    // -------------------------------------------------------------------------

    private void onCancel() {
        setResult(RESULT_CANCELED);
        finish();
    }

    private void onSubmit() {
        String pin = pinInput.getText().toString();
        if (pin.isEmpty()) {
            showError(getString(R.string.require_password));
            return;
        }

        submitButton.setEnabled(false);
        errorText.setVisibility(View.GONE);
        progressBar.setVisibility(View.VISIBLE);

        // Gate on biometric first so the TEE auth window is open before the
        // background thread calls KeyUtils.getStashCipher() — mirrors ManageActivity.
        biometricAuthHelper.authenticate(
                getString(R.string.bio_prompt_title),
                getString(R.string.bio_prompt_subtitle),
                new BiometricAuthHelper.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationSucceeded(
                            androidx.biometric.BiometricPrompt.AuthenticationResult result) {
                        executor.execute(() -> doSubmit(pin));
                    }

                    @Override
                    public void onAuthenticationFailed(String errorMessage) {
                        runOnUiThread(() -> {
                            submitButton.setEnabled(true);
                            progressBar.setVisibility(View.GONE);
                            showError(errorMessage);
                        });
                    }

                    @Override
                    public void onAuthenticationCancelled() {
                        runOnUiThread(() -> {
                            submitButton.setEnabled(true);
                            progressBar.setVisibility(View.GONE);
                        });
                    }
                });
    }

    // -------------------------------------------------------------------------
    // Background work
    // -------------------------------------------------------------------------

    private void doSubmit(String pin) {
        try {
            byte[] pinHash = KeyUtils.getPinHash(pin);
            byte[] lph = Arrays.copyOf(pinHash, 16);

            File walletFile = new File(getFilesDir(), walletFileName);
            Passkey passkey = Passkey.openKey(lph, walletFile);

            if (passkey == null) {
                runOnUiThread(() -> {
                    submitButton.setEnabled(true);
                    progressBar.setVisibility(View.GONE);
                    showError(getString(R.string.incorrect_password));
                    pinInput.setText("");
                });
                return;
            }

            Intent result = new Intent();

            if (DigitalCredentialProviderService.FLOW_GET.equals(flowType)) {
                String assertionJson = CredentialManagerAuthenticator.getAssertion(requestJson, passkey);
                Log.d(TAG, "doSubmit GET: assertionJson=" + assertionJson);
                PublicKeyCredential credential = new PublicKeyCredential(assertionJson);
                Log.d(TAG, "doSubmit GET: PublicKeyCredential created, calling setGetCredentialResponse");
                PendingIntentHandler.setGetCredentialResponse(
                        result, new GetCredentialResponse(credential));
                Log.d(TAG, "doSubmit GET: setGetCredentialResponse complete");

            } else { // FLOW_CREATE
                String attestationJson = CredentialManagerAuthenticator.makeCredential(
                        requestJson, passkey, lph, new File(getFilesDir(), walletFileName));
                Log.d(TAG, "doSubmit CREATE: attestationJson=" + attestationJson);
                PendingIntentHandler.setCreateCredentialResponse(
                        result, new CreatePublicKeyCredentialResponse(attestationJson));
            }

            setResult(RESULT_OK, result);
            finish();

        } catch (Exception e) {
            Log.d(TAG, "doSubmit failed", e);
            runOnUiThread(() -> {
                submitButton.setEnabled(true);
                progressBar.setVisibility(View.GONE);
                showError("Operation failed: " + e.getMessage());
            });
        }
    }

    /**
     * Pull the WebAuthn JSON request from the Credential Manager intent.
     *
     * <p>For GET: the entry is a {@code PublicKeyCredentialEntry}, so the intent carries a
     * {@link ProviderGetCredentialRequest}. Extract the first
     * {@link GetPublicKeyCredentialOption} from it.</p>
     * <p>For CREATE: the intent carries a {@link ProviderCreateCredentialRequest}.</p>
     */
    private String extractRequestJson() {
        if (DigitalCredentialProviderService.FLOW_GET.equals(flowType)) {
            ProviderGetCredentialRequest req =
                    PendingIntentHandler.retrieveProviderGetCredentialRequest(getIntent());
            Log.d(TAG, "extractRequestJson: retrieveProviderGetCredentialRequest=" + req);
            if (req != null) {
                for (androidx.credentials.CredentialOption opt : req.getCredentialOptions()) {
                    Log.d(TAG, "extractRequestJson: option type=" + opt.getClass().getSimpleName());
                    if (opt instanceof GetPublicKeyCredentialOption) {
                        return ((GetPublicKeyCredentialOption) opt).getRequestJson();
                    }
                }
            }
        } else {
            ProviderCreateCredentialRequest req =
                    PendingIntentHandler.retrieveProviderCreateCredentialRequest(getIntent());
            if (req != null
                    && req.getCallingRequest() instanceof CreatePublicKeyCredentialRequest) {
                return ((CreatePublicKeyCredentialRequest) req.getCallingRequest()).getRequestJson();
            }
        }
        return null;
    }

    /** Parse the RP ID from the WebAuthn JSON for display purposes. */
    private static String parseRpId(String json, String flowType) {
        if (json == null) return null;
        try {
            JSONObject obj = new JSONObject(json);
            if (DigitalCredentialProviderService.FLOW_CREATE.equals(flowType)) {
                // publicKey.rp.id
                return obj.optJSONObject("rp") != null
                        ? obj.optJSONObject("rp").optString("id", null)
                        : null;
            } else {
                return obj.optString("rpId", null);
            }
        } catch (Exception e) {
            Log.w(TAG, "parseRpId failed", e);
            return null;
        }
    }

    private void showError(String message) {
        errorText.setText(message);
        errorText.setVisibility(View.VISIBLE);
    }
}
