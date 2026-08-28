package com.isfs.blekey.activity;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.isfs.blekey.R;
import com.isfs.blekey.credential.VerifiableCredential;
import com.isfs.blekey.data.Passkey;
import com.isfs.blekey.oidc.CredentialOffer;
import com.isfs.blekey.oidc.IssuerMetadata;
import com.isfs.blekey.oidc.Oidc4VciClient;
import com.isfs.blekey.oidc.OidcException;
import com.isfs.blekey.util.AndroidHolderBindingKeyManager;
import com.isfs.blekey.util.BiometricAuthHelper;

import java.io.File;
import java.security.PrivateKey;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Activity for handling credential issuance flow.
 * Displays credential offer details and manages the issuance process.
 */
public class CredentialIssuanceActivity extends AppCompatActivity {
    
    private static final String TAG = CredentialIssuanceActivity.class.getCanonicalName();
    
    private TextView issuerNameText;
    private TextView issuerTrustText;
    private TextView credentialTypeText;
    private TextView credentialFormatText;
    private TextView credentialContextText;
    private TextView credentialTypesText;
    private TextView credentialClaimsText;
    private TextView validityPeriodText;
    private TextView expirationText;
    private Button acceptButton;
    private Button declineButton;
    private ProgressBar progressBar;
    private View contentLayout;
    
    private String credentialOfferUri;
    private CredentialOffer credentialOffer;
    private IssuerMetadata issuerMetadata;
    private byte[] passwordHash;
    private String passkeyFileName;
    private long receivedAtMillis;
    
    private final ExecutorService executorService = Executors.newSingleThreadExecutor();
    private android.os.Handler uiHandler;
    private Runnable expirationCheckRunnable;
    private BiometricAuthHelper biometricAuthHelper;
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_credential_issuance);
        
        initializeFido2Home();
        
        biometricAuthHelper = new BiometricAuthHelper(this);
        
        findViewById(R.id.backButton).setOnClickListener(view -> {
            setResult(RESULT_CANCELED);
            finish();
        });
        
        // Set up home button to navigate to MainActivity
        findViewById(R.id.homeButton).setOnClickListener(view -> {
            Intent intent = new Intent(this, com.isfs.blekey.MainActivity.class);
            intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(intent);
            finish();
        });
        
        initializeViews();
        
        uiHandler = new android.os.Handler(getMainLooper());
        
        Intent intent = getIntent();
        if (intent != null) {
            credentialOfferUri = intent.getStringExtra("credential_offer_uri");
            passwordHash = intent.getByteArrayExtra("passkey");
            passkeyFileName = intent.getStringExtra("file");
            receivedAtMillis = intent.getLongExtra("received_at_millis", System.currentTimeMillis());
            
            Log.d(TAG, "Received timestamp from intent: " + receivedAtMillis);
            Log.d(TAG, "Current time: " + System.currentTimeMillis());
            Log.d(TAG, "Time difference: " + (System.currentTimeMillis() - receivedAtMillis) + "ms");
        }
        
        if (credentialOfferUri != null) {
            fetchCredentialOffer();
        } else {
            showError("No credential offer provided");
        }
    }
    
    private void initializeFido2Home() {
        File appDataDir = getFilesDir();
        System.setProperty("FIDO2_HOME", appDataDir.getAbsolutePath());
    }
    
    private void initializeViews() {
        issuerNameText = findViewById(R.id.issuerName);
        issuerTrustText = findViewById(R.id.issuerTrust);
        credentialTypeText = findViewById(R.id.credentialType);
        credentialFormatText = findViewById(R.id.credentialFormat);
        credentialContextText = findViewById(R.id.credentialContext);
        credentialTypesText = findViewById(R.id.credentialTypes);
        credentialClaimsText = findViewById(R.id.credentialClaims);
        validityPeriodText = findViewById(R.id.validityPeriod);
        expirationText = findViewById(R.id.expirationText);
        acceptButton = findViewById(R.id.acceptButton);
        declineButton = findViewById(R.id.declineButton);
        progressBar = findViewById(R.id.progressBar);
        contentLayout = findViewById(R.id.contentLayout);
        acceptButton.setOnClickListener(v -> acceptCredentialOffer());
        declineButton.setOnClickListener(v -> declineCredentialOffer());
    }
    
    private void fetchCredentialOffer() {
        showProgress(true);
        
        executorService.execute(() -> {
            try {
                // Parse the offer preserving the original received timestamp
                java.net.URI parsedUri = java.net.URI.create(credentialOfferUri);
                String query = parsedUri.getQuery();
                if (query == null || query.isEmpty()) {
                    throw new OidcException("Credential offer URI must contain query parameters");
                }
                
                java.util.Map<String, String> params = parseQueryString(query);
                String offerJson = params.get("credential_offer");
                if (offerJson == null) {
                    throw new OidcException("Credential offer URI must contain credential_offer parameter");
                }
                
                @SuppressWarnings("unchecked")
                java.util.Map<String, Object> offerMap = (java.util.Map<String, Object>)
                    com.isfs.blekey.util.JsonUtils.decode(offerJson, java.util.Map.class);
                
                // Create CredentialOffer with the original received timestamp
                credentialOffer = new CredentialOffer(offerMap, receivedAtMillis);
                
                Log.d(TAG, "Created CredentialOffer with receivedAtMillis: " + receivedAtMillis);
                Log.d(TAG, "Offer expiresIn: " + credentialOffer.getExpiresIn() + "s");
                Log.d(TAG, "Offer expiration time: " + credentialOffer.getExpirationTimeMillis());
                Log.d(TAG, "Offer remaining seconds: " + credentialOffer.getRemainingSeconds());
                Log.d(TAG, "Offer is expired: " + credentialOffer.isExpired());
                
                // Check if offer has already expired
                if (credentialOffer.isExpired()) {
                    Log.i(TAG, "Credential offer has already expired");
                    runOnUiThread(() -> showError("Credential offer has expired"));
                    return;
                }
                
                issuerMetadata = IssuerMetadata.fetch(credentialOffer.getCredentialIssuer(), new com.isfs.blekey.util.http.HttpClient());
                
                runOnUiThread(this::displayOfferDetails);
            } catch (OidcException e) {
                Log.e(TAG, "Failed to fetch credential offer", e);
                runOnUiThread(() -> showError("Failed to fetch credential offer: " + e.getMessage()));
            } catch (Exception e) {
                Log.e(TAG, "Failed to fetch issuer metadata", e);
                runOnUiThread(() -> showError("Failed to fetch issuer metadata: " + e.getMessage()));
            }
        });
    }
    
    private void displayOfferDetails() {
        showProgress(false);
        
        // Check if offer is already expired
        if (credentialOffer != null && credentialOffer.isExpired()) {
            showError("Credential offer has expired");
            return;
        }
        
        if (issuerMetadata != null) {
            issuerNameText.setText(issuerMetadata.getCredentialIssuer());
            issuerTrustText.setText("Trusted Issuer");
            issuerTrustText.setTextColor(0xFF4CAF50);
        }
        
        if (credentialOffer != null && !credentialOffer.getCredentials().isEmpty()) {
            String configId = credentialOffer.getCredentials().get(0);
            credentialTypeText.setText("Type: " + configId);
            
            // Detect and display credential format
            com.isfs.blekey.credential.DigitalCredentialFormat format = detectCredentialFormat();
            if (format != null) {
                credentialFormatText.setText("Format: " + format.getDisplayName());
                
                // Show JSON-LD specific fields if applicable
                if (format == com.isfs.blekey.credential.DigitalCredentialFormat.JSON_LD) {
                    displayJsonLdFields();
                } else {
                    // Hide JSON-LD specific fields for other formats
                    credentialContextText.setVisibility(View.GONE);
                    credentialTypesText.setVisibility(View.GONE);
                }
            } else {
                credentialFormatText.setText("Format: SD-JWT-VC (default)");
                credentialContextText.setVisibility(View.GONE);
                credentialTypesText.setVisibility(View.GONE);
            }
            
            credentialClaimsText.setText("Claims: Standard credential claims");
            validityPeriodText.setText("Validity: As specified by issuer");
            
            // Start expiration countdown
            startExpirationCountdown();
        }
    }
    
    /**
     * Detects the credential format from issuer metadata.
     */
    private com.isfs.blekey.credential.DigitalCredentialFormat detectCredentialFormat() {
        if (issuerMetadata == null) {
            return null;
        }
        
        java.util.List<java.util.Map<String, Object>> credentialsSupported =
            issuerMetadata.getCredentialsSupported();
        
        if (credentialsSupported != null && !credentialsSupported.isEmpty()) {
            for (java.util.Map<String, Object> credConfig : credentialsSupported) {
                Object formatObj = credConfig.get("format");
                if (formatObj instanceof String) {
                    String formatStr = (String) formatObj;
                    
                    // Map format strings to enum
                    if ("ldp_vc".equals(formatStr) || "jwt_vc_json-ld".equals(formatStr)) {
                        return com.isfs.blekey.credential.DigitalCredentialFormat.JSON_LD;
                    } else if ("mso_mdoc".equals(formatStr)) {
                        return com.isfs.blekey.credential.DigitalCredentialFormat.ISO_MDOC;
                    } else if ("jwt_vc_json".equals(formatStr) || "vc+sd-jwt".equals(formatStr)) {
                        return com.isfs.blekey.credential.DigitalCredentialFormat.SD_JWT_VC;
                    }
                }
            }
        }
        
        return null;
    }
    
    /**
     * Displays JSON-LD specific fields from issuer metadata.
     */
    private void displayJsonLdFields() {
        if (issuerMetadata == null) {
            return;
        }
        
        java.util.List<java.util.Map<String, Object>> credentialsSupported =
            issuerMetadata.getCredentialsSupported();
        
        if (credentialsSupported != null && !credentialsSupported.isEmpty()) {
            java.util.Map<String, Object> credConfig = credentialsSupported.get(0);
            
            // Display @context
            Object contextObj = credConfig.get("@context");
            if (contextObj instanceof java.util.List) {
                @SuppressWarnings("unchecked")
                java.util.List<String> contexts = (java.util.List<String>) contextObj;
                if (!contexts.isEmpty()) {
                    StringBuilder contextStr = new StringBuilder("@context:\n");
                    for (String ctx : contexts) {
                        contextStr.append("  • ").append(ctx).append("\n");
                    }
                    credentialContextText.setText(contextStr.toString().trim());
                    credentialContextText.setVisibility(View.VISIBLE);
                }
            }
            
            // Display types
            Object credDefObj = credConfig.get("credential_definition");
            if (credDefObj instanceof java.util.Map) {
                @SuppressWarnings("unchecked")
                java.util.Map<String, Object> credDef = (java.util.Map<String, Object>) credDefObj;
                Object typesObj = credDef.get("type");
                if (typesObj instanceof java.util.List) {
                    @SuppressWarnings("unchecked")
                    java.util.List<String> types = (java.util.List<String>) typesObj;
                    if (!types.isEmpty()) {
                        StringBuilder typesStr = new StringBuilder("Types:\n");
                        for (String type : types) {
                            typesStr.append("  • ").append(type).append("\n");
                        }
                        credentialTypesText.setText(typesStr.toString().trim());
                        credentialTypesText.setVisibility(View.VISIBLE);
                    }
                }
            }
        }
    }
    
    /**
     * Starts a countdown timer that updates the expiration display.
     */
    private void startExpirationCountdown() {
        if (credentialOffer == null || expirationText == null) {
            return;
        }
        
        expirationCheckRunnable = new Runnable() {
            @Override
            public void run() {
                if (credentialOffer == null) {
                    return;
                }
                
                if (credentialOffer.isExpired()) {
                    expirationText.setText("Offer expired");
                    expirationText.setTextColor(0xFFFF0000);
                    acceptButton.setEnabled(false);
                    Toast.makeText(CredentialIssuanceActivity.this,
                                 "Credential offer has expired",
                                 Toast.LENGTH_LONG).show();
                    
                    // Set result to indicate expired offer so ManageActivity can clean up
                    Intent resultIntent = new Intent();
                    resultIntent.putExtra("offer_expired", true);
                    setResult(RESULT_CANCELED, resultIntent);
                    
                    uiHandler.postDelayed(() -> finish(), 2000);
                    return;
                }
                
                Long remainingSeconds = credentialOffer.getRemainingSeconds();
                if (remainingSeconds != null) {
                    long minutes = remainingSeconds / 60;
                    long seconds = remainingSeconds % 60;
                    String timeText = String.format("Expires in: %d:%02d", minutes, seconds);
                    expirationText.setText(timeText);
                    
                    // Change color based on remaining time
                    if (remainingSeconds < 60) {
                        expirationText.setTextColor(0xFFFF0000); // Red - less than 1 minute
                    } else if (remainingSeconds < 180) {
                        expirationText.setTextColor(0xFFFF9800); // Orange - less than 3 minutes
                    } else {
                        expirationText.setTextColor(0xFF4CAF50); // Green
                    }
                    
                    // Schedule next update in 1 second
                    uiHandler.postDelayed(this, 1000);
                }
            }
        };
        
        // Start the countdown
        uiHandler.post(expirationCheckRunnable);
    }
    
    /**
     * Stops the expiration countdown timer.
     */
    private void stopExpirationCountdown() {
        if (expirationCheckRunnable != null && uiHandler != null) {
            uiHandler.removeCallbacks(expirationCheckRunnable);
        }
    }
    
    private void acceptCredentialOffer() {
        if (passwordHash == null || passkeyFileName == null) {
            showError("Passkey information not available");
            return;
        }

        // Final expiration check before processing
        if (credentialOffer != null && credentialOffer.isExpired()) {
            showError("Credential offer has expired");
            return;
        }

        stopExpirationCountdown();

        // Must open a CryptoObject-bound biometric prompt so the TEE auth window
        // is open when processCredentialOffer() calls into Passkey/KeyUtils operations
        // that use the bio-gated platform key.
        biometricAuthHelper.authenticate(
            getString(R.string.bio_prompt_title),
            "Authenticate to receive the credential",
            new BiometricAuthHelper.AuthenticationCallback() {
                @Override
                public void onAuthenticationSucceeded(
                        androidx.biometric.BiometricPrompt.AuthenticationResult result) {
                    Log.i(TAG, "Biometric authentication succeeded, proceeding with credential issuance");
                    runOnUiThread(() -> {
                        setUiStateForProcessing(true);
                        // TEE window is open — safe to process the credential offer.
                        executorService.execute(CredentialIssuanceActivity.this::processCredentialOffer);
                    });
                }

                @Override
                public void onAuthenticationFailed(String errorMessage) {
                    Log.e(TAG, "Biometric authentication failed: " + errorMessage);
                    runOnUiThread(() -> {
                        showError(getString(R.string.authentication_required));
                        setUiStateForProcessing(false);
                    });
                }

                @Override
                public void onAuthenticationCancelled() {
                    Log.i(TAG, "Biometric authentication cancelled by user");
                    runOnUiThread(() -> {
                        Toast.makeText(CredentialIssuanceActivity.this,
                            getString(R.string.cancel), Toast.LENGTH_SHORT).show();
                        setUiStateForProcessing(false);
                    });
                }
            });
    }
    
    private void processCredentialOffer() {
        try {
            Log.i(TAG, "Starting credential issuance process");
            Log.d(TAG, "Credential offer URI: " + credentialOfferUri);
            
            File appDataDir = getFilesDir();
            File passkeyFile = new File(appDataDir, passkeyFileName);
            Log.d(TAG, "Opening passkey file: " + passkeyFile.getAbsolutePath());
            
            Passkey passkey = Passkey.openKey(passwordHash, passkeyFile);
            
            if (passkey == null) {
                Log.e(TAG, "Failed to open passkey - passkey is null");
                runOnUiThread(() -> {
                    showError("Failed to open passkey");
                    setUiStateForProcessing(false);
                });
                return;
            }
            
            Log.i(TAG, "Passkey opened successfully");
            Log.d(TAG, "Getting master key for holder binding");
            
            PrivateKey masterKey = AndroidHolderBindingKeyManager.getMasterKey();
            if (masterKey == null) {
                Log.e(TAG, "Failed to get master key");
                runOnUiThread(() -> {
                    showError("Failed to get master key");
                    setUiStateForProcessing(false);
                });
                return;
            }
            
            Log.i(TAG, "Master key obtained");
            Oidc4VciClient client = new Oidc4VciClient();
            String configId = credentialOffer.getCredentials().get(0);
            String credentialId = java.util.UUID.randomUUID().toString();
            
            Log.i(TAG, "Requesting credential from issuer");
            Log.d(TAG, "Credential ID: " + credentialId);
            Log.d(TAG, "Config ID: " + configId);
            Log.d(TAG, "Issuer: " + credentialOffer.getCredentialIssuer());
            
            VerifiableCredential vc = client.issueCredential(
                credentialOfferUri,
                credentialId,
                credentialOffer.getCredentialIssuer(),
                configId,
                masterKey
            );
            
            if (vc == null) {
                Log.e(TAG, "Credential issuance returned null");
                runOnUiThread(() -> {
                    showError("Failed to issue credential - no credential returned");
                    setUiStateForProcessing(false);
                });
                return;
            }
            
            Log.i(TAG, "Credential issued successfully");
            Log.d(TAG, "Adding credential to passkey");
            
            passkey.addVerifiableCredential(vc);
            
            Log.d(TAG, "Saving passkey with new credential");
            boolean saved = Passkey.writeKey(passkey, passwordHash, passkeyFile);
            
            if (saved) {
                Log.i(TAG, "Credential stored successfully in passkey");
            } else {
                Log.e(TAG, "Failed to save passkey file");
            }
            
            runOnUiThread(() -> {
                if (saved) {
                    showSuccess();
                } else {
                    showError("Failed to save credential");
                    setUiStateForProcessing(false);
                }
            });
            
        } catch (OidcException e) {
            Log.e(TAG, "OIDC error during credential issuance", e);
            Log.e(TAG, "OIDC error details: " + e.getMessage());
            
            runOnUiThread(() -> {
                // Check if offer has expired during the failed attempt
                if (credentialOffer != null && credentialOffer.isExpired()) {
                    Log.w(TAG, "Credential offer expired during issuance attempt");
                    showError("Credential offer has expired. Please request a new offer.");
                    
                    // Set result to indicate expired offer so ManageActivity can clean up
                    Intent resultIntent = new Intent();
                    resultIntent.putExtra("offer_expired", true);
                    setResult(RESULT_CANCELED, resultIntent);
                    
                    // Close activity after short delay to show error message
                    new android.os.Handler(getMainLooper()).postDelayed(() -> finish(), 2000);
                } else {
                    showError("Network error: " + e.getMessage());
                    setUiStateForProcessing(false);
                }
            });
        } catch (Exception e) {
            Log.e(TAG, "Failed to request credential", e);
            Log.e(TAG, "Error type: " + e.getClass().getName());
            Log.e(TAG, "Error message: " + e.getMessage());
            if (e.getCause() != null) {
                Log.e(TAG, "Caused by: " + e.getCause().getMessage());
            }
            
            runOnUiThread(() -> {
                // Check if offer has expired during the failed attempt
                if (credentialOffer != null && credentialOffer.isExpired()) {
                    Log.w(TAG, "Credential offer expired during issuance attempt");
                    showError("Credential offer has expired. Please request a new offer.");
                    
                    // Set result to indicate expired offer so ManageActivity can clean up
                    Intent resultIntent = new Intent();
                    resultIntent.putExtra("offer_expired", true);
                    setResult(RESULT_CANCELED, resultIntent);
                    
                    // Close activity after short delay to show error message
                    new android.os.Handler(getMainLooper()).postDelayed(() -> finish(), 2000);
                } else {
                    showError("Failed to request credential: " + e.getMessage());
                    setUiStateForProcessing(false);
                }
            });
        }
    }
    
    private void setUiStateForProcessing(boolean processing) {
        showProgress(processing);
        acceptButton.setEnabled(!processing);
        declineButton.setEnabled(!processing);
    }
    
    private void declineCredentialOffer() {
        Toast.makeText(this, "Credential offer declined", Toast.LENGTH_SHORT).show();
        setResult(RESULT_CANCELED);
        finish();
    }
    
    private void showProgress(boolean show) {
        progressBar.setVisibility(show ? View.VISIBLE : View.GONE);
        contentLayout.setVisibility(show ? View.GONE : View.VISIBLE);
    }
    
    private void showError(String message) {
        showProgress(false);
        Toast.makeText(this, message, Toast.LENGTH_LONG).show();
        acceptButton.setEnabled(false);
    }
    
    private void showSuccess() {
        showProgress(false);
        Toast.makeText(this, "Credential issued successfully!", Toast.LENGTH_LONG).show();
        finish();
    }
    
    @Override
    protected void onDestroy() {
        super.onDestroy();
        stopExpirationCountdown();
        executorService.shutdown();
    }
    
    @Override
    protected void onPause() {
        super.onPause();
        stopExpirationCountdown();
    }
    
    @Override
    protected void onResume() {
        super.onResume();
        if (credentialOffer != null && !credentialOffer.isExpired()) {
            startExpirationCountdown();
        }
    }
    
    /**
     * Parses a query string into a map of parameters.
     */
    private java.util.Map<String, String> parseQueryString(String query) {
        java.util.Map<String, String> params = new java.util.HashMap<>();
        String[] pairs = query.split("&");
        
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            if (idx > 0) {
                try {
                    String key = java.net.URLDecoder.decode(pair.substring(0, idx), "UTF-8");
                    String value = java.net.URLDecoder.decode(pair.substring(idx + 1), "UTF-8");
                    params.put(key, value);
                } catch (java.io.UnsupportedEncodingException e) {
                    Log.e(TAG, "Failed to decode query parameter", e);
                }
            }
        }
        
        return params;
    }
}

// Made with Bob
