package com.isfs.blekey.activity;

import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;
import android.view.ViewGroup;
import android.widget.ImageButton;

import androidx.activity.OnBackPressedCallback;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.card.MaterialCardView;

import com.isfs.blekey.R;
import com.isfs.blekey.data.Passkey;
import com.isfs.blekey.oidc.CredentialOffer;
import com.isfs.blekey.oidc.IssuerMetadata;
import com.isfs.blekey.oidc.OidcException;
import com.isfs.blekey.util.BiometricAuthHelper;
import com.isfs.blekey.util.FileUtils;
import com.isfs.blekey.util.KeyUtils;
import com.isfs.blekey.util.http.HttpClient;

import java.io.File;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Activity for managing passkeys.
 * This activity displays a list of available passkeys and allows the user
 * to select and manage them after entering the correct password.
 */
public class ManageActivity extends AppCompatActivity {
    /**
     * Enum representing the expiration status with associated visual indicators.
     * Encapsulates traffic light colors and status text based on remaining time percentage.
     */
    private enum ExpirationStatus {
        HEALTHY(0.5, "#4CAF50", "Expires in "),
        WARNING(0.2, "#FF9800", "Expires soon: "),
        CRITICAL(0.0, "#F44336", "Expiring: ");

        private final double threshold;
        private final int color;
        private final String statusText;

        ExpirationStatus(double threshold, String colorHex, String statusText) {
            this.threshold = threshold;
            this.color = Color.parseColor(colorHex);
            this.statusText = statusText;
        }

        /**
         * Determines the appropriate status based on the percentage of time remaining.
         * @param percentRemaining The percentage of time remaining (0.0 to 1.0)
         * @return The corresponding ExpirationStatus
         */
        static ExpirationStatus fromPercentRemaining(double percentRemaining) {
            if (percentRemaining > HEALTHY.threshold) return HEALTHY;
            if (percentRemaining > WARNING.threshold) return WARNING;
            return CRITICAL;
        }

        int getColor() {
            return color;
        }

        String getStatusText() {
            return statusText;
        }
    }
    /**
     * Result object encapsulating credential offer processing outcome.
     * Eliminates the need for array wrappers and provides type-safe error handling.
     */
    private static class CredentialOfferResult {
        private final CredentialOffer offer;
        private final String issuerName;
        private final long receivedAtMillis;
        private final boolean expired;

        
        private CredentialOfferResult(CredentialOffer offer, String issuerName, 
                                     long receivedAtMillis, boolean expired, Exception error) {
            this.offer = offer;
            this.issuerName = issuerName;
            this.receivedAtMillis = receivedAtMillis;
            this.expired = expired;
        }
        
        static CredentialOfferResult success(CredentialOffer offer, String issuerName) {
            return new CredentialOfferResult(offer, issuerName, 
                offer.getReceivedAtMillis(), false, null);
        }
        
        static CredentialOfferResult expired(CredentialOffer offer) {
            return new CredentialOfferResult(offer, null, 
                offer.getReceivedAtMillis(), true, null);
        }
        
        static CredentialOfferResult failure(CredentialOffer offer, Exception error) {
            long timestamp = offer != null ? offer.getReceivedAtMillis() : System.currentTimeMillis();
            return new CredentialOfferResult(offer, null, timestamp, false, error);
        }
        
        boolean isExpired() { return expired; }
        CredentialOffer getOffer() { return offer; }
        String getIssuerName() { return issuerName; }
        long getReceivedAtMillis() { return receivedAtMillis; }
    }


    
    private static final String TAG = ManageActivity.class.getCanonicalName();
    private final ExecutorService executorService = Executors.newSingleThreadExecutor();
    private TextView credentialInfo;
    private Button manageButton;
    private Button deleteButton;
    private Button createButton;
    
    // Passkeys list components
    private ListView passkeysListView;
    private TextView noPasskeysText;
    private LinearLayout passkeysListSection;
    private TextView mainTitleText;
    
    // Password protection components
    private EditText passwordInput;
    private Button unlockButton;
    private TextView passwordError;
    private LinearLayout passwordSection;
    private LinearLayout credentialOptionsSection;
    
    // Credential offer notification components
    private MaterialCardView credentialOfferNotification;
    private LinearLayout offerHeader;
    private LinearLayout offerDetails;
    private ImageButton expandButton;
    private TextView credentialTypeText;
    private TextView issuerNameText;
    private LinearLayout expirationIndicator;
    private TextView trafficLight;
    private TextView trafficLightCollapsed;
    private TextView expirationText;
    private boolean isOfferExpanded = false;
    
    // Expiration tracking
    private CredentialOffer currentOffer;
    private Handler expirationHandler;
    private Runnable expirationUpdateRunnable;
    
    // Activity Result Launcher for credential issuance
    private ActivityResultLauncher<Intent> credentialIssuanceLauncher;
    
    // Constants for expiration display
    private static final long DEFAULT_EXPIRATION_SECONDS = 300L;
    private static final int SECONDS_PER_MINUTE = 60;
    
    // Flow type constants
    private static final String FLOW_TYPE_ISSUANCE = "issuance";
    private static final String FLOW_TYPE_PRESENTATION = "presentation";

    private String rpId;
    private File selectedPasskeyFile;
    private int selectedPosition = -1;
    private BiometricAuthHelper biometricAuthHelper;
    
    @Override
    protected void onCreate(final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_manage);
        
        // Set background color explicitly to ensure visibility
        findViewById(android.R.id.content).setBackgroundColor(android.graphics.Color.WHITE);
        
        // Set up the custom toolbar
        setupToolbar();
        
        // Set up modern back press handling
        setupBackPressHandler();
        
        // Register activity result launcher for credential issuance
        registerCredentialIssuanceLauncher();
        
        biometricAuthHelper = new BiometricAuthHelper(this);

        initializeUIComponents();

        handleCredentialFlowIntent(getIntent());
        loadPasskeys();
        setupEventListeners();
    }
    
    /**
     * Called when the activity is resumed.
     * This is where we should refresh the passkeys list to show any newly created passkeys.
     */
    @Override
    protected void onStart() {
        super.onStart();
        
        // Check and hide expired offers when activity becomes visible
        Log.i(TAG, "onStart: Checking for expired offers");
        checkAndHideExpiredOffer();
    }
    
    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleCredentialFlowIntent(intent);
    }

    @Override
    protected void onResume() {
        super.onResume();
        
        Log.i(TAG, "onResume: Checking for expired offers");
        // Check and hide expired offers BEFORE any other UI updates
        checkAndHideExpiredOffer();
        
        // Restart expiration countdown if offer is still valid
        if (currentOffer != null && !currentOffer.isExpired()) {
            startExpirationCountdown();
        }
        
        // Reset UI state to show passkeys list and hide password section
        if (passwordSection != null && passwordSection.getVisibility() == View.VISIBLE) {
            showPasskeysList();
            if (passwordInput != null) {
                passwordInput.setText("");
            }
            if (passwordError != null) {
                passwordError.setVisibility(View.GONE);
            }
        }
        loadPasskeys();
    }
    
    @Override
    protected void onPause() {
        super.onPause();
        stopExpirationCountdown();
    }
    
    @Override
    protected void onDestroy() {
        super.onDestroy();
        stopExpirationCountdown();
        executorService.shutdown();
    }
    
    /**
     * Routes incoming credential intents to the appropriate handlers.
     */
    private void handleCredentialFlowIntent(Intent intent) {
        if (intent == null) {
            return;
        }

        String action = intent.getAction();
        if (action == null) {
            String flowType = intent.getStringExtra("flow_type");
            if (FLOW_TYPE_ISSUANCE.equals(flowType)) {
                showCredentialOfferNotification(intent);
            }
            return;
        }

        if ("com.isfs.blekey.CREDENTIAL_OFFER".equals(action)) {
            String uri = intent.getStringExtra("credential_offer_uri");
            if (uri != null) {
                handleCredentialOffer(uri);
            }
        } else if ("com.isfs.blekey.PRESENTATION_REQUEST".equals(action)) {
            String uri = intent.getStringExtra("presentation_request_uri");
            if (uri != null) {
                handlePresentationRequest(uri);
            }
        }
    }

    /**
     * Builds an intent for credential offer with all necessary extras.
     * Eliminates code duplication between success and error paths.
     * 
     * @param credentialOfferUri The credential offer URI
     * @param offer The credential offer object (may be null on error)
     * @param receivedAtMillis Timestamp when offer was received
     * @param issuerName Human-readable issuer name (may be null)
     * @return Intent configured with credential offer data
     */
    private Intent buildCredentialOfferIntent(String credentialOfferUri, 
                                             CredentialOffer offer, 
                                             long receivedAtMillis,
                                             String issuerName) {
        Intent intent = new Intent(getIntent());
        intent.setAction("com.isfs.blekey.CREDENTIAL_OFFER");
        intent.putExtra("credential_offer_uri", credentialOfferUri);
        intent.putExtra("flow_type", FLOW_TYPE_ISSUANCE);
        intent.putExtra("received_at_millis", receivedAtMillis);
        
        if (offer != null) {
            if (!offer.getCredentials().isEmpty()) {
                intent.putExtra("credential_type", offer.getCredentials().get(0));
            }
            intent.putExtra("issuer_url", offer.getCredentialIssuer());
        }
        
        if (issuerName != null) {
            intent.putExtra("issuer_name", issuerName);
        }
        
        return intent;
    }

    /**
     * Fetches credential offer and issuer metadata in background.
     * Encapsulates all background processing logic with proper error handling.
     * 
     * @param credentialOfferUri The credential offer URI to process
     * @return Result object containing offer, metadata, or error information
     */
    private CredentialOfferResult fetchCredentialOfferWithMetadata(String credentialOfferUri) {
        try {
            CredentialOffer offer = CredentialOffer.fromUri(credentialOfferUri);
            
            if (offer.isExpired()) {
                Log.i(TAG, "Credential offer has already expired");
                return CredentialOfferResult.expired(offer);
            }
            
            IssuerMetadata metadata = IssuerMetadata.fetch(
                offer.getCredentialIssuer(),
                new HttpClient()
            );
            
            String issuerName = extractIssuerName(metadata);
            return CredentialOfferResult.success(offer, issuerName);
            
        } catch (OidcException e) {
            Log.e(TAG, "Failed to parse credential offer", e);
            return CredentialOfferResult.failure(null, e);
        } catch (Exception e) {
            Log.e(TAG, "Failed to fetch offer metadata", e);
            // Try to parse offer even if metadata fetch fails
            try {
                CredentialOffer offer = CredentialOffer.fromUri(credentialOfferUri);
                return CredentialOfferResult.failure(offer, e);
            } catch (Exception parseError) {
                return CredentialOfferResult.failure(null, e);
            }
        }
    }

    /**
     * Handles a credential offer intent inside [ManageActivity](app/src/main/java/com/isfs/blekey/activity/ManageActivity.java)
     * and enriches the notification payload before showing it.
     *
     * Refactored to eliminate code duplication, remove array wrapper anti-pattern,
     * and consolidate UI thread updates for better performance and maintainability.
     */
    private void handleCredentialOffer(String credentialOfferUri) {
        if (credentialOfferUri == null) {
            Log.e(TAG, "No credential_offer_uri provided");
            Toast.makeText(this, "Invalid credential offer", Toast.LENGTH_SHORT).show();
            return;
        }

        Log.i(TAG, "Received credential offer: " + credentialOfferUri);

        executorService.execute(() -> {
            CredentialOfferResult result = fetchCredentialOfferWithMetadata(credentialOfferUri);
            
            runOnUiThread(() -> {
                if (result.isExpired()) {
                    Toast.makeText(this, "Credential offer has expired", Toast.LENGTH_LONG).show();
                    return;
                }
                
                Intent intent = buildCredentialOfferIntent(
                    credentialOfferUri,
                    result.getOffer(),
                    result.getReceivedAtMillis(),
                    result.getIssuerName()
                );
                
                setIntent(intent);
                showCredentialOfferNotification(intent);
            });
        });
    }

    /**
     * Extracts a human-readable issuer name from issuer metadata.
     */
    private String extractIssuerName(IssuerMetadata metadata) {
        if (metadata == null) {
            return null;
        }

        Object displayObj = metadata.getRawMetadata().get("display");
        if (displayObj instanceof java.util.Map) {
            @SuppressWarnings("unchecked")
            java.util.Map<String, Object> displayMap = (java.util.Map<String, Object>) displayObj;
            Object nameObj = displayMap.get("name");
            if (nameObj instanceof String) {
                return (String) nameObj;
            }
        }

        try {
            java.net.URI uri = java.net.URI.create(metadata.getCredentialIssuer());
            return uri.getHost();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Handles a presentation request intent inside [ManageActivity](app/src/main/java/com/isfs/blekey/activity/ManageActivity.java).
     */
    private void handlePresentationRequest(String presentationRequestUri) {
        if (presentationRequestUri == null) {
            Log.e(TAG, "No presentation_request_uri provided");
            Toast.makeText(this, "Invalid presentation request", Toast.LENGTH_SHORT).show();
            return;
        }

        Log.i(TAG, "Received presentation request: " + presentationRequestUri);

        Intent manageIntent = new Intent(getIntent());
        manageIntent.setAction("com.isfs.blekey.PRESENTATION_REQUEST");
        manageIntent.putExtra("presentation_request_uri", presentationRequestUri);
        manageIntent.putExtra("flow_type", FLOW_TYPE_PRESENTATION);
        setIntent(manageIntent);
    }

    /**
     * Registers the activity result launcher for credential issuance.
     * This replaces the deprecated startActivityForResult/onActivityResult pattern.
     */
    private void registerCredentialIssuanceLauncher() {
        credentialIssuanceLauncher = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            result -> {
                int resultCode = result.getResultCode();
                Intent data = result.getData();
                
                if (resultCode == RESULT_OK) {
                    Log.i(TAG, "Credential successfully issued, cleaning up notification");
                    hideCredentialOfferNotification();
                } else if (resultCode == RESULT_CANCELED) {
                    // Check if offer expired during issuance
                    boolean offerExpired = data != null && data.getBooleanExtra("offer_expired", false);
                    if (offerExpired) {
                        Log.i(TAG, "Credential offer expired during issuance, cleaning up notification");
                        hideCredentialOfferNotification();
                    } else {
                        // User cancelled or navigated back - check if offer is now expired
                        Log.i(TAG, "Issuance cancelled, checking if offer expired");
                        checkAndHideExpiredOffer();
                    }
                }
            }
        );
    }
    
    /**
     * Sets up modern back press handling using OnBackPressedCallback.
     * This replaces the deprecated onBackPressed() method.
     */
    private void setupBackPressHandler() {
        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override
            public void handleOnBackPressed() {
                handleBackNavigation();
            }
        });
    }
    
    /**
     * Sets up the custom toolbar with back button and home button functionality.
     */
    private void setupToolbar() {
        // Find the back button in the custom toolbar
        ImageButton backButton = findViewById(R.id.backButton);
        if (backButton != null) {
            // Set click listener to handle back navigation
            backButton.setOnClickListener(v -> handleBackNavigation());
        }
        
        // Find the home button in the custom toolbar
        ImageButton homeButton = findViewById(R.id.homeButton);
        if (homeButton != null) {
            // Set click listener to navigate to MainActivity
            homeButton.setOnClickListener(v -> navigateToHome());
        }
    }
    
    /**
     * Navigates to the main activity.
     */
    private void navigateToHome() {
        Intent intent = new Intent(this, com.isfs.blekey.MainActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(intent);
        finish();
    }
    
    /**
     * Handles back navigation based on current UI state.
     * If password section is visible, return to passkeys list.
     * Otherwise, finish the activity.
     */
    private void handleBackNavigation() {
        if (passwordSection.getVisibility() == View.VISIBLE) {
            // Return to passkeys list
            showPasskeysList();
            // Clear password input and error
            passwordInput.setText("");
            passwordError.setVisibility(View.GONE);
        } else {
            // Close the activity
            finish();
        }
    }
    
    /**
     * Initializes all UI components by finding views by ID.
     */
    private void initializeUIComponents() {
        // Initialize UI components
        credentialInfo = findViewById(R.id.credentialInfo);
        manageButton = findViewById(R.id.manageButton);
        deleteButton = findViewById(R.id.deleteButton);
        createButton = findViewById(R.id.createCredential);
        
        // Initialize passkeys list components
        passkeysListView = findViewById(R.id.passkeysListView);
        noPasskeysText = findViewById(R.id.noPasskeysText);
        passkeysListSection = findViewById(R.id.passkeysListSection);
        mainTitleText = findViewById(R.id.mainTitleText);
        
        // Initialize password protection components
        passwordInput = findViewById(R.id.passwordInput);
        unlockButton = findViewById(R.id.unlockButton);
        passwordError = findViewById(R.id.passwordError);
        passwordSection = findViewById(R.id.passwordSection);
        credentialOptionsSection = findViewById(R.id.credentialOptionsSection);
        
        // Initialize credential offer notification components
        credentialOfferNotification = findViewById(R.id.credentialOfferNotification);
        offerHeader = findViewById(R.id.offerHeader);
        offerDetails = findViewById(R.id.offerDetails);
        expandButton = findViewById(R.id.expandButton);
        credentialTypeText = findViewById(R.id.credentialTypeText);
        issuerNameText = findViewById(R.id.issuerNameText);
        expirationIndicator = findViewById(R.id.expirationIndicator);
        trafficLight = findViewById(R.id.trafficLight);
        trafficLightCollapsed = findViewById(R.id.trafficLightCollapsed);
        expirationText = findViewById(R.id.expirationText);
        
        // Initialize expiration handler
        expirationHandler = new Handler(Looper.getMainLooper());
    }
    
    /**
     * Extracts the relying party ID from a passkey filename.
     * Removes the .passkey extension if present.
     *
     * @param filename The passkey filename
     * @return The extracted relying party ID
     */
    private String extractPasskeyNameFromFilename(String filename) {
        return filename.endsWith(".passkey") ?
               filename.substring(0, filename.length() - 8) : filename;
    }
    
    /**
     * Shows the password section and hides the passkeys list.
     */
    private void showPasswordSection() {
        passkeysListSection.setVisibility(View.GONE);
        passwordSection.setVisibility(View.VISIBLE);
        
        // Hide the "Available Wallets" title when showing unlock view
        mainTitleText.setVisibility(View.GONE);
        
        // Hide create passkey, delete, and manage buttons when unlocking
        createButton.setVisibility(View.GONE);
        deleteButton.setVisibility(View.GONE);
        manageButton.setVisibility(View.GONE);
    }
    
    /**
     * Shows the passkeys list and credential options section.
     * This ensures the create button is always visible.
     */
    private void showPasskeysList() {
        passwordSection.setVisibility(View.GONE);
        credentialOptionsSection.setVisibility(View.VISIBLE);
        passkeysListSection.setVisibility(View.VISIBLE);
        
        // Show the "Available Wallets" title when showing passkeys list
        mainTitleText.setVisibility(View.VISIBLE);
        
        // Show create passkey button
        createButton.setVisibility(View.VISIBLE);
        
        // Show manage and delete buttons if a passkey is selected
        if (selectedPasskeyFile != null) {
            manageButton.setVisibility(View.VISIBLE);
            deleteButton.setVisibility(View.VISIBLE);
        } else {
            manageButton.setVisibility(View.GONE);
            deleteButton.setVisibility(View.GONE);
        }
    }
    
    /**
     * Sets up all event listeners.
     */
    private void setupEventListeners() {
        setupPasskeySelectionListener();
        setupUnlockButtonListener();
        setupManageButtonListener();
        setupDeleteButtonListener();
        setupCreateButtonListener();
    }
    
    /**
     * Sets up the passkey selection listener.
     */
    private void setupPasskeySelectionListener() {
        passkeysListView.setOnItemClickListener((parent, view, position, id) -> {
            // Update the selected position
            selectedPosition = position;
            
            // Get the selected passkey file
            selectedPasskeyFile = (File) parent.getItemAtPosition(position);
            
            // Extract passkey name from filename
            String filename = selectedPasskeyFile.getName();
            rpId = extractPasskeyNameFromFilename(filename);
            
            // Check if this is a credential issuance or presentation flow
            Intent currentIntent = getIntent();
            String flowType = currentIntent.getStringExtra("flow_type");
            
            if (FLOW_TYPE_ISSUANCE.equals(flowType) || FLOW_TYPE_PRESENTATION.equals(flowType)) {
                // For credential flows, immediately show password section
                Log.i(TAG, "Credential flow detected, showing password section for: " + rpId);
                credentialInfo.setText(getString(R.string.wallet_selected) + " " + filename);
                showPasswordSection();
            } else {
                // For normal passkey management, just show selection
                credentialInfo.setText(getString(R.string.wallet_selected) + " " + filename);
                
                // Make sure the manage and delete buttons are visible
                manageButton.setVisibility(View.VISIBLE);
                deleteButton.setVisibility(View.VISIBLE);
            }
            
            // Update the adapter to refresh the view
            Object adapter = parent.getAdapter();
            if (adapter instanceof ArrayAdapter<?>) {
                ((ArrayAdapter<?>) adapter).notifyDataSetChanged();
            }
        });
    }
    
    /**
     * Sets up the unlock button click listener.
     */
    private void setupUnlockButtonListener() {
        unlockButton.setOnClickListener(view -> validatePassword());
    }

    private void setupCreateButtonListener() {
        createButton.setOnClickListener(view -> {
            Intent intent = new Intent(getApplicationContext(), CreatePasskeyActivity.class);
            intent.putExtra("bioAuthTODO", false);
            startActivity(intent);
        });
    }
    
    /**
     * Sets up the update button click listener.
     */
    private void setupManageButtonListener() {
        manageButton.setOnClickListener(view -> {
            if (selectedPasskeyFile == null) {
                Toast.makeText(this, getString(R.string.no_passkey_wallet_selected), Toast.LENGTH_SHORT).show();
                return;
            }
            
            // Show password section when manage button is clicked
            showPasswordSection();
            
            // Add back button functionality
            setupBackButton();
        });
    }
    
    /**
     * Sets up the delete button click listener.
     */
    private void setupDeleteButtonListener() {
        deleteButton.setOnClickListener(view -> {
            if (selectedPasskeyFile == null) {
                Toast.makeText(this, getString(R.string.no_passkey_wallet_selected), Toast.LENGTH_SHORT).show();
                return;
            }
            deleteCredential();
            showPasskeysList();
            loadPasskeys(); // Refresh the list
        });
    }
    /**
     * Sets up the back button functionality.
     */
    private void setupBackButton() {
        View homeButton = findViewById(android.R.id.home);
        if (homeButton != null) {
            homeButton.setOnClickListener(v -> showPasskeysList());
        } else {
            // Fallback to using the toolbar back button that's already set up
            // The toolbar back button is set up in setupToolbar() method
        }
    }



    private boolean noPasskeysExist() {
        return FileUtils.listPasskeys() == null || FileUtils.listPasskeys().isEmpty();
    }
    
    private void passkeyUXVisible() {
        // Create a custom adapter that displays the filename without extension
        ArrayAdapter<File> adapter = new ArrayAdapter<File>(
            this,
            R.layout.passkey_list_item,
            FileUtils.listPasskeys()) {
                @Override
                public View getView(int position, View convertView, ViewGroup parent) {
                    View view = convertView;
                    if (view == null) {
                        view = getLayoutInflater().inflate(R.layout.passkey_list_item, parent, false);
                    }
                    
                    TextView text = (TextView) view.findViewById(android.R.id.text1);
                    
                    File file = getItem(position);
                    if (file != null) {
                        String filename = file.getName();
                        // Remove .passkey extension if present
                        text.setText(filename.endsWith(".passkey") ?
                                filename.substring(0, filename.length() - 8) : filename);
                    }
                    
                    // Set activated state for background selector
                    boolean isSelected = position == selectedPosition;
                    view.setActivated(isSelected);
                    
                    return view;
                }
            };
        
        passkeysListView.setAdapter(adapter);
        passkeysListView.setChoiceMode(ListView.CHOICE_MODE_SINGLE);
        passkeysListView.setVisibility(View.VISIBLE);
        noPasskeysText.setVisibility(View.GONE);
        
        // Show update and delete buttons when passkeys exist
        manageButton.setVisibility(View.VISIBLE);
        deleteButton.setVisibility(View.VISIBLE);
    }

    private void passkeyUXHidden() {
        passkeysListView.setVisibility(View.GONE);
        noPasskeysText.setVisibility(View.VISIBLE);
        
        // Make sure the create button is visible even when no passkeys exist
        createButton.setVisibility(View.VISIBLE);
        
        // Hide update and delete buttons when no passkeys exist
        manageButton.setVisibility(View.GONE);
        deleteButton.setVisibility(View.GONE);
        
        credentialOptionsSection.setVisibility(View.VISIBLE);
    }
    /**
     * Loads and displays the list of available passkeys.
     */
    private void loadPasskeys() {
        // Set background color explicitly to ensure visibility
        findViewById(android.R.id.content).setBackgroundColor(android.graphics.Color.WHITE);
        
        // Reset selection when reloading
        selectedPosition = -1;
        selectedPasskeyFile = null;
        rpId = null;
        
        // In Android, we should use the app's data directory
        File appDataDir = getFilesDir();
        System.setProperty("FIDO2_HOME", appDataDir.getAbsolutePath());
        if (noPasskeysExist()) {
            // No passkeys found
            passkeyUXHidden();
        } else {
            // Display passkeys in the list
            passkeyUXVisible();
        }
    }
    
    
    /**
     * Deletes the current credential by removing the passkey file.
     * This permanently removes the passkey from the device.
     */
    private void deleteCredential() {
        if (selectedPasskeyFile == null) {
            Toast.makeText(this, getString(R.string.no_passkey_wallet_selected), Toast.LENGTH_SHORT).show();
            return;
        }
        
        try {
            // Check if file exists
            if (selectedPasskeyFile.exists()) {
                // Delete the file
                boolean deleted = selectedPasskeyFile.delete();
                
                if (deleted) {
                    Toast.makeText(this, getString(R.string.passkey_deleted_success, rpId), Toast.LENGTH_SHORT).show();
                    // Clear the selected passkey
                    selectedPasskeyFile = null;
                    rpId = null;
                } else {
                    Toast.makeText(this, getString(R.string.passkey_delete_failed), Toast.LENGTH_SHORT).show();
                }
            } else {
                Toast.makeText(this, getString(R.string.passkey_file_not_found), Toast.LENGTH_SHORT).show();
            }
        } catch (Exception e) {
            Toast.makeText(this, getString(R.string.passkey_delete_error, e.getMessage()), Toast.LENGTH_SHORT).show();
        }
    }
    
    /**
     * Validates the entered password and launches the appropriate activity.
     * Opens a biometric prompt to set the TEE auth window before calling Passkey.openKey().
     */
    private void validatePassword() {
        String enteredPassword = passwordInput.getText().toString();
        byte[] pinHash = KeyUtils.getPinHash(enteredPassword);

        biometricAuthHelper.authenticate(
            getString(R.string.bio_prompt_title),
            getString(R.string.bio_prompt_subtitle),
            new BiometricAuthHelper.AuthenticationCallback() {
                @Override
                public void onAuthenticationSucceeded(
                        androidx.biometric.BiometricPrompt.AuthenticationResult result) {
                    // TEE auth window is now open — safe to call Passkey.openKey().
                    runOnUiThread(() -> completePasswordValidation(pinHash));
                }

                @Override
                public void onAuthenticationFailed(String errorMessage) {
                    runOnUiThread(() -> Toast.makeText(ManageActivity.this,
                        R.string.authentication_required, Toast.LENGTH_LONG).show());
                }

                @Override
                public void onAuthenticationCancelled() {
                    runOnUiThread(() -> Toast.makeText(ManageActivity.this,
                        getString(R.string.cancel), Toast.LENGTH_SHORT).show());
                }
            });
    }

    /**
     * Called on the UI thread after the CryptoObject biometric succeeds.
     * TEE auth window is open — safe to call Passkey.openKey() / writeKey().
     */
    private void completePasswordValidation(byte[] pinHash) {
        Passkey passkey = Passkey.openKey(pinHash, selectedPasskeyFile);

        if (passkey == null) {
            handleInvalidPassword();
            return;
        }

        Log.d(TAG, "Updating passkey header after successful unlock");
        boolean updated = Passkey.writeKey(passkey, pinHash, selectedPasskeyFile);
        if (!updated) {
            Log.w(TAG, "Failed to update passkey header, but passkey is still usable");
        }

        Toast.makeText(this, getString(R.string.wallet_unlocked), Toast.LENGTH_SHORT).show();
        hideKeyboard();
        launchAppropriateActivity(pinHash);
    }
    
    /**
     * Handles invalid password entry by showing error message and clearing input.
     */
    private void handleInvalidPassword() {
        passwordError.setText(getString(R.string.incorrect_password));
        passwordError.setVisibility(View.VISIBLE);
        passwordInput.setText("");
    }
    
    /**
     * Hides the soft keyboard.
     */
    private void hideKeyboard() {
        try {
            if (passwordInput != null) {
                passwordInput.clearFocus();
            }
            
            android.view.inputmethod.InputMethodManager imm = (android.view.inputmethod.InputMethodManager)
                    getSystemService(android.content.Context.INPUT_METHOD_SERVICE);
            View rootView = getWindow().getDecorView().getRootView();
            imm.hideSoftInputFromWindow(rootView.getWindowToken(), 0);
        } catch (Exception e) {
            Log.e(TAG, "Error hiding keyboard", e);
        }
    }
    
    /**
     * Launches the appropriate activity based on the current flow type.
     *
     * @param pinHash The hashed password for authentication
     */
    private void launchAppropriateActivity(byte[] pinHash) {
        Intent currentIntent = getIntent();
        String flowType = currentIntent.getStringExtra("flow_type");
        String credentialOfferUri = currentIntent.getStringExtra("credential_offer_uri");
        String presentationRequestUri = currentIntent.getStringExtra("presentation_request_uri");
        
        Log.i(TAG, "Flow type: " + flowType);
        Log.i(TAG, "Credential offer URI: " + (credentialOfferUri != null ? "present" : "null"));
        Log.i(TAG, "Presentation request URI: " + (presentationRequestUri != null ? "present" : "null"));
        
        if (FLOW_TYPE_ISSUANCE.equals(flowType) && credentialOfferUri != null) {
            launchCredentialIssuance(credentialOfferUri, pinHash);
        } else if (FLOW_TYPE_PRESENTATION.equals(flowType) && presentationRequestUri != null) {
            launchCredentialPresentation(presentationRequestUri, pinHash);
        } else {
            launchCredentialManagement(pinHash);
        }
    }
    
    /**
     * Launches the credential issuance activity.
     */
    private void launchCredentialIssuance(String credentialOfferUri, byte[] pinHash) {
        Log.i(TAG, "Launching CredentialIssuanceActivity for credential offer");
        Intent intent = new Intent(getApplicationContext(), CredentialIssuanceActivity.class);
        intent.putExtra("credential_offer_uri", credentialOfferUri);
        intent.putExtra("passkey", pinHash);
        intent.putExtra("file", selectedPasskeyFile.getName());
        
        if (currentOffer != null) {
            intent.putExtra("received_at_millis", currentOffer.getReceivedAtMillis());
        }
        
        credentialIssuanceLauncher.launch(intent);
    }
    
    /**
     * Launches the credential presentation activity.
     */
    private void launchCredentialPresentation(String presentationRequestUri, byte[] pinHash) {
        Log.i(TAG, "Launching CredentialPresentationActivity for presentation request");
        Intent intent = new Intent(getApplicationContext(), CredentialPresentationActivity.class);
        intent.putExtra("presentation_request_uri", presentationRequestUri);
        intent.putExtra("passkey", pinHash);
        intent.putExtra("file", selectedPasskeyFile.getName());
        startActivity(intent);
    }
    
    /**
     * Launches the resident credentials management activity.
     */
    private void launchCredentialManagement(byte[] pinHash) {
        Log.i(TAG, "Launching ResidentCredentialsActivity for passkey management");
        Intent intent = new Intent(getApplicationContext(), ResidentCredentialsActivity.class);
        intent.putExtra("passkey_file", selectedPasskeyFile.getAbsolutePath());
        intent.putExtra("passkey", pinHash);
        intent.putExtra("file", selectedPasskeyFile.getName());
        startActivity(intent);
    }

    
    /**
     * Shows the credential offer notification with collapsible details.
     * Only shows if there is an actual credential offer (flow_type is FLOW_TYPE_ISSUANCE).
     */
    private void showCredentialOfferNotification(Intent intent) {
        if (credentialOfferNotification == null) {
            Log.w(TAG, "Credential offer notification view not found in layout");
            return;
        }
        
        // Extract intent data
        String credentialOfferUri = intent.getStringExtra("credential_offer_uri");
        if (credentialOfferUri == null) {
            Log.w(TAG, "No credential offer URI in intent");
            return;
        }
        
        long receivedAtMillis = intent.getLongExtra("received_at_millis", System.currentTimeMillis());
        String credentialType = intent.getStringExtra("credential_type");
        String issuerName = intent.getStringExtra("issuer_name");
        String issuerUrl = intent.getStringExtra("issuer_url");
        
        // Parse and validate credential offer
        currentOffer = parseCredentialOfferFromUri(credentialOfferUri, receivedAtMillis);
        if (currentOffer == null) {
            return; // Parsing failed, already logged
        }
        
        if (currentOffer.isExpired()) {
            Log.i(TAG, "Credential offer has expired, not showing notification");
            hideCredentialOfferNotification();
            Toast.makeText(this, "Credential offer has expired", Toast.LENGTH_LONG).show();
            return;
        }
        
        // Update UI with offer details
        updateOfferNotificationUI(credentialType, issuerName, issuerUrl);
        
        // Set up expand/collapse functionality
        setupOfferExpandCollapse();
        
        // Show the notification (initially collapsed)
        credentialOfferNotification.setVisibility(View.VISIBLE);
        offerDetails.setVisibility(View.GONE);
        isOfferExpanded = false;
        
        // Start expiration countdown
        startExpirationCountdown();
        
        Log.i(TAG, "Showing credential offer notification");
    }
    
    /**
     * Parses a credential offer URI and creates a CredentialOffer object.
     *
     * @param credentialOfferUri The URI containing the credential offer
     * @param receivedAtMillis The timestamp when the offer was received
     * @return CredentialOffer object or null if parsing fails
     */
    private CredentialOffer parseCredentialOfferFromUri(String credentialOfferUri, long receivedAtMillis) {
        try {
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
            
            return new CredentialOffer(offerMap, receivedAtMillis);
            
        } catch (Exception e) {
            Log.e(TAG, "Failed to parse credential offer", e);
            return null;
        }
    }
    
    /**
     * Updates the credential offer notification UI with offer details.
     *
     * @param credentialType The type of credential being offered
     * @param issuerName The name of the issuer
     * @param issuerUrl The URL of the issuer
     */
    private void updateOfferNotificationUI(String credentialType, String issuerName, String issuerUrl) {
        // Format and set credential type
        String formattedType = formatCredentialType(credentialType);
        credentialTypeText.setText("Type: " + formattedType);
        
        // Set issuer information
        if (issuerName != null && !issuerName.isEmpty()) {
            issuerNameText.setText("From: " + issuerName);
        } else if (issuerUrl != null && !issuerUrl.isEmpty()) {
            issuerNameText.setText("From: " + issuerUrl);
        } else {
            issuerNameText.setText("From: Unknown Issuer");
        }
    }
    
    /**
     * Formats a credential type string for display.
     * Converts camelCase to space-separated words.
     *
     * @param credentialType The raw credential type string
     * @return Formatted credential type or default value
     */
    private String formatCredentialType(String credentialType) {
        if (credentialType != null && !credentialType.isEmpty()) {
            return credentialType.replaceAll("([A-Z])", " $1").trim();
        }
        return "Digital Credential";
    }
    
    /**
     * Sets up the expand/collapse functionality for the credential offer notification.
     */
    private void setupOfferExpandCollapse() {
        if (offerHeader == null || expandButton == null) {
            return;
        }
        
        View.OnClickListener toggleListener = v -> {
            isOfferExpanded = !isOfferExpanded;
            if (isOfferExpanded) {
                offerDetails.setVisibility(View.VISIBLE);
                expandButton.setRotation(180); // Rotate icon to indicate expanded state
            } else {
                offerDetails.setVisibility(View.GONE);
                expandButton.setRotation(0); // Reset icon rotation
            }
        };
        
        offerHeader.setOnClickListener(toggleListener);
        expandButton.setOnClickListener(toggleListener);
    }
    
    /**
     * Hides the credential offer notification.
     * Called when user proceeds with passkey selection.
     */
    private void hideCredentialOfferNotification() {
        stopExpirationCountdown();
        currentOffer = null;
        if (credentialOfferNotification != null) {
            credentialOfferNotification.setVisibility(View.GONE);
        }
    }
    
    /**
     * Starts the expiration countdown timer that updates the UI every second.
     */
    private void startExpirationCountdown() {
        stopExpirationCountdown();
        
        if (currentOffer == null || expirationIndicator == null) {
            return;
        }
        
        expirationUpdateRunnable = new Runnable() {
            @Override
            public void run() {
                updateExpirationDisplay();
                if (currentOffer != null && !currentOffer.isExpired()) {
                    expirationHandler.postDelayed(this, 1000);
                }
            }
        };
        
        expirationHandler.post(expirationUpdateRunnable);
    }
    
    /**
     * Stops the expiration countdown timer.
     */
    private void stopExpirationCountdown() {
        if (expirationHandler != null && expirationUpdateRunnable != null) {
            expirationHandler.removeCallbacks(expirationUpdateRunnable);
            expirationUpdateRunnable = null;
        }
    }


    /**
     * Formats the remaining time in a human-readable format.
     * @param remainingSeconds The number of seconds remaining
     * @return Formatted time string (e.g., "5m 30s" or "45s")
     */
    private String formatRemainingTime(long remainingSeconds) {
        if (remainingSeconds >= SECONDS_PER_MINUTE) {
            long minutes = remainingSeconds / SECONDS_PER_MINUTE;
            long seconds = remainingSeconds % SECONDS_PER_MINUTE;
            return String.format("%dm %ds", minutes, seconds);
        }
        return String.format("%ds", remainingSeconds);
    }

    /**
     * Validates whether the expiration display can be updated.
     * Handles null checks and expired offer scenarios.
     * @return true if display can be updated, false otherwise
     */
    private boolean canUpdateExpirationDisplay() {
        if (currentOffer == null || expirationIndicator == null) {
            return false;
        }
        
        if (currentOffer.isExpired()) {
            hideCredentialOfferNotification();
            Toast.makeText(this, "Credential offer has expired", Toast.LENGTH_SHORT).show();
            return false;
        }
        
        Long remainingSeconds = currentOffer.getRemainingSeconds();
        if (remainingSeconds == null) {
            hideExpirationIndicators();
            return false;
        }
        
        return true;
    }

    /**
     * Hides all expiration indicator UI elements.
     */
    private void hideExpirationIndicators() {
        expirationIndicator.setVisibility(View.GONE);
        if (trafficLightCollapsed != null) {
            trafficLightCollapsed.setVisibility(View.GONE);
        }
    }

    /**
     * Applies the expiration status to all UI elements.
     * @param status The expiration status containing color and text information
     * @param timeText The formatted time remaining text
     */
    private void applyExpirationUI(ExpirationStatus status, String timeText) {
        expirationIndicator.setVisibility(View.VISIBLE);
        
        // Update main traffic light
        trafficLight.setTextColor(status.getColor());
        
        // Update collapsed traffic light indicator
        if (trafficLightCollapsed != null) {
            trafficLightCollapsed.setVisibility(View.VISIBLE);
            trafficLightCollapsed.setTextColor(status.getColor());
        }
        
        // Update expiration text
        expirationText.setText(status.getStatusText() + timeText);
        expirationText.setTextColor(status.getColor());
    }

    
    /**
     * Updates the expiration display with traffic light indicator and countdown.
     * This method orchestrates the display update by delegating to helper methods.
     */
    private void updateExpirationDisplay() {
        if (!canUpdateExpirationDisplay()) {
            return;
        }
        
        Long remainingSeconds = currentOffer.getRemainingSeconds();
        Long totalSeconds = currentOffer.getExpiresIn();
        if (totalSeconds == null) {
            totalSeconds = DEFAULT_EXPIRATION_SECONDS;
        }
        
        double percentRemaining = (double) remainingSeconds / totalSeconds;
        ExpirationStatus status = ExpirationStatus.fromPercentRemaining(percentRemaining);
        String timeText = formatRemainingTime(remainingSeconds);
        
        applyExpirationUI(status, timeText);
    }
    
    /**
     * Checks if the credential offer in the current intent has expired.
     * If expired, hides the notification and shows a toast message.
     */
    private void checkAndHideExpiredOffer() {
        Intent intent = getIntent();
        String flowType = intent.getStringExtra("flow_type");
        
        if (!FLOW_TYPE_ISSUANCE.equals(flowType)) {
            return;
        }
        
        String credentialOfferUri = intent.getStringExtra("credential_offer_uri");
        if (credentialOfferUri == null) {
            return;
        }
        
        if (isOfferExpired(credentialOfferUri)) {
            Log.i(TAG, "Credential offer has expired, hiding notification");
            hideCredentialOfferNotification();
            
            // Only show toast if notification was actually visible
            if (credentialOfferNotification != null &&
                credentialOfferNotification.getVisibility() == View.VISIBLE) {
                Toast.makeText(this, "Credential offer has expired", Toast.LENGTH_SHORT).show();
            }
        }
    }
    
    /**
     * Checks if a credential offer URI represents an expired offer.
     *
     * @param credentialOfferUri The credential offer URI to check
     * @return true if the offer is expired, false otherwise
     */
    private boolean isOfferExpired(String credentialOfferUri) {
        try {
            CredentialOffer offer = CredentialOffer.fromUri(credentialOfferUri);
            return offer.isExpired();
        } catch (OidcException e) {
            Log.e(TAG, "Failed to parse credential offer for expiration check", e);
            return false;
        }
    }
    
    /**
     * Parses a query string into a map of parameters.
     * Helper method for parsing credential offer URIs.
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
