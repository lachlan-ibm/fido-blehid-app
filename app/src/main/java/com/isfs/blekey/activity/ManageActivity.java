package com.isfs.blekey.activity;

import android.content.Intent;
import android.os.Bundle;
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

import androidx.appcompat.app.AppCompatActivity;

import com.isfs.blekey.R;
import com.isfs.blekey.data.Passkey;
import com.isfs.blekey.util.FileUtils;
import com.isfs.blekey.util.KeyUtils;

import java.io.File;

/**
 * Activity for managing passkeys.
 * This activity displays a list of available passkeys and allows the user
 * to select and manage them after entering the correct password.
 */
public class ManageActivity extends AppCompatActivity {
    
    private static final String TAG = ManageActivity.class.getCanonicalName();
    private TextView credentialInfo;
    private Button manageButton;
    private Button deleteButton;
    private Button createButton;
    
    // Passkeys list components
    private ListView passkeysListView;
    private TextView noPasskeysText;
    private LinearLayout passkeysListSection;
    
    // Password protection components
    private EditText passwordInput;
    private Button unlockButton;
    private TextView passwordError;
    private LinearLayout passwordSection;
    private LinearLayout credentialOptionsSection;
    
    private String rpId;
    private File selectedPasskeyFile;
    private int selectedPosition = -1;
    
    @Override
    protected void onCreate(final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_manage);
        
        // Set background color explicitly to ensure visibility
        findViewById(android.R.id.content).setBackgroundColor(android.graphics.Color.WHITE);
        
        // Set up the custom toolbar
        setupToolbar();
        
        initializeUIComponents();
        loadPasskeys();
        setupEventListeners();
    }
    
    /**
     * Called when the activity is resumed.
     * This is where we should refresh the passkeys list to show any newly created passkeys.
     */
    @Override
    protected void onResume() {
        super.onResume();
        // Reset UI state to show passkeys list and hide password section
        if (passwordSection != null && passwordSection.getVisibility() == View.VISIBLE) {
            showPasskeysList();
            // Clear password input and error
            if (passwordInput != null) {
                passwordInput.setText("");
            }
            if (passwordError != null) {
                passwordError.setVisibility(View.GONE);
            }
        }
        // Reload passkeys to refresh the list
        loadPasskeys();
    }
    
    /**
     * Handles the hardware back button press.
     * Uses the same logic as the toolbar back button.
     */
    @Override
    public void onBackPressed() {
        handleBackNavigation();
    }
    
    /**
     * Sets up the custom toolbar with back button functionality.
     */
    private void setupToolbar() {
        // Find the back button in the custom toolbar
        ImageButton backButton = findViewById(R.id.backButton);
        if (backButton != null) {
            // Set click listener to handle back navigation
            backButton.setOnClickListener(v -> handleBackNavigation());
        }
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
        
        // Initialize password protection components
        passwordInput = findViewById(R.id.passwordInput);
        unlockButton = findViewById(R.id.unlockButton);
        passwordError = findViewById(R.id.passwordError);
        passwordSection = findViewById(R.id.passwordSection);
        credentialOptionsSection = findViewById(R.id.credentialOptionsSection);
    }
    
    /**
     * Extracts the relying party ID from a passkey filename.
     * Removes the .passkey extension if present.
     *
     * @param filename The passkey filename
     * @return The extracted relying party ID
     */
    private String extractRpIdFromFilename(String filename) {
        return filename.endsWith(".passkey") ?
               filename.substring(0, filename.length() - 8) : filename;
    }
    
    /**
     * Shows the password section and hides the passkeys list.
     */
    private void showPasswordSection() {
        passkeysListSection.setVisibility(View.GONE);
        passwordSection.setVisibility(View.VISIBLE);
        
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
            
            // Extract rpId from filename
            String filename = selectedPasskeyFile.getName();
            rpId = extractRpIdFromFilename(filename);
            
            // Show passkey details but don't show password section yet
            credentialInfo.setText("Selected passkey: " + rpId);
            
            // Make sure the manage and delete buttons are visible
            manageButton.setVisibility(View.VISIBLE);
            deleteButton.setVisibility(View.VISIBLE);
            
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
                Toast.makeText(this, getString(R.string.no_passkey_selected), Toast.LENGTH_SHORT).show();
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
                Toast.makeText(this, getString(R.string.no_passkey_selected), Toast.LENGTH_SHORT).show();
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
            Toast.makeText(this, getString(R.string.no_passkey_selected), Toast.LENGTH_SHORT).show();
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
     * Validates the entered password and shows/hides UI elements accordingly.
     * Uses SHA-256 to hash the password (full 32 bytes)
     * to attempt to decrypt the passkey file.
     */
    private void validatePassword() {
        String enteredPassword = passwordInput.getText().toString();
        byte[] pinHash = KeyUtils.getPinHash(enteredPassword);
        
        // Try to decrypt the passkey file
        Passkey passkey = Passkey.openKey(pinHash, selectedPasskeyFile);
        
        if (passkey != null) {
            // Password is correct
            Toast.makeText(this, getString(R.string.credential_unlocked), Toast.LENGTH_SHORT).show();
            
            // Hide keyboard before launching new activity
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
            
            // Launch ResidentCredentialsActivity directly
            Intent intent = new Intent(getApplicationContext(), ResidentCredentialsActivity.class);
            intent.putExtra("passkey_file", selectedPasskeyFile.getAbsolutePath());
            // Pass the password hash to allow decrypting the passkey file
            intent.putExtra("passkey", pinHash);
            intent.putExtra("file", selectedPasskeyFile.getName());
            startActivity(intent);
        } else {
            // Password is incorrect, show error message
            passwordError.setText(getString(R.string.incorrect_password));
            passwordError.setVisibility(View.VISIBLE);
            passwordInput.setText("");
        }
    }
}

// Made with Bob
