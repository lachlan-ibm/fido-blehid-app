package com.isfs.blekey.activity;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;
import android.view.ViewGroup;

import androidx.appcompat.app.AppCompatActivity;

import com.isfs.blekey.R;
import com.isfs.blekey.data.Passkey;
import com.isfs.blekey.util.FileUtils;
import com.isfs.blekey.util.KeyUtils;

import java.io.File;
import java.util.List;

/**
 * Activity for managing passkeys.
 * This activity displays a list of available passkeys and allows the user
 * to select and manage them after entering the correct password.
 */
public class ManageActivity extends AppCompatActivity {
    
    private TextView credentialInfo;
    private Button updateButton;
    private Button deleteButton;
    
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
    
    @Override
    protected void onCreate(final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_manage);
        
        initializeUIComponents();
        loadPasskeys();
        setupEventListeners();
    }
    
    /**
     * Initializes all UI components by finding views by ID.
     */
    private void initializeUIComponents() {
        // Initialize UI components
        credentialInfo = findViewById(R.id.credentialInfo);
        updateButton = findViewById(R.id.updateButton);
        deleteButton = findViewById(R.id.deleteButton);
        
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
    }
    
    /**
     * Shows the credential options section and hides the password section.
     */
    private void showCredentialOptions() {
        passwordSection.setVisibility(View.GONE);
        credentialOptionsSection.setVisibility(View.VISIBLE);
    }
    
    /**
     * Shows the passkeys list and hides other sections.
     */
    private void showPasskeysList() {
        passwordSection.setVisibility(View.GONE);
        credentialOptionsSection.setVisibility(View.GONE);
        passkeysListSection.setVisibility(View.VISIBLE);
    }
    
    /**
     * Sets up all event listeners.
     */
    private void setupEventListeners() {
        setupPasskeySelectionListener();
        setupUnlockButtonListener();
        setupUpdateButtonListener();
        setupDeleteButtonListener();
    }
    
    /**
     * Sets up the passkey selection listener.
     */
    private void setupPasskeySelectionListener() {
        passkeysListView.setOnItemClickListener((parent, view, position, id) -> {
            // Get the selected passkey file
            selectedPasskeyFile = (File) parent.getItemAtPosition(position);
            
            // Extract rpId from filename
            String filename = selectedPasskeyFile.getName();
            rpId = extractRpIdFromFilename(filename);
            
            // Show passkey details and password section
            credentialInfo.setText("Selected passkey: " + rpId);
            showPasswordSection();
            
            // Add back button functionality
            setupBackButton();
        });
    }
    
    /**
     * Sets up the unlock button click listener.
     */
    private void setupUnlockButtonListener() {
        unlockButton.setOnClickListener(view -> validatePassword());
    }
    
    /**
     * Sets up the update button click listener.
     */
    private void setupUpdateButtonListener() {
        updateButton.setOnClickListener(view -> {
            // Start the ResidentCredentialsActivity to manage resident credentials
            Intent intent = new Intent(getApplicationContext(), ResidentCredentialsActivity.class);
            intent.putExtra("passkey_file", selectedPasskeyFile.getAbsolutePath());
            startActivity(intent);
        });
    }
    
    /**
     * Sets up the delete button click listener.
     */
    private void setupDeleteButtonListener() {
        deleteButton.setOnClickListener(view -> {
            deleteCredential();
            // Return to the passkeys list
            showPasskeysList();
            loadPasskeys(); // Refresh the list
        });
    }
    
    /**
     * Sets up the back button functionality.
     */
    private void setupBackButton() {
        findViewById(android.R.id.home).setOnClickListener(v -> showPasskeysList());
    }
    
    /**
     * Loads and displays the list of available passkeys.
     */
    private void loadPasskeys() {
        List<File> passkeys = FileUtils.listPasskeys();
        
        if (passkeys == null || passkeys.isEmpty()) {
            // No passkeys found
            passkeysListView.setVisibility(View.GONE);
            noPasskeysText.setVisibility(View.VISIBLE);
        } else {
            // Display passkeys in the list
            // Create a custom adapter that displays the filename without extension
            ArrayAdapter<File> adapter = new ArrayAdapter<File>(
                this,
                android.R.layout.simple_list_item_1,
                passkeys) {
                    @Override
                    public View getView(int position, View convertView, ViewGroup parent) {
                        View view = super.getView(position, convertView, parent);
                        TextView text = (TextView) view.findViewById(android.R.id.text1);
                        
                        File file = getItem(position);
                        if (file != null) {
                            String filename = file.getName();
                            // Remove .passkey extension if present
                            text.setText(filename.endsWith(".passkey") ?
                                   filename.substring(0, filename.length() - 8) : filename);
                        }
                        return view;
                    }
                };
            
            passkeysListView.setAdapter(adapter);
            passkeysListView.setVisibility(View.VISIBLE);
            noPasskeysText.setVisibility(View.GONE);
        }
    }
    
    
    /**
     * Deletes the current credential.
     * This is a placeholder implementation that should be replaced with actual
     * credential deletion logic.
     */
    private void deleteCredential() {
        // TODO: Implement actual credential deletion logic
        // This would typically involve:
        // 1. Getting the current Passkey instance
        // 2. Removing the credential from the resident credentials map
        // 3. Saving the updated passkey
        
        Toast.makeText(this, "Deleting credential for: " + rpId, Toast.LENGTH_SHORT).show();
    }
    
    /**
     * Validates the entered password and shows/hides UI elements accordingly.
     * Uses SHA-256 to hash the password and extracts the lower 16 bytes
     * to attempt to decrypt the passkey file.
     */
    private void validatePassword() {
        String enteredPassword = passwordInput.getText().toString();
        byte[] lowerHash = KeyUtils.getLowerPinHash(enteredPassword);
        
        // Try to decrypt the passkey file
        Passkey passkey = Passkey.openKey(lowerHash, selectedPasskeyFile);
        
        if (passkey != null) {
            // Password is correct, show credential options
            showCredentialOptions();
            Toast.makeText(this, "Credential unlocked", Toast.LENGTH_SHORT).show();
        } else {
            // Password is incorrect, show error message
            passwordError.setText("Incorrect password. Please try again.");
            passwordError.setVisibility(View.VISIBLE);
            passwordInput.setText("");
        }
    }
}

// Made with Bob
