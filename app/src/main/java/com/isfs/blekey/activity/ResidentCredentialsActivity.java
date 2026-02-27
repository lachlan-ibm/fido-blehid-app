package com.isfs.blekey.activity;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.View.OnClickListener;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ListView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import android.widget.Toast;

import com.isfs.blekey.R;
import com.isfs.blekey.data.Passkey;
import java.io.File;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Activity for managing resident credentials stored on the device.
 * This activity displays a list of available credentials and allows the user
 * to select and manage them.
 */
public class ResidentCredentialsActivity extends AppCompatActivity {
    
    private static final String TAG = ResidentCredentialsActivity.class.getCanonicalName();
    
    // Passkey related fields
    private byte[] passwordHash;
    private String fileName;
    private Passkey passkey;
    
    /**
     * Inner class to represent a credential with both display string and raw data
     */
    private static class Credential {
        private final String displayName;
        private final byte[] rpId;
        
        public Credential(String displayName, byte[] rpId) {
            this.displayName = displayName;
            this.rpId = rpId;
        }
        
        public String getDisplayName() {
            return displayName;
        }
        
        public byte[] getRpId() {
            return rpId;
        }
        
        @Override
        public String toString() {
            // This is what will be displayed in the ListView
            return displayName;
        }
    }

    /**
     * Custom adapter for displaying credentials in the ListView
     */
    private class CredentialAdapter extends ArrayAdapter<Credential> {
        
        public CredentialAdapter(Context context, List<Credential> credentials) {
            super(context, android.R.layout.simple_list_item_activated_1, credentials);
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            // Get the credential item for this position
            Credential credential = getItem(position);
            
            // Check if an existing view is being reused, otherwise inflate the view
            if (convertView == null) {
                convertView = LayoutInflater.from(getContext()).inflate(
                    android.R.layout.simple_list_item_activated_1, parent, false);
            }
            
            // Lookup view for data population
            TextView text = (TextView) convertView.findViewById(android.R.id.text1);
            
            // Populate the data into the template view using the credential object
            text.setText(credential.getDisplayName());
            
            // Return the completed view to render on screen
            return convertView;
        }
    }
    
    private ListView credentialsList;
    private Button deleteButton;
    private TextView noCredentialsText;
    
    private List<Credential> credentials = new ArrayList<>();
    private int selectedPosition = -1;
    
    @Override
    protected void onCreate(final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_resident_credentials);
        
        // Get passkey file path and password hash from intent
        Intent intent = getIntent();
        if (intent != null) {
            passwordHash = intent.getByteArrayExtra("passkey");
            fileName = intent.getStringExtra("file");
        }
        
        // Set up back button in toolbar
        findViewById(R.id.backButton).setOnClickListener(view -> finish());
        
        // Change title to "Manage Credentials"
        TextView credentialsDescription = findViewById(R.id.credentialsDescription);
        credentialsDescription.setText(R.string.manage_credentials);
        
        // Initialize UI components
        credentialsList = findViewById(R.id.credentialsList);
        deleteButton = findViewById(R.id.deleteButton);
        noCredentialsText = findViewById(R.id.noCredentialsText);
        
        // Show manage button and rename it to "Delete"
        deleteButton.setText(R.string.delete);
        deleteButton.setVisibility(View.VISIBLE);
        
        // Set up the credentials list
        loadCredentials();
        
        // Set up list item selection listener
        credentialsList.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                selectedPosition = position;
                deleteButton.setEnabled(true);
            }
        });
        
        // Set up delete button click listener (previously manage button)
        deleteButton.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View view) {
                if (selectedPosition >= 0 && selectedPosition < credentials.size()) {
                    deleteCredential(credentials.get(selectedPosition).getRpId());
                }
            }
        });
    }

    private void updateCredentialsFromPasskeyFile() {
        credentials.clear();
        try {
            // Get the passkey file from the file name
            if (fileName != null && passwordHash != null) {
                // In Android, we should use the app's data directory
                File appDataDir = getFilesDir();
                System.setProperty("FIDO2_HOME", appDataDir.getAbsolutePath());
                
                // Find the passkey file
                File passkeyFile = new File(appDataDir, fileName);
                
                // Open the passkey with the password hash
                passkey = Passkey.openKey(passwordHash, passkeyFile);
                
                if (passkey != null) {
                    // Get resident credentials from the passkey
                    List<Map<String, byte[]>> resCreds = passkey.getResCreds();
                    
                    if (resCreds != null && !resCreds.isEmpty()) {
                        for (Map<String, byte[]> cred : resCreds) {
                            try {
                                String rpIdStr = new String(cred.get("rp.id"), "UTF-8");
                                credentials.add(new Credential("Credential: " + rpIdStr, cred.get("rp.id")));
                            } catch (UnsupportedEncodingException e) {
                                credentials.add(new Credential("Credential: [Encoding Error]", cred.get("rp.id")));
                            }
                        }
                    } else {
                        Log.i(TAG, "No resident credentials found in passkey");
                    }
                } else {
                    Log.e(TAG, "Failed to open passkey");
                    Toast.makeText(this, "Failed to open passkey", Toast.LENGTH_SHORT).show();
                }
            } else {
                Log.e(TAG, "Missing fileName or passwordHash");
                Toast.makeText(this, "Missing passkey information", Toast.LENGTH_SHORT).show();
            }
        } catch (Exception e) {
            Log.e(TAG, "Error loading credentials", e);
            Toast.makeText(this, "Error loading credentials: " + e.getMessage(), Toast.LENGTH_SHORT).show();
        }
    }

    /**
     * Loads the list of credentials from the passkey storage.
     */
    private void loadCredentials() {

        updateCredentialsFromPasskeyFile();

        // Update the UI based on whether credentials were found
        if (credentials.isEmpty()) {
            credentialsList.setVisibility(View.GONE);
            noCredentialsText.setVisibility(View.VISIBLE);
            noCredentialsText.setText("No credentials found");
            deleteButton.setEnabled(false);
        } else {
            // Use our custom adapter instead of the standard ArrayAdapter
            CredentialAdapter adapter = new CredentialAdapter(this, credentials);
            credentialsList.setAdapter(adapter);
            credentialsList.setVisibility(View.VISIBLE);
            noCredentialsText.setVisibility(View.GONE);
            deleteButton.setEnabled(selectedPosition >= 0);
        }
    }
    
    /**
     * Deletes the selected credential from the passkey.
     *
     * @param rpId The relying party ID of the credential to delete
     */
    private void deleteCredential(byte[] rpId) {
        if (passkey != null) {
            try {
                boolean removed = passkey.removeResidentCredential(rpId);
                if (removed) {
                    // Save the passkey back to the file using writeKey method
                    File appDataDir = getFilesDir();
                    File passkeyFile = new File(appDataDir, fileName);
                    Passkey.writeKey(passkey, passwordHash, passkeyFile);
                    
                    // Show success message
                    String rpIdStr = new String(rpId, "UTF-8");
                    Toast.makeText(this, "Credential deleted: " + rpIdStr, Toast.LENGTH_SHORT).show();
                    
                    // Reload the credentials list
                    loadCredentials();
                } else {
                    Toast.makeText(this, "Failed to delete credential", Toast.LENGTH_SHORT).show();
                }
            } catch (Exception e) {
                Log.e(TAG, "Error deleting credential", e);
                Toast.makeText(this, "Error deleting credential: " + e.getMessage(), Toast.LENGTH_SHORT).show();
            }
        } else {
            Toast.makeText(this, "Passkey not available", Toast.LENGTH_SHORT).show();
        }
    }
}

// Made with Bob
