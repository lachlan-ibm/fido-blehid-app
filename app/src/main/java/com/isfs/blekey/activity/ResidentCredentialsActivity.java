package com.isfs.blekey.activity;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
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

import com.isfs.blekey.R;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;

/**
 * Activity for managing resident credentials stored on the device.
 * This activity displays a list of available credentials and allows the user
 * to select and manage them.
 */
public class ResidentCredentialsActivity extends AppCompatActivity {
    
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
    private Button manageButton;
    private TextView noCredentialsText;
    
    private List<Credential> credentials = new ArrayList<>();
    private int selectedPosition = -1;
    
    @Override
    protected void onCreate(final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_resident_credentials);
        
        // Initialize UI components
        credentialsList = findViewById(R.id.credentialsList);
        manageButton = findViewById(R.id.manageButton);
        noCredentialsText = findViewById(R.id.noCredentialsText);
        
        // Set up the credentials list
        loadCredentials();
        
        // Set up list item selection listener
        credentialsList.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                selectedPosition = position;
                manageButton.setEnabled(true);
            }
        });
        
        // Set up manage button click listener
        manageButton.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View view) {
                if (selectedPosition >= 0 && selectedPosition < credentials.size()) {
                    launchManageActivity(credentials.get(selectedPosition).getRpId());
                }
            }
        });
    }
    
    /**
     * Loads the list of credentials from the passkey storage.
     * This is a placeholder implementation that should be replaced with actual
     * credential loading logic from the Passkey class.
     */
    private void loadCredentials() {
        // TODO: Replace with actual credential loading from Passkey
        // This would typically involve:
        // 1. Getting the current Passkey instance
        // 2. Retrieving the resident credentials map
        // 3. Converting the credential data to display strings
        
        credentials.clear();
        
        // Example of how this would be implemented with real data:
        /*
        Passkey passkey = getCurrentPasskey();
        if (passkey != null) {
            Map<byte[], Map> resCreds = passkey.getResCreds();
            if (resCreds != null && !resCreds.isEmpty()) {
                for (byte[] rpId : resCreds.keySet()) {
                    try {
                        String rpIdStr = new String(rpId, "UTF-8");
                        credentials.add(new Credential("Credential: " + rpIdStr, rpId));
                    } catch (UnsupportedEncodingException e) {
                        credentials.add(new Credential("Credential: [Encoding Error]", rpId));
                    }
                }
            }
        }
        */
        
        // For demonstration, add some sample credentials
        // Remove this when implementing actual credential loading
        addSampleCredentials();
        
        // Update the UI based on whether credentials were found
        if (credentials.isEmpty()) {
            credentialsList.setVisibility(View.GONE);
            noCredentialsText.setVisibility(View.VISIBLE);
        } else {
            // Use our custom adapter instead of the standard ArrayAdapter
            CredentialAdapter adapter = new CredentialAdapter(this, credentials);
            credentialsList.setAdapter(adapter);
            credentialsList.setVisibility(View.VISIBLE);
            noCredentialsText.setVisibility(View.GONE);
        }
    }
    
    /**
     * Adds sample credentials for demonstration purposes.
     * This should be removed when implementing actual credential loading.
     */
    private void addSampleCredentials() {
        // Sample data for demonstration
        try {
            credentials.add(new Credential("Credential: example.com", "example.com".getBytes("UTF-8")));
            credentials.add(new Credential("Credential: login.service.com", "login.service.com".getBytes("UTF-8")));
            credentials.add(new Credential("Credential: secure-auth.example.org", "secure-auth.example.org".getBytes("UTF-8")));
        } catch (UnsupportedEncodingException e) {
            // This shouldn't happen with UTF-8
        }
    }
    
    /**
     * Launches the ManageActivity to manage the selected credential.
     *
     * @param rpId The relying party ID of the credential to manage
     */
    private void launchManageActivity(byte[] rpId) {
        try {
            String rpIdStr = new String(rpId, "UTF-8");
            Intent intent = new Intent(this, ManageActivity.class);
            intent.putExtra("rpId", rpIdStr);
            startActivity(intent);
        } catch (UnsupportedEncodingException e) {
            // Handle encoding error
        }
    }
}

// Made with Bob
