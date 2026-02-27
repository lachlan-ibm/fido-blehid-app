 /*
 * Copyright IBM 2025
 */
package com.isfs.blekey;

import android.os.Bundle;
import android.view.View;
import android.content.Intent;
import androidx.appcompat.app.AppCompatActivity;
import android.view.View.OnClickListener;
import androidx.appcompat.app.AppCompatDelegate;
import android.util.Log;
import android.widget.Toast;

import android.widget.Button;

import com.isfs.blekey.activity.ManageActivity;
import com.isfs.blekey.activity.ServerActivity;
import com.isfs.blekey.data.Passkey;


/**
 * Main entry point for the BLE HID Passkey application.
 * This activity provides a simple user interface with a toggle button
 * that launches the PasskeyActivity when clicked.
 */
public class MainActivity extends AppCompatActivity {

    private static final String TAG = "MainActivity";

    /**
     * Initializes the activity, sets up the UI and configures the toggle button
     * to launch the PasskeyActivity when clicked.
     *
     * @param savedInstanceState If the activity is being re-initialized after previously
     *                           being shut down, this contains the data it most recently
     *                           supplied in onSaveInstanceState(Bundle).
     */
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        // Hide the back button in the toolbar since this is the main activity
        findViewById(R.id.backButton).setVisibility(View.GONE);
        AppCompatDelegate.setCompatVectorFromResourcesEnabled(true);
        
        // Initialize the root key pair for passkey encryption
        initializeRootKeyPair();
        Button serverButton = findViewById(R.id.serverButton);
        serverButton.setOnClickListener(new OnClickListener() {
            /**
             * Called when the server button is clicked.
             * Launches the ServerActivity to start the BLE HID service.
             *
             * @param view The view that was clicked (the button)
             */
            @Override
            public void onClick(View view) {
                startActivity(new Intent(getApplicationContext(), ServerActivity.class));
            }
        });
        
        Button manageButton = findViewById(R.id.manageButton);
        manageButton.setOnClickListener(new OnClickListener() {
            /**
             * Called when the manage button is clicked.
             * Launches the ManageActivity to manage Passkeys which are stored on this device.
             *
             * @param view The view that was clicked (the button)
             */
            @Override
            public void onClick(View view) {
                Intent intent = new Intent(getApplicationContext(), ManageActivity.class);
                // Add any necessary flags to ensure proper activity launch
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                startActivity(intent);
            }
        });
    }
    
    /**
     * Initializes the root key pair needed for passkey encryption.
     * This should be done once when the app starts.
     */
    private void initializeRootKeyPair() {
        try {
            // Set FIDO2_HOME to the app's files directory if not set
            String fido2Home = System.getProperty("FIDO2_HOME");
            if (fido2Home == null) {
                fido2Home = getFilesDir().getAbsolutePath();
                System.setProperty("FIDO2_HOME", fido2Home);
                Log.i(TAG, "Set FIDO2_HOME to: " + fido2Home);
            }
            
            // Get the platform key path
            String platformKeyPath = fido2Home +
                                    java.nio.file.FileSystems.getDefault().getSeparator() + "platform.key";
            
            // Initialize the root key pair using the public method
            Passkey.ensureRootKeyPair(platformKeyPath, null);
            
            Log.i(TAG, "Root key pair initialized successfully");

        } catch (Exception e) {
            Log.e(TAG, "Failed to initialize root key pair", e);
            Toast.makeText(this, "Failed to initialize platform key: " + e.getMessage(), Toast.LENGTH_SHORT).show();
        }
    }
}
