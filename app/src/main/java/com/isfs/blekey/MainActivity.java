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

import android.widget.ToggleButton;

import com.isfs.blekey.activity.ManageActivity;
import com.isfs.blekey.activity.ServerActivity;



/**
 * Main entry point for the BLE HID Passkey application.
 * This activity provides a simple user interface with a toggle button
 * that launches the PasskeyActivity when clicked.
 */
public class MainActivity extends AppCompatActivity {

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
        setTitle(getString(R.string.ble_hid));
        AppCompatDelegate.setCompatVectorFromResourcesEnabled(true);
        ToggleButton serverButton = findViewById(R.id.serverButton);
        serverButton.setOnClickListener(new OnClickListener() {
            /**
             * Called when the toggle button is clicked.
             * Launches the PasskeyActivity to start the BLE HID service.
             *
             * @param view The view that was clicked (the toggle button)
             */
            @Override
            public void onClick(View view) {
                startActivity(new Intent(getApplicationContext(), ServerActivity.class));
            }
        });
        ToggleButton manageButton = findViewById(R.id.manageButton);
        manageButton.setOnClickListener(new OnClickListener() {
            /**
             * Called when the toggle button is clicked.
             * Launches the ManageActivity to manage Passkeys which are stored on this device.
             *
             * @param view The view that was clicked (the toggle button)
             */
            @Override
            public void onClick(View view) {
                startActivity(new Intent(getApplicationContext(), ManageActivity.class));
            }
        });
    }
}
