/*
 * Copyright IBM 2025
 */
package com.isfs.blekey;

import android.app.Application;
import androidx.appcompat.app.AppCompatDelegate;

/**
 * Custom Application class for the BLE HID Passkey application.
 * Handles app-wide initialization and configuration.
 */
public class AyeBleKeyApplication extends Application {

    @Override
    public void onCreate() {
        super.onCreate();
        
        // Enable vector drawable support for AppCompat
        // This only needs to be set once for the entire application
        AppCompatDelegate.setCompatVectorFromResourcesEnabled(true);
    }
}

// Made with Bob
