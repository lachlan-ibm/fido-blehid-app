package com.isfs.blekey;


import android.os.Bundle;
import android.view.View;
import android.content.Intent;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.app.AppCompatDelegate;
import android.view.View.OnClickListener;

import android.widget.ToggleButton;

import java.util.Collections;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        setTitle(getString(R.string.ble_hid));
        //AppCompatDelegate.setCompatVectorFromResourcesEnabled(true);
        ToggleButton serverButton = findViewById(R.id.serverButton);
        serverButton.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View view) {
                startActivity(new Intent(getApplicationContext(), PasskeyActivity.class));
            }
        });
    }
}

