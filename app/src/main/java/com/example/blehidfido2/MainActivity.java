package com.example.blehidfido2;

import android.bluetooth.BluetoothDevice;
import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.app.AppCompatDelegate;
import com.welie.blessed.BluetoothCentral;
import com.welie.blessed.BluetoothPeripheralManager;
import com.welie.blessed.BluetoothPeripheralManagerCallback;

import android.widget.ToggleButton;

import java.util.Collections;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        setTitle(getString(string.ble_hid));
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

