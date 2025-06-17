package com.isfs.blekey;

import com.isfs.blekey.hidsvc.HIDService;
import com.isfs.blekey.util.BleUtils;

import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.content.DialogInterface.OnDismissListener;
import android.os.Bundle;
import android.os.Handler;
import android.content.Intent;
import android.bluetooth.BluetoothManager;
import android.content.Context;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AlertDialog.Builder;
import android.widget.Toast;


import com.isfs.blekey.R;

public class PasskeyActivity extends AppCompatActivity {

    private HIDService passkeyService;
    
    @Override
    protected void onCreate(final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        if (!HIDService.isBluetoothEnabled(this)) {
            HIDService.enableBluetooth(this);
            return;
        }

        if (!HIDService.isBleSupported(this) || !HIDService.isBlePeripheralSupported(this)) {
            // display alert and exit
            final AlertDialog alertDialog = new Builder(this).create();
            alertDialog.setTitle(getString(R.string.not_supported));
            alertDialog.setMessage(getString(R.string.ble_perip_not_supported));
            alertDialog.setButton(AlertDialog.BUTTON_NEUTRAL, getString(R.string.ok),
                    new OnClickListener() {
                        @Override
                        public void onClick(final DialogInterface dialog, final int which) {
                            dialog.dismiss();
                        }
                    });
            alertDialog.setOnDismissListener(new OnDismissListener() {
                @Override
                public void onDismiss(final DialogInterface dialog) {
                    finish();
                }
            });
            alertDialog.show();
        } else {
            setupPasskeyPeripheralProvider();
        }
    }
    
    public void setupPasskeyPeripheralProvider() {
        //TODO start HIDService
        passkeyService = new HIDService(this);
        passkeyService.setDeviceName(getString(R.string.ble_beekey));
        passkeyService.startAdvertising();
    };

    @Override
    protected void onActivityResult(final int requestCode, final int resultCode, final Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if (requestCode == HIDService.REQUEST_CODE_BLUETOOTH_ENABLE) {
            if (!HIDService.isBluetoothEnabled(this)) {
                // User selected NOT to use Bluetooth.
                // do nothing
                Toast.makeText(this, R.string.requires_bl_enabled, Toast.LENGTH_LONG).show();
                return;
            }

            if (!HIDService.isBleSupported(this) || !HIDService.isBlePeripheralSupported(this)) {
                // display alert and exit
                final AlertDialog alertDialog = new Builder(this).create();
                alertDialog.setTitle(getString(R.string.not_supported));
                alertDialog.setMessage(getString(R.string.ble_perip_not_supported));
                alertDialog.setButton(AlertDialog.BUTTON_NEUTRAL, getString(R.string.ok),
                        new OnClickListener() {
                            @Override
                            public void onClick(final DialogInterface dialog, final int which) {
                                dialog.dismiss();
                            }
                        });
                alertDialog.setOnDismissListener(new OnDismissListener() {
                    @Override
                    public void onDismiss(final DialogInterface dialog) {
                        finish();
                    }
                });
                alertDialog.show();
            } else {
                setupPasskeyPeripheralProvider();
            }
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        
        if (passkeyService != null) {
            passkeyService.stopAdvertising();
        }
    }
}
