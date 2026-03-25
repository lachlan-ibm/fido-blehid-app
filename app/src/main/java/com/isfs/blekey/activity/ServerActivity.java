/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.activity;

import com.isfs.blekey.BootReceiver;
import com.isfs.blekey.hidsvc.HIDService;
import com.isfs.blekey.hidsvc.HIDForegroundService;

import androidx.appcompat.widget.SwitchCompat;
import android.widget.CompoundButton;
import android.content.SharedPreferences;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;

import com.isfs.blekey.R;

import android.annotation.SuppressLint;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothProfile;
import android.Manifest;
import android.content.ComponentName;
import android.content.Context;
import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.content.DialogInterface.OnDismissListener;
import android.content.ServiceConnection;
import android.os.Build;
import android.os.Bundle;
import android.os.IBinder;
import android.util.Log;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AlertDialog.Builder;

import com.isfs.blekey.util.FileUtils;
import com.isfs.blekey.hidsvc.DeviceStateManager;
import com.isfs.blekey.MainActivity;

/**
 * Activity responsible for managing the BLE HID passkey service.
 * This activity checks for Bluetooth availability and compatibility,
 * then initializes and manages the HIDService GATT server for
 * BLE passkey functionality.
 */
public class ServerActivity extends AppCompatActivity {

    private final String TAG = ServerActivity.class.getCanonicalName();

    /** Device connection status values. */
    private enum DeviceStatus {
        DISCONNECTED,
        CONNECTED,
        HID_ENUMERATED,
        HID_ACTIVE,
        ERROR
    }

    /** Holds display name and current status for a BT device. */
    private static class DeviceItem {
        final String name;
        DeviceStatus status;

        DeviceItem(String name, DeviceStatus status) {
            this.name = name;
            this.status = status;
        }
    }

    /** Custom adapter that renders device_list_item rows with status colour. */
    private class DeviceListAdapter extends BaseAdapter {

        private final List<DeviceItem> items;
        private final LayoutInflater inflater;

        DeviceListAdapter(List<DeviceItem> items) {
            this.items = items;
            this.inflater = LayoutInflater.from(ServerActivity.this);
        }

        @Override public int getCount() { return items.size(); }
        @Override public DeviceItem getItem(int pos) { return items.get(pos); }
        @Override public long getItemId(int pos) { return pos; }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            if (convertView == null) {
                convertView = inflater.inflate(R.layout.device_list_item, parent, false);
            }
            DeviceItem item = items.get(position);

            TextView nameView = convertView.findViewById(R.id.deviceNameText);
            TextView statusView = convertView.findViewById(R.id.deviceStatusText);
            View statusBar = convertView.findViewById(R.id.deviceStatusBar);

            nameView.setText(item.name);

            switch (item.status) {
                case HID_ACTIVE:
                    statusView.setText(getString(R.string.device_active));
                    statusView.setTextColor(getColor(R.color.device_connected));
                    statusBar.setBackgroundColor(getColor(R.color.device_connected));
                    break;
                case HID_ENUMERATED:
                    statusView.setText(getString(R.string.device_discovered));
                    statusView.setTextColor(getColor(android.R.color.holo_orange_light));
                    statusBar.setBackgroundColor(getColor(android.R.color.holo_orange_light));
                    break;
                case CONNECTED:
                    statusView.setText(getString(R.string.device_status_connected));
                    statusView.setTextColor(getColor(R.color.device_connected));
                    statusBar.setBackgroundColor(getColor(R.color.device_connected));
                    break;
                case ERROR:
                    statusView.setText(getString(R.string.device_status_error));
                    statusView.setTextColor(getColor(R.color.device_error));
                    statusBar.setBackgroundColor(getColor(R.color.device_error));
                    break;
                default:
                    statusView.setText(getString(R.string.device_status_disconnected));
                    statusView.setTextColor(getColor(R.color.device_disconnected));
                    statusBar.setBackgroundColor(getColor(R.color.device_disconnected));
                    break;
            }
            return convertView;
        }
    }

    /** ConnectionListener implementation as a named inner class. */
    private class PasskeyConnectionListener implements HIDService.ConnectionListener {

        @Override
        @SuppressLint("MissingPermission")
        public void onDeviceConnected(BluetoothDevice device) {
            final String addr = device.getAddress();
            final String name = getDisplayName(device);
            runOnUiThread(() -> {
                upsertDevice(addr, name, DeviceStatus.CONNECTED);
                saveDeviceState(addr, name, DeviceStatus.CONNECTED);
                appendLog(getString(R.string.log_device_connected, name));
            });
        }

        @Override
        @SuppressLint("MissingPermission")
        public void onDeviceDisconnected(BluetoothDevice device) {
            final String addr = device.getAddress();
            final String name = getDisplayName(device);
            runOnUiThread(() -> {
                upsertDevice(addr, name, DeviceStatus.DISCONNECTED);
                saveDeviceState(addr, name, DeviceStatus.DISCONNECTED);
                appendLog(getString(R.string.log_device_disconnected, name));
            });
        }

        @Override
        @SuppressLint("MissingPermission")
        public void onDeviceError(BluetoothDevice device) {
            final String addr = device.getAddress();
            final String name = getDisplayName(device);
            runOnUiThread(() -> {
                upsertDevice(addr, name, DeviceStatus.ERROR);
                saveDeviceState(addr, name, DeviceStatus.ERROR);
                appendLog("[ERROR] " + name);
            });
        }

        @Override
        @SuppressLint("MissingPermission")
        public void onHidServiceEnumerated(BluetoothDevice device) {
            final String addr = device.getAddress();
            final String name = getDisplayName(device);
            runOnUiThread(() -> {
                upsertDevice(addr, name, DeviceStatus.HID_ENUMERATED);
                saveDeviceState(addr, name, DeviceStatus.HID_ENUMERATED);
                appendLog(name + ": HID service discovered");
            });
        }

        @Override
        @SuppressLint("MissingPermission")
        public void onHidServiceActive(BluetoothDevice device) {
            final String addr = device.getAddress();
            final String name = getDisplayName(device);
            runOnUiThread(() -> {
                upsertDevice(addr, name, DeviceStatus.HID_ACTIVE);
                saveDeviceState(addr, name, DeviceStatus.HID_ACTIVE);
                appendLog(name + ": HID ready for input");
            });
        }
    }

    /**
     * The HID service instance that provides passkey functionality over BLE.
     */
    private HIDService passkeyService;
    
    /**
     * Reference to the bound foreground service.
     */
    private HIDForegroundService foregroundService;
    private boolean serviceBound = false;
    
    /**
     * Manager for persistent device state storage.
     */
    private DeviceStateManager stateManager;

    /**
     * Reconciles device states by comparing persisted state with current BT state.
     * This ensures UI shows accurate state even after app/service restarts.
     */
    @SuppressLint("MissingPermission")
    private void reconcileDeviceStates() {
        if (passkeyService == null || stateManager == null) return;
        
        // Load persisted states
        Map<String, DeviceStateManager.DeviceState> persistedStates = stateManager.loadAllDeviceStates();
        
        // Get currently connected devices
        final BluetoothManager bluetoothManager = (BluetoothManager) getSystemService(BLUETOOTH_SERVICE);
        final List<BluetoothDevice> connectedDevices = bluetoothManager.getConnectedDevices(BluetoothProfile.GATT);
        Set<String> connectedAddresses = new HashSet<>();
        
        // Update connected devices with their HID state
        for (BluetoothDevice device : connectedDevices) {
            String addr = device.getAddress();
            connectedAddresses.add(addr);
            String name = getDisplayName(device);
            
            // Check HID state from service
            HIDService.HidEnumerationState hidState = passkeyService.getHidState(addr);
            DeviceStatus status = mapHidStateToDeviceStatus(hidState);
            
            upsertDevice(addr, name, status);
            saveDeviceState(addr, name, status);
            appendLog("Reconciled " + name + ": " + status);
        }
        
        // Mark disconnected devices
        for (Map.Entry<String, DeviceStateManager.DeviceState> entry : persistedStates.entrySet()) {
            if (!connectedAddresses.contains(entry.getKey())) {
                DeviceStateManager.DeviceState state = entry.getValue();
                upsertDevice(state.address, state.name, DeviceStatus.DISCONNECTED);
                state.btState = DeviceStateManager.BtState.DISCONNECTED;
                state.hidState = DeviceStateManager.HidState.NOT_ENUMERATED;
                stateManager.saveDeviceState(state.address, state);
                appendLog("Reconciled " + state.name + ": DISCONNECTED");
            }
        }
    }
    
    /**
     * Maps HID enumeration state to DeviceStatus.
     */
    private DeviceStatus mapHidStateToDeviceStatus(HIDService.HidEnumerationState hidState) {
        switch (hidState) {
            case ACTIVE:
                return DeviceStatus.HID_ACTIVE;
            case ENUMERATED:
                return DeviceStatus.HID_ENUMERATED;
            case NOT_ENUMERATED:
            default:
                return DeviceStatus.CONNECTED;
        }
    }
    
    /**
     * Saves device state to persistent storage.
     */
    private void saveDeviceState(String address, String name, DeviceStatus status) {
        if (stateManager == null) return;
        
        DeviceStateManager.BtState btState;
        DeviceStateManager.HidState hidState;
        
        switch (status) {
            case HID_ACTIVE:
                btState = DeviceStateManager.BtState.CONNECTED;
                hidState = DeviceStateManager.HidState.ACTIVE;
                break;
            case HID_ENUMERATED:
                btState = DeviceStateManager.BtState.CONNECTED;
                hidState = DeviceStateManager.HidState.ENUMERATED;
                break;
            case CONNECTED:
                btState = DeviceStateManager.BtState.CONNECTED;
                hidState = DeviceStateManager.HidState.NOT_ENUMERATED;
                break;
            case ERROR:
                btState = DeviceStateManager.BtState.ERROR;
                hidState = DeviceStateManager.HidState.NOT_ENUMERATED;
                break;
            case DISCONNECTED:
            default:
                btState = DeviceStateManager.BtState.DISCONNECTED;
                hidState = DeviceStateManager.HidState.NOT_ENUMERATED;
                break;
        }
        
        DeviceStateManager.DeviceState state = new DeviceStateManager.DeviceState(address, name, btState, hidState);
        stateManager.saveDeviceState(address, state);
    }
    
    /**
     * Service connection for binding to HIDForegroundService.
     */
    private final ServiceConnection serviceConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            Log.d(TAG, "Service connected");
            HIDForegroundService.LocalBinder binder = (HIDForegroundService.LocalBinder) service;
            foregroundService = binder.getService();
            serviceBound = true;
            
            passkeyService = foregroundService.getHidService();
            if (passkeyService != null) {
                passkeyService.setConnectionListener(new PasskeyConnectionListener());
                appendLog(getString(R.string.log_advertising_started));
                populateBondedDevices();
                reconcileDeviceStates();
            }
        }
        
        @Override
        public void onServiceDisconnected(ComponentName name) {
            Log.d(TAG, "Service disconnected");
            serviceBound = false;
            foregroundService = null;
            passkeyService = null;
        }
    };

    private final ActivityResultLauncher<Intent> enableBtLauncher = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            result -> {
                if (!HIDService.isBluetoothEnabled(this)) {
                    Toast.makeText(this, R.string.requires_bl_enabled, Toast.LENGTH_LONG).show();
                    return;
                }
                if (!HIDService.isBleSupported(this) || !HIDService.isBlePeripheralSupported(this)) {
                    showUXForNotPermitted();
                } else {
                    setupPasskeyPeripheralProvider();
                }
            });

    /** Flag to track if the Create Passkey button was clicked */
    private boolean createPasskeyClicked = false;

    // UI references
    private ListView devicesList;
    private TextView noDevicesText;
    private TextView activityLogText;
    private TextView bleDeviceNameText;
    private SwitchCompat autoStartSwitch;

    /** Ordered map: device address -> DeviceItem, preserves insertion order. */
    private final Map<String, DeviceItem> deviceMap = new LinkedHashMap<>();
    private final List<DeviceItem> deviceItems = new ArrayList<>();
    private DeviceListAdapter devicesAdapter;

    private final StringBuilder activityLog = new StringBuilder();
    private final SimpleDateFormat logTimeFmt = new SimpleDateFormat("HH:mm:ss", Locale.getDefault());

    /**
     * Initializes the activity and checks for Bluetooth availability and compatibility.
     */
    @Override
    protected void onCreate(final Bundle savedInstanceState) {
        Log.d(TAG, "onCreate");
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_server);

        devicesList = findViewById(R.id.devicesList);
        noDevicesText = findViewById(R.id.noDevicesText);
        activityLogText = findViewById(R.id.activityLogText);
        bleDeviceNameText = findViewById(R.id.bleDeviceNameText);
        autoStartSwitch = findViewById(R.id.autoStartSwitch);
        updateBleDeviceNameDisplay();

        devicesAdapter = new DeviceListAdapter(deviceItems);
        devicesList.setAdapter(devicesAdapter);

        // Initialize state manager
        stateManager = new DeviceStateManager(this);

        setupAutoStartSwitch();

        findViewById(R.id.backButton).setOnClickListener(view -> {
            unbindFromService();
            finish();
        });

        updatePermissionFlags();
        if (CONNECT_GRANTED == true && ADVERTISE_GRANTED == true) {
            Log.d(TAG, "Already have all required permissions, checking BT state");
            checkBluetoothAndStart();
        } else {
            Log.d(TAG, "Need to request permissions first");
            askForPermissions();
        }
    }

    /**
     * Checks Bluetooth state and BLE peripheral support, then starts the service.
     */
    private void checkBluetoothAndStart() {
        if (!HIDService.isBluetoothEnabled(this)) {
            Log.d(TAG, "Bluetooth is not enabled, requesting user to enable it");
            enableBtLauncher.launch(new Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE));
            return;
        }

        if (!HIDService.isBleSupported(this) || !HIDService.isBlePeripheralSupported(this)) {
            Log.d(TAG, "BLE peripheral mode not supported");
            showUXForNotPermitted();
            return;
        }

        setupPasskeyPeripheralProvider();
    }

    private void showUXForNotPermitted() {
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
    }

    /**
     * Flow-control entry point: checks for passkeys then starts the foreground service.
     */
    public void setupPasskeyPeripheralProvider() {
        if (noPasskeysExist()) {
            showNoPasskeysDialog();
            return;
        }
        startHIDForegroundService();
    }

    /**
     * Starts the HID foreground service and binds to it.
     */
    private void startHIDForegroundService() {
        Intent serviceIntent = new Intent(this, HIDForegroundService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(serviceIntent);
        } else {
            startService(serviceIntent);
        }
        
        if (autoStartSwitch != null && autoStartSwitch.isChecked()) {
            BootReceiver.enableAutoStart(this);
        }
        bindService(serviceIntent, serviceConnection, Context.BIND_AUTO_CREATE);
    }
    
    /**
     * Stops the HID foreground service.
     */
    private void stopHIDForegroundService() {
        unbindFromService();
        BootReceiver.disableAutoStart(this);
        Intent serviceIntent = new Intent(this, HIDForegroundService.class);
        stopService(serviceIntent);
        appendLog("Service stopped");
    }
    
    /**
     * Unbinds from the foreground service.
     */
    private void unbindFromService() {
        if (serviceBound) {
            unbindService(serviceConnection);
            serviceBound = false;
            foregroundService = null;
            passkeyService = null;
        }
    }
    
    /**
     * Populates the device list from OS-bonded BLE devices.
     */
    @SuppressLint("MissingPermission")
    private void populateBondedDevices() {
        if (passkeyService == null) return;
        
        final BluetoothManager bluetoothManager = 
                (BluetoothManager) getSystemService(BLUETOOTH_SERVICE);
        final BluetoothAdapter adapter = bluetoothManager.getAdapter();
        
        // Get currently connected GATT devices
        final List<BluetoothDevice> connectedDevices = 
                bluetoothManager.getConnectedDevices(BluetoothProfile.GATT);
        
        for (BluetoothDevice device : passkeyService.getBondedBleDevices(adapter)) {
            // Check if device is currently connected
            DeviceStatus status = connectedDevices.contains(device) 
                    ? DeviceStatus.CONNECTED 
                    : DeviceStatus.DISCONNECTED;
            upsertDevice(device.getAddress(), getDisplayName(device), status);
        }
    }

    /**
     * Populates the device name TextView with the Bluetooth adapter's advertised name.
     */
    @SuppressLint("MissingPermission")
    private void updateBleDeviceNameDisplay() {
        if (bleDeviceNameText == null) return;
        try {
            final android.bluetooth.BluetoothAdapter adapter =
                    ((android.bluetooth.BluetoothManager) getSystemService(BLUETOOTH_SERVICE)).getAdapter();
            String name = (adapter != null) ? adapter.getName() : null;
            if (name == null || name.isEmpty()) name = getString(R.string.ble_beekey);
            bleDeviceNameText.setText(getString(R.string.device_name_label, name));
        } catch (SecurityException e) {
            bleDeviceNameText.setText(getString(R.string.ble_beekey));
        }
    }

    /**
     * Resolves a human-readable display name for a BT device.
     */
    @SuppressLint("MissingPermission")
    private String getDisplayName(BluetoothDevice device) {
        String name = device.getName();
        return (name != null && !name.isEmpty()) ? name : device.getAddress();
    }

    /**
     * Inserts or updates a device entry and refreshes the list.
     */
    private void upsertDevice(String address, String displayName, DeviceStatus status) {
        DeviceItem existing = deviceMap.get(address);
        if (existing != null) {
            existing.status = status;
        } else {
            DeviceItem item = new DeviceItem(displayName, status);
            deviceMap.put(address, item);
            deviceItems.add(item);
        }
        devicesAdapter.notifyDataSetChanged();
        updateDeviceVisibility();
    }

    /**
     * Checks if any passkeys exist in the FIDO2_HOME directory.
     */
    private boolean noPasskeysExist() {
        File appDataDir = getFilesDir();
        System.setProperty("FIDO2_HOME", appDataDir.getAbsolutePath());
        return FileUtils.listPasskeys() == null || FileUtils.listPasskeys().isEmpty();
    }

    /**
     * Stops the passkey service and navigates back to MainActivity.
     */
    private void stopServiceAndReturnToMain() {
        stopHIDForegroundService();
        Intent mainIntent = new Intent(getApplicationContext(), MainActivity.class);
        mainIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(mainIntent);
        finish();
    }

    private void onCreatePasskeyClicked(DialogInterface dialog) {
        createPasskeyClicked = true;
        Intent intent = new Intent(ServerActivity.this, ManageActivity.class);
        startActivity(intent);
        dialog.dismiss();
        finish();
    }

    private void onCancelClicked(DialogInterface dialog) {
        Log.d(TAG, "Cancel button clicked, shutting down and returning to main activity");
        dialog.dismiss();
        stopServiceAndReturnToMain();
    }

    private void onDialogDismissed(DialogInterface dialog) {
        if (isFinishing() || createPasskeyClicked) {
            Log.d(TAG, "Dialog dismissed but activity is already finishing or create passkey was clicked");
            return;
        }
        Log.d(TAG, "Dialog dismissed without button click, shutting down and returning to main activity");
        stopServiceAndReturnToMain();
    }

    private void showNoPasskeysDialog() {
        final AlertDialog alertDialog = new Builder(this).create();
        alertDialog.setTitle(getString(R.string.no_passkeys));
        alertDialog.setMessage(getString(R.string.create_passkey_first));
        alertDialog.setButton(AlertDialog.BUTTON_POSITIVE, getString(R.string.create_passkey),
                (dialog, which) -> onCreatePasskeyClicked(dialog));
        alertDialog.setButton(AlertDialog.BUTTON_NEGATIVE, getString(R.string.cancel),
                (dialog, which) -> onCancelClicked(dialog));
        alertDialog.setOnDismissListener(dialog -> onDialogDismissed(dialog));
        alertDialog.show();
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        Log.d(TAG, "onRequestPermissionsResult");
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);

        if (requestCode == REQUEST_CODE_BLUETOOTH_CONNECT) {
            processPermissionsResults(permissions, grantResults);

            if (CONNECT_GRANTED == true && ADVERTISE_GRANTED == true) {
                Log.d(TAG, "Got all required permissions, checking BT state");
                checkBluetoothAndStart();
            } else {
                Log.d(TAG, "Permission denied: CONNECT=" + CONNECT_GRANTED + ", ADVERTISE=" + ADVERTISE_GRANTED);
                final AlertDialog alertDialog = new Builder(this).create();
                alertDialog.setTitle(getString(R.string.not_supported));
                alertDialog.setMessage(getString(R.string.ble_not_permitted));
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
            }
        }
    }

    public static final int REQUEST_CODE_BLUETOOTH_CONNECT = 0xb1e;

    private static Boolean CONNECT_GRANTED = null;
    private static Boolean ADVERTISE_GRANTED = null;

    private void processPermissionsResults(String[] permissions, int[] grantResults) {
        for (int i = 0; i < permissions.length; i++) {
            if (permissions[i].equals(Manifest.permission.BLUETOOTH_CONNECT)) {
                CONNECT_GRANTED = (grantResults[i] == PackageManager.PERMISSION_GRANTED);
                if (CONNECT_GRANTED) Log.d(TAG, "Have BLUETOOTH_CONNECT permission");
            } else if (permissions[i].equals(Manifest.permission.BLUETOOTH_ADVERTISE)) {
                ADVERTISE_GRANTED = (grantResults[i] == PackageManager.PERMISSION_GRANTED);
                if (ADVERTISE_GRANTED) Log.d(TAG, "Have BLUETOOTH_ADVERTISE permission");
            }
        }
    }

    private void updatePermissionFlags() {
        CONNECT_GRANTED = ContextCompat.checkSelfPermission(this,
                Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED;
        if (CONNECT_GRANTED) Log.d(TAG, "Have BLUETOOTH_CONNECT permission");

        ADVERTISE_GRANTED = ContextCompat.checkSelfPermission(this,
                Manifest.permission.BLUETOOTH_ADVERTISE) == PackageManager.PERMISSION_GRANTED;
        if (ADVERTISE_GRANTED) Log.d(TAG, "Have BLUETOOTH_ADVERTISE permission");
    }

    private void askForPermissions() {
        updatePermissionFlags();

        if (CONNECT_GRANTED == true && ADVERTISE_GRANTED == true) {
            Log.d(TAG, "Have all required Bluetooth permissions, start it up!");
            return;
        }

        if (!CONNECT_GRANTED &&
                ActivityCompat.shouldShowRequestPermissionRationale(this, Manifest.permission.BLUETOOTH_CONNECT)) {
            Log.d(TAG, "Can't do anything without BLUETOOTH_CONNECT permission");
            Toast.makeText(this, getString(R.string.ble_not_permitted), Toast.LENGTH_SHORT).show();
            finish();
            return;
        }

        try {
            Log.d(TAG, "Asking for Bluetooth permissions");
            List<String> permissionsToRequest = new ArrayList<>();
            if (!CONNECT_GRANTED) permissionsToRequest.add(Manifest.permission.BLUETOOTH_CONNECT);
            if (!ADVERTISE_GRANTED) permissionsToRequest.add(Manifest.permission.BLUETOOTH_ADVERTISE);

            if (!permissionsToRequest.isEmpty()) {
                requestPermissions(permissionsToRequest.toArray(new String[0]), REQUEST_CODE_BLUETOOTH_CONNECT);
            }
        } catch (Exception e) {
            Log.e(TAG, "Error asking for Bluetooth permissions", e);
        }
    }

    /**
     * Updates the visibility of the devices list vs the "no devices" placeholder.
     */
    private void updateDeviceVisibility() {
        if (deviceItems.isEmpty()) {
            noDevicesText.setVisibility(View.VISIBLE);
            devicesList.setVisibility(View.GONE);
        } else {
            noDevicesText.setVisibility(View.GONE);
            devicesList.setVisibility(View.VISIBLE);
        }
    }

    /**
     * Appends a timestamped entry to the activity log TextView.
     */
    private void appendLog(String message) {
        String entry = "[" + logTimeFmt.format(new Date()) + "] " + message + "\n";
        activityLog.append(entry);
        if (activityLogText != null) {
            activityLogText.setText(activityLog.toString());
        }
    }

    /**
     * Sets up the auto-start toggle switch.
     */
    private void setupAutoStartSwitch() {
        if (autoStartSwitch == null) return;
        
        SharedPreferences prefs = getSharedPreferences("HIDServicePrefs", Context.MODE_PRIVATE);
        boolean autoStartEnabled = prefs.getBoolean("auto_start_enabled", true);
        autoStartSwitch.setChecked(autoStartEnabled);
        
        autoStartSwitch.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                if (isChecked) {
                    BootReceiver.enableAutoStart(ServerActivity.this);
                    appendLog("Auto-start enabled");
                } else {
                    BootReceiver.disableAutoStart(ServerActivity.this);
                    appendLog("Auto-start disabled");
                }
            }
        });
    }

    /**
     * Called when the activity returns to the foreground.
     * Reconciles device states to handle changes that occurred while in background
     * (e.g., device unpaired, disconnected, etc.)
     */
    @Override
    protected void onResume() {
        super.onResume();
        Log.d(TAG, "onResume - reconciling device states");
        
        // Only reconcile if service is bound and ready
        if (serviceBound && passkeyService != null && stateManager != null) {
            reconcileDeviceStates();
        }
    }

    /**
     * Cleans up resources when the activity is destroyed.
     */
    @Override
    protected void onDestroy() {
        super.onDestroy();
        unbindFromService();
    }
}

// Made with Bob