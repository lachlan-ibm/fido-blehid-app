/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.activity;

import com.isfs.blekey.BootReceiver;
import com.isfs.blekey.hidsvc.BTHIDService;
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
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.IBinder;
import android.provider.Settings;
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
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AlertDialog.Builder;

import com.isfs.blekey.util.FileUtils;
import com.isfs.blekey.hidsvc.DeviceStateManager;
import com.isfs.blekey.MainActivity;

/**
 * Activity responsible for managing the Bluetooth HID passkey service.
 * This activity checks for Bluetooth availability and compatibility,
 * then initializes and manages the classic Bluetooth HID service for
 * passkey functionality.
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
    private class PasskeyConnectionListener implements BTHIDService.ConnectionListener {

        @Override
        public void onDeviceConnected(BluetoothDevice device) {
            if (!hasBluetoothConnectPermission()) {
                Log.w(TAG, "BLUETOOTH_CONNECT permission not granted in onDeviceConnected");
                return;
            }
            
            final String addr = device.getAddress();
            final String name = getDisplayName(device);
            runOnUiThread(() -> {
                upsertDevice(addr, name, DeviceStatus.CONNECTED);
                saveDeviceState(addr, name, DeviceStatus.CONNECTED);
                appendLog(getString(R.string.log_device_connected, name));
                
                // Initiate HID connection after Bluetooth profile connection
                if (passkeyService != null) {
                    appendLog("Requesting HID connection to " + name);
                    boolean success = passkeyService.connect(device);
                    if (!success) {
                        appendLog("Failed to request HID connection to " + name);
                    }
                }
            });
        }

        @Override
        public void onDeviceDisconnected(BluetoothDevice device) {
            if (!hasBluetoothConnectPermission()) {
                Log.w(TAG, "BLUETOOTH_CONNECT permission not granted in onDeviceDisconnected");
                return;
            }
            
            final String addr = device.getAddress();
            final String name = getDisplayName(device);
            runOnUiThread(() -> {
                upsertDevice(addr, name, DeviceStatus.DISCONNECTED);
                saveDeviceState(addr, name, DeviceStatus.DISCONNECTED);
                appendLog(getString(R.string.log_device_disconnected, name));
            });
        }

        @Override
        public void onDeviceError(BluetoothDevice device) {
            if (!hasBluetoothConnectPermission()) {
                Log.w(TAG, "BLUETOOTH_CONNECT permission not granted in onDeviceError");
                return;
            }
            
            final String addr = device.getAddress();
            final String name = getDisplayName(device);
            runOnUiThread(() -> {
                upsertDevice(addr, name, DeviceStatus.ERROR);
                saveDeviceState(addr, name, DeviceStatus.ERROR);
                appendLog("[ERROR] " + name);
            });
        }

        @Override
        public void onHidServiceEnumerated(BluetoothDevice device) {
            if (!hasBluetoothConnectPermission()) {
                Log.w(TAG, "BLUETOOTH_CONNECT permission not granted in onHidServiceEnumerated");
                return;
            }
            
            final String addr = device.getAddress();
            final String name = getDisplayName(device);
            runOnUiThread(() -> {
                upsertDevice(addr, name, DeviceStatus.HID_ENUMERATED);
                saveDeviceState(addr, name, DeviceStatus.HID_ENUMERATED);
                appendLog(name + ": HID service discovered");
            });
        }

        @Override
        public void onHidServiceActive(BluetoothDevice device) {
            if (!hasBluetoothConnectPermission()) {
                Log.w(TAG, "BLUETOOTH_CONNECT permission not granted in onHidServiceActive");
                return;
            }
            
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
     * The HID service instance that provides passkey functionality over classic Bluetooth.
     */
    private BTHIDService passkeyService;
    
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
     * Also removes devices that are no longer bonded at the OS level.
     */
    private void reconcileDeviceStates() {
        if (passkeyService == null || stateManager == null) return;
        
        if (!hasBluetoothConnectPermission()) {
            Log.w(TAG, "BLUETOOTH_CONNECT permission not granted, cannot reconcile device states");
            return;
        }
        
        try {
            // Load persisted states
            Map<String, DeviceStateManager.DeviceState> persistedStates = stateManager.loadAllDeviceStates();
            
            // Get currently bonded Bluetooth devices at OS level
            final BluetoothManager bluetoothManager = (BluetoothManager) getSystemService(BLUETOOTH_SERVICE);
            final Set<BluetoothDevice> bondedDevices = passkeyService.getBondedDevices();
            Set<String> bondedAddresses = new HashSet<>();
            for (BluetoothDevice device : bondedDevices) {
                bondedAddresses.add(device.getAddress());
            }
            
            // Get currently connected devices
            List<BluetoothDevice> connectedDevices = new ArrayList<>();
            boolean canQueryHidProfile = true;
            try {
                connectedDevices = bluetoothManager.getConnectedDevices(BluetoothProfile.HID_DEVICE);
            } catch (IllegalArgumentException e) {
                Log.w(TAG, "HID_DEVICE profile query not supported on this device", e);
                canQueryHidProfile = false;
            }
            Set<String> connectedAddresses = new HashSet<>();
            
            // Update connected devices with their HID state
            for (BluetoothDevice device : connectedDevices) {
                String addr = device.getAddress();
                connectedAddresses.add(addr);
                String name = getDisplayName(device);
                
                BTHIDService.HidDeviceState hidState = passkeyService.getDeviceState(addr);
                DeviceStatus status = mapHidStateToDeviceStatus(hidState);
                
                upsertDevice(addr, name, status);
                saveDeviceState(addr, name, status);
                appendLog("Reconciled " + name + ": " + status);
            }
            
            // If we can't query the HID profile, check bonded devices via service state
            if (!canQueryHidProfile) {
                for (BluetoothDevice device : bondedDevices) {
                    String addr = device.getAddress();
                    if (connectedAddresses.contains(addr)) {
                        continue;
                    }
                    
                    BTHIDService.HidDeviceState hidState = passkeyService.getDeviceState(addr);
                    if (hidState != BTHIDService.HidDeviceState.DISCONNECTED) {
                        connectedAddresses.add(addr);
                        String name = getDisplayName(device);
                        DeviceStatus status = mapHidStateToDeviceStatus(hidState);
                        
                        upsertDevice(addr, name, status);
                        saveDeviceState(addr, name, status);
                        appendLog("Reconciled (via service) " + name + ": " + status);
                    }
                }
            }
            
            // Process persisted devices
            for (Map.Entry<String, DeviceStateManager.DeviceState> entry : persistedStates.entrySet()) {
                String addr = entry.getKey();
                DeviceStateManager.DeviceState state = entry.getValue();
                
                if (!bondedAddresses.contains(addr)) {
                    removeDevice(addr);
                    stateManager.clearDeviceState(addr);
                    appendLog("Removed unbonded device: " + state.name);
                    continue;
                }
                
                if (!connectedAddresses.contains(addr)) {
                    upsertDevice(state.address, state.name, DeviceStatus.DISCONNECTED);
                    state.btState = DeviceStateManager.BtState.DISCONNECTED;
                    state.hidState = DeviceStateManager.HidState.NOT_ENUMERATED;
                    stateManager.saveDeviceState(state.address, state);
                    appendLog("Reconciled " + state.name + ": DISCONNECTED");
                }
            }
        } catch (SecurityException e) {
            Log.e(TAG, "SecurityException in reconcileDeviceStates", e);
            appendLog("Error: Permission denied while reconciling device states");
        }
    }
    
    /**
     * Maps HID device state to DeviceStatus.
     */
    private DeviceStatus mapHidStateToDeviceStatus(BTHIDService.HidDeviceState hidState) {
        switch (hidState) {
            case ACTIVE:
                return DeviceStatus.HID_ACTIVE;
            case REGISTERED:
                return DeviceStatus.HID_ENUMERATED;
            case CONNECTED:
            case CONNECTING:
            case DISCONNECTED:
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
                if (!BTHIDService.isBluetoothEnabled(this)) {
                    Toast.makeText(this, R.string.requires_bl_enabled, Toast.LENGTH_LONG).show();
                    return;
                }
                if (!BTHIDService.isClassicBTHIDSupported()) {
                    showUXForNotPermitted();
                } else {
                    setupPasskeyPeripheralProvider();
                }
            });

    private final ActivityResultLauncher<String> requestBluetoothConnectLauncher =
        registerForActivityResult(
            new ActivityResultContracts.RequestPermission(),
            isGranted -> {
                if (isGranted) {
                    Log.d(TAG, "BLUETOOTH_CONNECT permission granted");
                    CONNECT_GRANTED = true;
                    checkBluetoothAndStart();
                } else {
                    Log.d(TAG, "BLUETOOTH_CONNECT permission denied");
                    CONNECT_GRANTED = false;
                    showPermissionDeniedDialog();
                }
            }
        );

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
        setupRestartButton();

        findViewById(R.id.backButton).setOnClickListener(view -> {
            unbindFromService();
            finish();
        });
        
        // Set up home button to navigate to MainActivity
        findViewById(R.id.homeButton).setOnClickListener(view -> {
            Intent intent = new Intent(this, MainActivity.class);
            intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(intent);
            finish();
        });

        updatePermissionFlags();
        if (CONNECT_GRANTED == true) {
            Log.d(TAG, "Already have required permissions, checking BT state");
            checkBluetoothAndStart();
        } else {
            Log.d(TAG, "Need to request permissions first");
            askForPermissions();
        }
    }

    /**
     * Checks Bluetooth state and classic HID support, then starts the service.
     */
    private void checkBluetoothAndStart() {
        if (!BTHIDService.isBluetoothEnabled(this)) {
            Log.d(TAG, "Bluetooth is not enabled, requesting user to enable it");
            enableBtLauncher.launch(new Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE));
            return;
        }

        if (!BTHIDService.isClassicBTHIDSupported()) {
            Log.d(TAG, "Classic Bluetooth HID device mode not supported");
            showUXForNotPermitted();
            return;
        }

        setupPasskeyPeripheralProvider();
    }

    private void showUXForNotPermitted() {
        final AlertDialog alertDialog = new Builder(this).create();
        alertDialog.setTitle(getString(R.string.not_supported));
        alertDialog.setMessage(getString(R.string.device_not_supported, "Classic Bluetooth HID device mode"));
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
     * Sets up the restart service button click handler.
     */
    private void setupRestartButton() {
        View restartButton = findViewById(R.id.restartServiceButton);
        if (restartButton != null) {
            restartButton.setOnClickListener(view -> {
                appendLog("Restarting HID service...");
                restartHIDService();
            });
        }
    }

    /**
     * Restarts the HID service by stopping and starting it.
     */
    private void restartHIDService() {
        // Stop the service
        unbindFromService();
        Intent serviceIntent = new Intent(this, HIDForegroundService.class);
        stopService(serviceIntent);
        
        // Wait a moment then restart
        new android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(() -> {
            startHIDForegroundService();
            appendLog("HID service restarted");
            Toast.makeText(this, "HID Service Restarted", Toast.LENGTH_SHORT).show();
        }, 500);
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
     * Populates the device list from OS-bonded Bluetooth devices.
     */
    private void populateBondedDevices() {
        if (passkeyService == null) return;
        
        if (!hasBluetoothConnectPermission()) {
            Log.w(TAG, "BLUETOOTH_CONNECT permission not granted, cannot populate bonded devices");
            return;
        }
        
        try {
            final BluetoothManager bluetoothManager =
                    (BluetoothManager) getSystemService(BLUETOOTH_SERVICE);
            
            List<BluetoothDevice> connectedDevices = new ArrayList<>();
            try {
                connectedDevices = bluetoothManager.getConnectedDevices(BluetoothProfile.HID_DEVICE);
            } catch (IllegalArgumentException e) {
                Log.w(TAG, "HID_DEVICE profile query not supported on this device", e);
            }
            
            for (BluetoothDevice device : passkeyService.getBondedDevices()) {
                DeviceStatus status = connectedDevices.contains(device)
                        ? mapHidStateToDeviceStatus(passkeyService.getDeviceState(device.getAddress()))
                        : DeviceStatus.DISCONNECTED;
                upsertDevice(device.getAddress(), getDisplayName(device), status);
            }
        } catch (SecurityException e) {
            Log.e(TAG, "SecurityException in populateBondedDevices", e);
            appendLog("Error: Permission denied while loading bonded devices");
        }
    }

    /**
     * Populates the device name TextView with the Bluetooth adapter's advertised name.
     */
    private void updateBleDeviceNameDisplay() {
        if (bleDeviceNameText == null) return;
        
        if (!hasBluetoothConnectPermission()) {
            bleDeviceNameText.setText(getString(R.string.ble_beekey));
            return;
        }
        
        try {
            final android.bluetooth.BluetoothAdapter adapter =
                    ((android.bluetooth.BluetoothManager) getSystemService(BLUETOOTH_SERVICE)).getAdapter();
            String name = (adapter != null) ? adapter.getName() : null;
            if (name == null || name.isEmpty()) name = getString(R.string.ble_beekey);
            bleDeviceNameText.setText(getString(R.string.device_name_label, name));
        } catch (SecurityException e) {
            Log.e(TAG, "SecurityException getting adapter name", e);
            bleDeviceNameText.setText(getString(R.string.ble_beekey));
        }
    }

    /**
     * Resolves a human-readable display name for a BT device.
     * Returns the device address if permission is not granted or name is unavailable.
     */
    private String getDisplayName(BluetoothDevice device) {
        if (!hasBluetoothConnectPermission()) {
            Log.w(TAG, "BLUETOOTH_CONNECT permission not granted, using address");
            return device.getAddress();
        }
        
        try {
            String name = device.getName();
            return (name != null && !name.isEmpty()) ? name : device.getAddress();
        } catch (SecurityException e) {
            Log.e(TAG, "SecurityException getting device name", e);
            return device.getAddress();
        }
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
     * Removes a device from the UI list.
     */
    private void removeDevice(String address) {
        DeviceItem item = deviceMap.remove(address);
        if (item != null) {
            deviceItems.remove(item);
            devicesAdapter.notifyDataSetChanged();
            updateDeviceVisibility();
        }
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
        alertDialog.setTitle(getString(R.string.no_passkey_wallets));
        alertDialog.setMessage(getString(R.string.create_passkey_wallet_first));
        alertDialog.setButton(AlertDialog.BUTTON_POSITIVE, getString(R.string.create_passkey_wallet),
                (dialog, which) -> onCreatePasskeyClicked(dialog));
        alertDialog.setButton(AlertDialog.BUTTON_NEGATIVE, getString(R.string.cancel),
                (dialog, which) -> onCancelClicked(dialog));
        alertDialog.setOnDismissListener(dialog -> onDialogDismissed(dialog));
        alertDialog.show();
    }

    /**
     * Checks if BLUETOOTH_CONNECT permission is granted.
     * This should be called before any Bluetooth operation that requires the permission.
     *
     * @return true if permission is granted, false otherwise
     */
    private boolean hasBluetoothConnectPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            return ContextCompat.checkSelfPermission(this,
                Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED;
        }
        // On Android 11 and below, BLUETOOTH permission is sufficient
        return true;
    }

    private void showPermissionRationale() {
        new AlertDialog.Builder(this)
            .setTitle(R.string.bluetooth_permission_required)
            .setMessage(R.string.bluetooth_permission_rationale)
            .setPositiveButton(R.string.grant_permission, (dialog, which) -> {
                requestBluetoothConnectLauncher.launch(Manifest.permission.BLUETOOTH_CONNECT);
            })
            .setNegativeButton(R.string.cancel, (dialog, which) -> {
                dialog.dismiss();
                finish();
            })
            .show();
    }

    private void showPermissionDeniedDialog() {
        new AlertDialog.Builder(this)
            .setTitle(getString(R.string.not_supported))
            .setMessage(getString(R.string.bluetooth_not_permitted, "HID"))
            .setPositiveButton(R.string.open_settings, (dialog, which) -> {
                // Open app settings
                Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
                Uri uri = Uri.fromParts("package", getPackageName(), null);
                intent.setData(uri);
                startActivity(intent);
                finish();
            })
            .setNegativeButton(getString(R.string.ok), (dialog, which) -> {
                dialog.dismiss();
                finish();
            })
            .show();
    }

    private static Boolean CONNECT_GRANTED = null;

    private void updatePermissionFlags() {
        CONNECT_GRANTED = ContextCompat.checkSelfPermission(this,
                Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED;
        if (CONNECT_GRANTED) Log.d(TAG, "Have BLUETOOTH_CONNECT permission");
    }

    private void askForPermissions() {
        updatePermissionFlags();

        if (CONNECT_GRANTED == true) {
            Log.d(TAG, "Have required Bluetooth permissions, start it up!");
            return;
        }

        if (!CONNECT_GRANTED &&
                ActivityCompat.shouldShowRequestPermissionRationale(this,
                    Manifest.permission.BLUETOOTH_CONNECT)) {
            // Show rationale before requesting
            showPermissionRationale();
            return;
        }

        // Request permission using modern API
        Log.d(TAG, "Requesting BLUETOOTH_CONNECT permission");
        requestBluetoothConnectLauncher.launch(Manifest.permission.BLUETOOTH_CONNECT);
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