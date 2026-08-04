/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.activity;

import com.isfs.blekey.BootReceiver;
import com.isfs.blekey.hidsvc.BTHIDService;
import com.isfs.blekey.hidsvc.HIDForegroundService;

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
import com.isfs.blekey.util.BiometricAuthHelper;
import com.isfs.blekey.hidsvc.DeviceStateManager;
import com.isfs.blekey.MainActivity;

import androidx.annotation.Nullable;

/**
 * Activity responsible for managing the Bluetooth HID passkey service.
 * This activity checks for Bluetooth availability and compatibility,
 * then initializes and manages the classic Bluetooth HID service for
 * passkey functionality.
 *
 * <p>UP state (pending context, keepalive, wake lock, timeout) is owned by
 * {@link HIDForegroundService}.  This activity is a pure UI responder: it
 * receives {@link HIDForegroundService.UpActivityDelegate#showUpDialog} on the
 * main thread, shows the dialog, and calls back via the service's
 * {@code deliverUp*()} methods.</p>
 */
public class ServerActivity extends AppCompatActivity
        implements HIDForegroundService.UpActivityDelegate,
                   HIDForegroundService.BiometricDelegate,
                   HIDForegroundService.CancelListener,
                   HIDForegroundService.TimeoutListener {

    private final String TAG = ServerActivity.class.getCanonicalName();

    /** Device connection status values. */
    private enum DeviceStatus {
        DISCONNECTED,
        CONNECTED,
        HID_ENUMERATED,
        HID_ACTIVE,
        ERROR
    }

    /** Holds display name, address, and current status for a BT device. */
    private static class DeviceItem {
        final String name;
        final String address;
        DeviceStatus status;

        DeviceItem(String name, String address, DeviceStatus status) {
            this.name = name;
            this.address = address;
            this.status = status;
        }
    }
    
    /** Holds the result of collecting current device states from Bluetooth system. */
    private static class DeviceCollectionResult {
        final Set<String> bondedAddresses;
        final Set<String> connectedAddresses;
        final List<BluetoothDevice> connectedDevices;
        final boolean canQueryHidProfile;
        
        DeviceCollectionResult(Set<String> bonded, Set<String> connected,
                              List<BluetoothDevice> devices, boolean canQuery) {
            this.bondedAddresses = bonded;
            this.connectedAddresses = connected;
            this.connectedDevices = devices;
            this.canQueryHidProfile = canQuery;
        }
    }

    /** Custom adapter that renders device_list_item rows with status colour. */
    private class DeviceListAdapter extends BaseAdapter {

        private final List<DeviceItem> items;
        private final LayoutInflater inflater;
        private final View.OnClickListener reconnectClickListener = new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                DeviceItem item = (DeviceItem) v.getTag();
                ServerActivity.this.handleReconnect(item.address, item.name);
            }
        };
        private final View.OnClickListener disconnectClickListener = new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                DeviceItem item = (DeviceItem) v.getTag();
                ServerActivity.this.handleDisconnect(item.address, item.name);
            }
        };

        DeviceListAdapter(List<DeviceItem> items) {
            this.items = items;
            this.inflater = LayoutInflater.from(ServerActivity.this);
        }

        @Override public int getCount() { return items.size(); }
        @Override public DeviceItem getItem(int pos) { return items.get(pos); }
        @Override public long getItemId(int pos) { return pos; }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            ViewHolder holder;
            if (convertView == null) {
                convertView = inflater.inflate(R.layout.device_list_item, parent, false);
                holder = new ViewHolder(convertView);
                convertView.setTag(holder);
            } else {
                holder = (ViewHolder) convertView.getTag();
            }

            DeviceItem item = items.get(position);
            holder.nameView.setText(item.name);

            switch (item.status) {
                case HID_ACTIVE:
                case HID_ENUMERATED:
                    setDeviceStatus(holder,
                        item.status == DeviceStatus.HID_ACTIVE ?
                            getString(R.string.device_active) : getString(R.string.device_discovered),
                        R.color.device_connected);
                    setButtonVisibility(holder, false, true);
                    holder.disconnectButton.setTag(item);
                    holder.disconnectButton.setOnClickListener(disconnectClickListener);
                    break;
                case CONNECTED:
                    setDeviceStatus(holder,
                        getString(R.string.device_status_connected),
                        R.color.device_connected);
                    setButtonVisibility(holder, false, false);
                    break;
                case ERROR:
                    setDeviceStatus(holder,
                        getString(R.string.device_status_error),
                        R.color.device_error);
                    setButtonVisibility(holder, true, false);
                    holder.reconnectButton.setTag(item);
                    holder.reconnectButton.setOnClickListener(reconnectClickListener);
                    break;
                default:
                    setDeviceStatus(holder,
                        getString(R.string.device_status_disconnected),
                        R.color.device_disconnected);
                    setButtonVisibility(holder, true, false);
                    holder.reconnectButton.setTag(item);
                    holder.reconnectButton.setOnClickListener(reconnectClickListener);
                    break;
            }
            return convertView;
        }

        private void setDeviceStatus(ViewHolder holder, String statusText, int colorResId) {
            holder.statusView.setText(statusText);
            int color = getColor(colorResId);
            holder.statusView.setTextColor(color);
            holder.statusBar.setBackgroundColor(color);
        }

        private void setButtonVisibility(ViewHolder holder, boolean showReconnect, boolean showDisconnect) {
            holder.reconnectButton.setVisibility(showReconnect ? View.VISIBLE : View.GONE);
            holder.disconnectButton.setVisibility(showDisconnect ? View.VISIBLE : View.GONE);
        }

        /** ViewHolder pattern to cache view lookups. */
        private static class ViewHolder {
            final TextView nameView;
            final TextView statusView;
            final View statusBar;
            final android.widget.Button reconnectButton;
            final android.widget.Button disconnectButton;

            ViewHolder(View view) {
                nameView = view.findViewById(R.id.deviceNameText);
                statusView = view.findViewById(R.id.deviceStatusText);
                statusBar = view.findViewById(R.id.deviceStatusBar);
                reconnectButton = view.findViewById(R.id.reconnectButton);
                disconnectButton = view.findViewById(R.id.disconnectButton);
            }
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
                updateBtStatusIcon();
                
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
                updateBtStatusIcon();
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
                updateBtStatusIcon();
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
                updateBtStatusIcon();
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
                updateBtStatusIcon();
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

    // -------------------------------------------------------------------------
    // User Presence — UI-only state (all pending state lives in HIDForegroundService)
    // -------------------------------------------------------------------------

    private boolean isInForeground = false;
    private AlertDialog userPresenceDialog = null;

    /** Used to show biometric prompts for TEE-gated platform key operations. */
    private BiometricAuthHelper biometricHelper;

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
            Map<String, DeviceStateManager.DeviceState> persistedStates = stateManager.loadAllDeviceStates();
            BluetoothManager bluetoothManager = (BluetoothManager) getSystemService(BLUETOOTH_SERVICE);
            
            // Collect current device states from Bluetooth system
            DeviceCollectionResult devices = collectCurrentDevices(bluetoothManager);
            
            // Reconcile connected devices
            reconcileConnectedDevices(devices.connectedDevices, devices.connectedAddresses);
            
            // Reconcile bonded devices if HID profile query not supported
            if (!devices.canQueryHidProfile) {
                reconcileBondedDevicesViaService(
                    passkeyService.getBondedDevices(),
                    devices.connectedAddresses
                );
            }
            
            // Reconcile persisted devices
            reconcilePersistedDevices(
                persistedStates,
                devices.bondedAddresses,
                devices.connectedAddresses
            );
            
        } catch (SecurityException e) {
            Log.e(TAG, "SecurityException in reconcileDeviceStates", e);
            appendLog("Error: Permission denied while reconciling device states");
        }
    }
    
    /**
     * Helper method to reconcile and persist a device's state.
     * Combines upsert, save, and logging operations.
     */
    private void reconcileAndPersistDevice(String address, String name, DeviceStatus status, String logPrefix) {
        upsertDevice(address, name, status);
        saveDeviceState(address, name, status);
        appendLog(logPrefix + name + ": " + status);
    }
    
    /**
     * Collects current device states from the Bluetooth system.
     * Returns bonded devices, connected devices, and HID profile query capability.
     */
    private DeviceCollectionResult collectCurrentDevices(BluetoothManager bluetoothManager) {
        Set<BluetoothDevice> bondedDevices = passkeyService.getBondedDevices();
        Set<String> bondedAddresses = new HashSet<>();
        for (BluetoothDevice device : bondedDevices) {
            bondedAddresses.add(device.getAddress());
        }
        
        List<BluetoothDevice> connectedDevices = new ArrayList<>();
        boolean canQueryHidProfile = true;
        try {
            connectedDevices = bluetoothManager.getConnectedDevices(BluetoothProfile.HID_DEVICE);
        } catch (IllegalArgumentException e) {
            Log.w(TAG, "HID_DEVICE profile query not supported on this device", e);
            canQueryHidProfile = false;
        }
        
        Set<String> connectedAddresses = new HashSet<>();
        return new DeviceCollectionResult(bondedAddresses, connectedAddresses,
                                         connectedDevices, canQueryHidProfile);
    }
    
    /**
     * Reconciles currently connected HID devices and updates their states.
     */
    private void reconcileConnectedDevices(List<BluetoothDevice> connectedDevices,
                                          Set<String> connectedAddresses) {
        for (BluetoothDevice device : connectedDevices) {
            String addr = device.getAddress();
            connectedAddresses.add(addr);
            
            BTHIDService.HidDeviceState hidState = passkeyService.getDeviceState(addr);
            DeviceStatus status = mapHidStateToDeviceStatus(hidState);
            
            reconcileAndPersistDevice(addr, getDisplayName(device), status, "Reconciled ");
        }
    }
    
    /**
     * Reconciles bonded devices via service state when HID profile query is not supported.
     * This is a fallback mechanism for devices that don't support HID_DEVICE profile queries.
     */
    private void reconcileBondedDevicesViaService(Set<BluetoothDevice> bondedDevices,
                                                  Set<String> connectedAddresses) {
        for (BluetoothDevice device : bondedDevices) {
            String addr = device.getAddress();
            
            if (connectedAddresses.contains(addr)) {
                continue;
            }
            
            BTHIDService.HidDeviceState hidState = passkeyService.getDeviceState(addr);
            if (hidState == BTHIDService.HidDeviceState.DISCONNECTED) {
                continue;
            }
            
            connectedAddresses.add(addr);
            String name = getDisplayName(device);
            DeviceStatus status = mapHidStateToDeviceStatus(hidState);
            
            reconcileAndPersistDevice(addr, name, status, "Reconciled (via service) ");
        }
    }
    
    /**
     * Reconciles persisted device states with current Bluetooth state.
     * Removes unbonded devices and updates disconnected device states.
     */
    private void reconcilePersistedDevices(Map<String, DeviceStateManager.DeviceState> persistedStates,
                                          Set<String> bondedAddresses,
                                          Set<String> connectedAddresses) {
        for (Map.Entry<String, DeviceStateManager.DeviceState> entry : persistedStates.entrySet()) {
            String addr = entry.getKey();
            DeviceStateManager.DeviceState state = entry.getValue();
            
            if (!bondedAddresses.contains(addr)) {
                removeUnbondedDevice(addr, state.name);
                continue;
            }
            
            if (!connectedAddresses.contains(addr)) {
                reconcileDisconnectedDevice(state);
            }
        }
    }
    
    /**
     * Removes a device that is no longer bonded at the OS level.
     */
    private void removeUnbondedDevice(String address, String name) {
        removeDevice(address);
        stateManager.clearDeviceState(address);
        appendLog("Removed unbonded device: " + name);
    }
    
    /**
     * Updates a persisted device to disconnected state.
     */
    private void reconcileDisconnectedDevice(DeviceStateManager.DeviceState state) {
        upsertDevice(state.address, state.name, DeviceStatus.DISCONNECTED);
        state.btState = DeviceStateManager.BtState.DISCONNECTED;
        state.hidState = DeviceStateManager.HidState.NOT_ENUMERATED;
        stateManager.saveDeviceState(state.address, state);
        appendLog("Reconciled " + state.name + ": DISCONNECTED");
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

            // Reflect service-up state in BT icon (amber = advertising, no device yet)
            updateBtStatusIcon();

            // Register this activity as the UI delegate so the service can call
            // showUpDialog() when a UP ceremony begins while we are visible.
            foregroundService.setActivityDelegate(ServerActivity.this);

            // If a UP request arrived while we were unbound, show the dialog now.
            if (foregroundService.hasPendingUpRequest() && userPresenceDialog == null) {
                showUserPresenceDialog();
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
    private android.widget.ImageView btStatusIcon;

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

        biometricHelper = new BiometricAuthHelper(this);

        devicesList = findViewById(R.id.devicesList);
        noDevicesText = findViewById(R.id.noDevicesText);
        activityLogText = findViewById(R.id.activityLogText);
        bleDeviceNameText = findViewById(R.id.bleDeviceNameText);
        btStatusIcon = findViewById(R.id.btStatusIcon);
        updateBleDeviceNameDisplay();
        updateBtStatusIcon();

        devicesAdapter = new DeviceListAdapter(deviceItems);
        devicesList.setAdapter(devicesAdapter);

        // Initialize state manager
        stateManager = new DeviceStateManager(this);

        findViewById(R.id.advancedConfigButton).setOnClickListener(v ->
                startActivity(new Intent(this, AdvancedConfigActivity.class)));

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
        if (serviceBound) return;

        Intent serviceIntent = new Intent(this, HIDForegroundService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(serviceIntent);
        } else {
            startService(serviceIntent);
        }
        BootReceiver.enableAutoStart(this);
        bindService(serviceIntent, serviceConnection, Context.BIND_AUTO_CREATE);
    }
    
    /**
     * Updates the Bluetooth status icon colour to reflect service/advertising state:
     *  - Green  (device_connected)    — HID service is running and at least one device is active
     *  - Amber  (device_error)        — BT on, service running, but no device connected yet
     *  - Grey   (device_disconnected) — BT off / service not available
     */
    private void updateBtStatusIcon() {
        if (btStatusIcon == null) return;

        if (!BTHIDService.isBluetoothEnabled(this)) {
            btStatusIcon.setColorFilter(getColor(R.color.device_disconnected));
            return;
        }

        // Determine if any device is connected/active via the service
        boolean anyConnected = false;
        if (passkeyService != null) {
            for (DeviceItem item : deviceItems) {
                if (item.status == DeviceStatus.HID_ACTIVE
                        || item.status == DeviceStatus.HID_ENUMERATED
                        || item.status == DeviceStatus.CONNECTED) {
                    anyConnected = true;
                    break;
                }
            }
        }

        btStatusIcon.setColorFilter(getColor(
                anyConnected ? R.color.device_connected : R.color.device_error));
    }

    /**
     * Handles disconnect button click for a device.
     */
    private void handleDisconnect(String deviceAddress, String deviceName) {
        if (passkeyService == null) {
            appendLog("Service not available");
            return;
        }
        
        if (!hasBluetoothConnectPermission()) {
            appendLog("Bluetooth permission required");
            return;
        }
        
        try {
            BluetoothManager bluetoothManager = (BluetoothManager) getSystemService(Context.BLUETOOTH_SERVICE);
            BluetoothAdapter adapter = bluetoothManager.getAdapter();
            if (adapter != null) {
                BluetoothDevice device = adapter.getRemoteDevice(deviceAddress);
                boolean success = passkeyService.disconnect(device);
                if (success) {
                    appendLog("Disconnecting from " + deviceName);
                } else {
                    appendLog("Failed to disconnect from " + deviceName);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error disconnecting device", e);
            appendLog("Error disconnecting: " + e.getMessage());
        }
    }

    /**
     * Handles reconnect button click for a device.
     */
    private void handleReconnect(String deviceAddress, String deviceName) {
        if (passkeyService == null) {
            appendLog("Service not available");
            return;
        }
        
        if (!hasBluetoothConnectPermission()) {
            appendLog("Bluetooth permission required");
            return;
        }
        
        try {
            BluetoothManager bluetoothManager = (BluetoothManager) getSystemService(Context.BLUETOOTH_SERVICE);
            BluetoothAdapter adapter = bluetoothManager.getAdapter();
            if (adapter != null) {
                BluetoothDevice device = adapter.getRemoteDevice(deviceAddress);
                boolean success = passkeyService.connect(device);
                if (success) {
                    appendLog("Reconnecting to " + deviceName);
                } else {
                    appendLog("Failed to reconnect to " + deviceName);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error reconnecting device", e);
            appendLog("Error reconnecting: " + e.getMessage());
        }
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
        String truncDispName = displayName;
        if(displayName.length() > 16) {
            truncDispName = displayName.substring(0, 13) + "...";
        }
        if (existing != null) {
            existing.status = status;
        } else {
            DeviceItem item = new DeviceItem(truncDispName, address, status);
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
     * Called when the activity returns to the foreground.
     * Reconciles device states to handle changes that occurred while in background
     * (e.g., device unpaired, disconnected, etc.)
     */
    @Override
    protected void onResume() {
        super.onResume();
        isInForeground = true;
        Log.d(TAG, "onResume - reconciling device states");
        updateBtStatusIcon();
        if (serviceBound && passkeyService != null && stateManager != null) {
            reconcileDeviceStates();
        }
        // If a UP request arrived while we were backgrounded, show the dialog now.
        if (foregroundService != null
                && foregroundService.hasPendingUpRequest()
                && userPresenceDialog == null) {
            showUserPresenceDialog();
        }
    }

    /**
     * Called when this singleTop activity is re-launched while already on the back stack —
     * specifically when the user taps the UP notification from the lock screen / shade.
     *
     * NOTE: onNewIntent fires BEFORE onResume, so isInForeground is still false here.
     * Do NOT call showUserPresencePrompt() directly — it will re-post the notification
     * instead of showing the dialog because the foreground flag hasn't been set yet.
     * Simply cancel the stale notification; onResume fires immediately after and its
     * existing guard (pendingUpTxn != null && userPresenceDialog == null) will show
     * the dialog once isInForeground is true.
     */
    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        Log.d(TAG, "onNewIntent — UP notification tap");
        // Cancel the stale notification; onResume fires next and will show the dialog
        // (isInForeground is still false here so we must not call showUserPresenceDialog()).
        if (foregroundService != null && foregroundService.hasPendingUpRequest()) {
            foregroundService.cancelUpNotification();
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        isInForeground = false;
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        // Do NOT clear the AuthenticatorAPI callback — that is now owned by HIDForegroundService.
        dismissDialogIfShowing();
        if (foregroundService != null) {
            foregroundService.setActivityDelegate(null);
        }
        unbindFromService();
    }

    // -------------------------------------------------------------------------
    // HIDForegroundService.UpActivityDelegate
    // -------------------------------------------------------------------------

    /**
     * Called by {@link HIDForegroundService} on the main thread when a UP ceremony
     * begins.  If we are currently visible, show the dialog immediately; otherwise
     * the service has already posted a notification and we will show the dialog in
     * {@link #onResume()}.
     */
    @Override
    public void showUpDialog(@Nullable String rpId) {
        if (isInForeground) {
            showUserPresenceDialog();
        } else {
            // Activity is paused (backgrounded) but not destroyed — activityDelegate is still
            // set so UpHandler called us instead of postUpNotification().  Post the notification
            // ourselves so the user sees the heads-up / lock-screen alert.
            if (foregroundService != null) {
                foregroundService.postUpNotificationPublic();
            }
        }
    }

    // -------------------------------------------------------------------------
    // HIDForegroundService.BiometricDelegate
    // -------------------------------------------------------------------------

    @Override
    public void showBiometricPrompt(Runnable onSuccess, Runnable onFailed) {
        biometricHelper.authenticate(
            getString(R.string.bio_prompt_title),
            getString(R.string.bio_prompt_subtitle),
            new BiometricAuthHelper.AuthenticationCallback() {
                @Override
                public void onAuthenticationSucceeded(
                        androidx.biometric.BiometricPrompt.AuthenticationResult result) {
                    onSuccess.run();
                }
                @Override
                public void onAuthenticationFailed(String errorMessage) {
                    onFailed.run();
                }
                @Override
                public void onAuthenticationCancelled() {
                    onFailed.run();
                }
            }
        );
    }

    // -------------------------------------------------------------------------
    // HIDForegroundService.CancelListener
    // -------------------------------------------------------------------------

    /** Called by the service when a CTAP cancel frame arrives. */
    @Override
    public void onUpCancelled() {
        dismissDialogIfShowing();
    }

    // -------------------------------------------------------------------------
    // HIDForegroundService.TimeoutListener
    // -------------------------------------------------------------------------

    /** Called by the service when the UP timeout fires. */
    @Override
    public void onUpTimeout() {
        dismissDialogIfShowing();
        Toast.makeText(this, R.string.up_timeout_toast, Toast.LENGTH_SHORT).show();
    }

    // -------------------------------------------------------------------------
    // UP dialog helpers
    // -------------------------------------------------------------------------

    private void showUserPresenceDialog() {
        dismissDialogIfShowing();
        // AlertDialog lays out buttons left-to-right as: Negative | Positive.
        // Assigning Allow→Negative and Deny→Positive:  [Allow]  [Deny]
        userPresenceDialog = new AlertDialog.Builder(this)
            .setTitle(getString(R.string.up_getinfo_title))
            .setMessage(getString(R.string.up_getinfo_message))
            .setNegativeButton(R.string.up_allow, (d, w) -> {
                dismissDialogIfShowing();
                if (foregroundService != null) foregroundService.deliverUpApproved();
            })
            .setPositiveButton(R.string.up_deny, (d, w) -> {
                dismissDialogIfShowing();
                if (foregroundService != null) foregroundService.deliverUpDenied();
            })
            .setCancelable(false)
            .create();
        userPresenceDialog.show();
    }

    private void dismissDialogIfShowing() {
        if (userPresenceDialog != null && userPresenceDialog.isShowing()) {
            userPresenceDialog.dismiss();
        }
        userPresenceDialog = null;
    }
}

// Made with Bob