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
import android.widget.ImageView;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.fragment.app.Fragment;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AlertDialog.Builder;

import com.isfs.blekey.util.FileUtils;
import com.isfs.blekey.util.BiometricAuthHelper;
import com.isfs.blekey.hidsvc.DeviceStateManager;

import androidx.annotation.Nullable;

/**
 * Fragment responsible for managing the Bluetooth HID passkey service.
 * Previously {@code ServerActivity}; now embedded inline in {@code MainActivity}.
 *
 * <p>UP state (pending context, keepalive, wake lock, timeout) is owned by
 * {@link HIDForegroundService}.  This fragment is a pure UI responder: it
 * receives {@link HIDForegroundService.UpActivityDelegate#showUpDialog} on the
 * main thread, shows the dialog, and calls back via the service's
 * {@code deliverUp*()} methods.</p>
 */
public class ServerFragment extends Fragment
        implements HIDForegroundService.UpActivityDelegate,
                   HIDForegroundService.BiometricDelegate,
                   HIDForegroundService.CancelListener,
                   HIDForegroundService.TimeoutListener {

    private final String TAG = ServerFragment.class.getCanonicalName();

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
                ServerFragment.this.handleReconnect(item.address, item.name);
            }
        };
        private final View.OnClickListener disconnectClickListener = new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                DeviceItem item = (DeviceItem) v.getTag();
                ServerFragment.this.handleDisconnect(item.address, item.name);
            }
        };

        DeviceListAdapter(List<DeviceItem> items) {
            this.items = items;
            this.inflater = LayoutInflater.from(requireContext());
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
                            requireContext().getString(R.string.device_active) :
                            requireContext().getString(R.string.device_discovered),
                        R.color.device_connected);
                    setButtonVisibility(holder, false, true);
                    holder.disconnectButton.setTag(item);
                    holder.disconnectButton.setOnClickListener(disconnectClickListener);
                    break;
                case CONNECTED:
                    setDeviceStatus(holder,
                        requireContext().getString(R.string.device_status_connected),
                        R.color.device_connected);
                    setButtonVisibility(holder, false, false);
                    break;
                case ERROR:
                    setDeviceStatus(holder,
                        requireContext().getString(R.string.device_status_error),
                        R.color.device_error);
                    setButtonVisibility(holder, true, false);
                    holder.reconnectButton.setTag(item);
                    holder.reconnectButton.setOnClickListener(reconnectClickListener);
                    break;
                default:
                    setDeviceStatus(holder,
                        requireContext().getString(R.string.device_status_disconnected),
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
            int color = requireContext().getColor(colorResId);
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
            requireActivity().runOnUiThread(() -> {
                upsertDevice(addr, name, DeviceStatus.CONNECTED);
                saveDeviceState(addr, name, DeviceStatus.CONNECTED);
                appendLog(requireContext().getString(R.string.log_device_connected, name));
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
            requireActivity().runOnUiThread(() -> {
                upsertDevice(addr, name, DeviceStatus.DISCONNECTED);
                saveDeviceState(addr, name, DeviceStatus.DISCONNECTED);
                appendLog(requireContext().getString(R.string.log_device_disconnected, name));
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
            requireActivity().runOnUiThread(() -> {
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
            requireActivity().runOnUiThread(() -> {
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
            requireActivity().runOnUiThread(() -> {
                upsertDevice(addr, name, DeviceStatus.HID_ACTIVE);
                saveDeviceState(addr, name, DeviceStatus.HID_ACTIVE);
                appendLog(name + ": HID ready for input");
                updateBtStatusIcon();
            });
        }
    }

    /** The HID service instance that provides passkey functionality over classic Bluetooth. */
    private BTHIDService passkeyService;

    /** Reference to the bound foreground service. */
    private HIDForegroundService foregroundService;
    private boolean serviceBound = false;

    /** Manager for persistent device state storage. */
    private DeviceStateManager stateManager;

    /** Used to show the UP prompt dialog. */
    private AlertDialog userPresenceDialog = null;

    /** Used to show biometric prompts for TEE-gated platform key operations. */
    private BiometricAuthHelper biometricHelper;

    // ActivityResultLauncher fields — declared here, registered in onCreate(Bundle)
    private ActivityResultLauncher<Intent> enableBtLauncher;
    private ActivityResultLauncher<String> requestBluetoothConnectLauncher;

    /** Flag to track if the Create Passkey button was clicked */
    private boolean createPasskeyClicked = false;

    private static Boolean CONNECT_GRANTED = null;

    // UI references — nulled out in onDestroyView
    private ListView devicesList;
    private TextView noDevicesText;
    private TextView bleDeviceNameText;
    private ImageView btStatusIcon;

    /** Ordered map: device address -> DeviceItem, preserves insertion order. */
    private final Map<String, DeviceItem> deviceMap = new LinkedHashMap<>();
    private final List<DeviceItem> deviceItems = new ArrayList<>();
    private DeviceListAdapter devicesAdapter;

    /** Service connection for binding to HIDForegroundService. */
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
                appendLog(requireContext().getString(R.string.log_advertising_started));
                populateBondedDevices();
                reconcileDeviceStates();
            }

            // Reflect service-up state in BT icon (amber = advertising, no device yet)
            updateBtStatusIcon();

            // Register this fragment as the UI delegate so the service can call
            // showUpDialog() when a UP ceremony begins while we are visible.
            foregroundService.setActivityDelegate(ServerFragment.this);

            // If a UP request arrived while we were unbound / backgrounded, transition
            // Stage 0 → Stage 1 and show the dialog now.
            String rpId = foregroundService.transitionToForeground();
            if ((rpId != null || foregroundService.hasPendingUpRequest())
                    && userPresenceDialog == null) {
                showUserPresenceDialog(rpId);
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

    // -------------------------------------------------------------------------
    // Fragment lifecycle
    // -------------------------------------------------------------------------

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Register launchers here — before onStart, as required by Fragment lifecycle
        enableBtLauncher = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            result -> {
                if (!BTHIDService.isBluetoothEnabled(requireContext())) {
                    Toast.makeText(requireContext(), R.string.requires_bl_enabled, Toast.LENGTH_LONG).show();
                    return;
                }
                if (!BTHIDService.isClassicBTHIDSupported()) {
                    showUXForNotPermitted();
                } else {
                    setupPasskeyPeripheralProvider();
                }
            });

        requestBluetoothConnectLauncher = registerForActivityResult(
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
            });
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_server, container, false);
    }

    @Override
    public void onViewCreated(View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        biometricHelper = new BiometricAuthHelper(requireActivity());
        stateManager    = new DeviceStateManager(requireContext());

        devicesList       = view.findViewById(R.id.devicesList);
        noDevicesText     = view.findViewById(R.id.noDevicesText);
        bleDeviceNameText = view.findViewById(R.id.bleDeviceNameText);
        btStatusIcon      = view.findViewById(R.id.btStatusIcon);

        updateBleDeviceNameDisplay();
        updateBtStatusIcon();

        devicesAdapter = new DeviceListAdapter(deviceItems);
        devicesList.setAdapter(devicesAdapter);

        view.findViewById(R.id.advancedConfigButton).setOnClickListener(v ->
            startActivity(new Intent(requireContext(), AdvancedConfigActivity.class)));

        // NOTE: ServerActivity also wired backButton/homeButton here.
        // Those belong to the toolbar owned by MainActivity, which already sets
        // both buttons to View.GONE in setupToolbar(). Not duplicated here.
        btStatusIcon.setOnClickListener(v ->
            startActivity(new Intent(Settings.ACTION_BLUETOOTH_SETTINGS)));
        updatePermissionFlags();
        if (CONNECT_GRANTED == Boolean.TRUE) {
            checkBluetoothAndStart();
        } else {
            askForPermissions();
        }
    }

    @Override
    public void onStart() {
        super.onStart();
        if (foregroundService != null) {
            foregroundService.setActivityDelegate(this);
        }
    }

    @Override
    public void onStop() {
        super.onStop();
        if (foregroundService != null) {
            foregroundService.setActivityDelegate(null);
        }
        // Do NOT call unbindFromService() here — onStop fires every time the user
        // navigates to AdvancedConfigActivity (MainActivity pauses/stops while
        // AdvancedConfigActivity is on top). Unbinding would drop the ServiceConnection
        // and null out passkeyService on every such navigation.
        // unbindFromService() belongs in onDestroyView.
    }

    @Override
    public void onResume() {
        super.onResume();
        updateBtStatusIcon();
        if (serviceBound && passkeyService != null && stateManager != null) {
            reconcileDeviceStates();
        }
        if (foregroundService != null) {
            String rpId = foregroundService.transitionToForeground();
            if ((rpId != null || foregroundService.hasPendingUpRequest())
                    && userPresenceDialog == null) {
                showUserPresenceDialog(rpId);
            }
        }
    }

    @Override
    public void onPause() {
        super.onPause();
        // delegate stays registered until onStop
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        dismissDialogIfShowing();
        if (foregroundService != null) {
            foregroundService.setActivityDelegate(null);
        }
        unbindFromService();
        devicesList       = null;
        noDevicesText     = null;
        bleDeviceNameText = null;
        btStatusIcon      = null;
    }

    // -------------------------------------------------------------------------
    // Called from MainActivity.onNewIntent
    // -------------------------------------------------------------------------

    /**
     * Forwarded from {@link com.isfs.blekey.MainActivity#onNewIntent} when the user taps
     * the UP notification from the lock screen / shade.
     *
     * NOTE: onNewIntent fires BEFORE onResume, so the fragment is not yet resumed.
     * Simply cancel the stale notification; onResume fires immediately after and its
     * existing guard will show the dialog.
     */
    public void onNewIntent(Intent intent) {
        Log.d(TAG, "onNewIntent — UP notification tap");
        if (foregroundService != null && foregroundService.hasPendingUpRequest()) {
            foregroundService.cancelUpNotification();
        }
    }

    // -------------------------------------------------------------------------
    // Navigation helper — replaces stopServiceAndReturnToMain()
    // -------------------------------------------------------------------------

    /**
     * Navigates to ManageActivity.  The BT/HID service stays running.
     * Replaces all call sites of the old {@code stopServiceAndReturnToMain()}.
     */
    private void goToManageActivity() {
        startActivity(new Intent(requireContext(), ManageActivity.class));
    }

    // -------------------------------------------------------------------------
    // Bluetooth / service management
    // -------------------------------------------------------------------------

    private void checkBluetoothAndStart() {
        if (!BTHIDService.isBluetoothEnabled(requireContext())) {
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
        final AlertDialog alertDialog = new Builder(requireContext()).create();
        alertDialog.setTitle(requireContext().getString(R.string.not_supported));
        alertDialog.setMessage(requireContext().getString(R.string.device_not_supported,
                "Classic Bluetooth HID device mode"));
        alertDialog.setButton(AlertDialog.BUTTON_NEUTRAL,
                requireContext().getString(R.string.ok),
                new OnClickListener() {
                    @Override
                    public void onClick(final DialogInterface dialog, final int which) {
                        dialog.dismiss();
                    }
                });
        alertDialog.setOnDismissListener(new OnDismissListener() {
            @Override
            public void onDismiss(final DialogInterface dialog) {
                requireActivity().finish();
            }
        });
        alertDialog.show();
    }

    /** Flow-control entry point: checks for passkeys then starts the foreground service. */
    public void setupPasskeyPeripheralProvider() {
        if (noPasskeysExist()) {
            showNoPasskeysDialog();
            return;
        }
        startHIDForegroundService();
    }

    private void startHIDForegroundService() {
        if (serviceBound) return;

        Intent serviceIntent = new Intent(requireContext(), HIDForegroundService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            requireActivity().startForegroundService(serviceIntent);
        } else {
            requireActivity().startService(serviceIntent);
        }
        BootReceiver.enableAutoStart(requireContext());
        requireActivity().bindService(serviceIntent, serviceConnection, Context.BIND_AUTO_CREATE);
    }

    private void stopHIDForegroundService() {
        unbindFromService();
        BootReceiver.disableAutoStart(requireContext());
        Intent serviceIntent = new Intent(requireContext(), HIDForegroundService.class);
        requireActivity().stopService(serviceIntent);
        appendLog("Service stopped");
    }

    private void unbindFromService() {
        if (serviceBound) {
            requireActivity().unbindService(serviceConnection);
            serviceBound = false;
            foregroundService = null;
            passkeyService = null;
        }
    }

    // -------------------------------------------------------------------------
    // Device state reconciliation
    // -------------------------------------------------------------------------

    private void reconcileDeviceStates() {
        if (passkeyService == null || stateManager == null) return;

        if (!hasBluetoothConnectPermission()) {
            Log.w(TAG, "BLUETOOTH_CONNECT permission not granted, cannot reconcile device states");
            return;
        }

        try {
            Map<String, DeviceStateManager.DeviceState> persistedStates = stateManager.loadAllDeviceStates();
            BluetoothManager bluetoothManager =
                    (BluetoothManager) requireContext().getSystemService(Context.BLUETOOTH_SERVICE);

            DeviceCollectionResult devices = collectCurrentDevices(bluetoothManager);

            reconcileConnectedDevices(devices.connectedDevices, devices.connectedAddresses);

            if (!devices.canQueryHidProfile) {
                reconcileBondedDevicesViaService(
                    passkeyService.getBondedDevices(),
                    devices.connectedAddresses
                );
            }

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

    private void reconcileAndPersistDevice(String address, String name,
                                           DeviceStatus status, String logPrefix) {
        upsertDevice(address, name, status);
        saveDeviceState(address, name, status);
        appendLog(logPrefix + name + ": " + status);
    }

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

    private void removeUnbondedDevice(String address, String name) {
        removeDevice(address);
        stateManager.clearDeviceState(address);
        appendLog("Removed unbonded device: " + name);
    }

    private void reconcileDisconnectedDevice(DeviceStateManager.DeviceState state) {
        upsertDevice(state.address, state.name, DeviceStatus.DISCONNECTED);
        state.btState  = DeviceStateManager.BtState.DISCONNECTED;
        state.hidState = DeviceStateManager.HidState.NOT_ENUMERATED;
        stateManager.saveDeviceState(state.address, state);
        appendLog("Reconciled " + state.name + ": DISCONNECTED");
    }

    private DeviceStatus mapHidStateToDeviceStatus(BTHIDService.HidDeviceState hidState) {
        switch (hidState) {
            case ACTIVE:      return DeviceStatus.HID_ACTIVE;
            case REGISTERED:  return DeviceStatus.HID_ENUMERATED;
            case CONNECTED:
            case CONNECTING:
            case DISCONNECTED:
            default:          return DeviceStatus.CONNECTED;
        }
    }

    private void saveDeviceState(String address, String name, DeviceStatus status) {
        if (stateManager == null) return;

        DeviceStateManager.BtState btState;
        DeviceStateManager.HidState hidState;

        switch (status) {
            case HID_ACTIVE:
                btState  = DeviceStateManager.BtState.CONNECTED;
                hidState = DeviceStateManager.HidState.ACTIVE;
                break;
            case HID_ENUMERATED:
                btState  = DeviceStateManager.BtState.CONNECTED;
                hidState = DeviceStateManager.HidState.ENUMERATED;
                break;
            case CONNECTED:
                btState  = DeviceStateManager.BtState.CONNECTED;
                hidState = DeviceStateManager.HidState.NOT_ENUMERATED;
                break;
            case ERROR:
                btState  = DeviceStateManager.BtState.ERROR;
                hidState = DeviceStateManager.HidState.NOT_ENUMERATED;
                break;
            case DISCONNECTED:
            default:
                btState  = DeviceStateManager.BtState.DISCONNECTED;
                hidState = DeviceStateManager.HidState.NOT_ENUMERATED;
                break;
        }

        DeviceStateManager.DeviceState state =
                new DeviceStateManager.DeviceState(address, name, btState, hidState);
        stateManager.saveDeviceState(address, state);
    }

    // -------------------------------------------------------------------------
    // UI helpers
    // -------------------------------------------------------------------------

    private void updateBtStatusIcon() {
        if (btStatusIcon == null) return;

        if (!BTHIDService.isBluetoothEnabled(requireContext())) {
            btStatusIcon.setColorFilter(requireContext().getColor(R.color.device_disconnected));
            return;
        }

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

        btStatusIcon.setColorFilter(requireContext().getColor(
                anyConnected ? R.color.device_connected : R.color.device_error));
    }

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
            BluetoothManager bluetoothManager =
                    (BluetoothManager) requireContext().getSystemService(Context.BLUETOOTH_SERVICE);
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
            BluetoothManager bluetoothManager =
                    (BluetoothManager) requireContext().getSystemService(Context.BLUETOOTH_SERVICE);
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

    private void populateBondedDevices() {
        if (passkeyService == null) return;

        if (!hasBluetoothConnectPermission()) {
            Log.w(TAG, "BLUETOOTH_CONNECT permission not granted, cannot populate bonded devices");
            return;
        }

        try {
            final BluetoothManager bluetoothManager =
                    (BluetoothManager) requireContext().getSystemService(Context.BLUETOOTH_SERVICE);

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

    private void updateBleDeviceNameDisplay() {
        if (bleDeviceNameText == null) return;

        if (!hasBluetoothConnectPermission()) {
            bleDeviceNameText.setText(requireContext().getString(R.string.ble_beekey));
            return;
        }

        try {
            final BluetoothAdapter adapter =
                    ((BluetoothManager) requireContext()
                            .getSystemService(Context.BLUETOOTH_SERVICE)).getAdapter();
            String name = (adapter != null) ? adapter.getName() : null;
            if (name == null || name.isEmpty()) name = requireContext().getString(R.string.ble_beekey);
            bleDeviceNameText.setText(requireContext().getString(R.string.device_name_label, name));
        } catch (SecurityException e) {
            Log.e(TAG, "SecurityException getting adapter name", e);
            bleDeviceNameText.setText(requireContext().getString(R.string.ble_beekey));
        }
    }

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

    private void upsertDevice(String address, String displayName, DeviceStatus status) {
        DeviceItem existing = deviceMap.get(address);
        String truncDispName = displayName;
        if (displayName.length() > 16) {
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

    private void removeDevice(String address) {
        DeviceItem item = deviceMap.remove(address);
        if (item != null) {
            deviceItems.remove(item);
            devicesAdapter.notifyDataSetChanged();
            updateDeviceVisibility();
        }
    }

    private boolean noPasskeysExist() {
        File appDataDir = requireActivity().getFilesDir();
        System.setProperty("FIDO2_HOME", appDataDir.getAbsolutePath());
        return FileUtils.listPasskeys() == null || FileUtils.listPasskeys().isEmpty();
    }

    private void updateDeviceVisibility() {
        if (deviceItems.isEmpty()) {
            noDevicesText.setVisibility(View.VISIBLE);
            devicesList.setVisibility(View.GONE);
        } else {
            noDevicesText.setVisibility(View.GONE);
            devicesList.setVisibility(View.VISIBLE);
        }
    }

    private void appendLog(String message) {
        Log.d(TAG, message);
    }

    // -------------------------------------------------------------------------
    // No-passkeys dialog
    // -------------------------------------------------------------------------

    private void onCreatePasskeyClicked(DialogInterface dialog) {
        createPasskeyClicked = true;
        startActivity(new Intent(requireContext(), ManageActivity.class));
        dialog.dismiss();
    }

    private void onCancelClicked(DialogInterface dialog) {
        Log.d(TAG, "Cancel button clicked, navigating to ManageActivity");
        dialog.dismiss();
        goToManageActivity();
    }

    private void onDialogDismissed(DialogInterface dialog) {
        if (requireActivity().isFinishing() || createPasskeyClicked) {
            Log.d(TAG, "Dialog dismissed but activity is already finishing or create passkey was clicked");
            return;
        }
        Log.d(TAG, "Dialog dismissed without button click, navigating to ManageActivity");
        goToManageActivity();
    }

    private void showNoPasskeysDialog() {
        final AlertDialog alertDialog = new Builder(requireContext()).create();
        alertDialog.setTitle(requireContext().getString(R.string.no_passkey_wallets));
        alertDialog.setMessage(requireContext().getString(R.string.create_passkey_wallet_first));
        alertDialog.setButton(AlertDialog.BUTTON_POSITIVE,
                requireContext().getString(R.string.create_passkey_wallet),
                (dialog, which) -> onCreatePasskeyClicked(dialog));
        alertDialog.setButton(AlertDialog.BUTTON_NEGATIVE,
                requireContext().getString(R.string.cancel),
                (dialog, which) -> onCancelClicked(dialog));
        alertDialog.setOnDismissListener(dialog -> onDialogDismissed(dialog));
        alertDialog.show();
    }

    // -------------------------------------------------------------------------
    // Permission helpers
    // -------------------------------------------------------------------------

    private boolean hasBluetoothConnectPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            return ContextCompat.checkSelfPermission(requireContext(),
                Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED;
        }
        return true;
    }

    private void showPermissionRationale() {
        new AlertDialog.Builder(requireContext())
            .setTitle(R.string.bluetooth_permission_required)
            .setMessage(R.string.bluetooth_permission_rationale)
            .setPositiveButton(R.string.grant_permission, (dialog, which) -> {
                requestBluetoothConnectLauncher.launch(Manifest.permission.BLUETOOTH_CONNECT);
            })
            .setNegativeButton(R.string.cancel, (dialog, which) -> {
                dialog.dismiss();
                requireActivity().finish();
            })
            .show();
    }

    private void showPermissionDeniedDialog() {
        new AlertDialog.Builder(requireContext())
            .setTitle(requireContext().getString(R.string.not_supported))
            .setMessage(requireContext().getString(R.string.bluetooth_not_permitted, "HID"))
            .setPositiveButton(R.string.open_settings, (dialog, which) -> {
                Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
                Uri uri = Uri.fromParts("package", requireActivity().getPackageName(), null);
                intent.setData(uri);
                startActivity(intent);
                requireActivity().finish();
            })
            .setNegativeButton(requireContext().getString(R.string.ok), (dialog, which) -> {
                dialog.dismiss();
                requireActivity().finish();
            })
            .show();
    }

    private void updatePermissionFlags() {
        CONNECT_GRANTED = ContextCompat.checkSelfPermission(requireContext(),
                Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED;
        if (CONNECT_GRANTED) Log.d(TAG, "Have BLUETOOTH_CONNECT permission");
    }

    private void askForPermissions() {
        updatePermissionFlags();

        if (CONNECT_GRANTED == Boolean.TRUE) {
            Log.d(TAG, "Have required Bluetooth permissions, start it up!");
            return;
        }

        if (!CONNECT_GRANTED &&
                ActivityCompat.shouldShowRequestPermissionRationale(requireActivity(),
                    Manifest.permission.BLUETOOTH_CONNECT)) {
            showPermissionRationale();
            return;
        }

        Log.d(TAG, "Requesting BLUETOOTH_CONNECT permission");
        requestBluetoothConnectLauncher.launch(Manifest.permission.BLUETOOTH_CONNECT);
    }

    // -------------------------------------------------------------------------
    // HIDForegroundService.UpActivityDelegate
    // -------------------------------------------------------------------------

    /**
     * Called by {@link HIDForegroundService} on the main thread when a UP ceremony begins.
     * Uses fragment lifecycle state rather than the old {@code isInForeground} boolean.
     */
    @Override
    public void showUpDialog(@Nullable String rpId) {
        if (isAdded() && isVisible() && isResumed()) {
            showUserPresenceDialog(rpId);
        }
        // Background path no longer needed here — handled in onUpUvRequired.
    }

    // -------------------------------------------------------------------------
    // HIDForegroundService.BiometricDelegate
    // -------------------------------------------------------------------------

    @Override
    public void showBiometricPrompt(Runnable onSuccess, Runnable onFailed) {
        requireActivity().runOnUiThread(() -> biometricHelper.authenticate(
            requireContext().getString(R.string.bio_prompt_title),
            requireContext().getString(R.string.bio_prompt_subtitle),
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
        ));
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
        Toast.makeText(requireContext(), R.string.up_timeout_toast, Toast.LENGTH_SHORT).show();
    }

    // -------------------------------------------------------------------------
    // UP dialog helpers
    // -------------------------------------------------------------------------

    private void showUserPresenceDialog() {
        showUserPresenceDialog(null);
    }

    private void showUserPresenceDialog(@Nullable String rpId) {
        dismissDialogIfShowing();
        String title = (rpId != null)
            ? requireContext().getString(R.string.up_rp_wants_to_authenticate, rpId)
            : requireContext().getString(R.string.up_getinfo_title);
        // AlertDialog lays out buttons left-to-right as: Negative | Positive.
        // Assigning Allow→Negative and Deny→Positive:  [Allow]  [Deny]
        userPresenceDialog = new AlertDialog.Builder(requireContext())
            .setTitle(title)
            .setMessage(requireContext().getString(R.string.up_getinfo_message))
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
