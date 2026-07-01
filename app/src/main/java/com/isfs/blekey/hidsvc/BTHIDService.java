/*
 * Copyright IBM 2025
 */

package com.isfs.blekey.hidsvc;

import android.annotation.SuppressLint;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothHidDevice;
import android.bluetooth.BluetoothHidDeviceAppQosSettings;
import android.bluetooth.BluetoothHidDeviceAppSdpSettings;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothProfile;
import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executor;

/**
 * Classic Bluetooth HID Device Service.
 * Replaces BLE GATT server with BluetoothHidDevice API.
 */
public class BTHIDService implements IHIDTransport {
    
    private static final String TAG = BTHIDService.class.getSimpleName();
    
    public enum HidDeviceState {
        DISCONNECTED, CONNECTING, CONNECTED, REGISTERED, ACTIVE
    }
    
    public interface ConnectionListener {
        void onDeviceConnected(BluetoothDevice device);
        void onDeviceDisconnected(BluetoothDevice device);
        void onDeviceError(BluetoothDevice device);
        void onHidServiceEnumerated(BluetoothDevice device);
        void onHidServiceActive(BluetoothDevice device);
    }
    
    // Device info
    private String manufacturer = "lowkey";
    private String deviceName = "AyeBleKey";
    
    private final HIDPasskey passkey;
    
    // Core components
    private final Context applicationContext;
    private final Handler handler;
    private final BluetoothManager bluetoothManager;
    private final BluetoothAdapter bluetoothAdapter;
    private final Executor executor;
    
    // HID device
    @Nullable
    private BluetoothHidDevice hidDevice;
    private boolean isAppRegistered = false;
    
    // Connection tracking
    private final Map<String, BluetoothDevice> connectedDevices = new ConcurrentHashMap<>();
    private final Map<String, HidDeviceState> deviceStates = new ConcurrentHashMap<>();
    private final Queue<byte[]> inputReportQueue = new ConcurrentLinkedQueue<>();
    
    @Nullable
    private ConnectionListener connectionListener;
    
    public BTHIDService(@NonNull Context context) {
        this.applicationContext = context.getApplicationContext();
        this.handler = new Handler(Looper.getMainLooper());
        this.executor = command -> handler.post(command);
        this.bluetoothManager = (BluetoothManager) context.getSystemService(Context.BLUETOOTH_SERVICE);
        this.bluetoothAdapter = bluetoothManager.getAdapter();
        this.passkey = new HIDPasskey(this);
        Log.i(TAG, "BTHIDService initialized");
    }
    
    // Setters
    public void setConnectionListener(@Nullable ConnectionListener listener) {
        this.connectionListener = listener;
    }
    
    public void setManufacturer(String manufacturer) {
        this.manufacturer = manufacturer;
    }
    
    public void setDeviceName(String deviceName) {
        this.deviceName = deviceName;
    }
    
    // Getters
    public Set<BluetoothDevice> getDevices() {
        return Set.copyOf(connectedDevices.values());
    }
    
    public HidDeviceState getDeviceState(String address) {
        return deviceStates.getOrDefault(address, HidDeviceState.DISCONNECTED);
    }
    
    /**
     * Create SDP settings - defines what kind of HID device we are
     */
    private BluetoothHidDeviceAppSdpSettings createSdpSettings() {
        byte[] reportDescriptor = HIDPasskey.getReportMap();
        
        return new BluetoothHidDeviceAppSdpSettings(
            deviceName,
            "Passkey Device",
            manufacturer,
            BluetoothHidDevice.SUBCLASS1_COMBO,
            reportDescriptor  // SAME as BLE!
        );
    }
    
    /**
     * Create QoS settings - optimize for low latency
     */
    private BluetoothHidDeviceAppQosSettings createQosSettings() {
        return new BluetoothHidDeviceAppQosSettings(
            BluetoothHidDeviceAppQosSettings.SERVICE_BEST_EFFORT,
            800, 9000, 800, 10000, -1
        );
    }
    
    /**
     * Callback for HID device events
     */
    private final BluetoothHidDevice.Callback hidDeviceCallback = new BluetoothHidDevice.Callback() {
        
        @Override
        @SuppressLint("MissingPermission")
        public void onAppStatusChanged(BluetoothDevice pluggedDevice, boolean registered) {
            Log.i(TAG, "onAppStatusChanged: registered=" + registered);
            isAppRegistered = registered;
            if (registered && pluggedDevice != null) {
                deviceStates.put(pluggedDevice.getAddress(), HidDeviceState.REGISTERED);
            } else {
                connectedDevices.clear();
                deviceStates.clear();
            }
            
            // After registration, initiate connections to all bonded devices
            if (registered && bluetoothAdapter != null) {
                handler.postDelayed(() -> {
                    Set<BluetoothDevice> bondedDevices = getBondedDevices();
                    Log.i(TAG, "Initiating connections to " + bondedDevices.size() + " bonded devices");
                    for (BluetoothDevice device : bondedDevices) {
                        Log.i(TAG, "Connecting to bonded device: " + device.getAddress());
                        connect(device);
                    }
                }, 500); // Small delay to ensure registration is complete
            }
        }
        
        @Override
        public void onConnectionStateChanged(BluetoothDevice device, int state) {
            String address = device.getAddress();
            Log.i(TAG, "onConnectionStateChanged: " + address + " state=" + state);
            
            switch (state) {
                case BluetoothProfile.STATE_CONNECTED:
                    connectedDevices.put(address, device);
                    deviceStates.put(address, HidDeviceState.CONNECTED);
                    if (connectionListener != null) {
                        handler.post(() -> {
                            connectionListener.onDeviceConnected(device);
                            connectionListener.onHidServiceEnumerated(device);
                        });
                    }
                    processInputReportQueue();
                    break;
                    
                case BluetoothProfile.STATE_CONNECTING:
                    deviceStates.put(address, HidDeviceState.CONNECTING);
                    break;
                    
                case BluetoothProfile.STATE_DISCONNECTED:
                    connectedDevices.remove(address);
                    deviceStates.put(address, HidDeviceState.DISCONNECTED);
                    if (connectionListener != null) {
                        handler.post(() -> connectionListener.onDeviceDisconnected(device));
                    }
                    break;
            }
        }
        
        @Override
        public void onGetReport(BluetoothDevice device, byte type, byte id, int bufferSize) {
            Log.d(TAG, "onGetReport: type=" + type + " id=" + id);
            if (hidDevice != null) {
                hidDevice.replyReport(device, type, id, new byte[bufferSize]);
            }
        }
        
        @Override
        public void onSetReport(BluetoothDevice device, byte type, byte id, byte[] data) {
            Log.d(TAG, "onSetReport: type=" + type + " length=" + data.length);
            
            if (type == BluetoothHidDevice.REPORT_TYPE_OUTPUT) {
                passkey.onOutputReport(data);
                
                String address = device.getAddress();
                if (deviceStates.get(address) != HidDeviceState.ACTIVE) {
                    deviceStates.put(address, HidDeviceState.ACTIVE);
                    if (connectionListener != null) {
                        handler.post(() -> connectionListener.onHidServiceActive(device));
                    }
                }
            }
        }
        
        @Override
        public void onSetProtocol(BluetoothDevice device, byte protocol) {
            Log.d(TAG, "onSetProtocol: protocol=" + protocol);
        }
        
        @Override
        public void onInterruptData(BluetoothDevice device, byte reportId, byte[] data) {
            Log.d(TAG, "onInterruptData: reportId=" + reportId + " length=" + data.length);
            
            // Process interrupt data (OUTPUT reports from host)
            passkey.onOutputReport(data);
            
            String address = device.getAddress();
            if (deviceStates.get(address) != HidDeviceState.ACTIVE) {
                deviceStates.put(address, HidDeviceState.ACTIVE);
                if (connectionListener != null) {
                    handler.post(() -> connectionListener.onHidServiceActive(device));
                }
            }
        }
        
        @Override
        public void onVirtualCableUnplug(BluetoothDevice device) {
            Log.i(TAG, "onVirtualCableUnplug: " + device.getAddress());
            String address = device.getAddress();
            connectedDevices.remove(address);
            deviceStates.put(address, HidDeviceState.DISCONNECTED);
            if (connectionListener != null) {
                handler.post(() -> connectionListener.onDeviceDisconnected(device));
            }
        }
    };
    
    /**
     * Register HID device - starts the service
     */
    @SuppressLint("MissingPermission")
    public boolean registerHidDevice() {
        Log.i(TAG, "registerHidDevice()");
        
        if (bluetoothAdapter == null || !bluetoothAdapter.isEnabled()) {
            Log.e(TAG, "Bluetooth not available");
            return false;
        }
        
        if (hidDevice == null) {
            return bluetoothAdapter.getProfileProxy(
                applicationContext,
                profileListener,
                BluetoothProfile.HID_DEVICE
            );
        }
        
        return registerApp();
    }
    
    /**
     * Profile listener for BluetoothHidDevice
     */
    private final BluetoothProfile.ServiceListener profileListener = new BluetoothProfile.ServiceListener() {
        @Override
        public void onServiceConnected(int profile, BluetoothProfile proxy) {
            Log.i(TAG, "HID device profile connected");
            if (profile == BluetoothProfile.HID_DEVICE) {
                hidDevice = (BluetoothHidDevice) proxy;
                registerApp();
            }
        }
        
        @Override
        public void onServiceDisconnected(int profile) {
            Log.w(TAG, "HID device profile disconnected");
            if (profile == BluetoothProfile.HID_DEVICE) {
                hidDevice = null;
                isAppRegistered = false;
            }
        }
    };
    
    /**
     * Register the HID app
     */
    @SuppressLint("MissingPermission")
    private boolean registerApp() {
        if (hidDevice == null) {
            Log.e(TAG, "HID device proxy not available");
            return false;
        }
        
        if (isAppRegistered) {
            Log.i(TAG, "HID app already registered");
            return true;
        }
        
        BluetoothHidDeviceAppSdpSettings sdpSettings = createSdpSettings();
        BluetoothHidDeviceAppQosSettings qos = createQosSettings();
        
        boolean success = hidDevice.registerApp(sdpSettings, qos, qos, executor, hidDeviceCallback);
        Log.i(TAG, "HID app registration " + (success ? "initiated" : "failed"));
        return success;
    }
    
    /**
     * Unregister HID device - stops the service
     */
    @SuppressLint("MissingPermission")
    public void unregisterHidDevice() {
        Log.i(TAG, "unregisterHidDevice()");
        
        if (hidDevice != null && isAppRegistered) {
            hidDevice.unregisterApp();
        }
        
        connectedDevices.clear();
        deviceStates.clear();
        isAppRegistered = false;
        
        if (hidDevice != null) {
            bluetoothAdapter.closeProfileProxy(BluetoothProfile.HID_DEVICE, hidDevice);
            hidDevice = null;
        }
    }
    
    /**
     * Returns the {@link HIDPasskey} instance used by this service.
     */
    public HIDPasskey getPasskey() {
        return passkey;
    }

    /**
     * Add input report to queue (called by HIDPasskey)
     */
    protected void addInputReport(final byte[] inputReport) {
        if (inputReport != null && inputReport.length > 0) {
            inputReportQueue.offer(inputReport);
            processInputReportQueue();
        }
    }
    
    /**
     * Process queued reports
     */
    @SuppressLint("MissingPermission")
    private void processInputReportQueue() {
        if (hidDevice == null || !isAppRegistered) {
            return;
        }
        
        Set<BluetoothDevice> devices = getDevices();
        if (devices.isEmpty()) {
            return;
        }
        
        byte[] report;
        while ((report = inputReportQueue.poll()) != null) {
            for (BluetoothDevice device : devices) {
                sendInputReport(device, report);
            }
        }
    }
    
    /**
     * Send input report to device
     */
    @SuppressLint("MissingPermission")
    private boolean sendInputReport(BluetoothDevice device, byte[] report) {
        if (hidDevice == null || !isAppRegistered || device == null || report == null) {
            return false;
        }
        
        HidDeviceState state = deviceStates.get(device.getAddress());
        if (state != HidDeviceState.CONNECTED && state != HidDeviceState.ACTIVE) {
            Log.w(TAG, "Device not ready: " + state);
            return false;
        }
        
        byte reportId = 0;  // FIDO2 uses single report type
        boolean success = hidDevice.sendReport(device, reportId, report);
        
        if (success) {
            Log.d(TAG, "Sent report (" + report.length + " bytes)");
        } else {
            Log.e(TAG, "Failed to send report");
        }
        
        return success;
    }
    
    /**
     * Check if device is ready
     */
    public boolean isDeviceReady(BluetoothDevice device) {
        if (device == null) return false;
        HidDeviceState state = deviceStates.get(device.getAddress());
        return state == HidDeviceState.ACTIVE || state == HidDeviceState.CONNECTED;
    }
    
    /**
     * Check if service is ready (IHIDTransport interface)
     */
    @Override
    public boolean isReady() {
        return hidDevice != null && isAppRegistered && !connectedDevices.isEmpty();
    }
    
    /**
     * Check if device is discoverable
     * Note: Making device discoverable requires launching an Intent from an Activity.
     * This method only checks the current scan mode.
     * To make discoverable, use: startActivityForResult(new Intent(BluetoothAdapter.ACTION_REQUEST_DISCOVERABLE))
     */
    @SuppressLint("MissingPermission")
    public boolean isDiscoverable() {
        if (bluetoothAdapter == null) return false;
        int scanMode = bluetoothAdapter.getScanMode();
        return scanMode == BluetoothAdapter.SCAN_MODE_CONNECTABLE_DISCOVERABLE;
    }
    
    /**
     * Get bonded devices
     */
    @SuppressLint("MissingPermission")
    public Set<BluetoothDevice> getBondedDevices() {
        if (bluetoothAdapter == null) return Set.of();
        return bluetoothAdapter.getBondedDevices();
    }
    
    /**
     * Check Bluetooth availability
     */
    public static boolean isBluetoothAvailable(Context context) {
        BluetoothManager manager = (BluetoothManager) context.getSystemService(Context.BLUETOOTH_SERVICE);
        if (manager == null) return false;
        BluetoothAdapter adapter = manager.getAdapter();
        return adapter != null && adapter.isEnabled();
    }
    
    /**
     * Request connection to a bonded device
     * Note: In Classic BT HID, the device can request connection to initiate the HID session
     */
    @SuppressLint("MissingPermission")
    public boolean connect(BluetoothDevice device) {
        if (hidDevice == null || !isAppRegistered) {
            Log.e(TAG, "Cannot connect: HID device not registered");
            return false;
        }
        
        if (device == null) {
            Log.e(TAG, "Cannot connect: device is null");
            return false;
        }
        
        Log.i(TAG, "Requesting connection to " + device.getAddress());
        boolean success = hidDevice.connect(device);
        Log.i(TAG, "Connection request " + (success ? "sent" : "failed"));
        return success;
    }
    
    /**
     * Disconnect from a device
     */
    @SuppressLint("MissingPermission")
    public boolean disconnect(BluetoothDevice device) {
        if (hidDevice == null || device == null) {
            return false;
        }
        
        Log.i(TAG, "Disconnecting from " + device.getAddress());
        return hidDevice.disconnect(device);
    }
    
    /**
     * Check if Classic BT HID is supported (API 28+)
     */
    public static boolean isClassicBTHIDSupported() {
        return android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P;
    }
    
    public static boolean isBluetoothEnabled(Context context) {
        return isBluetoothAvailable(context);
    }
    
    // IHIDTransport interface implementation
    @Override
    public void sendInputReport(byte[] report) {
        addInputReport(report);
    }
}

// Made with Bob
