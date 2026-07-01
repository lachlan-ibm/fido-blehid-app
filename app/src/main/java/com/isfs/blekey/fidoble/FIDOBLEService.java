/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.fidoble;

import android.annotation.SuppressLint;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattDescriptor;
import android.bluetooth.BluetoothGattServer;
import android.bluetooth.BluetoothGattServerCallback;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.le.BluetoothLeAdvertiser;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.os.Handler;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;

import com.isfs.blekey.authenticator.AuthenticatorAPI;
import com.isfs.blekey.ctap.CtapBle;
import com.isfs.blekey.ctap.CtapTxn;
import com.isfs.blekey.util.BleUtils;
import com.isfs.blekey.util.Cbor;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * FIDO BLE GATT Service implementation per CTAP specification §11.4.5.
 * 
 * This service provides BLE transport for FIDO2/CTAP2 authentication operations.
 * It implements the FIDO service (UUID 0xFFFD) with four characteristics:
 * - Control Point: Write endpoint for CTAP commands
 * - Status: Notify endpoint for CTAP responses
 * - Control Point Length: Maximum message size
 * - Service Revision Bitfield: Supported FIDO versions
 * 
 * The service handles BLE framing, connection management, and routes messages
 * to the CtapBle processor for CTAP protocol handling.
 */
public class FIDOBLEService {

    private static final String TAG = FIDOBLEService.class.getCanonicalName();

    /**
     * FIDO service connection state for a device.
     */
    public enum FidoConnectionState {
        NOT_CONNECTED,      // Device not connected
        CONNECTED,          // Device connected but not ready
        READY               // Notifications enabled, ready for CTAP
    }

    /**
     * Listener for FIDO service connection events.
     */
    public interface ConnectionListener {
        void onDeviceConnected(BluetoothDevice device);
        void onDeviceDisconnected(BluetoothDevice device);
        void onDeviceReady(BluetoothDevice device);
        void onDeviceAuthenticated(BluetoothDevice device);
        void onDeviceError(BluetoothDevice device, String error);
    }

    // FIDO Service and Characteristics (CTAP spec §11.4.5)
    // Note: These are now defined in BleUtils.java
    private static final int PROPERTY_WRITE = BluetoothGattCharacteristic.PROPERTY_WRITE;
    private static final int PROPERTY_NOTIFY = BluetoothGattCharacteristic.PROPERTY_NOTIFY;
    private static final int PROPERTY_READ = BluetoothGattCharacteristic.PROPERTY_READ;
    
    // MITM-protected permissions for FIDO characteristics (LE Security Mode 1, Level 3)
    private static final int PERMISSION_READ_ENCRYPTED_MITM =
        BluetoothGattCharacteristic.PERMISSION_READ_ENCRYPTED_MITM;
    private static final int PERMISSION_WRITE_ENCRYPTED_MITM =
        BluetoothGattCharacteristic.PERMISSION_WRITE_ENCRYPTED_MITM;
    
    // FIDO BLE Constants (CTAP spec §11.2.9)
    private static final int DEFAULT_MAX_FRAGMENT_SIZE = 512;  // Maximum fragment size
    private static final byte[] SERVICE_REVISION_BITFIELD = new byte[] { 
        (byte) 0x80  // Bit 7 set = FIDO 2.0 supported
    };

    // Client Characteristic Configuration Descriptor
    private static final java.util.UUID DESCRIPTOR_CLIENT_CHARACTERISTIC_CONFIGURATION =
            java.util.UUID.fromString("00002902-0000-1000-8000-00805f9b34fb");

    private final Context applicationContext;
    private final Handler handler;
    private final FIDOBLEAdvertiser bleAdvertiser;
    
    @Nullable
    private BluetoothGattServer gattServer;
    
    private BluetoothGattCharacteristic controlPointCharacteristic;
    private BluetoothGattCharacteristic statusCharacteristic;
    private BluetoothGattCharacteristic controlPointLengthCharacteristic;
    private BluetoothGattCharacteristic serviceRevisionBitfieldCharacteristic;
    
    private final Map<String, BluetoothDevice> connectedDevices = new ConcurrentHashMap<>();
    private final Map<String, FidoConnectionState> deviceStates = new ConcurrentHashMap<>();
    private final Map<String, BroadcastReceiver> bondStateReceivers = new ConcurrentHashMap<>();
    
    @Nullable
    private ConnectionListener connectionListener;

    private final CtapBle ctapBle;
    private final BLEConnectionManager connectionManager;
    private final KeepaliveManager keepaliveManager;
    
    // Background executor for CTAP processing
    private final ExecutorService ctapExecutor;

    /**
     * Creates a new FIDO BLE Service.
     *
     * @param context Application context
     * @throws UnsupportedOperationException if BLE is not supported or permissions not granted
     */
    public FIDOBLEService(@NonNull Context context) throws UnsupportedOperationException {
        this.applicationContext = context.getApplicationContext();
        this.handler = new Handler(applicationContext.getMainLooper());

        // Check Bluetooth permissions
        if (!hasBluetoothConnectPermission() || !hasBluetoothAdvertisePermission()) {
            throw new UnsupportedOperationException("Bluetooth permissions not granted");
        }

        // Get Bluetooth adapter
        final BluetoothManager bluetoothManager = 
            (BluetoothManager) applicationContext.getSystemService(Context.BLUETOOTH_SERVICE);
        
        if (bluetoothManager == null) {
            throw new UnsupportedOperationException("BluetoothManager not available");
        }

        final BluetoothAdapter bluetoothAdapter = bluetoothManager.getAdapter();
        if (bluetoothAdapter == null) {
            throw new UnsupportedOperationException("Bluetooth is not available");
        }

        if (!bluetoothAdapter.isEnabled()) {
            throw new UnsupportedOperationException("Bluetooth is disabled");
        }

        if (!bluetoothAdapter.isMultipleAdvertisementSupported()) {
            throw new UnsupportedOperationException("BLE Advertising not supported");
        }

        final BluetoothLeAdvertiser bluetoothLeAdvertiser = bluetoothAdapter.getBluetoothLeAdvertiser();
        if (bluetoothLeAdvertiser == null) {
            throw new UnsupportedOperationException("BLE Advertising not available");
        }

        // Initialize advertiser
        this.bleAdvertiser = new FIDOBLEAdvertiser(context, handler, bluetoothLeAdvertiser);

        // Open GATT server
        try {
            gattServer = bluetoothManager.openGattServer(applicationContext, gattServerCallback);
            if (gattServer == null) {
                throw new UnsupportedOperationException("Failed to open GATT server");
            }
        } catch (SecurityException e) {
            throw new UnsupportedOperationException("Security exception: " + e.getMessage());
        }

        // Setup FIDO service
        setupFidoService();
        
        this.ctapBle = new CtapBle();
        this.connectionManager = new BLEConnectionManager();
        this.keepaliveManager = new KeepaliveManager(
            frame -> {
                // Deliver keepalive frame to the most-recently-connected device.
                // At most one BLE device is active at a time in the BLE FIDO path.
                if (!connectedDevices.isEmpty()) {
                    sendResponse(connectedDevices.values().iterator().next(), frame);
                }
            });
        this.ctapExecutor = Executors.newSingleThreadExecutor();
        
        Log.d(TAG, "FIDO BLE Service initialized with CTAP integration");
    }

    /**
     * Sets up the FIDO GATT service with all required characteristics.
     *
     * All FIDO characteristics use PERMISSION_*_ENCRYPTED_MITM
     * to enforce LE Security Mode 1, Level 3 (authenticated pairing with MITM protection)
     * per CTAP spec §11.4.2.
     */
    private void setupFidoService() {
        final BluetoothGattService fidoService = new BluetoothGattService(
            BleUtils.SERVICE_FIDO,
            BluetoothGattService.SERVICE_TYPE_PRIMARY
        );

        // 1. FIDO Control Point (Write) - receives CTAP commands
        // MITM protection required per CTAP spec
        controlPointCharacteristic = new BluetoothGattCharacteristic(
            BleUtils.CHAR_FIDO_CONTROL_POINT,
            PROPERTY_WRITE,
            PERMISSION_WRITE_ENCRYPTED_MITM  // Level 3: Authenticated + MITM
        );
        controlPointCharacteristic.setWriteType(BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT);
        fidoService.addCharacteristic(controlPointCharacteristic);

        // 2. FIDO Status (Notify) - sends CTAP responses
        // MITM protection required per CTAP spec
        statusCharacteristic = new BluetoothGattCharacteristic(
            BleUtils.CHAR_FIDO_STATUS,
            PROPERTY_NOTIFY,
            PERMISSION_READ_ENCRYPTED_MITM  // Level 3: Authenticated + MITM
        );
        
        // Add Client Characteristic Configuration Descriptor for notifications
        // CCCD also requires MITM protection
        final BluetoothGattDescriptor cccd = new BluetoothGattDescriptor(
            DESCRIPTOR_CLIENT_CHARACTERISTIC_CONFIGURATION,
            BluetoothGattDescriptor.PERMISSION_READ_ENCRYPTED_MITM |
            BluetoothGattDescriptor.PERMISSION_WRITE_ENCRYPTED_MITM
        );
        statusCharacteristic.addDescriptor(cccd);
        fidoService.addCharacteristic(statusCharacteristic);

        // 3. FIDO Control Point Length (Read) - maximum message size
        // MITM protection required per CTAP spec
        controlPointLengthCharacteristic = new BluetoothGattCharacteristic(
            BleUtils.CHAR_FIDO_CONTROL_POINT_LENGTH,
            PROPERTY_READ,
            PERMISSION_READ_ENCRYPTED_MITM  // Level 3: Authenticated + MITM
        );
        fidoService.addCharacteristic(controlPointLengthCharacteristic);

        // 4. FIDO Service Revision Bitfield (Read/Write) - supported FIDO versions
        // MITM protection required per CTAP spec
        serviceRevisionBitfieldCharacteristic = new BluetoothGattCharacteristic(
            BleUtils.CHAR_FIDO_SERVICE_REVISION_BITFIELD,
            PROPERTY_READ | PROPERTY_WRITE,  // Read and Write per spec
            PERMISSION_READ_ENCRYPTED_MITM | PERMISSION_WRITE_ENCRYPTED_MITM  // Level 3
        );
        fidoService.addCharacteristic(serviceRevisionBitfieldCharacteristic);

        // Add service to GATT server
        if (gattServer != null) {
            boolean added = gattServer.addService(fidoService);
            Log.d(TAG, "FIDO service added with MITM-protected characteristics: " + added);
        }
    }

    /**
     * Starts advertising the FIDO service.
     */
    public void startAdvertising() {
        bleAdvertiser.start();
        Log.d(TAG, "FIDO advertising started");
    }

    /**
     * Stops advertising the FIDO service.
     */
    public void stopAdvertising() {
        bleAdvertiser.stop();
        Log.d(TAG, "FIDO advertising stopped");
    }

    /**
     * Sets the connection listener.
     */
    public void setConnectionListener(@Nullable ConnectionListener listener) {
        this.connectionListener = listener;
    }

    /**
     * Gets all connected devices.
     */
    public Set<BluetoothDevice> getConnectedDevices() {
        return Set.copyOf(connectedDevices.values());
    }

    /**
     * Gets the connection state for a device.
     */
    public FidoConnectionState getDeviceState(@NonNull String address) {
        return deviceStates.getOrDefault(address, FidoConnectionState.NOT_CONNECTED);
    }

    /**
     * Sends a CTAP response to a device via the Status characteristic.
     * 
     * @param device Target device
     * @param data Response data
     */
    @SuppressLint("MissingPermission")
    public void sendResponse(@NonNull BluetoothDevice device, @NonNull byte[] data) {
        if (gattServer == null || statusCharacteristic == null) {
            Log.e(TAG, "GATT server or status characteristic not initialized");
            return;
        }

        if (!hasBluetoothConnectPermission()) {
            Log.e(TAG, "Missing BLUETOOTH_CONNECT permission");
            return;
        }

        handler.post(() -> {
            try {
                int result = gattServer.notifyCharacteristicChanged(
                    device, 
                    statusCharacteristic, 
                    false, 
                    data
                );
                Log.d(TAG, "Sent response to " + device.getAddress() + 
                    ", result=" + result + ", length=" + data.length);
            } catch (Exception e) {
                Log.e(TAG, "Failed to send response: " + e.getMessage());
                if (connectionListener != null) {
                    connectionListener.onDeviceError(device, "Failed to send response");
                }
            }
        });
    }

    /**
     * Closes the FIDO BLE service and releases resources.
     */
    @SuppressLint("MissingPermission")
    public void close() {
        stopAdvertising();
        
        // Unregister all bond state receivers
        for (BroadcastReceiver receiver : bondStateReceivers.values()) {
            try {
                applicationContext.unregisterReceiver(receiver);
            } catch (Exception e) {
                Log.w(TAG, "Error unregistering bond state receiver: " + e.getMessage());
            }
        }
        bondStateReceivers.clear();
        
        // Shutdown keepalive manager
        if (keepaliveManager != null) {
            keepaliveManager.shutdown();
        }
        
        // Shutdown CTAP executor
        if (ctapExecutor != null) {
            ctapExecutor.shutdown();
        }
        
        if (gattServer != null) {
            try {
                gattServer.close();
            } catch (Exception e) {
                Log.e(TAG, "Error closing GATT server: " + e.getMessage());
            }
            gattServer = null;
        }
        
        connectedDevices.clear();
        deviceStates.clear();
        
        if (connectionManager != null) {
            connectionManager.clear();
        }
        
        Log.d(TAG, "FIDO BLE Service closed");
    }

    /**
     * GATT Server callback for handling BLE events.
     */
    private final BluetoothGattServerCallback gattServerCallback = new BluetoothGattServerCallback() {

        @Override
        @SuppressLint("MissingPermission")
        public void onConnectionStateChange(BluetoothDevice device, int status, int newState) {
            super.onConnectionStateChange(device, status, newState);
            
            Log.d(TAG, "Connection state change: device=" + device.getAddress() +
                ", status=" + status + ", newState=" + newState);

            if (status != BluetoothGatt.GATT_SUCCESS) {
                Log.e(TAG, "GATT error: status=" + status);
                handleDeviceError(device, "GATT error: " + status);
                return;
            }

            switch (newState) {
                case BluetoothProfile.STATE_CONNECTED:
                    handleDeviceConnected(device);
                    
                    // Check bond state and enforce security
                    int bondState = device.getBondState();
                    Log.i(TAG, "Device connected with bondState=" + getBondStateString(bondState));
                    
                    if (bondState == BluetoothDevice.BOND_NONE) {
                        // Not paired - client must initiate pairing by accessing encrypted characteristic
                        Log.i(TAG, "Device not bonded, waiting for pairing request");
                        // Android will automatically trigger pairing when client tries to access
                        // a characteristic with PERMISSION_*_ENCRYPTED_MITM
                        
                    } else if (bondState == BluetoothDevice.BOND_BONDING) {
                        // Pairing in progress
                        Log.i(TAG, "Device bonding in progress");
                        registerBondStateReceiver(device);
                        
                    } else if (bondState == BluetoothDevice.BOND_BONDED) {
                        // Already paired - verify security level
                        Log.i(TAG, "Device already bonded, ready for FIDO operations");
                        onDeviceAuthenticated(device);
                    }
                    break;

                case BluetoothProfile.STATE_DISCONNECTED:
                    handleDeviceDisconnected(device);
                    break;

                default:
                    Log.d(TAG, "Unknown connection state: " + newState);
                    break;
            }
        }

        @Override
        public void onCharacteristicReadRequest(
                BluetoothDevice device,
                int requestId,
                int offset,
                BluetoothGattCharacteristic characteristic) {
            
            Log.d(TAG, "Read request: device=" + device.getAddress() +
                ", char=" + characteristic.getUuid() + ", offset=" + offset);

            // Verify device is bonded before processing FIDO requests
            if (isFIDOCharacteristic(characteristic.getUuid())) {
                if (device.getBondState() != BluetoothDevice.BOND_BONDED) {
                    Log.w(TAG, "Rejecting FIDO read from unbonded device: " + device.getAddress());
                    if (gattServer != null) {
                        gattServer.sendResponse(device, requestId,
                            BluetoothGatt.GATT_INSUFFICIENT_AUTHENTICATION, offset, null);
                    }
                    return;
                }
            }

            byte[] value = null;

            if (BleUtils.CHAR_FIDO_CONTROL_POINT_LENGTH.equals(characteristic.getUuid())) {
                // Return maximum fragment size as 2-byte little-endian
                ByteBuffer buffer = ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN);
                buffer.putShort((short) DEFAULT_MAX_FRAGMENT_SIZE);
                value = buffer.array();
                Log.d(TAG, "Returning Control Point Length: " + DEFAULT_MAX_FRAGMENT_SIZE);
                
            } else if (BleUtils.CHAR_FIDO_SERVICE_REVISION_BITFIELD.equals(characteristic.getUuid())) {
                // Return service revision bitfield
                value = SERVICE_REVISION_BITFIELD;
                Log.d(TAG, "Returning Service Revision Bitfield: " + Arrays.toString(value));
            }

            if (value != null && gattServer != null) {
                gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value);
            } else {
                if (gattServer != null) {
                    gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null);
                }
            }
        }

        @Override
        public void onCharacteristicWriteRequest(
                BluetoothDevice device,
                int requestId,
                BluetoothGattCharacteristic characteristic,
                boolean preparedWrite,
                boolean responseNeeded,
                int offset,
                byte[] value) {
            
            Log.d(TAG, "Write request: device=" + device.getAddress() +
                ", char=" + characteristic.getUuid() +
                ", offset=" + offset + ", length=" + (value != null ? value.length : 0));

            // Verify device is bonded before processing FIDO requests
            if (isFIDOCharacteristic(characteristic.getUuid())) {
                if (device.getBondState() != BluetoothDevice.BOND_BONDED) {
                    Log.w(TAG, "Rejecting FIDO write from unbonded device: " + device.getAddress());
                    if (responseNeeded && gattServer != null) {
                        gattServer.sendResponse(device, requestId,
                            BluetoothGatt.GATT_INSUFFICIENT_AUTHENTICATION, offset, null);
                    }
                    return;
                }
            }

            if (BleUtils.CHAR_FIDO_CONTROL_POINT.equals(characteristic.getUuid())) {
                handleControlPointWrite(device, value);
                
                if (responseNeeded && gattServer != null) {
                    gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, null);
                }
            } else if (BleUtils.CHAR_FIDO_SERVICE_REVISION_BITFIELD.equals(characteristic.getUuid())) {
                // Service Revision Bitfield write (optional per spec)
                Log.d(TAG, "Service Revision Bitfield write: " + Arrays.toString(value));
                
                if (responseNeeded && gattServer != null) {
                    gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, null);
                }
            } else {
                if (responseNeeded && gattServer != null) {
                    gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null);
                }
            }
        }

        @Override
        public void onDescriptorWriteRequest(
                BluetoothDevice device,
                int requestId,
                BluetoothGattDescriptor descriptor,
                boolean preparedWrite,
                boolean responseNeeded,
                int offset,
                byte[] value) {
            
            Log.d(TAG, "Descriptor write: device=" + device.getAddress() + 
                ", descriptor=" + descriptor.getUuid());

            // Handle CCCD writes for notifications
            if (DESCRIPTOR_CLIENT_CHARACTERISTIC_CONFIGURATION.equals(descriptor.getUuid())) {
                if (value != null && value.length == 2) {
                    boolean notificationsEnabled = (value[0] & 0x01) != 0;
                    Log.d(TAG, "Notifications " + (notificationsEnabled ? "enabled" : "disabled") + 
                        " for device " + device.getAddress());
                    
                    if (notificationsEnabled) {
                        handleDeviceReady(device);
                    }
                }
                
                if (responseNeeded && gattServer != null) {
                    gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value);
                }
            } else {
                if (responseNeeded && gattServer != null) {
                    gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null);
                }
            }
        }

        @Override
        public void onDescriptorReadRequest(
                BluetoothDevice device,
                int requestId,
                int offset,
                BluetoothGattDescriptor descriptor) {
            
            Log.d(TAG, "Descriptor read: device=" + device.getAddress() + 
                ", descriptor=" + descriptor.getUuid());

            // Return disabled notifications by default
            if (DESCRIPTOR_CLIENT_CHARACTERISTIC_CONFIGURATION.equals(descriptor.getUuid())) {
                byte[] value = new byte[] { 0x00, 0x00 };
                if (gattServer != null) {
                    gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value);
                }
            } else {
                if (gattServer != null) {
                    gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null);
                }
            }
        }
    };

    /**
     * Handles device connection.
     */
    private void handleDeviceConnected(@NonNull BluetoothDevice device) {
        connectedDevices.put(device.getAddress(), device);
        deviceStates.put(device.getAddress(), FidoConnectionState.CONNECTED);
        connectionManager.onDeviceConnected(device);
        
        Log.d(TAG, "Device connected: " + device.getAddress());
        
        handler.post(() -> {
            if (connectionListener != null) {
                connectionListener.onDeviceConnected(device);
            }
        });
    }

    /**
     * Handles device disconnection.
     */
    private void handleDeviceDisconnected(@NonNull BluetoothDevice device) {
        connectedDevices.remove(device.getAddress());
        deviceStates.remove(device.getAddress());
        connectionManager.onDeviceDisconnected(device);
        keepaliveManager.stopKeepalive(device.getAddress());
        
        Log.d(TAG, "Device disconnected: " + device.getAddress());
        
        handler.post(() -> {
            if (connectionListener != null) {
                connectionListener.onDeviceDisconnected(device);
            }
        });
    }

    /**
     * Handles device ready (notifications enabled).
     */
    private void handleDeviceReady(@NonNull BluetoothDevice device) {
        deviceStates.put(device.getAddress(), FidoConnectionState.READY);
        
        Log.d(TAG, "Device ready: " + device.getAddress());
        
        handler.post(() -> {
            if (connectionListener != null) {
                connectionListener.onDeviceReady(device);
            }
        });
    }

    /**
     * Handles device error.
     */
    private void handleDeviceError(@NonNull BluetoothDevice device, @NonNull String error) {
        connectedDevices.remove(device.getAddress());
        deviceStates.remove(device.getAddress());
        connectionManager.onDeviceDisconnected(device);
        keepaliveManager.stopKeepalive(device.getAddress());
        
        Log.e(TAG, "Device error: " + device.getAddress() + " - " + error);
        
        handler.post(() -> {
            if (connectionListener != null) {
                connectionListener.onDeviceError(device, error);
            }
        });
    }

    /**
     * Checks if a UUID is a FIDO characteristic.
     *
     * @param uuid The characteristic UUID
     * @return true if it's a FIDO characteristic
     */
    private boolean isFIDOCharacteristic(java.util.UUID uuid) {
        return BleUtils.CHAR_FIDO_CONTROL_POINT.equals(uuid) ||
               BleUtils.CHAR_FIDO_STATUS.equals(uuid) ||
               BleUtils.CHAR_FIDO_CONTROL_POINT_LENGTH.equals(uuid) ||
               BleUtils.CHAR_FIDO_SERVICE_REVISION_BITFIELD.equals(uuid);
    }

    /**
     * Gets a human-readable bond state string.
     *
     * @param bondState The bond state constant
     * @return String representation
     */
    private String getBondStateString(int bondState) {
        switch (bondState) {
            case BluetoothDevice.BOND_NONE: return "BOND_NONE";
            case BluetoothDevice.BOND_BONDING: return "BOND_BONDING";
            case BluetoothDevice.BOND_BONDED: return "BOND_BONDED";
            default: return "UNKNOWN(" + bondState + ")";
        }
    }

    /**
     * Registers a BroadcastReceiver to monitor pairing process for a device.
     *
     * Monitors bond state changes during pairing to detect when
     * the device becomes authenticated.
     *
     * @param device The device being paired
     */
    private void registerBondStateReceiver(@NonNull BluetoothDevice device) {
        String address = device.getAddress();
        
        // Don't register if already registered
        if (bondStateReceivers.containsKey(address)) {
            Log.d(TAG, "Bond state receiver already registered for " + address);
            return;
        }
        
        IntentFilter filter = new IntentFilter(BluetoothDevice.ACTION_BOND_STATE_CHANGED);
        
        BroadcastReceiver bondStateReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                if (!BluetoothDevice.ACTION_BOND_STATE_CHANGED.equals(intent.getAction())) {
                    return;
                }
                
                BluetoothDevice bondedDevice = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
                if (bondedDevice == null || !bondedDevice.getAddress().equals(device.getAddress())) {
                    return;
                }
                
                int bondState = intent.getIntExtra(BluetoothDevice.EXTRA_BOND_STATE, BluetoothDevice.ERROR);
                int previousBondState = intent.getIntExtra(BluetoothDevice.EXTRA_PREVIOUS_BOND_STATE, BluetoothDevice.ERROR);
                
                Log.i(TAG, "Bond state changed: " + getBondStateString(previousBondState) +
                          " -> " + getBondStateString(bondState) +
                          " for device: " + bondedDevice.getAddress());
                
                if (bondState == BluetoothDevice.BOND_BONDED) {
                    Log.i(TAG, "Device successfully bonded, ready for FIDO operations");
                    unregisterBondStateReceiver(device);
                    onDeviceAuthenticated(bondedDevice);
                    
                } else if (bondState == BluetoothDevice.BOND_NONE &&
                          previousBondState == BluetoothDevice.BOND_BONDING) {
                    Log.w(TAG, "Pairing failed or cancelled");
                    unregisterBondStateReceiver(device);
                    // Optionally disconnect device
                    if (gattServer != null) {
                        gattServer.cancelConnection(bondedDevice);
                    }
                }
            }
        };
        
        bondStateReceivers.put(address, bondStateReceiver);
        applicationContext.registerReceiver(bondStateReceiver, filter);
        Log.d(TAG, "Registered bond state receiver for " + address);
    }

    /**
     * Unregisters the bond state receiver for a device.
     *
     * @param device The device
     */
    private void unregisterBondStateReceiver(@NonNull BluetoothDevice device) {
        String address = device.getAddress();
        BroadcastReceiver receiver = bondStateReceivers.remove(address);
        
        if (receiver != null) {
            try {
                applicationContext.unregisterReceiver(receiver);
                Log.d(TAG, "Unregistered bond state receiver for " + address);
            } catch (Exception e) {
                Log.w(TAG, "Error unregistering bond state receiver: " + e.getMessage());
            }
        }
    }

    /**
     * Called when a device is authenticated (bonded and ready for FIDO operations).
     *
     * This is called after successful pairing with MITM protection.
     *
     * @param device The authenticated device
     */
    private void onDeviceAuthenticated(@NonNull BluetoothDevice device) {
        Log.i(TAG, "Device authenticated: " + device.getAddress());
        
        // Notify listener
        handler.post(() -> {
            if (connectionListener != null) {
                connectionListener.onDeviceAuthenticated(device);
            }
        });
    }

    /**
     * Handles Control Point characteristic write (CTAP command received).
     *
     * Phase 2 & 3: Implements BLE framing and routes to AuthenticatorAPI
     */
    private void handleControlPointWrite(@NonNull BluetoothDevice device, @Nullable byte[] data) {
        if (data == null || data.length == 0) {
            Log.w(TAG, "Empty Control Point write from " + device.getAddress());
            return;
        }

        Log.d(TAG, "Control Point write from " + device.getAddress() +
            ": " + data.length + " bytes");

        try {
            // Add fragment to connection manager
            connectionManager.addFragment(device, data);

            // Check if we have a complete message
            if (connectionManager.hasCompleteMessage(device)) {
                Log.d(TAG, "Complete message received from " + device.getAddress());
                
                // Get all fragments and reassemble
                List<byte[]> fragments = connectionManager.getPendingFragments(device);
                byte[] completeMessage = ctapBle.reassembleFragments(fragments);
                
                // Clear fragments after successful reassembly
                connectionManager.clearFragments(device);
                
                // Process the CTAP message asynchronously
                processCtapMessage(device, completeMessage);
            } else {
                Log.d(TAG, "Waiting for more fragments from " + device.getAddress());
            }
            
        } catch (Exception e) {
            Log.e(TAG, "Error handling Control Point write: " + e.getMessage(), e);
            connectionManager.clearFragments(device);
            
            // Send error response
            byte[] errorResponse = ctapBle.frameResponse(
                CtapBle.STATUS_INVALID_PAR,
                new byte[0]
            );
            sendResponse(device, errorResponse);
        }
    }

    /**
     * Processes a complete CTAP message and routes to AuthenticatorAPI.
     *
     * @param device The device that sent the message
     * @param message The complete CTAP message
     */
    private void processCtapMessage(@NonNull BluetoothDevice device, @NonNull byte[] message) {
        // Process on background thread to avoid blocking BLE callbacks
        ctapExecutor.execute(() -> {
            try {
                Log.d(TAG, "Processing CTAP message from " + device.getAddress() +
                    ", length=" + message.length);

                // Parse the BLE frame to extract command and data
                Object[] parsed = ctapBle.parseRequest(message);
                byte cmd = (byte) parsed[0];
                byte[] data = (byte[]) parsed[1];

                Log.d(TAG, "CTAP command: 0x" + String.format("%02X", cmd) +
                    ", data length: " + data.length);

                // Handle special commands
                if (cmd == CtapBle.CMD_PING) {
                    // Echo back the data
                    byte[] response = ctapBle.frameResponse(CtapBle.STATUS_SUCCESS, data);
                    sendResponse(device, response);
                    return;
                }

                if (cmd == CtapBle.CMD_CANCEL) {
                    // Cancel current operation
                    keepaliveManager.stopKeepalive(device.getAddress());
                    byte[] response = ctapBle.frameResponse(CtapBle.STATUS_SUCCESS, new byte[0]);
                    sendResponse(device, response);
                    return;
                }

                // For CTAP commands (CMD_MSG, CMD_CBOR), route to AuthenticatorAPI
                if (cmd == CtapBle.CMD_MSG || cmd == CtapBle.CMD_CBOR) {
                    // Start keepalive for long operations
                    keepaliveManager.startKeepalive(device.getAddress(), KeepaliveManager.STATUS_PROCESSING);

                    try {
                        // Parse CBOR request
                        Map<Integer, Object> request = null;
                        int ctapCommand = 0;

                        if (cmd == CtapBle.CMD_CBOR && data.length > 0) {
                            // First byte is CTAP command, rest is CBOR
                            ctapCommand = data[0] & 0xFF;
                            if (data.length > 1) {
                                byte[] cborData = Arrays.copyOfRange(data, 1, data.length);
                                Object decoded = Cbor.decode(cborData);
                                if (decoded instanceof Map) {
                                    @SuppressWarnings("unchecked")
                                    Map<Integer, Object> map = (Map<Integer, Object>) decoded;
                                    request = map;
                                }
                            }
                        }

                        // Create CTAP transaction for BLE transport
                        int deviceMtu = connectionManager.getMtu(device);
                        CtapTxn txn = new CtapTxn(device.getAddress(), deviceMtu, null, null, null);

                        // Process through AuthenticatorAPI
                        byte[] responseData = AuthenticatorAPI.process(txn, ctapCommand, request);

                        // Stop keepalive
                        keepaliveManager.stopKeepalive(device.getAddress());

                        // Frame and send response
                        byte[] response = ctapBle.frameResponse(CtapBle.STATUS_SUCCESS, responseData);
                        
                        // Fragment if needed based on device MTU
                        List<byte[]> responseFragments = ctapBle.fragmentMessage(response, deviceMtu);
                        
                        // Send all fragments
                        for (byte[] fragment : responseFragments) {
                            sendResponse(device, fragment);
                            // Small delay between fragments to avoid overwhelming the client
                            if (responseFragments.size() > 1) {
                                Thread.sleep(10);
                            }
                        }

                        Log.d(TAG, "CTAP response sent to " + device.getAddress() +
                            ", fragments=" + responseFragments.size());

                    } catch (Exception e) {
                        Log.e(TAG, "Error processing CTAP command: " + e.getMessage(), e);
                        keepaliveManager.stopKeepalive(device.getAddress());
                        
                        // Send error response
                        byte[] errorResponse = ctapBle.frameResponse(
                            CtapBle.STATUS_INVALID_CMD,
                            new byte[0]
                        );
                        sendResponse(device, errorResponse);
                    }
                } else {
                    // Unknown command
                    Log.w(TAG, "Unknown CTAP command: 0x" + String.format("%02X", cmd));
                    byte[] errorResponse = ctapBle.frameResponse(
                        CtapBle.STATUS_INVALID_CMD,
                        new byte[0]
                    );
                    sendResponse(device, errorResponse);
                }

            } catch (Exception e) {
                Log.e(TAG, "Error processing CTAP message: " + e.getMessage(), e);
                
                // Send error response
                byte[] errorResponse = ctapBle.frameResponse(
                    CtapBle.STATUS_INVALID_PAR,
                    new byte[0]
                );
                sendResponse(device, errorResponse);
            }
        });
    }

    /**
     * Checks if BLUETOOTH_CONNECT permission is granted.
     */
    private boolean hasBluetoothConnectPermission() {
        return ContextCompat.checkSelfPermission(
            applicationContext,
            android.Manifest.permission.BLUETOOTH_CONNECT
        ) == PackageManager.PERMISSION_GRANTED;
    }

    /**
     * Checks if BLUETOOTH_ADVERTISE permission is granted.
     */
    private boolean hasBluetoothAdvertisePermission() {
        return ContextCompat.checkSelfPermission(
            applicationContext,
            android.Manifest.permission.BLUETOOTH_ADVERTISE
        ) == PackageManager.PERMISSION_GRANTED;
    }
}

// Made with Bob
