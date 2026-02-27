/*
 * Copyright IBM 2025
 */


package com.isfs.blekey.hidsvc;

import java.util.Collections;
import java.util.UUID;
import java.util.Set;
import java.util.Queue;
import java.util.Map;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Arrays;
import java.util.Timer;
import java.util.TimerTask;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentLinkedQueue;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Handler;
import android.os.ParcelUuid;
import android.os.Build;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.BroadcastReceiver;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattServer;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothGattServerCallback;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothGattDescriptor;
import android.bluetooth.le.AdvertiseCallback;
import android.bluetooth.le.AdvertiseData;
import android.bluetooth.le.AdvertiseData.Builder;
import android.bluetooth.le.AdvertiseSettings;
import android.bluetooth.le.BluetoothLeAdvertiser;
import android.content.pm.PackageManager;
import android.util.Log;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;

import com.isfs.blekey.R;
import com.isfs.blekey.activity.ServerActivity;
import com.isfs.blekey.util.BleUtils;


public class HIDService {

    private static final String TAG = HIDService.class.getCanonicalName();

    private String manufacturer = "lowkey";
    private String deviceName = "IBleKey";
    private String serialNumber = "13371337";

    private final Context applicationContext;
    private final Handler handler;
    private final BluetoothLeAdvertiser bluetoothLeAdvertiser;
    private BluetoothGattCharacteristic inputReportCharacteristic;
    private BluetoothGattCharacteristic outputReportCharacteristic;
    @Nullable
    private BluetoothGattServer gattServer;
    private final Map<String, BluetoothDevice> bluetoothDevicesMap = new HashMap<>();
    

    private HIDPasskey passkey;

    /**
     * Device Information Service
     */
    private static final UUID SERVICE_DEVICE_INFORMATION = BleUtils.getCharateristicUuid(0x180A);
    private static final UUID CHARACTERISTIC_MANUFACTURER_NAME = BleUtils.getCharateristicUuid(0x2A29);
    private static final UUID CHARACTERISTIC_MODEL_NUMBER = BleUtils.getCharateristicUuid(0x2A24);
    private static final UUID CHARACTERISTIC_SERIAL_NUMBER = BleUtils.getCharateristicUuid(0x2A25);
    private static final int DEVICE_INFO_MAX_LENGTH = 20;

    /**
     * Battery Service
     */
    private static final UUID SERVICE_BATTERY = BleUtils.getCharateristicUuid(0x180F);
    private static final UUID CHARACTERISTIC_BATTERY_LEVEL = BleUtils.getCharateristicUuid(0x2A19);

    /**
     * HID Service
     */
    private static final UUID SERVICE_BLE_HID = BleUtils.getCharateristicUuid(0x1812);
    private static final UUID CHARACTERISTIC_HID_INFORMATION = BleUtils.getCharateristicUuid(0x2A4A);
    private static final UUID CHARACTERISTIC_REPORT_MAP = BleUtils.getCharateristicUuid(0x2A4B);
    private static final UUID CHARACTERISTIC_HID_CONTROL_POINT = BleUtils.getCharateristicUuid(0x2A4C);
    private static final UUID CHARACTERISTIC_REPORT = BleUtils.getCharateristicUuid(0x2A4D);
    private static final UUID CHARACTERISTIC_PROTOCOL_MODE = BleUtils.getCharateristicUuid(0x2A4E);

    /**
     * Gatt Characteristic Descriptor
     */
    private static final UUID DESCRIPTOR_REPORT_REFERENCE = BleUtils.getCharateristicUuid(0x2908);
    private static final UUID DESCRIPTOR_CLIENT_CHARACTERISTIC_CONFIGURATION = BleUtils.getCharateristicUuid(0x2902);

    private static final byte[] EMPTY_BYTES = {};
    private static final byte[] RESPONSE_HID_INFORMATION = {0x11, 0x01, 0x00, 0x03};

    public HIDService(final Context context, boolean bToothConnect, boolean bToothAdvertise) throws UnsupportedOperationException {
        applicationContext = context.getApplicationContext();
        if(!bToothConnect || !bToothAdvertise) {
            Log.e(TAG, "Bluetooth is not available/permitted...back to main");
            ServerActivity sa = (ServerActivity) context;
            Toast.makeText(sa, sa.getString(R.string.ble_perip_not_supported), Toast.LENGTH_SHORT).show();
            sa.finish();
        }
        handler = new Handler(applicationContext.getMainLooper());

        final BluetoothManager bluetoothManager = (BluetoothManager) applicationContext.getSystemService(Context.BLUETOOTH_SERVICE);

        final BluetoothAdapter bluetoothAdapter = bluetoothManager.getAdapter();
        if (bluetoothAdapter == null) {
            throw new UnsupportedOperationException("Bluetooth is not available.");
        }

        if (!bluetoothAdapter.isEnabled()) {
            throw new UnsupportedOperationException("Bluetooth is disabled.");
        }

        Log.d(TAG, "isMultipleAdvertisementSupported:" + bluetoothAdapter.isMultipleAdvertisementSupported());
        if (!bluetoothAdapter.isMultipleAdvertisementSupported()) {
            throw new UnsupportedOperationException("Bluetooth LE Advertising not supported on this device.");
        }

        bluetoothLeAdvertiser = bluetoothAdapter.getBluetoothLeAdvertiser();
        Log.d(TAG, "bluetoothLeAdvertiser: " + bluetoothLeAdvertiser);
        if (bluetoothLeAdvertiser == null) {
            throw new UnsupportedOperationException("Bluetooth LE Advertising not supported on this device.");
        }
        try {
            gattServer = bluetoothManager.openGattServer(applicationContext, gattServerCallback);
            if (gattServer == null) {
                throw new UnsupportedOperationException("gattServer is null, check Bluetooth is ON.");
            }
        } catch (SecurityException e) {
            throw new UnsupportedOperationException(e.getMessage());
        }

        // setup services
        addService(setUpHidService());
        addService(setUpDeviceInformationService());
        addService(setUpBatteryService());
        
        // send report each 50ms, if data available
        new Timer().scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                final byte[] polled = inputReportQueue.poll();
                if (polled != null && inputReportCharacteristic != null) {
                    //inputReportCharacteristic.setValue(polled); notifyCharacteristicChanged method updated
                    handler.post(new Runnable() {
                        @Override
                        @SuppressLint("MissingPermission")
                        public void run() {
                            final Set<BluetoothDevice> devices = getDevices();
                            for (final BluetoothDevice device : devices) {
                                try {
                                    if (gattServer != null && isPermitBToothConnect()) {
                                        gattServer.notifyCharacteristicChanged(device, inputReportCharacteristic, false, polled);
                                    }
                                } catch (final Throwable t) {
                                    Log.e(TAG, "Exception: " + t.getMessage());
                                }
                            }
                        }
                    });
                }
            }
        }, 0, 50);

        //create the passkey object
        this.passkey = new HIDPasskey(this);
    }

    // Check for BLUETOOTH_CONNECT permission
    private boolean isPermitBToothConnect() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            if (ContextCompat.checkSelfPermission(applicationContext, android.Manifest.permission.BLUETOOTH_CONNECT)
                    == PackageManager.PERMISSION_GRANTED) {
                return true;
            } else {
                Log.e(TAG, "BLUETOOTH_CONNECT permission not granted");
            }
            return false;
        }
        return true;
    }
    
    // Check for BLUETOOTH_ADVERTISE permission
    private boolean isPermitBToothAdvert() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            if (ContextCompat.checkSelfPermission(applicationContext, android.Manifest.permission.BLUETOOTH_ADVERTISE)
                    == PackageManager.PERMISSION_GRANTED) {
                return true;
            } else {
                Log.e(TAG, "BLUETOOTH_ADVERTISE permission not granted");
            }
            return false;
        }
        return true;
    }


    /**
     * Add GATT service to gattServer
     *
     * @param service the service
     */
    @SuppressLint("MissingPermission")
    private void addService(final BluetoothGattService service) {
        assert gattServer != null;
        boolean serviceAdded = false;
        while (!serviceAdded) {
            try {
                if(isPermitBToothConnect()) {
                    serviceAdded = gattServer.addService(service);
                }
            } catch (final Exception e) {
                Log.d(TAG, "Adding Service failed", e);
            }
        }
        Log.d(TAG, "Service: " + service.getUuid() + " added.");
    }

    /**
     * Setup Device Information Service
     *
     * @return the service
     */
    private static BluetoothGattService setUpDeviceInformationService() {
        final BluetoothGattService service = new BluetoothGattService(SERVICE_DEVICE_INFORMATION, BluetoothGattService.SERVICE_TYPE_PRIMARY);
        {
            final BluetoothGattCharacteristic characteristic = new BluetoothGattCharacteristic(CHARACTERISTIC_MANUFACTURER_NAME, BluetoothGattCharacteristic.PROPERTY_READ, BluetoothGattCharacteristic.PERMISSION_READ_ENCRYPTED);
            while (!service.addCharacteristic(characteristic));
        }
        {
            final BluetoothGattCharacteristic characteristic = new BluetoothGattCharacteristic(CHARACTERISTIC_MODEL_NUMBER, BluetoothGattCharacteristic.PROPERTY_READ, BluetoothGattCharacteristic.PERMISSION_READ_ENCRYPTED);
            while (!service.addCharacteristic(characteristic));
        }
        {
            final BluetoothGattCharacteristic characteristic = new BluetoothGattCharacteristic(CHARACTERISTIC_SERIAL_NUMBER, BluetoothGattCharacteristic.PROPERTY_READ, BluetoothGattCharacteristic.PERMISSION_READ_ENCRYPTED);
            while (!service.addCharacteristic(characteristic)) ;
        }

        return service;
    }


    /**
     * Setup Battery Service
     *
     * @return the service
     */
    private static BluetoothGattService setUpBatteryService() {
        final BluetoothGattService service = new BluetoothGattService(SERVICE_BATTERY, BluetoothGattService.SERVICE_TYPE_PRIMARY);

        // Battery Level
        final BluetoothGattCharacteristic characteristic = new BluetoothGattCharacteristic(
                CHARACTERISTIC_BATTERY_LEVEL,
                BluetoothGattCharacteristic.PROPERTY_NOTIFY | BluetoothGattCharacteristic.PROPERTY_READ,
                BluetoothGattCharacteristic.PERMISSION_READ_ENCRYPTED);

        final BluetoothGattDescriptor clientCharacteristicConfigurationDescriptor = new BluetoothGattDescriptor(
                DESCRIPTOR_CLIENT_CHARACTERISTIC_CONFIGURATION,
                BluetoothGattDescriptor.PERMISSION_READ | BluetoothGattDescriptor.PERMISSION_WRITE);
        // Note: As per Android issue #280288203, we should not set values directly on descriptors
        // Instead, we'll provide the value when responding to descriptor read requests
        characteristic.addDescriptor(clientCharacteristicConfigurationDescriptor);

        while (!service.addCharacteristic(characteristic));

        return service;
    }

    private void _addBaseServices(BluetoothGattService service) {
        // HID Information
        {
            final BluetoothGattCharacteristic characteristic = new BluetoothGattCharacteristic(
                    CHARACTERISTIC_HID_INFORMATION,
                    BluetoothGattCharacteristic.PROPERTY_READ,
                    BluetoothGattCharacteristic.PERMISSION_READ_ENCRYPTED);

            while (!service.addCharacteristic(characteristic));
        }

        // Report Map
        {
            final BluetoothGattCharacteristic characteristic = new BluetoothGattCharacteristic(
                    CHARACTERISTIC_REPORT_MAP,
                    BluetoothGattCharacteristic.PROPERTY_READ,
                    BluetoothGattCharacteristic.PERMISSION_READ_ENCRYPTED);

            while (!service.addCharacteristic(characteristic));
        }

        // Protocol Mode
        {
            final BluetoothGattCharacteristic characteristic = new BluetoothGattCharacteristic(
                    CHARACTERISTIC_PROTOCOL_MODE,
                    BluetoothGattCharacteristic.PROPERTY_READ | BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
                    BluetoothGattCharacteristic.PERMISSION_READ_ENCRYPTED | BluetoothGattCharacteristic.PERMISSION_WRITE_ENCRYPTED);
            characteristic.setWriteType(BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE);

            while(!service.addCharacteristic(characteristic));
        }

        // HID Control Point
        {
            final BluetoothGattCharacteristic characteristic = new BluetoothGattCharacteristic(
                    CHARACTERISTIC_HID_CONTROL_POINT,
                    BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
                    BluetoothGattCharacteristic.PERMISSION_WRITE_ENCRYPTED);
            characteristic.setWriteType(BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE);

            while (!service.addCharacteristic(characteristic));
        }
    }

    private void _addInputDescriptor(BluetoothGattService service) {
        // Input Report
        inputReportCharacteristic = new BluetoothGattCharacteristic(
                CHARACTERISTIC_REPORT,
                BluetoothGattCharacteristic.PROPERTY_NOTIFY | BluetoothGattCharacteristic.PROPERTY_READ | BluetoothGattCharacteristic.PROPERTY_WRITE,
                BluetoothGattCharacteristic.PERMISSION_READ_ENCRYPTED | BluetoothGattCharacteristic.PERMISSION_WRITE_ENCRYPTED);

        final BluetoothGattDescriptor clientCharacteristicConfigurationDescriptor = new BluetoothGattDescriptor(
                DESCRIPTOR_CLIENT_CHARACTERISTIC_CONFIGURATION,
                BluetoothGattDescriptor.PERMISSION_READ_ENCRYPTED | BluetoothGattDescriptor.PERMISSION_WRITE_ENCRYPTED); //  | BluetoothGattDescriptor.PERMISSION_WRITE
        // Note: As per Android issue #280288203, we should not set values directly on descriptors
        // Instead, we'll provide the value when responding to descriptor read requests
        inputReportCharacteristic.addDescriptor(clientCharacteristicConfigurationDescriptor);

        final BluetoothGattDescriptor descriptor = new BluetoothGattDescriptor(
                DESCRIPTOR_REPORT_REFERENCE,
                BluetoothGattDescriptor.PERMISSION_READ_ENCRYPTED | BluetoothGattDescriptor.PERMISSION_WRITE_ENCRYPTED);
        inputReportCharacteristic.addDescriptor(descriptor);

        while (!service.addCharacteristic(inputReportCharacteristic));
    }

    private void _addOutputDescriptor(BluetoothGattService service) {
        // Output Report
        outputReportCharacteristic = new BluetoothGattCharacteristic(
                CHARACTERISTIC_REPORT,
                BluetoothGattCharacteristic.PROPERTY_READ | BluetoothGattCharacteristic.PROPERTY_WRITE | BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
                BluetoothGattCharacteristic.PERMISSION_READ_ENCRYPTED | BluetoothGattCharacteristic.PERMISSION_WRITE_ENCRYPTED);
        outputReportCharacteristic.setWriteType(BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE);

        final BluetoothGattDescriptor descriptor = new BluetoothGattDescriptor(
                DESCRIPTOR_REPORT_REFERENCE,
                BluetoothGattDescriptor.PERMISSION_READ_ENCRYPTED | BluetoothGattDescriptor.PERMISSION_WRITE_ENCRYPTED);
        outputReportCharacteristic.addDescriptor(descriptor);
        while (!service.addCharacteristic(outputReportCharacteristic));
    }

    private void _addFeatureDescriptor(BluetoothGattService service) {
        // Feature Report
        final BluetoothGattCharacteristic featureCharacteristic = new BluetoothGattCharacteristic(
                CHARACTERISTIC_REPORT,
                BluetoothGattCharacteristic.PROPERTY_READ | BluetoothGattCharacteristic.PROPERTY_WRITE,
                BluetoothGattCharacteristic.PERMISSION_READ_ENCRYPTED | BluetoothGattCharacteristic.PERMISSION_WRITE_ENCRYPTED);

        final BluetoothGattDescriptor descriptor = new BluetoothGattDescriptor(
                DESCRIPTOR_REPORT_REFERENCE,
                BluetoothGattDescriptor.PERMISSION_READ_ENCRYPTED | BluetoothGattDescriptor.PERMISSION_WRITE_ENCRYPTED);
        featureCharacteristic.addDescriptor(descriptor);
        while (!service.addCharacteristic(featureCharacteristic));
    }

    private BluetoothGattService setUpHidService() {
        final BluetoothGattService service = new BluetoothGattService(SERVICE_BLE_HID, BluetoothGattService.SERVICE_TYPE_PRIMARY);

        _addBaseServices(service);

        _addInputDescriptor(service);

        _addOutputDescriptor(service);

        _addFeatureDescriptor(service);

        return service;
    }

    /**
     * HID Input Report
     */
    private final Queue<byte[]> inputReportQueue = new ConcurrentLinkedQueue<>();
    protected final void addInputReport(final byte[] inputReport) {
        if (inputReport != null && inputReport.length > 0) {
            inputReportQueue.offer(inputReport);
        }
    }


    /**
     * Starts advertising
     */
    public final void startAdvertising() {
        handler.post(new Runnable() {
            @Override
            @SuppressLint("MissingPermission")
            public void run() {
                // set up advertising setting
                final AdvertiseSettings advertiseSettings = new AdvertiseSettings.Builder()
                        .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
                        .setConnectable(true)
                        .setTimeout(0)
                        .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
                        .build();

                // Minimize advertising data as much as possible - BLE has a strict 31-byte limit
                final AdvertiseData advertiseData = new Builder()
                        .setIncludeTxPowerLevel(false)
                        .setIncludeDeviceName(false) // Remove device name to reduce packet size
                        // Only include the primary HID service UUID
                        .addServiceUuid(ParcelUuid.fromString(SERVICE_BLE_HID.toString()))
                        .build();

                // Put device name and other services in scan response
                final AdvertiseData scanResult = new Builder()
                        .setIncludeDeviceName(true) // Include device name in scan response instead
                        // Include other service UUIDs in scan response
                        .addServiceUuid(ParcelUuid.fromString(SERVICE_DEVICE_INFORMATION.toString()))
                        .addServiceUuid(ParcelUuid.fromString(SERVICE_BATTERY.toString()))
                        .build();

                Log.d(TAG, "advertiseData: " + advertiseData + ", scanResult: " + scanResult);
                
                // Check both BLUETOOTH_CONNECT and BLUETOOTH_ADVERTISE permissions
                if(isPermitBToothConnect() && isPermitBToothAdvert()) {
                    try {
                        bluetoothLeAdvertiser.startAdvertising(advertiseSettings, advertiseData, scanResult, advertiseCallback);
                    } catch (Exception e) {
                        Log.e(TAG, "Exception during startAdvertising: " + e.getMessage(), e);
                    }
                } else {
                    if (!isPermitBToothConnect()) {
                        Log.e(TAG, "Do not have BLUETOOTH_CONNECT permission.");
                    }
                    if (!isPermitBToothAdvert()) {
                        Log.e(TAG, "Do not have BLUETOOTH_ADVERTISE permission.");
                    }
                }
            }
        });
    }

    /**
     * Stops advertising
     */
    @SuppressLint("MissingPermission")
    public final void stopAdvertising() {
        handler.post(new Runnable() {
            @Override
            public void run() {
                if(isPermitBToothConnect()) {
                    try {
                        bluetoothLeAdvertiser.stopAdvertising(advertiseCallback);
                    } catch (final IllegalStateException ignored) {
                        Log.d(TAG, "BT Adapter is not turned ON");
                    }
                    try {
                        if (gattServer != null) {
                            final Set<BluetoothDevice> devices = getDevices();
                            for (final BluetoothDevice device : devices) {
                                gattServer.cancelConnection(device);
                            }
                            gattServer.close();
                            gattServer = null;
                        }
                    } catch (final IllegalStateException ignored) {
                        Log.d(TAG, "BT Adapter is not turned ON");
                    }
                } else {
                    Log.d(TAG, "Do not have BLUETOOTH_CONNECT permission.");
                }
            }
        });
    }

    /**
     * Callback for BLE advertising to provide detailed error information
     */
    private final AdvertiseCallback advertiseCallback = new AdvertiseCallback() {
        @Override
        public void onStartSuccess(AdvertiseSettings settingsInEffect) {
            Log.d(TAG, "Advertising started successfully");
        }

        @Override
        public void onStartFailure(int errorCode) {
            String errorMessage = "Unknown error";
            switch (errorCode) {
                case ADVERTISE_FAILED_ALREADY_STARTED:
                    errorMessage = "Already started";
                    break;
                case ADVERTISE_FAILED_DATA_TOO_LARGE:
                    errorMessage = "Data too large";
                    break;
                case ADVERTISE_FAILED_FEATURE_UNSUPPORTED:
                    errorMessage = "Feature unsupported";
                    break;
                case ADVERTISE_FAILED_INTERNAL_ERROR:
                    errorMessage = "Internal error";
                    break;
                case ADVERTISE_FAILED_TOO_MANY_ADVERTISERS:
                    errorMessage = "Too many advertisers";
                    break;
            }
            Log.e(TAG, "Failed to start advertising: " + errorMessage + " (code " + errorCode + ")");
        }
    };

    /**
     * Obtains connected Bluetooth devices
     *
     * @return the connected Bluetooth devices
     */
    private Set<BluetoothDevice> getDevices() {
        final Set<BluetoothDevice> deviceSet = new HashSet<>();
        synchronized (bluetoothDevicesMap) {
            deviceSet.addAll(bluetoothDevicesMap.values());
        }
        return Collections.unmodifiableSet(deviceSet);
    }

    /**
     * Callback for BLE data transfer
     */
    private final BluetoothGattServerCallback gattServerCallback = new BluetoothGattServerCallback() {

        @Override
        @SuppressLint("MissingPermission")
        public void onConnectionStateChange(final BluetoothDevice device, final int status, final int newState) {
            super.onConnectionStateChange(device, status, newState);
            Log.d(TAG, "onConnectionStateChange status: " + status + ", newState: " + newState);

            switch (newState) {
                case BluetoothProfile.STATE_CONNECTED:
                    // check bond status
                    Log.d(TAG, "BluetoothProfile.STATE_CONNECTED bondState: " + device.getBondState());
                    if (device.getBondState() == BluetoothDevice.BOND_NONE) {
                        applicationContext.registerReceiver(new BroadcastReceiver() {
                            @Override
                            public void onReceive(final Context context, final Intent intent) {
                                final String action = intent.getAction();
                                Log.d(TAG, "onReceive action: " + action);

                                if (BluetoothDevice.ACTION_BOND_STATE_CHANGED.equals(action)) {
                                    final int state = intent.getIntExtra(BluetoothDevice.EXTRA_BOND_STATE, BluetoothDevice.ERROR);

                                    if (state == BluetoothDevice.BOND_BONDED) {
                                        intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE, BluetoothDevice.class);
                                        // successfully bonded
                                        context.unregisterReceiver(this);

                                        handler.post(new Runnable() {
                                            @Override
                                            public void run() {
                                                if (gattServer != null) {
                                                    gattServer.connect(device, true);
                                                }
                                            }
                                        });
                                        Log.d(TAG, "successfully bonded");
                                    }
                                }
                            }
                        }, new IntentFilter(BluetoothDevice.ACTION_BOND_STATE_CHANGED));

                        // create bond
                        /* setPairingConfirmation requires BLUETOOTH_PRIVILEGED permission which I will not be able to get...
                        try {
                            device.setPairingConfirmation(true);
                        } catch (final SecurityException e) {
                            Log.d(TAG, e.getMessage(), e);
                        }
                        */
                        device.createBond();
                    } else if (device.getBondState() == BluetoothDevice.BOND_BONDED) {
                        handler.post(new Runnable() {
                            @Override
                            public void run() {
                                if (gattServer != null) {
                                    gattServer.connect(device, true);
                                }
                            }
                        });
                        synchronized (bluetoothDevicesMap) {
                            bluetoothDevicesMap.put(device.getAddress(), device);
                        }
                    }
                    break;

                case BluetoothProfile.STATE_DISCONNECTED:
                    final String deviceAddress = device.getAddress();

                    // try reconnect immediately
                    handler.post(new Runnable() {
                        @Override
                        public void run() {
                            if (gattServer != null) {
                                // gattServer.cancelConnection(device);
                                gattServer.connect(device, true);
                            }
                        }
                    });
                    
                    synchronized (bluetoothDevicesMap) {
                        bluetoothDevicesMap.remove(deviceAddress);
                    }
                    break;

                default:
                    // do nothing
                    break;
            }
        }

        @Override
        public void onCharacteristicReadRequest(final BluetoothDevice device, 
                                                final int requestId, 
                                                final int offset, 
                                                final BluetoothGattCharacteristic characteristic) {
            super.onCharacteristicReadRequest(device, requestId, offset, characteristic);
            if (gattServer == null) {
                return;
            }
            Log.d(TAG, "onCharacteristicReadRequest characteristic: " + characteristic.getUuid() + ", offset: " + offset);

            handler.post(new Runnable() {
                @Override
                @SuppressLint("MissingPermission")
                public void run() {

                    final UUID characteristicUuid = characteristic.getUuid();
                    if (BleUtils.matches(CHARACTERISTIC_HID_INFORMATION, characteristicUuid)) {
                        gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, RESPONSE_HID_INFORMATION);
                    } else if (BleUtils.matches(CHARACTERISTIC_REPORT_MAP, characteristicUuid)) {
                        if (offset == 0) {
                            gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, HIDPasskey.getReportMap());
                        } else {
                            final int remainLength = HIDPasskey.getReportMap().length - offset;
                            if (remainLength > 0) {
                                final byte[] data = new byte[remainLength];
                                System.arraycopy(HIDPasskey.getReportMap(), offset, data, 0, remainLength);
                                gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, data);
                            } else {
                                gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, null);
                            }
                        }
                    } else if (BleUtils.matches(CHARACTERISTIC_HID_CONTROL_POINT, characteristicUuid)) {
                        gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, new byte []{0});
                    } else if (BleUtils.matches(CHARACTERISTIC_REPORT, characteristicUuid)) {
                        gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, EMPTY_BYTES);
                    } else if (BleUtils.matches(CHARACTERISTIC_MANUFACTURER_NAME, characteristicUuid)) {
                        gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, manufacturer.getBytes(StandardCharsets.UTF_8));
                    } else if (BleUtils.matches(CHARACTERISTIC_SERIAL_NUMBER, characteristicUuid)) {
                        gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, serialNumber.getBytes(StandardCharsets.UTF_8));
                    } else if (BleUtils.matches(CHARACTERISTIC_MODEL_NUMBER, characteristicUuid)) {
                        gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, deviceName.getBytes(StandardCharsets.UTF_8));
                    } else if (BleUtils.matches(CHARACTERISTIC_BATTERY_LEVEL, characteristicUuid)) {
                        gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, new byte[] {0x64}); // always 100%
                    } else {
                        // Log information about the unhandled characteristic
                        Log.w(TAG, "Unhandled characteristic read request: " + characteristic.getUuid() +
                              ", service: " + characteristic.getService().getUuid() +
                              ", properties: " + characteristic.getProperties());
                        // For characteristics we don't explicitly handle above, return an empty response as a fallback
                        gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, EMPTY_BYTES);
                    }
                }
            });
        }

        @Override
        public void onDescriptorReadRequest(final BluetoothDevice device, 
                                            final int requestId, 
                                            final int offset, 
                                            final BluetoothGattDescriptor descriptor) {
            super.onDescriptorReadRequest(device, requestId, offset, descriptor);
            Log.d(TAG, "onDescriptorReadRequest requestId: " + requestId + ", offset: " + offset + ", descriptor: " + descriptor.getUuid());

            if (gattServer == null) {
                return;
            }

            handler.post(new Runnable() {
                @Override
                @SuppressLint("MissingPermission")
                public void run() {
                    if (BleUtils.matches(DESCRIPTOR_CLIENT_CHARACTERISTIC_CONFIGURATION, descriptor.getUuid())) {
                        // Return ENABLE_NOTIFICATION_VALUE for Client Characteristic Configuration Descriptor
                        gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0,
                                BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE);
                    } else if (BleUtils.matches(DESCRIPTOR_REPORT_REFERENCE, descriptor.getUuid())) {
                        final int characteristicProperties = descriptor.getCharacteristic().getProperties();
                        if (characteristicProperties == (BluetoothGattCharacteristic.PROPERTY_READ | BluetoothGattCharacteristic.PROPERTY_WRITE | BluetoothGattCharacteristic.PROPERTY_NOTIFY)) {
                            // Input Report
                            gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, new byte[]{0, 1});
                        } else if (characteristicProperties == (BluetoothGattCharacteristic.PROPERTY_READ | BluetoothGattCharacteristic.PROPERTY_WRITE | BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE)) {
                            // Output Report
                            gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, new byte[]{0, 2});
                        } else if (characteristicProperties == (BluetoothGattCharacteristic.PROPERTY_READ | BluetoothGattCharacteristic.PROPERTY_WRITE)) {
                            // Feature Report
                            gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, new byte[]{0, 3});
                        } else {
                            gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, 0, EMPTY_BYTES);
                        }
                    } else {
                        gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, 0, EMPTY_BYTES);
                    }
                }
            });
        }

        @Override
        @SuppressLint("MissingPermission")
        public void onCharacteristicWriteRequest(final BluetoothDevice device, 
                                                 final int requestId, 
                                                 final BluetoothGattCharacteristic characteristic, 
                                                 final boolean preparedWrite, 
                                                 final boolean responseNeeded, 
                                                 final int offset, 
                                                 final byte[] value) {
            super.onCharacteristicWriteRequest(device, requestId, characteristic, preparedWrite, responseNeeded, offset, value);
            Log.d(TAG, "onCharacteristicWriteRequest characteristic: " + characteristic.getUuid() + ", value: " + Arrays.toString(value));

            if (gattServer == null) {
                return;
            }

            if (responseNeeded) {
                if (BleUtils.matches(CHARACTERISTIC_REPORT, characteristic.getUuid())) {
                    if (characteristic.getProperties() == (BluetoothGattCharacteristic.PROPERTY_READ 
                                                            | BluetoothGattCharacteristic.PROPERTY_WRITE 
                                                            | BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE)) {
                        // process Output Report
                        passkey.onOutputReport(value);

                        // send empty
                        gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, EMPTY_BYTES);
                    } else {
                        // send empty
                        gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, EMPTY_BYTES);
                    }
                }
            }
        }

        @Override
        @SuppressLint("MissingPermission")
        public void onDescriptorWriteRequest(final BluetoothDevice device, 
                                             final int requestId, 
                                             final BluetoothGattDescriptor descriptor, 
                                             final boolean preparedWrite, 
                                             final boolean responseNeeded, 
                                             final int offset, 
                                             final byte[] value) {
            super.onDescriptorWriteRequest(device, requestId, descriptor, preparedWrite, responseNeeded, offset, value);
            Log.d(TAG, "onDescriptorWriteRequest descriptor: " + descriptor.getUuid() +
                     ", value: " + Arrays.toString(value) + ", responseNeeded: " + responseNeeded + ", preparedWrite: " + preparedWrite);

            // Note: As per Android issue #280288203, we should not set values directly on descriptors
            // Instead, we store the value in our application logic and use it when needed
            
            if (responseNeeded) {
                if (BleUtils.matches(DESCRIPTOR_CLIENT_CHARACTERISTIC_CONFIGURATION, descriptor.getUuid())) {
                    // send empty
                    if (gattServer != null) {
                        gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, EMPTY_BYTES);
                    }
                }
            }
        }

        @Override
        public void onServiceAdded(final int status, final BluetoothGattService service) {
            super.onServiceAdded(status, service);
            Log.d(TAG, "onServiceAdded status: " + status + ", service: " + service.getUuid());

            if (status != 0) {
                Log.d(TAG, "onServiceAdded Adding Service failed..");
            }
        }
    };

    /**
     * Set the manufacturer name
     *
     * @param newManufacturer the name
     */
    public final void setManufacturer(@NonNull final String newManufacturer) {
        // length check
        final byte[] manufacturerBytes = newManufacturer.getBytes(StandardCharsets.UTF_8);
        if (manufacturerBytes.length > DEVICE_INFO_MAX_LENGTH) {
            // shorten
            final byte[] bytes = new byte[DEVICE_INFO_MAX_LENGTH];
            System.arraycopy(manufacturerBytes, 0, bytes, 0, DEVICE_INFO_MAX_LENGTH);
            manufacturer = new String(bytes, StandardCharsets.UTF_8);
        } else {
            manufacturer = newManufacturer;
        }
    }

    /**
     * Set the device name
     *
     * @param newDeviceName the name
     */
    public final void setDeviceName(@NonNull final String newDeviceName) {
        // length check
        final byte[] deviceNameBytes = newDeviceName.getBytes(StandardCharsets.UTF_8);
        if (deviceNameBytes.length > DEVICE_INFO_MAX_LENGTH) {
            // shorten
            final byte[] bytes = new byte[DEVICE_INFO_MAX_LENGTH];
            System.arraycopy(deviceNameBytes, 0, bytes, 0, DEVICE_INFO_MAX_LENGTH);
            deviceName = new String(bytes, StandardCharsets.UTF_8);
        } else {
            deviceName = newDeviceName;
        }
    }

    /**
     * Set the serial number
     *
     * @param newSerialNumber the number
     */
    public final void setSerialNumber(@NonNull final String newSerialNumber) {
        // length check
        final byte[] deviceNameBytes = newSerialNumber.getBytes(StandardCharsets.UTF_8);
        if (deviceNameBytes.length > DEVICE_INFO_MAX_LENGTH) {
            // shorten
            final byte[] bytes = new byte[DEVICE_INFO_MAX_LENGTH];
            System.arraycopy(deviceNameBytes, 0, bytes, 0, DEVICE_INFO_MAX_LENGTH);
            serialNumber = new String(bytes, StandardCharsets.UTF_8);
        } else {
            serialNumber = newSerialNumber;
        }
    }

    /**
     * Check if Bluetooth LE device supported on the running environment.
     *
     * @param context the context
     * @return true if supported
     */
    @SuppressWarnings("deprecation")
    public static boolean isBleSupported(@NonNull final Context context) {
        try {
            if (context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE) == false) {
                return false;
            }

            final BluetoothManager bluetoothManager = (BluetoothManager) context.getSystemService(Context.BLUETOOTH_SERVICE);

            final BluetoothAdapter bluetoothAdapter;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
                bluetoothAdapter = bluetoothManager.getAdapter();
            } else {
                bluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
            }

            if (bluetoothAdapter != null) {
                return true;
            }
        } catch (final Throwable ignored) {
            // ignore exception
        }
        return false;
    }

    /**
     * Check if Bluetooth LE Peripheral mode supported on the running environment.
     *
     * @param context the context
     * @return true if supported
     */
    public static boolean isBlePeripheralSupported(@NonNull final Context context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            return false;
        }

        final BluetoothAdapter bluetoothAdapter =  (
                (BluetoothManager) context.getSystemService(Context.BLUETOOTH_SERVICE)).getAdapter();

        if (bluetoothAdapter == null) {
            return false;
        }

        return bluetoothAdapter.isMultipleAdvertisementSupported();
    }

    /**
     * Check if bluetooth function enabled
     *
     * @param context the context
     * @return true if bluetooth enabled
     */
    @SuppressWarnings("deprecation")
    public static boolean isBluetoothEnabled(@NonNull final Context context) {
        final BluetoothManager bluetoothManager = (BluetoothManager) context.getSystemService(Context.BLUETOOTH_SERVICE);

        if (bluetoothManager == null) {
            return false;
        }

        final BluetoothAdapter bluetoothAdapter;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
            bluetoothAdapter = bluetoothManager.getAdapter();
        } else {
            bluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
        }

        if (bluetoothAdapter == null) {
            return false;
        }

        return bluetoothAdapter.isEnabled();
    }


}
