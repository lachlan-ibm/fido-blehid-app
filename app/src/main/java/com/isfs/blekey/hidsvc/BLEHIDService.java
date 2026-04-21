/*
 * Copyright IBM 2025
 */


package com.isfs.blekey.hidsvc;

import java.util.Collections;
import java.util.UUID;
import java.util.Set;
import java.util.Queue;
import java.util.Map;
import java.util.List;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Arrays;
import java.util.Timer;
import java.util.TimerTask;
import java.util.LinkedList;
import java.util.function.Function;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Handler;
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


public class BLEHIDService implements IHIDTransport {

    private static final String TAG = BLEHIDService.class.getCanonicalName();

    /**
     * HID service enumeration state for a device.
     */
    public enum HidEnumerationState {
        NOT_ENUMERATED,  // HID service not discovered yet
        ENUMERATED,      // HID Report Map read (service discovered)
        ACTIVE           // Notifications enabled (ready for input)
    }

    /**
     * Listener for device connection/disconnection events.
     */
    public interface ConnectionListener {
        void onDeviceConnected(BluetoothDevice device);
        void onDeviceDisconnected(BluetoothDevice device);
        void onDeviceError(BluetoothDevice device);
        void onHidServiceEnumerated(BluetoothDevice device);
        void onHidServiceActive(BluetoothDevice device);
    }

    private String manufacturer = "lowkey";
    private String deviceName = "IBleKey";
    private String serialNumber = "1337C0D3";

    private final Context applicationContext;
    private final Handler handler;
    private final HIDBTAdvertiser bleAdvertiser;
    private BluetoothGattCharacteristic inputReportCharacteristic;
    private BluetoothGattCharacteristic outputReportCharacteristic;
    @Nullable
    private BluetoothGattServer gattServer;
    private final Map<String, BluetoothDevice> bluetoothDevicesMap = new ConcurrentHashMap<>();
    private final Map<String, HidEnumerationState> deviceHidState = new ConcurrentHashMap<>();
    @Nullable
    private ConnectionListener connectionListener;

    public void setConnectionListener(@Nullable ConnectionListener listener) {
        this.connectionListener = listener;
    }

    private HIDPasskey passkey;

    /**
     * Device Information Service
     */
    private static final UUID SERVICE_DEVICE_INFORMATION = BleUtils.SERVICE_DEVICE_INFORMATION;
    private static final UUID CHARACTERISTIC_MANUFACTURER_NAME = BleUtils.getCharateristicUuid(0x2A29);
    private static final UUID CHARACTERISTIC_MODEL_NUMBER = BleUtils.getCharateristicUuid(0x2A24);
    private static final UUID CHARACTERISTIC_SERIAL_NUMBER = BleUtils.getCharateristicUuid(0x2A25);
    private static final UUID CHARACTERISTIC_PNP_ID = BleUtils.getCharateristicUuid(0x2A50);
    private static final int DEVICE_INFO_MAX_LENGTH = 20;

    // PnP ID: source=USB IF (0x02), VID=0x1337, PID=0xC0D3, version=0x0001
    private static final byte[] PNP_ID = {0x02, 0x37, 0x13, (byte)0xD3, (byte)0xC0, 0x01, 0x00};

    /**
     * Battery Service
     */
    private static final UUID SERVICE_BATTERY = BleUtils.SERVICE_BATTERY;
    private static final UUID CHARACTERISTIC_BATTERY_LEVEL = BleUtils.getCharateristicUuid(0x2A19);

    /**
     * Generic Attribute Service — for Service Changed indications
     */
    private static final UUID SERVICE_GENERIC_ATTRIBUTE      = BleUtils.SERVICE_GENERIC_ATTRIBUTE;
    private static final UUID CHARACTERISTIC_SERVICE_CHANGED = BleUtils.CHARACTERISTIC_SERVICE_CHANGED;

    /**
     * HID Service
     */
    private static final UUID SERVICE_BLE_HID = BleUtils.SERVICE_BLE_HID;
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
    private static final byte[] RESPONSE_PROTOCOL_MODE = {0x01}; // Report Protocol Mode

    // Queue of services waiting to be added sequentially
    private final LinkedList<BluetoothGattService> pendingServices = new LinkedList<>();

    // Dispatch table: maps each characteristic UUID to a function that returns the response bytes
    private Map<UUID, Function<Integer, byte[]>> readHandlers;

    public BLEHIDService(final Context context, boolean bToothConnect, boolean bToothAdvertise) throws UnsupportedOperationException {
        applicationContext = context.getApplicationContext();
        if(!bToothConnect || !bToothAdvertise) {
            Log.e(TAG, "Bluetooth is not available/permitted");
            if (context instanceof ServerActivity) {
                ServerActivity sa = (ServerActivity) context;
                Toast.makeText(sa, sa.getString(R.string.device_not_supported, "Bluetooth LE Peripheral"), Toast.LENGTH_SHORT).show();
                sa.finish();
            }
            throw new UnsupportedOperationException("Bluetooth permissions not granted");
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

        final BluetoothLeAdvertiser bluetoothLeAdvertiser = bluetoothAdapter.getBluetoothLeAdvertiser();
        Log.d(TAG, "bluetoothLeAdvertiser: " + bluetoothLeAdvertiser);
        if (bluetoothLeAdvertiser == null) {
            throw new UnsupportedOperationException("Bluetooth LE Advertising not supported on this device.");
        }
        bleAdvertiser = new HIDBTAdvertiser(context, handler, bluetoothLeAdvertiser);
        try {
            gattServer = bluetoothManager.openGattServer(applicationContext, gattServerCallback);
            if (gattServer == null) {
                throw new UnsupportedOperationException("gattServer is null, check Bluetooth is ON.");
            }
        } catch (SecurityException e) {
            throw new UnsupportedOperationException(e.getMessage());
        }

        // Queue services - each is added only after onServiceAdded callback fires.
        // Note: Generic Attribute Service (0x1801) is added automatically by Android — do NOT add it manually.
        pendingServices.add(setUpHidService());
        pendingServices.add(setUpDeviceInformationService());
        pendingServices.add(setUpBatteryService());
        addNextPendingService();
        // reconnectBondedDevices() is called from onServiceAdded once all services are ready
        
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
                            Log.d(TAG, "notifyCharacteristicChanged devices=" + devices.size() + " data=" + Arrays.toString(polled));
                            Log.i(TAG, "SEND FRAME (" + polled.length + "bytes): " + Arrays.toString(polled));
                            for (final BluetoothDevice device : devices) {
                                try {
                                    if (gattServer != null && isPermitBToothConnect()) {
                                        int result = gattServer.notifyCharacteristicChanged(device, inputReportCharacteristic, false, polled);
                                        Log.d(TAG, "notifyCharacteristicChanged result=" + result + " device=" + device.getAddress());
                                    }
                                } catch (final Throwable t) {
                                    Log.e(TAG, "notifyCharacteristicChanged exception: " + t.getMessage());
                                }
                            }
                        }
                    });
                }
            }
        }, 0, 50);

        //create the passkey object
        this.passkey = new HIDPasskey((IHIDTransport) this);
        buildReadHandlers();
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
    


    /**
     * Add the next pending GATT service. Must only be called when no add is in progress.
     * Subsequent services are triggered from onServiceAdded callback.
     */
    @SuppressLint("MissingPermission")
    private void addNextPendingService() {
        if (gattServer == null || pendingServices.isEmpty()) {
            return;
        }
        final BluetoothGattService service = pendingServices.poll();
        try {
            if (isPermitBToothConnect()) {
                gattServer.addService(service);
            }
        } catch (final Exception e) {
            Log.e(TAG, "addService failed for " + service.getUuid(), e);
            addNextPendingService();
        }
    }

    /**
     * Reconnects to all previously bonded devices so the host re-enumerates HOGP
     * without requiring re-pairing after an app restart or reinstall.
     * Must only be called after all GATT services have been added.
     */
    @SuppressLint("MissingPermission")
    private void reconnectBondedDevices() {
        if (!isPermitBToothConnect()) return;
        final BluetoothManager bluetoothManager =
                (BluetoothManager) applicationContext.getSystemService(Context.BLUETOOTH_SERVICE);
        final BluetoothAdapter bluetoothAdapter = bluetoothManager.getAdapter();
        if (bluetoothAdapter == null) return;
        
        // Get list of connected GATT devices to detect existing connections
        final List<BluetoothDevice> connectedDevices = bluetoothManager.getConnectedDevices(BluetoothProfile.GATT);
        
        final Set<BluetoothDevice> bonded = bluetoothAdapter.getBondedDevices();
        if (bonded == null || bonded.isEmpty()) return;
        for (final BluetoothDevice device : bonded) {
            if (device.getType() == BluetoothDevice.DEVICE_TYPE_LE
                    || device.getType() == BluetoothDevice.DEVICE_TYPE_DUAL) {
                Log.d(TAG, "Reconnecting to bonded BLE device: " + device.getAddress());
                
                // Check if device is already connected (from before app restart)
                final boolean alreadyConnected = connectedDevices.contains(device);
                if (alreadyConnected) {
                    Log.d(TAG, "Device " + device.getAddress() + " already connected, updating UI state");
                    // Add to our device map and notify listener
                    bluetoothDevicesMap.put(device.getAddress(), device);
                    handler.post(() -> {
                        sendServiceChangedIndication(device);
                        postConnectedActions(device);
                    });
                }
                
                handler.post(() -> {
                    if (gattServer != null) {
                        gattServer.connect(device, true);
                    }
                });
            }
        }
    }

    /**
     * Returns all bonded BLE devices known to the Android Bluetooth stack.
     * Useful for pre-populating UI before any GATT connection callbacks fire.
     */
    @SuppressLint("MissingPermission")
    public Set<BluetoothDevice> getBondedBleDevices(BluetoothAdapter bluetoothAdapter) {
        final Set<BluetoothDevice> result = new HashSet<>();
        if (!isPermitBToothConnect()) return result;
        final Set<BluetoothDevice> bonded = bluetoothAdapter.getBondedDevices();
        if (bonded == null) return result;
        for (BluetoothDevice device : bonded) {
            if (device.getType() == BluetoothDevice.DEVICE_TYPE_LE
                    || device.getType() == BluetoothDevice.DEVICE_TYPE_DUAL) {
                result.add(device);
            }
        }
        return result;
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
        {
            final BluetoothGattCharacteristic characteristic = new BluetoothGattCharacteristic(CHARACTERISTIC_PNP_ID, BluetoothGattCharacteristic.PROPERTY_READ, BluetoothGattCharacteristic.PERMISSION_READ_ENCRYPTED);
            while (!service.addCharacteristic(characteristic));
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
        bleAdvertiser.start();
    }

    /**
     * Stops advertising
     */
    public final void stopAdvertising() {
        bleAdvertiser.stop();
        handler.post(new Runnable() {
            @Override
            @SuppressLint("MissingPermission")
            public void run() {
                if (!isPermitBToothConnect()) {
                    Log.d(TAG, "Do not have BLUETOOTH_CONNECT permission.");
                    return;
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
            }
        });
    }


    /**
     * Obtains connected Bluetooth devices
     *
     * @return the connected Bluetooth devices
     */
    private Set<BluetoothDevice> getDevices() {
        return Collections.unmodifiableSet(new HashSet<>(bluetoothDevicesMap.values()));
    }

    /**
     * Gets the HID enumeration state for a specific device.
     *
     * @param deviceAddress The Bluetooth address of the device
     * @return The HID enumeration state, or NOT_ENUMERATED if not found
     */
    public HidEnumerationState getHidState(String deviceAddress) {
        return deviceHidState.getOrDefault(deviceAddress, HidEnumerationState.NOT_ENUMERATED);
    }

    /**
     * Gets all devices with their HID enumeration states.
     *
     * @return Unmodifiable map of device address to HID state
     */
    public Map<String, HidEnumerationState> getAllHidStates() {
        return Collections.unmodifiableMap(new HashMap<>(deviceHidState));
    }

    private void postConnectedActions(final BluetoothDevice device) {
        handler.post(() -> {
            if (connectionListener != null) {
                connectionListener.onDeviceConnected(device);
            }
        });
    }

    @SuppressLint("MissingPermission")
    private void handleBondStateChange(final BluetoothDevice device) {
        applicationContext.registerReceiver(new BroadcastReceiver() {
            @Override
            public void onReceive(final Context context, final Intent intent) {
                if (!BluetoothDevice.ACTION_BOND_STATE_CHANGED.equals(intent.getAction())) return;
                final int state = intent.getIntExtra(BluetoothDevice.EXTRA_BOND_STATE, BluetoothDevice.ERROR);
                if (state == BluetoothDevice.BOND_BONDED) {
                    context.unregisterReceiver(this);
                    bluetoothDevicesMap.put(device.getAddress(), device);
                    postConnectedActions(device);
                    Log.d(TAG, "successfully bonded");
                }
            }
        }, new IntentFilter(BluetoothDevice.ACTION_BOND_STATE_CHANGED));
        device.createBond();
    }

    /**
     * Builds the characteristic UUID → response-builder dispatch table used by
     * {@link #onCharacteristicReadRequest}.
     */
    private void buildReadHandlers() {
        readHandlers = new HashMap<>();
        readHandlers.put(CHARACTERISTIC_HID_INFORMATION,   offset -> RESPONSE_HID_INFORMATION);
        readHandlers.put(CHARACTERISTIC_REPORT_MAP,        offset -> getReportMapSlice(offset));
        readHandlers.put(CHARACTERISTIC_PROTOCOL_MODE,     offset -> RESPONSE_PROTOCOL_MODE);
        readHandlers.put(CHARACTERISTIC_HID_CONTROL_POINT, offset -> new byte[]{0});
        readHandlers.put(CHARACTERISTIC_REPORT,            offset -> EMPTY_BYTES);
        readHandlers.put(CHARACTERISTIC_MANUFACTURER_NAME, offset -> manufacturer.getBytes(StandardCharsets.UTF_8));
        readHandlers.put(CHARACTERISTIC_SERIAL_NUMBER,     offset -> serialNumber.getBytes(StandardCharsets.UTF_8));
        readHandlers.put(CHARACTERISTIC_MODEL_NUMBER,      offset -> deviceName.getBytes(StandardCharsets.UTF_8));
        readHandlers.put(CHARACTERISTIC_PNP_ID,            offset -> PNP_ID);
        readHandlers.put(CHARACTERISTIC_BATTERY_LEVEL,     offset -> new byte[]{0x64});
    }

    /**
     * Returns a slice of the HID report map starting at {@code offset}.
     * Returns the full array when {@code offset} is 0, a sub-array when the
     * offset is within bounds, or {@code null} when the offset is past the end.
     */
    private byte[] getReportMapSlice(int offset) {
        final byte[] reportMap = HIDPasskey.getReportMap();
        if (offset == 0) return reportMap;
        final int remaining = reportMap.length - offset;
        if (remaining <= 0) return null;
        final byte[] slice = new byte[remaining];
        System.arraycopy(reportMap, offset, slice, 0, remaining);
        return slice;
    }

    /**
     * Sends a Service Changed indication (handles 0x0001–0xFFFF) to {@code device}.
     * This forces BlueZ (and other HOGP clients) to re-discover GATT services,
     * which is required when the app restarts and the client has a stale service cache.
     * Android auto-adds the Generic Attribute service (0x1801) and its Service Changed
     * characteristic (0x2A05) — we just need to locate and indicate it.
     */
    @SuppressLint("MissingPermission")
    private void sendServiceChangedIndication(final BluetoothDevice device) {
        if (gattServer == null || !isPermitBToothConnect()) return;
        final BluetoothGattService genericAttrService = gattServer.getService(SERVICE_GENERIC_ATTRIBUTE);
        if (genericAttrService == null) {
            Log.w(TAG, "Generic Attribute service (0x1801) not found — cannot send Service Changed");
            return;
        }
        final BluetoothGattCharacteristic serviceChanged =
                genericAttrService.getCharacteristic(CHARACTERISTIC_SERVICE_CHANGED);
        if (serviceChanged == null) {
            Log.w(TAG, "Service Changed characteristic (0x2A05) not found");
            return;
        }
        // Value: start handle 0x0001, end handle 0xFFFF (little-endian uint16 pair)
        final byte[] value = {0x01, 0x00, (byte) 0xFF, (byte) 0xFF};
        handler.postDelayed(() -> {
            if (gattServer != null && isPermitBToothConnect()) {
                final int result = gattServer.notifyCharacteristicChanged(device, serviceChanged, true, value);
                Log.d(TAG, "Service Changed indication sent to " + device.getAddress() + " result=" + result);
            }
        }, 500);
    }

    /**
     * Sends a {@link BluetoothGatt#GATT_SUCCESS} response on the GATT server.
     */
    @SuppressLint("MissingPermission")
    private void sendSuccessResponse(BluetoothDevice device, int requestId, int offset, byte[] data) {
        if (gattServer != null) {
            gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, data);
        }
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

            if (status != BluetoothGatt.GATT_SUCCESS) {
                Log.e(TAG, "GATT error status=" + status + " for device=" + device.getAddress());
                handler.post(() -> {
                    if (connectionListener != null) connectionListener.onDeviceError(device);
                });
                bluetoothDevicesMap.remove(device.getAddress());
                return;
            }

            switch (newState) {
                case BluetoothProfile.STATE_CONNECTED:
                    Log.d(TAG, "BluetoothProfile.STATE_CONNECTED bondState: " + device.getBondState());
                    if (device.getBondState() == BluetoothDevice.BOND_NONE) {
                        handleBondStateChange(device);
                    } else if (device.getBondState() == BluetoothDevice.BOND_BONDING) {
                        // Pairing in progress — wait for BOND_BONDED via handleBondStateChange
                        Log.d(TAG, "Device is bonding, waiting for bond completion: " + device.getAddress());
                        handleBondStateChange(device);
                    } else if (device.getBondState() == BluetoothDevice.BOND_BONDED) {
                        bluetoothDevicesMap.put(device.getAddress(), device);
                        sendServiceChangedIndication(device);
                        postConnectedActions(device);
                    }
                    break;

                case BluetoothProfile.STATE_DISCONNECTED:
                    bluetoothDevicesMap.remove(device.getAddress());
                    deviceHidState.remove(device.getAddress());
                    handler.post(() -> {
                        if (gattServer != null) gattServer.connect(device, true);
                        if (connectionListener != null) connectionListener.onDeviceDisconnected(device);
                    });
                    break;

                default:
                    break;
            }
        }

        @Override
        public void onCharacteristicReadRequest(final BluetoothDevice device,
                                                final int requestId,
                                                final int offset,
                                                final BluetoothGattCharacteristic characteristic) {
            super.onCharacteristicReadRequest(device, requestId, offset, characteristic);
            if (gattServer == null) return;
            Log.d(TAG, "onCharacteristicReadRequest characteristic: " + characteristic.getUuid() + ", offset: " + offset);

            handler.post(() -> {
                final Function<Integer, byte[]> readHandler = readHandlers.get(characteristic.getUuid());
                if (readHandler != null) {
                    sendSuccessResponse(device, requestId, offset, readHandler.apply(offset));
                    
                    // Track HID enumeration when Report Map is read
                    if (characteristic.getUuid().equals(CHARACTERISTIC_REPORT_MAP) && offset == 0) {
                        HidEnumerationState currentState = deviceHidState.get(device.getAddress());
                        if (currentState != HidEnumerationState.ACTIVE) {
                            deviceHidState.put(device.getAddress(), HidEnumerationState.ENUMERATED);
                            Log.d(TAG, "HID service enumerated for device: " + device.getAddress());
                            if (connectionListener != null) {
                                connectionListener.onHidServiceEnumerated(device);
                            }
                        }
                    }
                } else {
                    Log.w(TAG, "Unhandled characteristic read: " + characteristic.getUuid()
                            + ", service: " + characteristic.getService().getUuid()
                            + ", properties: " + characteristic.getProperties());
                    sendSuccessResponse(device, requestId, 0, EMPTY_BYTES);
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

            if (BleUtils.matches(CHARACTERISTIC_REPORT, characteristic.getUuid())) {
                // Process any write to a Report characteristic as CTAP HID output
                passkey.onOutputReport(value);
            }
            if (responseNeeded) {
                gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, EMPTY_BYTES);
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
            
            // Track HID activation when notifications are enabled
            if (BleUtils.matches(DESCRIPTOR_CLIENT_CHARACTERISTIC_CONFIGURATION, descriptor.getUuid())) {
                if (value != null && Arrays.equals(value, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)) {
                    deviceHidState.put(device.getAddress(), HidEnumerationState.ACTIVE);
                    Log.d(TAG, "HID service active for device: " + device.getAddress());
                    if (connectionListener != null) {
                        handler.post(() -> connectionListener.onHidServiceActive(device));
                    }
                }
            }
            
            if (responseNeeded) {
                if (BleUtils.matches(DESCRIPTOR_CLIENT_CHARACTERISTIC_CONFIGURATION, descriptor.getUuid())) {
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
                Log.e(TAG, "onServiceAdded failed for " + service.getUuid());
            }
            if (pendingServices.isEmpty()) {
                // All services registered — now safe to reconnect bonded devices
                Log.d(TAG, "All services added, reconnecting bonded devices");
                reconnectBondedDevices();
            } else {
                addNextPendingService();
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

        final BluetoothAdapter bluetoothAdapter =
                ((BluetoothManager) context.getSystemService(Context.BLUETOOTH_SERVICE)).getAdapter();

        if (bluetoothAdapter == null || !bluetoothAdapter.isEnabled()) {
            return false;
        }

        // isMultipleAdvertisementSupported() returns false on some devices that still support
        // single-slot BLE peripheral advertising. Check for advertiser availability directly.
        return bluetoothAdapter.getBluetoothLeAdvertiser() != null;
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

    // IHIDTransport interface implementation
    @Override
    public void sendInputReport(byte[] report) {
        addInputReport(report);
    }

    @Override
    public boolean isReady() {
        return gattServer != null && !bluetoothDevicesMap.isEmpty();
    }

}
