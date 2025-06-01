public class HIDService {

    private static final String TAG = HidPeripheral.class.getSimpleName();

    private String manufacturer = "lowkey";
    private String deviceName = "BeeKey HID";
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
    private static final UUID DESCRIPTOR_REPORT_REFERENCE = BleUuidUtils.fromShortValue(0x2908);
    private static final UUID DESCRIPTOR_CLIENT_CHARACTERISTIC_CONFIGURATION = BleUuidUtils.fromShortValue(0x2902);

    private static final byte[] EMPTY_BYTES = {};
    private static final byte[] RESPONSE_HID_INFORMATION = {0x11, 0x01, 0x00, 0x03};

    public HIDService(final Context context) throws UnsupportedOperationException {
        applicationContext = context.getApplicationContext();
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

        gattServer = bluetoothManager.openGattServer(applicationContext, gattServerCallback);
        if (gattServer == null) {
            throw new UnsupportedOperationException("gattServer is null, check Bluetooth is ON.");
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
                    inputReportCharacteristic.setValue(polled);
                    handler.post(new Runnable() {
                        @Override
                        public void run() {
                            final Set<BluetoothDevice> devices = getDevices();
                            for (final BluetoothDevice device : devices) {
                                try {
                                    if (gattServer != null) {
                                        gattServer.notifyCharacteristicChanged(device, inputReportCharacteristic, false);
                                    }
                                } catch (final Throwable ignored) {

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

    private BluetoothGattService setUpHidService() {
        final BluetoothGattService service = new BluetoothGattService(SERVICE_BLE_HID, BluetoothGattService.SERVICE_TYPE_PRIMARY);

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

        // Input Report
        {
            inputReportCharacteristic = new BluetoothGattCharacteristic(
                    CHARACTERISTIC_REPORT,
                    BluetoothGattCharacteristic.PROPERTY_NOTIFY | BluetoothGattCharacteristic.PROPERTY_READ | BluetoothGattCharacteristic.PROPERTY_WRITE,
                    BluetoothGattCharacteristic.PERMISSION_READ_ENCRYPTED | BluetoothGattCharacteristic.PERMISSION_WRITE_ENCRYPTED);

            final BluetoothGattDescriptor clientCharacteristicConfigurationDescriptor = new BluetoothGattDescriptor(
                    DESCRIPTOR_CLIENT_CHARACTERISTIC_CONFIGURATION,
                    BluetoothGattDescriptor.PERMISSION_READ_ENCRYPTED | BluetoothGattDescriptor.PERMISSION_WRITE_ENCRYPTED); //  | BluetoothGattDescriptor.PERMISSION_WRITE
            clientCharacteristicConfigurationDescriptor.setValue(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE);
            inputReportCharacteristic.addDescriptor(clientCharacteristicConfigurationDescriptor);

            final BluetoothGattDescriptor descriptor = new BluetoothGattDescriptor(
                    DESCRIPTOR_REPORT_REFERENCE,
                    BluetoothGattDescriptor.PERMISSION_READ_ENCRYPTED | BluetoothGattDescriptor.PERMISSION_WRITE_ENCRYPTED);
            inputReportCharacteristic.addDescriptor(descriptor);

            while (!service.addCharacteristic(inputReportCharacteristic));
        }

        // Output Report
        {
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

        // Feature Report
        {
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
            public void run() {
                // set up advertising setting
                final AdvertiseSettings advertiseSettings = new AdvertiseSettings.Builder()
                        .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
                        .setConnectable(true)
                        .setTimeout(0)
                        .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
                        .build();

                // set up advertising data
                final AdvertiseData advertiseData = new Builder()
                        .setIncludeTxPowerLevel(false)
                        .setIncludeDeviceName(true)
                        .addServiceUuid(ParcelUuid.fromString(SERVICE_DEVICE_INFORMATION.toString()))
                        .addServiceUuid(ParcelUuid.fromString(SERVICE_BLE_HID.toString()))
                        .addServiceUuid(ParcelUuid.fromString(SERVICE_BATTERY.toString()))
                        .build();

                // set up scan result
                final AdvertiseData scanResult = new Builder()
                        .addServiceUuid(ParcelUuid.fromString(SERVICE_DEVICE_INFORMATION.toString()))
                        .addServiceUuid(ParcelUuid.fromString(SERVICE_BLE_HID.toString()))
                        .addServiceUuid(ParcelUuid.fromString(SERVICE_BATTERY.toString()))
                        .build();

                Log.d(TAG, "advertiseData: " + advertiseData + ", scanResult: " + scanResult);
                bluetoothLeAdvertiser.startAdvertising(advertiseSettings, advertiseData, scanResult, advertiseCallback);
            }
        });
    }

    /**
     * Stops advertising
     */
    public final void stopAdvertising() {
        handler.post(new Runnable() {
            @Override
            public void run() {
                try {
                    bluetoothLeAdvertiser.stopAdvertising(advertiseCallback);
                } catch (final IllegalStateException ignored) {
                    // BT Adapter is not turned ON
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
                    // BT Adapter is not turned ON
                }
            }
        });
    }

    /**
     * Callback for BLE connection<br />
     * nothing to do.
     */
    private final AdvertiseCallback advertiseCallback = new NullAdvertiseCallback();
    private static class NullAdvertiseCallback extends AdvertiseCallback {
    }

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
                                        final BluetoothDevice bondedDevice = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);

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
                        try {
                            device.setPairingConfirmation(true);
                        } catch (final SecurityException e) {
                            Log.d(TAG, e.getMessage(), e);
                        }
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
                public void run() {

                    final UUID characteristicUuid = characteristic.getUuid();
                    if (BleUuidUtils.matches(CHARACTERISTIC_HID_INFORMATION, characteristicUuid)) {
                        gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, RESPONSE_HID_INFORMATION);
                    } else if (BleUuidUtils.matches(CHARACTERISTIC_REPORT_MAP, characteristicUuid)) {
                        if (offset == 0) {
                            gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, HIDPasskey.getReportMap());
                        } else {
                            final int remainLength = getReportMap().length - offset;
                            if (remainLength > 0) {
                                final byte[] data = new byte[remainLength];
                                System.arraycopy(getReportMap(), offset, data, 0, remainLength);
                                gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, data);
                            } else {
                                gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, null);
                            }
                        }
                    } else if (BleUuidUtils.matches(CHARACTERISTIC_HID_CONTROL_POINT, characteristicUuid)) {
                        gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, new byte []{0});
                    } else if (BleUuidUtils.matches(CHARACTERISTIC_REPORT, characteristicUuid)) {
                        gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, EMPTY_BYTES);
                    } else if (BleUuidUtils.matches(CHARACTERISTIC_MANUFACTURER_NAME, characteristicUuid)) {
                        gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, manufacturer.getBytes(StandardCharsets.UTF_8));
                    } else if (BleUuidUtils.matches(CHARACTERISTIC_SERIAL_NUMBER, characteristicUuid)) {
                        gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, serialNumber.getBytes(StandardCharsets.UTF_8));
                    } else if (BleUuidUtils.matches(CHARACTERISTIC_MODEL_NUMBER, characteristicUuid)) {
                        gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, deviceName.getBytes(StandardCharsets.UTF_8));
                    } else if (BleUuidUtils.matches(CHARACTERISTIC_BATTERY_LEVEL, characteristicUuid)) {
                        gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, new byte[] {0x64}); // always 100%
                    } else {
                        gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, characteristic.getValue());
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
                public void run() {
                    if (BleUuidUtils.matches(DESCRIPTOR_REPORT_REFERENCE, descriptor.getUuid())) {
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
                    }
                }
            });
        }

        @Override
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
                if (BleUuidUtils.matches(CHARACTERISTIC_REPORT, characteristic.getUuid())) {
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

            descriptor.setValue(value);

            if (responseNeeded) {
                if (BleUuidUtils.matches(DESCRIPTOR_CLIENT_CHARACTERISTIC_CONFIGURATION, descriptor.getUuid())) {
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
}
