# FIDO BLE HID App Testing Guide

## Installing app in emulator

```bash
$ANDROID_HOME/emulator/emulator -list-avds
$ANDROID_HOME/platform-tools/adb devices
$ANDROID_HOME/platform-tools/adb -s <atached-emulator-device> install -r <path/to.apk>
$ANDROID_HOME/platform-tools/adb -s <atached-emulator-device> uninstall com.isfs.blekey
```

## Debugging with Android Debugger Bridge (ADB)

```bash
#All trace from emulator
adb logcat
#Filter trace with app prefix
adb logcat | grep "com.isfs.blekey"
#Filter individual classes
adb logcat com.isfs.blekey.HIDService:D com.isfs.blekey.HIDPasskey:D *:S
```

## Testing Approach Overview

Based on analysis of the FIDO BLE HID app, the best testing approach involves a combination of emulator testing for UI components and Bluetooth emulation using Bumble, with additional physical device testing for comprehensive validation.

## 1. UI Testing on Emulator

The BleHidTest emulator is suitable for:

- Verifying app launches correctly
- Testing navigation between activities (MainActivity, ServerActivity, ManageActivity)
- Testing the passkey management interface
- Checking error handling when Bluetooth is not available
- Monitoring logcat for errors or warnings

## 2. Bluetooth Emulation with Bumble

[Bumble](https://github.com/google/bumble) is a full-featured Bluetooth stack written in Python that can be used to emulate Bluetooth functionality with the Android emulator:

### Key Features
- Supports both Bluetooth Low Energy (BLE) and Bluetooth Classic (BR/EDR)
- Specifically supports HID protocol, which is crucial for our FIDO BLE HID app
- Can connect to the Android emulator's virtual controller or bridge to physical controllers
- Enables testing without physical devices

### Setup Requirements
- Android emulator version 33.1.4.0 or later
- Python environment with Bumble installed (`pip install bumble`)
- USB Bluetooth dongle (optional, for physical controller bridging)

### Testing with Bumble
1. Launch the Android emulator with Bluetooth support:
   ```
   emulator -packet-streamer-endpoint default -avd BleHidTest
   ```

2. Run a Bumble GATT server to emulate a Bluetooth device:
   ```
   python -m bumble.apps.run_gatt_server device_config.json android-netsim
   ```

3. Test the app's interaction with the emulated Bluetooth device

For detailed setup instructions, refer to the [Bumble Android documentation](https://google.github.io/bumble/platforms/android.html).

## 3. FIDO BLE HID Testing with Python Scripts

This repository includes a comprehensive Python test script for testing the FIDO BLE HID functionality, specifically the authenticatorMakeCredential (HID_CREATE2) command.

### Prerequisites

1. Android emulator running with the FIDO BLE HID app installed
2. Python 3.7+ installed on your system
3. Required Python packages:
   - bumble
   - cbor2
   - pytest (for unit tests)

### Installation

Install the required Python packages:

```bash
pip install bumble cbor2 pytest
```

### Using the Test Script

The `fido_blehid_test.py` script provides multiple testing modes:

```bash
# Basic client test - tests connection and PING
python fido_blehid_test.py --mode client --transport android-netsim

# Test authenticatorMakeCredential (HID_CREATE2)
python fido_blehid_test.py --mode create --transport android-netsim

# Run unit tests
python fido_blehid_test.py --mode test --transport android-netsim

# Run all tests
python fido_blehid_test.py --mode all --transport android-netsim
```

The `android-netsim` transport connects to the Android emulator's Bluetooth stack.

### Understanding the Output

When running the test scripts, you should see output similar to the following:

1. Connection to the device
2. Service discovery
3. CTAP initialization
4. GetInfo command execution
5. MakeCredential command execution

A successful test will show:
- Successful connection to the device
- Successful service discovery
- Successful CTAP initialization
- Successful GetInfo response
- Successful MakeCredential response (or an expected error code)

### Troubleshooting

#### Connection Issues

If you have trouble connecting to the emulator:

1. Make sure the emulator is running and the FIDO BLE HID app is active
2. Verify that Bluetooth is enabled in the emulator
3. Check that the device name matches (default is 'IBeePasskey')
4. Try restarting the emulator and the app

#### CTAP Command Issues

If CTAP commands fail:

1. Check that the CTAP initialization succeeded
2. Verify that the input and output report characteristics were found
3. Look for error codes in the responses
4. Common error codes:
   - 0x36: PIN required
   - 0x01: Invalid parameter
   - 0x0E: No credentials

### Advanced Testing

For more advanced testing, you can modify the parameters in the `send_ctap_make_credential` method to test different scenarios:

- Different relying party IDs
- Different user information
- Different credential parameters
- Adding exclude lists
- Adding extensions

## 4. Functional Testing on Physical Device

While Bumble provides excellent emulation capabilities, complete testing of the BLE HID functionality should also include physical Android devices:

### Device Requirements
- Android device with BLE peripheral mode support (Android 5.0+ with hardware support)
- Another device (computer/phone) with Bluetooth to act as the client

### Testing Procedure
1. Install the app on the Android device
2. Enable Bluetooth on both devices
3. Launch the Server mode on the Android device
4. Attempt to pair from the client device
5. Test FIDO2 authentication flows with a compatible website or app

### Specific Tests
- Bluetooth advertising and discovery
- Pairing and bonding
- CTAP HID protocol communication
- Passkey creation and management
- Authentication flows

## 5. Testing Tools

### For Emulator Testing
- Android Debug Bridge (ADB)
- Espresso for UI testing
- JUnit for unit testing with mocks
- Bumble for Bluetooth emulation
- Python test scripts (fido_blehid_test.py)

### For Physical Device Testing
- FIDO2 test tools (like FIDO Conformance Tools)
- Bluetooth sniffers for protocol analysis
- Web browsers with WebAuthn support

## 6. Debugging Tips

Enable Bluetooth Logs:
```
adb shell setprop log.tag.BluetoothAdapter VERBOSE
adb shell setprop log.tag.BluetoothManager VERBOSE
```

Monitor Bluetooth State:
```
adb shell dumpsys bluetooth_manager
```

Analyze HCI Packets with Bumble:
```
bumble-show --format snoop btsnoop_hci.log
```

## 7. References

- [FIDO Client to Authenticator Protocol (CTAP) Specification](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)
- [Bumble Bluetooth Library](https://google.github.io/bumble/)
- [CBOR2 Library](https://pypi.org/project/cbor2/)