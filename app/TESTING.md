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

## 3. Classic Bluetooth HID Testing with Python Script

The app now uses **Classic Bluetooth HID profile** (BR/EDR) instead of BLE GATT. This provides better desktop compatibility and eliminates the random address issues that made BLE scanning difficult.

### Key Advantages of Classic BT HID

- **Fixed MAC Address**: No more Resolvable Private Addresses (RPA) that change every 15 minutes
- **Standard Discovery**: Uses SDP (Service Discovery Protocol) instead of GATT
- **Easier Terminal Scanning**: Works with standard tools like `hcitool` and `sdptool`
- **No Pairing Required for Discovery**: Can scan and query services without pairing first

### Prerequisites

1. Linux host with BlueZ
2. Python 3.7+ installed
3. Standard Bluetooth tools:
   - `hcitool` (from bluez package)
   - `sdptool` (from bluez package)
   - `bluetoothctl` (from bluez package)

### Permission Setup (Linux)

```bash
# Add user to bluetooth and input groups (one-time setup)
sudo usermod -a -G bluetooth,input $USER

# Logout and login for changes to take effect
# Then verify:
groups | grep -E 'bluetooth|input'
```

### Using the Classic BT HID Test Script

The [`test_bt_hid.py`](test_bt_hid.py) script provides comprehensive testing for Classic Bluetooth HID:

```bash
# Scan for Classic BT devices
python test_bt_hid.py --scan

# Test specific device by MAC address
python test_bt_hid.py --mac A8:88:CE:7F:89:32

# Test device by name
python test_bt_hid.py --name "OPPO CPH2735"

# Test and monitor HID reports
python test_bt_hid.py --mac A8:88:CE:7F:89:32 --monitor

# Enable debug logging
python test_bt_hid.py --mac A8:88:CE:7F:89:32 --debug
```

### What the Script Tests

1. **Device Discovery**: Scans for Classic BT devices using `hcitool scan`
2. **SDP Service Query**: Queries device services using `sdptool browse`
3. **HID Service Verification**: Confirms device advertises HID service (0x1124)
4. **Pairing**: Pairs with device if not already paired
5. **Connection**: Connects to the HID device
6. **HID Device Detection**: Finds corresponding `/dev/hidraw*` device
7. **Descriptor Reading**: Reads and verifies HID report descriptor
8. **Report Monitoring**: Optionally monitors HID reports (with `--monitor`)

### Expected Output

```
============================================================
Classic Bluetooth HID Test Starting
============================================================
Scanning for Classic Bluetooth devices...
This may take 10-15 seconds...
Found device: OPPO CPH2735 (A8:88:CE:7F:89:32)
Querying SDP services for A8:88:CE:7F:89:32...
✓ HID service found on A8:88:CE:7F:89:32
  Service Name: FIDO HID Device
Device A8:88:CE:7F:89:32 is already paired
Connecting to A8:88:CE:7F:89:32...
✓ Connected successfully
Looking for HID device in /dev/hidraw*...
✓ Found HID device: /dev/hidraw2
Reading HID descriptor from /dev/hidraw2...
HID descriptor size: 29 bytes
✓ HID descriptor read successfully (29 bytes)
✓ SUCCESS: HID descriptor matches expected FIDO CTAP HID descriptor!

============================================================
TEST RESULT: PASSED ✓
Classic Bluetooth HID is working correctly!
============================================================
```

### Manual Terminal Testing

You can also test Classic BT HID manually using standard Linux tools:

```bash
# 1. Scan for Classic BT devices (shows fixed MAC addresses)
hcitool scan

# 2. Query SDP services (no pairing needed)
sdptool browse A8:88:CE:7F:89:32

# 3. Look for HID service (0x1124)
sdptool search HID

# 4. Pair and connect using bluetoothctl
bluetoothctl
> pair A8:88:CE:7F:89:32
> trust A8:88:CE:7F:89:32
> connect A8:88:CE:7F:89:32

# 5. Verify HID device appeared
ls /dev/hidraw*
ls /sys/bus/hid/devices/

# 6. Check device info
cat /sys/class/hidraw/hidraw*/device/uevent
```

### Troubleshooting Classic BT HID

#### Device Not Found During Scan

**Problem**: `hcitool scan` doesn't find the device

**Solutions**:
1. Ensure Android app is running and shows "HID Service Active"
2. Check Bluetooth is enabled on Android device
3. Try scanning multiple times (Classic BT discovery can take 10-15 seconds)
4. Verify device is not already connected to another host

#### No HID Service in SDP

**Problem**: `sdptool browse` doesn't show HID service

**Solutions**:
1. Restart the Android app
2. Check Android logs: `adb logcat -s BTHIDService:D`
3. Verify app is using Classic BT mode (not BLE)
4. Ensure device supports Classic Bluetooth (not BLE-only)

#### Permission Denied

**Problem**: Cannot access `/dev/hidraw*` or Bluetooth adapter

**Solutions**:
1. Add user to required groups:
   ```bash
   sudo usermod -a -G bluetooth,input $USER
   ```
2. Logout and login for changes to take effect
3. Verify group membership: `groups`

#### HID Device Not Appearing

**Problem**: Device connects but no `/dev/hidraw*` appears

**Solutions**:
1. Check kernel module is loaded: `lsmod | grep uhid`
2. Verify `/dev/uhid` exists: `ls -la /dev/uhid`
3. Check BlueZ input.conf: `cat /etc/bluetooth/input.conf`
4. Look for errors in system logs: `journalctl -xe | grep -i bluetooth`

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

## 7. Initial Pairing Requirement for RPA Resolution

### The RPA Problem

Android BLE apps use **Resolvable Private Address (RPA)** for privacy. BlueZ cannot pair with an RPA without the **Identity Resolving Key (IRK)**, which is only exchanged during pairing - a chicken-and-egg problem.

### One-Time Manual Pairing Required

**You must pair the phone ONCE via Android Settings UI before the FIDO BLE HID app will work.**

#### Steps:

1. **On Android phone:**
   - Open **Settings** → **Bluetooth**
   - Ensure Bluetooth is ON
   - Phone is now discoverable

2. **On Linux host:**
   ```bash
   bluetoothctl
   power on
   agent on
   default-agent
   scan on
   ```

3. **Wait for phone to appear:**
   ```
   [NEW] Device A8:88:CE:7F:89:32 OPPO A5 5G
   ```

4. **Pair with public address:**
   ```bash
   pair A8:88:CE:7F:89:32
   ```
   Confirm pairing code on BOTH devices

5. **Trust device:**
   ```bash
   trust A8:88:CE:7F:89:32
   exit
   ```

6. **Verify IRK stored:**
   ```bash
   sudo cat /var/lib/bluetooth/<ADAPTER_MAC>/A8_88_CE_7F_89_32/info | grep -A2 "IdentityResolvingKey"
   ```

7. **Now start FIDO BLE HID app:**
   - BlueZ will resolve RPA → public address using stored IRK
   - HOGP plugin creates `/dev/hidraw*` automatically

### Why Scripting Doesn't Work

- Android uses RPA even when "discoverable"
- BlueZ cannot pair with RPA without IRK
- IRK is only obtained through successful pairing
- Automated pairing scripts cannot bypass this security feature

### After Initial Pairing

Once paired, the FIDO BLE HID app will work automatically:
- App advertises with RPA (e.g., `64:F5:85:5F:E7:80`)
- BlueZ resolves RPA → `A8:88:CE:7F:89:32` using stored IRK
- HOGP plugin creates HID device
- No manual intervention needed

## 8. Linux Host — BLE HID Device Verification and Recovery

This section documents the debugging process for connecting the Android BLE HID peripheral to a Linux host running BlueZ, and the nuances discovered during that process.

### Background: Why BlueZ Misses the HID Service

The Android device (`OPPO A5 5G` in testing) is a dual-mode device bonded over both classic BR/EDR (for A2DP/AVRCP) and BLE (for HID). BlueZ caches the service list from the classic BR/EDR SDP discovery. That cache contains only classic profiles — `0x1812` (HID) is absent. When the app advertises over BLE with `0x1812` in the AD payload, BlueZ receives the advertisement but skips GATT service discovery because it believes it already knows the device's services. The HOGP plugin never fires, no `uhid` device is created, and nothing appears in `/sys/bus/hid/devices/`.

**The fix** (implemented in [`HIDService.java`](../app/src/main/java/com/isfs/blekey/hidsvc/HIDService.java)): on every bonded LE reconnect, the app sends a `Service Changed` indication (characteristic `0x2A05`, handles `0x0001`–`0xFFFF`). BlueZ receives this, invalidates its service cache, re-runs GATT discovery, finds `0x1812`, and the HOGP plugin creates the `uhid` device automatically.

### Prerequisites on the Linux Host

```bash
# Verify uhid kernel module is loaded
lsmod | grep uhid

# Verify /dev/uhid exists
ls -la /dev/uhid

# Check input.conf defaults (UserspaceHID=true is the default — do not change)
cat /etc/bluetooth/input.conf
```

### Confirm the Advertisement Contains 0x1812

With the app running and advertising, capture HCI events:

```bash
sudo timeout 10 btmon | grep -A 10 "Human Interface Device\|0x1812"
```

Expected output:
```
16-bit Service UUIDs (complete): 1 entry
  Human Interface Device (0x1812)
```

If `0x1812` is absent from the advertisement, the app is not advertising correctly.

### Check BlueZ Bond State and Cached Services

```bash
# Replace <ADAPTER> and <DEVICE> with actual addresses
sudo cat /var/lib/bluetooth/<ADAPTER>/<DEVICE>/info | grep -A2 "Services\|LastUsedBearer\|AddressType"
```

If `Services=` does not contain `00001812-0000-1000-8000-00805f9b34fb`, BlueZ has a stale cache. The `Service Changed` indication from the app will fix this on next connection.

If `LastUsedBearer=bredr`, BlueZ is preferring classic BT. This is expected for dual-mode devices and does not prevent HOGP from working once the service cache is refreshed.

### Check BlueZ Device Info (Live)

```bash
bluetoothctl info <DEVICE_ADDRESS>
```

After a successful HOGP connection, `0x1812` should appear in the UUID list:
```
UUID: Human Interface Device    (00001812-0000-1000-8000-00805f9b34fb)
```

### Verify the HID Device Appeared on the Host

```bash
# Check for uhid-created HID devices
ls /sys/bus/hid/devices/

# Check input event nodes
ls /dev/input/

# Map event nodes to device names
grep -r "OPPO\|IBleKey\|IBeePasskey" /sys/class/input/*/device/name 2>/dev/null

# Or use evtest to list all input devices
sudo evtest --query /dev/input/event* 2>/dev/null | head -40
```

The FIDO HID device will appear with a name matching the app's advertised device name.

### Read Raw HID Reports from the Device

```bash
# Find the correct event node first
for f in /sys/class/input/event*/device/name; do echo "$f: $(cat $f)"; done

# Read raw HID input reports (replace eventN with the correct node)
sudo evtest /dev/input/eventN

# Or read raw bytes directly
sudo cat /dev/input/eventN | xxd | head -20
```

For FIDO HID, the report format is 64 bytes: `[CID(4)] [CMD(1)] [BCNTH(1)] [BCNTL(1)] [DATA(57)]`.

### Send a CTAP getInfo Command and Read the Response

The FIDO HID Usage Page is `0xF1D0`. Use `hidraw` for direct CTAP access:

```bash
# Find the hidraw node for the FIDO device
for f in /sys/class/hidraw/hidraw*/device/uevent; do
  echo "=== $f ==="; cat $f
done | grep -B5 "HID_NAME\|1337\|fido\|FIDO" -i

# Or check hid-fido binding
ls /sys/bus/hid/drivers/hid-fido/

# Send a CTAP PING (channel 0xFFFFFFFF, cmd 0x81, length 8, data 0x01..0x08)
# Then send authenticatorGetInfo (channel 0xFFFFFFFF, cmd 0x83, length 1, data 0x04)
python3 - <<'EOF'
import struct, os, time

# Find the hidraw device bound to hid-fido
import glob
fido_devs = glob.glob('/sys/bus/hid/drivers/hid-fido/*:*')
if not fido_devs:
    print("No hid-fido device found — check /sys/bus/hid/devices/")
    exit(1)

hid_id = fido_devs[0].split('/')[-1]
hidraw_path = glob.glob(f'/sys/bus/hid/devices/{hid_id}/hidraw/hidraw*')
if not hidraw_path:
    print(f"No hidraw node for {hid_id}")
    exit(1)

dev = '/dev/' + hidraw_path[0].split('/')[-1]
print(f"Using {dev}")

BROADCAST_CID = 0xFFFFFFFF
CMD_INIT      = 0x86
CMD_CBOR      = 0x83  # authenticatorGetInfo = 0x04

# CTAP_INIT: allocate a channel
nonce = bytes(range(8))
pkt = struct.pack('>IB', BROADCAST_CID, CMD_INIT) + struct.pack('>H', 8) + nonce
pkt = pkt.ljust(64, b'\x00')

fd = os.open(dev, os.O_RDWR)
os.write(fd, b'\x00' + pkt)  # prepend report ID 0x00
resp = os.read(fd, 65)[1:]   # strip report ID byte
cid = struct.unpack('>I', resp[15:19])[0]
print(f"Allocated CID: 0x{cid:08X}")

# authenticatorGetInfo (CBOR cmd 0x04)
payload = bytes([0x04])
pkt2 = struct.pack('>IB', cid, CMD_CBOR) + struct.pack('>H', len(payload)) + payload
pkt2 = pkt2.ljust(64, b'\x00')
os.write(fd, b'\x00' + pkt2)

time.sleep(0.1)
resp2 = os.read(fd, 65)[1:]
print(f"getInfo response (hex): {resp2.hex()}")
os.close(fd)
EOF
```

### Remove the Device and Re-pair (Full Reset)

Use this sequence when the bond is stale or HOGP is not connecting after app reinstall:

```bash
bluetoothctl << 'EOF'
power on
agent on
default-agent
scan on
EOF

# Wait until the device appears, then:
bluetoothctl remove <DEVICE_ADDRESS>

# Restart bluetooth to clear all runtime state
sudo systemctl restart bluetooth

# Re-scan with LE transport filter to see the BLE advertisement
bluetoothctl << 'EOF'
power on
agent on
default-agent
scan.transport le
scan on
EOF

# Once the device appears, pair it
bluetoothctl pair <DEVICE_ADDRESS>
# Confirm the passkey on both sides when prompted
bluetoothctl trust <DEVICE_ADDRESS>
bluetoothctl connect <DEVICE_ADDRESS>
```

**Important:** Use `scan.transport le` (not the default `bredr`) so BlueZ sees the BLE advertisement with `0x1812` and initiates GATT discovery over LE rather than falling back to classic SDP.

### Monitor BlueZ HOGP Plugin Activity

```bash
# Watch BlueZ logs for HOGP events in real time
sudo journalctl -u bluetooth -f | grep -i "hog\|uhid\|hid\|service changed\|0x1812"
```

Key log messages to look for:
- `HoG created uHID device` — HOGP plugin successfully created the uhid device
- `Service Changed indication` — client received the service cache invalidation
- `Device is already marked as connected` — classic BT conflict (should not appear after fix)
- `More than one BATT service exists` — informational only, does not block HID

### BlueZ Bond File Reference

Bond files are stored at `/var/lib/bluetooth/<ADAPTER_ADDR>/<DEVICE_ADDR>/info`.

Key fields relevant to BLE HID:

| Field | Expected value | Meaning |
|---|---|---|
| `AddressType` | `public` | Device uses a public BT address |
| `[IdentityResolvingKey]` | present | IRK stored — BlueZ can resolve Resolvable Private Addresses |
| `[PeripheralLongTermKey]` | present | LE encryption key stored |
| `CCC_LE=2` | `2` | Client subscribed to Service Changed indications |
| `Services=` | must include `00001812-...` | After first successful HOGP connection |

## 8. References

- [FIDO Client to Authenticator Protocol (CTAP) Specification](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)
- [Bumble Bluetooth Library](https://google.github.io/bumble/)
- [CBOR2 Library](https://pypi.org/project/cbor2/)
- [BlueZ HOGP plugin source — profiles/input/hog.c](https://git.kernel.org/pub/scm/bluetooth/bluez.git/tree/profiles/input/hog.c)

## 10. Understanding BLE HID Auto-Reconnection Behavior

### Overview: Why Auto-Reconnection Doesn't Work by Default

**The Issue:**
BLE HID devices (like this app) work perfectly during initial pairing, but fail to automatically reconnect after:
- Bluetooth radio sleep/wake cycles  
- Device reboots
- Connection loss

**This is NOT a bug in the app** - it's a deliberate policy decision by operating system Bluetooth stacks.

### Why Audio Devices Auto-Reconnect But HID Devices Don't

**Key Discovery:** Operating systems maintain a **whitelist of Bluetooth profiles** that should auto-reconnect. Audio profiles (A2DP, HFP, HSP) are in this whitelist by default, but **HID over GATT (HOGP) is NOT**.

From BlueZ (Linux Bluetooth stack) `/etc/bluetooth/main.conf`:
```conf
[Policy]
# Default reconnect whitelist includes audio profiles:
ReconnectUUIDs=00001112-0000-1000-8000-00805f9b34fb,  # Headset Audio
               0000111f-0000-1000-8000-00805f9b34fb,  # Handsfree Audio  
               0000110a-0000-1000-8000-00805f9b34fb,  # Audio Source (A2DP)
               0000110b-0000-1000-8000-00805f9b34fb   # Audio Sink (A2DP)
# Notice: 00001812 (HID over GATT) is MISSING
```

**Why HID is excluded:**
1. **Security**: HID devices (keyboards) can inject keystrokes - auto-reconnection without user awareness could be a security risk
2. **User Experience**: Audio devices are expected to "just work", while input devices may be more intentionally managed  
3. **Historical Reasons**: Classic Bluetooth HID had different reconnection behavior than BLE HOGP

### Solution: Enable Auto-Reconnection (Linux/BlueZ)

#### Automated Setup (Recommended)

Use the provided script:

```bash
cd app/host-utils
chmod +x linux-auto-reconnect-bt-hogp.sh
./linux-auto-reconnect-bt-hogp.sh
```

This configures BlueZ to auto-reconnect to HID devices with 7 attempts at increasing intervals (1s, 2s, 4s, 8s, 16s, 32s, 64s).

#### Manual Configuration

1. Edit BlueZ configuration:
   ```bash
   sudo nano /etc/bluetooth/main.conf
   ```

2. Add HID UUID (0x1812) to ReconnectUUIDs:
   ```conf
   [Policy]
   ReconnectUUIDs=00001112-0000-1000-8000-00805f9b34fb,0000111f-0000-1000-8000-00805f9b34fb,0000110a-0000-1000-8000-00805f9b34fb,0000110b-0000-1000-8000-00805f9b34fb,00001812-0000-1000-8000-00805f9b34fb
   ReconnectAttempts=7
   ReconnectIntervals=1,2,4,8,16,32,64
   ```

3. Restart Bluetooth:
   ```bash
   sudo systemctl restart bluetooth
   ```

#### Verification

Test auto-reconnection:

```bash
# Watch logs
journalctl -u bluetooth -f

# In another terminal: turn Bluetooth off, wait 10s, turn back on
# You should see reconnection attempts in logs
```

Ensure device is trusted:
```bash
bluetoothctl info XX:XX:XX:XX:XX:XX  # Check "Trusted: yes"
bluetoothctl trust XX:XX:XX:XX:XX:XX  # If not trusted
```

### Platform-Specific Behavior

#### Linux (BlueZ)
- **Status**: ✅ Fully solvable with configuration
- **Solution**: Use `linux-auto-reconnect-bt-hogp.sh` script  
- **Result**: Auto-reconnects within 1-64 seconds

#### Windows  
- **Status**: ⚠️ Requires manual reconnection
- **Reason**: Microsoft security policy - HID devices don't auto-reconnect
- **Workaround**: Settings → Bluetooth → Click device → Connect

#### macOS
- **Status**: ⚠️ Generally works but inconsistent
- **Note**: Better than Windows but not guaranteed

### Technical Details

#### Why Your App Code Is Correct

Your Android app does everything correctly:
- ✅ Continuous advertising via [`HIDBTAdvertiser`](../app/src/main/java/com/isfs/blekey/hidsvc/HIDBTAdvertiser.java:57)
- ✅ Proper HID service (UUID 0x1812) setup
- ✅ `gattServer.connect(device, true)` whitelists bonded devices
- ✅ Foreground service keeps it running
- ✅ Boot receiver restarts on Bluetooth enable

**BLE Architecture Constraint**: Peripherals (your app) CANNOT initiate connections - only centrals (laptops) can. The `autoConnect=true` parameter means "accept connections when central initiates", NOT "initiate connection to central".

The limitation is on the host (laptop) side, not your app.

#### Alternative: "Dummy" Audio Profile?

**Question**: Can you add an audio profile so it auto-reconnects?

**Answer**: Not recommended because:
- Profile conflicts (OS tries to use as audio device)
- Resource overhead (full A2DP implementation)
- User confusion (appears as both HID and audio)
- Violates Bluetooth SIG guidelines
- Won't guarantee reconnection anyway

**Better**: Add Battery Service (0x180F) - legitimate for HID devices, though also won't guarantee auto-reconnect without OS configuration.

### Troubleshooting

#### Device Not Auto-Reconnecting

1. Verify configuration:
   ```bash
   grep -A 3 "\[Policy\]" /etc/bluetooth/main.conf
   ```

2. Check bonded and trusted:
   ```bash
   bluetoothctl info XX:XX:XX:XX:XX:XX
   ```

3. Mark as trusted:
   ```bash
   bluetoothctl trust XX:XX:XX:XX:XX:XX
   ```

4. Check BlueZ version (needs 5.x+):
   ```bash
   bluetoothd --version
   ```

For detailed technical analysis, see [`docs/BLE_HID_RECONNECTION_SOLUTION.md`](../docs/BLE_HID_RECONNECTION_SOLUTION.md).

## 11. Troubleshooting HID Device Service Cache Issues

### Problem: HID Device Not Appearing After App Restart

## 10. Troubleshooting HID Device Reconnection Issues

### Problem: HID Device Not Reconnecting After App Restart

**Symptoms:**
- First connection works: `/dev/hidraw*` device appears and FIDO2 commands work
- After closing and restarting the app: device shows as "Connected" in `bluetoothctl` but no `/dev/hidraw*` device
- No BLE HID device appears in `/sys/bus/hid/devices/0005:*`

**Root Cause:**

When the Android app stops, [`HIDService.stopAdvertising()`](../app/src/main/java/com/isfs/blekey/hidsvc/HIDService.java:492-516) closes the GATT server entirely, which:
1. Terminates all BLE connections
2. Removes the HID device from the Linux kernel
3. Leaves a **stale service cache** in BlueZ

When the app restarts with a new GATT server instance, BlueZ reconnects but uses its cached service list (which may not include the HID service or has outdated GATT handles). The HOGP plugin never fires, and no HID device is created.

**Solution: Clear BlueZ Service Cache**

The app already sends **Service Changed indications** ([`HIDService.java:594-616`](../app/src/main/java/com/isfs/blekey/hidsvc/HIDService.java:594-616)) to trigger cache invalidation, but BlueZ sometimes doesn't properly invalidate the cache when connections are abruptly terminated.

#### Manual Fix (One-Time)

```bash
# Disconnect the device
bluetoothctl disconnect A8:88:CE:7F:89:32

# Clear the BlueZ service cache
# BlueZ stores device cache at: /var/lib/bluetooth/<HOST_ADAPTER_MAC>/<DEVICE_MAC>/cache
sudo rm -rf /var/lib/bluetooth/*/A8:88:CE:7F:89:32/cache

# Restart Bluetooth service
sudo systemctl restart bluetooth

# Wait a moment, then reconnect
sleep 3
bluetoothctl connect A8:88:CE:7F:89:32

# Verify HID device appeared
sleep 5
ls -la /sys/bus/hid/devices/0005:*
ls -la /dev/hidraw*

# Test FIDO2 functionality
fido2-token -I /dev/hidraw5  # Replace with your device
```

#### Automated Fix (Using Helper Script)

The [`bt-pair-device.sh`](../app/host-utils/bt-pair-device.sh) script now includes automatic cache clearing:

```bash
cd app/host-utils
./bt-pair-device.sh
```

This script will:
1. Detect your device's Bluetooth MAC address
2. Clear any stale BlueZ service cache
3. Pair and connect the device
4. Verify the HID device appears

#### Verification

After reconnecting, verify the HID device is functional:

```bash
# Check for BLE HID devices (vendor ID 0005)
ls -la /sys/bus/hid/devices/0005:*

# Check hidraw devices
ls -la /dev/hidraw*

# Verify FIDO2 functionality
for dev in /dev/hidraw*; do
    if sudo fido2-token -I "$dev" 2>/dev/null | grep -q "proto: 0x02"; then
        echo "✓ FIDO2 device found: $dev"
        sudo fido2-token -I "$dev" | head -10
        break
    fi
done

# Check Bluetooth connection status
bluetoothctl info A8:88:CE:7F:89:32 | grep Connected
```

Expected output:
- `Connected: yes`
- BLE HID device in `/sys/bus/hid/devices/0005:*`
- Working `/dev/hidraw*` device responding to FIDO2 commands

#### Why This Happens

BlueZ caches GATT services to avoid re-discovery on every connection. When the Android app:
1. Closes the GATT server (on app stop)
2. Creates a new GATT server instance (on app restart)
3. The GATT attribute handles change

BlueZ should receive the Service Changed indication and invalidate its cache, but this doesn't always work reliably when:
- The connection was abruptly terminated
- The device is dual-mode (BR/EDR + BLE) and BlueZ has cached classic services
- The Service Changed indication is lost or not processed

Manually clearing the cache forces BlueZ to perform fresh GATT service discovery, which correctly enumerates the HID service and triggers the HOGP plugin.

#### Prevention

The issue is mitigated by:
1. **Service Changed indications** (already implemented in [`HIDService.java`](../app/src/main/java/com/isfs/blekey/hidsvc/HIDService.java:594-616))
2. **Auto-reconnection logic** (already implemented in [`HIDService.java`](../app/src/main/java/com/isfs/blekey/hidsvc/HIDService.java:667))
3. **Cache clearing in pairing script** (now implemented in [`bt-pair-device.sh`](../app/host-utils/bt-pair-device.sh))

For most users, the automatic mechanisms work correctly. Manual cache clearing is only needed when:
- Testing during development (frequent app restarts)
- After app reinstallation
- When BlueZ's cache becomes corrupted

#### Related Issues

If you encounter similar issues with other symptoms:
- **Device shows as paired but won't connect**: Try `bluetoothctl remove <MAC>` then re-pair
- **HID device appears but doesn't respond**: Check permissions on `/dev/hidraw*` (should be `crw-rw----+`)
- **Multiple HID devices appear**: Old devices may persist; reboot to clean up
- [HID Descriptor Test Script](test_hid_descriptor.py) — Python script for testing HID Report Map on real devices and emulator
- [Bluetooth Core Spec Vol 3 Part G §7.1 — Service Changed characteristic](https://www.bluetooth.com/specifications/specs/core-specification/)

## 9. Testing HID Descriptor on Real Android Devices

This section explains how to test the FIDO BLE HID app on a real Android device using the [`test_hid_descriptor.py`](test_hid_descriptor.py) script.

### Prerequisites

#### Host Machine Requirements

- Linux, macOS, or Windows with Python 3.7+
- Bluetooth adapter (built-in or USB dongle)
- Python packages:
  ```bash
  pip install bumble
  ```

#### Android Device Requirements

- Android device with Bluetooth LE support
- FIDO BLE HID app installed and running
- Bluetooth enabled on the device

### Setup Steps

#### 1. Prepare the Android Device

1. Install and launch the FIDO BLE HID app
2. Enable Bluetooth on the device
3. Start the HID service (the app should begin advertising)
4. Note the device name shown in the app (e.g., "OPPO CPH2735")

#### 2. Identify Your Bluetooth Adapter

The test script uses USB Bluetooth adapters by default.

**For Linux:**
```bash
# List USB Bluetooth devices
lsusb | grep -i bluetooth

# Example output:
# Bus 001 Device 073: ID 8087:0033 Intel Corp. AX211 Bluetooth

# Use transport: usb:0 (first adapter) or usb:1 (second adapter)
# Note: Requires sudo or adding user to plugdev/bluetooth groups
```

**For macOS:**
- Built-in Bluetooth typically works with `usb:0`

**For Windows:**
- USB Bluetooth adapters work with `usb:0`
- May require additional drivers for some adapters

**Quick Test:**
```bash
# RECOMMENDED: Add user to groups (one-time, requires logout/login):
sudo usermod -a -G plugdev,bluetooth,uhid $USER
# Then run without sudo:
python test_hid_descriptor.py

# ALTERNATIVE: Run with sudo using full python path:
sudo $(which python) test_hid_descriptor.py
```

### Running the Test

#### Basic Usage (Auto-detect any HID device)

```bash
cd app
# RECOMMENDED: Add user to groups (one-time, requires logout/login):
sudo usermod -a -G plugdev,bluetooth,uhid $USER
# Then logout/login and run:
python test_hid_descriptor.py

# ALTERNATIVE: Run with sudo using full python path:
sudo $(which python) test_hid_descriptor.py
```

This will:
1. Scan for any BLE device advertising the HID service (UUID 0x1812)
2. Connect to the first HID device found
3. Read and verify the HID Report Map descriptor

**Note for Linux users:** USB Bluetooth access requires elevated permissions. You can either:
- Add your user to `plugdev`, `bluetooth`, and `uhid` groups (recommended, requires logout/login)
- Run with `sudo $(which python)` to use your user's Python environment

#### Specify Device Name

If multiple BLE HID devices are nearby, specify the exact device name:

```bash
python test_hid_descriptor.py --device-name "OPPO CPH2735"
# Or with sudo if not in groups:
sudo $(which python) test_hid_descriptor.py --device-name "OPPO CPH2735"
```

#### Specify Bluetooth Adapter

If you have multiple Bluetooth adapters:

```bash
# Use second USB adapter
python test_hid_descriptor.py --transport usb:1

# Use first HCI adapter (Linux)
python test_hid_descriptor.py --transport hci:0
```

#### Full Example

```bash
python test_hid_descriptor.py \
  --device-name "OPPO CPH2735" \
  --transport usb:0
```

#### Testing with Android Emulator

To test with the Android emulator instead:

```bash
python test_hid_descriptor.py \
  --device-name "sdk_gphone64_x86_64" \
  --transport android-netsim
```

### Expected Output

#### Successful Test

```
============================================================
HID Descriptor Test Starting
============================================================
[1/6] Opening transport: usb:0
[2/6] Creating Bumble device
✓ Pairing delegate configured (SC=True, MITM=True, Bonding=True, IO=DISPLAY_YES_NO)
✓ Device powered on
[3/6] Scanning for device with HID service
Found HID device: 'OPPO CPH2735' at XX:XX:XX:XX:XX:XX
✓ Found target HID device at address: XX:XX:XX:XX:XX:XX
[4/6] Connecting to OPPO CPH2735
✓ Connected successfully
Waiting for security request...
Initiating pairing...
✓ Pairing completed successfully
[5/6] Discovering GATT services
Discovered 3 services
✓ Found HID Service: 00001812-0000-1000-8000-00805f9b34fb
Discovering characteristics for HID service...
Found 5 characteristics in HID service
✓ Found Report Map Characteristic: 00002a4b-0000-1000-8000-00805f9b34fb
[6/6] Reading HID Report Map descriptor
✓ Report Map read successfully (34 bytes)

Verifying Report Map content...
✓ SUCCESS: Report Map matches expected FIDO CTAP HID descriptor!

Report Map Details:
  - Usage Page: 0xF1D0 (FIDO Alliance)
  - Usage: 0x01 (U2F HID Authenticator Device)
  - Input Report: 64 bytes
  - Output Report: 64 bytes

============================================================
TEST RESULT: PASSED ✓
The HID descriptor is being sent correctly!
============================================================
```

### Troubleshooting

#### Device Not Found

**Problem:** `Device 'XXX' not found`

**Solutions:**
1. Verify the app is running and advertising:
   - Check the app UI shows "Advertising" or "Ready"
   - Ensure Bluetooth is enabled on the Android device
2. Try scanning without specifying a device name:
   ```bash
   python test_hid_descriptor.py
   ```
3. Check if the device is visible to other BLE scanners:
   ```bash
   # Linux
   sudo hcitool lescan
   
   # Or use a BLE scanner app on another phone
   ```

#### Transport Error

**Problem:** `Failed to open transport`

**Solutions:**
1. Check Bluetooth adapter is recognized:
   ```bash
   # Linux
   hciconfig
   lsusb | grep -i bluetooth
   
   # macOS
   system_profiler SPBluetoothDataType
   ```
2. Try different transport options:
   - `usb:0`, `usb:1` for USB adapters
   - `hci:0`, `hci:1` for Linux HCI
3. Ensure no other process is using the Bluetooth adapter:
   ```bash
   # Linux - stop bluetoothd if needed
   sudo systemctl stop bluetooth
   ```

#### Pairing Failed

**Problem:** `Pairing failed: ...`

**Solutions:**
1. Clear existing pairing on Android device:
   - Go to Settings → Bluetooth
   - Forget/unpair the test client device
2. Reset Bluetooth on host:
   ```bash
   # Linux
   sudo systemctl restart bluetooth
   ```
3. Check Android logs for pairing details:
   ```bash
   adb logcat -s HIDService:D BluetoothGattServer:D
   ```

#### Permission Denied (Linux)

**Problem:** `Permission denied` when accessing Bluetooth adapter

**Solutions:**
1. Run with sudo (not recommended for regular use):
   ```bash
   sudo python test_hid_descriptor.py
   ```
2. Add user to `bluetooth` group (recommended):
   ```bash
   sudo usermod -a -G bluetooth $USER
   # Log out and back in for changes to take effect
   ```
3. Set capabilities on Python (advanced):
   ```bash
   sudo setcap 'cap_net_raw,cap_net_admin+eip' $(which python3)
   ```

#### Timeout Reading Report Map

**Problem:** `Timeout reading Report Map characteristic`

**Solutions:**
1. Check Android logs for GATT errors:
   ```bash
   adb logcat -s HIDService:D BluetoothGattServer:D
   ```
2. Verify the characteristic is properly registered in [`HIDService.java`](src/main/java/com/isfs/blekey/hidsvc/HIDService.java)
3. Ensure the device is not in power-saving mode
4. Try increasing the timeout in the script (line 314)

### Advanced Usage

#### Debug Mode

Enable debug logging to see all BLE advertisements:

```bash
# Edit test_hid_descriptor.py line 67
# Change: level=logging.DEBUG
python test_hid_descriptor.py
```

#### Monitor Android Logs

While running the test, monitor Android logs in another terminal:

```bash
adb logcat -s HIDService:D BluetoothGattServer:D bt_stack:D
```

#### Test Multiple Devices

Create a script to test multiple devices:

```bash
#!/bin/bash
for device in "OPPO CPH2735" "Pixel 6" "Galaxy S21"; do
    echo "Testing $device..."
    python test_hid_descriptor.py --device-name "$device"
done
```

- [BlueZ HOGP plugin source — profiles/input/hog.c](https://git.kernel.org/pub/scm/bluetooth/bluez.git/tree/profiles/input/hog.c)

## 11. Bluetooth Pairing Troubleshooting

### Problem: Device Not Found During BLE Scan

The diagnostic output shows the device was previously paired and uses **Resolvable Private Addresses (RPA)**:

```
[DEL] Device A8:88:CE:7F:89:32 OPPO A5 5G  (Public MAC)
[DEL] Device 5A:D6:9C:B9:F6:BB OPPO A5 5G  (RPA)
```

#### Root Cause

BLE scanning fails because:
1. **RPA Privacy**: Android BLE HID uses Resolvable Private Addresses that change periodically
2. **Previous Pairing**: Device was already paired, so it may not advertise actively
3. **Scan Timing**: RPA may not be visible during the scan window
4. **BlueZ Cache**: Cached pairing information may interfere

#### Solution 1: Use Existing Pairing (Recommended)

If device is already paired (check with diagnostic script):

```bash
# Run diagnostic to check pairing status
cd app/host-utils
./bt-diagnose-scan.sh

# If already paired, just connect
bluetoothctl trust A8:88:CE:7F:89:32
bluetoothctl connect A8:88:CE:7F:89:32
```

#### Solution 2: Direct Connection Without Scan

Since we know the public MAC address, try direct connection:

```bash
bluetoothctl power on
bluetoothctl agent on
bluetoothctl default-agent
bluetoothctl connect A8:88:CE:7F:89:32
```

This works because BlueZ can resolve the RPA if the device was previously paired.

#### Solution 3: Remove and Re-pair

If pairing is corrupted:

```bash
# Remove existing pairing
bluetoothctl remove A8:88:CE:7F:89:32

# Clear BlueZ cache
sudo rm -rf /var/lib/bluetooth/*/A8:88:CE:7F:89:32

# Restart Bluetooth
sudo systemctl restart bluetooth
sleep 3

# Run pairing script
cd app/host-utils
./bt-pair-device.sh
```

#### Solution 4: Manual Interactive Pairing

If automated scripts fail:

```bash
bluetoothctl
# In bluetoothctl:
power on
agent on
default-agent
scan on

# Wait 30 seconds, look for "OPPO A5 5G" or "CPH2735"
# Note the MAC address shown

# Connect using discovered MAC (either public or RPA)
connect <MAC_ADDRESS>

# Accept pairing on both devices
# Then trust the device
trust <MAC_ADDRESS>

scan off
exit
```

### Diagnostic Tools

#### 1. Run Diagnostic Script

```bash
cd app/host-utils
./bt-diagnose-scan.sh
```

This shows:
- Bluetooth adapter status
- Device pairing status
- Active scan results
- Discovered devices

#### 2. Check Android App Status

Verify app is advertising correctly:

```bash
# Check if app is running
adb shell dumpsys activity services | grep HIDService

# Check Bluetooth advertising
adb logcat -s HIDBTAdvertiser:* HIDService:* -d | tail -20

# Verify Bluetooth is enabled
adb shell settings get global bluetooth_on
```

#### 3. Monitor Bluetooth Events

```bash
# Watch for device advertisements
bluetoothctl
# Then: scan on
# Look for [NEW] and [CHG] events with device name
```

### Common Issues and Fixes

#### Issue: "No devices discovered during scan"

**Symptoms**: Scan completes but no devices found

**Fixes**:
1. Ensure Android app shows "Advertising..." status
2. Restart the Android app
3. Try direct connection with public MAC: `bluetoothctl connect A8:88:CE:7F:89:32`
4. Check if already paired: `bluetoothctl devices | grep A8:88:CE:7F:89:32`

#### Issue: "Device found but connection fails"

**Symptoms**: Device appears in scan but `connect` fails

**Fixes**:
1. Accept pairing request on both devices
2. Check Android notification for pairing request
3. Ensure no PIN/passkey mismatch
4. Try removing and re-pairing (Solution 3 above)

#### Issue: "Device paired but HID not working"

**Symptoms**: Connected but no `/dev/hidraw*` device

**Fixes**:
1. Clear BlueZ service cache:
   ```bash
   sudo rm -rf /var/lib/bluetooth/*/A8:88:CE:7F:89:32/cache
   sudo systemctl restart bluetooth
   ```
2. Verify Service Changed indication is sent (check Android logs)
3. See Section 10 for detailed HID reconnection troubleshooting

### Technical Notes

#### RPA Behavior
- **Changes**: Every 15 minutes (Android default)
- **Resolution**: Requires IRK (Identity Resolving Key) from pairing
- **Privacy**: Prevents tracking by non-paired devices
- **BlueZ**: Automatically resolves RPA after pairing

#### Why Direct Connection Works
BlueZ can connect without scanning if:
- Device accepts connections on public address
- Previous pairing exists (IRK stored)
- Device is in connectable mode

#### Pairing Process
1. **Discovery**: Host scans for BLE devices
2. **Connection**: Host connects to RPA or public address
3. **Pairing**: LE Secure Connections pairing (SMP)
4. **Key Exchange**: IRK, LTK, CSRK exchanged
5. **Resolution**: BlueZ can now resolve future RPAs

### Recommended Workflow

**First Time Setup:**
```bash
cd app/host-utils
./bt-pair-device.sh
```

**Subsequent Connections:**
```bash
cd app/host-utils
./bt-reconnect-hid.sh
```

**If Issues Occur:**
```bash
cd app/host-utils
./bt-diagnose-scan.sh
# Review output and follow recommendations
```

**Reset Pairing:**
```bash
cd app/host-utils
./bt-reset-pairing.sh
./bt-pair-device.sh
```

### Android App Checklist

Ensure app is configured correctly:

1. **Permissions Granted**:
   - BLUETOOTH_CONNECT
   - BLUETOOTH_ADVERTISE
   - BLUETOOTH_SCAN

2. **Advertising Active**:
   - App shows "Advertising..." status
   - Foreground service running
   - No errors in logcat

3. **Advertising Configuration** (from [`HIDBTAdvertiser.java`](src/main/java/com/isfs/blekey/hidsvc/HIDBTAdvertiser.java)):
   - Mode: `ADVERTISE_MODE_LOW_LATENCY`
   - TX Power: `ADVERTISE_TX_POWER_HIGH`
   - Connectable: `true`
   - Service UUID: `0x1812` (HID over GATT)

## 12. Mock OIDC Test Harness for Digital Credentials

The [`test-utils/`](test-utils/) directory contains mock OIDC4VCI issuer and OpenID4VP verifier servers for end-to-end testing of the digital credentials feature without requiring real issuer/verifier infrastructure.

### Overview

The mock servers implement simplified versions of the OIDC4VCI and OpenID4VP protocols, allowing the app to test the complete credential lifecycle:

1. Credential issuance from mock OIDC4VCI issuer
2. Credential storage in passkey files
3. Credential presentation to mock OpenID4VP verifier

### Components

#### Mock OIDC4VCI Issuer ([`mock-oidc4vci-issuer.sh`](test-utils/mock-oidc4vci-issuer.sh))

A Python-based HTTP server implementing:
- **Metadata endpoint**: `/.well-known/openid-credential-issuer`
- **Token endpoint**: `/token` (pre-authorized code flow)
- **Credential endpoint**: `/credential` (JWT VC issuance)

**Default Port**: 8080

**Features**:
- Issues JWT-format verifiable credentials
- Supports pre-authorized code grant type
- Generates mock University Degree credentials
- Returns c_nonce for proof-of-possession

#### Mock OpenID4VP Verifier ([`mock-openid4vp-verifier.sh`](test-utils/mock-openid4vp-verifier.sh))

A Python-based HTTP server implementing:
- **Request endpoint**: `/request/<session-id>` (presentation request)
- **Response endpoint**: `/response` (presentation submission)

**Default Port**: 8081

**Features**:
- Generates presentation requests with presentation definitions
- Accepts VP token submissions
- Validates presentation format
- Tracks session state

### Management Scripts

#### Start Mock Issuer

```bash
./test-utils/start-mock-issuer.sh [port]
```

- Creates PID file at `/tmp/mock-issuer.pid`
- Logs output to `/tmp/mock-issuer.log`
- Waits for server to be ready before returning

#### Start Mock Verifier

```bash
./test-utils/start-mock-verifier.sh [port]
```

- Creates PID file at `/tmp/mock-verifier.pid`
- Logs output to `/tmp/mock-verifier.log`
- Waits for server to be ready before returning

#### Stop All Mock Servers

```bash
./test-utils/stop-mock-servers.sh
```

- Kills processes listed in PID files
- Removes PID files
- Safe to run even if servers aren't running

### Usage in End-to-End Tests

The mock servers are automatically managed by [`test-e2e-complete-flow.sh`](test-e2e-complete-flow.sh):

```bash
# Run complete E2E test with mock servers
./test-e2e-complete-flow.sh [device-id]

# Example with specific device
./test-e2e-complete-flow.sh emulator-5554
```

The test script:
1. Starts mock issuer on port 8080
2. Starts mock verifier on port 8081
3. Runs complete credential lifecycle tests
4. Automatically stops servers on exit (via trap)

### Android Emulator Access

Mock servers run on `localhost` but are accessible to Android emulator via `10.0.2.2`:

- **Issuer URL**: `http://10.0.2.2:8080`
- **Verifier URL**: `http://10.0.2.2:8081`

### Manual Testing

Start servers manually for interactive testing:

```bash
# Terminal 1: Start issuer
cd app
./test-utils/mock-oidc4vci-issuer.sh 8080

# Terminal 2: Start verifier
cd app
./test-utils/mock-openid4vp-verifier.sh 8081

# Terminal 3: Test endpoints
curl http://localhost:8080/.well-known/openid-credential-issuer
curl http://localhost:8081/request/test-session
```

### Dependencies

Mock servers require:
- **Python 3.7+**
- Standard library modules only (no external packages)

### Credential Format

Mock issuer generates JWT credentials:

```json
{
  "iss": "http://localhost:8080",
  "sub": "did:example:holder123",
  "iat": 1234567890,
  "exp": 1266103890,
  "vc": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiableCredential", "UniversityDegree"],
    "credentialSubject": {
      "id": "did:example:holder123",
      "degree": {
        "type": "BachelorDegree",
        "name": "Bachelor of Science",
        "university": "Example University"
      },
      "name": "Alice Smith",
      "graduationDate": "2023-06-15"
    }
  }
}
```

### Troubleshooting

#### Server won't start

Check if port is already in use:
```bash
lsof -i :8080
lsof -i :8081
```

#### App can't reach server

1. Verify server is running: `curl http://localhost:8080/.well-known/openid-credential-issuer`
2. Ensure using `10.0.2.2` for emulator (not `localhost`)
3. Check firewall settings

#### View server logs

```bash
tail -f /tmp/mock-issuer.log
tail -f /tmp/mock-verifier.log
```

### Limitations

These are **test-only** mock servers:

- ❌ No real cryptographic signing (mock signatures only)
- ❌ No signature verification
- ❌ No DID resolution
- ❌ No credential status checking
- ❌ No selective disclosure support
- ❌ No authorization code flow (only pre-authorized)
- ❌ No HTTPS/TLS
- ❌ No authentication/authorization

**Never use these servers in production!**

### References

- [OpenID4VCI Specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- [OpenID4VP Specification](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/)
- [Presentation Exchange](https://identity.foundation/presentation-exchange/)

## 13. Android Emulator Biometric Authentication Setup

This section explains how to set up and use biometric authentication (fingerprint) in the Android emulator for testing the digital credentials feature.

### Overview

The Android emulator supports biometric authentication simulation, allowing you to test biometric-protected features without needing physical hardware. This is the **recommended approach** for development and testing, as it maintains the security model while enabling testing on emulated devices.

### Prerequisites

- Android Emulator with API level 23 (Android 6.0) or higher
- ADB (Android Debug Bridge) installed and accessible from command line
- Emulator with fingerprint sensor support (most modern emulator images)

### Quick Start

#### One-Time Setup
```bash
# On emulator: Settings → Security → Screen lock → Set PIN/Pattern
# On emulator: Settings → Security → Fingerprint → Add fingerprint
# In terminal, run 5 times:
adb -e emu finger touch 1
```

#### Daily Usage
```bash
# When biometric prompt appears in your app:
adb -e emu finger touch 1

# Or use the helper script:
./app/host-utils/emulator-fingerprint-touch.sh 1
```

### Step-by-Step Setup

#### 1. Create or Start an Emulator with Fingerprint Support

When creating a new emulator in Android Studio:
- Choose a device definition that supports fingerprint (e.g., Pixel 3, Pixel 4, Pixel 5)
- Select API level 30 (Android 11) or higher for best compatibility
- Ensure "Hardware - Fingerprint" is enabled in the AVD configuration

**Recommended Emulator Configuration:**
- Device: Pixel 3 or newer
- API Level: 30+ (Android R/11+)
- Target: Google APIs (includes Play Store)

#### 2. Enable Screen Lock on the Emulator

Before you can add fingerprints, you must set up a screen lock:

1. Open the emulator
2. Go to **Settings** → **Security** (or **Settings** → **Security & location**)
3. Tap **Screen lock**
4. Choose one of the following options:
   - **Pattern** (recommended for testing)
   - **PIN**
   - **Password**
5. Follow the prompts to set up your chosen screen lock method

#### 3. Enroll a Fingerprint

1. In Settings, go to **Security** → **Fingerprint**
2. Enter your screen lock credentials (pattern/PIN/password)
3. Tap **Add fingerprint** or **+ Add fingerprint**
4. When prompted to "Place your finger on the sensor", **DO NOT touch the emulator**
5. Instead, use the ADB command (see next step)

#### 4. Simulate Fingerprint Touch via ADB

Open a terminal/command prompt and run:

```bash
adb -e emu finger touch <finger_id>
```

Where `<finger_id>` is a number from 1 to 10.

**Example:**
```bash
adb -e emu finger touch 1
```

**Important Notes:**
- You may need to run this command **multiple times** (typically 3-5 times) to complete the fingerprint enrollment
- The emulator will show progress as you "scan" the fingerprint
- Use the same finger ID consistently during enrollment
- After enrollment is complete, you'll see "Fingerprint added" message

#### 5. Test Fingerprint Authentication

Once enrolled, you can test fingerprint authentication in your app:

1. Launch the app and trigger a biometric authentication prompt
2. When the biometric prompt appears, run the ADB command:
   ```bash
   adb -e emu finger touch 1
   ```
3. The authentication should succeed immediately

### Usage in Development

#### For Testing Digital Credentials Master Key Creation

When creating a master key for issued credentials:

1. Start the credential issuance flow in the app
2. When the biometric prompt appears, run:
   ```bash
   adb -e emu finger touch 1
   ```
3. The master key will be created with biometric protection

#### For Testing Credential Presentation

When presenting credentials that require biometric authentication:

1. Initiate the credential presentation
2. When prompted for biometric authentication, run:
   ```bash
   adb -e emu finger touch 1
   ```
3. The credential will be unlocked and presented

### Helper Script

A helper script is provided at `app/host-utils/emulator-fingerprint-touch.sh`:

```bash
# Single touch (default finger ID 1)
./app/host-utils/emulator-fingerprint-touch.sh

# Specific finger ID
./app/host-utils/emulator-fingerprint-touch.sh 2

# Multiple touches for enrollment
./app/host-utils/emulator-fingerprint-touch.sh 1 5
```

### Troubleshooting

#### Issue: "adb: command not found"

**Solution:** Add Android SDK platform-tools to your PATH:
```bash
export PATH=$PATH:$ANDROID_HOME/platform-tools
```

#### Issue: Fingerprint enrollment not progressing

**Solution:** 
- Run the `adb -e emu finger touch 1` command multiple times (3-5 times)
- Ensure you're using `-e` flag for emulator (not `-d` for device)
- Check that the emulator is running and visible to ADB: `adb devices`

#### Issue: "Fingerprint not recognized" during authentication

**Solution:**
- Use the same finger ID that you used during enrollment
- Ensure the emulator has focus when running the command
- Try re-enrolling the fingerprint

#### Issue: Biometric prompt doesn't appear

**Solution:**
- Verify that a fingerprint is enrolled in Settings → Security → Fingerprint
- Check that screen lock is enabled
- Ensure your app has the correct biometric permissions in AndroidManifest.xml
- Verify API level is 23 or higher

### Advanced Usage

#### Multiple Fingerprints

You can enroll multiple fingerprints using different finger IDs:

```bash
# Enroll first fingerprint (run 3-5 times)
adb -e emu finger touch 1

# Enroll second fingerprint (run 3-5 times)
adb -e emu finger touch 2
```

During authentication, you can use any enrolled finger ID:
```bash
adb -e emu finger touch 1  # or
adb -e emu finger touch 2
```

#### Testing Biometric Failure Scenarios

To test authentication failures:

1. Use an unenrolled finger ID:
   ```bash
   adb -e emu finger touch 9  # If only finger 1 is enrolled
   ```

2. Cancel the biometric prompt by pressing the back button or tapping outside the dialog

3. Test lockout scenarios by failing authentication multiple times

### Best Practices

1. **Always use emulator biometric simulation** instead of disabling biometric requirements in debug builds
2. **Document the finger ID** you use for testing (e.g., always use finger ID 1)
3. **Create helper scripts** for common biometric operations
4. **Test both success and failure scenarios** to ensure proper error handling
5. **Keep biometric requirements enabled** even in debug builds to catch integration issues early

### References

- [Android Biometric Authentication Documentation](https://developer.android.com/identity/sign-in/biometric-auth)
- [Android Emulator Console Commands](https://developer.android.com/studio/run/emulator-console)
- [Testing Biometric Authentication](https://developer.android.com/training/sign-in/biometric-auth#test)
   - Device name in scan response

## 14. QR Scanner Testing

### Overview

The QR Scanner feature allows users to scan QR codes containing credential offers (`openid-credential-offer://`) or presentation requests (`openid4vp://`) directly within the app, eliminating the need for third-party QR scanner apps.

### Test Components

1. **Unit Tests**: `app/src/test/java/com/isfs/blekey/activity/QRScannerActivityTest.java`
   - URI validation logic
   - Result code constants
   - Intent extra keys

2. **Integration Tests**: `app/test-qr-scanner.sh`
   - Automated tests for scanner functionality
   - Manual test instructions

### Running Unit Tests

```bash
# Run QR Scanner unit tests
cd lib
./run_tests.sh com.isfs.blekey.activity.QRScannerActivityTest

# Or run all app tests
cd app
./gradlew test
```

### Running Integration Tests

```bash
# Run automated integration tests
cd app
./test-qr-scanner.sh
```

The integration test script will:
- Check prerequisites (ADB, device connection, app installation)
- Grant camera permission
- Run 10 automated tests covering:
  - Scanner launch
  - Valid/invalid URI handling
  - Camera permission checks
  - Navigation (back button)
  - Activity lifecycle
  - Debounce behavior
  - Long URI handling
  - Flashlight toggle
- Display manual test instructions

### Manual Testing Procedures

#### 1. Basic QR Code Scanning

**Prerequisites:**
- Physical Android device with camera
- QR code generator (e.g., `qrencode`)

**Steps:**
1. Generate a test QR code:
   ```bash
   echo 'openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.example.com%22%7D' | qrencode -t UTF8
   ```

2. Launch the app and tap "Scan QR Code" button

3. Point camera at the QR code

4. **Expected Results:**
   - QR code is detected within 2 seconds
   - Vibration feedback occurs
   - Beep sound plays
   - Scanner closes
   - Credential offer flow begins

#### 2. Invalid QR Code Handling

**Steps:**
1. Generate an invalid QR code (HTTP URL):
   ```bash
   echo 'http://example.com/credential' | qrencode -t UTF8
   ```

2. Launch scanner and scan the invalid QR code

3. **Expected Results:**
   - Error toast displayed: "Invalid QR code format"
   - Double vibration (error feedback)
   - Scanner remains active for retry

#### 3. Flashlight Toggle

**Steps:**
1. Launch QR scanner
2. Tap the flashlight button (bottom-right corner)
3. Verify flashlight turns on
4. Tap again
5. Verify flashlight turns off

**Expected Results:**
- Flashlight toggles on/off smoothly
- Button content description updates
- Works in low-light conditions

#### 4. Camera Permission Flow

**Steps:**
1. Uninstall and reinstall the app
2. Tap "Scan QR Code" button
3. **Expected Results:**
   - Permission dialog appears
   - After granting, scanner launches immediately
   - After denying, toast message explains permission is required

#### 5. Navigation and Lifecycle

**Test Back Button:**
1. Launch scanner
2. Press back button
3. **Expected**: Returns to MainActivity

**Test Home Button:**
1. Launch scanner
2. Press home button
3. Return to app
4. **Expected**: Scanner resumes with camera active

**Test App Switching:**
1. Launch scanner
2. Switch to another app
3. Return to scanner
4. **Expected**: Camera resumes, flashlight state preserved

#### 6. Low Light Performance

**Steps:**
1. Test scanning in various lighting conditions:
   - Bright indoor light
   - Dim indoor light
   - Outdoor daylight
   - Near darkness (with flashlight)

2. **Expected Results:**
   - Scanner works in all conditions
   - Flashlight improves detection in low light
   - QR codes detected within 2-3 seconds

#### 7. Multiple Scan Debounce

**Steps:**
1. Launch scanner
2. Quickly scan the same QR code multiple times
3. **Expected**: Only first scan is processed, subsequent scans ignored

#### 8. Long URI Handling

**Steps:**
1. Generate a QR code with very long URI (>1000 characters)
2. Scan the QR code
3. **Expected**: 
   - URI is processed without crash
   - Flow continues normally

### Testing with Real Credential Offers

#### Using Mock Issuer

1. Start the mock issuer:
   ```bash
   cd app/test-utils
   ./test-real-device-issuance.sh
   ```

2. The script will:
   - Start a mock OIDC4VCI issuer
   - Generate a credential offer
   - Display a QR code

3. Use the QR scanner in the app to scan the displayed QR code

4. Complete the credential issuance flow

#### Using Mock Verifier

1. Start the mock verifier:
   ```bash
   cd app/test-utils
   ./start-mock-verifier.sh
   ```

2. Generate a presentation request QR code

3. Scan with the app's QR scanner

4. Complete the credential presentation flow

### Troubleshooting

#### Scanner Won't Launch

**Symptoms:**
- Tapping "Scan QR Code" button does nothing
- App crashes when launching scanner

**Solutions:**
1. Check camera permission:
   ```bash
   adb shell dumpsys package com.isfs.blekey | grep android.permission.CAMERA
   ```

2. Grant permission manually:
   ```bash
   adb shell pm grant com.isfs.blekey android.permission.CAMERA
   ```

3. Check logcat for errors:
   ```bash
   adb logcat | grep -E '(QRScannerActivity|CameraPermission)'
   ```

#### QR Code Not Detected

**Symptoms:**
- Camera preview shows but QR code not detected
- Scanner times out

**Solutions:**
1. Ensure QR code is clear and well-lit
2. Try using flashlight
3. Check QR code format (must be QR_CODE, not other barcode types)
4. Verify URI scheme is correct (`openid-credential-offer://` or `openid4vp://`)

#### Camera Preview Black/Frozen

**Symptoms:**
- Camera preview is black or frozen
- Scanner appears to hang

**Solutions:**
1. Close and reopen scanner
2. Restart app
3. Check if another app is using camera
4. Verify camera hardware works in other apps

#### Invalid QR Code Not Showing Error

**Symptoms:**
- Scanning invalid QR code doesn't show error
- Scanner closes unexpectedly

**Solutions:**
1. Check logcat for validation errors
2. Verify URI validation logic in QRScannerActivity
3. Test with known valid URI first

### Performance Benchmarks

Expected performance metrics:

| Metric | Target | Acceptable |
|--------|--------|------------|
| Scanner launch time | < 1 second | < 2 seconds |
| QR detection time | < 2 seconds | < 3 seconds |
| Camera preview FPS | 30 FPS | 24 FPS |
| Battery usage | < 5% per minute | < 10% per minute |
| Memory usage | < 50 MB | < 100 MB |

### Test Coverage

The QR Scanner tests cover:

- ✅ URI validation (valid/invalid schemes)
- ✅ Camera permission handling
- ✅ Activity lifecycle (onCreate, onResume, onPause, onDestroy)
- ✅ Navigation (back button, toolbar back)
- ✅ Flashlight toggle
- ✅ Success/error feedback (vibration, sound, toast)
- ✅ Debounce behavior
- ✅ Long URI handling
- ✅ Edge cases (null, empty, malformed URIs)

### Known Limitations

1. **Automated Camera Testing**: Camera functionality requires physical device testing; automated tests use deep links to simulate scans

2. **QR Code Generation**: Integration tests don't generate actual QR code images; manual testing required for end-to-end validation

3. **Lighting Conditions**: Automated tests can't verify performance in various lighting conditions

4. **Flashlight Hardware**: Tests assume flashlight is available; gracefully degrades if not present

### References

- ZXing Library: https://github.com/zxing/zxing
- ZXing Android Embedded: https://github.com/journeyapps/zxing-android-embedded
- OpenID4VCI Specification: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
- Android Camera Permissions: https://developer.android.com/training/permissions/requesting
