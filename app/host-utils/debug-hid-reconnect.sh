#!/bin/bash
# debug-hid-reconnect.sh
# Diagnoses why HID device doesn't reappear when app restarts

set -e

DEVICE_MAC="${1:-A8:88:CE:7F:89:32}"

echo "=== HID Reconnection Debugging ==="
echo "Device MAC: $DEVICE_MAC"
echo

# 1. Check if app is running
echo "[1/8] Checking if FIDO BLE HID app is running..."
if adb shell "ps -A | grep com.isfs.blekey" | grep -q "com.isfs.blekey"; then
    echo "✓ App process is running"
    adb shell "ps -A | grep com.isfs.blekey"
else
    echo "✗ App is NOT running"
    echo "Start the app and try again"
    exit 1
fi
echo

# 2. Check Bluetooth adapter state on Android
echo "[2/8] Checking Android Bluetooth state..."
BT_STATE=$(adb shell settings get global bluetooth_on)
if [ "$BT_STATE" = "1" ]; then
    echo "✓ Bluetooth is enabled on Android"
else
    echo "✗ Bluetooth is disabled on Android"
    exit 1
fi
echo

# 3. Check if GATT server is advertising
echo "[3/8] Checking BLE advertising status..."
adb logcat -d -s HIDService:D HIDBTAdvertiser:D | tail -20 | grep -i "advertising\|gatt"
echo

# 4. Check bonded devices on Android
echo "[4/8] Checking bonded devices on Android..."
adb shell dumpsys bluetooth_manager | grep -A5 "Bonded devices:"
echo

# 5. Check BlueZ connection state
echo "[5/8] Checking BlueZ connection state..."
if bluetoothctl info "$DEVICE_MAC" | grep -q "Connected: yes"; then
    echo "✓ BlueZ shows device as connected"
else
    echo "✗ BlueZ shows device as disconnected"
    bluetoothctl info "$DEVICE_MAC" | grep "Connected:"
fi
echo

# 6. Check if HID device exists
echo "[6/8] Checking for HID device..."
if ls /sys/bus/hid/devices/0005:1337:* 2>/dev/null | grep -q .; then
    echo "✓ HID device exists:"
    ls -la /sys/bus/hid/devices/0005:1337:*
    HID_DEV=$(ls -d /sys/bus/hid/devices/0005:1337:* 2>/dev/null | head -1)
    echo
    echo "HID device details:"
    cat "$HID_DEV/uevent" 2>/dev/null || echo "Cannot read uevent"
else
    echo "✗ No HID device found"
    echo "This is the problem - HOGP plugin didn't create the device"
fi
echo

# 7. Check BlueZ HOGP logs
echo "[7/8] Checking BlueZ HOGP logs (last 50 lines)..."
sudo journalctl -u bluetooth -n 50 --no-pager | grep -i "hog\|uhid\|service.changed\|0x1812\|$DEVICE_MAC" || echo "No relevant HOGP logs found"
echo

# 8. Check if Service Changed was sent
echo "[8/8] Checking if Service Changed indication was sent..."
adb logcat -d -s HIDService:D | grep -i "service.changed" | tail -5
echo

echo "=== Diagnosis Complete ==="
echo
echo "Common issues:"
echo "1. If 'Advertising started' not in logs → App didn't start GATT server"
echo "2. If 'Connected: no' in BlueZ → Device not connected, check pairing"
echo "3. If no HID device but connected → Service Changed not sent or BlueZ cache issue"
echo "4. If 'Service Changed indication sent' not in logs → App didn't send it"
echo
echo "To force reconnection:"
echo "  bluetoothctl disconnect $DEVICE_MAC"
echo "  bluetoothctl connect $DEVICE_MAC"

# Made with Bob
