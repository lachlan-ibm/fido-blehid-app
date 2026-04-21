#!/bin/bash
# bt-diagnose-scan.sh
# Diagnostic script to troubleshoot BLE scanning issues

set -e

echo "=== Bluetooth BLE Scan Diagnostics ==="
echo

# Check Bluetooth adapter status
echo "1. Checking Bluetooth adapter status..."
if ! command -v bluetoothctl &> /dev/null; then
    echo "ERROR: bluetoothctl not found. Install bluez package."
    exit 1
fi

echo "Bluetooth adapter info:"
bluetoothctl show | grep -E "Controller|Powered|Discoverable|Pairable"
echo

# Check if device is connected via ADB
echo "2. Checking ADB connection..."
ADB_DEVICES=$(adb devices 2>/dev/null | grep -v "List of devices" | grep "device$" | wc -l)
if [ "$ADB_DEVICES" -eq 0 ]; then
    echo "⚠ No ADB device connected"
else
    echo "✓ ADB device found"
    BT_MAC=$(adb shell settings get secure bluetooth_address 2>/dev/null | tr -d '\r')
    echo "Device Bluetooth MAC: $BT_MAC"
fi
echo

# Restart Bluetooth for clean state
echo "3. Restarting Bluetooth service..."
sudo systemctl restart bluetooth
sleep 5
echo "✓ Bluetooth restarted"
echo

# Note: scan-filter-clear may not be available in all bluetoothctl versions
echo "4. Preparing for scan..."
echo "✓ Ready to scan"
echo

# Start active scanning with verbose output
echo "5. Starting BLE scan (45 seconds)..."
echo "Looking for device: 'OPPO A5 5G'"
echo

# Create a temporary file for scan output
SCAN_LOG="/tmp/bt-scan-diagnostic.log"
rm -f "$SCAN_LOG"

# Start scan with bluetoothctl
(
    echo "power on"
    echo "agent on"
    echo "default-agent"
    echo "scan on"
    sleep 45
    echo "scan off"
) | bluetoothctl 2>&1 | tee "$SCAN_LOG" &
SCAN_PID=$!

# Wait for scan
wait $SCAN_PID 2>/dev/null || true
sleep 2

echo
echo "6. Scan results:"
echo "=================="

# Parse discovered devices
if [ -f "$SCAN_LOG" ]; then
    echo "All discovered devices:"
    grep -E "\[NEW\]|\[CHG\]" "$SCAN_LOG" | grep "Device" || echo "No devices found"
    echo
    
    echo "Devices matching OPPO/CPH/IBL/BEE:"
    grep -iE "oppo|cph|ibl|bee" "$SCAN_LOG" || echo "No matching devices found"
    echo
fi

# List currently visible devices
echo "7. Currently visible devices:"
bluetoothctl devices
echo

# Check for paired devices
echo "8. Paired devices:"
bluetoothctl devices Paired
echo

echo "=== Diagnostic Complete ==="
echo
echo "If no devices were found:"
echo "  1. Ensure the FIDO BLE HID app is running and advertising"
echo "  2. Check that Bluetooth is enabled on the phone"
echo "  3. Try moving the phone closer to the computer"
echo "  4. Check phone's Bluetooth visibility settings"
echo "  5. Restart the app and try again"

# Made with Bob
