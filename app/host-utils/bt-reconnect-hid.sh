#!/bin/bash
# bt-reconnect-hid.sh
# Reconnects BLE HID device after app restart by clearing BlueZ cache
# Use this when the app restarts and HID device doesn't enumerate

set -e

DEVICE_MAC="A8:88:CE:7F:89:32"
DEVICE_NAME="OPPO A5 5G"

echo "=== BLE HID Reconnection Helper for $DEVICE_NAME ==="
echo

# Check if device is paired
if ! bluetoothctl devices | grep -q "$DEVICE_MAC"; then
    echo "ERROR: Device $DEVICE_MAC is not paired"
    echo "Run ./bt-pair-device.sh first"
    exit 1
fi

echo "Device: $DEVICE_NAME ($DEVICE_MAC)"
echo

# Check current connection status
CONNECTED=$(bluetoothctl info "$DEVICE_MAC" | grep "Connected:" | awk '{print $2}')
echo "Current status: Connected=$CONNECTED"

# If connected, disconnect first
if [ "$CONNECTED" = "yes" ]; then
    echo "Disconnecting device..."
    bluetoothctl disconnect "$DEVICE_MAC" 2>/dev/null || true
    sleep 2
fi

# Clear the BlueZ service cache to force GATT re-discovery
echo "Clearing BlueZ service cache..."
sudo rm -rf /var/lib/bluetooth/*/"$DEVICE_MAC"/cache 2>/dev/null || true

# Restart Bluetooth service for clean state
echo "Restarting Bluetooth service..."
sudo systemctl restart bluetooth
sleep 3

# Reconnect
echo "Reconnecting to device..."
if bluetoothctl connect "$DEVICE_MAC"; then
    echo "✓ Connection successful"
else
    echo "ERROR: Connection failed"
    exit 1
fi

# Wait for HID enumeration
echo
echo "Waiting for HID device enumeration..."
sleep 5

# Check for HID device
if ls /sys/bus/hid/devices/0005:* 2>/dev/null | grep -q .; then
    echo "✓ BLE HID device detected:"
    ls -la /sys/bus/hid/devices/0005:*/
    echo
    
    # Find corresponding hidraw device
    echo "HID raw devices:"
    ls -la /dev/hidraw* | tail -3
    echo
    
    # Try to identify the FIDO device
    echo "Checking for FIDO2 device..."
    for dev in /dev/hidraw*; do
        if sudo fido2-token -I "$dev" 2>/dev/null | grep -q "proto: 0x02"; then
            echo "✓ FIDO2 device found: $dev"
            echo
            sudo fido2-token -I "$dev" | head -10
            break
        fi
    done
else
    echo "WARNING: No BLE HID device (0005:*) found"
    echo "The device may need more time to enumerate, or there may be an issue"
    echo
    echo "Try:"
    echo "  1. Check if app is running on phone"
    echo "  2. Wait 10 more seconds and check: ls /sys/bus/hid/devices/0005:*"
    echo "  3. Check Bluetooth logs: sudo journalctl -u bluetooth -n 50"
fi

echo
echo "=== Reconnection Complete ==="
echo
echo "If HID device still doesn't appear:"
echo "  1. Ensure the FIDO BLE HID app is running on the phone"
echo "  2. Check app shows 'Server Status' as active"
echo "  3. Try running this script again"
echo "  4. As last resort, run ./bt-reset-pairing.sh and re-pair"

# Made with Bob