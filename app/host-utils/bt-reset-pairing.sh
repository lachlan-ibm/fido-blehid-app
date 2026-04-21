#!/bin/bash
# bt-reset-pairing.sh
# Removes Bluetooth pairing/trust for OPPO A5 5G device
# Use this before reinstalling the app to clear stale bond state

set -e

DEVICE_ADDRESS="A8:88:CE:7F:89:32"
DEVICE_NAME="OPPO A5 5G"

echo "=== Bluetooth Pairing Reset for $DEVICE_NAME ==="
echo

# Check if device is known to BlueZ
echo "Checking if device $DEVICE_ADDRESS is paired..."
if ! bluetoothctl devices | grep -q "$DEVICE_ADDRESS"; then
    echo "Device $DEVICE_ADDRESS is not paired"
    echo "Nothing to do"
    exit 0
fi
echo "✓ Device found in paired devices list"

# Disconnect if connected
echo
echo "Disconnecting device (if connected)..."
bluetoothctl disconnect "$DEVICE_ADDRESS" 2>/dev/null || true
sleep 1

# Remove device (unpair and untrust)
echo
echo "Removing device pairing and trust..."
bluetoothctl remove "$DEVICE_ADDRESS"
sleep 1

# Restart bluetooth service to clear runtime state
echo
echo "Restarting bluetooth service to clear cache..."
sudo systemctl restart bluetooth
sleep 2

# Verify removal
echo
echo "Verifying device removal..."
if bluetoothctl devices | grep -q "$DEVICE_ADDRESS"; then
    echo "WARNING: Device still appears in paired list"
    echo "You may need to manually remove it from GNOME Settings"
else
    echo "✓ Device successfully removed"
fi

echo
echo "=== Reset Complete ==="
echo
echo "To re-pair the device after app reinstall:"
echo "1. Start the app on the phone"
echo "2. Run: bluetoothctl scan.transport le"
echo "3. Run: bluetoothctl scan on"
echo "4. Wait for device to appear, then:"
echo "   bluetoothctl pair $DEVICE_ADDRESS"
echo "   bluetoothctl trust $DEVICE_ADDRESS"
echo "   bluetoothctl connect $DEVICE_ADDRESS"

# Made with Bob
