#!/bin/bash
# adb-wireless-setup.sh
# Sets up wireless ADB connection to OPPO A5 5G device
# Assumes device is connected via USB initially

set -e

DEVICE_SERIAL="TWUKAYMVPRC6S85D"
ADB_PORT=5555

echo "=== ADB Wireless Setup for OPPO A5 5G ==="
echo

# Check if device is connected via USB
echo "Checking for USB-connected device..."
if ! adb devices | grep -q "$DEVICE_SERIAL"; then
    echo "ERROR: Device $DEVICE_SERIAL not found via USB"
    echo "Please connect the device via USB and enable USB debugging"
    exit 1
fi
echo "✓ Device found via USB"

# Enable TCP/IP mode on device
echo
echo "Enabling TCP/IP mode on port $ADB_PORT..."
adb -s "$DEVICE_SERIAL" tcpip "$ADB_PORT"
sleep 2

# Get device IP address
echo
echo "Getting device IP address..."
DEVICE_IP=$(adb -s "$DEVICE_SERIAL" shell ip addr show wlan0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)

if [ -z "$DEVICE_IP" ]; then
    echo "ERROR: Could not determine device IP address"
    echo "Make sure the device is connected to Wi-Fi"
    exit 1
fi
echo "✓ Device IP: $DEVICE_IP"

# Connect wirelessly
echo
echo "Connecting to $DEVICE_IP:$ADB_PORT..."
sleep 1
adb connect "$DEVICE_IP:$ADB_PORT"

# Verify connection
echo
echo "Verifying wireless connection..."
sleep 1
if adb devices | grep -q "$DEVICE_IP:$ADB_PORT"; then
    echo "✓ Wireless ADB connection established"
    echo
    echo "You can now disconnect the USB cable"
    echo "To reconnect after reboot: adb connect $DEVICE_IP:$ADB_PORT"
else
    echo "ERROR: Wireless connection failed"
    exit 1
fi

echo
echo "=== Setup Complete ==="
adb devices

# Made with Bob
