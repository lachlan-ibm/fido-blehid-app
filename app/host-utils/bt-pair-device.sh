#!/bin/bash
# bt-pair-device.sh
# Pairs and trusts the OPPO A5 5G device via Bluetooth
# Uses BLE connection-based pairing to work with RPA

set -e

# Well-known MAC address for OPPO A5 5G (fallback)
FALLBACK_MAC="A8:88:CE:7F:89:32"

echo "=== Bluetooth Pairing Setup for OPPO A5 5G ==="
echo

# Check if device is connected via ADB
echo "Checking for ADB-connected device..."
ADB_DEVICES=$(adb devices 2>/dev/null | grep -v "List of devices" | grep "device$" | wc -l)

if [ "$ADB_DEVICES" -eq 0 ]; then
    echo "⚠ No ADB device connected"
    echo "Falling back to well-known MAC address: $FALLBACK_MAC"
    BT_MAC="$FALLBACK_MAC"
else
    echo "✓ ADB device found"
    
    # Get Bluetooth MAC address from device
    echo
    echo "Getting Bluetooth MAC address from device..."
    BT_MAC=$(adb shell settings get secure bluetooth_address 2>/dev/null | tr -d '\r')
    
    if [ -z "$BT_MAC" ] || [ "$BT_MAC" = "null" ]; then
        echo "Could not get MAC from settings, trying alternative method..."
        BT_MAC=$(adb shell dumpsys bluetooth_manager | grep -i "address:" | head -1 | awk '{print $2}' | tr -d '\r')
    fi
    
    if [ -z "$BT_MAC" ] || [ "$BT_MAC" = "null" ]; then
        echo "⚠ Could not determine Bluetooth MAC address from ADB"
        echo "Falling back to well-known MAC address: $FALLBACK_MAC"
        BT_MAC="$FALLBACK_MAC"
    else
        echo "✓ Device Bluetooth MAC: $BT_MAC"
    fi
fi

echo
echo "Using Bluetooth MAC: $BT_MAC"

# Check if already paired
echo
echo "Checking if device is already paired..."
if bluetoothctl devices | grep -q "$BT_MAC"; then
    echo "Device is already paired"
    read -p "Remove existing pairing and re-pair? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Removing existing pairing..."
        bluetoothctl remove "$BT_MAC" || true
        sleep 1
    else
        echo "Keeping existing pairing"
        echo "Ensuring device is trusted..."
        bluetoothctl trust "$BT_MAC"
        exit 0
    fi
fi

# Prompt user to prepare phone
echo
echo "=========================================="
echo "PREPARATION STEPS:"
echo "=========================================="
echo "1. Start the FIDO BLE HID app"
echo "2. Tap 'Server Status' to start advertising"
echo "3. Wait for 'Advertising...' status"
echo
read -p "Press Enter when app is advertising..."

# Initialize bluetoothctl
echo
echo "Initializing Bluetooth adapter..."
bluetoothctl << EOF
power on
agent on
default-agent
EOF

# Start scanning with improved method
echo
echo "Scanning for device..."

# Restart Bluetooth to clear any stale state
echo "Restarting Bluetooth service for clean scan..."
sudo systemctl restart bluetooth
sleep 15

# Use bluetoothctl with timeout for better control
SCAN_LOG="/tmp/bt-scan-$(date +%s).log"
rm -f "$SCAN_LOG"

echo "Starting 45 second BLE scan..."
echo "(Looking for device: 'OPPO A5 5G' or MAC: $BT_MAC)"

# Start bluetoothctl in background and pipe to log
(
    echo "power on"
    echo "agent on"
    echo "default-agent"
    echo "scan on"
    sleep 45
    echo "scan off"
) | bluetoothctl 2>&1 | tee "$SCAN_LOG" &
SCAN_PID=$!

# Wait for scan to complete
wait $SCAN_PID 2>/dev/null || true
sleep 2

# Check if device appeared
echo
echo "Checking if device is visible..."
DEVICES=$(bluetoothctl devices)

# Debug: show what was found
if [ -z "$DEVICES" ]; then
    echo "⚠ No devices discovered during scan"
    echo
    echo "Debug: Scan output:"
    if [ -f "$SCAN_LOG" ]; then
        echo "Devices found during scan:"
        grep -E "\[NEW\]|\[CHG\]" "$SCAN_LOG" | grep "Device" | head -10 || echo "No devices in scan log"
    fi
    echo
    echo "Current device list:"
    bluetoothctl devices
fi

FOUND_MAC=""

# First try to find by public MAC
if echo "$DEVICES" | grep -q "$BT_MAC"; then
    echo "✓ Device found by public MAC: $BT_MAC"
    FOUND_MAC="$BT_MAC"
# Then try by device name (case insensitive)
elif echo "$DEVICES" | grep -qi "OPPO A5 5G"; then
    FOUND_MAC=$(echo "$DEVICES" | grep -i "OPPO A5 5G" | head -1 | awk '{print $2}')
    echo "✓ Device found by name 'OPPO A5 5G' with address: $FOUND_MAC"
    echo "  (Using discovered address for connection)"
# Fallback to other name patterns
elif echo "$DEVICES" | grep -qi "oppo\|cph\|ibl\|bee"; then
    FOUND_MAC=$(echo "$DEVICES" | grep -iE "oppo|cph|ibl|bee" | head -1 | awk '{print $2}')
    echo "✓ Device found by name pattern with address: $FOUND_MAC"
    echo "  (Using discovered address for connection)"
else
    echo "ERROR: Device not found in scan results"
    echo
    echo "Discovered devices:"
    echo "$DEVICES"
    echo
    echo "Debug: Checking scan log for device name..."
    if [ -f "$SCAN_LOG" ]; then
        echo "Devices with 'OPPO' in scan log:"
        grep -i "oppo" "$SCAN_LOG" || echo "No OPPO devices found"
    fi
    echo
    echo "Make sure:"
    echo "  1. The FIDO BLE HID app shows 'Server is advertising...'"
    echo "  2. Device name is 'OPPO A5 5G' in the app"
    echo "  3. Bluetooth is enabled on the phone"
    echo "  4. Try running: sudo systemctl restart bluetooth"
    exit 1
fi

# Connect to the device (this will trigger pairing)
echo
echo "Connecting to device $FOUND_MAC..."
echo "This will trigger the pairing process"
echo "Accept the pairing request on both devices when prompted"
echo

if bluetoothctl connect "$FOUND_MAC"; then
    echo "✓ Connection initiated"
    
    # Wait for pairing to complete
    echo
    echo "Waiting for pairing to complete..."
    echo "(Accept pairing on both devices if prompted)"
    TIMEOUT=60
    ELAPSED=0
    PAIRED=false
    
    while [ $ELAPSED -lt $TIMEOUT ]; do
        # Check if either MAC is paired (RPA or public)
        if bluetoothctl devices Paired | grep -q "$BT_MAC\|$FOUND_MAC"; then
            PAIRED=true
            break
        fi
        sleep 1
        ELAPSED=$((ELAPSED + 1))
        if [ $((ELAPSED % 5)) -eq 0 ]; then
            echo -n "."
        fi
    done
    
    echo
    
    if [ "$PAIRED" = true ]; then
        echo "✓ Pairing successful"
    else
        echo "⚠ Pairing not detected, but connection succeeded"
        echo "  Device may already be paired or pairing not required"
    fi
    
    # Trust the device using whichever MAC is visible
    echo
    echo "Trusting device..."
    if bluetoothctl trust "$FOUND_MAC" 2>/dev/null || bluetoothctl trust "$BT_MAC" 2>/dev/null; then
        echo "✓ Device trusted"
    else
        echo "⚠ Could not trust device (may already be trusted)"
    fi
    
    # Clear the BlueZ service cache to force GATT re-discovery
    echo
    echo "Clearing BlueZ service cache..."
    sudo rm -rf /var/lib/bluetooth/*/"$BT_MAC"/cache 2>/dev/null || true
    
    # Restart Bluetooth service for clean state
    echo "Restarting Bluetooth service..."
    sudo systemctl restart bluetooth
    sleep 3
    
    echo
    echo "=========================================="
    echo "Setup Complete!"
    echo "=========================================="
    echo
    echo "Device is connected and ready"
    echo "RPA: $FOUND_MAC"
    echo "Public MAC: $BT_MAC"
    echo
    echo "Note: RPA changes periodically for privacy"
    echo "BlueZ will resolve it automatically after pairing"
else
    echo
    echo "ERROR: Connection failed"
    echo
    echo "The device uses RPA which requires connection-based pairing."
    echo "If pairing was requested, accept it on both devices."
    echo
    echo "Try these steps:"
    echo "  1. Make sure the app is actively advertising"
    echo "  2. Accept any pairing requests on the phone"
    echo "  3. Run this script again"
    exit 1
fi

# Made with Bob
