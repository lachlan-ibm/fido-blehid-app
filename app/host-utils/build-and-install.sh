#!/bin/bash
# build-and-install.sh
# Builds debug APK and installs to paired ADB device
# Requires: Android SDK with Gradle wrapper in project root

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
APK_PATH="$PROJECT_ROOT/app/build/outputs/apk/debug/app-debug.apk"
PACKAGE_NAME="com.isfs.blekey"

echo "=== FIDO BLE HID App - Build and Install ==="
echo
echo "Project root: $PROJECT_ROOT"
echo

# Check if gradlew exists
if [ ! -f "$PROJECT_ROOT/gradlew" ]; then
    echo "ERROR: gradlew not found in $PROJECT_ROOT"
    echo "Run 'gradle wrapper' in the project root first"
    exit 1
fi

# Check for ADB device
echo "Checking for ADB device..."
ADB_DEVICES=$(adb devices 2>/dev/null | grep -v "List of devices" | grep "device$" | wc -l)

if [ "$ADB_DEVICES" -eq 0 ]; then
    echo "ERROR: No ADB device connected"
    echo
    echo "Connect device via USB or wireless ADB:"
    echo "  USB: Connect device and enable USB debugging"
    echo "  Wireless: Run ./adb-wireless-setup.sh"
    exit 1
fi

echo "✓ ADB device found"
adb devices | grep "device$"
echo

# Clean previous build
echo "Cleaning previous build..."
cd "$PROJECT_ROOT"
./gradlew clean

# Build debug APK
echo
echo "Building debug APK..."
echo "This may take a few minutes on first build..."
./gradlew :app:assembleDebug

# Check if APK was created
if [ ! -f "$APK_PATH" ]; then
    echo
    echo "ERROR: APK not found at $APK_PATH"
    echo "Build may have failed. Check output above for errors."
    exit 1
fi

echo
echo "✓ Build successful"
echo "APK: $APK_PATH"
APK_SIZE=$(du -h "$APK_PATH" | cut -f1)
echo "Size: $APK_SIZE"

# Uninstall old version if it exists
echo
echo "Checking if app is already installed..."
if adb shell pm list packages | grep -q "$PACKAGE_NAME"; then
    echo "App is already installed - removing old version..."
    adb uninstall "$PACKAGE_NAME" || true
    sleep 1
    echo "✓ Old version removed"
else
    echo "App not currently installed"
fi

# Install APK (fresh install after uninstall)
echo
echo "Installing debug APK to device..."
if adb install "$APK_PATH"; then
    echo "✓ Installation successful"
else
    echo
    echo "ERROR: Installation failed"
    echo
    echo "Common issues:"
    echo "  1. Device storage full"
    echo "  2. Signature mismatch (uninstall old version first)"
    echo "  3. ADB connection lost"
    exit 1
fi

# Verify installation
echo
echo "Verifying installation..."
if adb shell pm list packages | grep -q "$PACKAGE_NAME"; then
    echo "✓ App verified on device"
    
    # Get app info
    echo
    echo "App information:"
    adb shell dumpsys package "$PACKAGE_NAME" | grep -E "versionCode|versionName|firstInstallTime|lastUpdateTime" | head -4
else
    echo "WARNING: Could not verify app installation"
fi

echo
echo "=== Build and Install Complete ==="
echo
echo "Debug APK installed with:"
echo "  - Debug mode: ENABLED (debuggable=true)"
echo "  - Verbose logging: DEBUG level (logback.xml)"
echo "  - Package: $PACKAGE_NAME"
echo
echo "To launch the app:"
echo "  adb shell am start -n $PACKAGE_NAME/.MainActivity"
echo
echo "To view verbose logs:"
echo "  adb logcat -s HIDService:D HIDBTAdvertiser:D HIDForegroundService:D"
echo "  adb logcat | grep 'com.isfs.blekey'"
echo
echo "To uninstall:"
echo "  adb uninstall $PACKAGE_NAME"

# Made with Bob