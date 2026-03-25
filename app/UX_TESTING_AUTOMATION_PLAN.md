# Automated UX Testing Plan for FIDO BLE HID App

## Overview

This document outlines a comprehensive plan for automating UX testing of the FIDO BLE HID authenticator app on Android emulators and devices.

## Current State Analysis

Based on the existing codebase:
- **Activities**: MainActivity, ServerActivity, ManageActivity, ResidentCredentialsActivity, CreatePasskeyActivity
- **Current Testing**: Manual UI testing on emulator, Python-based FIDO protocol testing
- **Gap**: No automated UI/UX testing framework

## Testing Approach Options

### Option 1: UI Automator (Recommended)
**Pros:**
- Native Android testing framework
- Works on emulators and real devices
- No app modification required
- Can test across different apps
- Good for black-box testing

**Cons:**
- Requires separate test APK
- More setup than Espresso

### Option 2: Espresso
**Pros:**
- Faster execution
- Better integration with app code
- More precise UI element targeting

**Cons:**
- Requires app instrumentation
- Only tests your own app
- More invasive

### Option 3: Appium
**Pros:**
- Cross-platform (iOS/Android)
- Language agnostic (Python, Java, etc.)
- Industry standard

**Cons:**
- More complex setup
- Requires Appium server
- Slower than native frameworks

**Recommendation**: Start with **UI Automator** for its simplicity and flexibility.

## Automated Test Scenarios

### 1. App Launch and Initialization
- **Test**: App launches successfully
- **Verify**: MainActivity is displayed
- **Check**: No crash on startup
- **Validate**: Foreground service starts

### 2. Navigation Flow
- **Test**: Navigate between activities
  - MainActivity → ServerActivity
  - MainActivity → ManageActivity
  - ManageActivity → ResidentCredentialsActivity
  - ManageActivity → CreatePasskeyActivity
- **Verify**: Each activity loads correctly
- **Check**: Back button navigation works

### 3. Bluetooth Permission Handling
- **Test**: App requests Bluetooth permissions
- **Verify**: Permission dialog appears
- **Test**: Grant/deny permissions
- **Verify**: App handles both cases gracefully

### 4. Passkey Management UI
- **Test**: View passkey list
- **Verify**: List displays correctly (empty or with items)
- **Test**: Create new passkey flow
- **Verify**: Input fields are accessible
- **Test**: Delete passkey
- **Verify**: Confirmation dialog appears

### 5. Server Activity
- **Test**: Start/stop HID service
- **Verify**: Service status updates
- **Check**: Notification appears when service is running

### 6. Error Handling
- **Test**: Bluetooth disabled scenario
- **Verify**: Appropriate error message shown
- **Test**: Invalid input handling
- **Verify**: Validation messages appear

### 7. Resident Credentials
- **Test**: View resident credentials list
- **Verify**: Credentials display correctly
- **Test**: Credential details view
- **Verify**: All fields are readable

## Implementation Plan

### Phase 1: Setup and Infrastructure (Week 1)
1. **Create test module structure**
   - Add `app/src/androidTest/` directory
   - Configure build.gradle for UI Automator dependencies
   - Set up test runner configuration

2. **Create base test classes**
   - BaseUITest.java - Common setup/teardown
   - TestHelper.java - Utility methods
   - ScreenObjects.java - Page object pattern

3. **Set up test execution scripts**
   - Shell script to run tests on emulator
   - ADB commands for test APK installation
   - Log collection automation

### Phase 2: Core Test Implementation (Week 2)
1. **Implement basic tests**
   - App launch test
   - Navigation tests
   - Permission handling tests

2. **Create screen object models**
   - MainActivityScreen.java
   - ServerActivityScreen.java
   - ManageActivityScreen.java

3. **Add assertion helpers**
   - Custom matchers for UI elements
   - Screenshot capture on failure
   - Logcat integration

### Phase 3: Advanced Scenarios (Week 3)
1. **Implement complex flows**
   - Passkey creation end-to-end
   - Service lifecycle tests
   - Multi-activity workflows

2. **Add performance checks**
   - Activity launch time
   - UI responsiveness
   - Memory usage monitoring

3. **Error scenario testing**
   - Network errors
   - Bluetooth errors
   - Invalid state handling

### Phase 4: Integration and CI/CD (Week 4)
1. **Integrate with build system**
   - Gradle task for running tests
   - Test report generation
   - Coverage reporting

2. **Create test documentation**
   - Test case descriptions
   - How to run tests
   - Troubleshooting guide

3. **Set up continuous testing**
   - GitHub Actions workflow (if applicable)
   - Automated test runs on commits
   - Test result notifications

## Technical Implementation Details

### Directory Structure
```
app/
├── src/
│   ├── androidTest/
│   │   └── java/
│   │       └── com/
│   │           └── isfs/
│   │               └── blekey/
│   │                   ├── BaseUITest.java
│   │                   ├── TestHelper.java
│   │                   ├── screens/
│   │                   │   ├── MainActivityScreen.java
│   │                   │   ├── ServerActivityScreen.java
│   │                   │   ├── ManageActivityScreen.java
│   │                   │   └── CreatePasskeyScreen.java
│   │                   └── tests/
│   │                       ├── AppLaunchTest.java
│   │                       ├── NavigationTest.java
│   │                       ├── PasskeyManagementTest.java
│   │                       └── ServiceLifecycleTest.java
│   └── main/
└── build.gradle (updated with test dependencies)
```

### Required Dependencies (build.gradle)
```gradle
androidTestImplementation 'androidx.test.ext:junit:1.1.5'
androidTestImplementation 'androidx.test:runner:1.5.2'
androidTestImplementation 'androidx.test:rules:1.5.0'
androidTestImplementation 'androidx.test.uiautomator:uiautomator:2.3.0'
androidTestImplementation 'androidx.test.espresso:espresso-core:3.5.1'
```

### Test Execution Commands

#### Run all UI tests
```bash
./gradlew connectedAndroidTest
```

#### Run specific test class
```bash
./gradlew connectedAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=com.isfs.blekey.tests.AppLaunchTest
```

#### Run tests with ADB
```bash
# Install test APK
adb install -r app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk

# Run tests
adb shell am instrument -w com.isfs.blekey.test/androidx.test.runner.AndroidJUnitRunner

# Pull test results
adb pull /sdcard/Android/data/com.isfs.blekey/files/test-results/
```

## Test Execution Script

Create `app/run-ui-tests.sh`:
```bash
#!/bin/bash
# Automated UI test execution script

set -e

DEVICE_SERIAL="${1:-emulator-5554}"
PACKAGE="com.isfs.blekey"

echo "=== FIDO BLE HID App - UI Test Automation ==="
echo "Device: $DEVICE_SERIAL"
echo ""

# Check device connection
echo "Checking device connection..."
adb -s "$DEVICE_SERIAL" get-state || {
    echo "Error: Device not connected"
    exit 1
}

# Build test APK
echo "Building test APK..."
./gradlew assembleDebugAndroidTest

# Install app and test APK
echo "Installing APKs..."
adb -s "$DEVICE_SERIAL" install -r app/build/outputs/apk/debug/app-debug.apk
adb -s "$DEVICE_SERIAL" install -r app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk

# Clear app data
echo "Clearing app data..."
adb -s "$DEVICE_SERIAL" shell pm clear "$PACKAGE"

# Run tests
echo "Running UI tests..."
adb -s "$DEVICE_SERIAL" shell am instrument -w \
    -e package com.isfs.blekey.tests \
    "$PACKAGE.test/androidx.test.runner.AndroidJUnitRunner"

# Pull test results
echo "Pulling test results..."
mkdir -p test-results
adb -s "$DEVICE_SERIAL" pull /sdcard/Android/data/"$PACKAGE"/files/test-results/ test-results/ || true

# Pull screenshots
adb -s "$DEVICE_SERIAL" pull /sdcard/Pictures/Screenshots/ test-results/screenshots/ || true

echo ""
echo "=== Test execution complete ==="
echo "Results available in: test-results/"
```

## Integration with Existing Testing

### Complement Python FIDO Testing
- UI tests verify the app interface
- Python scripts test FIDO protocol compliance
- Together they provide full coverage

### Use with ADB MCP Server
- Leverage existing ADB tools for device control
- Automate test device setup
- Collect logs and diagnostics

### Combine with Manual Testing
- Automated tests for regression
- Manual testing for exploratory scenarios
- UI tests validate common workflows

## Success Metrics

1. **Coverage**: 80%+ of critical user flows automated
2. **Reliability**: Tests pass consistently (>95% success rate)
3. **Speed**: Full test suite runs in <10 minutes
4. **Maintainability**: Tests are easy to update when UI changes
5. **Debugging**: Clear failure messages and screenshots

## Maintenance Plan

### Regular Updates
- Update tests when UI changes
- Add tests for new features
- Remove obsolete tests

### Test Review
- Monthly review of test effectiveness
- Identify flaky tests
- Optimize slow tests

### Documentation
- Keep test documentation current
- Document known issues
- Share best practices

## Alternative: Quick Start with ADB UI Automator

For immediate testing without full framework setup:

### Using `adb shell uiautomator`
```bash
# Dump UI hierarchy
adb shell uiautomator dump
adb pull /sdcard/window_dump.xml

# Record UI interactions
adb shell uiautomator runtest <jar> -c <class>
```

### Using Python + uiautomator2
```bash
pip install uiautomator2

# Python script for quick UI testing
python3 << 'EOF'
import uiautomator2 as u2

d = u2.connect()  # Connect to device
d.app_start("com.isfs.blekey")  # Launch app
d(text="Server").click()  # Click button
d.screenshot("test_screenshot.png")  # Capture screen
EOF
```

## Next Steps

1. **Review and approve this plan**
2. **Choose testing approach** (UI Automator recommended)
3. **Set up development environment**
4. **Implement Phase 1** (infrastructure)
5. **Create first test** (app launch)
6. **Iterate and expand** test coverage

## Resources

- [UI Automator Documentation](https://developer.android.com/training/testing/ui-automator)
- [Android Testing Codelab](https://developer.android.com/codelabs/advanced-android-kotlin-training-testing-basics)
- [Testing Best Practices](https://developer.android.com/training/testing/fundamentals)
- [uiautomator2 Python Library](https://github.com/openatx/uiautomator2)

## Questions to Consider

1. **Test frequency**: Run on every commit, daily, or weekly?
2. **Test environment**: Emulator only or include real devices?
3. **CI/CD integration**: GitHub Actions, Jenkins, or other?
4. **Reporting**: Where should test results be published?
5. **Maintenance**: Who will maintain the test suite?