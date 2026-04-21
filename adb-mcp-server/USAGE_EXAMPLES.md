# ADB MCP Server - Usage Examples

This document provides practical examples of using the ADB MCP Server tools.

## Device Management

### List All Connected Devices
```json
{
  "tool": "adb_devices",
  "arguments": {
    "long_output": true
  }
}
```

### Check Device State
```json
{
  "tool": "adb_get_state",
  "arguments": {
    "device_serial": "emulator-5554"
  }
}
```

### Wait for Device to be Ready
```json
{
  "tool": "adb_wait_for_device",
  "arguments": {
    "state": "device",
    "transport": "any"
  }
}
```

## Wireless Connection

### Enable TCP/IP Mode and Connect
```json
// Step 1: Enable TCP/IP on port 5555
{
  "tool": "adb_tcpip",
  "arguments": {
    "port": 5555
  }
}

// Step 2: Connect to device via WiFi
{
  "tool": "adb_connect",
  "arguments": {
    "host": "192.168.1.100",
    "port": 5555
  }
}
```

### Pair with Device (Android 11+)
```json
{
  "tool": "adb_pair",
  "arguments": {
    "host": "192.168.1.100",
    "port": 37891,
    "pairing_code": "123456"
  }
}
```

## Port Forwarding

### Forward Local Port to Device
```json
{
  "tool": "adb_forward",
  "arguments": {
    "local": "tcp:8080",
    "remote": "tcp:8080",
    "no_rebind": false
  }
}
```

### List All Port Forwards
```json
{
  "tool": "adb_forward_list",
  "arguments": {}
}
```

### Reverse Forward (Device to Host)
```json
{
  "tool": "adb_reverse",
  "arguments": {
    "remote": "tcp:3000",
    "local": "tcp:3000"
  }
}
```

## File Operations

### Push File to Device
```json
{
  "tool": "adb_push",
  "arguments": {
    "local_path": "./myapp.apk",
    "remote_path": "/sdcard/Download/myapp.apk",
    "sync": false,
    "compression": "brotli"
  }
}
```

### Pull File from Device
```json
{
  "tool": "adb_pull",
  "arguments": {
    "remote_path": "/sdcard/screenshot.png",
    "local_path": "./screenshot.png",
    "preserve": true
  }
}
```

## App Management

### Install APK with Permissions
```json
{
  "tool": "adb_install",
  "arguments": {
    "apk_path": "./myapp.apk",
    "replace": true,
    "grant_permissions": true,
    "allow_test": false
  }
}
```

### List Installed Packages
```json
// List all third-party apps
{
  "tool": "adb_pm_list_packages",
  "arguments": {
    "filter": "third-party",
    "show_path": true
  }
}
```

### Clear App Data
```json
{
  "tool": "adb_pm_clear",
  "arguments": {
    "package": "com.example.myapp"
  }
}
```

### Grant Runtime Permission
```json
{
  "tool": "adb_pm_grant",
  "arguments": {
    "package": "com.example.myapp",
    "permission": "android.permission.CAMERA"
  }
}
```

### Uninstall App
```json
{
  "tool": "adb_uninstall",
  "arguments": {
    "package": "com.example.myapp",
    "keep_data": false
  }
}
```

## Activity Management

### Start an Activity
```json
{
  "tool": "adb_am_start",
  "arguments": {
    "component": "com.example.myapp/.MainActivity",
    "wait": true
  }
}
```

### Start Activity with Intent Data
```json
{
  "tool": "adb_am_start",
  "arguments": {
    "component": "com.android.browser/.BrowserActivity",
    "action": "android.intent.action.VIEW",
    "data_uri": "https://example.com"
  }
}
```

### Force Stop Application
```json
{
  "tool": "adb_am_force_stop",
  "arguments": {
    "package": "com.example.myapp"
  }
}
```

### Send Broadcast
```json
{
  "tool": "adb_am_broadcast",
  "arguments": {
    "action": "android.intent.action.BOOT_COMPLETED"
  }
}
```

## Input Simulation

### Send Text Input
```json
{
  "tool": "adb_input_text",
  "arguments": {
    "text": "Hello World"
  }
}
```

### Send Key Event
```json
// Press Home button
{
  "tool": "adb_input_keyevent",
  "arguments": {
    "keycode": "KEYCODE_HOME"
  }
}

// Press Back button
{
  "tool": "adb_input_keyevent",
  "arguments": {
    "keycode": "KEYCODE_BACK"
  }
}
```

### Tap Screen
```json
{
  "tool": "adb_input_tap",
  "arguments": {
    "x": 500,
    "y": 1000
  }
}
```

### Swipe Gesture
```json
// Swipe up
{
  "tool": "adb_input_swipe",
  "arguments": {
    "x1": 500,
    "y1": 1500,
    "x2": 500,
    "y2": 500,
    "duration": 300
  }
}
```

## Screen Capture

### Take Screenshot
```json
{
  "tool": "adb_screencap",
  "arguments": {
    "remote_path": "/sdcard/screenshot.png"
  }
}
```

### Record Screen Video
```json
{
  "tool": "adb_screenrecord",
  "arguments": {
    "remote_path": "/sdcard/demo.mp4",
    "time_limit": 30,
    "bit_rate": 6000000,
    "size": "1280x720"
  }
}
```

## System Information

### Get Android Version
```json
{
  "tool": "adb_getprop",
  "arguments": {
    "property": "ro.build.version.release"
  }
}
```

### Get Device Model
```json
{
  "tool": "adb_getprop",
  "arguments": {
    "property": "ro.product.model"
  }
}
```

### List All Properties
```json
{
  "tool": "adb_getprop",
  "arguments": {}
}
```

### Get System Setting
```json
{
  "tool": "adb_settings_get",
  "arguments": {
    "namespace": "system",
    "key": "screen_brightness"
  }
}
```

### Set System Setting
```json
{
  "tool": "adb_settings_put",
  "arguments": {
    "namespace": "system",
    "key": "screen_brightness",
    "value": "100"
  }
}
```

### Get Battery Information
```json
{
  "tool": "adb_dumpsys",
  "arguments": {
    "service": "battery"
  }
}
```

### Get WiFi Information
```json
{
  "tool": "adb_dumpsys",
  "arguments": {
    "service": "wifi"
  }
}
```

## Debugging

### View Logcat (Errors Only)
```json
{
  "tool": "adb_logcat",
  "arguments": {
    "clear": false,
    "dump": true,
    "filter": "*:E"
  }
}
```

### View Logcat for Specific Tag
```json
{
  "tool": "adb_logcat",
  "arguments": {
    "dump": true,
    "tag": "MyApp"
  }
}
```

### Clear Logcat
```json
{
  "tool": "adb_logcat",
  "arguments": {
    "clear": true,
    "dump": false
  }
}
```

### Generate Bug Report
```json
{
  "tool": "adb_bugreport",
  "arguments": {
    "path": "./bugreport_2024.zip"
  }
}
```

### List JDWP Processes
```json
{
  "tool": "adb_jdwp",
  "arguments": {}
}
```

## Shell Commands

### Execute Custom Shell Command
```json
{
  "tool": "adb_shell",
  "arguments": {
    "command": "ls -la /sdcard/",
    "timeout": 30
  }
}
```

### Get Running Processes
```json
{
  "tool": "adb_shell",
  "arguments": {
    "command": "ps | grep com.example"
  }
}
```

### Check Disk Usage
```json
{
  "tool": "adb_shell",
  "arguments": {
    "command": "df -h"
  }
}
```

## System Control

### Reboot Device
```json
{
  "tool": "adb_reboot",
  "arguments": {
    "target": "system"
  }
}
```

### Reboot to Bootloader
```json
{
  "tool": "adb_reboot",
  "arguments": {
    "target": "bootloader"
  }
}
```

### Reboot to Recovery
```json
{
  "tool": "adb_reboot",
  "arguments": {
    "target": "recovery"
  }
}
```

### Enable Root Access
```json
{
  "tool": "adb_root",
  "arguments": {}
}
```

### Remount System Partition
```json
{
  "tool": "adb_remount",
  "arguments": {
    "auto_reboot": false
  }
}
```

## Security

### Disable dm-verity
```json
{
  "tool": "adb_disable_verity",
  "arguments": {}
}
```

### Enable dm-verity
```json
{
  "tool": "adb_enable_verity",
  "arguments": {}
}
```

## Server Management

### Start ADB Server
```json
{
  "tool": "adb_start_server",
  "arguments": {}
}
```

### Kill ADB Server
```json
{
  "tool": "adb_kill_server",
  "arguments": {}
}
```

### Check ADB Version
```json
{
  "tool": "adb_version",
  "arguments": {}
}
```

## Common Workflows

### Complete App Testing Workflow
```json
// 1. Install app
{
  "tool": "adb_install",
  "arguments": {
    "apk_path": "./myapp.apk",
    "replace": true,
    "grant_permissions": true
  }
}

// 2. Start app
{
  "tool": "adb_am_start",
  "arguments": {
    "component": "com.example.myapp/.MainActivity",
    "wait": true
  }
}

// 3. Simulate user input
{
  "tool": "adb_input_tap",
  "arguments": {
    "x": 500,
    "y": 1000
  }
}

// 4. Take screenshot
{
  "tool": "adb_screencap",
  "arguments": {
    "remote_path": "/sdcard/test_result.png"
  }
}

// 5. Pull screenshot
{
  "tool": "adb_pull",
  "arguments": {
    "remote_path": "/sdcard/test_result.png",
    "local_path": "./test_result.png"
  }
}

// 6. Check logs
{
  "tool": "adb_logcat",
  "arguments": {
    "dump": true,
    "tag": "MyApp"
  }
}

// 7. Clear app data
{
  "tool": "adb_pm_clear",
  "arguments": {
    "package": "com.example.myapp"
  }
}
```

### WiFi Debugging Setup
```json
// 1. Connect device via USB first
{
  "tool": "adb_devices",
  "arguments": {}
}

// 2. Enable TCP/IP mode
{
  "tool": "adb_tcpip",
  "arguments": {
    "port": 5555
  }
}

// 3. Get device IP (via shell)
{
  "tool": "adb_shell",
  "arguments": {
    "command": "ip addr show wlan0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1"
  }
}

// 4. Disconnect USB and connect via WiFi
{
  "tool": "adb_connect",
  "arguments": {
    "host": "192.168.1.100",
    "port": 5555
  }
}

// 5. Verify connection
{
  "tool": "adb_devices",
  "arguments": {
    "long_output": true
  }
}