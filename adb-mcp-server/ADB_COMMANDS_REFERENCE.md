# Android Debug Bridge (ADB) Commands Reference

**Version:** 1.0.41 (36.0.0-13206524)

## Overview

ADB (Android Debug Bridge) is a versatile command-line tool that lets you communicate with a device. The ADB command facilitates a variety of device actions, such as installing and debugging apps, and it provides access to a Unix shell that you can use to run a variety of commands on a device.

ADB connects to the ADB Server via its smart socket interface. Tasks are performed via commands - some are fulfilled directly by the server while others are forwarded to the adbd (ADB daemon) running on the device.

## Table of Contents
1. [Global Options](#global-options)
2. [General Commands](#general-commands)
3. [Networking Commands](#networking-commands)
4. [File Transfer Commands](#file-transfer-commands)
5. [Shell Commands](#shell-commands)
6. [App Installation Commands](#app-installation-commands)
7. [Debugging Commands](#debugging-commands)
8. [Security Commands](#security-commands)
9. [Scripting Commands](#scripting-commands)
10. [Internal Debugging Commands](#internal-debugging-commands)
11. [USB Commands](#usb-commands)
12. [Environment Variables](#environment-variables)

---

## Global Options

| Option | Description |
|--------|-------------|
| `-a` | Listen on all network interfaces, not just localhost |
| `-d` | Use USB device (error if multiple devices connected) |
| `-e` | Use TCP/IP device (error if multiple TCP/IP devices available) |
| `-s SERIAL` | Use device with given serial (overrides $ANDROID_SERIAL) |
| `-t ID` | Use device with given transport id |
| `-H` | Name of adb server host [default=localhost] |
| `-P` | Port of adb server [default=5037] |
| `-L SOCKET` | Listen on given socket for adb server [default=tcp:localhost:5037] |
| `--one-device SERIAL\|USB` | Only allowed with 'start-server' or 'server nodaemon', server will only connect to one USB device |
| `--exit-on-write-error` | Exit if stdout is closed |

---

## General Commands

### `devices [-l]`
List connected devices
- `-l` flag provides long output with additional device information

**Example:**
```bash
adb devices
adb devices -l
```

### `help`
Show help message with all available commands

### `version`
Show ADB version number

---

## Networking Commands

### `connect HOST[:PORT]`
Connect to a device via TCP/IP
- Default port: 5555

**Example:**
```bash
adb connect 192.168.1.100:5555
```

### `disconnect [HOST[:PORT]]`
Disconnect from given TCP/IP device or all devices
- Default port: 5555

**Example:**
```bash
adb disconnect
adb disconnect 192.168.1.100:5555
```

### `pair HOST[:PORT] [PAIRING CODE]`
Pair with a device for secure TCP/IP communication

**Example:**
```bash
adb pair 192.168.1.100:5555 123456
```

### `forward --list`
List all forward socket connections

### `forward [--no-rebind] LOCAL REMOTE`
Forward socket connection using various protocols:
- `tcp:<port>` (local may be "tcp:0" to pick any open port)
- `localabstract:<unix domain socket name>`
- `localreserved:<unix domain socket name>`
- `localfilesystem:<unix domain socket name>`
- `dev:<character device name>`
- `dev-raw:<character device name>` (open device in raw mode)
- `jdwp:<process pid>` (remote only)
- `vsock:<CID>:<port>` (remote only)
- `acceptfd:<fd>` (listen only)

**Example:**
```bash
adb forward tcp:8080 tcp:8080
adb forward --no-rebind tcp:9000 localabstract:logd
```

### `forward --remove LOCAL`
Remove specific forward socket connection

### `forward --remove-all`
Remove all forward socket connections

### `reverse --list`
List all reverse socket connections from device

### `reverse [--no-rebind] REMOTE LOCAL`
Reverse socket connection using:
- `tcp:<port>` (remote may be "tcp:0" to pick any open port)
- `localabstract:<unix domain socket name>`
- `localreserved:<unix domain socket name>`
- `localfilesystem:<unix domain socket name>`

**Example:**
```bash
adb reverse tcp:8081 tcp:8081
```

### `reverse --remove REMOTE`
Remove specific reverse socket connection

### `reverse --remove-all`
Remove all reverse socket connections from device

### `mdns check`
Check if mdns discovery is available

### `mdns services`
List all discovered services

---

## File Transfer Commands

### `push [--sync] [-z ALGORITHM] [-Z] LOCAL... REMOTE`
Copy local files/directories to device

**Options:**
- `-n` : Dry run - push files without storing to filesystem
- `-q` : Suppress progress messages
- `-Z` : Disable compression
- `-z` : Enable compression with algorithm (any/none/brotli/lz4/zstd)
- `--sync` : Only push files with different timestamps

**Example:**
```bash
adb push myfile.txt /sdcard/
adb push --sync myapp/ /data/local/tmp/
adb push -z brotli largefile.bin /sdcard/
```

### `pull [-a] [-z ALGORITHM] [-Z] REMOTE... LOCAL`
Copy files/directories from device

**Options:**
- `-a` : Preserve file timestamp and mode
- `-q` : Suppress progress messages
- `-Z` : Disable compression
- `-z` : Enable compression with algorithm (any/none/brotli/lz4/zstd)

**Example:**
```bash
adb pull /sdcard/myfile.txt .
adb pull -a /data/local/tmp/logs/ ./logs/
```

### `sync [-l] [-z ALGORITHM] [-Z] [PARTITION]`
Sync a local build from $ANDROID_PRODUCT_OUT to device

**Partitions:** all, data, odm, oem, product, system, system_ext, vendor (default: all)

**Options:**
- `-l` : List files that would be copied without copying
- `-n` : Dry run - push files without storing to filesystem
- `-q` : Suppress progress messages
- `-Z` : Disable compression
- `-z` : Enable compression with algorithm

**Example:**
```bash
adb sync
adb sync system
adb sync -l
```

---

## Shell Commands

### `shell [-e ESCAPE] [-n] [-Tt] [-x] [COMMAND...]`
Run remote shell command (interactive shell if no command given)

**Options:**
- `-e` : Choose escape character, or "none" [default: '~']
- `-n` : Don't read from stdin
- `-T` : Disable pty allocation
- `-t` : Allocate a pty if on a tty (-tt: force pty allocation)
- `-x` : Disable remote exit codes and stdout/stderr separation

**Examples:**
```bash
adb shell
adb shell ls -la /sdcard/
adb shell pm list packages
adb shell dumpsys battery
adb shell screencap /sdcard/screen.png
adb shell screenrecord /sdcard/demo.mp4
adb shell input text "Hello"
adb shell input keyevent KEYCODE_HOME
adb shell am start -n com.package.name/.ActivityName
adb shell pm clear com.package.name
adb shell settings get secure android_id
```

### `emu COMMAND`
Run emulator console command

---

## App Installation Commands

### `install [-lrtsdg] [--instant] PACKAGE`
Push a single package to device and install it

**Options:**
- `-r` : Replace existing application
- `-t` : Allow test packages
- `-d` : Allow version code downgrade (debuggable packages only)
- `-g` : Grant all runtime permissions
- `--abi ABI` : Override platform's default ABI
- `--instant` : Install as ephemeral install app
- `--no-streaming` : Always push APK and invoke Package Manager separately
- `--streaming` : Force streaming APK directly into Package Manager
- `--fastdeploy` : Use fast deploy
- `--no-fastdeploy` : Prevent use of fast deploy
- `--force-agent` : Force update of deployment agent with fast deploy
- `--date-check-agent` : Update agent when local version is newer
- `--version-check-agent` : Update agent when version code differs
- `--local-agent` : Locate agent files from local source build

**Example:**
```bash
adb install myapp.apk
adb install -r myapp.apk
adb install -g myapp.apk
```

### `install-multiple [-lrtsdpg] [--instant] PACKAGE...`
Push multiple APKs for a single package and install them

**Options:** Same as `install` plus:
- `-p` : Partial application install

**Example:**
```bash
adb install-multiple base.apk split1.apk split2.apk
```

### `install-multi-package [-lrtsdpg] [--instant] PACKAGE...`
Push one or more packages and install them atomically

**Example:**
```bash
adb install-multi-package app1.apk app2.apk
```

### `uninstall [-k] PACKAGE`
Remove app package from device

**Options:**
- `-k` : Keep the data and cache directories

**Example:**
```bash
adb uninstall com.example.myapp
adb uninstall -k com.example.myapp
```

---

## Debugging Commands

### `bugreport [PATH]`
Write bugreport to given PATH [default=bugreport.zip]
- If PATH is a directory, bug report is saved there
- Devices without zipped bug report support output to stdout

**Example:**
```bash
adb bugreport
adb bugreport ./bug_reports/
adb bugreport bugreport_$(date +%Y%m%d_%H%M%S).zip
```

### `jdwp`
List PIDs of processes hosting a JDWP transport

### `logcat`
Show device log

**Common logcat options:**
```bash
adb logcat
adb logcat -c                    # Clear log
adb logcat -d                    # Dump log and exit
adb logcat -v time              # Include timestamps
adb logcat *:E                  # Show only errors
adb logcat -s TAG               # Filter by tag
adb logcat | grep "pattern"     # Filter output
```

---

## Security Commands

### `disable-verity`
Disable dm-verity checking on userdebug builds

**Example:**
```bash
adb disable-verity
adb reboot
```

### `enable-verity`
Re-enable dm-verity checking on userdebug builds

**Example:**
```bash
adb enable-verity
adb reboot
```

### `keygen FILE`
Generate adb public/private key
- Private key stored in FILE

**Example:**
```bash
adb keygen ~/.android/adbkey
```

---

## Scripting Commands

### `wait-for[-TRANSPORT]-STATE`
Wait for device to be in a given state

**States:** device, recovery, rescue, sideload, bootloader, disconnect
**Transports:** usb, local, any [default=any]

**Examples:**
```bash
adb wait-for-device
adb wait-for-usb-device
adb wait-for-recovery
adb wait-for-bootloader
```

### `get-state`
Print device state: offline | bootloader | device

### `get-serialno`
Print device serial number

### `get-devpath`
Print device path

### `remount [-R]`
Remount partitions read-write
- `-R` : Automatically reboot if required

**Example:**
```bash
adb remount
adb remount -R
```

### `reboot [TARGET]`
Reboot the device

**Targets:**
- (none) : Boot to system image (default)
- `bootloader` : Reboot to bootloader
- `recovery` : Reboot to recovery
- `sideload` : Reboot to recovery and start sideload mode
- `sideload-auto-reboot` : Same as sideload but reboots after

**Examples:**
```bash
adb reboot
adb reboot bootloader
adb reboot recovery
adb reboot sideload
```

### `sideload OTAPACKAGE`
Sideload the given full OTA package

**Example:**
```bash
adb sideload ota_update.zip
```

### `root`
Restart adbd with root permissions

### `unroot`
Restart adbd without root permissions

### `usb`
Restart adbd listening on USB

### `tcpip PORT`
Restart adbd listening on TCP on specified PORT

**Example:**
```bash
adb tcpip 5555
```

---

## Internal Debugging Commands

### `start-server`
Ensure that there is a server running

### `kill-server`
Kill the server if it is running

### `reconnect`
Kick connection from host side to force reconnect

### `reconnect device`
Kick connection from device side to force reconnect

### `reconnect offline`
Reset offline/unauthorized devices to force reconnect

---

## USB Commands

### `attach`
Attach a detached USB device

### `detach`
Detach from a USB device to allow use by other processes

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `$ADB_TRACE` | Comma/space separated list of debug info to log: all, adb, sockets, packets, rwx, usb, sync, sysdeps, transport, jdwp, services, auth, fdevent, shell, incremental |
| `$ADB_VENDOR_KEYS` | Colon-separated list of keys (files or directories) |
| `$ANDROID_SERIAL` | Serial number to connect to (see -s option) |
| `$ANDROID_LOG_TAGS` | Tags to be used by logcat (see logcat --help) |
| `$ADB_LOCAL_TRANSPORT_MAX_PORT` | Max emulator scan port (default 5585, 16 emus) |
| `$ADB_MDNS_AUTO_CONNECT` | Comma-separated list of mdns services to allow auto-connect (default adb-tls-connect) |

---

## Common Use Cases

### Device Management
```bash
# List all connected devices
adb devices -l

# Connect to device over WiFi
adb tcpip 5555
adb connect 192.168.1.100:5555

# Get device info
adb shell getprop ro.build.version.release  # Android version
adb shell getprop ro.product.model          # Device model
adb shell getprop ro.serialno               # Serial number
```

### File Operations
```bash
# Copy file to device
adb push local.txt /sdcard/

# Copy file from device
adb pull /sdcard/remote.txt ./

# List files on device
adb shell ls -la /sdcard/
```

### App Management
```bash
# Install APK
adb install app.apk

# Uninstall app
adb uninstall com.example.app

# List installed packages
adb shell pm list packages

# Clear app data
adb shell pm clear com.example.app

# Start activity
adb shell am start -n com.example.app/.MainActivity
```

### Debugging
```bash
# View logs
adb logcat

# Capture screenshot
adb shell screencap /sdcard/screen.png
adb pull /sdcard/screen.png

# Record screen
adb shell screenrecord /sdcard/demo.mp4

# Get bug report
adb bugreport
```

### System Control
```bash
# Reboot device
adb reboot

# Reboot to bootloader
adb reboot bootloader

# Reboot to recovery
adb reboot recovery

# Root access
adb root
```

---

## Additional ADB Features

### `host-features`
List features supported by adb server

**Example:**
```bash
adb host-features
```

### `features`
List features supported by both adb server and device

**Example:**
```bash
adb features
```

### `server-status`
Display server configuration (USB backend, mDNS backend, log location, binary path)

**Example:**
```bash
adb server-status
```

---

## Common ADB Shell Commands

The `adb shell` command provides access to a Unix shell on the Android device. Here are commonly used shell commands:

### Package Manager (pm)

```bash
# List all packages
adb shell pm list packages

# List only system packages
adb shell pm list packages -s

# List only third-party packages
adb shell pm list packages -3

# List packages with their paths
adb shell pm list packages -f

# Search for specific package
adb shell pm list packages | grep keyword

# Get package path
adb shell pm path com.example.app

# Clear app data
adb shell pm clear com.example.app

# Disable app
adb shell pm disable-user com.example.app

# Enable app
adb shell pm enable com.example.app

# Uninstall app
adb shell pm uninstall com.example.app

# Grant permission
adb shell pm grant com.example.app android.permission.CAMERA

# Revoke permission
adb shell pm revoke com.example.app android.permission.CAMERA

# List permissions
adb shell pm list permissions

# Get app info
adb shell dumpsys package com.example.app
```

### Activity Manager (am)

```bash
# Start an activity
adb shell am start -n com.example.app/.MainActivity

# Start activity with data
adb shell am start -a android.intent.action.VIEW -d "http://example.com"

# Start service
adb shell am startservice -n com.example.app/.MyService

# Stop service
adb shell am stopservice -n com.example.app/.MyService

# Broadcast intent
adb shell am broadcast -a android.intent.action.BOOT_COMPLETED

# Force stop app
adb shell am force-stop com.example.app

# Kill app
adb shell am kill com.example.app

# Start activity for result
adb shell am start -W -n com.example.app/.MainActivity
```

### Input Commands

```bash
# Send text
adb shell input text "Hello World"

# Send keyevent
adb shell input keyevent KEYCODE_HOME
adb shell input keyevent KEYCODE_BACK
adb shell input keyevent KEYCODE_MENU
adb shell input keyevent 3  # HOME key
adb shell input keyevent 4  # BACK key

# Tap screen at coordinates
adb shell input tap 500 1000

# Swipe gesture
adb shell input swipe 500 1000 500 100  # Swipe up

# Long press
adb shell input swipe 500 1000 500 1000 1000  # 1 second press
```

### Screen Capture

```bash
# Take screenshot
adb shell screencap /sdcard/screenshot.png
adb pull /sdcard/screenshot.png

# Record screen (Ctrl+C to stop)
adb shell screenrecord /sdcard/demo.mp4
adb pull /sdcard/demo.mp4

# Record with options
adb shell screenrecord --time-limit 10 /sdcard/demo.mp4  # 10 seconds
adb shell screenrecord --bit-rate 6000000 /sdcard/demo.mp4  # 6Mbps
adb shell screenrecord --size 1280x720 /sdcard/demo.mp4  # Custom resolution
```

### System Information

```bash
# Get Android version
adb shell getprop ro.build.version.release

# Get SDK version
adb shell getprop ro.build.version.sdk

# Get device model
adb shell getprop ro.product.model

# Get device manufacturer
adb shell getprop ro.product.manufacturer

# Get serial number
adb shell getprop ro.serialno

# Get device ID
adb shell settings get secure android_id

# List all properties
adb shell getprop

# Get screen resolution
adb shell wm size

# Get screen density
adb shell wm density

# Get battery info
adb shell dumpsys battery

# Get memory info
adb shell dumpsys meminfo

# Get CPU info
adb shell cat /proc/cpuinfo

# Get disk usage
adb shell df

# Get running processes
adb shell ps

# Get top processes
adb shell top -n 1
```

### Settings Commands

```bash
# Get setting
adb shell settings get system screen_brightness
adb shell settings get secure android_id
adb shell settings get global airplane_mode_on

# Set setting
adb shell settings put system screen_brightness 100
adb shell settings put global airplane_mode_on 1

# List all settings
adb shell settings list system
adb shell settings list secure
adb shell settings list global

# Enable/disable WiFi
adb shell svc wifi enable
adb shell svc wifi disable

# Enable/disable mobile data
adb shell svc data enable
adb shell svc data disable

# Enable/disable Bluetooth
adb shell svc bluetooth enable
adb shell svc bluetooth disable
```

### File Operations

```bash
# List files
adb shell ls /sdcard/
adb shell ls -la /data/local/tmp/

# Create directory
adb shell mkdir /sdcard/mydir

# Remove file
adb shell rm /sdcard/file.txt

# Remove directory
adb shell rm -r /sdcard/mydir

# Copy file
adb shell cp /sdcard/source.txt /sdcard/dest.txt

# Move file
adb shell mv /sdcard/old.txt /sdcard/new.txt

# View file content
adb shell cat /sdcard/file.txt

# Search in file
adb shell grep "pattern" /sdcard/file.txt

# Find files
adb shell find /sdcard -name "*.txt"

# Get file info
adb shell stat /sdcard/file.txt

# Change permissions
adb shell chmod 755 /data/local/tmp/script.sh
```

### Network Commands

```bash
# Get IP address
adb shell ip addr show wlan0

# Ping
adb shell ping -c 4 google.com

# Check network connectivity
adb shell dumpsys connectivity

# List network interfaces
adb shell netcfg

# Get WiFi info
adb shell dumpsys wifi

# Netstat
adb shell netstat
```

### Process Management

```bash
# List processes
adb shell ps

# List processes by name
adb shell ps | grep com.example.app

# Kill process
adb shell kill <PID>

# Kill process by name
adb shell pkill -f com.example.app

# Get process info
adb shell dumpsys activity processes
```

### Dumpsys Commands

```bash
# Battery info
adb shell dumpsys battery

# Display info
adb shell dumpsys display

# Window info
adb shell dumpsys window

# Activity info
adb shell dumpsys activity

# Package info
adb shell dumpsys package com.example.app

# Memory info
adb shell dumpsys meminfo com.example.app

# CPU info
adb shell dumpsys cpuinfo

# Network stats
adb shell dumpsys netstats

# Alarm info
adb shell dumpsys alarm

# Notification info
adb shell dumpsys notification

# List all services
adb shell service list
```

### Logcat Filtering

```bash
# View all logs
adb logcat

# Clear logs
adb logcat -c

# View and save logs
adb logcat > logfile.txt

# Filter by priority
adb logcat *:E  # Error
adb logcat *:W  # Warning
adb logcat *:I  # Info
adb logcat *:D  # Debug
adb logcat *:V  # Verbose

# Filter by tag
adb logcat -s TAG_NAME

# Filter by package
adb logcat | grep com.example.app

# Multiple filters
adb logcat TAG1:D TAG2:W *:S

# Time format
adb logcat -v time
adb logcat -v threadtime
adb logcat -v long

# Dump and exit
adb logcat -d

# Show recent logs
adb logcat -t 100

# Filter by regex
adb logcat -e "pattern"
```

---

## Advanced Environment Variables

| Variable | Description |
|----------|-------------|
| `$ADB_MDNS_OPENSCREEN` | Forces mDNS backend to openscreen when set to "1". Default is Bonjour (mdnsResponder) |
| `$ADB_LIBUSB` | Set to "1" to enable libusb, or "0" to enable ADB backend implementation |

---

## USB Backend Information

ADB has its own USB backend implementation but can also employ libusb. Use these commands to identify which is in use:

```bash
# Check USB backend (usb: prefix omitted for libusb)
adb devices -l

# Check for libusb support
adb host-features
```

---

## Troubleshooting

### Device Not Detected

```bash
# Restart ADB server
adb kill-server
adb start-server

# Check devices
adb devices

# Check USB connection
lsusb  # On Linux
```

### Unauthorized Device

```bash
# Revoke USB debugging authorizations on device
# Settings > Developer Options > Revoke USB debugging authorizations

# Then reconnect and accept the prompt on device
adb devices
```

### Multiple Devices

```bash
# List devices with serial numbers
adb devices

# Use specific device
adb -s <serial> shell
adb -s <serial> install app.apk
```

### Connection Issues

```bash
# Reconnect
adb reconnect

# Reconnect device
adb reconnect device

# Reset offline devices
adb reconnect offline
```

---

## Online Documentation

For more information, visit:
- Official Documentation: https://android.googlesource.com/platform/packages/modules/adb/+/refs/heads/main/docs/user/adb.1.md
- Issue Tracker: https://issuetracker.google.com/issues/new?component=192795&template=1310483
- Android Developer Guide: https://developer.android.com/studio/command-line/adb