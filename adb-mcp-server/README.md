# ADB MCP Server

A comprehensive Model Context Protocol (MCP) server that provides access to Android Debug Bridge (ADB) functionality. This server exposes ADB commands as MCP tools, enabling AI assistants and other MCP clients to interact with Android devices.

## Features

### Device Management
- List connected devices
- Get device state and serial number
- Wait for device states
- Connect/disconnect via TCP/IP
- Pair devices for secure communication

### Networking
- TCP/IP connection management
- Port forwarding (local to remote)
- Reverse port forwarding (remote to local)
- USB/TCP mode switching

### File Operations
- Push files to device
- Pull files from device
- Support for compression algorithms (brotli, lz4, zstd)
- Sync operations

### App Management
- Install/uninstall APKs
- List installed packages
- Clear app data
- Grant/revoke permissions
- Start activities and services
- Force stop applications

### Shell Commands
- Execute arbitrary shell commands
- Package manager (pm) operations
- Activity manager (am) operations
- Input simulation (text, tap, swipe, keyevents)

### Screen Capture
- Take screenshots
- Record screen video with customizable settings

### System Information
- Get device properties
- Read/write system settings
- Dump system service information
- View battery, memory, and CPU info

### Debugging
- View logcat output with filtering
- Generate bug reports
- List JDWP processes

### System Control
- Reboot device (normal, bootloader, recovery)
- Root/unroot adbd
- Remount partitions
- Enable/disable dm-verity

## Installation

### Prerequisites
- Python 3.10 or higher
- ADB installed and available in PATH
- Android device with USB debugging enabled

### Install from source

```bash
cd adb-mcp-server
pip install -e .
```

### Install dependencies only

```bash
pip install mcp
```

## Usage

### Running the Server

The server communicates via stdio, which is the standard for MCP servers:

```bash
python server.py
```

### Configuration with Claude Desktop

Add to your Claude Desktop configuration file:

**MacOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "adb": {
      "command": "python",
      "args": ["/path/to/adb-mcp-server/server.py"]
    }
  }
}
```

### Configuration with other MCP clients

Use the stdio transport with the command:
```bash
python /path/to/adb-mcp-server/server.py
```

## Available Resources

The server provides searchable documentation resources that can be accessed by MCP clients:

- **README.md** - Comprehensive documentation including features, installation, usage, and available tools
- **USAGE_EXAMPLES.md** - Practical examples for all tools covering common workflows and use cases
- **ARCHITECTURE.md** - Technical architecture documentation with design patterns and extension points
- **ADB_COMMANDS_REFERENCE.md** - Complete reference guide for all ADB commands with syntax, options, and examples

These resources are accessible through the MCP resource protocol, allowing AI assistants to search and reference the documentation when helping with ADB operations.


## Available Tools

### Device Management
- `adb_devices` - List all connected devices
- `adb_get_state` - Get device state
- `adb_get_serialno` - Get device serial number
- `adb_wait_for_device` - Wait for device to reach specific state

### Networking
- `adb_connect` - Connect to device via TCP/IP
- `adb_disconnect` - Disconnect from TCP/IP device
- `adb_tcpip` - Enable TCP/IP mode
- `adb_usb` - Enable USB mode
- `adb_pair` - Pair with device

### Port Forwarding
- `adb_forward` - Forward local port to remote
- `adb_forward_list` - List all forwards
- `adb_forward_remove` - Remove specific forward
- `adb_forward_remove_all` - Remove all forwards
- `adb_reverse` - Reverse forward remote to local
- `adb_reverse_list` - List all reverse forwards
- `adb_reverse_remove` - Remove specific reverse forward
- `adb_reverse_remove_all` - Remove all reverse forwards

### File Transfer
- `adb_push` - Copy files to device
- `adb_pull` - Copy files from device

### App Management
- `adb_install` - Install APK
- `adb_uninstall` - Uninstall app
- `adb_pm_list_packages` - List installed packages
- `adb_pm_path` - Get package path
- `adb_pm_clear` - Clear app data
- `adb_pm_grant` - Grant permission
- `adb_pm_revoke` - Revoke permission

### Activity Manager
- `adb_am_start` - Start activity
- `adb_am_force_stop` - Force stop app
- `adb_am_broadcast` - Send broadcast

### Input
- `adb_input_text` - Send text input
- `adb_input_keyevent` - Send key event
- `adb_input_tap` - Tap at coordinates
- `adb_input_swipe` - Perform swipe gesture

### Screen Capture
- `adb_screencap` - Take screenshot
- `adb_screenrecord` - Record screen video

### System Information
- `adb_getprop` - Get device property
- `adb_settings_get` - Get system setting
- `adb_settings_put` - Set system setting
- `adb_dumpsys` - Dump system service info

### Debugging
- `adb_logcat` - View device logs
- `adb_bugreport` - Generate bug report
- `adb_jdwp` - List JDWP processes
- `adb_shell` - Execute shell command

### System Control
- `adb_reboot` - Reboot device
- `adb_root` - Restart with root
- `adb_unroot` - Restart without root
- `adb_remount` - Remount partitions

### Security
- `adb_disable_verity` - Disable dm-verity
- `adb_enable_verity` - Enable dm-verity

### Server Management
- `adb_start_server` - Start ADB server
- `adb_kill_server` - Kill ADB server
- `adb_version` - Show ADB version

## Examples

### List Connected Devices
```python
# Tool: adb_devices
# Arguments: {"long_output": true}
```

### Install an APK
```python
# Tool: adb_install
# Arguments: {
#   "apk_path": "/path/to/app.apk",
#   "replace": true,
#   "grant_permissions": true
# }
```

### Take a Screenshot
```python
# Tool: adb_screencap
# Arguments: {
#   "remote_path": "/sdcard/screenshot.png"
# }
# Then pull it:
# Tool: adb_pull
# Arguments: {
#   "remote_path": "/sdcard/screenshot.png",
#   "local_path": "./screenshot.png"
# }
```

### Execute Shell Command
```python
# Tool: adb_shell
# Arguments: {
#   "command": "pm list packages -3"
# }
```

### Connect via WiFi
```python
# First enable TCP/IP mode:
# Tool: adb_tcpip
# Arguments: {"port": 5555}

# Then connect:
# Tool: adb_connect
# Arguments: {
#   "host": "192.168.1.100",
#   "port": 5555
# }
```

## Architecture

The server is built with:
- **ADBExecutor**: Core class that handles ADB command execution
- **Tool Definitions**: Comprehensive tool catalog with input schemas
- **Tool Implementations**: Handler functions for each tool
- **Error Handling**: Robust error handling and timeout management

### Code Organization
- Efficient code reuse through the `ADBExecutor` class
- Consistent parameter handling across all tools
- Optional device serial targeting for multi-device scenarios
- Configurable timeouts for long-running operations

## Development

### Running Tests
```bash
pytest tests/
```

### Code Formatting
```bash
black server.py
```

### Type Checking
```bash
mypy server.py
```

## Requirements

- Python 3.10+
- mcp >= 0.9.0
- ADB (Android Debug Bridge) installed and in PATH

## Troubleshooting

### ADB Not Found
Ensure ADB is installed and available in your system PATH:
```bash
adb version
```

### Device Not Detected
1. Enable USB debugging on your Android device
2. Check USB connection
3. Run `adb devices` to verify connection
4. Accept the authorization prompt on your device

### Permission Denied
Some operations require root access. Use `adb_root` to restart adbd with root permissions.

### Multiple Devices
When multiple devices are connected, specify the `device_serial` parameter in tool calls to target a specific device.

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## References

- [Android Debug Bridge (ADB) Documentation](https://developer.android.com/studio/command-line/adb)
- [Model Context Protocol](https://modelcontextprotocol.io/)
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)