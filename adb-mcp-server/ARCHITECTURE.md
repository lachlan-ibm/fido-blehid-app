# ADB MCP Server - Architecture Documentation

## Overview

The ADB MCP Server is a comprehensive Model Context Protocol server that exposes Android Debug Bridge (ADB) functionality through a well-structured set of tools. The architecture emphasizes code reuse, maintainability, and extensibility.

## Core Components

### 1. ADBExecutor Class

The `ADBExecutor` class is the foundation of the server, providing a reusable interface for executing ADB commands.

**Key Features:**
- Asynchronous command execution using `asyncio`
- Configurable timeouts
- Device targeting via serial number
- Unified error handling
- Separate methods for direct ADB commands and shell commands

**Methods:**
- `execute(args, device_serial, timeout)` - Execute ADB commands
- `shell(command, device_serial, timeout)` - Execute shell commands on device

### 2. ADBResult Dataclass

Encapsulates the result of an ADB command execution:
- `success: bool` - Whether the command succeeded
- `stdout: str` - Standard output
- `stderr: str` - Standard error
- `returncode: int` - Process exit code

### 3. Resource Handlers

The server exposes documentation as searchable MCP resources, enabling AI assistants to access comprehensive information about the server's capabilities.

**Available Resources:**
- `README.md` - Main documentation with features, installation, and tool reference
- `USAGE_EXAMPLES.md` - Practical examples for all tools
- `ARCHITECTURE.md` - Technical architecture and design documentation
- `ADB_COMMANDS_REFERENCE.md` - Complete ADB command reference with syntax and examples

**Implementation:**
- `list_resources()` - Returns list of available documentation resources
- `read_resource(uri)` - Reads and returns content of requested resource
- Resources use `file://` URI scheme with validation
- Only whitelisted documentation files can be accessed


### 3. Tool Definitions

**Tool Loading Architecture:**

Tools are now defined in a separate [`tools.json`](tools.json) file, which provides several benefits:
- **Separation of Concerns**: Tool definitions are separated from implementation logic
- **Easier Maintenance**: Tools can be modified without touching Python code
- **Better Organization**: JSON format makes it easy to see all tools at a glance
- **Extensibility**: New tools can be added by simply editing the JSON file

The `load_tools_from_json()` function reads the tool definitions from `tools.json` and converts them into MCP `Tool` objects. This approach makes the codebase more maintainable and allows for easier tool management.

**Tool Categories:**

Tools are organized into logical categories:

#### Device Management (4 tools)
- Device listing and state queries
- Wait for device states
- Serial number retrieval

#### Networking (9 tools)
- TCP/IP connection management
- Device pairing
- USB/TCP mode switching

#### Port Forwarding (8 tools)
- Local to remote forwarding
- Reverse forwarding (remote to local)
- List and remove forwards

#### File Transfer (2 tools)
- Push files to device
- Pull files from device
- Compression support

#### App Management (7 tools)
- Install/uninstall APKs
- Package manager operations
- Permission management

#### Activity Manager (3 tools)
- Start activities
- Force stop apps
- Send broadcasts

#### Input Simulation (4 tools)
- Text input
- Key events
- Touch gestures (tap, swipe)

#### Screen Capture (2 tools)
- Screenshots
- Screen recording

#### System Information (4 tools)
- Device properties
- System settings
- Service information dumps

#### Debugging (4 tools)
- Logcat viewing
- Bug report generation
- JDWP process listing
- Shell command execution

#### System Control (4 tools)
- Reboot operations
- Root/unroot
- Partition remounting

#### Security (2 tools)
- dm-verity control

#### Server Management (3 tools)
- Start/kill ADB server
- Version information

**Total: 60+ tools**

## Design Patterns

### 1. Command Builder Pattern

Tools build ADB command arguments incrementally based on provided parameters:

```python
args = ["install"]
if arguments.get("replace", False):
    args.append("-r")
if arguments.get("grant_permissions", False):
    args.append("-g")
args.append(arguments["apk_path"])
result = await executor.execute(args, device_serial)
```

### 2. Unified Error Handling

All tool implementations follow a consistent error handling pattern:

```python
try:
    # Execute command
    result = await executor.execute(...)
    
    # Format response
    if result.success:
        response_text = f"Command executed successfully\n\n"
        if result.stdout:
            response_text += f"Output:\n{result.stdout}"
    else:
        response_text = f"Command failed (exit code: {result.returncode})\n\n"
        if result.stderr:
            response_text += f"Error:\n{result.stderr}"
    
    return [TextContent(type="text", text=response_text)]
    
except Exception as e:
    logger.error(f"Error executing tool {name}: {e}", exc_info=True)
    return [TextContent(type="text", text=f"Error executing tool: {str(e)}")]
```

### 3. Optional Device Targeting

Most tools support an optional `device_serial` parameter for multi-device scenarios:

```python
device_serial = arguments.get("device_serial")
result = await executor.execute(args, device_serial)
```

### 4. Timeout Management

Different operations have appropriate default timeouts:
- Standard commands: 30 seconds
- File transfers: 120 seconds
- Bug reports: 300 seconds
- Screen recording: 200 seconds

## Data Flow

```
MCP Client
    ↓
[Tool Request with Arguments]
    ↓
Tool Handler (call_tool)
    ↓
Command Builder
    ↓
ADBExecutor
    ↓
subprocess (adb command)
    ↓
ADBResult
    ↓
Response Formatter
    ↓
TextContent
    ↓
MCP Client
```

## Tool Schema Design

Each tool has a well-defined JSON schema:

```python
Tool(
    name="tool_name",
    description="Clear description of what the tool does",
    inputSchema={
        "type": "object",
        "properties": {
            "param1": {
                "type": "string",
                "description": "Parameter description"
            },
            "param2": {
                "type": "boolean",
                "description": "Parameter description",
                "default": False
            }
        },
        "required": ["param1"]  # Only truly required params
    }
)
```

## Code Organization

```
adb-mcp-server/
├── server.py              # Main server implementation
├── tools.json             # Tool definitions (NEW)
├── pyproject.toml         # Project configuration
├── requirements.txt       # Dependencies
├── README.md             # User documentation
├── ARCHITECTURE.md       # This file
├── USAGE_EXAMPLES.md     # Practical examples
├── ADB_COMMANDS_REFERENCE.md  # ADB command reference
├── LICENSE               # MIT License
├── .gitignore           # Git ignore rules
└── test_server.py       # Test suite
```

## Extension Points

### Adding New Tools

1. Add tool definition to `tools.json`:
```json
{
  "name": "adb_new_feature",
  "description": "Description of the new feature",
  "inputSchema": {
    "type": "object",
    "properties": {
      "param1": {
        "type": "string",
        "description": "Parameter description"
      }
    },
    "required": ["param1"]
  }
}
```

2. Add implementation to `call_tool()` in `server.py`:
```python
elif name == "adb_new_feature":
    # Build command
    args = ["new-feature"]
    # Execute
    result = await executor.execute(args, device_serial)
```

### Adding New Command Categories

Follow the existing pattern:
1. Group related tools together
2. Use consistent naming (e.g., `adb_category_action`)
3. Document in README.md
4. Add examples to USAGE_EXAMPLES.md

### Custom ADB Path

Modify the `ADBExecutor.__init__()` method:
```python
def __init__(self, adb_path: str = "adb"):
    self.adb_path = adb_path
```

## Performance Considerations

### Async Execution
All ADB commands run asynchronously, allowing the server to handle multiple requests efficiently.

### Timeout Protection
Every command has a timeout to prevent hanging operations.

### Efficient Output Handling
Large outputs (like logcat) are handled efficiently through streaming.

### Connection Pooling
The ADB server maintains persistent connections to devices, reducing overhead.

## Security Considerations

### Command Injection Prevention
All arguments are passed as list elements to `subprocess`, preventing shell injection.

### Device Authorization
ADB's built-in authorization mechanism is preserved - devices must be authorized before use.

### Root Access Control
Root operations are explicit tools that require user intent.

### No Credential Storage
The server doesn't store any credentials or sensitive data.

## Error Handling Strategy

### Levels of Error Handling

1. **Process Level**: Capture subprocess errors
2. **Timeout Level**: Handle command timeouts
3. **Tool Level**: Catch and log exceptions
4. **Response Level**: Format errors for client

### Error Information

Errors include:
- Exit code
- stderr output
- stdout output (if any)
- Exception details (when applicable)

## Testing Strategy

### Unit Tests
Test individual components:
- ADBExecutor command building
- Error handling
- Timeout behavior

### Integration Tests
Test with actual ADB:
- Device connectivity
- Command execution
- Error scenarios

### Manual Testing
Use test_server.py for quick validation.

## Future Enhancements

Potential areas for expansion:

1. **Batch Operations**: Execute multiple commands in sequence
2. **File Watching**: Monitor device files for changes
3. **Event Streaming**: Real-time logcat streaming
4. **Device Profiles**: Save common device configurations
5. **Command History**: Track executed commands
6. **Performance Metrics**: Measure command execution times
7. **Advanced Filtering**: More sophisticated logcat filtering
8. **Screenshot Analysis**: Built-in image analysis tools
9. **APK Analysis**: Extract APK information before installation
10. **Backup/Restore**: Device backup and restore operations

## Dependencies

### Required
- Python 3.10+
- mcp >= 0.9.0
- ADB (external tool)

### Optional (Development)
- pytest
- pytest-asyncio
- black
- mypy

## Conclusion

The ADB MCP Server provides a robust, well-architected interface to ADB functionality. Its design emphasizes:
- **Simplicity**: Easy to understand and use
- **Extensibility**: Simple to add new features
- **Reliability**: Comprehensive error handling
- **Performance**: Async execution and efficient resource usage
- **Maintainability**: Clean code organization and documentation