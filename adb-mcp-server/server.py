#!/usr/bin/env python3
"""
ADB MCP Server - Model Context Protocol server for Android Debug Bridge
Provides comprehensive ADB functionality through MCP tools
"""

import asyncio
import json
import logging
import shlex
import subprocess
from typing import Any, Optional, Sequence
from dataclasses import dataclass
from pathlib import Path

from mcp.server import Server
from mcp.types import (
    Tool,
    TextContent,
    ImageContent,
    EmbeddedResource,
    Resource,
)
import mcp.server.stdio
from pydantic import AnyUrl

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("adb-mcp-server")

# Server instance
app = Server("adb-mcp-server")


@dataclass
class ADBResult:
    """Result from an ADB command execution"""
    success: bool
    stdout: str
    stderr: str
    returncode: int


class ADBExecutor:
    """Core ADB command executor with reusable functionality"""
    
    def __init__(self):
        self.adb_path = "adb"
    
    async def execute(
        self,
        args: list[str],
        device_serial: Optional[str] = None,
        timeout: int = 30
    ) -> ADBResult:
        """Execute an ADB command with optional device targeting"""
        cmd = [self.adb_path]
        
        # Add device selector if specified
        if device_serial:
            cmd.extend(["-s", device_serial])
        
        cmd.extend(args)
        
        try:
            logger.info(f"Executing: {' '.join(cmd)}")
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            return ADBResult(
                success=process.returncode == 0,
                stdout=stdout.decode('utf-8', errors='replace'),
                stderr=stderr.decode('utf-8', errors='replace'),
                returncode=process.returncode or 0
            )
        except asyncio.TimeoutError:
            return ADBResult(
                success=False,
                stdout="",
                stderr=f"Command timed out after {timeout} seconds",
                returncode=-1
            )
        except Exception as e:
            return ADBResult(
                success=False,
                stdout="",
                stderr=str(e),
                returncode=-1
            )
    
    async def shell(
        self,
        command: str,
        device_serial: Optional[str] = None,
        timeout: int = 30
    ) -> ADBResult:
        """Execute a shell command on the device"""
        return await self.execute(["shell", command], device_serial, timeout)


# Global executor instance
executor = ADBExecutor()


# ============================================================================
# TOOL DEFINITIONS
# ============================================================================

def load_tools_from_json() -> list[Tool]:
    """Load tool definitions from tools.json file"""
    tools_file = Path(__file__).parent / "tools.json"
    try:
        with open(tools_file, 'r') as f:
            tools_data = json.load(f)
        
        return [Tool(**tool_def) for tool_def in tools_data]
    except Exception as e:
        logger.error(f"Failed to load tools from {tools_file}: {e}")
        return []


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List all available ADB tools"""
    return load_tools_from_json()


# ============================================================================
# TOOL IMPLEMENTATIONS
# ============================================================================

@app.call_tool()
async def call_tool(name: str, arguments: Any) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
    """Handle tool execution"""
    
    try:
        device_serial = arguments.get("device_serial")
        
        # Device Management
        if name == "adb_devices":
            args = ["devices"]
            if arguments.get("long_output", False):
                args.append("-l")
            result = await executor.execute(args)
            
        elif name == "adb_get_state":
            result = await executor.execute(["get-state"], device_serial)
            
        elif name == "adb_get_serialno":
            result = await executor.execute(["get-serialno"], device_serial)
            
        elif name == "adb_wait_for_device":
            state = arguments.get("state", "device")
            transport = arguments.get("transport", "any")
            cmd = f"wait-for-{transport}-{state}" if transport != "any" else f"wait-for-{state}"
            result = await executor.execute([cmd], device_serial)
        
        # Networking
        elif name == "adb_connect":
            host = arguments["host"]
            port = arguments.get("port", 5555)
            result = await executor.execute(["connect", f"{host}:{port}"])
            
        elif name == "adb_disconnect":
            if "host" in arguments:
                host = arguments["host"]
                port = arguments.get("port", 5555)
                result = await executor.execute(["disconnect", f"{host}:{port}"])
            else:
                result = await executor.execute(["disconnect"])
                
        elif name == "adb_tcpip":
            port = arguments["port"]
            result = await executor.execute(["tcpip", str(port)], device_serial)
            
        elif name == "adb_usb":
            result = await executor.execute(["usb"], device_serial)
            
        elif name == "adb_pair":
            host = arguments["host"]
            port = arguments["port"]
            code = arguments["pairing_code"]
            result = await executor.execute(["pair", f"{host}:{port}", code])
        
        # Port Forwarding
        elif name == "adb_forward":
            args = ["forward"]
            if arguments.get("no_rebind", False):
                args.append("--no-rebind")
            args.extend([arguments["local"], arguments["remote"]])
            result = await executor.execute(args, device_serial)
            
        elif name == "adb_forward_list":
            result = await executor.execute(["forward", "--list"], device_serial)
            
        elif name == "adb_forward_remove":
            result = await executor.execute(["forward", "--remove", arguments["local"]], device_serial)
            
        elif name == "adb_forward_remove_all":
            result = await executor.execute(["forward", "--remove-all"], device_serial)
            
        elif name == "adb_reverse":
            args = ["reverse"]
            if arguments.get("no_rebind", False):
                args.append("--no-rebind")
            args.extend([arguments["remote"], arguments["local"]])
            result = await executor.execute(args, device_serial)
            
        elif name == "adb_reverse_list":
            result = await executor.execute(["reverse", "--list"], device_serial)
            
        elif name == "adb_reverse_remove":
            result = await executor.execute(["reverse", "--remove", arguments["remote"]], device_serial)
            
        elif name == "adb_reverse_remove_all":
            result = await executor.execute(["reverse", "--remove-all"], device_serial)
        
        # File Transfer
        elif name == "adb_push":
            args = ["push"]
            if arguments.get("sync", False):
                args.append("--sync")
            if "compression" in arguments:
                args.extend(["-z", arguments["compression"]])
            args.extend([arguments["local_path"], arguments["remote_path"]])
            result = await executor.execute(args, device_serial, timeout=120)
            
        elif name == "adb_pull":
            args = ["pull"]
            if arguments.get("preserve", False):
                args.append("-a")
            if "compression" in arguments:
                args.extend(["-z", arguments["compression"]])
            args.extend([arguments["remote_path"], arguments["local_path"]])
            result = await executor.execute(args, device_serial, timeout=120)
        
        # App Management
        elif name == "adb_install":
            args = ["install"]
            if arguments.get("replace", False):
                args.append("-r")
            if arguments.get("grant_permissions", False):
                args.append("-g")
            if arguments.get("allow_test", False):
                args.append("-t")
            if arguments.get("allow_downgrade", False):
                args.append("-d")
            if arguments.get("instant", False):
                args.append("--instant")
            args.append(arguments["apk_path"])
            result = await executor.execute(args, device_serial, timeout=120)
            
        elif name == "adb_uninstall":
            args = ["uninstall"]
            if arguments.get("keep_data", False):
                args.append("-k")
            args.append(arguments["package"])
            result = await executor.execute(args, device_serial)
        
        # Shell Commands
        elif name == "adb_shell":
            timeout = arguments.get("timeout", 30)
            result = await executor.shell(arguments["command"], device_serial, timeout)
        
        # Package Manager
        elif name == "adb_pm_list_packages":
            cmd = "pm list packages"
            filter_type = arguments.get("filter", "all")
            if filter_type == "system":
                cmd += " -s"
            elif filter_type == "third-party":
                cmd += " -3"
            elif filter_type == "enabled":
                cmd += " -e"
            elif filter_type == "disabled":
                cmd += " -d"
            if arguments.get("show_path", False):
                cmd += " -f"
            result = await executor.shell(cmd, device_serial)
            
        elif name == "adb_pm_path":
            result = await executor.shell(f"pm path {arguments['package']}", device_serial)
            
        elif name == "adb_pm_clear":
            result = await executor.shell(f"pm clear {arguments['package']}", device_serial)
            
        elif name == "adb_pm_grant":
            result = await executor.shell(
                f"pm grant {arguments['package']} {arguments['permission']}", 
                device_serial
            )
            
        elif name == "adb_pm_revoke":
            result = await executor.shell(
                f"pm revoke {arguments['package']} {arguments['permission']}", 
                device_serial
            )
        
        # Activity Manager
        elif name == "adb_am_start":
            cmd = "am start"
            if arguments.get("wait", False):
                cmd += " -W"
            if "action" in arguments:
                cmd += f" -a {arguments['action']}"
            if "data_uri" in arguments:
                cmd += f" -d {arguments['data_uri']}"
            cmd += f" -n {arguments['component']}"
            result = await executor.shell(cmd, device_serial)
            
        elif name == "adb_am_force_stop":
            result = await executor.shell(f"am force-stop {arguments['package']}", device_serial)
            
        elif name == "adb_am_broadcast":
            result = await executor.shell(f"am broadcast -a {arguments['action']}", device_serial)
        
        # Input Commands
        elif name == "adb_input_text":
            # Escape text for shell
            text = arguments["text"].replace(" ", "%s")
            result = await executor.shell(f"input text {text}", device_serial)
            
        elif name == "adb_input_keyevent":
            result = await executor.shell(f"input keyevent {arguments['keycode']}", device_serial)
            
        elif name == "adb_input_tap":
            result = await executor.shell(
                f"input tap {arguments['x']} {arguments['y']}", 
                device_serial
            )
            
        elif name == "adb_input_swipe":
            duration = arguments.get("duration", 300)
            result = await executor.shell(
                f"input swipe {arguments['x1']} {arguments['y1']} {arguments['x2']} {arguments['y2']} {duration}",
                device_serial
            )
        
        # Screen Capture
        elif name == "adb_screencap":
            remote_path = arguments.get("remote_path", "/sdcard/screenshot.png")
            result = await executor.shell(f"screencap {remote_path}", device_serial)
            
        elif name == "adb_screenrecord":
            remote_path = arguments.get("remote_path", "/sdcard/screenrecord.mp4")
            cmd = f"screenrecord"
            if "time_limit" in arguments:
                cmd += f" --time-limit {arguments['time_limit']}"
            if "bit_rate" in arguments:
                cmd += f" --bit-rate {arguments['bit_rate']}"
            if "size" in arguments:
                cmd += f" --size {arguments['size']}"
            cmd += f" {remote_path}"
            result = await executor.shell(cmd, device_serial, timeout=200)
        
        # System Information
        elif name == "adb_getprop":
            if "property" in arguments and arguments["property"]:
                result = await executor.shell(f"getprop {arguments['property']}", device_serial)
            else:
                result = await executor.shell("getprop", device_serial)
                
        elif name == "adb_settings_get":
            result = await executor.shell(
                f"settings get {arguments['namespace']} {arguments['key']}", 
                device_serial
            )
            
        elif name == "adb_settings_put":
            result = await executor.shell(
                f"settings put {arguments['namespace']} {arguments['key']} {arguments['value']}", 
                device_serial
            )
            
        elif name == "adb_dumpsys":
            if "service" in arguments and arguments["service"]:
                result = await executor.shell(f"dumpsys {arguments['service']}", device_serial)
            else:
                result = await executor.shell("dumpsys -l", device_serial)
        
        # Debugging
        elif name == "adb_logcat":
            cmd = "logcat"
            if arguments.get("clear", False):
                await executor.shell("logcat -c", device_serial)
            if arguments.get("dump", True):
                cmd += " -d"
            if "filter" in arguments:
                cmd += f" {arguments['filter']}"
            if "tag" in arguments:
                cmd += f" -s {arguments['tag']}"
            # Limit output lines to prevent timeouts with large log buffers
            max_lines = arguments.get("max_lines", 1000)
            cmd += f" -t {max_lines}"
            # Use configurable timeout
            timeout = arguments.get("timeout", 120)
            result = await executor.shell(cmd, device_serial, timeout=timeout)
            
        elif name == "adb_bugreport":
            path = arguments.get("path", "bugreport.zip")
            result = await executor.execute(["bugreport", path], device_serial, timeout=300)
            
        elif name == "adb_jdwp":
            result = await executor.execute(["jdwp"], device_serial)
        
        # System Control
        elif name == "adb_reboot":
            target = arguments.get("target", "system")
            if target == "system":
                result = await executor.execute(["reboot"], device_serial)
            else:
                result = await executor.execute(["reboot", target], device_serial)
                
        elif name == "adb_root":
            result = await executor.execute(["root"], device_serial)
            
        elif name == "adb_unroot":
            result = await executor.execute(["unroot"], device_serial)
            
        elif name == "adb_remount":
            args = ["remount"]
            if arguments.get("auto_reboot", False):
                args.append("-R")
            result = await executor.execute(args, device_serial)
        
        # Security
        elif name == "adb_disable_verity":
            result = await executor.execute(["disable-verity"], device_serial)
            
        elif name == "adb_enable_verity":
            result = await executor.execute(["enable-verity"], device_serial)
        
        # Server Management
        elif name == "adb_start_server":
            result = await executor.execute(["start-server"])
        elif name == "adb_kill_server":
            result = await executor.execute(["kill-server"])
            
        elif name == "adb_version":
            result = await executor.execute(["version"])
        
        else:
            return [TextContent(
                type="text",
                text=f"Unknown tool: {name}"
            )]
        
        # Format response
        if result.success:
            response_text = f"Command executed successfully\n\n"
            if result.stdout:
                response_text += f"Output:\n{result.stdout}"
            if result.stderr:
                response_text += f"\n\nWarnings/Info:\n{result.stderr}"
        else:
            response_text = f"Command failed (exit code: {result.returncode})\n\n"
            if result.stderr:
                response_text += f"Error:\n{result.stderr}"
            if result.stdout:
                response_text += f"\n\nOutput:\n{result.stdout}"
        
        return [TextContent(
            type="text",
            text=response_text
        )]
        
    except Exception as e:
        logger.error(f"Error executing tool {name}: {e}", exc_info=True)
        return [TextContent(
            type="text",
            text=f"Error executing tool: {str(e)}"
        )]


# ============================================================================
# RESOURCE HANDLERS
# ============================================================================

@app.list_resources()
async def list_resources() -> list[Resource]:
    """List available documentation resources"""
    base_path = Path(__file__).parent
    
    return [
        Resource(
            uri=AnyUrl(f"file://{base_path}/README.md"),
            name="ADB MCP Server Documentation",
            mimeType="text/markdown",
            description="Comprehensive documentation for the ADB MCP Server including features, installation, usage, and available tools"
        ),
        Resource(
            uri=AnyUrl(f"file://{base_path}/USAGE_EXAMPLES.md"),
            name="ADB MCP Server Usage Examples",
            mimeType="text/markdown",
            description="Practical examples of using ADB MCP Server tools for device management, app testing, debugging, and more"
        ),
        Resource(
            uri=AnyUrl(f"file://{base_path}/ARCHITECTURE.md"),
            name="ADB MCP Server Architecture",
            mimeType="text/markdown",
            description="Technical architecture documentation covering design patterns, code organization, and extension points"
        ),
        Resource(
            uri=AnyUrl(f"file://{base_path}/ADB_COMMANDS_REFERENCE.md"),
            name="ADB Commands Reference",
            mimeType="text/markdown",
            description="Complete reference guide for all ADB commands including syntax, options, examples, and common use cases"
        ),
    ]


@app.read_resource()
async def read_resource(uri: AnyUrl) -> str:
    """Read a documentation resource"""
    base_path = Path(__file__).parent
    uri_str = str(uri)
    
    # Extract filename from URI
    if uri_str.startswith("file://"):
        file_path = Path(uri_str.replace(f"file://{base_path}/", ""))
    else:
        raise ValueError(f"Unsupported URI scheme: {uri_str}")
    
    # Validate the file is one of our documentation files
    allowed_files = {"README.md", "USAGE_EXAMPLES.md", "ARCHITECTURE.md", "ADB_COMMANDS_REFERENCE.md"}
    if file_path.name not in allowed_files:
        raise ValueError(f"Access denied to file: {file_path.name}")
    
    # Read and return the file content
    full_path = base_path / file_path.name
    try:
        return full_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ValueError(f"Resource not found: {file_path.name}")
    except Exception as e:
        raise ValueError(f"Error reading resource: {str(e)}")


async def main():
    """Main entry point for the server"""
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())
            
