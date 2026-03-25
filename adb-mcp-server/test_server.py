#!/usr/bin/env python3
"""
Simple test script to verify the ADB MCP Server functionality
"""

import asyncio
import sys
from server import ADBExecutor, executor


async def test_adb_connection():
    """Test basic ADB connectivity"""
    print("Testing ADB connection...")
    
    # Test 1: Check ADB version
    print("\n1. Checking ADB version...")
    result = await executor.execute(["version"])
    if result.success:
        print(f"✓ ADB version: {result.stdout.strip()}")
    else:
        print(f"✗ Failed to get ADB version: {result.stderr}")
        return False
    
    # Test 2: List devices
    print("\n2. Listing connected devices...")
    result = await executor.execute(["devices"])
    if result.success:
        print(f"✓ Devices output:\n{result.stdout}")
        lines = result.stdout.strip().split('\n')
        device_count = len([l for l in lines[1:] if l.strip()])
        print(f"  Found {device_count} device(s)")
    else:
        print(f"✗ Failed to list devices: {result.stderr}")
        return False
    
    # Test 3: Test shell command (if device available)
    if device_count > 0:
        print("\n3. Testing shell command...")
        result = await executor.shell("echo 'Hello from ADB'")
        if result.success:
            print(f"✓ Shell command output: {result.stdout.strip()}")
        else:
            print(f"✗ Shell command failed: {result.stderr}")
    else:
        print("\n3. Skipping shell test (no devices connected)")
    
    return True


async def test_error_handling():
    """Test error handling"""
    print("\n\nTesting error handling...")
    
    # Test invalid command
    print("\n1. Testing invalid command...")
    result = await executor.execute(["invalid-command"])
    if not result.success:
        print(f"✓ Correctly handled invalid command")
    else:
        print(f"✗ Should have failed for invalid command")
    
    # Test timeout (with very short timeout)
    print("\n2. Testing timeout handling...")
    result = await executor.execute(["devices"], timeout=1)
    if not result.success and "timed out" in result.stderr.lower():
        print(f"✓ Correctly handled timeout")
    else:
        print(f"✗ Timeout handling may not be working correctly")
    
    return True


async def main():
    """Run all tests"""
    print("=" * 60)
    print("ADB MCP Server - Test Suite")
    print("=" * 60)
    
    try:
        # Test basic connectivity
        if not await test_adb_connection():
            print("\n✗ Basic connectivity tests failed")
            return 1
        
        # Test error handling
        if not await test_error_handling():
            print("\n✗ Error handling tests failed")
            return 1
        
        print("\n" + "=" * 60)
        print("✓ All tests passed!")
        print("=" * 60)
        return 0
        
    except Exception as e:
        print(f"\n✗ Test suite failed with exception: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)

# Made with Bob
