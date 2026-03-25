#!/usr/bin/env python3
"""
Simple HID Descriptor Test for FIDO BLE HID App

This script connects to a BLE device running the FIDO BLE HID app and reads
the HID Report Map descriptor to verify it's being sent correctly.

Usage:
    # RECOMMENDED: Add user to groups (one-time setup, requires logout/login):
    sudo usermod -a -G plugdev,bluetooth,uhid $USER
    # Then logout/login and run without sudo:
    python test_hid_descriptor.py
    
    # ALTERNATIVE: Run with sudo using full python path:
    sudo $(which python) test_hid_descriptor.py
    
    # Specify device name:
    python test_hid_descriptor.py --device-name "OPPO CPH2735"
    
    # For Android emulator:
    python test_hid_descriptor.py --device-name "sdk_gphone64_x86_64" --transport android-netsim

Requirements:
    - bumble (pip install bumble)
    - For real device: USB Bluetooth adapter on host machine
    - For emulator: Android emulator running with the FIDO BLE HID app active

Transport Options:
    - usb:0 - Use first USB Bluetooth adapter (default for real device)
    - usb:1 - Use second USB Bluetooth adapter
    - android-netsim - Use Android emulator's network simulator

Permission Issues (Linux):
    If you get LIBUSB_ERROR_ACCESS [-3]:
    RECOMMENDED: Add user to groups (logout/login required):
      sudo usermod -a -G plugdev,bluetooth,uhid $USER
      Then run: python test_hid_descriptor.py
    
    ALTERNATIVE: Run with sudo using full python path:
      sudo $(which python) test_hid_descriptor.py
"""

import asyncio
import logging
import binascii
import sys
import subprocess
import re

try:
    from bumble.device import Device
    from bumble.transport import open_transport_or_link
    from bumble.hci import Address
    from bumble.pairing import PairingDelegate, PairingConfig
except ImportError:
    print("ERROR: Bumble library not found. Install with: pip install bumble")
    sys.exit(1)


class SimplePairingDelegate(PairingDelegate):
    """Simple pairing delegate that accepts all pairing requests with DISPLAY_YES_NO capability."""
    
    def __init__(self):
        # Initialize with DISPLAY_OUTPUT_AND_YES_NO_INPUT to support MITM
        super().__init__(io_capability=PairingDelegate.DISPLAY_OUTPUT_AND_YES_NO_INPUT)
    
    async def accept(self):
        """Accept pairing request."""
        logger.info("Pairing request - accepting")
        return True
    
    async def confirm(self, auto=True):
        """Confirm pairing (for Just Works with MITM)."""
        logger.info("Pairing confirmation requested - confirming")
        return True
    
    async def compare_numbers(self, number, digits=6):
        """Compare numbers for Numeric Comparison method."""
        logger.info(f"Numeric comparison: {number:0{digits}d} - auto-accepting")
        return True
    
    async def get_number(self):
        """Get passkey from user (for Passkey Entry input)."""
        # For testing, return a default passkey
        logger.info("Passkey entry requested - using default: 000000")
        return 0
    
    async def display_number(self, number, digits=6):
        """Display passkey to user (for Passkey Entry display)."""
        logger.info(f"Display passkey: {number:0{digits}d}")

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,  # Changed to DEBUG to see all advertisements
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('hid_descriptor_test')

# BLE HID Service UUIDs (from HIDService.java)
SERVICE_BLE_HID = '00001812-0000-1000-8000-00805f9b34fb'
CHARACTERISTIC_REPORT_MAP = '00002a4b-0000-1000-8000-00805f9b34fb'

# Expected HID Report Map from HIDPasskey.getReportMap()
EXPECTED_REPORT_MAP = bytes([
    0x06, 0xD0, 0xF1,       # Usage Page (FIDO Alliance)
    0x09, 0x01,             # Usage (U2F HID Authenticator Device)
    0xA1, 0x01,             # Collection (Application)
    0x09, 0x20,             #   Usage (Input Report Data)
    0x15, 0x00,             #   Logical Minimum (0)
    0x26, 0xFF, 0x00,       #   Logical Maximum (255)
    0x75, 0x08,             #   Report Size (8)
    0x95, 0x40,             #   Report Count (64)
    0x81, 0x02,             #   Input (Data, Variable, Absolute)
    0x09, 0x21,             #   Usage (Output Report Data)
    0x15, 0x00,
    0x26, 0xFF, 0x00,
    0x75, 0x08,
    0x95, 0x40,
    0x91, 0x02,             #   Output (Data, Variable, Absolute)
    0xC0                    # End Collection
])


def check_android_logs():
    """Check Android logcat for HID service registration details."""
    try:
        result = subprocess.run(
            ['adb', 'logcat', '-d', '-s', 'HIDService:D'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0 and result.stdout:
            logger.info("Android HIDService logs:")
            for line in result.stdout.strip().split('\n')[-20:]:
                if 'onCharacteristicReadRequest' in line or 'characteristic:' in line:
                    logger.info(f"  {line}")
        
        # Also check for GATT server errors
        result = subprocess.run(
            ['adb', 'logcat', '-d'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            for line in reversed(result.stdout.strip().split('\n')):
                if 'onCharacteristicReadRequest() no char for handle' in line:
                    logger.error(f"Android framework error: {line.strip()}")
                    break
                    
    except Exception as e:
        logger.debug(f"Could not check Android logs: {e}")


async def test_hid_descriptor(device_name=None, transport='usb:0'):
    """
    Test that connects to the BLE HID device and reads the Report Map descriptor.
    
    Args:
        device_name: Name of the BLE device to connect to (None = any HID device)
        transport: Transport specification (default: usb:0 for real device)
                  Options:
                  - usb:0 - First USB Bluetooth adapter (may require sudo on Linux)
                  - usb:1 - Second USB Bluetooth adapter
                  - android-netsim - Android emulator
    
    Returns:
        True if test passed, False otherwise
    """
    logger.info("=" * 60)
    logger.info("HID Descriptor Test Starting")
    logger.info("=" * 60)
    
    device = None
    connection = None
    transport_obj = None
    
    try:
        # Step 1: Open transport
        logger.info(f"[1/6] Opening transport: {transport}")
        transport_obj = await open_transport_or_link(transport)
        
        # Step 2: Create and power on device
        logger.info("[2/6] Creating Bumble device")
        device = Device.with_hci(
            'HID Test Client',
            Address('F0:F1:F2:F3:F4:F5'),
            transport_obj.source,
            transport_obj.sink
        )
        
        # Configure pairing - match what the Android device requests
        # Use delegate with DISPLAY_YES_NO capability to support MITM
        pairing_config = PairingConfig(
            sc=True,  # Use Secure Connections (device requests sc=1)
            mitm=True,  # MITM protection (device requests MITM=1)
            bonding=True,  # Enable bonding (device requests bonding_flags=1)
            delegate=SimplePairingDelegate()  # Delegate with DISPLAY_YES_NO IO capability
        )
        device.pairing_config_factory = lambda connection: pairing_config
        logger.info("✓ Pairing delegate configured (SC=True, MITM=True, Bonding=True, IO=DISPLAY_YES_NO)")
        
        await device.power_on()
        logger.info("✓ Device powered on")
        
        # Step 3: Scan for the target device
        logger.info(f"[3/6] Scanning for device with HID service")
        target_address = None
        
        def on_advertisement(advertisement):
            nonlocal target_address
            
            # Log every advertisement for debugging
            logger.debug(f"Advertisement from {advertisement.address}")
            logger.debug(f"  Data: {advertisement.data if hasattr(advertisement, 'data') else 'No data'}")
            
            # Look for device advertising the HID service UUID
            if hasattr(advertisement, 'data'):
                # Get device name
                adv_name = advertisement.data.get(0x09)  # Complete Local Name
                name_str = ''
                if adv_name:
                    name_str = adv_name if isinstance(adv_name, str) else adv_name.decode('utf-8', errors='ignore')
                    logger.debug(f"  Name: {name_str}")
                
                # Check for HID service UUID in advertisement
                service_uuids = advertisement.data.get_all(0x03)  # Complete List of 16-bit Service UUIDs
                service_uuids.extend(advertisement.data.get_all(0x07))  # Complete List of 128-bit Service UUIDs
                
                if service_uuids:
                    logger.debug(f"  Service UUIDs: {service_uuids}")
                
                # Flatten the list and check each UUID
                for uuid_list in service_uuids:
                    if isinstance(uuid_list, list):
                        for uuid_obj in uuid_list:
                            uuid_str = str(uuid_obj)
                            logger.debug(f"    Checking UUID: {uuid_str}")
                            if SERVICE_BLE_HID.lower() in uuid_str.lower() or '1812' in uuid_str.lower():
                                logger.info(f"Found HID device: '{name_str}' at {advertisement.address}")
                                if not device_name or name_str == device_name:
                                    target_address = advertisement.address
                                    logger.info(f"✓ Found target HID device at address: {target_address}")
                                    return  # Exit the callback
                    else:
                        uuid_str = str(uuid_list)
                        logger.debug(f"    Checking UUID: {uuid_str}")
                        if SERVICE_BLE_HID.lower() in uuid_str.lower() or '1812' in uuid_str.lower():
                            logger.info(f"Found HID device: '{name_str}' at {advertisement.address}")
                            if not device_name or name_str == device_name:
                                target_address = advertisement.address
                                logger.info(f"✓ Found target HID device at address: {target_address}")
                                return  # Exit the callback
        
        device.on('advertisement', on_advertisement)
        await device.start_scanning(filter_duplicates=True)
        
        # Wait up to 10 seconds for device discovery
        for i in range(20):
            if target_address:
                break
            await asyncio.sleep(0.5)
        
        await device.stop_scanning()
        
        if not target_address:
            logger.error(f"✗ Device '{device_name}' not found")
            logger.error("  Make sure the app is running and advertising")
            return False
        
        # Step 4: Connect to device
        logger.info(f"[4/6] Connecting to {device_name}")
        connection = await device.connect(target_address)
        logger.info("✓ Connected successfully")
        
        # Step 4.5: Wait for and handle security request, then pair
        logger.info("Waiting for security request...")
        await asyncio.sleep(1)  # Give time for SMP_SECURITY_REQUEST to arrive
        
        logger.info("Initiating pairing...")
        try:
            # Initiate pairing in response to the security request
            await connection.pair()
            logger.info("✓ Pairing completed successfully")
        except Exception as e:
            logger.error(f"Pairing failed: {e}")
            return False

        # Step 5: Discover services
        logger.info("[5/6] Discovering GATT services")
        
        await connection.gatt_client.discover_services()
        logger.info(f"Discovered {len(connection.gatt_client.services)} services")
        
        # Find HID service
        # HID Service UUID: 0x1812
        hid_service = None
        for service in connection.gatt_client.services:
            service_uuid_str = str(service.uuid).lower()
            logger.debug(f"Checking service: {service_uuid_str}")
            # Look for HID service UUID: 1812
            if '1812' in service_uuid_str:
                hid_service = service
                logger.info(f"✓ Found HID Service: {service.uuid}")
                break
        
        if not hid_service:
            logger.error("✗ HID Service not found")
            return False
        
        # Discover characteristics for the HID service
        logger.info("Discovering characteristics for HID service...")
        # Pass empty tuple to discover all characteristics in the service
        await connection.gatt_client.discover_characteristics(uuids=[], service=hid_service)
        logger.info(f"Found {len(hid_service.characteristics)} characteristics in HID service")
        
        # Find Report Map characteristic
        # Report Map UUID: 0x2A4B
        report_map_char = None
        for characteristic in hid_service.characteristics:
            char_uuid_str = str(characteristic.uuid).lower()
            logger.debug(f"  Characteristic: {char_uuid_str}")
            # Look for Report Map UUID: 2a4b
            if '2a4b' in char_uuid_str:
                report_map_char = characteristic
                logger.info(f"✓ Found Report Map Characteristic: {characteristic.uuid}")
                break
        
        if not report_map_char:
            logger.error("✗ Report Map Characteristic not found")
            logger.info(f"Available characteristics: {[str(c.uuid) for c in hid_service.characteristics]}")
            return False
        
        # Step 6: Read Report Map
        logger.info("[6/6] Reading HID Report Map descriptor")
        logger.info(f"  Attempting to read from characteristic: {report_map_char.uuid}")
        logger.info(f"  Characteristic handle: {report_map_char.handle}")
        
        try:
            report_map_data = await asyncio.wait_for(
                connection.gatt_client.read_value(report_map_char),
                timeout=10.0
            )
        except asyncio.TimeoutError:
            logger.error("✗ Timeout reading Report Map characteristic")
            logger.error("  This suggests the Android GATT server isn't responding to the read request")
            logger.error("  The characteristic is discovered but the read callback may not be triggered")
            logger.info("")
            logger.info("Checking Android logs for more details...")
            check_android_logs()
            return False
        except Exception as e:
            logger.error(f"✗ Error reading Report Map: {e}")
            return False
        
        logger.info(f"✓ Report Map read successfully ({len(report_map_data)} bytes)")
        logger.info(f"  Raw data: {binascii.hexlify(report_map_data).decode()}")
        
        # Verify the descriptor matches expected value
        logger.info("")
        logger.info("Verifying Report Map content...")
        
        if report_map_data == EXPECTED_REPORT_MAP:
            logger.info("✓ SUCCESS: Report Map matches expected FIDO CTAP HID descriptor!")
            logger.info("")
            logger.info("Report Map Details:")
            logger.info("  - Usage Page: 0xF1D0 (FIDO Alliance)")
            logger.info("  - Usage: 0x01 (U2F HID Authenticator Device)")
            logger.info("  - Input Report: 64 bytes")
            logger.info("  - Output Report: 64 bytes")
            return True
        else:
            logger.error("✗ FAILED: Report Map does not match expected descriptor")
            logger.error(f"  Expected ({len(EXPECTED_REPORT_MAP)} bytes): {binascii.hexlify(EXPECTED_REPORT_MAP).decode()}")
            logger.error(f"  Received ({len(report_map_data)} bytes): {binascii.hexlify(report_map_data).decode()}")
            
            # Show differences
            if len(report_map_data) == len(EXPECTED_REPORT_MAP):
                logger.error("  Byte differences:")
                for i, (expected, actual) in enumerate(zip(EXPECTED_REPORT_MAP, report_map_data)):
                    if expected != actual:
                        logger.error(f"    Byte {i}: expected 0x{expected:02x}, got 0x{actual:02x}")
            return False
            
    except Exception as e:
        logger.error(f"✗ Test failed with exception: {e}", exc_info=True)
        return False
    
    finally:
        # Cleanup
        if connection:
            try:
                await connection.disconnect()
                logger.info("Disconnected from device")
            except:
                pass
        
        if device:
            try:
                await device.power_off()
                logger.info("Device powered off")
            except:
                pass
        
        if transport_obj:
            try:
                await transport_obj.close()
            except:
                pass


async def main():
    """Main entry point for the test."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Test HID Report Map descriptor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # RECOMMENDED: Add user to groups (one-time, requires logout/login):
  sudo usermod -a -G plugdev,bluetooth,uhid $USER
  # Then run without sudo:
  python test_hid_descriptor.py
  
  # ALTERNATIVE: Run with sudo using full python path:
  sudo $(which python) test_hid_descriptor.py
  
  # Test with specific device name:
  python test_hid_descriptor.py --device-name "OPPO CPH2735"
  
  # Test with Android emulator (no sudo needed):
  python test_hid_descriptor.py --device-name "sdk_gphone64_x86_64" --transport android-netsim
  
  # Use second USB Bluetooth adapter:
  python test_hid_descriptor.py --transport usb:1

Permission Issues (Linux):
  If you get LIBUSB_ERROR_ACCESS [-3]:
  RECOMMENDED: Add user to groups (logout/login required):
    sudo usermod -a -G plugdev,bluetooth,uhid $USER
  ALTERNATIVE: Run with sudo using full python path:
    sudo $(which python) test_hid_descriptor.py
        """
    )
    parser.add_argument('--device-name', default=None,
                       help='Name of the BLE device (default: None = any device with HID service)')
    parser.add_argument('--transport', default='usb:0',
                       help='Transport specification (default: usb:0 for real device, use android-netsim for emulator)')
    args = parser.parse_args()
    
    success = await test_hid_descriptor(args.device_name, args.transport)
    
    logger.info("")
    logger.info("=" * 60)
    if success:
        logger.info("TEST RESULT: PASSED ✓")
        logger.info("The HID descriptor is being sent correctly!")
    else:
        logger.info("TEST RESULT: FAILED ✗")
        logger.info("The HID descriptor was not sent correctly.")
    logger.info("=" * 60)
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    asyncio.run(main())

# Made with Bob
