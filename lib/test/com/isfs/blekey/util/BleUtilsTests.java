/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.util;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.UUID;

import org.junit.Test;

public class BleUtilsTests {
    
    @Test
    public void testShortUUID() {
        // Test with a characteristic UUID (which is a full UUID with base UUID format)
        UUID fullUuid = BleUtils.getCharateristicUuid(0x180A);
        assertFalse("Full UUID should not be detected as short UUID", BleUtils.isShortUuid(fullUuid));
        
        // Create a true short UUID (16-bit UUID)
        UUID shortUuid = new UUID(0x0000180A00000000L, 0L);
        assertTrue("Short UUID should be detected correctly", BleUtils.isShortUuid(shortUuid));
        
        // Test matching between short and full UUIDs
        UUID fullDeviceInfoUuid = UUID.fromString("0000180A-0000-1000-8000-00805F9B34FB");
        UUID shortDeviceInfoUuid = new UUID(0x0000180A00000000L, 0L);
        assertTrue("Short and full UUIDs with same service ID should match",
                  BleUtils.matches(shortDeviceInfoUuid, fullDeviceInfoUuid));
        UUID differentShort = new UUID(0x0000180B00000000L, 0L);
        assertFalse("Short and full UUIDs with different service ID should not match",
                  BleUtils.matches(fullDeviceInfoUuid, differentShort));
    }

    @Test
    public void testUUIDMatches() {
        UUID u1 = UUID.fromString("0000180a-0000-1000-8000-00805f9b34fb");
        UUID u2 = UUID.fromString("0000180a-0000-1000-8000-00805f9b34fb");
        UUID u3 = UUID.fromString("0000180b-0000-1000-8000-00805f9b34fb");

        assertTrue(BleUtils.matches(u1, u2));
        assertFalse(BleUtils.matches(u2, u3));
    }


    @Test
    public void testGetCharacteristic() {
        assertNotNull(BleUtils.getCharateristicUuid(0x180A));
        assertNotNull(BleUtils.getCharateristicUuid(0x2A29));
        assertNotNull(BleUtils.getCharateristicUuid(0x2A24));
        assertNotNull(BleUtils.getCharateristicUuid(0x2A25));
    }
}
