/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.mdl;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Unit tests for {@link DeviceSigned}.
 */
class DeviceSignedTest {
    
    @Test
    void testConstructor_ValidParameters() {
        Map<String, List<DeviceSignedItem>> nameSpaces = new HashMap<>();
        List<DeviceSignedItem> items = new ArrayList<>();
        items.add(new DeviceSignedItem("family_name", "Smith"));
        nameSpaces.put(NameSpace.ISO_18013_5_1, items);
        
        byte[] deviceAuth = new byte[]{1, 2, 3, 4};
        
        DeviceSigned deviceSigned = new DeviceSigned(nameSpaces, deviceAuth);
        
        assertNotNull(deviceSigned);
        assertEquals(1, deviceSigned.getNameSpaces().size());
        assertArrayEquals(deviceAuth, deviceSigned.getDeviceAuth());
    }
    
    @Test
    void testConstructor_NullNameSpaces() {
        byte[] deviceAuth = new byte[]{1, 2, 3, 4};
        
        assertThrows(IllegalArgumentException.class, () -> {
            new DeviceSigned(null, deviceAuth);
        });
    }
    
    @Test
    void testConstructor_NullDeviceAuth() {
        Map<String, List<DeviceSignedItem>> nameSpaces = new HashMap<>();
        
        assertThrows(IllegalArgumentException.class, () -> {
            new DeviceSigned(nameSpaces, null);
        });
    }
    
    @Test
    void testConstructor_EmptyDeviceAuth() {
        Map<String, List<DeviceSignedItem>> nameSpaces = new HashMap<>();
        
        assertThrows(IllegalArgumentException.class, () -> {
            new DeviceSigned(nameSpaces, new byte[0]);
        });
    }
    
    @Test
    void testConstructor_EmptyNameSpaces() {
        Map<String, List<DeviceSignedItem>> nameSpaces = new HashMap<>();
        byte[] deviceAuth = new byte[]{1, 2, 3, 4};
        
        DeviceSigned deviceSigned = new DeviceSigned(nameSpaces, deviceAuth);
        
        assertNotNull(deviceSigned);
        assertTrue(deviceSigned.getNameSpaces().isEmpty());
    }
    
    @Test
    void testGetNameSpaces_ReturnsUnmodifiableCopy() {
        Map<String, List<DeviceSignedItem>> nameSpaces = new HashMap<>();
        List<DeviceSignedItem> items = new ArrayList<>();
        items.add(new DeviceSignedItem("family_name", "Smith"));
        nameSpaces.put(NameSpace.ISO_18013_5_1, items);
        
        byte[] deviceAuth = new byte[]{1, 2, 3, 4};
        DeviceSigned deviceSigned = new DeviceSigned(nameSpaces, deviceAuth);
        
        Map<String, List<DeviceSignedItem>> retrieved = deviceSigned.getNameSpaces();
        
        // Verify we can't modify the returned map
        assertThrows(UnsupportedOperationException.class, () -> {
            retrieved.put("test", new ArrayList<>());
        });
        
        // Verify we can't modify the lists in the map
        assertThrows(UnsupportedOperationException.class, () -> {
            retrieved.get(NameSpace.ISO_18013_5_1).add(new DeviceSignedItem("test", "value"));
        });
    }
    
    @Test
    void testGetDeviceAuth_ReturnsCopy() {
        Map<String, List<DeviceSignedItem>> nameSpaces = new HashMap<>();
        byte[] deviceAuth = new byte[]{1, 2, 3, 4};
        
        DeviceSigned deviceSigned = new DeviceSigned(nameSpaces, deviceAuth);
        
        byte[] retrieved = deviceSigned.getDeviceAuth();
        retrieved[0] = 99; // Modify the copy
        
        // Original should be unchanged
        assertArrayEquals(new byte[]{1, 2, 3, 4}, deviceSigned.getDeviceAuth());
    }
    
    @Test
    void testToCbor_EmptyNameSpaces() {
        Map<String, List<DeviceSignedItem>> nameSpaces = new HashMap<>();
        byte[] deviceAuth = new byte[]{1, 2, 3, 4};
        
        DeviceSigned deviceSigned = new DeviceSigned(nameSpaces, deviceAuth);
        byte[] cbor = deviceSigned.toCbor();
        
        assertNotNull(cbor);
        assertTrue(cbor.length > 0);
    }
    
    @Test
    void testToCbor_WithNameSpaces() {
        Map<String, List<DeviceSignedItem>> nameSpaces = new HashMap<>();
        List<DeviceSignedItem> items = new ArrayList<>();
        items.add(new DeviceSignedItem("family_name", "Smith"));
        items.add(new DeviceSignedItem("given_name", "John"));
        nameSpaces.put(NameSpace.ISO_18013_5_1, items);
        
        byte[] deviceAuth = new byte[]{1, 2, 3, 4};
        
        DeviceSigned deviceSigned = new DeviceSigned(nameSpaces, deviceAuth);
        byte[] cbor = deviceSigned.toCbor();
        
        assertNotNull(cbor);
        assertTrue(cbor.length > 0);
    }
    
    @Test
    void testFromCbor_EmptyNameSpaces() throws MdlException {
        Map<String, List<DeviceSignedItem>> nameSpaces = new HashMap<>();
        byte[] deviceAuth = new byte[]{1, 2, 3, 4};
        
        DeviceSigned original = new DeviceSigned(nameSpaces, deviceAuth);
        byte[] cbor = original.toCbor();
        
        DeviceSigned decoded = DeviceSigned.fromCbor(cbor);
        
        assertNotNull(decoded);
        assertTrue(decoded.getNameSpaces().isEmpty());
        assertArrayEquals(deviceAuth, decoded.getDeviceAuth());
    }
    
    @Test
    void testFromCbor_WithNameSpaces() throws MdlException {
        Map<String, List<DeviceSignedItem>> nameSpaces = new HashMap<>();
        List<DeviceSignedItem> items = new ArrayList<>();
        items.add(new DeviceSignedItem("family_name", "Smith"));
        items.add(new DeviceSignedItem("given_name", "John"));
        nameSpaces.put(NameSpace.ISO_18013_5_1, items);
        
        byte[] deviceAuth = new byte[]{1, 2, 3, 4};
        
        DeviceSigned original = new DeviceSigned(nameSpaces, deviceAuth);
        byte[] cbor = original.toCbor();
        
        DeviceSigned decoded = DeviceSigned.fromCbor(cbor);
        
        assertNotNull(decoded);
        assertEquals(1, decoded.getNameSpaces().size());
        assertTrue(decoded.getNameSpaces().containsKey(NameSpace.ISO_18013_5_1));
        assertEquals(2, decoded.getNameSpaces().get(NameSpace.ISO_18013_5_1).size());
        assertArrayEquals(deviceAuth, decoded.getDeviceAuth());
    }
    
    @Test
    void testFromCbor_MultipleNameSpaces() throws MdlException {
        Map<String, List<DeviceSignedItem>> nameSpaces = new HashMap<>();
        
        List<DeviceSignedItem> isoItems = new ArrayList<>();
        isoItems.add(new DeviceSignedItem("family_name", "Smith"));
        nameSpaces.put(NameSpace.ISO_18013_5_1, isoItems);
        
        List<DeviceSignedItem> aamvaItems = new ArrayList<>();
        aamvaItems.add(new DeviceSignedItem("organ_donor", true));
        nameSpaces.put(NameSpace.ISO_18013_5_1_AAMVA, aamvaItems);
        
        byte[] deviceAuth = new byte[]{1, 2, 3, 4};
        
        DeviceSigned original = new DeviceSigned(nameSpaces, deviceAuth);
        byte[] cbor = original.toCbor();
        
        DeviceSigned decoded = DeviceSigned.fromCbor(cbor);
        
        assertNotNull(decoded);
        assertEquals(2, decoded.getNameSpaces().size());
        assertTrue(decoded.getNameSpaces().containsKey(NameSpace.ISO_18013_5_1));
        assertTrue(decoded.getNameSpaces().containsKey(NameSpace.ISO_18013_5_1_AAMVA));
    }
    
    @Test
    void testFromCbor_InvalidData() {
        byte[] invalidCbor = new byte[]{0x01, 0x02, 0x03};
        
        assertThrows(MdlException.class, () -> {
            DeviceSigned.fromCbor(invalidCbor);
        });
    }
    
    @Test
    void testEquals_SameObject() {
        Map<String, List<DeviceSignedItem>> nameSpaces = new HashMap<>();
        byte[] deviceAuth = new byte[]{1, 2, 3, 4};
        
        DeviceSigned deviceSigned = new DeviceSigned(nameSpaces, deviceAuth);
        
        assertEquals(deviceSigned, deviceSigned);
    }
    
    @Test
    void testEquals_EqualObjects() {
        Map<String, List<DeviceSignedItem>> nameSpaces1 = new HashMap<>();
        List<DeviceSignedItem> items1 = new ArrayList<>();
        items1.add(new DeviceSignedItem("family_name", "Smith"));
        nameSpaces1.put(NameSpace.ISO_18013_5_1, items1);
        byte[] deviceAuth1 = new byte[]{1, 2, 3, 4};
        
        Map<String, List<DeviceSignedItem>> nameSpaces2 = new HashMap<>();
        List<DeviceSignedItem> items2 = new ArrayList<>();
        items2.add(new DeviceSignedItem("family_name", "Smith"));
        nameSpaces2.put(NameSpace.ISO_18013_5_1, items2);
        byte[] deviceAuth2 = new byte[]{1, 2, 3, 4};
        
        DeviceSigned deviceSigned1 = new DeviceSigned(nameSpaces1, deviceAuth1);
        DeviceSigned deviceSigned2 = new DeviceSigned(nameSpaces2, deviceAuth2);
        
        assertEquals(deviceSigned1, deviceSigned2);
        assertEquals(deviceSigned1.hashCode(), deviceSigned2.hashCode());
    }
    
    @Test
    void testEquals_DifferentDeviceAuth() {
        Map<String, List<DeviceSignedItem>> nameSpaces = new HashMap<>();
        
        DeviceSigned deviceSigned1 = new DeviceSigned(nameSpaces, new byte[]{1, 2, 3, 4});
        DeviceSigned deviceSigned2 = new DeviceSigned(nameSpaces, new byte[]{5, 6, 7, 8});
        
        assertNotEquals(deviceSigned1, deviceSigned2);
    }
    
    @Test
    void testEquals_DifferentNameSpaces() {
        Map<String, List<DeviceSignedItem>> nameSpaces1 = new HashMap<>();
        List<DeviceSignedItem> items1 = new ArrayList<>();
        items1.add(new DeviceSignedItem("family_name", "Smith"));
        nameSpaces1.put(NameSpace.ISO_18013_5_1, items1);
        
        Map<String, List<DeviceSignedItem>> nameSpaces2 = new HashMap<>();
        List<DeviceSignedItem> items2 = new ArrayList<>();
        items2.add(new DeviceSignedItem("given_name", "John"));
        nameSpaces2.put(NameSpace.ISO_18013_5_1, items2);
        
        byte[] deviceAuth = new byte[]{1, 2, 3, 4};
        
        DeviceSigned deviceSigned1 = new DeviceSigned(nameSpaces1, deviceAuth);
        DeviceSigned deviceSigned2 = new DeviceSigned(nameSpaces2, deviceAuth);
        
        assertNotEquals(deviceSigned1, deviceSigned2);
    }
    
    @Test
    void testEquals_Null() {
        Map<String, List<DeviceSignedItem>> nameSpaces = new HashMap<>();
        byte[] deviceAuth = new byte[]{1, 2, 3, 4};
        
        DeviceSigned deviceSigned = new DeviceSigned(nameSpaces, deviceAuth);
        
        assertNotEquals(deviceSigned, null);
    }
    
    @Test
    void testEquals_DifferentClass() {
        Map<String, List<DeviceSignedItem>> nameSpaces = new HashMap<>();
        byte[] deviceAuth = new byte[]{1, 2, 3, 4};
        
        DeviceSigned deviceSigned = new DeviceSigned(nameSpaces, deviceAuth);
        
        assertNotEquals(deviceSigned, "not a DeviceSigned");
    }
    
    @Test
    void testToString() {
        Map<String, List<DeviceSignedItem>> nameSpaces = new HashMap<>();
        List<DeviceSignedItem> items = new ArrayList<>();
        items.add(new DeviceSignedItem("family_name", "Smith"));
        nameSpaces.put(NameSpace.ISO_18013_5_1, items);
        
        byte[] deviceAuth = new byte[]{1, 2, 3, 4};
        
        DeviceSigned deviceSigned = new DeviceSigned(nameSpaces, deviceAuth);
        String str = deviceSigned.toString();
        
        assertNotNull(str);
        assertTrue(str.contains("DeviceSigned"));
        assertTrue(str.contains("nameSpaces=1"));
        assertTrue(str.contains("deviceAuthLength=4"));
    }
    
    @Test
    void testRoundTrip_ComplexStructure() throws MdlException {
        Map<String, List<DeviceSignedItem>> nameSpaces = new HashMap<>();
        
        // ISO namespace
        List<DeviceSignedItem> isoItems = new ArrayList<>();
        isoItems.add(new DeviceSignedItem("family_name", "Smith"));
        isoItems.add(new DeviceSignedItem("given_name", "John"));
        isoItems.add(new DeviceSignedItem("birth_date", "1990-01-01"));
        nameSpaces.put(NameSpace.ISO_18013_5_1, isoItems);
        
        // AAMVA namespace
        List<DeviceSignedItem> aamvaItems = new ArrayList<>();
        aamvaItems.add(new DeviceSignedItem("organ_donor", true));
        aamvaItems.add(new DeviceSignedItem("veteran", false));
        nameSpaces.put(NameSpace.ISO_18013_5_1_AAMVA, aamvaItems);
        
        byte[] deviceAuth = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        
        DeviceSigned original = new DeviceSigned(nameSpaces, deviceAuth);
        byte[] cbor = original.toCbor();
        DeviceSigned decoded = DeviceSigned.fromCbor(cbor);
        
        assertEquals(original, decoded);
    }
}

// Made with Bob
