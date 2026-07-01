/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.mdl;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Unit tests for DeviceSignedItem.
 */
public class DeviceSignedItemTest {
    
    @Test
    public void testConstructorWithValidParameters() {
        DeviceSignedItem item = new DeviceSignedItem("age_over_18", true);
        
        assertEquals("age_over_18", item.getElementIdentifier());
        assertEquals(true, item.getElementValue());
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testConstructorWithNullElementIdentifier() {
        new DeviceSignedItem(null, true);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testConstructorWithEmptyElementIdentifier() {
        new DeviceSignedItem("", true);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testConstructorWithWhitespaceElementIdentifier() {
        new DeviceSignedItem("   ", true);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testConstructorWithNullElementValue() {
        new DeviceSignedItem("age_over_18", null);
    }
    
    @Test
    public void testToCborAndFromCbor() throws MdlException {
        DeviceSignedItem original = new DeviceSignedItem("age_over_18", true);
        
        byte[] cbor = original.toCbor();
        DeviceSignedItem decoded = DeviceSignedItem.fromCbor(cbor);
        
        assertEquals(original, decoded);
    }
    
    @Test
    public void testToCborWithStringValue() throws MdlException {
        DeviceSignedItem original = new DeviceSignedItem("custom_field", "custom_value");
        
        byte[] cbor = original.toCbor();
        DeviceSignedItem decoded = DeviceSignedItem.fromCbor(cbor);
        
        assertEquals(original, decoded);
    }
    
    @Test
    public void testToCborWithIntegerValue() throws MdlException {
        DeviceSignedItem original = new DeviceSignedItem("counter", 42);
        
        byte[] cbor = original.toCbor();
        DeviceSignedItem decoded = DeviceSignedItem.fromCbor(cbor);
        
        assertEquals(original, decoded);
    }
    
    @Test(expected = MdlException.class)
    public void testFromCborWithInvalidData() throws MdlException {
        byte[] invalidCbor = new byte[]{0x01, 0x02, 0x03};
        DeviceSignedItem.fromCbor(invalidCbor);
    }
    
    @Test
    public void testEquals() {
        DeviceSignedItem item1 = new DeviceSignedItem("age_over_18", true);
        DeviceSignedItem item2 = new DeviceSignedItem("age_over_18", true);
        DeviceSignedItem item3 = new DeviceSignedItem("age_over_21", true);
        DeviceSignedItem item4 = new DeviceSignedItem("age_over_18", false);
        
        assertEquals(item1, item2);
        assertNotEquals(item1, item3);
        assertNotEquals(item1, item4);
        assertNotEquals(item1, null);
        assertNotEquals(item1, "not a DeviceSignedItem");
    }
    
    @Test
    public void testHashCode() {
        DeviceSignedItem item1 = new DeviceSignedItem("age_over_18", true);
        DeviceSignedItem item2 = new DeviceSignedItem("age_over_18", true);
        
        assertEquals(item1.hashCode(), item2.hashCode());
    }
    
    @Test
    public void testToString() {
        DeviceSignedItem item = new DeviceSignedItem("age_over_18", true);
        
        String str = item.toString();
        assertTrue(str.contains("DeviceSignedItem"));
        assertTrue(str.contains("age_over_18"));
        assertTrue(str.contains("true"));
    }
}

// Made with Bob
