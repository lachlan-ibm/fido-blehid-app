/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.mdl;

import org.junit.Test;
import static org.junit.Assert.*;

import java.util.List;
import java.util.Map;

/**
 * Unit tests for MobileDocument.
 */
public class MobileDocumentTest {
    
    @Test
    public void testConstructorWithValidDocType() {
        MobileDocument doc = new MobileDocument(MobileDocument.DOCTYPE_MDL);
        assertEquals(MobileDocument.DOCTYPE_MDL, doc.getDocType());
        assertTrue(doc.isMdl());
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testConstructorWithNullDocType() {
        new MobileDocument(null);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testConstructorWithEmptyDocType() {
        new MobileDocument("");
    }
    
    @Test
    public void testIsMdl() {
        MobileDocument mdl = new MobileDocument(MobileDocument.DOCTYPE_MDL);
        assertTrue(mdl.isMdl());
        
        MobileDocument custom = new MobileDocument("com.example.custom");
        assertFalse(custom.isMdl());
    }
    
    @Test
    public void testAddIssuerSignedItem() {
        MobileDocument doc = new MobileDocument(MobileDocument.DOCTYPE_MDL);
        byte[] random = new byte[]{0x01, 0x02, 0x03, 0x04};
        IssuerSignedItem item = new IssuerSignedItem(0, random, "family_name", "Doe");
        
        doc.addIssuerSignedItem(NameSpace.ISO_18013_5_1, item);
        
        Map<String, List<IssuerSignedItem>> items = doc.getIssuerSignedItems();
        assertEquals(1, items.size());
        assertTrue(items.containsKey(NameSpace.ISO_18013_5_1));
        assertEquals(1, items.get(NameSpace.ISO_18013_5_1).size());
        assertEquals(item, items.get(NameSpace.ISO_18013_5_1).get(0));
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testAddIssuerSignedItemWithNullNamespace() {
        MobileDocument doc = new MobileDocument(MobileDocument.DOCTYPE_MDL);
        byte[] random = new byte[]{0x01, 0x02, 0x03, 0x04};
        IssuerSignedItem item = new IssuerSignedItem(0, random, "family_name", "Doe");
        
        doc.addIssuerSignedItem(null, item);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testAddIssuerSignedItemWithNullItem() {
        MobileDocument doc = new MobileDocument(MobileDocument.DOCTYPE_MDL);
        doc.addIssuerSignedItem(NameSpace.ISO_18013_5_1, null);
    }
    
    @Test
    public void testAddMultipleIssuerSignedItemsToSameNamespace() {
        MobileDocument doc = new MobileDocument(MobileDocument.DOCTYPE_MDL);
        byte[] random1 = new byte[]{0x01, 0x02, 0x03, 0x04};
        byte[] random2 = new byte[]{0x05, 0x06, 0x07, 0x08};
        
        IssuerSignedItem item1 = new IssuerSignedItem(0, random1, "family_name", "Doe");
        IssuerSignedItem item2 = new IssuerSignedItem(1, random2, "given_name", "John");
        
        doc.addIssuerSignedItem(NameSpace.ISO_18013_5_1, item1);
        doc.addIssuerSignedItem(NameSpace.ISO_18013_5_1, item2);
        
        Map<String, List<IssuerSignedItem>> items = doc.getIssuerSignedItems();
        assertEquals(1, items.size());
        assertEquals(2, items.get(NameSpace.ISO_18013_5_1).size());
    }
    
    @Test
    public void testAddDeviceSignedItem() {
        MobileDocument doc = new MobileDocument(MobileDocument.DOCTYPE_MDL);
        DeviceSignedItem item = new DeviceSignedItem("age_over_18", true);
        
        doc.addDeviceSignedItem(NameSpace.ISO_18013_5_1, item);
        
        Map<String, List<DeviceSignedItem>> items = doc.getDeviceSignedItems();
        assertEquals(1, items.size());
        assertTrue(items.containsKey(NameSpace.ISO_18013_5_1));
        assertEquals(1, items.get(NameSpace.ISO_18013_5_1).size());
        assertEquals(item, items.get(NameSpace.ISO_18013_5_1).get(0));
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testAddDeviceSignedItemWithNullNamespace() {
        MobileDocument doc = new MobileDocument(MobileDocument.DOCTYPE_MDL);
        DeviceSignedItem item = new DeviceSignedItem("age_over_18", true);
        
        doc.addDeviceSignedItem(null, item);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testAddDeviceSignedItemWithNullItem() {
        MobileDocument doc = new MobileDocument(MobileDocument.DOCTYPE_MDL);
        doc.addDeviceSignedItem(NameSpace.ISO_18013_5_1, null);
    }
    
    @Test
    public void testAddError() {
        MobileDocument doc = new MobileDocument(MobileDocument.DOCTYPE_MDL);
        doc.addError(NameSpace.ISO_18013_5_1, "Error message");
        
        Map<String, Object> errors = doc.getErrors();
        assertEquals(1, errors.size());
        assertEquals("Error message", errors.get(NameSpace.ISO_18013_5_1));
    }
    
    @Test
    public void testGetIssuerSignedItemsReturnsUnmodifiableMap() {
        MobileDocument doc = new MobileDocument(MobileDocument.DOCTYPE_MDL);
        byte[] random = new byte[]{0x01, 0x02, 0x03, 0x04};
        IssuerSignedItem item = new IssuerSignedItem(0, random, "family_name", "Doe");
        doc.addIssuerSignedItem(NameSpace.ISO_18013_5_1, item);
        
        Map<String, List<IssuerSignedItem>> items = doc.getIssuerSignedItems();
        
        try {
            items.put("new_namespace", null);
            fail("Should throw UnsupportedOperationException");
        } catch (UnsupportedOperationException e) {
            // Expected
        }
    }
    
    @Test
    public void testToCborAndFromCbor() throws MdlException {
        MobileDocument original = new MobileDocument(MobileDocument.DOCTYPE_MDL);
        
        byte[] random1 = new byte[]{0x01, 0x02, 0x03, 0x04};
        byte[] random2 = new byte[]{0x05, 0x06, 0x07, 0x08};
        
        IssuerSignedItem item1 = new IssuerSignedItem(0, random1, "family_name", "Doe");
        IssuerSignedItem item2 = new IssuerSignedItem(1, random2, "given_name", "John");
        
        original.addIssuerSignedItem(NameSpace.ISO_18013_5_1, item1);
        original.addIssuerSignedItem(NameSpace.ISO_18013_5_1, item2);
        
        DeviceSignedItem deviceItem = new DeviceSignedItem("age_over_18", true);
        original.addDeviceSignedItem(NameSpace.ISO_18013_5_1, deviceItem);
        
        byte[] cbor = original.toCbor();
        MobileDocument decoded = MobileDocument.fromCbor(cbor);
        
        assertEquals(original.getDocType(), decoded.getDocType());
        assertEquals(original.getIssuerSignedItems().size(), decoded.getIssuerSignedItems().size());
        assertEquals(original.getDeviceSignedItems().size(), decoded.getDeviceSignedItems().size());
    }
    
    @Test
    public void testToCborWithoutDeviceSignedItems() throws MdlException {
        MobileDocument original = new MobileDocument(MobileDocument.DOCTYPE_MDL);
        
        byte[] random = new byte[]{0x01, 0x02, 0x03, 0x04};
        IssuerSignedItem item = new IssuerSignedItem(0, random, "family_name", "Doe");
        original.addIssuerSignedItem(NameSpace.ISO_18013_5_1, item);
        
        byte[] cbor = original.toCbor();
        MobileDocument decoded = MobileDocument.fromCbor(cbor);
        
        assertEquals(original.getDocType(), decoded.getDocType());
        assertEquals(1, decoded.getIssuerSignedItems().size());
        assertEquals(0, decoded.getDeviceSignedItems().size());
    }
    
    @Test(expected = MdlException.class)
    public void testFromCborWithInvalidData() throws MdlException {
        byte[] invalidCbor = new byte[]{0x01, 0x02, 0x03};
        MobileDocument.fromCbor(invalidCbor);
    }
    
    @Test
    public void testEquals() {
        MobileDocument doc1 = new MobileDocument(MobileDocument.DOCTYPE_MDL);
        MobileDocument doc2 = new MobileDocument(MobileDocument.DOCTYPE_MDL);
        MobileDocument doc3 = new MobileDocument("com.example.custom");
        
        assertEquals(doc1, doc2);
        assertNotEquals(doc1, doc3);
        assertNotEquals(doc1, null);
        assertNotEquals(doc1, "not a MobileDocument");
    }
    
    @Test
    public void testHashCode() {
        MobileDocument doc1 = new MobileDocument(MobileDocument.DOCTYPE_MDL);
        MobileDocument doc2 = new MobileDocument(MobileDocument.DOCTYPE_MDL);
        
        assertEquals(doc1.hashCode(), doc2.hashCode());
    }
    
    @Test
    public void testToString() {
        MobileDocument doc = new MobileDocument(MobileDocument.DOCTYPE_MDL);
        
        String str = doc.toString();
        assertTrue(str.contains("MobileDocument"));
        assertTrue(str.contains(MobileDocument.DOCTYPE_MDL));
    }
    
    @Test
    public void testDocTypeConstant() {
        assertEquals("org.iso.18013.5.1.mDL", MobileDocument.DOCTYPE_MDL);
    }
}

// Made with Bob
