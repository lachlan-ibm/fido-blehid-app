/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.mdl;

import org.junit.Test;
import static org.junit.Assert.*;

import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Unit tests for IssuerSignedItem.
 */
public class IssuerSignedItemTest {
    
    @Test
    public void testConstructorWithValidParameters() {
        byte[] random = new byte[]{0x01, 0x02, 0x03, 0x04};
        IssuerSignedItem item = new IssuerSignedItem(0, random, "family_name", "Doe");
        
        assertEquals(0, item.getDigestId());
        assertArrayEquals(random, item.getRandom());
        assertEquals("family_name", item.getElementIdentifier());
        assertEquals("Doe", item.getElementValue());
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testConstructorWithNegativeDigestId() {
        byte[] random = new byte[]{0x01, 0x02, 0x03, 0x04};
        new IssuerSignedItem(-1, random, "family_name", "Doe");
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testConstructorWithNullRandom() {
        new IssuerSignedItem(0, null, "family_name", "Doe");
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testConstructorWithEmptyRandom() {
        new IssuerSignedItem(0, new byte[0], "family_name", "Doe");
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testConstructorWithNullElementIdentifier() {
        byte[] random = new byte[]{0x01, 0x02, 0x03, 0x04};
        new IssuerSignedItem(0, random, null, "Doe");
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testConstructorWithEmptyElementIdentifier() {
        byte[] random = new byte[]{0x01, 0x02, 0x03, 0x04};
        new IssuerSignedItem(0, random, "", "Doe");
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testConstructorWithNullElementValue() {
        byte[] random = new byte[]{0x01, 0x02, 0x03, 0x04};
        new IssuerSignedItem(0, random, "family_name", null);
    }
    
    @Test
    public void testGetRandomReturnsCopy() {
        byte[] random = new byte[]{0x01, 0x02, 0x03, 0x04};
        IssuerSignedItem item = new IssuerSignedItem(0, random, "family_name", "Doe");
        
        byte[] retrieved = item.getRandom();
        retrieved[0] = (byte) 0xFF;
        
        // Original should not be modified
        assertArrayEquals(random, item.getRandom());
    }
    
    @Test
    public void testToCborAndFromCbor() throws MdlException {
        byte[] random = new byte[]{0x01, 0x02, 0x03, 0x04};
        IssuerSignedItem original = new IssuerSignedItem(0, random, "family_name", "Doe");
        
        byte[] cbor = original.toCbor();
        IssuerSignedItem decoded = IssuerSignedItem.fromCbor(cbor);
        
        assertEquals(original, decoded);
    }
    
    @Test
    public void testToCborWithIntegerValue() throws MdlException {
        byte[] random = new byte[]{0x01, 0x02, 0x03, 0x04};
        IssuerSignedItem original = new IssuerSignedItem(1, random, "age", 30);
        
        byte[] cbor = original.toCbor();
        IssuerSignedItem decoded = IssuerSignedItem.fromCbor(cbor);
        
        assertEquals(original, decoded);
    }
    
    @Test(expected = MdlException.class)
    public void testFromCborWithInvalidData() throws MdlException {
        byte[] invalidCbor = new byte[]{0x01, 0x02, 0x03};
        IssuerSignedItem.fromCbor(invalidCbor);
    }
    
    @Test
    public void testCalculateDigestSha256() throws MdlException {
        byte[] random = new byte[]{0x01, 0x02, 0x03, 0x04};
        IssuerSignedItem item = new IssuerSignedItem(0, random, "family_name", "Doe");
        
        byte[] digest = item.calculateDigest("SHA-256");
        
        assertNotNull(digest);
        assertEquals(32, digest.length); // SHA-256 produces 32 bytes
    }
    
    @Test
    public void testCalculateDigestSha384() throws MdlException {
        byte[] random = new byte[]{0x01, 0x02, 0x03, 0x04};
        IssuerSignedItem item = new IssuerSignedItem(0, random, "family_name", "Doe");
        
        byte[] digest = item.calculateDigest("SHA-384");
        
        assertNotNull(digest);
        assertEquals(48, digest.length); // SHA-384 produces 48 bytes
    }
    
    @Test
    public void testCalculateDigestSha512() throws MdlException {
        byte[] random = new byte[]{0x01, 0x02, 0x03, 0x04};
        IssuerSignedItem item = new IssuerSignedItem(0, random, "family_name", "Doe");
        
        byte[] digest = item.calculateDigest("SHA-512");
        
        assertNotNull(digest);
        assertEquals(64, digest.length); // SHA-512 produces 64 bytes
    }
    
    @Test(expected = MdlException.class)
    public void testCalculateDigestWithUnsupportedAlgorithm() throws MdlException {
        byte[] random = new byte[]{0x01, 0x02, 0x03, 0x04};
        IssuerSignedItem item = new IssuerSignedItem(0, random, "family_name", "Doe");
        
        item.calculateDigest("INVALID-ALGORITHM");
    }
    
    @Test
    public void testCalculateDigestConsistency() throws Exception {
        byte[] random = new byte[]{0x01, 0x02, 0x03, 0x04};
        IssuerSignedItem item = new IssuerSignedItem(0, random, "family_name", "Doe");
        
        byte[] digest1 = item.calculateDigest("SHA-256");
        byte[] digest2 = item.calculateDigest("SHA-256");
        
        assertArrayEquals(digest1, digest2);
    }
    
    @Test
    public void testEquals() {
        byte[] random = new byte[]{0x01, 0x02, 0x03, 0x04};
        IssuerSignedItem item1 = new IssuerSignedItem(0, random, "family_name", "Doe");
        IssuerSignedItem item2 = new IssuerSignedItem(0, random, "family_name", "Doe");
        IssuerSignedItem item3 = new IssuerSignedItem(1, random, "family_name", "Doe");
        
        assertEquals(item1, item2);
        assertNotEquals(item1, item3);
        assertNotEquals(item1, null);
        assertNotEquals(item1, "not an IssuerSignedItem");
    }
    
    @Test
    public void testHashCode() {
        byte[] random = new byte[]{0x01, 0x02, 0x03, 0x04};
        IssuerSignedItem item1 = new IssuerSignedItem(0, random, "family_name", "Doe");
        IssuerSignedItem item2 = new IssuerSignedItem(0, random, "family_name", "Doe");
        
        assertEquals(item1.hashCode(), item2.hashCode());
    }
    
    @Test
    public void testToString() {
        byte[] random = new byte[]{0x01, 0x02, 0x03, 0x04};
        IssuerSignedItem item = new IssuerSignedItem(0, random, "family_name", "Doe");
        
        String str = item.toString();
        assertTrue(str.contains("IssuerSignedItem"));
        assertTrue(str.contains("digestId=0"));
        assertTrue(str.contains("family_name"));
        assertTrue(str.contains("Doe"));
    }
}

// Made with Bob
