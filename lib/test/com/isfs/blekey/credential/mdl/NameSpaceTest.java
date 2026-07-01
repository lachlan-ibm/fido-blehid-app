/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.mdl;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Unit tests for NameSpace.
 */
public class NameSpaceTest {
    
    @Test
    public void testConstructorWithValidName() {
        NameSpace ns = new NameSpace("org.iso.18013.5.1");
        assertEquals("org.iso.18013.5.1", ns.getName());
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testConstructorWithNullName() {
        new NameSpace(null);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testConstructorWithEmptyName() {
        new NameSpace("");
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testConstructorWithWhitespaceName() {
        new NameSpace("   ");
    }
    
    @Test
    public void testIsStandardMdlNamespace() {
        NameSpace standard = new NameSpace(NameSpace.ISO_18013_5_1);
        assertTrue(standard.isStandardMdlNamespace());
        
        NameSpace custom = new NameSpace("com.example.custom");
        assertFalse(custom.isStandardMdlNamespace());
    }
    
    @Test
    public void testIsAamvaNamespace() {
        NameSpace aamva = new NameSpace(NameSpace.ISO_18013_5_1_AAMVA);
        assertTrue(aamva.isAamvaNamespace());
        
        NameSpace standard = new NameSpace(NameSpace.ISO_18013_5_1);
        assertFalse(standard.isAamvaNamespace());
    }
    
    @Test
    public void testEquals() {
        NameSpace ns1 = new NameSpace("org.iso.18013.5.1");
        NameSpace ns2 = new NameSpace("org.iso.18013.5.1");
        NameSpace ns3 = new NameSpace("org.iso.18013.5.1.aamva");
        
        assertEquals(ns1, ns2);
        assertNotEquals(ns1, ns3);
        assertNotEquals(ns1, null);
        assertNotEquals(ns1, "org.iso.18013.5.1");
    }
    
    @Test
    public void testHashCode() {
        NameSpace ns1 = new NameSpace("org.iso.18013.5.1");
        NameSpace ns2 = new NameSpace("org.iso.18013.5.1");
        
        assertEquals(ns1.hashCode(), ns2.hashCode());
    }
    
    @Test
    public void testToString() {
        NameSpace ns = new NameSpace("org.iso.18013.5.1");
        assertEquals("org.iso.18013.5.1", ns.toString());
    }
    
    @Test
    public void testConstants() {
        assertEquals("org.iso.18013.5.1", NameSpace.ISO_18013_5_1);
        assertEquals("org.iso.18013.5.1.aamva", NameSpace.ISO_18013_5_1_AAMVA);
    }
}

// Made with Bob
