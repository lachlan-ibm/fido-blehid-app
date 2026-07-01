/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.mdl;

import org.junit.Test;
import static org.junit.Assert.*;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;

/**
 * Unit tests for MobileSecurityObject.
 */
public class MobileSecurityObjectTest {
    
    private Map<String, Map<Integer, byte[]>> createTestValueDigests() {
        Map<String, Map<Integer, byte[]>> valueDigests = new HashMap<>();
        Map<Integer, byte[]> digests = new HashMap<>();
        digests.put(0, new byte[]{0x01, 0x02, 0x03, 0x04});
        digests.put(1, new byte[]{0x05, 0x06, 0x07, 0x08});
        valueDigests.put(NameSpace.ISO_18013_5_1, digests);
        return valueDigests;
    }
    
    private Map<String, Object> createTestDeviceKeyInfo() {
        Map<String, Object> deviceKeyInfo = new HashMap<>();
        deviceKeyInfo.put("deviceKey", new byte[]{0x01, 0x02, 0x03});
        return deviceKeyInfo;
    }
    
    @Test
    public void testConstructorWithValidParameters() {
        Instant now = Instant.now();
        Instant validFrom = now.minus(1, ChronoUnit.DAYS);
        Instant validUntil = now.plus(30, ChronoUnit.DAYS);
        
        MobileSecurityObject mso = new MobileSecurityObject(
            MobileSecurityObject.VERSION_1_0,
            MobileSecurityObject.DIGEST_ALGORITHM_SHA256,
            createTestValueDigests(),
            createTestDeviceKeyInfo(),
            MobileDocument.DOCTYPE_MDL,
            now,
            validFrom,
            validUntil
        );
        
        assertEquals(MobileSecurityObject.VERSION_1_0, mso.getVersion());
        assertEquals(MobileSecurityObject.DIGEST_ALGORITHM_SHA256, mso.getDigestAlgorithm());
        assertEquals(MobileDocument.DOCTYPE_MDL, mso.getDocType());
        assertEquals(now, mso.getSigned());
        assertEquals(validFrom, mso.getValidFrom());
        assertEquals(validUntil, mso.getValidUntil());
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testConstructorWithNullVersion() {
        Instant now = Instant.now();
        new MobileSecurityObject(
            null,
            MobileSecurityObject.DIGEST_ALGORITHM_SHA256,
            createTestValueDigests(),
            createTestDeviceKeyInfo(),
            MobileDocument.DOCTYPE_MDL,
            now, now, now.plus(1, ChronoUnit.DAYS)
        );
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testConstructorWithInvalidDigestAlgorithm() {
        Instant now = Instant.now();
        new MobileSecurityObject(
            MobileSecurityObject.VERSION_1_0,
            "INVALID-ALGORITHM",
            createTestValueDigests(),
            createTestDeviceKeyInfo(),
            MobileDocument.DOCTYPE_MDL,
            now, now, now.plus(1, ChronoUnit.DAYS)
        );
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testConstructorWithNullValueDigests() {
        Instant now = Instant.now();
        new MobileSecurityObject(
            MobileSecurityObject.VERSION_1_0,
            MobileSecurityObject.DIGEST_ALGORITHM_SHA256,
            null,
            createTestDeviceKeyInfo(),
            MobileDocument.DOCTYPE_MDL,
            now, now, now.plus(1, ChronoUnit.DAYS)
        );
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testConstructorWithEmptyValueDigests() {
        Instant now = Instant.now();
        new MobileSecurityObject(
            MobileSecurityObject.VERSION_1_0,
            MobileSecurityObject.DIGEST_ALGORITHM_SHA256,
            new HashMap<>(),
            createTestDeviceKeyInfo(),
            MobileDocument.DOCTYPE_MDL,
            now, now, now.plus(1, ChronoUnit.DAYS)
        );
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testConstructorWithValidFromAfterValidUntil() {
        Instant now = Instant.now();
        Instant validFrom = now.plus(30, ChronoUnit.DAYS);
        Instant validUntil = now.minus(1, ChronoUnit.DAYS);
        
        new MobileSecurityObject(
            MobileSecurityObject.VERSION_1_0,
            MobileSecurityObject.DIGEST_ALGORITHM_SHA256,
            createTestValueDigests(),
            createTestDeviceKeyInfo(),
            MobileDocument.DOCTYPE_MDL,
            now, validFrom, validUntil
        );
    }
    
    @Test
    public void testIsValidDigestAlgorithm() {
        assertTrue(MobileSecurityObject.isValidDigestAlgorithm(
            MobileSecurityObject.DIGEST_ALGORITHM_SHA256));
        assertTrue(MobileSecurityObject.isValidDigestAlgorithm(
            MobileSecurityObject.DIGEST_ALGORITHM_SHA384));
        assertTrue(MobileSecurityObject.isValidDigestAlgorithm(
            MobileSecurityObject.DIGEST_ALGORITHM_SHA512));
        assertFalse(MobileSecurityObject.isValidDigestAlgorithm("MD5"));
        assertFalse(MobileSecurityObject.isValidDigestAlgorithm("INVALID"));
    }
    
    @Test
    public void testIsValid() {
        Instant now = Instant.now();
        Instant validFrom = now.minus(1, ChronoUnit.DAYS);
        Instant validUntil = now.plus(30, ChronoUnit.DAYS);
        
        MobileSecurityObject mso = new MobileSecurityObject(
            MobileSecurityObject.VERSION_1_0,
            MobileSecurityObject.DIGEST_ALGORITHM_SHA256,
            createTestValueDigests(),
            createTestDeviceKeyInfo(),
            MobileDocument.DOCTYPE_MDL,
            now, validFrom, validUntil
        );
        
        assertTrue(mso.isValid());
    }
    
    @Test
    public void testIsValidAt() {
        Instant now = Instant.now();
        Instant validFrom = now.minus(1, ChronoUnit.DAYS);
        Instant validUntil = now.plus(30, ChronoUnit.DAYS);
        
        MobileSecurityObject mso = new MobileSecurityObject(
            MobileSecurityObject.VERSION_1_0,
            MobileSecurityObject.DIGEST_ALGORITHM_SHA256,
            createTestValueDigests(),
            createTestDeviceKeyInfo(),
            MobileDocument.DOCTYPE_MDL,
            now, validFrom, validUntil
        );
        
        assertTrue(mso.isValidAt(now));
        assertTrue(mso.isValidAt(validFrom));
        assertTrue(mso.isValidAt(validUntil));
        assertFalse(mso.isValidAt(validFrom.minus(1, ChronoUnit.SECONDS)));
        assertFalse(mso.isValidAt(validUntil.plus(1, ChronoUnit.SECONDS)));
    }
    
    @Test
    public void testToCborAndFromCbor() throws MdlException {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant validFrom = now.minus(1, ChronoUnit.DAYS);
        Instant validUntil = now.plus(30, ChronoUnit.DAYS);
        
        MobileSecurityObject original = new MobileSecurityObject(
            MobileSecurityObject.VERSION_1_0,
            MobileSecurityObject.DIGEST_ALGORITHM_SHA256,
            createTestValueDigests(),
            createTestDeviceKeyInfo(),
            MobileDocument.DOCTYPE_MDL,
            now, validFrom, validUntil
        );
        
        byte[] cbor = original.toCbor();
        MobileSecurityObject decoded = MobileSecurityObject.fromCbor(cbor);
        
        assertEquals(original.getVersion(), decoded.getVersion());
        assertEquals(original.getDigestAlgorithm(), decoded.getDigestAlgorithm());
        assertEquals(original.getDocType(), decoded.getDocType());
        assertEquals(original.getSigned(), decoded.getSigned());
        assertEquals(original.getValidFrom(), decoded.getValidFrom());
        assertEquals(original.getValidUntil(), decoded.getValidUntil());
    }
    
    @Test
    public void testToCborWithSHA384() throws MdlException {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        
        MobileSecurityObject original = new MobileSecurityObject(
            MobileSecurityObject.VERSION_1_0,
            MobileSecurityObject.DIGEST_ALGORITHM_SHA384,
            createTestValueDigests(),
            createTestDeviceKeyInfo(),
            MobileDocument.DOCTYPE_MDL,
            now, now, now.plus(1, ChronoUnit.DAYS)
        );
        
        byte[] cbor = original.toCbor();
        MobileSecurityObject decoded = MobileSecurityObject.fromCbor(cbor);
        
        assertEquals(MobileSecurityObject.DIGEST_ALGORITHM_SHA384, decoded.getDigestAlgorithm());
    }
    
    @Test
    public void testToCborWithSHA512() throws MdlException {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        
        MobileSecurityObject original = new MobileSecurityObject(
            MobileSecurityObject.VERSION_1_0,
            MobileSecurityObject.DIGEST_ALGORITHM_SHA512,
            createTestValueDigests(),
            createTestDeviceKeyInfo(),
            MobileDocument.DOCTYPE_MDL,
            now, now, now.plus(1, ChronoUnit.DAYS)
        );
        
        byte[] cbor = original.toCbor();
        MobileSecurityObject decoded = MobileSecurityObject.fromCbor(cbor);
        
        assertEquals(MobileSecurityObject.DIGEST_ALGORITHM_SHA512, decoded.getDigestAlgorithm());
    }
    
    @Test(expected = MdlException.class)
    public void testFromCborWithInvalidData() throws MdlException {
        byte[] invalidCbor = new byte[]{0x01, 0x02, 0x03};
        MobileSecurityObject.fromCbor(invalidCbor);
    }
    
    @Test
    public void testValidate() throws MdlException {
        Instant now = Instant.now();
        Instant validFrom = now.minus(1, ChronoUnit.DAYS);
        Instant validUntil = now.plus(30, ChronoUnit.DAYS);
        
        MobileSecurityObject mso = new MobileSecurityObject(
            MobileSecurityObject.VERSION_1_0,
            MobileSecurityObject.DIGEST_ALGORITHM_SHA256,
            createTestValueDigests(),
            createTestDeviceKeyInfo(),
            MobileDocument.DOCTYPE_MDL,
            now, validFrom, validUntil
        );
        
        mso.validate(); // Should not throw
    }
    
    @Test(expected = MdlException.class)
    public void testValidateWithExpiredMso() throws MdlException {
        Instant now = Instant.now();
        Instant validFrom = now.minus(30, ChronoUnit.DAYS);
        Instant validUntil = now.minus(1, ChronoUnit.DAYS);
        
        MobileSecurityObject mso = new MobileSecurityObject(
            MobileSecurityObject.VERSION_1_0,
            MobileSecurityObject.DIGEST_ALGORITHM_SHA256,
            createTestValueDigests(),
            createTestDeviceKeyInfo(),
            MobileDocument.DOCTYPE_MDL,
            validFrom, validFrom, validUntil
        );
        
        mso.validate();
    }
    
    @Test
    public void testGetValueDigestsReturnsUnmodifiableCopy() {
        Instant now = Instant.now();
        
        MobileSecurityObject mso = new MobileSecurityObject(
            MobileSecurityObject.VERSION_1_0,
            MobileSecurityObject.DIGEST_ALGORITHM_SHA256,
            createTestValueDigests(),
            createTestDeviceKeyInfo(),
            MobileDocument.DOCTYPE_MDL,
            now, now, now.plus(1, ChronoUnit.DAYS)
        );
        
        Map<String, Map<Integer, byte[]>> digests = mso.getValueDigests();
        
        try {
            digests.put("new_namespace", new HashMap<>());
            fail("Should throw UnsupportedOperationException");
        } catch (UnsupportedOperationException e) {
            // Expected
        }
    }
    
    @Test
    public void testEquals() {
        Instant now = Instant.now();
        
        MobileSecurityObject mso1 = new MobileSecurityObject(
            MobileSecurityObject.VERSION_1_0,
            MobileSecurityObject.DIGEST_ALGORITHM_SHA256,
            createTestValueDigests(),
            createTestDeviceKeyInfo(),
            MobileDocument.DOCTYPE_MDL,
            now, now, now.plus(1, ChronoUnit.DAYS)
        );
        
        MobileSecurityObject mso2 = new MobileSecurityObject(
            MobileSecurityObject.VERSION_1_0,
            MobileSecurityObject.DIGEST_ALGORITHM_SHA256,
            createTestValueDigests(),
            createTestDeviceKeyInfo(),
            MobileDocument.DOCTYPE_MDL,
            now, now, now.plus(1, ChronoUnit.DAYS)
        );
        
        MobileSecurityObject mso3 = new MobileSecurityObject(
            MobileSecurityObject.VERSION_1_0,
            MobileSecurityObject.DIGEST_ALGORITHM_SHA384,
            createTestValueDigests(),
            createTestDeviceKeyInfo(),
            MobileDocument.DOCTYPE_MDL,
            now, now, now.plus(1, ChronoUnit.DAYS)
        );
        
        assertEquals(mso1, mso2);
        assertNotEquals(mso1, mso3);
        assertNotEquals(mso1, null);
        assertNotEquals(mso1, "not an MSO");
    }
    
    @Test
    public void testHashCode() {
        Instant now = Instant.now();
        
        MobileSecurityObject mso1 = new MobileSecurityObject(
            MobileSecurityObject.VERSION_1_0,
            MobileSecurityObject.DIGEST_ALGORITHM_SHA256,
            createTestValueDigests(),
            createTestDeviceKeyInfo(),
            MobileDocument.DOCTYPE_MDL,
            now, now, now.plus(1, ChronoUnit.DAYS)
        );
        
        MobileSecurityObject mso2 = new MobileSecurityObject(
            MobileSecurityObject.VERSION_1_0,
            MobileSecurityObject.DIGEST_ALGORITHM_SHA256,
            createTestValueDigests(),
            createTestDeviceKeyInfo(),
            MobileDocument.DOCTYPE_MDL,
            now, now, now.plus(1, ChronoUnit.DAYS)
        );
        
        assertEquals(mso1.hashCode(), mso2.hashCode());
    }
    
    @Test
    public void testToString() {
        Instant now = Instant.now();
        
        MobileSecurityObject mso = new MobileSecurityObject(
            MobileSecurityObject.VERSION_1_0,
            MobileSecurityObject.DIGEST_ALGORITHM_SHA256,
            createTestValueDigests(),
            createTestDeviceKeyInfo(),
            MobileDocument.DOCTYPE_MDL,
            now, now, now.plus(1, ChronoUnit.DAYS)
        );
        
        String str = mso.toString();
        assertTrue(str.contains("MobileSecurityObject"));
        assertTrue(str.contains("1.0"));
        assertTrue(str.contains("SHA-256"));
        assertTrue(str.contains(MobileDocument.DOCTYPE_MDL));
    }
    
    @Test
    public void testConstants() {
        assertEquals("1.0", MobileSecurityObject.VERSION_1_0);
        assertEquals("SHA-256", MobileSecurityObject.DIGEST_ALGORITHM_SHA256);
        assertEquals("SHA-384", MobileSecurityObject.DIGEST_ALGORITHM_SHA384);
        assertEquals("SHA-512", MobileSecurityObject.DIGEST_ALGORITHM_SHA512);
    }
    
    @Test
    public void testMultipleNamespaces() {
        Map<String, Map<Integer, byte[]>> valueDigests = new HashMap<>();
        
        Map<Integer, byte[]> digests1 = new HashMap<>();
        digests1.put(0, new byte[]{0x01, 0x02});
        valueDigests.put(NameSpace.ISO_18013_5_1, digests1);
        
        Map<Integer, byte[]> digests2 = new HashMap<>();
        digests2.put(0, new byte[]{0x03, 0x04});
        valueDigests.put(NameSpace.ISO_18013_5_1_AAMVA, digests2);
        
        Instant now = Instant.now();
        
        MobileSecurityObject mso = new MobileSecurityObject(
            MobileSecurityObject.VERSION_1_0,
            MobileSecurityObject.DIGEST_ALGORITHM_SHA256,
            valueDigests,
            createTestDeviceKeyInfo(),
            MobileDocument.DOCTYPE_MDL,
            now, now, now.plus(1, ChronoUnit.DAYS)
        );
        
        assertEquals(2, mso.getValueDigests().size());
    }
}

// Made with Bob
