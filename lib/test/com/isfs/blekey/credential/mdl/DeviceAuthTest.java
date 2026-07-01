/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.mdl;

import com.isfs.blekey.cose.CoseUtils;
import COSE.AlgorithmID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * Unit tests for {@link DeviceAuth}.
 */
class DeviceAuthTest {
    
    private KeyPair deviceKeyPair;
    private byte[] sessionTranscript;
    private byte[] deviceNameSpacesBytes;
    
    @BeforeEach
    void setUp() throws Exception {
        // Generate EC key pair for testing
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        deviceKeyPair = keyGen.generateKeyPair();
        
        // Create sample session transcript
        Map<String, Object> transcript = new HashMap<>();
        transcript.put("session_id", "test-session-123");
        transcript.put("timestamp", System.currentTimeMillis());
        sessionTranscript = com.isfs.blekey.util.Cbor.encode(transcript);
        
        // Create sample device namespaces
        Map<String, Object> nameSpaces = new HashMap<>();
        nameSpaces.put(NameSpace.ISO_18013_5_1, new Object[]{});
        deviceNameSpacesBytes = com.isfs.blekey.util.Cbor.encode(nameSpaces);
    }
    
    @Test
    void testWithSignature_ValidSignature() {
        byte[] signature = new byte[]{1, 2, 3, 4};
        
        DeviceAuth deviceAuth = DeviceAuth.withSignature(signature);
        
        assertNotNull(deviceAuth);
        assertTrue(deviceAuth.hasSignature());
        assertFalse(deviceAuth.hasMac());
        assertArrayEquals(signature, deviceAuth.getDeviceSignature());
        assertNull(deviceAuth.getDeviceMac());
    }
    
    @Test
    void testWithSignature_NullSignature() {
        assertThrows(IllegalArgumentException.class, () -> {
            DeviceAuth.withSignature(null);
        });
    }
    
    @Test
    void testWithSignature_EmptySignature() {
        assertThrows(IllegalArgumentException.class, () -> {
            DeviceAuth.withSignature(new byte[0]);
        });
    }
    
    @Test
    void testWithMac_ValidMac() {
        byte[] mac = new byte[]{1, 2, 3, 4};
        
        DeviceAuth deviceAuth = DeviceAuth.withMac(mac);
        
        assertNotNull(deviceAuth);
        assertFalse(deviceAuth.hasSignature());
        assertTrue(deviceAuth.hasMac());
        assertNull(deviceAuth.getDeviceSignature());
        assertArrayEquals(mac, deviceAuth.getDeviceMac());
    }
    
    @Test
    void testWithMac_NullMac() {
        assertThrows(IllegalArgumentException.class, () -> {
            DeviceAuth.withMac(null);
        });
    }
    
    @Test
    void testWithMac_EmptyMac() {
        assertThrows(IllegalArgumentException.class, () -> {
            DeviceAuth.withMac(new byte[0]);
        });
    }
    
    @Test
    void testCreateSignature_ValidParameters() throws Exception {
        DeviceAuth deviceAuth = DeviceAuth.createSignature(
            sessionTranscript,
            deviceNameSpacesBytes,
            deviceKeyPair.getPrivate(),
            AlgorithmID.ECDSA_256
        );
        
        assertNotNull(deviceAuth);
        assertTrue(deviceAuth.hasSignature());
        assertFalse(deviceAuth.hasMac());
        assertNotNull(deviceAuth.getDeviceSignature());
        assertTrue(deviceAuth.getDeviceSignature().length > 0);
    }
    
    @Test
    void testCreateSignature_NullSessionTranscript() {
        assertThrows(IllegalArgumentException.class, () -> {
            DeviceAuth.createSignature(
                null,
                deviceNameSpacesBytes,
                deviceKeyPair.getPrivate(),
                AlgorithmID.ECDSA_256
            );
        });
    }
    
    @Test
    void testCreateSignature_EmptySessionTranscript() {
        assertThrows(IllegalArgumentException.class, () -> {
            DeviceAuth.createSignature(
                new byte[0],
                deviceNameSpacesBytes,
                deviceKeyPair.getPrivate(),
                AlgorithmID.ECDSA_256
            );
        });
    }
    
    @Test
    void testCreateSignature_NullDeviceNameSpaces() {
        assertThrows(IllegalArgumentException.class, () -> {
            DeviceAuth.createSignature(
                sessionTranscript,
                null,
                deviceKeyPair.getPrivate(),
                AlgorithmID.ECDSA_256
            );
        });
    }
    
    @Test
    void testCreateSignature_EmptyDeviceNameSpaces() {
        assertThrows(IllegalArgumentException.class, () -> {
            DeviceAuth.createSignature(
                sessionTranscript,
                new byte[0],
                deviceKeyPair.getPrivate(),
                AlgorithmID.ECDSA_256
            );
        });
    }
    
    @Test
    void testCreateSignature_NullPrivateKey() {
        assertThrows(IllegalArgumentException.class, () -> {
            DeviceAuth.createSignature(
                sessionTranscript,
                deviceNameSpacesBytes,
                null,
                AlgorithmID.ECDSA_256
            );
        });
    }
    
    @Test
    void testCreateSignature_NullAlgorithm() {
        assertThrows(IllegalArgumentException.class, () -> {
            DeviceAuth.createSignature(
                sessionTranscript,
                deviceNameSpacesBytes,
                deviceKeyPair.getPrivate(),
                null
            );
        });
    }
    
    @Test
    void testVerifySignature_ValidSignature() throws Exception {
        DeviceAuth deviceAuth = DeviceAuth.createSignature(
            sessionTranscript,
            deviceNameSpacesBytes,
            deviceKeyPair.getPrivate(),
            AlgorithmID.ECDSA_256
        );
        
        boolean valid = deviceAuth.verifySignature(
            sessionTranscript,
            deviceNameSpacesBytes,
            deviceKeyPair.getPublic()
        );
        
        assertTrue(valid);
    }
    
    @Test
    void testVerifySignature_InvalidSignature() throws Exception {
        DeviceAuth deviceAuth = DeviceAuth.createSignature(
            sessionTranscript,
            deviceNameSpacesBytes,
            deviceKeyPair.getPrivate(),
            AlgorithmID.ECDSA_256
        );
        
        // Create different session transcript
        Map<String, Object> differentTranscript = new HashMap<>();
        differentTranscript.put("session_id", "different-session");
        byte[] differentSessionTranscript = com.isfs.blekey.util.Cbor.encode(differentTranscript);
        
        boolean valid = deviceAuth.verifySignature(
            differentSessionTranscript,
            deviceNameSpacesBytes,
            deviceKeyPair.getPublic()
        );
        
        assertFalse(valid);
    }
    
    @Test
    void testVerifySignature_WrongPublicKey() throws Exception {
        DeviceAuth deviceAuth = DeviceAuth.createSignature(
            sessionTranscript,
            deviceNameSpacesBytes,
            deviceKeyPair.getPrivate(),
            AlgorithmID.ECDSA_256
        );
        
        // Generate different key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        KeyPair differentKeyPair = keyGen.generateKeyPair();
        
        boolean valid = deviceAuth.verifySignature(
            sessionTranscript,
            deviceNameSpacesBytes,
            differentKeyPair.getPublic()
        );
        
        assertFalse(valid);
    }
    
    @Test
    void testVerifySignature_NoSignaturePresent() {
        byte[] mac = new byte[]{1, 2, 3, 4};
        DeviceAuth deviceAuth = DeviceAuth.withMac(mac);
        
        assertThrows(MdlException.class, () -> {
            deviceAuth.verifySignature(
                sessionTranscript,
                deviceNameSpacesBytes,
                deviceKeyPair.getPublic()
            );
        });
    }
    
    @Test
    void testVerifySignature_NullSessionTranscript() throws Exception {
        DeviceAuth deviceAuth = DeviceAuth.createSignature(
            sessionTranscript,
            deviceNameSpacesBytes,
            deviceKeyPair.getPrivate(),
            AlgorithmID.ECDSA_256
        );
        
        assertThrows(IllegalArgumentException.class, () -> {
            deviceAuth.verifySignature(
                null,
                deviceNameSpacesBytes,
                deviceKeyPair.getPublic()
            );
        });
    }
    
    @Test
    void testVerifySignature_NullDeviceNameSpaces() throws Exception {
        DeviceAuth deviceAuth = DeviceAuth.createSignature(
            sessionTranscript,
            deviceNameSpacesBytes,
            deviceKeyPair.getPrivate(),
            AlgorithmID.ECDSA_256
        );
        
        assertThrows(IllegalArgumentException.class, () -> {
            deviceAuth.verifySignature(
                sessionTranscript,
                null,
                deviceKeyPair.getPublic()
            );
        });
    }
    
    @Test
    void testVerifySignature_NullPublicKey() throws Exception {
        DeviceAuth deviceAuth = DeviceAuth.createSignature(
            sessionTranscript,
            deviceNameSpacesBytes,
            deviceKeyPair.getPrivate(),
            AlgorithmID.ECDSA_256
        );
        
        assertThrows(IllegalArgumentException.class, () -> {
            deviceAuth.verifySignature(
                sessionTranscript,
                deviceNameSpacesBytes,
                null
            );
        });
    }
    
    @Test
    void testGetDeviceSignature_ReturnsCopy() {
        byte[] signature = new byte[]{1, 2, 3, 4};
        DeviceAuth deviceAuth = DeviceAuth.withSignature(signature);
        
        byte[] retrieved = deviceAuth.getDeviceSignature();
        retrieved[0] = 99; // Modify the copy
        
        // Original should be unchanged
        assertArrayEquals(new byte[]{1, 2, 3, 4}, deviceAuth.getDeviceSignature());
    }
    
    @Test
    void testGetDeviceMac_ReturnsCopy() {
        byte[] mac = new byte[]{1, 2, 3, 4};
        DeviceAuth deviceAuth = DeviceAuth.withMac(mac);
        
        byte[] retrieved = deviceAuth.getDeviceMac();
        retrieved[0] = 99; // Modify the copy
        
        // Original should be unchanged
        assertArrayEquals(new byte[]{1, 2, 3, 4}, deviceAuth.getDeviceMac());
    }
    
    @Test
    void testToCbor_WithSignature() {
        byte[] signature = new byte[]{1, 2, 3, 4};
        DeviceAuth deviceAuth = DeviceAuth.withSignature(signature);
        
        byte[] cbor = deviceAuth.toCbor();
        
        assertNotNull(cbor);
        assertTrue(cbor.length > 0);
    }
    
    @Test
    void testToCbor_WithMac() {
        byte[] mac = new byte[]{1, 2, 3, 4};
        DeviceAuth deviceAuth = DeviceAuth.withMac(mac);
        
        byte[] cbor = deviceAuth.toCbor();
        
        assertNotNull(cbor);
        assertTrue(cbor.length > 0);
    }
    
    @Test
    void testFromCbor_WithSignature() throws Exception {
        byte[] signature = new byte[]{1, 2, 3, 4};
        DeviceAuth original = DeviceAuth.withSignature(signature);
        
        byte[] cbor = original.toCbor();
        DeviceAuth decoded = DeviceAuth.fromCbor(cbor);
        
        assertNotNull(decoded);
        assertTrue(decoded.hasSignature());
        assertFalse(decoded.hasMac());
        assertArrayEquals(signature, decoded.getDeviceSignature());
    }
    
    @Test
    void testFromCbor_WithMac() throws Exception {
        byte[] mac = new byte[]{1, 2, 3, 4};
        DeviceAuth original = DeviceAuth.withMac(mac);
        
        byte[] cbor = original.toCbor();
        DeviceAuth decoded = DeviceAuth.fromCbor(cbor);
        
        assertNotNull(decoded);
        assertFalse(decoded.hasSignature());
        assertTrue(decoded.hasMac());
        assertArrayEquals(mac, decoded.getDeviceMac());
    }
    
    @Test
    void testFromCbor_InvalidData() {
        byte[] invalidCbor = new byte[]{0x01, 0x02, 0x03};
        
        assertThrows(MdlException.class, () -> {
            DeviceAuth.fromCbor(invalidCbor);
        });
    }
    
    @Test
    void testFromCbor_MissingBothFields() throws Exception {
        // Create a CBOR map without deviceSignature or deviceMac
        Map<String, Object> map = new HashMap<>();
        map.put("other", "value");
        byte[] cbor = com.isfs.blekey.util.Cbor.encode(map);
        
        assertThrows(MdlException.class, () -> {
            DeviceAuth.fromCbor(cbor);
        });
    }
    
    @Test
    void testEquals_SameObject() {
        byte[] signature = new byte[]{1, 2, 3, 4};
        DeviceAuth deviceAuth = DeviceAuth.withSignature(signature);
        
        assertEquals(deviceAuth, deviceAuth);
    }
    
    @Test
    void testEquals_EqualSignatures() {
        byte[] signature1 = new byte[]{1, 2, 3, 4};
        byte[] signature2 = new byte[]{1, 2, 3, 4};
        
        DeviceAuth deviceAuth1 = DeviceAuth.withSignature(signature1);
        DeviceAuth deviceAuth2 = DeviceAuth.withSignature(signature2);
        
        assertEquals(deviceAuth1, deviceAuth2);
        assertEquals(deviceAuth1.hashCode(), deviceAuth2.hashCode());
    }
    
    @Test
    void testEquals_EqualMacs() {
        byte[] mac1 = new byte[]{1, 2, 3, 4};
        byte[] mac2 = new byte[]{1, 2, 3, 4};
        
        DeviceAuth deviceAuth1 = DeviceAuth.withMac(mac1);
        DeviceAuth deviceAuth2 = DeviceAuth.withMac(mac2);
        
        assertEquals(deviceAuth1, deviceAuth2);
        assertEquals(deviceAuth1.hashCode(), deviceAuth2.hashCode());
    }
    
    @Test
    void testEquals_DifferentSignatures() {
        DeviceAuth deviceAuth1 = DeviceAuth.withSignature(new byte[]{1, 2, 3, 4});
        DeviceAuth deviceAuth2 = DeviceAuth.withSignature(new byte[]{5, 6, 7, 8});
        
        assertNotEquals(deviceAuth1, deviceAuth2);
    }
    
    @Test
    void testEquals_SignatureVsMac() {
        DeviceAuth deviceAuth1 = DeviceAuth.withSignature(new byte[]{1, 2, 3, 4});
        DeviceAuth deviceAuth2 = DeviceAuth.withMac(new byte[]{1, 2, 3, 4});
        
        assertNotEquals(deviceAuth1, deviceAuth2);
    }
    
    @Test
    void testEquals_Null() {
        byte[] signature = new byte[]{1, 2, 3, 4};
        DeviceAuth deviceAuth = DeviceAuth.withSignature(signature);
        
        assertNotEquals(deviceAuth, null);
    }
    
    @Test
    void testEquals_DifferentClass() {
        byte[] signature = new byte[]{1, 2, 3, 4};
        DeviceAuth deviceAuth = DeviceAuth.withSignature(signature);
        
        assertNotEquals(deviceAuth, "not a DeviceAuth");
    }
    
    @Test
    void testToString_WithSignature() {
        byte[] signature = new byte[]{1, 2, 3, 4};
        DeviceAuth deviceAuth = DeviceAuth.withSignature(signature);
        
        String str = deviceAuth.toString();
        
        assertNotNull(str);
        assertTrue(str.contains("DeviceAuth"));
        assertTrue(str.contains("deviceSignature"));
        assertTrue(str.contains("4 bytes"));
    }
    
    @Test
    void testToString_WithMac() {
        byte[] mac = new byte[]{1, 2, 3, 4};
        DeviceAuth deviceAuth = DeviceAuth.withMac(mac);
        
        String str = deviceAuth.toString();
        
        assertNotNull(str);
        assertTrue(str.contains("DeviceAuth"));
        assertTrue(str.contains("deviceMac"));
        assertTrue(str.contains("4 bytes"));
    }
    
    @Test
    void testRoundTrip_WithRealSignature() throws Exception {
        DeviceAuth original = DeviceAuth.createSignature(
            sessionTranscript,
            deviceNameSpacesBytes,
            deviceKeyPair.getPrivate(),
            AlgorithmID.ECDSA_256
        );
        
        byte[] cbor = original.toCbor();
        DeviceAuth decoded = DeviceAuth.fromCbor(cbor);
        
        // Verify signature still works after round-trip
        boolean valid = decoded.verifySignature(
            sessionTranscript,
            deviceNameSpacesBytes,
            deviceKeyPair.getPublic()
        );
        
        assertTrue(valid);
    }
}

// Made with Bob
