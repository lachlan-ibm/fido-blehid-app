/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.mdl;

import com.isfs.blekey.util.Cbor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Map;

/**
 * Unit tests for {@link DeviceEngagement}.
 */
class DeviceEngagementTest {

    private KeyPair deviceKeyPair;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        deviceKeyPair = keyGen.generateKeyPair();
    }

    // -------------------------------------------------------------------------
    // Constructor tests (lines 52-66)
    // -------------------------------------------------------------------------

    @Test
    void testConstructor_ValidParameters() {
        DeviceEngagement de = new DeviceEngagement("1.0", deviceKeyPair.getPublic(), 1);
        assertNotNull(de);
        assertEquals("1.0", de.getVersion());
        assertEquals(deviceKeyPair.getPublic(), de.getDevicePublicKey());
        assertEquals(1, de.getCipherSuite());
    }

    @Test
    void testConstructor_NullVersion() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
            new DeviceEngagement(null, deviceKeyPair.getPublic(), 1));
        assertTrue(ex.getMessage().contains("version"));
    }

    @Test
    void testConstructor_EmptyVersion() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
            new DeviceEngagement("", deviceKeyPair.getPublic(), 1));
        assertTrue(ex.getMessage().contains("version"));
    }

    @Test
    void testConstructor_NullPublicKey() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
            new DeviceEngagement("1.0", null, 1));
        assertTrue(ex.getMessage().contains("devicePublicKey"));
    }

    @Test
    void testConstructor_NonECKey() throws Exception {
        // RSA key should be rejected because only EC keys are supported
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048);
        PublicKey rsaKey = rsaGen.generateKeyPair().getPublic();

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
            new DeviceEngagement("1.0", rsaKey, 1));
        assertTrue(ex.getMessage().contains("EC"));
    }

    @Test
    void testConstructor_CustomVersion() {
        DeviceEngagement de = new DeviceEngagement("2.0", deviceKeyPair.getPublic(), 2);
        assertEquals("2.0", de.getVersion());
        assertEquals(2, de.getCipherSuite());
    }

    @Test
    void testConstructor_DifferentCipherSuite() {
        DeviceEngagement de = new DeviceEngagement("1.0", deviceKeyPair.getPublic(), 2);
        assertEquals(2, de.getCipherSuite());
    }

    // -------------------------------------------------------------------------
    // Factory method tests (line 76)
    // -------------------------------------------------------------------------

    @Test
    void testCreate_ValidPublicKey() {
        DeviceEngagement de = DeviceEngagement.create(deviceKeyPair.getPublic());
        assertNotNull(de);
        assertEquals("1.0", de.getVersion());
        assertEquals(1, de.getCipherSuite());
        assertEquals(deviceKeyPair.getPublic(), de.getDevicePublicKey());
    }

    @Test
    void testCreate_NullPublicKey() {
        assertThrows(IllegalArgumentException.class, () ->
            DeviceEngagement.create(null));
    }

    // -------------------------------------------------------------------------
    // CBOR encoding tests (lines 85-106)
    // -------------------------------------------------------------------------

    @Test
    void testToCbor_ValidEncoding() throws Exception {
        DeviceEngagement de = new DeviceEngagement("1.0", deviceKeyPair.getPublic(), 1);
        byte[] cbor = de.toCbor();
        assertNotNull(cbor);
        assertTrue(cbor.length > 0);
    }

    @Test
    void testToCbor_VerifyVersionField() throws Exception {
        DeviceEngagement de = new DeviceEngagement("1.0", deviceKeyPair.getPublic(), 1);
        byte[] cbor = de.toCbor();

        Object decoded = Cbor.decode(cbor);
        assertTrue(decoded instanceof Map);
        @SuppressWarnings("unchecked")
        Map<String, Object> map = (Map<String, Object>) decoded;
        assertEquals("1.0", map.get("version"));
    }

    @Test
    void testToCbor_VerifySecurityField() throws Exception {
        DeviceEngagement de = new DeviceEngagement("1.0", deviceKeyPair.getPublic(), 1);
        byte[] cbor = de.toCbor();

        Object decoded = Cbor.decode(cbor);
        @SuppressWarnings("unchecked")
        Map<String, Object> map = (Map<String, Object>) decoded;
        assertNotNull(map.get("security"));
        assertTrue(map.get("security") instanceof Map);
    }

    @Test
    void testToCbor_VerifyCipherSuite() throws Exception {
        DeviceEngagement de = new DeviceEngagement("1.0", deviceKeyPair.getPublic(), 1);
        byte[] cbor = de.toCbor();

        Object decoded = Cbor.decode(cbor);
        @SuppressWarnings("unchecked")
        Map<String, Object> map = (Map<String, Object>) decoded;
        @SuppressWarnings("unchecked")
        Map<Integer, Object> security = (Map<Integer, Object>) map.get("security");
        assertEquals(1, security.get(1));
    }

    @Test
    void testToCbor_VerifyDeviceRetrievalMethods() throws Exception {
        DeviceEngagement de = new DeviceEngagement("1.0", deviceKeyPair.getPublic(), 1);
        byte[] cbor = de.toCbor();

        Object decoded = Cbor.decode(cbor);
        @SuppressWarnings("unchecked")
        Map<String, Object> map = (Map<String, Object>) decoded;
        assertNotNull(map.get("deviceRetrievalMethods"));
    }

    // -------------------------------------------------------------------------
    // CBOR decoding tests (lines 115-155)
    // -------------------------------------------------------------------------

    @Test
    void testFromCbor_ValidDecoding() throws Exception {
        DeviceEngagement original = new DeviceEngagement("1.0", deviceKeyPair.getPublic(), 1);
        byte[] cbor = original.toCbor();

        DeviceEngagement decoded = DeviceEngagement.fromCbor(cbor);
        assertNotNull(decoded);
        assertEquals("1.0", decoded.getVersion());
        assertEquals(1, decoded.getCipherSuite());
    }

    @Test
    void testFromCbor_NotAMap() {
        // Encode a CBOR array instead of map
        byte[] cborArray = Cbor.encode(new Object[]{1, 2, 3});
        assertThrows(MdlException.class, () -> DeviceEngagement.fromCbor(cborArray));
    }

    @Test
    void testFromCbor_MissingVersion() {
        // Build a map missing "version"
        java.util.Map<String, Object> map = new java.util.HashMap<>();
        map.put("security", new java.util.HashMap<>());
        byte[] cbor = Cbor.encode(map);
        assertThrows(MdlException.class, () -> DeviceEngagement.fromCbor(cbor));
    }

    @Test
    void testFromCbor_MissingSecurity() {
        java.util.Map<String, Object> map = new java.util.HashMap<>();
        map.put("version", "1.0");
        byte[] cbor = Cbor.encode(map);
        assertThrows(MdlException.class, () -> DeviceEngagement.fromCbor(cbor));
    }

    @Test
    void testFromCbor_MissingCipherSuite() {
        // security map missing key 1 (cipher suite)
        java.util.Map<Integer, Object> security = new java.util.HashMap<>();
        // key 1 intentionally absent
        security.put(2, new byte[]{0x01});

        java.util.Map<String, Object> map = new java.util.HashMap<>();
        map.put("version", "1.0");
        map.put("security", security);
        byte[] cbor = Cbor.encode(map);
        assertThrows(MdlException.class, () -> DeviceEngagement.fromCbor(cbor));
    }

    @Test
    void testFromCbor_MissingPublicKey() {
        // security map missing key 2 (coseKeyBytes)
        java.util.Map<Integer, Object> security = new java.util.HashMap<>();
        security.put(1, 1);
        // key 2 intentionally absent

        java.util.Map<String, Object> map = new java.util.HashMap<>();
        map.put("version", "1.0");
        map.put("security", security);
        byte[] cbor = Cbor.encode(map);
        assertThrows(MdlException.class, () -> DeviceEngagement.fromCbor(cbor));
    }

    @Test
    void testFromCbor_InvalidCoseKey() {
        // security map with key 2 set to non-map CBOR bytes (i.e. a CBOR integer)
        byte[] invalidCoseKeyBytes = Cbor.encode(42); // integer, not a map

        java.util.Map<Integer, Object> security = new java.util.HashMap<>();
        security.put(1, 1);
        security.put(2, invalidCoseKeyBytes);

        java.util.Map<String, Object> map = new java.util.HashMap<>();
        map.put("version", "1.0");
        map.put("security", security);
        byte[] cbor = Cbor.encode(map);
        assertThrows(MdlException.class, () -> DeviceEngagement.fromCbor(cbor));
    }

    @Test
    void testFromCbor_RoundTrip() throws Exception {
        DeviceEngagement original = new DeviceEngagement("1.0", deviceKeyPair.getPublic(), 1);
        byte[] cbor = original.toCbor();
        DeviceEngagement decoded = DeviceEngagement.fromCbor(cbor);

        assertEquals(original.getVersion(), decoded.getVersion());
        assertEquals(original.getCipherSuite(), decoded.getCipherSuite());
        assertNotNull(decoded.getDevicePublicKey());
    }

    // -------------------------------------------------------------------------
    // QR code payload tests (lines 163-187)
    // -------------------------------------------------------------------------

    @Test
    void testToQrCodePayload_ValidFormat() throws Exception {
        DeviceEngagement de = new DeviceEngagement("1.0", deviceKeyPair.getPublic(), 1);
        String qrPayload = de.toQrCodePayload();
        assertNotNull(qrPayload);
        assertTrue(qrPayload.startsWith("mdoc:"));
    }

    @Test
    void testToQrCodePayload_Base64Decoding() throws Exception {
        DeviceEngagement de = new DeviceEngagement("1.0", deviceKeyPair.getPublic(), 1);
        String qrPayload = de.toQrCodePayload();

        String base64 = qrPayload.substring(5);
        byte[] decoded = java.util.Base64.getDecoder().decode(base64);
        // Should be valid CBOR – Cbor.decode should not throw
        Object obj = Cbor.decode(decoded);
        assertNotNull(obj);
    }

    @Test
    void testFromQrCodePayload_ValidPayload() throws Exception {
        DeviceEngagement original = new DeviceEngagement("1.0", deviceKeyPair.getPublic(), 1);
        String qrPayload = original.toQrCodePayload();

        DeviceEngagement decoded = DeviceEngagement.fromQrCodePayload(qrPayload);
        assertNotNull(decoded);
        assertEquals(original.getVersion(), decoded.getVersion());
        assertEquals(original.getCipherSuite(), decoded.getCipherSuite());
    }

    @Test
    void testFromQrCodePayload_NullPayload() {
        assertThrows(MdlException.class, () ->
            DeviceEngagement.fromQrCodePayload(null));
    }

    @Test
    void testFromQrCodePayload_MissingPrefix() {
        assertThrows(MdlException.class, () ->
            DeviceEngagement.fromQrCodePayload("notmdoc:abc123"));
    }

    @Test
    void testFromQrCodePayload_InvalidBase64() {
        assertThrows(MdlException.class, () ->
            DeviceEngagement.fromQrCodePayload("mdoc:!!!not-base64!!!"));
    }

    @Test
    void testFromQrCodePayload_RoundTrip() throws Exception {
        DeviceEngagement original = DeviceEngagement.create(deviceKeyPair.getPublic());
        String qrPayload = original.toQrCodePayload();
        DeviceEngagement roundTripped = DeviceEngagement.fromQrCodePayload(qrPayload);

        assertEquals(original.getVersion(), roundTripped.getVersion());
        assertEquals(original.getCipherSuite(), roundTripped.getCipherSuite());
    }

    // -------------------------------------------------------------------------
    // Getter tests (lines 233-253)
    // -------------------------------------------------------------------------

    @Test
    void testGetVersion() {
        DeviceEngagement de = new DeviceEngagement("2.0", deviceKeyPair.getPublic(), 1);
        assertEquals("2.0", de.getVersion());
    }

    @Test
    void testGetDevicePublicKey() {
        PublicKey pub = deviceKeyPair.getPublic();
        DeviceEngagement de = new DeviceEngagement("1.0", pub, 1);
        assertEquals(pub, de.getDevicePublicKey());
    }

    @Test
    void testGetCipherSuite() {
        DeviceEngagement de = new DeviceEngagement("1.0", deviceKeyPair.getPublic(), 5);
        assertEquals(5, de.getCipherSuite());
    }

    // -------------------------------------------------------------------------
    // toString test (lines 256-259)
    // -------------------------------------------------------------------------

    @Test
    void testToString() {
        DeviceEngagement de = new DeviceEngagement("1.0", deviceKeyPair.getPublic(), 1);
        String s = de.toString();
        assertTrue(s.contains("1.0"));
        assertTrue(s.contains("1"));
    }
}
