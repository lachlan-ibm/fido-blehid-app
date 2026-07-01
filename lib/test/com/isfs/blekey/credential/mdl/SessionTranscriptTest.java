/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.mdl;

import com.isfs.blekey.util.Cbor;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link SessionTranscript}.
 */
class SessionTranscriptTest {

    private byte[] deviceEngagementBytes;
    private byte[] eReaderKeyBytes;
    private byte[] handoverBytes;

    @BeforeEach
    void setUp() {
        deviceEngagementBytes = new byte[]{0x01, 0x02, 0x03};
        eReaderKeyBytes = new byte[]{0x04, 0x05, 0x06};
        handoverBytes = new byte[]{0x07, 0x08, 0x09};
    }

    // -------------------------------------------------------------------------
    // Constructor tests (lines 43-54)
    // -------------------------------------------------------------------------

    @Test
    void testConstructor_ValidParameters() {
        SessionTranscript st = new SessionTranscript(deviceEngagementBytes, eReaderKeyBytes, handoverBytes);
        assertNotNull(st);
    }

    @Test
    void testConstructor_ValidParametersNoHandover() {
        SessionTranscript st = new SessionTranscript(deviceEngagementBytes, eReaderKeyBytes, null);
        assertNotNull(st);
        assertFalse(st.hasHandover());
        assertNull(st.getHandover());
    }

    @Test
    void testConstructor_NullDeviceEngagement() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
            new SessionTranscript(null, eReaderKeyBytes, null));
        assertTrue(ex.getMessage().contains("deviceEngagementBytes"));
    }

    @Test
    void testConstructor_EmptyDeviceEngagement() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
            new SessionTranscript(new byte[0], eReaderKeyBytes, null));
        assertTrue(ex.getMessage().contains("deviceEngagementBytes"));
    }

    @Test
    void testConstructor_NullReaderKey() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
            new SessionTranscript(deviceEngagementBytes, null, null));
        assertTrue(ex.getMessage().contains("eReaderKeyBytes"));
    }

    @Test
    void testConstructor_EmptyReaderKey() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
            new SessionTranscript(deviceEngagementBytes, new byte[0], null));
        assertTrue(ex.getMessage().contains("eReaderKeyBytes"));
    }

    @Test
    void testConstructor_DefensiveCopy() {
        byte[] deBytes = {0x01, 0x02};
        byte[] rkBytes = {0x03, 0x04};
        byte[] hoBytes = {0x05, 0x06};

        SessionTranscript st = new SessionTranscript(deBytes, rkBytes, hoBytes);

        // Mutate originals – stored copies must remain unchanged
        deBytes[0] = (byte) 0xFF;
        rkBytes[0] = (byte) 0xFF;
        hoBytes[0] = (byte) 0xFF;

        assertArrayEquals(new byte[]{0x01, 0x02}, st.getDeviceEngagementBytes());
        assertArrayEquals(new byte[]{0x03, 0x04}, st.getEReaderKeyBytes());
        assertArrayEquals(new byte[]{0x05, 0x06}, st.getHandover());
    }

    // -------------------------------------------------------------------------
    // Factory method tests (line 65)
    // -------------------------------------------------------------------------

    @Test
    void testCreate_ValidParameters() {
        SessionTranscript st = SessionTranscript.create(deviceEngagementBytes, eReaderKeyBytes);
        assertNotNull(st);
        assertFalse(st.hasHandover());
    }

    @Test
    void testCreate_NullDeviceEngagement() {
        assertThrows(IllegalArgumentException.class, () ->
            SessionTranscript.create(null, eReaderKeyBytes));
    }

    // -------------------------------------------------------------------------
    // CBOR encoding tests (lines 73-79)
    // -------------------------------------------------------------------------

    @Test
    void testToCbor_WithHandover() {
        SessionTranscript st = new SessionTranscript(deviceEngagementBytes, eReaderKeyBytes, handoverBytes);
        byte[] cbor = st.toCbor();
        assertNotNull(cbor);
        assertTrue(cbor.length > 0);
    }

    @Test
    void testToCbor_WithoutHandover() {
        SessionTranscript st = new SessionTranscript(deviceEngagementBytes, eReaderKeyBytes, null);
        byte[] cbor = st.toCbor();
        assertNotNull(cbor);
        assertTrue(cbor.length > 0);
    }

    @Test
    void testToCbor_VerifyArrayStructure() {
        SessionTranscript st = new SessionTranscript(deviceEngagementBytes, eReaderKeyBytes, handoverBytes);
        byte[] cbor = st.toCbor();

        Object decoded = Cbor.decode(cbor);
        assertTrue(decoded instanceof List);
        @SuppressWarnings("unchecked")
        List<Object> array = (List<Object>) decoded;
        assertEquals(3, array.size());
    }

    @Test
    void testToCbor_VerifyElementOrder() {
        SessionTranscript st = new SessionTranscript(deviceEngagementBytes, eReaderKeyBytes, handoverBytes);
        byte[] cbor = st.toCbor();

        Object decoded = Cbor.decode(cbor);
        @SuppressWarnings("unchecked")
        List<Object> array = (List<Object>) decoded;
        assertArrayEquals(deviceEngagementBytes, (byte[]) array.get(0));
        assertArrayEquals(eReaderKeyBytes, (byte[]) array.get(1));
        assertArrayEquals(handoverBytes, (byte[]) array.get(2));
    }

    // -------------------------------------------------------------------------
    // CBOR decoding tests (lines 88-111)
    // -------------------------------------------------------------------------

    @Test
    void testFromCbor_ValidWithHandover() throws Exception {
        SessionTranscript original = new SessionTranscript(deviceEngagementBytes, eReaderKeyBytes, handoverBytes);
        byte[] cbor = original.toCbor();

        SessionTranscript decoded = SessionTranscript.fromCbor(cbor);
        assertNotNull(decoded);
        assertArrayEquals(deviceEngagementBytes, decoded.getDeviceEngagementBytes());
        assertArrayEquals(eReaderKeyBytes, decoded.getEReaderKeyBytes());
        assertArrayEquals(handoverBytes, decoded.getHandover());
        assertTrue(decoded.hasHandover());
    }

    @Test
    void testFromCbor_ValidWithoutHandover() throws Exception {
        // Encode a 2-element array (no handover)
        byte[] cbor = Cbor.encode(new Object[]{deviceEngagementBytes, eReaderKeyBytes});

        SessionTranscript decoded = SessionTranscript.fromCbor(cbor);
        assertNotNull(decoded);
        assertArrayEquals(deviceEngagementBytes, decoded.getDeviceEngagementBytes());
        assertArrayEquals(eReaderKeyBytes, decoded.getEReaderKeyBytes());
        assertFalse(decoded.hasHandover());
    }

    @Test
    void testFromCbor_NotAnArray() {
        // Encode a CBOR map instead of array
        java.util.Map<String, Object> map = new java.util.HashMap<>();
        map.put("key", "value");
        byte[] cbor = Cbor.encode(map);
        assertThrows(MdlException.class, () -> SessionTranscript.fromCbor(cbor));
    }

    @Test
    void testFromCbor_TooFewElements() {
        // 1-element array
        byte[] cbor = Cbor.encode(new Object[]{deviceEngagementBytes});
        assertThrows(MdlException.class, () -> SessionTranscript.fromCbor(cbor));
    }

    @Test
    void testFromCbor_RoundTripWithHandover() throws Exception {
        SessionTranscript original = new SessionTranscript(deviceEngagementBytes, eReaderKeyBytes, handoverBytes);
        byte[] cbor = original.toCbor();
        SessionTranscript decoded = SessionTranscript.fromCbor(cbor);

        assertArrayEquals(original.getDeviceEngagementBytes(), decoded.getDeviceEngagementBytes());
        assertArrayEquals(original.getEReaderKeyBytes(), decoded.getEReaderKeyBytes());
        assertArrayEquals(original.getHandover(), decoded.getHandover());
    }

    @Test
    void testFromCbor_RoundTripWithoutHandover() throws Exception {
        SessionTranscript original = SessionTranscript.create(deviceEngagementBytes, eReaderKeyBytes);
        byte[] cbor = original.toCbor();
        SessionTranscript decoded = SessionTranscript.fromCbor(cbor);

        assertArrayEquals(original.getDeviceEngagementBytes(), decoded.getDeviceEngagementBytes());
        assertArrayEquals(original.getEReaderKeyBytes(), decoded.getEReaderKeyBytes());
        assertFalse(decoded.hasHandover());
    }

    // -------------------------------------------------------------------------
    // Getter tests (lines 118-147)
    // -------------------------------------------------------------------------

    @Test
    void testGetDeviceEngagementBytes() {
        SessionTranscript st = new SessionTranscript(deviceEngagementBytes, eReaderKeyBytes, null);
        assertArrayEquals(deviceEngagementBytes, st.getDeviceEngagementBytes());
    }

    @Test
    void testGetDeviceEngagementBytes_DefensiveCopy() {
        SessionTranscript st = new SessionTranscript(deviceEngagementBytes, eReaderKeyBytes, null);
        byte[] returned = st.getDeviceEngagementBytes();
        returned[0] = (byte) 0xFF;
        // A second call must return the original value
        assertEquals(0x01, st.getDeviceEngagementBytes()[0]);
    }

    @Test
    void testGetEReaderKeyBytes() {
        SessionTranscript st = new SessionTranscript(deviceEngagementBytes, eReaderKeyBytes, null);
        assertArrayEquals(eReaderKeyBytes, st.getEReaderKeyBytes());
    }

    @Test
    void testGetEReaderKeyBytes_DefensiveCopy() {
        SessionTranscript st = new SessionTranscript(deviceEngagementBytes, eReaderKeyBytes, null);
        byte[] returned = st.getEReaderKeyBytes();
        returned[0] = (byte) 0xFF;
        assertEquals(0x04, st.getEReaderKeyBytes()[0]);
    }

    @Test
    void testGetHandover_WithHandover() {
        SessionTranscript st = new SessionTranscript(deviceEngagementBytes, eReaderKeyBytes, handoverBytes);
        assertArrayEquals(handoverBytes, st.getHandover());
    }

    @Test
    void testGetHandover_WithoutHandover() {
        SessionTranscript st = new SessionTranscript(deviceEngagementBytes, eReaderKeyBytes, null);
        assertNull(st.getHandover());
    }

    @Test
    void testGetHandover_DefensiveCopy() {
        SessionTranscript st = new SessionTranscript(deviceEngagementBytes, eReaderKeyBytes, handoverBytes);
        byte[] returned = st.getHandover();
        returned[0] = (byte) 0xFF;
        assertEquals(0x07, st.getHandover()[0]);
    }

    @Test
    void testHasHandover_True() {
        SessionTranscript st = new SessionTranscript(deviceEngagementBytes, eReaderKeyBytes, handoverBytes);
        assertTrue(st.hasHandover());
    }

    @Test
    void testHasHandover_False() {
        SessionTranscript st = new SessionTranscript(deviceEngagementBytes, eReaderKeyBytes, null);
        assertFalse(st.hasHandover());
    }

    // -------------------------------------------------------------------------
    // toString tests (lines 150-155)
    // -------------------------------------------------------------------------

    @Test
    void testToString_WithHandover() {
        SessionTranscript st = new SessionTranscript(deviceEngagementBytes, eReaderKeyBytes, handoverBytes);
        String s = st.toString();
        // handover.length + " bytes" should appear
        assertTrue(s.contains("bytes"));
        assertFalse(s.contains("null"));
    }

    @Test
    void testToString_WithoutHandover() {
        SessionTranscript st = new SessionTranscript(deviceEngagementBytes, eReaderKeyBytes, null);
        String s = st.toString();
        assertTrue(s.contains("null"));
    }
}
