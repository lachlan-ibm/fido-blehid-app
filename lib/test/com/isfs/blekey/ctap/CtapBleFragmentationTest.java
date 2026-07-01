/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.ctap;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import java.util.List;

/**
 * Unit tests for CtapBle fragmentation functionality (multi-packet).
 * Tests Sub-Phase 2.3: BLE Fragmentation Logic
 */
public class CtapBleFragmentationTest {

    private CtapBle ctapBle;

    @BeforeEach
    public void setUp() {
        ctapBle = new CtapBle();
    }

    // ========== Single Packet Tests (no fragmentation needed) ==========

    @Test
    public void testFragmentMessage_SinglePacket_SmallMessage() {
        byte[] data = new byte[] { 0x01, 0x02, 0x03 };
        byte[] message = ctapBle.frameRequest(CtapBle.CMD_PING, data);
        
        List<byte[]> fragments = ctapBle.fragmentMessage(message, 23);
        
        assertNotNull(fragments);
        assertEquals(1, fragments.size());
        assertArrayEquals(message, fragments.get(0));
    }

    @Test
    public void testFragmentMessage_SinglePacket_ExactMTU() {
        byte[] data = new byte[21]; // 21 + 2 (header) = 23 (MTU)
        Arrays.fill(data, (byte) 0xAA);
        byte[] message = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        
        List<byte[]> fragments = ctapBle.fragmentMessage(message, 23);
        
        assertEquals(1, fragments.size());
        assertArrayEquals(message, fragments.get(0));
    }

    // ========== Multi-Packet Fragmentation Tests ==========

    @Test
    public void testFragmentMessage_TwoPackets_MTU23() {
        // Create message that requires 2 packets
        byte[] data = new byte[30]; // Exceeds single MTU-2
        Arrays.fill(data, (byte) 0xBB);
        byte[] message = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        
        List<byte[]> fragments = ctapBle.fragmentMessage(message, 23);
        
        assertNotNull(fragments);
        assertEquals(2, fragments.size());
        
        // First fragment: [CMD] [HLEN] [LLEN] [DATA(20)]
        byte[] first = fragments.get(0);
        assertEquals(23, first.length);
        assertEquals(CtapBle.CMD_CBOR, first[0]);
        assertEquals(0, first[1]); // HLEN
        assertEquals(30, first[2] & 0xFF); // LLEN = 30
        
        // Continuation fragment: [SEQ] [DATA(10)]
        byte[] cont = fragments.get(1);
        assertEquals(11, cont.length); // 1 + 10 remaining bytes
        assertEquals(0, cont[0]); // SEQ = 0
    }

    @Test
    public void testFragmentMessage_MultiplePackets_MTU50() {
        // Create 150-byte data
        byte[] data = new byte[150];
        Arrays.fill(data, (byte) 0xCC);
        byte[] message = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        
        List<byte[]> fragments = ctapBle.fragmentMessage(message, 50);
        
        assertNotNull(fragments);
        // First: 47 bytes, Cont1: 49 bytes, Cont2: 49 bytes, Cont3: 5 bytes
        assertEquals(4, fragments.size());
        
        // Verify first fragment
        assertEquals(50, fragments.get(0).length);
        assertEquals(CtapBle.CMD_CBOR, fragments.get(0)[0]);
        
        // Verify continuation sequences
        assertEquals(0, fragments.get(1)[0]); // SEQ = 0
        assertEquals(1, fragments.get(2)[0]); // SEQ = 1
        assertEquals(2, fragments.get(3)[0]); // SEQ = 2
    }

    @Test
    public void testFragmentMessage_LargeMessage_MTU512() {
        // Create 500-byte data (fits in single packet with MTU 512)
        byte[] data = new byte[500];
        Arrays.fill(data, (byte) 0xDD);
        byte[] message = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        
        List<byte[]> fragments = ctapBle.fragmentMessage(message, 512);
        
        assertEquals(1, fragments.size());
        assertArrayEquals(message, fragments.get(0));
    }

    @Test
    public void testFragmentMessage_VeryLargeMessage_MTU100() {
        // Create 512-byte data (maximum allowed)
        byte[] data = new byte[512];
        Arrays.fill(data, (byte) 0xEE);
        byte[] message = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        
        List<byte[]> fragments = ctapBle.fragmentMessage(message, 100);
        
        assertNotNull(fragments);
        assertTrue(fragments.size() > 1);
        
        // Verify all fragments have valid structure
        for (int i = 0; i < fragments.size(); i++) {
            byte[] frag = fragments.get(i);
            assertNotNull(frag);
            assertTrue(frag.length > 0);
            
            if (i == 0) {
                // First fragment has CMD/HLEN/LLEN
                assertTrue(frag.length >= 3);
            } else {
                // Continuation has SEQ
                assertEquals(i - 1, frag[0]); // Verify sequence
            }
        }
    }

    // ========== Reassembly Tests ==========

    @Test
    public void testReassembleFragments_SinglePacket() {
        byte[] data = new byte[] { 0x01, 0x02, 0x03 };
        byte[] original = ctapBle.frameRequest(CtapBle.CMD_PING, data);
        
        List<byte[]> fragments = ctapBle.fragmentMessage(original, 23);
        byte[] reassembled = ctapBle.reassembleFragments(fragments);
        
        assertArrayEquals(original, reassembled);
    }

    @Test
    public void testReassembleFragments_TwoPackets() {
        byte[] data = new byte[30];
        Arrays.fill(data, (byte) 0xAA);
        byte[] original = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        
        List<byte[]> fragments = ctapBle.fragmentMessage(original, 23);
        byte[] reassembled = ctapBle.reassembleFragments(fragments);
        
        assertArrayEquals(original, reassembled);
    }

    @Test
    public void testReassembleFragments_MultiplePackets() {
        byte[] data = new byte[200];
        Arrays.fill(data, (byte) 0xBB);
        byte[] original = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        
        List<byte[]> fragments = ctapBle.fragmentMessage(original, 50);
        byte[] reassembled = ctapBle.reassembleFragments(fragments);
        
        assertArrayEquals(original, reassembled);
    }

    @Test
    public void testReassembleFragments_MaxSize() {
        byte[] data = new byte[512];
        Arrays.fill(data, (byte) 0xCC);
        byte[] original = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        
        List<byte[]> fragments = ctapBle.fragmentMessage(original, 100);
        byte[] reassembled = ctapBle.reassembleFragments(fragments);
        
        assertArrayEquals(original, reassembled);
    }

    // ========== Round-trip Tests with Various MTU Sizes ==========

    @Test
    public void testRoundTrip_MTU23() {
        testRoundTripWithMTU(23, 50);
    }

    @Test
    public void testRoundTrip_MTU50() {
        testRoundTripWithMTU(50, 150);
    }

    @Test
    public void testRoundTrip_MTU100() {
        testRoundTripWithMTU(100, 300);
    }

    @Test
    public void testRoundTrip_MTU512() {
        testRoundTripWithMTU(512, 512);
    }

    private void testRoundTripWithMTU(int mtu, int dataSize) {
        byte[] data = new byte[dataSize];
        Arrays.fill(data, (byte) 0xFF);
        byte[] original = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        
        List<byte[]> fragments = ctapBle.fragmentMessage(original, mtu);
        byte[] reassembled = ctapBle.reassembleFragments(fragments);
        
        assertArrayEquals(original, reassembled);
    }

    // ========== Error Cases ==========

    @Test
    public void testFragmentMessage_NullMessage() {
        assertThrows(IllegalArgumentException.class, () -> {
            ctapBle.fragmentMessage(null, 23);
        });
    }

    @Test
    public void testFragmentMessage_MessageTooShort() {
        byte[] message = new byte[] { 0x01 }; // Only 1 byte
        
        assertThrows(IllegalArgumentException.class, () -> {
            ctapBle.fragmentMessage(message, 23);
        });
    }

    @Test
    public void testFragmentMessage_MTUTooSmall() {
        byte[] data = new byte[] { 0x01, 0x02 };
        byte[] message = ctapBle.frameRequest(CtapBle.CMD_PING, data);
        
        assertThrows(IllegalArgumentException.class, () -> {
            ctapBle.fragmentMessage(message, 3); // MTU < 4 (header size)
        });
    }

    @Test
    public void testReassembleFragments_NullFragments() {
        assertThrows(IllegalArgumentException.class, () -> {
            ctapBle.reassembleFragments(null);
        });
    }

    @Test
    public void testReassembleFragments_EmptyFragments() {
        assertThrows(IllegalArgumentException.class, () -> {
            ctapBle.reassembleFragments(Arrays.asList());
        });
    }

    @Test
    public void testReassembleFragments_FirstFragmentTooShort() {
        List<byte[]> fragments = Arrays.asList(
            new byte[] { 0x01, 0x02 } // Too short for multi-packet
        );
        
        // Should work for single packet
        byte[] result = ctapBle.reassembleFragments(fragments);
        assertNotNull(result);
    }

    @Test
    public void testReassembleFragments_SequenceMismatch() {
        // Create valid first fragment
        byte[] first = new byte[] { CtapBle.CMD_PING, 0x00, 0x0A, 0x01, 0x02 };
        
        // Create continuation with wrong sequence
        byte[] cont = new byte[] { 0x05, 0x03, 0x04 }; // SEQ = 5 (should be 0)
        
        List<byte[]> fragments = Arrays.asList(first, cont);
        
        assertThrows(IllegalArgumentException.class, () -> {
            ctapBle.reassembleFragments(fragments);
        });
    }

    // ========== Sequence Number Tests ==========

    @Test
    public void testFragmentMessage_SequenceNumbering() {
        // Create large message requiring many fragments
        byte[] data = new byte[300];
        Arrays.fill(data, (byte) 0xAA);
        byte[] message = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        
        List<byte[]> fragments = ctapBle.fragmentMessage(message, 30);
        
        // Verify sequence numbers are sequential
        for (int i = 1; i < fragments.size(); i++) {
            byte seq = fragments.get(i)[0];
            assertEquals(i - 1, seq, "Sequence number mismatch at fragment " + i);
        }
    }

    @Test
    public void testFragmentMessage_SequenceOverflow() {
        // This would require a message large enough to need >128 fragments
        // With MTU=23, first fragment has 20 bytes, continuations have 22 bytes
        // To exceed 127 sequences: 20 + (127 * 22) = 2814 bytes
        // But max message is 512 bytes, so this can't happen in practice
        
        // Test that we handle the theoretical case
        byte[] data = new byte[512];
        Arrays.fill(data, (byte) 0xFF);
        byte[] message = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        
        // With MTU 23, this should work fine (< 128 fragments)
        List<byte[]> fragments = ctapBle.fragmentMessage(message, 23);
        assertNotNull(fragments);
        assertTrue(fragments.size() < 128);
    }

    // ========== Data Integrity Tests ==========

    @Test
    public void testDataIntegrity_AllBytes() {
        // Test that all byte values are preserved
        byte[] data = new byte[256];
        for (int i = 0; i < 256; i++) {
            data[i] = (byte) i;
        }
        
        byte[] original = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        List<byte[]> fragments = ctapBle.fragmentMessage(original, 50);
        byte[] reassembled = ctapBle.reassembleFragments(fragments);
        
        assertArrayEquals(original, reassembled);
        
        // Verify data portion
        Object[] parsed = ctapBle.parseRequest(reassembled);
        assertArrayEquals(data, (byte[]) parsed[1]);
    }

    @Test
    public void testDataIntegrity_RandomData() {
        // Test with pseudo-random data
        byte[] data = new byte[400];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) ((i * 7 + 13) % 256);
        }
        
        byte[] original = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        List<byte[]> fragments = ctapBle.fragmentMessage(original, 75);
        byte[] reassembled = ctapBle.reassembleFragments(fragments);
        
        assertArrayEquals(original, reassembled);
    }
}

// Made with Bob