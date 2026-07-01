/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.ctap;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Random;

/**
 * Integration tests for MTU variation scenarios.
 * 
 * Tests Phase 5.2: Various MTU sizes (20-512 bytes)
 * 
 * Verifies:
 * - Correct fragmentation for different MTU sizes
 * - Reassembly works across all MTU sizes
 * - Fragment count calculations are accurate
 * - Edge cases (MTU boundaries, minimum/maximum)
 * - Performance characteristics with different MTUs
 * 
 * MTU Test Matrix:
 * - 20 bytes: Below BLE minimum (edge case)
 * - 23 bytes: BLE minimum (default)
 * - 50 bytes: Small MTU
 * - 100 bytes: Medium MTU
 * - 247 bytes: Large MTU (common maximum)
 * - 512 bytes: Maximum MTU (theoretical)
 */
public class MTUVariationIntegrationTest {

    private CtapBle ctapBle;
    private Random random;

    // Test MTU sizes
    private static final int MTU_BELOW_MIN = 20;
    private static final int MTU_MIN = 23;
    private static final int MTU_SMALL = 50;
    private static final int MTU_MEDIUM = 100;
    private static final int MTU_LARGE = 247;
    private static final int MTU_MAX = 512;

    // Test data sizes
    private static final int DATA_TINY = 10;
    private static final int DATA_SMALL = 50;
    private static final int DATA_MEDIUM = 150;
    private static final int DATA_LARGE = 300;
    private static final int DATA_MAX = 512;

    @Before
    public void setUp() {
        ctapBle = new CtapBle();
        random = new Random(42); // Fixed seed for reproducibility
    }

    // ========== MTU 23 (BLE Minimum) Tests ==========

    @Test
    public void testMTU23_TinyData() {
        byte[] data = createTestData(DATA_TINY);
        byte[] message = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        
        List<byte[]> fragments = ctapBle.fragmentMessage(message, MTU_MIN);
        
        assertEquals("Tiny data should fit in single packet", 1, fragments.size());
        verifyReassembly(message, fragments);
    }

    @Test
    public void testMTU23_SmallData() {
        byte[] data = createTestData(DATA_SMALL);
        byte[] message = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        
        List<byte[]> fragments = ctapBle.fragmentMessage(message, MTU_MIN);
        
        assertTrue("Small data should require multiple fragments", fragments.size() > 1);
        verifyFragmentSizes(fragments, MTU_MIN);
        verifyReassembly(message, fragments);
    }

    @Test
    public void testMTU23_MediumData() {
        byte[] data = createTestData(DATA_MEDIUM);
        byte[] message = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        
        List<byte[]> fragments = ctapBle.fragmentMessage(message, MTU_MIN);
        
        // Calculate expected fragments: first (20 bytes) + continuations (22 bytes each)
        int expectedFragments = calculateExpectedFragments(message.length, MTU_MIN);
        assertEquals("Fragment count should match calculation", 
            expectedFragments, fragments.size());
        verifyReassembly(message, fragments);
    }

    @Test
    public void testMTU23_LargeData() {
        byte[] data = createTestData(DATA_LARGE);
        byte[] message = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        
        List<byte[]> fragments = ctapBle.fragmentMessage(message, MTU_MIN);
        
        assertTrue("Large data should require many fragments", fragments.size() > 10);
        verifyReassembly(message, fragments);
    }

    @Test
    public void testMTU23_MaxData() {
        byte[] data = createTestData(DATA_MAX);
        byte[] message = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        
        List<byte[]> fragments = ctapBle.fragmentMessage(message, MTU_MIN);
        
        verifyFragmentSizes(fragments, MTU_MIN);
        verifySequenceNumbers(fragments);
        verifyReassembly(message, fragments);
    }

    // ========== MTU 50 (Small) Tests ==========

    @Test
    public void testMTU50_SmallData() {
        byte[] data = createTestData(DATA_SMALL);
        byte[] message = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        
        List<byte[]> fragments = ctapBle.fragmentMessage(message, MTU_SMALL);
        
        // With MTU 50, small data should fit in 1-2 packets
        assertTrue("Should require 1-2 fragments", fragments.size() <= 2);
        verifyReassembly(message, fragments);
    }

    @Test
    public void testMTU50_MediumData() {
        byte[] data = createTestData(DATA_MEDIUM);
        byte[] message = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        
        List<byte[]> fragments = ctapBle.fragmentMessage(message, MTU_SMALL);
        
        int expectedFragments = calculateExpectedFragments(message.length, MTU_SMALL);
        assertEquals("Fragment count should match", expectedFragments, fragments.size());
        verifyReassembly(message, fragments);
    }

    @Test
    public void testMTU50_LargeData() {
        byte[] data = createTestData(DATA_LARGE);
        byte[] message = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        
        List<byte[]> fragments = ctapBle.fragmentMessage(message, MTU_SMALL);
        
        verifyFragmentSizes(fragments, MTU_SMALL);
        verifyReassembly(message, fragments);
    }

    // ========== MTU 100 (Medium) Tests ==========

    @Test
    public void testMTU100_MediumData() {
        byte[] data = createTestData(DATA_MEDIUM);
        byte[] message = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        
        List<byte[]> fragments = ctapBle.fragmentMessage(message, MTU_MEDIUM);
        
        // With MTU 100, medium data should fit in 1-2 packets
        assertTrue("Should require 1-2 fragments", fragments.size() <= 2);
        verifyReassembly(message, fragments);
    }

    @Test
    public void testMTU100_LargeData() {
        byte[] data = createTestData(DATA_LARGE);
        byte[] message = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        
        List<byte[]> fragments = ctapBle.fragmentMessage(message, MTU_MEDIUM);
        
        int expectedFragments = calculateExpectedFragments(message.length, MTU_MEDIUM);
        assertEquals("Fragment count should match", expectedFragments, fragments.size());
        verifyReassembly(message, fragments);
    }

    @Test
    public void testMTU100_MaxData() {
        byte[] data = createTestData(DATA_MAX);
        byte[] message = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        
        List<byte[]> fragments = ctapBle.fragmentMessage(message, MTU_MEDIUM);
        
        verifyFragmentSizes(fragments, MTU_MEDIUM);
        verifyReassembly(message, fragments);
    }

    // ========== MTU 247 (Large) Tests ==========

    @Test
    public void testMTU247_MediumData() {
        byte[] data = createTestData(DATA_MEDIUM);
        byte[] message = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        
        List<byte[]> fragments = ctapBle.fragmentMessage(message, MTU_LARGE);
        
        assertEquals("Medium data should fit in single packet with large MTU", 
            1, fragments.size());
        verifyReassembly(message, fragments);
    }

    @Test
    public void testMTU247_LargeData() {
        byte[] data = createTestData(DATA_LARGE);
        byte[] message = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        
        List<byte[]> fragments = ctapBle.fragmentMessage(message, MTU_LARGE);
        
        // With MTU 247, large data should fit in 1-2 packets
        assertTrue("Should require 1-2 fragments", fragments.size() <= 2);
        verifyReassembly(message, fragments);
    }

    @Test
    public void testMTU247_MaxData() {
        byte[] data = createTestData(DATA_MAX);
        byte[] message = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        
        List<byte[]> fragments = ctapBle.fragmentMessage(message, MTU_LARGE);
        
        // With MTU 247, max data should fit in 2-3 packets
        assertTrue("Should require 2-3 fragments", fragments.size() <= 3);
        verifyReassembly(message, fragments);
    }

    // ========== MTU 512 (Maximum) Tests ==========

    @Test
    public void testMTU512_AllDataSizes() {
        // With maximum MTU, most data should fit in single packet
        // Note: 512 bytes data + 2 byte header = 514 bytes, which exceeds MTU 512
        int[] dataSizes = { DATA_TINY, DATA_SMALL, DATA_MEDIUM, DATA_LARGE };
        
        for (int dataSize : dataSizes) {
            byte[] data = createTestData(dataSize);
            byte[] message = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
            
            List<byte[]> fragments = ctapBle.fragmentMessage(message, MTU_MAX);
            
            assertEquals("Data up to 300 bytes should fit in single packet with MTU 512",
                1, fragments.size());
            verifyReassembly(message, fragments);
        }
        
        // Test maximum data size separately (will require 2 fragments)
        byte[] maxData = createTestData(DATA_MAX);
        byte[] maxMessage = ctapBle.frameRequest(CtapBle.CMD_CBOR, maxData);
        List<byte[]> maxFragments = ctapBle.fragmentMessage(maxMessage, MTU_MAX);
        
        assertEquals("512 byte data (514 total) should require 2 fragments with MTU 512",
            2, maxFragments.size());
        verifyReassembly(maxMessage, maxFragments);
    }

    // ========== Edge Case Tests ==========

    @Test
    public void testMTU_BoundaryConditions() {
        // Test data that exactly fills MTU boundaries
        int[] mtuSizes = { MTU_MIN, MTU_SMALL, MTU_MEDIUM, MTU_LARGE };
        
        for (int mtu : mtuSizes) {
            // Data that exactly fills one packet (mtu - 2 for header)
            byte[] exactData = createTestData(mtu - 2);
            byte[] message = ctapBle.frameRequest(CtapBle.CMD_CBOR, exactData);
            
            List<byte[]> fragments = ctapBle.fragmentMessage(message, mtu);
            
            assertEquals("Exact MTU data should fit in single packet",
                1, fragments.size());
            assertEquals("Fragment should be exactly MTU size",
                mtu, fragments.get(0).length);
            verifyReassembly(message, fragments);
        }
    }

    @Test
    public void testMTU_OffByOne() {
        // Test data that is 1 byte over MTU boundary
        int[] mtuSizes = { MTU_MIN, MTU_SMALL, MTU_MEDIUM };
        
        for (int mtu : mtuSizes) {
            // Data that is 1 byte over single packet (mtu - 2 + 1)
            byte[] overData = createTestData(mtu - 1);
            byte[] message = ctapBle.frameRequest(CtapBle.CMD_CBOR, overData);
            
            List<byte[]> fragments = ctapBle.fragmentMessage(message, mtu);
            
            assertEquals("Data 1 byte over should require 2 packets",
                2, fragments.size());
            verifyReassembly(message, fragments);
        }
    }

    @Test
    public void testMTU_RandomDataSizes() {
        // Test with random data sizes across different MTUs
        int[] mtuSizes = { MTU_MIN, MTU_SMALL, MTU_MEDIUM, MTU_LARGE };
        
        for (int mtu : mtuSizes) {
            for (int i = 0; i < 10; i++) {
                int dataSize = random.nextInt(DATA_MAX) + 1;
                byte[] data = createTestData(dataSize);
                byte[] message = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
                
                List<byte[]> fragments = ctapBle.fragmentMessage(message, mtu);
                
                assertNotNull("Fragments should not be null", fragments);
                assertTrue("Should have at least one fragment", fragments.size() > 0);
                verifyFragmentSizes(fragments, mtu);
                verifyReassembly(message, fragments);
            }
        }
    }

    // ========== Performance Comparison Tests ==========

    @Test
    public void testFragmentCountComparison() {
        // Compare fragment counts across different MTUs for same data
        byte[] data = createTestData(DATA_LARGE);
        byte[] message = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        
        int[] mtuSizes = { MTU_MIN, MTU_SMALL, MTU_MEDIUM, MTU_LARGE, MTU_MAX };
        int[] fragmentCounts = new int[mtuSizes.length];
        
        for (int i = 0; i < mtuSizes.length; i++) {
            List<byte[]> fragments = ctapBle.fragmentMessage(message, mtuSizes[i]);
            fragmentCounts[i] = fragments.size();
        }
        
        // Verify that larger MTU results in fewer fragments
        for (int i = 1; i < fragmentCounts.length; i++) {
            assertTrue("Larger MTU should result in fewer or equal fragments",
                fragmentCounts[i] <= fragmentCounts[i-1]);
        }
    }

    @Test
    public void testOverheadCalculation() {
        // Calculate overhead for different MTU sizes
        byte[] data = createTestData(DATA_MEDIUM);
        byte[] message = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        
        int[] mtuSizes = { MTU_MIN, MTU_SMALL, MTU_MEDIUM, MTU_LARGE };
        
        for (int mtu : mtuSizes) {
            List<byte[]> fragments = ctapBle.fragmentMessage(message, mtu);
            
            int totalBytes = 0;
            for (byte[] fragment : fragments) {
                totalBytes += fragment.length;
            }
            
            int overhead = totalBytes - message.length;
            int expectedOverhead = calculateExpectedOverhead(fragments.size());
            
            assertEquals("Overhead should match expected",
                expectedOverhead, overhead);
        }
    }

    // ========== Helper Methods ==========

    /**
     * Creates test data of specified size with predictable pattern.
     */
    private byte[] createTestData(int size) {
        byte[] data = new byte[size];
        for (int i = 0; i < size; i++) {
            data[i] = (byte) (i & 0xFF);
        }
        return data;
    }

    /**
     * Verifies that all fragments respect MTU size limits.
     */
    private void verifyFragmentSizes(List<byte[]> fragments, int mtu) {
        for (int i = 0; i < fragments.size(); i++) {
            byte[] fragment = fragments.get(i);
            
            if (i < fragments.size() - 1) {
                // All fragments except last should be exactly MTU size
                assertEquals("Fragment " + i + " should be MTU size",
                    mtu, fragment.length);
            } else {
                // Last fragment can be smaller
                assertTrue("Last fragment should not exceed MTU",
                    fragment.length <= mtu);
            }
        }
    }

    /**
     * Verifies sequence numbers in continuation fragments.
     */
    private void verifySequenceNumbers(List<byte[]> fragments) {
        if (fragments.size() <= 1) {
            return; // No continuation fragments
        }
        
        for (int i = 1; i < fragments.size(); i++) {
            byte[] fragment = fragments.get(i);
            byte seq = fragment[0];
            
            assertEquals("Sequence number should match fragment index",
                i - 1, seq & 0xFF);
        }
    }

    /**
     * Verifies that reassembly produces original message.
     */
    private void verifyReassembly(byte[] original, List<byte[]> fragments) {
        byte[] reassembled = ctapBle.reassembleFragments(fragments);
        
        assertNotNull("Reassembled message should not be null", reassembled);
        assertArrayEquals("Reassembled message should match original",
            original, reassembled);
    }

    /**
     * Calculates expected number of fragments for given message and MTU.
     */
    private int calculateExpectedFragments(int messageLength, int mtu) {
        if (messageLength <= mtu) {
            return 1;
        }
        
        // First fragment: mtu - 3 (CMD + HLEN + LLEN)
        int firstDataSize = mtu - 3;
        int remainingData = messageLength - 2 - firstDataSize; // -2 for CMD + HLEN
        
        if (remainingData <= 0) {
            return 1;
        }
        
        // Continuation fragments: mtu - 1 (SEQ)
        int contDataSize = mtu - 1;
        int contFragments = (remainingData + contDataSize - 1) / contDataSize;
        
        return 1 + contFragments;
    }

    /**
     * Calculates expected overhead for given number of fragments.
     */
    private int calculateExpectedOverhead(int fragmentCount) {
        if (fragmentCount == 1) {
            return 0; // No overhead for single packet
        }
        
        // First fragment adds LLEN (1 byte)
        // Each continuation adds SEQ (1 byte) but removes CMD+HLEN (-2 bytes)
        // Net: +1 for first, -1 for each continuation
        return 1 + (fragmentCount - 1);
    }
}
