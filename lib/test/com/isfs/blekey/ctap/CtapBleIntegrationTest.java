/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.ctap;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * End-to-end integration tests for BLE FIDO CTAP2 framing protocol.
 * 
 * Tests the complete pipeline:
 * 1. Frame request/response
 * 2. Fragment into BLE packets
 * 3. Reassemble fragments
 * 4. Verify data integrity
 * 
 * Phase 2.6: End-to-End Framing Test
 */
public class CtapBleIntegrationTest {

    private CtapBle ctapBle;
    private Random random;

    @Before
    public void setUp() {
        ctapBle = new CtapBle();
        random = new Random(42); // Fixed seed for reproducibility
    }

    /**
     * Test end-to-end framing with PING command (small message, single packet).
     */
    @Test
    public void testEndToEndFraming_PingCommand() {
        // Create PING request with small data
        byte[] pingData = "Hello FIDO!".getBytes();
        byte[] request = ctapBle.frameRequest(CtapBle.CMD_PING, pingData);
        
        // Fragment (should be single packet for small data)
        int mtu = 23;
        List<byte[]> fragments = ctapBle.fragmentMessage(request, mtu);
        
        // Verify single packet
        assertEquals("Small message should fit in single packet", 1, fragments.size());
        
        // Reassemble
        byte[] reassembled = ctapBle.reassembleFragments(fragments);
        
        // Verify integrity
        assertArrayEquals("Reassembled message should match original", request, reassembled);
        
        // Parse and verify
        Object[] parsed = ctapBle.parseRequest(reassembled);
        assertEquals("Command should be PING", CtapBle.CMD_PING, (byte) parsed[0]);
        assertArrayEquals("Data should match", pingData, (byte[]) parsed[1]);
    }

    /**
     * Test end-to-end framing with large CBOR message (multi-packet).
     */
    @Test
    public void testEndToEndFraming_LargeCborMessage() {
        // Create large CBOR data (300 bytes)
        byte[] largeData = new byte[300];
        random.nextBytes(largeData);
        
        byte[] request = ctapBle.frameRequest(CtapBle.CMD_CBOR, largeData);
        
        // Fragment with default MTU
        int mtu = 23;
        List<byte[]> fragments = ctapBle.fragmentMessage(request, mtu);
        
        // Verify multiple packets
        assertTrue("Large message should require multiple packets", fragments.size() > 1);
        
        // Reassemble
        byte[] reassembled = ctapBle.reassembleFragments(fragments);
        
        // Verify integrity
        assertArrayEquals("Reassembled message should match original", request, reassembled);
        
        // Parse and verify
        Object[] parsed = ctapBle.parseRequest(reassembled);
        assertEquals("Command should be CBOR", CtapBle.CMD_CBOR, (byte) parsed[0]);
        assertArrayEquals("Data should match", largeData, (byte[]) parsed[1]);
    }

    /**
     * Test with MTU = 23 (minimum BLE MTU).
     */
    @Test
    public void testEndToEndFraming_MTU23() {
        testEndToEndWithMtu(23, 100);
    }

    /**
     * Test with MTU = 50.
     */
    @Test
    public void testEndToEndFraming_MTU50() {
        testEndToEndWithMtu(50, 100);
    }

    /**
     * Test with MTU = 100.
     */
    @Test
    public void testEndToEndFraming_MTU100() {
        testEndToEndWithMtu(100, 200);
    }

    /**
     * Test with MTU = 512 (maximum).
     */
    @Test
    public void testEndToEndFraming_MTU512() {
        testEndToEndWithMtu(512, 500);
    }

    /**
     * Helper method to test end-to-end framing with specific MTU.
     */
    private void testEndToEndWithMtu(int mtu, int dataSize) {
        byte[] data = new byte[dataSize];
        random.nextBytes(data);
        
        byte[] request = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        List<byte[]> fragments = ctapBle.fragmentMessage(request, mtu);
        byte[] reassembled = ctapBle.reassembleFragments(fragments);
        
        assertArrayEquals("Data integrity check for MTU=" + mtu, request, reassembled);
        
        Object[] parsed = ctapBle.parseRequest(reassembled);
        assertArrayEquals("Parsed data should match for MTU=" + mtu, data, (byte[]) parsed[1]);
    }

    /**
     * Test PING command end-to-end.
     */
    @Test
    public void testEndToEndFraming_PingCommandType() {
        byte[] data = "PING".getBytes();
        testCommandType(CtapBle.CMD_PING, data);
    }

    /**
     * Test CBOR command end-to-end.
     */
    @Test
    public void testEndToEndFraming_CborCommandType() {
        byte[] data = new byte[150];
        random.nextBytes(data);
        testCommandType(CtapBle.CMD_CBOR, data);
    }

    /**
     * Test KEEPALIVE command end-to-end.
     */
    @Test
    public void testEndToEndFraming_KeepaliveCommandType() {
        byte[] data = new byte[] { 0x01 }; // Status code
        testCommandType(CtapBle.CMD_KEEPALIVE, data);
    }

    /**
     * Helper method to test specific command type.
     */
    private void testCommandType(byte cmd, byte[] data) {
        byte[] request = ctapBle.frameRequest(cmd, data);
        List<byte[]> fragments = ctapBle.fragmentMessage(request, 23);
        byte[] reassembled = ctapBle.reassembleFragments(fragments);
        
        assertArrayEquals("Command type test failed", request, reassembled);
        
        Object[] parsed = ctapBle.parseRequest(reassembled);
        assertEquals("Command should match", cmd, (byte) parsed[0]);
        assertArrayEquals("Data should match", data, (byte[]) parsed[1]);
    }

    /**
     * Test response framing end-to-end.
     */
    @Test
    public void testEndToEndFraming_Response() {
        byte[] responseData = new byte[200];
        random.nextBytes(responseData);
        
        byte[] response = ctapBle.frameResponse(CtapBle.STATUS_SUCCESS, responseData);
        List<byte[]> fragments = ctapBle.fragmentMessage(response, 23);
        byte[] reassembled = ctapBle.reassembleFragments(fragments);
        
        assertArrayEquals("Response should match", response, reassembled);
        
        Object[] parsed = ctapBle.parseResponse(reassembled);
        assertEquals("Status should be SUCCESS", CtapBle.STATUS_SUCCESS, (byte) parsed[0]);
        assertArrayEquals("Response data should match", responseData, (byte[]) parsed[1]);
    }

    /**
     * Test with maximum message size (512 bytes).
     */
    @Test
    public void testEndToEndFraming_MaxMessageSize() {
        byte[] maxData = new byte[512];
        random.nextBytes(maxData);
        
        byte[] request = ctapBle.frameRequest(CtapBle.CMD_CBOR, maxData);
        List<byte[]> fragments = ctapBle.fragmentMessage(request, 23);
        byte[] reassembled = ctapBle.reassembleFragments(fragments);
        
        assertArrayEquals("Max size message should work", request, reassembled);
    }

    /**
     * Test with empty data.
     */
    @Test
    public void testEndToEndFraming_EmptyData() {
        byte[] emptyData = new byte[0];
        
        byte[] request = ctapBle.frameRequest(CtapBle.CMD_PING, emptyData);
        List<byte[]> fragments = ctapBle.fragmentMessage(request, 23);
        byte[] reassembled = ctapBle.reassembleFragments(fragments);
        
        assertArrayEquals("Empty data should work", request, reassembled);
        
        Object[] parsed = ctapBle.parseRequest(reassembled);
        assertEquals("Empty data length", 0, ((byte[]) parsed[1]).length);
    }

    /**
     * Test fragmentation and reassembly with simulated packet loss recovery.
     * This tests that fragments are properly ordered and can be reassembled.
     */
    @Test
    public void testEndToEndFraming_FragmentOrdering() {
        byte[] data = new byte[250];
        random.nextBytes(data);
        
        byte[] request = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        List<byte[]> fragments = ctapBle.fragmentMessage(request, 23);
        
        // Verify fragment count
        assertTrue("Should have multiple fragments", fragments.size() > 1);
        
        // Verify first fragment has proper header
        byte[] firstFragment = fragments.get(0);
        assertEquals("First fragment should have CMD", CtapBle.CMD_CBOR, firstFragment[0]);
        
        // Verify continuation fragments have sequence numbers
        for (int i = 1; i < fragments.size(); i++) {
            byte[] contFragment = fragments.get(i);
            assertEquals("Continuation fragment " + i + " should have correct SEQ", 
                (byte)(i - 1), contFragment[0]);
        }
        
        // Reassemble and verify
        byte[] reassembled = ctapBle.reassembleFragments(fragments);
        assertArrayEquals("Fragment ordering test", request, reassembled);
    }

    /**
     * Test with various data sizes to ensure robustness.
     */
    @Test
    public void testEndToEndFraming_VariousDataSizes() {
        int[] dataSizes = { 1, 10, 20, 50, 100, 200, 300, 400, 500, 512 };
        
        for (int size : dataSizes) {
            byte[] data = new byte[size];
            random.nextBytes(data);
            
            byte[] request = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
            List<byte[]> fragments = ctapBle.fragmentMessage(request, 23);
            byte[] reassembled = ctapBle.reassembleFragments(fragments);
            
            assertArrayEquals("Data size " + size + " failed", request, reassembled);
        }
    }

    /**
     * Test complete pipeline with mock connection manager simulation.
     * This simulates how BLEConnectionManager would use these methods.
     */
    @Test
    public void testEndToEndFraming_WithConnectionManagerSimulation() {
        // Simulate device sending a request
        byte[] requestData = "Authenticate me!".getBytes();
        byte[] request = ctapBle.frameRequest(CtapBle.CMD_CBOR, requestData);
        
        // Fragment for transmission
        int mtu = 23;
        List<byte[]> fragments = ctapBle.fragmentMessage(request, mtu);
        
        // Simulate receiving fragments (as BLEConnectionManager would)
        List<byte[]> receivedFragments = new ArrayList<>();
        for (byte[] fragment : fragments) {
            // Simulate adding fragment to pending list
            receivedFragments.add(fragment);
        }
        
        // Reassemble when complete
        byte[] reassembled = ctapBle.reassembleFragments(receivedFragments);
        
        // Verify
        assertArrayEquals("Connection manager simulation", request, reassembled);
        
        // Parse request
        Object[] parsed = ctapBle.parseRequest(reassembled);
        assertEquals("Command should be CBOR", CtapBle.CMD_CBOR, (byte) parsed[0]);
        assertArrayEquals("Request data should match", requestData, (byte[]) parsed[1]);
    }

    /**
     * Test bidirectional communication (request and response).
     */
    @Test
    public void testEndToEndFraming_BidirectionalCommunication() {
        // Client sends request
        byte[] requestData = "GetAssertion".getBytes();
        byte[] request = ctapBle.frameRequest(CtapBle.CMD_CBOR, requestData);
        List<byte[]> requestFragments = ctapBle.fragmentMessage(request, 23);
        byte[] reassembledRequest = ctapBle.reassembleFragments(requestFragments);
        
        assertArrayEquals("Request should match", request, reassembledRequest);
        
        // Server sends response
        byte[] responseData = new byte[100];
        random.nextBytes(responseData);
        byte[] response = ctapBle.frameResponse(CtapBle.STATUS_SUCCESS, responseData);
        List<byte[]> responseFragments = ctapBle.fragmentMessage(response, 23);
        byte[] reassembledResponse = ctapBle.reassembleFragments(responseFragments);
        
        assertArrayEquals("Response should match", response, reassembledResponse);
        
        // Verify both
        Object[] parsedRequest = ctapBle.parseRequest(reassembledRequest);
        Object[] parsedResponse = ctapBle.parseResponse(reassembledResponse);
        
        assertEquals("Request command", CtapBle.CMD_CBOR, (byte) parsedRequest[0]);
        assertEquals("Response status", CtapBle.STATUS_SUCCESS, (byte) parsedResponse[0]);
    }
}

// Made with Bob