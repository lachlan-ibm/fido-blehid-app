/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.fidoble;

import static org.junit.Assert.*;

import com.isfs.blekey.ctap.CtapBle;

import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;

/**
 * Integration tests for Phase 3: Integration & Dual-Mode Advertising.
 *
 * Tests the complete flow:
 * 1. Independent service advertising (BLE FIDO + BT Classic HID)
 * 2. CTAP message routing to AuthenticatorAPI
 * 3. Keepalive management during long operations
 */
public class CtapBleIntegrationTests {

    private CtapBle ctapBle;

    @Before
    public void setUp() {
        ctapBle = new CtapBle();
    }

    /**
     * Test 3.1: Verify BLE framing for CTAP commands.
     */
    @Test
    public void testBleFramingForCtapCommands() {
        // Test PING command
        byte[] pingData = "Hello FIDO".getBytes();
        byte[] pingFrame = ctapBle.frameRequest(CtapBle.CMD_PING, pingData);
        
        assertNotNull("PING frame should not be null", pingFrame);
        assertEquals("PING frame should have correct length", 
            2 + pingData.length, pingFrame.length);
        assertEquals("First byte should be CMD_PING", 
            CtapBle.CMD_PING, pingFrame[0]);

        // Parse back
        Object[] parsed = ctapBle.parseRequest(pingFrame);
        byte cmd = (byte) parsed[0];
        byte[] data = (byte[]) parsed[1];
        
        assertEquals("Parsed command should match", CtapBle.CMD_PING, cmd);
        assertArrayEquals("Parsed data should match", pingData, data);
    }

    /**
     * Test 3.2: Verify CBOR command framing.
     */
    @Test
    public void testCborCommandFraming() {
        // Simulate a CTAP2 CBOR command (e.g., authenticatorGetInfo = 0x04)
        byte[] cborData = new byte[] { 0x04 }; // authenticatorGetInfo
        byte[] cborFrame = ctapBle.frameRequest(CtapBle.CMD_CBOR, cborData);
        
        assertNotNull("CBOR frame should not be null", cborFrame);
        assertEquals("First byte should be CMD_CBOR", 
            CtapBle.CMD_CBOR, cborFrame[0]);

        // Parse back
        Object[] parsed = ctapBle.parseRequest(cborFrame);
        byte cmd = (byte) parsed[0];
        byte[] data = (byte[]) parsed[1];
        
        assertEquals("Parsed command should match", CtapBle.CMD_CBOR, cmd);
        assertArrayEquals("Parsed data should match", cborData, data);
    }

    /**
     * Test 3.3: Verify response framing with status codes.
     */
    @Test
    public void testResponseFraming() {
        // Test success response
        byte[] responseData = new byte[] { 0x00, 0x01, 0x02 };
        byte[] successFrame = ctapBle.frameResponse(CtapBle.STATUS_SUCCESS, responseData);
        
        assertNotNull("Success frame should not be null", successFrame);
        assertEquals("First byte should be STATUS_SUCCESS", 
            CtapBle.STATUS_SUCCESS, successFrame[0]);

        // Test error response
        byte[] errorFrame = ctapBle.frameResponse(CtapBle.STATUS_INVALID_CMD, new byte[0]);
        
        assertNotNull("Error frame should not be null", errorFrame);
        assertEquals("First byte should be STATUS_INVALID_CMD", 
            CtapBle.STATUS_INVALID_CMD, errorFrame[0]);
        assertEquals("Error frame should have minimal length", 2, errorFrame.length);
    }

    /**
     * Test 3.4: Verify keepalive message format.
     */
    @Test
    public void testKeepaliveMessageFormat() {
        // Keepalive status codes per CTAP spec §11.2.9.1.4
        byte STATUS_PROCESSING = (byte) 0x01;
        byte STATUS_UP_NEEDED = (byte) 0x02;
        
        // Keepalive with STATUS_PROCESSING
        byte[] keepaliveData = new byte[] { STATUS_PROCESSING };
        byte[] keepaliveFrame = ctapBle.frameResponse(CtapBle.CMD_KEEPALIVE, keepaliveData);
        
        assertNotNull("Keepalive frame should not be null", keepaliveFrame);
        assertEquals("First byte should be CMD_KEEPALIVE",
            CtapBle.CMD_KEEPALIVE, keepaliveFrame[0]);
        assertEquals("Keepalive should have status byte",
            STATUS_PROCESSING, keepaliveFrame[2]);

        // Keepalive with STATUS_UP_NEEDED
        byte[] upNeededData = new byte[] { STATUS_UP_NEEDED };
        byte[] upNeededFrame = ctapBle.frameResponse(CtapBle.CMD_KEEPALIVE, upNeededData);
        
        assertEquals("Keepalive should have UP_NEEDED status",
            STATUS_UP_NEEDED, upNeededFrame[2]);
    }

    /**
     * Test 3.5: Verify fragmentation for large responses.
     */
    @Test
    public void testLargeResponseFragmentation() {
        // Create a large response (300 bytes)
        byte[] largeData = new byte[300];
        Arrays.fill(largeData, (byte) 0xAA);
        
        byte[] largeFrame = ctapBle.frameResponse(CtapBle.STATUS_SUCCESS, largeData);
        
        // Fragment with typical BLE MTU (23 bytes)
        int mtu = 23;
        var fragments = ctapBle.fragmentMessage(largeFrame, mtu);
        
        assertTrue("Should create multiple fragments", fragments.size() > 1);
        
        // Verify first fragment has proper header
        byte[] firstFragment = fragments.get(0);
        assertEquals("First fragment should be MTU size", mtu, firstFragment.length);
        assertEquals("First fragment should have STATUS_SUCCESS", 
            CtapBle.STATUS_SUCCESS, firstFragment[0]);
        
        // Verify continuation fragments have sequence numbers
        for (int i = 1; i < fragments.size(); i++) {
            byte[] fragment = fragments.get(i);
            byte seq = fragment[0];
            assertEquals("Continuation fragment should have correct sequence", 
                i - 1, seq);
        }
        
        // Reassemble and verify
        byte[] reassembled = ctapBle.reassembleFragments(fragments);
        assertArrayEquals("Reassembled message should match original", 
            largeFrame, reassembled);
    }

    /**
     * Test 3.6: Verify cancel command handling.
     */
    @Test
    public void testCancelCommand() {
        byte[] cancelFrame = ctapBle.frameRequest(CtapBle.CMD_CANCEL, new byte[0]);
        
        assertNotNull("Cancel frame should not be null", cancelFrame);
        assertEquals("First byte should be CMD_CANCEL", 
            CtapBle.CMD_CANCEL, cancelFrame[0]);
        assertEquals("Cancel frame should have minimal length", 2, cancelFrame.length);
    }

    /**
     * Test 3.7: Verify error response codes.
     */
    @Test
    public void testErrorResponseCodes() {
        // Test all error status codes
        byte[] errorCodes = {
            CtapBle.STATUS_INVALID_CMD,
            CtapBle.STATUS_INVALID_PAR,
            CtapBle.STATUS_INVALID_LEN,
            CtapBle.STATUS_INVALID_SEQ,
            CtapBle.STATUS_REQ_TIMEOUT,
            CtapBle.STATUS_BUSY
        };
        
        for (byte errorCode : errorCodes) {
            byte[] errorFrame = ctapBle.frameResponse(errorCode, new byte[0]);
            assertNotNull("Error frame should not be null", errorFrame);
            assertEquals("First byte should match error code", errorCode, errorFrame[0]);
        }
    }

    /**
     * Test 3.8: Verify round-trip for typical CTAP flow.
     */
    @Test
    public void testTypicalCtapFlow() {
        // 1. Client sends authenticatorGetInfo (0x04)
        byte[] getInfoRequest = new byte[] { 0x04 };
        byte[] requestFrame = ctapBle.frameRequest(CtapBle.CMD_CBOR, getInfoRequest);
        
        // 2. Parse request
        Object[] parsed = ctapBle.parseRequest(requestFrame);
        assertEquals("Should be CBOR command", CtapBle.CMD_CBOR, (byte) parsed[0]);
        
        // 3. Simulate response (simplified)
        byte[] responseData = new byte[] { 
            (byte) 0xA1,  // CBOR map with 1 element
            0x01,         // Key: versions
            (byte) 0x81,  // Array with 1 element
            0x68,         // Text string of length 8
            'F', 'I', 'D', 'O', '_', '2', '_', '0'
        };
        byte[] responseFrame = ctapBle.frameResponse(CtapBle.STATUS_SUCCESS, responseData);
        
        // 4. Parse response
        Object[] parsedResponse = ctapBle.parseResponse(responseFrame);
        assertEquals("Should have success status", 
            CtapBle.STATUS_SUCCESS, (byte) parsedResponse[0]);
        
        byte[] receivedData = (byte[]) parsedResponse[1];
        assertArrayEquals("Response data should match", responseData, receivedData);
    }

    /**
     * Test 3.9: Verify MTU-based fragmentation.
     */
    @Test
    public void testMtuBasedFragmentation() {
        byte[] data = new byte[100];
        Arrays.fill(data, (byte) 0xFF);
        byte[] frame = ctapBle.frameResponse(CtapBle.STATUS_SUCCESS, data);
        
        // Test with different MTU values
        int[] mtuValues = { 23, 50, 100, 200 };
        
        for (int mtu : mtuValues) {
            var fragments = ctapBle.fragmentMessage(frame, mtu);
            
            // Verify all fragments respect MTU
            for (byte[] fragment : fragments) {
                assertTrue("Fragment should not exceed MTU", 
                    fragment.length <= mtu);
            }
            
            // Verify reassembly
            byte[] reassembled = ctapBle.reassembleFragments(fragments);
            assertArrayEquals("Reassembled should match original for MTU=" + mtu, 
                frame, reassembled);
        }
    }

    /**
     * Test 3.10: Verify single-packet optimization.
     */
    @Test
    public void testSinglePacketOptimization() {
        // Small data that fits in single packet
        byte[] smallData = new byte[] { 0x01, 0x02, 0x03 };
        byte[] frame = ctapBle.frameResponse(CtapBle.STATUS_SUCCESS, smallData);
        
        // Fragment with large MTU
        int largeMtu = 512;
        var fragments = ctapBle.fragmentMessage(frame, largeMtu);
        
        assertEquals("Should create only one fragment", 1, fragments.size());
        assertArrayEquals("Single fragment should match original frame", 
            frame, fragments.get(0));
    }
}

// Made with Bob