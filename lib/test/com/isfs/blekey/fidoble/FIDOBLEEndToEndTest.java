/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.fidoble;

import static org.junit.Assert.*;

import com.isfs.blekey.ctap.CtapBle;

import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Random;

/**
 * End-to-end integration tests for BLE FIDO CTAP2 flow.
 * 
 * Complete BLE FIDO flow testing
 * 
 * Tests the complete pipeline:
 * 1. Frame CTAP command
 * 2. Fragment into BLE packets
 * 3. Reassemble fragments
 * 4. Process command
 * 5. Frame response
 * 6. Fragment response
 * 7. Reassemble response
 * 8. Verify data integrity
 * 
 * Verifies:
 * - PING command round-trip
 * - CBOR command round-trip
 * - Large message handling
 * - Error responses
 * - Keepalive messages
 */
public class FIDOBLEEndToEndTest {

    private CtapBle ctapBle;
    private Random random;

    @Before
    public void setUp() {
        ctapBle = new CtapBle();
        random = new Random(42); // Fixed seed for reproducibility
    }

    // ========== PING Command Round-Trip Tests ==========

    @Test
    public void testPingRoundTrip_EmptyData() {
        // 1. Frame PING request with empty data
        byte[] request = ctapBle.frameRequest(CtapBle.CMD_PING, null);
        
        // 2. Fragment (should be single packet)
        int mtu = 23;
        List<byte[]> requestFragments = ctapBle.fragmentMessage(request, mtu);
        
        assertEquals("Empty PING should be single packet", 1, requestFragments.size());
        
        // 3. Reassemble
        byte[] reassembledRequest = ctapBle.reassembleFragments(requestFragments);
        
        // 4. Parse request
        Object[] parsed = ctapBle.parseRequest(reassembledRequest);
        byte cmd = (byte) parsed[0];
        byte[] data = (byte[]) parsed[1];
        
        assertEquals("Command should be PING", CtapBle.CMD_PING, cmd);
        assertEquals("Data should be empty", 0, data.length);
        
        // 5. Frame response (echo data back)
        byte[] response = ctapBle.frameResponse(CtapBle.STATUS_SUCCESS, data);
        
        // 6. Fragment response
        List<byte[]> responseFragments = ctapBle.fragmentMessage(response, mtu);
        
        // 7. Reassemble response
        byte[] reassembledResponse = ctapBle.reassembleFragments(responseFragments);
        
        // 8. Verify
        assertArrayEquals("Response should match", response, reassembledResponse);
    }

    @Test
    public void testPingRoundTrip_SmallData() {
        // 1. Frame PING request
        byte[] pingData = "Hello FIDO!".getBytes();
        byte[] request = ctapBle.frameRequest(CtapBle.CMD_PING, pingData);
        
        // 2. Fragment
        int mtu = 23;
        List<byte[]> requestFragments = ctapBle.fragmentMessage(request, mtu);
        
        // 3. Reassemble
        byte[] reassembledRequest = ctapBle.reassembleFragments(requestFragments);
        
        // 4. Parse and echo
        Object[] parsed = ctapBle.parseRequest(reassembledRequest);
        byte[] echoData = (byte[]) parsed[1];
        
        // 5. Frame response
        byte[] response = ctapBle.frameResponse(CtapBle.STATUS_SUCCESS, echoData);
        
        // 6. Fragment response
        List<byte[]> responseFragments = ctapBle.fragmentMessage(response, mtu);
        
        // 7. Reassemble response
        byte[] reassembledResponse = ctapBle.reassembleFragments(responseFragments);
        
        // 8. Parse response
        Object[] responseParsed = ctapBle.parseResponse(reassembledResponse);
        byte status = (byte) responseParsed[0];
        byte[] responseData = (byte[]) responseParsed[1];
        
        // 9. Verify
        assertEquals("Status should be SUCCESS", CtapBle.STATUS_SUCCESS, status);
        assertArrayEquals("Echo data should match", pingData, responseData);
    }

    @Test
    public void testPingRoundTrip_LargeData() {
        // 1. Frame PING request with large data (300 bytes)
        byte[] pingData = new byte[300];
        random.nextBytes(pingData);
        byte[] request = ctapBle.frameRequest(CtapBle.CMD_PING, pingData);
        
        // 2. Fragment with default MTU
        int mtu = 23;
        List<byte[]> requestFragments = ctapBle.fragmentMessage(request, mtu);
        
        assertTrue("Large data should require multiple fragments",
            requestFragments.size() > 1);
        
        // 3. Reassemble
        byte[] reassembledRequest = ctapBle.reassembleFragments(requestFragments);
        
        // 4. Parse and echo
        Object[] parsed = ctapBle.parseRequest(reassembledRequest);
        byte[] echoData = (byte[]) parsed[1];
        
        // 5. Frame response
        byte[] response = ctapBle.frameResponse(CtapBle.STATUS_SUCCESS, echoData);
        
        // 6. Fragment response
        List<byte[]> responseFragments = ctapBle.fragmentMessage(response, mtu);
        
        // 7. Reassemble response
        byte[] reassembledResponse = ctapBle.reassembleFragments(responseFragments);
        
        // 8. Parse response
        Object[] responseParsed = ctapBle.parseResponse(reassembledResponse);
        byte[] responseData = (byte[]) responseParsed[1];
        
        // 9. Verify
        assertArrayEquals("Echo data should match original", pingData, responseData);
    }

    @Test
    public void testPingRoundTrip_MaximumData() {
        // 1. Frame PING request with maximum data (512 bytes)
        byte[] pingData = new byte[512];
        for (int i = 0; i < 512; i++) {
            pingData[i] = (byte) (i & 0xFF);
        }
        byte[] request = ctapBle.frameRequest(CtapBle.CMD_PING, pingData);
        
        // 2. Fragment
        int mtu = 23;
        List<byte[]> requestFragments = ctapBle.fragmentMessage(request, mtu);
        
        // 3. Reassemble
        byte[] reassembledRequest = ctapBle.reassembleFragments(requestFragments);
        
        // 4. Parse and echo
        Object[] parsed = ctapBle.parseRequest(reassembledRequest);
        byte[] echoData = (byte[]) parsed[1];
        
        // 5. Frame response
        byte[] response = ctapBle.frameResponse(CtapBle.STATUS_SUCCESS, echoData);
        
        // 6. Fragment response
        List<byte[]> responseFragments = ctapBle.fragmentMessage(response, mtu);
        
        // 7. Reassemble response
        byte[] reassembledResponse = ctapBle.reassembleFragments(responseFragments);
        
        // 8. Parse response
        Object[] responseParsed = ctapBle.parseResponse(reassembledResponse);
        byte[] responseData = (byte[]) responseParsed[1];
        
        // 9. Verify
        assertArrayEquals("Maximum data should be echoed correctly", pingData, responseData);
    }

    // ========== CBOR Command Round-Trip Tests ==========

    @Test
    public void testCborRoundTrip_GetInfo() {
        // Simulate authenticatorGetInfo command (0x04)
        byte[] cborCommand = new byte[] { 0x04 };
        
        // 1. Frame CBOR request
        byte[] request = ctapBle.frameRequest(CtapBle.CMD_CBOR, cborCommand);
        
        // 2. Fragment
        int mtu = 23;
        List<byte[]> requestFragments = ctapBle.fragmentMessage(request, mtu);
        
        // 3. Reassemble
        byte[] reassembledRequest = ctapBle.reassembleFragments(requestFragments);
        
        // 4. Parse
        Object[] parsed = ctapBle.parseRequest(reassembledRequest);
        byte cmd = (byte) parsed[0];
        byte[] data = (byte[]) parsed[1];
        
        assertEquals("Command should be CBOR", CtapBle.CMD_CBOR, cmd);
        assertArrayEquals("Data should match", cborCommand, data);
        
        // 5. Simulate response (simplified CBOR map)
        byte[] cborResponse = new byte[] { 
            (byte) 0xA1,  // Map with 1 entry
            0x01,         // Key: versions
            (byte) 0x81,  // Array with 1 element
            0x68,         // Text string of length 8
            'F', 'I', 'D', 'O', '_', '2', '_', '0'
        };
        
        // 6. Frame response
        byte[] response = ctapBle.frameResponse(CtapBle.STATUS_SUCCESS, cborResponse);
        
        // 7. Fragment response
        List<byte[]> responseFragments = ctapBle.fragmentMessage(response, mtu);
        
        // 8. Reassemble response
        byte[] reassembledResponse = ctapBle.reassembleFragments(responseFragments);
        
        // 9. Parse response
        Object[] responseParsed = ctapBle.parseResponse(reassembledResponse);
        byte status = (byte) responseParsed[0];
        byte[] responseData = (byte[]) responseParsed[1];
        
        // 10. Verify
        assertEquals("Status should be SUCCESS", CtapBle.STATUS_SUCCESS, status);
        assertArrayEquals("Response data should match", cborResponse, responseData);
    }

    @Test
    public void testCborRoundTrip_LargeResponse() {
        // Simulate command with large CBOR response
        byte[] cborCommand = new byte[] { 0x04 };
        
        // 1. Frame request
        byte[] request = ctapBle.frameRequest(CtapBle.CMD_CBOR, cborCommand);
        
        // 2-3. Fragment and reassemble
        int mtu = 50;
        List<byte[]> requestFragments = ctapBle.fragmentMessage(request, mtu);
        byte[] reassembledRequest = ctapBle.reassembleFragments(requestFragments);
        
        // 4. Parse
        Object[] parsed = ctapBle.parseRequest(reassembledRequest);
        
        // 5. Simulate large CBOR response (200 bytes)
        byte[] largeCborResponse = new byte[200];
        random.nextBytes(largeCborResponse);
        
        // 6. Frame response
        byte[] response = ctapBle.frameResponse(CtapBle.STATUS_SUCCESS, largeCborResponse);
        
        // 7. Fragment response
        List<byte[]> responseFragments = ctapBle.fragmentMessage(response, mtu);
        
        assertTrue("Large response should require multiple fragments",
            responseFragments.size() > 1);
        
        // 8. Reassemble response
        byte[] reassembledResponse = ctapBle.reassembleFragments(responseFragments);
        
        // 9. Parse response
        Object[] responseParsed = ctapBle.parseResponse(reassembledResponse);
        byte[] responseData = (byte[]) responseParsed[1];
        
        // 10. Verify
        assertArrayEquals("Large response should match", largeCborResponse, responseData);
    }

    // ========== Error Response Tests ==========

    @Test
    public void testErrorResponse_InvalidCommand() {
        // 1. Frame invalid command
        byte[] request = ctapBle.frameRequest((byte) 0xFF, new byte[0]);
        
        // 2-3. Fragment and reassemble
        int mtu = 23;
        List<byte[]> requestFragments = ctapBle.fragmentMessage(request, mtu);
        byte[] reassembledRequest = ctapBle.reassembleFragments(requestFragments);
        
        // 4. Frame error response
        byte[] response = ctapBle.frameResponse(CtapBle.STATUS_INVALID_CMD, new byte[0]);
        
        // 5-6. Fragment and reassemble response
        List<byte[]> responseFragments = ctapBle.fragmentMessage(response, mtu);
        byte[] reassembledResponse = ctapBle.reassembleFragments(responseFragments);
        
        // 7. Parse response
        Object[] responseParsed = ctapBle.parseResponse(reassembledResponse);
        byte status = (byte) responseParsed[0];
        
        // 8. Verify
        assertEquals("Status should be INVALID_CMD", CtapBle.STATUS_INVALID_CMD, status);
    }

    @Test
    public void testErrorResponse_InvalidParameter() {
        // Frame error response with error data
        byte[] errorData = new byte[] { 0x01, 0x02 };
        byte[] response = ctapBle.frameResponse(CtapBle.STATUS_INVALID_PAR, errorData);
        
        // Fragment and reassemble
        int mtu = 23;
        List<byte[]> responseFragments = ctapBle.fragmentMessage(response, mtu);
        byte[] reassembledResponse = ctapBle.reassembleFragments(responseFragments);
        
        // Parse response
        Object[] responseParsed = ctapBle.parseResponse(reassembledResponse);
        byte status = (byte) responseParsed[0];
        byte[] responseData = (byte[]) responseParsed[1];
        
        // Verify
        assertEquals("Status should be INVALID_PAR", CtapBle.STATUS_INVALID_PAR, status);
        assertArrayEquals("Error data should match", errorData, responseData);
    }

    @Test
    public void testErrorResponse_AllErrorCodes() {
        byte[] errorCodes = {
            CtapBle.STATUS_INVALID_CMD,
            CtapBle.STATUS_INVALID_PAR,
            CtapBle.STATUS_INVALID_LEN,
            CtapBle.STATUS_INVALID_SEQ,
            CtapBle.STATUS_REQ_TIMEOUT,
            CtapBle.STATUS_BUSY
        };
        
        int mtu = 23;
        
        for (byte errorCode : errorCodes) {
            // Frame error response
            byte[] response = ctapBle.frameResponse(errorCode, new byte[0]);
            
            // Fragment and reassemble
            List<byte[]> fragments = ctapBle.fragmentMessage(response, mtu);
            byte[] reassembled = ctapBle.reassembleFragments(fragments);
            
            // Parse
            Object[] parsed = ctapBle.parseResponse(reassembled);
            byte status = (byte) parsed[0];
            
            // Verify
            assertEquals("Status should match error code", errorCode, status);
        }
    }

    // ========== Keepalive Message Tests ==========

    @Test
    public void testKeepalive_Processing() {
        // Frame keepalive with PROCESSING status
        byte STATUS_PROCESSING = (byte) 0x01;
        byte[] keepaliveData = new byte[] { STATUS_PROCESSING };
        byte[] keepalive = ctapBle.frameResponse(CtapBle.CMD_KEEPALIVE, keepaliveData);
        
        // Fragment and reassemble
        int mtu = 23;
        List<byte[]> fragments = ctapBle.fragmentMessage(keepalive, mtu);
        byte[] reassembled = ctapBle.reassembleFragments(fragments);
        
        // Parse
        Object[] parsed = ctapBle.parseResponse(reassembled);
        byte cmd = (byte) parsed[0];
        byte[] data = (byte[]) parsed[1];
        
        // Verify
        assertEquals("Command should be KEEPALIVE", CtapBle.CMD_KEEPALIVE, cmd);
        assertEquals("Should have 1 byte data", 1, data.length);
        assertEquals("Status should be PROCESSING", STATUS_PROCESSING, data[0]);
    }

    @Test
    public void testKeepalive_UserPresenceNeeded() {
        // Frame keepalive with UP_NEEDED status
        byte STATUS_UP_NEEDED = (byte) 0x02;
        byte[] keepaliveData = new byte[] { STATUS_UP_NEEDED };
        byte[] keepalive = ctapBle.frameResponse(CtapBle.CMD_KEEPALIVE, keepaliveData);
        
        // Fragment and reassemble
        int mtu = 23;
        List<byte[]> fragments = ctapBle.fragmentMessage(keepalive, mtu);
        byte[] reassembled = ctapBle.reassembleFragments(fragments);
        
        // Parse
        Object[] parsed = ctapBle.parseResponse(reassembled);
        byte[] data = (byte[]) parsed[1];
        
        // Verify
        assertEquals("Status should be UP_NEEDED", STATUS_UP_NEEDED, data[0]);
    }

    // ========== Large Message Handling Tests ==========

    @Test
    public void testLargeMessage_VariousMTUs() {
        // Create large message (400 bytes)
        byte[] largeData = new byte[400];
        random.nextBytes(largeData);
        byte[] request = ctapBle.frameRequest(CtapBle.CMD_CBOR, largeData);
        
        int[] mtuSizes = { 23, 50, 100, 247 };
        
        for (int mtu : mtuSizes) {
            // Fragment
            List<byte[]> fragments = ctapBle.fragmentMessage(request, mtu);
            
            // Reassemble
            byte[] reassembled = ctapBle.reassembleFragments(fragments);
            
            // Parse
            Object[] parsed = ctapBle.parseRequest(reassembled);
            byte[] data = (byte[]) parsed[1];
            
            // Verify
            assertArrayEquals("Data should match for MTU " + mtu, largeData, data);
        }
    }

    @Test
    public void testLargeMessage_MaximumSize() {
        // Create maximum size message (512 bytes)
        byte[] maxData = new byte[512];
        for (int i = 0; i < 512; i++) {
            maxData[i] = (byte) (i & 0xFF);
        }
        
        // Request
        byte[] request = ctapBle.frameRequest(CtapBle.CMD_CBOR, maxData);
        
        // Fragment with minimum MTU
        int mtu = 23;
        List<byte[]> requestFragments = ctapBle.fragmentMessage(request, mtu);
        byte[] reassembledRequest = ctapBle.reassembleFragments(requestFragments);
        
        // Parse
        Object[] parsed = ctapBle.parseRequest(reassembledRequest);
        byte[] requestData = (byte[]) parsed[1];
        
        // Response
        byte[] response = ctapBle.frameResponse(CtapBle.STATUS_SUCCESS, maxData);
        List<byte[]> responseFragments = ctapBle.fragmentMessage(response, mtu);
        byte[] reassembledResponse = ctapBle.reassembleFragments(responseFragments);
        
        // Parse response
        Object[] responseParsed = ctapBle.parseResponse(reassembledResponse);
        byte[] responseData = (byte[]) responseParsed[1];
        
        // Verify
        assertArrayEquals("Request data should match", maxData, requestData);
        assertArrayEquals("Response data should match", maxData, responseData);
    }

    // ========== Complete Flow Tests ==========

    @Test
    public void testCompleteFlow_MultipleCommands() {
        int mtu = 50;
        
        // Command 1: PING
        byte[] ping1 = "Test1".getBytes();
        byte[] req1 = ctapBle.frameRequest(CtapBle.CMD_PING, ping1);
        List<byte[]> frags1 = ctapBle.fragmentMessage(req1, mtu);
        byte[] reasm1 = ctapBle.reassembleFragments(frags1);
        Object[] parsed1 = ctapBle.parseRequest(reasm1);
        byte[] resp1 = ctapBle.frameResponse(CtapBle.STATUS_SUCCESS, (byte[]) parsed1[1]);
        List<byte[]> respFrags1 = ctapBle.fragmentMessage(resp1, mtu);
        byte[] respReasm1 = ctapBle.reassembleFragments(respFrags1);
        Object[] respParsed1 = ctapBle.parseResponse(respReasm1);
        
        assertArrayEquals("PING 1 should match", ping1, (byte[]) respParsed1[1]);
        
        // Command 2: CBOR
        byte[] cbor = new byte[] { 0x04 };
        byte[] req2 = ctapBle.frameRequest(CtapBle.CMD_CBOR, cbor);
        List<byte[]> frags2 = ctapBle.fragmentMessage(req2, mtu);
        byte[] reasm2 = ctapBle.reassembleFragments(frags2);
        Object[] parsed2 = ctapBle.parseRequest(reasm2);
        
        assertEquals("CBOR command should match", CtapBle.CMD_CBOR, (byte) parsed2[0]);
        
        // Command 3: PING with large data
        byte[] ping3 = new byte[200];
        random.nextBytes(ping3);
        byte[] req3 = ctapBle.frameRequest(CtapBle.CMD_PING, ping3);
        List<byte[]> frags3 = ctapBle.fragmentMessage(req3, mtu);
        byte[] reasm3 = ctapBle.reassembleFragments(frags3);
        Object[] parsed3 = ctapBle.parseRequest(reasm3);
        byte[] resp3 = ctapBle.frameResponse(CtapBle.STATUS_SUCCESS, (byte[]) parsed3[1]);
        List<byte[]> respFrags3 = ctapBle.fragmentMessage(resp3, mtu);
        byte[] respReasm3 = ctapBle.reassembleFragments(respFrags3);
        Object[] respParsed3 = ctapBle.parseResponse(respReasm3);
        
        assertArrayEquals("PING 3 should match", ping3, (byte[]) respParsed3[1]);
    }

    @Test
    public void testCompleteFlow_DataIntegrity() {
        // Test data integrity across multiple round-trips
        int mtu = 23;
        
        for (int size = 10; size <= 512; size += 50) {
            byte[] data = new byte[size];
            random.nextBytes(data);
            
            // Request
            byte[] request = ctapBle.frameRequest(CtapBle.CMD_PING, data);
            List<byte[]> reqFrags = ctapBle.fragmentMessage(request, mtu);
            byte[] reqReasm = ctapBle.reassembleFragments(reqFrags);
            Object[] reqParsed = ctapBle.parseRequest(reqReasm);
            
            // Response
            byte[] response = ctapBle.frameResponse(CtapBle.STATUS_SUCCESS, (byte[]) reqParsed[1]);
            List<byte[]> respFrags = ctapBle.fragmentMessage(response, mtu);
            byte[] respReasm = ctapBle.reassembleFragments(respFrags);
            Object[] respParsed = ctapBle.parseResponse(respReasm);
            
            // Verify
            assertArrayEquals("Data integrity should be maintained for size " + size,
                data, (byte[]) respParsed[1]);
        }
    }
}

// Made with Bob
