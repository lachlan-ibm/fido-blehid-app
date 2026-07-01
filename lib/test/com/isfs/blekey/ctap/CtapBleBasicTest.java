/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.ctap;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;

/**
 * Unit tests for CtapBle basic framing functionality (single-packet).
 * Tests Sub-Phase 2.2: CtapBle Basic Structure
 */
public class CtapBleBasicTest {

    private CtapBle ctapBle;

    @BeforeEach
    public void setUp() {
        ctapBle = new CtapBle();
    }

    // ========== frameRequest Tests ==========

    @Test
    public void testFrameRequest_Ping_EmptyData() {
        byte[] frame = ctapBle.frameRequest(CtapBle.CMD_PING, null);
        
        assertNotNull(frame);
        assertEquals(2, frame.length); // CMD + HLEN only
        assertEquals(CtapBle.CMD_PING, frame[0]);
        assertEquals(0, frame[1]); // HLEN = 0 for empty data
    }

    @Test
    public void testFrameRequest_Ping_SmallData() {
        byte[] data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        byte[] frame = ctapBle.frameRequest(CtapBle.CMD_PING, data);
        
        assertNotNull(frame);
        assertEquals(6, frame.length); // CMD + HLEN + 4 bytes data
        assertEquals(CtapBle.CMD_PING, frame[0]);
        assertEquals(0, frame[1]); // HLEN = 0 (data.length < 256)
        assertArrayEquals(data, Arrays.copyOfRange(frame, 2, frame.length));
    }

    @Test
    public void testFrameRequest_Cbor_LargeData() {
        // Create 300-byte data (HLEN should be 1)
        byte[] data = new byte[300];
        Arrays.fill(data, (byte) 0xAA);
        
        byte[] frame = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        
        assertNotNull(frame);
        assertEquals(302, frame.length); // CMD + HLEN + 300 bytes
        assertEquals(CtapBle.CMD_CBOR, frame[0]);
        assertEquals(1, frame[1]); // HLEN = 1 (300 >> 8 = 1)
        assertArrayEquals(data, Arrays.copyOfRange(frame, 2, frame.length));
    }

    @Test
    public void testFrameRequest_MaxSize() {
        byte[] data = new byte[512]; // Maximum allowed
        Arrays.fill(data, (byte) 0xFF);
        
        byte[] frame = ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        
        assertNotNull(frame);
        assertEquals(514, frame.length);
        assertEquals(CtapBle.CMD_CBOR, frame[0]);
        assertEquals(2, frame[1]); // HLEN = 2 (512 >> 8 = 2)
    }

    @Test
    public void testFrameRequest_ExceedsMaxSize() {
        byte[] data = new byte[513]; // Exceeds maximum
        
        assertThrows(IllegalArgumentException.class, () -> {
            ctapBle.frameRequest(CtapBle.CMD_CBOR, data);
        });
    }

    // ========== frameResponse Tests ==========

    @Test
    public void testFrameResponse_Success_EmptyData() {
        byte[] frame = ctapBle.frameResponse(CtapBle.STATUS_SUCCESS, null);
        
        assertNotNull(frame);
        assertEquals(2, frame.length); // STATUS + HLEN only
        assertEquals(CtapBle.STATUS_SUCCESS, frame[0]);
        assertEquals(0, frame[1]); // HLEN = 0
    }

    @Test
    public void testFrameResponse_Success_SmallData() {
        byte[] data = new byte[] { 0x10, 0x20, 0x30 };
        byte[] frame = ctapBle.frameResponse(CtapBle.STATUS_SUCCESS, data);
        
        assertNotNull(frame);
        assertEquals(5, frame.length);
        assertEquals(CtapBle.STATUS_SUCCESS, frame[0]);
        assertEquals(0, frame[1]); // HLEN = 0
        assertArrayEquals(data, Arrays.copyOfRange(frame, 2, frame.length));
    }

    @Test
    public void testFrameResponse_Error_InvalidCommand() {
        byte[] frame = ctapBle.frameResponse(CtapBle.STATUS_INVALID_CMD, null);
        
        assertNotNull(frame);
        assertEquals(2, frame.length);
        assertEquals(CtapBle.STATUS_INVALID_CMD, frame[0]);
        assertEquals(0, frame[1]);
    }

    @Test
    public void testFrameResponse_LargeData() {
        byte[] data = new byte[400];
        Arrays.fill(data, (byte) 0xBB);
        
        byte[] frame = ctapBle.frameResponse(CtapBle.STATUS_SUCCESS, data);
        
        assertNotNull(frame);
        assertEquals(402, frame.length);
        assertEquals(CtapBle.STATUS_SUCCESS, frame[0]);
        assertEquals(1, frame[1]); // HLEN = 1 (400 >> 8 = 1)
    }

    // ========== parseRequest Tests ==========

    @Test
    public void testParseRequest_Ping() {
        byte[] data = new byte[] { 0x01, 0x02, 0x03 };
        byte[] frame = ctapBle.frameRequest(CtapBle.CMD_PING, data);
        
        Object[] parsed = ctapBle.parseRequest(frame);
        
        assertNotNull(parsed);
        assertEquals(2, parsed.length);
        assertEquals(CtapBle.CMD_PING, (byte) parsed[0]);
        assertArrayEquals(data, (byte[]) parsed[1]);
    }

    @Test
    public void testParseRequest_EmptyData() {
        byte[] frame = ctapBle.frameRequest(CtapBle.CMD_CBOR, new byte[0]);
        
        Object[] parsed = ctapBle.parseRequest(frame);
        
        assertNotNull(parsed);
        assertEquals(CtapBle.CMD_CBOR, (byte) parsed[0]);
        assertEquals(0, ((byte[]) parsed[1]).length);
    }

    @Test
    public void testParseRequest_InvalidFrame() {
        byte[] frame = new byte[] { 0x01 }; // Too short
        
        assertThrows(IllegalArgumentException.class, () -> {
            ctapBle.parseRequest(frame);
        });
    }

    // ========== parseResponse Tests ==========

    @Test
    public void testParseResponse_Success() {
        byte[] data = new byte[] { 0x11, 0x22, 0x33 };
        byte[] frame = ctapBle.frameResponse(CtapBle.STATUS_SUCCESS, data);
        
        Object[] parsed = ctapBle.parseResponse(frame);
        
        assertNotNull(parsed);
        assertEquals(2, parsed.length);
        assertEquals(CtapBle.STATUS_SUCCESS, (byte) parsed[0]);
        assertArrayEquals(data, (byte[]) parsed[1]);
    }

    @Test
    public void testParseResponse_Error() {
        byte[] frame = ctapBle.frameResponse(CtapBle.STATUS_INVALID_PAR, null);
        
        Object[] parsed = ctapBle.parseResponse(frame);
        
        assertNotNull(parsed);
        assertEquals(CtapBle.STATUS_INVALID_PAR, (byte) parsed[0]);
        assertEquals(0, ((byte[]) parsed[1]).length);
    }

    // ========== Round-trip Tests ==========

    @Test
    public void testRoundTrip_Request() {
        byte[] originalData = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };
        
        // Frame
        byte[] frame = ctapBle.frameRequest(CtapBle.CMD_CBOR, originalData);
        
        // Parse
        Object[] parsed = ctapBle.parseRequest(frame);
        
        // Verify
        assertEquals(CtapBle.CMD_CBOR, (byte) parsed[0]);
        assertArrayEquals(originalData, (byte[]) parsed[1]);
    }

    @Test
    public void testRoundTrip_Response() {
        byte[] originalData = new byte[] { 0x10, 0x20, 0x30 };
        
        // Frame
        byte[] frame = ctapBle.frameResponse(CtapBle.STATUS_SUCCESS, originalData);
        
        // Parse
        Object[] parsed = ctapBle.parseResponse(frame);
        
        // Verify
        assertEquals(CtapBle.STATUS_SUCCESS, (byte) parsed[0]);
        assertArrayEquals(originalData, (byte[]) parsed[1]);
    }

    // ========== Command Code Tests ==========

    @Test
    public void testAllCommandCodes() {
        byte[] commands = {
            CtapBle.CMD_MSG,
            CtapBle.CMD_CBOR,
            CtapBle.CMD_PING,
            CtapBle.CMD_KEEPALIVE,
            CtapBle.CMD_CANCEL,
            CtapBle.CMD_ERROR
        };
        
        for (byte cmd : commands) {
            byte[] frame = ctapBle.frameRequest(cmd, new byte[] { 0x01 });
            assertNotNull(frame);
            assertEquals(cmd, frame[0]);
        }
    }

    // ========== Status Code Tests ==========

    @Test
    public void testAllStatusCodes() {
        byte[] statuses = {
            CtapBle.STATUS_SUCCESS,
            CtapBle.STATUS_INVALID_CMD,
            CtapBle.STATUS_INVALID_PAR,
            CtapBle.STATUS_INVALID_LEN,
            CtapBle.STATUS_INVALID_SEQ,
            CtapBle.STATUS_REQ_TIMEOUT,
            CtapBle.STATUS_BUSY
        };
        
        for (byte status : statuses) {
            byte[] frame = ctapBle.frameResponse(status, new byte[] { 0x01 });
            assertNotNull(frame);
            assertEquals(status, frame[0]);
        }
    }
}

// Made with Bob