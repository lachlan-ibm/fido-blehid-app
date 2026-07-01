/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.ctap;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;

/**
 * Unit tests for CTAP2 status code mappings in BLE transport.
 * 
 * Command/status mapping
 * 
 * Verifies:
 * - All CTAP2 status codes are correctly mapped
 * - BLE status codes match CTAP spec §11.4.4.2
 * - Error response framing is correct
 * - Keepalive status codes are properly handled
 */
public class CtapBleStatusMappingTest {

    private CtapBle ctapBle;

    @BeforeEach
    public void setUp() {
        ctapBle = new CtapBle();
    }

    // ========== BLE Status Code Constants Tests ==========

    @Test
    public void testStatusCodeConstants() {
        // Verify BLE status codes match CTAP spec §11.4.4.2
        assertEquals((byte) 0x00, CtapBle.STATUS_SUCCESS, "STATUS_SUCCESS should be 0x00");
        assertEquals((byte) 0x01, CtapBle.STATUS_INVALID_CMD, "STATUS_INVALID_CMD should be 0x01");
        assertEquals((byte) 0x02, CtapBle.STATUS_INVALID_PAR, "STATUS_INVALID_PAR should be 0x02");
        assertEquals((byte) 0x03, CtapBle.STATUS_INVALID_LEN, "STATUS_INVALID_LEN should be 0x03");
        assertEquals((byte) 0x04, CtapBle.STATUS_INVALID_SEQ, "STATUS_INVALID_SEQ should be 0x04");
        assertEquals((byte) 0x05, CtapBle.STATUS_REQ_TIMEOUT, "STATUS_REQ_TIMEOUT should be 0x05");
        assertEquals((byte) 0x06, CtapBle.STATUS_BUSY, "STATUS_BUSY should be 0x06");
    }

    @Test
    public void testCommandCodeConstants() {
        // Verify command codes match CTAP spec §8.1.9.1.1
        assertEquals((byte) 0x83, CtapBle.CMD_MSG, "CMD_MSG should be 0x83");
        assertEquals((byte) 0x90, CtapBle.CMD_CBOR, "CMD_CBOR should be 0x90");
        assertEquals((byte) 0x81, CtapBle.CMD_PING, "CMD_PING should be 0x81");
        assertEquals((byte) 0x82, CtapBle.CMD_KEEPALIVE, "CMD_KEEPALIVE should be 0x82");
        assertEquals((byte) 0x91, CtapBle.CMD_CANCEL, "CMD_CANCEL should be 0x91");
        assertEquals((byte) 0xBF, CtapBle.CMD_ERROR, "CMD_ERROR should be 0xBF");
    }

    // ========== Success Response Tests ==========

    @Test
    public void testSuccessResponse_EmptyData() {
        byte[] response = ctapBle.frameResponse(CtapBle.STATUS_SUCCESS, null);
        
        assertNotNull(response);
        assertEquals(2, response.length, "Empty success response should be 2 bytes");
        assertEquals(CtapBle.STATUS_SUCCESS, response[0], "First byte should be STATUS_SUCCESS");
        assertEquals(0, response[1], "HLEN should be 0 for empty data");
    }

    @Test
    public void testSuccessResponse_WithData() {
        byte[] data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        byte[] response = ctapBle.frameResponse(CtapBle.STATUS_SUCCESS, data);
        
        assertNotNull(response);
        assertEquals(6, response.length, "Response should be 2 + 4 bytes");
        assertEquals(CtapBle.STATUS_SUCCESS, response[0]);
        assertEquals(0, response[1], "HLEN should be 0 for small data");
        assertArrayEquals(data, Arrays.copyOfRange(response, 2, response.length));
    }

    @Test
    public void testSuccessResponse_LargeData() {
        byte[] data = new byte[300];
        Arrays.fill(data, (byte) 0xAA);
        byte[] response = ctapBle.frameResponse(CtapBle.STATUS_SUCCESS, data);
        
        assertNotNull(response);
        assertEquals(302, response.length);
        assertEquals(CtapBle.STATUS_SUCCESS, response[0]);
        assertEquals(1, response[1], "HLEN should be 1 for 300 bytes (300 >> 8 = 1)");
        assertArrayEquals(data, Arrays.copyOfRange(response, 2, response.length));
    }

    // ========== Error Response Tests ==========

    @Test
    public void testErrorResponse_InvalidCommand() {
        byte[] response = ctapBle.frameResponse(CtapBle.STATUS_INVALID_CMD, new byte[0]);
        
        assertNotNull(response);
        assertEquals(2, response.length);
        assertEquals(CtapBle.STATUS_INVALID_CMD, response[0]);
        assertEquals(0, response[1]);
    }

    @Test
    public void testErrorResponse_InvalidParameter() {
        byte[] response = ctapBle.frameResponse(CtapBle.STATUS_INVALID_PAR, new byte[0]);
        
        assertNotNull(response);
        assertEquals(CtapBle.STATUS_INVALID_PAR, response[0]);
    }

    @Test
    public void testErrorResponse_InvalidLength() {
        byte[] response = ctapBle.frameResponse(CtapBle.STATUS_INVALID_LEN, new byte[0]);
        
        assertNotNull(response);
        assertEquals(CtapBle.STATUS_INVALID_LEN, response[0]);
    }

    @Test
    public void testErrorResponse_InvalidSequence() {
        byte[] response = ctapBle.frameResponse(CtapBle.STATUS_INVALID_SEQ, new byte[0]);
        
        assertNotNull(response);
        assertEquals(CtapBle.STATUS_INVALID_SEQ, response[0]);
    }

    @Test
    public void testErrorResponse_RequestTimeout() {
        byte[] response = ctapBle.frameResponse(CtapBle.STATUS_REQ_TIMEOUT, new byte[0]);
        
        assertNotNull(response);
        assertEquals(CtapBle.STATUS_REQ_TIMEOUT, response[0]);
    }

    @Test
    public void testErrorResponse_Busy() {
        byte[] response = ctapBle.frameResponse(CtapBle.STATUS_BUSY, new byte[0]);
        
        assertNotNull(response);
        assertEquals(CtapBle.STATUS_BUSY, response[0]);
    }

    @Test
    public void testErrorResponse_WithErrorData() {
        // Some errors may include additional data
        byte[] errorData = new byte[] { 0x01, 0x02 };
        byte[] response = ctapBle.frameResponse(CtapBle.STATUS_INVALID_PAR, errorData);
        
        assertNotNull(response);
        assertEquals(4, response.length);
        assertEquals(CtapBle.STATUS_INVALID_PAR, response[0]);
        assertArrayEquals(errorData, Arrays.copyOfRange(response, 2, response.length));
    }

    // ========== Keepalive Status Tests ==========

    @Test
    public void testKeepaliveResponse_Processing() {
        // Keepalive status: 0x01 = Processing
        byte STATUS_PROCESSING = (byte) 0x01;
        byte[] keepaliveData = new byte[] { STATUS_PROCESSING };
        byte[] response = ctapBle.frameResponse(CtapBle.CMD_KEEPALIVE, keepaliveData);
        
        assertNotNull(response);
        assertEquals(3, response.length, "Keepalive should be 3 bytes");
        assertEquals(CtapBle.CMD_KEEPALIVE, response[0], "First byte should be CMD_KEEPALIVE");
        assertEquals(0, response[1], "HLEN should be 0");
        assertEquals(STATUS_PROCESSING, response[2], "Status should be PROCESSING");
    }

    @Test
    public void testKeepaliveResponse_UserPresenceNeeded() {
        // Keepalive status: 0x02 = User presence needed
        byte STATUS_UP_NEEDED = (byte) 0x02;
        byte[] keepaliveData = new byte[] { STATUS_UP_NEEDED };
        byte[] response = ctapBle.frameResponse(CtapBle.CMD_KEEPALIVE, keepaliveData);
        
        assertNotNull(response);
        assertEquals(3, response.length);
        assertEquals(CtapBle.CMD_KEEPALIVE, response[0]);
        assertEquals(STATUS_UP_NEEDED, response[2], "Status should be UP_NEEDED");
    }

    // ========== CTAP2 Status Code Mapping Tests ==========

    /**
     * Test mapping of CTAP2 status codes to BLE responses.
     * CTAP2 status codes are defined in CTAP spec §6.3.
     */
    @Test
    public void testCtap2StatusCodeMapping_Success() {
        // CTAP2_OK = 0x00
        byte ctap2Status = (byte) 0x00;
        byte[] response = ctapBle.frameResponse(ctap2Status, new byte[0]);
        
        assertEquals(CtapBle.STATUS_SUCCESS, response[0]);
    }

    @Test
    public void testCtap2StatusCodeMapping_InvalidCBOR() {
        // CTAP2_ERR_INVALID_CBOR = 0x12
        byte ctap2Status = (byte) 0x12;
        byte[] response = ctapBle.frameResponse(ctap2Status, new byte[0]);
        
        // Should be passed through as-is
        assertEquals(ctap2Status, response[0]);
    }

    @Test
    public void testCtap2StatusCodeMapping_MissingParameter() {
        // CTAP2_ERR_MISSING_PARAMETER = 0x14
        byte ctap2Status = (byte) 0x14;
        byte[] response = ctapBle.frameResponse(ctap2Status, new byte[0]);
        
        assertEquals(ctap2Status, response[0]);
    }

    @Test
    public void testCtap2StatusCodeMapping_PinRequired() {
        // CTAP2_ERR_PIN_REQUIRED = 0x36
        byte ctap2Status = (byte) 0x36;
        byte[] response = ctapBle.frameResponse(ctap2Status, new byte[0]);
        
        assertEquals(ctap2Status, response[0]);
    }

    @Test
    public void testCtap2StatusCodeMapping_PinInvalid() {
        // CTAP2_ERR_PIN_INVALID = 0x31
        byte ctap2Status = (byte) 0x31;
        byte[] response = ctapBle.frameResponse(ctap2Status, new byte[0]);
        
        assertEquals(ctap2Status, response[0]);
    }

    @Test
    public void testCtap2StatusCodeMapping_UserActionTimeout() {
        // CTAP2_ERR_USER_ACTION_TIMEOUT = 0x3A
        byte ctap2Status = (byte) 0x3A;
        byte[] response = ctapBle.frameResponse(ctap2Status, new byte[0]);
        
        assertEquals(ctap2Status, response[0]);
    }

    // ========== Edge Cases ==========

    @Test
    public void testStatusCode_AllValidValues() {
        // Test all possible status code values (0x00-0xFF)
        for (int i = 0; i <= 0xFF; i++) {
            byte status = (byte) i;
            byte[] response = ctapBle.frameResponse(status, new byte[0]);
            
            assertNotNull(response, "Response should not be null for status 0x" + 
                String.format("%02X", i));
            assertEquals(status, response[0], "Status byte should match for 0x" + 
                String.format("%02X", i));
        }
    }

    @Test
    public void testResponseFraming_MaxDataSize() {
        // Test with maximum allowed data size (512 bytes)
        byte[] maxData = new byte[512];
        Arrays.fill(maxData, (byte) 0xFF);
        
        byte[] response = ctapBle.frameResponse(CtapBle.STATUS_SUCCESS, maxData);
        
        assertNotNull(response);
        assertEquals(514, response.length, "Response should be 2 + 512 bytes");
        assertEquals(CtapBle.STATUS_SUCCESS, response[0]);
        assertEquals(2, response[1], "HLEN should be 2 for 512 bytes (512 >> 8 = 2)");
    }

    @Test
    public void testResponseFraming_ExceedsMaxSize() {
        // Test with data exceeding maximum size
        byte[] oversizedData = new byte[513];
        
        assertThrows(IllegalArgumentException.class, () -> {
            ctapBle.frameResponse(CtapBle.STATUS_SUCCESS, oversizedData);
        }, "Should throw exception for data > 512 bytes");
    }

    @Test
    public void testErrorCommand_Framing() {
        // Test CMD_ERROR command framing
        byte[] errorData = new byte[] { CtapBle.STATUS_INVALID_CMD };
        byte[] response = ctapBle.frameResponse(CtapBle.CMD_ERROR, errorData);
        
        assertNotNull(response);
        assertEquals(CtapBle.CMD_ERROR, response[0]);
        assertEquals(CtapBle.STATUS_INVALID_CMD, response[2]);
    }

    // ========== Status Code Documentation Tests ==========

    @Test
    public void testStatusCodeDocumentation() {
        // Verify that status codes are properly documented
        // This test serves as living documentation
        
        // BLE-specific status codes (§11.4.4.2)
        byte[] bleStatusCodes = {
            CtapBle.STATUS_SUCCESS,      // 0x00: Success
            CtapBle.STATUS_INVALID_CMD,  // 0x01: Invalid command
            CtapBle.STATUS_INVALID_PAR,  // 0x02: Invalid parameter
            CtapBle.STATUS_INVALID_LEN,  // 0x03: Invalid length
            CtapBle.STATUS_INVALID_SEQ,  // 0x04: Invalid sequence
            CtapBle.STATUS_REQ_TIMEOUT,  // 0x05: Request timeout
            CtapBle.STATUS_BUSY          // 0x06: Busy
        };
        
        // Verify all are unique
        for (int i = 0; i < bleStatusCodes.length; i++) {
            for (int j = i + 1; j < bleStatusCodes.length; j++) {
                assertNotEquals(bleStatusCodes[i], bleStatusCodes[j],
                    "Status codes should be unique");
            }
        }
    }

    @Test
    public void testCommandCodeDocumentation() {
        // Verify that command codes are properly documented
        
        // Command codes (§8.1.9.1.1)
        byte[] commandCodes = {
            CtapBle.CMD_PING,       // 0x81: Echo data
            CtapBle.CMD_KEEPALIVE,  // 0x82: Keepalive
            CtapBle.CMD_MSG,        // 0x83: CTAP1/U2F
            CtapBle.CMD_CBOR,       // 0x90: CTAP2 CBOR
            CtapBle.CMD_CANCEL,     // 0x91: Cancel
            CtapBle.CMD_ERROR       // 0xBF: Error
        };
        
        // Verify all are unique
        for (int i = 0; i < commandCodes.length; i++) {
            for (int j = i + 1; j < commandCodes.length; j++) {
                assertNotEquals(commandCodes[i], commandCodes[j],
                    "Command codes should be unique");
            }
        }
    }
}

// Made with Bob
