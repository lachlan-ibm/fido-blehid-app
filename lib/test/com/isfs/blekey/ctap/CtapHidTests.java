/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.ctap;

import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

import org.junit.Test;

public class CtapHidTests {
    
    // Channel ID for testing
    private static final byte[] TEST_CID = new byte[] {0x01, 0x02, 0x03, 0x04};
    
    /**
     * Creates an init packet (command frame) with the specified parameters
     *
     * @param cid Channel ID (4 bytes)
     * @param cmd Command type (CtapHidCmd)
     * @param dataLength Length of the payload data
     * @param data Payload data
     * @return Complete init packet as byte array
     */
    private byte[] createInitPacket(byte[] cid, CtapHidCmd cmd, int dataLength, byte[] data) {
        ByteBuffer buffer = ByteBuffer.allocate(64); // Max size of CTAP HID frame
        
        // Write channel ID (4 bytes)
        buffer.put(cid);
        
        // Write command (1 byte)
        buffer.put((byte) cmd.getValue());
        
        // Write data length (2 bytes, big-endian)
        buffer.put((byte) ((dataLength >> 8) & 0xFF));
        buffer.put((byte) (dataLength & 0xFF));
        
        // Write payload data
        if (data != null) {
            buffer.put(data);
        }
        
        // Return the filled buffer as byte array
        byte[] packet = new byte[buffer.position()];
        buffer.rewind();
        buffer.get(packet);
        return packet;
    }
    
    /**
     * Creates a sequence packet with the specified parameters
     *
     * @param cid Channel ID (4 bytes)
     * @param sequenceNum Sequence number (0-127)
     * @param data Payload data
     * @return Complete sequence packet as byte array
     */
    private byte[] createSequencePacket(byte[] cid, int sequenceNum, byte[] data) {
        ByteBuffer buffer = ByteBuffer.allocate(64); // Max size of CTAP HID frame
        
        // Write channel ID (4 bytes)
        buffer.put(cid);
        
        // Write sequence number (1 byte)
        buffer.put((byte) (sequenceNum & 0x7F)); // Ensure it's 7 bits
        
        // Write payload data
        if (data != null) {
            buffer.put(data);
        }
        
        // Return the filled buffer as byte array
        byte[] packet = new byte[buffer.position()];
        buffer.rewind();
        buffer.get(packet);
        return packet;
    }
    
    @Test
    public void initPacketTest() {
        // Create a test INIT packet (for PING command)
        byte[] pingData = "Hello CTAP".getBytes();
        byte[] initPacket = createInitPacket(TEST_CID, CtapHidCmd.PING, pingData.length, pingData);
        
        // Create CtapHid instance with the init packet
        CtapHid ctapHid = new CtapHid(initPacket);
        
        // Verify the channel ID was extracted correctly
        assertArrayEquals("Channel ID should match", TEST_CID, ctapHid.getCid());
        
        // Verify the message type was extracted correctly
        assertEquals("Message type should be PING", CtapHidCmd.PING, ctapHid.getCmd());
        
        // Verify the byte count was extracted correctly
        assertEquals("Byte count should match data length", pingData.length, ctapHid.getSize());
        
        try {
            // Process the message (should generate a response)
            ctapHid.processMessage();
            
            // Verify response is ready
            assertTrue("Response should be ready", ctapHid.isResponseReady());
            
            // Get the response segment
            byte[] response = ctapHid.getResponseSegment();
            
            // Verify response is not null
            assertNotNull("Response should not be null", response);
            
            // Verify response length (should be 64 bytes for CTAP HID)
            assertEquals("Response length should be 64 bytes", 64, response.length);
            
            // Verify response channel ID
            byte[] responseCid = Arrays.copyOfRange(response, 0, 4);
            assertArrayEquals("Response channel ID should match", TEST_CID, responseCid);
            
            // Verify response command (should be PING for echo)
            assertEquals("Response command should be PING", CtapHidCmd.PING.getValue(), response[4] & 0xFF);
            
            // Extract response data length
            int responseLength = ((response[5] & 0xFF) << 8) | (response[6] & 0xFF);
            assertEquals("Response data length should match", pingData.length, responseLength);
            
            // Extract and verify response data (should echo the ping data)
            byte[] responseData = Arrays.copyOfRange(response, 7, 7 + pingData.length);
            assertArrayEquals("Response data should match ping data", pingData, responseData);
            
        } catch (Exception e) {
            fail("Exception should not be thrown: " + e.getMessage());
        }
    }

    /**
     * Constants for CTAP HID packet sizes and structure
     */
    private static final int MAX_PACKET_SIZE = 64;
    private static final int INIT_PACKET_HEADER_SIZE = 7; // 4 bytes CID + 1 byte cmd + 2 bytes length
    private static final int SEQUENCE_PACKET_HEADER_SIZE = 5; // 4 bytes CID + 1 byte sequence number
    private static final int INIT_PACKET_DATA_SIZE = MAX_PACKET_SIZE - INIT_PACKET_HEADER_SIZE;
    private static final int SEQUENCE_PACKET_DATA_SIZE = MAX_PACKET_SIZE - SEQUENCE_PACKET_HEADER_SIZE;

    /**
     * Generates a test payload of the specified size filled with a test pattern
     *
     * @param size Size of the payload to generate
     * @return Byte array containing the test payload
     */
    private byte[] generateTestPayload(int size) {
        byte[] payload = new byte[size];
        Arrays.fill(payload, (byte) 0xAA); // Fill with a test pattern
        return payload;
    }

    /**
     * Creates and processes an init packet with the first portion of the payload
     *
     * @param payload The complete payload
     * @return CtapHid instance initialized with the init packet
     */
    private CtapHid processInitPacket(byte[] payload) {
        // Calculate how much data fits in the init packet
        int initDataSize = Math.min(payload.length, INIT_PACKET_DATA_SIZE);
        
        // Create the init packet with the first part of the data
        byte[] initData = Arrays.copyOfRange(payload, 0, initDataSize);
        byte[] initPacket = createInitPacket(TEST_CID, CtapHidCmd.PING, payload.length, initData);
        
        // Create and return the CtapHid instance
        return new CtapHid(initPacket);
    }

    /**
     * Creates and processes sequence packets for the remaining payload data
     *
     * @param ctapHid The CtapHid instance to process sequence packets
     * @param payload The complete payload
     */
    private void processSequencePackets(CtapHid ctapHid, byte[] payload) {
        // Skip if payload fits entirely in init packet
        if (payload.length <= INIT_PACKET_DATA_SIZE) {
            return;
        }
        
        int offset = INIT_PACKET_DATA_SIZE;
        int sequenceNum = 0;
        
        while (offset < payload.length) {
            // Calculate size of this sequence packet's data
            int dataSize = Math.min(SEQUENCE_PACKET_DATA_SIZE, payload.length - offset);
            
            // Create sequence data and packet
            byte[] sequenceData = Arrays.copyOfRange(payload, offset, offset + dataSize);
            byte[] sequencePacket = createSequencePacket(TEST_CID, sequenceNum, sequenceData);
            
            // Process the sequence packet
            ctapHid.processSequence(sequencePacket);
            
            // Update for next packet
            offset += dataSize;
            sequenceNum++;
        }
    }

    /**
     * Verifies that the data extracted from the CtapHid instance matches the original payload
     *
     * @param ctapHid The CtapHid instance
     * @param expectedPayload The original payload for comparison
     * @throws IOException If an error occurs during data extraction
     */
    private void verifyDataExtraction(CtapHid ctapHid, byte[] expectedPayload) throws IOException {
        assertTrue("Should have sufficient bytes", ctapHid.hasSufficientBytes());
        byte[] extractedData = ctapHid.getCtapHidData();
        assertArrayEquals("Extracted data should match original payload", expectedPayload, extractedData);
    }

    /**
     * Verifies the response handling for the processed message
     *
     * @param ctapHid The CtapHid instance
     * @param expectedSequencePackets The expected number of sequence packets in the response
     * @throws IOException If an error occurs during response processing
     */
    private void verifyResponseHandling(CtapHid ctapHid, int expectedSequencePackets) throws Exception {
        // Process the message
        ctapHid.processMessage();
        assertTrue("Response should be ready", ctapHid.isResponseReady());
        
        // Get and verify the init response
        byte[] initResponse = ctapHid.getResponseSegment();
        assertNotNull("Init response should not be null", initResponse);
        assertEquals("Init response length should be 64 bytes", MAX_PACKET_SIZE, initResponse.length);
        
        // Check for sequence responses
        int sequenceResponseCount = 0;
        while (ctapHid.hasMoreResponses()) {
            byte[] sequenceResponse = ctapHid.getResponseSegment();
            assertNotNull("Sequence response should not be null", sequenceResponse);
            assertEquals("Sequence response length should be 64 bytes", MAX_PACKET_SIZE, sequenceResponse.length);
            sequenceResponseCount++;
        }
        
        // Verify the number of sequence responses matches expectations
        assertTrue("Number of sequence responses should match expected count",
                  sequenceResponseCount <= expectedSequencePackets);
    }

    /**
     * Tests the processing of sequence packets with a payload that requires multiple packets.
     * This test verifies that:
     * 1. The init packet and sequence packet are correctly processed
     * 2. The extracted data matches the original payload
     * 3. The response handling works correctly for multi-packet responses
     */
    @Test
    public void sequencePacketTest() {
        // Create a payload that will require multiple packets (init + sequence)
        int payloadSize = INIT_PACKET_DATA_SIZE + 10; // Slightly larger than what fits in init packet
        byte[] payload = generateTestPayload(payloadSize);
        
        // Process init packet
        CtapHid ctapHid = processInitPacket(payload);
        
        // Process sequence packets
        processSequencePackets(ctapHid, payload);
        
        try {
            // Verify data extraction
            verifyDataExtraction(ctapHid, payload);
            
            // Verify response handling
            verifyResponseHandling(ctapHid, 1); // Expect 1 sequence packet
            
        } catch (IOException e) {
            fail("IOException should not be thrown: " + e.getMessage());
        } catch (Exception e) {
            fail("Exception should not be thrown: " + e.getMessage());
        }
    }
    
    /**
     * Additional test for a small payload that fits entirely in the init packet
     */
    @Test
    public void sequencePacketTestSmallPayload() {
        // Create a payload that fits entirely in the init packet
        int payloadSize = INIT_PACKET_DATA_SIZE - 5; // Smaller than what fits in init packet
        byte[] payload = generateTestPayload(payloadSize);
        
        // Process init packet
        CtapHid ctapHid = processInitPacket(payload);
        
        // No sequence packets needed
        
        try {
            // Verify data extraction
            verifyDataExtraction(ctapHid, payload);
            
            // Verify response handling
            verifyResponseHandling(ctapHid, 0); // Expect 0 sequence packets
            
        } catch (IOException e) {
            fail("IOException should not be thrown: " + e.getMessage());
        } catch (Exception e) {
            fail("Exception should not be thrown: " + e.getMessage());
        }
    }
    
    /**
     * Additional test for a large payload that requires multiple sequence packets
     */
    @Test
    public void sequencePacketTestLargePayload() {
        // Create a payload that requires multiple sequence packets
        int payloadSize = INIT_PACKET_DATA_SIZE + SEQUENCE_PACKET_DATA_SIZE + 10;
        byte[] payload = generateTestPayload(payloadSize);
        
        // Process init packet
        CtapHid ctapHid = processInitPacket(payload);
        
        // Process sequence packets
        processSequencePackets(ctapHid, payload);
        
        try {
            // Verify data extraction
            verifyDataExtraction(ctapHid, payload);
            
            // Verify response handling
            verifyResponseHandling(ctapHid, 2); // Expect 2 sequence packets
            
        } catch (IOException e) {
            fail("IOException should not be thrown: " + e.getMessage());
        } catch (Exception e) {
            fail("Exception should not be thrown: " + e.getMessage());
        }
    }
    
    @Test
    public void testInvalidInitPacket() {
        // Test with too short packet
        byte[] tooShortPacket = new byte[5]; // Less than minimum 7 bytes
        
        try {
            new CtapHid(tooShortPacket);
            fail("Should throw IllegalArgumentException for too short packet");
        } catch (IllegalArgumentException e) {
            // Expected exception
            assertEquals("Command frame too short", e.getMessage());
        }
    }

    @Test
    public void testChannelInitialization() throws Exception {
        System.err.println("testChannelInitialization");
        byte[] payload = new byte[15];
        for (int i = 0; i < 4; i++) { //broadcast cid
            payload[i] = (byte) 0xFF;
        }
        payload[4] =  (byte) CtapHidCmd.INIT.getValue();
        payload[5] = (8 & 0xFF00) >> 8;
        payload[6] = 8 & 0xFF;
        byte[] nonce = new byte[8];
        new SecureRandom().nextBytes(nonce);
        System.arraycopy(nonce, 0, payload, 7, 8);
        System.err.println("payload :: " + Arrays.toString(payload));
        CtapHid ctapHid = new CtapHid(payload);
        assertTrue(ctapHid.hasSufficientBytes());
        ctapHid.processMessage();
        assertTrue(ctapHid.isResponseReady());
        byte[] response = ctapHid.getResponseSegment();
        System.err.println(Arrays.toString(response));
        assertTrue(response.length >= 24);
        for(int i = 0; i < 4; i++) { //broadcast cid
            assertEquals((byte) 0xFF, response[i]);
        }
        assertTrue(response[4] == CtapHidCmd.INIT.getValue()); //cmd
        assertTrue(response[6] == 17); //bcnt
        byte[] rspNonce = new byte[8];
        System.arraycopy(response, 7, rspNonce, 0, 8);
        assertTrue(Arrays.equals(nonce, rspNonce));
        //TODO verify assigned CID, device version, capabilities
    }
}
