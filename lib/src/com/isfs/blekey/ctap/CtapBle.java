/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.ctap;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * BLE FIDO CTAP2 framing protocol implementation per CTAP spec §11.4.4.
 * 
 * This class handles BLE-specific framing that differs from USB HID:
 * - Variable frame size based on MTU
 * - No channel ID (per-device state)
 * 
 * Frame Format:
 * - Request:  [CMD(1)] [HLEN(1)] [DATA(0-512)]
 * - Response: [STATUS(1)] [HLEN(1)] [DATA(0-512)]
 * 
 * Fragmentation Format (when message > MTU):
 * - First Fragment:  [CMD(1)] [HLEN(1)] [LLEN(1)] [DATA(mtu-3)]
 * - Continuation:    [SEQ(1)] [DATA(mtu-1)]
 */
public class CtapBle {

    private static final Logger logger = LoggerFactory.getLogger(CtapBle.class);

    // Command codes (same as USB HID per CTAP spec §8.1.9.1.1)
    public static final byte CMD_MSG = (byte) 0x83;         // CTAP1/U2F raw message
    public static final byte CMD_CBOR = (byte) 0x90;        // CTAP2 CBOR encoded
    public static final byte CMD_PING = (byte) 0x81;        // Echo data
    public static final byte CMD_KEEPALIVE = (byte) 0x82;   // Keepalive message
    public static final byte CMD_CANCEL = (byte) 0x91;      // Cancel current operation
    public static final byte CMD_ERROR = (byte) 0xBF;       // Error response

    // Status codes (CTAP spec §11.4.4.2)
    public static final byte STATUS_SUCCESS = (byte) 0x00;
    public static final byte STATUS_INVALID_CMD = (byte) 0x01;
    public static final byte STATUS_INVALID_PAR = (byte) 0x02;
    public static final byte STATUS_INVALID_LEN = (byte) 0x03;
    public static final byte STATUS_INVALID_SEQ = (byte) 0x04;
    public static final byte STATUS_REQ_TIMEOUT = (byte) 0x05;
    public static final byte STATUS_BUSY = (byte) 0x06;

    // BLE FIDO Constants
    private static final int DEFAULT_MTU = 23;              // Default BLE MTU
    private static final int MAX_MESSAGE_SIZE = 512;        // Maximum message size per spec
    private static final int HEADER_SIZE_SINGLE = 2;        // CMD + HLEN
    private static final int HEADER_SIZE_FIRST = 3;         // CMD + HLEN + LLEN
    private static final int HEADER_SIZE_CONTINUATION = 1;  // SEQ only

    /**
     * Frames a request for BLE transport (single packet only).
     * 
     * Format: [CMD(1)] [HLEN(1)] [DATA(0-512)]
     * 
     * @param cmd Command byte (e.g., CMD_CBOR, CMD_PING)
     * @param data Data payload (can be null or empty)
     * @return Framed request packet
     * @throws IllegalArgumentException if data exceeds MAX_MESSAGE_SIZE
     */
    public byte[] frameRequest(byte cmd, byte[] data) {
        if (data == null) {
            data = new byte[0];
        }

        if (data.length > MAX_MESSAGE_SIZE) {
            throw new IllegalArgumentException(
                "Data length " + data.length + " exceeds maximum " + MAX_MESSAGE_SIZE);
        }

        // Calculate high-order length byte (HLEN)
        // HLEN = (data.length >> 8) & 0xFF for lengths > 255
        int hlen = (data.length >> 8) & 0xFF;

        ByteArrayOutputStream bos = new ByteArrayOutputStream(HEADER_SIZE_SINGLE + data.length);
        bos.write(cmd);
        bos.write(hlen);
        
        if (data.length > 0) {
            try {
                bos.write(data);
            } catch (IOException e) {
                // Should never happen with ByteArrayOutputStream
                logger.error("Unexpected IOException: {}", e.getMessage());
            }
        }

        byte[] frame = bos.toByteArray();
        logger.debug("Framed request: cmd=0x{}, hlen={}, data_len={}, total_len={}",
            String.format("%02X", cmd), hlen, data.length, frame.length);
        
        return frame;
    }

    /**
     * Frames a response for BLE transport (single packet only).
     * 
     * Format: [STATUS(1)] [HLEN(1)] [DATA(0-512)]
     * 
     * @param status Status byte (e.g., STATUS_SUCCESS)
     * @param data Data payload (can be null or empty)
     * @return Framed response packet
     * @throws IllegalArgumentException if data exceeds MAX_MESSAGE_SIZE
     */
    public byte[] frameResponse(byte status, byte[] data) {
        if (data == null) {
            data = new byte[0];
        }

        if (data.length > MAX_MESSAGE_SIZE) {
            throw new IllegalArgumentException(
                "Data length " + data.length + " exceeds maximum " + MAX_MESSAGE_SIZE);
        }

        // Calculate high-order length byte (HLEN)
        int hlen = (data.length >> 8) & 0xFF;

        ByteArrayOutputStream bos = new ByteArrayOutputStream(HEADER_SIZE_SINGLE + data.length);
        bos.write(status);
        bos.write(hlen);
        
        if (data.length > 0) {
            try {
                bos.write(data);
            } catch (IOException e) {
                // Should never happen with ByteArrayOutputStream
                logger.error("Unexpected IOException: {}", e.getMessage());
            }
        }

        byte[] frame = bos.toByteArray();
        logger.debug("Framed response: status=0x{}, hlen={}, data_len={}, total_len={}",
            String.format("%02X", status), hlen, data.length, frame.length);
        
        return frame;
    }

    /**
     * Fragments a message into multiple BLE packets based on MTU.
     * 
     * First Fragment:  [CMD(1)] [HLEN(1)] [LLEN(1)] [DATA(mtu-3)]
     * Continuation:    [SEQ(1)] [DATA(mtu-1)]
     * 
     * @param message Complete message to fragment (must include CMD/STATUS + HLEN + DATA)
     * @param mtu Maximum Transmission Unit (typically 23-512 bytes)
     * @return List of fragmented packets
     * @throws IllegalArgumentException if message is invalid or MTU too small
     */
    public List<byte[]> fragmentMessage(byte[] message, int mtu) {
        if (message == null || message.length < HEADER_SIZE_SINGLE) {
            throw new IllegalArgumentException("Message too short or null");
        }

        if (mtu < HEADER_SIZE_FIRST + 1) {
            throw new IllegalArgumentException("MTU too small: " + mtu);
        }

        List<byte[]> fragments = new ArrayList<>();

        // If message fits in single packet, return as-is
        if (message.length <= mtu) {
            fragments.add(message);
            logger.debug("Message fits in single packet: {} bytes", message.length);
            return fragments;
        }

        // Extract header and data
        byte cmdOrStatus = message[0];
        byte hlen = message[1];
        byte[] data = Arrays.copyOfRange(message, HEADER_SIZE_SINGLE, message.length);

        // Calculate low-order length byte (LLEN) for total data length
        int llen = data.length & 0xFF;

        // First fragment: [CMD] [HLEN] [LLEN] [DATA(mtu-3)]
        int firstDataSize = mtu - HEADER_SIZE_FIRST;
        byte[] firstFragment = new byte[mtu];
        firstFragment[0] = cmdOrStatus;
        firstFragment[1] = hlen;
        firstFragment[2] = (byte) llen;
        System.arraycopy(data, 0, firstFragment, HEADER_SIZE_FIRST, 
            Math.min(firstDataSize, data.length));
        fragments.add(firstFragment);

        logger.debug("First fragment: cmd=0x{}, hlen={}, llen={}, data_size={}",
            String.format("%02X", cmdOrStatus), hlen, llen, firstDataSize);

        // Continuation fragments: [SEQ] [DATA(mtu-1)]
        int offset = firstDataSize;
        int seq = 0;

        while (offset < data.length) {
            int remainingData = data.length - offset;
            int contDataSize = Math.min(mtu - HEADER_SIZE_CONTINUATION, remainingData);
            
            byte[] contFragment = new byte[HEADER_SIZE_CONTINUATION + contDataSize];
            contFragment[0] = (byte) seq;
            System.arraycopy(data, offset, contFragment, HEADER_SIZE_CONTINUATION, contDataSize);
            fragments.add(contFragment);

            logger.debug("Continuation fragment: seq={}, data_size={}", seq, contDataSize);

            offset += contDataSize;
            seq++;

            if (seq > 127) {
                throw new IllegalArgumentException("Too many fragments (seq > 127)");
            }
        }

        logger.debug("Fragmented message into {} packets (mtu={})", fragments.size(), mtu);
        return fragments;
    }

    /**
     * Reassembles fragments back into complete message.
     * 
     * @param fragments List of BLE packets to reassemble
     * @return Complete reassembled message
     * @throws IllegalArgumentException if fragments are invalid or out of order
     */
    public byte[] reassembleFragments(List<byte[]> fragments) {
        if (fragments == null || fragments.isEmpty()) {
            throw new IllegalArgumentException("No fragments to reassemble");
        }

        // Single packet case
        if (fragments.size() == 1) {
            byte[] single = fragments.get(0);
            if (single.length < HEADER_SIZE_SINGLE) {
                throw new IllegalArgumentException("Single fragment too short");
            }
            logger.debug("Single packet message: {} bytes", single.length);
            return single;
        }

        // Multi-packet case
        byte[] firstFragment = fragments.get(0);
        if (firstFragment.length < HEADER_SIZE_FIRST) {
            throw new IllegalArgumentException("First fragment too short");
        }

        byte cmdOrStatus = firstFragment[0];
        byte hlen = firstFragment[1];
        byte llen = firstFragment[2];
        
        // Calculate expected total data length
        int expectedDataLen = ((hlen & 0xFF) << 8) | (llen & 0xFF);
        
        logger.debug("Reassembling: cmd=0x{}, hlen={}, llen={}, expected_data_len={}",
            String.format("%02X", cmdOrStatus), hlen, llen, expectedDataLen);

        // Extract data from first fragment
        ByteArrayOutputStream dataStream = new ByteArrayOutputStream(expectedDataLen);
        dataStream.write(firstFragment, HEADER_SIZE_FIRST,
            firstFragment.length - HEADER_SIZE_FIRST);

        // Process continuation fragments
        for (int i = 1; i < fragments.size(); i++) {
            byte[] contFragment = fragments.get(i);
            
            if (contFragment.length < HEADER_SIZE_CONTINUATION) {
                throw new IllegalArgumentException("Continuation fragment " + i + " too short");
            }

            byte seq = contFragment[0];
            if (seq != (i - 1)) {
                throw new IllegalArgumentException(
                    "Sequence mismatch: expected " + (i - 1) + ", got " + seq);
            }

            dataStream.write(contFragment, HEADER_SIZE_CONTINUATION,
                contFragment.length - HEADER_SIZE_CONTINUATION);
        }

        byte[] data = dataStream.toByteArray();
        
        // Trim to expected length (remove any padding)
        if (data.length > expectedDataLen) {
            data = Arrays.copyOf(data, expectedDataLen);
        }

        // Reconstruct complete message: [CMD/STATUS] [HLEN] [DATA]
        ByteArrayOutputStream message = new ByteArrayOutputStream(HEADER_SIZE_SINGLE + data.length);
        message.write(cmdOrStatus);
        message.write(hlen);
        message.write(data, 0, data.length);

        byte[] result = message.toByteArray();
        logger.debug("Reassembled message: {} bytes from {} fragments", 
            result.length, fragments.size());
        
        return result;
    }

    /**
     * Parses a framed request to extract command and data.
     * 
     * @param frame Framed request packet
     * @return Array containing [cmd_byte, data_bytes]
     * @throws IllegalArgumentException if frame is invalid
     */
    public Object[] parseRequest(byte[] frame) {
        if (frame == null || frame.length < HEADER_SIZE_SINGLE) {
            throw new IllegalArgumentException("Frame too short or null");
        }

        byte cmd = frame[0];
        byte hlen = frame[1];
        
        // Calculate expected data length
        int dataLen = ((hlen & 0xFF) << 8) | (frame.length - HEADER_SIZE_SINGLE);
        
        byte[] data = new byte[0];
        if (frame.length > HEADER_SIZE_SINGLE) {
            data = Arrays.copyOfRange(frame, HEADER_SIZE_SINGLE, frame.length);
        }

        logger.debug("Parsed request: cmd=0x{}, hlen={}, data_len={}",
            String.format("%02X", cmd), hlen, data.length);

        return new Object[] { cmd, data };
    }

    /**
     * Parses a framed response to extract status and data.
     * 
     * @param frame Framed response packet
     * @return Array containing [status_byte, data_bytes]
     * @throws IllegalArgumentException if frame is invalid
     */
    public Object[] parseResponse(byte[] frame) {
        if (frame == null || frame.length < HEADER_SIZE_SINGLE) {
            throw new IllegalArgumentException("Frame too short or null");
        }

        byte status = frame[0];
        byte hlen = frame[1];
        
        byte[] data = new byte[0];
        if (frame.length > HEADER_SIZE_SINGLE) {
            data = Arrays.copyOfRange(frame, HEADER_SIZE_SINGLE, frame.length);
        }

        logger.debug("Parsed response: status=0x{}, hlen={}, data_len={}",
            String.format("%02X", status), hlen, data.length);

        return new Object[] { status, data };
    }
}

// Made with Bob