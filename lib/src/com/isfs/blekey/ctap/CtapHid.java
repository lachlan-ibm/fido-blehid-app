/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.ctap;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.isfs.blekey.authenticator.AuthenticatorAPI;
import com.isfs.blekey.util.Cbor;

/**
 * This class accumulates HID message frames until a complete message
 * has been received. It then unpacks the message and generates a 
 * response.
 * 
 * Responses can be collected by using the method cmd.getPendingResponse method,
 * which will fetch the next pending response buffer.
 */
public class CtapHid {

    /**
     * Maximum size of a CTAP HID frame (64 bytes).
     */
    private final int MAX_SIZE = 64;

    /**
     * The initial command frame received from the host.
     */
    private byte[] cmdFrame;
    
    /**
     * List of sequence frames that follow the initial command frame.
     */
    private List<byte[]> sequenceFrames;
    
    /**
     * The channel identifier for this CTAP HID transaction.
     */
    private byte[] cid;
    
    /**
     * The number of bytes expected in the complete message.
     */
    private int byteCount;
    
    /**
     * The type of CTAP HID command being processed.
     */
    private CtapHidCmd messageType;
    
    /**
     * The initial response frame to be sent back to the host.
     */
    private byte[] initResponse;
    
    /**
     * List of sequence response frames that follow the initial response.
     */
    private List<byte[]> responseSegments;
    
    /**
     * Flag indicating whether a response is ready to be sent.
     */
    private boolean responseReady = false;
    
    /**
     * Index of the current response segment (-1 for init, 0+ for sequences).
     */
    private int responseSegment = -1; //send init then start sequences at 0
    
    /**
     * Map of assigned channel IDs and their ongoing CTAP transaction context.
     */
    private static Map<byte[], CtapTxn> assignedCids = new HashMap<byte[], CtapTxn>();

    /**
     * Logger for debugging and error reporting.
     */
    private static final Logger logger = LoggerFactory.getLogger(CtapHid.class);

    /**
     * Constructs a new CtapHid instance from an initial command frame.
     * Parses the frame to extract the channel ID, command type, and byte count.
     *
     * @param request The initial command frame
     * @throws IllegalArgumentException if the command frame is too short
     */
    public CtapHid(byte[] request) {
        this.cmdFrame = request;
        if (cmdFrame.length < 6) {
            throw new IllegalArgumentException("Command frame too short");
        }

        this.sequenceFrames = new ArrayList<byte[]>();
        this.responseSegments = new ArrayList<byte[]>();
        this.responseReady = false;
        this.responseSegment = -1;

        ByteBuffer byteBuffer = ByteBuffer.wrap(request);
        this.cid = new byte[4];
        byteBuffer.get(this.cid); // bytes 0–3
        int cmdByte = byteBuffer.get() & 0x7F; // byte 4, mask MSB if needed
        this.messageType = CtapHidCmd.fromValue(cmdByte);

        int high = byteBuffer.get() & 0xFF; // byte 5
        int low = byteBuffer.get() & 0xFF; // byte 6
        this.byteCount = (high << 8) | low; // combine to 16-bit int
    }

    /**
     * Retrieves a pending CTAP HID instance for a given channel ID.
     *
     * @param cid The channel ID to look up
     * @return The associated CtapHid instance, or null if none exists
     */
    public static CtapHid getPendingByCid(byte[] cid) {
        if (CtapHid.assignedCids.containsKey(cid)) {
            return CtapHid.assignedCids.get(cid).getCmd();
        } //else 
        return null;
    }

    /**
     * Checks if a channel ID has an open CTAP HID transaction.
     *
     * @param cid The channel ID to check
     * @return true if the channel ID has an open transaction, false otherwise
     */
    public static boolean hasOpenCid(byte[] cid) {
        return CtapHid.assignedCids.containsKey(cid);
    }

    /**
     * Processes a sequence frame for an ongoing CTAP HID transaction.
     * Adds the frame to the list of sequence frames and attempts to process
     * the complete message if enough bytes have been received.
     *
     * @param segment The sequence frame to process
     * @return This CtapHid instance
     */
    public CtapHid processSequence(byte[] segment) {
        this.sequenceFrames.add(segment);
        if(this.hasSufficientBytes()) {
            try {
                this.processMessage();
            } catch (Exception e) {
                logger.error("processSequence", e);
            }
        }
        return this;
    }

    /**
     * Gets the channel ID for this CTAP HID transaction.
     *
     * @return The channel ID as a byte array
     */
    public byte[] getCid() {
        return this.cid;
    }

    /**
     * Checks if enough bytes have been received to process the complete message.
     *
     * @return true if enough bytes have been received, false otherwise
     */
    public boolean hasSufficientBytes() {
        int totalBytes = cmdFrame.length - 7 + sumOfSegmentFrames(); // subtract cid, cmd and byte count
        return totalBytes >= this.byteCount;
    }

    /**
     * Calculates the total number of payload bytes in all sequence frames.
     *
     * @return The total number of payload bytes
     */
    private int sumOfSegmentFrames() {
        int totalBytes = 0;
        for (byte[] sequenceFrames : this.sequenceFrames) {
            totalBytes += sequenceFrames.length - 5; // subtract cid and sequence number
        }
        return totalBytes;
    }

    /**
     * Checks if a response is ready to be sent.
     *
     * @return true if a response is ready, false otherwise
     */
    public boolean isResponseReady() {
        return this.responseReady;
    }

    /**
     * Gets the next response segment to be sent to the host.
     * Returns the initial response frame first, then sequence frames.
     *
     * @return The next response segment as a byte array
     * @throws RuntimeException if there are no more response segments
     */
    public byte[] getResponseSegment() {
        if(this.responseSegment < 0) {//Init packet
            this.responseSegment = 0;
            return this.initResponse;
        } else if(this.responseSegments != null && this.responseSegment < this.responseSegments.size()) { //Sequence packet
            return this.responseSegments.get(this.responseSegment++);
        } else {
            return null;
        }
    }

    /**
     * Checks if there are more response segments to be sent.
     *
     * @return true if there are more response segments, false otherwise
     */
    private boolean hasMoreResponse() {
        if(this.responseSegment < 0) {
            return true;
        } else if (this.responseSegments != null) {
            return this.responseSegment < this.responseSegments.size();
        } // else
        return false;
    }

    /**
     * Extracts the CTAP HID data payload from all received frames.
     *
     * @return The complete CTAP HID data payload
     * @throws IOException if the command frame is too short
     */
    public byte[] getCtapHidData() throws IOException {
        if(cmdFrame.length < 7) {
            throw new IOException("Command frame too short");
        }
        // Extract payload from command frame (after 7 bytes: 4 for CID, 1 for command, 2 for byte count)
        byte[] cmdPayload = Arrays.copyOfRange(cmdFrame, 7, cmdFrame.length);
    
        // Extract payloads from sequence frames (after 5 bytes: 4 for CID, 1 for sequence number)
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(cmdPayload);
        for (byte[] frame : sequenceFrames) {
            if (frame.length > 5) {
                outputStream.write(frame, 5, frame.length - 5);
            }
        }
        return outputStream.toByteArray();
    }

    /**
     * Processes the complete CTAP HID message based on its message type.
     *
     * @throws Exception if an error occurs during processing
     */
    public void processMessage() throws Exception {
        switch(this.messageType)
        {
            case MSG:
                this.u2f(this.getCtapHidData()); break;
            case CBOR:
                this.cbor(this.getCtapHidData()); break;
            case INIT:
                this.init(this.getCtapHidData()); break;
            case PING:
                this.ping(this.getCtapHidData()); break;
            case CANCEL:
                this.cancel(this.getCtapHidData()); break;
            case KEEP_ALIVE:
                this.keepAlive(this.getCtapHidData()); break;
            case WINK:
                this.wink(this.getCtapHidData()); break;
            case LOCK:
                this.lock(this.getCtapHidData()); break;
            default:
                this.ctapErr(Ctap2StatusCode.INVALID_COMMAND);
        }
    }

    /**
     * Creates a CTAP acknowledgement response.
     *
     * @param bcnt The byte count for the response
     * @param data The data payload for the response
     * @throws IOException if an error occurs while creating the response
     */
    private void ctapAck(int bcnt, byte[] data) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(64);
        bos.write(this.getCid());
        bos.write(this.messageType.getValue());
        bos.write((bcnt & 0xFF00) >> 8);
        bos.write(bcnt & 0xFF);
        if (data != null) {
            bos.write(data);
        }
        bos.write(new byte[MAX_SIZE - bos.size()]);
        this.initResponse = bos.toByteArray();
        this.responseReady = true;
    }

    /**
     * Creates a CTAP error response.
     *
     * @param code The error code to include in the response
     * @throws IOException if an error occurs while creating the response
     */
    private void ctapErr(Ctap2StatusCode code) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(64);
        bos.write(this.getCid());
        bos.write(CtapHidCmd.ERROR.getValue());
        bos.write(0);
        bos.write(1);
        bos.write(code.getCode());
        bos.write(new byte[MAX_SIZE - bos.size()]);
        this.initResponse = bos.toByteArray();
        this.responseReady = true;  
    }

    /**
     * Processes a U2F message (not implemented).
     *
     * @param data The U2F message data
     */
    private void u2f(byte[] data) {   
        return;
    }

    /**
     * Builds CBOR response packets, splitting large responses into multiple segments.
     *
     * @param cborResponse The CBOR response data
     */
    private void buildCborInitAndSequencePackets(byte[] cborResponse) {
        System.err.println("raw CBOR response" + Arrays.toString(cborResponse));
        this.initResponse = new byte[64];
        System.arraycopy(this.getCid(), 0, this.initResponse, 0, 4);
        int rspLen = cborResponse.length;
        this.initResponse[4] = (byte) CtapHidCmd.MSG.getValue();
        this.initResponse[5] = (byte) ((rspLen & 0xFF00) >> 8 );
        this.initResponse[6] = (byte) (rspLen & 0xFF);
        //Now copy in satus and data
        if (cborResponse.length == 1) {
            //Error code in response, update the buffer
            this.initResponse[7] = cborResponse[0];
        }
        else if (cborResponse.length <= 56) {
            System.arraycopy(cborResponse, 0, this.initResponse, 7, cborResponse.length);
        } else {
            System.arraycopy(cborResponse, 0, this.initResponse, 7, 57);
            this.responseSegments = new ArrayList<byte[]>();
            int offset = 57;
            int seg = 0;
            while(offset < cborResponse.length) {
                byte[] segment = new byte[64];
                System.arraycopy(this.getCid(), 0, segment, 0, 4);
                segment[4] = (byte) seg;
                seg++;
                System.arraycopy(cborResponse, offset, segment, 5, 
                        Math.min(64 - 5, cborResponse.length - offset));
                this.responseSegments.add(segment);
                offset += 59;
            }
        }
    }

    /**
     * Processes a CBOR message, decoding it and passing it to the AuthenticatorAPI.
     *
     * @param data The CBOR message data
     * @throws IOException if an error occurs while processing the message
     */
    @SuppressWarnings({ "unchecked", "rawtypes" })
    private void cbor(byte[] data) throws IOException {
        if(data.length < 1) {
            this.ctapErr(Ctap2StatusCode.INVALID_CBOR);
        } else {
            int api = (int) data[0];
            logger.debug("api: " + api);
            byte[] cborBytes = new byte[data.length - 1];
            System.arraycopy(data, 1, cborBytes, 0, data.length - 1);
            Object cborObj = Cbor.decode(cborBytes);
            logger.debug("cborObj" + cborObj);
            if(cborObj == null || !(cborObj instanceof Map)) {
                this.ctapErr(Ctap2StatusCode.INVALID_CBOR);
            } else {
                try {
                    Map cbor = (Map) cborObj;
                    buildCborInitAndSequencePackets(
                        AuthenticatorAPI.process(
                                        CtapHid.assignedCids.get(this.cid), api, (Map<Integer, Object>) cbor));
                } catch (Exception e) {
                    System.err.println(e.getMessage());
                    this.ctapErr(Ctap2StatusCode.INVALID_CBOR);
                }
            }
        }
        this.responseReady = true;
    }

    /**
     * Processes an initialization message, generating a new channel ID.
     *
     * @param data The initialization message data
     */
    private void init(byte[] data) {
        byte[] nonce = new byte[8];
        System.arraycopy(data, 0, nonce, 0, 8);
        SecureRandom random = new SecureRandom();
        byte[] newCid = new byte[4];
        random.nextBytes(newCid);
        this.initResponse = new byte[64];
        this.initResponse[0] = (byte) CtapHidCmd.INIT.getValue();
        this.initResponse[1] = (17  & 0xFF00) >> 8; // Byte count
        this.initResponse[2] = (17 & 0xFF);
        System.arraycopy(nonce, 0, this.initResponse, 3, 8);
        System.arraycopy(newCid, 0, this.initResponse, 11, 4);
                                    //version 2; leeet; CAPABILITY_CBOR | CAPABILITY_NMSG
        byte[] specStuff = new byte[] {0x02, 0x13, 0x33, 0x37, 0x0C};
        System.arraycopy(specStuff, 0, this.initResponse, 15, 5);
        CtapTxn txn = new CtapTxn(newCid, this, null, null, null);
        CtapHid.assignedCids.put(newCid, txn);

        this.responseReady = true;
    }

    /**
     * Processes a ping message, echoing back the data.
     *
     * @param data The ping message data
     * @throws IOException if an error occurs while creating the response
     */
    private void ping(byte[] data) throws IOException {
        ctapAck(this.byteCount, data);
    }

    /**
     * Processes a cancel message, canceling any ongoing transaction.
     *
     * @param data The cancel message data
     * @throws IOException if an error occurs while creating the response
     */
    private void cancel(byte[] data) throws IOException  {
        if(CtapHid.assignedCids.keySet().contains(this.getCid())) {
            //TODO cleanup request in progress
            ctapAck(0, null);
        }
    }

    /**
     * Processes a keep-alive message.
     *
     * @param data The keep-alive message data
     * @throws IOException if an error occurs while creating the response
     */
    private void keepAlive(byte[] data) throws IOException {
        ctapAck(1, new byte[] {0x01});
    }

    /**
     * Processes a wink message, which can be used to identify the device.
     *
     * @param data The wink message data
     * @throws IOException if an error occurs while creating the response
     */
    private void wink(byte[] data) throws IOException {
        ctapAck(0, null);
    }

    /**
     * Processes a lock message, which can be used to lock the channel.
     *
     * @param data The lock message data
     * @throws IOException if an error occurs while creating the response
     */
    private void lock(byte[] data) throws IOException {
        ctapAck(0, null);
    }

    /**
     * Checks if there are more response segments to be sent.
     *
     * @return true if there are more response segments, false otherwise
     */
    public boolean hasMoreResponses(){
        return this.hasMoreResponse();
    }
}
