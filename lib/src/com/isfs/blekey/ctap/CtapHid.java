/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.ctap;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
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
     * Keyed by hex string to avoid byte[] reference-equality pitfall in HashMap.
     */
    private static Map<String, CtapTxn> assignedCids = new java.util.concurrent.ConcurrentHashMap<String, CtapTxn>();

    /** Callback invoked when a CANCEL command dismisses a deferred UP request. */
    private static volatile Runnable onCancelCallback = null;

    /**
     * Registers a callback that fires when a CTAPHID_CANCEL command arrives while a
     * deferred user-presence command is outstanding.  The app layer uses this to
     * dismiss any pending dialog and stop keepalive.
     *
     * @param r Runnable to invoke on the calling thread (schedule to UI thread if needed)
     */
    public static void setOnCancelCallback(Runnable r) { onCancelCallback = r; }

    private static String cidKey(byte[] cid) {
        StringBuilder sb = new StringBuilder(cid.length * 2);
        for (byte b : cid) sb.append(String.format("%02x", b));
        return sb.toString();
    }

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
        
        logger.info("=== CtapHid NEW COMMAND ===");
        logger.info("CID: {}", java.util.Arrays.toString(this.cid));
        logger.info("Command: {} (0x{:02x})", this.messageType, cmdByte);
        logger.info("Byte count: {}", this.byteCount);
    }

    /**
     * Retrieves a pending CTAP HID instance for a given channel ID.
     *
     * @param cid The channel ID to look up
     * @return The associated CtapHid instance, or null if none exists
     */
    public static CtapHid getPendingByCid(byte[] cid) {
        CtapTxn txn = CtapHid.assignedCids.get(cidKey(cid));
        return txn != null ? txn.getCmd() : null;
    }

    /**
     * Checks if a channel ID has an open CTAP HID transaction.
     *
     * @param cid The channel ID to check
     * @return true if the channel ID has an open transaction, false otherwise
     */
    public static boolean hasOpenCid(byte[] cid) {
        return CtapHid.assignedCids.containsKey(cidKey(cid));
    }

    /**
     * Updates the transaction for an existing channel ID.
     * This is used when a new command arrives on an existing CID.
     * Preserves PIN token, passkey, and other authentication state from the existing transaction.
     *
     * @param cid The channel ID to update
     * @param txn The new transaction to associate with the CID
     */
    public static void updateCidTransaction(byte[] cid, CtapTxn txn) {
        // Get existing transaction to preserve authentication state
        CtapTxn existingTxn = CtapHid.assignedCids.get(cidKey(cid));
        logger.info("=== PIN HASH TRACKING: updateCidTransaction called, CID: {}, existing txn: {}, new txn: {}",
                    cid != null ? java.util.Arrays.toString(cid) : "null",
                    existingTxn != null ? existingTxn.hashCode() : "null",
                    txn != null ? txn.hashCode() : "null");
        
        if (existingTxn != null) {
            // Preserve PIN token, passkey, PIN hash, passkey filename, and UP cache
            if (existingTxn.getPinAuthTkn() != null) {
                txn.setPinAuthTkn(existingTxn.getPinAuthTkn());
                logger.debug("Preserved PIN token ({} bytes) when updating CID transaction",
                    existingTxn.getPinAuthTkn().length);
            }
            if (existingTxn.getPasskey() != null) {
                txn.setPasskey(existingTxn.getPasskey());
            }
            if (existingTxn.getPinHash() != null) {
                txn.setPinHash(existingTxn.getPinHash());
                logger.info("=== PIN HASH TRACKING: Preserved PIN hash from existing txn, size: {} bytes",
                            existingTxn.getPinHash().length);
            } else {
                logger.warn("=== PIN HASH TRACKING: Existing txn has NULL PIN hash!");
            }
            if (existingTxn.getPasskeyFileName() != null) {
                txn.setPasskeyFileName(existingTxn.getPasskeyFileName());
            }
            // Propagate cached user presence so makeCredential / getAssertion still proceed
            if (existingTxn.isUserPresent()) {
                txn.setUserPresent(true);
                logger.debug("Preserved userPresent=true when updating CID transaction");
            }
            // Propagate denial — once the user has denied on this CID every subsequent
            // command must be rejected immediately, regardless of MSG/CBOR type.
            if (existingTxn.isUserDenied()) {
                txn.setUserDenied(true);
                logger.debug("Preserved userDenied=true when updating CID transaction");
            }
            if (existingTxn.getEcdhKeyPair() != null) {
                txn.setEcdhKeyPair(existingTxn.getEcdhKeyPair());
                logger.debug("Preserved ecdhKeyPair when updating CID transaction");
            }
            // Propagate UX state and latch so the latch-wait path survives a txn update.
            txn.setUxState(existingTxn.getUxState());
            if (existingTxn.getUxLatch() != null) {
                txn.setUxLatch(existingTxn.getUxLatch());
                logger.debug("Preserved uxState={} and uxLatch when updating CID transaction",
                    existingTxn.getUxState());
            }
        } else {
            logger.warn("=== PIN HASH TRACKING: No existing transaction found for CID!");
        }
        CtapHid.assignedCids.put(cidKey(cid), txn);
        
        // Verify what was stored
        CtapTxn storedTxn = CtapHid.assignedCids.get(cidKey(cid));
        logger.info("=== PIN HASH TRACKING: After put, stored txn: {}, has PIN hash: {}",
                    storedTxn != null ? storedTxn.hashCode() : "null",
                    storedTxn != null && storedTxn.getPinHash() != null);
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
        logger.debug("Processing sequence frame, total frames: {}", this.sequenceFrames.size() + 1);
        this.sequenceFrames.add(segment);
        if(this.hasSufficientBytes()) {
            logger.info("Sufficient bytes received, processing complete message");
            try {
                this.processMessage();
            } catch (Exception e) {
                logger.error("processSequence exception: {}", e.getMessage(), e);
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
        // Only return true if response is actually ready
        if(!this.responseReady) {
            return false;
        }
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
        // Trim to byteCount to strip HID frame zero-padding
        byte[] raw = outputStream.toByteArray();
        return Arrays.copyOf(raw, Math.min(this.byteCount, raw.length));
    }

    /**
     * Processes the complete CTAP HID message based on its message type.
     *
     * @throws Exception if an error occurs during processing
     */
    public void processMessage() throws Exception {
        logger.debug("CMD :: " + this.messageType);
        logger.debug("=== processMessage: messageType={}, byteCount={}", this.messageType, this.byteCount);
        try {
            byte[] payload = this.getCtapHidData();
            logger.debug("Assembled payload ({} bytes): {}", payload.length,
                payload.length <= 200 ? java.util.Arrays.toString(payload) :
                java.util.Arrays.toString(java.util.Arrays.copyOf(payload, 200)) + "...");
        } catch (Exception e) {
            logger.error("Failed to get payload for logging: {}", e.getMessage());
        }
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
     * 
     * @param seq
     */
    private void _writeSequenceFrames(byte[] seq) {
        this.responseSegments = new ArrayList<byte[]>();
        int segCount = 0;
        int offset = 0;
        while(offset < seq.length) {
            byte[] segment = new byte[MAX_SIZE];
            System.arraycopy(this.getCid(), 0, segment, 0, 4);
            segment[4] = (byte) segCount;
            segCount++;
            System.arraycopy(seq, offset, segment, 5, Math.min(64 - 5, seq.length - offset));
            this.responseSegments.add(segment);
            offset += 59;
        }
    }

    /**
     * 
     */
    private void _writeResponseFrame(byte[] rsp) {
        this.initResponse = new byte[MAX_SIZE];
        System.arraycopy(rsp, 0, this.initResponse, 0, rsp.length);
        this.responseReady = true;
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
        bos.write(0x80 | this.messageType.getValue()); // Response command byte — MSB must be set per CTAP HID spec §11.2.4
        bos.write((bcnt & 0xFF00) >> 8);
        bos.write(bcnt & 0xFF);
        if(data == null || data.length == 0) { /* continue */ }
        else if (data.length <= 56) {
            bos.write(data);
        }
        else { //data > 56
            bos.write(data, 0, 57);
            int seqLen = data.length - 57;
            byte[] theRest = new byte[seqLen];
            System.arraycopy(data, 57, theRest, 0, seqLen);
            _writeSequenceFrames(theRest);
        }
        _writeResponseFrame(bos.toByteArray());
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
        bos.write(0x80 | CtapHidCmd.ERROR.getValue()); // MSB must be set on command bytes
        bos.write(0);
        bos.write(1);
        bos.write(code.getCode());
        _writeResponseFrame(bos.toByteArray());
    }

    /**
     * Sends a CTAPHID_MSG response frame (U2F APDU response).
     * ctapAck uses this.messageType (MSG) to set the correct CMD byte.
     *
     * @param apduResponse The U2F APDU response bytes (data + SW1 + SW2)
     * @throws IOException if an error occurs while creating the response
     */
    private void ctapMsgAck(byte[] apduResponse) throws IOException {
        ctapAck(apduResponse.length, apduResponse);
    }

    /**
     * Dispatches a CTAPHID_MSG (U2F) APDU to the appropriate handler.
     * Supports U2F_VERSION (0x03), U2F_REGISTER (0x01), and U2F_AUTHENTICATE (0x02).
     *
     * @param data The raw U2F extended APDU bytes
     * @throws IOException if an error occurs while creating the response
     */
    private void u2f(byte[] data) throws IOException {
        if (data.length < 7) {
            // Too short for a minimal extended APDU header
            ctapMsgAck(new byte[]{(byte) 0x67, (byte) 0x00}); // SW_WRONG_LENGTH
            return;
        }
        byte   cla     = data[0];
        byte   ins     = data[1];
        byte   p1      = data[2];
        // P2 = data[3] — ignored for all current INS values
        // data[4] == 0x00 indicates extended Lc; data[5:7] = big-endian length
        byte[] payload = Arrays.copyOfRange(data, 7, data.length);

        if (cla != 0x00) {
            ctapMsgAck(new byte[]{(byte) 0x6A, (byte) 0x86}); // SW_INCORRECT_PARAMETERS
            return;
        }
        switch (ins & 0xFF) {
            case 0x03: u2fVersion();                  break;
            case 0x01: u2fRegister(payload);          break;
            case 0x02: u2fAuthenticate(p1, payload);  break;
            default:
                ctapMsgAck(new byte[]{(byte) 0x6D, (byte) 0x00}); // SW_INS_NOT_SUPPORTED
        }
    }

    /**
     * Handles U2F_VERSION (INS=0x03). Returns "U2F_V2" + SW_NO_ERROR.
     *
     * @throws IOException if an error occurs while creating the response
     */
    private void u2fVersion() throws IOException {
        byte[] ver = new byte[]{'U', '2', 'F', '_', 'V', '2'};
        byte[] rsp = new byte[ver.length + 2];
        System.arraycopy(ver, 0, rsp, 0, ver.length);
        rsp[ver.length]     = (byte) 0x90;
        rsp[ver.length + 1] = (byte) 0x00;
        ctapMsgAck(rsp);
    }

    /**
     * Handles U2F_REGISTER (INS=0x01). Delegates to AuthenticatorAPI.u2fRegister().
     * Response is returned synchronously (no bio gate).
     *
     * @param apduData challenge_param[32] || app_param[32]
     * @throws IOException if an error occurs while creating the response
     */
    private void u2fRegister(byte[] apduData) throws IOException {
        if (apduData.length < 64) {
            ctapMsgAck(new byte[]{(byte) 0x67, (byte) 0x00}); // SW_WRONG_LENGTH
            return;
        }
        byte[] challengeParam = Arrays.copyOfRange(apduData, 0,  32);
        byte[] appParam       = Arrays.copyOfRange(apduData, 32, 64);

        CtapTxn txn = CtapHid.assignedCids.get(cidKey(this.cid));
        if (txn != null && txn.isUserDenied()) {
            logger.warn("u2fRegister: CID {} already denied — rejecting", cidKey(this.cid));
            ctapMsgAck(new byte[]{(byte) 0x69, (byte) 0x00}); // SW_CONDITIONS_NOT_SATISFIED
            return;
        }
        byte[] response = AuthenticatorAPI.u2fRegister(txn, challengeParam, appParam);
        ctapMsgAck(response);
    }

    /**
     * Handles U2F_AUTHENTICATE (INS=0x02). Delegates to AuthenticatorAPI.u2fAuthenticate().
     * Check-only requests (p1=0x07) are answered synchronously; sign requests are also
     * returned synchronously (no bio gate).
     *
     * @param p1       U2F control byte (0x03 = UP+sign, 0x07 = check-only, 0x08 = sign no UP)
     * @param apduData challenge_param[32] || app_param[32] || kh_len[1] || key_handle[kh_len]
     * @throws IOException if an error occurs while creating the response
     */
    private void u2fAuthenticate(byte p1, byte[] apduData) throws IOException {
        if (apduData.length < 65) {
            ctapMsgAck(new byte[]{(byte) 0x67, (byte) 0x00}); // SW_WRONG_LENGTH
            return;
        }
        byte[] challengeParam = Arrays.copyOfRange(apduData, 0,  32);
        byte[] appParam       = Arrays.copyOfRange(apduData, 32, 64);
        int    khLen          = apduData[64] & 0xFF;
        if (apduData.length < 65 + khLen) {
            ctapMsgAck(new byte[]{(byte) 0x67, (byte) 0x00}); // SW_WRONG_LENGTH
            return;
        }
        byte[] keyHandle = Arrays.copyOfRange(apduData, 65, 65 + khLen);

        // Check-only: validate key handle and return immediately without signing
        if ((p1 & 0xFF) == 0x07) {
            CtapTxn checkTxn = CtapHid.assignedCids.get(cidKey(this.cid));
            boolean valid = AuthenticatorAPI.u2fCheckKeyHandle(checkTxn, appParam, keyHandle);
            ctapMsgAck(valid
                ? new byte[]{(byte) 0x69, (byte) 0x85}   // SW_CONDITIONS_NOT_SATISFIED (key valid)
                : new byte[]{(byte) 0x6A, (byte) 0x80}); // SW_WRONG_DATA (unknown key handle)
            return;
        }

        CtapTxn txn = CtapHid.assignedCids.get(cidKey(this.cid));
        if (txn != null && txn.isUserDenied()) {
            logger.warn("u2fAuthenticate: CID {} already denied — rejecting", cidKey(this.cid));
            ctapMsgAck(new byte[]{(byte) 0x69, (byte) 0x00}); // SW_CONDITIONS_NOT_SATISFIED
            return;
        }
        boolean requireUP = (p1 & 0xFF) != 0x08;
        byte[] response = AuthenticatorAPI.u2fAuthenticate(
            txn, challengeParam, appParam, keyHandle, requireUP);
        ctapMsgAck(response);
    }

    /**
     * Builds CBOR response packets, splitting large responses into multiple segments.
     *
     * @param cborResponse The CBOR response data
     */
    private void buildCborInitAndSequencePackets(byte[] cborResponse) throws IOException {

        if(cborResponse == null || cborResponse.length == 0) { 
            throw new RuntimeException("Invalid cbor response");
        }
        logger.debug("raw CBOR response" + Arrays.toString(cborResponse));
        ctapAck(cborResponse.length, cborResponse);
    }

    /**
     * Processes a CBOR message, decoding it and passing it to the AuthenticatorAPI.
     *
     * @param data The CBOR message data
     * @throws IOException if an error occurs while processing the message
     */
    @SuppressWarnings({ "unchecked" })
    private void cbor(byte[] data) throws IOException {
        // Calculate hash for duplicate detection
        int dataHash = java.util.Arrays.hashCode(data);
        
        logger.info("=== CBOR REQUEST RECEIVED ===");
        logger.info("Data size: {} bytes", data.length);
        logger.info("Data hash: {}", dataHash);
        logger.info("Full data: {}", java.util.Arrays.toString(data));
        logger.info("CID: {}", java.util.Arrays.toString(this.cid));
        
        if(data.length < 1) {
            logger.error("CBOR data too short");
            this.ctapErr(Ctap2StatusCode.INVALID_CBOR);
        } else {
            int api = (int) data[0];
            logger.info("API command: {} ({})", api,
                api == 1 ? "makeCredential" :
                api == 2 ? "getAssertion" :
                api == 4 ? "getInfo" :
                api == 6 ? "clientPIN" :
                api == 11 ? "authenticatorSelection" :
                "unknown");
            logger.debug("api : : " + api);
            
            try {
                Map<Integer, Object> cbor = null;
                if (data.length > 1) {
                    byte[] cborBytes = new byte[data.length - 1];
                    System.arraycopy(data, 1, cborBytes, 0, cborBytes.length);
                    Object cborObj = Cbor.decode(cborBytes);
                    if (!(cborObj instanceof Map)) {
                        logger.error("CBOR decode failed - not a map");
                        this.ctapErr(Ctap2StatusCode.INVALID_CBOR);
                        return;
                    }
                    cbor = (Map<Integer, Object>) cborObj;
                    logger.info("CBOR: {}", cbor.toString());
                }
                logger.info("=== END CBOR REQUEST ===");
                // Set the deferred cmd BEFORE calling process() so
                // the callback exists when processing the txn.
                CtapTxn txn = CtapHid.assignedCids.get(cidKey(this.cid));
                if (txn != null && txn.isUserDenied()) {
                    logger.warn("cbor: CID {} already denied — returning OPERATION_DENIED without biometric", cidKey(this.cid));
                    buildCborInitAndSequencePackets(
                        AuthenticatorAPI.buildErrorResponse(Ctap2StatusCode.OPERATION_DENIED));
                    return;
                }
                // Always register this CtapHid as the deferred cmd before calling process().
                // process() returns null on both the legacy deferred path and the new
                // latch-waiter thread path; in both cases the DeferredResponseSender
                // needs txn.takeDeferredCmd() to return this instance.
                if (txn != null) {
                    txn.setDeferredCmd(this);
                }
                byte[] response = AuthenticatorAPI.process(txn, api, cbor);
                if (response == null) {
                    // Deferred (legacy path) — deferredCmd already set on txn above.
                    logger.info("CBOR response deferred for CID {}", cidKey(this.cid));
                    return;
                }
                // Non-deferred — clear any cmd slot we may have set, then build packets.
                if (txn != null) {
                    txn.setDeferredCmd(null);
                }
                buildCborInitAndSequencePackets(response);
                // responseReady is set inside _writeResponseFrame — do NOT add another set here
            } catch (Exception e) {
                logger.error(e.getMessage(), e);
                this.ctapErr(Ctap2StatusCode.INVALID_CBOR);
            }
        }
        // NOTE: responseReady is set by _writeResponseFrame() inside ctapAck/ctapErr.
        // The unconditional set that was formerly here has been removed (it fired even
        // when the deferred path returned early, or after ctapErr had already set it).
    }

    /**
     * Injects a deferred CBOR response after user-presence resolution.
     * After this returns, {@link #hasMoreResponses()} is true and the caller
     * must drain {@link #getResponseSegment()} and write HID input reports.
     *
     * @param cborResponse The fully-formed CTAP response bytes (status byte + CBOR payload)
     * @throws IOException if building the HID packets fails
     */
    public void injectDeferredResponse(byte[] cborResponse) throws IOException {
        this.responseSegment = -1;          // reset drain cursor
        buildCborInitAndSequencePackets(cborResponse);
        // _writeResponseFrame sets responseReady = true
    }

    /**
     * Processes an initialization message, generating a new channel ID.
     *
     * @param data The initialization message data
     */
    private void init(byte[] data) throws IOException {
        logger.debug("init");
        byte[] nonce = new byte[8];
        System.arraycopy(data, 0, nonce, 0, 8);
        logger.debug("nonce :: " + Arrays.toString(nonce));
        SecureRandom random = new SecureRandom();
        byte[] newCid = new byte[4];
        random.nextBytes(newCid);
        logger.debug("newCid :: " + Arrays.toString(newCid));
                                   //version 2; leeet; CAPABILITY_WINK | CAPABILITY_CBOR
        byte[] specStuff = new byte[] {0x02, 0x13, 0x33, 0x37, 0x01 | 0x04};
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(nonce);
        bos.write(newCid);
        bos.write(specStuff);
        byte[] rsp = bos.toByteArray();
        logger.debug("init response :: " + Arrays.toString(rsp));
        CtapTxn txn = new CtapTxn(newCid, this, null, null, null);
        CtapHid.assignedCids.put(cidKey(newCid), txn);
        ctapAck(rsp.length, rsp);
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
    private void cancel(byte[] data) throws IOException {
        CtapTxn txn = assignedCids.get(cidKey(this.getCid()));
        if (txn != null) {
            CtapHid pending = txn.takeDeferredCmd();
            if (pending != null) {
                // Inject KEEPALIVE_CANCEL into the original deferred command
                pending.injectDeferredResponse(
                    new byte[]{ (byte) Ctap2StatusCode.KEEPALIVE_CANCEL.getCode() });
                logger.info("CANCEL: injected KEEPALIVE_CANCEL for CID {}", cidKey(this.getCid()));
                // Notify the app layer so it can dismiss any dialog and stop keepalive
                if (onCancelCallback != null) {
                    onCancelCallback.run();
                }
                // Per spec §11.2.9.1.5: no reply to the CANCEL frame itself.
                return;
            }
        }
        // No deferred command — acknowledge normally.
        ctapAck(0, null);
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
    
    /**
     * Gets the command type for this CTAP HID transaction.
     *
     * @return The command type as a CtapHidCmd enum
     */
    public CtapHidCmd getCmd() {
        return this.messageType;
    }
    
    /**
     * Gets the byte count for this CTAP HID transaction.
     *
     * @return The byte count as an integer
     */
    public int getSize() {
        return this.byteCount;
    }

    /**
     * Returns the {@link CtapTxn} for the given channel ID, or null if no transaction exists.
     * Used by the app layer to retrieve the deferred command after user-presence resolution.
     *
     * @param cid The 4-byte channel identifier
     * @return The associated transaction, or null
     */
    public static CtapTxn getCidTransaction(byte[] cid) {
        return assignedCids.get(cidKey(cid));
    }

    /**
     * Evicts a channel from the active CID map.
     *
     * <p>Call when the channel enters an unrecoverable state (e.g. the deferred
     * {@link CtapHid} object was lost before the CBOR response could be delivered).
     * Any subsequent commands arriving on this CID will be silently discarded.</p>
     *
     * @param cid 4-byte channel identifier
     */
    public static void evictCid(byte[] cid) {
        CtapTxn removed = assignedCids.remove(cidKey(cid));
        logger.warn("evictCid: CID {} removed from active map (was {})",
                    cidKey(cid), removed != null ? "present" : "already absent");
    }

    /**
     * Builds a zero-padded 64-byte {@code CTAPHID_ERROR} HID input report frame.
     *
     * <p>Used to send a transport-level error when no live {@link CtapHid} instance
     * exists for the channel (e.g. the deferred cmd was lost before delivery).
     * Format: {@code CID[4] | 0xBF | 0x00 | 0x01 | errorCode | 0x00...}</p>
     *
     * @param cid  4-byte channel identifier
     * @param code HID-layer error code (use {@link Ctap2StatusCode#OTHER} for
     *             unspecified internal errors, per spec §11.2.9)
     * @return zero-padded 64-byte HID input report
     */
    public static byte[] buildHidErrorFrame(byte[] cid, Ctap2StatusCode code) {
        byte[] frame = new byte[64]; // zero-padded to 64 bytes
        frame[0] = cid[0];
        frame[1] = cid[1];
        frame[2] = cid[2];
        frame[3] = cid[3];
        frame[4] = (byte) (0x80 | CtapHidCmd.ERROR.getValue()); // 0xBF
        frame[5] = 0x00;  // BCNT high byte
        frame[6] = 0x01;  // BCNT low byte = 1
        frame[7] = (byte) code.getCode();
        return frame;
    }
}
