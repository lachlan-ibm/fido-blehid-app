
package com.isfs.blekey.ctap;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
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

    private final int MAX_SIZE = 64;

    private byte[] cmdFrame;
    private List<byte[]> sequenceFrames;
    private byte[] cid;
    private int byteCount;
    private CtapHidCmd messageType;
    private byte[] initResponse;
    private List<byte[]> responseSegments;
    private boolean responseReady = false;
    private int responseSegment = -1; //send init then start sequences at 0
    
    // Map of assigned CID's and the last message processed on the given CID.
    private static Map<byte[], CtapHid> assignedCids = new HashMap<byte[], CtapHid>();

    private static final Logger logger = LoggerFactory.getLogger(CtapHid.class);

    public CtapHid(byte[] request) {
        this.cmdFrame = request;
        if (cmdFrame.length < 6) {
            throw new IllegalArgumentException("Command frame too short");
        }

        ByteBuffer byteBuffer = ByteBuffer.wrap(request);
        this.cid = new byte[4];
        byteBuffer.get(this.cid); // bytes 0–3

        byte cmdByte = byteBuffer.get(); // byte 4
        this.messageType = CtapHidCmd.values()[cmdByte & 0x7F]; // mask MSB if needed

        int high = byteBuffer.get() & 0xFF; // byte 5
        int low = byteBuffer.get() & 0xFF; // byte 6
        this.byteCount = (high << 8) | low; // combine to 16-bit int
    }

    public static CtapHid getPendingByCid(byte[] cid) {
        if (assignedCids.containsKey(cid)) {
            return assignedCids.get(cid);
        } //else 
        return null;
    }

    public static boolean hasOpenCid(byte[] cid) {
        return assignedCids.containsKey(cid);
    }

    public static void addKeyToCid(byte[] cid, PrivateKey key) {
        assignedCids.get(cid);
    }

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

    public byte[] getCid() {
        return this.cid;
    }

    public boolean hasSufficientBytes() {
        int totalBytes = cmdFrame.length - 7 + sumOfSegmentFrames(); // subtract cid, cmd and byte count
        return totalBytes >= this.byteCount;
    }

    private int sumOfSegmentFrames() {
        int totalBytes = 0;
        for (byte[] sequenceFrames : this.sequenceFrames) {
            totalBytes += sequenceFrames.length - 5; // subtract cid and sequence number
        }
        return totalBytes;
    }

    private boolean isResponseReady() {
        return this.responseReady;
    }

    public byte[] getResponseSegment() {
        if(this.responseSegment < 0) {//Init packet
            this.responseSegment = 0;
            return this.initResponse;
        } else if(this.responseSegments != null) { //Sequence packet
            return this.responseSegments.get(this.responseSegment++);
        } else {
            throw new RuntimeException("Asked for a sequence packet and I don't have any.");
        }
    }

    private boolean hasMoreResponse() {
        if(this.responseSegment < 0) {
            return true;
        } else if (this.responseSegments != null) {
            return this.responseSegment >= this.responseSegments.size();
        } // else
        return false;
    }


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

    private interface CtapFcnPtr {
        void process(byte[] request);
    }

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

    private void u2f(byte[] data) {   
        return;
    }

    private void buildCborInitAndSequencePackets(byte[] cborResponse) {
        this.initResponse = new byte[64];
        System.arraycopy(this.getCid(), 0, this.initResponse, 0, 4);
        int rspLen = cborResponse.length + 1;
        this.initResponse[4] = (byte) CtapHidCmd.MSG.getValue();
        this.initResponse[5] = (byte) ((rspLen & 0xFF00) >> 8 );
        this.initResponse[6] = (byte) (rspLen & 0xFF);
        this.initResponse[7] = (byte) Ctap2StatusCode.SUCCESS.getCode();
        //Now copy in data
        if(cborResponse != null && cborResponse.length <= 56) {
            System.arraycopy(cborResponse, 0, this.initResponse, 8, cborResponse.length);
        } else {
            System.arraycopy(cborResponse, 0, this.initResponse, 8, 56);
            this.responseSegments = new ArrayList<byte[]>();
            int offset = 56;
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

    private void cbor(byte[] data) throws IOException {
        if(data.length < 1) {
            this.ctapErr(Ctap2StatusCode.INVALID_CBOR);
        } else {
            int api = (int) data[0];
            byte[] cborBytes = new byte[data.length - 1];
            System.arraycopy(data, 1, cborBytes, 0, data.length - 1);
            Object cborObj = Cbor.decode(cborBytes);
            if(cborObj == null || !(cborObj instanceof Map)) {
                this.ctapErr(Ctap2StatusCode.INVALID_CBOR);
            } else {
                try {
                    Map cbor = (Map) cborObj;
                    buildCborInitAndSequencePackets(
                        AuthenticatorAPI.process(this.cid, api, (Map<Integer, Object>) cbor));
                } catch (Exception e) {
                    logger.error("cbor", e);
                    this.ctapErr(Ctap2StatusCode.INVALID_CBOR);
                }
            }
        }
        this.responseReady = true;
    }

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
        this.responseReady = true;
    }

    private void ping(byte[] data) throws IOException {
        ctapAck(this.byteCount, data);
    }

    private void cancel(byte[] data) throws IOException  {
        if(assignedCids.keySet().contains(this.getCid())) {
            //TODO cleanup request in progress
            ctapAck(0, null);
        }
    }

    private void keepAlive(byte[] data) throws IOException {
        ctapAck(1, new byte[] {0x01});
    }

    private void wink(byte[] data) throws IOException {
        ctapAck(0, null);
    }

    private void lock(byte[] data) throws IOException {
        ctapAck(0, null);
    }

    public boolean hasMoreResponses(){
        return this.hasMoreResponse();
    }
}