
package com.example.blehidfido2.ctap;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.example.blehidfido2.PasskeyPeripheral;
import com.example.blehidfido2.authenticator.AuthenticatorAPI;
import com.example.blehidfido2.util.Cbor;


/**
 * This class accumulates HID message frames until a complete message
 * has been recieved. It then unpacks the message and generates a 
 * response.
 * 
 * Responses can be collected by using the static method CtapHid.getPendingResponse
 * which will fetch the next pending response buffer from the internal queue.
 */
public class CtapHid {  

    private byte[] cmdFrame;
    private List<byte[]> sequenceFrames;
    private byte[] cid;
    private int byteCount;
    private CtapHidCmd messageType;
    private byte[] initResponse;
    private List<byte[]> responseSegments;
    private boolean responseReady = false;
    private int responseSegment = -1; //send init then start sequences at 0
    
    // List of outportReport requests which have not been replied to.
    private static Deque<CtapHidTimeoutRsp> pending = new ArrayDeque<CtapHidTimeoutRsp>();
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

    public static byte[] getPendingByCid(byte[] cid) {
        if (assignedCids.containsKey(cid)) {
            return assignedCids.get(cid).getCid();
        } //else 
        return null;
    }

    public CtapHid processSequence(byte[] segment) {
        this.sequenceFrames.add(segment);
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

    private byte[] getResponseSegment() {
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
        Map<CtapHidCmd, CtapFcnPtr> fcnPtrs = Map.of(
            CtapHidCmd.MSG, this::u2f,
            CtapHidCmd.CBOR, this::cbor,
            CtapHidCmd.INIT, this::init,
            CtapHidCmd.PING, this::ping,
            CtapHidCmd.CANCEL, this::cancel,
            CtapHidCmd.ERROR, this::error,
            CtapHidCmd.KEEP_ALIVE, this::keepAlive,
            CtapHidCmd.WINK, this::wink,
            CtapHidCmd.LOCK, this::lock
        );
        fcnPtrs.get(this.messageType).process( this.getCtapHidData() );
        if(this.responseReady == true) {
            CtapHidTimeoutRsp pendingRsp = CtapHid.pending.pollFirst();
            if (pendingRsp != null && !pendingRsp.hasResponded()) {
                pendingRsp.setResponded(true);
                PasskeyPeripheral.sendResponse(pendingRsp.getCentral(),
                                               pendingRsp.getCharacteristic(),
                                               this.getResponseSegment());
            }
        }
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

    private void invalidCborRequest() {
        logger.warn("Invalid CBOR Data recieved, PANIC!");
        this.initResponse = new byte[64];
        System.arraycopy(this.getCid(), 0, this.initResponse, 0, 4);
        this.initResponse[6] = 0x01;
        this.initResponse[7] = (byte) Ctap2StatusCode.INVALID_CBOR.getCode();
    }

    private void cbor(byte[] data) {
        if(data.length < 1) {
            invalidCborRequest();
        } else {
            int api = (int) data[0];
            byte[] cborBytes = new byte[data.length - 1];
            System.arraycopy(data, 1, cborBytes, 0, data.length - 1);
            Object cborObj = Cbor.decode(cborBytes);
            if(cborObj == null || !(cborObj instanceof Map)) {
                invalidCborRequest();
            } else {
                Map cbor = (Map) cborObj;
                buildCborInitAndSequencePackets(AuthenticatorAPI.process(api, (Map<String, Object>) cbor));
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
        byte[] rsp = new byte[64];
        rsp[0] = (byte) CtapHidCmd.INIT.getValue();
        rsp[1] = (17  & 0xFF00) >> 8; // Byte count
        rsp[2] = (17 & 0xFF);
        System.arraycopy(nonce, 0, rsp, 3, 8);
        System.arraycopy(newCid, 0, rsp, 11, 4);
                                    //version 2; leeet; CAPABILITY_CBOR | CAPABILITY_NMSG
        byte[] specStuff = new byte[] {0x02, 0x13, 0x33, 0x37, 0x0C};
        System.arraycopy(specStuff, 0, rsp, 15, 5);
        this.initResponse = rsp;
        this.responseReady = true;
    }

    private void ping(byte[] data) {
        this.initResponse = new byte[0];
    }

    private void cancel(byte[] data) {
        this.initResponse = new byte[0];
    }

    private void error(byte[] data) {
        this.initResponse = new byte[0];
    }

    private void keepAlive(byte[] data) {
        this.initResponse = new byte[0];
    }

    private void wink(byte[] data) {
        this.initResponse = new byte[0];
    }

    private void lock(byte[] data) {
        this.initResponse = new byte[0];
    }

    public static byte[] getPendingResponse() {
        for(byte[] cid: CtapHid.assignedCids.keySet()) {
            CtapHid cmd = CtapHid.assignedCids.get(cid);
            if(cmd.isResponseReady() && cmd.hasMoreResponse()) {
                return cmd.getResponseSegment();
            }
        }
        return null;

    }

    public static void sendOrQueuePendingResponse(
            BluetoothCentral central, 
            BluetoothGattCharacteristic characteristic) {
        byte[] maybeRsp = CtapHid.getPendingResponse();
        if(maybeRsp != null) {
            PasskeyPeripheral.sendResponse(central, characteristic, maybeRsp);
        } else {
            CtapHidTimeoutRsp timeoutRsp = new CtapHidTimeoutRsp(central, characteristic);
            timeoutRsp.start();
            CtapHid.pending.addLast(timeoutRsp);
        }
    }

    public class CtapHidTimeoutRsp extends Thread {

        private volatile boolean responded = false;
        private BluetoothCentral central;
        private BluetoothGattCharacteristic characteristic;

        public CtapHidTimeoutRsp(BluetoothCentral cent, BluetoothGattCharacteristic character) {
            this.central = cent;
            this.characteristic = character;
         }

        @Override
        public void run() {
            // Leave a report as pending for 0.5s at most
            long timeout = System.currentTimeMillis() + 500;
            while(!responded) {
                sleep(5);
                long now = System.currentTimeMillis();
                if(now >= timeout && !responded) {
                    responded = true;
                    PasskeyPeripheral.sendResponse(central, characteristic, 
                                            //CTAPHID_KEEPALIVE; length 1; STATUS_PROCESSING
                            new byte[] {(byte) CtapHidCmd.KEEP_ALIVE.getValue(), 0x01, 0x02});
                    break;
                }
            }
        }

        public void setResponded(boolean rsp) {
            this.responded = rsp;
        }

        public boolean hasResponded() {
            return this.responded;
        }

        public BluetoothCentral getCentral() {
            return this.central;
        }

        public BluetoothGattCharacteristic getCharacteristic() {
            return this.characteristic;
        }
    }
}
