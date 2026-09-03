/*
 * Copyright IBM 2025
 */

package com.isfs.blekey.bthid;

import com.isfs.blekey.ctap.Ctap2StatusCode;
import com.isfs.blekey.ctap.CtapHid;
import com.isfs.blekey.ctap.CtapTxn;
import com.isfs.blekey.transport.ICtapTransport;

import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implements the FIDO2 passkey functionality over the HID protocol.
 * This class bridges between the BLE HID service and the CTAP protocol,
 * handling HID reports and translating them to CTAP commands and responses.
 */
public class HIDPasskey {

    /**
     * Reference to the HID transport layer.
     */
    private ICtapTransport _transport;

    /**
     * Logger for debugging and error reporting.
     */
    private static final Logger logger = LoggerFactory.getLogger(HIDPasskey.class);

    private final static String TAG = HIDPasskey.class.getCanonicalName();

    /**
     * Constructs a new HIDPasskey instance with a reference to the HID transport.
     *
     * @param transport The HID transport that will handle communication (BLE or Classic BT)
     */
    public HIDPasskey(ICtapTransport transport) {
        this._transport = transport;
    }

    /**
     * Returns the HID report descriptor map for a FIDO CTAP HID device.
     * This descriptor defines the input and output report formats according to
     * the FIDO CTAP HID specification.
     *
     * @return A byte array containing the HID report descriptor
     */
    protected static byte[] getReportMap() {
        logger.debug(TAG, "getReportMap");
        return new byte[]{
            (byte) 0x06, (byte) 0xD0, (byte) 0xF1,       // Usage Page (FIDO Alliance)
            (byte) 0x09, 0x01,                   // Usage (U2F HID Authenticator Device)
            (byte) 0xA1, 0x01,                   // Collection (Application)
            (byte) 0x09, 0x20,                   //   Usage (Input Report Data)
            (byte) 0x15, 0x00,                   //   Logical Minimum (0)
            (byte) 0x26, (byte) 0xFF, (byte) 0x00,      //   Logical Maximum (255)
            (byte) 0x75, 0x08,                   //   Report Size (8)
            (byte) 0x95, 0x40,                   //   Report Count (64)
            (byte) 0x81, 0x02,                   //   Input (Data, Variable, Absolute)
            (byte) 0x09, 0x21,                   //   Usage (Output Report Data)
            (byte) 0x15, 0x00,
            (byte) 0x26, (byte) 0xFF, (byte) 0x00,
            (byte) 0x75, 0x08,
            (byte) 0x95, 0x40,
            (byte) 0x91, 0x02,                   //   Output (Data, Variable, Absolute)
            (byte) 0xC0                          // End Collection
        };
    }

    /**
     * Processes an output report received from the host device.
     * Parses the report as a CTAP HID command or sequence, processes it,
     * and queues any response back to the host.
     *
     * @param report The output report data received from the host
     */
    public void onOutputReport(byte[] report) {
        logger.debug(TAG, "onOutputReport");
        // Log the complete received frame
        logger.info("RECV FRAME ({}bytes): {}", report != null ? report.length : 0,
            report != null ? java.util.Arrays.toString(report) : "null");
        
        // The kernel HID layer prepends a Report ID byte (0x00) to every write.
        // Strip it so the CTAP HID frame starts at the correct offset.
        if (report != null && report.length > 0 && report[0] == 0x00) {
            report = Arrays.copyOfRange(report, 1, report.length);
        }
        if(report != null && report.length > 5) { //cid + (cmd || seq) === 5 bytes min
            byte[] cid = Arrays.copyOfRange(report, 0, 4);
            // Parse the CTAPHID command
            byte cmdByte = report[4];
            logger.debug("CID: {} CMD: {}", Arrays.toString(cid), cmdByte);
            logger.info("After strip - CID: {} cmdByte: 0x{} ({})",
                Arrays.toString(cid), String.format("%02X", cmdByte & 0xFF), cmdByte);
            CtapHid cmd = null;
            boolean isNewCommand = false;
            if((cmdByte & 0x80) > 0) {
                // New command frame - create new CtapHid instance
                cmd = new CtapHid(report);
                isNewCommand = true;
                
                // Update the assignedCids map with the new command
                // This ensures continuation frames use the correct CtapHid instance
                if (CtapHid.hasOpenCid(cid)) {
                    logger.info("Updating existing CID {} with new command", Arrays.toString(cid));
                    // Create a new transaction with the new command
                    // updateCidTransaction will preserve PIN token and other state
                    CtapHid.updateCidTransaction(cid,
                                new CtapTxn(cid, cmd, null, null, null));
                }
            } else {
                cmd = CtapHid.getPendingByCid(cid);
                logger.info("=== SEQUENCE FRAME: Retrieved cmd from map: {}", cmd != null ? cmd.hashCode() : "NULL");
                if (cmd != null) {
                    logger.info("=== SEQUENCE FRAME: Calling processSequence on cmd {}", cmd.hashCode());
                    cmd.processSequence(report);
                    logger.info("=== SEQUENCE FRAME: After processSequence, hasMoreResponses: {}", cmd.hasMoreResponses());
                } else {
                    logger.error("=== SEQUENCE FRAME: cmd is NULL! Cannot process sequence frame!");
                }
            }
            // Only process message for new command frames if sufficient bytes already received
            // Sequence frames will trigger processing via processSequence() -> processMessage()
            if(cmd != null && isNewCommand && cmd.hasSufficientBytes()) {
                try {
                    cmd.processMessage();
                } catch (Exception e) {
                    logger.error(TAG, e);
                }
            }
            
            // Send any pending responses (must be outside isNewCommand check)
            // Responses can be generated by either:
            // 1. New command frames with sufficient bytes (processed above)
            // 2. Sequence frames completing a multi-frame message (via processSequence)
            logger.info("=== RESPONSE CHECK: cmd={}, hasMoreResponses={}",
                        cmd != null ? cmd.hashCode() : "NULL",
                        cmd != null ? cmd.hasMoreResponses() : "N/A");
            if(cmd != null && cmd.hasMoreResponses()) {
                logger.info("=== SENDING RESPONSES: Starting response transmission");
                try {
                    int frameCount = 0;
                    byte[] rspFrame;
                    // Get and send frames until getResponseSegment returns null
                    while((rspFrame = cmd.getResponseSegment()) != null) {
                        frameCount++;
                        logger.info("=== SENDING RESPONSES: Frame #{}, length: {}", frameCount, rspFrame.length);
                        if (_transport != null) {
                            _transport.sendResponse(rspFrame);
                            logger.info("=== SENDING RESPONSES: Frame #{} sent successfully", frameCount);
                        } else {
                            logger.error("=== SENDING RESPONSES: _transport is NULL! Cannot send frame #{}", frameCount);
                        }
                    }
                    logger.info("=== SENDING RESPONSES: Completed, sent {} frames", frameCount);
                } catch (Exception e) {
                    logger.error("=== SENDING RESPONSES: Exception occurred", e);
                }
            } else {
                logger.warn("=== RESPONSE CHECK: No responses to send (cmd={}, hasMoreResponses={})",
                           cmd != null ? "present" : "NULL",
                           cmd != null ? cmd.hasMoreResponses() : "N/A");
            }
        }
    }

    /**
     * Delivers a deferred CBOR response to the host after user-presence resolution.
     *
     * <p>Takes the deferred {@link CtapHid} from {@code txn}, injects {@code cborResponse}
     * into it, then drains every HID frame via the transport.  Works for both the
     * multi-frame approved path and the single-frame deny/timeout/cancel path.</p>
     *
     * @param txn          The live {@link CtapTxn} holding the deferred command
     * @param cborResponse Pre-built CTAP response bytes (status byte + optional CBOR payload)
     */
    public void sendDeferredResponse(CtapTxn txn, byte[] cborResponse) {
        if (txn == null) {
            logger.error("sendDeferredResponse: txn is null");
            return;
        }
        CtapHid cmd = txn.takeDeferredCmd();
        if (cmd == null) {
            logger.error("sendDeferredResponse: no deferred cmd on txn {} — " +
                         "channel state is invalid; sending CTAPHID_ERROR and evicting CID",
                         java.util.Arrays.toString(txn.getCid()));
            // Send CTAPHID_ERROR(ERR_OTHER) so the platform knows the transaction is dead.
            if (_transport != null) {
                _transport.sendResponse(
                    CtapHid.buildHidErrorFrame(txn.getCid(), Ctap2StatusCode.OTHER));
            } else {
                logger.error("sendDeferredResponse: _transport is also NULL — " +
                             "platform will not be notified of channel failure");
            }
            // Evict the poisoned CID so no further commands are accepted on it.
            CtapHid.evictCid(txn.getCid());
            return;
        }
        try {
            cmd.injectDeferredResponse(cborResponse);
            byte[] frame;
            int frameCount = 0;
            while ((frame = cmd.getResponseSegment()) != null) {
                frameCount++;
                if (_transport != null) {
                    _transport.sendResponse(frame);
                    logger.info("=== DEFERRED RESPONSE: Frame #{} sent successfully", frameCount);
                } else {
                    logger.error("sendDeferredResponse: _transport is NULL — cannot send frame");
                    break;
                }
            }
            logger.info("sendDeferredResponse: response sent ({} bytes injected)", cborResponse.length);
        } catch (Exception e) {
            logger.error("sendDeferredResponse: exception", e);
        }
    }

}
