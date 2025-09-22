/*
 * Copyright IBM 2025
 */
/*IBM Confidential
* OCO Source Materials
* 5725-V89 5725-V90
*
* Copyright IBM Corp. 2025
*
* The source code for this program is not published or otherwise divested of its trade secrets,
* irrespective of what has been deposited with the U.S. Copyright Office.
*/

package com.isfs.blekey.hidsvc;

import com.isfs.blekey.ctap.CtapHid;

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
     * Reference to the parent HID service that manages BLE connections.
     */
    private HIDService _service;

    /**
     * Logger for debugging and error reporting.
     */
    private static final Logger logger = LoggerFactory.getLogger(HIDPasskey.class);

    /**
     * Constructs a new HIDPasskey instance with a reference to the parent HID service.
     *
     * @param service The HID service that will handle BLE communication
     */
    public HIDPasskey(HIDService service) {
        this._service = service;
    }

    /**
     * Returns the HID report descriptor map for a FIDO CTAP HID device.
     * This descriptor defines the input and output report formats according to
     * the FIDO CTAP HID specification.
     *
     * @return A byte array containing the HID report descriptor
     */
    protected static byte[] getReportMap() {
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
        if(report != null && report.length > 5) { //cid + (cmd || seq) === 5 bytes min
            byte[] cid = Arrays.copyOfRange(report, 0, 4);
            // Parse the CTAPHID command
            byte cmdByte = report[4];
            CtapHid cmd = null;
            if((cmdByte & 0x80) > 0) {
                cmd = new CtapHid(report);
            } else {
                cmd = CtapHid.getPendingByCid(cid);
                if (cmd != null) { 
                    cmd.processSequence(report);
                }
            }
            if(cmd != null && cmd.hasSufficientBytes()) {
                try {
                    cmd.processMessage();
                    // queue any response back
                    while(cmd.hasMoreResponses()) {
                        byte[] rspFrame = cmd.getResponseSegment();
                        this._service.addInputReport(rspFrame);
                    }
                } catch (Exception e) {
                    logger.error(HIDPasskey.class.getSimpleName() + "onOutputReport", e);
                }
            }
        }
    }

}
