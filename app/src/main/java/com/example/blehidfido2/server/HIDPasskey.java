package com.example.blehidfido2.server;

import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothGattDescriptor;

import com.welie.blessed.BluetoothCentral;
import com.welie.blessed.BluetoothPeripheralManager;

import com.example.blehidfido2.util.BleUtils;
import com.example.blehidfido2.ctap.CtapHid;

import java.util.Arrays;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class HIDPasskey {
    private HIDService s;

    public HIDPasskey(HIDService s) {
        this.service = s;
    }

    private static final Logger logger = LoggerFactory.getLogger(PasskeyPeripheral.class);

    @Override
    protected static byte[] getReportMap() {
        return new byte[]{
            (byte) 0x06, (byte) 0xD0, 0xF1,       // Usage Page (FIDO Alliance)
            (byte) 0x09, 0x01,                   // Usage (U2F HID Authenticator Device)
            (byte) 0xA1, 0x01,                   // Collection (Application)
            (byte) 0x09, 0x20,                   //   Usage (Input Report Data)
            (byte) 0x15, 0x00,                   //   Logical Minimum (0)
            (byte) 0x26, (byte) 0xFF, 0x00,      //   Logical Maximum (255)
            (byte) 0x75, 0x08,                   //   Report Size (8)
            (byte) 0x95, 0x40,                   //   Report Count (64)
            (byte) 0x81, 0x02,                   //   Input (Data, Variable, Absolute)
            (byte) 0x09, 0x21,                   //   Usage (Output Report Data)
            (byte) 0x15, 0x00,
            (byte) 0x26, (byte) 0xFF, 0x00,
            (byte) 0x75, 0x08,
            (byte) 0x95, 0x40,
            (byte) 0x91, 0x02,                   //   Output (Data, Variable, Absolute)
            (byte) 0xC0                          // End Collection
        };
    }

    public void onOutputReport(byte[] report) {
        if(report != null && report.length > 5) { //cid + (cmd || seq) === 5 bytes min
            byte[] cid = Arrays.copyOfRange(report, 0, 4);
            // Parse the CTAPHID command
            byte cmdByte = report[4];
            CtapHid cmd = null;
            if(cmdByte & 0x80) {
                cmd = new CtapHid(report);
            } else {
                cmd = CtapHid.getPendingByCid(cid);
                if (cmd != null) { 
                    cmd.processSequence(report);
                }
            }
            if(cmd != null && cmd.hasSufficientBytes()) {
                cmd.processMessage();
                // queue any response back
                while(cmd.hasMoreResponses()) {
                    service.addInputReport(cmd.getResponse());
                }
            }

        }
    }
}

