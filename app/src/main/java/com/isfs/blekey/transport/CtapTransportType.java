/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.transport;

/**
 * Identifies the active CTAP transport framing protocol.
 */
public enum CtapTransportType {
    /** Classic Bluetooth HID (CTAP HID §8). */
    HID,
    /** BLE GATT FIDO profile (CTAP BLE §11). */
    BLE_GATT
}
