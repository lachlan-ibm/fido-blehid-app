/*
 * Copyright IBM 2025
 */

package com.isfs.blekey.hidsvc;

/**
 * Interface for HID transport layer.
 * Allows HIDPasskey to work with both BLE and Classic BT.
 */
public interface IHIDTransport {
    /**
     * Send input report to host
     */
    void sendInputReport(byte[] report);
    
    /**
     * Check if transport is ready
     */
    boolean isReady();
}

// Made with Bob
