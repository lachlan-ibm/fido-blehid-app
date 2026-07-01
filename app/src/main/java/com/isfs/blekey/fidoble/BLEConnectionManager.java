/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.fidoble;

import android.bluetooth.BluetoothDevice;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages BLE FIDO connections and per-device state.
 * 
 * This manager tracks connected devices, their MTU settings, and pending
 * message fragments. It provides thread-safe operations for managing
 * multiple simultaneous BLE connections.
 * 
 * Phase 2.4: Single-device support (multi-device collision handling in Phase 3)
 */
public class BLEConnectionManager {

    private static final String TAG = BLEConnectionManager.class.getCanonicalName();

    // Default BLE MTU (minimum guaranteed by spec)
    private static final int DEFAULT_MTU = 23;
    
    // Connection timeout (30 seconds of inactivity)
    private static final long CONNECTION_TIMEOUT_MS = 30_000;

    /**
     * Per-device connection state.
     */
    private static class DeviceState {
        final BluetoothDevice device;
        int mtu = DEFAULT_MTU;
        final List<byte[]> pendingFragments = new ArrayList<>();
        long lastActivityTime = System.currentTimeMillis();
        boolean hasCompleteMessage = false;

        DeviceState(BluetoothDevice device) {
            this.device = device;
        }

        void updateActivity() {
            this.lastActivityTime = System.currentTimeMillis();
        }

        boolean isStale() {
            return (System.currentTimeMillis() - lastActivityTime) > CONNECTION_TIMEOUT_MS;
        }
    }

    // Thread-safe map: device address -> state
    private final ConcurrentHashMap<String, DeviceState> deviceStates = new ConcurrentHashMap<>();

    /**
     * Called when a device connects.
     * 
     * @param device The connected device
     */
    public void onDeviceConnected(@NonNull BluetoothDevice device) {
        String address = device.getAddress();
        DeviceState state = new DeviceState(device);
        deviceStates.put(address, state);
        
        Log.d(TAG, "Device connected: " + address + ", MTU=" + DEFAULT_MTU);
    }

    /**
     * Called when a device disconnects.
     * 
     * @param device The disconnected device
     */
    public void onDeviceDisconnected(@NonNull BluetoothDevice device) {
        String address = device.getAddress();
        DeviceState removed = deviceStates.remove(address);
        
        if (removed != null) {
            Log.d(TAG, "Device disconnected: " + address + 
                ", had " + removed.pendingFragments.size() + " pending fragments");
        }
    }

    /**
     * Called when MTU changes for a device.
     * 
     * @param device The device
     * @param mtu The new MTU value
     */
    public void onMtuChanged(@NonNull BluetoothDevice device, int mtu) {
        String address = device.getAddress();
        DeviceState state = deviceStates.get(address);
        
        if (state != null) {
            state.mtu = mtu;
            state.updateActivity();
            Log.d(TAG, "MTU changed for " + address + ": " + mtu);
        } else {
            Log.w(TAG, "MTU change for unknown device: " + address);
        }
    }

    /**
     * Gets the current MTU for a device.
     * 
     * @param device The device
     * @return The MTU value, or DEFAULT_MTU if device not found
     */
    public int getMtu(@NonNull BluetoothDevice device) {
        String address = device.getAddress();
        DeviceState state = deviceStates.get(address);
        return (state != null) ? state.mtu : DEFAULT_MTU;
    }

    /**
     * Adds a fragment for a device.
     * 
     * @param device The device
     * @param fragment The fragment data
     */
    public void addFragment(@NonNull BluetoothDevice device, @NonNull byte[] fragment) {
        String address = device.getAddress();
        DeviceState state = deviceStates.get(address);
        
        if (state == null) {
            Log.w(TAG, "Fragment received for unknown device: " + address);
            return;
        }

        state.pendingFragments.add(fragment);
        state.updateActivity();
        
        Log.d(TAG, "Fragment added for " + address + 
            ", total fragments: " + state.pendingFragments.size() +
            ", fragment size: " + fragment.length);

        // Check if we have a complete message
        checkCompleteMessage(state);
    }

    /**
     * Gets pending fragments for a device.
     * 
     * @param device The device
     * @return List of pending fragments (may be empty)
     */
    @NonNull
    public List<byte[]> getPendingFragments(@NonNull BluetoothDevice device) {
        String address = device.getAddress();
        DeviceState state = deviceStates.get(address);
        
        if (state == null) {
            return new ArrayList<>();
        }

        return new ArrayList<>(state.pendingFragments);
    }

    /**
     * Clears pending fragments for a device.
     * 
     * @param device The device
     */
    public void clearFragments(@NonNull BluetoothDevice device) {
        String address = device.getAddress();
        DeviceState state = deviceStates.get(address);
        
        if (state != null) {
            int count = state.pendingFragments.size();
            state.pendingFragments.clear();
            state.hasCompleteMessage = false;
            state.updateActivity();
            
            Log.d(TAG, "Cleared " + count + " fragments for " + address);
        }
    }

    /**
     * Checks if a device has a complete message ready.
     * 
     * @param device The device
     * @return true if a complete message is available
     */
    public boolean hasCompleteMessage(@NonNull BluetoothDevice device) {
        String address = device.getAddress();
        DeviceState state = deviceStates.get(address);
        
        return (state != null) && state.hasCompleteMessage;
    }

    /**
     * Gets all connected device addresses.
     * 
     * @return Set of device addresses
     */
    @NonNull
    public Set<String> getConnectedDevices() {
        return Set.copyOf(deviceStates.keySet());
    }

    /**
     * Gets the number of connected devices.
     * 
     * @return Number of connected devices
     */
    public int getConnectedDeviceCount() {
        return deviceStates.size();
    }

    /**
     * Cleans up stale connections (inactive for > 30 seconds).
     * 
     * @return Number of connections cleaned up
     */
    public int cleanupStaleConnections() {
        int cleaned = 0;
        
        for (String address : deviceStates.keySet()) {
            DeviceState state = deviceStates.get(address);
            
            if (state != null && state.isStale()) {
                deviceStates.remove(address);
                cleaned++;
                Log.d(TAG, "Cleaned up stale connection: " + address);
            }
        }
        
        if (cleaned > 0) {
            Log.d(TAG, "Cleaned up " + cleaned + " stale connections");
        }
        
        return cleaned;
    }

    /**
     * Checks if fragments form a complete message.
     * 
     * This is a simplified check for Phase 2.4 (single-device support).
     * A complete message is detected when:
     * 1. Single fragment (no fragmentation)
     * 2. Multiple fragments with proper sequence (0, 1, 2, ...)
     * 
     * @param state The device state
     */
    private void checkCompleteMessage(@NonNull DeviceState state) {
        List<byte[]> fragments = state.pendingFragments;
        
        if (fragments.isEmpty()) {
            state.hasCompleteMessage = false;
            return;
        }

        // Single fragment case
        if (fragments.size() == 1) {
            byte[] first = fragments.get(0);
            // Check if it's a complete single-packet message (has CMD/STATUS + HLEN)
            if (first.length >= 2) {
                state.hasCompleteMessage = true;
                Log.d(TAG, "Complete single-packet message detected for " + 
                    state.device.getAddress());
            }
            return;
        }

        // Multi-fragment case
        // First fragment should have 3+ bytes (CMD/STATUS + HLEN + LLEN)
        byte[] first = fragments.get(0);
        if (first.length < 3) {
            state.hasCompleteMessage = false;
            return;
        }

        // Extract expected data length from first fragment
        byte hlen = first[1];
        byte llen = first[2];
        int expectedDataLen = ((hlen & 0xFF) << 8) | (llen & 0xFF);

        // Calculate total data received so far
        int totalData = first.length - 3; // First fragment data (after header)
        
        for (int i = 1; i < fragments.size(); i++) {
            byte[] frag = fragments.get(i);
            
            // Verify sequence number
            if (frag.length < 1 || frag[0] != (i - 1)) {
                Log.w(TAG, "Invalid sequence at fragment " + i + " for " + 
                    state.device.getAddress());
                state.hasCompleteMessage = false;
                return;
            }
            
            totalData += frag.length - 1; // Continuation data (after SEQ)
        }

        // Check if we have all the data
        state.hasCompleteMessage = (totalData >= expectedDataLen);
        
        if (state.hasCompleteMessage) {
            Log.d(TAG, "Complete multi-packet message detected for " + 
                state.device.getAddress() + 
                ", fragments=" + fragments.size() +
                ", expected_data=" + expectedDataLen +
                ", received_data=" + totalData);
        }
    }

    /**
     * Gets device state for debugging.
     * 
     * @param device The device
     * @return Device state info string, or null if not found
     */
    @Nullable
    public String getDeviceStateInfo(@NonNull BluetoothDevice device) {
        String address = device.getAddress();
        DeviceState state = deviceStates.get(address);
        
        if (state == null) {
            return null;
        }

        long inactiveSec = (System.currentTimeMillis() - state.lastActivityTime) / 1000;
        
        return String.format("Device: %s, MTU: %d, Fragments: %d, Complete: %s, Inactive: %ds",
            address, state.mtu, state.pendingFragments.size(), 
            state.hasCompleteMessage, inactiveSec);
    }

    /**
     * Clears all device states (shutdown).
     */
    public void clear() {
        int count = deviceStates.size();
        deviceStates.clear();
        Log.d(TAG, "Cleared all device states (" + count + " devices)");
    }
}

// Made with Bob