/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.ctap;

import com.isfs.blekey.data.Passkey;

/**
 * Represents a CTAP (Client to Authenticator Protocol) transaction.
 * This class encapsulates the data needed for a FIDO2 transaction between
 * a client (relying party) and the authenticator.
 *
 * Supports multiple transport types: USB HID, BLE FIDO, and Bluetooth Classic HID.
 */
public class CtapTxn {
    
    /**
     * Transport type for CTAP transactions.
     */
    public enum TransportType {
        /** BLE FIDO transport (new) */
        BLE_FIDO,
        /** Bluetooth Classic HID transport */
        BT_CLASSIC_HID
    }
    /**
     * The channel identifier for this transaction.
     */
    private byte[] cid;
    
    /**
     * The CtapHid command enapsulating the type of CTAP command.
     */
    private CtapHid cmd;
    
    /**
     * The PIN authentication token used for this transaction.
     */
    private byte[] pinAuthTkn;
    
    /**
     * The passkey associated with this transaction.
     */
    private Passkey passkey;

    /**
     * The PIN hash (32 bytes) for the passkey.
     */
    private byte[] pinHash;

    /**
     * The passkey file name used to open the passkey.
     */
    private String passkeyFileName;

    /**
     * The transport type for this transaction (default: BT_CLASSIC_HID for backward compatibility).
     */
    private TransportType transport = TransportType.BT_CLASSIC_HID;

    /**
     * The device identifier for BLE transport (e.g., MAC address).
     * Null for BT_CLASSIC_HID transport.
     */
    private String deviceIdentifier;

    /**
     * The BLE MTU for BLE transport (default: 23 bytes).
     */
    private int bleMtu = 23;

    /**
     * True once the user has approved a UP prompt on this channel.
     * Cached here so makeCredential / getAssertion can proceed without a second prompt.
     */
    private boolean userPresent = false;

    /**
     * True once the platform key TEE auth window has been successfully opened on
     * this channel. Allows makeCredential / getAssertion / getTkn to skip bio re-challenge.
     */
    private boolean bioVerified = false;

    /**
     * Raw ECDH IKM derived during the first bio-gate opening on this channel.
     * Cached so subsequent CTAP commands can recompute the HKDF seed without re-bio.
     * Null until the first successful bio-gate on this CID.
     * Must NOT be serialised to disk.
     */
    private byte[] platformIkm = null;

    /**
     * The CtapHid instance whose response is deferred pending user presence.
     * Null when no deferred command is outstanding.
     */
    private CtapHid pendingDeferredCmd = null;

    /**
     * Default constructor for creating an empty CTAP transaction.
     * Uses USB_HID transport by default for backward compatibility.
     */
    public CtapTxn() {
        // Default constructor
    }
    
    /**
     * Constructs a new CTAP transaction with the specified parameters.
     *
     * @param cid The channel identifier
     * @param cmd The CtapHid command
     * @param pinAuthTkn The PIN authentication token
     * @param passkey The passkey for this transaction
     * @param pinHash The full PIN hash
     */
    public CtapTxn(byte[] cid, CtapHid cmd, byte[] pinAuthTkn, Passkey passkey, byte[] pinHash) {
        this.cid = cid != null ? cid.clone() : null;
        this.cmd = cmd;
        this.pinAuthTkn = pinAuthTkn != null ? pinAuthTkn.clone() : null;
        this.passkey = passkey;
        this.pinHash = pinHash != null ? pinHash.clone() : null;
    }
    
    /**
     * Constructs a new CTAP transaction for BLE transport.
     *
     * @param deviceIdentifier The device identifier (e.g., MAC address)
     * @param mtu The BLE MTU value
     * @param pinAuthTkn The PIN authentication token
     * @param passkey The passkey for this transaction
     * @param pinHash The full PIN hash
     */
    public CtapTxn(String deviceIdentifier, int mtu, byte[] pinAuthTkn,
                   Passkey passkey, byte[] pinHash) {
        this.transport = TransportType.BLE_FIDO;
        this.deviceIdentifier = deviceIdentifier;
        this.bleMtu = mtu;
        this.cid = null; // BLE doesn't use channel IDs
        this.cmd = null; // Set later
        this.pinAuthTkn = pinAuthTkn != null ? pinAuthTkn.clone() : null;
        this.passkey = passkey;
        this.pinHash = pinHash != null ? pinHash.clone() : null;
    }
    
    /**
     * Gets the channel identifier for this transaction.
     *
     * @return A copy of the channel identifier
     */
    public byte[] getCid() {
        return cid != null ? cid.clone() : null;
    }
    
    /**
     * Sets the channel identifier for this transaction.
     *
     * @param cid The channel identifier to set
     */
    public void setCid(byte[] cid) {
        this.cid = cid != null ? cid.clone() : null;
    }
    
    /**
     * Gets the command byte for this transaction.
     *
     * @return The CtapHidcommand
     */
    public CtapHid getCmd() {
        return cmd;
    }
    
    /**
     * Sets the command byte for this transaction.
     *
     * @param cmd The CtapHid command to set
     */
    public void setCmd(CtapHid cmd) {
        this.cmd = cmd;
    }
    
    /**
     * Gets the PIN authentication token for this transaction.
     *
     * @return A copy of the PIN authentication token
     */
    public byte[] getPinAuthTkn() {
        return pinAuthTkn != null ? pinAuthTkn.clone() : null;
    }
    
    /**
     * Sets the PIN authentication token for this transaction.
     *
     * @param pinAuthTkn The PIN authentication token to set
     */
    public void setPinAuthTkn(byte[] pinAuthTkn) {
        this.pinAuthTkn = pinAuthTkn != null ? pinAuthTkn.clone() : null;
    }
    
    /**
     * Gets the passkey associated with this transaction.
     *
     * @return The passkey
     */
    public Passkey getPasskey() {
        return passkey;
    }
    
    /**
     * Sets the passkey associated with this transaction.
     *
     * @param passkey The passkey to set
     */
    public void setPasskey(Passkey passkey) {
        this.passkey = passkey;
    }

    /**
     * Sets the PIN hash for this transaction.
     *
     * @param ph The PIN hash to set
     */
    public void setPinHash(byte[] ph) {
        this.pinHash = ph != null ? ph.clone() : null;
    }

    /**
     * Gets the PIN hash for this transaction.
     *
     * @return A copy of the PIN hash
     */
    public byte[] getPinHash() {
        return pinHash != null ? pinHash.clone() : null;
    }

    /**
     * Sets the passkey file name for this transaction.
     *
     * @param fileName The passkey file name
     */
    public void setPasskeyFileName(String fileName) {
        this.passkeyFileName = fileName;
    }

    /**
     * Gets the passkey file name for this transaction.
     *
     * @return The passkey file name
     */
    public String getPasskeyFileName() {
        return passkeyFileName;
    }

    /**
     * Gets the transport type for this transaction.
     *
     * @return The transport type
     */
    public TransportType getTransport() {
        return transport;
    }

    /**
     * Sets the transport type for this transaction.
     *
     * @param transport The transport type to set
     */
    public void setTransport(TransportType transport) {
        this.transport = transport;
    }

    /**
     * Gets the device identifier for this transaction.
     *
     * @return The device identifier (e.g., MAC address), or null if not using BLE transport
     */
    public String getDeviceIdentifier() {
        return deviceIdentifier;
    }

    /**
     * Sets the device identifier for this transaction.
     *
     * @param deviceIdentifier The device identifier to set (e.g., MAC address)
     */
    public void setDeviceIdentifier(String deviceIdentifier) {
        this.deviceIdentifier = deviceIdentifier;
    }

    /**
     * Gets the BLE MTU for this transaction.
     *
     * @return The BLE MTU value
     */
    public int getBleMtu() {
        return bleMtu;
    }

    /**
     * Sets the BLE MTU for this transaction.
     *
     * @param bleMtu The BLE MTU value to set
     */
    public void setBleMtu(int bleMtu) {
        this.bleMtu = bleMtu;
    }

    /**
     * Returns true if user presence has been approved on this channel.
     *
     * @return true if user presence was collected for this transaction
     */
    public boolean isUserPresent() {
        return userPresent;
    }

    /**
     * Sets the user presence flag for this transaction.
     *
     * @param v true to mark user presence as collected
     */
    public void setUserPresent(boolean v) {
        this.userPresent = v;
    }

    /**
     * Returns true if the platform key TEE auth window has been opened on this channel.
     *
     * @return true if bio-verified
     */
    public boolean isBioVerified() { return bioVerified; }

    /**
     * Sets the bio-verified flag.
     *
     * @param v true to mark the channel as bio-verified
     */
    public void setBioVerified(boolean v) { this.bioVerified = v; }

    /**
     * Gets the cached ECDH IKM for this channel.
     *
     * @return A copy of the platform IKM, or null if not yet derived
     */
    public byte[] getPlatformIkm() { return platformIkm != null ? platformIkm.clone() : null; }

    /**
     * Caches the ECDH IKM for this channel.
     *
     * @param ikm The IKM to cache (defensive copy is made)
     */
    public void setPlatformIkm(byte[] ikm) { this.platformIkm = ikm != null ? ikm.clone() : null; }

    /**
     * Stores the deferred CtapHid command awaiting user presence resolution.
     *
     * @param cmd The CtapHid instance to defer
     */
    public void setDeferredCmd(CtapHid cmd) {
        this.pendingDeferredCmd = cmd;
    }

    /**
     * Retrieves and clears the deferred CtapHid command (so it cannot be injected twice).
     *
     * @return The deferred CtapHid instance, or null if none is pending
     */
    public CtapHid takeDeferredCmd() {
        CtapHid cmd = this.pendingDeferredCmd;
        this.pendingDeferredCmd = null;
        return cmd;
    }
}

// Made with Bob
