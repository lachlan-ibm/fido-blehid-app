/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.ctap;

import java.security.KeyPair;

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
     * The transport type for this transaction (default: BT_CLASSIC_HID).
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
     * Cached so makeCredential / getAssertion can proceed without repeated prompts.
     */
    private boolean userPresent = false;

    /**
     * True once the user has explicitly denied a UP prompt on this channel.
     * Any subsequent command on this CID — regardless of MSG type — must be
     * rejected immediately without opening a new biometric prompt.
     */
    private boolean userDenied = false;

    /**
     * Ephemeral ECDH key pair generated for this CID's key-agreement ceremony.
     * Populated by AuthenticatorAPI.getKey(); consumed and nulled by getTkn().
     * Must NOT be serialised to disk.
     */
    private KeyPair ecdhKeyPair = null;

    /**
     * The CtapHid instance whose response is deferred pending user presence.
     * Null when no deferred command is outstanding.
     */
    private CtapHid pendingDeferredCmd = null;


    /**
     * POJO constructor for creating an empty CTAP transaction.
     * Uses USB_HID transport by default.
     */
    public CtapTxn() {
        // POJO constructor
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
     * Gets the passkey file name for this transaction.
     *
     * @return The passkey file name
     */
    public String getPasskeyFileName() {
        return passkey == null ? null : passkey.getFileName();
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
     * Returns true if the user explicitly denied the UP prompt on this channel.
     *
     * @return true if denied
     */
    public boolean isUserDenied() { return userDenied; }

    /**
     * Marks this channel as explicitly denied by the user.
     * Once set, all subsequent commands on this CID are rejected immediately.
     *
     * @param v true to mark as denied
     */
    public void setUserDenied(boolean v) { this.userDenied = v; }

    /**
     * Returns the ephemeral ECDH key pair for this channel's PIN ceremony.
     * Null until GETKEY has been processed on this CID.
     *
     * @return the key pair, or null if GETKEY has not yet been called
     */
    public java.security.KeyPair getEcdhKeyPair() { return ecdhKeyPair; }

    /**
     * Stores the ephemeral ECDH key pair generated during GETKEY.
     *
     * @param kp Fresh P-256 key pair; pass null to clear after use.
     */
    public void setEcdhKeyPair(java.security.KeyPair kp) { this.ecdhKeyPair = kp; }

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
