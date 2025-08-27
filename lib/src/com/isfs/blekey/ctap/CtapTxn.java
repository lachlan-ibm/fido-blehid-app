/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.ctap;

import com.isfs.blekey.data.Passkey;

/**
 * Represents a CTAP (Client to Authenticator Protocol) transaction.
 * This class encapsulates the data needed for a FIDO2 transaction between
 * a client (relying party) and the authenticator.
 */
public class CtapTxn {
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

    private byte[] pinHash;

    /**
     * Default constructor for creating an empty CTAP transaction.
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
     */
    public CtapTxn(byte[] cid, CtapHid cmd, byte[] pinAuthTkn, Passkey passkey, byte[] pinHash) {
        this.cid = cid != null ? cid.clone() : null;
        this.cmd = cmd;
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
}

// Made with Bob
