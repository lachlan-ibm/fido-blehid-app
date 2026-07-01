/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.mdl;

/**
 * Exception thrown when an error occurs during ISO mDL (mobile Driver's License) operations.
 * 
 * <p>This exception is used for errors specific to ISO 18013-5 mDL processing, including:
 * <ul>
 *   <li>Invalid mDL data structure</li>
 *   <li>CBOR encoding/decoding errors</li>
 *   <li>Signature verification failures</li>
 *   <li>Invalid namespace or element identifiers</li>
 *   <li>Digest calculation errors</li>
 * </ul>
 * 
 * @see <a href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5:2021</a>
 */
public class MdlException extends Exception {
    
    private static final long serialVersionUID = 1L;
    
    /**
     * Constructs a new MdlException with the specified detail message.
     * 
     * @param message the detail message
     */
    public MdlException(String message) {
        super(message);
    }
    
    /**
     * Constructs a new MdlException with the specified detail message and cause.
     * 
     * @param message the detail message
     * @param cause the cause of this exception
     */
    public MdlException(String message, Throwable cause) {
        super(message, cause);
    }
    
    /**
     * Constructs a new MdlException with the specified cause.
     * 
     * @param cause the cause of this exception
     */
    public MdlException(Throwable cause) {
        super(cause);
    }
}

// Made with Bob
