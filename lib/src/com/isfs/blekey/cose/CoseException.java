/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.cose;

/**
 * Exception thrown when COSE operations fail.
 * This exception wraps errors from COSE signing, verification, and encoding/decoding operations.
 */
public class CoseException extends Exception {
    
    /**
     * Constructs a new CoseException with the specified detail message.
     *
     * @param message the detail message
     */
    public CoseException(String message) {
        super(message);
    }
    
    /**
     * Constructs a new CoseException with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause of this exception
     */
    public CoseException(String message, Throwable cause) {
        super(message, cause);
    }
    
    /**
     * Constructs a new CoseException with the specified cause.
     *
     * @param cause the cause of this exception
     */
    public CoseException(Throwable cause) {
        super(cause);
    }
}

// Made with Bob
