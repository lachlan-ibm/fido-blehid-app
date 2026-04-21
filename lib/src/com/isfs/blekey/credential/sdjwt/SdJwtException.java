/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.credential.sdjwt;

/**
 * Exception thrown when SD-JWT operations fail.
 */
public class SdJwtException extends Exception {
    
    public SdJwtException(String message) {
        super(message);
    }
    
    public SdJwtException(String message, Throwable cause) {
        super(message, cause);
    }
}

// Made with Bob