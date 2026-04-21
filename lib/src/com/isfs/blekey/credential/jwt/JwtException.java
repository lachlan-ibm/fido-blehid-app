/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.credential.jwt;

/**
 * Exception thrown when JWT operations fail.
 */
public class JwtException extends Exception {
    
    public JwtException(String message) {
        super(message);
    }

    public JwtException(String message, Throwable cause) {
        super(message, cause);
    }
}

// Made with Bob
