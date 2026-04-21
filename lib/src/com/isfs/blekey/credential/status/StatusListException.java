/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.credential.status;

/**
 * Exception thrown when status list operations fail.
 */
public class StatusListException extends Exception {
    
    public StatusListException(String message) {
        super(message);
    }
    
    public StatusListException(String message, Throwable cause) {
        super(message, cause);
    }
}

// Made with Bob