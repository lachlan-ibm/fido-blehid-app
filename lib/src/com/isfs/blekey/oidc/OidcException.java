/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.oidc;

/**
 * Exception thrown when OIDC operations fail.
 * This includes errors in authorization, token exchange, credential issuance, and presentation.
 */
public class OidcException extends Exception {
    
    public OidcException(String message) {
        super(message);
    }
    
    public OidcException(String message, Throwable cause) {
        super(message, cause);
    }
}

// Made with Bob