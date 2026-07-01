/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.jsonld;

/**
 * Exception thrown when an error occurs during JSON-LD credential operations.
 * 
 * <p>This exception is used for errors specific to JSON-LD processing, including:
 * <ul>
 *   <li>Invalid JSON-LD structure or syntax</li>
 *   <li>Context resolution failures</li>
 *   <li>JSON-LD expansion/compaction errors</li>
 *   <li>Proof generation or verification failures</li>
 *   <li>Missing required fields in credentials</li>
 *   <li>Invalid credential subject data</li>
 * </ul>
 * 
 * @see <a href="https://www.w3.org/TR/json-ld11/">JSON-LD 1.1</a>
 * @see <a href="https://www.w3.org/TR/vc-data-model/">Verifiable Credentials Data Model</a>
 */
public class JsonLdException extends Exception {
    
    private static final long serialVersionUID = 1L;
    
    /**
     * Constructs a new JsonLdException with the specified detail message.
     * 
     * @param message the detail message
     */
    public JsonLdException(String message) {
        super(message);
    }
    
    /**
     * Constructs a new JsonLdException with the specified detail message and cause.
     * 
     * @param message the detail message
     * @param cause the cause of this exception
     */
    public JsonLdException(String message, Throwable cause) {
        super(message, cause);
    }
    
    /**
     * Constructs a new JsonLdException with the specified cause.
     * 
     * @param cause the cause of this exception
     */
    public JsonLdException(Throwable cause) {
        super(cause);
    }
}

// Made with Bob