/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.credential.status;

/**
 * Enumeration of credential status values according to Status List 2021 (RFC 9102).
 */
public enum CredentialStatus {
    /**
     * Credential is valid and can be used.
     */
    VALID,
    
    /**
     * Credential has been revoked and should not be accepted.
     */
    REVOKED,
    
    /**
     * Credential is temporarily suspended.
     */
    SUSPENDED,
    
    /**
     * Status is unknown (e.g., network error, invalid status list).
     */
    UNKNOWN
}

// Made with Bob