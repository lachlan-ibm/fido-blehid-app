/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator;

/**
 * Enum representing the type of credential that can be created.
 */
public enum CredentialType {
    /**
     * No credential can be created (null/none).
     */
    NONE(0),
    
    /**
     * UP only authentication credential.
     */
    TWO_FACTOR(1),
    
    /**
     * UV authentication credential (non-resident).
     */
    PASSKEY(2),

    /**
     * Resident credential (discoverable credential).
     */
    RESIDENT(3);
    
    private final int value;
    
    CredentialType(int value) {
        this.value = value;
    }
    
    /**
     * Gets the integer value of the credential type.
     * 
     * @return The integer value
     */
    public int getValue() {
        return value;
    }
    
    /**
     * Gets the CredentialType from an integer value.
     * 
     * @param value The integer value
     * @return The corresponding CredentialType, or NONE if not found
     */
    public static CredentialType fromInt(int value) {
        for (CredentialType type : values()) {
            if (type.value == value) {
                return type;
            }
        }
        return NONE;
    }
}

// Made with Bob
