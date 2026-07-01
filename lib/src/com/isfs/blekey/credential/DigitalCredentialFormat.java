/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential;

/**
 * Enumeration of supported digital credential formats.
 * 
 * MVP Implementation: Only SD-JWT-VC format is supported.
 * Post-MVP: Will add ISO_MDOC and JSON_LD formats.
 */
public enum DigitalCredentialFormat {
    /**
     * SD-JWT Verifiable Credential format (RFC 7519 + SD-JWT).
     * This is the primary format for MVP implementation.
     */
    SD_JWT_VC("sd-jwt-vc", "SD-JWT Verifiable Credential"),
    
    /**
     * ISO/IEC 18013-5 Mobile Document format (mdoc).
     * Post-MVP: For mobile driver's licenses and similar documents.
     */
    ISO_MDOC("iso-mdoc", "ISO Mobile Document"),
    
    /**
     * JSON-LD Verifiable Credential format (W3C VC Data Model).
     * Post-MVP: For broader W3C ecosystem compatibility.
     */
    JSON_LD("json-ld", "JSON-LD Verifiable Credential");
    
    private final String identifier;
    private final String displayName;
    
    DigitalCredentialFormat(String identifier, String displayName) {
        this.identifier = identifier;
        this.displayName = displayName;
    }
    
    /**
     * Gets the format identifier string.
     * @return Format identifier (e.g., "sd-jwt-vc")
     */
    public String getIdentifier() {
        return identifier;
    }
    
    /**
     * Gets the human-readable display name.
     * @return Display name (e.g., "SD-JWT Verifiable Credential")
     */
    public String getDisplayName() {
        return displayName;
    }
    
    /**
     * Parses a format identifier string to enum value.
     * @param identifier Format identifier string
     * @return Corresponding enum value
     * @throws IllegalArgumentException if identifier is not recognized
     */
    public static DigitalCredentialFormat fromIdentifier(String identifier) {
        for (DigitalCredentialFormat format : values()) {
            if (format.identifier.equals(identifier)) {
                return format;
            }
        }
        throw new IllegalArgumentException("Unknown credential format: " + identifier);
    }
    
    /**
     * Checks if this format is supported in the current implementation.
     * @return true if format is supported, false otherwise
     */
    public boolean isSupported() {
        return this == SD_JWT_VC || this == ISO_MDOC || this == JSON_LD;
    }
}

// Made with Bob
