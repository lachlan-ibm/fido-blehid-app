/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.mdl;

import java.util.Objects;

/**
 * Represents a namespace in an ISO mDL (mobile Driver's License) credential.
 * 
 * <p>Namespaces are used to organize data elements in an mDL. Each namespace
 * contains a set of related data elements. The ISO 18013-5 standard defines
 * several standard namespaces, with the most common being:
 * <ul>
 *   <li>{@code org.iso.18013.5.1} - Standard mDL data elements</li>
 *   <li>{@code org.iso.18013.5.1.aamva} - AAMVA-specific elements</li>
 * </ul>
 * 
 * <p>Example usage:
 * <pre>{@code
 * NameSpace ns = new NameSpace("org.iso.18013.5.1");
 * String name = ns.getName(); // "org.iso.18013.5.1"
 * }</pre>
 * 
 * @see <a href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5:2021 Section 8.3.2.1</a>
 */
public class NameSpace {
    
    /**
     * Standard ISO 18013-5 mDL namespace for core data elements.
     */
    public static final String ISO_18013_5_1 = "org.iso.18013.5.1";
    
    /**
     * AAMVA-specific namespace for additional mDL data elements.
     */
    public static final String ISO_18013_5_1_AAMVA = "org.iso.18013.5.1.aamva";
    
    private final String name;
    
    /**
     * Creates a new namespace with the specified name.
     * 
     * @param name the namespace name (e.g., "org.iso.18013.5.1")
     * @throws IllegalArgumentException if name is null or empty
     */
    public NameSpace(String name) {
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException("Namespace name cannot be null or empty");
        }
        this.name = name;
    }
    
    /**
     * Returns the namespace name.
     * 
     * @return the namespace name
     */
    public String getName() {
        return name;
    }
    
    /**
     * Checks if this is the standard ISO 18013-5 mDL namespace.
     * 
     * @return true if this is the standard mDL namespace
     */
    public boolean isStandardMdlNamespace() {
        return ISO_18013_5_1.equals(name);
    }
    
    /**
     * Checks if this is the AAMVA-specific namespace.
     * 
     * @return true if this is the AAMVA namespace
     */
    public boolean isAamvaNamespace() {
        return ISO_18013_5_1_AAMVA.equals(name);
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NameSpace nameSpace = (NameSpace) o;
        return Objects.equals(name, nameSpace.name);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(name);
    }
    
    @Override
    public String toString() {
        return name;
    }
}

// Made with Bob
