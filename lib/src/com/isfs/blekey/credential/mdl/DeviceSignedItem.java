/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.mdl;

import com.isfs.blekey.util.Cbor;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Represents a device-signed data element in an ISO mDL credential.
 * 
 * <p>A DeviceSignedItem contains a data element that is signed by the device (holder)
 * rather than the issuer. This is used for data that the device generates or controls,
 * such as:
 * <ul>
 *   <li>Age attestations (e.g., "age_over_18")</li>
 *   <li>Biometric templates</li>
 *   <li>Device-specific metadata</li>
 * </ul>
 * 
 * <p>Unlike IssuerSignedItems, DeviceSignedItems do not have digestID or random fields
 * because they are not included in the issuer's Mobile Security Object (MSO). Instead,
 * they are signed directly by the device during presentation.
 * 
 * <p>CBOR structure (as per ISO 18013-5 Section 8.3.2.1.2.2):
 * <pre>
 * DeviceSignedItem = {
 *   "elementIdentifier": tstr,
 *   "elementValue": any
 * }
 * </pre>
 * 
 * @see <a href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5:2021 Section 8.3.2.1.2.2</a>
 */
public class DeviceSignedItem {
    
    private final String elementIdentifier;
    private final Object elementValue;
    
    /**
     * Creates a new DeviceSignedItem.
     * 
     * @param elementIdentifier the name of the data element
     * @param elementValue the value of the data element
     * @throws IllegalArgumentException if any parameter is invalid
     */
    public DeviceSignedItem(String elementIdentifier, Object elementValue) {
        if (elementIdentifier == null || elementIdentifier.trim().isEmpty()) {
            throw new IllegalArgumentException("elementIdentifier cannot be null or empty");
        }
        if (elementValue == null) {
            throw new IllegalArgumentException("elementValue cannot be null");
        }
        
        this.elementIdentifier = elementIdentifier;
        this.elementValue = elementValue;
    }
    
    /**
     * Returns the element identifier.
     * 
     * @return the element identifier
     */
    public String getElementIdentifier() {
        return elementIdentifier;
    }
    
    /**
     * Returns the element value.
     * 
     * @return the element value
     */
    public Object getElementValue() {
        return elementValue;
    }
    
    /**
     * Encodes this DeviceSignedItem to CBOR format.
     * 
     * <p>The CBOR structure follows ISO 18013-5 Section 8.3.2.1.2.2:
     * <pre>
     * {
     *   "elementIdentifier": elementIdentifier,
     *   "elementValue": elementValue
     * }
     * </pre>
     * 
     * @return CBOR-encoded bytes
     */
    public byte[] toCbor() {
        Map<String, Object> map = new HashMap<>();
        map.put("elementIdentifier", elementIdentifier);
        map.put("elementValue", elementValue);
        return Cbor.encode(map);
    }
    
    /**
     * Decodes a DeviceSignedItem from CBOR format.
     * 
     * @param cbor the CBOR-encoded bytes
     * @return the decoded DeviceSignedItem
     * @throws MdlException if decoding fails or the structure is invalid
     */
    public static DeviceSignedItem fromCbor(byte[] cbor) throws MdlException {
        try {
            Object decoded = Cbor.decode(cbor);
            if (!(decoded instanceof Map)) {
                throw new MdlException("DeviceSignedItem must be a CBOR map");
            }
            
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) decoded;
            
            Object elementIdentifierObj = map.get("elementIdentifier");
            if (!(elementIdentifierObj instanceof String)) {
                throw new MdlException("elementIdentifier must be a string");
            }
            String elementIdentifier = (String) elementIdentifierObj;
            
            Object elementValue = map.get("elementValue");
            if (elementValue == null) {
                throw new MdlException("elementValue is required");
            }
            
            return new DeviceSignedItem(elementIdentifier, elementValue);
            
        } catch (MdlException e) {
            throw e;
        } catch (Exception e) {
            throw new MdlException("Failed to decode DeviceSignedItem from CBOR", e);
        }
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DeviceSignedItem that = (DeviceSignedItem) o;
        return Objects.equals(elementIdentifier, that.elementIdentifier) &&
               Objects.equals(elementValue, that.elementValue);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(elementIdentifier, elementValue);
    }
    
    @Override
    public String toString() {
        return String.format("DeviceSignedItem{elementIdentifier='%s', elementValue=%s}",
                elementIdentifier, elementValue);
    }
}

// Made with Bob
