/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.mdl;

import com.isfs.blekey.util.Cbor;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Represents a complete ISO mDL (mobile Driver's License) document.
 * 
 * <p>A MobileDocument is the top-level container for an mDL credential. It contains:
 * <ul>
 *   <li>Document type (e.g., "org.iso.18013.5.1.mDL")</li>
 *   <li>Issuer-signed data (IssuerSigned)</li>
 *   <li>Device-signed data (DeviceSigned) - optional</li>
 *   <li>Errors - optional</li>
 * </ul>
 * 
 * <p>The document type identifies the type of credential. For a mobile driver's license,
 * the standard document type is "org.iso.18013.5.1.mDL".
 * 
 * <p>CBOR structure (as per ISO 18013-5 Section 8.3.2.1.2.2):
 * <pre>
 * MobileDocument = {
 *   "docType": tstr,
 *   "issuerSigned": IssuerSigned,
 *   ?"deviceSigned": DeviceSigned,
 *   ?"errors": Errors
 * }
 * </pre>
 * 
 * <p>Example usage:
 * <pre>{@code
 * MobileDocument doc = new MobileDocument("org.iso.18013.5.1.mDL");
 * // Add issuer-signed and device-signed data...
 * byte[] cbor = doc.toCbor();
 * }</pre>
 * 
 * @see <a href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5:2021 Section 8.3.2.1.2.2</a>
 */
public class MobileDocument {
    
    /**
     * Standard document type for ISO 18013-5 mobile driver's license.
     */
    public static final String DOCTYPE_MDL = "org.iso.18013.5.1.mDL";
    
    private final String docType;
    private final Map<String, List<IssuerSignedItem>> issuerSignedItems;
    private final Map<String, List<DeviceSignedItem>> deviceSignedItems;
    private final Map<String, Object> errors;
    
    /**
     * Creates a new MobileDocument with the specified document type.
     * 
     * @param docType the document type (e.g., "org.iso.18013.5.1.mDL")
     * @throws IllegalArgumentException if docType is null or empty
     */
    public MobileDocument(String docType) {
        if (docType == null || docType.trim().isEmpty()) {
            throw new IllegalArgumentException("docType cannot be null or empty");
        }
        this.docType = docType;
        this.issuerSignedItems = new HashMap<>();
        this.deviceSignedItems = new HashMap<>();
        this.errors = new HashMap<>();
    }
    
    /**
     * Returns the document type.
     * 
     * @return the document type
     */
    public String getDocType() {
        return docType;
    }
    
    /**
     * Checks if this is a mobile driver's license document.
     * 
     * @return true if this is an mDL document
     */
    public boolean isMdl() {
        return DOCTYPE_MDL.equals(docType);
    }
    
    /**
     * Adds an issuer-signed item to the specified namespace.
     * 
     * @param namespace the namespace
     * @param item the issuer-signed item
     * @throws IllegalArgumentException if namespace or item is null
     */
    public void addIssuerSignedItem(String namespace, IssuerSignedItem item) {
        if (namespace == null || namespace.trim().isEmpty()) {
            throw new IllegalArgumentException("namespace cannot be null or empty");
        }
        if (item == null) {
            throw new IllegalArgumentException("item cannot be null");
        }
        
        issuerSignedItems.computeIfAbsent(namespace, k -> new ArrayList<>()).add(item);
    }
    
    /**
     * Adds a device-signed item to the specified namespace.
     * 
     * @param namespace the namespace
     * @param item the device-signed item
     * @throws IllegalArgumentException if namespace or item is null
     */
    public void addDeviceSignedItem(String namespace, DeviceSignedItem item) {
        if (namespace == null || namespace.trim().isEmpty()) {
            throw new IllegalArgumentException("namespace cannot be null or empty");
        }
        if (item == null) {
            throw new IllegalArgumentException("item cannot be null");
        }
        
        deviceSignedItems.computeIfAbsent(namespace, k -> new ArrayList<>()).add(item);
    }
    
    /**
     * Returns an unmodifiable map of issuer-signed items by namespace.
     * 
     * @return map of namespace to list of issuer-signed items
     */
    public Map<String, List<IssuerSignedItem>> getIssuerSignedItems() {
        Map<String, List<IssuerSignedItem>> result = new HashMap<>();
        for (Map.Entry<String, List<IssuerSignedItem>> entry : issuerSignedItems.entrySet()) {
            result.put(entry.getKey(), Collections.unmodifiableList(entry.getValue()));
        }
        return Collections.unmodifiableMap(result);
    }
    
    /**
     * Returns an unmodifiable map of device-signed items by namespace.
     * 
     * @return map of namespace to list of device-signed items
     */
    public Map<String, List<DeviceSignedItem>> getDeviceSignedItems() {
        Map<String, List<DeviceSignedItem>> result = new HashMap<>();
        for (Map.Entry<String, List<DeviceSignedItem>> entry : deviceSignedItems.entrySet()) {
            result.put(entry.getKey(), Collections.unmodifiableList(entry.getValue()));
        }
        return Collections.unmodifiableMap(result);
    }
    
    /**
     * Adds an error for the specified namespace.
     * 
     * @param namespace the namespace
     * @param error the error information
     */
    public void addError(String namespace, Object error) {
        if (namespace != null && error != null) {
            errors.put(namespace, error);
        }
    }
    
    /**
     * Returns an unmodifiable map of errors by namespace.
     * 
     * @return map of namespace to error information
     */
    public Map<String, Object> getErrors() {
        return Collections.unmodifiableMap(errors);
    }
    
    /**
     * Encodes this MobileDocument to CBOR format.
     * 
     * <p>The CBOR structure follows ISO 18013-5 Section 8.3.2.1.2.2.
     * 
     * @return CBOR-encoded bytes
     */
    public byte[] toCbor() {
        Map<String, Object> map = new HashMap<>();
        map.put("docType", docType);
        
        // Encode issuerSigned
        Map<String, Object> issuerSigned = new HashMap<>();
        Map<String, List<byte[]>> nameSpaces = new HashMap<>();
        for (Map.Entry<String, List<IssuerSignedItem>> entry : issuerSignedItems.entrySet()) {
            List<byte[]> items = new ArrayList<>();
            for (IssuerSignedItem item : entry.getValue()) {
                items.add(Cbor.encodeWithTag24(item.toCbor()));
            }
            nameSpaces.put(entry.getKey(), items);
        }
        issuerSigned.put("nameSpaces", nameSpaces);
        // Note: issuerAuth will be added in Phase 2C
        map.put("issuerSigned", issuerSigned);
        
        // Encode deviceSigned if present
        if (!deviceSignedItems.isEmpty()) {
            Map<String, Object> deviceSigned = new HashMap<>();
            Map<String, List<byte[]>> deviceNameSpaces = new HashMap<>();
            for (Map.Entry<String, List<DeviceSignedItem>> entry : deviceSignedItems.entrySet()) {
                List<byte[]> items = new ArrayList<>();
                for (DeviceSignedItem item : entry.getValue()) {
                    items.add(item.toCbor());
                }
                deviceNameSpaces.put(entry.getKey(), items);
            }
            deviceSigned.put("nameSpaces", deviceNameSpaces);
            // Note: deviceAuth will be added in Phase 2D
            map.put("deviceSigned", deviceSigned);
        }
        
        // Encode errors if present
        if (!errors.isEmpty()) {
            map.put("errors", errors);
        }
        
        return Cbor.encode(map);
    }
    
    /**
     * Decodes a MobileDocument from CBOR format.
     * 
     * @param cbor the CBOR-encoded bytes
     * @return the decoded MobileDocument
     * @throws MdlException if decoding fails or the structure is invalid
     */
    public static MobileDocument fromCbor(byte[] cbor) throws MdlException {
        try {
            Object decoded = Cbor.decode(cbor);
            if (!(decoded instanceof Map)) {
                throw new MdlException("MobileDocument must be a CBOR map");
            }
            
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) decoded;
            
            // Extract docType
            Object docTypeObj = map.get("docType");
            if (!(docTypeObj instanceof String)) {
                throw new MdlException("docType must be a string");
            }
            String docType = (String) docTypeObj;
            
            MobileDocument doc = new MobileDocument(docType);
            
            // Extract issuerSigned
            Object issuerSignedObj = map.get("issuerSigned");
            if (issuerSignedObj instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> issuerSigned = (Map<String, Object>) issuerSignedObj;
                
                Object nameSpacesObj = issuerSigned.get("nameSpaces");
                if (nameSpacesObj instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, List<byte[]>> nameSpaces = (Map<String, List<byte[]>>) nameSpacesObj;
                    
                    for (Map.Entry<String, List<byte[]>> entry : nameSpaces.entrySet()) {
                        String namespace = entry.getKey();
                        for (byte[] itemBytes : entry.getValue()) {
                            Object unwrapped = Cbor.decodeWithTag24(itemBytes);
                            if (!(unwrapped instanceof byte[])) {
                                throw new MdlException("Tag 24 content must be byte string");
                            }
                            IssuerSignedItem item = IssuerSignedItem.fromCbor((byte[]) unwrapped);
                            doc.addIssuerSignedItem(namespace, item);
                        }
                    }
                }
            }
            
            // Extract deviceSigned if present
            Object deviceSignedObj = map.get("deviceSigned");
            if (deviceSignedObj instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> deviceSigned = (Map<String, Object>) deviceSignedObj;
                
                Object nameSpacesObj = deviceSigned.get("nameSpaces");
                if (nameSpacesObj instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, List<byte[]>> nameSpaces = (Map<String, List<byte[]>>) nameSpacesObj;
                    
                    for (Map.Entry<String, List<byte[]>> entry : nameSpaces.entrySet()) {
                        String namespace = entry.getKey();
                        for (byte[] itemBytes : entry.getValue()) {
                            DeviceSignedItem item = DeviceSignedItem.fromCbor(itemBytes);
                            doc.addDeviceSignedItem(namespace, item);
                        }
                    }
                }
            }
            
            // Extract errors if present
            Object errorsObj = map.get("errors");
            if (errorsObj instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> errorMap = (Map<String, Object>) errorsObj;
                for (Map.Entry<String, Object> entry : errorMap.entrySet()) {
                    doc.addError(entry.getKey(), entry.getValue());
                }
            }
            
            return doc;
            
        } catch (MdlException e) {
            throw e;
        } catch (Exception e) {
            throw new MdlException("Failed to decode MobileDocument from CBOR", e);
        }
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MobileDocument that = (MobileDocument) o;
        return Objects.equals(docType, that.docType) &&
               Objects.equals(issuerSignedItems, that.issuerSignedItems) &&
               Objects.equals(deviceSignedItems, that.deviceSignedItems) &&
               Objects.equals(errors, that.errors);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(docType, issuerSignedItems, deviceSignedItems, errors);
    }
    
    @Override
    public String toString() {
        return String.format("MobileDocument{docType='%s', issuerSignedItems=%d namespaces, deviceSignedItems=%d namespaces}",
                docType, issuerSignedItems.size(), deviceSignedItems.size());
    }
}

// Made with Bob
