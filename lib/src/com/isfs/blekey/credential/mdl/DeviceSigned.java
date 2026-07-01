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
 * Represents the DeviceSigned structure in an ISO mDL credential.
 * 
 * <p>DeviceSigned contains:
 * <ul>
 *   <li>nameSpaces - Map of namespace to list of DeviceSignedItems</li>
 *   <li>deviceAuth - The device's authentication</li>
 * </ul>
 * 
 * <p>CBOR structure (as per ISO 18013-5 Section 8.3.2.1.2.2):
 * <pre>
 * DeviceSigned = {
 *   "nameSpaces": DeviceNameSpaces,
 *   "deviceAuth": DeviceAuth
 * }
 * 
 * DeviceNameSpaces = {
 *   NameSpace => [ + DeviceSignedItemBytes ]
 * }
 * 
 * DeviceSignedItemBytes = #6.24(bstr .cbor DeviceSignedItem)
 * </pre>
 * 
 * @see <a href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5:2021 Section 8.3.2.1.2.2</a>
 */
public class DeviceSigned {
    
    private final Map<String, List<DeviceSignedItem>> nameSpaces;
    private final byte[] deviceAuth;
    
    /**
     * Creates a new DeviceSigned structure.
     * 
     * @param nameSpaces map of namespace to list of device-signed items
     * @param deviceAuth the device authentication bytes
     * @throws IllegalArgumentException if parameters are invalid
     */
    public DeviceSigned(Map<String, List<DeviceSignedItem>> nameSpaces, byte[] deviceAuth) {
        if (nameSpaces == null) {
            throw new IllegalArgumentException("nameSpaces cannot be null");
        }
        if (deviceAuth == null || deviceAuth.length == 0) {
            throw new IllegalArgumentException("deviceAuth cannot be null or empty");
        }
        
        this.nameSpaces = deepCopyNameSpaces(nameSpaces);
        this.deviceAuth = deviceAuth.clone();
    }
    
    /**
     * Returns an unmodifiable view of the namespaces.
     * 
     * @return map of namespace to list of device-signed items
     */
    public Map<String, List<DeviceSignedItem>> getNameSpaces() {
        Map<String, List<DeviceSignedItem>> copy = new HashMap<>();
        for (Map.Entry<String, List<DeviceSignedItem>> entry : nameSpaces.entrySet()) {
            copy.put(entry.getKey(), Collections.unmodifiableList(new ArrayList<>(entry.getValue())));
        }
        return Collections.unmodifiableMap(copy);
    }
    
    /**
     * Returns a copy of the device authentication bytes.
     * 
     * @return the device authentication
     */
    public byte[] getDeviceAuth() {
        return deviceAuth.clone();
    }
    
    /**
     * Encodes this DeviceSigned to CBOR format.
     * 
     * @return CBOR-encoded bytes
     */
    public byte[] toCbor() {
        Map<String, Object> map = new HashMap<>();
        
        // Encode nameSpaces
        if (!nameSpaces.isEmpty()) {
            Map<String, List<byte[]>> encodedNameSpaces = new HashMap<>();
            for (Map.Entry<String, List<DeviceSignedItem>> entry : nameSpaces.entrySet()) {
                List<byte[]> encodedItems = new ArrayList<>();
                for (DeviceSignedItem item : entry.getValue()) {
                    encodedItems.add(item.toCbor());
                }
                encodedNameSpaces.put(entry.getKey(), encodedItems);
            }
            map.put("nameSpaces", encodedNameSpaces);
        }
        
        map.put("deviceAuth", deviceAuth);
        
        return Cbor.encode(map);
    }
    
    /**
     * Decodes a DeviceSigned from CBOR format.
     * 
     * @param cbor the CBOR-encoded bytes
     * @return the decoded DeviceSigned
     * @throws MdlException if decoding fails
     */
    public static DeviceSigned fromCbor(byte[] cbor) throws MdlException {
        try {
            Object decoded = Cbor.decode(cbor);
            if (!(decoded instanceof Map)) {
                throw new MdlException("DeviceSigned must be a CBOR map");
            }
            
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) decoded;
            
            Map<String, List<DeviceSignedItem>> nameSpaces = new HashMap<>();
            Object nameSpacesObj = map.get("nameSpaces");
            if (nameSpacesObj != null) {
                @SuppressWarnings("unchecked")
                Map<String, List<byte[]>> encodedNameSpaces = 
                    (Map<String, List<byte[]>>) nameSpacesObj;
                
                for (Map.Entry<String, List<byte[]>> entry : encodedNameSpaces.entrySet()) {
                    List<DeviceSignedItem> items = new ArrayList<>();
                    for (byte[] itemBytes : entry.getValue()) {
                        DeviceSignedItem item = DeviceSignedItem.fromCbor(itemBytes);
                        items.add(item);
                    }
                    nameSpaces.put(entry.getKey(), items);
                }
            }
            
            byte[] deviceAuth = (byte[]) map.get("deviceAuth");
            
            return new DeviceSigned(nameSpaces, deviceAuth);
            
        } catch (MdlException e) {
            throw e;
        } catch (Exception e) {
            throw new MdlException("Failed to decode DeviceSigned from CBOR", e);
        }
    }
    
    private static Map<String, List<DeviceSignedItem>> deepCopyNameSpaces(
            Map<String, List<DeviceSignedItem>> original) {
        Map<String, List<DeviceSignedItem>> copy = new HashMap<>();
        for (Map.Entry<String, List<DeviceSignedItem>> entry : original.entrySet()) {
            copy.put(entry.getKey(), new ArrayList<>(entry.getValue()));
        }
        return copy;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DeviceSigned that = (DeviceSigned) o;
        return Objects.equals(nameSpaces, that.nameSpaces) &&
               java.util.Arrays.equals(deviceAuth, that.deviceAuth);
    }
    
    @Override
    public int hashCode() {
        int result = Objects.hash(nameSpaces);
        result = 31 * result + java.util.Arrays.hashCode(deviceAuth);
        return result;
    }
    
    @Override
    public String toString() {
        return String.format("DeviceSigned{nameSpaces=%d, deviceAuthLength=%d}",
                nameSpaces.size(), deviceAuth.length);
    }
}

// Made with Bob
