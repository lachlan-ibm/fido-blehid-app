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
 * Represents the IssuerSigned structure in an ISO mDL credential.
 * 
 * <p>IssuerSigned contains:
 * <ul>
 *   <li>nameSpaces - Map of namespace to list of IssuerSignedItems (encoded with tag 24)</li>
 *   <li>issuerAuth - The issuer's authentication (COSE_Sign1 over MSO)</li>
 * </ul>
 * 
 * <p>CBOR structure (as per ISO 18013-5 Section 8.3.2.1.2.2):
 * <pre>
 * IssuerSigned = {
 *   "nameSpaces": IssuerNameSpaces,
 *   "issuerAuth": IssuerAuth
 * }
 * 
 * IssuerNameSpaces = {
 *   NameSpace => [ + IssuerSignedItemBytes ]
 * }
 * 
 * IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem)
 * </pre>
 * 
 * @see <a href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5:2021 Section 8.3.2.1.2.2</a>
 */
public class IssuerSigned {
    
    private final Map<String, List<IssuerSignedItem>> nameSpaces;
    private final byte[] issuerAuth;
    
    /**
     * Creates a new IssuerSigned structure.
     * 
     * @param nameSpaces map of namespace to list of issuer-signed items
     * @param issuerAuth the issuer authentication (COSE_Sign1 bytes)
     * @throws IllegalArgumentException if parameters are invalid
     */
    public IssuerSigned(Map<String, List<IssuerSignedItem>> nameSpaces, byte[] issuerAuth) {
        if (nameSpaces == null || nameSpaces.isEmpty()) {
            throw new IllegalArgumentException("nameSpaces cannot be null or empty");
        }
        if (issuerAuth == null || issuerAuth.length == 0) {
            throw new IllegalArgumentException("issuerAuth cannot be null or empty");
        }
        
        this.nameSpaces = deepCopyNameSpaces(nameSpaces);
        this.issuerAuth = issuerAuth.clone();
    }
    
    /**
     * Returns an unmodifiable view of the namespaces.
     * 
     * @return map of namespace to list of issuer-signed items
     */
    public Map<String, List<IssuerSignedItem>> getNameSpaces() {
        Map<String, List<IssuerSignedItem>> copy = new HashMap<>();
        for (Map.Entry<String, List<IssuerSignedItem>> entry : nameSpaces.entrySet()) {
            copy.put(entry.getKey(), Collections.unmodifiableList(new ArrayList<>(entry.getValue())));
        }
        return Collections.unmodifiableMap(copy);
    }
    
    /**
     * Returns a copy of the issuer authentication bytes.
     * 
     * @return the issuer authentication (COSE_Sign1)
     */
    public byte[] getIssuerAuth() {
        return issuerAuth.clone();
    }
    
    /**
     * Encodes this IssuerSigned to CBOR format.
     * 
     * @return CBOR-encoded bytes
     */
    public byte[] toCbor() {
        Map<String, Object> map = new HashMap<>();
        
        // Encode nameSpaces with tag 24
        Map<String, List<byte[]>> encodedNameSpaces = new HashMap<>();
        for (Map.Entry<String, List<IssuerSignedItem>> entry : nameSpaces.entrySet()) {
            List<byte[]> encodedItems = new ArrayList<>();
            for (IssuerSignedItem item : entry.getValue()) {
                encodedItems.add(Cbor.encodeWithTag24(item.toCbor()));
            }
            encodedNameSpaces.put(entry.getKey(), encodedItems);
        }
        map.put("nameSpaces", encodedNameSpaces);
        map.put("issuerAuth", issuerAuth);
        
        return Cbor.encode(map);
    }
    
    /**
     * Decodes an IssuerSigned from CBOR format.
     * 
     * @param cbor the CBOR-encoded bytes
     * @return the decoded IssuerSigned
     * @throws MdlException if decoding fails
     */
    public static IssuerSigned fromCbor(byte[] cbor) throws MdlException {
        try {
            Object decoded = Cbor.decode(cbor);
            if (!(decoded instanceof Map)) {
                throw new MdlException("IssuerSigned must be a CBOR map");
            }
            
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) decoded;
            
            @SuppressWarnings("unchecked")
            Map<String, List<byte[]>> encodedNameSpaces = 
                (Map<String, List<byte[]>>) map.get("nameSpaces");
            
            Map<String, List<IssuerSignedItem>> nameSpaces = new HashMap<>();
            for (Map.Entry<String, List<byte[]>> entry : encodedNameSpaces.entrySet()) {
                List<IssuerSignedItem> items = new ArrayList<>();
                for (byte[] itemBytes : entry.getValue()) {
                    Object unwrapped = Cbor.decodeWithTag24(itemBytes);
                    if (!(unwrapped instanceof byte[])) {
                        throw new MdlException("Tag 24 content must be byte string");
                    }
                    IssuerSignedItem item = IssuerSignedItem.fromCbor((byte[]) unwrapped);
                    items.add(item);
                }
                nameSpaces.put(entry.getKey(), items);
            }
            
            byte[] issuerAuth = (byte[]) map.get("issuerAuth");
            
            return new IssuerSigned(nameSpaces, issuerAuth);
            
        } catch (MdlException e) {
            throw e;
        } catch (Exception e) {
            throw new MdlException("Failed to decode IssuerSigned from CBOR", e);
        }
    }
    
    private static Map<String, List<IssuerSignedItem>> deepCopyNameSpaces(
            Map<String, List<IssuerSignedItem>> original) {
        Map<String, List<IssuerSignedItem>> copy = new HashMap<>();
        for (Map.Entry<String, List<IssuerSignedItem>> entry : original.entrySet()) {
            copy.put(entry.getKey(), new ArrayList<>(entry.getValue()));
        }
        return copy;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        IssuerSigned that = (IssuerSigned) o;
        return Objects.equals(nameSpaces, that.nameSpaces) &&
               java.util.Arrays.equals(issuerAuth, that.issuerAuth);
    }
    
    @Override
    public int hashCode() {
        int result = Objects.hash(nameSpaces);
        result = 31 * result + java.util.Arrays.hashCode(issuerAuth);
        return result;
    }
    
    @Override
    public String toString() {
        return String.format("IssuerSigned{nameSpaces=%d, issuerAuthLength=%d}",
                nameSpaces.size(), issuerAuth.length);
    }
}

// Made with Bob
