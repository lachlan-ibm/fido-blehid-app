/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.mdl;

import com.isfs.blekey.util.Cbor;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Represents an issuer-signed data element in an ISO mDL credential.
 * 
 * <p>An IssuerSignedItem contains a single data element that has been signed by the issuer.
 * Each item consists of:
 * <ul>
 *   <li>digestID - A unique identifier for this item within its namespace</li>
 *   <li>random - Random bytes for digest calculation</li>
 *   <li>elementIdentifier - The name of the data element (e.g., "family_name")</li>
 *   <li>elementValue - The value of the data element</li>
 * </ul>
 * 
 * <p>The issuer calculates a digest over the CBOR-encoded IssuerSignedItem and includes
 * this digest in the Mobile Security Object (MSO). This allows selective disclosure:
 * the holder can choose which items to reveal while maintaining the issuer's signature.
 * 
 * <p>CBOR structure (as per ISO 18013-5 Section 8.3.2.1.2.2):
 * <pre>
 * IssuerSignedItem = {
 *   "digestID": uint,
 *   "random": bstr,
 *   "elementIdentifier": tstr,
 *   "elementValue": any
 * }
 * </pre>
 * 
 * @see <a href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5:2021 Section 8.3.2.1.2.2</a>
 */
public class IssuerSignedItem {
    
    private final int digestId;
    private final byte[] random;
    private final String elementIdentifier;
    private final Object elementValue;
    
    /**
     * Creates a new IssuerSignedItem.
     * 
     * @param digestId unique identifier for this item within its namespace
     * @param random random bytes for digest calculation (should be cryptographically random)
     * @param elementIdentifier the name of the data element
     * @param elementValue the value of the data element
     * @throws IllegalArgumentException if any parameter is invalid
     */
    public IssuerSignedItem(int digestId, byte[] random, String elementIdentifier, Object elementValue) {
        if (digestId < 0) {
            throw new IllegalArgumentException("digestId must be non-negative");
        }
        if (random == null || random.length == 0) {
            throw new IllegalArgumentException("random cannot be null or empty");
        }
        if (elementIdentifier == null || elementIdentifier.trim().isEmpty()) {
            throw new IllegalArgumentException("elementIdentifier cannot be null or empty");
        }
        if (elementValue == null) {
            throw new IllegalArgumentException("elementValue cannot be null");
        }
        
        this.digestId = digestId;
        this.random = Arrays.copyOf(random, random.length);
        this.elementIdentifier = elementIdentifier;
        this.elementValue = elementValue;
    }
    
    /**
     * Returns the digest ID.
     * 
     * @return the digest ID
     */
    public int getDigestId() {
        return digestId;
    }
    
    /**
     * Returns a copy of the random bytes.
     * 
     * @return a copy of the random bytes
     */
    public byte[] getRandom() {
        return Arrays.copyOf(random, random.length);
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
     * Encodes this IssuerSignedItem to CBOR format.
     * 
     * <p>The CBOR structure follows ISO 18013-5 Section 8.3.2.1.2.2:
     * <pre>
     * {
     *   "digestID": digestId,
     *   "random": random,
     *   "elementIdentifier": elementIdentifier,
     *   "elementValue": elementValue
     * }
     * </pre>
     * 
     * @return CBOR-encoded bytes
     */
    public byte[] toCbor() {
        Map<String, Object> map = new HashMap<>();
        map.put("digestID", digestId);
        map.put("random", random);
        map.put("elementIdentifier", elementIdentifier);
        map.put("elementValue", elementValue);
        return Cbor.encode(map);
    }
    
    /**
     * Decodes an IssuerSignedItem from CBOR format.
     * 
     * @param cbor the CBOR-encoded bytes
     * @return the decoded IssuerSignedItem
     * @throws MdlException if decoding fails or the structure is invalid
     */
    public static IssuerSignedItem fromCbor(byte[] cbor) throws MdlException {
        try {
            Object decoded = Cbor.decode(cbor);
            if (!(decoded instanceof Map)) {
                throw new MdlException("IssuerSignedItem must be a CBOR map");
            }
            
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) decoded;
            
            Object digestIdObj = map.get("digestID");
            if (!(digestIdObj instanceof Integer)) {
                throw new MdlException("digestID must be an integer");
            }
            int digestId = (Integer) digestIdObj;
            
            Object randomObj = map.get("random");
            if (!(randomObj instanceof byte[])) {
                throw new MdlException("random must be a byte string");
            }
            byte[] random = (byte[]) randomObj;
            
            Object elementIdentifierObj = map.get("elementIdentifier");
            if (!(elementIdentifierObj instanceof String)) {
                throw new MdlException("elementIdentifier must be a string");
            }
            String elementIdentifier = (String) elementIdentifierObj;
            
            Object elementValue = map.get("elementValue");
            if (elementValue == null) {
                throw new MdlException("elementValue is required");
            }
            
            return new IssuerSignedItem(digestId, random, elementIdentifier, elementValue);
            
        } catch (MdlException e) {
            throw e;
        } catch (Exception e) {
            throw new MdlException("Failed to decode IssuerSignedItem from CBOR", e);
        }
    }
    
    /**
     * Calculates the digest of this IssuerSignedItem using the specified algorithm.
     * 
     * <p>The digest is calculated over the CBOR-encoded IssuerSignedItem, as specified
     * in ISO 18013-5 Section 9.1.2.4.
     * 
     * @param algorithm the digest algorithm (e.g., "SHA-256", "SHA-384", "SHA-512")
     * @return the calculated digest
     * @throws MdlException if digest calculation fails
     */
    public byte[] calculateDigest(String algorithm) throws MdlException {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            byte[] encoded = toCbor();
            return md.digest(encoded);
        } catch (NoSuchAlgorithmException e) {
            throw new MdlException("Unsupported digest algorithm: " + algorithm, e);
        }
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        IssuerSignedItem that = (IssuerSignedItem) o;
        return digestId == that.digestId &&
               Arrays.equals(random, that.random) &&
               Objects.equals(elementIdentifier, that.elementIdentifier) &&
               Objects.equals(elementValue, that.elementValue);
    }
    
    @Override
    public int hashCode() {
        int result = Objects.hash(digestId, elementIdentifier, elementValue);
        result = 31 * result + Arrays.hashCode(random);
        return result;
    }
    
    @Override
    public String toString() {
        return String.format("IssuerSignedItem{digestId=%d, elementIdentifier='%s', elementValue=%s}",
                digestId, elementIdentifier, elementValue);
    }
}

// Made with Bob
