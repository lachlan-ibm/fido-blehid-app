/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.mdl;

import com.isfs.blekey.util.Cbor;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Represents the Mobile Security Object (MSO) in an ISO mDL credential.
 * 
 * <p>The MSO is a critical component of the mDL that contains:
 * <ul>
 *   <li>Version information</li>
 *   <li>Digest algorithm used for IssuerSignedItems</li>
 *   <li>Value digests organized by namespace and digest ID</li>
 *   <li>Device key information</li>
 *   <li>Document type</li>
 *   <li>Validity information (issued and expiration dates)</li>
 * </ul>
 * 
 * <p>The MSO is signed by the issuer and included in the IssuerAuth structure.
 * It allows selective disclosure by containing digests of individual data elements
 * rather than the elements themselves.
 * 
 * <p>CBOR structure (as per ISO 18013-5 Section 9.1.2):
 * <pre>
 * MobileSecurityObject = {
 *   "version": tstr,
 *   "digestAlgorithm": tstr,
 *   "valueDigests": {
 *     NameSpace => {
 *       DigestID => Digest
 *     }
 *   },
 *   "deviceKeyInfo": DeviceKeyInfo,
 *   "docType": tstr,
 *   "validityInfo": {
 *     "signed": tdate,
 *     "validFrom": tdate,
 *     "validUntil": tdate
 *   }
 * }
 * </pre>
 * 
 * @see <a href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5:2021 Section 9.1.2</a>
 */
public class MobileSecurityObject {
    
    /** MSO version 1.0 as per ISO 18013-5 */
    public static final String VERSION_1_0 = "1.0";
    
    /** SHA-256 digest algorithm identifier */
    public static final String DIGEST_ALGORITHM_SHA256 = "SHA-256";
    
    /** SHA-384 digest algorithm identifier */
    public static final String DIGEST_ALGORITHM_SHA384 = "SHA-384";
    
    /** SHA-512 digest algorithm identifier */
    public static final String DIGEST_ALGORITHM_SHA512 = "SHA-512";
    
    private final String version;
    private final String digestAlgorithm;
    private final Map<String, Map<Integer, byte[]>> valueDigests;
    private final Map<String, Object> deviceKeyInfo;
    private final String docType;
    private final Instant signed;
    private final Instant validFrom;
    private final Instant validUntil;
    
    /**
     * Creates a new MobileSecurityObject.
     * 
     * @param version MSO version (typically "1.0")
     * @param digestAlgorithm digest algorithm (SHA-256, SHA-384, or SHA-512)
     * @param valueDigests map of namespace to (digestID to digest value)
     * @param deviceKeyInfo device key information
     * @param docType document type
     * @param signed timestamp when MSO was signed
     * @param validFrom validity start timestamp
     * @param validUntil validity end timestamp
     * @throws IllegalArgumentException if any parameter is invalid
     */
    public MobileSecurityObject(
            String version,
            String digestAlgorithm,
            Map<String, Map<Integer, byte[]>> valueDigests,
            Map<String, Object> deviceKeyInfo,
            String docType,
            Instant signed,
            Instant validFrom,
            Instant validUntil) {
        
        if (version == null || version.trim().isEmpty()) {
            throw new IllegalArgumentException("version cannot be null or empty");
        }
        if (!isValidDigestAlgorithm(digestAlgorithm)) {
            throw new IllegalArgumentException("Invalid digest algorithm: " + digestAlgorithm);
        }
        if (valueDigests == null || valueDigests.isEmpty()) {
            throw new IllegalArgumentException("valueDigests cannot be null or empty");
        }
        if (deviceKeyInfo == null || deviceKeyInfo.isEmpty()) {
            throw new IllegalArgumentException("deviceKeyInfo cannot be null or empty");
        }
        if (docType == null || docType.trim().isEmpty()) {
            throw new IllegalArgumentException("docType cannot be null or empty");
        }
        if (signed == null) {
            throw new IllegalArgumentException("signed timestamp cannot be null");
        }
        if (validFrom == null) {
            throw new IllegalArgumentException("validFrom timestamp cannot be null");
        }
        if (validUntil == null) {
            throw new IllegalArgumentException("validUntil timestamp cannot be null");
        }
        if (validFrom.isAfter(validUntil)) {
            throw new IllegalArgumentException("validFrom must be before validUntil");
        }
        
        this.version = version;
        this.digestAlgorithm = digestAlgorithm;
        this.valueDigests = deepCopyValueDigests(valueDigests);
        this.deviceKeyInfo = new HashMap<>(deviceKeyInfo);
        this.docType = docType;
        this.signed = signed;
        this.validFrom = validFrom;
        this.validUntil = validUntil;
    }
    
    /**
     * Checks if the given digest algorithm is valid.
     * 
     * @param algorithm the algorithm to check
     * @return true if valid
     */
    public static boolean isValidDigestAlgorithm(String algorithm) {
        return DIGEST_ALGORITHM_SHA256.equals(algorithm) ||
               DIGEST_ALGORITHM_SHA384.equals(algorithm) ||
               DIGEST_ALGORITHM_SHA512.equals(algorithm);
    }
    
    /**
     * Returns the MSO version.
     * 
     * @return the version
     */
    public String getVersion() {
        return version;
    }
    
    /**
     * Returns the digest algorithm.
     * 
     * @return the digest algorithm
     */
    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }
    
    /**
     * Returns an unmodifiable view of the value digests.
     * 
     * @return map of namespace to (digestID to digest value)
     */
    public Map<String, Map<Integer, byte[]>> getValueDigests() {
        return Collections.unmodifiableMap(deepCopyValueDigests(valueDigests));
    }
    
    /**
     * Returns an unmodifiable view of the device key info.
     * 
     * @return the device key info
     */
    public Map<String, Object> getDeviceKeyInfo() {
        return Collections.unmodifiableMap(deviceKeyInfo);
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
     * Returns the signed timestamp.
     * 
     * @return the signed timestamp
     */
    public Instant getSigned() {
        return signed;
    }
    
    /**
     * Returns the validFrom timestamp.
     * 
     * @return the validFrom timestamp
     */
    public Instant getValidFrom() {
        return validFrom;
    }
    
    /**
     * Returns the validUntil timestamp.
     * 
     * @return the validUntil timestamp
     */
    public Instant getValidUntil() {
        return validUntil;
    }
    
    /**
     * Checks if the MSO is currently valid based on the current time.
     * 
     * @return true if valid
     */
    public boolean isValid() {
        return isValidAt(Instant.now());
    }
    
    /**
     * Checks if the MSO is valid at the specified time.
     * 
     * @param timestamp the timestamp to check
     * @return true if valid at the given time
     */
    public boolean isValidAt(Instant timestamp) {
        return !timestamp.isBefore(validFrom) && !timestamp.isAfter(validUntil);
    }
    
    /**
     * Encodes this MobileSecurityObject to CBOR format.
     * 
     * @return CBOR-encoded bytes
     */
    public byte[] toCbor() {
        Map<String, Object> map = new HashMap<>();
        map.put("version", version);
        map.put("digestAlgorithm", digestAlgorithm);
        map.put("valueDigests", convertValueDigestsForCbor(valueDigests));
        map.put("deviceKeyInfo", deviceKeyInfo);
        map.put("docType", docType);
        
        Map<String, Object> validityInfo = new HashMap<>();
        validityInfo.put("signed", signed.toString());
        validityInfo.put("validFrom", validFrom.toString());
        validityInfo.put("validUntil", validUntil.toString());
        map.put("validityInfo", validityInfo);
        
        return Cbor.encode(map);
    }
    
    /**
     * Decodes a MobileSecurityObject from CBOR format.
     * 
     * @param cbor the CBOR-encoded bytes
     * @return the decoded MobileSecurityObject
     * @throws MdlException if decoding fails or the structure is invalid
     */
    public static MobileSecurityObject fromCbor(byte[] cbor) throws MdlException {
        try {
            Object decoded = Cbor.decode(cbor);
            if (!(decoded instanceof Map)) {
                throw new MdlException("MobileSecurityObject must be a CBOR map");
            }
            
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) decoded;
            
            String version = (String) map.get("version");
            String digestAlgorithm = (String) map.get("digestAlgorithm");
            String docType = (String) map.get("docType");
            
            @SuppressWarnings("unchecked")
            Map<String, Object> valueDigestsRaw = (Map<String, Object>) map.get("valueDigests");
            Map<String, Map<Integer, byte[]>> valueDigests = convertValueDigestsFromCbor(valueDigestsRaw);
            
            @SuppressWarnings("unchecked")
            Map<String, Object> deviceKeyInfo = (Map<String, Object>) map.get("deviceKeyInfo");
            
            @SuppressWarnings("unchecked")
            Map<String, Object> validityInfo = (Map<String, Object>) map.get("validityInfo");
            Instant signed = Instant.parse((String) validityInfo.get("signed"));
            Instant validFrom = Instant.parse((String) validityInfo.get("validFrom"));
            Instant validUntil = Instant.parse((String) validityInfo.get("validUntil"));
            
            return new MobileSecurityObject(
                version, digestAlgorithm, valueDigests, deviceKeyInfo,
                docType, signed, validFrom, validUntil
            );
            
        } catch (MdlException e) {
            throw e;
        } catch (Exception e) {
            throw new MdlException("Failed to decode MobileSecurityObject from CBOR", e);
        }
    }
    
    /**
     * Validates that the MSO structure is correct.
     * 
     * @throws MdlException if validation fails
     */
    public void validate() throws MdlException {
        if (!isValidDigestAlgorithm(digestAlgorithm)) {
            throw new MdlException("Unsupported digest algorithm: " + digestAlgorithm);
        }
        
        if (valueDigests.isEmpty()) {
            throw new MdlException("valueDigests cannot be empty");
        }
        
        if (validFrom.isAfter(validUntil)) {
            throw new MdlException("validFrom must be before validUntil");
        }
        
        if (!isValid()) {
            throw new MdlException("MSO is not currently valid");
        }
    }
    
    private static Map<String, Map<Integer, byte[]>> deepCopyValueDigests(
            Map<String, Map<Integer, byte[]>> original) {
        Map<String, Map<Integer, byte[]>> copy = new HashMap<>();
        for (Map.Entry<String, Map<Integer, byte[]>> entry : original.entrySet()) {
            Map<Integer, byte[]> innerCopy = new HashMap<>();
            for (Map.Entry<Integer, byte[]> innerEntry : entry.getValue().entrySet()) {
                innerCopy.put(innerEntry.getKey(), 
                    Arrays.copyOf(innerEntry.getValue(), innerEntry.getValue().length));
            }
            copy.put(entry.getKey(), innerCopy);
        }
        return copy;
    }
    
    private static Map<String, Object> convertValueDigestsForCbor(
            Map<String, Map<Integer, byte[]>> valueDigests) {
        Map<String, Object> result = new HashMap<>();
        for (Map.Entry<String, Map<Integer, byte[]>> entry : valueDigests.entrySet()) {
            result.put(entry.getKey(), new HashMap<>(entry.getValue()));
        }
        return result;
    }
    
    @SuppressWarnings("unchecked")
    private static Map<String, Map<Integer, byte[]>> convertValueDigestsFromCbor(
            Map<String, Object> raw) throws MdlException {
        Map<String, Map<Integer, byte[]>> result = new HashMap<>();
        for (Map.Entry<String, Object> entry : raw.entrySet()) {
            if (!(entry.getValue() instanceof Map)) {
                throw new MdlException("Invalid valueDigests structure");
            }
            Map<Integer, byte[]> innerMap = new HashMap<>();
            Map<Object, Object> rawInner = (Map<Object, Object>) entry.getValue();
            for (Map.Entry<Object, Object> innerEntry : rawInner.entrySet()) {
                if (!(innerEntry.getKey() instanceof Integer)) {
                    throw new MdlException("Digest ID must be an integer");
                }
                if (!(innerEntry.getValue() instanceof byte[])) {
                    throw new MdlException("Digest value must be a byte array");
                }
                innerMap.put((Integer) innerEntry.getKey(), (byte[]) innerEntry.getValue());
            }
            result.put(entry.getKey(), innerMap);
        }
        return result;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MobileSecurityObject that = (MobileSecurityObject) o;
        return Objects.equals(version, that.version) &&
               Objects.equals(digestAlgorithm, that.digestAlgorithm) &&
               valueDigestsEquals(valueDigests, that.valueDigests) &&
               deviceKeyInfoEquals(deviceKeyInfo, that.deviceKeyInfo) &&
               Objects.equals(docType, that.docType) &&
               Objects.equals(signed, that.signed) &&
               Objects.equals(validFrom, that.validFrom) &&
               Objects.equals(validUntil, that.validUntil);
    }
    
    private static boolean valueDigestsEquals(
            Map<String, Map<Integer, byte[]>> a,
            Map<String, Map<Integer, byte[]>> b) {
        if (a.size() != b.size()) return false;
        for (Map.Entry<String, Map<Integer, byte[]>> entry : a.entrySet()) {
            Map<Integer, byte[]> bInner = b.get(entry.getKey());
            if (bInner == null || bInner.size() != entry.getValue().size()) {
                return false;
            }
            for (Map.Entry<Integer, byte[]> innerEntry : entry.getValue().entrySet()) {
                byte[] bDigest = bInner.get(innerEntry.getKey());
                if (!Arrays.equals(innerEntry.getValue(), bDigest)) {
                    return false;
                }
            }
        }
        return true;
    }
    
    private static boolean deviceKeyInfoEquals(Map<String, Object> a, Map<String, Object> b) {
        if (a.size() != b.size()) return false;
        for (Map.Entry<String, Object> entry : a.entrySet()) {
            Object bValue = b.get(entry.getKey());
            if (bValue == null) return false;
            
            Object aValue = entry.getValue();
            // Handle byte arrays specially
            if (aValue instanceof byte[] && bValue instanceof byte[]) {
                if (!Arrays.equals((byte[]) aValue, (byte[]) bValue)) {
                    return false;
                }
            } else if (!Objects.equals(aValue, bValue)) {
                return false;
            }
        }
        return true;
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(version, digestAlgorithm, docType, signed, validFrom, validUntil);
    }
    
    @Override
    public String toString() {
        return String.format(
            "MobileSecurityObject{version='%s', digestAlgorithm='%s', docType='%s', " +
            "validFrom=%s, validUntil=%s, namespaces=%d}",
            version, digestAlgorithm, docType, validFrom, validUntil, valueDigests.size()
        );
    }
}

// Made with Bob
