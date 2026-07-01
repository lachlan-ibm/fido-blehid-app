/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.mdl;

import com.isfs.blekey.util.Cbor;
import com.isfs.blekey.util.KeyUtils;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * Represents Device Engagement structure for ISO 18013-5 presentation.
 * 
 * <p>Device Engagement contains:
 * <ul>
 *   <li>version - Protocol version</li>
 *   <li>security - Security parameters (device public key)</li>
 *   <li>deviceRetrievalMethods - Available retrieval methods (QR, NFC, BLE)</li>
 * </ul>
 * 
 * <p>CBOR structure (as per ISO 18013-5 Section 8.2.1):
 * <pre>
 * DeviceEngagement = {
 *   "version": tstr,
 *   "security": Security,
 *   "deviceRetrievalMethods": [+ DeviceRetrievalMethod]
 * }
 * 
 * Security = {
 *   1: int,  ; cipher suite identifier
 *   2: bstr  ; device ephemeral public key (COSE_Key)
 * }
 * </pre>
 * 
 * @see <a href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5:2021 Section 8.2.1</a>
 */
public class DeviceEngagement {
    
    private final String version;
    private final PublicKey devicePublicKey;
    private final int cipherSuite;
    
    /**
     * Creates a new DeviceEngagement.
     * 
     * @param version Protocol version (e.g., "1.0")
     * @param devicePublicKey Device's ephemeral public key
     * @param cipherSuite Cipher suite identifier (1 = ECDH-ES+A256GCM)
     * @throws IllegalArgumentException if parameters are invalid
     */
    public DeviceEngagement(String version, PublicKey devicePublicKey, int cipherSuite) {
        if (version == null || version.isEmpty()) {
            throw new IllegalArgumentException("version cannot be null or empty");
        }
        if (devicePublicKey == null) {
            throw new IllegalArgumentException("devicePublicKey cannot be null");
        }
        if (!"EC".equals(devicePublicKey.getAlgorithm())) {
            throw new IllegalArgumentException("Only EC keys are supported");
        }
        
        this.version = version;
        this.devicePublicKey = devicePublicKey;
        this.cipherSuite = cipherSuite;
    }
    
    /**
     * Creates a DeviceEngagement with default parameters.
     * 
     * @param devicePublicKey Device's ephemeral public key
     * @return DeviceEngagement instance
     * @throws IllegalArgumentException if devicePublicKey is invalid
     */
    public static DeviceEngagement create(PublicKey devicePublicKey) {
        return new DeviceEngagement("1.0", devicePublicKey, 1);
    }
    
    /**
     * Encodes this DeviceEngagement to CBOR format.
     * 
     * @return CBOR-encoded bytes
     * @throws MdlException if encoding fails
     */
    public byte[] toCbor() throws MdlException {
        try {
            Map<String, Object> engagement = new HashMap<>();
            engagement.put("version", version);
            
            // Encode security
            Map<Integer, Object> security = new HashMap<>();
            security.put(1, cipherSuite);
            security.put(2, encodePublicKeyAsCoseKey(devicePublicKey));
            engagement.put("security", security);
            
            // Device retrieval methods (QR code only for MVP)
            Map<Integer, Object> qrMethod = new HashMap<>();
            qrMethod.put(0, 2); // type: QR code
            engagement.put("deviceRetrievalMethods", new Object[] { qrMethod });
            
            return Cbor.encode(engagement);
            
        } catch (Exception e) {
            throw new MdlException("Failed to encode DeviceEngagement", e);
        }
    }
    
    /**
     * Decodes a DeviceEngagement from CBOR format.
     * 
     * @param cbor the CBOR-encoded bytes
     * @return the decoded DeviceEngagement
     * @throws MdlException if decoding fails
     */
    public static DeviceEngagement fromCbor(byte[] cbor) throws MdlException {
        try {
            Object decoded = Cbor.decode(cbor);
            if (!(decoded instanceof Map)) {
                throw new MdlException("DeviceEngagement must be a CBOR map");
            }
            
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) decoded;
            
            String version = (String) map.get("version");
            if (version == null) {
                throw new MdlException("DeviceEngagement missing version");
            }
            
            @SuppressWarnings("unchecked")
            Map<Integer, Object> security = (Map<Integer, Object>) map.get("security");
            if (security == null) {
                throw new MdlException("DeviceEngagement missing security");
            }
            
            Integer cipherSuite = (Integer) security.get(1);
            if (cipherSuite == null) {
                throw new MdlException("DeviceEngagement missing cipher suite");
            }
            
            byte[] coseKeyBytes = (byte[]) security.get(2);
            if (coseKeyBytes == null) {
                throw new MdlException("DeviceEngagement missing device public key");
            }
            
            PublicKey publicKey = decodePublicKeyFromCoseKey(coseKeyBytes);
            
            return new DeviceEngagement(version, publicKey, cipherSuite);
            
        } catch (MdlException e) {
            throw e;
        } catch (Exception e) {
            throw new MdlException("Failed to decode DeviceEngagement from CBOR", e);
        }
    }
    
    /**
     * Generates a QR code payload for device engagement.
     * 
     * @return Base64-encoded device engagement with "mdoc:" prefix
     * @throws MdlException if generation fails
     */
    public String toQrCodePayload() throws MdlException {
        byte[] cbor = toCbor();
        return "mdoc:" + java.util.Base64.getEncoder().encodeToString(cbor);
    }
    
    /**
     * Parses a QR code payload to extract DeviceEngagement.
     * 
     * @param qrPayload the QR code payload string
     * @return the decoded DeviceEngagement
     * @throws MdlException if parsing fails
     */
    public static DeviceEngagement fromQrCodePayload(String qrPayload) throws MdlException {
        if (qrPayload == null || !qrPayload.startsWith("mdoc:")) {
            throw new MdlException("Invalid QR code payload format");
        }
        
        try {
            String base64 = qrPayload.substring(5); // Remove "mdoc:" prefix
            byte[] cbor = java.util.Base64.getDecoder().decode(base64);
            return fromCbor(cbor);
        } catch (IllegalArgumentException e) {
            throw new MdlException("Invalid base64 encoding in QR payload", e);
        }
    }
    
    /**
     * Encodes a public key as COSE_Key format using KeyUtils.
     *
     * @param publicKey the public key to encode
     * @return CBOR-encoded COSE_Key
     * @throws MdlException if encoding fails
     */
    private byte[] encodePublicKeyAsCoseKey(PublicKey publicKey) throws MdlException {
        try {
            Map<Integer, Object> coseKey = KeyUtils.toCoseKey(publicKey);
            return Cbor.encode(coseKey);
        } catch (Exception e) {
            throw new MdlException("Failed to encode public key as COSE_Key", e);
        }
    }
    
    /**
     * Decodes a public key from COSE_Key format using KeyUtils.
     *
     * @param coseKeyBytes the CBOR-encoded COSE_Key
     * @return the decoded public key
     * @throws MdlException if decoding fails
     */
    private static PublicKey decodePublicKeyFromCoseKey(byte[] coseKeyBytes) throws MdlException {
        try {
            Object decoded = Cbor.decode(coseKeyBytes);
            if (!(decoded instanceof Map)) {
                throw new MdlException("COSE_Key must be a CBOR map");
            }
            
            @SuppressWarnings("unchecked")
            Map<Integer, Object> coseKey = (Map<Integer, Object>) decoded;
            
            return KeyUtils.fromCoseKey(coseKey);
        } catch (Exception e) {
            throw new MdlException("Failed to decode public key from COSE_Key", e);
        }
    }
    
    /**
     * Returns the protocol version.
     * 
     * @return the version string
     */
    public String getVersion() {
        return version;
    }
    
    /**
     * Returns the device's public key.
     * 
     * @return the public key
     */
    public PublicKey getDevicePublicKey() {
        return devicePublicKey;
    }
    
    /**
     * Returns the cipher suite identifier.
     * 
     * @return the cipher suite
     */
    public int getCipherSuite() {
        return cipherSuite;
    }
    
    @Override
    public String toString() {
        return String.format("DeviceEngagement{version=%s, cipherSuite=%d}", 
            version, cipherSuite);
    }
}

// Made with Bob