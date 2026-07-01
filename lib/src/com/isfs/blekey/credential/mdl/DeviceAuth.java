/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.mdl;

import com.isfs.blekey.cose.CoseException;
import com.isfs.blekey.cose.CoseUtils;
import com.isfs.blekey.util.Cbor;
import COSE.AlgorithmID;
import COSE.Sign1Message;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * Represents the DeviceAuth structure in an ISO mDL credential.
 * 
 * <p>DeviceAuth provides device authentication through either:
 * <ul>
 *   <li>deviceSignature - COSE_Sign1 signature by device key</li>
 *   <li>deviceMac - COSE_Mac0 MAC by device key</li>
 * </ul>
 * 
 * <p>The device signature/MAC is computed over:
 * <ul>
 *   <li>SessionTranscript - Transcript of the session</li>
 *   <li>DeviceNameSpacesBytes - CBOR-encoded device namespaces</li>
 * </ul>
 * 
 * <p>CBOR structure (as per ISO 18013-5 Section 9.1.3):
 * <pre>
 * DeviceAuth = {
 *   "deviceSignature": DeviceSignature
 * } / {
 *   "deviceMac": DeviceMac
 * }
 * 
 * DeviceSignature = COSE_Sign1
 * DeviceMac = COSE_Mac0
 * </pre>
 * 
 * @see <a href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5:2021 Section 9.1.3</a>
 */
public class DeviceAuth {
    
    private final byte[] deviceSignature;
    private final byte[] deviceMac;
    
    /**
     * Creates a DeviceAuth with a device signature.
     * 
     * @param deviceSignature the COSE_Sign1 signature bytes
     * @throws IllegalArgumentException if deviceSignature is null or empty
     */
    private DeviceAuth(byte[] deviceSignature, byte[] deviceMac) {
        if (deviceSignature == null && deviceMac == null) {
            throw new IllegalArgumentException("Either deviceSignature or deviceMac must be provided");
        }
        if (deviceSignature != null && deviceMac != null) {
            throw new IllegalArgumentException("Only one of deviceSignature or deviceMac can be provided");
        }
        
        this.deviceSignature = deviceSignature != null ? deviceSignature.clone() : null;
        this.deviceMac = deviceMac != null ? deviceMac.clone() : null;
    }
    
    /**
     * Creates a DeviceAuth with a device signature.
     * 
     * @param deviceSignature the COSE_Sign1 signature bytes
     * @return the DeviceAuth instance
     * @throws IllegalArgumentException if deviceSignature is null or empty
     */
    public static DeviceAuth withSignature(byte[] deviceSignature) {
        if (deviceSignature == null || deviceSignature.length == 0) {
            throw new IllegalArgumentException("deviceSignature cannot be null or empty");
        }
        return new DeviceAuth(deviceSignature, null);
    }
    
    /**
     * Creates a DeviceAuth with a device MAC.
     * 
     * @param deviceMac the COSE_Mac0 MAC bytes
     * @return the DeviceAuth instance
     * @throws IllegalArgumentException if deviceMac is null or empty
     */
    public static DeviceAuth withMac(byte[] deviceMac) {
        if (deviceMac == null || deviceMac.length == 0) {
            throw new IllegalArgumentException("deviceMac cannot be null or empty");
        }
        return new DeviceAuth(null, deviceMac);
    }
    
    /**
     * Creates a device signature over the session transcript and device namespaces.
     *
     * @param sessionTranscript the session transcript bytes
     * @param deviceNameSpacesBytes the CBOR-encoded device namespaces
     * @param devicePrivateKey the device's private key
     * @param algorithm the signature algorithm (e.g., AlgorithmID.ECDSA_256 for ES256)
     * @return the DeviceAuth with signature
     * @throws MdlException if signature creation fails
     */
    public static DeviceAuth createSignature(
            byte[] sessionTranscript,
            byte[] deviceNameSpacesBytes,
            PrivateKey devicePrivateKey,
            AlgorithmID algorithm) throws MdlException {
        
        if (sessionTranscript == null || sessionTranscript.length == 0) {
            throw new IllegalArgumentException("sessionTranscript cannot be null or empty");
        }
        if (deviceNameSpacesBytes == null || deviceNameSpacesBytes.length == 0) {
            throw new IllegalArgumentException("deviceNameSpacesBytes cannot be null or empty");
        }
        if (devicePrivateKey == null) {
            throw new IllegalArgumentException("devicePrivateKey cannot be null");
        }
        if (algorithm == null) {
            throw new IllegalArgumentException("algorithm cannot be null");
        }
        
        try {
            // Build payload: ["DeviceAuthentication", SessionTranscript, DeviceNameSpacesBytes]
            Object[] payload = new Object[] {
                "DeviceAuthentication",
                Cbor.decode(sessionTranscript),
                Cbor.decode(deviceNameSpacesBytes)
            };
            byte[] payloadBytes = Cbor.encode(payload);
            
            // Create COSE_Sign1 signature
            Sign1Message sign1 = CoseUtils.createSign1(payloadBytes, devicePrivateKey, algorithm);
            byte[] signature = CoseUtils.encodeSign1(sign1);
            
            return withSignature(signature);
            
        } catch (CoseException e) {
            throw new MdlException("Failed to create device signature", e);
        } catch (Exception e) {
            throw new MdlException("Failed to encode device authentication payload", e);
        }
    }
    
    /**
     * Verifies the device signature using the device public key.
     *
     * @param sessionTranscript the session transcript bytes
     * @param deviceNameSpacesBytes the CBOR-encoded device namespaces
     * @param devicePublicKey the device's public key
     * @return true if signature is valid, false otherwise
     * @throws MdlException if verification fails
     */
    public boolean verifySignature(
            byte[] sessionTranscript,
            byte[] deviceNameSpacesBytes,
            PublicKey devicePublicKey) throws MdlException {
        
        if (deviceSignature == null) {
            throw new MdlException("No device signature present");
        }
        if (sessionTranscript == null || sessionTranscript.length == 0) {
            throw new IllegalArgumentException("sessionTranscript cannot be null or empty");
        }
        if (deviceNameSpacesBytes == null || deviceNameSpacesBytes.length == 0) {
            throw new IllegalArgumentException("deviceNameSpacesBytes cannot be null or empty");
        }
        if (devicePublicKey == null) {
            throw new IllegalArgumentException("devicePublicKey cannot be null");
        }
        
        try {
            // Build expected payload
            Object[] payload = new Object[] {
                "DeviceAuthentication",
                Cbor.decode(sessionTranscript),
                Cbor.decode(deviceNameSpacesBytes)
            };
            byte[] payloadBytes = Cbor.encode(payload);
            
            // Decode and verify COSE_Sign1 signature
            Sign1Message sign1 = CoseUtils.decodeSign1(deviceSignature);
            
            // Verify the payload matches
            byte[] actualPayload = CoseUtils.getPayload(sign1);
            if (!java.util.Arrays.equals(payloadBytes, actualPayload)) {
                return false;
            }
            
            // Verify the signature
            return CoseUtils.verifySign1(sign1, devicePublicKey);
            
        } catch (CoseException e) {
            throw new MdlException("Failed to verify device signature", e);
        } catch (Exception e) {
            throw new MdlException("Failed to decode device authentication payload", e);
        }
    }
    
    /**
     * Returns whether this DeviceAuth uses a signature.
     * 
     * @return true if using signature, false if using MAC
     */
    public boolean hasSignature() {
        return deviceSignature != null;
    }
    
    /**
     * Returns whether this DeviceAuth uses a MAC.
     * 
     * @return true if using MAC, false if using signature
     */
    public boolean hasMac() {
        return deviceMac != null;
    }
    
    /**
     * Returns a copy of the device signature bytes.
     * 
     * @return the device signature, or null if using MAC
     */
    public byte[] getDeviceSignature() {
        return deviceSignature != null ? deviceSignature.clone() : null;
    }
    
    /**
     * Returns a copy of the device MAC bytes.
     * 
     * @return the device MAC, or null if using signature
     */
    public byte[] getDeviceMac() {
        return deviceMac != null ? deviceMac.clone() : null;
    }
    
    /**
     * Encodes this DeviceAuth to CBOR format.
     * 
     * @return CBOR-encoded bytes
     */
    public byte[] toCbor() {
        Map<String, byte[]> map = new HashMap<>();
        if (deviceSignature != null) {
            map.put("deviceSignature", deviceSignature);
        } else {
            map.put("deviceMac", deviceMac);
        }
        return Cbor.encode(map);
    }
    
    /**
     * Decodes a DeviceAuth from CBOR format.
     * 
     * @param cbor the CBOR-encoded bytes
     * @return the decoded DeviceAuth
     * @throws MdlException if decoding fails
     */
    public static DeviceAuth fromCbor(byte[] cbor) throws MdlException {
        try {
            Object decoded = Cbor.decode(cbor);
            if (!(decoded instanceof Map)) {
                throw new MdlException("DeviceAuth must be a CBOR map");
            }
            
            @SuppressWarnings("unchecked")
            Map<String, byte[]> map = (Map<String, byte[]>) decoded;
            
            byte[] deviceSignature = map.get("deviceSignature");
            byte[] deviceMac = map.get("deviceMac");
            
            if (deviceSignature != null) {
                return withSignature(deviceSignature);
            } else if (deviceMac != null) {
                return withMac(deviceMac);
            } else {
                throw new MdlException("DeviceAuth must contain either deviceSignature or deviceMac");
            }
            
        } catch (MdlException e) {
            throw e;
        } catch (Exception e) {
            throw new MdlException("Failed to decode DeviceAuth from CBOR", e);
        }
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DeviceAuth that = (DeviceAuth) o;
        return java.util.Arrays.equals(deviceSignature, that.deviceSignature) &&
               java.util.Arrays.equals(deviceMac, that.deviceMac);
    }
    
    @Override
    public int hashCode() {
        int result = java.util.Arrays.hashCode(deviceSignature);
        result = 31 * result + java.util.Arrays.hashCode(deviceMac);
        return result;
    }
    
    @Override
    public String toString() {
        if (deviceSignature != null) {
            return String.format("DeviceAuth{deviceSignature=%d bytes}", deviceSignature.length);
        } else {
            return String.format("DeviceAuth{deviceMac=%d bytes}", deviceMac.length);
        }
    }
}

// Made with Bob
