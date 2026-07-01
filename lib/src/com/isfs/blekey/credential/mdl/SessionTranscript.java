/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.mdl;

import com.isfs.blekey.util.Cbor;
import java.util.List;

/**
 * Represents the SessionTranscript structure for ISO 18013-5 device authentication.
 * 
 * <p>SessionTranscript is used as input to device authentication and contains:
 * <ul>
 *   <li>DeviceEngagementBytes - CBOR-encoded device engagement</li>
 *   <li>EReaderKeyBytes - CBOR-encoded reader's ephemeral public key</li>
 *   <li>Handover - Handover data (optional)</li>
 * </ul>
 * 
 * <p>CBOR structure (as per ISO 18013-5 Section 9.1.3.1):
 * <pre>
 * SessionTranscript = [
 *   DeviceEngagementBytes,
 *   EReaderKeyBytes,
 *   Handover
 * ]
 * </pre>
 * 
 * @see <a href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5:2021 Section 9.1.3.1</a>
 */
public class SessionTranscript {
    
    private final byte[] deviceEngagementBytes;
    private final byte[] eReaderKeyBytes;
    private final byte[] handover;
    
    /**
     * Creates a new SessionTranscript.
     * 
     * @param deviceEngagementBytes CBOR-encoded device engagement
     * @param eReaderKeyBytes CBOR-encoded reader's ephemeral public key
     * @param handover Handover data (can be null)
     * @throws IllegalArgumentException if required parameters are invalid
     */
    public SessionTranscript(byte[] deviceEngagementBytes, byte[] eReaderKeyBytes, byte[] handover) {
        if (deviceEngagementBytes == null || deviceEngagementBytes.length == 0) {
            throw new IllegalArgumentException("deviceEngagementBytes cannot be null or empty");
        }
        if (eReaderKeyBytes == null || eReaderKeyBytes.length == 0) {
            throw new IllegalArgumentException("eReaderKeyBytes cannot be null or empty");
        }
        
        this.deviceEngagementBytes = deviceEngagementBytes.clone();
        this.eReaderKeyBytes = eReaderKeyBytes.clone();
        this.handover = handover != null ? handover.clone() : null;
    }
    
    /**
     * Creates a SessionTranscript without handover data.
     * 
     * @param deviceEngagementBytes CBOR-encoded device engagement
     * @param eReaderKeyBytes CBOR-encoded reader's ephemeral public key
     * @return SessionTranscript instance
     * @throws IllegalArgumentException if parameters are invalid
     */
    public static SessionTranscript create(byte[] deviceEngagementBytes, byte[] eReaderKeyBytes) {
        return new SessionTranscript(deviceEngagementBytes, eReaderKeyBytes, null);
    }
    
    /**
     * Encodes this SessionTranscript to CBOR format.
     * 
     * @return CBOR-encoded bytes
     */
    public byte[] toCbor() {
        Object[] transcript = handover != null ?
            new Object[] { deviceEngagementBytes, eReaderKeyBytes, handover } :
            new Object[] { deviceEngagementBytes, eReaderKeyBytes, null };
        
        return Cbor.encode(transcript);
    }
    
    /**
     * Decodes a SessionTranscript from CBOR format.
     * 
     * @param cbor the CBOR-encoded bytes
     * @return the decoded SessionTranscript
     * @throws MdlException if decoding fails
     */
    public static SessionTranscript fromCbor(byte[] cbor) throws MdlException {
        try {
            Object decoded = Cbor.decode(cbor);
            if (!(decoded instanceof List)) {
                throw new MdlException("SessionTranscript must be a CBOR array");
            }
            
            @SuppressWarnings("unchecked")
            List<Object> array = (List<Object>) decoded;
            if (array.size() < 2) {
                throw new MdlException("SessionTranscript must have at least 2 elements");
            }
            
            byte[] deviceEngagementBytes = (byte[]) array.get(0);
            byte[] eReaderKeyBytes = (byte[]) array.get(1);
            byte[] handover = array.size() > 2 ? (byte[]) array.get(2) : null;
            
            return new SessionTranscript(deviceEngagementBytes, eReaderKeyBytes, handover);
            
        } catch (MdlException e) {
            throw e;
        } catch (Exception e) {
            throw new MdlException("Failed to decode SessionTranscript from CBOR", e);
        }
    }
    
    /**
     * Returns a copy of the device engagement bytes.
     * 
     * @return the device engagement bytes
     */
    public byte[] getDeviceEngagementBytes() {
        return deviceEngagementBytes.clone();
    }
    
    /**
     * Returns a copy of the reader's ephemeral public key bytes.
     * 
     * @return the reader key bytes
     */
    public byte[] getEReaderKeyBytes() {
        return eReaderKeyBytes.clone();
    }
    
    /**
     * Returns a copy of the handover data, or null if not present.
     * 
     * @return the handover data, or null
     */
    public byte[] getHandover() {
        return handover != null ? handover.clone() : null;
    }
    
    /**
     * Returns whether this SessionTranscript has handover data.
     * 
     * @return true if handover data is present
     */
    public boolean hasHandover() {
        return handover != null;
    }
    
    @Override
    public String toString() {
        return String.format("SessionTranscript{deviceEngagement=%d bytes, eReaderKey=%d bytes, handover=%s}",
            deviceEngagementBytes.length, 
            eReaderKeyBytes.length,
            handover != null ? handover.length + " bytes" : "null");
    }
}

// Made with Bob