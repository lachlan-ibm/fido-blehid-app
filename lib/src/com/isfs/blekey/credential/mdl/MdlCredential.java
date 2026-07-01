/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.mdl;

import com.isfs.blekey.credential.DigitalCredentialFormat;
import com.isfs.blekey.credential.DigitalCredentialMetadata;
import com.isfs.blekey.credential.VerifiableCredential;
import com.isfs.blekey.util.Cbor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents a complete ISO 18013-5 mobile Driver's License (mDL) credential.
 * 
 * <p>This class extends {@link VerifiableCredential} to provide mDL-specific
 * functionality including:
 * <ul>
 *   <li>Complete mDL structure (IssuerSigned + DeviceSigned)</li>
 *   <li>Selective disclosure of data elements</li>
 *   <li>Signature verification (issuer and device)</li>
 *   <li>CBOR serialization per ISO 18013-5</li>
 * </ul>
 * 
 * <p>CBOR structure (as per ISO 18013-5 Section 8.3.2.1.2.2):
 * <pre>
 * MobileDocument = {
 *   "docType": DocType,
 *   "issuerSigned": IssuerSigned,
 *   "deviceSigned": DeviceSigned
 * }
 * </pre>
 * 
 * @see <a href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5:2021</a>
 */
public class MdlCredential extends VerifiableCredential {
    
    private static final Logger logger = LoggerFactory.getLogger(MdlCredential.class);
    
    private String docType;
    private IssuerSigned issuerSigned;
    private DeviceSigned deviceSigned;
    
    /**
     * Creates a new empty MdlCredential.
     */
    public MdlCredential() {
        super();
        setFormat(DigitalCredentialFormat.ISO_MDOC);
        this.docType = MobileDocument.DOCTYPE_MDL;
    }
    
    /**
     * Creates a new MdlCredential with specified components.
     * 
     * @param docType the document type
     * @param issuerSigned the issuer-signed portion
     * @param deviceSigned the device-signed portion
     * @param metadata credential metadata
     */
    public MdlCredential(String docType, IssuerSigned issuerSigned, 
                        DeviceSigned deviceSigned, DigitalCredentialMetadata metadata) {
        super(DigitalCredentialFormat.ISO_MDOC, metadata, null);
        this.docType = docType;
        this.issuerSigned = issuerSigned;
        this.deviceSigned = deviceSigned;
    }
    
    /**
     * Returns the document type.
     * 
     * @return the document type (e.g., "org.iso.18013.5.1.mDL")
     */
    public String getDocType() {
        return docType;
    }
    
    /**
     * Sets the document type.
     * 
     * @param docType the document type
     */
    public void setDocType(String docType) {
        this.docType = docType;
    }
    
    /**
     * Returns the issuer-signed portion of the mDL.
     * 
     * @return the issuer-signed data
     */
    public IssuerSigned getIssuerSigned() {
        return issuerSigned;
    }
    
    /**
     * Sets the issuer-signed portion of the mDL.
     * 
     * @param issuerSigned the issuer-signed data
     */
    public void setIssuerSigned(IssuerSigned issuerSigned) {
        this.issuerSigned = issuerSigned;
    }
    
    /**
     * Returns the device-signed portion of the mDL.
     * 
     * @return the device-signed data
     */
    public DeviceSigned getDeviceSigned() {
        return deviceSigned;
    }
    
    /**
     * Sets the device-signed portion of the mDL.
     * 
     * @param deviceSigned the device-signed data
     */
    public void setDeviceSigned(DeviceSigned deviceSigned) {
        this.deviceSigned = deviceSigned;
    }
    
    /**
     * Verifies the issuer signature on this mDL.
     * 
     * @param issuerPublicKey the issuer's public key
     * @return true if the signature is valid
     * @throws MdlException if verification fails
     */
    public boolean verifyIssuerSignature(PublicKey issuerPublicKey) throws MdlException {
        if (issuerSigned == null) {
            throw new MdlException("No issuer-signed data present");
        }
        
        try {
            IssuerAuth issuerAuth = IssuerAuth.fromCbor(issuerSigned.getIssuerAuth());
            return issuerAuth.verify(issuerPublicKey);
        } catch (Exception e) {
            throw new MdlException("Failed to verify issuer signature", e);
        }
    }
    
    /**
     * Verifies the device signature on this mDL.
     * 
     * @param sessionTranscript the session transcript bytes
     * @param devicePublicKey the device's public key
     * @return true if the signature is valid
     * @throws MdlException if verification fails
     */
    public boolean verifyDeviceSignature(byte[] sessionTranscript, PublicKey devicePublicKey) 
            throws MdlException {
        if (deviceSigned == null) {
            throw new MdlException("No device-signed data present");
        }
        
        try {
            DeviceAuth deviceAuth = DeviceAuth.fromCbor(deviceSigned.getDeviceAuth());
            
            // Encode device namespaces for verification
            Map<String, List<DeviceSignedItem>> nameSpaces = deviceSigned.getNameSpaces();
            Map<String, Object> nameSpacesMap = new HashMap<>();
            for (Map.Entry<String, List<DeviceSignedItem>> entry : nameSpaces.entrySet()) {
                List<byte[]> items = new ArrayList<>();
                for (DeviceSignedItem item : entry.getValue()) {
                    items.add(item.toCbor());
                }
                nameSpacesMap.put(entry.getKey(), items);
            }
            byte[] deviceNameSpacesBytes = Cbor.encode(nameSpacesMap);
            
            return deviceAuth.verifySignature(sessionTranscript, deviceNameSpacesBytes, devicePublicKey);
        } catch (Exception e) {
            throw new MdlException("Failed to verify device signature", e);
        }
    }
    
    /**
     * Creates a selective disclosure of this mDL containing only specified elements.
     * 
     * @param requestedNamespaces map of namespace to list of element identifiers to disclose
     * @return a new MdlCredential with only the requested elements
     * @throws MdlException if selective disclosure fails
     */
    public MdlCredential selectiveDisclosure(Map<String, List<String>> requestedNamespaces) 
            throws MdlException {
        if (issuerSigned == null) {
            throw new MdlException("No issuer-signed data present");
        }
        
        try {
            // Filter issuer-signed items
            Map<String, List<IssuerSignedItem>> filteredIssuerItems = new HashMap<>();
            Map<String, List<IssuerSignedItem>> allIssuerItems = issuerSigned.getNameSpaces();
            
            for (Map.Entry<String, List<String>> request : requestedNamespaces.entrySet()) {
                String namespace = request.getKey();
                List<String> requestedElements = request.getValue();
                
                List<IssuerSignedItem> namespaceItems = allIssuerItems.get(namespace);
                if (namespaceItems != null) {
                    List<IssuerSignedItem> filtered = new ArrayList<>();
                    for (IssuerSignedItem item : namespaceItems) {
                        if (requestedElements.contains(item.getElementIdentifier())) {
                            filtered.add(item);
                        }
                    }
                    if (!filtered.isEmpty()) {
                        filteredIssuerItems.put(namespace, filtered);
                    }
                }
            }
            
            // Create new IssuerSigned with filtered items
            IssuerSigned newIssuerSigned = new IssuerSigned(
                filteredIssuerItems,
                issuerSigned.getIssuerAuth()
            );
            
            // Device-signed data remains the same (or could be filtered similarly)
            MdlCredential disclosed = new MdlCredential(
                docType,
                newIssuerSigned,
                deviceSigned,
                getMetadata()
            );
            disclosed.setId(getId());
            
            return disclosed;
        } catch (Exception e) {
            throw new MdlException("Failed to create selective disclosure", e);
        }
    }
    
    /**
     * Gets all issuer-signed items for a specific namespace.
     * 
     * @param namespace the namespace to query
     * @return list of issuer-signed items, or empty list if namespace not found
     */
    public List<IssuerSignedItem> getIssuerSignedItems(String namespace) {
        if (issuerSigned == null) {
            return new ArrayList<>();
        }
        
        Map<String, List<IssuerSignedItem>> nameSpaces = issuerSigned.getNameSpaces();
        List<IssuerSignedItem> items = nameSpaces.get(namespace);
        return items != null ? new ArrayList<>(items) : new ArrayList<>();
    }
    
    /**
     * Gets all device-signed items for a specific namespace.
     * 
     * @param namespace the namespace to query
     * @return list of device-signed items, or empty list if namespace not found
     */
    public List<DeviceSignedItem> getDeviceSignedItems(String namespace) {
        if (deviceSigned == null) {
            return new ArrayList<>();
        }
        
        Map<String, List<DeviceSignedItem>> nameSpaces = deviceSigned.getNameSpaces();
        List<DeviceSignedItem> items = nameSpaces.get(namespace);
        return items != null ? new ArrayList<>(items) : new ArrayList<>();
    }
    
    /**
     * Encodes this mDL credential to CBOR format.
     * 
     * @return CBOR-encoded mDL
     * @throws MdlException if encoding fails
     */
    public byte[] toMdlCbor() throws MdlException {
        try {
            Map<String, Object> map = new HashMap<>();
            map.put("docType", docType);
            
            if (issuerSigned != null) {
                map.put("issuerSigned", Cbor.decode(issuerSigned.toCbor()));
            }
            
            if (deviceSigned != null) {
                map.put("deviceSigned", Cbor.decode(deviceSigned.toCbor()));
            }
            
            return Cbor.encode(map);
        } catch (Exception e) {
            throw new MdlException("Failed to encode mDL to CBOR", e);
        }
    }
    
    /**
     * Decodes an mDL credential from CBOR format.
     * 
     * @param cbor the CBOR-encoded mDL
     * @return the decoded MdlCredential
     * @throws MdlException if decoding fails
     */
    public static MdlCredential fromMdlCbor(byte[] cbor) throws MdlException {
        try {
            Object decoded = Cbor.decode(cbor);
            if (!(decoded instanceof Map)) {
                throw new MdlException("mDL must be a CBOR map");
            }
            
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) decoded;
            
            String docType = (String) map.get("docType");
            
            IssuerSigned issuerSigned = null;
            Object issuerSignedObj = map.get("issuerSigned");
            if (issuerSignedObj != null) {
                byte[] issuerSignedBytes = Cbor.encode(issuerSignedObj);
                issuerSigned = IssuerSigned.fromCbor(issuerSignedBytes);
            }
            
            DeviceSigned deviceSigned = null;
            Object deviceSignedObj = map.get("deviceSigned");
            if (deviceSignedObj != null) {
                byte[] deviceSignedBytes = Cbor.encode(deviceSignedObj);
                deviceSigned = DeviceSigned.fromCbor(deviceSignedBytes);
            }
            
            MdlCredential credential = new MdlCredential();
            credential.setDocType(docType);
            credential.setIssuerSigned(issuerSigned);
            credential.setDeviceSigned(deviceSigned);
            
            return credential;
        } catch (MdlException e) {
            throw e;
        } catch (Exception e) {
            throw new MdlException("Failed to decode mDL from CBOR", e);
        }
    }
    
    @Override
    public String toString() {
        return String.format("MdlCredential{id='%s', docType='%s', hasIssuerSigned=%b, hasDeviceSigned=%b}",
                getId(), docType, issuerSigned != null, deviceSigned != null);
    }
}

// Made with Bob
