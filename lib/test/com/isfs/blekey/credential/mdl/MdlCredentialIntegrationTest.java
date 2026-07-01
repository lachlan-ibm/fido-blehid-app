/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.mdl;

import com.isfs.blekey.credential.DigitalCredentialMetadata;
import com.isfs.blekey.cose.CoseUtils;
import COSE.AlgorithmID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Integration tests for {@link MdlCredential}.
 * Tests the complete mDL lifecycle including creation, signing, and verification.
 */
class MdlCredentialIntegrationTest {
    
    private KeyPair issuerKeyPair;
    private KeyPair deviceKeyPair;
    private byte[] sessionTranscript;
    
    @BeforeEach
    void setUp() throws Exception {
        // Generate key pairs
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        issuerKeyPair = keyGen.generateKeyPair();
        deviceKeyPair = keyGen.generateKeyPair();
        
        // Create session transcript
        Map<String, Object> transcript = new HashMap<>();
        transcript.put("session_id", "test-session-123");
        transcript.put("timestamp", System.currentTimeMillis());
        sessionTranscript = com.isfs.blekey.util.Cbor.encode(transcript);
    }
    
    @Test
    void testCreateCompleteMdl() throws Exception {
        // Create issuer-signed items
        List<IssuerSignedItem> isoItems = new ArrayList<>();
        isoItems.add(new IssuerSignedItem(0, new byte[]{1, 2, 3}, "family_name", "Smith"));
        isoItems.add(new IssuerSignedItem(1, new byte[]{4, 5, 6}, "given_name", "John"));
        isoItems.add(new IssuerSignedItem(2, new byte[]{7, 8, 9}, "birth_date", "1990-01-01"));
        
        Map<String, List<IssuerSignedItem>> issuerNameSpaces = new HashMap<>();
        issuerNameSpaces.put(NameSpace.ISO_18013_5_1, isoItems);
        
        // Create MSO
        Map<String, Map<Integer, byte[]>> valueDigests = new HashMap<>();
        Map<Integer, byte[]> digests = new HashMap<>();
        for (IssuerSignedItem item : isoItems) {
            byte[] digest = item.calculateDigest(MobileSecurityObject.DIGEST_ALGORITHM_SHA256);
            digests.put(item.getDigestId(), digest);
        }
        valueDigests.put(NameSpace.ISO_18013_5_1, digests);
        
        Map<String, Object> deviceKeyInfo = new HashMap<>();
        deviceKeyInfo.put("deviceKey", deviceKeyPair.getPublic().getEncoded());
        
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        MobileSecurityObject mso = new MobileSecurityObject(
            MobileSecurityObject.VERSION_1_0,
            MobileSecurityObject.DIGEST_ALGORITHM_SHA256,
            valueDigests,
            deviceKeyInfo,
            MobileDocument.DOCTYPE_MDL,
            now,
            now.minus(1, ChronoUnit.DAYS),
            now.plus(365, ChronoUnit.DAYS)
        );
        
        // Create IssuerAuth
        IssuerAuth issuerAuth = IssuerAuth.create(mso, issuerKeyPair.getPrivate(), null);
        
        // Create IssuerSigned
        IssuerSigned issuerSigned = new IssuerSigned(issuerNameSpaces, issuerAuth.toCbor());
        
        // Create device-signed items
        List<DeviceSignedItem> deviceItems = new ArrayList<>();
        deviceItems.add(new DeviceSignedItem("portrait", new byte[]{0x01, 0x02, 0x03}));
        
        Map<String, List<DeviceSignedItem>> deviceNameSpaces = new HashMap<>();
        deviceNameSpaces.put(NameSpace.ISO_18013_5_1, deviceItems);
        
        // Create DeviceAuth
        Map<String, Object> deviceNameSpacesMap = new HashMap<>();
        List<byte[]> deviceItemsBytes = new ArrayList<>();
        for (DeviceSignedItem item : deviceItems) {
            deviceItemsBytes.add(item.toCbor());
        }
        deviceNameSpacesMap.put(NameSpace.ISO_18013_5_1, deviceItemsBytes);
        byte[] deviceNameSpacesBytes = com.isfs.blekey.util.Cbor.encode(deviceNameSpacesMap);
        
        DeviceAuth deviceAuth = DeviceAuth.createSignature(
            sessionTranscript,
            deviceNameSpacesBytes,
            deviceKeyPair.getPrivate(),
            AlgorithmID.ECDSA_256
        );
        
        // Create DeviceSigned
        DeviceSigned deviceSigned = new DeviceSigned(deviceNameSpaces, deviceAuth.toCbor());
        
        // Create MdlCredential
        DigitalCredentialMetadata metadata = new DigitalCredentialMetadata();
        metadata.setCredentialType("mDL");
        metadata.setIssuerDid("did:example:issuer");
        
        MdlCredential mdl = new MdlCredential(
            MobileDocument.DOCTYPE_MDL,
            issuerSigned,
            deviceSigned,
            metadata
        );
        
        // Verify structure
        assertNotNull(mdl);
        assertEquals(MobileDocument.DOCTYPE_MDL, mdl.getDocType());
        assertNotNull(mdl.getIssuerSigned());
        assertNotNull(mdl.getDeviceSigned());
        
        // Verify issuer signature
        assertTrue(mdl.verifyIssuerSignature(issuerKeyPair.getPublic()));
        
        // Verify device signature
        assertTrue(mdl.verifyDeviceSignature(sessionTranscript, deviceKeyPair.getPublic()));
    }
    
    @Test
    void testMdlSerialization() throws Exception {
        // Create a simple mDL
        List<IssuerSignedItem> items = new ArrayList<>();
        items.add(new IssuerSignedItem(0, new byte[]{1, 2, 3}, "family_name", "Smith"));
        
        Map<String, List<IssuerSignedItem>> nameSpaces = new HashMap<>();
        nameSpaces.put(NameSpace.ISO_18013_5_1, items);
        
        // Create MSO
        Map<String, Map<Integer, byte[]>> valueDigests = new HashMap<>();
        Map<Integer, byte[]> digests = new HashMap<>();
        byte[] digest = items.get(0).calculateDigest(MobileSecurityObject.DIGEST_ALGORITHM_SHA256);
        digests.put(0, digest);
        valueDigests.put(NameSpace.ISO_18013_5_1, digests);
        
        Map<String, Object> deviceKeyInfo = new HashMap<>();
        deviceKeyInfo.put("deviceKey", new byte[]{1, 2, 3});
        
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        MobileSecurityObject mso = new MobileSecurityObject(
            MobileSecurityObject.VERSION_1_0,
            MobileSecurityObject.DIGEST_ALGORITHM_SHA256,
            valueDigests,
            deviceKeyInfo,
            MobileDocument.DOCTYPE_MDL,
            now, now, now.plus(1, ChronoUnit.DAYS)
        );
        
        IssuerAuth issuerAuth = IssuerAuth.create(mso, issuerKeyPair.getPrivate(), null);
        IssuerSigned issuerSigned = new IssuerSigned(nameSpaces, issuerAuth.toCbor());
        
        DeviceSigned deviceSigned = new DeviceSigned(new HashMap<>(), new byte[]{1, 2, 3, 4});
        
        MdlCredential original = new MdlCredential(
            MobileDocument.DOCTYPE_MDL,
            issuerSigned,
            deviceSigned,
            new DigitalCredentialMetadata()
        );
        
        // Serialize and deserialize
        byte[] cbor = original.toMdlCbor();
        MdlCredential decoded = MdlCredential.fromMdlCbor(cbor);
        
        // Verify
        assertEquals(original.getDocType(), decoded.getDocType());
        assertNotNull(decoded.getIssuerSigned());
        assertNotNull(decoded.getDeviceSigned());
    }
    
    @Test
    void testSelectiveDisclosure() throws Exception {
        // Create mDL with multiple elements
        List<IssuerSignedItem> items = new ArrayList<>();
        items.add(new IssuerSignedItem(0, new byte[]{1, 2, 3}, "family_name", "Smith"));
        items.add(new IssuerSignedItem(1, new byte[]{4, 5, 6}, "given_name", "John"));
        items.add(new IssuerSignedItem(2, new byte[]{7, 8, 9}, "birth_date", "1990-01-01"));
        items.add(new IssuerSignedItem(3, new byte[]{10, 11, 12}, "address", "123 Main St"));
        
        Map<String, List<IssuerSignedItem>> nameSpaces = new HashMap<>();
        nameSpaces.put(NameSpace.ISO_18013_5_1, items);
        
        // Create MSO
        Map<String, Map<Integer, byte[]>> valueDigests = new HashMap<>();
        Map<Integer, byte[]> digests = new HashMap<>();
        for (IssuerSignedItem item : items) {
            byte[] digest = item.calculateDigest(MobileSecurityObject.DIGEST_ALGORITHM_SHA256);
            digests.put(item.getDigestId(), digest);
        }
        valueDigests.put(NameSpace.ISO_18013_5_1, digests);
        
        Map<String, Object> deviceKeyInfo = new HashMap<>();
        deviceKeyInfo.put("deviceKey", new byte[]{1, 2, 3});
        
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        MobileSecurityObject mso = new MobileSecurityObject(
            MobileSecurityObject.VERSION_1_0,
            MobileSecurityObject.DIGEST_ALGORITHM_SHA256,
            valueDigests,
            deviceKeyInfo,
            MobileDocument.DOCTYPE_MDL,
            now, now, now.plus(1, ChronoUnit.DAYS)
        );
        
        IssuerAuth issuerAuth = IssuerAuth.create(mso, issuerKeyPair.getPrivate(), null);
        IssuerSigned issuerSigned = new IssuerSigned(nameSpaces, issuerAuth.toCbor());
        
        DeviceSigned deviceSigned = new DeviceSigned(new HashMap<>(), new byte[]{1, 2, 3, 4});
        
        MdlCredential fullMdl = new MdlCredential(
            MobileDocument.DOCTYPE_MDL,
            issuerSigned,
            deviceSigned,
            new DigitalCredentialMetadata()
        );
        
        // Request selective disclosure (only name fields)
        Map<String, List<String>> requestedElements = new HashMap<>();
        List<String> requestedFields = new ArrayList<>();
        requestedFields.add("family_name");
        requestedFields.add("given_name");
        requestedElements.put(NameSpace.ISO_18013_5_1, requestedFields);
        
        MdlCredential disclosed = fullMdl.selectiveDisclosure(requestedElements);
        
        // Verify only requested elements are present
        List<IssuerSignedItem> disclosedItems = disclosed.getIssuerSignedItems(NameSpace.ISO_18013_5_1);
        assertEquals(2, disclosedItems.size());
        
        boolean hasFamily = false;
        boolean hasGiven = false;
        for (IssuerSignedItem item : disclosedItems) {
            if ("family_name".equals(item.getElementIdentifier())) hasFamily = true;
            if ("given_name".equals(item.getElementIdentifier())) hasGiven = true;
        }
        assertTrue(hasFamily);
        assertTrue(hasGiven);
        
        // Verify signature still valid
        assertTrue(disclosed.verifyIssuerSignature(issuerKeyPair.getPublic()));
    }
    
    @Test
    void testGetIssuerSignedItems() throws Exception {
        List<IssuerSignedItem> items = new ArrayList<>();
        items.add(new IssuerSignedItem(0, new byte[]{1, 2, 3}, "family_name", "Smith"));
        items.add(new IssuerSignedItem(1, new byte[]{4, 5, 6}, "given_name", "John"));
        
        Map<String, List<IssuerSignedItem>> nameSpaces = new HashMap<>();
        nameSpaces.put(NameSpace.ISO_18013_5_1, items);
        
        Map<String, Map<Integer, byte[]>> valueDigests = new HashMap<>();
        Map<Integer, byte[]> digests = new HashMap<>();
        for (IssuerSignedItem item : items) {
            digests.put(item.getDigestId(), item.calculateDigest(MobileSecurityObject.DIGEST_ALGORITHM_SHA256));
        }
        valueDigests.put(NameSpace.ISO_18013_5_1, digests);
        
        Map<String, Object> deviceKeyInfo = new HashMap<>();
        deviceKeyInfo.put("deviceKey", new byte[]{1, 2, 3});
        
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        MobileSecurityObject mso = new MobileSecurityObject(
            MobileSecurityObject.VERSION_1_0,
            MobileSecurityObject.DIGEST_ALGORITHM_SHA256,
            valueDigests,
            deviceKeyInfo,
            MobileDocument.DOCTYPE_MDL,
            now, now, now.plus(1, ChronoUnit.DAYS)
        );
        
        IssuerAuth issuerAuth = IssuerAuth.create(mso, issuerKeyPair.getPrivate(), null);
        IssuerSigned issuerSigned = new IssuerSigned(nameSpaces, issuerAuth.toCbor());
        
        MdlCredential mdl = new MdlCredential(
            MobileDocument.DOCTYPE_MDL,
            issuerSigned,
            null,
            new DigitalCredentialMetadata()
        );
        
        List<IssuerSignedItem> retrieved = mdl.getIssuerSignedItems(NameSpace.ISO_18013_5_1);
        assertEquals(2, retrieved.size());
        
        List<IssuerSignedItem> empty = mdl.getIssuerSignedItems("nonexistent");
        assertTrue(empty.isEmpty());
    }
    
    @Test
    void testGetDeviceSignedItems() throws Exception {
        List<DeviceSignedItem> items = new ArrayList<>();
        items.add(new DeviceSignedItem("portrait", new byte[]{1, 2, 3}));
        
        Map<String, List<DeviceSignedItem>> nameSpaces = new HashMap<>();
        nameSpaces.put(NameSpace.ISO_18013_5_1, items);
        
        DeviceSigned deviceSigned = new DeviceSigned(nameSpaces, new byte[]{1, 2, 3, 4});
        
        MdlCredential mdl = new MdlCredential(
            MobileDocument.DOCTYPE_MDL,
            null,
            deviceSigned,
            new DigitalCredentialMetadata()
        );
        
        List<DeviceSignedItem> retrieved = mdl.getDeviceSignedItems(NameSpace.ISO_18013_5_1);
        assertEquals(1, retrieved.size());
        assertEquals("portrait", retrieved.get(0).getElementIdentifier());
    }
    
    @Test
    void testVerifyIssuerSignature_NoIssuerSigned() {
        MdlCredential mdl = new MdlCredential();
        
        assertThrows(MdlException.class, () -> {
            mdl.verifyIssuerSignature(issuerKeyPair.getPublic());
        });
    }
    
    @Test
    void testVerifyDeviceSignature_NoDeviceSigned() {
        MdlCredential mdl = new MdlCredential();
        
        assertThrows(MdlException.class, () -> {
            mdl.verifyDeviceSignature(sessionTranscript, deviceKeyPair.getPublic());
        });
    }
    
    @Test
    void testToString() {
        MdlCredential mdl = new MdlCredential();
        mdl.setDocType(MobileDocument.DOCTYPE_MDL);
        
        String str = mdl.toString();
        assertNotNull(str);
        assertTrue(str.contains("MdlCredential"));
        assertTrue(str.contains(MobileDocument.DOCTYPE_MDL));
    }
}

// Made with Bob
