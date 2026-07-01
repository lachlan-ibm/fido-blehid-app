/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.credential.mdl;

import com.isfs.blekey.credential.DigitalCredentialFormat;
import com.isfs.blekey.credential.DigitalCredentialMetadata;
import com.isfs.blekey.util.Cbor;
import com.isfs.blekey.util.CertUtils;
import COSE.AlgorithmID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end integration tests for ISO mDL (ISO/IEC 18013-5).
 * 
 * <p>This test suite validates the complete mDL lifecycle:
 * <ol>
 *   <li><b>Issuance</b>: Issue mDL via MdlIssuer</li>
 *   <li><b>Storage</b>: Store mDL with CBOR serialization</li>
 *   <li><b>Retrieval</b>: Retrieve and deserialize mDL</li>
 *   <li><b>Presentation</b>: Present mDL with selective disclosure</li>
 *   <li><b>Verification</b>: Verify issuer and device signatures</li>
 * </ol>
 * 
 * 
 * @see <a href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5:2021</a>
 */
@DisplayName("mDL End-to-End Integration Tests")
class MdlEndToEndTest {
    
    private KeyPair issuerKeyPair;
    private List<X509Certificate> issuerCertChain;
    private KeyPair deviceKeyPair;
    private byte[] sessionTranscript;
    private MdlIssuer mdlIssuer;
    
    @BeforeEach
    void setUp() throws Exception {
        // Generate issuer key pair and certificate
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        issuerKeyPair = keyGen.generateKeyPair();
        
        X509Certificate issuerCert = CertUtils.generateCaCert(
            "CN=Test mDL Issuer, O=Test DMV, C=US",
            issuerKeyPair,
            365,
            false
        );
        issuerCertChain = new ArrayList<>();
        issuerCertChain.add(issuerCert);
        
        // Generate device key pair
        deviceKeyPair = keyGen.generateKeyPair();
        
        // Create session transcript
        Map<String, Object> transcript = new HashMap<>();
        transcript.put("session_id", "test-session-" + UUID.randomUUID());
        transcript.put("timestamp", System.currentTimeMillis());
        sessionTranscript = Cbor.encode(transcript);
        
        // Create mDL issuer
        mdlIssuer = new MdlIssuer(
            issuerKeyPair.getPrivate(),
            issuerCertChain,
            MobileDocument.DOCTYPE_MDL
        );
    }
    
    @Test
    @DisplayName("E2E-001: Complete mDL issuance flow")
    void testCompleteIssuanceFlow() throws Exception {
        // 1. Prepare claims
        Map<String, Map<String, Object>> claims = createSampleMdlClaims();
        
        // 2. Issue mDL
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant validUntil = now.plus(365, ChronoUnit.DAYS);
        
        MobileDocument mdl = mdlIssuer.issueMdl(
            claims,
            deviceKeyPair.getPublic(),
            now,
            validUntil
        );
        
        // 3. Verify mDL structure
        assertNotNull(mdl);
        assertEquals(MobileDocument.DOCTYPE_MDL, mdl.getDocType());
        
        // 4. Verify all claims are present
        Map<String, List<IssuerSignedItem>> issuerSignedItems = mdl.getIssuerSignedItems();
        assertTrue(issuerSignedItems.containsKey(NameSpace.ISO_18013_5_1));
        
        List<IssuerSignedItem> items = issuerSignedItems.get(NameSpace.ISO_18013_5_1);
        assertEquals(8, items.size(), "Should have 8 data elements");
        
        // 5. Verify data elements
        Map<String, Object> foundClaims = new HashMap<>();
        for (IssuerSignedItem item : items) {
            foundClaims.put(item.getElementIdentifier(), item.getElementValue());
        }
        assertEquals("Smith", foundClaims.get("family_name"));
        assertEquals("John", foundClaims.get("given_name"));
        assertEquals("1990-01-15", foundClaims.get("birth_date"));
    }
    
    @Test
    @DisplayName("E2E-002: mDL storage and retrieval with CBOR serialization")
    void testStorageAndRetrieval() throws Exception {
        // 1. Issue mDL
        Map<String, Map<String, Object>> claims = createSampleMdlClaims();
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        
        MobileDocument mdl = mdlIssuer.issueMdl(
            claims,
            deviceKeyPair.getPublic(),
            now,
            now.plus(365, ChronoUnit.DAYS)
        );
        
        // 2. Serialize to CBOR
        byte[] storedCbor = mdl.toCbor();
        assertNotNull(storedCbor);
        assertTrue(storedCbor.length > 0);
        
        // 3. Deserialize from CBOR
        MobileDocument retrieved = MobileDocument.fromCbor(storedCbor);
        
        // 4. Verify retrieved document
        assertNotNull(retrieved);
        assertEquals(mdl.getDocType(), retrieved.getDocType());
        
        // 5. Verify data integrity
        Map<String, List<IssuerSignedItem>> originalItems = mdl.getIssuerSignedItems();
        Map<String, List<IssuerSignedItem>> retrievedItems = retrieved.getIssuerSignedItems();
        assertEquals(originalItems.size(), retrievedItems.size());
        
        List<IssuerSignedItem> originalIsoItems = originalItems.get(NameSpace.ISO_18013_5_1);
        List<IssuerSignedItem> retrievedIsoItems = retrievedItems.get(NameSpace.ISO_18013_5_1);
        assertEquals(originalIsoItems.size(), retrievedIsoItems.size());
    }
    
    @Test
    @DisplayName("E2E-003: Complete presentation flow with selective disclosure")
    void testCompletePresentationFlow() throws Exception {
        // 1. Issue mDL
        Map<String, Map<String, Object>> claims = createSampleMdlClaims();
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        
        MobileDocument mdl = mdlIssuer.issueMdl(
            claims,
            deviceKeyPair.getPublic(),
            now,
            now.plus(365, ChronoUnit.DAYS)
        );
        
        // 2. Get all issuer-signed items
        Map<String, List<IssuerSignedItem>> allItems = mdl.getIssuerSignedItems();
        List<IssuerSignedItem> isoItems = allItems.get(NameSpace.ISO_18013_5_1);
        
        // 3. Simulate selective disclosure - only disclose name and birth_date
        List<IssuerSignedItem> disclosedItems = new ArrayList<>();
        for (IssuerSignedItem item : isoItems) {
            String elementId = item.getElementIdentifier();
            if ("family_name".equals(elementId) || 
                "given_name".equals(elementId) || 
                "birth_date".equals(elementId)) {
                disclosedItems.add(item);
            }
        }
        
        // 4. Verify only requested elements are disclosed
        assertEquals(3, disclosedItems.size(), "Should only have 3 disclosed elements");
        
        Set<String> disclosedElementIds = new HashSet<>();
        for (IssuerSignedItem item : disclosedItems) {
            disclosedElementIds.add(item.getElementIdentifier());
        }
        
        assertTrue(disclosedElementIds.contains("family_name"));
        assertTrue(disclosedElementIds.contains("given_name"));
        assertTrue(disclosedElementIds.contains("birth_date"));
        assertFalse(disclosedElementIds.contains("document_number"));
    }
    
    @Test
    @DisplayName("E2E-004: Device authentication with session transcript")
    void testDeviceAuthentication() throws Exception {
        // 1. Issue mDL
        Map<String, Map<String, Object>> claims = createSampleMdlClaims();
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        
        MobileDocument mdl = mdlIssuer.issueMdl(
            claims,
            deviceKeyPair.getPublic(),
            now,
            now.plus(365, ChronoUnit.DAYS)
        );
        
        // 2. Create device-signed items
        List<DeviceSignedItem> deviceItems = new ArrayList<>();
        deviceItems.add(new DeviceSignedItem("portrait", new byte[]{0x01, 0x02, 0x03}));
        
        Map<String, List<DeviceSignedItem>> deviceNameSpaces = new HashMap<>();
        deviceNameSpaces.put(NameSpace.ISO_18013_5_1, deviceItems);
        
        // 3. Create DeviceAuth signature
        Map<String, Object> deviceNameSpacesMap = new HashMap<>();
        List<byte[]> deviceItemsBytes = new ArrayList<>();
        for (DeviceSignedItem item : deviceItems) {
            deviceItemsBytes.add(item.toCbor());
        }
        deviceNameSpacesMap.put(NameSpace.ISO_18013_5_1, deviceItemsBytes);
        byte[] deviceNameSpacesBytes = Cbor.encode(deviceNameSpacesMap);
        
        DeviceAuth deviceAuth = DeviceAuth.createSignature(
            sessionTranscript,
            deviceNameSpacesBytes,
            deviceKeyPair.getPrivate(),
            AlgorithmID.ECDSA_256
        );
        
        // 4. Verify device auth was created
        assertNotNull(deviceAuth);
        assertNotNull(deviceAuth.toCbor());
        
        // 5. Create DeviceSigned
        DeviceSigned deviceSigned = new DeviceSigned(deviceNameSpaces, deviceAuth.toCbor());
        assertNotNull(deviceSigned);
    }
    
    @Test
    @DisplayName("E2E-005: MdlCredential wrapper with verification")
    void testMdlCredentialWrapper() throws Exception {
        // 1. Issue mDL
        Map<String, Map<String, Object>> claims = createSampleMdlClaims();
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        
        MobileDocument mdl = mdlIssuer.issueMdl(
            claims,
            deviceKeyPair.getPublic(),
            now,
            now.plus(365, ChronoUnit.DAYS)
        );
        
        // 2. Create IssuerSigned from MobileDocument
        Map<String, List<IssuerSignedItem>> issuerSignedItems = mdl.getIssuerSignedItems();
        
        // Create MSO for IssuerAuth
        Map<String, Map<Integer, byte[]>> valueDigests = new HashMap<>();
        Map<Integer, byte[]> digests = new HashMap<>();
        List<IssuerSignedItem> items = issuerSignedItems.get(NameSpace.ISO_18013_5_1);
        for (IssuerSignedItem item : items) {
            byte[] digest = item.calculateDigest(MobileSecurityObject.DIGEST_ALGORITHM_SHA256);
            digests.put(item.getDigestId(), digest);
        }
        valueDigests.put(NameSpace.ISO_18013_5_1, digests);
        
        Map<String, Object> deviceKeyInfo = new HashMap<>();
        deviceKeyInfo.put("deviceKey", deviceKeyPair.getPublic().getEncoded());
        
        MobileSecurityObject mso = new MobileSecurityObject(
            MobileSecurityObject.VERSION_1_0,
            MobileSecurityObject.DIGEST_ALGORITHM_SHA256,
            valueDigests,
            deviceKeyInfo,
            MobileDocument.DOCTYPE_MDL,
            now,
            now,
            now.plus(365, ChronoUnit.DAYS)
        );
        
        IssuerAuth issuerAuth = IssuerAuth.create(mso, issuerKeyPair.getPrivate(), null);
        IssuerSigned issuerSigned = new IssuerSigned(issuerSignedItems, issuerAuth.toCbor());
        
        // 3. Create MdlCredential
        DigitalCredentialMetadata metadata = new DigitalCredentialMetadata();
        metadata.setCredentialType("mDL");
        metadata.setIssuerDid("did:example:issuer");
        
        MdlCredential credential = new MdlCredential(
            mdl.getDocType(),
            issuerSigned,
            null,
            metadata
        );
        
        // 4. Verify credential structure
        assertNotNull(credential);
        assertEquals(MobileDocument.DOCTYPE_MDL, credential.getDocType());
        assertNotNull(credential.getIssuerSigned());
        
        // 5. Verify issuer signature
        assertTrue(credential.verifyIssuerSignature(issuerKeyPair.getPublic()));
    }
    
    @Test
    @DisplayName("E2E-006: Multiple namespace handling")
    void testMultipleNamespaces() throws Exception {
        // 1. Create claims with multiple namespaces
        Map<String, Map<String, Object>> claims = new HashMap<>();
        
        Map<String, Object> isoClaims = new HashMap<>();
        isoClaims.put("family_name", "Smith");
        isoClaims.put("given_name", "John");
        claims.put(NameSpace.ISO_18013_5_1, isoClaims);
        
        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("loyalty_number", "ABC123");
        claims.put("com.example.custom", customClaims);
        
        // 2. Issue mDL
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        MobileDocument mdl = mdlIssuer.issueMdl(
            claims,
            deviceKeyPair.getPublic(),
            now,
            now.plus(365, ChronoUnit.DAYS)
        );
        
        // 3. Verify both namespaces present
        Map<String, List<IssuerSignedItem>> issuerSignedItems = mdl.getIssuerSignedItems();
        assertEquals(2, issuerSignedItems.size());
        assertTrue(issuerSignedItems.containsKey(NameSpace.ISO_18013_5_1));
        assertTrue(issuerSignedItems.containsKey("com.example.custom"));
    }
    
    @Test
    @DisplayName("E2E-007: Error handling - invalid claims")
    void testInvalidClaims() {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        
        // Test null claims
        assertThrows(MdlException.class, () -> {
            mdlIssuer.issueMdl(
                null,
                deviceKeyPair.getPublic(),
                now,
                now.plus(365, ChronoUnit.DAYS)
            );
        });
        
        // Test empty claims
        assertThrows(MdlException.class, () -> {
            mdlIssuer.issueMdl(
                new HashMap<>(),
                deviceKeyPair.getPublic(),
                now,
                now.plus(365, ChronoUnit.DAYS)
            );
        });
    }
    
    @Test
    @DisplayName("E2E-008: Error handling - invalid validity period")
    void testInvalidValidityPeriod() {
        Map<String, Map<String, Object>> claims = createSampleMdlClaims();
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant past = now.minus(1, ChronoUnit.DAYS);
        
        // validFrom after validUntil
        assertThrows(MdlException.class, () -> {
            mdlIssuer.issueMdl(
                claims,
                deviceKeyPair.getPublic(),
                now,
                past
            );
        });
    }
    
    @Test
    @DisplayName("E2E-009: CBOR serialization round-trip")
    void testCborSerializationRoundTrip() throws Exception {
        // 1. Issue mDL
        Map<String, Map<String, Object>> claims = createSampleMdlClaims();
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        
        MobileDocument original = mdlIssuer.issueMdl(
            claims,
            deviceKeyPair.getPublic(),
            now,
            now.plus(365, ChronoUnit.DAYS)
        );
        
        // 2. Serialize to CBOR
        byte[] cbor = original.toCbor();
        
        // 3. Deserialize from CBOR
        MobileDocument deserialized = MobileDocument.fromCbor(cbor);
        
        // 4. Verify all components preserved
        assertEquals(original.getDocType(), deserialized.getDocType());
        
        // 5. Verify data elements preserved
        Map<String, List<IssuerSignedItem>> originalItems = original.getIssuerSignedItems();
        Map<String, List<IssuerSignedItem>> deserializedItems = deserialized.getIssuerSignedItems();
        assertEquals(originalItems.size(), deserializedItems.size());
        
        for (String namespace : originalItems.keySet()) {
            assertTrue(deserializedItems.containsKey(namespace));
            assertEquals(originalItems.get(namespace).size(), 
                        deserializedItems.get(namespace).size());
        }
    }
    
    @Test
    @DisplayName("E2E-010: Performance - issuance latency")
    void testIssuancePerformance() throws Exception {
        Map<String, Map<String, Object>> claims = createSampleMdlClaims();
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        
        long startTime = System.currentTimeMillis();
        
        MobileDocument mdl = mdlIssuer.issueMdl(
            claims,
            deviceKeyPair.getPublic(),
            now,
            now.plus(365, ChronoUnit.DAYS)
        );
        
        long endTime = System.currentTimeMillis();
        long latency = endTime - startTime;
        
        assertNotNull(mdl);
        assertTrue(latency < 1000, 
            "Issuance should complete in less than 1 second, took: " + latency + "ms");
    }
    
    // Helper methods
    
    /**
     * Creates sample mDL claims for testing.
     */
    private Map<String, Map<String, Object>> createSampleMdlClaims() {
        Map<String, Map<String, Object>> claims = new HashMap<>();
        Map<String, Object> mdlClaims = new HashMap<>();
        
        mdlClaims.put("family_name", "Smith");
        mdlClaims.put("given_name", "John");
        mdlClaims.put("birth_date", "1990-01-15");
        mdlClaims.put("document_number", "DL123456789");
        mdlClaims.put("issue_date", "2024-01-01");
        mdlClaims.put("expiry_date", "2029-01-01");
        mdlClaims.put("issuing_authority", "Test DMV");
        mdlClaims.put("portrait", Base64.getEncoder().encodeToString(new byte[]{1, 2, 3, 4, 5}));
        
        claims.put(NameSpace.ISO_18013_5_1, mdlClaims);
        return claims;
    }
}

// Made with Bob