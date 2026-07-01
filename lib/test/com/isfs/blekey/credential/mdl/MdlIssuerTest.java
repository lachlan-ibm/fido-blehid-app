/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.mdl;

import static org.junit.Assert.*;

import com.isfs.blekey.util.CertUtils;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Before;
import org.junit.Test;

/**
 * Unit tests for {@link MdlIssuer}.
 */
public class MdlIssuerTest {
    
    private PrivateKey issuerPrivateKey;
    private PublicKey issuerPublicKey;
    private List<X509Certificate> issuerCertChain;
    private KeyPair deviceKeyPair;
    
    @Before
    public void setUp() throws Exception {
        // Generate issuer key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        KeyPair issuerKeyPair = keyGen.generateKeyPair();
        issuerPrivateKey = issuerKeyPair.getPrivate();
        issuerPublicKey = issuerKeyPair.getPublic();
        
        // Create a self-signed certificate for testing
        X509Certificate cert = CertUtils.generateCaCert(
            "CN=Test Issuer, O=Test Organization, C=US",
            issuerKeyPair,
            365,
            false  // addSki
        );
        issuerCertChain = new ArrayList<>();
        issuerCertChain.add(cert);
        
        // Generate device key pair
        deviceKeyPair = keyGen.generateKeyPair();
    }
    
    @Test
    public void testConstructor_ValidParameters() {
        MdlIssuer issuer = new MdlIssuer(
            issuerPrivateKey,
            issuerCertChain,
            MobileDocument.DOCTYPE_MDL
        );
        
        assertNotNull(issuer);
        assertEquals(MobileDocument.DOCTYPE_MDL, issuer.getDocType());
        assertEquals(MdlIssuer.DEFAULT_DIGEST_ALGORITHM, issuer.getDigestAlgorithm());
    }
    
    @Test
    public void testConstructor_CustomDigestAlgorithm() {
        MdlIssuer issuer = new MdlIssuer(
            issuerPrivateKey,
            issuerCertChain,
            MobileDocument.DOCTYPE_MDL,
            MobileSecurityObject.DIGEST_ALGORITHM_SHA384
        );
        
        assertEquals(MobileSecurityObject.DIGEST_ALGORITHM_SHA384, issuer.getDigestAlgorithm());
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testConstructor_NullPrivateKey() {
        new MdlIssuer(
            null,
            List.of(),
            MobileDocument.DOCTYPE_MDL
        );
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testConstructor_NullCertChain() {
        new MdlIssuer(
            issuerPrivateKey,
            null,
            MobileDocument.DOCTYPE_MDL
        );
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testConstructor_EmptyCertChain() {
        new MdlIssuer(
            issuerPrivateKey,
            new ArrayList<>(),
            MobileDocument.DOCTYPE_MDL
        );
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testConstructor_NullDocType() {
        new MdlIssuer(
            issuerPrivateKey,
            List.of(),
            null
        );
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testConstructor_EmptyDocType() {
        new MdlIssuer(
            issuerPrivateKey,
            List.of(),
            ""
        );
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testConstructor_InvalidDigestAlgorithm() {
        new MdlIssuer(
            issuerPrivateKey,
            List.of(),
            MobileDocument.DOCTYPE_MDL,
            "INVALID-ALGORITHM"
        );
    }
    
    @Test
    public void testIssueMdl_BasicClaims() throws Exception {
        MdlIssuer issuer = new MdlIssuer(
            issuerPrivateKey,
            issuerCertChain,
            MobileDocument.DOCTYPE_MDL
        );
        
        // Prepare claims
        Map<String, Map<String, Object>> claims = new HashMap<>();
        Map<String, Object> mdlClaims = new HashMap<>();
        mdlClaims.put("family_name", "Doe");
        mdlClaims.put("given_name", "John");
        mdlClaims.put("birth_date", "1990-01-01");
        claims.put("org.iso.18013.5.1", mdlClaims);
        
        // Issue mDL
        Instant now = Instant.now();
        Instant validUntil = now.plusSeconds(86400 * 365); // 1 year
        
        MobileDocument mdl = issuer.issueMdl(
            claims,
            deviceKeyPair.getPublic(),
            now,
            validUntil
        );
        
        // Verify result
        assertNotNull(mdl);
        assertEquals(MobileDocument.DOCTYPE_MDL, mdl.getDocType());
        
        // Verify issuer-signed items
        Map<String, List<IssuerSignedItem>> issuerSignedItems = mdl.getIssuerSignedItems();
        assertNotNull(issuerSignedItems);
        assertTrue(issuerSignedItems.containsKey("org.iso.18013.5.1"));
        
        List<IssuerSignedItem> items = issuerSignedItems.get("org.iso.18013.5.1");
        assertEquals(3, items.size());
        
        // Verify all claims are present
        Map<String, Object> foundClaims = new HashMap<>();
        for (IssuerSignedItem item : items) {
            foundClaims.put(item.getElementIdentifier(), item.getElementValue());
        }
        
        assertEquals("Doe", foundClaims.get("family_name"));
        assertEquals("John", foundClaims.get("given_name"));
        assertEquals("1990-01-01", foundClaims.get("birth_date"));
    }
    
    @Test
    public void testIssueMdl_MultipleNamespaces() throws Exception {
        MdlIssuer issuer = new MdlIssuer(
            issuerPrivateKey,
            issuerCertChain,
            MobileDocument.DOCTYPE_MDL
        );
        
        // Prepare claims with multiple namespaces
        Map<String, Map<String, Object>> claims = new HashMap<>();
        
        Map<String, Object> mdlClaims = new HashMap<>();
        mdlClaims.put("family_name", "Doe");
        mdlClaims.put("given_name", "John");
        claims.put("org.iso.18013.5.1", mdlClaims);
        
        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("custom_field", "custom_value");
        claims.put("com.example.custom", customClaims);
        
        // Issue mDL
        Instant now = Instant.now();
        MobileDocument mdl = issuer.issueMdl(
            claims,
            deviceKeyPair.getPublic(),
            now,
            now.plusSeconds(86400)
        );
        
        // Verify both namespaces are present
        Map<String, List<IssuerSignedItem>> issuerSignedItems = mdl.getIssuerSignedItems();
        assertEquals(2, issuerSignedItems.size());
        assertTrue(issuerSignedItems.containsKey("org.iso.18013.5.1"));
        assertTrue(issuerSignedItems.containsKey("com.example.custom"));
    }
    
    @Test
    public void testIssueMdl_DigestIDsAreSequential() throws Exception {
        MdlIssuer issuer = new MdlIssuer(
            issuerPrivateKey,
            issuerCertChain,
            MobileDocument.DOCTYPE_MDL
        );
        
        Map<String, Map<String, Object>> claims = new HashMap<>();
        Map<String, Object> mdlClaims = new HashMap<>();
        mdlClaims.put("field1", "value1");
        mdlClaims.put("field2", "value2");
        mdlClaims.put("field3", "value3");
        claims.put("org.iso.18013.5.1", mdlClaims);
        
        Instant now = Instant.now();
        MobileDocument mdl = issuer.issueMdl(
            claims,
            deviceKeyPair.getPublic(),
            now,
            now.plusSeconds(86400)
        );
        
        List<IssuerSignedItem> items = mdl.getIssuerSignedItems().get("org.iso.18013.5.1");
        
        // Verify digest IDs are sequential starting from 0
        List<Integer> digestIds = new ArrayList<>();
        for (IssuerSignedItem item : items) {
            digestIds.add(item.getDigestId());
        }
        
        assertTrue(digestIds.contains(0));
        assertTrue(digestIds.contains(1));
        assertTrue(digestIds.contains(2));
    }
    
    @Test
    public void testIssueMdl_RandomBytesAreUnique() throws Exception {
        MdlIssuer issuer = new MdlIssuer(
            issuerPrivateKey,
            issuerCertChain,
            MobileDocument.DOCTYPE_MDL
        );
        
        Map<String, Map<String, Object>> claims = new HashMap<>();
        Map<String, Object> mdlClaims = new HashMap<>();
        mdlClaims.put("field1", "value1");
        mdlClaims.put("field2", "value2");
        claims.put("org.iso.18013.5.1", mdlClaims);
        
        Instant now = Instant.now();
        MobileDocument mdl = issuer.issueMdl(
            claims,
            deviceKeyPair.getPublic(),
            now,
            now.plusSeconds(86400)
        );
        
        List<IssuerSignedItem> items = mdl.getIssuerSignedItems().get("org.iso.18013.5.1");
        
        // Verify random bytes are different for each item
        byte[] random1 = items.get(0).getRandom();
        byte[] random2 = items.get(1).getRandom();
        
        assertFalse(java.util.Arrays.equals(random1, random2));
    }
    
    @Test(expected = MdlException.class)
    public void testIssueMdl_NullClaims() throws Exception {
        MdlIssuer issuer = new MdlIssuer(
            issuerPrivateKey,
            issuerCertChain,
            MobileDocument.DOCTYPE_MDL
        );
        
        Instant now = Instant.now();
        issuer.issueMdl(
            null,
            deviceKeyPair.getPublic(),
            now,
            now.plusSeconds(86400)
        );
    }
    
    @Test(expected = MdlException.class)
    public void testIssueMdl_EmptyClaims() throws Exception {
        MdlIssuer issuer = new MdlIssuer(
            issuerPrivateKey,
            issuerCertChain,
            MobileDocument.DOCTYPE_MDL
        );
        
        Instant now = Instant.now();
        issuer.issueMdl(
            new HashMap<>(),
            deviceKeyPair.getPublic(),
            now,
            now.plusSeconds(86400)
        );
    }
    
    @Test(expected = MdlException.class)
    public void testIssueMdl_NullDeviceKey() throws Exception {
        MdlIssuer issuer = new MdlIssuer(
            issuerPrivateKey,
            issuerCertChain,
            MobileDocument.DOCTYPE_MDL
        );
        
        Map<String, Map<String, Object>> claims = new HashMap<>();
        Map<String, Object> mdlClaims = new HashMap<>();
        mdlClaims.put("field", "value");
        claims.put("org.iso.18013.5.1", mdlClaims);
        
        Instant now = Instant.now();
        issuer.issueMdl(
            claims,
            null,
            now,
            now.plusSeconds(86400)
        );
    }
    
    @Test(expected = MdlException.class)
    public void testIssueMdl_InvalidValidityPeriod() throws Exception {
        MdlIssuer issuer = new MdlIssuer(
            issuerPrivateKey,
            issuerCertChain,
            MobileDocument.DOCTYPE_MDL
        );
        
        Map<String, Map<String, Object>> claims = new HashMap<>();
        Map<String, Object> mdlClaims = new HashMap<>();
        mdlClaims.put("field", "value");
        claims.put("org.iso.18013.5.1", mdlClaims);
        
        Instant now = Instant.now();
        Instant past = now.minusSeconds(86400);
        
        // validFrom is after validUntil
        issuer.issueMdl(
            claims,
            deviceKeyPair.getPublic(),
            now,
            past
        );
    }
    
    @Test
    public void testIssueMdl_DifferentDigestAlgorithms() throws Exception {
        String[] algorithms = {
            MobileSecurityObject.DIGEST_ALGORITHM_SHA256,
            MobileSecurityObject.DIGEST_ALGORITHM_SHA384,
            MobileSecurityObject.DIGEST_ALGORITHM_SHA512
        };
        
        for (String algorithm : algorithms) {
            MdlIssuer issuer = new MdlIssuer(
                issuerPrivateKey,
                issuerCertChain,
                MobileDocument.DOCTYPE_MDL,
                algorithm
            );
            
            Map<String, Map<String, Object>> claims = new HashMap<>();
            Map<String, Object> mdlClaims = new HashMap<>();
            mdlClaims.put("field", "value");
            claims.put("org.iso.18013.5.1", mdlClaims);
            
            Instant now = Instant.now();
            MobileDocument mdl = issuer.issueMdl(
                claims,
                deviceKeyPair.getPublic(),
                now,
                now.plusSeconds(86400)
            );
            
            assertNotNull("Failed for algorithm: " + algorithm, mdl);
            assertEquals(algorithm, issuer.getDigestAlgorithm());
        }
    }
    
    @Test
    public void testGetters() {
        MdlIssuer issuer = new MdlIssuer(
            issuerPrivateKey,
            issuerCertChain,
            "custom.doctype",
            MobileSecurityObject.DIGEST_ALGORITHM_SHA384
        );
        
        assertEquals("custom.doctype", issuer.getDocType());
        assertEquals(MobileSecurityObject.DIGEST_ALGORITHM_SHA384, issuer.getDigestAlgorithm());
        assertNotNull(issuer.getIssuerCertificateChain());
        assertEquals(1, issuer.getIssuerCertificateChain().size());
    }
}

// Made with Bob
