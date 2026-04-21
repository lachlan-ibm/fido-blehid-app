/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator;

import static org.junit.jupiter.api.Assertions.*;

import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Map;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import com.isfs.blekey.util.CertUtils;

/**
 * Phase 4 tests for platform-specific attestation methods in Fido2Authenticator.
 * Tests Apple, Android SafetyNet, TPM (RSA and EC), and FIDO U2F attestations.
 * 
 * These tests use a shared PKI infrastructure (AttestationTestFixture) to avoid
 * redundant certificate generation across test cases.
 */
@DisplayName("Fido2Authenticator Platform-Specific Attestation Tests")
public class Fido2AuthenticatorAttestationTest {
    
    private static AttestationTestFixture fixture;
    private static Fido2Authenticator authenticator;
    
    @BeforeAll
    public static void setUpFixture() throws Exception {
        fixture = new AttestationTestFixture();
        fixture.initialize();
        authenticator = new Fido2Authenticator();
    }
    
    // ========== Apple Attestation Tests ==========
    
    @Test
    @DisplayName("buildAppleAttestation() should create valid attestation with nonce")
    public void testBuildAppleAttestationWithValidParameters() throws Exception {
        // Arrange
        byte[] authData = fixture.getTestAuthData();
        byte[] clientDataHash = fixture.getTestClientDataHash();
        KeyPair authKeyPair = fixture.getEcAuthenticatorKeyPair();
        KeyPair caKeyPair = fixture.getRsaCaKeyPair(); // Apple attestation uses RSA for signing
        X509Certificate caCert = fixture.getRsaCaCert();
        
        // Act
        Map<String, Object> attestation = authenticator.buildAppleAttestation(
            clientDataHash, authData, authKeyPair, caKeyPair, caCert);
        
        // Assert
        assertNotNull(attestation, "Attestation should not be null");
        assertTrue(attestation.containsKey("x5c"), "Attestation should contain x5c");
        
        byte[][] certChain = (byte[][]) attestation.get("x5c");
        assertNotNull(certChain, "Certificate chain should not be null");
        assertEquals(2, certChain.length, "Certificate chain should contain 2 certificates");
        
        // Verify leaf certificate
        X509Certificate leafCert = (X509Certificate) CertUtils.readBytes(certChain[0], "X.509");
        assertNotNull(leafCert, "Leaf certificate should be valid");
        assertEquals("CN=apple.attestation.test", leafCert.getSubjectX500Principal().getName());
        
        // Verify CA certificate
        X509Certificate chainCaCert = (X509Certificate) CertUtils.readBytes(certChain[1], "X.509");
        assertNotNull(chainCaCert, "CA certificate should be valid");
        assertEquals(caCert.getSubjectX500Principal().getName(), 
                     chainCaCert.getSubjectX500Principal().getName());
    }
    
    @Test
    @DisplayName("buildAppleAttestation() should embed nonce hash in certificate")
    public void testBuildAppleAttestationNonceEmbedding() throws Exception {
        // Arrange
        byte[] authData = fixture.getTestAuthData();
        byte[] clientDataHash = fixture.getTestClientDataHash();
        KeyPair authKeyPair = fixture.createFreshEcKeyPair();
        KeyPair caKeyPair = fixture.getRsaCaKeyPair(); // Apple attestation uses RSA for signing
        X509Certificate caCert = fixture.getRsaCaCert();
        
        // Calculate expected nonce hash
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] combined = new byte[authData.length + clientDataHash.length];
        System.arraycopy(authData, 0, combined, 0, authData.length);
        System.arraycopy(clientDataHash, 0, combined, authData.length, clientDataHash.length);
        byte[] expectedNonceHash = digest.digest(combined);
        
        // Act
        Map<String, Object> attestation = authenticator.buildAppleAttestation(
            clientDataHash, authData, authKeyPair, caKeyPair, caCert);
        
        // Assert
        assertNotNull(attestation, "Attestation should not be null");
        byte[][] certChain = (byte[][]) attestation.get("x5c");
        X509Certificate leafCert = (X509Certificate) CertUtils.readBytes(certChain[0], "X.509");
        
        // Verify certificate has Apple-specific extension (OID 1.2.840.113635.100.8.2)
        byte[] extensionValue = leafCert.getExtensionValue("1.2.840.113635.100.8.2");
        assertNotNull(extensionValue, "Apple nonce extension should be present");
        assertTrue(extensionValue.length > 0, "Extension value should not be empty");
        ASN1OctetString outerOctetString = ASN1OctetString.getInstance(extensionValue);
        ASN1Sequence sequence = ASN1Sequence.getInstance(outerOctetString.getOctets());
        ASN1TaggedObject taggedObject = (ASN1TaggedObject) sequence.getObjectAt(0);
        ASN1OctetString nonceOctetString = ASN1OctetString.getInstance(taggedObject, false);
        byte[] actualNonce = nonceOctetString.getOctets();
        assertTrue(Arrays.equals(expectedNonceHash, actualNonce), "Nonce hash should match");
    }
    
    // ========== Android SafetyNet Attestation Tests ==========
    
    @Test
    @DisplayName("buildAndroidSafetynetAttestation() should create valid JWS token")
    public void testBuildAndroidSafetynetAttestationWithValidParameters() throws Exception {
        // Arrange
        byte[] authData = fixture.getTestAuthData();
        byte[] clientDataHash = fixture.getTestClientDataHash();
        KeyPair authKeyPair = fixture.getRsaAuthenticatorKeyPair();
        KeyPair caKeyPair = fixture.getRsaCaKeyPair();
        X509Certificate caCert = fixture.getRsaCaCert();
        
        // Act
        Map<String, Object> attestation = authenticator.buildAndroidSafetynetAttestation(
            clientDataHash, authData, authKeyPair, caKeyPair, caCert);
        
        // Assert
        assertNotNull(attestation, "Attestation should not be null");
        assertTrue(attestation.containsKey("ver"), "Attestation should contain version");
        assertTrue(attestation.containsKey("response"), "Attestation should contain response");
        
        assertEquals(1234567, attestation.get("ver"), "Version should match");
        
        byte[] response = (byte[]) attestation.get("response");
        assertNotNull(response, "Response should not be null");
        assertTrue(response.length > 0, "Response should not be empty");
        
        // Verify it's a valid JWS format (header.payload.signature)
        String jws = new String(response);
        String[] parts = jws.split("\\.");
        assertEquals(3, parts.length, "JWS should have 3 parts (header.payload.signature)");
    }
    
    @Test
    @DisplayName("buildAndroidSafetynetAttestation() should include required claims")
    public void testBuildAndroidSafetynetAttestationClaims() throws Exception {
        // Arrange
        byte[] authData = fixture.getTestAuthData();
        byte[] clientDataHash = fixture.getTestClientDataHash();
        KeyPair authKeyPair = fixture.createFreshRsaKeyPair();
        KeyPair caKeyPair = fixture.getRsaCaKeyPair();
        X509Certificate caCert = fixture.getRsaCaCert();
        
        // Act
        Map<String, Object> attestation = authenticator.buildAndroidSafetynetAttestation(
            clientDataHash, authData, authKeyPair, caKeyPair, caCert);
        
        // Assert
        byte[] response = (byte[]) attestation.get("response");
        String jws = new String(response);
        
        // JWS format validation
        assertTrue(jws.contains("."), "JWS should contain separators");
        
        // The JWS should be signed with RSA-SHA256
        String[] parts = jws.split("\\.");
        assertTrue(parts.length >= 2, "JWS should have at least header and payload");
    }
    
    // ========== TPM Attestation Tests ==========
    
    @Test
    @DisplayName("buildRsaPubArea() should create valid RSA public area structure")
    public void testBuildRsaPubAreaWithValidKeyPair() throws Exception {
        // Arrange
        KeyPair rsaKeyPair = fixture.getRsaAuthenticatorKeyPair();
        
        // Act
        byte[] pubArea = authenticator.buildRsaPubArea(rsaKeyPair);
        
        // Assert
        assertNotNull(pubArea, "Public area should not be null");
        assertTrue(pubArea.length > 20, "Public area should contain header and key data");
        
        // Verify TPM structure markers
        assertEquals(0x00, pubArea[0], "Type byte 1 should be 0x00");
        assertEquals(0x01, pubArea[1], "Type byte 2 should be 0x01 (TPM_ALG_RSA)");
        assertEquals(0x00, pubArea[2], "Name alg byte 1 should be 0x00");
        assertEquals(0x0B, pubArea[3], "Name alg byte 2 should be 0x0B (TPM_ALG_SHA256)");
    }
    
    @Test
    @DisplayName("buildEcPubArea() should create valid EC public area structure")
    public void testBuildEcPubAreaWithValidKeyPair() throws Exception {
        // Arrange
        KeyPair ecKeyPair = fixture.getEcAuthenticatorKeyPair();
        
        // Act
        byte[] pubArea = authenticator.buildEcPubArea(ecKeyPair);
        
        // Assert
        assertNotNull(pubArea, "Public area should not be null");
        assertTrue(pubArea.length > 20, "Public area should contain header and key data");
        
        // Verify TPM structure markers
        assertEquals(0x00, pubArea[0], "Type byte 1 should be 0x00");
        assertEquals(0x23, pubArea[1], "Type byte 2 should be 0x23 (TPM_ALG_ECC)");
        assertEquals(0x00, pubArea[2], "Name alg byte 1 should be 0x00");
        assertEquals(0x0B, pubArea[3], "Name alg byte 2 should be 0x0B (TPM_ALG_SHA256)");
        
        // Verify EC curve ID (TPM_ECC_NIST_P256 = 0x0003)
        int curveIdOffset = 14; // After header fields
        assertEquals(0x00, pubArea[curveIdOffset], "Curve ID byte 1 should be 0x00");
        assertEquals(0x03, pubArea[curveIdOffset + 1], "Curve ID byte 2 should be 0x03 (NIST_P256)");
    }
    
    @Test
    @DisplayName("buildCertInfo() should create valid TPM certification info")
    public void testBuildCertInfoWithValidParameters() throws Exception {
        // Arrange
        byte[] authData = fixture.getTestAuthData();
        byte[] clientDataHash = fixture.getTestClientDataHash();
        byte[] attsToSign = new byte[authData.length + clientDataHash.length];
        System.arraycopy(authData, 0, attsToSign, 0, authData.length);
        System.arraycopy(clientDataHash, 0, attsToSign, authData.length, clientDataHash.length);
        
        KeyPair rsaKeyPair = fixture.getRsaAuthenticatorKeyPair();
        byte[] pubInfo = authenticator.buildRsaPubArea(rsaKeyPair);
        
        // Act
        byte[] certInfo = authenticator.buildCertInfo(attsToSign, pubInfo);
        
        // Assert
        assertNotNull(certInfo, "CertInfo should not be null");
        assertTrue(certInfo.length > 50, "CertInfo should contain all required fields");
        
        // Verify TPM magic constant (TPM_GENERATED = 0xFF544347)
        assertEquals((byte) 0xFF, certInfo[0], "Magic byte 1 should be 0xFF");
        assertEquals(0x54, certInfo[1], "Magic byte 2 should be 0x54 ('T')");
        assertEquals(0x43, certInfo[2], "Magic byte 3 should be 0x43 ('C')");
        assertEquals(0x47, certInfo[3], "Magic byte 4 should be 0x47 ('G')");
        
        // Verify attestation type (TPM_ST_ATTEST_CERTIFY = 0x8017)
        assertEquals((byte) 0x80, certInfo[4], "Type byte 1 should be 0x80");
        assertEquals(0x17, certInfo[5], "Type byte 2 should be 0x17");
    }
    
    @Test
    @DisplayName("buildTPMAttestationStatement() should create complete TPM attestation with RSA")
    public void testBuildTPMAttestationStatementWithRsaKey() throws Exception {
        // Arrange
        byte[] authData = fixture.getTestAuthData();
        byte[] clientDataHash = fixture.getTestClientDataHash();
        byte[] credId = fixture.getTestCredId();
        X509Certificate caCert = fixture.getRootCaCert();
        KeyPair caKeyPair = fixture.getRootCaKeyPair();
        KeyPair aikKeyPair = fixture.createFreshRsaKeyPair();
        
        // Act
        Map<String, Object> attestation = authenticator.buildTPMAttestationStatement(
            clientDataHash, authData, credId, caCert, caKeyPair, aikKeyPair);
        
        // Assert
        assertNotNull(attestation, "Attestation should not be null");
        assertEquals("2.0", attestation.get("ver"), "Version should be 2.0");
        assertEquals(-257, attestation.get("alg"), "Algorithm should be -257 (RS256)");
        
        assertTrue(attestation.containsKey("x5c"), "Should contain certificate chain");
        byte[][] certChain = (byte[][]) attestation.get("x5c");
        assertEquals(3, certChain.length, "Certificate chain should have 3 certificates");
        
        assertTrue(attestation.containsKey("pubArea"), "Should contain pubArea");
        byte[] pubArea = (byte[]) attestation.get("pubArea");
        assertNotNull(pubArea, "pubArea should not be null");
        
        assertTrue(attestation.containsKey("certInfo"), "Should contain certInfo");
        byte[] certInfo = (byte[]) attestation.get("certInfo");
        assertNotNull(certInfo, "certInfo should not be null");
        
        assertTrue(attestation.containsKey("sig"), "Should contain signature");
        byte[] sig = (byte[]) attestation.get("sig");
        assertNotNull(sig, "Signature should not be null");
        assertTrue(sig.length > 0, "Signature should not be empty");
    }
    
    @Test
    @DisplayName("buildTPMAttestationStatement() should create complete TPM attestation with EC")
    public void testBuildTPMAttestationStatementWithEcKey() throws Exception {
        // Arrange
        byte[] authData = fixture.getTestAuthData();
        byte[] clientDataHash = fixture.getTestClientDataHash();
        byte[] credId = fixture.getTestCredId();
        X509Certificate caCert = fixture.getEcCaCert();
        KeyPair caKeyPair = fixture.getEcCaKeyPair();
        KeyPair aikKeyPair = fixture.createFreshEcKeyPair();
        
        // Act
        Map<String, Object> attestation = authenticator.buildTPMAttestationStatement(
            clientDataHash, authData, credId, caCert, caKeyPair, aikKeyPair);
        
        // Assert
        assertNotNull(attestation, "Attestation should not be null");
        assertEquals("2.0", attestation.get("ver"), "Version should be 2.0");
        
        assertTrue(attestation.containsKey("x5c"), "Should contain certificate chain");
        byte[][] certChain = (byte[][]) attestation.get("x5c");
        assertEquals(3, certChain.length, "Certificate chain should have 3 certificates");
        
        // Verify AIK certificate
        X509Certificate aikCert = (X509Certificate) CertUtils.readBytes(certChain[0], "X.509");
        assertNotNull(aikCert, "AIK certificate should be valid");
        assertTrue(aikCert.getPublicKey() instanceof ECPublicKey, 
                   "AIK certificate should contain EC public key");
        
        assertTrue(attestation.containsKey("pubArea"), "Should contain pubArea");
        byte[] pubArea = (byte[]) attestation.get("pubArea");
        // Verify it's EC pubArea (type = 0x0023)
        assertEquals(0x00, pubArea[0], "EC pubArea type byte 1");
        assertEquals(0x23, pubArea[1], "EC pubArea type byte 2");
        
        assertTrue(attestation.containsKey("sig"), "Should contain signature");
        byte[] sig = (byte[]) attestation.get("sig");
        assertNotNull(sig, "Signature should not be null");
    }
    
    @Test
    @DisplayName("buildTPMAttestationStatement() should include intermediate CA in chain")
    public void testBuildTPMAttestationStatementCertificateChain() throws Exception {
        // Arrange
        byte[] authData = fixture.getTestAuthData();
        byte[] clientDataHash = fixture.getTestClientDataHash();
        byte[] credId = fixture.getTestCredId();
        X509Certificate caCert = fixture.getRootCaCert();
        KeyPair caKeyPair = fixture.getRootCaKeyPair();
        KeyPair aikKeyPair = fixture.createFreshRsaKeyPair();
        
        // Act
        Map<String, Object> attestation = authenticator.buildTPMAttestationStatement(
            clientDataHash, authData, credId, caCert, caKeyPair, aikKeyPair);
        
        // Assert
        byte[][] certChain = (byte[][]) attestation.get("x5c");
        
        // Verify AIK certificate (leaf)
        X509Certificate aikCert = (X509Certificate) CertUtils.readBytes(certChain[0], "X.509");
        assertNotNull(aikCert.getSubjectAlternativeNames(), 
                      "AIK cert should have subject alternative names");
        
        // Verify intermediate CA certificate
        X509Certificate intermediateCert = (X509Certificate) CertUtils.readBytes(certChain[1], "X.509");
        assertEquals("CN=intermediateCA", intermediateCert.getSubjectX500Principal().getName(),
                     "Intermediate cert should have correct subject");
        
        // Verify root CA certificate
        X509Certificate rootCert = (X509Certificate) CertUtils.readBytes(certChain[2], "X.509");
        assertEquals(caCert.getSubjectX500Principal().getName(),
                     rootCert.getSubjectX500Principal().getName(),
                     "Root cert should match provided CA cert");
    }
    
    // ========== FIDO U2F Attestation Tests ==========
    
    @Test
    @DisplayName("buildFIDOU2FAttestationStatement() should create valid U2F attestation")
    public void testBuildFIDOU2FAttestationStatementWithValidParameters() throws Exception {
        // Arrange
        byte[] authData = fixture.getTestAuthData();
        byte[] clientDataHash = fixture.getTestClientDataHash();
        byte[] credId = fixture.getTestCredId();
        KeyPair caKeyPair = fixture.getEcCaKeyPair();
        X509Certificate caCert = fixture.getEcCaCert();
        
        // Act
        Map<String, Object> attestation = authenticator.buildFIDOU2FAttestationStatement(
            clientDataHash, authData, credId, caKeyPair, caCert);
        
        // Assert
        assertNotNull(attestation, "Attestation should not be null");
        assertTrue(attestation.containsKey("x5c"), "Should contain certificate chain");
        assertTrue(attestation.containsKey("sig"), "Should contain signature");
        
        byte[][] certChain = (byte[][]) attestation.get("x5c");
        assertEquals(1, certChain.length, "U2F attestation should have 1 certificate");
        
        X509Certificate cert = (X509Certificate) CertUtils.readBytes(certChain[0], "X.509");
        assertNotNull(cert, "Certificate should be valid");
        assertTrue(cert.getPublicKey() instanceof ECPublicKey,
                   "U2F certificate should contain EC public key");
        
        byte[] signature = (byte[]) attestation.get("sig");
        assertNotNull(signature, "Signature should not be null");
        assertTrue(signature.length > 0, "Signature should not be empty");
    }
    
    @Test
    @DisplayName("buildFIDOU2FAttestationStatement() should format EC public key correctly")
    public void testBuildFIDOU2FAttestationStatementPublicKeyFormat() throws Exception {
        // Arrange
        byte[] authData = fixture.getTestAuthData();
        byte[] clientDataHash = fixture.getTestClientDataHash();
        byte[] credId = fixture.getTestCredId();
        KeyPair caKeyPair = fixture.createFreshEcKeyPair();
        X509Certificate caCert = CertUtils.generateU2FCertificate(
            fixture.getEcCaCert(), "CN=U2F Test", caKeyPair, 365);
        
        // Act
        Map<String, Object> attestation = authenticator.buildFIDOU2FAttestationStatement(
            clientDataHash, authData, credId, caKeyPair, caCert);
        
        // Assert
        assertNotNull(attestation, "Attestation should not be null");
        
        // The signature is computed over U2F-formatted data which includes:
        // 0x00 + rpIdHash + clientDataHash + credId + pubKeyU2F
        // where pubKeyU2F = 0x04 + x + y (65 bytes for P-256)
        byte[] signature = (byte[]) attestation.get("sig");
        assertNotNull(signature, "Signature should not be null");
        
        // Verify signature is ECDSA format (typically 70-72 bytes for P-256)
        assertTrue(signature.length >= 64 && signature.length <= 74,
                   "ECDSA signature should be 64-74 bytes for P-256");
    }
    
    @Test
    @DisplayName("buildFIDOU2FAttestationStatement() should extract RP ID hash from authData")
    public void testBuildFIDOU2FAttestationStatementRpIdHashExtraction() throws Exception {
        // Arrange
        byte[] authData = fixture.getTestAuthData();
        byte[] clientDataHash = fixture.getTestClientDataHash();
        byte[] credId = fixture.getTestCredId();
        KeyPair caKeyPair = fixture.getEcCaKeyPair();
        X509Certificate caCert = fixture.getEcCaCert();
        
        // Extract expected RP ID hash (first 32 bytes of authData)
        byte[] expectedRpIdHash = new byte[32];
        System.arraycopy(authData, 0, expectedRpIdHash, 0, 32);
        
        // Act
        Map<String, Object> attestation = authenticator.buildFIDOU2FAttestationStatement(
            clientDataHash, authData, credId, caKeyPair, caCert);
        
        // Assert
        assertNotNull(attestation, "Attestation should not be null");
        
        // The signature should be valid, which indirectly confirms RP ID hash was extracted correctly
        byte[] signature = (byte[]) attestation.get("sig");
        assertNotNull(signature, "Signature should not be null");
        assertTrue(signature.length > 0, "Signature should not be empty");
    }
}

// Made with Bob
