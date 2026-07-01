/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.credential.jsonld.proof;

import com.isfs.blekey.credential.jsonld.CredentialSubject;
import com.isfs.blekey.credential.jsonld.JsonLdCredential;
import com.isfs.blekey.credential.jsonld.JsonLdException;
import com.isfs.blekey.credential.jsonld.JsonLdProof;

import org.junit.Before;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;

import static org.junit.Assert.*;

/**
 * Unit tests for JwsProofHandler.
 * Tests JsonWebSignature2020 proof generation and verification.
 */
public class JwsProofHandlerTest {
    
    private JwsProofHandler handler;
    private KeyPair keyPair;
    
    @Before
    public void setUp() throws Exception {
        handler = new JwsProofHandler();
        
        // Generate EC key pair for testing
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        keyPair = keyGen.generateKeyPair();
    }
    
    @Test
    public void testGetProofType() {
        assertEquals("JsonWebSignature2020", handler.getProofType());
    }
    
    @Test
    public void testSupportsProofType() {
        assertTrue(handler.supportsProofType("JsonWebSignature2020"));
        assertFalse(handler.supportsProofType("Ed25519Signature2020"));
    }
    
    @Test
    public void testGenerateProof_ValidCredential() throws Exception {
        JsonLdCredential credential = createValidCredential();
        
        JsonLdProof proof = handler.generateProof(
            credential,
            keyPair.getPrivate(),
            "did:example:issuer#key-1"
        );
        
        assertNotNull(proof);
        assertEquals("JsonWebSignature2020", proof.getType());
        assertEquals("did:example:issuer#key-1", proof.getVerificationMethod());
        assertEquals("assertionMethod", proof.getProofPurpose());
        assertNotNull(proof.getCreated());
        assertNotNull(proof.getJws());
        
        // JWS should be detached (header..signature format)
        String jws = proof.getJws();
        assertTrue("JWS should contain ..", jws.contains(".."));
        String[] parts = jws.split("\\.\\.");
        assertEquals("JWS should have 2 parts", 2, parts.length);
    }
    
    @Test(expected = JsonLdException.class)
    public void testGenerateProof_NullCredential() throws Exception {
        handler.generateProof(
            null,
            keyPair.getPrivate(),
            "did:example:issuer#key-1"
        );
    }
    
    @Test(expected = JsonLdException.class)
    public void testGenerateProof_NullSigningKey() throws Exception {
        JsonLdCredential credential = createValidCredential();
        
        handler.generateProof(
            credential,
            null,
            "did:example:issuer#key-1"
        );
    }
    
    @Test(expected = JsonLdException.class)
    public void testGenerateProof_NullVerificationMethod() throws Exception {
        JsonLdCredential credential = createValidCredential();
        
        handler.generateProof(
            credential,
            keyPair.getPrivate(),
            null
        );
    }
    
    @Test(expected = JsonLdException.class)
    public void testGenerateProof_EmptyVerificationMethod() throws Exception {
        JsonLdCredential credential = createValidCredential();
        
        handler.generateProof(
            credential,
            keyPair.getPrivate(),
            ""
        );
    }
    
    @Test(expected = JsonLdException.class)
    public void testGenerateProof_CredentialWithoutIssuer() throws Exception {
        JsonLdCredential credential = createValidCredential();
        credential.setIssuer(null);
        
        handler.generateProof(
            credential,
            keyPair.getPrivate(),
            "did:example:issuer#key-1"
        );
    }
    
    @Test(expected = JsonLdException.class)
    public void testGenerateProof_CredentialWithoutSubject() throws Exception {
        JsonLdCredential credential = createValidCredential();
        credential.setCredentialSubject(null);
        
        handler.generateProof(
            credential,
            keyPair.getPrivate(),
            "did:example:issuer#key-1"
        );
    }
    
    @Test(expected = JsonLdException.class)
    public void testGenerateProof_CredentialAlreadyHasProof() throws Exception {
        JsonLdCredential credential = createValidCredential();
        credential.setProof(new JsonLdProof("JsonWebSignature2020"));
        
        handler.generateProof(
            credential,
            keyPair.getPrivate(),
            "did:example:issuer#key-1"
        );
    }
    
    @Test
    public void testVerifyProof_ValidProof() throws Exception {
        // Generate credential with proof
        JsonLdCredential credential = createValidCredential();
        
        JsonLdProof proof = handler.generateProof(
            credential,
            keyPair.getPrivate(),
            "did:example:issuer#key-1"
        );
        
        credential.setProof(proof);
        
        // Verify the proof
        boolean isValid = handler.verifyProof(credential, keyPair.getPublic());
        
        assertTrue("Proof should be valid", isValid);
    }
    
    @Test
    public void testVerifyProof_InvalidSignature() throws Exception {
        // Generate credential with proof using one key
        JsonLdCredential credential = createValidCredential();
        
        JsonLdProof proof = handler.generateProof(
            credential,
            keyPair.getPrivate(),
            "did:example:issuer#key-1"
        );
        
        credential.setProof(proof);
        
        // Try to verify with different key
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        KeyPair differentKeyPair = keyGen.generateKeyPair();
        
        boolean isValid = handler.verifyProof(credential, differentKeyPair.getPublic());
        
        assertFalse("Proof should be invalid with wrong key", isValid);
    }
    
    @Test
    public void testVerifyProof_ModifiedCredential() throws Exception {
        // Generate credential with proof
        JsonLdCredential credential = createValidCredential();
        
        JsonLdProof proof = handler.generateProof(
            credential,
            keyPair.getPrivate(),
            "did:example:issuer#key-1"
        );
        
        credential.setProof(proof);
        
        // Modify the credential after signing
        credential.setIssuer("did:example:different-issuer");
        
        // Verification should fail
        boolean isValid = handler.verifyProof(credential, keyPair.getPublic());
        
        assertFalse("Proof should be invalid after credential modification", isValid);
    }
    
    @Test(expected = JsonLdException.class)
    public void testVerifyProof_NullCredential() throws Exception {
        handler.verifyProof(null, keyPair.getPublic());
    }
    
    @Test(expected = JsonLdException.class)
    public void testVerifyProof_NullVerificationKey() throws Exception {
        JsonLdCredential credential = createValidCredential();
        JsonLdProof proof = new JsonLdProof("JsonWebSignature2020")
            .setVerificationMethod("did:example:issuer#key-1")
            .setProofPurpose("assertionMethod")
            .setCreated(Instant.now())
            .setJws("header..signature");
        credential.setProof(proof);
        
        handler.verifyProof(credential, null);
    }
    
    @Test(expected = JsonLdException.class)
    public void testVerifyProof_CredentialWithoutProof() throws Exception {
        JsonLdCredential credential = createValidCredential();
        
        handler.verifyProof(credential, keyPair.getPublic());
    }
    
    @Test(expected = JsonLdException.class)
    public void testVerifyProof_ProofWithoutJws() throws Exception {
        JsonLdCredential credential = createValidCredential();
        JsonLdProof proof = new JsonLdProof("JsonWebSignature2020")
            .setVerificationMethod("did:example:issuer#key-1")
            .setProofPurpose("assertionMethod")
            .setCreated(Instant.now());
        credential.setProof(proof);
        
        handler.verifyProof(credential, keyPair.getPublic());
    }
    
    @Test(expected = JsonLdException.class)
    public void testVerifyProof_WrongProofType() throws Exception {
        JsonLdCredential credential = createValidCredential();
        JsonLdProof proof = new JsonLdProof("Ed25519Signature2020")
            .setVerificationMethod("did:example:issuer#key-1")
            .setProofPurpose("assertionMethod")
            .setCreated(Instant.now())
            .setProofValue("signature");
        credential.setProof(proof);
        
        handler.verifyProof(credential, keyPair.getPublic());
    }
    
    @Test
    public void testRoundTrip_GenerateAndVerify() throws Exception {
        // Create credential
        JsonLdCredential credential = createValidCredential();
        
        // Generate proof
        JsonLdProof proof = handler.generateProof(
            credential,
            keyPair.getPrivate(),
            "did:example:issuer#key-1"
        );
        
        // Add proof to credential
        credential.setProof(proof);
        
        // Verify proof
        boolean isValid = handler.verifyProof(credential, keyPair.getPublic());
        
        assertTrue("Round-trip proof should be valid", isValid);
    }
    
    @Test
    public void testRoundTrip_WithComplexCredential() throws Exception {
        // Create complex credential with multiple types and claims
        CredentialSubject subject = new CredentialSubject("did:example:student123");
        subject.addClaim("degree", "Bachelor of Science");
        subject.addClaim("degreeType", "BachelorDegree");
        subject.addClaim("name", "Alice Smith");
        subject.addClaim("gpa", 3.8);
        
        JsonLdCredential credential = new JsonLdCredential()
            .setId("http://example.edu/credentials/3732")
            .addType("UniversityDegreeCredential")
            .addType("AlumniCredential")
            .setIssuer("did:example:university")
            .setIssuanceDate(Instant.parse("2024-01-01T00:00:00Z"))
            .setExpirationDate(Instant.parse("2029-01-01T00:00:00Z"))
            .setCredentialSubject(subject);
        
        // Generate proof
        JsonLdProof proof = handler.generateProof(
            credential,
            keyPair.getPrivate(),
            "did:example:university#key-1"
        );
        
        credential.setProof(proof);
        
        // Verify proof
        boolean isValid = handler.verifyProof(credential, keyPair.getPublic());
        
        assertTrue("Complex credential proof should be valid", isValid);
    }
    
    @Test
    public void testProofStructure() throws Exception {
        JsonLdCredential credential = createValidCredential();
        
        JsonLdProof proof = handler.generateProof(
            credential,
            keyPair.getPrivate(),
            "did:example:issuer#key-1"
        );
        
        // Validate proof structure
        assertNotNull("Proof type should not be null", proof.getType());
        assertNotNull("Verification method should not be null", proof.getVerificationMethod());
        assertNotNull("Proof purpose should not be null", proof.getProofPurpose());
        assertNotNull("Created timestamp should not be null", proof.getCreated());
        assertNotNull("JWS should not be null", proof.getJws());
        
        assertEquals("JsonWebSignature2020", proof.getType());
        assertEquals("assertionMethod", proof.getProofPurpose());
        
        // Validate JWS format (detached)
        String jws = proof.getJws();
        assertTrue("JWS should be detached", jws.contains(".."));
        assertFalse("JWS should not have three dots", jws.contains("..."));
    }
    
    /**
     * Helper method to create a valid credential for testing.
     */
    private JsonLdCredential createValidCredential() {
        CredentialSubject subject = new CredentialSubject("did:example:student");
        subject.addClaim("degree", "Bachelor of Science");
        subject.addClaim("degreeType", "BachelorDegree");
        
        return new JsonLdCredential()
            .setId("http://example.edu/credentials/3732")
            .addType("UniversityDegreeCredential")
            .setIssuer("did:example:issuer")
            .setIssuanceDate(Instant.now())
            .setCredentialSubject(subject);
    }
}

// Made with Bob