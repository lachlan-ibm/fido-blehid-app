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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;

import static org.junit.Assert.*;

/**
 * Unit tests for ProofHandler abstract class.
 * Tests the base validation and helper methods.
 */
public class ProofHandlerTest {
    
    private TestProofHandler handler;
    private KeyPair keyPair;
    
    /**
     * Test implementation of ProofHandler for testing purposes.
     */
    private static class TestProofHandler extends ProofHandler {
        @Override
        public String getProofType() {
            return "TestProof2020";
        }
        
        @Override
        public JsonLdProof generateProof(
            JsonLdCredential credential,
            PrivateKey signingKey,
            String verificationMethod
        ) throws JsonLdException {
            validateCredentialForProof(credential);
            return new JsonLdProof()
                .setType(getProofType())
                .setVerificationMethod(verificationMethod)
                .setProofPurpose("assertionMethod")
                .setCreated(Instant.now())
                .setProofValue("test-signature");
        }
        
        @Override
        public boolean verifyProof(
            JsonLdCredential credential,
            PublicKey verificationKey
        ) throws JsonLdException {
            validateCredentialForVerification(credential);
            return true;
        }
    }
    
    @Before
    public void setUp() throws Exception {
        handler = new TestProofHandler();
        
        // Generate test key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        keyPair = keyGen.generateKeyPair();
    }
    
    @Test
    public void testGetProofType() {
        assertEquals("TestProof2020", handler.getProofType());
    }
    
    @Test
    public void testSupportsProofType() {
        assertTrue(handler.supportsProofType("TestProof2020"));
        assertFalse(handler.supportsProofType("OtherProof2020"));
        assertFalse(handler.supportsProofType(null));
    }
    
    @Test
    public void testValidateCredentialForProof_Valid() throws Exception {
        JsonLdCredential credential = createValidCredential();
        
        // Should not throw
        handler.validateCredentialForProof(credential);
    }
    
    @Test(expected = JsonLdException.class)
    public void testValidateCredentialForProof_NullCredential() throws Exception {
        handler.validateCredentialForProof(null);
    }
    
    @Test(expected = JsonLdException.class)
    public void testValidateCredentialForProof_NoIssuer() throws Exception {
        JsonLdCredential credential = createValidCredential();
        credential.setIssuer(null);
        
        handler.validateCredentialForProof(credential);
    }
    
    @Test(expected = JsonLdException.class)
    public void testValidateCredentialForProof_EmptyIssuer() throws Exception {
        JsonLdCredential credential = createValidCredential();
        credential.setIssuer("");
        
        handler.validateCredentialForProof(credential);
    }
    
    @Test(expected = JsonLdException.class)
    public void testValidateCredentialForProof_NoSubject() throws Exception {
        JsonLdCredential credential = createValidCredential();
        credential.setCredentialSubject(null);
        
        handler.validateCredentialForProof(credential);
    }
    
    @Test(expected = JsonLdException.class)
    public void testValidateCredentialForProof_AlreadyHasProof() throws Exception {
        JsonLdCredential credential = createValidCredential();
        credential.setProof(new JsonLdProof("TestProof2020"));
        
        handler.validateCredentialForProof(credential);
    }
    
    @Test
    public void testValidateCredentialForVerification_Valid() throws Exception {
        JsonLdCredential credential = createValidCredential();
        credential.setProof(new JsonLdProof("TestProof2020")
            .setVerificationMethod("did:example:issuer#key-1")
            .setProofPurpose("assertionMethod")
            .setProofValue("signature"));
        
        // Should not throw
        handler.validateCredentialForVerification(credential);
    }
    
    @Test(expected = JsonLdException.class)
    public void testValidateCredentialForVerification_NullCredential() throws Exception {
        handler.validateCredentialForVerification(null);
    }
    
    @Test(expected = JsonLdException.class)
    public void testValidateCredentialForVerification_NoProof() throws Exception {
        JsonLdCredential credential = createValidCredential();
        
        handler.validateCredentialForVerification(credential);
    }
    
    @Test(expected = JsonLdException.class)
    public void testValidateCredentialForVerification_UnsupportedProofType() throws Exception {
        JsonLdCredential credential = createValidCredential();
        credential.setProof(new JsonLdProof("UnsupportedProof2020")
            .setVerificationMethod("did:example:issuer#key-1")
            .setProofPurpose("assertionMethod")
            .setProofValue("signature"));
        
        handler.validateCredentialForVerification(credential);
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
        assertEquals("TestProof2020", proof.getType());
        assertEquals("did:example:issuer#key-1", proof.getVerificationMethod());
        assertEquals("assertionMethod", proof.getProofPurpose());
        assertNotNull(proof.getCreated());
        assertEquals("test-signature", proof.getProofValue());
    }
    
    @Test(expected = JsonLdException.class)
    public void testGenerateProof_InvalidCredential() throws Exception {
        JsonLdCredential credential = createValidCredential();
        credential.setIssuer(null);
        
        handler.generateProof(
            credential,
            keyPair.getPrivate(),
            "did:example:issuer#key-1"
        );
    }
    
    @Test
    public void testVerifyProof_ValidCredential() throws Exception {
        JsonLdCredential credential = createValidCredential();
        credential.setProof(new JsonLdProof("TestProof2020")
            .setVerificationMethod("did:example:issuer#key-1")
            .setProofPurpose("assertionMethod")
            .setProofValue("signature"));
        
        boolean result = handler.verifyProof(credential, keyPair.getPublic());
        
        assertTrue(result);
    }
    
    @Test(expected = JsonLdException.class)
    public void testVerifyProof_InvalidCredential() throws Exception {
        JsonLdCredential credential = createValidCredential();
        
        handler.verifyProof(credential, keyPair.getPublic());
    }
    
    /**
     * Helper method to create a valid credential for testing.
     */
    private JsonLdCredential createValidCredential() {
        CredentialSubject subject = new CredentialSubject("did:example:student");
        subject.addClaim("degree", "Bachelor of Science");
        
        return new JsonLdCredential()
            .setId("http://example.edu/credentials/3732")
            .addType("UniversityDegreeCredential")
            .setIssuer("did:example:issuer")
            .setIssuanceDate(Instant.now())
            .setCredentialSubject(subject);
    }
}

// Made with Bob