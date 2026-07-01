/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.credential.jsonld.proof;

import com.isfs.blekey.credential.jsonld.CredentialSubject;
import com.isfs.blekey.credential.jsonld.JsonLdContext;
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
 * Unit tests for ProofVerifier.
 * Tests proof verification registry and delegation.
 */
public class ProofVerifierTest {
    
    private ProofVerifier verifier;
    private JwsProofHandler jwsHandler;
    private KeyPair keyPair;
    
    @Before
    public void setUp() throws Exception {
        verifier = new ProofVerifier();
        jwsHandler = new JwsProofHandler();
        
        // Generate EC key pair for testing
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        keyPair = keyGen.generateKeyPair();
    }
    
    @Test
    public void testConstructor_NoHandlers() {
        ProofVerifier v = new ProofVerifier();
        assertEquals(0, v.getHandlerCount());
    }
    
    @Test
    public void testConstructor_WithDefaults() {
        ProofVerifier v = new ProofVerifier(true);
        assertTrue(v.getHandlerCount() > 0);
        assertTrue(v.hasHandler("JsonWebSignature2020"));
    }
    
    @Test
    public void testRegisterDefaultHandlers() {
        verifier.registerDefaultHandlers();
        
        assertTrue(verifier.hasHandler("JsonWebSignature2020"));
        assertEquals(1, verifier.getHandlerCount());
    }
    
    @Test
    public void testRegisterHandler() {
        verifier.registerHandler(jwsHandler);
        
        assertTrue(verifier.hasHandler("JsonWebSignature2020"));
        assertEquals(1, verifier.getHandlerCount());
        assertNotNull(verifier.getHandler("JsonWebSignature2020"));
    }
    
    @Test
    public void testRegisterHandler_Null() {
        verifier.registerHandler(null);
        
        assertEquals(0, verifier.getHandlerCount());
    }
    
    @Test
    public void testRegisterHandler_Multiple() {
        verifier.registerHandler(jwsHandler);
        
        // Create a test handler for another proof type
        ProofHandler testHandler = new ProofHandler() {
            @Override
            public String getProofType() {
                return "TestProof2020";
            }
            
            @Override
            public JsonLdProof generateProof(JsonLdCredential credential, 
                                            java.security.PrivateKey signingKey,
                                            String verificationMethod) {
                return null;
            }
            
            @Override
            public boolean verifyProof(JsonLdCredential credential,
                                      java.security.PublicKey verificationKey) {
                return true;
            }
        };
        
        verifier.registerHandler(testHandler);
        
        assertEquals(2, verifier.getHandlerCount());
        assertTrue(verifier.hasHandler("JsonWebSignature2020"));
        assertTrue(verifier.hasHandler("TestProof2020"));
    }
    
    @Test
    public void testUnregisterHandler() {
        verifier.registerHandler(jwsHandler);
        assertTrue(verifier.hasHandler("JsonWebSignature2020"));
        
        verifier.unregisterHandler("JsonWebSignature2020");
        
        assertFalse(verifier.hasHandler("JsonWebSignature2020"));
        assertEquals(0, verifier.getHandlerCount());
    }
    
    @Test
    public void testGetHandler() {
        verifier.registerHandler(jwsHandler);
        
        ProofHandler handler = verifier.getHandler("JsonWebSignature2020");
        
        assertNotNull(handler);
        assertEquals("JsonWebSignature2020", handler.getProofType());
    }
    
    @Test
    public void testGetHandler_NotRegistered() {
        ProofHandler handler = verifier.getHandler("UnknownProof2020");
        
        assertNull(handler);
    }
    
    @Test
    public void testHasHandler() {
        assertFalse(verifier.hasHandler("JsonWebSignature2020"));
        
        verifier.registerHandler(jwsHandler);
        
        assertTrue(verifier.hasHandler("JsonWebSignature2020"));
        assertFalse(verifier.hasHandler("Ed25519Signature2020"));
    }
    
    @Test
    public void testGetRegisteredProofTypes() {
        verifier.registerHandler(jwsHandler);
        
        String[] types = verifier.getRegisteredProofTypes();
        
        assertEquals(1, types.length);
        assertEquals("JsonWebSignature2020", types[0]);
    }
    
    @Test
    public void testGetHandlerCount() {
        assertEquals(0, verifier.getHandlerCount());
        
        verifier.registerHandler(jwsHandler);
        assertEquals(1, verifier.getHandlerCount());
        
        verifier.unregisterHandler("JsonWebSignature2020");
        assertEquals(0, verifier.getHandlerCount());
    }
    
    @Test
    public void testVerify_ValidProof() throws Exception {
        verifier.registerHandler(jwsHandler);
        
        // Create and sign credential
        JsonLdCredential credential = createValidCredential();
        JsonLdProof proof = jwsHandler.generateProof(
            credential,
            keyPair.getPrivate(),
            "did:example:issuer#key-1"
        );
        credential.setProof(proof);
        
        // Verify
        boolean isValid = verifier.verify(credential, keyPair.getPublic());
        
        assertTrue("Proof should be valid", isValid);
    }
    
    @Test
    public void testVerify_InvalidProof() throws Exception {
        verifier.registerHandler(jwsHandler);
        
        // Create and sign credential
        JsonLdCredential credential = createValidCredential();
        JsonLdProof proof = jwsHandler.generateProof(
            credential,
            keyPair.getPrivate(),
            "did:example:issuer#key-1"
        );
        credential.setProof(proof);
        
        // Verify with wrong key
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        KeyPair wrongKeyPair = keyGen.generateKeyPair();
        
        boolean isValid = verifier.verify(credential, wrongKeyPair.getPublic());
        
        assertFalse("Proof should be invalid with wrong key", isValid);
    }
    
    @Test(expected = JsonLdException.class)
    public void testVerify_NullCredential() throws Exception {
        verifier.registerHandler(jwsHandler);
        verifier.verify(null, keyPair.getPublic());
    }
    
    @Test(expected = JsonLdException.class)
    public void testVerify_NullVerificationKey() throws Exception {
        verifier.registerHandler(jwsHandler);
        JsonLdCredential credential = createValidCredential();
        verifier.verify(credential, null);
    }
    
    @Test(expected = JsonLdException.class)
    public void testVerify_CredentialWithoutProof() throws Exception {
        verifier.registerHandler(jwsHandler);
        JsonLdCredential credential = createValidCredential();
        
        verifier.verify(credential, keyPair.getPublic());
    }
    
    @Test(expected = JsonLdException.class)
    public void testVerify_ProofWithoutType() throws Exception {
        verifier.registerHandler(jwsHandler);
        
        JsonLdCredential credential = createValidCredential();
        JsonLdProof proof = new JsonLdProof()
            .setVerificationMethod("did:example:issuer#key-1")
            .setProofPurpose("assertionMethod")
            .setJws("header..signature");
        credential.setProof(proof);
        
        verifier.verify(credential, keyPair.getPublic());
    }
    
    @Test(expected = JsonLdException.class)
    public void testVerify_NoHandlerForProofType() throws Exception {
        JsonLdCredential credential = createValidCredential();
        JsonLdProof proof = new JsonLdProof("JsonWebSignature2020")
            .setVerificationMethod("did:example:issuer#key-1")
            .setProofPurpose("assertionMethod")
            .setJws("header..signature");
        credential.setProof(proof);
        
        // Don't register any handler
        verifier.verify(credential, keyPair.getPublic());
    }
    
    @Test
    public void testVerifyQuietly_ValidProof() throws Exception {
        verifier.registerHandler(jwsHandler);
        
        // Create and sign credential
        JsonLdCredential credential = createValidCredential();
        JsonLdProof proof = jwsHandler.generateProof(
            credential,
            keyPair.getPrivate(),
            "did:example:issuer#key-1"
        );
        credential.setProof(proof);
        
        // Verify quietly
        boolean isValid = verifier.verifyQuietly(credential, keyPair.getPublic());
        
        assertTrue("Proof should be valid", isValid);
    }
    
    @Test
    public void testVerifyQuietly_InvalidProof() throws Exception {
        verifier.registerHandler(jwsHandler);
        
        JsonLdCredential credential = createValidCredential();
        
        // Verify quietly without proof (should return false, not throw)
        boolean isValid = verifier.verifyQuietly(credential, keyPair.getPublic());
        
        assertFalse("Should return false for invalid credential", isValid);
    }
    
    @Test
    public void testVerifyQuietly_NullCredential() {
        verifier.registerHandler(jwsHandler);
        
        // Should return false, not throw
        boolean isValid = verifier.verifyQuietly(null, keyPair.getPublic());
        
        assertFalse("Should return false for null credential", isValid);
    }
    
    @Test
    public void testValidateForVerification_Valid() throws Exception {
        verifier.registerHandler(jwsHandler);
        
        JsonLdCredential credential = createValidCredential();
        JsonLdProof proof = jwsHandler.generateProof(
            credential,
            keyPair.getPrivate(),
            "did:example:issuer#key-1"
        );
        credential.setProof(proof);
        
        // Should not throw
        verifier.validateForVerification(credential);
    }
    
    @Test(expected = JsonLdException.class)
    public void testValidateForVerification_NullCredential() throws Exception {
        verifier.validateForVerification(null);
    }
    
    @Test(expected = JsonLdException.class)
    public void testValidateForVerification_CredentialWithoutProof() throws Exception {
        verifier.registerHandler(jwsHandler);
        JsonLdCredential credential = createValidCredential();
        
        verifier.validateForVerification(credential);
    }
    
    @Test(expected = JsonLdException.class)
    public void testValidateForVerification_NoHandlerRegistered() throws Exception {
        JsonLdCredential credential = createValidCredential();
        JsonLdProof proof = new JsonLdProof("JsonWebSignature2020")
            .setVerificationMethod("did:example:issuer#key-1")
            .setProofPurpose("assertionMethod")
            .setJws("header..signature");
        credential.setProof(proof);
        
        verifier.validateForVerification(credential);
    }
    
    @Test
    public void testMethodChaining() {
        ProofVerifier v = new ProofVerifier()
            .registerHandler(jwsHandler)
            .registerHandler(jwsHandler); // Register again (should be idempotent)
        
        assertEquals(1, v.getHandlerCount());
        
        v.unregisterHandler("JsonWebSignature2020");
        assertEquals(0, v.getHandlerCount());
    }
    
    @Test
    public void testEndToEnd_CreateSignVerify() throws Exception {
        // Setup verifier with handler
        verifier.registerHandler(jwsHandler);
        
        // Create credential
        JsonLdCredential credential = createValidCredential();
        
        // Generate proof
        JsonLdProof proof = jwsHandler.generateProof(
            credential,
            keyPair.getPrivate(),
            "did:example:issuer#key-1"
        );
        
        // Add proof to credential
        credential.setProof(proof);
        
        // Validate structure
        verifier.validateForVerification(credential);
        
        // Verify proof
        boolean isValid = verifier.verify(credential, keyPair.getPublic());
        
        assertTrue("End-to-end verification should succeed", isValid);
    }
    
    @Test
    public void testEndToEnd_MultipleCredentials() throws Exception {
        verifier.registerHandler(jwsHandler);
        
        // Create and verify multiple credentials
        for (int i = 0; i < 5; i++) {
            JsonLdCredential credential = createValidCredential();
            credential.setId("http://example.edu/credentials/" + i);
            
            JsonLdProof proof = jwsHandler.generateProof(
                credential,
                keyPair.getPrivate(),
                "did:example:issuer#key-" + i
            );
            
            credential.setProof(proof);
            
            boolean isValid = verifier.verify(credential, keyPair.getPublic());
            assertTrue("Credential " + i + " should be valid", isValid);
        }
    }
    
    /**
     * Helper method to create a valid credential for testing.
     */
    private JsonLdCredential createValidCredential() {
        CredentialSubject subject = new CredentialSubject("did:example:student");
        subject.addClaim("degree", "Bachelor of Science");
        subject.addClaim("degreeType", "BachelorDegree");
        
        JsonLdCredential credential = new JsonLdCredential()
            .setId("http://example.edu/credentials/3732")
            .addType("VerifiableCredential")  // Add required base type
            .addType("UniversityDegreeCredential")
            .setIssuer("did:example:issuer")
            .setIssuanceDate(Instant.now())
            .setCredentialSubject(subject);
        
        // Add required W3C VC context
        credential.getContext().addContextUrl(JsonLdContext.W3C_VC_CONTEXT);
        
        return credential;
    }
}

// Made with Bob