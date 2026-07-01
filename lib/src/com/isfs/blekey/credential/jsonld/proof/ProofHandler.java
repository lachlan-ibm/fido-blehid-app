/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.credential.jsonld.proof;

import com.isfs.blekey.credential.jsonld.JsonLdCredential;
import com.isfs.blekey.credential.jsonld.JsonLdException;
import com.isfs.blekey.credential.jsonld.JsonLdProof;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Abstract interface for handling JSON-LD credential proofs.
 * 
 * <p>Implementations provide specific proof mechanisms such as:
 * <ul>
 *   <li>JsonWebSignature2020 - JWS-based proofs using detached payloads</li>
 *   <li>Ed25519Signature2020 - Ed25519 signature proofs</li>
 *   <li>EcdsaSecp256k1Signature2019 - ECDSA signature proofs</li>
 * </ul>
 * 
 * <p>Each proof handler is responsible for:
 * <ul>
 *   <li>Generating proofs for credentials</li>
 *   <li>Verifying proofs on credentials</li>
 *   <li>Managing proof-specific parameters</li>
 * </ul>
 * 
 * @see JwsProofHandler
 */
public abstract class ProofHandler {
    
    /**
     * Get the proof type identifier for this handler.
     * 
     * @return The proof type (e.g., "JsonWebSignature2020")
     */
    public abstract String getProofType();
    
    /**
     * Generate a proof for the given credential.
     * 
     * <p>The proof is created by:
     * <ol>
     *   <li>Canonicalizing the credential (without existing proof)</li>
     *   <li>Creating a signature over the canonical form</li>
     *   <li>Constructing a JsonLdProof with the signature and metadata</li>
     * </ol>
     * 
     * @param credential The credential to create a proof for (without proof)
     * @param signingKey The private key to sign with
     * @param verificationMethod The verification method identifier (e.g., DID#key-1)
     * @return The generated proof
     * @throws JsonLdException if proof generation fails
     */
    public abstract JsonLdProof generateProof(
        JsonLdCredential credential,
        PrivateKey signingKey,
        String verificationMethod
    ) throws JsonLdException;
    
    /**
     * Verify a proof on the given credential.
     * 
     * <p>Verification involves:
     * <ol>
     *   <li>Extracting the proof from the credential</li>
     *   <li>Canonicalizing the credential (without proof)</li>
     *   <li>Verifying the signature against the canonical form</li>
     * </ol>
     * 
     * @param credential The credential with proof to verify
     * @param verificationKey The public key to verify with
     * @return true if the proof is valid, false otherwise
     * @throws JsonLdException if verification fails due to invalid structure
     */
    public abstract boolean verifyProof(
        JsonLdCredential credential,
        PublicKey verificationKey
    ) throws JsonLdException;
    
    /**
     * Check if this handler supports the given proof type.
     * 
     * @param proofType The proof type to check
     * @return true if this handler supports the proof type
     */
    public boolean supportsProofType(String proofType) {
        return getProofType().equals(proofType);
    }
    
    /**
     * Validate that the credential is ready for proof generation.
     * 
     * <p>Checks that:
     * <ul>
     *   <li>Credential has required fields (issuer, subject, etc.)</li>
     *   <li>Credential does not already have a proof</li>
     * </ul>
     * 
     * @param credential The credential to validate
     * @throws JsonLdException if the credential is not valid for proof generation
     */
    protected void validateCredentialForProof(JsonLdCredential credential) throws JsonLdException {
        if (credential == null) {
            throw new JsonLdException("Credential cannot be null");
        }
        
        if (credential.getIssuer() == null || credential.getIssuer().isEmpty()) {
            throw new JsonLdException("Credential must have an issuer");
        }
        
        if (credential.getCredentialSubject() == null) {
            throw new JsonLdException("Credential must have a credential subject");
        }
        
        if (credential.getProof() != null) {
            throw new JsonLdException("Credential already has a proof");
        }
    }
    
    /**
     * Validate that the credential has a proof for verification.
     * 
     * @param credential The credential to validate
     * @throws JsonLdException if the credential does not have a valid proof
     */
    protected void validateCredentialForVerification(JsonLdCredential credential) throws JsonLdException {
        if (credential == null) {
            throw new JsonLdException("Credential cannot be null");
        }
        
        if (credential.getProof() == null) {
            throw new JsonLdException("Credential does not have a proof");
        }
        
        JsonLdProof proof = credential.getProof();
        if (!supportsProofType(proof.getType())) {
            throw new JsonLdException("Unsupported proof type: " + proof.getType());
        }
    }
}

// Made with Bob