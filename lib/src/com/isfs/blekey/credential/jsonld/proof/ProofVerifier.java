/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.credential.jsonld.proof;

import com.isfs.blekey.credential.jsonld.JsonLdCredential;
import com.isfs.blekey.credential.jsonld.JsonLdException;
import com.isfs.blekey.credential.jsonld.JsonLdProof;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * Verifies cryptographic proofs on JSON-LD credentials.
 * 
 * <p>This class provides a registry-based approach to proof verification,
 * allowing different proof handlers to be registered for different proof types.
 * It automatically selects the appropriate handler based on the proof type
 * in the credential.
 * 
 * <p>Example usage:
 * <pre>{@code
 * // Create verifier and register handlers
 * ProofVerifier verifier = new ProofVerifier();
 * verifier.registerHandler(new JwsProofHandler());
 * 
 * // Verify a credential
 * PublicKey issuerKey = ...; // Get issuer's public key
 * boolean isValid = verifier.verify(credential, issuerKey);
 * 
 * if (isValid) {
 *     System.out.println("Credential proof is valid!");
 * } else {
 *     System.out.println("Credential proof is invalid!");
 * }
 * }</pre>
 * 
 * <p>Supported proof types (when handlers are registered):
 * <ul>
 *   <li>JsonWebSignature2020 - via {@link JwsProofHandler}</li>
 *   <li>Ed25519Signature2020 - via custom handler (future)</li>
 *   <li>EcdsaSecp256k1Signature2019 - via custom handler (future)</li>
 * </ul>
 */
public class ProofVerifier {
    
    /**
     * Registry of proof handlers by proof type.
     */
    private final Map<String, ProofHandler> handlers;
    
    /**
     * Constructs a new proof verifier with no handlers registered.
     */
    public ProofVerifier() {
        this.handlers = new HashMap<>();
    }
    
    /**
     * Constructs a proof verifier with default handlers.
     * 
     * @param registerDefaults if true, registers default handlers (JwsProofHandler)
     */
    public ProofVerifier(boolean registerDefaults) {
        this();
        if (registerDefaults) {
            registerDefaultHandlers();
        }
    }
    
    /**
     * Register default proof handlers.
     * Currently registers:
     * <ul>
     *   <li>JwsProofHandler for JsonWebSignature2020</li>
     * </ul>
     */
    public void registerDefaultHandlers() {
        registerHandler(new JwsProofHandler());
    }
    
    /**
     * Register a proof handler for its supported proof type.
     * 
     * @param handler the proof handler to register
     * @return this verifier for method chaining
     */
    public ProofVerifier registerHandler(ProofHandler handler) {
        if (handler != null) {
            handlers.put(handler.getProofType(), handler);
        }
        return this;
    }
    
    /**
     * Unregister a proof handler for the given proof type.
     * 
     * @param proofType the proof type to unregister
     * @return this verifier for method chaining
     */
    public ProofVerifier unregisterHandler(String proofType) {
        handlers.remove(proofType);
        return this;
    }
    
    /**
     * Get the handler for a specific proof type.
     * 
     * @param proofType the proof type
     * @return the handler, or null if not registered
     */
    public ProofHandler getHandler(String proofType) {
        return handlers.get(proofType);
    }
    
    /**
     * Check if a handler is registered for the given proof type.
     * 
     * @param proofType the proof type to check
     * @return true if a handler is registered
     */
    public boolean hasHandler(String proofType) {
        return handlers.containsKey(proofType);
    }
    
    /**
     * Verify the proof on a credential.
     * 
     * <p>This method:
     * <ol>
     *   <li>Checks that the credential has a proof</li>
     *   <li>Finds the appropriate handler for the proof type</li>
     *   <li>Delegates verification to the handler</li>
     * </ol>
     * 
     * @param credential the credential to verify
     * @param verificationKey the public key to verify with
     * @return true if the proof is valid, false otherwise
     * @throws JsonLdException if verification fails due to invalid structure or missing handler
     */
    public boolean verify(JsonLdCredential credential, PublicKey verificationKey) throws JsonLdException {
        if (credential == null) {
            throw new JsonLdException("Credential cannot be null");
        }
        
        if (verificationKey == null) {
            throw new JsonLdException("Verification key cannot be null");
        }
        
        JsonLdProof proof = credential.getProof();
        if (proof == null) {
            throw new JsonLdException("Credential does not have a proof");
        }
        
        String proofType = proof.getType();
        if (proofType == null || proofType.isEmpty()) {
            throw new JsonLdException("Proof does not have a type");
        }
        
        ProofHandler handler = handlers.get(proofType);
        if (handler == null) {
            throw new JsonLdException("No handler registered for proof type: " + proofType);
        }
        
        return handler.verifyProof(credential, verificationKey);
    }
    
    /**
     * Verify the proof on a credential, returning false instead of throwing exceptions.
     * 
     * <p>This is a convenience method that catches all exceptions and returns false.
     * Use {@link #verify(JsonLdCredential, PublicKey)} if you need detailed error information.
     * 
     * @param credential the credential to verify
     * @param verificationKey the public key to verify with
     * @return true if the proof is valid, false otherwise (including on errors)
     */
    public boolean verifyQuietly(JsonLdCredential credential, PublicKey verificationKey) {
        try {
            return verify(credential, verificationKey);
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Verify that a credential has a valid structure for verification.
     * 
     * <p>This checks:
     * <ul>
     *   <li>Credential has all required fields</li>
     *   <li>Credential has a proof</li>
     *   <li>Proof has a supported type</li>
     * </ul>
     * 
     * <p>This does NOT verify the cryptographic signature.
     * 
     * @param credential the credential to check
     * @throws JsonLdException if the credential is not valid for verification
     */
    public void validateForVerification(JsonLdCredential credential) throws JsonLdException {
        if (credential == null) {
            throw new JsonLdException("Credential cannot be null");
        }
        
        // Validate credential structure
        credential.validate();
        
        // Check proof
        JsonLdProof proof = credential.getProof();
        if (proof == null) {
            throw new JsonLdException("Credential does not have a proof");
        }
        
        // Validate proof structure
        proof.validate();
        
        // Check handler availability
        String proofType = proof.getType();
        if (!hasHandler(proofType)) {
            throw new JsonLdException("No handler registered for proof type: " + proofType);
        }
    }
    
    /**
     * Get all registered proof types.
     * 
     * @return array of registered proof types
     */
    public String[] getRegisteredProofTypes() {
        return handlers.keySet().toArray(new String[0]);
    }
    
    /**
     * Get the number of registered handlers.
     * 
     * @return the number of handlers
     */
    public int getHandlerCount() {
        return handlers.size();
    }
}

// Made with Bob