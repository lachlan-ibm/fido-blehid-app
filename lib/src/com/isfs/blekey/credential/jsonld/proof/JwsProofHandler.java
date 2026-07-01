/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.credential.jsonld.proof;

import com.google.gson.JsonObject;
import com.isfs.blekey.credential.jsonld.JsonLdCredential;
import com.isfs.blekey.credential.jsonld.JsonLdException;
import com.isfs.blekey.credential.jsonld.JsonLdProof;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Base64;

/**
 * Proof handler for JsonWebSignature2020 proof type.
 * 
 * <p>This implementation uses JWS (JSON Web Signature) with detached payload
 * to create and verify proofs for JSON-LD credentials. The proof follows the
 * W3C Data Integrity specification for JsonWebSignature2020.
 * 
 * <p>Key features:
 * <ul>
 *   <li>Uses ES256 (ECDSA with P-256 and SHA-256) algorithm</li>
 *   <li>Creates detached JWS signatures (payload not included in JWS)</li>
 *   <li>Supports verification method identifiers (DIDs)</li>
 *   <li>Includes creation timestamp in proof</li>
 * </ul>
 * 
 * <p>Proof structure:
 * <pre>
 * {
 *   "type": "JsonWebSignature2020",
 *   "created": "2024-01-01T00:00:00Z",
 *   "verificationMethod": "did:example:123#key-1",
 *   "proofPurpose": "assertionMethod",
 *   "jws": "eyJhbGc...signature"
 * }
 * </pre>
 * 
 * @see <a href="https://w3c-ccg.github.io/lds-jws2020/">JsonWebSignature2020 Specification</a>
 */
public class JwsProofHandler extends ProofHandler {
    
    private static final String PROOF_TYPE = "JsonWebSignature2020";
    private static final String PROOF_PURPOSE = "assertionMethod";
    private static final String ALGORITHM = AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256;
    
    @Override
    public String getProofType() {
        return PROOF_TYPE;
    }
    
    @Override
    public JsonLdProof generateProof(
        JsonLdCredential credential,
        PrivateKey signingKey,
        String verificationMethod
    ) throws JsonLdException {
        
        validateCredentialForProof(credential);
        
        if (signingKey == null) {
            throw new JsonLdException("Signing key cannot be null");
        }
        
        if (verificationMethod == null || verificationMethod.isEmpty()) {
            throw new JsonLdException("Verification method cannot be null or empty");
        }
        
        try {
            // Canonicalize the credential (without proof)
            String canonicalCredential = canonicalizeCredential(credential);
            
            // Create JWS with detached payload
            String jws = createDetachedJws(canonicalCredential, signingKey);
            
            // Build the proof
            Instant created = Instant.now();
            
            return new JsonLdProof()
                .setType(PROOF_TYPE)
                .setCreated(created)
                .setVerificationMethod(verificationMethod)
                .setProofPurpose(PROOF_PURPOSE)
                .setJws(jws);
                
        } catch (Exception e) {
            throw new JsonLdException("Failed to generate JWS proof: " + e.getMessage(), e);
        }
    }
    
    @Override
    public boolean verifyProof(
        JsonLdCredential credential,
        PublicKey verificationKey
    ) throws JsonLdException {
        
        validateCredentialForVerification(credential);
        
        if (verificationKey == null) {
            throw new JsonLdException("Verification key cannot be null");
        }
        
        try {
            JsonLdProof proof = credential.getProof();
            String jws = proof.getJws();
            
            if (jws == null || jws.isEmpty()) {
                throw new JsonLdException("Proof does not contain JWS");
            }
            
            // Remove proof from credential for canonicalization
            JsonLdCredential credentialWithoutProof = createCredentialWithoutProof(credential);
            String canonicalCredential = canonicalizeCredential(credentialWithoutProof);
            
            // Verify the detached JWS
            return verifyDetachedJws(jws, canonicalCredential, verificationKey);
            
        } catch (JsonLdException e) {
            throw e;
        } catch (Exception e) {
            throw new JsonLdException("Failed to verify JWS proof: " + e.getMessage(), e);
        }
    }
    
    /**
     * Canonicalize a credential for signing/verification.
     * 
     * <p>This implementation uses a simple JSON serialization approach.
     * In a production system, this should use JSON-LD canonicalization
     * (URDNA2015) for proper semantic equivalence.
     * 
     * @param credential The credential to canonicalize
     * @return The canonical form as a string
     */
    private String canonicalizeCredential(JsonLdCredential credential) {
        // Simple canonicalization: serialize to JSON
        // TODO: Implement proper JSON-LD canonicalization (URDNA2015) in future phase
        JsonObject json = credential.toJsonObject();
        return json.toString();
    }
    
    /**
     * Create a copy of the credential without the proof.
     *
     * @param credential The credential with proof
     * @return A new credential without proof
     */
    private JsonLdCredential createCredentialWithoutProof(JsonLdCredential credential) {
        JsonLdCredential copy = new JsonLdCredential();
        copy.setContext(credential.getContext());
        copy.setId(credential.getId());
        
        // Copy types
        for (String type : credential.getTypes()) {
            if (!copy.getTypes().contains(type)) {
                copy.addType(type);
            }
        }
        
        copy.setIssuer(credential.getIssuer());
        copy.setIssuanceDate(credential.getIssuanceDate());
        copy.setExpirationDate(credential.getExpirationDate());
        copy.setCredentialSubject(credential.getCredentialSubject());
        // Intentionally do NOT copy the proof
        
        return copy;
    }
    
    /**
     * Create a detached JWS signature.
     * 
     * <p>A detached JWS has the payload removed from the compact serialization,
     * resulting in a signature of the form: header..signature
     * 
     * @param payload The payload to sign
     * @param signingKey The private key to sign with
     * @return The detached JWS string
     * @throws JoseException if JWS creation fails
     */
    private String createDetachedJws(String payload, PrivateKey signingKey) throws JoseException {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(payload);
        jws.setKey(signingKey);
        jws.setAlgorithmHeaderValue(ALGORITHM);
        
        // Get compact serialization and remove payload (make it detached)
        String compactJws = jws.getCompactSerialization();
        return makeDetached(compactJws);
    }
    
    /**
     * Verify a detached JWS signature.
     * 
     * @param detachedJws The detached JWS (header..signature)
     * @param payload The original payload
     * @param verificationKey The public key to verify with
     * @return true if signature is valid
     * @throws JoseException if verification fails
     */
    private boolean verifyDetachedJws(
        String detachedJws,
        String payload,
        PublicKey verificationKey
    ) throws JoseException {
        
        // Reattach payload for verification
        String compactJws = reattachPayload(detachedJws, payload);
        
        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(compactJws);
        jws.setKey(verificationKey);
        
        return jws.verifySignature();
    }
    
    /**
     * Make a JWS detached by removing the payload.
     * 
     * <p>Converts: header.payload.signature → header..signature
     * 
     * @param compactJws The compact JWS
     * @return The detached JWS
     */
    private String makeDetached(String compactJws) {
        String[] parts = compactJws.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid JWS format");
        }
        return parts[0] + ".." + parts[2];
    }
    
    /**
     * Reattach payload to a detached JWS.
     * 
     * <p>Converts: header..signature → header.payload.signature
     * 
     * @param detachedJws The detached JWS
     * @param payload The payload to reattach
     * @return The compact JWS
     */
    private String reattachPayload(String detachedJws, String payload) {
        String[] parts = detachedJws.split("\\.\\.");
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid detached JWS format");
        }
        
        // Base64url encode the payload
        String encodedPayload = Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(payload.getBytes(StandardCharsets.UTF_8));
        
        return parts[0] + "." + encodedPayload + "." + parts[1];
    }
}

// Made with Bob