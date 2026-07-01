/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.mdl;

import com.isfs.blekey.cose.CoseException;
import com.isfs.blekey.cose.CoseUtils;
import COSE.AlgorithmID;
import COSE.Sign1Message;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Represents the IssuerAuth structure in an ISO mDL credential.
 * 
 * <p>IssuerAuth is a COSE_Sign1 structure that contains:
 * <ul>
 *   <li>The Mobile Security Object (MSO) as the payload</li>
 *   <li>The issuer's signature over the MSO</li>
 *   <li>Optional X.509 certificate chain in unprotected headers</li>
 * </ul>
 * 
 * <p>The IssuerAuth provides cryptographic proof that the MSO (and thus the
 * credential data) was issued by a trusted authority.
 * 
 * <p>CBOR structure (as per ISO 18013-5 Section 9.1.2.4):
 * <pre>
 * IssuerAuth = COSE_Sign1
 * </pre>
 * 
 * @see <a href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5:2021 Section 9.1.2.4</a>
 */
public class IssuerAuth {
    
    private final byte[] coseSign1Bytes;
    private final MobileSecurityObject mso;
    private final List<X509Certificate> certificateChain;
    
    /**
     * Creates a new IssuerAuth by signing the MSO.
     * 
     * @param mso the Mobile Security Object to sign
     * @param privateKey the issuer's private key
     * @param certificateChain the issuer's certificate chain (optional)
     * @return the created IssuerAuth
     * @throws MdlException if signing fails
     */
    public static IssuerAuth create(
            MobileSecurityObject mso,
            PrivateKey privateKey,
            List<X509Certificate> certificateChain) throws MdlException {
        try {
            byte[] msoBytes = mso.toCbor();
            
            // Create COSE_Sign1 with ES256 algorithm
            Sign1Message sign1 = CoseUtils.createSign1(
                msoBytes,
                privateKey,
                AlgorithmID.ECDSA_256
            );
            
            // Add certificate chain to unprotected headers if provided
            if (certificateChain != null && !certificateChain.isEmpty()) {
                // Certificate chain handling would go here
                // For now, we'll store it separately
            }
            
            byte[] coseSign1Bytes = sign1.EncodeToBytes();
            
            return new IssuerAuth(coseSign1Bytes, mso, certificateChain);
            
        } catch (CoseException e) {
            throw new MdlException("Failed to create IssuerAuth", e);
        } catch (Exception e) {
            throw new MdlException("Failed to create IssuerAuth", e);
        }
    }
    
    /**
     * Creates an IssuerAuth from existing COSE_Sign1 bytes.
     * 
     * @param coseSign1Bytes the COSE_Sign1 encoded bytes
     * @param mso the Mobile Security Object
     * @param certificateChain the certificate chain (optional)
     */
    public IssuerAuth(
            byte[] coseSign1Bytes,
            MobileSecurityObject mso,
            List<X509Certificate> certificateChain) {
        if (coseSign1Bytes == null || coseSign1Bytes.length == 0) {
            throw new IllegalArgumentException("coseSign1Bytes cannot be null or empty");
        }
        if (mso == null) {
            throw new IllegalArgumentException("mso cannot be null");
        }
        
        this.coseSign1Bytes = coseSign1Bytes.clone();
        this.mso = mso;
        this.certificateChain = certificateChain != null ? 
            new ArrayList<>(certificateChain) : new ArrayList<>();
    }
    
    /**
     * Returns a copy of the COSE_Sign1 bytes.
     * 
     * @return the COSE_Sign1 bytes
     */
    public byte[] getCoseSign1Bytes() {
        return coseSign1Bytes.clone();
    }
    
    /**
     * Returns the Mobile Security Object.
     * 
     * @return the MSO
     */
    public MobileSecurityObject getMso() {
        return mso;
    }
    
    /**
     * Returns an unmodifiable view of the certificate chain.
     * 
     * @return the certificate chain
     */
    public List<X509Certificate> getCertificateChain() {
        return Collections.unmodifiableList(certificateChain);
    }
    
    /**
     * Verifies the IssuerAuth signature.
     * 
     * @param publicKey the public key to verify with
     * @return true if signature is valid
     * @throws MdlException if verification fails
     */
    public boolean verify(PublicKey publicKey) throws MdlException {
        try {
            Sign1Message sign1 = (Sign1Message) Sign1Message.DecodeFromBytes(coseSign1Bytes);
            
            // Verify the signature
            boolean valid = CoseUtils.verifySign1(sign1, publicKey);
            
            if (valid) {
                // Verify that the payload matches the MSO
                byte[] payload = sign1.GetContent();
                byte[] expectedMso = mso.toCbor();
                valid = Arrays.equals(payload, expectedMso);
            }
            
            return valid;
            
        } catch (CoseException e) {
            throw new MdlException("Failed to verify IssuerAuth", e);
        } catch (Exception e) {
            throw new MdlException("Failed to verify IssuerAuth", e);
        }
    }
    
    /**
     * Encodes this IssuerAuth to CBOR format (returns the COSE_Sign1 bytes).
     * 
     * @return CBOR-encoded bytes
     */
    public byte[] toCbor() {
        return coseSign1Bytes.clone();
    }
    
    /**
     * Decodes an IssuerAuth from CBOR format.
     * 
     * @param cbor the CBOR-encoded bytes (COSE_Sign1)
     * @return the decoded IssuerAuth
     * @throws MdlException if decoding fails
     */
    public static IssuerAuth fromCbor(byte[] cbor) throws MdlException {
        try {
            Sign1Message sign1 = (Sign1Message) Sign1Message.DecodeFromBytes(cbor);
            
            // Extract MSO from payload
            byte[] msoBytes = sign1.GetContent();
            MobileSecurityObject mso = MobileSecurityObject.fromCbor(msoBytes);
            
            // Extract certificate chain from unprotected headers if present
            List<X509Certificate> certificateChain = new ArrayList<>();
            // Certificate chain extraction would go here
            
            return new IssuerAuth(cbor, mso, certificateChain);
            
        } catch (Exception e) {
            throw new MdlException("Failed to decode IssuerAuth from CBOR", e);
        }
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        IssuerAuth that = (IssuerAuth) o;
        return Arrays.equals(coseSign1Bytes, that.coseSign1Bytes) &&
               mso.equals(that.mso);
    }
    
    @Override
    public int hashCode() {
        int result = Arrays.hashCode(coseSign1Bytes);
        result = 31 * result + mso.hashCode();
        return result;
    }
    
    @Override
    public String toString() {
        return String.format("IssuerAuth{coseSign1Length=%d, certChainSize=%d}",
                coseSign1Bytes.length, certificateChain.size());
    }
}

// Made with Bob
