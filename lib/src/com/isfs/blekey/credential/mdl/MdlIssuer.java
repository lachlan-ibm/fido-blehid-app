/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.mdl;

import com.isfs.blekey.cose.CoseUtils;
import com.isfs.blekey.util.Cbor;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Issuer-side implementation for creating ISO mDL (Mobile Driver's License) credentials.
 * 
 * <p>This class provides functionality to:
 * <ul>
 *   <li>Create mDL credentials from claims</li>
 *   <li>Generate Mobile Security Object (MSO)</li>
 *   <li>Sign MSO with issuer's private key (IssuerAuth)</li>
 *   <li>Assemble complete mDL structure</li>
 * </ul>
 * 
 * <p>Usage example:
 * <pre>{@code
 * // Create issuer
 * MdlIssuer issuer = new MdlIssuer(
 *     issuerPrivateKey,
 *     issuerCertificateChain,
 *     "org.iso.18013.5.1.mDL"
 * );
 * 
 * // Prepare claims
 * Map<String, Map<String, Object>> claims = new HashMap<>();
 * Map<String, Object> mdlClaims = new HashMap<>();
 * mdlClaims.put("family_name", "Doe");
 * mdlClaims.put("given_name", "John");
 * mdlClaims.put("birth_date", "1990-01-01");
 * claims.put("org.iso.18013.5.1", mdlClaims);
 * 
 * // Issue mDL
 * MobileDocument mdl = issuer.issueMdl(
 *     claims,
 *     devicePublicKey,
 *     Instant.now(),
 *     Instant.now().plusSeconds(86400 * 365)
 * );
 * }</pre>
 * 
 * @see <a href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5:2021</a>
 */
public class MdlIssuer {
    
    /** Default digest algorithm for MSO */
    public static final String DEFAULT_DIGEST_ALGORITHM = MobileSecurityObject.DIGEST_ALGORITHM_SHA256;
    
    /** Default MSO version */
    public static final String DEFAULT_MSO_VERSION = MobileSecurityObject.VERSION_1_0;
    
    private final PrivateKey issuerPrivateKey;
    private final List<X509Certificate> issuerCertificateChain;
    private final String docType;
    private final String digestAlgorithm;
    private final SecureRandom secureRandom;
    
    /**
     * Creates a new MdlIssuer with default digest algorithm (SHA-256).
     * 
     * @param issuerPrivateKey the issuer's private key for signing
     * @param issuerCertificateChain the issuer's certificate chain
     * @param docType the document type (e.g., "org.iso.18013.5.1.mDL")
     * @throws IllegalArgumentException if any parameter is invalid
     */
    public MdlIssuer(
            PrivateKey issuerPrivateKey,
            List<X509Certificate> issuerCertificateChain,
            String docType) {
        this(issuerPrivateKey, issuerCertificateChain, docType, DEFAULT_DIGEST_ALGORITHM);
    }
    
    /**
     * Creates a new MdlIssuer with specified digest algorithm.
     * 
     * @param issuerPrivateKey the issuer's private key for signing
     * @param issuerCertificateChain the issuer's certificate chain
     * @param docType the document type (e.g., "org.iso.18013.5.1.mDL")
     * @param digestAlgorithm the digest algorithm to use
     * @throws IllegalArgumentException if any parameter is invalid
     */
    public MdlIssuer(
            PrivateKey issuerPrivateKey,
            List<X509Certificate> issuerCertificateChain,
            String docType,
            String digestAlgorithm) {
        
        if (issuerPrivateKey == null) {
            throw new IllegalArgumentException("issuerPrivateKey cannot be null");
        }
        if (issuerCertificateChain == null || issuerCertificateChain.isEmpty()) {
            throw new IllegalArgumentException("issuerCertificateChain cannot be null or empty");
        }
        if (docType == null || docType.trim().isEmpty()) {
            throw new IllegalArgumentException("docType cannot be null or empty");
        }
        if (!MobileSecurityObject.isValidDigestAlgorithm(digestAlgorithm)) {
            throw new IllegalArgumentException("Invalid digest algorithm: " + digestAlgorithm);
        }
        
        this.issuerPrivateKey = issuerPrivateKey;
        this.issuerCertificateChain = new ArrayList<>(issuerCertificateChain);
        this.docType = docType;
        this.digestAlgorithm = digestAlgorithm;
        this.secureRandom = new SecureRandom();
    }
    
    /**
     * Issues a new mDL credential.
     * 
     * @param claims map of namespace to claims (elementIdentifier to value)
     * @param devicePublicKey the device's public key for binding
     * @param validFrom validity start timestamp
     * @param validUntil validity end timestamp
     * @return the complete MobileDocument
     * @throws MdlException if issuance fails
     */
    public MobileDocument issueMdl(
            Map<String, Map<String, Object>> claims,
            PublicKey devicePublicKey,
            Instant validFrom,
            Instant validUntil) throws MdlException {
        
        if (claims == null || claims.isEmpty()) {
            throw new MdlException("claims cannot be null or empty");
        }
        if (devicePublicKey == null) {
            throw new MdlException("devicePublicKey cannot be null");
        }
        if (validFrom == null || validUntil == null) {
            throw new MdlException("validity timestamps cannot be null");
        }
        if (validFrom.isAfter(validUntil)) {
            throw new MdlException("validFrom must be before validUntil");
        }
        
        try {
            // 1. Convert claims to IssuerSignedItems
            Map<String, List<IssuerSignedItem>> nameSpaces = createIssuerSignedItems(claims);
            
            // 2. Calculate digests for MSO
            Map<String, Map<Integer, byte[]>> valueDigests = calculateValueDigests(nameSpaces);
            
            // 3. Create device key info
            Map<String, Object> deviceKeyInfo = createDeviceKeyInfo(devicePublicKey);
            
            // 4. Create MSO
            Instant signed = Instant.now();
            MobileSecurityObject mso = new MobileSecurityObject(
                DEFAULT_MSO_VERSION,
                digestAlgorithm,
                valueDigests,
                deviceKeyInfo,
                docType,
                signed,
                validFrom,
                validUntil
            );
            
            // 5. Sign MSO to create IssuerAuth
            IssuerAuth issuerAuth = IssuerAuth.create(mso, issuerPrivateKey, issuerCertificateChain);
            
            // 6. Create IssuerSigned
            IssuerSigned issuerSigned = new IssuerSigned(nameSpaces, issuerAuth.getCoseSign1Bytes());
            
            // 7. Create MobileDocument and populate it
            MobileDocument mobileDocument = new MobileDocument(docType);
            
            // Add all issuer-signed items to the document
            for (Map.Entry<String, List<IssuerSignedItem>> entry : nameSpaces.entrySet()) {
                String namespace = entry.getKey();
                for (IssuerSignedItem item : entry.getValue()) {
                    mobileDocument.addIssuerSignedItem(namespace, item);
                }
            }
            
            return mobileDocument;
            
        } catch (Exception e) {
            throw new MdlException("Failed to issue mDL", e);
        }
    }
    
    /**
     * Creates IssuerSignedItems from claims.
     * 
     * @param claims map of namespace to claims
     * @return map of namespace to list of IssuerSignedItems
     * @throws MdlException if creation fails
     */
    private Map<String, List<IssuerSignedItem>> createIssuerSignedItems(
            Map<String, Map<String, Object>> claims) throws MdlException {
        
        Map<String, List<IssuerSignedItem>> nameSpaces = new HashMap<>();
        
        for (Map.Entry<String, Map<String, Object>> nsEntry : claims.entrySet()) {
            String namespace = nsEntry.getKey();
            Map<String, Object> nsClaims = nsEntry.getValue();
            
            List<IssuerSignedItem> items = new ArrayList<>();
            int digestID = 0;
            
            for (Map.Entry<String, Object> claimEntry : nsClaims.entrySet()) {
                String elementIdentifier = claimEntry.getKey();
                Object elementValue = claimEntry.getValue();
                
                // Generate random bytes for each item
                byte[] random = new byte[16];
                secureRandom.nextBytes(random);
                
                IssuerSignedItem item = new IssuerSignedItem(
                    digestID++,
                    random,
                    elementIdentifier,
                    elementValue
                );
                
                items.add(item);
            }
            
            nameSpaces.put(namespace, items);
        }
        
        return nameSpaces;
    }
    
    /**
     * Calculates value digests for the MSO.
     * 
     * @param nameSpaces map of namespace to IssuerSignedItems
     * @return map of namespace to (digestID to digest)
     * @throws MdlException if digest calculation fails
     */
    private Map<String, Map<Integer, byte[]>> calculateValueDigests(
            Map<String, List<IssuerSignedItem>> nameSpaces) throws MdlException {
        
        try {
            MessageDigest md = getMessageDigest();
            Map<String, Map<Integer, byte[]>> valueDigests = new HashMap<>();
            
            for (Map.Entry<String, List<IssuerSignedItem>> entry : nameSpaces.entrySet()) {
                String namespace = entry.getKey();
                List<IssuerSignedItem> items = entry.getValue();
                
                Map<Integer, byte[]> digests = new HashMap<>();
                
                for (IssuerSignedItem item : items) {
                    // Digest the CBOR-encoded IssuerSignedItem
                    byte[] itemBytes = item.toCbor();
                    byte[] digest = md.digest(itemBytes);
                    digests.put(item.getDigestId(), digest);
                    
                    // Reset for next digest
                    md.reset();
                }
                
                valueDigests.put(namespace, digests);
            }
            
            return valueDigests;
            
        } catch (Exception e) {
            throw new MdlException("Failed to calculate value digests", e);
        }
    }
    
    /**
     * Creates device key info structure for MSO.
     * 
     * @param devicePublicKey the device's public key
     * @return device key info map
     * @throws MdlException if creation fails
     */
    private Map<String, Object> createDeviceKeyInfo(PublicKey devicePublicKey) throws MdlException {
        try {
            // Convert public key to COSE_Key format
            Map<Integer, Object> coseKey = CoseUtils.publicKeyToCoseKey(devicePublicKey);
            
            Map<String, Object> deviceKeyInfo = new HashMap<>();
            deviceKeyInfo.put("deviceKey", coseKey);
            
            return deviceKeyInfo;
            
        } catch (Exception e) {
            throw new MdlException("Failed to create device key info", e);
        }
    }
    
    /**
     * Gets the MessageDigest instance for the configured algorithm.
     * 
     * @return MessageDigest instance
     * @throws MdlException if algorithm is not available
     */
    private MessageDigest getMessageDigest() throws MdlException {
        try {
            // Map ISO algorithm names to Java algorithm names
            String javaAlgorithm;
            switch (digestAlgorithm) {
                case MobileSecurityObject.DIGEST_ALGORITHM_SHA256:
                    javaAlgorithm = "SHA-256";
                    break;
                case MobileSecurityObject.DIGEST_ALGORITHM_SHA384:
                    javaAlgorithm = "SHA-384";
                    break;
                case MobileSecurityObject.DIGEST_ALGORITHM_SHA512:
                    javaAlgorithm = "SHA-512";
                    break;
                default:
                    throw new MdlException("Unsupported digest algorithm: " + digestAlgorithm);
            }
            
            return MessageDigest.getInstance(javaAlgorithm);
            
        } catch (Exception e) {
            throw new MdlException("Failed to get MessageDigest", e);
        }
    }
    
    /**
     * Returns the document type this issuer creates.
     * 
     * @return the document type
     */
    public String getDocType() {
        return docType;
    }
    
    /**
     * Returns the digest algorithm used by this issuer.
     * 
     * @return the digest algorithm
     */
    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }
    
    /**
     * Returns an unmodifiable view of the issuer certificate chain.
     * 
     * @return the certificate chain
     */
    public List<X509Certificate> getIssuerCertificateChain() {
        return new ArrayList<>(issuerCertificateChain);
    }
}

// Made with Bob
