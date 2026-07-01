/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.cose;

import com.isfs.blekey.util.Cbor;
import COSE.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

/**
 * Utility class for COSE (CBOR Object Signing and Encryption) operations.
 * This class provides a simplified wrapper around the COSE-Java library
 * for ISO mDL (mobile Driver's License) support.
 * 
 * <p>COSE is defined in RFC 8152 and is used in ISO 18013-5 for signing
 * mobile driver's license credentials.</p>
 * 
 * <p>This implementation focuses on COSE_Sign1 structures, which are
 * single-signer signatures commonly used in ISO mDL.</p>
 */
public class CoseUtils {
    
    private static final Logger logger = LoggerFactory.getLogger(CoseUtils.class);
    
    /**
     * Algorithm identifier for ES256 (ECDSA with SHA-256).
     * This is the required algorithm for ISO 18013-5 mDL.
     */
    public static final AlgorithmID ALGORITHM_ES256 = AlgorithmID.ECDSA_256;
    
    /**
     * Private constructor to prevent instantiation.
     */
    private CoseUtils() {
        throw new UnsupportedOperationException("Utility class");
    }
    
    /**
     * Creates a COSE_Sign1 message with the given payload and signs it.
     * 
     * @param payload the payload to sign
     * @param privateKey the private key to use for signing
     * @param algorithm the algorithm to use (typically ES256)
     * @return the signed COSE_Sign1 message
     * @throws CoseException if signing fails
     */
    public static Sign1Message createSign1(byte[] payload, PrivateKey privateKey, AlgorithmID algorithm) 
            throws CoseException {
        try {
            logger.debug("Creating COSE_Sign1 message with algorithm: {}", algorithm);
            
            Sign1Message msg = new Sign1Message();
            msg.SetContent(payload);
            msg.addAttribute(HeaderKeys.Algorithm, algorithm.AsCBOR(), Attribute.PROTECTED);
            
            OneKey key = createOneKeyFromPrivateKey(privateKey, algorithm);
            msg.sign(key);
            
            logger.debug("COSE_Sign1 message created and signed successfully");
            return msg;
            
        } catch (CoseException e) {
            throw e;
        } catch (Exception e) {
            throw new CoseException("Failed to create and sign COSE_Sign1 message", e);
        }
    }
    
    /**
     * Creates a COSE_Sign1 message with protected and unprotected headers.
     * 
     * @param payload the payload to sign
     * @param privateKey the private key to use for signing
     * @param algorithm the algorithm to use
     * @param keyId optional key identifier to include in unprotected headers
     * @return the signed COSE_Sign1 message
     * @throws CoseException if signing fails
     */
    public static Sign1Message createSign1WithHeaders(
            byte[] payload, 
            PrivateKey privateKey, 
            AlgorithmID algorithm,
            byte[] keyId) throws CoseException {
        try {
            logger.debug("Creating COSE_Sign1 message with headers");
            
            Sign1Message msg = new Sign1Message();
            msg.SetContent(payload);
            
            // Add protected header (algorithm)
            msg.addAttribute(HeaderKeys.Algorithm, algorithm.AsCBOR(), Attribute.PROTECTED);
            
            // Add unprotected header (key ID) if provided
            if (keyId != null && keyId.length > 0) {
                msg.addAttribute(HeaderKeys.KID, keyId, Attribute.UNPROTECTED);
            }
            
            OneKey key = createOneKeyFromPrivateKey(privateKey, algorithm);
            msg.sign(key);
            
            logger.debug("COSE_Sign1 message with headers created successfully");
            return msg;
            
        } catch (CoseException e) {
            throw e;
        } catch (Exception e) {
            throw new CoseException("Failed to create COSE_Sign1 message with headers", e);
        }
    }
    
    /**
     * Verifies a COSE_Sign1 message using a public key.
     * 
     * @param sign1Message the COSE_Sign1 message to verify
     * @param publicKey the public key to use for verification
     * @return true if the signature is valid, false otherwise
     * @throws CoseException if verification fails due to an error (not invalid signature)
     */
    public static boolean verifySign1(Sign1Message sign1Message, PublicKey publicKey) 
            throws CoseException {
        try {
            logger.debug("Verifying COSE_Sign1 message");
            
            OneKey key = createOneKeyFromPublicKey(publicKey);
            boolean valid = sign1Message.validate(key);
            
            logger.debug("COSE_Sign1 verification result: {}", valid);
            return valid;
            
        } catch (Exception e) {
            throw new CoseException("Failed to verify COSE_Sign1 message", e);
        }
    }
    
    /**
     * Verifies a COSE_Sign1 message using a certificate.
     * 
     * @param sign1Message the COSE_Sign1 message to verify
     * @param certificate the X.509 certificate containing the public key
     * @return true if the signature is valid, false otherwise
     * @throws CoseException if verification fails due to an error
     */
    public static boolean verifySign1(Sign1Message sign1Message, X509Certificate certificate) 
            throws CoseException {
        return verifySign1(sign1Message, certificate.getPublicKey());
    }
    
    /**
     * Encodes a COSE_Sign1 message to CBOR bytes with tag 18.
     * 
     * @param sign1Message the COSE_Sign1 message to encode
     * @return CBOR encoded bytes with tag 18
     * @throws CoseException if encoding fails
     */
    public static byte[] encodeSign1(Sign1Message sign1Message) throws CoseException {
        try {
            logger.debug("Encoding COSE_Sign1 message to CBOR");
            byte[] encoded = sign1Message.EncodeToBytes();
            logger.debug("COSE_Sign1 message encoded, size: {} bytes", encoded.length);
            return encoded;
        } catch (Exception e) {
            throw new CoseException("Failed to encode COSE_Sign1 message", e);
        }
    }
    
    /**
     * Decodes a COSE_Sign1 message from CBOR bytes.
     * 
     * @param cborData the CBOR encoded data
     * @return the decoded COSE_Sign1 message
     * @throws CoseException if decoding fails
     */
    public static Sign1Message decodeSign1(byte[] cborData) throws CoseException {
        try {
            logger.debug("Decoding COSE_Sign1 message from CBOR, size: {} bytes", cborData.length);
            Sign1Message msg = (Sign1Message) Message.DecodeFromBytes(cborData, MessageTag.Sign1);
            logger.debug("COSE_Sign1 message decoded successfully");
            return msg;
        } catch (Exception e) {
            throw new CoseException("Failed to decode COSE_Sign1 message", e);
        }
    }
    
    /**
     * Extracts the payload from a COSE_Sign1 message.
     * 
     * @param sign1Message the COSE_Sign1 message
     * @return the payload bytes
     */
    public static byte[] getPayload(Sign1Message sign1Message) {
        return sign1Message.GetContent();
    }
    
    /**
     * Gets the algorithm from a COSE_Sign1 message's protected headers.
     * 
     * @param sign1Message the COSE_Sign1 message
     * @return the algorithm ID, or null if not present
     * @throws CoseException if the algorithm cannot be retrieved
     */
    public static AlgorithmID getAlgorithm(Sign1Message sign1Message) throws CoseException {
        try {
            return AlgorithmID.FromCBOR(sign1Message.findAttribute(HeaderKeys.Algorithm));
        } catch (Exception e) {
            throw new CoseException("Failed to get algorithm from COSE_Sign1 message", e);
        }
    }
    
    /**
     * Gets the key ID from a COSE_Sign1 message's unprotected headers.
     * 
     * @param sign1Message the COSE_Sign1 message
     * @return the key ID bytes, or null if not present
     */
    public static byte[] getKeyId(Sign1Message sign1Message) {
        try {
            return sign1Message.findAttribute(HeaderKeys.KID).GetByteString();
        } catch (Exception e) {
            logger.debug("No key ID found in COSE_Sign1 message");
            return null;
        }
    }
    
    /**
     * Creates a OneKey from a private key for signing operations.
     * This is an internal helper method.
     * 
     * @param privateKey the private key
     * @param algorithm the algorithm to use
     * @return a OneKey suitable for signing
     * @throws CoseException if key creation fails
     */
    private static OneKey createOneKeyFromPrivateKey(PrivateKey privateKey, AlgorithmID algorithm) 
            throws CoseException {
        try {
            // For ES256, we expect an EC private key
            if (algorithm == AlgorithmID.ECDSA_256) {
                if (!privateKey.getAlgorithm().equals("EC")) {
                    throw new CoseException("Expected EC private key for ES256 algorithm, got: " 
                            + privateKey.getAlgorithm());
                }
                return new OneKey(null, privateKey);
            }
            
            throw new CoseException("Unsupported algorithm: " + algorithm);
            
        } catch (CoseException e) {
            throw e;
        } catch (Exception e) {
            throw new CoseException("Failed to create OneKey from private key", e);
        }
    }
    
    /**
     * Creates a OneKey from a public key for verification operations.
     * This is an internal helper method.
     * 
     * @param publicKey the public key
     * @return a OneKey suitable for verification
     * @throws CoseException if key creation fails
     */
    private static OneKey createOneKeyFromPublicKey(PublicKey publicKey) throws CoseException {
        try {
            return new OneKey(publicKey, null);
        } catch (Exception e) {
            throw new CoseException("Failed to create OneKey from public key", e);
        }
    }
    
    /**
     * Converts a COSE_Sign1 message to diagnostic notation for debugging.
     * 
     * @param sign1Message the COSE_Sign1 message
     * @return a human-readable string representation
     */
    public static String toDiagnosticNotation(Sign1Message sign1Message) {
        try {
            byte[] encoded = sign1Message.EncodeToBytes();
            Object decoded = Cbor.decode(encoded);
            return Cbor.toDiagnosticNotation(decoded);
        } catch (Exception e) {
            logger.warn("Failed to convert COSE_Sign1 to diagnostic notation", e);
            return sign1Message.toString();
        }
    }
    
    // ========== COSE_Key Support (Phase 3) ==========
    
    /**
     * COSE key type for Elliptic Curve keys (EC2).
     * As defined in RFC 8152 Section 13.1.
     */
    public static final int COSE_KEY_TYPE_EC2 = 2;
    
    /**
     * COSE curve identifier for P-256 (secp256r1).
     * As defined in RFC 8152 Section 13.1.1.
     */
    public static final int COSE_CURVE_P256 = 1;
    
    /**
     * COSE key parameter labels as defined in RFC 8152.
     */
    public static final int COSE_KEY_PARAM_KTY = 1;   // Key type
    public static final int COSE_KEY_PARAM_KID = 2;   // Key ID
    public static final int COSE_KEY_PARAM_ALG = 3;   // Algorithm
    public static final int COSE_KEY_PARAM_CRV = -1;  // EC curve
    public static final int COSE_KEY_PARAM_X = -2;    // EC x-coordinate
    public static final int COSE_KEY_PARAM_Y = -3;    // EC y-coordinate
    public static final int COSE_KEY_PARAM_D = -4;    // EC private key
    
    /**
     * Converts a Java KeyPair to a COSE_Key map representation.
     * This method supports EC keys on the P-256 curve (secp256r1).
     *
     * <p>The COSE_Key format is defined in RFC 8152 Section 7.
     * For EC2 keys, the structure is:
     * <pre>
     * {
     *   1: 2,           // kty: EC2
     *   -1: 1,          // crv: P-256
     *   -2: x_bytes,    // x-coordinate
     *   -3: y_bytes,    // y-coordinate
     *   -4: d_bytes     // private key (optional, only if private key present)
     * }
     * </pre>
     *
     * @param keyPair the Java KeyPair to convert (must be EC P-256)
     * @param includePrivateKey whether to include the private key in the output
     * @return a Map representing the COSE_Key structure
     * @throws CoseException if the key type is unsupported or conversion fails
     */
    public static Map<Integer, Object> keyPairToCoseKey(KeyPair keyPair, boolean includePrivateKey)
            throws CoseException {
        try {
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            
            if (!(publicKey instanceof ECPublicKey)) {
                throw new CoseException("Only EC public keys are supported, got: "
                        + publicKey.getAlgorithm());
            }
            
            ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
            
            // Verify it's P-256 curve
            ECParameterSpec params = ecPublicKey.getParams();
            String curveName = params.toString();
            
            // Check if it's P-256 by comparing the curve parameters
            boolean isP256 = false;
            
            // Try to get the curve name from various sources
            if (curveName.contains("secp256r1") || curveName.contains("prime256v1") || curveName.contains("P-256")) {
                isP256 = true;
            } else if (params instanceof org.bouncycastle.jce.spec.ECNamedCurveSpec) {
                // BouncyCastle named curve spec
                org.bouncycastle.jce.spec.ECNamedCurveSpec namedSpec = (org.bouncycastle.jce.spec.ECNamedCurveSpec) params;
                String name = namedSpec.getName();
                isP256 = name.equals("secp256r1") || name.equals("prime256v1") || name.equals("P-256");
            }
            
            if (!isP256) {
                throw new CoseException("Only P-256 curve is supported, got curve: " + curveName);
            }
            
            // Extract x and y coordinates
            ECPoint point = ecPublicKey.getW();
            byte[] xBytes = point.getAffineX().toByteArray();
            byte[] yBytes = point.getAffineY().toByteArray();
            
            // Ensure coordinates are exactly 32 bytes (remove sign byte if present)
            xBytes = normalizeCoordinate(xBytes);
            yBytes = normalizeCoordinate(yBytes);
            
            // Build COSE_Key map
            Map<Integer, Object> coseKey = new HashMap<>();
            coseKey.put(COSE_KEY_PARAM_KTY, COSE_KEY_TYPE_EC2);
            coseKey.put(COSE_KEY_PARAM_CRV, COSE_CURVE_P256);
            coseKey.put(COSE_KEY_PARAM_X, xBytes);
            coseKey.put(COSE_KEY_PARAM_Y, yBytes);
            
            // Include private key if requested and available
            if (includePrivateKey && privateKey != null) {
                if (!(privateKey instanceof ECPrivateKey)) {
                    throw new CoseException("Only EC private keys are supported, got: "
                            + privateKey.getAlgorithm());
                }
                
                ECPrivateKey ecPrivateKey = (ECPrivateKey) privateKey;
                byte[] dBytes = ecPrivateKey.getS().toByteArray();
                dBytes = normalizeCoordinate(dBytes);
                coseKey.put(COSE_KEY_PARAM_D, dBytes);
            }
            
            logger.debug("Converted KeyPair to COSE_Key (includePrivate={})", includePrivateKey);
            return coseKey;
            
        } catch (CoseException e) {
            throw e;
        } catch (Exception e) {
            throw new CoseException("Failed to convert KeyPair to COSE_Key", e);
        }
    }
    
    /**
     * Converts a Java PublicKey to a COSE_Key map representation.
     *
     * @param publicKey the Java PublicKey to convert (must be EC P-256)
     * @return a Map representing the COSE_Key structure
     * @throws CoseException if the key type is unsupported or conversion fails
     */
    public static Map<Integer, Object> publicKeyToCoseKey(PublicKey publicKey) throws CoseException {
        KeyPair keyPair = new KeyPair(publicKey, null);
        return keyPairToCoseKey(keyPair, false);
    }
    
    /**
     * Converts a COSE_Key map to a Java KeyPair.
     * This method supports EC2 keys on the P-256 curve.
     *
     * @param coseKey the COSE_Key map
     * @return a Java KeyPair (private key will be null if not present in COSE_Key)
     * @throws CoseException if the key type is unsupported or conversion fails
     */
    public static KeyPair coseKeyToKeyPair(Map<Integer, Object> coseKey) throws CoseException {
        try {
            // Validate key type
            Object ktyObj = coseKey.get(COSE_KEY_PARAM_KTY);
            if (ktyObj == null) {
                throw new CoseException("COSE_Key missing required parameter: kty (1)");
            }
            int kty = ((Number) ktyObj).intValue();
            if (kty != COSE_KEY_TYPE_EC2) {
                throw new CoseException("Unsupported COSE key type: " + kty + " (only EC2 supported)");
            }
            
            // Validate curve
            Object crvObj = coseKey.get(COSE_KEY_PARAM_CRV);
            if (crvObj == null) {
                throw new CoseException("COSE_Key missing required parameter: crv (-1)");
            }
            int crv = ((Number) crvObj).intValue();
            if (crv != COSE_CURVE_P256) {
                throw new CoseException("Unsupported COSE curve: " + crv + " (only P-256 supported)");
            }
            
            // Extract coordinates
            byte[] xBytes = (byte[]) coseKey.get(COSE_KEY_PARAM_X);
            byte[] yBytes = (byte[]) coseKey.get(COSE_KEY_PARAM_Y);
            
            if (xBytes == null || yBytes == null) {
                throw new CoseException("COSE_Key missing required coordinates (x=-2, y=-3)");
            }
            
            // Create public key
            BigInteger x = new BigInteger(1, xBytes);
            BigInteger y = new BigInteger(1, yBytes);
            ECPoint point = new ECPoint(x, y);
            
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            ECParameterSpec ecParams = getP256ParameterSpec();
            ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(point, ecParams);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
            
            // Create private key if present
            PrivateKey privateKey = null;
            byte[] dBytes = (byte[]) coseKey.get(COSE_KEY_PARAM_D);
            if (dBytes != null) {
                BigInteger d = new BigInteger(1, dBytes);
                ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(d, ecParams);
                privateKey = keyFactory.generatePrivate(privateKeySpec);
            }
            
            logger.debug("Converted COSE_Key to KeyPair (hasPrivate={})", privateKey != null);
            return new KeyPair(publicKey, privateKey);
            
        } catch (CoseException e) {
            throw e;
        } catch (Exception e) {
            throw new CoseException("Failed to convert COSE_Key to KeyPair", e);
        }
    }
    
    /**
     * Converts a COSE_Key map to a Java PublicKey.
     *
     * @param coseKey the COSE_Key map
     * @return a Java PublicKey
     * @throws CoseException if the key type is unsupported or conversion fails
     */
    public static PublicKey coseKeyToPublicKey(Map<Integer, Object> coseKey) throws CoseException {
        return coseKeyToKeyPair(coseKey).getPublic();
    }
    
    /**
     * Encodes a COSE_Key map to CBOR bytes.
     *
     * @param coseKey the COSE_Key map
     * @return CBOR encoded bytes
     * @throws CoseException if encoding fails
     */
    public static byte[] encodeCoseKey(Map<Integer, Object> coseKey) throws CoseException {
        try {
            logger.debug("Encoding COSE_Key to CBOR");
            byte[] encoded = Cbor.encode(coseKey);
            logger.debug("COSE_Key encoded, size: {} bytes", encoded.length);
            return encoded;
        } catch (Exception e) {
            throw new CoseException("Failed to encode COSE_Key", e);
        }
    }
    
    /**
     * Decodes a COSE_Key from CBOR bytes.
     *
     * @param cborData the CBOR encoded data
     * @return a Map representing the COSE_Key structure
     * @throws CoseException if decoding fails
     */
    public static Map<Integer, Object> decodeCoseKey(byte[] cborData) throws CoseException {
        try {
            logger.debug("Decoding COSE_Key from CBOR, size: {} bytes", cborData.length);
            Object decoded = Cbor.decode(cborData);
            
            if (!(decoded instanceof Map)) {
                throw new CoseException("COSE_Key must be a CBOR map, got: "
                        + decoded.getClass().getSimpleName());
            }
            
            // Convert to Map<Integer, Object>
            Map<?, ?> rawMap = (Map<?, ?>) decoded;
            Map<Integer, Object> coseKey = new HashMap<>();
            for (Map.Entry<?, ?> entry : rawMap.entrySet()) {
                if (entry.getKey() instanceof Number) {
                    coseKey.put(((Number) entry.getKey()).intValue(), entry.getValue());
                }
            }
            
            logger.debug("COSE_Key decoded successfully");
            return coseKey;
            
        } catch (CoseException e) {
            throw e;
        } catch (Exception e) {
            throw new CoseException("Failed to decode COSE_Key", e);
        }
    }
    
    /**
     * Normalizes a coordinate byte array to exactly 32 bytes.
     * Removes leading zero byte if present (from BigInteger sign byte),
     * or pads with leading zeros if too short.
     *
     * @param bytes the coordinate bytes
     * @return normalized 32-byte array
     */
    private static byte[] normalizeCoordinate(byte[] bytes) {
        if (bytes.length == 32) {
            return bytes;
        } else if (bytes.length == 33 && bytes[0] == 0) {
            // Remove sign byte
            byte[] result = new byte[32];
            System.arraycopy(bytes, 1, result, 0, 32);
            return result;
        } else if (bytes.length < 32) {
            // Pad with leading zeros
            byte[] result = new byte[32];
            System.arraycopy(bytes, 0, result, 32 - bytes.length, bytes.length);
            return result;
        } else {
            throw new IllegalArgumentException("Coordinate too large: " + bytes.length + " bytes");
        }
    }
    
    /**
     * Gets the EC parameter specification for the P-256 curve (secp256r1).
     * This is needed for creating EC keys from coordinates.
     *
     * @return the P-256 EC parameter specification
     * @throws CoseException if the parameter spec cannot be obtained
     */
    private static ECParameterSpec getP256ParameterSpec() throws CoseException {
        try {
            // Generate a temporary P-256 key to get the parameter spec
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair tempKeyPair = keyGen.generateKeyPair();
            ECPublicKey tempPublicKey = (ECPublicKey) tempKeyPair.getPublic();
            return tempPublicKey.getParams();
        } catch (Exception e) {
            throw new CoseException("Failed to get P-256 parameter spec", e);
        }
    }
}

// Made with Bob
