/*
 *Copyright IBM 2025, 2026
/*IBM Confidential
* OCO Source Materials
* 5725-V89 5725-V90
*
* Copyright IBM Corp. 2019, 2025
*
* The source code for this program is not published or otherwise divested of its trade secrets,
* irrespective of what has been deposited with the U.S. Copyright Office.
*/
package com.isfs.blekey.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Provider;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KeyUtils {

    private static final Logger logger = LoggerFactory.getLogger(KeyUtils.class);
    
    private static final String BOUNCY_CASTLE_PROVIDER_NAME = "BC";
    
    // Add the BouncyCastle provider once when the class is loaded
    static {
        final Provider provider = Security.getProvider(BOUNCY_CASTLE_PROVIDER_NAME);
        // Android registers its own BC provider. As it might be outdated and might not include
        // all needed ciphers, we substitute it with a known BC bundled in the app.
        // Android's BC has its package rewritten to "com.android.org.bouncycastle" and because
        // of that it's possible to have another BC implementation loaded in VM.
        if (provider == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        } else if (!provider.getClass().equals(BouncyCastleProvider.class)) {
            Security.removeProvider(BOUNCY_CASTLE_PROVIDER_NAME);
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
    }
    
    // Ensure BouncyCastle provider is registered and at position 1 for priority
    public static void ensureBouncyCastleProvider() {
        final Provider provider = Security.getProvider(BOUNCY_CASTLE_PROVIDER_NAME);
        // Android registers its own BC provider. As it might be outdated and might not include
        // all needed ciphers, we substitute it with a known BC bundled in the app.
        // Android's BC has its package rewritten to "com.android.org.bouncycastle" and because
        // of that it's possible to have another BC implementation loaded in VM.
        if (provider == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        } else if (!provider.getClass().equals(BouncyCastleProvider.class)) {
            Security.removeProvider(BOUNCY_CASTLE_PROVIDER_NAME);
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
    }
    
    // COSE Key Common Parameters
    private static final int COSE_KEY_KTY = 1;  // Key Type
    private static final int COSE_KEY_ALG = 3;  // Algorithm

    // COSE Key Types
    private static final int COSE_KEY_TYPE_OKP = 1;  // Octet Key Pair (for Ed25519)
    private static final int COSE_KEY_TYPE_EC2 = 2;  // Elliptic Curve Keys
    private static final int COSE_KEY_TYPE_RSA = 3;  // RSA Keys
    
    // Exception Messages
    private static final String ERROR_INVALID_OKP_KEY = "Invalid COSE OKP key: missing required parameters";
    private static final String ERROR_UNSUPPORTED_OKP_CURVE = "Unsupported OKP curve: ";
    private static final String ERROR_UNSUPPORTED_OKP_ALGORITHM = "Unsupported OKP algorithm: ";
    private static final String ERROR_INVALID_EC_KEY = "Invalid COSE EC key: missing required parameters";
    private static final String ERROR_UNSUPPORTED_EC_CURVE = "Unsupported curve: ";
    private static final String ERROR_UNSUPPORTED_EC_ALGORITHM = "Unsupported EC algorithm: ";

    // Algorithm Constants
    private static final String EC_ALGORITHM = "ECDSA";
    private static final String RSA_ALGORITHM = "RSA";
    private static final String ED25519_ALGORITHM = "Ed25519";
    private static final String EDDSA_ALGORITHM = "EdDSA";

    // COSE Elliptic Curve Parameters
    private static final int COSE_EC_CRV = -1;  // Curve
    private static final int COSE_EC_X = -2;    // X Coordinate
    private static final int COSE_EC_Y = -3;    // Y Coordinate
    private static final int COSE_EC_CRV_P256 = 1;  // P-256 Curve
    private static final int COSE_EC_CRV_P384 = 2; // P-384 Curve
    private static final int COSE_EC_CRV_P521 = 3; // P-521 Curve
    
    // Map of COSE curve identifiers to standard curve names
    private static final Map<Integer, String> COSE_CURVE_TO_STD_NAME = Map.of(
        COSE_EC_CRV_P256, "secp256r1",
        COSE_EC_CRV_P384, "secp384r1",
        COSE_EC_CRV_P521, "secp521r1"
    );

    // COSE RSA Parameters
    private static final int COSE_RSA_N = -1;  // Modulus
    private static final int COSE_RSA_E = -2;  // Exponent

    // COSE OKP (Ed25519) Parameters
    private static final int COSE_OKP_CRV = -1;  // Curve
    private static final int COSE_OKP_X = -2;    // Public Key
    private static final int COSE_OKP_CRV_ED25519 = 6;  // Ed25519 Curve

    // COSE Algorithms
    private static final int COSE_ALG_EDDSA = -8;    // EdDSA
    private static final int COSE_ALG_ES256 = -7;    // ECDSA with SHA-256
    private static final int COSE_ALG_ECDH_ES_HKDF_256 = -25; // ECDH with SHA-256
    private static final int COSE_ALG_RS256 = -257;  // RSASSA-PKCS1-v1_5 with SHA-256
    
    private KeyUtils() { }
    
    public static KeyPair getKeyPair(String alg) {
        // Ensure BouncyCastle is available
        ensureBouncyCastleProvider();
        try {
            if (RSA_ALGORITHM.equals(alg)) {
                return getRSAKeyPair();
            }
            else if (EC_ALGORITHM.equals(alg)) {
                return getECKeyPair();
            }
            else if (ED25519_ALGORITHM.equals(alg)) {
                return getE25519KeyPair();
            }
        } catch (Exception e) {
            logger.error("Error generating key pair: " + e.getMessage(), e);
        }
        return null;
    }

    /**
    * Converts a public key to a COSE key format.
    * Supports EC P256, RSA, and Ed25519 keys.
    *
    * @param pubkey The public key to convert
    * @return A map containing the COSE key parameters
    * @throws IllegalArgumentException if the public key is null
    * @throws UnsupportedOperationException if the key type is not supported
    */
   public static Map<Integer, Object> toCoseKey(PublicKey pubkey) {
       return toCoseKey(pubkey, null);
   }
   
   /**
    * Converts a public key to a COSE key format with a specified algorithm.
    * Supports EC P256, RSA, and Ed25519 keys.
    * 
    * The algorithm is used to allow for switching between EC and ECDH COSE keys. This
    * is requried from the platform key exchange as part of the pin auth algorithm.
    *
    * @param pubkey The public key to convert
    * @param algorithm Optional algorithm to use for the key (can be null for default)
    * @return A map containing the COSE key parameters
    * @throws IllegalArgumentException if the public key is null
    * @throws UnsupportedOperationException if the key type is not supported
    */
   public static Map<Integer, Object> toCoseKey(PublicKey pubkey, Integer algorithm) {
       if (pubkey == null) {
           throw new IllegalArgumentException("Public key cannot be null");
       }
       
       if (pubkey instanceof ECPublicKey) {
           return createCoseEcKey((ECPublicKey) pubkey, algorithm);
       } else if (pubkey instanceof RSAPublicKey) {
           return createCoseRsaKey((RSAPublicKey) pubkey);
       } else if ("EdDSA".equals(pubkey.getAlgorithm()) ||
                  pubkey.getClass().getName().contains("Ed25519")) {
           return createCoseEd25519Key(pubkey);
       }
       logger.error("NO COSE KEY FOR " + pubkey);
       logger.error(pubkey.getAlgorithm());
       logger.error(pubkey.getClass().getCanonicalName());
       throw new UnsupportedOperationException(
           "Unsupported key type: " + pubkey.getClass().getName());
   }
   
   /**
    * Creates a COSE key representation of an EC public key with a specified algorithm.
    * Currently supports P-256 curve only.
    *
    * @param ecKey The EC public key
    * @param algorithm Optional algorithm to use (COSE_ALG_ES256 or COSE_ALG_ECDH_ES_HKDF_256)
    * @return A map containing the COSE key parameters
    */
   private static Map<Integer, Object> createCoseEcKey(ECPublicKey ecKey, Integer algorithm) {
       Map<Integer, Object> coseKey = new HashMap<>();
       ECPoint point = ecKey.getW();
       
       // COSE key parameters for EC P256 key
       coseKey.put(COSE_KEY_KTY, COSE_KEY_TYPE_EC2);
       
       // Set algorithm based on parameter or default to ES256
       if (algorithm != null) {
           coseKey.put(COSE_KEY_ALG, algorithm);
       } else {
           coseKey.put(COSE_KEY_ALG, COSE_ALG_ES256);
       }
       
       coseKey.put(COSE_EC_CRV, COSE_EC_CRV_P256);
       
       // Extract x and y coordinates as byte arrays
       byte[] xBytes = point.getAffineX().toByteArray();
       byte[] yBytes = point.getAffineY().toByteArray();
       
       // Ensure coordinates are exactly 32 bytes (P-256 field size)
       byte[] x = normalizeCoordinate(xBytes, 32);
       byte[] y = normalizeCoordinate(yBytes, 32);
       
       coseKey.put(COSE_EC_X, x); // x-coordinate
       coseKey.put(COSE_EC_Y, y); // y-coordinate
       
       return coseKey;
   }
   
   /**
    * Creates a COSE key representation of an RSA public key.
    *
    * @param rsaKey The RSA public key
    * @return A map containing the COSE key parameters
    */
   private static Map<Integer, Object> createCoseRsaKey(RSAPublicKey rsaKey) {
       Map<Integer, Object> coseKey = new HashMap<>();
       
       // COSE key parameters for RSA key
       coseKey.put(COSE_KEY_KTY, COSE_KEY_TYPE_RSA);
       coseKey.put(COSE_KEY_ALG, COSE_ALG_RS256);
       
       // Extract modulus and exponent
       byte[] nBytes = rsaKey.getModulus().toByteArray();
       byte[] eBytes = rsaKey.getPublicExponent().toByteArray();
       
       // Remove leading zero if present (due to BigInteger sign bit)
       nBytes = removeLeadingZero(nBytes);
       eBytes = removeLeadingZero(eBytes);
       
       coseKey.put(COSE_RSA_N, nBytes); // n: modulus
       coseKey.put(COSE_RSA_E, eBytes); // e: exponent
       
       return coseKey;
   }
   
   /**
    * Creates a COSE key representation of an Ed25519 public key.
    *
    * @param pubkey The Ed25519 public key
    * @return A map containing the COSE key parameters
    */
   private static Map<Integer, Object> createCoseEd25519Key(PublicKey pubkey) {
       Map<Integer, Object> coseKey = new HashMap<>();
       
       // COSE key parameters for Ed25519 key
       coseKey.put(COSE_KEY_KTY, COSE_KEY_TYPE_OKP);
       coseKey.put(COSE_KEY_ALG, COSE_ALG_EDDSA);
       coseKey.put(COSE_OKP_CRV, COSE_OKP_CRV_ED25519);
       
       // Extract public key bytes
       byte[] pubKeyBytes = pubkey.getEncoded();
       byte[] x = extractEd25519PublicKeyBytes(pubKeyBytes);
       
       coseKey.put(COSE_OKP_X, x); // x: public key
       
       return coseKey;
   }
   
   /**
    * Normalizes a coordinate to the specified length.
    * Handles potential leading zeros or extra length.
    *
    * @param coordinate The coordinate as a byte array
    * @param targetLength The desired length of the result
    * @return A byte array of the specified length
    */
   private static byte[] normalizeCoordinate(byte[] coordinate, int targetLength) {
       byte[] result = new byte[targetLength];
       
       System.arraycopy(
           coordinate, Math.max(0, coordinate.length - targetLength),
           result, Math.max(0, targetLength - coordinate.length),
           Math.min(targetLength, coordinate.length)
       );
       
       return result;
   }
   
   /**
    * Removes a leading zero byte if present and the array has more than one byte.
    * This is needed because BigInteger.toByteArray() may include a leading zero
    * for the sign bit.
    *
    * @param data The input byte array
    * @return The byte array with leading zero removed if applicable
    */
   private static byte[] removeLeadingZero(byte[] data) {
       if (data[0] == 0 && data.length > 1) {
           byte[] result = new byte[data.length - 1];
           System.arraycopy(data, 1, result, 0, result.length);
           return result;
       }
       return data;
   }
    
    /**
     * Extracts the raw Ed25519 public key bytes from an encoded public key.
     * This is a simplified implementation and may need to be adjusted based on the actual encoding.
     *
     * @param encodedKey The encoded public key
     * @return The raw public key bytes
     */
    private static byte[] extractEd25519PublicKeyBytes(byte[] encodedKey) {
        // This is a simplified approach to extract Ed25519 public key bytes
        // The actual implementation depends on how Ed25519 keys are encoded in your system
        
        // For many implementations, the last 32 bytes of the encoded key are the actual key material
        if (encodedKey.length >= 32) {
            byte[] result = new byte[32];
            System.arraycopy(encodedKey, encodedKey.length - 32, result, 0, 32);
            return result;
        }
        
        return encodedKey; // Return as-is if we can't determine the format
    }

    /**
     * Converts a COSE key to a Java PublicKey.
     * Supports EC P256, RSA, and Ed25519 keys.
     *
     * @param coseKey The COSE key map
     * @return The corresponding PublicKey
     * @throws RuntimeException if the key cannot be created
     */
    public static PublicKey fromCoseKey(Map<Integer, Object> coseKey) {
        try {
            // Get key type
            Integer kty = (Integer) coseKey.get(COSE_KEY_KTY);
            if (kty == null) {
                throw new IllegalArgumentException("Invalid COSE key: missing key type");
            }
            
            // Handle different key types
            switch (kty) {
                case COSE_KEY_TYPE_EC2: // EC key
                    return fromCoseEcKey(coseKey);
                case COSE_KEY_TYPE_RSA: // RSA key
                    return fromCoseRsaKey(coseKey);
                case COSE_KEY_TYPE_OKP: // OKP key (Ed25519)
                    return fromCoseOkpKey(coseKey);
                default:
                    throw new IllegalArgumentException("Unsupported key type: " + kty);
            }
        } catch (Exception e) {
            throw new RuntimeException("Error creating public key from COSE key", e);
        }
    }
    
    /**
     * Validates a COSE EC key map to ensure it contains all required parameters
     * and has supported curve and algorithm values.
     *
     * @param coseKey The COSE key map to validate
     * @throws IllegalArgumentException if the key is invalid or contains unsupported values
     */
    private static void validateCoseEcKey(Map<Integer, Object> coseKey) throws IllegalArgumentException {
       // Extract curve and coordinates
       Integer crv = (Integer) coseKey.get(COSE_EC_CRV);
       byte[] x = (byte[]) coseKey.get(COSE_EC_X);
       byte[] y = (byte[]) coseKey.get(COSE_EC_Y);
       
       if (crv == null || x == null || y == null) {
           throw new IllegalArgumentException(ERROR_INVALID_EC_KEY);
       }
       
       // Check if curve is supported
       if (!COSE_CURVE_TO_STD_NAME.containsKey(crv)) {
           throw new IllegalArgumentException(ERROR_UNSUPPORTED_EC_CURVE + crv);
       }
       
       // Check algorithm if present (optional)
       Integer alg = (Integer) coseKey.get(COSE_KEY_ALG);
       if (alg != null && alg != COSE_ALG_ES256 && alg != COSE_ALG_ECDH_ES_HKDF_256) {
           throw new IllegalArgumentException(ERROR_UNSUPPORTED_EC_ALGORITHM + alg);
       }
    }
    
    /**
     * Creates an ECPoint from x and y coordinates provided as byte arrays.
     *
     * @param x The x-coordinate as a byte array
     * @param y The y-coordinate as a byte array
     * @return The ECPoint representing the coordinates
     */
    private static ECPoint createECPoint(byte[] x, byte[] y) {
       BigInteger xBi = new BigInteger(1, x);
       BigInteger yBi = new BigInteger(1, y);
       return new ECPoint(xBi, yBi);
    }
    
    /**
     * Creates an ECParameterSpec for the specified curve name.
     *
     * @param curveName The standard curve name (e.g., "secp256r1")
     * @return The ECParameterSpec for the curve
     * @throws Exception if the parameters cannot be created
     */
    private static ECParameterSpec createECParameterSpec(String curveName) throws Exception {
       AlgorithmParameters parameters = AlgorithmParameters.getInstance(EC_ALGORITHM);
       parameters.init(new ECGenParameterSpec(curveName));
       return parameters.getParameterSpec(ECParameterSpec.class);
    }
    
    /**
     * Converts a COSE EC key to a Java ECPublicKey.
     *
     * @param coseKey The COSE key map
     * @return The corresponding ECPublicKey
     * @throws Exception if the key cannot be created
     */
    private static PublicKey fromCoseEcKey(Map<Integer, Object> coseKey) throws Exception {
       // Validate the COSE key
       validateCoseEcKey(coseKey);
       
       // Extract curve and coordinates
       Integer crv = (Integer) coseKey.get(COSE_EC_CRV);
       byte[] x = (byte[]) coseKey.get(COSE_EC_X);
       byte[] y = (byte[]) coseKey.get(COSE_EC_Y);
       
       // Get standard curve name from map
       String curveName = COSE_CURVE_TO_STD_NAME.get(crv);
       
       // Create EC point from coordinates
       ECPoint point = createECPoint(x, y);
       
       // Get EC parameters
       ECParameterSpec ecParams = createECParameterSpec(curveName);
       
       // Create key spec and generate public key
       ECPublicKeySpec keySpec = new ECPublicKeySpec(point, ecParams);
       KeyFactory keyFactory = KeyFactory.getInstance(EC_ALGORITHM);
       return keyFactory.generatePublic(keySpec);
    }
    
    /**
     * Converts a COSE RSA key to a Java RSAPublicKey.
     *
     * @param coseKey The COSE key map
     * @return The corresponding RSAPublicKey
     * @throws Exception if the key cannot be created
     */
    private static PublicKey fromCoseRsaKey(Map<Integer, Object> coseKey) throws Exception {
        // Extract modulus and exponent
        byte[] n = (byte[]) coseKey.get(COSE_RSA_N);
        byte[] e = (byte[]) coseKey.get(COSE_RSA_E);
        
        if (n == null || e == null) {
            throw new IllegalArgumentException("Invalid COSE RSA key: missing required parameters");
        }
        
        // Check algorithm if present (optional)
        Integer alg = (Integer) coseKey.get(COSE_KEY_ALG);
        if (alg != null && alg != COSE_ALG_RS256) {
            throw new IllegalArgumentException("Unsupported RSA algorithm: " + alg);
        }
        
        // Convert byte arrays to BigIntegers
        BigInteger modulus = new BigInteger(1, n);
        BigInteger exponent = new BigInteger(1, e);
        
        // Create key spec
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
        
        // Generate public key
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }
    
    /**
     * Converts a COSE OKP key to a Java Ed25519PublicKey.
     *
     * @param coseKey The COSE key map
     * @return The corresponding Ed25519PublicKey
     * @throws Exception if the key cannot be created
     */
    private static PublicKey fromCoseOkpKey(Map<Integer, Object> coseKey) throws Exception {
        // Extract and validate parameters
        Integer crv = (Integer) coseKey.get(COSE_OKP_CRV);
        byte[] x = (byte[]) coseKey.get(COSE_OKP_X);
        
        validateOkpParameters(crv, x);
        validateOkpAlgorithm(coseKey);
        
        // Create Ed25519 public key
        return createEd25519Key(x);
    }
    
    /**
     * Validates the parameters for an OKP key.
     *
     * @param crv The curve parameter
     * @param x The public key bytes
     * @throws IllegalArgumentException if parameters are invalid
     */
    private static void validateOkpParameters(Integer crv, byte[] x) {
        if (crv == null || x == null) {
            throw new IllegalArgumentException(ERROR_INVALID_OKP_KEY);
        }
        
        // Check if it's Ed25519
        if (crv != COSE_OKP_CRV_ED25519) {
            throw new IllegalArgumentException(ERROR_UNSUPPORTED_OKP_CURVE + crv);
        }
    }
    
    /**
     * Validates the algorithm for an OKP key if present.
     *
     * @param coseKey The COSE key map
     * @throws IllegalArgumentException if the algorithm is unsupported
     */
    private static void validateOkpAlgorithm(Map<Integer, Object> coseKey) {
        Integer alg = (Integer) coseKey.get(COSE_KEY_ALG);
        if (alg != null && alg != COSE_ALG_EDDSA) {
            throw new IllegalArgumentException(ERROR_UNSUPPORTED_OKP_ALGORITHM + alg);
        }
    }

    
    /**
     * Creates an Ed25519 public key using Bouncy Castle.
     *
     * @param publicKeyBytes The raw public key bytes
     * @return The Ed25519 public key
     * @throws Exception if the key cannot be created
     */
    private static PublicKey createEd25519Key(byte[] publicKeyBytes) throws Exception {
        // Ensure BouncyCastle is available for Ed25519 operations
        ensureBouncyCastleProvider();
        try {
            // Create an Ed25519 public key parameters object from the raw bytes
            Ed25519PublicKeyParameters pubKeyParams = new Ed25519PublicKeyParameters(publicKeyBytes, 0);
            // Convert to SubjectPublicKeyInfo format
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pubKeyParams);
            // Convert to X.509 encoded format
            byte[] encodedKey = spki.getEncoded();
            // Create a public key from the encoded format
            KeyFactory keyFactory = KeyFactory.getInstance(EDDSA_ALGORITHM);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create Ed25519 key using Bouncy Castle: " + e.getMessage(), e);
        }
    }

    /**
     * Decapsulates a shared secret using ECDH key agreement.
     *
     * @param theirKey The public key of the other party
     * @param myKey The private key of this party
     * @return The shared secret as a byte array, or null if the operation fails
     */
    public static byte[] decapsulate(PublicKey theirKey, PrivateKey myKey) {
        try {
            if (!(theirKey instanceof java.security.interfaces.ECPublicKey) ||
                !(myKey instanceof java.security.interfaces.ECPrivateKey)) {
                throw new IllegalArgumentException("Keys must be EC keys for ECDH");
            }
            
            java.security.interfaces.ECPublicKey ecPublicKey = (java.security.interfaces.ECPublicKey) theirKey;
            java.security.interfaces.ECPrivateKey ecPrivateKey = (java.security.interfaces.ECPrivateKey) myKey;
            
            // Get the public key point
            java.security.spec.ECPoint publicPoint = ecPublicKey.getW();
            
            // Get the private key scalar
            java.math.BigInteger privateScalar = ecPrivateKey.getS();
            
            // Perform scalar multiplication: privateScalar * publicPoint
            java.security.spec.ECPoint sharedPoint = scalmult(
                    ecPublicKey.getParams().getCurve(),
                    publicPoint,
                    privateScalar);
            
            // Use the x-coordinate of the shared point as the shared secret
            byte[] sharedX = sharedPoint.getAffineX().toByteArray();
            
            // Hash the shared secret to derive the AES key
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            return digest.digest(sharedX);
        } catch (Exception e) {
            // Log the error and return null
            System.err.println("Error decapsulating shared secret: " + e.getMessage());
            return null;
        }
    }

    /**
     * Reads a private key from raw bytes
     *
     * @param raw Raw key bytes in PKCS8 format
     * @param alg Algorithm name (e.g., "EC", "RSA")
     * @return The private key
     * @throws NoSuchAlgorithmException If the algorithm is not available
     * @throws InvalidKeySpecException If the key specification is invalid
     */
    public static PrivateKey getPrivate(byte[] raw, String alg)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory kf = KeyFactory.getInstance(alg);
        return kf.generatePrivate(new PKCS8EncodedKeySpec(raw));
    }


    public static PublicKey getPublic(byte[] raw, String alg) 
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        KeyFactory kf = KeyFactory.getInstance(alg);
        return kf.generatePublic(new X509EncodedKeySpec(raw));
    }

    private static class FieldP {
        final static BigInteger _2 = BigInteger.valueOf(2);
        final static BigInteger _3 = BigInteger.valueOf(3);
    }

    private static ECPoint doublePoint(final BigInteger p, final BigInteger a,
            final ECPoint R) {
        if (R.equals(ECPoint.POINT_INFINITY)) {
            return R;
        }
        BigInteger slope = (R.getAffineX().pow(2)).multiply(FieldP._3);
        slope = slope.add(a);
        slope = slope.multiply((R.getAffineY().multiply(FieldP._2)).modInverse(p));
        final BigInteger Xout = slope.pow(2).subtract(R.getAffineX().multiply(FieldP._2))
                .mod(p);
        final BigInteger Yout = (R.getAffineY().negate())
                .add(slope.multiply(R.getAffineX().subtract(Xout))).mod(p);
        return new ECPoint(Xout, Yout);
    }

    private static ECPoint addPoint(final BigInteger p, final BigInteger a, final ECPoint r,
            final ECPoint g) {
        if (r.equals(ECPoint.POINT_INFINITY)) {
            return g;
        }
        if (g.equals(ECPoint.POINT_INFINITY)) {
            return r;
        }
        if (r == g || r.equals(g)) {
            return doublePoint(p, a, r);
        }
        final BigInteger gX = g.getAffineX();
        final BigInteger sY = g.getAffineY();
        final BigInteger rX = r.getAffineX();
        final BigInteger rY = r.getAffineY();
        final BigInteger slope = (rY.subtract(sY)).multiply(rX.subtract(gX).modInverse(p))
                .mod(p);
        final BigInteger Xout = (slope.modPow(FieldP._2, p).subtract(rX)).subtract(gX).mod(p);
        BigInteger Yout = sY.negate().mod(p);
        Yout = Yout.add(slope.multiply(gX.subtract(Xout))).mod(p);
        return new ECPoint(Xout, Yout);
    }

    public static ECPoint scalmult(final EllipticCurve curve, final ECPoint g,
            final BigInteger kin) {
        final ECField field = curve.getField();
        if (!(field instanceof ECFieldFp)) {
            throw new UnsupportedOperationException(field.getClass().getCanonicalName());
        }
        final BigInteger p = ((ECFieldFp) field).getP();
        final BigInteger a = curve.getA();
        ECPoint R = ECPoint.POINT_INFINITY;
        BigInteger k = kin.mod(p);
        final int length = k.bitLength();
        final byte[] binarray = new byte[length];
        for (int i = 0; i <= length - 1; i++) {
            binarray[i] = k.mod(FieldP._2).byteValue();
            k = k.shiftRight(1);
        }
        for (int i = length - 1; i >= 0; i--) {
            R = doublePoint(p, a, R);
            if (binarray[i] == 1) {
                R = addPoint(p, a, R, g);
            }
        }
        return R;
    }

    public static ECPublicKey getPubKey(final ECPrivateKey pk)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        ECParameterSpec spec = pk.getParams();
        ECPoint w = scalmult(spec.getCurve(), pk.getParams().getGenerator(), pk.getS());
        KeyFactory kf = KeyFactory.getInstance("EC");
        return (ECPublicKey) kf.generatePublic(new ECPublicKeySpec(w, spec));
    }

    public static RSAPublicKey getPubKey(final RSAPrivateCrtKey pk)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        RSAPublicKeySpec spec = new RSAPublicKeySpec(pk.getModulus(), pk.getPublicExponent());
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) kf.generatePublic(spec);
    }

    public static PrivateKey generatePrivate(String alg, int keySize)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        return generateKeyPair(alg, keySize).getPrivate();
    }
    
    
    private static KeyPair getRSAKeyPair() throws Exception {
        return generateKeyPair(RSA_ALGORITHM, 2048);
    }
    
    
    private static KeyPair getECKeyPair() throws Exception {
        return generateKeyPair(EC_ALGORITHM, 521);
    }
    
    
    private static KeyPair getE25519KeyPair() throws Exception {
        // Ed25519 has a fixed key size, so don't pass a size parameter
        // Ensure BouncyCastle is available for Ed25519
        ensureBouncyCastleProvider();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(ED25519_ALGORITHM);
        return kpg.generateKeyPair();
    }

    public static KeyPair generateKeyPair(String alg, int keySize)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        // Ensure BouncyCastle is available for specialized curves
        ensureBouncyCastleProvider();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg, BOUNCY_CASTLE_PROVIDER_NAME);
        kpg.initialize(keySize);
        return kpg.genKeyPair();
    }

    public static KeyPair getCAKeyPair(String alg) 
            throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, NoSuchProviderException {
        PrivateKey privateKey = null;
        PublicKey publicKey = null;
        if (EC_ALGORITHM.equals(alg)) {
            privateKey = generatePrivate(alg, 256);
            publicKey = getPubKey((ECPrivateKey) privateKey);
        }
        else if (RSA_ALGORITHM.equals(alg)) {
            privateKey = generatePrivate(alg, 2048);
            publicKey =  getPubKey((RSAPrivateCrtKey) privateKey);
        }
        else {
            throw new NoSuchAlgorithmException(String.format("Invalid alg:  %s", alg));
        }
        return new KeyPair(publicKey, privateKey);      
    }

    /**
     * Creates and initializes an AES-GCM cipher for encryption or decryption.
     *
     * @param sharedSecret The shared secret key (32 bytes for AES-256)
     * @param iv The initialization vector (16 bytes)
     * @param mode Cipher mode (Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE)
     * @return Initialized cipher instance
     * @throws NoSuchAlgorithmException if AES/GCM is not available
     * @throws NoSuchPaddingException if padding scheme is not available
     * @throws InvalidKeyException if the key is invalid
     * @throws InvalidAlgorithmParameterException if GCM parameters are invalid
     */
    private static Cipher getAESCipher(byte[] sharedSecret, byte[] iv, int mode)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
                   InvalidKeyException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(sharedSecret, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv); // 128-bit auth tag
        cipher.init(mode, keySpec, gcmSpec);
        return cipher;
    }

    /**
     * Converts a PEM-encoded public key to a PublicKey object.
     *
     * @param pemBytes The PEM-encoded public key bytes
     * @return The PublicKey object
     * @throws Exception if conversion fails
     */
    private static PublicKey pemToPublicKey(byte[] pemBytes) throws Exception {
        String pemString = new String(pemBytes, java.nio.charset.StandardCharsets.UTF_8);
        // Remove PEM headers and decode base64
        String base64Key = pemString
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s", "");
        byte[] derBytes = java.util.Base64.getDecoder().decode(base64Key);
        
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(derBytes);
        return keyFactory.generatePublic(keySpec);
    }

    public static byte[] getPublicKeyBytes(ECPublicKey publicKey) throws IOException {
        // Convert to PEM format
        ByteArrayOutputStream pemOut = new ByteArrayOutputStream();
        try (java.io.OutputStreamWriter writer = new java.io.OutputStreamWriter(pemOut);
                org.bouncycastle.openssl.jcajce.JcaPEMWriter pemWriter =
                    new org.bouncycastle.openssl.jcajce.JcaPEMWriter(writer)) {
            pemWriter.writeObject(publicKey);
        }
        return pemOut.toByteArray();
    }

    /**
     * Encrypts plaintext using ECDH with the recipient's public key.
     *
     * This method:
     * 1. Generates an ephemeral EC P-256 key pair
     * 2. Performs ECDH key agreement with the recipient's public key
     * 3. Uses the derived shared secret to encrypt the plaintext with AES-GCM
     * 4. Returns the ciphertext along with the ephemeral public key
     *
     * @param plaintext The data to encrypt
     * @param recipient The recipient's public key
     * @return Encrypted data in format: [ephemeral public key bytes][IV][ciphertext][auth tag]
     * @throws RuntimeException if encryption fails
     */
    public static byte[] ecdhEncrypt(byte[] plaintext, PublicKey recipient) {
        try {
            ensureBouncyCastleProvider();
            
            // 1. Generate ephemeral EC P-256 key pair
            KeyPair ephemeralKeyPair = generateKeyPair("EC", 256);

            // 2. Perform ECDH key agreement
            byte[] sharedSecret = decapsulate(recipient, ephemeralKeyPair.getPrivate());
            if (sharedSecret == null || sharedSecret.length != 32) {
                throw new RuntimeException("Failed to derive shared secret");
            }
            
            // 3. Generate random IV (16 bytes to match Python)
            byte[] iv = new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            
            // 4. Encrypt plaintext using AES-256-GCM
            Cipher cipher = getAESCipher(sharedSecret, iv, Cipher.ENCRYPT_MODE);
            byte[] ciphertext = cipher.doFinal(plaintext);

            byte[] ephemeralPubKeyBytes = getPublicKeyBytes((ECPublicKey) ephemeralKeyPair.getPublic());
            
            // 6. Extract tag from ciphertext (last 16 bytes)
            byte[] actualCiphertext = Arrays.copyOfRange(ciphertext, 0, ciphertext.length - 16);
            byte[] tag = Arrays.copyOfRange(ciphertext, ciphertext.length - 16, ciphertext.length);
            
            // 7. Combine: [pub key len (4 bytes big endian)][pub key][IV][tag][ciphertext]
            ByteBuffer combined = ByteBuffer.allocate(
                    4 + ephemeralPubKeyBytes.length + iv.length + tag.length + actualCiphertext.length);
            combined.putInt(ephemeralPubKeyBytes.length); // Big endian by default
            combined.put(ephemeralPubKeyBytes);
            combined.put(iv);
            combined.put(tag);
            combined.put(actualCiphertext);
            
            return combined.array();
            
        } catch (Exception e) {
            throw new RuntimeException("ECDH encryption failed", e);
        }
    }

    private static void verifyDecryptInputs(byte[] ciphertext, PrivateKey key) {
        // For P-256: 4 (length) + 178 (PEM key) + 16 (IV) + 16 (tag) + 1 (min ciphertext) = 215
        // Minimum is 1 byte plaintext (e.g., empty CBOR list)
        final int MIN_CIPHERTEXT_SIZE = 215;
        if (ciphertext == null || ciphertext.length < MIN_CIPHERTEXT_SIZE) {
            throw new IllegalArgumentException(
                "Ciphertext too short: expected at least " + MIN_CIPHERTEXT_SIZE +
                " bytes, got " + (ciphertext == null ? "null" : ciphertext.length));
        }
        if (key == null) {
            throw new IllegalArgumentException("Key cannot be null");
        }
    }

    private static byte[] extractAndDecrypt(ByteBuffer buffer, PublicKey sender, 
            PrivateKey recipient) throws GeneralSecurityException {
        // Extract IV (16 bytes)
        byte[] iv = new byte[16];
        buffer.get(iv);
        
        // Extract authentication tag (16 bytes)
        byte[] tag = new byte[16];
        buffer.get(tag);
        
        // Extract ciphertext (remaining bytes)
        byte[] encryptedData = new byte[buffer.remaining()];
        buffer.get(encryptedData);
        
        // 2. Perform ECDH key agreement using existing decapsulate method
        byte[] sharedSecret = decapsulate(sender, recipient);
        if (sharedSecret == null) {
            throw new RuntimeException("Failed to derive shared secret");
        }
        
        // 3. Combine ciphertext and tag for GCM (tag must be at the end)
        byte[] ciphertextWithTag = new byte[encryptedData.length + tag.length];
        System.arraycopy(encryptedData, 0, ciphertextWithTag, 0, encryptedData.length);
        System.arraycopy(tag, 0, ciphertextWithTag, encryptedData.length, tag.length);
        
        // 4. Decrypt ciphertext using AES-GCM
        Cipher cipher = getAESCipher(sharedSecret, iv, Cipher.DECRYPT_MODE);
        return cipher.doFinal(ciphertextWithTag);
    }

    /**
     * Decrypts ciphertext using ECDH with the recipient's private key.
     *
     * This method:
     * 1. Extracts the ephemeral public key from the ciphertext (PEM format)
     * 2. Performs ECDH key agreement with the recipient's private key
     * 3. Uses the derived shared secret to decrypt the ciphertext with AES-GCM
     * 4. Returns the plaintext
     *
     * Format: [4 bytes length (big endian)][PEM public key][16 bytes IV][16 bytes tag][ciphertext]
     *
     * @param ciphertext The encrypted data
     * @param recipient The recipient's private key
     * @return The decrypted plaintext
     * @throws RuntimeException if decryption fails
     */
    public static byte[] ecdhDecrypt(byte[] ciphertext, PrivateKey recipient) {
        verifyDecryptInputs(ciphertext, recipient);
        
        try {
            // 1. Extract components from ciphertext
            ByteBuffer buffer = ByteBuffer.wrap(ciphertext);
            
            // Extract ephemeral public key length (4 bytes, big endian)
            int pubKeyLength = buffer.getInt();
            // P-256 public key in PEM format is exactly 178 bytes
            final int EXPECTED_P256_PEM_SIZE = 178;
            if (pubKeyLength != EXPECTED_P256_PEM_SIZE) {
                throw new IllegalArgumentException(
                    "Invalid P-256 public key length: expected " + EXPECTED_P256_PEM_SIZE +
                    ", got " + pubKeyLength);
            }
            
            // Validate remaining buffer size
            if (buffer.remaining() < pubKeyLength + 32) { // 32 = 16 (IV) + 16 (tag)
                throw new IllegalArgumentException(
                    "Ciphertext too short for declared public key length");
            }
            
            byte[] ephemeralPubKeyPem = new byte[pubKeyLength];
            buffer.get(ephemeralPubKeyPem);
            
            // Convert PEM to public key
            PublicKey ephemeralPubKey = pemToPublicKey(ephemeralPubKeyPem);
            
            return extractAndDecrypt(buffer, ephemeralPubKey, recipient);
            
        } catch (Exception e) {
            throw new RuntimeException("ECDH decryption failed", e);
        }
    }

    public static ECPublicKey publicFromPrivate(final ECPrivateKey privateKey) throws Exception {
        ECParameterSpec params = privateKey.getParams();
        org.bouncycastle.jce.spec.ECParameterSpec bcSpec = org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util
            .convertSpec(params);
        org.bouncycastle.math.ec.ECPoint q = bcSpec.getG().multiply(privateKey.getS());
        org.bouncycastle.math.ec.ECPoint bcW = bcSpec.getCurve().decodePoint(q.getEncoded(false));
        ECPoint w = new ECPoint(
            bcW.getAffineXCoord().toBigInteger(),
            bcW.getAffineYCoord().toBigInteger());
        ECPublicKeySpec keySpec = new ECPublicKeySpec(w, tryFindNamedCurveSpec(params));
        return (ECPublicKey) KeyFactory
            .getInstance("EC", org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME)
            .generatePublic(keySpec);
    }

    @SuppressWarnings("unchecked")
    public static ECParameterSpec tryFindNamedCurveSpec(ECParameterSpec params) {
        org.bouncycastle.jce.spec.ECParameterSpec bcSpec
            = org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util.convertSpec(params);
        for (Object name : Collections.list(org.bouncycastle.jce.ECNamedCurveTable.getNames())) {
            org.bouncycastle.jce.spec.ECNamedCurveParameterSpec bcNamedSpec
                = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec((String) name);
            if (bcNamedSpec.getN().equals(bcSpec.getN())
                && bcNamedSpec.getH().equals(bcSpec.getH())
                && bcNamedSpec.getCurve().equals(bcSpec.getCurve())
                && bcNamedSpec.getG().equals(bcSpec.getG())) {
                return new org.bouncycastle.jce.spec.ECNamedCurveSpec(
                    bcNamedSpec.getName(),
                    bcNamedSpec.getCurve(),
                    bcNamedSpec.getG(),
                    bcNamedSpec.getN(),
                    bcNamedSpec.getH(),
                    bcNamedSpec.getSeed());
            }
        }
        return params;
    }

    /* PKCS12 */
    /**
     * Read a PKCS12 keystore from bytes.
     *
     * @param pkcs12Bytes The PKCS12 data as a byte array
     * @param pinHash The 32-byte SHA256 hash to use as the password (will be converted to char[])
     * @return The loaded KeyStore
     * @throws Exception if there's an error loading the PKCS12 keystore
     */
    public static KeyStore readPKCS12(byte[] pkcs12Bytes, byte[] pinHash) throws Exception {
        // Ensure BouncyCastle is available for PKCS12 operations
        ensureBouncyCastleProvider();
        
        // Convert pinHash to char[] using ISO-8859-1 for 1:1 byte-to-char mapping
        char[] nonce = new String(pinHash, StandardCharsets.ISO_8859_1).toCharArray();
        
        KeyStore keyStore = KeyStore.getInstance("PKCS12", BOUNCY_CASTLE_PROVIDER_NAME);
        
        try (InputStream is = new ByteArrayInputStream(pkcs12Bytes)) {
            keyStore.load(is, nonce);
        }

        return keyStore;
    }

    /**
     * Extract private key from a PKCS12 KeyStore.
     *
     * @param keyStore The KeyStore to extract from
     * @param alias The alias of the key entry
     * @param pinHash The 32-byte SHA256 hash to use as the password (will be converted to char[])
     * @return The private key
     * @throws Exception if there's an error extracting the key
     */
    public static PrivateKey getPrivateKeyFromPKCS12(KeyStore keyStore, String alias, byte[] pinHash) throws Exception {
        char[] nonce = new String(pinHash, StandardCharsets.ISO_8859_1).toCharArray();
        return (PrivateKey) keyStore.getKey(alias, nonce);
    }

    /**
     * Extract certificate from a PKCS12 KeyStore.
     *
     * @param keyStore The KeyStore to extract from
     * @param alias The alias of the certificate
     * @return The X509 certificate
     * @throws Exception if there's an error extracting the certificate
     */
    public static X509Certificate getCertificateFromPKCS12(KeyStore keyStore, String alias) throws Exception {
        return (X509Certificate) keyStore.getCertificate(alias);
    }

    /**
     * Get first key pair from a PKCS12 KeyStore (when you don't know the alias).
     *
     * @param keyStore The KeyStore to extract from
     * @param pinHash The 32-byte SHA256 hash to use as the password (will be converted to char[])
     * @return The first key pair found
     * @throws Exception if there's an error or no key entries are found
     */
    public static KeyPair getFirstKeyPairFromPKCS12(KeyStore keyStore, byte[] pinHash) throws Exception {
        char[] nonce = new String(pinHash, StandardCharsets.ISO_8859_1).toCharArray();
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, nonce);
                X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
                return new KeyPair(cert.getPublicKey(), privateKey);
            }
        }
        throw new KeyStoreException("No key entries found in the PKCS12 file");
    }

    /**
     * Write a private key and certificate to PKCS12 format.
     * Creates a PKCS12 keystore with modern AES encryption compatible with OpenSSL 3.0+.
     *
     * @param key The private key to store
     * @param cert The certificate associated with the private key
     * @param pinHash The 32-byte SHA256 hash to use as the password (will be converted to char[])
     * @return The serialized PKCS12 data as a byte array
     * @throws Exception if there's an error creating or storing the PKCS12 keystore
     */
    public static byte[] writePKCS12(PrivateKey key, Certificate cert, byte[] pinHash) throws Exception {
        // Ensure BouncyCastle is available for PKCS12 operations
        ensureBouncyCastleProvider();
        
        // Convert pinHash to char[] by base64 encodign the pin hash before encoding charts to utf-8
        char[] password = Base64.getEncoder().encodeToString(pinHash).toCharArray();
        
        // Create a new PKCS12 KeyStore using BouncyCastle provider
        KeyStore keyStore = KeyStore.getInstance("PKCS12", BOUNCY_CASTLE_PROVIDER_NAME);
        keyStore.load(null, password);
        Certificate[] certChain = new Certificate[]{cert};
        // Using "1" as a simple default alias since no specific alias is required
        keyStore.setKeyEntry("1", key, password, certChain);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        keyStore.store(outputStream, password);
        
        return outputStream.toByteArray();
    }

    public static byte[] getPinHash(String pin) {
        try {
            // Hash the password using SHA-256
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] pinBytes = pin.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            return digest.digest(pinBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not supported", e);
        }
    }

    public static byte[] getLowerPinHash(String pin) {
        byte[] pinHash = getPinHash(pin);
        if(pinHash != null && pinHash.length >= 16) {
                        // Extract the lower 16 bytes of the hash
            byte[] lowerHash = new byte[16];
            System.arraycopy(pinHash, 0, lowerHash, 0, 16);
            return lowerHash;
        }
        return null;
    }

    public static String getPasskeySeed(byte[] entropy, PrivateKey key) {
        try {
            Signature signer = Signature.getInstance("ECDSAwithSHA256");
            signer.initSign(key);
            signer.update(entropy);
            byte[] sig = signer.sign();
            return Base64.getUrlEncoder().withoutPadding().encodeToString(Arrays.copyOfRange(sig, 0, 32));
        } catch (GeneralSecurityException e) {
            logger.error(e.getMessage(), e);
        }
        return null;
    }
    /**
     * Encrypts the data with app key (if available) ECDH.
     * This provides encryption for PIN hash caching:
     * - App key encryption for fast access (hardware-backed when available)
     *
     * @param plaintext The bytes to encrypt
     * @param keystoreManager The platform-specific keystore manager (may be null)
     * @return byte[] containing: [ciphertext]
     * @throws IOException if writing to the stream fails
     */
    public static byte[] ksmEncrypt(
            byte[] plaintext, 
            KeystoreManager keystoreManager) throws IOException {
        
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        
        // Encrypt upper hash with app key if available
        if (keystoreManager != null && keystoreManager.isKeystoreAvailable()) {
            try {
                bos.write(keystoreManager.encryptWithAppKey(plaintext));
                logger.debug("Encrypted plaintext with app key (length: {})", plaintext.length);
            } catch (Exception e) {
                logger.warn("Failed to encrypt with app key, writing zero length", e);
            }
        } else {
            logger.debug("KeystoreManager not available, skipping app key encryption");
        }
        return bos.toByteArray();
    }
    
    /**
     * Decrypts the data with the app key
     * This method reads the encrypted data.
     *
     * @param ciphertext The encrypted data
     * @param keystoreManager The platform-specific keystore manager (may be null)
     * @return Array containing [plaintext]
     * @throws Exception if decryption fails with both methods
     */
    public static byte[] ksmDecrypt(
            byte[] ciphertext,
            KeystoreManager keystoreManager) throws Exception {
        if (keystoreManager != null && keystoreManager.isKeystoreAvailable()) {
            try {
                return keystoreManager.decryptWithAppKey(ciphertext);
            } catch (Exception e) {
                logger.debug("App key decryption failed", e);
                return null;
            }
        }
        return null;
    }

    private static final String PLATFORM_KEY = "platform.key";

    public static PrivateKey getPlatformKey() {
        File platKeyFile = new File(FileUtils.getFido2Home() + File.separator + PLATFORM_KEY);
        try {
            if (!platKeyFile.exists()) {
                return FileUtils.readPrivatePEM(platKeyFile);
            }
        } catch (Exception e) {
            logger.error("Reading platform key failed", e);
        }
        return null;
    }
}