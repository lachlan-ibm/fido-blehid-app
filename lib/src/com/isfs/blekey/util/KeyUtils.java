/*
 * Copyright IBM 2025
 */
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
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
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
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCSException;

public class KeyUtils {
    
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

    // COSE Elliptic Curve Parameters
    private static final int COSE_EC_CRV = -1;  // Curve
    private static final int COSE_EC_X = -2;    // X Coordinate
    private static final int COSE_EC_Y = -3;    // Y Coordinate
    private static final int COSE_EC_CRV_P256 = 1;  // P-256 Curve

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
        try {
            if (alg == "RSA") {
                return getRSAKeyPair();
            }
            else if (alg == "EC") {
                return getECKeyPair();
            }
            else if (alg == "E25519") {
                return getE25519KeyPair();
            }
        } catch (Exception e) {
            //logging.error("Error generating key pair: " + e.getMessage());
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
       } else if ("Ed25519".equals(pubkey.getAlgorithm()) ||
                  pubkey.getClass().getName().contains("Ed25519")) {
           return createCoseEd25519Key(pubkey);
       }
       
       throw new UnsupportedOperationException(
           "Unsupported key type: " + pubkey.getClass().getName());
   }
   
   /**
    * Creates a COSE key representation of an EC public key.
    * Currently supports P-256 curve only.
    *
    * @param ecKey The EC public key
    * @return A map containing the COSE key parameters
    */
   private static Map<Integer, Object> createCoseEcKey(ECPublicKey ecKey) {
       return createCoseEcKey(ecKey, null);
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
     * Converts a COSE EC key to a Java ECPublicKey.
     *
     * @param coseKey The COSE key map
     * @return The corresponding ECPublicKey
     * @throws Exception if the key cannot be created
     */
    private static PublicKey fromCoseEcKey(Map<Integer, Object> coseKey) throws Exception {
        // Extract curve and coordinates
        Integer crv = (Integer) coseKey.get(COSE_EC_CRV);
        byte[] x = (byte[]) coseKey.get(COSE_EC_X);
        byte[] y = (byte[]) coseKey.get(COSE_EC_Y);
        
        if (crv == null || x == null || y == null) {
            throw new IllegalArgumentException("Invalid COSE EC key: missing required parameters");
        }
        
        // Map COSE curve identifier to standard curve name
        String curveName;
        switch (crv) {
            case COSE_EC_CRV_P256:
                curveName = "secp256r1"; // P-256
                break;
            // Add support for other curves as needed
            // case 2: curveName = "secp384r1"; break; // P-384
            // case 3: curveName = "secp521r1"; break; // P-521
            default:
                throw new IllegalArgumentException("Unsupported curve: " + crv);
        }
        
        // Check algorithm if present (optional)
        Integer alg = (Integer) coseKey.get(COSE_KEY_ALG);
        if (alg != null && alg != COSE_ALG_ES256 && alg != COSE_ALG_ECDH_ES_HKDF_256) {
            throw new IllegalArgumentException("Unsupported EC algorithm: " + alg);
        }
        
        // Convert byte arrays to BigIntegers
        BigInteger xBi = new BigInteger(1, x);
        BigInteger yBi = new BigInteger(1, y);
        
        // Create EC point
        ECPoint point = new ECPoint(xBi, yBi);
        
        // Get EC parameters using standard Java API
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec(curveName));
        ECParameterSpec ecParams = parameters.getParameterSpec(ECParameterSpec.class);
        
        // Create key spec
        ECPublicKeySpec keySpec = new ECPublicKeySpec(point, ecParams);
        
        // Generate public key
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
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
        return isModernJavaApiAvailable()
            ? createEd25519KeyUsingModernApi(x)
            : createEd25519KeyFromRawBytes(x);
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
    
    // Cache for Java API availability check
    private static Boolean modernJavaApiAvailable = null;
    
    /**
     * Checks if the modern Java API (Java 15+) for Ed25519 keys is available.
     *
     * @return true if the modern API is available, false otherwise
     */
    private static boolean isModernJavaApiAvailable() {
        if (modernJavaApiAvailable == null) {
            try {
                Class.forName("java.security.spec.EdECPublicKeySpec");
                Class.forName("java.security.spec.NamedParameterSpec");
                modernJavaApiAvailable = Boolean.TRUE;
            } catch (ClassNotFoundException e) {
                modernJavaApiAvailable = Boolean.FALSE;
            }
        }
        return modernJavaApiAvailable;
    }
    
    /**
     * Creates an Ed25519 public key using the modern Java API (Java 15+).
     *
     * @param publicKeyBytes The raw public key bytes
     * @return The Ed25519 public key
     * @throws Exception if the key cannot be created
     */
    private static PublicKey createEd25519KeyUsingModernApi(byte[] publicKeyBytes) throws Exception {
        try {
            // Get the required classes via reflection
            Class<?> edPublicKeyClass = Class.forName("java.security.spec.EdECPublicKeySpec");
            Class<?> namedParamSpecClass = Class.forName("java.security.spec.NamedParameterSpec");
            
            // Get the named parameter spec for Ed25519
            Object ed25519ParamSpec = namedParamSpecClass.getField("ED25519").get(null);
            
            // Create the key spec
            Object keySpec = edPublicKeyClass.getConstructor(namedParamSpecClass, byte[].class)
                .newInstance(ed25519ParamSpec, publicKeyBytes);
            
            // Generate the public key
            KeyFactory keyFactory = KeyFactory.getInstance("EdDSA");
            return keyFactory.generatePublic((java.security.spec.KeySpec) keySpec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create Ed25519 key using modern Java API", e);
        }
    }
    
    /**
     * Creates an Ed25519 public key from raw bytes.
     * This is a fallback method for Java versions that don't support the EdECPublicKeySpec API.
     *
     * @param rawBytes The raw public key bytes
     * @return The corresponding Ed25519PublicKey
     * @throws Exception if the key cannot be created
     */
    private static PublicKey createEd25519KeyFromRawBytes(byte[] rawBytes) throws Exception {
        // This is a simplified approach and may need to be adjusted based on your environment
        // For many environments, you might need to use a third-party library like Bouncy Castle
        
        try {
            // Try using reflection to access the Ed25519PublicKeyImpl constructor if available
            Class<?> keyClass = Class.forName("sun.security.ec.Ed25519PublicKeyImpl");
            return (PublicKey) keyClass.getConstructor(byte[].class).newInstance(rawBytes);
        } catch (Exception e) {
            // If that fails, try to encode as X509
            byte[] encodedKey = encodeEd25519PublicKey(rawBytes);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
            
            try {
                KeyFactory keyFactory = KeyFactory.getInstance("EdDSA");
                return keyFactory.generatePublic(keySpec);
            } catch (NoSuchAlgorithmException nsae) {
                // Try Ed25519 as algorithm name
                KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");
                return keyFactory.generatePublic(keySpec);
            }
        }
    }
    
    /**
     * Encodes raw Ed25519 public key bytes in X509 format.
     * This is a simplified implementation and may need to be adjusted.
     *
     * @param rawBytes The raw public key bytes
     * @return The X509 encoded key
     */
    private static byte[] encodeEd25519PublicKey(byte[] rawBytes) {
        // This is a simplified ASN.1 DER encoding for Ed25519 public keys
        // The actual implementation depends on your environment
        
        // Simple ASN.1 structure for Ed25519 public key:
        // PublicKeyInfo ::= SEQUENCE {
        //   algorithm   AlgorithmIdentifier,
        //   publicKey   BIT STRING
        // }
        // AlgorithmIdentifier ::= SEQUENCE {
        //   algorithm   OBJECT IDENTIFIER,
        //   parameters  ANY DEFINED BY algorithm OPTIONAL
        // }
        
        // This is a placeholder implementation
        // In a real implementation, you would use a proper ASN.1 encoder
        byte[] prefix = {
            0x30, (byte) (rawBytes.length + 12), // SEQUENCE
            0x30, 0x08, // SEQUENCE for AlgorithmIdentifier
            0x06, 0x03, 0x2B, 0x65, 0x70, // OID for Ed25519 (1.3.101.112)
            0x05, 0x00, // NULL for parameters
            0x03, (byte) (rawBytes.length + 1), 0x00 // BIT STRING with no unused bits
        };
        
        byte[] result = new byte[prefix.length + rawBytes.length];
        System.arraycopy(prefix, 0, result, 0, prefix.length);
        System.arraycopy(rawBytes, 0, result, prefix.length, rawBytes.length);
        
        return result;
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

    public static PublicKey readPublic(String fileName, String alg)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] rawKey = FileUtils.readPEMFile(fileName);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(rawKey);
        KeyFactory kf = KeyFactory.getInstance(alg);
        return kf.generatePublic(spec);
    }

    /**
     * Reads a private key from a PKCS8 file
     *
     * @param fileName Path to the PKCS8 file
     * @param alg Algorithm name (e.g., "EC", "RSA")
     * @return The private key
     * @throws IOException If the file cannot be read
     * @throws NoSuchAlgorithmException If the algorithm is not available
     * @throws InvalidKeySpecException If the key specification is invalid
     */
    public static PrivateKey readPrivate(String fileName, String alg)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] rawKey = FileUtils.readPEMFile(fileName);
        KeyFactory kf = KeyFactory.getInstance(alg);
        PrivateKey pk = (PrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(rawKey));
        return pk;
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
    public static PrivateKey readPrivate(byte[] raw, String alg)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory kf = KeyFactory.getInstance(alg);
        PrivateKey pk = (PrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(raw));
        return pk;
    }
    
    /**
     * Reads a password-protected private key from a PKCS8 or PEM file.
     *
     * @param fileName Path to the encrypted key file
     * @param passwordChars Password for decryption
     * @return The private key
     * @throws IOException If the file cannot be read
     * @throws PKCSException If decryption fails (wrong password)
     * @throws OperatorCreationException If the decryptor cannot be created
     * @throws IllegalArgumentException If parameters are invalid
     * @throws NoSuchAlgorithmException If the algorithm is not available
     * @throws InvalidKeySpecException If the key specification is invalid
     */
    public static PrivateKey readPrivate(String fileName, char[] passwordChars)
            throws IOException, PKCSException, OperatorCreationException,
                   NoSuchAlgorithmException, InvalidKeySpecException {
        
        // Validate parameters
        if (fileName == null || fileName.isEmpty()) {
            throw new IllegalArgumentException("File name cannot be null or empty");
        }
        if (passwordChars == null || passwordChars.length == 0) {
            return readPrivate(fileName, "EC"); //Assume EC key, no password
        }
        
        InputStream inputStream = null;
        try {
            inputStream = new FileInputStream(fileName);
            Object pemObject = parsePemObject(inputStream);
            PrivateKey key = decryptPrivateKey(pemObject, passwordChars);
            clearPassword(passwordChars); // Security: clear password from memory
            return key;
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    // Ignore close errors
                }
            }
            clearPassword(passwordChars); // Ensure password is cleared even if exception occurs
        }
    }

    /**
     * Parses a PEM object from an input stream.
     *
     * @param inputStream The input stream to read from
     * @return The parsed PEM object
     * @throws IOException If the PEM object cannot be read
     * @throws IllegalArgumentException If no PEM object is found
     */
    private static Object parsePemObject(InputStream inputStream) throws IOException {
        try (PEMParser pemParser = new PEMParser(new InputStreamReader(inputStream))) {
            Object pemObject = pemParser.readObject();
            if (pemObject == null) {
                throw new IllegalArgumentException("No PEM object found in the input");
            }
            return pemObject;
        }
    }


    // Singleton instance of BouncyCastleProvider for better performance
    private static BouncyCastleProvider bouncyCastleProvider;

    /**
     * Gets the Bouncy Castle provider instance, creating it if necessary.
     *
     * @return The Bouncy Castle provider
     */
    private static synchronized BouncyCastleProvider getBouncyCastleProvider() {
        if (bouncyCastleProvider == null) {
            bouncyCastleProvider = new BouncyCastleProvider();
        }
        return bouncyCastleProvider;
    }

    /**
     * Decrypts a private key from a PEM object using the provided password.
     *
     * @param pemObject The PEM object to decrypt
     * @param passwordChars The password as a character array
     * @return The decrypted private key
     * @throws PKCSException If decryption fails (wrong password)
     * @throws OperatorCreationException If the decryptor cannot be created
     * @throws IOException If an I/O error occurs
     * @throws IllegalArgumentException If the key format is not supported
     */
    private static PrivateKey decryptPrivateKey(Object pemObject, char[] passwordChars)
            throws PKCSException, OperatorCreationException, IOException {
        
        if (pemObject instanceof PKCS8EncryptedPrivateKeyInfo) {
            PKCS8EncryptedPrivateKeyInfo encryptedInfo = (PKCS8EncryptedPrivateKeyInfo) pemObject;
            JceOpenSSLPKCS8DecryptorProviderBuilder jce = new JceOpenSSLPKCS8DecryptorProviderBuilder();
            jce.setProvider(getBouncyCastleProvider());
            InputDecryptorProvider decryptorProvider = jce.build(passwordChars);
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(getBouncyCastleProvider());
            return converter.getPrivateKey(encryptedInfo.decryptPrivateKeyInfo(decryptorProvider));
        } else if (pemObject instanceof PEMEncryptedKeyPair) {
            PEMEncryptedKeyPair encryptedKeyPair = (PEMEncryptedKeyPair) pemObject;
            PEMDecryptorProvider decryptorProvider = new JcePEMDecryptorProviderBuilder().build(passwordChars);
            PEMKeyPair keyPair = encryptedKeyPair.decryptKeyPair(decryptorProvider);
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(getBouncyCastleProvider());
            return converter.getPrivateKey(keyPair.getPrivateKeyInfo());
        } else {
            throw new IllegalArgumentException("Unsupported PEM object type: " +
                (pemObject != null ? pemObject.getClass().getName() : "null"));
        }
    }

    /**
     * Clears a password from memory for security.
     *
     * @param passwordChars The password character array to clear
     */
    private static void clearPassword(char[] passwordChars) {
        if (passwordChars != null) {
            for (int i = 0; i < passwordChars.length; i++) {
                passwordChars[i] = 0;
            }
        }
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

    public static KeyPair generateKeyPair(String alg, int keySize)
            throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg);
        kpg.initialize(keySize);
        return kpg.genKeyPair();
    }

    public static KeyPair getCAKeyPair(String alg) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        PrivateKey privateKey = null;
        PublicKey publicKey = null;
        if (alg == "EC") {
            privateKey = generatePrivate(alg, 256);
            publicKey = getPubKey((ECPrivateKey) privateKey);
        }
        else if (alg == "RSA") {
            privateKey = generatePrivate(alg, 2048);
            publicKey =  getPubKey((RSAPrivateCrtKey) privateKey);
        }
        else {
            throw new NoSuchAlgorithmException(String.format("Invalid alg:  %s", alg));
        }
        return new KeyPair(publicKey, privateKey);      
    }
    
    public static PrivateKey generatePrivate(String alg, int keySize)
            throws NoSuchAlgorithmException {
        return generateKeyPair(alg, keySize).getPrivate();
    }
    
    
    private static KeyPair getRSAKeyPair() throws Exception {
        return generateKeyPair("RSA", 2048);
    }
    
    
    private static KeyPair getECKeyPair() throws Exception {
        return generateKeyPair("EC", 521);
    }
    
    
    private static KeyPair getE25519KeyPair() throws Exception {
        return generateKeyPair("E25519", 512);
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
            // 1. Generate ephemeral EC P-256 key pair
            KeyPair ephemeralKeyPair = generateKeyPair("EC", 256);

            // 2. Perform ECDH key agreement using existing decapsulate method
            byte[] aesKey = decapsulate(recipient, ephemeralKeyPair.getPrivate());
            if (aesKey == null || aesKey.length != 32) {
                throw new RuntimeException("Failed to derive shared secret");
            }
            
            // 4. Encrypt plaintext using AES-GCM
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
            
            // Generate random IV (12 bytes for GCM)
            byte[] iv = new byte[12];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv); // 128-bit auth tag
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            byte[] ciphertext = cipher.doFinal(plaintext);
            
            // 5. Encode public key
            byte[] ephemeralPubKeyBytes = ephemeralKeyPair.getPublic().getEncoded();
            
            // 6. Combine all components: [public key length (2 bytes)][ public key][IV][ciphertext]
            ByteBuffer combined = ByteBuffer.allocate(2 + ephemeralPubKeyBytes.length + iv.length + ciphertext.length);
            combined.putShort((short) ephemeralPubKeyBytes.length);
            combined.put(ephemeralPubKeyBytes);
            combined.put(iv);
            combined.put(ciphertext);
            
            return combined.array();
            
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException |
                 NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("ECDH encryption failed", e);
        }
    }

    /**
     * Decrypts ciphertext using ECDH with the recipient's private key.
     *
     * This method:
     * 1. Extracts the ephemeral public key from the ciphertext
     * 2. Performs ECDH key agreement with the recipient's private key
     * 3. Uses the derived shared secret to decrypt the ciphertext with AES-GCM
     * 4. Returns the plaintext
     *
     * @param ciphertext The encrypted data in format: [public key bytes][IV][ciphertext][auth tag]
     * @param recipient The recipient's private key
     * @return The decrypted plaintext
     * @throws RuntimeException if decryption fails
     */
    public static byte[] ecdhDecrypt(byte[] ciphertext, PrivateKey recipient) {
        try {
            // 1. Extract components from ciphertext
            ByteBuffer buffer = ByteBuffer.wrap(ciphertext);
            
            // Extract ephemeral public key
            short pubKeyLength = buffer.getShort();
            byte[] ephemeralPubKeyBytes = new byte[pubKeyLength];
            buffer.get(ephemeralPubKeyBytes);
            
            // Convert bytes to public key
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(ephemeralPubKeyBytes);
            PublicKey ephemeralPubKey = keyFactory.generatePublic(keySpec);
            
            // Extract IV (12 bytes for GCM)
            byte[] iv = new byte[12];
            buffer.get(iv);
            
            // Extract encrypted data (remaining bytes)
            byte[] encryptedData = new byte[buffer.remaining()];
            buffer.get(encryptedData);
            
            // 2. Perform ECDH key agreement using existing decapsulate method
            byte[] aesKey = decapsulate(ephemeralPubKey, recipient);
            if (aesKey == null) {
                throw new RuntimeException("Failed to derive shared secret");
            }
            
            // 4. Decrypt ciphertext using AES-GCM
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec2 = new SecretKeySpec(aesKey, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv); // 128-bit auth tag
            
            cipher.init(Cipher.DECRYPT_MODE, keySpec2, gcmSpec);
            return cipher.doFinal(encryptedData);
            
        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException |
                 NoSuchPaddingException | InvalidAlgorithmParameterException |
                 IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("ECDH decryption failed", e);
        }
    }

    /**
     * Creates a simplified map representation of an elliptic curve private key.
     * The map contains only the essential parameters needed to reconstruct the key:
     * - 'c': The curve name as used by Java cryptography libraries
     * - 'pv': The private scalar value
     *
     * @param privateKey The EC private key to convert
     * @return A map containing the key parameters
     * @throws IllegalArgumentException if the key is not an EC private key
     */
    public static Map<String, Object> getECPrivateKeyParameters(PrivateKey privateKey) {
        if (!(privateKey instanceof ECPrivateKey)) {
            throw new IllegalArgumentException("Key must be an EC private key");
        }
        
        ECPrivateKey ecPrivateKey = (ECPrivateKey) privateKey;
        Map<String, Object> keyParams = new HashMap<>();
        
        // Extract the scalar value
        keyParams.put("pv", ecPrivateKey.getS());
        
        // Determine the curve name from the parameters
        ECParameterSpec params = ecPrivateKey.getParams();
        String curveName = getCurveName(params);
        keyParams.put("c", curveName);
        
        return keyParams;
    }

    /**
     * Recreates an EC private key from simplified parameters.
     * This method takes a map containing the curve name and private scalar value,
     * and reconstructs a fully functional EC private key.
     *
     * @param keyParamMap A map containing 'c' (curve name) and 'pv' (private value/scalar)
     * @return The reconstructed EC private key
     * @throws IllegalArgumentException if the parameters are invalid or missing
     * @throws RuntimeException if key creation fails
     */
    public static PrivateKey fromECPrivateKeyParameters(Map<String, Object> keyParamMap) throws 
            IllegalArgumentException, ClassCastException {
        try {
            // Validate required parameters
            if (keyParamMap == null) {
                throw new IllegalArgumentException("Key parameter map cannot be null");
            }
            
            // Extract curve name and private value
            String curveName = (String) keyParamMap.get("c");
            BigInteger privateValue = (BigInteger) keyParamMap.get("pv");
            
            if (curveName == null || privateValue == null) {
                throw new IllegalArgumentException("Missing required parameters: curve name or private value");
            }
            
            // Get EC parameters based on curve name using AlgorithmParameters
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec(curveName));
            ECParameterSpec ecParams = parameters.getParameterSpec(ECParameterSpec.class);
            
            // Create the EC private key specification
            ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(privateValue, ecParams);
            
            // Generate the private key
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            return keyFactory.generatePrivate(privateKeySpec);
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException | InvalidKeySpecException e) {
            throw new RuntimeException("Failed to create EC private key from parameters", e);
        } catch (ClassCastException e) {
            throw new IllegalArgumentException("Invalid parameter type in key map", e);
        }
    }

    /**
     * Determines the standard curve name from EC parameters.
     *
     * @param params The EC parameter specification
     * @return The standard curve name (e.g., "secp256r1" for P-256)
     */
    public static String getCurveName(ECParameterSpec params) {
        // Compare with known curves
        if (isP256Curve(params)) {
            return "secp256r1"; // Also known as P-256 or prime256v1
        } else if (isP384Curve(params)) {
            return "secp384r1"; // P-384
        } else if (isP521Curve(params)) {
            return "secp521r1"; // P-521
        }
        
        // Default fallback - examine field size
        int fieldSize = ((ECFieldFp)params.getCurve().getField()).getP().bitLength();
        return "unknown-" + fieldSize;
    }
    
    /**
     * Checks if the parameters match the P-256 curve.
     */
    private static boolean isP256Curve(ECParameterSpec params) {
        BigInteger p256Prime = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
        ECField field = params.getCurve().getField();
        
        if (field instanceof ECFieldFp) {
            BigInteger prime = ((ECFieldFp) field).getP();
            return prime.equals(p256Prime) && params.getOrder().bitLength() == 256;
        }
        return false;
    }
    
    /**
     * Checks if the parameters match the P-384 curve.
     */
    private static boolean isP384Curve(ECParameterSpec params) {
        BigInteger p384Prime = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", 16);
        ECField field = params.getCurve().getField();
        
        if (field instanceof ECFieldFp) {
            BigInteger prime = ((ECFieldFp) field).getP();
            return prime.equals(p384Prime) && params.getOrder().bitLength() == 384;
        }
        return false;
    }
    
    /**
     * Checks if the parameters match the P-521 curve.
     */
    private static boolean isP521Curve(ECParameterSpec params) {
        BigInteger p521Prime = new BigInteger("1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);
        ECField field = params.getCurve().getField();
        
        if (field instanceof ECFieldFp) {
            BigInteger prime = ((ECFieldFp) field).getP();
            return prime.equals(p521Prime) && params.getOrder().bitLength() == 521;
        }
        return false;
    }

    /* PKCS12 */
    public static KeyStore readPKCS12(byte[] pkcs12Bytes, char[] password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
        
        try (InputStream is = new ByteArrayInputStream(pkcs12Bytes)) {
            keyStore.load(is, password);
        }

        return keyStore;
    }

    // Extract private key
    public static PrivateKey getPrivateKeyFromPKCS12(KeyStore keyStore, String alias, char[] password) throws Exception {
        return (PrivateKey) keyStore.getKey(alias, password);
    }

    // Extract certificate
    public static X509Certificate getCertificateFromPKCS12(KeyStore keyStore, String alias) throws Exception {
        return (X509Certificate) keyStore.getCertificate(alias);
    }

    // Get first key pair (when you don't know the alias)
    public static KeyPair getFirstKeyPairFromPKCS12(KeyStore keyStore, char[] password) throws Exception {
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password);
                X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
                return new KeyPair(cert.getPublicKey(), privateKey);
            }
        }
        throw new KeyStoreException("No key entries found in the PKCS12 file");
    }

}