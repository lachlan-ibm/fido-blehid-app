/*
 *Copyright IBM 2025, 2026
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
import java.security.Signature;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import com.isfs.blekey.data.AppConfig;
import com.isfs.blekey.data.StashCipher;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyAgreement;

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KeyUtils {

    private static final Logger logger = LoggerFactory.getLogger(KeyUtils.class);

    // -----------------------------------------------------------------------
    // KeystoreManager — owns the TEE-backed platform key
    // -----------------------------------------------------------------------

    private static KeystoreManager keystoreManager;

    public static void setKeystoreManager(KeystoreManager manager) {
        keystoreManager = manager;
        stashCipher = null; // invalidate cached cipher so it is rebuilt with the new manager
        logger.info("KeystoreManager set: {}", manager != null ? manager.getClass().getSimpleName() : "null");
    }

    public static KeystoreManager getKeystoreManager() {
        return keystoreManager;
    }

    // -----------------------------------------------------------------------
    // Root key pair — file-based ECDH fallback for stash encryption
    // -----------------------------------------------------------------------

    private static PublicKey rootPublicKey;
    private static PrivateKey rootPrivateKey;

    /**
     * Initialize the root key pair from a PKCS8 file containing an EC private key.
     * This should be called during application initialization.
     *
     * @param pkcs8File Path to the PKCS8 file containing the EC private key
     * @param password  Password for the encrypted PKCS8 file, or null if not encrypted
     * @return true if successful, false if the file doesn't exist or contains an invalid key
     */
    public static boolean initRootKeyPair(String pkcs8File, String password) {
        try {
            PrivateKey privateKey = FileUtils.readPrivatePEM(new File(pkcs8File), password);
            if (!(privateKey instanceof java.security.interfaces.ECPrivateKey)) {
                logger.error("Private key in {} is not an EC key", pkcs8File);
                return false;
            }
            PublicKey publicKey = getPubKey((java.security.interfaces.ECPrivateKey) privateKey);
            rootPublicKey = publicKey;
            rootPrivateKey = privateKey;
            stashCipher = null; // invalidate so it rebuilds with new root keys
            logger.info("Root key pair initialized from file: {}", pkcs8File);
            return true;
        } catch (Exception e) {
            logger.error("Failed to read private key from file: {}", pkcs8File, e);
            return false;
        }
    }

    /**
     * Ensures a root key pair is available for ECDH encryption/decryption.
     * Loads from the specified file, falls back to the default location, and
     * generates a new key pair if none is found.
     *
     * @param keyPath  Path to the PKCS8 file, or null to use the default location
     * @param password Password for the encrypted PKCS8 file, or null if not encrypted
     */
    public static void ensureRootKeyPair(String keyPath, String password) {
        if (rootPublicKey != null && rootPrivateKey != null) {
            return;
        }
        String resolvedKeyPath = resolveRootKeyFilePath(keyPath);
        File keyFile = new File(resolvedKeyPath);
        if (keyFile.exists()) {
            loadExistingRootKey(resolvedKeyPath, password);
        } else {
            generateAndSaveNewRootKey(resolvedKeyPath);
        }
        if (rootPublicKey == null || rootPrivateKey == null) {
            throw new RuntimeException("Failed to read or generate platform key pair");
        }
    }

    private static final String ROOT_KEY_FILE = "platform.key";
    private static final String ROOT_KEY_ALGORITHM = "ECDSA";
    private static final int ROOT_KEY_SIZE = 256;

    private static String resolveRootKeyFilePath(String keyPath) {
        if (keyPath != null) {
            return keyPath;
        }
        String fido2Home = FileUtils.getFido2Home();
        if (fido2Home == null || fido2Home.isEmpty()) {
            throw new RuntimeException("FIDO2_HOME environment variable or system property is not set");
        }
        return fido2Home + java.nio.file.FileSystems.getDefault().getSeparator() + ROOT_KEY_FILE;
    }

    private static void loadExistingRootKey(String keyPath, String password) {
        try {
            boolean keyLoaded = initRootKeyPair(keyPath, password);
            if (!keyLoaded) {
                logger.warn("Failed to initialize root key pair from {}", keyPath);
            }
        } catch (Exception e) {
            logger.warn("Failed to read platform key from {}", keyPath, e);
        }
    }

    private static void generateAndSaveNewRootKey(String keyPath) {
        try {
            logger.info("Platform key not found, generating a new one at {}", keyPath);
            KeyPair keyPair = generateKeyPair(ROOT_KEY_ALGORITHM, ROOT_KEY_SIZE);
            FileUtils.writePrivatePEM(keyPair.getPrivate(), new File(keyPath));
            rootPublicKey = keyPair.getPublic();
            rootPrivateKey = keyPair.getPrivate();
            stashCipher = null;
            logger.info("Generated and saved new platform key at: {}", keyPath);
        } catch (java.io.IOException e) {
            logger.error("Failed to write platform key to file: {}", keyPath, e);
            throw new RuntimeException("Failed to write platform key to file: " + keyPath, e);
        } catch (Exception e) {
            logger.error("Failed to generate platform key", e);
            throw new RuntimeException("Failed to generate platform key", e);
        }
    }

    // -----------------------------------------------------------------------
    // StashCipher — lazily built from keystoreManager + root key pair
    // -----------------------------------------------------------------------

    private static StashCipher stashCipher;

    /** Returns the shared {@link StashCipher}, creating it on first call. */
    public static StashCipher getStashCipher() {
        if (stashCipher == null) {
            stashCipher = StashCipher.create(keystoreManager, rootPublicKey, rootPrivateKey);
        }
        return stashCipher;
    }

    /**
     * Deletes the current platform key and immediately generates a fresh one.
     *
     * <p>TEE path: calls {@link KeystoreManager#deleteAppKey()} to erase the
     * Android Keystore entry. The new key is created lazily on the next call to
     * {@link KeystoreManager#getEC256PrivateKey()}.
     *
     * <p>File path: deletes {@code $FIDO2_HOME/platform.key} and calls
     * {@link #generateAndSaveNewRootKey(String)} to produce a fresh PEM file,
     * then reloads the static {@code rootPublicKey}/{@code rootPrivateKey} fields.
     *
     * <p>In both cases {@code stashCipher} is nulled so the next call to
     * {@link #getStashCipher()} rebuilds with the new key.
     *
     * <p>All existing {@code .stash} files become permanently unreadable after
     * this call.
     *
     * @throws RuntimeException if key deletion or generation fails
     */
    public static void resetPlatformKey() {
        if (keystoreManager != null && keystoreManager.isKeystoreAvailable()) {
            // TEE / StrongBox path
            boolean deleted = keystoreManager.deleteAppKey();
            if (!deleted) {
                throw new RuntimeException("Failed to delete TEE platform key");
            }
            stashCipher = null;
            logger.info("TEE platform key deleted; new key will be generated on first use");
        } else {
            // File-based path
            String keyPath = resolveRootKeyFilePath(null);
            File keyFile = new File(keyPath);
            if (keyFile.exists() && !keyFile.delete()) {
                throw new RuntimeException("Failed to delete platform key file: " + keyPath);
            }
            rootPublicKey  = null;
            rootPrivateKey = null;
            stashCipher    = null;
            generateAndSaveNewRootKey(keyPath);
            logger.info("File-based platform key regenerated at: {}", keyPath);
        }
    }

    
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
        } else {
            // BC exists and is correct class, but ensure it's at position 1
            Provider[] providers = Security.getProviders();
            if (providers.length > 0 && !providers[0].getName().equals(BOUNCY_CASTLE_PROVIDER_NAME)) {
                // BC is not at position 1, so remove and re-insert it
                Security.removeProvider(BOUNCY_CASTLE_PROVIDER_NAME);
                Security.insertProviderAt(new BouncyCastleProvider(), 1);
            }
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
    private static final String ECDSA_ALGORITHM = "ECDSA";
    private static final String EC_ALGORITHM = "EC";
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
    
    // EC Coordinate Lengths
    private static final int P256_COORDINATE_LENGTH = 32;
    
    /**
     * Builder class for constructing COSE EC keys with type safety.
     */
    private static class CoseEcKeyBuilder {
        private final Map<Integer, Object> key = new HashMap<>();
        
        CoseEcKeyBuilder withKeyType(int type) {
            key.put(COSE_KEY_KTY, type);
            return this;
        }
        
        CoseEcKeyBuilder withAlgorithm(int alg) {
            key.put(COSE_KEY_ALG, alg);
            return this;
        }
        
        CoseEcKeyBuilder withCurve(int crv) {
            key.put(COSE_EC_CRV, crv);
            return this;
        }
        
        CoseEcKeyBuilder withCoordinates(byte[] x, byte[] y) {
            key.put(COSE_EC_X, x);
            key.put(COSE_EC_Y, y);
            return this;
        }
        
        Map<Integer, Object> build() {
            return Collections.unmodifiableMap(key);
        }
    }
    
    private KeyUtils() { }
    
    public static KeyPair getKeyPair(String alg) {
        // Ensure BouncyCastle is available
        ensureBouncyCastleProvider();
        try {
            if (RSA_ALGORITHM.equals(alg)) {
                return getRSAKeyPair();
            }
            else if (EC_ALGORITHM.equals(alg) || ECDSA_ALGORITHM.equals(alg)) {
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
                  pubkey.getClass().getName().contains("Ed25519") ||
                  pubkey.getClass().getName().contains("EdDSA")) {
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
       ECPoint point = ecKey.getW();
       
       // Extract and normalize coordinates to P-256 field size
       byte[] x = extractAndNormalizeCoordinate(point.getAffineX(), P256_COORDINATE_LENGTH, "X");
       byte[] y = extractAndNormalizeCoordinate(point.getAffineY(), P256_COORDINATE_LENGTH, "Y");
       
       // Determine algorithm to use
       int algorithmToUse = (algorithm != null) ? algorithm : COSE_ALG_ES256;
       
       // Build COSE key using builder pattern
       Map<Integer, Object> coseKey = new CoseEcKeyBuilder()
           .withKeyType(COSE_KEY_TYPE_EC2)
           .withAlgorithm(algorithmToUse)
           .withCurve(COSE_EC_CRV_P256)
           .withCoordinates(x, y)
           .build();
       
       logCoseKeyIfDebugEnabled(coseKey, algorithm);
       
       return coseKey;
   }
   
   /**
    * Extracts a coordinate from a BigInteger, normalizes it to the target length,
    * and logs debug information if debug logging is enabled.
    *
    * @param coordinate The coordinate as a BigInteger
    * @param targetLength The desired length in bytes
    * @param coordinateName The name of the coordinate (for logging)
    * @return A normalized byte array of the specified length
    */
   private static byte[] extractAndNormalizeCoordinate(BigInteger coordinate, int targetLength, String coordinateName) {
       byte[] rawBytes = coordinate.toByteArray();
       
       if (logger.isDebugEnabled()) {
           logger.debug("Raw {} coordinate bytes (length={}): {}",
               coordinateName, rawBytes.length, ByteUtils.bytesToHex(rawBytes));
       }
       
       byte[] normalized = normalizeCoordinate(rawBytes, targetLength);
       
       if (logger.isDebugEnabled()) {
           logger.debug("Normalized {} coordinate ({} bytes): {}",
               coordinateName, targetLength, ByteUtils.bytesToHex(normalized));
       }
       
       return normalized;
   }
   
   /**
    * Logs COSE key structure details if debug logging is enabled.
    *
    * @param coseKey The COSE key map to log
    * @param algorithm The algorithm used (may be null)
    */
   private static void logCoseKeyIfDebugEnabled(Map<Integer, Object> coseKey, Integer algorithm) {
       if (logger.isDebugEnabled()) {
           logger.debug("COSE key structure created:");
           logger.debug("  kty (1): {} (EC2)", coseKey.get(COSE_KEY_KTY));
           logger.debug("  alg (3): {} ({})", coseKey.get(COSE_KEY_ALG), getAlgorithmName(algorithm));
           logger.debug("  crv (-1): {} (P-256)", coseKey.get(COSE_EC_CRV));
       }
   }
   
   /**
    * Returns a human-readable name for the COSE algorithm.
    *
    * @param algorithm The COSE algorithm identifier (may be null)
    * @return The algorithm name
    */
   private static String getAlgorithmName(Integer algorithm) {
       if (algorithm != null && algorithm == COSE_ALG_ECDH_ES_HKDF_256) {
           return "ECDH-ES+HKDF-256";
       }
       return "ES256";
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
       AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC", "BC");
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
       logger.debug("KeyUtils: fromCoseEcKey: Parsing COSE EC key");
       
       // Validate the COSE key
       validateCoseEcKey(coseKey);
       
       // Extract curve and coordinates
       Integer crv = (Integer) coseKey.get(COSE_EC_CRV);
       byte[] x = (byte[]) coseKey.get(COSE_EC_X);
       byte[] y = (byte[]) coseKey.get(COSE_EC_Y);
       
       logger.debug("KeyUtils: fromCoseEcKey: Extracted coordinates:");
       logger.debug("  Curve: " + crv + " (" + COSE_CURVE_TO_STD_NAME.get(crv) + ")");
       logger.debug("  X length: " + x.length + " bytes");
       logger.debug("  X hex: " + ByteUtils.bytesToHex(x));
       logger.debug("  Y length: " + y.length + " bytes");
       logger.debug("  Y hex: " + ByteUtils.bytesToHex(y));
       
       // Get standard curve name from map
       String curveName = COSE_CURVE_TO_STD_NAME.get(crv);
       
       // Create EC point from coordinates
       ECPoint point = createECPoint(x, y);
       logger.debug("KeyUtils: fromCoseEcKey: Created ECPoint:");
       logger.debug("  X (BigInteger): " + point.getAffineX().toString(16));
       logger.debug("  Y (BigInteger): " + point.getAffineY().toString(16));
       
       // Get EC parameters
       ECParameterSpec ecParams = createECParameterSpec(curveName);
       
       // Create key spec and generate public key
       ECPublicKeySpec keySpec = new ECPublicKeySpec(point, ecParams);
       KeyFactory keyFactory = KeyFactory.getInstance(EC_ALGORITHM, BOUNCY_CASTLE_PROVIDER_NAME);
       PublicKey publicKey = keyFactory.generatePublic(keySpec);
       logger.debug("KeyUtils: fromCoseEcKey: Successfully created PublicKey");
       
       return publicKey;
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
     * @param theirKey The EC public key of the other party (must not be null)
     * @param myKey The EC private key of this party (must not be null)
     * @return The shared secret as a 32-byte array
     * @throws IllegalArgumentException if keys are null or not EC keys
     * @throws RuntimeException if ECDH operation fails
     */
    public static byte[] decapsulate(PublicKey theirKey, PrivateKey myKey) {
        if (theirKey == null || myKey == null) {
            throw new IllegalArgumentException("Keys cannot be null");
        }
        
        // Check if keys are EC keys
        boolean isPublicKeyEC = theirKey.getAlgorithm().equals("EC") ||
                                theirKey.getClass().getName().contains("ECPublicKey");
        boolean isPrivateKeyEC = myKey.getAlgorithm().equals("EC") ||
                                 myKey.getClass().getName().contains("ECPrivateKey");
        
        if (!isPublicKeyEC || !isPrivateKeyEC) {
            throw new IllegalArgumentException("Keys must be EC keys for ECDH, got " +
                theirKey.getClass().getCanonicalName() + " and " + myKey.getClass().getCanonicalName());
        }
        
        try {
            logger.debug("Starting ECDH key agreement");
            
            // Use standard KeyAgreement API (works for all EC keys including Android Keystore)
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(myKey);
            keyAgreement.doPhase(theirKey, true);
            byte[] sharedSecret = keyAgreement.generateSecret();
            
            // Normalize to 32 bytes (x-coordinate)
            byte[] xCoordinate = normalizeCoordinate(sharedSecret, 32);
            
            // Per CTAP spec: shared secret = SHA-256(x-coordinate)
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashedSecret = digest.digest(xCoordinate);
            
            logger.debug("ECDH key agreement completed successfully, hashed shared secret");
            return hashedSecret;
            
        } catch (IllegalArgumentException e) {
            logger.error("Invalid arguments for ECDH: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            logger.error("ECDH key agreement failed", e);
            throw new RuntimeException("Failed to decapsulate shared secret: " + e.getMessage(), e);
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

    public static ECPublicKey getPubKey(final ECPrivateKey pk)
            throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        ECParameterSpec spec = pk.getParams();
        org.bouncycastle.math.ec.ECPoint bcG = EC5Util.convertPoint(
                EC5Util.convertCurve(spec.getCurve()), spec.getGenerator());
        org.bouncycastle.math.ec.ECPoint bcW =
                new FixedPointCombMultiplier().multiply(bcG, pk.getS()).normalize();
        ECPoint w = EC5Util.convertPoint(bcW);
        KeyFactory kf = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
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
        ensureBouncyCastleProvider();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(ECDSA_ALGORITHM);
        kpg.initialize(256);
        return kpg.generateKeyPair();
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
        if (ECDSA_ALGORITHM.equals(alg) || EC_ALGORITHM.equals(alg)) {
            privateKey = generatePrivate(ECDSA_ALGORITHM, 256);
            publicKey = getPubKey((ECPrivateKey) privateKey);
        }
        else if (RSA_ALGORITHM.equals(alg)) {
            privateKey = generatePrivate(alg, 2048);
            publicKey =  getPubKey((RSAPrivateCrtKey) privateKey);
        }
        else {
            throw new NoSuchAlgorithmException(String.format("Invalid alg: %s", alg));
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
            
            // 1. Generate ephemeral EC key pair using the same curve as the recipient
            int keySize = 256; // Default to P-256
            if (recipient instanceof ECPublicKey) {
                ECPublicKey ecPubKey = (ECPublicKey) recipient;
                keySize = ecPubKey.getParams().getCurve().getField().getFieldSize();
            }
            KeyPair ephemeralKeyPair = generateKeyPair("EC", keySize);

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
            
            // Validate public key length for standard NIST curves
            // P-256 (secp256r1): 178 bytes
            // P-384 (secp384r1): 215 bytes
            // P-521 (secp521r1): 268 bytes
            final int P256_PEM_SIZE = 178;
            final int P384_PEM_SIZE = 215;
            final int P521_PEM_SIZE = 268;
            
            if (pubKeyLength != P256_PEM_SIZE &&
                pubKeyLength != P384_PEM_SIZE &&
                pubKeyLength != P521_PEM_SIZE) {
                throw new IllegalArgumentException(
                    "Invalid EC public key PEM length: expected " + P256_PEM_SIZE +
                    " (P-256), " + P384_PEM_SIZE + " (P-384), or " + P521_PEM_SIZE +
                    " (P-521) bytes, got " + pubKeyLength);
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
        
        // Convert pinHash to char[] using ISO-8859-1 for 1:1 byte-to-char mapping
        char[] password = new String(pinHash, StandardCharsets.ISO_8859_1).toCharArray();
        
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

    /**
     * Derives a passkey seed using HKDF (HMAC-based Key Derivation Function) as defined in RFC 5869.
     *
     * <p>HKDF provides a standardized, secure way to derive cryptographic keys from input key material.
     * It uses an extract-then-expand paradigm:
     * <ol>
     *   <li>Extract: Derive a pseudorandom key (PRK) from the input key material using HMAC</li>
     *   <li>Expand: Expand the PRK into the desired output key material using HMAC</li>
     * </ol>
     *
     * <p><b>Parameters used:</b>
     * <ul>
     *   <li><b>IKM (Input Keying Material)</b>: The encoded private key bytes - provides high-entropy secret material</li>
     *   <li><b>Salt</b>: The entropy parameter (rpId bytes) - provides domain separation per relying party</li>
     *   <li><b>Info</b>: Fixed context string "FIDO2-PASSKEY-SEED" - prevents cross-application attacks</li>
     *   <li><b>Hash</b>: SHA-256 - provides 256-bit security level</li>
     *   <li><b>Output Length</b>: 32 bytes - suitable for AES-256 encryption</li>
     * </ul>
     *
     * <p><b>Security Properties:</b>
     * <ul>
     *   <li>Deterministic: Same inputs always produce the same output (required for credential recovery)</li>
     *   <li>Standardized: Follows RFC 5869 with formal security analysis</li>
     *   <li>Domain Separation: Salt and info parameters prevent cross-protocol attacks</li>
     *   <li>One-way: Computationally infeasible to derive the private key from the seed</li>
     * </ul>
     *
     * <p><b>BREAKING CHANGE:</b> This method now uses HKDF instead of the previous non-standard
     * cryptographic construction. Credentials encrypted with seeds from the old implementation cannot
     * be decrypted with seeds from this new implementation. Migration requires credential re-registration.
     *
     * @param entropy The entropy bytes (typically rpId bytes) used as salt for domain separation
     * @param ikm The input key material
     * @return A Base64 URL-encoded 32-byte seed suitable for AES-256 key derivation, or null on error
     * @see <a href="https://www.rfc-editor.org/rfc/rfc5869">RFC 5869: HKDF</a>
     */
    public static String getPasskeySeed(byte[] entropy, byte[] ikm, AppConfig config) {
        if (entropy == null || ikm == null || config == null) {
            logger.error("HKDF key derivation failed: entropy, key, and config must not be null");
            return null;
        }
        try {
            byte[] info = config.getInfo().getBytes(StandardCharsets.UTF_8);
            byte[] okm  = hkdf(ikm, entropy, info, 32);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(okm);
        } catch (Exception e) {
            logger.error("HKDF key derivation failed: {}", e.getMessage(), e);
            return null;
        }
    }
    /**
     * Performs HKDF key derivation with custom parameters.
     * This is a generic HKDF implementation for use cases beyond passkey seeds.
     * 
     * @param ikm Input keying material
     * @param salt Salt value for extraction phase
     * @param info Context and application-specific information
     * @param length Desired output length in bytes
     * @return Derived key material
     * @throws IllegalArgumentException if parameters are invalid
     */
    public static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int length) {
        if (ikm == null || ikm.length == 0) {
            throw new IllegalArgumentException("Input keying material cannot be null or empty");
        }
        if (length <= 0 || length > 255 * 32) {
            throw new IllegalArgumentException("Invalid output length: " + length);
        }
        
        try {
            HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
            hkdf.init(new HKDFParameters(ikm, salt, info));
            
            byte[] output = new byte[length];
            hkdf.generateBytes(output, 0, length);
            
            return output;
        } catch (Exception e) {
            logger.error("HKDF derivation failed", e);
            throw new RuntimeException("HKDF derivation failed", e);
        }
    }
    
    /**
     * Signs data using a private key.
     * Supports EC (ECDSA with SHA-256) and RSA (RSASSA-PKCS1-v1_5 with SHA-256) keys.
     * 
     * @param data Data to sign
     * @param privateKey Private key for signing
     * @return Signature bytes
     * @throws IllegalArgumentException if parameters are invalid
     * @throws RuntimeException if signing fails
     */
    public static byte[] sign(byte[] data, PrivateKey privateKey) {
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Data to sign cannot be null or empty");
        }
        if (privateKey == null) {
            throw new IllegalArgumentException("Private key cannot be null");
        }
        
        try {
            java.security.Signature signature;
            String algorithm = privateKey.getAlgorithm().toUpperCase();
            
            // Check algorithm name to support both standard and Android Keystore keys
            if ("EC".equals(algorithm) || privateKey instanceof ECPrivateKey) {
                signature = Signature.getInstance("SHA256withECDSA");
                
            } else if ("RSA".equals(algorithm) || privateKey instanceof RSAPrivateKey) {
                signature = Signature.getInstance("SHA256withRSA");
            } else {
                throw new IllegalArgumentException("Unsupported private key type: " +
                                                 privateKey.getClass().getName() +
                                                 " with algorithm: " + algorithm);
            }
            
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();
        } catch (Exception e) {
            logger.error("Signing failed", e);
            throw new RuntimeException("Signing failed", e);
        }
    }


    public static PrivateKey getPlatformKey() {
        if (keystoreManager != null) {
            try {
                return keystoreManager.getEC256PrivateKey();
            } catch (Exception e) {
                logger.error("TEE platform key retrieval failed", e);
            }
        }
        // File-based fallback (non-Android / tests)
        File platKeyFile = new File(FileUtils.getFido2Home() + File.separator + ROOT_KEY_FILE);
        try {
            if (platKeyFile.exists()) {
                return FileUtils.readPrivatePEM(platKeyFile);
            }
        } catch (Exception e) {
            logger.error("Reading platform key failed", e);
        }
        return null;
    }

    // -----------------------------------------------------------------------
    // Credential-ID helpers — compact key-material encoding/decoding
    // -----------------------------------------------------------------------

    /**
     * Extract the 32-byte canonical key material from an EC P-256 private key.
     *
     * <p>Returns the big-endian private scalar {@code S}, left-padded with zeros
     * to exactly 32 bytes (removing any leading sign byte that
     * {@link java.math.BigInteger#toByteArray()} may add).
     *
     * @param key an EC P-256 private key
     * @return 32-byte key material
     * @throws UnsupportedOperationException if the key type is not supported
     */
    public static byte[] extractKeyMaterial(PrivateKey key) {
        if (key instanceof ECPrivateKey) {
            byte[] s = ((ECPrivateKey) key).getS().toByteArray();
            // BigInteger may have a leading 0x00 sign byte — normalise to 32 bytes
            byte[] out = new byte[32];
            int src = Math.max(0, s.length - 32);
            int dst = Math.max(0, 32 - s.length);
            System.arraycopy(s, src, out, dst, s.length - src);
            return out;
        }
        throw new UnsupportedOperationException(
            "Cannot extract 32-byte key material from: " + key.getClass().getName());
    }

    /**
     * Return the COSE algorithm ID that corresponds to {@code key}.
     *
     * @param key a private key
     * @return {@code -7} for EC P-256 (ES256)
     * @throws UnsupportedOperationException if the key type is not recognised
     */
    public static int inferCoseAlg(PrivateKey key) {
        if (key instanceof ECPrivateKey) return -7;   // ES256
        throw new UnsupportedOperationException(
            "Unknown COSE alg for key type: " + key.getAlgorithm());
    }

    /**
     * Reconstruct an EC P-256 {@link KeyPair} from a COSE algorithm ID and the
     * 32-byte private scalar produced by {@link #extractKeyMaterial}.
     *
     * @param coseAlg    COSE algorithm ID (currently only {@code -7} / ES256 is supported)
     * @param keyMaterial 32-byte big-endian private scalar
     * @return reconstructed {@link KeyPair}
     * @throws UnsupportedOperationException if {@code coseAlg} is not supported
     * @throws Exception if key reconstruction fails
     */
    public static KeyPair reconstructKeyPair(int coseAlg, byte[] keyMaterial) throws Exception {
        if (coseAlg == -7) { // ES256 / EC P-256
            ensureBouncyCastleProvider();
            BigInteger s = new BigInteger(1, keyMaterial); // treat as unsigned
            org.bouncycastle.jce.spec.ECNamedCurveParameterSpec spec =
                org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("P-256");
            org.bouncycastle.jce.spec.ECNamedCurveSpec namedSpec =
                new org.bouncycastle.jce.spec.ECNamedCurveSpec(
                    "P-256", spec.getCurve(), spec.getG(), spec.getN());
            java.security.spec.ECPrivateKeySpec privSpec =
                new java.security.spec.ECPrivateKeySpec(s, namedSpec);
            KeyFactory kf = KeyFactory.getInstance("EC",
                org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME);
            ECPrivateKey priv = (ECPrivateKey) kf.generatePrivate(privSpec);
            ECPublicKey  pub  = getPubKey(priv);
            return new KeyPair(pub, priv);
        }
        throw new UnsupportedOperationException("Unsupported COSE alg: " + coseAlg);
    }
}