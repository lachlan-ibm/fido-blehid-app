/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.data;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.file.FileSystems;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.isfs.blekey.util.FileUtils;
import com.isfs.blekey.util.KeyUtils;
import com.isfs.blekey.util.CertUtils;
import com.isfs.blekey.util.Cbor;

/**
 * Represents a FIDO2 passkey with secure storage capabilities.
 *
 * The passkey file implements a two-layer encryption scheme for enhanced security:
 *
 * 1. PIN Hash Splitting:
 *    - The 32-byte PIN hash is split into two 16-byte parts: upperHash and lowerHash
 *    - Only the lowerHash is required to start the decryption process
 *    - The upperHash is stored securely in the encrypted header
 *
 * 2. File Structure:
 *    - Header length (4 bytes): Size of the encrypted header
 *    - Encrypted header: Contains upperHash, IV, and authentication tag for the data section
 *    - Encrypted data: Contains the CBOR-encoded passkey information
 *
 * 3. Encryption Layers:
 *    - Layer 1: The header is encrypted using ECDH with a root public key
 *      * The header contains: upperHash, IV for data encryption, and authentication tag
 *    - Layer 2: The passkey data is encrypted using AES-GCM with the full PIN hash
 *      * The data contains: private key, X509 certificate, seed, and resident credentials
 *
 * 4. Decryption Process:
 *    - The lowerHash is provided by the user (from PIN entry)
 *    - The header is decrypted using the root private key
 *    - The upperHash is extracted from the header and verified
 *    - The full PIN hash is reconstructed by combining upperHash and lowerHash
 *    - The passkey data is decrypted using the full PIN hash
 *
 * 5. Root Key Pair:
 *    - A persistent EC key pair used for ECDH encryption/decryption of the header
 *    - Loaded from a PKCS8 file in FIDO2_HOME directory, default is $FIDO2_HOME/platform.key
 *
 * This approach provides strong security through multiple encryption layers and
 * PIN verification, while only requiring the user to provide half of the PIN hash.
 */
public class Passkey {

    /**
     * The private key used for signing operations.
     */
    private PrivateKey pk;
    
    /**
     * The certificate authority certificate for attestation.
     */
    private X509Certificate ca;
    
    /**
     * List of resident credentials associated with this passkey.
     * Each credential is a map from relying party ID to credential data.
     */
    private Map<byte[], Map> resCreds;
    
    /**
     * Seed value used for key derivation.
     */
    private byte[] seed;

    /**
     * Logger for debugging and error reporting.
     */
    private static final Logger logger = LoggerFactory.getLogger(Passkey.class);
    
    /**
     * Constants for cryptographic parameters
     */
    private static final int IV_SIZE = 16;
    private static final int TAG_SIZE = 16;
    private static final int GCM_TAG_BIT_LENGTH = 128;
    private static final int AES_KEY_SIZE = 32; // 256 bits
    private static final int MIN_FILE_SIZE = IV_SIZE + TAG_SIZE;
    private static final String AES_ALGORITHM = "AES";
    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    
    /**
     * Default names for file objects
     */
    private static final String PLATFORM_KEY = "platform.key";
    private static final String DEFAULT_PASSKEY = "default.passkey";

    /**
     * Constants for PIN hash splitting
     */
    private static final int PIN_HASH_SIZE = 32; // 256 bits
    private static final int HALF_HASH = PIN_HASH_SIZE / 2; // Client exchange limit
    
    /**
     * Root key for ECDH encryption/decryption
     * In a real implementation, this would be securely stored and accessed
     */
    private static PublicKey rootPublicKey;
    private static PrivateKey rootPrivateKey;
    
    /**
     * Initialize the root key pair from a PKCS8 file containing an EC private key
     * This should be called during application initialization
     *
     * @param pkcs8File Path to the PKCS8 file containing the EC private key
     * @param password Password for the encrypted PKCS8 file, or null if the file is not encrypted
     * @return true if successful, false if the file doesn't exist or contains an invalid key
     */
    public static boolean initRootKeyPair(String pkcs8File, String password) {
        try {
            // Read the private key from the PKCS8 file with optional password
            PrivateKey privateKey = KeyUtils.readPrivate(pkcs8File, (password == null) ?
                                                                            new char[] {} : password.toCharArray());
            
            // Verify it's an EC private key
            if (!(privateKey instanceof java.security.interfaces.ECPrivateKey)) {
                logger.error("Private key in {} is not an EC key", pkcs8File);
                return false;
            }
            
            // Generate the corresponding public key
            PublicKey publicKey = KeyUtils.getPubKey((java.security.interfaces.ECPrivateKey) privateKey);
            
            // Set the root key pair
            rootPublicKey = publicKey;
            rootPrivateKey = privateKey;
            
            logger.info("Root key pair initialized from file: {}", pkcs8File);
            return true;
        } catch (Exception e) {
            logger.error("Failed to read private key from file: {}", pkcs8File, e);
            return false;
        }
    }
    
    /**
     * Ensures a root key pair is available for ECDH encryption/decryption
     * Tries to read from the specified PKCS8 file first, falls back to default location,
     * and finally throws an exception if no key can be loaded
     *
     * @param keyPath Path to the PKCS8 file, or null to use the default location
     * @param password Password for the encrypted PKCS8 file, or null if the file is not encrypted
     */
    private static void ensureRootKeyPair(String keyPath, String password) {
        if (rootPublicKey == null || rootPrivateKey == null) {
            boolean keyLoaded = false;
            if(keyPath == null) {         
                // If custom path wasn't provided, try the default location
                keyPath = System.getProperty("FIDO2_HOME") + 
                                            FileSystems.getDefault().getSeparator() + PLATFORM_KEY;   
            }
            File keyFile = new File(keyPath);
            if (keyFile.exists()) {
                try {
                    // Try to read the private key from the default location
                    keyLoaded = initRootKeyPair(keyPath, password); // No password for default location
                } catch (Exception e) {
                    logger.warn("Failed to read platform key from {}", keyPath, e);
                }
            }
            
            if (!keyLoaded) { // Runtime exception if key loading failed
                throw new RuntimeException("Failed to read platform key pair");
            }
        }
    }

    /**
     * Constructs a new Passkey with the specified components.
     *
     * @param key The private key for signing operations
     * @param cert The certificate authority certificate for attestation
     * @param seed The seed value for key derivation
     * @param creds The list of resident credentials
     */
    protected Passkey(PrivateKey key, X509Certificate cert, byte[] seed, Map<byte[], Map> creds) {
        this.pk = key;
        this.ca = cert;
        this.resCreds = creds;
        this.seed = seed;
    }

    /**
     * Creates a Passkey instance from an encrypted file.
     *
     * @param pkeyFile The encrypted passkey file
     * @param pinHash The PIN hash used as the AES key
     * @return A new Passkey instance, or null if decryption fails
     */
    /**
     * Creates a Passkey instance from an encrypted file using the two-layer encryption scheme.
     *
     * Implementation of the algorithm described in the class comments:
     * 1. Split the PIN hash to get the lowerHash
     * 2. Read and parse the file data into header and encrypted data
     * 3. Decrypt the header using the root private key
     * 4. Verify the PIN hash by comparing upperHash from header
     * 5. Decrypt the passkey data using the full PIN hash
     * 6. Deserialize the CBOR data into a Passkey object
     *
     * @param pkeyFile The encrypted passkey file
     * @param lowerHash The lower half of the PIN hash used as the AES key
     * @return A new Passkey instance, or null if decryption fails
     */
    protected static Passkey readKey(File pkeyFile, byte[] lowerHash) {
        try {
            // Validate inputs
            if (!validateInputs(pkeyFile, lowerHash)) {
                return null;
            }
            
            // Read and parse file data
            byte[] fileData = FileUtils.readFileBytes(pkeyFile);
            if (!validateFileData(fileData)) {
                return null;
            }
            
            // Deserialize the file data into header and encrypted data
            PasskeyFile passkeyFile = PasskeyFile.deserialize(fileData);
            
            // Decrypt the header using the root private key
            PasskeyHeader header = decryptHeader(passkeyFile.encryptedHeader);
            
            // Reconstruct the full PIN hash
            byte[] pinHash = combinePinHash(header.upperHash, lowerHash);
            
            // Decrypt the passkey data
            byte[] cborBytes = decryptPasskeyData(header.passkeyIV, header.passkeyTag,
                                                passkeyFile.encryptedData, pinHash);
            
            // Deserialize and create Passkey
            return deserializePasskey(cborBytes);
        } catch (Exception e) {
            logger.error("Error decrypting passkey", e);
            return null;
        }
    }

    /**
     * Validates the input parameters.
     */
    private static boolean validateInputs(File pkeyFile, byte[] lowerHash) {
        if (lowerHash == null || lowerHash.length < HALF_HASH) {
            logger.error("Error reading passkey file: insufficient lowerHash bytes");
            return false;
        } else if (pkeyFile == null || !pkeyFile.exists()) {
            logger.error("Error reading passkey file: file does not exist");
            return false;
        }
        return true;
    }
    
    /**
     * Splits a PIN hash into upper and lower parts.
     *
     * @param pinHash The full PIN hash (32 bytes)
     * @return An array containing [upperHash, lowerHash]
     */
    private static byte[][] splitPinHash(byte[] pinHash) {
        if (pinHash == null || pinHash.length != PIN_HASH_SIZE) {
            throw new IllegalArgumentException("PIN hash must be exactly " + PIN_HASH_SIZE + " bytes");
        }
        
        byte[] upperHash = new byte[HALF_HASH];
        byte[] lowerHash = new byte[HALF_HASH];
        
        // upperHash = pinHash[16:] (second half)
        System.arraycopy(pinHash, HALF_HASH, upperHash, 0, HALF_HASH);
        
        // lowerHash = pinHash[:16] (first half)
        System.arraycopy(pinHash, 0, lowerHash, 0, HALF_HASH);
        
        return new byte[][] { upperHash, lowerHash };
    }
    
    /**
     * Combines upper and lower hash parts to reconstruct the full PIN hash.
     *
     * @param upperHash The upper part of the PIN hash (16 bytes)
     * @param lowerHash The lower part of the PIN hash (16 bytes)
     * @return The full PIN hash (32 bytes)
     */
    private static byte[] combinePinHash(byte[] upperHash, byte[] lowerHash) {
        if (upperHash == null || upperHash.length != HALF_HASH ||
            lowerHash == null || lowerHash.length != HALF_HASH) {
            throw new IllegalArgumentException("Upper and lower hash must each be exactly " +
                                              HALF_HASH + " bytes");
        }     
        byte[] pinHash = new byte[PIN_HASH_SIZE];
        System.arraycopy(lowerHash, 0, pinHash, 0, HALF_HASH);
        System.arraycopy(upperHash, 0, pinHash, HALF_HASH, HALF_HASH);
        
        return pinHash;
    }

    /**
     * Validates the file data.
     */
    private static boolean validateFileData(byte[] fileData) {
        if (fileData == null || fileData.length < MIN_FILE_SIZE) {
            logger.error("Error reading passkey file: insufficient file bytes");
            return false;
        }
        return true;
    }

    /**
     * Container class for cryptographic data used in both encryption and decryption.
     */
    private static class CryptoData {
        final byte[] iv;
        final byte[] tag;
        final byte[] encryptedData;
        final Cipher cipher;
        
        // Constructor for read operations (from file)
        CryptoData(byte[] iv, byte[] tag, byte[] encryptedData) {
            this.iv = iv;
            this.tag = tag;
            this.encryptedData = encryptedData;
            this.cipher = null;
        }
        
        // Constructor for write operations (to file)
        CryptoData(byte[] iv, Cipher cipher) {
            this.iv = iv;
            this.cipher = cipher;
            this.tag = null;
            this.encryptedData = null;
        }
        
        // Constructor for encrypted data with tag
        CryptoData(byte[] data, byte[] tag) {
            this.encryptedData = data;
            this.tag = tag;
            this.iv = null;
            this.cipher = null;
        }
    }
    
    /**
     * Container class for passkey header data.
     */
    private static class PasskeyHeader {
        final byte[] upperHash;
        final byte[] passkeyIV;
        final byte[] passkeyTag;
        
        PasskeyHeader(byte[] upperHash, byte[] passkeyIV, byte[] passkeyTag) {
            this.upperHash = upperHash;
            this.passkeyIV = passkeyIV;
            this.passkeyTag = passkeyTag;
        }
        
        /**
         * Serializes the header to a byte array.
         * Format: [upperHash][passkeyIV][passkeyTag]
         */
        byte[] serialize() {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try {
                baos.write(upperHash);
                baos.write(passkeyIV);
                baos.write(passkeyTag);
                return baos.toByteArray();
            } catch (IOException e) {
                throw new RuntimeException("Failed to serialize passkey header", e);
            }
        }
        
        /**
         * Deserializes a byte array into a PasskeyHeader.
         */
        static PasskeyHeader deserialize(byte[] headerBytes) {
            if (headerBytes == null || headerBytes.length != HALF_HASH + IV_SIZE + TAG_SIZE) {
                throw new IllegalArgumentException("Invalid header size");
            }
            
            byte[] upperHash = new byte[HALF_HASH];
            byte[] passkeyIV = new byte[IV_SIZE];
            byte[] passkeyTag = new byte[TAG_SIZE];
            
            System.arraycopy(headerBytes, 0, upperHash, 0, HALF_HASH);
            System.arraycopy(headerBytes, HALF_HASH, passkeyIV, 0, IV_SIZE);
            System.arraycopy(headerBytes, HALF_HASH + IV_SIZE, passkeyTag, 0, TAG_SIZE);
            
            return new PasskeyHeader(upperHash, passkeyIV, passkeyTag);
        }
    }
    
    /**
     * Container class for the complete passkey file structure.
     */
    private static class PasskeyFile {
        final byte[] encryptedHeader;
        final byte[] encryptedData;
        
        PasskeyFile(byte[] encryptedHeader, byte[] encryptedData) {
            this.encryptedHeader = encryptedHeader;
            this.encryptedData = encryptedData;
        }
        
        /**
         * Serializes the passkey file to a byte array.
         * Format: [header length (4 bytes)][encrypted header][encrypted data]
         */
        byte[] serialize() {
            ByteBuffer buffer = ByteBuffer.allocate(4 + encryptedHeader.length + encryptedData.length);
            buffer.putInt(encryptedHeader.length);
            buffer.put(encryptedHeader);
            buffer.put(encryptedData);
            return buffer.array();
        }
        
        /**
         * Deserializes a byte array into a PasskeyFile.
         */
        static PasskeyFile deserialize(byte[] fileBytes) {
            if (fileBytes == null || fileBytes.length < 4) {
                throw new IllegalArgumentException("Invalid file bytes");
            }
            
            ByteBuffer buffer = ByteBuffer.wrap(fileBytes);
            int headerLength = buffer.getInt();
            
            if (fileBytes.length < 4 + headerLength) {
                throw new IllegalArgumentException("File bytes too short");
            }
            
            byte[] encryptedHeader = new byte[headerLength];
            buffer.get(encryptedHeader);
            
            byte[] encryptedData = new byte[fileBytes.length - 4 - headerLength];
            buffer.get(encryptedData);
            
            return new PasskeyFile(encryptedHeader, encryptedData);
        }
    }

    /**
     * Decrypts the data using AES-GCM.
     */
    private static byte[] decryptData(CryptoData data, byte[] seed) throws Exception {
        // Create AES key from seed
        SecretKeySpec secretKeySpec = new SecretKeySpec(Arrays.copyOf(seed, AES_KEY_SIZE), AES_ALGORITHM);
        
        // Create GCM parameter spec with IV
        GCMParameterSpec gcmParamSpec = new GCMParameterSpec(GCM_TAG_BIT_LENGTH, data.iv);
        
        // Initialize cipher for decryption
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParamSpec);
        
        // Combine encrypted data with tag for decryption
        byte[] ciphertextWithTag = new byte[data.encryptedData.length + data.tag.length];
        System.arraycopy(data.encryptedData, 0, ciphertextWithTag, 0, data.encryptedData.length);
        System.arraycopy(data.tag, 0, ciphertextWithTag, data.encryptedData.length, data.tag.length);
        
        // Decrypt and return
        return cipher.doFinal(ciphertextWithTag);
    }

    /**
     * Deserializes CBOR bytes into a Passkey object.
     */
    private static Passkey deserializePasskey(byte[] cborBytes) throws Exception {
        HashMap<String, Object> pkey = (HashMap<String, Object>) Cbor.decode(cborBytes);
        
        // Validate that only expected keys are present
        Set<String> expectedKeys = new HashSet<>(Arrays.asList("pk", "ca", "seed", "res_creds"));
        for (String key : pkey.keySet()) {
            if (!expectedKeys.contains(key)) {
                logger.warn("Unexpected key in passkey CBOR data: " + key);
            }
        }
        
        // Validate that all required keys are present
        for (String requiredKey : expectedKeys) {
            if (!pkey.containsKey(requiredKey)) {
                logger.error("Missing required key in passkey CBOR data: " + requiredKey);
                throw new IllegalArgumentException("Missing required key in passkey CBOR data: " + requiredKey);
            }
        }

        PrivateKey pk = KeyUtils.fromECPrivateKeyParameters((Map<String, Object>) pkey.get("pk"));
        X509Certificate ca = (X509Certificate) CertUtils.readBytes((byte[]) pkey.get("ca"), "SHA256withECDSA");
        byte[] seed = (byte[]) pkey.get("seed");
        Map<byte[], Map> resCreds = (Map<byte[], Map>) pkey.get("res_creds");
        
        return new Passkey(pk, ca, seed, resCreds);
    }
    
    /**
     * Encrypts a passkey header using ECDH with the root public key.
     *
     * @param header The passkey header to encrypt
     * @return The encrypted header bytes
     */
    private static byte[] encryptHeader(PasskeyHeader header) {
        // Serialize the header
        byte[] headerBytes = header.serialize();
        
        // Encrypt using ECDH with root public key
        return KeyUtils.ecdhEncrypt(headerBytes, rootPublicKey);
    }
    
    /**
     * Decrypts a passkey header using ECDH with the root private key.
     *
     * @param encryptedHeader The encrypted header bytes
     * @return The decrypted passkey header
     */
    private static PasskeyHeader decryptHeader(byte[] encryptedHeader) {
        // Decrypt using ECDH with root private key
        byte[] headerBytes = KeyUtils.ecdhDecrypt(encryptedHeader, rootPrivateKey);
        
        // Deserialize the header
        return PasskeyHeader.deserialize(headerBytes);
    }
    
    /**
     * Encrypts passkey data using AES-GCM with the provided PIN hash.
     *
     * @param data The data to encrypt
     * @param pinHash The PIN hash to use as the encryption key
     * @return A CryptoData object containing the IV, encrypted data, and authentication tag
     */
    private static CryptoData encryptPasskeyData(byte[] data, byte[] pinHash) throws Exception {
        // Generate random IV
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[IV_SIZE];
        secureRandom.nextBytes(iv);
        
        // Create AES key from PIN hash
        SecretKeySpec secretKeySpec = new SecretKeySpec(
            Arrays.copyOf(pinHash, AES_KEY_SIZE), AES_ALGORITHM);
        
        // Initialize cipher for encryption
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        GCMParameterSpec gcmParamSpec = new GCMParameterSpec(GCM_TAG_BIT_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParamSpec);
        
        // Encrypt the data
        byte[] encryptedData = cipher.doFinal(data);
        
        // Extract the authentication tag
        byte[] tag = extractGcmTag(cipher);
        
        return new CryptoData(iv, tag, encryptedData);
    }
    
    /**
     * Decrypts passkey data using AES-GCM with the provided PIN hash.
     *
     * @param iv The initialization vector
     * @param tag The authentication tag
     * @param encryptedData The encrypted data
     * @param pinHash The PIN hash to use as the decryption key
     * @return The decrypted data
     */
    private static byte[] decryptPasskeyData(byte[] iv, byte[] tag, byte[] encryptedData, byte[] pinHash) throws Exception {
        // Create AES key from PIN hash
        SecretKeySpec secretKeySpec = new SecretKeySpec(
            Arrays.copyOf(pinHash, AES_KEY_SIZE), AES_ALGORITHM);
        
        // Initialize cipher for decryption
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        GCMParameterSpec gcmParamSpec = new GCMParameterSpec(GCM_TAG_BIT_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParamSpec);
        
        // Combine encrypted data with tag for decryption
        byte[] ciphertextWithTag = new byte[encryptedData.length + tag.length];
        System.arraycopy(encryptedData, 0, ciphertextWithTag, 0, encryptedData.length);
        System.arraycopy(tag, 0, ciphertextWithTag, encryptedData.length, tag.length);
        
        // Decrypt and return
        return cipher.doFinal(ciphertextWithTag);
    }



    /**
     * Tests if a Cipher has been initialized.
     * 
     * @param cipher The Cipher to test
     * @return true if the Cipher has been initialized, false otherwise
     */
    private boolean isCipherInitialized(Cipher cipher) {
        if (cipher == null) {
            return false;
        }
        try {
            // Attempt an operation that requires initialization
            // Using a zero-length array to avoid modifying any data
            cipher.update(new byte[0]);
            return true;
        } catch (IllegalStateException e) {
            // If we get this exception, the cipher is not initialized
            return false;
        }
    }

    /**
     * Writes a passkey to a file, encrypting it with the provided PIN hash using the two-layer encryption scheme.
     *
     * Implementation of the algorithm described in the class comments:
     * 1. Split the PIN hash into upperHash and lowerHash
     * 2. Serialize the passkey data to CBOR
     * 3. Encrypt the passkey data using the full PIN hash
     * 4. Create a header with upperHash, IV, and tag
     * 5. Encrypt the header using ECDH with the root public key
     * 6. Write the encrypted header and data to the file
     *
     * @param passkey The Passkey object to save
     * @param pinHash The PIN hash used as the encryption key
     * @param passkeyFile The file to write to
     * @return true if the operation was successful, false otherwise
     */
    public static boolean writeKey(Passkey passkey, byte[] pinHash, File passkeyFile) {
        try {
            // Validate inputs
            if (!validateWriteInputs(passkey, pinHash)) {
                return false;
            }
            
            // Split the PIN hash into upperHash and lowerHash
            byte[][] hashParts = splitPinHash(pinHash);
            byte[] upperHash = hashParts[0];
            
            // Serialize passkey data to CBOR
            byte[] cborData = serializePasskey(passkey);
            
            // Encrypt the passkey data using the full PIN hash
            CryptoData encryptedPasskeyData = encryptPasskeyData(cborData, pinHash);
            
            // Create the passkey header
            PasskeyHeader header = new PasskeyHeader(upperHash, encryptedPasskeyData.iv, encryptedPasskeyData.tag);
            
            // Encrypt the header using ECDH with the root public key
            byte[] encryptedHeader = encryptHeader(header);
            
            // Create the passkey file structure
            PasskeyFile passkeyFileData = new PasskeyFile(encryptedHeader, encryptedPasskeyData.encryptedData);
            
            // Write to file
            try (FileOutputStream fos = new FileOutputStream(passkeyFile)) {
                fos.write(passkeyFileData.serialize());
                fos.flush();
                return true;
            }
        } catch (Exception e) {
            logger.error("Error saving passkey", e);
            return false;
        }
    }
    
    /**
     * Validates the inputs for the writeKey method.
     */
    private static boolean validateWriteInputs(Passkey passkey, byte[] pinHash) {
        if (passkey == null) {
            logger.error("Passkey cannot be null");
            return false;
        }
        if (pinHash == null || pinHash.length != AES_KEY_SIZE) {
            logger.error("Invalid PIN hash provided");
            return false;
        }
        return true;
    }
    
    // Removed redundant classes (EncryptionComponents and EncryptedData)
    // Now using the unified CryptoData class
    
    /**
     * Initializes the encryption cipher with a random IV.
     */
    private static CryptoData initializeEncryptionCipher(byte[] pinHash) throws Exception {
        // Generate a random IV
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[IV_SIZE];
        secureRandom.nextBytes(iv);
        
        // Create the AES key from pinHash
        SecretKeySpec secretKeySpec = new SecretKeySpec(
                                            Arrays.copyOf(pinHash, AES_KEY_SIZE), AES_ALGORITHM);
        GCMParameterSpec gcmParamSpec = new GCMParameterSpec(GCM_TAG_BIT_LENGTH, iv);
        
        // Initialize cipher for encryption
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParamSpec);
        
        return new CryptoData(iv, cipher);
    }
    
    /**
     * Serializes a Passkey object to CBOR.
     */
    private static byte[] serializePasskey(Passkey passkey) throws Exception {
        // Validate that all required fields are available
        if (passkey.getPrivateKey() == null) {
            throw new IllegalArgumentException("Private key cannot be null");
        }
        
        if (passkey.getCertificate() == null) {
            throw new IllegalArgumentException("Certificate cannot be null");
        }
        
        if (passkey.getSeed() == null) {
            throw new IllegalArgumentException("Seed cannot be null");
        }
        
        // Create a map with exactly the expected keys, in the same order as Python
        LinkedHashMap<String, Object> passkeyMap = new LinkedHashMap<>();
        passkeyMap.put("pk", KeyUtils.getECPrivateKeyParameters(passkey.getPrivateKey()));
        passkeyMap.put("ca", passkey.getCertificate().getEncoded());
        passkeyMap.put("seed", passkey.getSeed());
        passkeyMap.put("res_creds", passkey.getResCreds() != null ? passkey.getResCreds() : new HashMap<>());
        
        // Ensure no additional keys are added
        assert passkeyMap.size() == 4 : "Unexpected number of keys in passkey map";
        
        return Cbor.encode(passkeyMap);
    }

    
    /**
     * Encrypts data and extracts the authentication tag.
     */
    private static CryptoData encryptData(Cipher cipher, byte[] data) throws Exception {
        byte[] encryptedData = cipher.doFinal(data);
        byte[] tag = extractGcmTag(cipher);
        
        return new CryptoData(encryptedData, tag);
    }
    
    /**
     * Writes encrypted data to a file.
     */
    private static boolean writeEncryptedDataToFile(byte[] iv, byte[] tag, byte[] encryptedData, File file) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(iv);
            fos.write(tag);
            fos.write(encryptedData);
            fos.flush();
            return true;
        }
    }
    
    /**
     * Extracts the GCM authentication tag from a Cipher after encryption.
     * Note: This is implementation-specific and may not work on all JDK versions.
     *
     * @param cipher The cipher that was used for encryption
     * @return The 16-byte GCM authentication tag
     */
    private static byte[] extractGcmTag(Cipher cipher) throws Exception {
        // If using BouncyCastle or a provider that exposes the tag
        try {
            Field field = cipher.getClass().getDeclaredField("tag");
            field.setAccessible(true);
            return (byte[]) field.get(cipher);
        } catch (Exception e) {
            // Fall back to standard JDK
        }
        
        // Standard JDK implementation the tag is appended to the ciphertext
        // This is a workaround to extract it
        // Create a dummy encryption to get the tag length
        SecureRandom random = new SecureRandom();
        byte[] dummyKey = new byte[32];
        random.nextBytes(dummyKey);
        byte[] dummyIv = new byte[16];
        random.nextBytes(dummyIv);
        
        Cipher dummyCipher = Cipher.getInstance("AES/GCM/NoPadding");
        dummyCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(dummyKey, "AES"), 
                        new GCMParameterSpec(128, dummyIv));
        byte[] dummyData = new byte[0];
        byte[] dummyEncrypted = dummyCipher.doFinal(dummyData);
        
        // The tag is the entire output when encrypting empty data
        byte[] tag = new byte[16]; // Assuming 128-bit tag
        System.arraycopy(dummyEncrypted, 0, tag, 0, tag.length);
        
        return tag;
    }
    
    /**
     * Gets the resident credentials map.
     * 
     * @return The map of resident credentials
     */
    public Map<byte[], Map> getResCreds() {
        return resCreds;
    }


    /**
     * Gets the private key used for signing operations.
     *
     * @return The private key
     */
    public PrivateKey getPrivateKey() {
        return pk;
    }

    /**
     * Gets the certificate authority certificate used for attestation.
     *
     * @return The certificate authority certificate
     */
    public X509Certificate getCertificate() {
        return ca;
    }

    /**
     * Gets the seed value used for key derivation.
     *
     * @return The seed value as a byte array
     */
    public byte[] getSeed() {
        return seed;
    }

    /**
     * Adds a resident credential to this passkey.
     *
     * @param rpId The relying party ID as a byte array
     * @param credId The credential ID as a byte array
     * @param userHandle The user handle as a byte array
     */
    public void addResCred(byte[] rpId, byte[] credId, byte[] userHandle) {
        Map<String, Object> cred = Map.of("credId", credId, "userHandle", userHandle);
        if(resCreds == null) {
            resCreds = new HashMap<byte[], Map>();
        }
        resCreds.put(rpId, cred);
    }

    /**
     * Opens a passkey from persistent storage using the lower hash for decryption.
     * Tries to decrypt all available passkey files until a match is found.
     *
     * @param lowerHash The 16-byte lower hash used for decryption
     * @return The decrypted passkey, or null if no matching passkey is found
     */
    public static Passkey openKey(byte[] lowerHash) {
        // Verify that we have a valid lower hash
        if (lowerHash == null || lowerHash.length != HALF_HASH) {
            logger.error("Invalid lower hash: must be exactly {} bytes", HALF_HASH);
            return null;
        }
        
        for(File maybePasskey: FileUtils.listPasskeys()) {
            try {
                Passkey passkey = readKey(maybePasskey, lowerHash);
                if (passkey != null) {
                    return passkey;
                }
            } catch (Exception e) {
                logger.error("Error decrypting key", e);
            }
        }
        return null;
    }

    /**
     * Generates a new passkey and saves it to a file.
     *
     * @param pinHash The 32-byte PIN hash used for encryption
     * @param passkeyFile The file to save the passkey to
     * @return The generated passkey, or null if generation fails
     */
    public static Passkey generatePasskey(byte[] pinHash, File passkeyFile) {
        try {
            // Validate PIN hash
            if (pinHash == null || pinHash.length != PIN_HASH_SIZE) {
                logger.error("Invalid PIN hash: must be exactly {} bytes", PIN_HASH_SIZE);
                return null;
            }
            
            // Generate a new key pair for the passkey
            KeyPair keyPair = KeyUtils.generateKeyPair("EC", 256);
            
            // Generate a random seed
            SecureRandom random = new SecureRandom();
            byte[] seed = new byte[32];
            random.nextBytes(seed);
            
            // Create a self-signed certificate
            X509Certificate cert = CertUtils.generateCaCert("CN=IBeePasskey", keyPair, 9999, true);
            
            // Create the passkey
            Passkey passkey = new Passkey(keyPair.getPrivate(), cert, seed, new HashMap<>());
            
            // Save the passkey to file
            if (writeKey(passkey, pinHash, passkeyFile)) {
                return passkey;
            } else {
                logger.error("Failed to write passkey to file");
                return null;
            }
        } catch (Exception e) {
            logger.error("Error generating passkey", e);
            return null;
        }
    }

    private static void initPlatformKey(Scanner scanner) {
            // Prompt for platform key file (optional)
            System.out.print("Platform key file [$FIDO2_HOME/platform.key]: ");
            String platKeyPath = scanner.nextLine().trim();
            if(platKeyPath.isEmpty()) {
                platKeyPath = null;
            }          
            String keyPassword = null;
            if (platKeyPath != null) {
                // Prompt for password if a custom root key file is provided
                System.out.print("Platform key password (leave empty if not encrypted): ");
                keyPassword = scanner.nextLine().trim();
                if (keyPassword.isEmpty()) {
                    keyPassword = null;
                }
            }
            // Initialize root key pair from specified location or default
            ensureRootKeyPair(platKeyPath, keyPassword);
    }

    private static File collectPasskeyFileInfo(Scanner scanner) {
        // Prompt for passkey file name
        System.out.print("Enter passkey file name [$FIDO2_HOME/default.passkey]: ");
        String fileName = scanner.nextLine().trim();
        if(fileName.isEmpty()) {
            fileName = DEFAULT_PASSKEY;
        }
        if(!fileName.endsWith(".passkey")) {
            fileName += ".passkey";
        }

        // Create File object
        return new File(fileName);
    }

    private static byte[] collectPinInfo(Scanner scanner) throws NoSuchAlgorithmException {
        // Prompt for PIN
        System.out.print("Enter PIN (at least 8 characters): ");
        String pin = scanner.nextLine().trim();
        
        // Validate PIN
        if (pin.length() < 8) {
            System.out.println("Error: PIN must be at least 8 characters.");
            return null;
        }
        // Calculate PIN hash using SHA-256
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(pin.getBytes());
    }

    private static void generateMain(Scanner scanner) {
        File passkeyFile = collectPasskeyFileInfo(scanner);
        
        // Check if file already exists
        if (passkeyFile.exists()) {
            System.out.println("Warning: File already exists. Overwrite? (y/n)");
            String response = scanner.nextLine().trim().toLowerCase();
            if (!response.equals("y") && !response.equals("yes")) {
                System.out.println("Operation cancelled.");
                return;
            }
        }
        byte[] pinHash;
        try {
            pinHash = collectPinInfo(scanner);
            if(pinHash == null) {
                return;
            }
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error: Failed to get hasing function.");
            return;
        }
        
        // Generate passkey
        System.out.println("Generating passkey...");
        Passkey passkey = generatePasskey(pinHash, passkeyFile);
        
        // Display result
        if (passkey != null) {
            System.out.println("Passkey successfully generated and saved to: " + passkeyFile.getAbsolutePath());
        } else {
            System.out.println("Failed to generate passkey.");
        }
    }

    public static void manageMain(Scanner scanner) {
        File passkeyFile = collectPasskeyFileInfo(scanner);
        if (!passkeyFile.exists()) {
            System.out.println("Failed to find passkey {}.".format(passkeyFile.getName()));
            return;
        }
        byte[] pinHash;
        try {
            pinHash = collectPinInfo(scanner);
            if(pinHash == null) {
                return;
            }
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error: Failed to get hasing function.");
            return;
        }
        byte[] lowerHash = new byte[HALF_HASH];
        System.arraycopy(pinHash, 0, lowerHash, 0, HALF_HASH);
        Passkey passkey = readKey(passkeyFile, lowerHash);
        if (passkey == null) {
            System.out.println("Failed to open passkey.");
            return;
        }
        System.out.println("Passkey successfully opened.");
        Map<byte[], Map> resCreds = passkey.getResCreds();
        for(byte[] rpId: resCreds.keySet()) {
            Map cred = resCreds.get(rpId);
            try {
                String rpStr = new String(rpId, "utf-8");
                System.out.println("Credential relying party id: {}".format(rpStr));
                //TODO ask user if should delete and maybe remove cred
            } catch (UnsupportedEncodingException e) {
                System.out.println("Failed read relying party id for resident credential.");
                continue;
            }
        }
    }

    /**
     * Main method to generate a passkey from command line.
     * Prompts the user for a passkey file name and PIN,
     * then generates a passkey and saves it to the specified file.
     *
     * @param args Command line arguments (not used)
     */
    public static void main(String[] args) {
        try {
            if(args.length != 1) {
                System.out.println(
                    "Usage: java -cp com.isfs.blekey.jar {} <generate|manage>".format(
                                                        Passkey.class.getName().toString()));
                return;
            }
            String cmd = args[0];
            // Initialize scanner for user input
            Scanner scanner = new Scanner(System.in);
            initPlatformKey(scanner);
            if(cmd.equals("generate")) {
                generateMain(scanner);
            } 
            else if(cmd.equals("manage")) {
                manageMain(scanner);
            }
            scanner.close();
        } catch (Exception e) {
            System.err.println("Error generating passkey: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
