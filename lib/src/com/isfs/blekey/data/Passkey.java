/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.data;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.UnsupportedEncodingException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.FileSystems;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.isfs.blekey.credential.VerifiableCredential;
import com.isfs.blekey.util.FileUtils;
import com.isfs.blekey.util.KeyUtils;
import com.isfs.blekey.util.CertUtils;
import com.isfs.blekey.util.Cbor;
import com.isfs.blekey.util.KeystoreManager;

/**
 * Represents a FIDO2 passkey with secure storage capabilities.
 *
 * The passkey file implements a two-layer encryption scheme for enhanced security:
 *
 * 1. PIN Hash Splitting:
 *    - The 32-byte PIN hash is split into two 16-byte parts: upperHash and lowerHash
 *    - Only the lowerHash (first 16 bytes) is required from the user for decryption
 *    - The upperHash (last 16 bytes) is cached in the encrypted header for PIN auth protocol
 *
 * 2. File Structure (in order):
 *    - Header (230 bytes): Encrypted upperHash using ECDH with platform public key or KSM
 *    - Length prefix (4 bytes, little-endian): Length of PKCS12 data
 *    - PKCS12 data (variable): Contains passkey private key and X.509 certificate, encrypted with full PIN hash
 *    - Resident credentials (variable): CBOR-encoded array of credentials, ECDH encrypted with passkey public key
 *      Each credential contains: {"cred.id": bytes, "user.id": bytes, "rp.id": bytes}
 *
 * 3. Encryption Process (writeKey):
 *    - Split PIN hash into upperHash and lowerHash
 *    - Encrypt upperHash with KSM (if available) or ECDH with platform public key -> header
 *    - Serialize passkey (private key + certificate) to PKCS12 using full PIN hash
 *    - ECDH encrypt resident credentials using passkey's public key
 *    - Write: [header][length][PKCS12 data][encrypted resident credentials]
 *
 * 4. Decryption Process (readKey):
 *    - User provides lowerHash (16 bytes) or full PIN hash (32 bytes)
 *    - Read header and decrypt with KSM or platform private key -> upperHash
 *    - Read length prefix (little-endian) to determine PKCS12 data size
 *    - Reconstruct full PIN hash: [lowerHash][upperHash] (if only lowerHash provided)
 *    - Decrypt PKCS12 data using full PIN hash -> passkey private key and certificate
 *    - ECDH decrypt resident credentials using passkey's private key
 *    - Decode CBOR to get list of resident credentials
 *
 * 5. Platform Key Pair:
 *    - A persistent EC key pair used for ECDH encryption/decryption of the cached upperHash
 *    - Loaded from PKCS8 file in FIDO2_HOME directory (default: $FIDO2_HOME/platform.key)
 *    - Generated automatically if not found
 *    - Can be password-protected (optional)
 *
 * 6. Keystore Manager (KSM):
 *    - Platform-specific secure storage (e.g., Android Keystore, iOS Keychain)
 *    - Used as primary encryption method for upperHash if available
 *    - Falls back to ECDH with platform key pair if KSM unavailable
 *
 * This approach provides layered encryption and PIN verification while only requiring
 * the user to provide half of the PIN hash (lowerHash) for authentication.
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
    private List<Map<String, byte[]>> resCreds;
    
    /**
     * List of verifiable credentials associated with this passkey.
     * This is optional and may be null for passkeys that don't have digital credentials.
     */
    private List<VerifiableCredential> verifiableCredentials;

    /**
     * The file name of this passkey (without path).
     */
    private String fileName;

    /**
     * Logger for debugging and error reporting.
     */
    private static final Logger logger = LoggerFactory.getLogger(Passkey.class);
    
    /**
     * Constants for ecdh encrypt pin hash operations
     */
    private static final int HEADER_SIZE = 230;
    
    /**
     * Default names for file objects
     */
    private static final String PLATFORM_KEY = "platform.key";
    private static final String DEFAULT_PASSKEY = "default.passkey";
    
    /**
     * Constants for key generation
     */
    private static final String KEY_ALGORITHM = "ECDSA";
    private static final int KEY_SIZE = 256;

    private static final int PIN_HASH_SIZE = 32;
    private static final int HALF_HASH = PIN_HASH_SIZE / 2;
    
    /**
     * Root key for ECDH encryption/decryption
     * In a real implementation, this would be securely stored and accessed
     */
    private static PublicKey rootPublicKey;
    private static PrivateKey rootPrivateKey;
    
    /**
     * Platform-specific keystore manager for app key encryption
     * This should be set during application initialization
     */
    private static KeystoreManager keystoreManager;
    
    /**
     * Sets the platform-specific keystore manager.
     * This should be called during application initialization before any passkey operations.
     *
     * @param manager The KeystoreManager implementation for the current platform
     */
    public static void setKeystoreManager(KeystoreManager manager) {
        keystoreManager = manager;
        logger.info("KeystoreManager set: {}", manager != null ? manager.getClass().getSimpleName() : "null");
    }
    
    /**
     * Gets the current keystore manager.
     *
     * @return The current KeystoreManager instance, or null if not set
     */
    public static KeystoreManager getKeystoreManager() {
        return keystoreManager;
    }
    
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
            PrivateKey privateKey = FileUtils.readPrivatePEM(new File(pkcs8File), password);
            
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
     * Ensures a root key pair is available for ECDH encryption/decryption.
     * Tries to read from the specified PKCS8 file first, falls back to default location,
     * and finally throws an exception if no key can be loaded.
     *
     * @param keyPath Path to the PKCS8 file, or null to use the default location
     * @param password Password for the encrypted PKCS8 file, or null if the file is not encrypted
     */
    public static void ensureRootKeyPair(String keyPath, String password) {
        if (rootPublicKey != null && rootPrivateKey != null) {
            return; // Key pair already initialized
        }
        
        // Resolve the key file path
        String resolvedKeyPath = resolveKeyFilePath(keyPath);
        File keyFile = new File(resolvedKeyPath);
        
        // Try to load existing key or generate a new one
        if (keyFile.exists()) {
            loadExistingKey(resolvedKeyPath, password);
        } else {
            generateAndSaveNewKey(resolvedKeyPath);
        }
        
        // Verify key was loaded or generated
        if (rootPublicKey == null || rootPrivateKey == null) {
            throw new RuntimeException("Failed to read or generate platform key pair");
        }
    }
    
    /**
     * Resolves the key file path, using the provided path or the default location.
     *
     * @param keyPath Custom key path or null for default
     * @return The resolved key file path
     */
    private static String resolveKeyFilePath(String keyPath) {
        if (keyPath != null) {
            return keyPath;
        }
        
        String fido2Home = FileUtils.getFido2Home();
        if (fido2Home == null || fido2Home.isEmpty()) {
            throw new RuntimeException("FIDO2_HOME environment variable or system property is not set");
        }
        
        return fido2Home + FileSystems.getDefault().getSeparator() + PLATFORM_KEY;
    }
    
    /**
     * Loads an existing key from the specified path.
     *
     * @param keyPath Path to the key file
     * @param password Password for the encrypted key file, or null if not encrypted
     */
    private static void loadExistingKey(String keyPath, String password) {
        try {
            boolean keyLoaded = initRootKeyPair(keyPath, password);
            if (!keyLoaded) {
                logger.warn("Failed to initialize root key pair from {}", keyPath);
            }
        } catch (Exception e) {
            logger.warn("Failed to read platform key from {}", keyPath, e);
        }
    }
    
    /**
     * Generates a new key pair and saves it to the specified path.
     *
     * @param keyPath Path to save the new key
     */
    private static void generateAndSaveNewKey(String keyPath) {
        try {
            logger.info("Platform key not found, generating a new one at {}", keyPath);
            
            // Generate a new EC key pair
            KeyPair keyPair = KeyUtils.generateKeyPair(KEY_ALGORITHM, KEY_SIZE);
            File keyFile = new File(keyPath);
            FileUtils.writePrivatePEM(keyPair.getPrivate(), keyFile);
            
            rootPublicKey = keyPair.getPublic();
            rootPrivateKey = keyPair.getPrivate();
            
            logger.info("Generated and saved new platform key at: {}", keyPath);
        } catch (IOException e) {
            logger.error("Failed to write platform key to file: {}", keyPath, e);
            throw new RuntimeException("Failed to write platform key to file: " + keyPath, e);
        } catch (Exception e) {
            logger.error("Failed to generate platform key", e);
            throw new RuntimeException("Failed to generate platform key", e);
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
    protected Passkey(PrivateKey key, X509Certificate cert, List<Map<String, byte[]>> creds) {
        this.pk = key;
        this.ca = cert;
        this.resCreds = creds;
        this.verifiableCredentials = null;
        this.fileName = null;
    }

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
    @SuppressWarnings("unchecked")
    protected static Passkey readKey(File pkeyFile, byte[] lowerHash) {
        try {
            // Validate inputs
            if (!validateInputs(pkeyFile, lowerHash)) {
                return null;
            }
            
            // Read and parse file data
            byte[] fileData;
            try {
                logger.debug("Attempting to read passkey file: {}", pkeyFile.getAbsolutePath());
                logger.debug("File exists: {}, canRead: {}, length: {}",
                    pkeyFile.exists(), pkeyFile.canRead(), pkeyFile.length());
                fileData = FileUtils.readFileBytes(pkeyFile);
                logger.debug("Read {} bytes from file", fileData != null ? fileData.length : "null");
            } catch (java.io.IOException e) {
                logger.error("IOException reading passkey file: {}", e.getMessage(), e);
                return null;
            } catch (Exception e) {
                logger.error("Unexpected exception reading passkey file: {}", e.getMessage(), e);
                return null;
            }
            
            if (!validateFileData(fileData)) {
                return null;
            }

            logger.debug("File size: {} bytes", fileData.length);
            byte[] upperHashObf = Arrays.copyOfRange(fileData, 0, HEADER_SIZE);
            byte[] upperHash = keystoreManager.isKeystoreAvailable() ?
                        KeyUtils.ksmDecrypt(upperHashObf, keystoreManager) : KeyUtils.ecdhDecrypt(upperHashObf, rootPrivateKey);
            
            byte[] passkeyData = Arrays.copyOfRange(fileData, HEADER_SIZE, fileData.length);
            
            logger.debug("Header size: {}, Passkey data size: {}", HEADER_SIZE, passkeyData.length);
            
            ByteBuffer buffer = ByteBuffer.wrap(Arrays.copyOfRange(passkeyData, 0, 4));
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            int p12Len = buffer.getInt();
            
            logger.debug("PKCS12 length from file: {}", p12Len);
            
            if (p12Len < 0 || p12Len > passkeyData.length - 4) {
                logger.error("Invalid PKCS12 length: {} (passkey data size: {})", p12Len, passkeyData.length);
                return null;
            }
            
            byte[] p12Bytes = Arrays.copyOfRange(passkeyData, 4, p12Len + 4);
            
            int remainingDataStart = p12Len + 4;
            byte[] remainingData = Arrays.copyOfRange(passkeyData, remainingDataStart, passkeyData.length);
            
            // Reconstruct the full PIN hash
            byte[] pinHash = (lowerHash.length == 32) ? lowerHash : getCachedPinHash(upperHash, lowerHash);
            KeyStore pki = KeyUtils.readPKCS12(p12Bytes, pinHash);
            PrivateKey key = (PrivateKey) pki.getKey("1", null);
            X509Certificate cert = (X509Certificate) pki.getCertificate("1");
            
            // Parse remaining data: could be just resident credentials, or resident credentials + VC section
            List<Map<String, byte[]>> resCreds;
            List<VerifiableCredential> vcs = null;
            
            // Check if there's a VC section length marker (4 bytes before end)
            if (remainingData.length >= 4) {
                // Try to read VC section length from the last 4 bytes
                int potentialVcSectionStart = remainingData.length - 4;
                ByteBuffer vcLenBuffer = ByteBuffer.wrap(Arrays.copyOfRange(remainingData, potentialVcSectionStart, remainingData.length));
                vcLenBuffer.order(ByteOrder.LITTLE_ENDIAN);
                int vcSectionLen = vcLenBuffer.getInt();
                
                // Validate: VC section length should be reasonable and fit within remaining data
                if (vcSectionLen > 0 && vcSectionLen < remainingData.length - 4) {
                    // This looks like a file with VC section
                    int vcDataStart = potentialVcSectionStart - vcSectionLen;
                    if (vcDataStart >= 0) {
                        // Extract resident credentials (everything before VC data)
                        byte[] encResCreds = Arrays.copyOfRange(remainingData, 0, vcDataStart);
                        byte[] cborResCreds = KeyUtils.ecdhDecrypt(encResCreds, key);
                        resCreds = (List<Map<String, byte[]>>) Cbor.decode(cborResCreds);
                        
                        // Extract and decrypt VC section
                        byte[] encVcData = Arrays.copyOfRange(remainingData, vcDataStart, potentialVcSectionStart);
                        vcs = readVerifiableCredentials(encVcData, key);
                    } else {
                        // Invalid VC section, treat as old format
                        byte[] cborResCreds = KeyUtils.ecdhDecrypt(remainingData, key);
                        resCreds = (List<Map<String, byte[]>>) Cbor.decode(cborResCreds);
                    }
                } else {
                    // No valid VC section, treat as old format
                    byte[] cborResCreds = KeyUtils.ecdhDecrypt(remainingData, key);
                    resCreds = (List<Map<String, byte[]>>) Cbor.decode(cborResCreds);
                }
            } else {
                // Too small for VC section, treat as old format
                byte[] cborResCreds = KeyUtils.ecdhDecrypt(remainingData, key);
                resCreds = (List<Map<String, byte[]>>) Cbor.decode(cborResCreds);
            }
            
            Passkey passkey = new Passkey(key, cert, resCreds);
            passkey.verifiableCredentials = vcs;
            passkey.fileName = pkeyFile.getName();
            return passkey;
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
     * @param encUpperHash The encrypted upper part of the PIN hash (280 bytes)
     * @param lowerHash The lower part of the PIN hash (16 bytes)
     * @return The full PIN hash (32 bytes)
     */
    private static byte[] getCachedPinHash(byte[] upperHash, byte[] lowerHash) {
        if (upperHash == null || upperHash.length != HALF_HASH ||
            lowerHash == null || lowerHash.length != HALF_HASH) {
            throw new IllegalArgumentException("Upper hash must be " + HALF_HASH +
                                              " bytes and lower hash must be " + HALF_HASH + " bytes");
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
        if (fileData == null || fileData.length < HEADER_SIZE) {
            logger.error("Error reading passkey file: insufficient file bytes (expected at least {} bytes, got {})",
                        HEADER_SIZE, fileData != null ? fileData.length : 0);
            return false;
        }
        return true;
    }

    
    // Register BouncyCastle provider statically
    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
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
            byte[] passkeyData = serializePasskey(passkey, pinHash);
            
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            
            // Encrypt upper hash with app key if available, then with ECDH as fallback
            byte[] pinHashCiphertext = keystoreManager.isKeystoreAvailable() ? 
                        KeyUtils.ksmEncrypt(upperHash, keystoreManager) : KeyUtils.ecdhEncrypt(upperHash, rootPublicKey);
            bos.write(pinHashCiphertext);
            bos.write(passkeyData);
            
            // Write to file
            try (FileOutputStream fos = new FileOutputStream(passkeyFile)) {
                fos.write(bos.toByteArray());
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
        if (pinHash == null || pinHash.length != PIN_HASH_SIZE) {
            logger.error("Invalid PIN hash provided");
            return false;
        }
        return true;
    }
    
    /**
     * Serializes a Passkey object to CBOR.
     */
    private static byte[] serializePasskey(Passkey passkey, byte[] pinHash) throws Exception {
        // Validate that all required fields are available
        if (passkey.getPrivateKey() == null) {
            throw new IllegalArgumentException("Private key cannot be null");
        }
        ECPrivateKey key = (ECPrivateKey) passkey.getPrivateKey();
        
        if (passkey.getCertificate() == null) {
            throw new IllegalArgumentException("Certificate cannot be null");
        }
        X509Certificate cert = passkey.getCertificate();
        byte[] p12_bytes = KeyUtils.writePKCS12(key, cert, pinHash);

        ECPublicKey pub = KeyUtils.publicFromPrivate(key);
        byte[] encResCreds = KeyUtils.ecdhEncrypt(Cbor.encode(passkey.getResCreds()), pub);
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(p12_bytes.length);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(buffer.array());
        outputStream.write(p12_bytes);
        outputStream.write(encResCreds);
        
        // Add VC section if present
        if (passkey.verifiableCredentials != null && !passkey.verifiableCredentials.isEmpty()) {
            byte[] vcData = writeVerifiableCredentials(passkey.verifiableCredentials, pub);
            outputStream.write(vcData);
            
            // Write VC section length (4 bytes, little-endian)
            ByteBuffer vcLenBuffer = ByteBuffer.allocate(4);
            vcLenBuffer.order(ByteOrder.LITTLE_ENDIAN);
            vcLenBuffer.putInt(vcData.length);
            outputStream.write(vcLenBuffer.array());
        }
        
        return outputStream.toByteArray();
    }
    
    /**
     * Reads and decrypts verifiable credentials from encrypted data.
     *
     * @param encryptedData Encrypted VC data
     * @param privateKey Private key for ECDH decryption
     * @return List of VerifiableCredential objects, or null if decryption fails
     */
    private static List<VerifiableCredential> readVerifiableCredentials(byte[] encryptedData, PrivateKey privateKey) {
        try {
            if (encryptedData == null || encryptedData.length == 0) {
                return null;
            }
            
            // Decrypt the VC data using ECDH with passkey's private key
            byte[] cborVcData = KeyUtils.ecdhDecrypt(encryptedData, privateKey);
            
            // Decode CBOR array of credentials
            @SuppressWarnings("unchecked")
            List<byte[]> vcCborList = (List<byte[]>) Cbor.decode(cborVcData);
            
            // Deserialize each credential
            List<VerifiableCredential> credentials = new ArrayList<>();
            for (byte[] vcCbor : vcCborList) {
                credentials.add(VerifiableCredential.fromCbor(vcCbor));
            }
            
            logger.debug("Read {} verifiable credentials", credentials.size());
            return credentials;
        } catch (Exception e) {
            logger.error("Failed to read verifiable credentials", e);
            return null;
        }
    }
    
    /**
     * Encrypts and writes verifiable credentials.
     *
     * @param credentials List of VerifiableCredential objects
     * @param publicKey Public key for ECDH encryption
     * @return Encrypted VC data
     */
    private static byte[] writeVerifiableCredentials(List<VerifiableCredential> credentials, PublicKey publicKey)
            throws Exception {
        if (credentials == null || credentials.isEmpty()) {
            return new byte[0];
        }
        
        // Serialize each credential to CBOR
        List<byte[]> vcCborList = new ArrayList<>();
        for (VerifiableCredential vc : credentials) {
            vcCborList.add(vc.toCbor());
        }
        
        // Encode list as CBOR array
        byte[] cborVcData = Cbor.encode(vcCborList);
        
        // Encrypt using ECDH with passkey's public key
        byte[] encryptedData = KeyUtils.ecdhEncrypt(cborVcData, publicKey);
        
        logger.debug("Wrote {} verifiable credentials ({} bytes encrypted)",
                    credentials.size(), encryptedData.length);
        return encryptedData;
    }

    
    /**
     * Gets the resident credentials map.
     *
     * @return The map of resident credentials
     */
    public List<Map<String, byte[]>> getResCreds() {
        return resCreds;
    }
    
    /**
     * Gets the list of verifiable credentials associated with this passkey.
     *
     * @return List of verifiable credentials, or null if none exist
     */
    public List<VerifiableCredential> getVerifiableCredentials() {
        return verifiableCredentials;
    }
    
    /**
     * Sets the list of verifiable credentials for this passkey.
     *
     * @param credentials List of verifiable credentials
     */
    public void setVerifiableCredentials(List<VerifiableCredential> credentials) {
        this.verifiableCredentials = credentials;
    }
    
    /**
     * Adds a verifiable credential to this passkey.
     *
     * @param credential The verifiable credential to add
     */
    public void addVerifiableCredential(VerifiableCredential credential) {
        if (this.verifiableCredentials == null) {
            this.verifiableCredentials = new ArrayList<>();
        }
        this.verifiableCredentials.add(credential);
    }
    
    /**
     * Removes a verifiable credential from this passkey by ID.
     *
     * @param credentialId The ID of the credential to remove
     * @return true if the credential was removed, false otherwise
     */
    public boolean removeVerifiableCredential(String credentialId) {
        if (verifiableCredentials == null) {
            return false;
        }
        return verifiableCredentials.removeIf(vc -> vc.getId().equals(credentialId));
    }

    /**
     * Removes a resident credential from this passkey.
     *
     * @param rpId The relying party identifier of the resident credential to remove
     * @return True if the credential was removed, false otherwise
     */
    public boolean removeResidentCredential(byte[] rpId) {
        boolean removed = false;
        if (resCreds != null) {
            // We need to find the matching key since byte[] equality is based on reference
            for (Map<String, byte[]> cred : resCreds) {
                if (java.util.Arrays.equals(cred.get("rp.id"), rpId)) {
                    resCreds.remove(cred);
                    removed = true;
                    break;
                }
            }
        }
        return removed;
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
     * Gets the file name of this passkey.
     *
     * @return The file name (without path)
     */
    public String getFileName() {
        return fileName;
    }

    /**
     * Adds a resident credential to this passkey.
     *
     * @param rpId The relying party ID as a byte array
     * @param credId The credential ID as a byte array
     * @param userHandle The user handle as a byte array
     */
    public void addResCred(byte[] rpId, byte[] credId, byte[] userHandle) {
        Map<String, byte[]> cred = Map.of("cred.id", credId, "user.id", userHandle, "rp.id", rpId);
        if(resCreds == null) {
            resCreds = new ArrayList<Map<String, byte[]>>();
        }
        resCreds.add(cred);
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
        
        List<File> passkeyFiles = FileUtils.listPasskeys();
        if (passkeyFiles != null) {
            for(File maybePasskey: passkeyFiles) {
                try {
                    Passkey passkey = readKey(maybePasskey, lowerHash);
                    if (passkey != null) {
                        return passkey;
                    }
                } catch (Exception e) {
                    logger.error("Error decrypting key", e);
                }
            }
        }
        return null;
    }

    /**
     * Opens a passkey from a file using the lower pin hash for decryption.
     * 
     * @param lowerHash The 16-byte lower hash used for decryption
     * @param passkeyFile The file to open the passkey from
     * @return The decrypted passkey, or null if decryption fails
     */
    public static Passkey openKey(byte[] lowerHash, File passkeyFile) {
        try {
            return readKey(passkeyFile, lowerHash);
        } catch (Exception e) {
            return null;
        }
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
            
            // Generate PKI for the passkey
            KeyPair keyPair = KeyUtils.generateKeyPair(KEY_ALGORITHM, KEY_SIZE);
            X509Certificate cert = CertUtils.generateCaCert("CN=IBeePasskey", keyPair, 9999, true);
            
            // Create the passkey
            Passkey passkey = new Passkey(keyPair.getPrivate(), cert, new ArrayList<>());
            
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
        String fido2Home = FileUtils.getFido2Home();
        File passkeyFile = new File(fido2Home + File.separator + fileName);
        logger.debug("collectPasskeyFileInfo: fido2Home={}, fileName={}, fullPath={}",
            fido2Home, fileName, passkeyFile.getAbsolutePath());
        return passkeyFile;
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
        return KeyUtils.getPinHash(pin);
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
            System.out.println(String.format("Failed to find passkey %s.", passkeyFile.getName()));
            return;
        }
        byte[] lowerHash;
        try {
            lowerHash = collectPinInfo(scanner);
            if(lowerHash == null) {
                return;
            }
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error: Failed to get hasing function.");
            return;
        }
        Passkey passkey = readKey(passkeyFile, lowerHash);
        if (passkey == null) {
            System.out.println("Failed to open passkey.");
            return;
        }
        System.out.println("Passkey successfully opened.");
        List<Map<String, byte[]>> resCreds = passkey.getResCreds();
        ArrayList<Map<String, byte[]>> credsToRemove = new ArrayList<>();
        for(Map<String, byte[]> cred: resCreds) {
            try {
                String rpStr = new String(cred.get("rp.id"), "utf-8");
                System.out.println(String.format("Credential relying party id: %s", rpStr));
                if(confirmDelete(scanner)) {
                    credsToRemove.add(cred);
                }
            } catch (UnsupportedEncodingException e) {
                System.out.println("Failed read relying party id for resident credential.");
                continue;
            }
        }
        resCreds.removeAll(credsToRemove);
    }

    /**
     * Prompts the user to confirm deletion of a credential.
     * The default action is to preserve the credential.
     *
     * @param scanner Scanner to read user input
     * @return true if the user confirms deletion, false otherwise
     */
    private static boolean confirmDelete(Scanner scanner) {
        System.out.print("Delete this credential? (y/N): ");
        String response = scanner.nextLine().trim().toLowerCase();
        
        // Default is to preserve (return false)
        // Only return true if user explicitly confirms with 'y' or 'yes'
        return response.equals("y") || response.equals("yes");
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
                    String.format("Usage: java -cp com.isfs.blekey.jar %s <generate|manage>",
                                                        Passkey.class.getName().toString()));
                return;
            }
            String cmd = args[0];
            // Initialize scanner for user input
            Scanner scanner = new Scanner(System.in);
            initPlatformKey(scanner);
            if(cmd.equals("generate")) {
                System.out.println("Generating a passkey file");
                generateMain(scanner);
            } 
            else if(cmd.equals("manage")) {
                System.out.println("Managing a passkey file");
                manageMain(scanner);
            }
            else {
                System.out.println("Usage: generate || manage");
            }
            scanner.close();
        } catch (Exception e) {
            System.err.println("Error generating passkey: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
