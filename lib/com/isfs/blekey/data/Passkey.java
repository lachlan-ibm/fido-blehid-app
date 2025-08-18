package com.isfs.blekey.data;

import java.io.File;
import java.io.FileInputStream;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.isfs.blekey.util.FileUtils;

/**
 * Represents a FIDO2 passkey stored on the device.
 * This class encapsulates the cryptographic material and metadata
 * needed for FIDO2 authentication operations.
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
    private List<Map<byte[], Object>> resCreds;
    
    /**
     * Seed value used for key derivation.
     */
    private byte[] seed;

    /**
     * Logger for debugging and error reporting.
     */
    private static final Logger logger = LoggerFactory.getLogger(Passkey.class);

    /**
     * Constructs a new Passkey with the specified components.
     *
     * @param key The private key for signing operations
     * @param cert The certificate authority certificate for attestation
     * @param seed The seed value for key derivation
     * @param creds The list of resident credentials
     */
    Passkey(PrivateKey key, X509Certificate cert, byte[] seed, List<Map<byte[], Object>> creds) {
        this.pk = key;
        this.ca = cert;
        this.resCreds = creds;
        this.seed = seed;
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
        resCreds.add(Map.of(rpId, cred));
    }

    /**
     * Writes a passkey to persistent storage.
     * Note: This method is currently a stub and does not implement the actual writing.
     *
     * @param key The passkey to write
     */
    public static void writeKey(Passkey key) {
        return;
    }

    /**
     * Opens a passkey from persistent storage using a PIN hash for decryption.
     * Tries to decrypt all available passkey files until a match is found.
     *
     * @param pinHash The PIN hash used for decryption
     * @return The decrypted passkey, or null if no matching passkey is found
     */
    public static Passkey openKey(byte[] pinHash) {
        for(File maybePasskey: FileUtils.listPasskeys()) {
            try {
                Passkey passkey = decryptKey(maybePasskey, pinHash);
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
     * Decrypts a passkey file using a PIN hash.
     * Note: This method is currently incomplete and returns null.
     *
     * @param maybePasskey The passkey file to decrypt
     * @param pinHash The PIN hash used for decryption
     * @return The decrypted passkey, or null if decryption fails
     * @throws Exception if an error occurs during decryption
     */
    private static Passkey decryptKey(File maybePasskey, byte[] pinHash) throws Exception {
        FileInputStream fis = new FileInputStream(maybePasskey);
        byte[] data = fis.readAllBytes();
        fis.close();
        byte[] iv = new byte[16];
        byte[] tag = new byte[16];
        System.arraycopy(data, 0, iv, 0, 16);
        System.arraycopy(data, 16, tag, 0, 16);
        //TODO
        return null;
    }
}
