/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.data;

import java.io.ByteArrayOutputStream;
import java.io.Console;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.security.cert.Certificate;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;


import com.isfs.blekey.util.Cbor;
import com.isfs.blekey.util.CertUtils;
import com.isfs.blekey.util.KeyUtils;

/**
 * Utility class for migrating passkeys from FernetKey (v1) encryption to SymmetricKey (v2) encryption.
 * 
 * The migration process:
 * 1. Decrypts the passkey using FernetKey with the lower 16 bytes of the PIN hash
 * 2. Re-encrypts it using SymmetricKey with the entire 32-byte PIN hash
 * 3. Creates a header containing the upper 16 bytes of the PIN hash, IV, and authentication tag
 * 4. Encrypts the header using the platform key
 * 5. Outputs the result to a file with a .v2 suffix
 */
public class MigratePasskeys {

    private static final int HALF_HASH = 16;
    private static final int IV_SIZE = 16;
    private static final int TAG_SIZE = 16;
    private static final int GCM_TAG_BIT_LENGTH = 16;
    private static final String AES_ALGORITHM = "AES";
    private static final String CIPHER_TRANSFORMATION = "CBC";

    /**
     * Migrates a passkey from v1 (FernetKey) to v2 (SymmetricKey) format.
     * 
     * @param passkeyFile File containing the v1 passkey
     * @param pinSecret The PIN or secret used to derive the encryption key
     * @param platformKey The platform public key for encrypting the header
     * @return File containing the newly created v2 passkey
     * @throws Exception if migration fails
     */
    @SuppressWarnings("unchecked")
    public static File v1MigrateV2(File passkeyFile, String pinSecret, PublicKey platformKey) throws Exception {
        // Read the v1 passkey from file
        byte[] passkeyBytes = Files.readAllBytes(passkeyFile.toPath());
        
        // Generate the full 32-byte PIN hash
        byte[] fullPinHash = KeyUtils.getPinHash(pinSecret);
        
        // Split the PIN hash into upper and lower parts
        byte[] upperHash = new byte[HALF_HASH];
        byte[] lowerHash = new byte[HALF_HASH];
        System.arraycopy(fullPinHash, HALF_HASH, upperHash, 0, HALF_HASH);
        System.arraycopy(fullPinHash, 0, lowerHash, 0, HALF_HASH);
        
        // Extract IV, tag, and encrypted data from the file
        byte[] iv = new byte[IV_SIZE];
        byte[] tag = new byte[TAG_SIZE];
        byte[] encryptedData = new byte[passkeyBytes.length - IV_SIZE - TAG_SIZE];
        
        System.arraycopy(passkeyBytes, 0, iv, 0, IV_SIZE);
        System.arraycopy(passkeyBytes, IV_SIZE, tag, 0, TAG_SIZE);
        System.arraycopy(passkeyBytes, IV_SIZE + TAG_SIZE, encryptedData, 0, encryptedData.length);
        
        // Create AES key from full PIN hash
        SecretKeySpec secretKeySpec = new SecretKeySpec(fullPinHash, AES_ALGORITHM);
        
        // Initialize cipher for decryption
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        GCMParameterSpec gcmParamSpec = new GCMParameterSpec(GCM_TAG_BIT_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParamSpec);
        
        // Combine ciphertext and tag for decryption
        byte[] ciphertextWithTag = new byte[encryptedData.length + tag.length];
        System.arraycopy(encryptedData, 0, ciphertextWithTag, 0, encryptedData.length);
        System.arraycopy(tag, 0, ciphertextWithTag, encryptedData.length, tag.length);
        
        // Decrypt the data
        byte[] decryptedCbor = cipher.doFinal(ciphertextWithTag);
        
        // Decode the CBOR to get the key parameters and validate
        Map<String, Object> keyParams = (Map<String, Object>) Cbor.decode(decryptedCbor);
        PrivateKey key = KeyUtils.getPrivate((byte[]) keyParams.get("key"), pinSecret);
        Certificate cert = CertUtils.readBytes((byte[]) keyParams.get("x5c"), "X.509");
        List<Map<String, byte[]>> resCreds = (List<Map<String, byte[]>>) keyParams.get("res.creds");
        // Key is valid
    
        
        // Create the output file with .v2 suffix
        File outputFile = new File(passkeyFile.getAbsolutePath() + ".v2");
        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            fos.write(encryptPasskeyData(key, cert, resCreds, KeyUtils.getPinHash(pinSecret), platformKey));
        }
        
        return outputFile;
    }
    
    /**
     * Encrypts passkey data using AES-GCM with the provided PIN hash.
     *
     * @param data The data to encrypt
     * @param pinHash The PIN hash to use as the encryption key
     * @return A CryptoData object containing the IV, encrypted data, and authentication tag
     */
    private static byte[] encryptPasskeyData(PrivateKey key, 
                                            Certificate cert, 
                                            List<Map<String, byte[]>> resCreds, 
                                            byte[] pinHash,
                                            PublicKey platformKey)
            throws Exception {
        byte[] encPinHash = KeyUtils.ecdhEncrypt(Arrays.copyOfRange(pinHash, 16, 32), platformKey);
        byte[] p12_bytes = KeyUtils.writePKCS12(key, cert, pinHash);
        ECPublicKey pub = KeyUtils.publicFromPrivate((ECPrivateKey) key);
        byte[] encResCreds = KeyUtils.ecdhEncrypt(Cbor.encode(resCreds), pub);
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(p12_bytes.length);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(encPinHash);
        bos.write(buffer.array());
        bos.write(p12_bytes);
        bos.write(encResCreds);
        return bos.toByteArray();
    }
    
    /**
     * Command-line interface for migrating v1 passkey files to v2.
     * Usage: java com.isfs.blekey.data.MigratePasskeys <passkey_file_path>
     *
     * @param args Command line arguments (expects file path as first argument)
     */
    public static void main(String[] args) {
        try {
            // Check if file path is provided
            if (args.length < 1) {
                System.err.println("Error: Missing file path argument");
                System.err.println("Usage: java com.isfs.blekey.data.MigratePasskeys <passkey_file_path>");
                System.exit(1);
            }
            
            // Get file path from arguments
            String filePath = args[0];
            File passkeyFile = new File(filePath);
            
            // Check if file exists
            if (!passkeyFile.exists() || !passkeyFile.isFile()) {
                System.err.println("Error: File not found or not a regular file: " + filePath);
                System.exit(1);
            }
            
            // Prompt for secret/PIN
            String pinSecret = promptForSecret();
            if (pinSecret == null || pinSecret.isEmpty()) {
                System.err.println("Error: Secret cannot be empty");
                System.exit(1);
            }
            
            // Generate a platform key pair for the migration
            System.out.println("Generating platform key pair...");
            KeyPair platformKeyPair = KeyUtils.generateKeyPair("EC", 256);
            
            // Perform the migration
            System.out.println("Migrating passkey file...");
            File v2File = v1MigrateV2(passkeyFile, pinSecret, platformKeyPair.getPublic());
            
            // Report success
            System.out.println("Migration successful!");
            System.out.println("V2 passkey file created: " + v2File.getAbsolutePath());
            
        } catch (Exception e) {
            System.err.println("Error during migration: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
    
    /**
     * Prompts the user for a secret/PIN, trying to use the Console for secure input if available.
     * Falls back to Scanner if Console is not available (e.g., when running in an IDE).
     *
     * @return The secret entered by the user
     */
    private static String promptForSecret() {
        // Try to use Console for password masking
        Console console = System.console();
        if (console != null) {
            char[] secret = console.readPassword("Enter passkey secret/PIN: ");
            return new String(secret);
        } else {
            // Fall back to Scanner if Console is not available (e.g., in IDE)
            System.out.print("Enter passkey secret/PIN (input will be visible): ");
            Scanner scanner = null;
            try {
                scanner = new Scanner(System.in);
                return scanner.nextLine();
            } finally {
                if (scanner != null) {
                    scanner.close();
                }
            }
        }
    }
}

// Made with Bob
