/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class FileUtils {

    private static final Logger logger = LoggerFactory.getLogger(FileUtils.class);

    public static byte[] readX509PEM(String fName)  throws IOException {
        StringBuilder sb = null;
        try { // try read file from string
            InputStream inStream = new FileInputStream(fName);
            BufferedReader br = new BufferedReader(new InputStreamReader(inStream));
            sb = new StringBuilder();
            boolean inKey = false;
            for (String line = br.readLine(); line != null; line = br.readLine()) {
                if (!inKey) {
                    if (line.contains("BEGIN")
                            && (line.contains("KEY") || line.contains("CERTIFICATE"))) {
                        inKey = true;
                    }
                    continue;
                } else {
                    if (line.contains("END")
                            && (line.contains("KEY") || line.contains("CERTIFICATE"))) {
                        inKey = false;
                        break;
                    }
                    sb.append(line);
                }
            }
            br.close();
            inStream.close();
        } catch (IOException ioe) { // if we fail use the literal string
            sb = new StringBuilder(fName);
        }
        byte[] rawKey = Base64.decode(sb.toString());
        return rawKey;
    }

    /**
     * Gets the FIDO2_HOME directory path, checking both environment variables and system properties.
     *
     * @return The FIDO2_HOME directory path, or null if not set
     */
    public static String getFido2Home() {
        // First check environment variable
        String fidoHomeStr = System.getenv("FIDO2_HOME");
        
        // If not set, check system property as fallback
        if (fidoHomeStr == null || fidoHomeStr.isEmpty()) {
            fidoHomeStr = System.getProperty("FIDO2_HOME");
        }
        
        return fidoHomeStr;
    }

    public static List<File> listPasskeys() {
        String fidoHomeStr = getFido2Home();
        if (fidoHomeStr == null || fidoHomeStr.isEmpty()) {
            return null;
        }
        
        List<File> result = new ArrayList<>();
        File fidoHomeDir = new File(fidoHomeStr);
        
        if (!fidoHomeDir.exists() || !fidoHomeDir.isDirectory()) {
            logger.warn("FIDO2_HOME directory does not exist: {}", fidoHomeStr);
            return result;
        }
        
        File[] files = fidoHomeDir.listFiles();
        if (files == null) {
            logger.warn("Failed to list files in FIDO2_HOME directory: {}", fidoHomeStr);
            return result;
        }
        
        for(File maybePasskey: files) {
            try {
                if(maybePasskey.isFile() &&
                        maybePasskey.getAbsolutePath().endsWith(".passkey")) {
                    result.add(maybePasskey);
                }
            } catch (Exception e) {
                logger.error("Error processing passkey file", e);
            }
        }
        return result;
    }


    /**
     * Reads all bytes from a file using Java NIO.
     * 
     * @param file The file to read
     * @return The byte contents of the file
     * 
     */
    public static byte[] readFileBytes(File file) {
        try {
            return Files.readAllBytes(file.toPath());
        } catch (IOException e) {
            logger.error("Error reading file", e);
            return new byte[0];
        }

    }

    public static void _writeFile(File file, String[] content) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(file)) {

            for (int i = 0; i < content.length; i += 64)  {
                fos.write(content[i].getBytes());
                fos.write("\n".getBytes());
            }
            fos.flush();
            fos.close();
        }
    }

    public static void writePublicPEM(PublicKey publicKey, File file) throws IOException {
        // Check if parent directory exists
        if (!file.getParentFile().exists()) {
            throw new IOException("Parent directory does not exist: " + file.getParentFile().getAbsolutePath());
        }
        
        try {
            // Ensure BouncyCastle provider is properly registered
            KeyUtils.ensureBouncyCastleProvider();
            
            // Write the public key to the file using Bouncy Castle
            try (FileWriter fileWriter = new FileWriter(file);
                 JcaPEMWriter pemWriter = new JcaPEMWriter(fileWriter)) {
                
                pemWriter.writeObject(publicKey);
            }
        } catch (Exception e) {
            throw new IOException("Failed to write public key: " + e.getMessage(), e);
        }
    }

    /**
     * Writes a private key to a file in PKCS8 format.
     *
     * @param privateKey The private key to write
     * @param file The file to write to
     * @throws IOException If the file cannot be written or the parent directory doesn't exist
     */
    public static void writePrivatePEM(PrivateKey privateKey, File file) throws IOException {
        writePrivatePEM(privateKey, file, null);
    }
    
    /**
     * Writes a private key to a file in PKCS8 format with optional password protection.
     *
     * @param privateKey The private key to write
     * @param file The file to write to
     * @param password The password to protect the private key with (null for unencrypted)
     * @throws IOException If the file cannot be written or the parent directory doesn't exist
     */
    public static void writePrivatePEM(PrivateKey privateKey, File file, String password) throws IOException {
        // Check if parent directory exists
        File parentDir = file.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
            throw new IOException("Parent directory missing: " + parentDir.getAbsolutePath());
        }
        
        try {
            // Ensure BouncyCastle provider is properly registered
            KeyUtils.ensureBouncyCastleProvider();
            
            // Write the private key to the file using Bouncy Castle
            try (FileWriter fileWriter = new FileWriter(file);
                 JcaPEMWriter pemWriter = new JcaPEMWriter(fileWriter)) {
                
                if (password == null || password.isEmpty()) {
                    // Write unencrypted private key in PKCS#8 format
                    pemWriter.writeObject(new JcaPKCS8Generator(privateKey, null));
                } else {
                    // For encrypted keys, create an appropriate encryptor for PKCS#8
                    JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder =
                        new JceOpenSSLPKCS8EncryptorBuilder(NISTObjectIdentifiers.id_aes256_CBC);
                    
                    // Configure encryption parameters for OpenSSL compatibility
                    encryptorBuilder.setIterationCount(2048);
                    encryptorBuilder.setRandom(new java.security.SecureRandom());
                    encryptorBuilder.setPassword(password.toCharArray());
                    
                    // Create the PKCS#8 generator with the encryptor
                    JcaPKCS8Generator pkcs8Generator = new JcaPKCS8Generator(
                        privateKey, encryptorBuilder.build());
                    
                    // Write the encrypted key in PKCS#8 format
                    pemWriter.writeObject(pkcs8Generator);
                }
            }
        } catch (Exception e) {
            throw new IOException("Failed to write private key: " + e.getMessage(), e);
        }
    }
    
    /**
     * Reads a private key from a PEM file, with optional password support.
     *
     * @param file The file to read from
     * @param password The password to decrypt the private key (null for unencrypted keys)
     * @return The private key
     * @throws IOException If the file cannot be read
     */
    public static PrivateKey readPrivatePEM(File file, String password) throws IOException {
        try {
            // Ensure BouncyCastle provider is properly registered
            KeyUtils.ensureBouncyCastleProvider();
            
            if (password == null || password.isEmpty()) {
                // Try to parse as unencrypted PKCS#8
            try (FileReader fileReader = new FileReader(file);
                 PEMParser pemParser = new PEMParser(fileReader)) {
                
                    Object object = pemParser.readObject();
                    if (object == null) {
                        throw new IOException("Failed to read PEM object from file");
                    }
                    
                    JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
                    
                    if (object instanceof PEMKeyPair) {
                        // Traditional format private key
                        KeyPair kp = converter.getKeyPair((PEMKeyPair) object);
                        return kp.getPrivate();
                    } else if (object instanceof PrivateKeyInfo) {
                        return converter.getPrivateKey((PrivateKeyInfo) object);
                    } else {
                        throw new IOException("Unsupported PEM object: " + object.getClass().getName());
                    }
                }
            } else {
                // Try to parse as encrypted PKCS#8
                try (FileReader fileReader = new FileReader(file);
                     PEMParser pemParser = new PEMParser(fileReader)) {
                    
                    Object object = pemParser.readObject();
                    if (object == null) {
                        throw new IOException("Failed to read PEM object from file");
                    }
                    
                    // Debug: Log the actual type of object we're getting
                    logger.info("Encrypted PEM object type: " + object.getClass().getName());
                    
                    if (object instanceof PKCS8EncryptedPrivateKeyInfo) {
                        // Handle PKCS#8 encrypted private key from PEM
                        PKCS8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = (PKCS8EncryptedPrivateKeyInfo) object;
                        InputDecryptorProvider decryptorProvider = new JcePKCSPBEInputDecryptorProviderBuilder()
                                .setProvider("BC")
                                .build(password.toCharArray());
                        
                        PrivateKeyInfo privateKeyInfo = encryptedPrivateKeyInfo.decryptPrivateKeyInfo(decryptorProvider);
                        try {
                            java.security.spec.PKCS8EncodedKeySpec keySpec =
                                new java.security.spec.PKCS8EncodedKeySpec(privateKeyInfo.getEncoded());
                            
                            // Determine the algorithm from the key info
                            String algorithm = privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm().getId();
                            String keyAlgorithm = "EC";
                            if (algorithm.equals("1.2.840.113549.1.1.1")) {
                                keyAlgorithm = "RSA";
                            } else if (algorithm.equals("1.3.101.112")) {
                                keyAlgorithm = "EdDSA";
                            }                       
                            // Try to get a key factory for the algorithm
                            java.security.KeyFactory keyFactory =
                                java.security.KeyFactory.getInstance(keyAlgorithm, "BC");
                            
                            return keyFactory.generatePrivate(keySpec);
                        } catch (Exception e) {
                            // Fall back to the original approach if the above fails
                            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
                            return converter.getPrivateKey(privateKeyInfo);
                        }
                    } else {
                        throw new IOException("Unsupported encrypted PEM object: " + object.getClass().getName());
                    }
                } catch (Exception e) {
                    throw new IOException("Failed to read encrypted private key: " + e.getMessage(), e);
                }
            }
        } catch (Exception e) {
            throw new IOException("Failed to read private key: " + e.getMessage(), e);
        }
    }
    
    /**
     * Reads a private key from a PEM file (unencrypted).
     *
     * @param file The file to read from
     * @return The private key
     * @throws IOException If the file cannot be read
     */
    public static PrivateKey readPrivatePEM(File file) throws IOException {
        return readPrivatePEM(file, null);
    }
    
    /**
     * Reads a public key from a PEM file.
     *
     * @param file The file to read from
     * @return The public key
     * @throws IOException If the file cannot be read
     */
    public static PublicKey readPublicPEM(File file) throws IOException {
        try {
            // Ensure BouncyCastle provider is registered
            if (Security.getProvider("BC") == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
            
            // Read the public key from the file
            try (FileReader fileReader = new FileReader(file);
                 PEMParser pemParser = new PEMParser(fileReader)) {
                
                Object object = pemParser.readObject();
                if (object == null) {
                    throw new IOException("Failed to read PEM object from file");
                }
                
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
                
                if (object instanceof PEMKeyPair) {
                    // Key pair - extract public key
                    PEMKeyPair keyPair = (PEMKeyPair) object;
                    return converter.getKeyPair(keyPair).getPublic();
                } else if (object instanceof SubjectPublicKeyInfo) {
                    // Direct public key info
                    return converter.getPublicKey((SubjectPublicKeyInfo) object);
                } else {
                    throw new IOException("Unsupported PEM object for public key: " + object.getClass().getName());
                }
            }
        } catch (Exception e) {
            throw new IOException("Failed to read public key: " + e.getMessage(), e);
        }
    }
}
