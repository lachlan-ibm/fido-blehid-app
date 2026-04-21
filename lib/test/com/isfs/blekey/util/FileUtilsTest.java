/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

/**
 * Test class for FileUtils focusing on error paths and edge cases.
 *
 */
public class FileUtilsTest {

    @TempDir
    Path tempDir;
    
    private String originalFido2Home;
    
    @BeforeEach
    public void setUp() {
        originalFido2Home = System.getProperty("FIDO2_HOME");
    }
    
    @AfterEach
    public void tearDown() {
        if (originalFido2Home != null) {
            System.setProperty("FIDO2_HOME", originalFido2Home);
        } else {
            System.clearProperty("FIDO2_HOME");
        }
    }

    /**
     * Test readX509PEM() with non-existent file (IOException at line 48, fallback at line 70-72)
     */
    @Test
    public void testReadX509PEM_NonExistentFile_UsesFallback() throws IOException {
        String nonExistentFile = "SGVsbG8gV29ybGQ="; // Base64 encoded "Hello World"
        
        byte[] result = FileUtils.readX509PEM(nonExistentFile);
        
        assertNotNull(result);
        assertEquals("Hello World", new String(result));
    }

    /**
     * Test listPasskeys() with null/empty FIDO2_HOME (lines 96-97)
     */
    @Test
    public void testListPasskeys_NullFido2Home_ReturnsNull() {
        System.clearProperty("FIDO2_HOME");
        
        List<File> result = FileUtils.listPasskeys();
        
        assertNull(result);
    }

    /**
     * Test listPasskeys() with empty FIDO2_HOME
     */
    @Test
    public void testListPasskeys_EmptyFido2Home_ReturnsNull() {
        System.setProperty("FIDO2_HOME", "");
        
        List<File> result = FileUtils.listPasskeys();
        
        assertNull(result);
    }

    /**
     * Test listPasskeys() with non-existent directory (lines 103-106)
     */
    @Test
    public void testListPasskeys_NonExistentDirectory_ReturnsEmptyList() {
        String nonExistentDir = tempDir.resolve("nonexistent").toString();
        System.setProperty("FIDO2_HOME", nonExistentDir);
        
        List<File> result = FileUtils.listPasskeys();
        
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    /**
     * Test listPasskeys() with directory listing failure (lines 109-112)
     * This tests the case where listFiles() returns null
     */
    @Test
    public void testListPasskeys_DirectoryListingFailure_ReturnsEmptyList() throws IOException {
        File regularFile = tempDir.resolve("notadirectory.txt").toFile();
        Files.writeString(regularFile.toPath(), "test");
        System.setProperty("FIDO2_HOME", regularFile.getAbsolutePath());
        
        List<File> result = FileUtils.listPasskeys();
        
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    /**
     * Test listPasskeys() with exception during file processing (lines 120-122)
     */
    @Test
    public void testListPasskeys_ValidDirectory_FiltersPasskeyFiles() throws IOException {
        File fido2Home = tempDir.toFile();
        System.setProperty("FIDO2_HOME", fido2Home.getAbsolutePath());
        
        Files.writeString(tempDir.resolve("test1.passkey"), "passkey1");
        Files.writeString(tempDir.resolve("test2.txt"), "not a passkey");
        Files.writeString(tempDir.resolve("test3.passkey"), "passkey2");
        
        List<File> result = FileUtils.listPasskeys();
        
        assertNotNull(result);
        assertEquals(2, result.size());
        assertTrue(result.stream().allMatch(f -> f.getName().endsWith(".passkey")));
    }

    /**
     * Test readFileBytes() with null file parameter (line 136-137)
     */
    @Test
    public void testReadFileBytes_NullFile_ThrowsIOException() {
        IOException exception = assertThrows(IOException.class, () -> {
            FileUtils.readFileBytes(null);
        });
        
        assertTrue(exception.getMessage().contains("null"));
    }

    /**
     * Test readFileBytes() with non-readable file (lines 139-141)
     */
    @Test
    public void testReadFileBytes_NonExistentFile_ThrowsIOException() {
        File nonExistent = new File(tempDir.toFile(), "nonexistent.txt");
        
        IOException exception = assertThrows(IOException.class, () -> {
            FileUtils.readFileBytes(nonExistent);
        });
        
        assertTrue(exception.getMessage().contains("does not exist"));
    }

    /**
     * Test _writeFile() with valid content array (lines 146-154)
     */
    @Test
    public void testWriteFile_ValidContentArray_WritesSuccessfully() throws IOException {
        File outputFile = tempDir.resolve("output.txt").toFile();
        String[] content = {"line1", "line2", "line3"};
        
        FileUtils._writeFile(outputFile, content);
        
        assertTrue(outputFile.exists());
        String fileContent = Files.readString(outputFile.toPath());
        assertTrue(fileContent.contains("line1"));
    }

    /**
     * Test writePublicPEM() with non-existent parent directory (lines 159-161)
     */
    @Test
    public void testWritePublicPEM_NonExistentParentDirectory_ThrowsIOException() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair("EC", 256);
        PublicKey publicKey = keyPair.getPublic();
        File fileWithMissingParent = new File(tempDir.toFile(), "nonexistent/public.pem");
        
        IOException exception = assertThrows(IOException.class, () -> {
            FileUtils.writePublicPEM(publicKey, fileWithMissingParent);
        });
        
        assertTrue(exception.getMessage().contains("Parent directory does not exist"));
    }

    /**
     * Test writePrivatePEM() with non-existent parent directory (lines 199-200)
     */
    @Test
    public void testWritePrivatePEM_NonExistentParentDirectory_ThrowsIOException() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair("EC", 256);
        PrivateKey privateKey = keyPair.getPrivate();
        File fileWithMissingParent = new File(tempDir.toFile(), "nonexistent/private.pem");
        
        IOException exception = assertThrows(IOException.class, () -> {
            FileUtils.writePrivatePEM(privateKey, fileWithMissingParent);
        });
        
        assertTrue(exception.getMessage().contains("Parent directory missing"));
    }

    /**
     * Additional test: Verify writePublicPEM() works with valid parent directory
     */
    @Test
    public void testWritePublicPEM_ValidParentDirectory_WritesSuccessfully() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair("EC", 256);
        PublicKey publicKey = keyPair.getPublic();
        File outputFile = tempDir.resolve("public.pem").toFile();
        
        FileUtils.writePublicPEM(publicKey, outputFile);
        
        assertTrue(outputFile.exists());
        assertTrue(outputFile.length() > 0);
    }

    /**
     * Additional test: Verify writePrivatePEM() works with valid parent directory
     */
    @Test
    public void testWritePrivatePEM_ValidParentDirectory_WritesSuccessfully() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair("EC", 256);
        PrivateKey privateKey = keyPair.getPrivate();
        File outputFile = tempDir.resolve("private.pem").toFile();
        
        FileUtils.writePrivatePEM(privateKey, outputFile);
        
        assertTrue(outputFile.exists());
        assertTrue(outputFile.length() > 0);
    }

    /**
     * Additional test: Verify round-trip of public key write/read
     */
    @Test
    public void testPublicKeyRoundTrip_WriteAndRead_PreservesKey() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair("EC", 256);
        PublicKey originalPublicKey = keyPair.getPublic();
        File outputFile = tempDir.resolve("public_roundtrip.pem").toFile();
        
        FileUtils.writePublicPEM(originalPublicKey, outputFile);
        PublicKey readPublicKey = FileUtils.readPublicPEM(outputFile);
        
        assertNotNull(readPublicKey);
        assertArrayEquals(originalPublicKey.getEncoded(), readPublicKey.getEncoded());
    }

    /**
     * Additional test: Verify round-trip of private key write/read
     */
    @Test
    public void testPrivateKeyRoundTrip_WriteAndRead_PreservesKey() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair("EC", 256);
        PrivateKey originalPrivateKey = keyPair.getPrivate();
        File outputFile = tempDir.resolve("private_roundtrip.pem").toFile();
        
        FileUtils.writePrivatePEM(originalPrivateKey, outputFile);
        PrivateKey readPrivateKey = FileUtils.readPrivatePEM(outputFile);
        
        assertNotNull(readPrivateKey);
        assertArrayEquals(originalPrivateKey.getEncoded(), readPrivateKey.getEncoded());
    }

    /**
     * Test getFido2Home() with environment variable set
     */
    @Test
    public void testGetFido2Home_EnvironmentVariable_ReturnsValue() {
        String testPath = "/test/fido2/home";
        System.setProperty("FIDO2_HOME", testPath);
        
        String result = FileUtils.getFido2Home();
        
        assertEquals(testPath, result);
    }

    /**
     * Test getFido2Home() with no value set
     */
    @Test
    public void testGetFido2Home_NotSet_ReturnsNull() {
        System.clearProperty("FIDO2_HOME");
        
        String result = FileUtils.getFido2Home();
        
        assertNull(result);
    }
}

// Made with Bob
