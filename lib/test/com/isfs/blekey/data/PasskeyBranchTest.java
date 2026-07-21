/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.data;

import static org.junit.Assert.*;

import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.isfs.blekey.authenticator.TestHelper;
import com.isfs.blekey.util.CertUtils;
import com.isfs.blekey.util.FileUtils;
import com.isfs.blekey.util.KeyUtils;
import com.isfs.blekey.util.KeystoreManager;

/**
 * Branch coverage tests for Passkey class.
 * Targets high-impact branches and uncovered methods identified in Phase 3 of the coverage improvement plan.
 */
public class PasskeyBranchTest {
    
    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();
    
    private KeyPair rootKeyPair;
    private File tempPasskeyFile;
    private byte[] testPinHash;
    private static final int PIN_HASH_SIZE = 32;
    private static final int HALF_HASH = PIN_HASH_SIZE / 2;
    
    @Before
    public void setUp() throws Exception {
        // Initialize mock KeystoreManager
        KeystoreManager mockKeystoreManager = TestHelper.createMockKeystoreManager();
        KeyUtils.setKeystoreManager(mockKeystoreManager);
        
        // Generate test PIN hash
        testPinHash = new byte[PIN_HASH_SIZE];
        new SecureRandom().nextBytes(testPinHash);
        
        // Create temporary file
        tempPasskeyFile = tempFolder.newFile("test.passkey");
        
        // Generate root key pair
        rootKeyPair = KeyUtils.generateKeyPair("EC", 256);
        setRootKeyPair(rootKeyPair.getPublic(), rootKeyPair.getPrivate());
    }
    
    @After
    public void tearDown() throws Exception {
        // Clear root key pair
        setRootKeyPair(null, null);
    }
    
    /**
     * Helper method to set root key pair using reflection.
     */
    private void setRootKeyPair(PublicKey publicKey, PrivateKey privateKey) throws Exception {
        Field rootPublicKeyField = KeyUtils.class.getDeclaredField("rootPublicKey");
        rootPublicKeyField.setAccessible(true);
        rootPublicKeyField.set(null, publicKey);
        
        Field rootPrivateKeyField = KeyUtils.class.getDeclaredField("rootPrivateKey");
        rootPrivateKeyField.setAccessible(true);
        rootPrivateKeyField.set(null, privateKey);
    }
    
    /**
     * Helper method to create a test passkey.
     */
    private Passkey createTestPasskey() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair("EC", 256);
        X509Certificate cert = CertUtils.generateCaCert("CN=Test", keyPair, 365, true);
        List<Map<String, byte[]>> resCreds = new ArrayList<>();
        
        // Use reflection to create Passkey instance
        java.lang.reflect.Constructor<Passkey> constructor =
            Passkey.class.getDeclaredConstructor(PrivateKey.class, X509Certificate.class, List.class);
        constructor.setAccessible(true);
        return constructor.newInstance(keyPair.getPrivate(), cert, resCreds);
    }
    
    /**
     * Test ensureRootKeyPair() with missing keys (lines 210, 219, 226).
     * Tests initialization when root key pair is not set.
     */
    @Test
    public void testEnsureRootKeyPairWithMissingKeys() throws Exception {
        // Clear root key pair
        setRootKeyPair(null, null);
        
        // Create a temporary key file
        File keyFile = tempFolder.newFile("platform.key");
        FileUtils.writePrivatePEM(rootKeyPair.getPrivate(), keyFile);
        
        // Call ensureRootKeyPair with the key file path
        Method ensureRootKeyPair = KeyUtils.class.getDeclaredMethod("ensureRootKeyPair", String.class, String.class);
        ensureRootKeyPair.setAccessible(true);
        ensureRootKeyPair.invoke(null, keyFile.getAbsolutePath(), null);
        
        // Verify keys were loaded
        Field rootPublicKeyField = KeyUtils.class.getDeclaredField("rootPublicKey");
        rootPublicKeyField.setAccessible(true);
        PublicKey loadedPublicKey = (PublicKey) rootPublicKeyField.get(null);
        assertNotNull("Root public key should be loaded", loadedPublicKey);
    }
    
    /**
     * Test resolveKeyFilePath() path resolution edge cases (lines 238, 243).
     * Tests path resolution with null input and FIDO2_HOME.
     */
    @Test
    public void testResolveKeyFilePathEdgeCases() throws Exception {
        Method resolveKeyFilePath = KeyUtils.class.getDeclaredMethod("resolveRootKeyFilePath", String.class);
        resolveKeyFilePath.setAccessible(true);
        
        // Test with custom path
        String customPath = "/custom/path/key.pem";
        String resolved = (String) resolveKeyFilePath.invoke(null, customPath);
        assertEquals("Should return custom path", customPath, resolved);
        
        // Test with null path (should use FIDO2_HOME)
        // This will throw RuntimeException if FIDO2_HOME is not set
        try {
            String defaultPath = (String) resolveKeyFilePath.invoke(null, (String) null);
            assertNotNull("Should return default path", defaultPath);
            assertTrue("Should contain platform.key", defaultPath.contains("platform.key"));
        } catch (Exception e) {
            // Expected if FIDO2_HOME is not set
            assertTrue("Should throw RuntimeException for missing FIDO2_HOME", 
                      e.getCause() instanceof RuntimeException);
        }
    }
    
    /**
     * Test readKey() with corrupted data.
     * Tests error handling for various corruption scenarios.
     */
    @Test
    public void testReadKeyWithCorruptedData() throws Exception {
        Method readKey = Passkey.class.getDeclaredMethod("readKey", File.class, byte[].class);
        readKey.setAccessible(true);
        
        // Test 1: File doesn't exist
        File nonExistentFile = new File(tempFolder.getRoot(), "nonexistent.passkey");
        byte[] lowerHash = Arrays.copyOfRange(testPinHash, 0, HALF_HASH);
        Passkey result1 = (Passkey) readKey.invoke(null, nonExistentFile, lowerHash);
        assertNull("Should return null for non-existent file", result1);
        
        // Test 2: Insufficient lowerHash bytes
        byte[] shortHash = new byte[HALF_HASH - 1];
        Passkey result2 = (Passkey) readKey.invoke(null, tempPasskeyFile, shortHash);
        assertNull("Should return null for insufficient hash bytes", result2);
        
        // Test 3: Passkey file too short (fewer than 4 bytes)
        byte[] shortData = new byte[3]; // Less than minimum 4 bytes
        java.nio.file.Files.write(tempPasskeyFile.toPath(), shortData);
        Passkey result3 = (Passkey) readKey.invoke(null, tempPasskeyFile, lowerHash);
        assertNull("Should return null for passkey file too short", result3);
        
        // Test 4: Passkey file valid but stash file missing
        byte[] validData = new byte[100]; // More than 4 bytes
        java.nio.file.Files.write(tempPasskeyFile.toPath(), validData);
        // No stash file written — readKey should detect missing stash
        Passkey result4 = (Passkey) readKey.invoke(null, tempPasskeyFile, lowerHash);
        assertNull("Should return null when stash file is missing", result4);
    }
    
    /**
     * Test getCachedPinHash() cache hit/miss scenarios (line 435).
     * Tests PIN hash reconstruction from upper and lower parts.
     */
    @Test
    public void testGetCachedPinHash() throws Exception {
        Method getCachedPinHash = Passkey.class.getDeclaredMethod("getCachedPinHash", byte[].class, byte[].class);
        getCachedPinHash.setAccessible(true);
        
        // Split test PIN hash
        byte[] upperHash = Arrays.copyOfRange(testPinHash, HALF_HASH, PIN_HASH_SIZE);
        byte[] lowerHash = Arrays.copyOfRange(testPinHash, 0, HALF_HASH);
        
        // Reconstruct PIN hash
        byte[] reconstructed = (byte[]) getCachedPinHash.invoke(null, upperHash, lowerHash);
        
        assertNotNull("Reconstructed hash should not be null", reconstructed);
        assertEquals("Reconstructed hash should be 32 bytes", PIN_HASH_SIZE, reconstructed.length);
        assertArrayEquals("Reconstructed hash should match original", testPinHash, reconstructed);
        
        // Test with invalid sizes
        try {
            getCachedPinHash.invoke(null, new byte[10], lowerHash);
            fail("Should throw exception for invalid upper hash size");
        } catch (Exception e) {
            assertTrue("Should throw IllegalArgumentException", 
                      e.getCause() instanceof IllegalArgumentException);
        }
    }
    
    /**
     * Test validateFileData() with invalid formats.
     * Tests file data validation (minimum 4 bytes for PKCS12 length prefix).
     */
    @Test
    public void testValidateFileData() throws Exception {
        Method validateFileData = Passkey.class.getDeclaredMethod("validateFileData", byte[].class);
        validateFileData.setAccessible(true);
        
        // Test with null data
        boolean result1 = (boolean) validateFileData.invoke(null, (byte[]) null);
        assertFalse("Should return false for null data", result1);
        
        // Test with insufficient data (fewer than 4 bytes)
        byte[] shortData = new byte[3];
        boolean result2 = (boolean) validateFileData.invoke(null, shortData);
        assertFalse("Should return false for fewer than 4 bytes", result2);
        
        // Test with valid data (exactly 4 bytes — the length prefix)
        byte[] validData = new byte[4];
        boolean result3 = (boolean) validateFileData.invoke(null, validData);
        assertTrue("Should return true for 4 or more bytes", result3);
        
        // Test with larger valid data
        byte[] largeData = new byte[250];
        boolean result4 = (boolean) validateFileData.invoke(null, largeData);
        assertTrue("Should return true for larger data", result4);
    }
    
    /**
     * Test writeKey() error handling (lines 487, 501, 502).
     * Tests validation and error paths in writeKey.
     */
    @Test
    public void testWriteKeyErrorHandling() throws Exception {
        // Test with null passkey (line 487)
        boolean result1 = Passkey.writeKey(null, testPinHash, tempPasskeyFile);
        assertFalse("Should return false for null passkey", result1);
        
        // Test with null PIN hash
        Passkey testPasskey = createTestPasskey();
        boolean result2 = Passkey.writeKey(testPasskey, null, tempPasskeyFile);
        assertFalse("Should return false for null PIN hash", result2);
        
        // Test with invalid PIN hash size
        byte[] shortPinHash = new byte[16];
        boolean result3 = Passkey.writeKey(testPasskey, shortPinHash, tempPasskeyFile);
        assertFalse("Should return false for invalid PIN hash size", result3);
    }
    
    /**
     * Test serializePasskey() with edge cases (lines 538, 543).
     * Tests serialization validation.
     */
    @Test
    public void testSerializePasskeyEdgeCases() throws Exception {
        Method serializePasskey = Passkey.class.getDeclaredMethod("serializePasskey", Passkey.class, byte[].class);
        serializePasskey.setAccessible(true);
        
        // Create passkey with null private key
        List<Map<String, byte[]>> resCreds = new ArrayList<>();
        java.lang.reflect.Constructor<Passkey> constructor = 
            Passkey.class.getDeclaredConstructor(PrivateKey.class, X509Certificate.class, List.class);
        constructor.setAccessible(true);
        
        KeyPair keyPair = KeyUtils.generateKeyPair("EC", 256);
        X509Certificate cert = CertUtils.generateCaCert("CN=Test", keyPair, 365, true);
        
        // Test with null private key (line 538)
        Passkey passkeyNullKey = constructor.newInstance(null, cert, resCreds);
        try {
            serializePasskey.invoke(null, passkeyNullKey, testPinHash);
            fail("Should throw exception for null private key");
        } catch (Exception e) {
            assertTrue("Should throw IllegalArgumentException", 
                      e.getCause() instanceof IllegalArgumentException);
        }
        
        // Test with null certificate (line 543)
        Passkey passkeyNullCert = constructor.newInstance(keyPair.getPrivate(), null, resCreds);
        try {
            serializePasskey.invoke(null, passkeyNullCert, testPinHash);
            fail("Should throw exception for null certificate");
        } catch (Exception e) {
            assertTrue("Should throw IllegalArgumentException", 
                      e.getCause() instanceof IllegalArgumentException);
        }
    }
    
    /**
     * Test removeResidentCredential() with various credential states (lines 579-590).
     * Tests credential removal logic.
     */
    @Test
    public void testRemoveResidentCredential() throws Exception {
        Passkey testPasskey = createTestPasskey();
        
        // Test with null resCreds
        byte[] rpId1 = "example.com".getBytes();
        boolean result1 = testPasskey.removeResidentCredential(rpId1);
        assertFalse("Should return false when resCreds is null", result1);
        
        // Add some credentials
        byte[] rpId2 = "test.com".getBytes();
        byte[] credId = new byte[]{1, 2, 3, 4};
        byte[] userHandle = new byte[]{5, 6, 7, 8};
        testPasskey.addResCred(rpId2, credId, userHandle);
        
        // Test removing existing credential
        boolean result2 = testPasskey.removeResidentCredential(rpId2);
        assertTrue("Should return true when credential is removed", result2);
        
        // Test removing non-existent credential
        byte[] rpId3 = "nonexistent.com".getBytes();
        boolean result3 = testPasskey.removeResidentCredential(rpId3);
        assertFalse("Should return false when credential doesn't exist", result3);
    }
    
    /**
     * Test openKey() with invalid PIN (lines 645, 650, 653).
     * Tests openKey validation and error handling.
     */
    @Test
    public void testOpenKeyWithInvalidPin() throws Exception {
        // Test with null lowerHash (line 645)
        Passkey result1 = Passkey.openKey(null);
        assertNull("Should return null for null lowerHash", result1);
        
        // Test with invalid lowerHash size (line 645)
        byte[] shortHash = new byte[HALF_HASH - 1];
        Passkey result2 = Passkey.openKey(shortHash);
        assertNull("Should return null for invalid lowerHash size", result2);
        
        // Test with valid lowerHash but no passkey files
        byte[] validHash = Arrays.copyOfRange(testPinHash, 0, HALF_HASH);
        Passkey result3 = Passkey.openKey(validHash);
        assertNull("Should return null when no passkey files found", result3);
    }
    
    /**
     * Test initRootKeyPair() initialization (line 178).
     * Tests root key pair initialization from file.
     */
    @Test
    public void testInitRootKeyPair() throws Exception {
        // Create a temporary key file
        File keyFile = tempFolder.newFile("test_platform.key");
        FileUtils.writePrivatePEM(rootKeyPair.getPrivate(), keyFile);
        
        // Clear existing root key pair
        setRootKeyPair(null, null);
        
        // Initialize from file
        boolean result = KeyUtils.initRootKeyPair(keyFile.getAbsolutePath(), null);
        assertTrue("Should successfully initialize root key pair", result);
        
        // Verify keys were set
        Field rootPublicKeyField = KeyUtils.class.getDeclaredField("rootPublicKey");
        rootPublicKeyField.setAccessible(true);
        PublicKey loadedPublicKey = (PublicKey) rootPublicKeyField.get(null);
        assertNotNull("Root public key should be set", loadedPublicKey);
        
        // Test with non-existent file
        boolean result2 = KeyUtils.initRootKeyPair("/nonexistent/path/key.pem", null);
        assertFalse("Should return false for non-existent file", result2);
    }
    
    /**
     * Test loadExistingKey() key loading (line 258).
     * Tests loading of existing key from file.
     */
    @Test
    public void testLoadExistingKey() throws Exception {
        Method loadExistingKey = KeyUtils.class.getDeclaredMethod("loadExistingRootKey", String.class, String.class);
        loadExistingKey.setAccessible(true);
        
        // Create a temporary key file
        File keyFile = tempFolder.newFile("existing_platform.key");
        FileUtils.writePrivatePEM(rootKeyPair.getPrivate(), keyFile);
        
        // Clear existing root key pair
        setRootKeyPair(null, null);
        
        // Load the key
        loadExistingKey.invoke(null, keyFile.getAbsolutePath(), null);
        
        // Verify keys were loaded
        Field rootPublicKeyField = KeyUtils.class.getDeclaredField("rootPublicKey");
        rootPublicKeyField.setAccessible(true);
        PublicKey loadedPublicKey = (PublicKey) rootPublicKeyField.get(null);
        assertNotNull("Root public key should be loaded", loadedPublicKey);
    }
    
    /**
     * Test getFileName() name generation (line 618).
     * Tests retrieval of passkey file name.
     */
    @Test
    public void testGetFileName() throws Exception {
        Passkey testPasskey = createTestPasskey();
        
        // Initially should be null
        assertNull("File name should be null initially", testPasskey.getFileName());
        
        // Set file name using reflection
        Field fileNameField = Passkey.class.getDeclaredField("fileName");
        fileNameField.setAccessible(true);
        fileNameField.set(testPasskey, "test.passkey");
        
        assertEquals("File name should match", "test.passkey", testPasskey.getFileName());
    }
    
    /**
     * Test addResCred() with null resCreds initialization (line 630).
     * Tests adding credentials when list is null.
     */
    @Test
    public void testAddResCredWithNullList() throws Exception {
        Passkey testPasskey = createTestPasskey();
        
        // Ensure resCreds is null
        Field resCredsField = Passkey.class.getDeclaredField("resCreds");
        resCredsField.setAccessible(true);
        resCredsField.set(testPasskey, null);
        
        // Add a credential
        byte[] rpId = "example.com".getBytes();
        byte[] credId = new byte[]{1, 2, 3, 4};
        byte[] userHandle = new byte[]{5, 6, 7, 8};
        testPasskey.addResCred(rpId, credId, userHandle);
        
        // Verify list was initialized and credential added
        List<Map<String, byte[]>> resCreds = testPasskey.getResCreds();
        assertNotNull("ResCreds should be initialized", resCreds);
        assertEquals("Should have one credential", 1, resCreds.size());
    }
}

// Made with Bob
