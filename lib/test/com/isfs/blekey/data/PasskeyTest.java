/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.data;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import org.junit.Before;
import org.jose4j.base64url.Base64;
import org.junit.After;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.mockito.Mockito;
import org.mockito.MockedStatic;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Collection;
import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Map;

import com.isfs.blekey.authenticator.TestHelper;
import com.isfs.blekey.util.FileUtils;
import com.isfs.blekey.util.KeyUtils;
import com.isfs.blekey.util.KeystoreManager;
import com.isfs.blekey.util.CertUtils;

/**
 * Comprehensive test suite for the Passkey class.
 * 
 * This test class covers:
 * 1. Core functionality (PIN hash management, serialization/deserialization)
 * 2. Encryption/decryption operations
 * 3. File I/O operations
 * 4. Security aspects (tamper detection, invalid inputs)
 * 5. Integration tests for end-to-end flows
 */
public class PasskeyTest {

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();
    
    private KeyPair rootKeyPair;
    private File tempPasskeyFile;
    private byte[] testPinHash;
    
    @Before
    public void setUp() throws Exception {
        // Initialize mock KeystoreManager for Passkey encryption operations
        KeystoreManager mockKeystoreManager = TestHelper.createMockKeystoreManager();
        KeyUtils.setKeystoreManager(mockKeystoreManager);
        
        // Generate a test PIN hash (32 bytes)
        testPinHash = new byte[32];
        new SecureRandom().nextBytes(testPinHash);
        
        // Create a temporary file for passkey storage
        tempPasskeyFile = tempFolder.newFile("test.passkey");
        
        // Generate a root key pair for testing
        rootKeyPair = KeyUtils.generateKeyPair("EC", 256);
        
        // Set the root key pair in Passkey class using reflection
        setRootKeyPair(rootKeyPair.getPublic(), rootKeyPair.getPrivate());
    }
    
    @After
    public void tearDown() throws Exception {
        // Clean up any resources
    }
    
    /**
     * Helper method to set the root key pair in the Passkey class using reflection
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
     * Helper method to access private methods using reflection
     */
    private Method getPrivateMethod(String methodName, Class<?>... parameterTypes) throws Exception {
        Method method = Passkey.class.getDeclaredMethod(methodName, parameterTypes);
        method.setAccessible(true);
        return method;
    }
    
    /**
     * Helper method to create a test Passkey instance
     */
    private Passkey createTestPasskey() throws Exception {
        KeyPair keyPair = KeyUtils.generateKeyPair("EC", 256);
        X509Certificate cert = CertUtils.generateCaCert("CN=TestPasskey", keyPair, 365, true);
        List<Map<String, byte[]>> resCreds = new ArrayList<>();
        
        return new Passkey(keyPair.getPrivate(), cert, resCreds);
    }

    //-------------------------------------------------------------------------
    // 1. PIN Hash Management Tests
    //-------------------------------------------------------------------------
    
    // Test removed - combinePinHash method no longer exists in Passkey class
    // The PIN hash splitting/combining functionality has been refactored
    
    /**
     * Test PIN hash splitting with invalid input
     */
    @Test(expected = IllegalArgumentException.class)
    public void testSplitPinHashWithInvalidInput() throws Exception {
        try {
            Method splitMethod = getPrivateMethod("splitPinHash", byte[].class);
            
            // Try to split a PIN hash that's too short
            byte[] shortPinHash = new byte[16]; // Should be 32 bytes
            splitMethod.invoke(null, shortPinHash);
        } catch (Exception e) {
            e.printStackTrace();
            throw (Exception) e.getCause();
        }
    }
    

    //-------------------------------------------------------------------------
    // 3. Encryption/Decryption Tests
    //-------------------------------------------------------------------------
    
    /**
     * Test encryption and decryption of passkey data.
     * Verifies the new two-file format: body in .passkey, ciphertext in .stash.
     */
    @Test
    public void testEncryptDecryptPasskeyData() throws Exception {
        // Use a mock KeystoreManager that returns false for isKeystoreAvailable()
        // so that ECDH encryption is used instead of KSM encryption
        KeystoreManager mockKsm = mock(KeystoreManager.class);
        when(mockKsm.isKeystoreAvailable()).thenReturn(false);
        KeyUtils.setKeystoreManager(mockKsm);
        
        byte[] pinHash = KeyUtils.getPinHash("nonce");
        List<Map<String, byte[]>> resCreds = new ArrayList<>();
        resCreds.add(Map.of("rp.id", "example.com".getBytes(), "user.id", "testuser".getBytes(), "cred.id", "cred".getBytes()));
        resCreds.add(Map.of("rp.id", "pirate.passkey".getBytes(), "user.id", "demouser".getBytes(), "cred.id", "newcred".getBytes()));

        KeyPair kp = KeyUtils.generateKeyPair("EC", 521);
        X509Certificate cert = CertUtils.generateCaCert("CN=root", kp, 365, false);

        // Write the passkey to file
        Passkey passkey = new Passkey(kp.getPrivate(), cert, resCreds);
        boolean writeSuccess = Passkey.writeKey(passkey, pinHash, tempPasskeyFile);
        assertTrue("Writing passkey should succeed", writeSuccess);
        
        // Verify .passkey body: starts with 4-byte LE PKCS12 length, no 230-byte header
        byte[] passkeyFileData = Files.readAllBytes(tempPasskeyFile.toPath());
        assertNotNull("Passkey file data should not be null", passkeyFileData);
        assertTrue("Passkey file should be at least 4 bytes", passkeyFileData.length >= 4);
        
        // Verify .stash file exists and contains the ciphertext
        File stashFile = FileUtils.getStashFile(tempPasskeyFile);
        assertTrue("Stash file should exist", stashFile.exists());
        byte[] stashData = Files.readAllBytes(stashFile.toPath());
        assertNotNull("Stash data should not be null", stashData);
        assertTrue("Stash data should not be empty", stashData.length > 0);
        
        // Decrypt the stash to verify upper hash
        byte[] upperHash = KeyUtils.ecdhDecrypt(stashData, rootKeyPair.getPrivate());
        assertNotNull("Decrypted upper hash should not be null", upperHash);
        assertEquals("Upper hash should be 16 bytes", 16, upperHash.length);
        
        // Verify it matches the expected upper hash from PIN
        byte[] expectedUpperHash = Arrays.copyOfRange(pinHash, 16, 32);
        assertArrayEquals("Decrypted upper hash should match original", expectedUpperHash, upperHash);
    }
    
    /**
     * Test header encryption and decryption
     */
    @Test
    public void testEncryptDecryptHeader() throws Exception {
        
        // Create test header
        byte[] pinHash = KeyUtils.getPinHash("nonce");
        byte[] upperHash = Arrays.copyOfRange(pinHash, 16, 32);        
        
        // Encrypt the header
        byte[] encUpperHash = KeyUtils.ecdhEncrypt(upperHash, rootKeyPair.getPublic());
        assertNotNull("Encrypted header should not be null", encUpperHash);
        
        // Decrypt the header
        byte[] recoveredHash = KeyUtils.ecdhDecrypt(encUpperHash, rootKeyPair.getPrivate());
        assertNotNull("Decrypted header should not be null", recoveredHash);
        assertTrue(Arrays.equals(upperHash, recoveredHash));

    }

    //-------------------------------------------------------------------------
    // 4. End-to-End Tests
    //-------------------------------------------------------------------------
    
    /**
     * Test generating a passkey and reading it back
     */
    @Test
    public void testGenerateAndReadPasskey() throws Exception {
        // Use a mock KeystoreManager that returns false for isKeystoreAvailable()
        // so that ECDH encryption is used instead of KSM encryption
        KeystoreManager mockKsm = mock(KeystoreManager.class);
        when(mockKsm.isKeystoreAvailable()).thenReturn(false);
        KeyUtils.setKeystoreManager(mockKsm);
        
        // Generate a passkey
        Passkey generatedPasskey = Passkey.generatePasskey(testPinHash, tempPasskeyFile);
        assertNotNull("Generated passkey should not be null", generatedPasskey);
        
        // Extract the lower hash
        Method splitMethod = getPrivateMethod("splitPinHash", byte[].class);
        byte[][] hashParts = (byte[][])splitMethod.invoke(null, testPinHash);
        byte[] lowerHash = hashParts[1];
        
        // Read the passkey back
        Passkey readPasskey = Passkey.openKey(lowerHash, tempPasskeyFile);
        
        // Verify the passkey was read correctly
        assertNotNull("Read passkey should not be null", readPasskey);
        assertNotNull("Private key should not be null", readPasskey.getPrivateKey());
        assertNotNull("Certificate should not be null", readPasskey.getCertificate());
        
        // Verify key components match (EC and ECDSA are equivalent)
        String generatedAlg = generatedPasskey.getPrivateKey().getAlgorithm();
        String readAlg = readPasskey.getPrivateKey().getAlgorithm();
        assertTrue("Private key algorithm should be EC or ECDSA",
                   ("EC".equals(generatedAlg) || "ECDSA".equals(generatedAlg)) &&
                   ("EC".equals(readAlg) || "ECDSA".equals(readAlg)));
        
        // Verify certificate
        assertEquals("Certificate subject DN mismatch",
                    generatedPasskey.getCertificate().getSubjectX500Principal().getName(),
                    readPasskey.getCertificate().getSubjectX500Principal().getName());
    }
    
    /**
     * Test resident credential management
     */
    @Test
    public void testResidentCredentialManagement() throws Exception {
        // Use a mock KeystoreManager that returns false for isKeystoreAvailable()
        // so that ECDH encryption is used instead of KSM encryption
        KeystoreManager mockKsm = mock(KeystoreManager.class);
        when(mockKsm.isKeystoreAvailable()).thenReturn(false);
        KeyUtils.setKeystoreManager(mockKsm);
        
        // Create a passkey
        Passkey passkey = createTestPasskey();
        
        // Add a resident credential
        byte[] rpId = "example.com".getBytes();
        byte[] credId = new byte[16];
        byte[] userHandle = new byte[16];
        new SecureRandom().nextBytes(credId);
        new SecureRandom().nextBytes(userHandle);
        
        passkey.addResCred(rpId, credId, userHandle);
        
        // Verify credential was added
        List<Map<String, byte[]>> retrievedCreds = passkey.getResCreds();
        assertNotNull("Retrieved credentials should not be null", retrievedCreds);
        assertEquals("Should have one credential", 1, retrievedCreds.size());
        
        // Find the credential by rpId
        Map<String, byte[]> cred = null;
        for (Map<String, byte[]> rc : retrievedCreds) {
            if (Arrays.equals(rpId, rc.get("rp.id"))) {
                cred = rc;
                break;
            }
        }
        
        assertNotNull("Credential should be found", cred);
        assertArrayEquals("Credential ID mismatch", credId, (byte[])cred.get("cred.id"));
        assertArrayEquals("User handle mismatch", userHandle, (byte[])cred.get("user.id"));
        
        // Save and reload the passkey
        assertTrue("Writing passkey should succeed", 
                  Passkey.writeKey(passkey, testPinHash, tempPasskeyFile));
        
        // Extract the lower hash
        Method splitMethod = getPrivateMethod("splitPinHash", byte[].class);
        byte[][] hashParts = (byte[][])splitMethod.invoke(null, testPinHash);
        byte[] lowerHash = hashParts[1];
        
        // Read the passkey back
        Passkey readPasskey = Passkey.openKey(lowerHash, tempPasskeyFile);
        assertNotNull("Read passkey should not be null", readPasskey);
        
        // Verify credential was preserved
        List<Map<String, byte[]>> reloadedCreds = readPasskey.getResCreds();
        assertNotNull("Reloaded credentials should not be null", reloadedCreds);
        assertEquals("Should still have one credential", 1, reloadedCreds.size());
        
        // Find the credential by rpId
        Map<String, byte[]> reloadedCred = null;
        for (Map<String, byte[]> rc : reloadedCreds) {
            if (Arrays.equals(rc.get("rp.id"), rpId)) {
                reloadedCred = rc;
                break;
            }
        }
        
        assertNotNull("Reloaded credential should be found", reloadedCred);
        assertArrayEquals("Reloaded credential ID mismatch",
                         credId, (byte[])reloadedCred.get("cred.id"));
        assertArrayEquals("Reloaded user handle mismatch",
                         userHandle, (byte[])reloadedCred.get("user.id"));
    }

    //-------------------------------------------------------------------------
    // 5. Security Tests
    //-------------------------------------------------------------------------
    
    /**
     * Test with invalid PIN hash
     */
    @Test
    public void testInvalidPinHash() throws Exception {
        // Generate a valid passkey
        Passkey generatedPasskey = Passkey.generatePasskey(testPinHash, tempPasskeyFile);
        assertNotNull("Generated passkey should not be null", generatedPasskey);
        
        // Create an incorrect lower hash
        byte[] incorrectLowerHash = new byte[16];
        new SecureRandom().nextBytes(incorrectLowerHash);
        
        // Try to open with incorrect PIN hash
        Passkey result = Passkey.openKey(incorrectLowerHash, tempPasskeyFile);
        
        // Should fail to open
        assertNull("Should not open with incorrect PIN hash", result);
    }
    
    /**
     * Test file tampering detection
     */
    @Test
    public void testTamperedFile() throws Exception {
        // Generate a valid passkey
        Passkey generatedPasskey = Passkey.generatePasskey(testPinHash, tempPasskeyFile);
        assertNotNull("Generated passkey should not be null", generatedPasskey);
        
        // Extract the lower hash
        Method splitMethod = getPrivateMethod("splitPinHash", byte[].class);
        byte[][] hashParts = (byte[][])splitMethod.invoke(null, testPinHash);
        byte[] lowerHash = hashParts[1];
        
        // Read the file bytes
        byte[] fileBytes = Files.readAllBytes(tempPasskeyFile.toPath());
        
        // Tamper with the bytes (modify some bytes in the middle)
        fileBytes[fileBytes.length / 2] ^= 0xFF;
        
        // Write the tampered bytes back
        Files.write(tempPasskeyFile.toPath(), fileBytes);
        
        // Try to open with correct lower hash
        Passkey result = Passkey.openKey(lowerHash, tempPasskeyFile);
        
        // Should fail to open due to tampering
        assertNull("Should not open tampered file", result);
    }
    
    /**
     * Test input validation for writeKey
     */
    @Test
    public void testWriteKeyInputValidation() throws Exception {
        // Test with null passkey
        assertFalse("Should reject null passkey", 
                   Passkey.writeKey(null, testPinHash, tempPasskeyFile));
        
        // Test with null PIN hash
        Passkey passkey = createTestPasskey();
        assertFalse("Should reject null PIN hash", 
                   Passkey.writeKey(passkey, null, tempPasskeyFile));
        
        // Test with incorrect PIN hash length
        byte[] shortPinHash = new byte[16]; // Should be 32
        assertFalse("Should reject short PIN hash", 
                   Passkey.writeKey(passkey, shortPinHash, tempPasskeyFile));
    }
    
    /**
     * Test input validation for readKey
     */
    @Test
    public void testReadKeyInputValidation() throws Exception {
        // Get the private method
        Method readKeyMethod = getPrivateMethod("readKey", File.class, byte[].class);
        
        // Test with null file
        assertNull("Should reject null file", 
                  readKeyMethod.invoke(null, null, new byte[16]));
        
        // Test with null lower hash
        assertNull("Should reject null lower hash", 
                  readKeyMethod.invoke(null, tempPasskeyFile, null));
        
        // Test with incorrect lower hash length
        byte[] shortLowerHash = new byte[8]; // Should be 16
        assertNull("Should reject short lower hash", 
                  readKeyMethod.invoke(null, tempPasskeyFile, shortLowerHash));
    }

    //-------------------------------------------------------------------------
    // 6. Mock-Based Tests
    //-------------------------------------------------------------------------
    
    /**
     * Test openKey with mocked FileUtils
     */
    @Test
    public void testOpenKeyWithMockedFileUtils() throws Exception {
        // This test requires Mockito and PowerMockito for static mocking
        // If not available, skip this test
        try {
            Class.forName("org.mockito.Mockito");
        } catch (ClassNotFoundException e) {
            System.out.println("Skipping mock test - Mockito not available");
            return;
        }
        
        // Create a test passkey
        Passkey testPasskey = createTestPasskey();
        
        // Create test files
        File mockFile1 = new File("mock1.passkey");
        File mockFile2 = new File("mock2.passkey");
        
        // Mock FileUtils.listPasskeys() using Mockito's static mocking
        try (MockedStatic<FileUtils> mockedFileUtils = Mockito.mockStatic(FileUtils.class)) {
            mockedFileUtils.when(FileUtils::listPasskeys).thenReturn((List<File>) List.of(mockFile1, mockFile2));
            
            // Mock Passkey.readKey using PowerMockito
            try (MockedStatic<Passkey> mockedPasskey = Mockito.mockStatic(Passkey.class)) {
                // Set up the mock to return null for mockFile1 and testPasskey for mockFile2
                byte[] lowerHash = new byte[16];
                mockedPasskey.when(() -> Passkey.readKey(Mockito.eq(mockFile1), Mockito.eq(lowerHash)))
                           .thenReturn(null);
                mockedPasskey.when(() -> Passkey.readKey(Mockito.eq(mockFile2), Mockito.eq(lowerHash)))
                           .thenReturn(testPasskey);
                
                // Allow the real openKey method to be called
                mockedPasskey.when(() -> Passkey.openKey(Mockito.eq(lowerHash)))
                           .thenCallRealMethod();
                
                // Call the method under test
                Passkey result = Passkey.openKey(lowerHash);
                
                // Verify result
                assertSame("Should return the test passkey", testPasskey, result);
            }
        }
    }

    //-------------------------------------------------------------------------
    // 7. Performance and Stress Tests
    //-------------------------------------------------------------------------
    
    /**
     * Test with a large number of resident credentials
     */
    @Test
    public void testLargeNumberOfResidentCredentials() throws Exception {
        // Use a mock KeystoreManager that returns false for isKeystoreAvailable()
        // so that ECDH encryption is used instead of KSM encryption
        KeystoreManager mockKsm = mock(KeystoreManager.class);
        when(mockKsm.isKeystoreAvailable()).thenReturn(false);
        KeyUtils.setKeystoreManager(mockKsm);
        
        // Create a passkey
        Passkey passkey = createTestPasskey();
        
        // Add a large number of resident credentials (100 for testing, could be more in real stress test)
        int credentialCount = 100;
        for (int i = 0; i < credentialCount; i++) {
            byte[] rpId = ("example" + i + ".com").getBytes();
            byte[] credId = new byte[16];
            byte[] userHandle = new byte[16];
            new SecureRandom().nextBytes(credId);
            new SecureRandom().nextBytes(userHandle);
            
            passkey.addResCred(rpId, credId, userHandle);
        }
        
        // Verify all credentials were added
        assertEquals("Should have added all credentials", 
                    credentialCount, passkey.getResCreds().size());
        
        // Save and reload
        assertTrue("Writing passkey should succeed", 
                  Passkey.writeKey(passkey, testPinHash, tempPasskeyFile));
        
        // Extract the lower hash
        Method splitMethod = getPrivateMethod("splitPinHash", byte[].class);
        byte[][] hashParts = (byte[][])splitMethod.invoke(null, testPinHash);
        byte[] lowerHash = hashParts[1];
        
        // Read back
        Passkey readPasskey = Passkey.openKey(lowerHash, tempPasskeyFile);
        
        // Verify all credentials were preserved
        assertNotNull("Read passkey should not be null", readPasskey);
        assertEquals("Should have preserved all credentials", 
                    credentialCount, readPasskey.getResCreds().size());
    }
    
    //-------------------------------------------------------------------------
    // 8. Parameterized Tests
    //-------------------------------------------------------------------------
    
    /**
     * Parameterized test class for testing Passkey with different key sizes.
     * This demonstrates how to run the same test with different parameters.
     */
    @RunWith(Parameterized.class)
    public static class PasskeyKeySizeTest {
        
        @Rule
        public TemporaryFolder tempFolder = new TemporaryFolder();
        
        private final String keyAlgorithm;
        private final int keySize;
        private final boolean shouldSucceed;
        private File tempPasskeyFile;
        private byte[] testPinHash;
        
        /**
         * Define the parameters for the test.
         * Each array element represents a test case with:
         * - Key algorithm
         * - Key size
         * - Whether the operation should succeed
         */
        @Parameters(name = "{0} key with {1} bits (should succeed: {2})")
        public static Collection<Object[]> data() {
            return Arrays.asList(new Object[][] {
                // Valid key sizes for EC
                { "EC", 256, true },
                { "EC", 384, true },
                { "EC", 521, true },
                // Invalid key size for EC
                { "EC", 123, false },
            });
        }
        
        /**
         * Constructor for the parameterized test
         */
        public PasskeyKeySizeTest(String keyAlgorithm, int keySize, boolean shouldSucceed) {
            this.keyAlgorithm = keyAlgorithm;
            this.keySize = keySize;
            this.shouldSucceed = shouldSucceed;
        }
        
        @Before
        public void setUp() throws Exception {
            // Initialize mock KeystoreManager for Passkey encryption operations
            KeystoreManager mockKeystoreManager = TestHelper.createMockKeystoreManager();
            KeyUtils.setKeystoreManager(mockKeystoreManager);
            
            // Generate a test PIN hash (32 bytes)
            testPinHash = new byte[32];
            new SecureRandom().nextBytes(testPinHash);
            
            // Create a temporary file for passkey storage
            tempPasskeyFile = tempFolder.newFile("test_" + keyAlgorithm + "_" + keySize + ".passkey");
            
            // Set up the root key pair
            try {
                KeyPair rootKeyPair = KeyUtils.generateKeyPair("EC", 256);
                setRootKeyPair(rootKeyPair.getPublic(), rootKeyPair.getPrivate());
            } catch (Exception e) {
                System.err.println("Failed to set up root key pair: " + e.getMessage());
            }
        }
        
        /**
         * Helper method to set the root key pair in the Passkey class using reflection
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
         * Test generating a passkey with different key sizes
         */
        @Test
        public void testPasskeyWithDifferentKeySizes() {
            try {
                // Generate a key pair with the specified algorithm and size
                KeyPair keyPair = null;
                try {
                    keyPair = KeyUtils.generateKeyPair(keyAlgorithm, keySize);
                } catch (Exception e) {
                    if (shouldSucceed) {
                        fail("Key generation failed but should have succeeded: " + e.getMessage());
                    } else {
                        // Expected failure for invalid key sizes
                        return;
                    }
                }
                
                // If we get here and shouldn't succeed, fail the test
                if (!shouldSucceed) {
                    fail("Key generation succeeded but should have failed");
                }
                
                // Create a certificate
                X509Certificate cert = CertUtils.generateCaCert(
                    "CN=Test" + keyAlgorithm + keySize, keyPair, 365, true);
                
                // Create a passkey
                Passkey passkey = new Passkey(keyPair.getPrivate(), cert, new ArrayList<>());
                
                // Write the passkey to file
                boolean writeResult = Passkey.writeKey(passkey, testPinHash, tempPasskeyFile);
                assertTrue("Writing passkey should succeed", writeResult);
                
                // Extract the lower hash
                Method splitMethod = Passkey.class.getDeclaredMethod("splitPinHash", byte[].class);
                splitMethod.setAccessible(true);
                byte[][] hashParts = (byte[][])splitMethod.invoke(null, testPinHash);
                byte[] lowerHash = hashParts[1];
                
                // Read the passkey back
                Passkey readPasskey = Passkey.openKey(lowerHash, tempPasskeyFile);
                
                // Verify the passkey was read correctly
                assertNotNull("Read passkey should not be null", readPasskey);
                assertEquals("Key algorithm should match",
                            keyPair.getPrivate().getAlgorithm(),
                            readPasskey.getPrivateKey().getAlgorithm());
                
                // For EC keys, verify the key size
                if (keyAlgorithm.equals("EC")) {
                    java.security.interfaces.ECKey ecKey =
                        (java.security.interfaces.ECKey)readPasskey.getPrivateKey();
                    int readKeySize = ecKey.getParams().getCurve().getField().getFieldSize();
                    assertEquals("Key size should match", keySize, readKeySize);
                }
                
            } catch (Exception e) {
                if (shouldSucceed) {
                    fail("Test failed but should have succeeded: " + e.getMessage());
                }
                // Otherwise, exception is expected for invalid parameters
            }
        }
    }
    
    /**
     * Parameterized test class for testing Passkey with different PIN hash sizes.
     */
    @RunWith(Parameterized.class)
    public static class PasskeyPinHashSizeTest {
        
        @Rule
        public TemporaryFolder tempFolder = new TemporaryFolder();
        
        private final int pinHashSize;
        private final boolean shouldSucceed;
        private File tempPasskeyFile;
        
        /**
         * Define the parameters for the test.
         * Each array element represents a test case with:
         * - PIN hash size
         * - Whether the operation should succeed
         */
        @Parameters(name = "PIN hash size: {0} bytes (should succeed: {1})")
        public static Collection<Object[]> data() {
            return Arrays.asList(new Object[][] {
                // Valid PIN hash size
                { 32, true },
                // Invalid PIN hash sizes
                { 16, false },  // Too small
                { 24, false },  // Not the expected size
                { 64, false }   // Too large
            });
        }
        
        /**
         * Constructor for the parameterized test
         */
        public PasskeyPinHashSizeTest(int pinHashSize, boolean shouldSucceed) {
            this.pinHashSize = pinHashSize;
            this.shouldSucceed = shouldSucceed;
        }
        
        @Before
        public void setUp() throws Exception {
            // Initialize mock KeystoreManager for Passkey encryption operations
            KeystoreManager mockKeystoreManager = TestHelper.createMockKeystoreManager();
            KeyUtils.setKeystoreManager(mockKeystoreManager);
            
            // Create a temporary file for passkey storage
            tempPasskeyFile = tempFolder.newFile("test_pinhash_" + pinHashSize + ".passkey");
            
            // Set up the root key pair
            try {
                KeyPair rootKeyPair = KeyUtils.generateKeyPair("EC", 256);
                setRootKeyPair(rootKeyPair.getPublic(), rootKeyPair.getPrivate());
            } catch (Exception e) {
                System.err.println("Failed to set up root key pair: " + e.getMessage());
            }
        }
        
        /**
         * Helper method to set the root key pair in the Passkey class using reflection
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
         * Test generating a passkey with different PIN hash sizes
         */
        @Test
        public void testPasskeyWithDifferentPinHashSizes() {
            try {
                // Generate a PIN hash of the specified size
                byte[] pinHash = new byte[pinHashSize];
                new SecureRandom().nextBytes(pinHash);
                
                // Create a passkey
                Passkey passkey = null;
                try {
                    // Generate a test passkey
                    KeyPair keyPair = KeyUtils.generateKeyPair("EC", 256);
                    X509Certificate cert = CertUtils.generateCaCert("CN=TestPinHash", keyPair, 365, true);
                    passkey = new Passkey(keyPair.getPrivate(), cert, new ArrayList<>());
                } catch (Exception e) {
                    fail("Failed to create test passkey: " + e.getMessage());
                }
                
                // Write the passkey to file
                boolean writeResult = Passkey.writeKey(passkey, pinHash, tempPasskeyFile);
                
                if (shouldSucceed) {
                    assertTrue("Writing passkey should succeed", writeResult);
                    byte[] passkeyBytes = Files.readAllBytes(Path.of(tempPasskeyFile.getAbsolutePath()));
                    System.err.println(Base64.encode(passkeyBytes));
                    assertNotNull("Passkey bytes hould exist", passkeyBytes);
                    assertTrue("Passkey bytes should exist", passkeyBytes.length > 0);
                    
                    // Try to extract the lower hash
                    try {
                        Method splitMethod = Passkey.class.getDeclaredMethod("splitPinHash", byte[].class);
                        splitMethod.setAccessible(true);
                        byte[][] hashParts = (byte[][])splitMethod.invoke(null, pinHash);
                        byte[] lowerHash = hashParts[1];
                        
                        // Read the passkey back
                        Passkey readPasskey = Passkey.openKey(lowerHash, tempPasskeyFile);
                        assertNotNull("Read passkey should not be null", readPasskey);
                        assertNotNull("read passkey's private key should not be null", readPasskey.getPrivateKey());
                        assertEquals(passkey.getPrivateKey(), readPasskey.getPrivateKey());
                    } catch (Exception e) {
                        fail("Failed to read passkey: " + e.getMessage());
                    }
                } else {
                    assertFalse("Writing passkey should fail with invalid PIN hash size", writeResult);
                }
                
            } catch (Exception e) {
                if (shouldSucceed) {
                    fail("Test failed but should have succeeded: " + e.getMessage());
                }
                // Otherwise, exception is expected for invalid parameters
            }
        }
    }
    
}

// Made with Bob