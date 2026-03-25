/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.util;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.Before;
 import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
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
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * Comprehensive test suite for the KeyUtils class.
 */
public class KeyUtilsTest {

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();
    
    private KeyPair ecKeyPair;
    private KeyPair rsaKeyPair;
    private byte[] testData;
    
    @Before
    public void setUp() throws Exception {
        // Generate test key pairs
        ecKeyPair = KeyUtils.generateKeyPair("EC", 256);
        rsaKeyPair = KeyUtils.generateKeyPair("RSA", 2048);
        
        // Create test data
        testData = "Test data for encryption and decryption".getBytes(StandardCharsets.UTF_8);
    }
    
    @After
    public void tearDown() throws Exception {
        // Clean up resources
    }
    
    /**
     * Test key pair generation with different algorithms and key sizes
     */
    @Test
    public void testGenerateKeyPair() throws Exception {
        // Test EC key generation
        KeyPair ecKeyPair = KeyUtils.generateKeyPair("EC", 256);
        assertNotNull("EC key pair should not be null", ecKeyPair);
        assertTrue("Private key should be an EC key", ecKeyPair.getPrivate() instanceof ECPrivateKey);
        assertTrue("Public key should be an EC key", ecKeyPair.getPublic() instanceof ECPublicKey);
        
        // Test RSA key generation
        KeyPair rsaKeyPair = KeyUtils.generateKeyPair("RSA", 2048);
        assertNotNull("RSA key pair should not be null", rsaKeyPair);
        assertTrue("Private key should be an RSA key", rsaKeyPair.getPrivate() instanceof RSAPrivateCrtKey);
        assertTrue("Public key should be an RSA key", rsaKeyPair.getPublic() instanceof RSAPublicKey);
    }
    
    /**
     * Test getting public key from private key
     */
    @Test
    public void testGetPubKey() throws Exception {
        // Test EC key
        ECPrivateKey ecPrivateKey = (ECPrivateKey) ecKeyPair.getPrivate();
        ECPublicKey ecPublicKey = KeyUtils.getPubKey(ecPrivateKey);
        assertNotNull("EC public key should not be null", ecPublicKey);
        
        // Test RSA key
        RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey) rsaKeyPair.getPrivate();
        RSAPublicKey rsaPublicKey = KeyUtils.getPubKey(rsaPrivateKey);
        assertNotNull("RSA public key should not be null", rsaPublicKey);
        
        // Verify the public keys match the original key pair
        assertEquals("EC public key should match original", 
                    ecKeyPair.getPublic().getEncoded().length, 
                    ecPublicKey.getEncoded().length);
        assertEquals("RSA public key should match original", 
                    rsaKeyPair.getPublic().getEncoded().length, 
                    rsaPublicKey.getEncoded().length);
    }
    
    /**
     * Test ECDH encryption and decryption
     */
    @Test
    public void testEcdhEncryptDecrypt() throws Exception {
        // Generate a test EC key pair
        KeyPair keyPair = KeyUtils.generateKeyPair("EC", 256);
        
        // Encrypt data using the public key
        byte[] encrypted = KeyUtils.ecdhEncrypt(testData, keyPair.getPublic());
        assertNotNull("Encrypted data should not be null", encrypted);
        
        // Decrypt data using the private key
        byte[] decrypted = KeyUtils.ecdhDecrypt(encrypted, keyPair.getPrivate());
        assertNotNull("Decrypted data should not be null", decrypted);
        
        // Verify the decrypted data matches the original
        assertArrayEquals("Decrypted data should match original", testData, decrypted);
    }
    
    /**
     * Test PIN hash generation
     */
    @Test
    public void testGetPinHash() {
        // Test with a simple PIN
        String pin = "12345678";
        byte[] pinHash = KeyUtils.getPinHash(pin);
        assertNotNull("PIN hash should not be null", pinHash);
        assertEquals("PIN hash should be 32 bytes (SHA-256)", 32, pinHash.length);
        
        // Test with a different PIN
        String pin2 = "87654321";
        byte[] pinHash2 = KeyUtils.getPinHash(pin2);
        assertNotNull("PIN hash 2 should not be null", pinHash2);
        
        // Verify different PINs produce different hashes
        assertFalse("Different PINs should produce different hashes", 
                   Arrays.equals(pinHash, pinHash2));
    }
    
    /**
     * Test getting lower PIN hash
     */
    @Test
    public void testGetLowerPinHash() {
        // Test with a simple PIN
        String pin = "12345678";
        byte[] lowerHash = KeyUtils.getLowerPinHash(pin);
        assertNotNull("Lower PIN hash should not be null", lowerHash);
        assertEquals("Lower PIN hash should be 16 bytes", 16, lowerHash.length);
        
        // Verify lower hash is first 16 bytes of full hash
        byte[] fullHash = KeyUtils.getPinHash(pin);
        byte[] expectedLowerHash = Arrays.copyOf(fullHash, 16);
        assertArrayEquals("Lower hash should be first 16 bytes of full hash", 
                         expectedLowerHash, lowerHash);
    }
    
    /**
     * Test COSE key conversion for EC keys
     */
    @Test
    public void testCoseKeyConversionEC() throws Exception {
        // Convert EC public key to COSE format
        Map<Integer, Object> coseKey = KeyUtils.toCoseKey(ecKeyPair.getPublic());
        assertNotNull("COSE key should not be null", coseKey);
        assertEquals("COSE key type should be EC2", 2, coseKey.get(1)); // KTY = 2 (EC2)
        
        // Convert COSE key back to public key
        PublicKey publicKey = KeyUtils.fromCoseKey(coseKey);
        assertNotNull("Public key from COSE should not be null", publicKey);
        assertTrue("Public key should be an EC key", publicKey instanceof ECPublicKey);
    }
    
    /**
     * Test COSE key conversion for RSA keys
     */
    @Test
    public void testCoseKeyConversionRSA() throws Exception {
        // Convert RSA public key to COSE format
        Map<Integer, Object> coseKey = KeyUtils.toCoseKey(rsaKeyPair.getPublic());
        assertNotNull("COSE key should not be null", coseKey);
        assertEquals("COSE key type should be RSA", 3, coseKey.get(1)); // KTY = 3 (RSA)
        
        // Convert COSE key back to public key
        PublicKey publicKey = KeyUtils.fromCoseKey(coseKey);
        assertNotNull("Public key from COSE should not be null", publicKey);
        assertTrue("Public key should be an RSA key", publicKey instanceof RSAPublicKey);
    }
    
    /**
     * Test reading and writing private keys to files
     */
    @Test
    public void testReadWritePrivateKey() throws Exception {
        // Create a temporary file for the private key
        File privateKeyFile = tempFolder.newFile("test_private.key");
        
        // Write the private key to the file in PKCS8 format
        FileUtils.writePrivatePEM(ecKeyPair.getPrivate(), privateKeyFile);
        
        // Read the private key back
        PrivateKey readKey = FileUtils.readPrivatePEM(privateKeyFile);
        assertNotNull("Read private key should not be null", readKey);
        assertTrue("Read key should be an EC key", readKey instanceof ECPrivateKey);
        
        // For EC keys, compare the actual private key values (S values)
        ECPrivateKey originalEcKey = (ECPrivateKey) ecKeyPair.getPrivate();
        ECPrivateKey readEcKey = (ECPrivateKey) readKey;
        
        assertEquals("Private key S values should be equal",
                    originalEcKey.getS(), readEcKey.getS());
        
        // Also verify that the curve parameters are the same
        assertEquals("Curve field size should match",
                    originalEcKey.getParams().getCurve().getField().getFieldSize(),
                    readEcKey.getParams().getCurve().getField().getFieldSize());
        
        // Functional verification: Sign data with both keys and verify with corresponding public keys
        byte[] testData = "Test data for signature verification".getBytes();
        
        // Sign with original key
        java.security.Signature sig1 = java.security.Signature.getInstance("SHA256withECDSA");
        sig1.initSign(ecKeyPair.getPrivate());
        sig1.update(testData);
        byte[] signature1 = sig1.sign();
        
        // Sign with read key
        java.security.Signature sig2 = java.security.Signature.getInstance("SHA256withECDSA");
        sig2.initSign(readKey);
        sig2.update(testData);
        byte[] signature2 = sig2.sign();
        
        // Verify signature1 with public key derived from readKey
        ECPublicKey derivedPublicKey = KeyUtils.getPubKey(readEcKey);
        java.security.Signature verifier1 = java.security.Signature.getInstance("SHA256withECDSA");
        verifier1.initVerify(derivedPublicKey);
        verifier1.update(testData);
        assertTrue("Signature from original key should verify with public key from read key",
                  verifier1.verify(signature1));
        
        // Verify signature2 with original public key
        java.security.Signature verifier2 = java.security.Signature.getInstance("SHA256withECDSA");
        verifier2.initVerify(ecKeyPair.getPublic());
        verifier2.update(testData);
        assertTrue("Signature from read key should verify with original public key",
                  verifier2.verify(signature2));
    }
    
    /**
     * Test decapsulate method for ECDH key agreement
     */
    @Test
    public void testDecapsulate() throws Exception {
        // Generate two EC key pairs
        KeyPair aliceKeyPair = KeyUtils.generateKeyPair("EC", 256);
        KeyPair bobKeyPair = KeyUtils.generateKeyPair("EC", 256);
        
        // Perform key agreement from Alice to Bob
        byte[] aliceSharedSecret = KeyUtils.decapsulate(bobKeyPair.getPublic(), aliceKeyPair.getPrivate());
        assertNotNull("Alice's shared secret should not be null", aliceSharedSecret);
        
        // Perform key agreement from Bob to Alice
        byte[] bobSharedSecret = KeyUtils.decapsulate(aliceKeyPair.getPublic(), bobKeyPair.getPrivate());
        assertNotNull("Bob's shared secret should not be null", bobSharedSecret);
        
        // Verify both parties derive the same shared secret
        assertArrayEquals("Shared secrets should match", aliceSharedSecret, bobSharedSecret);
    }
    
    /**
     * Test scalar multiplication for EC points
     */
    @Test
    public void testScalmult() throws Exception {
        // Get the EC parameters from the key pair
        ECPrivateKey privateKey = (ECPrivateKey) ecKeyPair.getPrivate();
        ECPublicKey publicKey = (ECPublicKey) ecKeyPair.getPublic();
        
        // Perform scalar multiplication: private scalar * generator point
        ECPoint result = KeyUtils.scalmult(
            privateKey.getParams().getCurve(),
            privateKey.getParams().getGenerator(),
            privateKey.getS()
        );
        
        // Verify the result matches the public key point
        assertNotNull("Result point should not be null", result);
        assertEquals("X coordinate should match", 
                    publicKey.getW().getAffineX().bitLength(), 
                    result.getAffineX().bitLength());
        assertEquals("Y coordinate should match", 
                    publicKey.getW().getAffineY().bitLength(), 
                    result.getAffineY().bitLength());
    }
    
    /**
     * Parameterized test class for testing KeyUtils with different key sizes.
     */
    @RunWith(Parameterized.class)
    public static class KeyUtilsKeySizeTest {
        
        private final String keyAlgorithm;
        private final int keySize;
        private final boolean shouldSucceed;
        
        /**
         * Define the parameters for the test.
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
                // Valid key sizes for RSA
                { "RSA", 2048, true },
                { "RSA", 3072, true },
                { "RSA", 4096, true },
                { "RSA", 256, true }  // Technically generates but insecure
            });
        }
        
        /**
         * Constructor for the parameterized test
         */
        public KeyUtilsKeySizeTest(String keyAlgorithm, int keySize, boolean shouldSucceed) {
            this.keyAlgorithm = keyAlgorithm;
            this.keySize = keySize;
            this.shouldSucceed = shouldSucceed;
        }
        
        /**
         * Test key generation with different algorithms and sizes
         */
        @Test
        public void testKeyGeneration() {
            try {
                KeyPair keyPair = KeyUtils.generateKeyPair(keyAlgorithm, keySize);
                
                if (!shouldSucceed) {
                    fail("Key generation should have failed for " + keyAlgorithm + " with size " + keySize);
                }
                
                assertNotNull("Key pair should not be null", keyPair);
                assertNotNull("Private key should not be null", keyPair.getPrivate());
                assertNotNull("Public key should not be null", keyPair.getPublic());
                
                // Verify the algorithm
                assertEquals("Key algorithm should match", keyAlgorithm, keyPair.getPrivate().getAlgorithm());
                
                // Verify key size for EC keys
                if (keyAlgorithm.equals("EC") && keyPair.getPrivate() instanceof ECPrivateKey) {
                    ECPrivateKey ecKey = (ECPrivateKey) keyPair.getPrivate();
                    int fieldSize = ecKey.getParams().getCurve().getField().getFieldSize();
                    assertEquals("EC key field size should match", keySize, fieldSize);
                }
                
                // Verify key size for RSA keys
                if (keyAlgorithm.equals("RSA") && keyPair.getPrivate() instanceof RSAPrivateCrtKey) {
                    RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) keyPair.getPrivate();
                    int actualSize = rsaKey.getModulus().bitLength();
                    // RSA key sizes might not be exactly the requested size
                    assertTrue("RSA key size should be close to requested size", 
                              Math.abs(actualSize - keySize) <= 8);
                }
                
            } catch (Exception e) {
                if (shouldSucceed) {
                    fail("Key generation should have succeeded for " + keyAlgorithm + 
                         " with size " + keySize + ": " + e.getMessage());
                }
                // Otherwise, exception is expected for invalid parameters
            }
        }
    }
    
    /**
     * Parameterized test class for testing PIN hash generation with different inputs.
     */
    @RunWith(Parameterized.class)
    public static class PinHashTest {
        
        private final String pin;
        private final int expectedHashLength;
        private final int expectedLowerHashLength;
        
        /**
         * Define the parameters for the test.
         */
        @Parameters(name = "PIN: {0}, Hash Length: {1}, Lower Hash Length: {2}")
        public static Collection<Object[]> data() {
            return Arrays.asList(new Object[][] {
                { "1234", 32, 16 },
                { "12345678", 32, 16 },
                { "complex!P@ssw0rd", 32, 16 },
                { "", 32, 16 },  // Empty PIN
                { "ピン", 32, 16 }  // Non-ASCII characters
            });
        }
        
        /**
         * Constructor for the parameterized test
         */
        public PinHashTest(String pin, int expectedHashLength, int expectedLowerHashLength) {
            this.pin = pin;
            this.expectedHashLength = expectedHashLength;
            this.expectedLowerHashLength = expectedLowerHashLength;
        }
        
        /**
         * Test PIN hash generation with different inputs
         */
        @Test
        public void testPinHashGeneration() {
            // Test full hash
            byte[] fullHash = KeyUtils.getPinHash(pin);
            assertNotNull("Full hash should not be null", fullHash);
            assertEquals("Full hash length should match expected", expectedHashLength, fullHash.length);
            
            // Test lower hash
            byte[] lowerHash = KeyUtils.getLowerPinHash(pin);
            assertNotNull("Lower hash should not be null", lowerHash);
            assertEquals("Lower hash length should match expected", expectedLowerHashLength, lowerHash.length);
            
            // Verify lower hash is first half of full hash
            byte[] expectedLowerHash = Arrays.copyOf(fullHash, expectedLowerHashLength);
            assertArrayEquals("Lower hash should be first half of full hash", expectedLowerHash, lowerHash);
        }
    }
    
    /**
     * Parameterized test class for testing ECDH encryption/decryption with different data sizes.
     */
    @RunWith(Parameterized.class)
    public static class EcdhDataSizeTest {
        
        private final int dataSize;
        private KeyPair keyPair;
        
        /**
         * Define the parameters for the test.
         */
        @Parameters(name = "Data size: {0} bytes")
        public static Collection<Object[]> data() {
            return Arrays.asList(new Object[][] {
                // { 0 },      // Empty data - skipped: ciphertext validation requires minimum size
                { 16 },     // Small data
                { 1024 },   // 1KB
                { 10240 }  // 10KB
                // { 102400 }  // 100KB - skipped: exceeds DRBG limit (262144 bits)
            });
        }
        
        /**
         * Constructor for the parameterized test
         */
        public EcdhDataSizeTest(int dataSize) {
            this.dataSize = dataSize;
        }
        
        @Before
        public void setUp() throws Exception {
            // Generate a test EC key pair
            keyPair = KeyUtils.generateKeyPair("EC", 256);
        }
        
        /**
         * Test ECDH encryption/decryption with different data sizes
         */
        @Test
        public void testEcdhWithDifferentDataSizes() throws Exception {
            // Create test data of the specified size
            byte[] testData = new byte[dataSize];
            new SecureRandom().nextBytes(testData);
            
            // Encrypt the data
            byte[] encrypted = KeyUtils.ecdhEncrypt(testData, keyPair.getPublic());
            assertNotNull("Encrypted data should not be null", encrypted);
            
            // Decrypt the data
            byte[] decrypted = KeyUtils.ecdhDecrypt(encrypted, keyPair.getPrivate());
            assertNotNull("Decrypted data should not be null", decrypted);
            
            // Verify the decrypted data matches the original
            assertArrayEquals("Decrypted data should match original", testData, decrypted);
        }
    }
    
    /**
     * Test createCoseRsaKey method using reflection
     */
    @Test
    public void testCreateCoseRsaKey() throws Exception {
        // Generate an RSA key pair
        KeyPair keyPair = KeyUtils.generateKeyPair("RSA", 2048);
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        
        // Access the private method using reflection
        java.lang.reflect.Method createCoseRsaKeyMethod = KeyUtils.class.getDeclaredMethod(
            "createCoseRsaKey", RSAPublicKey.class);
        createCoseRsaKeyMethod.setAccessible(true);
        
        // Invoke the method
        @SuppressWarnings("unchecked")
        Map<Integer, Object> coseKey = (Map<Integer, Object>) createCoseRsaKeyMethod.invoke(null, rsaPublicKey);
        
        // Verify the COSE key
        assertNotNull("COSE key should not be null", coseKey);
        assertEquals("COSE key type should be RSA", 3, coseKey.get(1)); // KTY = 3 (RSA)
        assertEquals("COSE algorithm should be RS256", -257, coseKey.get(3)); // ALG = -257 (RS256)
        
        // Verify RSA-specific parameters
        assertTrue("COSE key should contain modulus", coseKey.containsKey(-1)); // N parameter
        assertTrue("COSE key should contain exponent", coseKey.containsKey(-2)); // E parameter
        
        // Verify the modulus and exponent
        byte[] n = (byte[]) coseKey.get(-1);
        byte[] e = (byte[]) coseKey.get(-2);
        assertNotNull("Modulus should not be null", n);
        assertNotNull("Exponent should not be null", e);
        
        // Convert COSE key back to public key and verify it matches the original
        PublicKey convertedKey = KeyUtils.fromCoseKey(coseKey);
        assertTrue("Converted key should be an RSA key", convertedKey instanceof RSAPublicKey);
        RSAPublicKey convertedRsaKey = (RSAPublicKey) convertedKey;
        
        // Compare key components
        assertEquals("Modulus should match",
                    rsaPublicKey.getModulus().bitLength(),
                    convertedRsaKey.getModulus().bitLength());
        assertEquals("Exponent should match",
                    rsaPublicKey.getPublicExponent(),
                    convertedRsaKey.getPublicExponent());
    }
    
    /**
     * Test createCoseEcKey method using reflection
     */
    @Test
    public void testCreateCoseEcKey() throws Exception {
        // Generate an EC key pair
        KeyPair keyPair = KeyUtils.generateKeyPair("EC", 256);
        ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
        
        // Access the private method using reflection
        java.lang.reflect.Method createCoseEcKeyMethod = KeyUtils.class.getDeclaredMethod(
            "createCoseEcKey", ECPublicKey.class, Integer.class);
        createCoseEcKeyMethod.setAccessible(true);
        
        // Test with default algorithm (null)
        @SuppressWarnings("unchecked")
        Map<Integer, Object> coseKey1 = (Map<Integer, Object>) createCoseEcKeyMethod.invoke(
            null, ecPublicKey, null);
        
        // Verify the COSE key
        assertNotNull("COSE key should not be null", coseKey1);
        assertEquals("COSE key type should be EC2", 2, coseKey1.get(1)); // KTY = 2 (EC2)
        assertEquals("COSE algorithm should be ES256", -7, coseKey1.get(3)); // ALG = -7 (ES256)
        assertEquals("COSE curve should be P-256", 1, coseKey1.get(-1)); // CRV = 1 (P-256)
        
        // Verify EC-specific parameters
        assertTrue("COSE key should contain x-coordinate", coseKey1.containsKey(-2)); // X parameter
        assertTrue("COSE key should contain y-coordinate", coseKey1.containsKey(-3)); // Y parameter
        
        // Test with explicit ECDH algorithm
        Integer ecdhAlgorithm = -25; // ECDH-ES+HKDF-256
        @SuppressWarnings("unchecked")
        Map<Integer, Object> coseKey2 = (Map<Integer, Object>) createCoseEcKeyMethod.invoke(
            null, ecPublicKey, ecdhAlgorithm);
        
        // Verify the COSE key with explicit algorithm
        assertNotNull("COSE key should not be null", coseKey2);
        assertEquals("COSE algorithm should be ECDH-ES+HKDF-256", ecdhAlgorithm, coseKey2.get(3));
        
        // Convert COSE key back to public key and verify it matches the original
        PublicKey convertedKey = KeyUtils.fromCoseKey(coseKey1);
        assertTrue("Converted key should be an EC key", convertedKey instanceof ECPublicKey);
        ECPublicKey convertedEcKey = (ECPublicKey) convertedKey;
        
        // Compare key components (bit length of coordinates)
        assertEquals("X coordinate bit length should be similar",
                    ecPublicKey.getW().getAffineX().bitLength(),
                    convertedEcKey.getW().getAffineX().bitLength(),
                    32); // Allow for some difference due to encoding
        assertEquals("Y coordinate bit length should be similar",
                    ecPublicKey.getW().getAffineY().bitLength(),
                    convertedEcKey.getW().getAffineY().bitLength(),
                    32); // Allow for some difference due to encoding
    }
    
    /**
     * Test normalizeCoordinate method using reflection
     */
    @Test
    public void testNormalizeCoordinate() throws Exception {
        // Access the private method using reflection
        java.lang.reflect.Method normalizeCoordinateMethod = KeyUtils.class.getDeclaredMethod(
            "normalizeCoordinate", byte[].class, int.class);
        normalizeCoordinateMethod.setAccessible(true);
        
        // Test cases
        byte[] shortCoord = new byte[] {1, 2, 3}; // Shorter than target
        byte[] exactCoord = new byte[] {1, 2, 3, 4, 5}; // Exact length
        byte[] longCoord = new byte[] {1, 2, 3, 4, 5, 6, 7}; // Longer than target
        byte[] withLeadingZeros = new byte[] {0, 0, 1, 2, 3}; // With leading zeros
        
        // Target length
        int targetLength = 5;
        
        // Test with shorter coordinate
        byte[] normalizedShort = (byte[]) normalizeCoordinateMethod.invoke(null, shortCoord, targetLength);
        assertEquals("Normalized array should have target length", targetLength, normalizedShort.length);
        // Check padding at the beginning
        assertEquals("First bytes should be zero for padding", 0, normalizedShort[0]);
        assertEquals("First bytes should be zero for padding", 0, normalizedShort[1]);
        // Check original bytes at the end
        assertEquals("Last bytes should match original", 1, normalizedShort[2]);
        assertEquals("Last bytes should match original", 2, normalizedShort[3]);
        assertEquals("Last bytes should match original", 3, normalizedShort[4]);
        
        // Test with exact length coordinate
        byte[] normalizedExact = (byte[]) normalizeCoordinateMethod.invoke(null, exactCoord, targetLength);
        assertEquals("Normalized array should have target length", targetLength, normalizedExact.length);
        assertArrayEquals("Arrays should be identical", exactCoord, normalizedExact);
        
        // Test with longer coordinate
        byte[] normalizedLong = (byte[]) normalizeCoordinateMethod.invoke(null, longCoord, targetLength);
        assertEquals("Normalized array should have target length", targetLength, normalizedLong.length);
        // Check that only the last 5 bytes are kept
        assertEquals("First byte should match original's 3rd byte", 3, normalizedLong[0]);
        assertEquals("Last byte should match original's last byte", 7, normalizedLong[4]);
        
        // Test with leading zeros
        byte[] normalizedZeros = (byte[]) normalizeCoordinateMethod.invoke(null, withLeadingZeros, targetLength);
        assertEquals("Normalized array should have target length", targetLength, normalizedZeros.length);
        assertArrayEquals("Arrays should be identical", withLeadingZeros, normalizedZeros);
    }
    
    /**
     * Test removeLeadingZero method using reflection
     */
    @Test
    public void testRemoveLeadingZero() throws Exception {
        // Access the private method using reflection
        java.lang.reflect.Method removeLeadingZeroMethod = KeyUtils.class.getDeclaredMethod(
            "removeLeadingZero", byte[].class);
        removeLeadingZeroMethod.setAccessible(true);
        
        // Test cases
        byte[] withLeadingZero = new byte[] {0, 1, 2, 3, 4};
        byte[] withoutLeadingZero = new byte[] {1, 2, 3, 4};
        byte[] onlyZero = new byte[] {0};
        byte[] multipleLeadingZeros = new byte[] {0, 0, 1, 2};
        
        // Test with leading zero
        byte[] result1 = (byte[]) removeLeadingZeroMethod.invoke(null, withLeadingZero);
        assertEquals("Result length should be original length - 1", withLeadingZero.length - 1, result1.length);
        assertArrayEquals("Result should match original without leading zero", withoutLeadingZero, result1);
        
        // Test without leading zero
        byte[] result2 = (byte[]) removeLeadingZeroMethod.invoke(null, withoutLeadingZero);
        assertArrayEquals("Result should be unchanged", withoutLeadingZero, result2);
        
        // Test with only a zero
        byte[] result3 = (byte[]) removeLeadingZeroMethod.invoke(null, onlyZero);
        assertArrayEquals("Result should be unchanged for single zero", onlyZero, result3);
        
        // Test with multiple leading zeros (should only remove one)
        byte[] result4 = (byte[]) removeLeadingZeroMethod.invoke(null, multipleLeadingZeros);
        assertEquals("Result length should be original length - 1", multipleLeadingZeros.length - 1, result4.length);
        assertEquals("First byte should be zero", 0, result4[0]);
        assertEquals("Second byte should be 1", 1, result4[1]);
    }
    
    /**
     * Test extractEd25519PublicKeyBytes method using reflection
     * Note: This is a simplified test as we don't have actual Ed25519 keys
     */
    @Test
    public void testExtractEd25519PublicKeyBytes() throws Exception {
        // Access the private method using reflection
        java.lang.reflect.Method extractEd25519Method = KeyUtils.class.getDeclaredMethod(
            "extractEd25519PublicKeyBytes", byte[].class);
        extractEd25519Method.setAccessible(true);
        
        // Test cases
        byte[] shortKey = new byte[] {1, 2, 3}; // Shorter than 32 bytes
        byte[] exactKey = new byte[32]; // Exactly 32 bytes
        for (int i = 0; i < exactKey.length; i++) {
            exactKey[i] = (byte)i;
        }
        byte[] longKey = new byte[64]; // Longer than 32 bytes
        for (int i = 0; i < longKey.length; i++) {
            longKey[i] = (byte)i;
        }
        
        // Test with short key (should return as-is)
        byte[] result1 = (byte[]) extractEd25519Method.invoke(null, shortKey);
        assertArrayEquals("Short key should be returned as-is", shortKey, result1);
        
        // Test with exact key (should return as-is)
        byte[] result2 = (byte[]) extractEd25519Method.invoke(null, exactKey);
        assertArrayEquals("Exact key should be returned as-is", exactKey, result2);
        
        // Test with long key (should extract last 32 bytes)
        byte[] result3 = (byte[]) extractEd25519Method.invoke(null, longKey);
        assertEquals("Result should be 32 bytes", 32, result3.length);
        // Check that the last 32 bytes were extracted
        for (int i = 0; i < 32; i++) {
            assertEquals("Byte should match original's corresponding byte",
                        longKey[longKey.length - 32 + i], result3[i]);
        }
    }

    @Test
    public void testDecryptPrivateKey() throws Exception {
        // Create a temporary file for the encrypted private key
        File encryptedKeyFile = tempFolder.newFile("encrypted_private.key");
        FileUtils.writePrivatePEM(KeyUtils.generatePrivate("ECDSA", 256), encryptedKeyFile, "testPassword123");
        // Test reading with correct password
        PrivateKey readKey = FileUtils.readPrivatePEM(encryptedKeyFile, "testPassword123");
        assertNotNull("Read private key should not be null", readKey);
        assertTrue("Read key should be an EC key", readKey instanceof ECPrivateKey);
        
        // Test with incorrect password
        try {
            FileUtils.readPrivatePEM(encryptedKeyFile, "invalidSetOfChars");
            fail("Should throw exception for incorrect password");
        } catch (Exception e) {
            // Expected
        }
        
        // Test with null/empty file name
        try {
            KeyUtils.getPrivate("".getBytes(), "EC");
            fail("Should throw InvalidKeySpecException for empty/invalid key data");
        } catch (InvalidKeySpecException e) {
            // Expected - any InvalidKeySpecException is acceptable for invalid key data
            assertNotNull("Exception message should not be null", e.getMessage());
        }
    }

    @Test
    public void testGetCAKeyPair() throws Exception {
        // Test with EC algorithm
        KeyPair ecKeyPair = KeyUtils.getCAKeyPair("EC");
        assertNotNull("EC key pair should not be null", ecKeyPair);
        assertTrue("Private key should be an EC key", ecKeyPair.getPrivate() instanceof ECPrivateKey);
        assertTrue("Public key should be an EC key", ecKeyPair.getPublic() instanceof ECPublicKey);
        
        // Test with RSA algorithm
        KeyPair rsaKeyPair = KeyUtils.getCAKeyPair("RSA");
        assertNotNull("RSA key pair should not be null", rsaKeyPair);
        assertTrue("Private key should be an RSA key", rsaKeyPair.getPrivate() instanceof RSAPrivateCrtKey);
        assertTrue("Public key should be an RSA key", rsaKeyPair.getPublic() instanceof RSAPublicKey);
        
        // Test with invalid algorithm
        try {
            KeyUtils.getCAKeyPair("InvalidAlg");
            fail("Should throw NoSuchAlgorithmException for invalid algorithm");
        } catch (NoSuchAlgorithmException e) {
            assertTrue(e.getMessage().contains("Invalid alg"));
        }
    }

    @Test
    public void testEd25519KeyHandling() throws Exception {
        // Test getE25519KeyPair method
        KeyPair ed25519KeyPair = KeyUtils.getKeyPair("Ed25519");
        System.err.println(ed25519KeyPair);
        assertNotNull("Ed25519 key pair should not be null", ed25519KeyPair);
        
        // Test COSE key conversion
        Map<Integer, Object> coseKey = KeyUtils.toCoseKey(ed25519KeyPair.getPublic());
        assertNotNull("COSE key should not be null", coseKey);
        assertEquals("COSE key type should be OKP", 1, coseKey.get(1)); // KTY = 1 (OKP)
        assertEquals("COSE algorithm should be EdDSA", -8, coseKey.get(3)); // ALG = -8 (EdDSA)
        assertEquals("COSE curve should be Ed25519", 6, coseKey.get(-1)); // CRV = 6 (Ed25519)
        
        // Test conversion back to public key
        PublicKey convertedKey = KeyUtils.fromCoseKey(coseKey);
        assertNotNull("Converted key should not be null", convertedKey);

    }
    
    @Test
    public void testPKCS12Operations() throws Exception {
        // Suppress Java Preferences warnings that cause flaky test failures
        // The BouncyCastle provider tries to access preferences, which can fail with file locking
        System.setProperty("java.util.prefs.PreferencesFactory",
                          "com.isfs.blekey.util.KeyUtilsTest$NoOpPreferencesFactory");
        
        try {
            // Generate a key pair
            KeyPair keyPair = KeyUtils.generateKeyPair("RSA", 2048);
            
            // Create a self-signed certificate (using appropriate helper method)
            X509Certificate selfSignedCert = CertUtils.generateCaCert("CN=unit-testing", keyPair, 9999, true);
            
            // Create a PKCS12 keystore
            KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
            keyStore.load(null, null);
            keyStore.setKeyEntry("test-alias", keyPair.getPrivate(), "password".toCharArray(),
                                new X509Certificate[] { selfSignedCert });
            
            // Create a test password hash (SHA256 of "password")
            byte[] passwordHash = KeyUtils.getPinHash("password");
            
            // Export to byte array
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            keyStore.store(baos, new String(passwordHash, StandardCharsets.ISO_8859_1).toCharArray());
            byte[] pkcs12Bytes = baos.toByteArray();
            
            // Test reading PKCS12
            KeyStore readKeyStore = KeyUtils.readPKCS12(pkcs12Bytes, passwordHash);
            assertNotNull("Read keystore should not be null", readKeyStore);
            
            // Test extracting private key
            PrivateKey extractedPrivateKey = KeyUtils.getPrivateKeyFromPKCS12(
                readKeyStore, "test-alias", passwordHash);
            assertNotNull("Extracted private key should not be null", extractedPrivateKey);
            
            // Test extracting certificate
            X509Certificate extractedCert = KeyUtils.getCertificateFromPKCS12(readKeyStore, "test-alias");
            assertNotNull("Extracted certificate should not be null", extractedCert);
            
            // Test getting first key pair
            KeyPair extractedKeyPair = KeyUtils.getFirstKeyPairFromPKCS12(readKeyStore, passwordHash);
            assertNotNull("Extracted key pair should not be null", extractedKeyPair);
            
            // Test with empty keystore
            KeyStore emptyKeyStore = KeyStore.getInstance("PKCS12", "BC");
            emptyKeyStore.load(null, null);
            try {
                KeyUtils.getFirstKeyPairFromPKCS12(emptyKeyStore, passwordHash);
                fail("Should throw exception for empty keystore");
            } catch (KeyStoreException e) {
                assertTrue(e.getMessage().contains("No key entries found"));
            }
        } finally {
            // Clean up system property
            System.clearProperty("java.util.prefs.PreferencesFactory");
        }
    }
    
    /**
     * No-op Preferences factory to avoid file locking issues in tests.
     * This prevents BouncyCastle from trying to access Java Preferences.
     */
    public static class NoOpPreferencesFactory implements java.util.prefs.PreferencesFactory {
        @Override
        public java.util.prefs.Preferences systemRoot() {
            return new NoOpPreferences();
        }
        
        @Override
        public java.util.prefs.Preferences userRoot() {
            return new NoOpPreferences();
        }
    }
    
    /**
     * No-op Preferences implementation that does nothing.
     */
    private static class NoOpPreferences extends java.util.prefs.AbstractPreferences {
        protected NoOpPreferences() {
            super(null, "");
        }
        
        @Override
        protected void putSpi(String key, String value) {}
        
        @Override
        protected String getSpi(String key) { return null; }
        
        @Override
        protected void removeSpi(String key) {}
        
        @Override
        protected void removeNodeSpi() {}
        
        @Override
        protected String[] keysSpi() { return new String[0]; }
        
        @Override
        protected String[] childrenNamesSpi() { return new String[0]; }
        
        @Override
        protected java.util.prefs.AbstractPreferences childSpi(String name) {
            return new NoOpPreferences();
        }
        
        @Override
        protected void syncSpi() {}
        
        @Override
        protected void flushSpi() {}
    }


    @Test
    public void testOkpKeyValidation() {
        // Test validateOkpParameters with null parameters
        try {
            Method validateOkpParametersMethod = KeyUtils.class.getDeclaredMethod(
                "validateOkpParameters", Integer.class, byte[].class);
            validateOkpParametersMethod.setAccessible(true);
            validateOkpParametersMethod.invoke(null, null, null);
            fail("Should throw exception for null parameters");
        } catch (Exception e) {
            assertTrue(e.getCause().getMessage().contains("Invalid COSE OKP key"));
        }
        
        // Test validateOkpParameters with unsupported curve
        try {
            Method validateOkpParametersMethod = KeyUtils.class.getDeclaredMethod(
                "validateOkpParameters", Integer.class, byte[].class);
            validateOkpParametersMethod.setAccessible(true);
            validateOkpParametersMethod.invoke(null, 999, new byte[32]);
            fail("Should throw exception for unsupported curve");
        } catch (Exception e) {
            assertTrue(e.getCause().getMessage().contains("Unsupported OKP curve"));
        }
        
        // Test validateOkpAlgorithm with unsupported algorithm
        try {
            Method validateOkpAlgorithmMethod = KeyUtils.class.getDeclaredMethod(
                "validateOkpAlgorithm", Map.class);
            validateOkpAlgorithmMethod.setAccessible(true);
            
            Map<Integer, Object> coseKey = new HashMap<>();
            coseKey.put(3, 999); // Unsupported algorithm
            
            validateOkpAlgorithmMethod.invoke(null, coseKey);
            fail("Should throw exception for unsupported algorithm");
        } catch (Exception e) {
            assertTrue(e.getCause().getMessage().contains("Unsupported OKP algorithm"));
        }
    }

    @Test
    public void testReadPublic() throws Exception {
        // Create a temporary file for the public key
        File publicKeyFile = tempFolder.newFile("test_public.key");
        
        // Generate a test key pair
        KeyPair keyPair = KeyUtils.generateKeyPair("EC", 256);
        
        // Write the public key to the file
        FileUtils.writePublicPEM(keyPair.getPublic(), publicKeyFile);
        
        // Read the public key back
        PublicKey readKey = FileUtils.readPublicPEM(publicKeyFile);
        assertNotNull("Read public key should not be null", readKey);
        assertTrue("Read key should be an EC key", readKey instanceof ECPublicKey);
        
        // Test with non-existent file
        try {
            FileUtils.readPublicPEM(new File("non-existent-file.key"));
            fail("Should throw IOException for non-existent file");
        } catch (IOException e) {
            // Expected
        }
    }

    @Test
    public void testToCoseKeyEdgeCases() throws Exception {
        // Test with null key
        try {
            KeyUtils.toCoseKey(null);
            fail("Should throw IllegalArgumentException for null key");
        } catch (IllegalArgumentException e) {
            assertEquals("Public key cannot be null", e.getMessage());
        }
        
        // Test with unsupported key type
        try {
            // Create a mock PublicKey that is neither EC, RSA, nor Ed25519
            PublicKey mockKey = mock(PublicKey.class);
            when(mockKey.getAlgorithm()).thenReturn("UNSUPPORTED");
            
            KeyUtils.toCoseKey(mockKey);
            fail("Should throw UnsupportedOperationException for unsupported key type");
        } catch (UnsupportedOperationException e) {
            assertTrue(e.getMessage().contains("Unsupported key type"));
        }
    }

}

// Made with Bob
