/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.util;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Base64;

/**
 * Test suite for HKDF-based passkey seed generation in KeyUtils.
 * Tests the getPasskeySeed() method which now uses HKDF (RFC 5869) instead of
 * the previous non-standard cryptographic construction.
 */
public class KeyUtilsHKDFTest {

    private KeyPair ecKeyPair;
    private byte[] testEntropy;
    private byte[] testEntropy2;

    @Before
    public void setUp() throws Exception {
        // Generate a test EC key pair using EC algorithm with P-256 curve
        ecKeyPair = KeyUtils.generateKeyPair("EC", 256);
        assertNotNull("EC key pair should be generated", ecKeyPair);
        
        // Create test entropy (simulating rpId bytes)
        testEntropy = "example.com".getBytes(StandardCharsets.UTF_8);
        testEntropy2 = "another.com".getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Test 1: Determinism - Same inputs produce same output
     * This is critical for credential recovery
     */
    @Test
    public void testDeterministicOutput() {
        String seed1 = KeyUtils.getPasskeySeed(testEntropy, ecKeyPair.getPrivate());
        String seed2 = KeyUtils.getPasskeySeed(testEntropy, ecKeyPair.getPrivate());
        
        assertNotNull("First seed should not be null", seed1);
        assertNotNull("Second seed should not be null", seed2);
        assertEquals("Same inputs should produce identical seeds", seed1, seed2);
    }

    /**
     * Test 2: Output Format - Verify 32-byte output, Base64 URL-encoded
     */
    @Test
    public void testOutputFormat() {
        String seed = KeyUtils.getPasskeySeed(testEntropy, ecKeyPair.getPrivate());
        
        assertNotNull("Seed should not be null", seed);
        
        // Decode the Base64 URL-encoded seed
        byte[] decodedSeed = Base64.getUrlDecoder().decode(seed);
        
        assertEquals("Decoded seed should be exactly 32 bytes", 32, decodedSeed.length);
        
        // Verify it's Base64 URL-encoded (no padding, no +/ characters)
        assertFalse("Seed should not contain padding", seed.contains("="));
        assertFalse("Seed should not contain + character", seed.contains("+"));
        assertFalse("Seed should not contain / character", seed.contains("/"));
    }

    /**
     * Test 3: Different Entropy - Different rpId produces different output
     */
    @Test
    public void testDifferentEntropy() {
        String seed1 = KeyUtils.getPasskeySeed(testEntropy, ecKeyPair.getPrivate());
        String seed2 = KeyUtils.getPasskeySeed(testEntropy2, ecKeyPair.getPrivate());
        
        assertNotNull("First seed should not be null", seed1);
        assertNotNull("Second seed should not be null", seed2);
        assertNotEquals("Different entropy should produce different seeds", seed1, seed2);
    }

    /**
     * Test 4: Different Keys - Different private keys produce different output
     */
    @Test
    public void testDifferentKeys() throws Exception {
        KeyPair keyPair2 = KeyUtils.generateKeyPair("EC", 256);
        
        String seed1 = KeyUtils.getPasskeySeed(testEntropy, ecKeyPair.getPrivate());
        String seed2 = KeyUtils.getPasskeySeed(testEntropy, keyPair2.getPrivate());
        
        assertNotNull("First seed should not be null", seed1);
        assertNotNull("Second seed should not be null", seed2);
        assertNotEquals("Different keys should produce different seeds", seed1, seed2);
    }

    /**
     * Test 5: Null Handling - Proper error handling for null entropy
     */
    @Test
    public void testNullEntropy() {
        String seed = KeyUtils.getPasskeySeed(null, ecKeyPair.getPrivate());
        
        // HKDF should handle null salt gracefully or return null
        // The implementation returns null on exception
        assertNull("Null entropy should result in null seed", seed);
    }

    /**
     * Test 6: Null Handling - Proper error handling for null key
     */
    @Test
    public void testNullKey() {
        String seed = KeyUtils.getPasskeySeed(testEntropy, null);
        
        assertNull("Null key should result in null seed", seed);
    }

    /**
     * Test 7: Empty Entropy - Handle empty entropy array
     */
    @Test
    public void testEmptyEntropy() {
        byte[] emptyEntropy = new byte[0];
        String seed = KeyUtils.getPasskeySeed(emptyEntropy, ecKeyPair.getPrivate());
        
        // HKDF should still work with empty salt
        assertNotNull("Empty entropy should still produce a seed", seed);
        
        // Verify it's still 32 bytes
        byte[] decodedSeed = Base64.getUrlDecoder().decode(seed);
        assertEquals("Seed should still be 32 bytes", 32, decodedSeed.length);
    }

    /**
     * Test 8: Compatibility with SymmetricKey - Verify output works with SymmetricKey class
     */
    @Test
    public void testSymmetricKeyCompatibility() {
        String seed = KeyUtils.getPasskeySeed(testEntropy, ecKeyPair.getPrivate());
        
        assertNotNull("Seed should not be null", seed);
        
        // Try to create a SymmetricKey with the seed
        // This verifies the seed format is compatible with downstream usage
        try {
            com.isfs.blekey.data.SymmetricKey symKey = new com.isfs.blekey.data.SymmetricKey(seed);
            assertNotNull("SymmetricKey should be created successfully", symKey);
        } catch (Exception e) {
            fail("Seed should be compatible with SymmetricKey: " + e.getMessage());
        }
    }

    /**
     * Test 9: Multiple Iterations - Verify consistency across multiple calls
     */
    @Test
    public void testMultipleIterations() {
        String firstSeed = KeyUtils.getPasskeySeed(testEntropy, ecKeyPair.getPrivate());
        
        // Call multiple times and verify all produce the same result
        for (int i = 0; i < 10; i++) {
            String seed = KeyUtils.getPasskeySeed(testEntropy, ecKeyPair.getPrivate());
            assertEquals("Iteration " + i + " should produce same seed", firstSeed, seed);
        }
    }

    /**
     * Test 10: Different Key Algorithms - Test with RSA key
     */
    @Test
    public void testRSAKey() throws Exception {
        KeyPair rsaKeyPair = KeyUtils.generateKeyPair("RSA", 2048);
        
        String seed = KeyUtils.getPasskeySeed(testEntropy, rsaKeyPair.getPrivate());
        
        assertNotNull("RSA key should produce a valid seed", seed);
        
        byte[] decodedSeed = Base64.getUrlDecoder().decode(seed);
        assertEquals("RSA-derived seed should be 32 bytes", 32, decodedSeed.length);
    }

    /**
     * Test 11: Large Entropy - Test with large entropy values
     */
    @Test
    public void testLargeEntropy() {
        byte[] largeEntropy = new byte[1024];
        for (int i = 0; i < largeEntropy.length; i++) {
            largeEntropy[i] = (byte) (i % 256);
        }
        
        String seed = KeyUtils.getPasskeySeed(largeEntropy, ecKeyPair.getPrivate());
        
        assertNotNull("Large entropy should produce a valid seed", seed);
        
        byte[] decodedSeed = Base64.getUrlDecoder().decode(seed);
        assertEquals("Seed should still be 32 bytes", 32, decodedSeed.length);
    }

    /**
     * Test 12: Entropy with Special Characters - Test with various byte values
     */
    @Test
    public void testEntropyWithSpecialCharacters() {
        byte[] specialEntropy = new byte[]{0x00, 0x01, (byte) 0xFF, (byte) 0xFE, 0x7F, (byte) 0x80};
        
        String seed = KeyUtils.getPasskeySeed(specialEntropy, ecKeyPair.getPrivate());
        
        assertNotNull("Special entropy should produce a valid seed", seed);
        
        byte[] decodedSeed = Base64.getUrlDecoder().decode(seed);
        assertEquals("Seed should be 32 bytes", 32, decodedSeed.length);
    }

    /**
     * Test 13: Seed Uniqueness - Verify seeds are sufficiently unique
     */
    @Test
    public void testSeedUniqueness() throws Exception {
        // Generate multiple key pairs and entropy values
        int numTests = 20;
        String[] seeds = new String[numTests];
        
        for (int i = 0; i < numTests; i++) {
            KeyPair kp = KeyUtils.generateKeyPair("EC", 256);
            byte[] entropy = ("test" + i + ".com").getBytes(StandardCharsets.UTF_8);
            seeds[i] = KeyUtils.getPasskeySeed(entropy, kp.getPrivate());
        }
        
        // Verify all seeds are unique
        for (int i = 0; i < numTests; i++) {
            for (int j = i + 1; j < numTests; j++) {
                assertNotEquals("Seed " + i + " and " + j + " should be different", 
                    seeds[i], seeds[j]);
            }
        }
    }

    /**
     * Test 14: Seed Entropy - Verify output has high entropy (no obvious patterns)
     */
    @Test
    public void testSeedEntropy() {
        String seed = KeyUtils.getPasskeySeed(testEntropy, ecKeyPair.getPrivate());
        byte[] decodedSeed = Base64.getUrlDecoder().decode(seed);
        
        // Check that not all bytes are the same
        boolean allSame = true;
        byte firstByte = decodedSeed[0];
        for (byte b : decodedSeed) {
            if (b != firstByte) {
                allSame = false;
                break;
            }
        }
        assertFalse("Seed should not have all identical bytes", allSame);
        
        // Check that seed is not all zeros
        boolean allZeros = true;
        for (byte b : decodedSeed) {
            if (b != 0) {
                allZeros = false;
                break;
            }
        }
        assertFalse("Seed should not be all zeros", allZeros);
    }

    /**
     * Test 15: Thread Safety - Verify method is thread-safe
     */
    @Test
    public void testThreadSafety() throws Exception {
        final int numThreads = 10;
        final String[] results = new String[numThreads];
        final Thread[] threads = new Thread[numThreads];
        
        // Create threads that all generate seeds with same inputs
        for (int i = 0; i < numThreads; i++) {
            final int index = i;
            threads[i] = new Thread(() -> {
                results[index] = KeyUtils.getPasskeySeed(testEntropy, ecKeyPair.getPrivate());
            });
        }
        
        // Start all threads
        for (Thread thread : threads) {
            thread.start();
        }
        
        // Wait for all threads to complete
        for (Thread thread : threads) {
            thread.join();
        }
        
        // Verify all results are identical
        String firstResult = results[0];
        assertNotNull("First result should not be null", firstResult);
        
        for (int i = 1; i < numThreads; i++) {
            assertEquals("Thread " + i + " should produce same result", firstResult, results[i]);
        }
    }
}

// Made with Bob
