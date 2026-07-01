/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.cose;

import COSE.AlgorithmID;
import COSE.Sign1Message;
import org.junit.Before;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Unit tests for CoseUtils (Phase 1B).
 * Tests basic COSE library integration and wrapper functionality.
 */
public class CoseUtilsTest {
    
    private KeyPair keyPair;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    
    @Before
    public void setUp() throws Exception {
        // Generate an EC key pair for ES256
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        keyPair = keyGen.generateKeyPair();
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();
    }
    
    @Test
    public void testCreateSign1() throws Exception {
        byte[] payload = "test payload".getBytes();
        
        Sign1Message msg = CoseUtils.createSign1(payload, privateKey, CoseUtils.ALGORITHM_ES256);
        
        assertNotNull(msg);
        assertArrayEquals(payload, CoseUtils.getPayload(msg));
    }
    
    @Test
    public void testCreateSign1WithHeaders() throws Exception {
        byte[] payload = "test payload".getBytes();
        byte[] keyId = new byte[]{1, 2, 3, 4};
        
        Sign1Message msg = CoseUtils.createSign1WithHeaders(
            payload, privateKey, CoseUtils.ALGORITHM_ES256, keyId);
        
        assertNotNull(msg);
        assertArrayEquals(payload, CoseUtils.getPayload(msg));
        assertArrayEquals(keyId, CoseUtils.getKeyId(msg));
    }
    
    @Test
    public void testCreateSign1WithNullKeyId() throws Exception {
        byte[] payload = "test payload".getBytes();
        
        Sign1Message msg = CoseUtils.createSign1WithHeaders(
            payload, privateKey, CoseUtils.ALGORITHM_ES256, null);
        
        assertNotNull(msg);
        assertArrayEquals(payload, CoseUtils.getPayload(msg));
        assertNull(CoseUtils.getKeyId(msg));
    }
    
    @Test
    public void testVerifySign1WithPublicKey() throws Exception {
        byte[] payload = "test payload".getBytes();
        
        Sign1Message msg = CoseUtils.createSign1(payload, privateKey, CoseUtils.ALGORITHM_ES256);
        boolean valid = CoseUtils.verifySign1(msg, publicKey);
        
        assertTrue("Signature should be valid", valid);
    }
    
    @Test
    public void testVerifySign1WithWrongKey() throws Exception {
        byte[] payload = "test payload".getBytes();
        
        // Create message with one key
        Sign1Message msg = CoseUtils.createSign1(payload, privateKey, CoseUtils.ALGORITHM_ES256);
        
        // Try to verify with a different key
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair wrongKeyPair = keyGen.generateKeyPair();
        
        boolean valid = CoseUtils.verifySign1(msg, wrongKeyPair.getPublic());
        
        assertFalse("Signature should be invalid with wrong key", valid);
    }
    
    @Test
    public void testEncodeDecodeSign1() throws Exception {
        byte[] payload = "test payload".getBytes();
        
        Sign1Message original = CoseUtils.createSign1(payload, privateKey, CoseUtils.ALGORITHM_ES256);
        byte[] encoded = CoseUtils.encodeSign1(original);
        Sign1Message decoded = CoseUtils.decodeSign1(encoded);
        
        assertNotNull(decoded);
        assertArrayEquals(payload, CoseUtils.getPayload(decoded));
        
        // Verify the decoded message
        assertTrue("Decoded message should verify", CoseUtils.verifySign1(decoded, publicKey));
    }
    
    @Test
    public void testGetAlgorithm() throws Exception {
        byte[] payload = "test payload".getBytes();
        
        Sign1Message msg = CoseUtils.createSign1(payload, privateKey, CoseUtils.ALGORITHM_ES256);
        AlgorithmID algorithm = CoseUtils.getAlgorithm(msg);
        
        assertEquals(CoseUtils.ALGORITHM_ES256, algorithm);
    }
    
    @Test
    public void testGetPayload() throws Exception {
        byte[] payload = "test payload with special chars: 你好世界".getBytes();
        
        Sign1Message msg = CoseUtils.createSign1(payload, privateKey, CoseUtils.ALGORITHM_ES256);
        byte[] retrieved = CoseUtils.getPayload(msg);
        
        assertArrayEquals(payload, retrieved);
    }
    
    @Test
    public void testGetKeyId() throws Exception {
        byte[] payload = "test payload".getBytes();
        byte[] keyId = new byte[]{(byte)0xFF, 0x00, 0x11, 0x22};
        
        Sign1Message msg = CoseUtils.createSign1WithHeaders(
            payload, privateKey, CoseUtils.ALGORITHM_ES256, keyId);
        byte[] retrieved = CoseUtils.getKeyId(msg);
        
        assertArrayEquals(keyId, retrieved);
    }
    
    @Test
    public void testGetKeyIdWhenNotPresent() throws Exception {
        byte[] payload = "test payload".getBytes();
        
        Sign1Message msg = CoseUtils.createSign1(payload, privateKey, CoseUtils.ALGORITHM_ES256);
        byte[] keyId = CoseUtils.getKeyId(msg);
        
        assertNull(keyId);
    }
    
    @Test
    public void testRoundTripWithLargePayload() throws Exception {
        // Test with a large payload
        byte[] payload = new byte[10000];
        for (int i = 0; i < payload.length; i++) {
            payload[i] = (byte)(i % 256);
        }
        
        Sign1Message msg = CoseUtils.createSign1(payload, privateKey, CoseUtils.ALGORITHM_ES256);
        byte[] encoded = CoseUtils.encodeSign1(msg);
        Sign1Message decoded = CoseUtils.decodeSign1(encoded);
        
        assertArrayEquals(payload, CoseUtils.getPayload(decoded));
        assertTrue(CoseUtils.verifySign1(decoded, publicKey));
    }
    
    @Test
    public void testRoundTripWithEmptyPayload() throws Exception {
        byte[] payload = new byte[0];
        
        Sign1Message msg = CoseUtils.createSign1(payload, privateKey, CoseUtils.ALGORITHM_ES256);
        byte[] encoded = CoseUtils.encodeSign1(msg);
        Sign1Message decoded = CoseUtils.decodeSign1(encoded);
        
        assertArrayEquals(payload, CoseUtils.getPayload(decoded));
        assertTrue(CoseUtils.verifySign1(decoded, publicKey));
    }
    
    @Test
    public void testToDiagnosticNotation() throws Exception {
        byte[] payload = "test payload".getBytes();
        
        Sign1Message msg = CoseUtils.createSign1(payload, privateKey, CoseUtils.ALGORITHM_ES256);
        String notation = CoseUtils.toDiagnosticNotation(msg);
        
        assertNotNull(notation);
        assertFalse(notation.isEmpty());
        // Should contain tag 18 for COSE_Sign1
        assertTrue(notation.contains("18("));
    }
    
    @Test(expected = CoseException.class)
    public void testDecodeInvalidData() throws Exception {
        byte[] invalid = new byte[]{1, 2, 3, 4, 5};
        CoseUtils.decodeSign1(invalid);
    }
    
    @Test
    public void testMultipleSignAndVerify() throws Exception {
        // Test signing and verifying multiple messages with the same key
        for (int i = 0; i < 10; i++) {
            byte[] payload = ("test payload " + i).getBytes();
            
            Sign1Message msg = CoseUtils.createSign1(payload, privateKey, CoseUtils.ALGORITHM_ES256);
            boolean valid = CoseUtils.verifySign1(msg, publicKey);
            
            assertTrue("Message " + i + " should verify", valid);
        }
    }
    
    // ========== COSE_Key Tests (Phase 3) ==========
    
    @Test
    public void testKeyPairToCoseKeyWithPrivate() throws Exception {
        Map<Integer, Object> coseKey = CoseUtils.keyPairToCoseKey(keyPair, true);
        
        assertNotNull(coseKey);
        assertEquals(CoseUtils.COSE_KEY_TYPE_EC2, ((Number)coseKey.get(CoseUtils.COSE_KEY_PARAM_KTY)).intValue());
        assertEquals(CoseUtils.COSE_CURVE_P256, ((Number)coseKey.get(CoseUtils.COSE_KEY_PARAM_CRV)).intValue());
        
        // Check coordinates are present
        assertNotNull(coseKey.get(CoseUtils.COSE_KEY_PARAM_X));
        assertNotNull(coseKey.get(CoseUtils.COSE_KEY_PARAM_Y));
        assertNotNull(coseKey.get(CoseUtils.COSE_KEY_PARAM_D));
        
        // Check coordinate sizes (should be 32 bytes for P-256)
        assertEquals(32, ((byte[])coseKey.get(CoseUtils.COSE_KEY_PARAM_X)).length);
        assertEquals(32, ((byte[])coseKey.get(CoseUtils.COSE_KEY_PARAM_Y)).length);
        assertEquals(32, ((byte[])coseKey.get(CoseUtils.COSE_KEY_PARAM_D)).length);
    }
    
    @Test
    public void testKeyPairToCoseKeyWithoutPrivate() throws Exception {
        Map<Integer, Object> coseKey = CoseUtils.keyPairToCoseKey(keyPair, false);
        
        assertNotNull(coseKey);
        assertEquals(CoseUtils.COSE_KEY_TYPE_EC2, ((Number)coseKey.get(CoseUtils.COSE_KEY_PARAM_KTY)).intValue());
        assertEquals(CoseUtils.COSE_CURVE_P256, ((Number)coseKey.get(CoseUtils.COSE_KEY_PARAM_CRV)).intValue());
        
        // Check coordinates are present
        assertNotNull(coseKey.get(CoseUtils.COSE_KEY_PARAM_X));
        assertNotNull(coseKey.get(CoseUtils.COSE_KEY_PARAM_Y));
        
        // Private key should not be present
        assertNull(coseKey.get(CoseUtils.COSE_KEY_PARAM_D));
    }
    
    @Test
    public void testPublicKeyToCoseKey() throws Exception {
        Map<Integer, Object> coseKey = CoseUtils.publicKeyToCoseKey(publicKey);
        
        assertNotNull(coseKey);
        assertEquals(CoseUtils.COSE_KEY_TYPE_EC2, ((Number)coseKey.get(CoseUtils.COSE_KEY_PARAM_KTY)).intValue());
        assertEquals(CoseUtils.COSE_CURVE_P256, ((Number)coseKey.get(CoseUtils.COSE_KEY_PARAM_CRV)).intValue());
        
        // Check coordinates are present
        assertNotNull(coseKey.get(CoseUtils.COSE_KEY_PARAM_X));
        assertNotNull(coseKey.get(CoseUtils.COSE_KEY_PARAM_Y));
        
        // Private key should not be present
        assertNull(coseKey.get(CoseUtils.COSE_KEY_PARAM_D));
    }
    
    @Test
    public void testCoseKeyToKeyPairRoundTrip() throws Exception {
        // Convert KeyPair to COSE_Key
        Map<Integer, Object> coseKey = CoseUtils.keyPairToCoseKey(keyPair, true);
        
        // Convert back to KeyPair
        KeyPair recovered = CoseUtils.coseKeyToKeyPair(coseKey);
        
        assertNotNull(recovered);
        assertNotNull(recovered.getPublic());
        assertNotNull(recovered.getPrivate());
        
        // Verify the recovered key can sign and verify
        byte[] payload = "test payload".getBytes();
        Sign1Message msg = CoseUtils.createSign1(payload, recovered.getPrivate(), CoseUtils.ALGORITHM_ES256);
        assertTrue(CoseUtils.verifySign1(msg, recovered.getPublic()));
        
        // Verify with original public key
        assertTrue(CoseUtils.verifySign1(msg, publicKey));
    }
    
    @Test
    public void testCoseKeyToKeyPairPublicOnly() throws Exception {
        // Convert public key to COSE_Key
        Map<Integer, Object> coseKey = CoseUtils.publicKeyToCoseKey(publicKey);
        
        // Convert back to KeyPair
        KeyPair recovered = CoseUtils.coseKeyToKeyPair(coseKey);
        
        assertNotNull(recovered);
        assertNotNull(recovered.getPublic());
        assertNull(recovered.getPrivate());
        
        // Verify the recovered public key can verify signatures
        byte[] payload = "test payload".getBytes();
        Sign1Message msg = CoseUtils.createSign1(payload, privateKey, CoseUtils.ALGORITHM_ES256);
        assertTrue(CoseUtils.verifySign1(msg, recovered.getPublic()));
    }
    
    @Test
    public void testCoseKeyToPublicKey() throws Exception {
        Map<Integer, Object> coseKey = CoseUtils.publicKeyToCoseKey(publicKey);
        PublicKey recovered = CoseUtils.coseKeyToPublicKey(coseKey);
        
        assertNotNull(recovered);
        assertTrue(recovered instanceof ECPublicKey);
        
        // Verify the recovered key works
        byte[] payload = "test payload".getBytes();
        Sign1Message msg = CoseUtils.createSign1(payload, privateKey, CoseUtils.ALGORITHM_ES256);
        assertTrue(CoseUtils.verifySign1(msg, recovered));
    }
    
    @Test
    public void testEncodeDecodeCoseKey() throws Exception {
        Map<Integer, Object> original = CoseUtils.keyPairToCoseKey(keyPair, true);
        
        // Encode to CBOR
        byte[] encoded = CoseUtils.encodeCoseKey(original);
        assertNotNull(encoded);
        assertTrue(encoded.length > 0);
        
        // Decode from CBOR
        Map<Integer, Object> decoded = CoseUtils.decodeCoseKey(encoded);
        assertNotNull(decoded);
        
        // Verify all parameters match
        assertEquals(original.get(CoseUtils.COSE_KEY_PARAM_KTY), decoded.get(CoseUtils.COSE_KEY_PARAM_KTY));
        assertEquals(original.get(CoseUtils.COSE_KEY_PARAM_CRV), decoded.get(CoseUtils.COSE_KEY_PARAM_CRV));
        assertArrayEquals((byte[])original.get(CoseUtils.COSE_KEY_PARAM_X),
                         (byte[])decoded.get(CoseUtils.COSE_KEY_PARAM_X));
        assertArrayEquals((byte[])original.get(CoseUtils.COSE_KEY_PARAM_Y),
                         (byte[])decoded.get(CoseUtils.COSE_KEY_PARAM_Y));
        assertArrayEquals((byte[])original.get(CoseUtils.COSE_KEY_PARAM_D),
                         (byte[])decoded.get(CoseUtils.COSE_KEY_PARAM_D));
    }
    
    @Test
    public void testCoseKeyRoundTripMultipleKeys() throws Exception {
        // Test with multiple different keys
        for (int i = 0; i < 5; i++) {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair testKeyPair = keyGen.generateKeyPair();
            
            // Convert to COSE_Key and back
            Map<Integer, Object> coseKey = CoseUtils.keyPairToCoseKey(testKeyPair, true);
            byte[] encoded = CoseUtils.encodeCoseKey(coseKey);
            Map<Integer, Object> decoded = CoseUtils.decodeCoseKey(encoded);
            KeyPair recovered = CoseUtils.coseKeyToKeyPair(decoded);
            
            // Verify signing and verification works
            byte[] payload = ("test payload " + i).getBytes();
            Sign1Message msg = CoseUtils.createSign1(payload, recovered.getPrivate(), CoseUtils.ALGORITHM_ES256);
            assertTrue("Key " + i + " should verify", CoseUtils.verifySign1(msg, recovered.getPublic()));
        }
    }
    
    @Test(expected = CoseException.class)
    public void testCoseKeyToKeyPairMissingKty() throws Exception {
        Map<Integer, Object> invalidKey = new java.util.HashMap<>();
        invalidKey.put(CoseUtils.COSE_KEY_PARAM_CRV, CoseUtils.COSE_CURVE_P256);
        invalidKey.put(CoseUtils.COSE_KEY_PARAM_X, new byte[32]);
        invalidKey.put(CoseUtils.COSE_KEY_PARAM_Y, new byte[32]);
        
        CoseUtils.coseKeyToKeyPair(invalidKey);
    }
    
    @Test(expected = CoseException.class)
    public void testCoseKeyToKeyPairMissingCrv() throws Exception {
        Map<Integer, Object> invalidKey = new java.util.HashMap<>();
        invalidKey.put(CoseUtils.COSE_KEY_PARAM_KTY, CoseUtils.COSE_KEY_TYPE_EC2);
        invalidKey.put(CoseUtils.COSE_KEY_PARAM_X, new byte[32]);
        invalidKey.put(CoseUtils.COSE_KEY_PARAM_Y, new byte[32]);
        
        CoseUtils.coseKeyToKeyPair(invalidKey);
    }
    
    @Test(expected = CoseException.class)
    public void testCoseKeyToKeyPairMissingCoordinates() throws Exception {
        Map<Integer, Object> invalidKey = new java.util.HashMap<>();
        invalidKey.put(CoseUtils.COSE_KEY_PARAM_KTY, CoseUtils.COSE_KEY_TYPE_EC2);
        invalidKey.put(CoseUtils.COSE_KEY_PARAM_CRV, CoseUtils.COSE_CURVE_P256);
        
        CoseUtils.coseKeyToKeyPair(invalidKey);
    }
    
    @Test(expected = CoseException.class)
    public void testCoseKeyToKeyPairUnsupportedKeyType() throws Exception {
        Map<Integer, Object> invalidKey = new java.util.HashMap<>();
        invalidKey.put(CoseUtils.COSE_KEY_PARAM_KTY, 999); // Invalid key type
        invalidKey.put(CoseUtils.COSE_KEY_PARAM_CRV, CoseUtils.COSE_CURVE_P256);
        invalidKey.put(CoseUtils.COSE_KEY_PARAM_X, new byte[32]);
        invalidKey.put(CoseUtils.COSE_KEY_PARAM_Y, new byte[32]);
        
        CoseUtils.coseKeyToKeyPair(invalidKey);
    }
    
    @Test(expected = CoseException.class)
    public void testCoseKeyToKeyPairUnsupportedCurve() throws Exception {
        Map<Integer, Object> invalidKey = new java.util.HashMap<>();
        invalidKey.put(CoseUtils.COSE_KEY_PARAM_KTY, CoseUtils.COSE_KEY_TYPE_EC2);
        invalidKey.put(CoseUtils.COSE_KEY_PARAM_CRV, 999); // Invalid curve
        invalidKey.put(CoseUtils.COSE_KEY_PARAM_X, new byte[32]);
        invalidKey.put(CoseUtils.COSE_KEY_PARAM_Y, new byte[32]);
        
        CoseUtils.coseKeyToKeyPair(invalidKey);
    }
    
    @Test(expected = CoseException.class)
    public void testDecodeCoseKeyInvalidData() throws Exception {
        byte[] invalid = new byte[]{1, 2, 3, 4, 5};
        CoseUtils.decodeCoseKey(invalid);
    }
    
    @Test
    public void testCoseKeyIntegrationWithSign1() throws Exception {
        // Create a COSE_Key from the key pair
        Map<Integer, Object> coseKey = CoseUtils.keyPairToCoseKey(keyPair, true);
        byte[] encodedKey = CoseUtils.encodeCoseKey(coseKey);
        
        // Decode and recover the key pair
        Map<Integer, Object> decodedKey = CoseUtils.decodeCoseKey(encodedKey);
        KeyPair recoveredKeyPair = CoseUtils.coseKeyToKeyPair(decodedKey);
        
        // Use the recovered key to sign a message
        byte[] payload = "Integration test payload".getBytes();
        Sign1Message msg = CoseUtils.createSign1(payload, recoveredKeyPair.getPrivate(), CoseUtils.ALGORITHM_ES256);
        
        // Verify with both original and recovered public keys
        assertTrue("Should verify with original key", CoseUtils.verifySign1(msg, publicKey));
        assertTrue("Should verify with recovered key", CoseUtils.verifySign1(msg, recoveredKeyPair.getPublic()));
    }
}

// Made with Bob
