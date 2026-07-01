/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.util;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;
import java.lang.reflect.Method;

/**
 * Test suite for COSE key format operations in KeyUtils.
 * Tests fromCoseKey, toCoseKey, and COSE key validation methods.
 */
public class KeyUtilsCoseTest {

    private KeyPair ecKeyPair;
    private KeyPair rsaKeyPair;
    private KeyPair ed25519KeyPair;

    @Before
    public void setUp() throws Exception {
        ecKeyPair = KeyUtils.generateKeyPair("EC", 256);
        rsaKeyPair = KeyUtils.generateKeyPair("RSA", 2048);
        ed25519KeyPair = KeyUtils.generateKeyPair("Ed25519", 256);
    }

    // Generates no key
    @Test
    public void testGenerateBad() {
        assertNull(KeyUtils.getKeyPair("BAD"));
    }


    // ========== fromCoseKey Tests ==========

    @Test
    public void testFromCoseKeyEC() throws Exception {
        Map<Integer, Object> coseKey = KeyUtils.toCoseKey(ecKeyPair.getPublic());
        
        PublicKey reconstructed = KeyUtils.fromCoseKey(coseKey);
        
        assertNotNull("Reconstructed key should not be null", reconstructed);
        assertTrue("Reconstructed key should be EC public key",
                   reconstructed instanceof ECPublicKey);
    }

    @Test
    public void testFromCoseKeyRSA() throws Exception {
        Map<Integer, Object> coseKey = KeyUtils.toCoseKey(rsaKeyPair.getPublic());
        
        PublicKey reconstructed = KeyUtils.fromCoseKey(coseKey);
        
        assertNotNull("Reconstructed key should not be null", reconstructed);
        assertTrue("Reconstructed key should be RSA public key",
                   reconstructed instanceof RSAPublicKey);
    }

    @Test
    public void testFromCoseKeyEd25519() throws Exception {
        Map<Integer, Object> coseKey = KeyUtils.toCoseKey(ed25519KeyPair.getPublic());
        
        PublicKey reconstructed = KeyUtils.fromCoseKey(coseKey);
        
        assertNotNull("Reconstructed key should not be null", reconstructed);
    }

    @Test(expected = Exception.class)
    public void testFromCoseKeyNullMap() throws Exception {
        KeyUtils.fromCoseKey(null);
    }

    @Test(expected = Exception.class)
    public void testFromCoseKeyEmptyMap() throws Exception {
        KeyUtils.fromCoseKey(new HashMap<>());
    }

    @Test(expected = Exception.class)
    public void testFromCoseKeyMissingKty() throws Exception {
        Map<Integer, Object> invalidKey = new HashMap<>();
        invalidKey.put(3, -7); // alg but no kty
        KeyUtils.fromCoseKey(invalidKey);
    }

    @Test(expected = Exception.class)
    public void testFromCoseKeyUnsupportedKty() throws Exception {
        Map<Integer, Object> invalidKey = new HashMap<>();
        invalidKey.put(1, 99); // Invalid kty
        KeyUtils.fromCoseKey(invalidKey);
    }

    @Test(expected = Exception.class)
    public void testFromCoseKeyMissingECParameters() throws Exception {
        Map<Integer, Object> invalidKey = new HashMap<>();
        invalidKey.put(1, 2); // kty = EC
        // Missing crv, x, y
        KeyUtils.fromCoseKey(invalidKey);
    }

    @Test(expected = Exception.class)
    public void testFromCoseKeyMissingCrv() throws Exception {
        Map<Integer, Object> invalidKey = new HashMap<>();
        invalidKey.put(1, 2); // kty = EC
        invalidKey.put(-2, new byte[32]); // x
        invalidKey.put(-3, new byte[32]); // y
        // Missing crv (-1)
        KeyUtils.fromCoseKey(invalidKey);
    }

    @Test(expected = Exception.class)
    public void testFromCoseKeyMissingX() throws Exception {
        Map<Integer, Object> invalidKey = new HashMap<>();
        invalidKey.put(1, 2); // kty = EC
        invalidKey.put(-1, 1); // crv = P-256
        invalidKey.put(-3, new byte[32]); // y
        // Missing x coordinate
        KeyUtils.fromCoseKey(invalidKey);
    }

    @Test(expected = Exception.class)
    public void testFromCoseKeyMissingY() throws Exception {
        Map<Integer, Object> invalidKey = new HashMap<>();
        invalidKey.put(1, 2); // kty = EC
        invalidKey.put(-1, 1); // crv = P-256
        invalidKey.put(-2, new byte[32]); // x
        // Missing y coordinate
        KeyUtils.fromCoseKey(invalidKey);
    }

    @Test(expected = Exception.class)
    public void testFromCoseKeyInvalidCrv() throws Exception {
        Map<Integer, Object> invalidKey = new HashMap<>();
        invalidKey.put(1, 2); // kty = EC
        invalidKey.put(-1, 999); // Invalid crv
        invalidKey.put(-2, new byte[32]); // x
        invalidKey.put(-3, new byte[32]); // y
        KeyUtils.fromCoseKey(invalidKey);
    }

    // ========== toCoseKey Tests ==========

    @Test
    public void testToCoseKeyEC() throws Exception {
        Map<Integer, Object> coseKey = KeyUtils.toCoseKey(ecKeyPair.getPublic());
        
        assertNotNull("COSE key should not be null", coseKey);
        assertEquals("Key type should be EC2 (2)", 2, coseKey.get(1));
        assertNotNull("Curve should be present", coseKey.get(-1));
        assertNotNull("X coordinate should be present", coseKey.get(-2));
        assertNotNull("Y coordinate should be present", coseKey.get(-3));
    }

    @Test
    public void testToCoseKeyRSA() throws Exception {
        Map<Integer, Object> coseKey = KeyUtils.toCoseKey(rsaKeyPair.getPublic());
        
        assertNotNull("COSE key should not be null", coseKey);
        assertEquals("Key type should be RSA (3)", 3, coseKey.get(1));
        assertNotNull("Modulus should be present", coseKey.get(-1));
        assertNotNull("Exponent should be present", coseKey.get(-2));
    }

    @Test
    public void testToCoseKeyEd25519() throws Exception {
        Map<Integer, Object> coseKey = KeyUtils.toCoseKey(ed25519KeyPair.getPublic());
        
        assertNotNull("COSE key should not be null", coseKey);
        assertEquals("Key type should be OKP (1)", 1, coseKey.get(1));
    }

    // ========== Round Trip Tests ==========

    @Test
    public void testCoseKeyRoundTripEC() throws Exception {
        Map<Integer, Object> coseKey = KeyUtils.toCoseKey(ecKeyPair.getPublic());
        PublicKey reconstructed = KeyUtils.fromCoseKey(coseKey);
        
        assertNotNull("Reconstructed key should not be null", reconstructed);
        
        // Verify the key can be used for encryption
        byte[] testData = "test".getBytes();
        byte[] encrypted = KeyUtils.ecdhEncrypt(testData, reconstructed);
        byte[] decrypted = KeyUtils.ecdhDecrypt(encrypted, ecKeyPair.getPrivate());
        
        assertArrayEquals("Round trip should preserve functionality", testData, decrypted);
    }

    @Test
    public void testCoseKeyRoundTripRSA() throws Exception {
        Map<Integer, Object> coseKey = KeyUtils.toCoseKey(rsaKeyPair.getPublic());
        PublicKey reconstructed = KeyUtils.fromCoseKey(coseKey);
        
        assertNotNull("Reconstructed key should not be null", reconstructed);
        assertTrue("Reconstructed key should be RSA", reconstructed instanceof RSAPublicKey);
    }

    @Test
    public void testCoseKeyRoundTripEd25519() throws Exception {
        Map<Integer, Object> coseKey = KeyUtils.toCoseKey(ed25519KeyPair.getPublic());
        PublicKey reconstructed = KeyUtils.fromCoseKey(coseKey);
        
        assertNotNull("Reconstructed key should not be null", reconstructed);
    }

    // ========== Multiple Keys Tests ==========

    @Test
    public void testToCoseKeyMultipleECKeys() throws Exception {
        KeyPair keyPair1 = KeyUtils.generateKeyPair("EC", 256);
        KeyPair keyPair2 = KeyUtils.generateKeyPair("EC", 256);
        
        Map<Integer, Object> coseKey1 = KeyUtils.toCoseKey(keyPair1.getPublic());
        Map<Integer, Object> coseKey2 = KeyUtils.toCoseKey(keyPair2.getPublic());
        
        assertNotNull("First COSE key should not be null", coseKey1);
        assertNotNull("Second COSE key should not be null", coseKey2);
        
        // X coordinates should be different
        byte[] x1 = (byte[]) coseKey1.get(-2);
        byte[] x2 = (byte[]) coseKey2.get(-2);
        assertFalse("Different keys should have different X coordinates",
                    java.util.Arrays.equals(x1, x2));
    }

    // ========== Edge Cases ==========

    @Test(expected = Exception.class)
    public void testToCoseKeyNullKey() throws Exception {
        KeyUtils.toCoseKey(null);
    }

    @Test
    public void testFromCoseKeyWithAlgorithm() throws Exception {
        Map<Integer, Object> coseKey = new java.util.HashMap<>(KeyUtils.toCoseKey(ecKeyPair.getPublic()));
        coseKey.put(3, -7); // Add algorithm ES256
        
        PublicKey reconstructed = KeyUtils.fromCoseKey(coseKey);
        
        assertNotNull("Reconstructed key should not be null", reconstructed);
    }

    @Test
    public void testCoseKeyPreservesKeyType() throws Exception {
        Map<Integer, Object> ecCoseKey = KeyUtils.toCoseKey(ecKeyPair.getPublic());
        Map<Integer, Object> rsaCoseKey = KeyUtils.toCoseKey(rsaKeyPair.getPublic());
        
        assertEquals("EC key should have kty=2", 2, ecCoseKey.get(1));
        assertEquals("RSA key should have kty=3", 3, rsaCoseKey.get(1));
    }

    @Test
    public void testCoseKeyCoordinatesNotNull() throws Exception {
        Map<Integer, Object> coseKey = KeyUtils.toCoseKey(ecKeyPair.getPublic());
        
        byte[] x = (byte[]) coseKey.get(-2);
        byte[] y = (byte[]) coseKey.get(-3);
        
        assertNotNull("X coordinate should not be null", x);
        assertNotNull("Y coordinate should not be null", y);
        assertTrue("X coordinate should have content", x.length > 0);
        assertTrue("Y coordinate should have content", y.length > 0);
    }

    @Test
    public void testCoseKeyCoordinatesCorrectLength() throws Exception {
        Map<Integer, Object> coseKey = KeyUtils.toCoseKey(ecKeyPair.getPublic());
        
        byte[] x = (byte[]) coseKey.get(-2);
        byte[] y = (byte[]) coseKey.get(-3);
        
        // For P-256, coordinates should be 32 bytes
        assertEquals("X coordinate should be 32 bytes for P-256", 32, x.length);
        assertEquals("Y coordinate should be 32 bytes for P-256", 32, y.length);
    }

    @Test
    public void testFromCoseKeyDifferentCurves() throws Exception {
        // Test with P-256
        KeyPair p256KeyPair = KeyUtils.generateKeyPair("EC", 256);
        Map<Integer, Object> p256CoseKey = KeyUtils.toCoseKey(p256KeyPair.getPublic());
        PublicKey p256Reconstructed = KeyUtils.fromCoseKey(p256CoseKey);
        
        assertNotNull("P-256 key should be reconstructed", p256Reconstructed);
    }

    @Test
    public void testCoseKeyMapStructure() throws Exception {
        Map<Integer, Object> coseKey = KeyUtils.toCoseKey(ecKeyPair.getPublic());
        
        assertTrue("COSE key should contain kty", coseKey.containsKey(1));
        assertTrue("COSE key should contain crv", coseKey.containsKey(-1));
        assertTrue("COSE key should contain x", coseKey.containsKey(-2));
        assertTrue("COSE key should contain y", coseKey.containsKey(-3));
    }

    // ========== L355: getAlgorithmName — gated by isDebugEnabled(), covered indirectly ==========
    // L355 lives inside logCoseKeyIfDebugEnabled() which only runs when debug logging is enabled.
    // These tests exercise toCoseKey with both algorithm values to confirm correct algorithm storage.

    @Test
    public void testToCoseKeyWithECDHAlgorithm() throws Exception {
        // COSE_ALG_ECDH_ES_HKDF_256 = -25 stored when algorithm=-25 is passed
        Map<Integer, Object> coseKey = KeyUtils.toCoseKey(ecKeyPair.getPublic(), -25);
        assertNotNull("COSE key with ECDH algorithm should not be null", coseKey);
        assertEquals("Key type should be EC2 (2)", 2, coseKey.get(1));
        assertEquals("Algorithm should be ECDH-ES+HKDF-256 (-25)", -25, coseKey.get(3));
    }

    @Test
    public void testToCoseKeyWithES256AlgorithmNull() throws Exception {
        // null algorithm → default ES256 (-7)
        Map<Integer, Object> coseKey = KeyUtils.toCoseKey(ecKeyPair.getPublic(), null);
        assertNotNull("COSE key with null algorithm should not be null", coseKey);
        assertEquals("Algorithm should default to ES256 (-7)", -7, coseKey.get(3));
    }

    // ========== L263-264: toCoseKey EdDSA branch — exercise via Ed25519 key ==========

    @Test
    public void testToCoseKeyEdDSAViaEd25519KeyPair() throws Exception {
        // Ed25519 key → "EdDSA".equals(pubkey.getAlgorithm()) should be true (L263)
        Map<Integer, Object> coseKey = KeyUtils.toCoseKey(ed25519KeyPair.getPublic());
        assertNotNull("COSE key for EdDSA should not be null", coseKey);
        assertEquals("Key type should be OKP (1)", 1, coseKey.get(1));
        assertNotNull("OKP x coordinate should be present", coseKey.get(-2));
    }

    // ========== L525: EC algorithm validation — exercises all three sub-conditions of compound AND ==========

    @Test(expected = RuntimeException.class)
    public void testFromCoseKeyECWithUnsupportedAlgorithm() throws Exception {
        // alg=999: alg!=null(T) && alg!=-7(T) && alg!=-25(T) → throws — all three conditions evaluated
        Map<Integer, Object> coseKey = new HashMap<>(KeyUtils.toCoseKey(ecKeyPair.getPublic()));
        coseKey.put(3, 999);
        KeyUtils.fromCoseKey(coseKey);
    }

    @Test
    public void testFromCoseKeyECWithECDHAlgorithm() throws Exception {
        // alg=-25: alg!=null(T) && alg!=-7(T) && alg!=-25(F) → no throw — exercises third sub-condition false
        Map<Integer, Object> coseKey = new HashMap<>(KeyUtils.toCoseKey(ecKeyPair.getPublic()));
        coseKey.put(3, -25); // ECDH-ES+HKDF-256 is a valid EC algorithm
        PublicKey key = KeyUtils.fromCoseKey(coseKey);
        assertNotNull("EC key with ECDH algorithm should be reconstructed", key);
    }

    // ========== L614-615: null RSA n or e throws ==========

    @Test(expected = RuntimeException.class)
    public void testFromCoseKeyRSANullModulus() throws Exception {
        Map<Integer, Object> coseKey = new HashMap<>(KeyUtils.toCoseKey(rsaKeyPair.getPublic()));
        coseKey.put(-1, null); // n = null — exercises L614-615
        KeyUtils.fromCoseKey(coseKey);
    }

    @Test(expected = RuntimeException.class)
    public void testFromCoseKeyRSANullExponent() throws Exception {
        Map<Integer, Object> coseKey = new HashMap<>(KeyUtils.toCoseKey(rsaKeyPair.getPublic()));
        coseKey.put(-2, null); // e = null — exercises L614-615
        KeyUtils.fromCoseKey(coseKey);
    }

    // ========== L620-621: RSA algorithm validation — exercises both sides of compound condition ==========

    @Test(expected = RuntimeException.class)
    public void testFromCoseKeyRSAUnsupportedAlgorithm() throws Exception {
        // alg=999: alg!=null(T) && alg!=-257(T) → throws
        Map<Integer, Object> coseKey = new HashMap<>(KeyUtils.toCoseKey(rsaKeyPair.getPublic()));
        coseKey.put(3, 999);
        KeyUtils.fromCoseKey(coseKey);
    }

    @Test
    public void testFromCoseKeyRSANoAlgorithm() throws Exception {
        // alg=null → alg!=null(F) → short-circuit, no throw — exercises L620 null/false branch
        Map<Integer, Object> coseKey = new HashMap<>(KeyUtils.toCoseKey(rsaKeyPair.getPublic()));
        coseKey.remove(3); // remove alg entirely → alg will be null
        PublicKey key = KeyUtils.fromCoseKey(coseKey);
        assertNotNull("RSA key without algorithm field should be reconstructed", key);
        assertTrue("Reconstructed key should be RSA", key instanceof RSAPublicKey);
    }

    // ========== L663: null OKP crv or x throws ==========

    @Test(expected = RuntimeException.class)
    public void testFromCoseKeyOKPNullCurve() throws Exception {
        Map<Integer, Object> coseKey = new HashMap<>(KeyUtils.toCoseKey(ed25519KeyPair.getPublic()));
        coseKey.put(-1, null); // crv = null — exercises L663-664
        KeyUtils.fromCoseKey(coseKey);
    }

    @Test(expected = RuntimeException.class)
    public void testFromCoseKeyOKPNullX() throws Exception {
        Map<Integer, Object> coseKey = new HashMap<>(KeyUtils.toCoseKey(ed25519KeyPair.getPublic()));
        coseKey.put(-2, null); // x = null — exercises L663-664
        KeyUtils.fromCoseKey(coseKey);
    }

    // ========== L681: OKP algorithm validation — both sides of condition ==========

    @Test(expected = RuntimeException.class)
    public void testFromCoseKeyOKPUnsupportedAlgorithm() throws Exception {
        // alg=999: alg!=null(T) && alg!=-8(T) → throws
        Map<Integer, Object> coseKey = new HashMap<>(KeyUtils.toCoseKey(ed25519KeyPair.getPublic()));
        coseKey.put(3, 999);
        KeyUtils.fromCoseKey(coseKey);
    }

    @Test
    public void testFromCoseKeyOKPNoAlgorithm() throws Exception {
        // alg=null → alg!=null(F) → short-circuit, no throw — exercises L681 null/false branch
        Map<Integer, Object> coseKey = new HashMap<>(KeyUtils.toCoseKey(ed25519KeyPair.getPublic()));
        coseKey.remove(3); // remove alg entirely → alg will be null
        PublicKey key = KeyUtils.fromCoseKey(coseKey);
        assertNotNull("OKP key without algorithm field should be reconstructed", key);
    }
}

// Made with Bob
