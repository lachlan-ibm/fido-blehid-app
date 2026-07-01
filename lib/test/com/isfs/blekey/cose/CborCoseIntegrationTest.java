/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.cose;

import COSE.Sign1Message;
import com.isfs.blekey.util.Cbor;
import org.junit.Before;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Integration tests for CBOR and COSE infrastructure (Phase 1E).
 * Tests end-to-end workflows combining CBOR encoding/decoding with COSE signing/verification.
 */
public class CborCoseIntegrationTest {
    
    private KeyPair keyPair;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    
    @Before
    public void setUp() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        keyPair = keyGen.generateKeyPair();
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();
    }
    
    @Test
    public void testCborEncodingToCoseSigningRoundTrip() throws Exception {
        // Create a CBOR structure
        Map<String, Object> data = new HashMap<>();
        data.put("name", "John Doe");
        data.put("age", 30);
        data.put("verified", true);
        
        // Encode to CBOR
        byte[] cborData = Cbor.encode(data);
        
        // Sign with COSE
        Sign1Message signed = CoseUtils.createSign1(cborData, privateKey, CoseUtils.ALGORITHM_ES256);
        
        // Encode COSE message
        byte[] coseCbor = CoseUtils.encodeSign1(signed);
        
        // Decode COSE message
        Sign1Message decoded = CoseUtils.decodeSign1(coseCbor);
        
        // Verify signature
        assertTrue(CoseUtils.verifySign1(decoded, publicKey));
        
        // Extract and decode CBOR payload
        byte[] extractedCbor = CoseUtils.getPayload(decoded);
        Object decodedData = Cbor.decode(extractedCbor);
        
        assertTrue(decodedData instanceof Map);
        @SuppressWarnings("unchecked")
        Map<String, Object> finalData = (Map<String, Object>) decodedData;
        assertEquals("John Doe", finalData.get("name"));
        assertEquals(30, finalData.get("age"));
        assertEquals(true, finalData.get("verified"));
    }
    
    @Test
    public void testNestedCborWithCoseSign1() throws Exception {
        // Create nested CBOR structure
        Map<String, Object> inner = new HashMap<>();
        inner.put("credential_id", "12345");
        inner.put("issued_at", 1234567890);
        
        Map<String, Object> outer = new HashMap<>();
        outer.put("type", "mDL");
        outer.put("data", inner);
        
        byte[] payload = Cbor.encode(outer);
        
        // Sign with COSE
        Sign1Message signed = CoseUtils.createSign1(payload, privateKey, CoseUtils.ALGORITHM_ES256);
        byte[] encoded = CoseUtils.encodeSign1(signed);
        
        // Verify round trip
        Sign1Message decoded = CoseUtils.decodeSign1(encoded);
        assertTrue(CoseUtils.verifySign1(decoded, publicKey));
        
        Object result = Cbor.decode(CoseUtils.getPayload(decoded));
        assertTrue(result instanceof Map);
    }
    
    @Test
    public void testCoseSign1WithTag18() throws Exception {
        // Create COSE_Sign1 and verify it has tag 18
        byte[] payload = "test".getBytes();
        Sign1Message msg = CoseUtils.createSign1(payload, privateKey, CoseUtils.ALGORITHM_ES256);
        byte[] encoded = CoseUtils.encodeSign1(msg);
        
        // Decode as generic CBOR to check tag
        Object decoded = Cbor.decode(encoded);
        assertTrue("Should be tagged", decoded instanceof Cbor.Tagged);
        
        Cbor.Tagged tagged = (Cbor.Tagged) decoded;
        assertEquals("Should have tag 18", Cbor.TAG_COSE_SIGN1, tagged.getTag());
        
        // Verify the value is an array with 4 elements
        assertTrue(tagged.getValue() instanceof List);
        List<?> array = (List<?>) tagged.getValue();
        assertEquals(4, array.size());
    }
    
    @Test
    public void testTag24EncodedCborWithCoseSign1() throws Exception {
        // Create data with tag 24 (encoded CBOR)
        Map<String, Object> innerData = new HashMap<>();
        innerData.put("field1", "value1");
        innerData.put("field2", 42);
        
        byte[] tag24Encoded = Cbor.encodeWithTag24(innerData);
        
        // Sign the tag 24 encoded data
        Sign1Message signed = CoseUtils.createSign1(tag24Encoded, privateKey, CoseUtils.ALGORITHM_ES256);
        byte[] coseEncoded = CoseUtils.encodeSign1(signed);
        
        // Decode and verify
        Sign1Message decoded = CoseUtils.decodeSign1(coseEncoded);
        assertTrue(CoseUtils.verifySign1(decoded, publicKey));
        
        // Extract and decode tag 24 data
        byte[] extractedTag24 = CoseUtils.getPayload(decoded);
        Object finalData = Cbor.decodeWithTag24(extractedTag24);
        
        assertTrue(finalData instanceof Map);
        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) finalData;
        assertEquals("value1", result.get("field1"));
        assertEquals(42, result.get("field2"));
    }
    
    @Test
    public void testMultipleCoseSign1Messages() throws Exception {
        // Test signing multiple different payloads
        String[] payloads = {
            "payload1",
            "payload2",
            "payload3"
        };
        
        Sign1Message[] messages = new Sign1Message[payloads.length];
        
        // Sign all payloads
        for (int i = 0; i < payloads.length; i++) {
            messages[i] = CoseUtils.createSign1(
                payloads[i].getBytes(), 
                privateKey, 
                CoseUtils.ALGORITHM_ES256
            );
        }
        
        // Verify all signatures
        for (int i = 0; i < messages.length; i++) {
            assertTrue("Message " + i + " should verify", 
                CoseUtils.verifySign1(messages[i], publicKey));
            assertArrayEquals(payloads[i].getBytes(), CoseUtils.getPayload(messages[i]));
        }
    }
    
    @Test
    public void testCoseSign1WithComplexCborPayload() throws Exception {
        // Create a complex CBOR structure similar to mDL
        Map<String, Object> deviceKey = new HashMap<>();
        deviceKey.put("kty", 2); // EC2
        deviceKey.put("crv", 1); // P-256
        deviceKey.put("x", new byte[32]);
        deviceKey.put("y", new byte[32]);
        
        Map<String, Object> nameSpace = new HashMap<>();
        nameSpace.put("family_name", "Doe");
        nameSpace.put("given_name", "John");
        nameSpace.put("birth_date", "1990-01-01");
        
        Map<String, Object> document = new HashMap<>();
        document.put("docType", "org.iso.18013.5.1.mDL");
        document.put("deviceKey", deviceKey);
        document.put("nameSpaces", nameSpace);
        
        byte[] payload = Cbor.encode(document);
        
        // Sign with COSE
        Sign1Message signed = CoseUtils.createSign1WithHeaders(
            payload, 
            privateKey, 
            CoseUtils.ALGORITHM_ES256,
            new byte[]{1, 2, 3, 4}
        );
        
        byte[] encoded = CoseUtils.encodeSign1(signed);
        
        // Decode and verify
        Sign1Message decoded = CoseUtils.decodeSign1(encoded);
        assertTrue(CoseUtils.verifySign1(decoded, publicKey));
        
        // Verify payload integrity
        byte[] extractedPayload = CoseUtils.getPayload(decoded);
        assertArrayEquals(payload, extractedPayload);
        
        // Decode payload
        Object decodedPayload = Cbor.decode(extractedPayload);
        assertTrue(decodedPayload instanceof Map);
    }
    
    @Test
    public void testDiagnosticNotationForCoseSign1() throws Exception {
        byte[] payload = "test payload".getBytes();
        Sign1Message msg = CoseUtils.createSign1(payload, privateKey, CoseUtils.ALGORITHM_ES256);
        
        String notation = CoseUtils.toDiagnosticNotation(msg);
        
        assertNotNull(notation);
        assertTrue(notation.contains("18(")); // Tag 18
        assertTrue(notation.contains("[")); // Array
        assertTrue(notation.contains("h'")); // Byte strings
    }
    
    @Test
    public void testCborDiagnosticNotationForComplexStructure() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("string", "value");
        data.put("number", 42);
        data.put("boolean", true);
        data.put("bytes", new byte[]{1, 2, 3});
        data.put("array", Arrays.asList(1, 2, 3));
        
        String notation = Cbor.toDiagnosticNotation(data);
        
        assertNotNull(notation);
        assertTrue(notation.contains("\"string\""));
        assertTrue(notation.contains("42"));
        assertTrue(notation.contains("true"));
        assertTrue(notation.contains("h'"));
    }
    
    @Test
    public void testPerformanceBenchmark() throws Exception {
        // Simple performance test
        int iterations = 100;
        byte[] payload = "benchmark payload".getBytes();
        
        long startTime = System.currentTimeMillis();
        
        for (int i = 0; i < iterations; i++) {
            Sign1Message msg = CoseUtils.createSign1(payload, privateKey, CoseUtils.ALGORITHM_ES256);
            byte[] encoded = CoseUtils.encodeSign1(msg);
            Sign1Message decoded = CoseUtils.decodeSign1(encoded);
            CoseUtils.verifySign1(decoded, publicKey);
        }
        
        long endTime = System.currentTimeMillis();
        long totalTime = endTime - startTime;
        double avgTime = totalTime / (double) iterations;
        
        System.out.println("Performance benchmark:");
        System.out.println("  Iterations: " + iterations);
        System.out.println("  Total time: " + totalTime + " ms");
        System.out.println("  Average time per iteration: " + avgTime + " ms");
        
        // Sanity check - should complete in reasonable time
        assertTrue("Should complete in less than 10 seconds", totalTime < 10000);
    }
    
    @Test
    public void testMemoryEfficiencyWithLargePayload() throws Exception {
        // Test with 1MB payload
        byte[] largePayload = new byte[1024 * 1024];
        Arrays.fill(largePayload, (byte) 0x42);
        
        Sign1Message msg = CoseUtils.createSign1(largePayload, privateKey, CoseUtils.ALGORITHM_ES256);
        byte[] encoded = CoseUtils.encodeSign1(msg);
        Sign1Message decoded = CoseUtils.decodeSign1(encoded);
        
        assertTrue(CoseUtils.verifySign1(decoded, publicKey));
        assertArrayEquals(largePayload, CoseUtils.getPayload(decoded));
    }
    
    @Test
    public void testErrorHandlingInvalidCoseStructure() throws Exception {
        // Create invalid COSE structure (not an array)
        byte[] invalid = Cbor.encode(new Cbor.Tagged(18, "not an array"));
        
        try {
            CoseUtils.decodeSign1(invalid);
            fail("Should throw CoseException");
        } catch (CoseException e) {
            // Expected
            assertTrue(e.getMessage(), e.getMessage().equals("Failed to decode COSE_Sign1 message"));
        }
    }
    
    @Test
    public void testErrorHandlingInvalidSignature() throws Exception {
        byte[] payload = "test".getBytes();
        Sign1Message msg = CoseUtils.createSign1(payload, privateKey, CoseUtils.ALGORITHM_ES256);
        
        // Generate a different key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair wrongKeyPair = keyGen.generateKeyPair();
        
        // Verification should fail with wrong key
        assertFalse(CoseUtils.verifySign1(msg, wrongKeyPair.getPublic()));
    }
    
    @Test
    public void testCborTagPreservationThroughCose() throws Exception {
        // Create data with custom tag
        Cbor.Tagged taggedData = new Cbor.Tagged(100, "custom tagged data");
        byte[] payload = Cbor.encode(taggedData);
        
        // Sign with COSE
        Sign1Message msg = CoseUtils.createSign1(payload, privateKey, CoseUtils.ALGORITHM_ES256);
        byte[] encoded = CoseUtils.encodeSign1(msg);
        
        // Decode and verify
        Sign1Message decoded = CoseUtils.decodeSign1(encoded);
        assertTrue(CoseUtils.verifySign1(decoded, publicKey));
        
        // Verify tag is preserved
        Object extractedPayload = Cbor.decode(CoseUtils.getPayload(decoded));
        assertTrue(extractedPayload instanceof Cbor.Tagged);
        Cbor.Tagged extractedTagged = (Cbor.Tagged) extractedPayload;
        assertEquals(100, extractedTagged.getTag());
        assertEquals("custom tagged data", extractedTagged.getValue());
    }
    
    @Test
    public void testInteroperabilityWithRawCbor() throws Exception {
        // Create COSE_Sign1 using CoseUtils
        byte[] payload = "interop test".getBytes();
        Sign1Message msg = CoseUtils.createSign1(payload, privateKey, CoseUtils.ALGORITHM_ES256);
        byte[] encoded = CoseUtils.encodeSign1(msg);
        
        // Decode using raw CBOR
        Object decoded = Cbor.decode(encoded);
        assertTrue(decoded instanceof Cbor.Tagged);
        
        Cbor.Tagged tagged = (Cbor.Tagged) decoded;
        assertEquals(Cbor.TAG_COSE_SIGN1, tagged.getTag());
        
        // Verify structure
        assertTrue(tagged.getValue() instanceof List);
        List<?> coseArray = (List<?>) tagged.getValue();
        assertEquals(4, coseArray.size());
        
        // Element 0: protected headers (byte string)
        assertTrue(coseArray.get(0) instanceof byte[]);
        
        // Element 1: unprotected headers (map)
        assertTrue(coseArray.get(1) instanceof Map);
        
        // Element 2: payload (byte string)
        assertTrue(coseArray.get(2) instanceof byte[]);
        assertArrayEquals(payload, (byte[]) coseArray.get(2));
        
        // Element 3: signature (byte string)
        assertTrue(coseArray.get(3) instanceof byte[]);
    }
}

// Made with Bob

