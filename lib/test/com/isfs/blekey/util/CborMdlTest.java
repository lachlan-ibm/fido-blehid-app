/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.util;

import org.junit.Test;
import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Unit tests for CBOR enhancements for ISO mDL support (Phase 1A).
 * Tests CBOR tag handling, diagnostic notation, and mDL-specific methods.
 */
public class CborMdlTest {

    @Test
    public void testTaggedValueCreation() {
        Cbor.Tagged tagged = new Cbor.Tagged(18, "test");
        assertEquals(18, tagged.getTag());
        assertEquals("test", tagged.getValue());
    }

    @Test
    public void testTaggedValueToString() {
        Cbor.Tagged tagged = new Cbor.Tagged(24, "data");
        String str = tagged.toString();
        assertTrue(str.contains("24"));
        assertTrue(str.contains("data"));
    }

    @Test
    public void testEncodeDecodeTaggedValue() {
        Cbor.Tagged original = new Cbor.Tagged(18, "test value");
        byte[] encoded = Cbor.encode(original);
        Object decoded = Cbor.decode(encoded);
        
        assertTrue(decoded instanceof Cbor.Tagged);
        Cbor.Tagged decodedTagged = (Cbor.Tagged) decoded;
        assertEquals(18, decodedTagged.getTag());
        assertEquals("test value", decodedTagged.getValue());
    }

    @Test
    public void testEncodeDecodeTag24() {
        Map<String, Object> data = new HashMap<>();
        data.put("name", "John Doe");
        data.put("age", 30);
        
        byte[] encoded = Cbor.encodeWithTag24(data);
        Object decoded = Cbor.decodeWithTag24(encoded);
        
        assertTrue(decoded instanceof Map);
        @SuppressWarnings("unchecked")
        Map<String, Object> decodedMap = (Map<String, Object>) decoded;
        assertEquals("John Doe", decodedMap.get("name"));
        assertEquals(30, decodedMap.get("age"));
    }

    @Test
    public void testEncodeDecodeCoseSign1() {
        // Create a mock COSE_Sign1 structure: [protected, unprotected, payload, signature]
        byte[] protectedHeaders = new byte[]{(byte)0xa1, 0x01, 0x26}; // {1: -7} (ES256)
        Map<Object, Object> unprotectedHeaders = new HashMap<>();
        byte[] payload = "test payload".getBytes();
        byte[] signature = new byte[64]; // Mock signature
        Arrays.fill(signature, (byte)0xAB);
        
        List<Object> coseSign1 = Arrays.asList(
            protectedHeaders,
            unprotectedHeaders,
            payload,
            signature
        );
        
        byte[] encoded = Cbor.encodeCoseSign1(coseSign1);
        List<?> decoded = Cbor.decodeCoseSign1(encoded);
        
        assertEquals(4, decoded.size());
        assertArrayEquals(protectedHeaders, (byte[]) decoded.get(0));
        assertTrue(decoded.get(1) instanceof Map);
        assertArrayEquals(payload, (byte[]) decoded.get(2));
        assertArrayEquals(signature, (byte[]) decoded.get(3));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEncodeCoseSign1InvalidSize() {
        List<Object> invalid = Arrays.asList("only", "three", "elements");
        Cbor.encodeCoseSign1(invalid);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDecodeCoseSign1WrongTag() {
        // Encode with tag 24 instead of 18
        Cbor.Tagged wrongTag = new Cbor.Tagged(24, Arrays.asList(1, 2, 3, 4));
        byte[] encoded = Cbor.encode(wrongTag);
        Cbor.decodeCoseSign1(encoded);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDecodeCoseSign1NotTagged() {
        // Encode without tag
        List<Object> data = Arrays.asList(1, 2, 3, 4);
        byte[] encoded = Cbor.encode(data);
        Cbor.decodeCoseSign1(encoded);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDecodeCoseSign1NotArray() {
        // Encode with correct tag but wrong type
        Cbor.Tagged wrongType = new Cbor.Tagged(18, "not an array");
        byte[] encoded = Cbor.encode(wrongType);
        Cbor.decodeCoseSign1(encoded);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDecodeCoseSign1WrongArraySize() {
        // Encode with correct tag but wrong array size
        Cbor.Tagged wrongSize = new Cbor.Tagged(18, Arrays.asList(1, 2, 3));
        byte[] encoded = Cbor.encode(wrongSize);
        Cbor.decodeCoseSign1(encoded);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDecodeWithTag24WrongTag() {
        Cbor.Tagged wrongTag = new Cbor.Tagged(18, new byte[]{1, 2, 3});
        byte[] encoded = Cbor.encode(wrongTag);
        Cbor.decodeWithTag24(encoded);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDecodeWithTag24NotByteString() {
        Cbor.Tagged wrongType = new Cbor.Tagged(24, "not bytes");
        byte[] encoded = Cbor.encode(wrongType);
        Cbor.decodeWithTag24(encoded);
    }

    @Test
    public void testDiagnosticNotationNull() {
        String notation = Cbor.toDiagnosticNotation(null);
        assertEquals("null", notation);
    }

    @Test
    public void testDiagnosticNotationBoolean() {
        assertEquals("true", Cbor.toDiagnosticNotation(true));
        assertEquals("false", Cbor.toDiagnosticNotation(false));
    }

    @Test
    public void testDiagnosticNotationNumber() {
        assertEquals("42", Cbor.toDiagnosticNotation(42));
        assertEquals("3.14", Cbor.toDiagnosticNotation(3.14));
    }

    @Test
    public void testDiagnosticNotationString() {
        String notation = Cbor.toDiagnosticNotation("hello");
        assertEquals("\"hello\"", notation);
    }

    @Test
    public void testDiagnosticNotationStringEscaping() {
        String notation = Cbor.toDiagnosticNotation("hello\nworld\t\"test\"");
        assertTrue(notation.contains("\\n"));
        assertTrue(notation.contains("\\t"));
        assertTrue(notation.contains("\\\""));
    }

    @Test
    public void testDiagnosticNotationByteString() {
        byte[] bytes = new byte[]{0x01, 0x02, 0x03, (byte)0xFF};
        String notation = Cbor.toDiagnosticNotation(bytes);
        assertTrue(notation.startsWith("h'"));
        assertTrue(notation.endsWith("'"));
        assertTrue(notation.contains("010203ff"));
    }

    @Test
    public void testDiagnosticNotationEmptyList() {
        String notation = Cbor.toDiagnosticNotation(Arrays.asList());
        assertEquals("[]", notation);
    }

    @Test
    public void testDiagnosticNotationList() {
        List<Object> list = Arrays.asList(1, "test", true);
        String notation = Cbor.toDiagnosticNotation(list);
        assertTrue(notation.contains("["));
        assertTrue(notation.contains("]"));
        assertTrue(notation.contains("1"));
        assertTrue(notation.contains("\"test\""));
        assertTrue(notation.contains("true"));
    }

    @Test
    public void testDiagnosticNotationEmptyMap() {
        String notation = Cbor.toDiagnosticNotation(new HashMap<>());
        assertEquals("{}", notation);
    }

    @Test
    public void testDiagnosticNotationMap() {
        Map<String, Object> map = new HashMap<>();
        map.put("name", "Alice");
        map.put("age", 25);
        String notation = Cbor.toDiagnosticNotation(map);
        assertTrue(notation.contains("{"));
        assertTrue(notation.contains("}"));
        assertTrue(notation.contains("\"name\""));
        assertTrue(notation.contains("\"Alice\""));
        assertTrue(notation.contains("\"age\""));
        assertTrue(notation.contains("25"));
    }

    @Test
    public void testDiagnosticNotationTagged() {
        Cbor.Tagged tagged = new Cbor.Tagged(18, "payload");
        String notation = Cbor.toDiagnosticNotation(tagged);
        assertTrue(notation.startsWith("18("));
        assertTrue(notation.endsWith(")"));
        assertTrue(notation.contains("\"payload\""));
    }

    @Test
    public void testDiagnosticNotationNestedStructure() {
        Map<String, Object> inner = new HashMap<>();
        inner.put("key", "value");
        
        List<Object> list = Arrays.asList(1, inner, true);
        
        Map<String, Object> outer = new HashMap<>();
        outer.put("data", list);
        
        String notation = Cbor.toDiagnosticNotation(outer);
        assertTrue(notation.contains("\"data\""));
        assertTrue(notation.contains("\"key\""));
        assertTrue(notation.contains("\"value\""));
    }

    @Test
    public void testRoundTripWithTag18() {
        // Test encoding and decoding with COSE_Sign1 tag
        List<Object> original = Arrays.asList(
            new byte[]{1, 2, 3},
            new HashMap<>(),
            "payload".getBytes(),
            new byte[64]
        );
        
        byte[] encoded = Cbor.encodeCoseSign1(original);
        List<?> decoded = Cbor.decodeCoseSign1(encoded);
        
        assertEquals(4, decoded.size());
    }

    @Test
    public void testRoundTripWithTag24() {
        // Test encoding and decoding with encoded CBOR tag
        Map<Integer, String> original = new HashMap<>();
        original.put(1, "first");
        original.put(2, "second");
        
        byte[] encoded = Cbor.encodeWithTag24(original);
        Object decoded = Cbor.decodeWithTag24(encoded);
        
        assertTrue(decoded instanceof Map);
        @SuppressWarnings("unchecked")
        Map<Integer, String> decodedMap = (Map<Integer, String>) decoded;
        assertEquals("first", decodedMap.get(1));
        assertEquals("second", decodedMap.get(2));
    }

    @Test
    public void testNestedTaggedValues() {
        // Test tag within tag
        Cbor.Tagged inner = new Cbor.Tagged(24, "inner data");
        Cbor.Tagged outer = new Cbor.Tagged(18, inner);
        
        byte[] encoded = Cbor.encode(outer);
        Object decoded = Cbor.decode(encoded);
        
        assertTrue(decoded instanceof Cbor.Tagged);
        Cbor.Tagged decodedOuter = (Cbor.Tagged) decoded;
        assertEquals(18, decodedOuter.getTag());
        
        assertTrue(decodedOuter.getValue() instanceof Cbor.Tagged);
        Cbor.Tagged decodedInner = (Cbor.Tagged) decodedOuter.getValue();
        assertEquals(24, decodedInner.getTag());
        assertEquals("inner data", decodedInner.getValue());
    }

    @Test
    public void testTagPreservation() {
        // Test that arbitrary tags are preserved
        for (int tag : new int[]{0, 1, 5, 10, 100, 1000}) {
            Cbor.Tagged original = new Cbor.Tagged(tag, "test");
            byte[] encoded = Cbor.encode(original);
            Object decoded = Cbor.decode(encoded);
            
            assertTrue(decoded instanceof Cbor.Tagged);
            assertEquals(tag, ((Cbor.Tagged) decoded).getTag());
        }
    }

    @Test
    public void testComplexCoseSign1Structure() {
        // Test a more realistic COSE_Sign1 structure
        Map<Integer, Object> protectedMap = new HashMap<>();
        protectedMap.put(1, -7); // alg: ES256
        byte[] protectedHeaders = Cbor.encode(protectedMap);
        
        Map<Integer, Object> unprotectedHeaders = new HashMap<>();
        unprotectedHeaders.put(4, new byte[]{1, 2, 3, 4}); // kid
        
        String payloadStr = "This is the payload";
        byte[] payload = payloadStr.getBytes();
        
        byte[] signature = new byte[64];
        for (int i = 0; i < signature.length; i++) {
            signature[i] = (byte) i;
        }
        
        List<Object> coseSign1 = Arrays.asList(
            protectedHeaders,
            unprotectedHeaders,
            payload,
            signature
        );
        
        byte[] encoded = Cbor.encodeCoseSign1(coseSign1);
        List<?> decoded = Cbor.decodeCoseSign1(encoded);
        
        assertEquals(4, decoded.size());
        
        // Verify protected headers
        byte[] decodedProtected = (byte[]) decoded.get(0);
        Object protectedObj = Cbor.decode(decodedProtected);
        assertTrue(protectedObj instanceof Map);
        
        // Verify unprotected headers
        assertTrue(decoded.get(1) instanceof Map);
        
        // Verify payload
        assertArrayEquals(payload, (byte[]) decoded.get(2));
        
        // Verify signature
        assertArrayEquals(signature, (byte[]) decoded.get(3));
    }

    @Test
    public void testDiagnosticNotationForCoseSign1() {
        List<Object> coseSign1 = Arrays.asList(
            new byte[]{(byte)0xa1, 0x01, 0x26},
            new HashMap<>(),
            "payload".getBytes(),
            new byte[]{1, 2, 3, 4}
        );
        
        Cbor.Tagged tagged = new Cbor.Tagged(18, coseSign1);
        String notation = Cbor.toDiagnosticNotation(tagged);
        
        assertTrue(notation.startsWith("18("));
        assertTrue(notation.contains("["));
        assertTrue(notation.contains("h'"));
    }

    @Test
    public void testEmptyByteStringInTag24() {
        byte[] empty = new byte[0];
        byte[] encoded = Cbor.encodeWithTag24(empty);
        Object decoded = Cbor.decodeWithTag24(encoded);
        
        assertTrue(decoded instanceof byte[]);
        assertEquals(0, ((byte[]) decoded).length);
    }

    @Test
    public void testLargePayloadInCoseSign1() {
        // Test with a large payload
        byte[] largePayload = new byte[10000];
        Arrays.fill(largePayload, (byte)0x42);
        
        List<Object> coseSign1 = Arrays.asList(
            new byte[]{1, 2, 3},
            new HashMap<>(),
            largePayload,
            new byte[64]
        );
        
        byte[] encoded = Cbor.encodeCoseSign1(coseSign1);
        List<?> decoded = Cbor.decodeCoseSign1(encoded);
        
        assertArrayEquals(largePayload, (byte[]) decoded.get(2));
    }
}

// Made with Bob
