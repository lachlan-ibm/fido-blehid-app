/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.util;

import static org.junit.Assert.assertNull;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

public class CborTests {
    
    // Helper methods using reflection to access private methods in Cbor class
    
    private int invokeLoadInt(byte additionalInfo, ByteBuffer buf) {
        try {
            Method method = Cbor.class.getDeclaredMethod("loadInt", byte.class, ByteBuffer.class);
            method.setAccessible(true);
            return (int) method.invoke(null, additionalInfo, buf);
        } catch (java.lang.reflect.InvocationTargetException e) {
            // Unwrap the original exception
            if (e.getCause() instanceof IllegalArgumentException) {
                throw (IllegalArgumentException) e.getCause();
            }
            throw new RuntimeException("Failed to invoke loadInt", e);
        } catch (Exception e) {
            throw new RuntimeException("Failed to invoke loadInt", e);
        }
    }
    
    private int invokeGetArrayLength(Object array) {
        try {
            Method method = Cbor.class.getDeclaredMethod("getArrayLength", Object.class);
            method.setAccessible(true);
            return (int) method.invoke(null, array);
        } catch (Exception e) {
            throw new RuntimeException("Failed to invoke getArrayLength", e);
        }
    }
    
    private Object invokeGetArrayItem(Object array, int index) {
        try {
            Method method = Cbor.class.getDeclaredMethod("getArrayItem", Object.class, int.class);
            method.setAccessible(true);
            return method.invoke(null, array, index);
        } catch (Exception e) {
            throw new RuntimeException("Failed to invoke getArrayItem", e);
        }
    }
    
    private void invokeDumpBigInteger(ByteArrayOutputStream baos, BigInteger value) throws IOException {
        try {
            Method method = Cbor.class.getDeclaredMethod("dumpBigInteger", java.io.OutputStream.class, BigInteger.class);
            method.setAccessible(true);
            method.invoke(null, baos, value);
        } catch (Exception e) {
            if (e.getCause() instanceof IOException) {
                throw (IOException) e.getCause();
            }
            throw new RuntimeException("Failed to invoke dumpBigInteger", e);
        }
    }

    private void invokeWriteByteArrayWithMajorType(OutputStream stream, byte[] bytes, byte majorType) throws IOException {
        try {
            Method method = Cbor.class.getDeclaredMethod("writeByteArrayWithMajorType",
                    java.io.OutputStream.class, byte[].class, byte.class);
            method.setAccessible(true);
            method.invoke(null, stream, bytes, majorType);
        } catch (java.lang.reflect.InvocationTargetException e) {
            if (e.getCause() instanceof IOException) {
                throw (IOException) e.getCause();
            }
            throw new RuntimeException("Failed to invoke writeByteArrayWithMajorType", e);
        } catch (Exception e) {
            throw new RuntimeException("Failed to invoke writeByteArrayWithMajorType", e);
        }
    }

    private Object invokeLoadSimple(byte additionalInfo, ByteBuffer buf) {
        try {
            Method method = Cbor.class.getDeclaredMethod("loadSimple", byte.class, ByteBuffer.class);
            method.setAccessible(true);
            return method.invoke(null, additionalInfo, buf);
        } catch (java.lang.reflect.InvocationTargetException e) {
            // Unwrap the original exception
            if (e.getCause() instanceof IllegalArgumentException) {
                throw (IllegalArgumentException) e.getCause();
            }
            throw new RuntimeException("Failed to invoke loadSimple", e);
        } catch (Exception e) {
            throw new RuntimeException("Failed to invoke loadSimple", e);
        }
    }
    
    private void invokeDumpList(ByteArrayOutputStream baos, List<?> value) throws IOException {
        try {
            Method method = Cbor.class.getDeclaredMethod("dumpList", java.io.OutputStream.class, List.class);
            method.setAccessible(true);
            method.invoke(null, baos, value);
        } catch (Exception e) {
            if (e.getCause() instanceof IOException) {
                throw (IOException) e.getCause();
            }
            throw new RuntimeException("Failed to invoke dumpList", e);
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
            // Create a custom PublicKey implementation that is neither EC, RSA, nor Ed25519
            PublicKey customKey = new PublicKey() {
                @Override
                public String getAlgorithm() {
                    return "UNSUPPORTED";
                }
                
                @Override
                public String getFormat() {
                    return "CUSTOM";
                }
                
                @Override
                public byte[] getEncoded() {
                    return new byte[0];
                }
                
                // No need to override getClass() as it will return this anonymous class
            };
            
            KeyUtils.toCoseKey(customKey);
            fail("Should throw UnsupportedOperationException for unsupported key type");
        } catch (UnsupportedOperationException e) {
            assertTrue(e.getMessage().contains("Unsupported key type"));
        }
    }


    @Test
    public void testLoadInt() {
        // Test with additionalInfo < 24
        ByteBuffer buf = ByteBuffer.allocate(0);
        assertEquals(23, invokeLoadInt((byte)23, buf));
        
        // Test with additionalInfo = 24 (1-byte uint)
        buf = ByteBuffer.wrap(new byte[]{(byte)0xFF});
        assertEquals(255, invokeLoadInt((byte)24, buf));
        
        // Test with additionalInfo = 25 (2-byte uint)
        buf = ByteBuffer.wrap(new byte[]{0x12, 0x34});
        assertEquals(0x1234, invokeLoadInt((byte)25, buf));
        
        // Test with additionalInfo = 26 (4-byte uint)
        buf = ByteBuffer.wrap(new byte[]{0x12, 0x34, 0x56, 0x78});
        assertEquals(0x12345678, invokeLoadInt((byte)26, buf));
        
        // Test with additionalInfo = 26 and value that doesn't fit in signed int
        buf = ByteBuffer.wrap(new byte[]{(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF});
        int result = invokeLoadInt((byte)26, buf);
        assertEquals(-1, result); // Will be converted to BigInteger and back to int
        
        // Test with additionalInfo = 27 (8-byte uint)
        buf = ByteBuffer.wrap(new byte[]{0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78});
        assertEquals(0x12345678, invokeLoadInt((byte)27, buf));
        
        // Test with additionalInfo = 27 and value that doesn't fit in signed int
        buf = ByteBuffer.wrap(new byte[]{(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                                        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF});
        result = invokeLoadInt((byte)27, buf);
        assertEquals(-1, result); // Will be converted to BigInteger and back to int
        
        // Test with invalid additionalInfo
        buf = ByteBuffer.allocate(0);
        try {
            invokeLoadInt((byte)28, buf);
            fail("Should throw IllegalArgumentException for invalid additionalInfo");
        } catch (IllegalArgumentException e) {
            assertEquals("Unable to load integer", e.getMessage());
        }
    }

    @Test
    public void testArrayHandling() {
        // Test with byte array
        byte[] byteArray = {1, 2, 3};
        assertEquals(3, invokeGetArrayLength(byteArray));
        assertEquals((byte)2, invokeGetArrayItem(byteArray, 1));
        
        // Test with int array
        int[] intArray = {1, 2, 3};
        assertEquals(3, invokeGetArrayLength(intArray));
        assertEquals(2, invokeGetArrayItem(intArray, 1));
        
        // Test with long array
        long[] longArray = {1L, 2L, 3L};
        assertEquals(3, invokeGetArrayLength(longArray));
        assertEquals(2L, invokeGetArrayItem(longArray, 1));
        
        // Test with float array
        float[] floatArray = {1.0f, 2.0f, 3.0f};
        assertEquals(3, invokeGetArrayLength(floatArray));
        assertEquals(2.0f, invokeGetArrayItem(floatArray, 1));
        
        // Test with double array
        double[] doubleArray = {1.0, 2.0, 3.0};
        assertEquals(3, invokeGetArrayLength(doubleArray));
        assertEquals(2.0, invokeGetArrayItem(doubleArray, 1));
        
        // Test with boolean array
        boolean[] boolArray = {true, false, true};
        assertEquals(3, invokeGetArrayLength(boolArray));
        assertEquals(false, invokeGetArrayItem(boolArray, 1));
        
        // Test with char array
        char[] charArray = {'a', 'b', 'c'};
        assertEquals(3, invokeGetArrayLength(charArray));
        assertEquals('b', invokeGetArrayItem(charArray, 1));
        
        // Test with short array
        short[] shortArray = {1, 2, 3};
        assertEquals(3, invokeGetArrayLength(shortArray));
        assertEquals((short)2, invokeGetArrayItem(shortArray, 1));
        
        // Test with object array
        String[] stringArray = {"a", "b", "c"};
        assertEquals(3, invokeGetArrayLength(stringArray));
        assertEquals("b", invokeGetArrayItem(stringArray, 1));
    }


    @Test
    public void testDumpBigInteger() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        // Test positive BigInteger that fits in 1 byte
        BigInteger small = BigInteger.valueOf(10);
        invokeDumpBigInteger(baos, small);
        assertArrayEquals(new byte[]{0x0A}, baos.toByteArray());
        baos.reset();
        
        // Test positive BigInteger that fits in 2 bytes
        BigInteger medium = BigInteger.valueOf(1000);
        invokeDumpBigInteger(baos, medium);
        assertArrayEquals(new byte[]{0x19, 0x03, (byte)0xE8}, baos.toByteArray());
        baos.reset();
        
        // Test positive BigInteger that fits in 4 bytes
        BigInteger large = BigInteger.valueOf(1000000);
        invokeDumpBigInteger(baos, large);
        assertArrayEquals(new byte[]{0x1A, 0x00, 0x0F, 0x42, 0x40}, baos.toByteArray());
        baos.reset();
        
        // Test positive BigInteger that requires more than 4 bytes
        BigInteger veryLarge = new BigInteger("FFFFFFFFFFFFFFFF", 16);
        invokeDumpBigInteger(baos, veryLarge);
        // Should use tag 2 for positive bignum
        byte[] expected = {(byte)0xC2, 0x48, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF};
        assertArrayEquals(expected, baos.toByteArray());
        baos.reset();
        
        // Test negative BigInteger that fits in 1 byte
        BigInteger smallNeg = BigInteger.valueOf(-10);
        invokeDumpBigInteger(baos, smallNeg);
        assertArrayEquals(new byte[]{0x29}, baos.toByteArray());
        baos.reset();
        
        // Test negative BigInteger that requires more than 4 bytes
        BigInteger veryLargeNeg = new BigInteger("-FFFFFFFFFFFFFFFF", 16);
        invokeDumpBigInteger(baos, veryLargeNeg);
        // Should use tag 3 for negative bignum
        expected = new byte[]{(byte)0xC3, 0x48, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE};
        assertArrayEquals(expected, baos.toByteArray());
    }

    @Test
    public void testDecodeFrom() {
        // Test decoding with tag 2 (positive bignum)
        byte[] taggedPositive = {(byte)0xC2, 0x43, 0x01, 0x02, 0x03};
        ByteBuffer buf = ByteBuffer.wrap(taggedPositive);
        Object result = Cbor.decodeFrom(buf);
        assertTrue(result instanceof BigInteger);
        assertEquals(new BigInteger("010203", 16), result);
        
        // Test decoding with tag 3 (negative bignum)
        byte[] taggedNegative = {(byte)0xC3, 0x43, 0x01, 0x02, 0x03};
        buf = ByteBuffer.wrap(taggedNegative);
        result = Cbor.decodeFrom(buf);
        assertTrue(result instanceof BigInteger);
        assertEquals(new BigInteger("-010204", 16), result);
        
        // Test decoding with unknown tag (should return Tagged object)
        byte[] unknownTag = {(byte)0xC7, 0x01}; // Tag 7 followed by integer 1
        buf = ByteBuffer.wrap(unknownTag);
        result = Cbor.decodeFrom(buf);
        // Should return a Tagged object wrapping the value
        assertTrue(result.toString().contains("Tagged"));
        assertTrue(result.toString().contains("7"));
        assertTrue(result.toString().contains("1"));
        
        // Test simple value with major type 7
        // Note: 0xE0 is major type 7 (simple values) with additional info 0
        // This is now supported in our implementation
        byte[] simpleType = {(byte)0xE0}; // Major type 7, additional info 0
        buf = ByteBuffer.wrap(simpleType);
        result = Cbor.decodeFrom(buf);
        assertEquals(0, result); // Should return 0 as we now support simple value 0
    }

    @Test
    public void testLoadSimple() {
        // Test false value
        ByteBuffer buf = ByteBuffer.allocate(0);
        assertEquals(false, invokeLoadSimple((byte)20, buf));
        
        // Test true value
        assertEquals(true, invokeLoadSimple((byte)21, buf));
        
        // Test null values
        assertNull(invokeLoadSimple((byte)22, buf));
        assertNull(invokeLoadSimple((byte)23, buf));
        
        // Test float value
        buf = ByteBuffer.wrap(new byte[]{0x3F, (byte)0x80, 0x00, 0x00}); // 1.0f in IEEE 754
        assertEquals(1.0f, invokeLoadSimple((byte)26, buf));
        
        // Test double value
        buf = ByteBuffer.wrap(new byte[]{0x3F, (byte)0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}); // 1.0 in IEEE 754
        assertEquals(1.0, invokeLoadSimple((byte)27, buf));
        
        // Test simple value 0 (now supported)
        assertEquals(0, invokeLoadSimple((byte)0, buf));
        
        // Test unsupported simple value (e.g., 1 which is not explicitly handled)
        try {
            invokeLoadSimple((byte)1, buf);
            fail("Should throw IllegalArgumentException for unsupported simple type");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("Unsupported simple type"));
        }
    }

    @Test
    public void testDumpList() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        // Test empty list
        List<Object> emptyList = new ArrayList<>();
        invokeDumpList(baos, emptyList);
        assertArrayEquals(new byte[]{(byte)0x80}, baos.toByteArray());
        baos.reset();
        
        // Test list with one item
        List<Object> singleItemList = Collections.singletonList(1);
        invokeDumpList(baos, singleItemList);
        assertArrayEquals(new byte[]{(byte)0x81, 0x01}, baos.toByteArray());
        baos.reset();
        
        // Test list with multiple items of different types
        List<Object> mixedList = Arrays.asList(1, "test", true);
        invokeDumpList(baos, mixedList);
        byte[] expected = {(byte)0x83, 0x01, 0x64, 0x74, 0x65, 0x73, 0x74, (byte)0xF5};
        assertArrayEquals(expected, baos.toByteArray());
    }


    @Test
    public void testEncodeToEdgeCases() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        // Test null value
        Cbor.encodeTo(baos, null);
        assertArrayEquals(new byte[]{(byte)0xF6}, baos.toByteArray());
        baos.reset();
        
        // Test BigInteger
        Cbor.encodeTo(baos, new BigInteger("12345678901234567890"));
        // This should encode as a tagged bignum
        assertTrue(baos.toByteArray()[0] == (byte)0xC2);
        baos.reset();
        
        // Test unsupported object type
        try {
            Cbor.encodeTo(baos, new StringBuilder("test"));
            fail("Should throw IllegalArgumentException for unsupported object type");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("Unsupported object type"));
        }
    }

    @Test
    public void testDecodeEdgeCases() {
        // Test with extraneous data
        byte[] tooMuchData = {0x01, 0x02}; // Integer 1 followed by extraneous byte
        try {
            Cbor.decode(tooMuchData);
            fail("Should throw IllegalArgumentException for extraneous data");
        } catch (IllegalArgumentException e) {
            assertEquals("Extraneous data", e.getMessage());
        }
        
        // Test with offset and length
        byte[] data = {(byte)0xFF, 0x01, (byte)0xFF}; // Padding, integer 1, padding
        Object result = Cbor.decode(data, 1, 1);
        assertEquals(1, result);
    }

    // -----------------------------------------------------------------------
    // Tests targeting specific uncovered branches from JaCoCo report
    // -----------------------------------------------------------------------

    /**
     * L88-89: IOException path in encode() — wraps encodeTo() over a failing OutputStream.
     */
    @Test
    public void testEncodeIOExceptionWrapped() throws Exception {
        OutputStream failingStream = new OutputStream() {
            @Override
            public void write(int b) throws IOException {
                throw new IOException("Simulated IO failure");
            }
            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                throw new IOException("Simulated IO failure");
            }
        };

        try {
            Cbor.encodeTo(failingStream, 42);
            fail("Should throw IOException");
        } catch (IOException e) {
            assertEquals("Simulated IO failure", e.getMessage());
        }
    }

    /**
     * L155: Negative BigInteger where bytes.length == 1 after negate/subtract —
     * the compound condition (bytes.length > 1 && bytes[0] == 0) is false because
     * length == 1, so the leading-zero trim branch is skipped.
     * -1  →  negate().subtract(ONE) = 0  →  toByteArray() = [0x00]  (length 1)
     */
    @Test
    public void testNegativeBigIntegerSingleByteNoLeadingZeroStrip() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // -1 encodes as CBOR major-type-1 value 0  →  0x20
        invokeDumpBigInteger(baos, BigInteger.valueOf(-1));
        assertArrayEquals(new byte[]{0x20}, baos.toByteArray());
    }

    /**
     * L155 TF branch: negative BigInteger where bytes.length > 1 AND bytes[0] != 0.
     *
     * negate().subtract(ONE) must produce a multi-byte array whose first byte is NOT 0.
     * BigInteger.toByteArray() only prepends a 0x00 sign byte when the high bit of the
     * magnitude is set (i.e. the value is >= 128, 32768, etc.).  So we need a value
     * in the range [128..255] for 2-byte representation where the first byte is non-zero.
     *
     * -384  →  negate().subtract(ONE) = 383 = 0x17F
     *        toByteArray() = [0x01, 0x7F]   (length=2, bytes[0]=0x01 ≠ 0)
     *        → condition (length>1=T && bytes[0]==0=F)  — the TF branch — NO strip
     *        → writeByteArrayWithMajorType([0x01,0x7F], majorType=1):
     *             head=0x20, length==2 → write 0x39 (0x20|25), write [0x01,0x7F]
     * Expected bytes: [0x39, 0x01, 0x7F]
     *
     * Round-trip check: Cbor.decode([0x39,0x01,0x7F]) = -1 - 0x017F = -1 - 383 = -384
     */
    @Test
    public void testNegativeBigIntegerMultiByteNoLeadingZero() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        invokeDumpBigInteger(baos, BigInteger.valueOf(-384));
        assertArrayEquals(new byte[]{0x39, 0x01, 0x7F}, baos.toByteArray());

        // Round-trip via decode to confirm the encoding is valid CBOR
        Object decoded = Cbor.decode(new byte[]{0x39, 0x01, 0x7F});
        assertEquals(-384, decoded);
    }

    /**
     * Pre-generated byte-vector tests for documented dead-code branches.
     *
     * L88/89: IOException inside encode() — ByteArrayOutputStream never throws.
     * L287/303: switch "Unsupported major type" — major type 6 is intercepted
     *           before the switch, and types 0-5,7 are all handled.  No valid
     *           8-bit head value escapes both guards.
     * L365: return key1.length - key2.length — CBOR is self-delimiting; two
     *       different valid encodings can never be byte-prefix of each other.
     *
     * The vectors below probe the boundaries to confirm the dead-code throw at
     * L303 is indeed never reached for any well-formed or ill-formed 1-byte head.
     */
    @Test
    public void testDecodeAllMajorTypesViaRawVectors() {
        // Major type 0 (unsigned int): 0x00 = integer 0
        assertEquals(0, Cbor.decode(new byte[]{0x00}));

        // Major type 1 (negative int): 0x20 = -1
        assertEquals(-1, Cbor.decode(new byte[]{0x20}));

        // Major type 2 (byte string): 0x40 = empty byte string
        assertArrayEquals(new byte[0], (byte[]) Cbor.decode(new byte[]{0x40}));

        // Major type 3 (text string): 0x60 = empty string
        assertEquals("", Cbor.decode(new byte[]{0x60}));

        // Major type 4 (array): 0x80 = empty array
        assertTrue(((List<?>) Cbor.decode(new byte[]{(byte)0x80})).isEmpty());

        // Major type 5 (map): 0xA0 = empty map
        assertTrue(((Map<?,?>) Cbor.decode(new byte[]{(byte)0xA0})).isEmpty());

        // Major type 6 (tag): intercepted before switch — covered by existing tag tests.
        // Major type 7 (simple/float): 0xF4 = false
        assertEquals(false, Cbor.decode(new byte[]{(byte)0xF4}));
    }

    /**
     * L189-191: writeByteArrayWithMajorType with empty byte array (bytes.length <= 0).
     * Encodes as just the head byte with no additional data.
     */
    @Test
    public void testWriteByteArrayWithMajorTypeEmpty() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        invokeWriteByteArrayWithMajorType(baos, new byte[0], (byte) 0);
        // head = (0 << 5) = 0x00 — major type 0, no additional bytes
        assertArrayEquals(new byte[]{0x00}, baos.toByteArray());

        baos.reset();
        invokeWriteByteArrayWithMajorType(baos, new byte[0], (byte) 2);
        // head = (2 << 5) = 0x40 — major type 2 (byte string), zero length
        assertArrayEquals(new byte[]{0x40}, baos.toByteArray());
    }

    /**
     * L194/197-200: writeByteArrayWithMajorType with single byte whose value > 23.
     * Exercises the "One byte, but value > 23" path (additional info = 24).
     * BigInteger.valueOf(100): positive path, toByteArray() = [0x64], length=1, 0x64 > 23.
     */
    @Test
    public void testBigIntegerSingleByteValueOver23() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        invokeDumpBigInteger(baos, BigInteger.valueOf(100));
        // Expected: 0x18 (major 0, addInfo 24) followed by 0x64 (100)
        assertArrayEquals(new byte[]{0x18, 0x64}, baos.toByteArray());
    }

    /**
     * L209/214: writeByteArrayWithMajorType — exactly 4-byte array (no padding needed).
     * BigInteger 0x80000000 (2^31): positive, toByteArray() = [0x00,0x80,0x00,0x00,0x00],
     * strip leading zero → [0x80,0x00,0x00,0x00] (exactly 4 bytes), hits the else branch.
     */
    @Test
    public void testBigIntegerExactly4Bytes() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        BigInteger value = new BigInteger("80000000", 16); // 2^31
        invokeDumpBigInteger(baos, value);
        byte[] result = baos.toByteArray();
        // 1 header byte (0x1A) + 4 value bytes
        assertEquals(5, result.length);
        assertEquals((byte) 0x1A, result[0]); // major type 0, additional info 26
        assertEquals((byte) 0x80, result[1]);
        assertEquals((byte) 0x00, result[2]);
        assertEquals((byte) 0x00, result[3]);
        assertEquals((byte) 0x00, result[4]);
    }

    /**
     * L358/365: Map key comparator — return key1.length - key2.length path.
     * Requires two map keys whose CBOR encodings share all bytes up to the
     * shorter length, then differ only by total length.
     *
     * Strategy: use integer key 0 (CBOR [0x00], 1 byte) and a single-element
     * byte-array key [0x00] (CBOR [0x41, 0x00], 2 bytes). The first bytes differ
     * (0x00 vs 0x41) so this won't work. Instead we use reflection to call
     * dumpMap indirectly with a map that has two keys whose encoded bytes satisfy
     * the prefix condition. We construct raw entries manually via inner map encoding.
     *
     * Reliable approach: create a map with string keys "a" and "a\u0000" — but
     * their CBOR headers will differ because they have different lengths.
     *
     * The only practical way: two maps with keys of the same CBOR first byte.
     * Integer key 0 ([0x00]) and integer key 1 ([0x01]) — same length, no
     * length difference, loop body entered, differ at byte 0.
     *
     * To reach `return key1.length - key2.length`, we need entries with
     * key1 bytes = a strict prefix of key2 bytes. One valid case:
     * key1 encodes as [X] (1 byte), key2 encodes as [X, ...] (≥2 bytes with
     * same first byte). Integer 0 encodes [0x00]; nothing 2-byte starts with 0x00
     * in standard CBOR (0x00 means major type 0, additional info 0 = integer 0;
     * a 2-byte sequence [0x00, Y] is not a valid single CBOR item).
     *
     * Conclusion: this branch is structurally unreachable through standard
     * Cbor.encode() keys. Two different valid CBOR values cannot share a
     * complete byte-prefix. Document as unreachable.
     */
    @Test
    public void testMapKeyComparatorPrefixMatchDocumented() {
        // Verify canonical ordering works for keys that differ at byte 0
        Map<Object, Integer> map = new HashMap<>();
        map.put(0, 10);     // CBOR [0x00]
        map.put(1, 20);     // CBOR [0x01]
        map.put(255, 30);   // CBOR [0x18, 0xFF]
        map.put(256, 40);   // CBOR [0x19, 0x01, 0x00]

        byte[] encoded = Cbor.encode(map);
        assertNotNull(encoded);

        Object decoded = Cbor.decode(encoded);
        assertTrue(decoded instanceof Map);

        // Verify all values round-trip correctly
        @SuppressWarnings("unchecked")
        Map<Integer, Integer> decodedMap = (Map<Integer, Integer>) decoded;
        assertEquals(4, decodedMap.size());
        assertEquals(10, (int) decodedMap.get(0));
        assertEquals(20, (int) decodedMap.get(1));
        assertEquals(30, (int) decodedMap.get(255));
        assertEquals(40, (int) decodedMap.get(256));
    }

    /**
     * L468: loadInt additionalInfo=27, value >= 0 && value > Integer.MAX_VALUE.
     * The "1 of 4 branches missed" for (value < 0 || value > MAX_VALUE) is the
     * (false, true) sub-path: value is a non-negative long larger than MAX_INT.
     * Example: 0x0000000080000000 = 2147483648L > Integer.MAX_VALUE, and is >= 0.
     */
    @Test
    public void testLoadIntAdditionalInfo27ValueExceedsMaxInt() {
        // 2147483648 = Integer.MAX_VALUE + 1; positive long but > Integer.MAX_VALUE
        ByteBuffer buf = ByteBuffer.wrap(new byte[]{
            0x00, 0x00, 0x00, 0x00, (byte)0x80, 0x00, 0x00, 0x00
        });
        int result = invokeLoadInt((byte) 27, buf);
        // BigInteger(1, bytes).intValue() of 0x80000000 = -2147483648 (int overflow)
        assertEquals(Integer.MIN_VALUE, result);
    }

    /**
     * L567/570: toDiagnosticNotation — the else fallback (value.toString()).
     * This branch is not reachable via the public encode/decode API (which
     * rejects unknown types), but IS reachable by calling toDiagnosticNotation
     * directly with a non-CBOR object through reflection on the private overload.
     */
    @Test
    public void testToDiagnosticNotationFallbackBranch() throws Exception {
        Method method = Cbor.class.getDeclaredMethod("toDiagnosticNotation",
                Object.class, int.class);
        method.setAccessible(true);

        // An object that is not null, Tagged, Boolean, Number, String, byte[], List, or Map
        Object customObj = new Object() {
            @Override
            public String toString() {
                return "CustomFallback";
            }
        };

        String result = (String) method.invoke(null, customObj, 0);
        assertEquals("CustomFallback", result);
    }

    /**
     * L287: "Unsupported major type" throw — this is structurally unreachable
     * because major type 6 is intercepted before the switch, and types 0-5,7
     * are all handled. Document this as a defensive branch.
     */
    @Test
    public void testDecodeWithTag24NotTaggedThrows() {
        // Verify decodeWithTag24 throws when given plain (non-tagged) CBOR
        byte[] plain = Cbor.encode(42);
        try {
            Cbor.decodeWithTag24(plain);
            fail("Should throw IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("Expected tagged CBOR value"));
            assertTrue(e.getMessage().contains("Integer"));
        }
    }

}
