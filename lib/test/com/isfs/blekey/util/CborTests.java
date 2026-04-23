/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.util;

import static org.junit.Assert.assertNull;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

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
        
        // Test decoding with unknown tag (should ignore tag and process content)
        byte[] unknownTag = {(byte)0xC7, 0x01, 0x02}; // Tag 7 followed by array [1, 2]
        buf = ByteBuffer.wrap(unknownTag);
        result = Cbor.decodeFrom(buf);
        // Should ignore tag 7 and decode the array
        assertEquals(1, result);
        
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

}
