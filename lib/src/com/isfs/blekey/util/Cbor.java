/*
 * Copyright IBM 2025
 */
/*
 * Copyright (C) 2020-2023 Yubico.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.isfs.blekey.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Provides canonical CBOR encoding and decoding.
 *
 * <p>Only a small subset of CBOR is implemented, sufficient for CTAP2 functionality.
 *
 * <p>Note that while any integer type can be encoded into canonical CBOR, but all CBOR integers
 * will decode to an int. Thus, numeric map keys can use any integer type (byte, short, int, long)
 * when encoding to send to a device, but any response will have ints for keys.
 */
public class Cbor {
  /**
   * Encodes an object into canonical CBOR.
   *
   * @param value the Object to encode.
   * @return CBOR encoded bytes.
   */
  public static byte[] encode(Object value) {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try {
      encodeTo(baos, value);
    } catch (IOException e) {
      throw new RuntimeException(e); // Shouldn't happen
    }
    return baos.toByteArray();
  }

  /**
   * Encodes an object into canonical CBOR, to an OutputStream.
   *
   * @param stream the output stream to write to
   * @param value the Object to encode.
   * @throws IOException A communication error in the transport layer.
   */
  public static void encodeTo(OutputStream stream, Object value) throws IOException {
    if (value == null) {
      dumpSimple(stream, null);
    } else if (value instanceof BigInteger) {
      dumpBigInteger(stream, (BigInteger) value);
    } else if (value instanceof Number) {
      dumpInt(stream, ((Number) value).intValue(), 0);
    } else if (value instanceof Boolean) {
      dumpSimple(stream, (Boolean) value);
    } else if (value instanceof List) {
      dumpList(stream, (List<?>) value);
    } else if (value instanceof Map) {
      dumpMap(stream, (Map<?, ?>) value);
    } else if (value instanceof byte[]) {
      dumpBytes(stream, (byte[]) value);
    } else if (value instanceof String) {
      dumpText(stream, (String) value);
    } else if (value.getClass().isArray()) {
      dumpArray(stream, value);
    } else {
      throw new IllegalArgumentException(
          String.format(Locale.ROOT, "Unsupported object type: %s", value.getClass()));
    }
  }

  /**
   * Encodes a BigInteger into canonical CBOR.
   *
   * @param stream the output stream to write to
   * @param value the BigInteger to encode
   * @throws IOException A communication error in the transport layer
   */
  private static void dumpBigInteger(OutputStream stream, BigInteger value) throws IOException {
    if (value.signum() < 0) {
      // Negative BigInteger
      byte majorType = 1;
      value = value.negate().subtract(BigInteger.ONE);
      byte[] bytes = value.toByteArray();
      
      // Remove leading zero if present (BigInteger.toByteArray may add a leading zero)
      if (bytes.length > 1 && bytes[0] == 0) {
        byte[] trimmed = new byte[bytes.length - 1];
        System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
        bytes = trimmed;
      }
      
      writeByteArrayWithMajorType(stream, bytes, majorType);
    } else {
      // Positive BigInteger
      byte majorType = 0;
      byte[] bytes = value.toByteArray();
      
      // Remove leading zero if present (BigInteger.toByteArray may add a leading zero)
      if (bytes.length > 1 && bytes[0] == 0) {
        byte[] trimmed = new byte[bytes.length - 1];
        System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
        bytes = trimmed;
      }
      
      writeByteArrayWithMajorType(stream, bytes, majorType);
    }
  }
  
  /**
   * Helper method to write a byte array with a specific major type.
   *
   * @param stream the output stream to write to
   * @param bytes the byte array to write
   * @param majorType the major type to use
   * @throws IOException A communication error in the transport layer
   */
  private static void writeByteArrayWithMajorType(OutputStream stream, byte[] bytes, byte majorType) throws IOException {
    byte head = (byte) (majorType << 5);
    
    if (bytes.length <= 0) {
      stream.write((byte) (head));
      return;
    }
    
    if (bytes.length == 1 && (bytes[0] & 0xFF) <= 23) {
      // Can fit in the additional info byte
      stream.write((byte) (head | (bytes[0] & 0xFF)));
    } else if (bytes.length == 1) {
      // One byte, but value > 23
      stream.write((byte) (head | 24));
      stream.write(bytes[0]);
    } else if (bytes.length == 2) {
      // Two bytes
      stream.write((byte) (head | 25));
      stream.write(bytes);
    } else if (bytes.length <= 4) {
      // Up to four bytes
      stream.write((byte) (head | 26));
      // Pad to 4 bytes if needed
      if (bytes.length < 4) {
        byte[] padded = new byte[4];
        System.arraycopy(bytes, 0, padded, 4 - bytes.length, bytes.length);
        stream.write(padded);
      } else {
        stream.write(bytes);
      }
    } else {
      // More than 4 bytes - use tag 2 for bignum
      if (majorType == 0) {
        stream.write((byte) 0xC2); // Tag 2 for positive bignum
      } else {
        stream.write((byte) 0xC3); // Tag 3 for negative bignum
      }
      dumpBytes(stream, bytes);
    }
  }

  /**
   * Decodes an Object from CBOR data.
   *
   * @param data The CBOR encoded byte array.
   * @param offset The offset of where the CBOR encoded data is in the given byte array.
   * @param length The length of CBOR encoded data.
   * @return The decoded Object.
   */
  public static Object decode(byte[] data, int offset, int length) {
    ByteBuffer buf = ByteBuffer.wrap(data, offset, length);
    Object decoded = decodeFrom(buf);
    if (buf.hasRemaining()) {
      throw new IllegalArgumentException("Extraneous data");
    }
    return decoded;
  }

  /**
   * Decodes an Object from CBOR data.
   *
   * @param data The CBOR encoded byte array.
   * @return The decoded Object.
   */
  public static Object decode(byte[] data) {
    return decode(data, 0, data.length);
  }

  /**
   * Decodes a single Object from a ByteBuffer containing CBOR encoded data at the buffers current
   * position. The position will be updated to point to the end of the CBOR data.
   *
   * @param buf the ByteBuffer from where the Object should be decoded.
   * @return The decoded object.
   */
  public static Object decodeFrom(ByteBuffer buf) {
    int head = 0xff & buf.get();
    byte additionalInfo = (byte) (head & 0b11111);
    
    // Check for tags (major type 6)
    if ((head >> 5) == 6) {
      int tagNumber = loadInt(additionalInfo, buf);
      if (tagNumber == 2) {
        // Tag 2: positive bignum
        byte[] bytes = (byte[]) loadBytes((byte) (buf.get() & 0b11111), buf);
        return new BigInteger(1, bytes);
      } else if (tagNumber == 3) {
        // Tag 3: negative bignum
        byte[] bytes = (byte[]) loadBytes((byte) (buf.get() & 0b11111), buf);
        return new BigInteger(-1, bytes).subtract(BigInteger.ONE);
      } else {
        // Ignore other tags and process the tagged item
        return decodeFrom(buf);
      }
    }
    
    switch (head >> 5) {
      case 0:
        return loadInt(additionalInfo, buf);
      case 1:
        return loadNint(additionalInfo, buf);
      case 2:
        return loadBytes(additionalInfo, buf);
      case 3:
        return loadString(additionalInfo, buf);
      case 4:
        return loadList(additionalInfo, buf);
      case 5:
        return loadMap(additionalInfo, buf);
      case 7:
        return loadSimple(additionalInfo, buf);
    }
    throw new IllegalArgumentException("Unsupported major type");
  }

  private static void dumpInt(OutputStream stream, int value, int majorType) throws IOException {
    if (value < 0) {
      majorType = 1;
      value = -1 - value;
    }

    byte head = (byte) (majorType << 5);
    if (value <= 23) {
      stream.write((byte) (head | value));
    } else if (value <= 0xff) {
      stream.write((byte) (head | 24));
      stream.write((byte) value);
    } else if (value <= 0xffff) {
      stream.write((byte) (head | 25));
      stream.write(ByteBuffer.allocate(2).putShort((short) value).array());
    } else {
      stream.write((byte) (head | 26));
      stream.write(ByteBuffer.allocate(4).putInt(value).array());
    }
  }

  private static void dumpSimple(OutputStream stream, Boolean value) throws IOException {
    if (value == null) {
      stream.write((byte) 0xf6);
    } else {
      stream.write((byte) (value ? 0xf5 : 0xf4));
    }
  }

  private static void dumpList(OutputStream stream, List<?> value) throws IOException {
    dumpInt(stream, value.size(), 4);
    for (Object item : value) {
      stream.write(encode(item));
    }
  }

  private static void dumpMap(OutputStream stream, Map<?, ?> value) throws IOException {
    dumpInt(stream, value.size(), 5);
    List<byte[][]> entries = new ArrayList<>();
    for (Map.Entry<?, ?> entry : value.entrySet()) {
      entries.add(new byte[][] {encode(entry.getKey()), encode(entry.getValue())});
    }
    // Canonical order of map keys, as specified here:
    // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#ctap2-canonical-cbor-encoding-form
    // Corresponds to lexicographical comparison.
    //noinspection Java8ListSort // List.sort(Comparator<>) is available first in Android API 24
    Collections.sort(
        entries,
        (o1, o2) -> {
          byte[] key1 = o1[0];
          byte[] key2 = o2[0];
          int minLength = Math.min(key1.length, key2.length);
          for (int i = 0; i < minLength; i++) {
            int a = 0xff & key1[i];
            int b = 0xff & key2[i];
            if (a != b) {
              return a - b;
            }
          }
          return key1.length - key2.length;
        });
    for (byte[][] entry : entries) {
      stream.write(entry[0]);
      stream.write(entry[1]);
    }
  }

  private static void dumpBytes(OutputStream stream, byte[] value) throws IOException {
    dumpInt(stream, value.length, 2);
    stream.write(value);
  }

  private static void dumpText(OutputStream stream, String value) throws IOException {
    byte[] data = value.getBytes(StandardCharsets.UTF_8);
    dumpInt(stream, data.length, 3);
    stream.write(data);
  }

  /**
   * Encodes any array type as a CBOR array.
   *
   * @param stream the output stream to write to
   * @param array the array to encode
   * @throws IOException A communication error in the transport layer.
   */
  private static void dumpArray(OutputStream stream, Object array) throws IOException {
    int length = getArrayLength(array);
    dumpInt(stream, length, 4); // Major type 4 for arrays
    
    for (int i = 0; i < length; i++) {
      Object item = getArrayItem(array, i);
      stream.write(encode(item));
    }
  }
  
  /**
   * Gets the length of any array type.
   *
   * @param array the array object
   * @return the length of the array
   */
  private static int getArrayLength(Object array) {
    Class<?> componentType = array.getClass().getComponentType();
    
    if (componentType == byte.class) return ((byte[]) array).length;
    if (componentType == int.class) return ((int[]) array).length;
    if (componentType == long.class) return ((long[]) array).length;
    if (componentType == float.class) return ((float[]) array).length;
    if (componentType == double.class) return ((double[]) array).length;
    if (componentType == boolean.class) return ((boolean[]) array).length;
    if (componentType == char.class) return ((char[]) array).length;
    if (componentType == short.class) return ((short[]) array).length;
    
    // Must be an object array
    return ((Object[]) array).length;
  }
  
  /**
   * Gets an item from any array type at the specified index.
   *
   * @param array the array object
   * @param index the index of the item to get
   * @return the item at the specified index
   */
  private static Object getArrayItem(Object array, int index) {
    Class<?> componentType = array.getClass().getComponentType();
    
    if (componentType == byte.class) return ((byte[]) array)[index];
    if (componentType == int.class) return ((int[]) array)[index];
    if (componentType == long.class) return ((long[]) array)[index];
    if (componentType == float.class) return ((float[]) array)[index];
    if (componentType == double.class) return ((double[]) array)[index];
    if (componentType == boolean.class) return ((boolean[]) array)[index];
    if (componentType == char.class) return ((char[]) array)[index];
    if (componentType == short.class) return ((short[]) array)[index];
    
    // Must be an object array
    return ((Object[]) array)[index];
  }

  private static int loadInt(byte additionalInfo, ByteBuffer buf) {
    if (additionalInfo < 24) {
      return 0xff & additionalInfo;
    } else if (additionalInfo == 24) {
      return 0xff & buf.get();
    } else if (additionalInfo == 25) {
      return 0xffff & buf.getShort();
    } else if (additionalInfo == 26) {
      int value = buf.getInt();
      if (value < 0) {
        // This is a large positive integer that doesn't fit in a signed int
        // Convert to BigInteger and return its int value (may lose precision)
        byte[] bytes = new byte[4];
        buf.position(buf.position() - 4);  // Go back to read the bytes again
        buf.get(bytes);
        BigInteger bigInt = new BigInteger(1, bytes);  // 1 means positive
        return bigInt.intValue();  // This will lose precision but maintain compatibility
      }
      return value;
    } else if (additionalInfo == 27) {
      // Handle 8-byte integers (long)
      long value = buf.getLong();
      if (value < 0 || value > Integer.MAX_VALUE) {
        // Convert to BigInteger and return its int value (may lose precision)
        byte[] bytes = new byte[8];
        buf.position(buf.position() - 8);  // Go back to read the bytes again
        buf.get(bytes);
        BigInteger bigInt = new BigInteger(1, bytes);  // 1 means positive
        return bigInt.intValue();  // This will lose precision but maintain compatibility
      }
      return (int) value;
    }
    throw new IllegalArgumentException("Unable to load integer");
  }

  private static int loadNint(byte additionalInfo, ByteBuffer buf) {
    return -1 - loadInt(additionalInfo, buf);
  }

  private static Object loadSimple(byte additionalInfo, ByteBuffer buf) {
    switch (additionalInfo) {
      case 20:
        return false;
      case 21:
        return true;
      case 22:
      case 23:
        return null;
      case 26:
        return buf.getFloat();
      case 27:
        return buf.getDouble();
      default:
        throw new IllegalArgumentException("Unsupported simple type: " + additionalInfo);
    }
  }

  private static byte[] loadBytes(byte additionalInfo, ByteBuffer buf) {
    byte[] value = new byte[(int) loadInt(additionalInfo, buf)];
    buf.get(value);
    return value;
  }

  private static String loadString(byte additionalInfo, ByteBuffer buf) {
    return new String(loadBytes(additionalInfo, buf), StandardCharsets.UTF_8);
  }

  private static List<?> loadList(byte additionalInfo, ByteBuffer buf) {
    List<Object> list = new ArrayList<>();
    for (int i = loadInt(additionalInfo, buf); i > 0; i--) {
      list.add(decodeFrom(buf));
    }
    return list;
  }

  private static Map<?, ?> loadMap(byte additionalInfo, ByteBuffer buf) {
    Map<Object, Object> map = new HashMap<>();
    for (int i = loadInt(additionalInfo, buf); i > 0; i--) {
      map.put(decodeFrom(buf), decodeFrom(buf));
    }
    return map;
  }
}

