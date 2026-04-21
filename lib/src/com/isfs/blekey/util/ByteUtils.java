/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.util;

/**
 * Utility class for byte array operations and formatting.
 */
public class ByteUtils {

    private ByteUtils() {
        // Utility class - prevent instantiation
    }

    /**
     * Converts a byte array to a hexadecimal string representation.
     * 
     * @param bytes The byte array to convert
     * @return A hexadecimal string representation of the bytes
     */
    public static String bytesToHex(byte[] bytes) {
        if (bytes == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    /**
     * Creates a formatted hex dump of a byte array with offset, hex, and ASCII representation.
     * 
     * @param bytes The byte array to dump
     * @param label Optional label to prefix the dump
     * @return A formatted hex dump string
     */
    public static String hexDump(byte[] bytes, String label) {
        if (bytes == null) {
            return (label != null ? label + ": " : "") + "null";
        }
        
        StringBuilder sb = new StringBuilder();
        if (label != null && !label.isEmpty()) {
            sb.append(label).append(" (").append(bytes.length).append(" bytes):\n");
        }
        
        for (int i = 0; i < bytes.length; i += 16) {
            // Offset
            sb.append(String.format("%04x: ", i));
            
            // Hex bytes
            for (int j = 0; j < 16; j++) {
                if (i + j < bytes.length) {
                    sb.append(String.format("%02x ", bytes[i + j] & 0xff));
                } else {
                    sb.append("   ");
                }
                if (j == 7) {
                    sb.append(" ");
                }
            }
            
            // ASCII representation
            sb.append(" |");
            for (int j = 0; j < 16 && i + j < bytes.length; j++) {
                byte b = bytes[i + j];
                if (b >= 32 && b < 127) {
                    sb.append((char) b);
                } else {
                    sb.append('.');
                }
            }
            sb.append("|\n");
        }
        
        return sb.toString();
    }

    /**
     * Creates a compact hex dump suitable for single-line logging.
     * 
     * @param bytes The byte array to dump
     * @return A compact hex string
     */
    public static String hexDumpCompact(byte[] bytes) {
        if (bytes == null) {
            return "null";
        }
        if (bytes.length == 0) {
            return "[]";
        }
        
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) {
                sb.append(" ");
            }
            sb.append(String.format("%02x", bytes[i] & 0xff));
        }
        sb.append("]");
        return sb.toString();
    }
}

// Made with Bob
