/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.data;

import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.After;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * Unit tests for FernetKey class using Python's cryptography package as a verifier.
 */
public class FernetKeyTest {
    
    private static final String TEST_DATA = "Hello, Fernet!";
    private String testKey;
    
    // Python script as a string constant
    private static final String PYTHON_SCRIPT = """
#!/usr/bin/env python3
import sys
import time
import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  

def error(message):
    print(f"Unknown command")
    sys.exit(1)

def verify_key(key):
    try:
        # Try to create a Fernet instance with the key
        fernet = Fernet(key)
        print("KEY_VALID")
    except Exception as e:
        print(f"KEY_INVALID: {str(e)}")
        sys.exit(1)

def encrypt(key, data):
    try:
        fernet = Fernet(key)
        token = fernet.encrypt(data.encode('utf-8'))
        print(token.decode('utf-8'))
    except Exception as e:
        print(f"ENCRYPTION_FAILED: {str(e)}")
        sys.exit(1)

def decrypt(key, token):
    try:
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(token.encode('utf-8'))
        print(decrypted_data.decode('utf-8'))
    except Exception as e:
        print(f"DECRYPTION_FAILED: {str(e)}")
        sys.exit(1)

def create_expired_token(key, data):
    try:
        # Create a token with a timestamp from 31 days ago (beyond the 30-day TTL)
        from cryptography.fernet import Fernet
        import time
        import base64
        import os
        from cryptography.hazmat.primitives import hashes, padding
        from cryptography.hazmat.primitives.hmac import HMAC
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        
        # Decode the key
        key_bytes = base64.urlsafe_b64decode(key)
        signing_key = key_bytes[:16]
        encryption_key = key_bytes[16:]
        
        # Current time minus 31 days in seconds
        current_time = int(time.time())
        timestamp = current_time - (31 * 24 * 60 * 60)
        
        # Generate IV
        iv = os.urandom(16)
        
        # Encrypt the data
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data.encode('utf-8')) + padder.finalize()
        
        cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Build the token
        basic_parts = (
            b'\\x80' +  # Version
            timestamp.to_bytes(8, byteorder='big') +  # Timestamp
            iv +  # IV
            ciphertext  # Ciphertext
        )
        
        # Generate HMAC
        h = HMAC(signing_key, hashes.SHA256(), backend=default_backend())
        h.update(basic_parts)
        hmac_value = h.finalize()
        
        # Combine all parts and encode
        token = base64.urlsafe_b64encode(basic_parts + hmac_value)
        print(token.decode('utf-8'))
    except Exception as e:
        print(f"CREATE_EXPIRED_TOKEN_FAILED: {str(e)}")
        sys.exit(1)
    
    def create_invalid_token(key, data):
        try:
            # Create a valid token first
            fernet = Fernet(key)
            token = fernet.encrypt(data.encode('utf-8'))
            
            # Corrupt the token by changing a byte
            token_bytes = bytearray(token)
            if len(token_bytes) > 10:
                token_bytes[10] = (token_bytes[10] + 1) % 256
            
            print(bytes(token_bytes).decode('utf-8', errors='replace'))
        except Exception as e:
            print(f"CREATE_INVALID_TOKEN_FAILED: {str(e)}")
            sys.exit(1)
    
    def main():
        if len(sys.argv) < 2:
            print("Usage: python fernet_verifier.py <command> [args...]")
            sys.exit(1)
        
        command = sys.argv[1]
        args = sys.argv[2:]
        
        commands = {
            "verify_key": verify_key,
            "encrypt": encrypt,
            "decrypt": decrypt,
            "create_expired_token": create_expired_token,
            "create_invalid_token": create_invalid_token
        }
        
        func = commands.get(command, error)
        
        try:
            func(*args)
        except TypeError as e:
            print(f"ERROR: Invalid arguments for command '{command}'")
            print(f"Function signature: {func.__name__}({', '.join(func.__code__.co_varnames[:func.__code__.co_argcount])})")
            print(f"Error: {str(e)}")
            sys.exit(1)

if __name__ == "__main__":
    main()
""";
    
    @Before
    public void setUp() throws Exception {
        // Generate a test key
        testKey = FernetKey.generateSeed();
    }
    
    @After
    public void tearDown() throws Exception {
        // Clean up any temporary files if needed
    }
    
    /**
     * Test that keys generated by FernetKey.java can be used by Python's cryptography.fernet
     */
    @Test
    public void testKeyGenerationCompatibility() throws Exception {
        // Execute Python script to verify the key
        ProcessBuilder pb = new ProcessBuilder("python3", "-c", PYTHON_SCRIPT, "verify_key", testKey);
        Process process = pb.start();
        
        // Read all output
        String output = readProcessOutput(process);
        
        // Wait for the process to complete
        int exitCode = process.waitFor();
        
        // Verify
        assertEquals("Python process should exit with code 0", 0, exitCode);
        assertTrue("Output should contain KEY_VALID", output.contains("KEY_VALID"));
    }
    
    /**
     * Test that tokens generated by FernetKey.java can be decrypted by Python's cryptography.fernet
     */
    @Test
    public void testJavaEncryptionPythonDecryption() throws Exception {
        // Encrypt data using Java
        byte[] data = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        String token = FernetKey.encrypt(testKey, data);
        
        // Execute Python script to decrypt the token
        ProcessBuilder pb = new ProcessBuilder("python3", "-c", PYTHON_SCRIPT, "decrypt", testKey, token);
        Process process = pb.start();
        
        // Read all output
        String decryptedData = readProcessOutput(process);
        
        // Wait for the process to complete
        int exitCode = process.waitFor();
        
        // Verify
        assertEquals("Python process should exit with code 0", 0, exitCode);
        assertTrue("Decrypted data should match original", decryptedData.contains(TEST_DATA));
    }
    
    /**
     * Test that tokens generated by Python's cryptography.fernet can be decrypted by FernetKey.java
     */
    @Test
    public void testPythonEncryptionJavaDecryption() throws Exception {
        // Execute Python script to encrypt the data
        ProcessBuilder pb = new ProcessBuilder("python3", "-c", PYTHON_SCRIPT, "encrypt", testKey, TEST_DATA);
        Process process = pb.start();
        
        // Read all output (encrypted token)
        String token = readProcessOutput(process);
        
        // Wait for the process to complete
        int exitCode = process.waitFor();
        
        // Verify Python encryption worked
        assertEquals("Python process should exit with code 0", 0, exitCode);
        assertNotNull("Token should not be null", token);
        
        // Decrypt using Java
        byte[] decryptedData = FernetKey.decrypt(testKey, token.trim());
        String decryptedString = new String(decryptedData, StandardCharsets.UTF_8);
        
        // Verify
        assertEquals("Decrypted data should match original", TEST_DATA, decryptedString);
    }
    
    /**
     * Test error handling for invalid tokens
     */
    @Test(expected = SecurityException.class)
    public void testInvalidToken() throws Exception {
        // Generate a valid token
        byte[] data = TEST_DATA.getBytes(StandardCharsets.UTF_8);
        String token = FernetKey.encrypt(testKey, data);
        
        // Corrupt the token by changing a character
        String corruptedToken = token.substring(0, token.length() - 1) + "X";
        
        // This should throw a SecurityException
        FernetKey.decrypt(testKey, corruptedToken);
    }
    
    /**
     * Test error handling for expired tokens
     */
    @Test
    public void testExpiredToken() throws Exception {
        // Execute Python script to create an expired token
        ProcessBuilder pb = new ProcessBuilder("python3", "-c", PYTHON_SCRIPT, "create_expired_token", testKey, TEST_DATA);
        Process process = pb.start();
        
        // Read all output (expired token)
        String expiredToken = readProcessOutput(process);
        
        // Wait for the process to complete
        int exitCode = process.waitFor();
        
        // Verify Python script worked
        assertEquals("Python process should exit with code 0", 0, exitCode);
        assertNotNull("Token should not be null", expiredToken);
        
        // Attempt to decrypt the expired token
        boolean exceptionThrown = false;
        try {
            FernetKey.decrypt(testKey, expiredToken.trim());
        } catch (SecurityException e) {
            exceptionThrown = true;
            assertTrue("Exception message should mention expiration",
                      e.getMessage().toLowerCase().contains("expired"));
        }
        
        assertTrue("SecurityException should be thrown for expired token", exceptionThrown);
    }
    
    /**
     * Helper method to read all output from a process
     */
    private String readProcessOutput(Process process) throws Exception {
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
        }
        
        // Also check for any errors
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                System.err.println("Python error: " + line);
            }
        }
        
        return output.toString().trim();
    }
}

// Made with Bob
