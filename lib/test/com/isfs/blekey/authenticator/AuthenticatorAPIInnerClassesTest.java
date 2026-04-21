/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator;

import com.isfs.blekey.ctap.Ctap2StatusCode;
import com.isfs.blekey.data.Passkey;
import com.isfs.blekey.util.KeyUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for AuthenticatorAPI inner classes.
 * Phase 1 of coverage improvement plan - targeting 0% → 100% coverage for:
 * - AuthenticationContext
 * - PinAuthException
 */
public class AuthenticatorAPIInnerClassesTest {

    @TempDir
    Path tempDir;
    
    private Passkey testPasskey;
    private PublicKey testPlatformKey;

    @BeforeEach
    public void setUp() throws Exception {
        System.setProperty("FIDO2_HOME", tempDir.toString());
        
        KeyPair keyPair = KeyUtils.generateKeyPair("EC", 256);
        testPlatformKey = keyPair.getPublic();
        
        File passkeyFile = tempDir.resolve("test.passkey").toFile();
        byte[] pinHash = new byte[32];
        java.security.SecureRandom random = new java.security.SecureRandom();
        random.nextBytes(pinHash);
        testPasskey = Passkey.generatePasskey(pinHash, passkeyFile);
    }


    /**
     * Test PinAuthException constructor with message and status code (lines 348-351)
     */
    @Test
    public void testPinAuthException_Constructor_WithMessageAndStatusCode() throws Exception {
        Class<?> exceptionClass = Class.forName("com.isfs.blekey.authenticator.AuthenticatorAPI$PinAuthException");
        Constructor<?> constructor = exceptionClass.getDeclaredConstructor(String.class, Ctap2StatusCode.class);
        constructor.setAccessible(true);
        
        String testMessage = "PIN authentication failed";
        Ctap2StatusCode testCode = Ctap2StatusCode.PIN_INVALID;
        
        Exception exception = (Exception) constructor.newInstance(testMessage, testCode);
        
        assertNotNull(exception);
        assertEquals(testMessage, exception.getMessage());
    }

    /**
     * Test PinAuthException code field retrieval
     */
    @Test
    public void testPinAuthException_CodeField_ReturnsCorrectValue() throws Exception {
        Class<?> exceptionClass = Class.forName("com.isfs.blekey.authenticator.AuthenticatorAPI$PinAuthException");
        Constructor<?> constructor = exceptionClass.getDeclaredConstructor(String.class, Ctap2StatusCode.class);
        constructor.setAccessible(true);
        
        String testMessage = "PIN blocked";
        Ctap2StatusCode testCode = Ctap2StatusCode.PIN_BLOCKED;
        
        Exception exception = (Exception) constructor.newInstance(testMessage, testCode);
        
        Field codeField = exceptionClass.getDeclaredField("code");
        codeField.setAccessible(true);
        Ctap2StatusCode retrievedCode = (Ctap2StatusCode) codeField.get(exception);
        
        assertEquals(testCode, retrievedCode);
    }

    /**
     * Additional test: Verify PinAuthException with different error codes
     */
    @Test
    public void testPinAuthException_DifferentErrorCodes_StoresCorrectly() throws Exception {
        Class<?> exceptionClass = Class.forName("com.isfs.blekey.authenticator.AuthenticatorAPI$PinAuthException");
        Constructor<?> constructor = exceptionClass.getDeclaredConstructor(String.class, Ctap2StatusCode.class);
        constructor.setAccessible(true);
        
        Ctap2StatusCode[] testCodes = {
            Ctap2StatusCode.PIN_INVALID,
            Ctap2StatusCode.PIN_BLOCKED,
            Ctap2StatusCode.PIN_AUTH_INVALID,
            Ctap2StatusCode.PIN_AUTH_BLOCKED
        };
        
        Field codeField = exceptionClass.getDeclaredField("code");
        codeField.setAccessible(true);
        
        for (Ctap2StatusCode testCode : testCodes) {
            Exception exception = (Exception) constructor.newInstance("Test message", testCode);
            Ctap2StatusCode retrievedCode = (Ctap2StatusCode) codeField.get(exception);
            assertEquals(testCode, retrievedCode, "Code should match for " + testCode);
        }
    }

    /**
     * Additional test: Verify PinAuthException inheritance from Exception
     */
    @Test
    public void testPinAuthException_InheritsFromException() throws Exception {
        Class<?> exceptionClass = Class.forName("com.isfs.blekey.authenticator.AuthenticatorAPI$PinAuthException");
        
        assertTrue(Exception.class.isAssignableFrom(exceptionClass));
    }

    /**
     * Additional test: Verify PinAuthException is a static inner class
     */
    @Test
    public void testPinAuthException_IsStaticInnerClass() throws Exception {
        Class<?> exceptionClass = Class.forName("com.isfs.blekey.authenticator.AuthenticatorAPI$PinAuthException");
        
        assertTrue(java.lang.reflect.Modifier.isStatic(exceptionClass.getModifiers()));
    }
}

// Made with Bob
