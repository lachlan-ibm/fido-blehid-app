/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.jsonld;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link JsonLdException}.
 */
class JsonLdExceptionTest {
    
    @Test
    void testConstructorWithMessage() {
        String message = "Test error message";
        JsonLdException exception = new JsonLdException(message);
        
        assertEquals(message, exception.getMessage());
        assertNull(exception.getCause());
    }
    
    @Test
    void testConstructorWithMessageAndCause() {
        String message = "Test error message";
        Throwable cause = new RuntimeException("Root cause");
        JsonLdException exception = new JsonLdException(message, cause);
        
        assertEquals(message, exception.getMessage());
        assertEquals(cause, exception.getCause());
    }
    
    @Test
    void testConstructorWithCause() {
        Throwable cause = new RuntimeException("Root cause");
        JsonLdException exception = new JsonLdException(cause);
        
        assertEquals(cause, exception.getCause());
        assertTrue(exception.getMessage().contains("RuntimeException"));
    }
    
    @Test
    void testExceptionIsThrowable() {
        JsonLdException exception = new JsonLdException("Test");
        
        assertThrows(JsonLdException.class, () -> {
            throw exception;
        });
    }
    
    @Test
    void testExceptionCanBeCaught() {
        try {
            throw new JsonLdException("Test exception");
        } catch (JsonLdException e) {
            assertEquals("Test exception", e.getMessage());
        }
    }
    
    @Test
    void testExceptionWithNullMessage() {
        JsonLdException exception = new JsonLdException((String) null);
        assertNull(exception.getMessage());
    }
    
    @Test
    void testExceptionWithEmptyMessage() {
        String message = "";
        JsonLdException exception = new JsonLdException(message);
        assertEquals(message, exception.getMessage());
    }
}

// Made with Bob