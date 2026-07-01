/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.mdl;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Unit tests for MdlException.
 */
public class MdlExceptionTest {
    
    @Test
    public void testConstructorWithMessage() {
        String message = "Test error message";
        MdlException exception = new MdlException(message);
        
        assertEquals(message, exception.getMessage());
        assertNull(exception.getCause());
    }
    
    @Test
    public void testConstructorWithMessageAndCause() {
        String message = "Test error message";
        Throwable cause = new RuntimeException("Root cause");
        MdlException exception = new MdlException(message, cause);
        
        assertEquals(message, exception.getMessage());
        assertEquals(cause, exception.getCause());
    }
    
    @Test
    public void testConstructorWithCause() {
        Throwable cause = new RuntimeException("Root cause");
        MdlException exception = new MdlException(cause);
        
        assertEquals(cause, exception.getCause());
        assertTrue(exception.getMessage().contains("RuntimeException"));
    }
}

// Made with Bob
