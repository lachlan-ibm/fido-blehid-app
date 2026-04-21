/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.credential.sdjwt;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for SelectiveDisclosureBuilder.
 * Tests SD-JWT disclosure filtering and hash verification.
 */
public class SelectiveDisclosureBuilderTest {
    
    private static final String TEST_ISSUER_JWT = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZTppc3N1ZXIifQ.sig";
    
    @Test
    public void testBuildPresentation_WithSelectedClaims() throws Exception {
        String[] allDisclosures = {
            "WyJzYWx0MSIsIm5hbWUiLCJKb2huIERvZSJd",  // ["salt1","name","John Doe"]
            "WyJzYWx0MiIsImFnZSIsIjMwIl0",          // ["salt2","age","30"]
            "WyJzYWx0MyIsImVtYWlsIiwidGVzdEBleGFtcGxlLmNvbSJd"  // ["salt3","email","test@example.com"]
        };
        
        Set<String> selectedClaims = new HashSet<>(Arrays.asList("name", "age"));
        
        String presentation = SelectiveDisclosureBuilder.buildPresentation(
            TEST_ISSUER_JWT, allDisclosures, selectedClaims);
        
        assertNotNull(presentation);
        assertTrue(presentation.startsWith(TEST_ISSUER_JWT));
        assertTrue(presentation.contains("~"));
        
        // Should contain 2 disclosures (name and age)
        String[] parts = presentation.split("~");
        assertTrue(parts.length >= 3); // issuer JWT + 2 disclosures
    }
    
    @Test
    public void testBuildPresentation_NoDisclosures() throws Exception {
        String[] allDisclosures = {};
        Set<String> selectedClaims = new HashSet<>(Arrays.asList("name"));
        
        String presentation = SelectiveDisclosureBuilder.buildPresentation(
            TEST_ISSUER_JWT, allDisclosures, selectedClaims);
        
        assertEquals(TEST_ISSUER_JWT, presentation);
    }
    
    @Test
    public void testBuildPresentation_NoSelectedClaims() throws Exception {
        String[] allDisclosures = {
            "WyJzYWx0MSIsIm5hbWUiLCJKb2huIERvZSJd"
        };
        Set<String> selectedClaims = new HashSet<>();
        
        String presentation = SelectiveDisclosureBuilder.buildPresentation(
            TEST_ISSUER_JWT, allDisclosures, selectedClaims);
        
        assertEquals(TEST_ISSUER_JWT, presentation);
    }
    
    @Test
    public void testBuildPresentation_NullIssuerJwt() {
        String[] allDisclosures = {"WyJzYWx0MSIsIm5hbWUiLCJKb2huIl0"};
        Set<String> selectedClaims = new HashSet<>(Arrays.asList("name"));
        
        assertThrows(SdJwtException.class, () -> {
            SelectiveDisclosureBuilder.buildPresentation(null, allDisclosures, selectedClaims);
        });
    }
    
    @Test
    public void testBuildPresentation_EmptyIssuerJwt() {
        String[] allDisclosures = {"WyJzYWx0MSIsIm5hbWUiLCJKb2huIl0"};
        Set<String> selectedClaims = new HashSet<>(Arrays.asList("name"));
        
        assertThrows(SdJwtException.class, () -> {
            SelectiveDisclosureBuilder.buildPresentation("", allDisclosures, selectedClaims);
        });
    }
    
    @Test
    public void testBuildPresentation_NullDisclosures() throws Exception {
        Set<String> selectedClaims = new HashSet<>(Arrays.asList("name"));
        
        String presentation = SelectiveDisclosureBuilder.buildPresentation(
            TEST_ISSUER_JWT, null, selectedClaims);
        
        assertEquals(TEST_ISSUER_JWT, presentation);
    }
    
    @Test
    public void testBuildPresentation_NullSelectedClaims() throws Exception {
        String[] allDisclosures = {"WyJzYWx0MSIsIm5hbWUiLCJKb2huIl0"};
        
        String presentation = SelectiveDisclosureBuilder.buildPresentation(
            TEST_ISSUER_JWT, allDisclosures, null);
        
        assertEquals(TEST_ISSUER_JWT, presentation);
    }
    
    @Test
    public void testBuildPresentationWithKeyBinding() throws Exception {
        String[] allDisclosures = {
            "WyJzYWx0MSIsIm5hbWUiLCJKb2huIl0"
        };
        Set<String> selectedClaims = new HashSet<>(Arrays.asList("name"));
        String keyBindingJwt = "eyJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJ2ZXJpZmllciJ9.kb_sig";
        
        String presentation = SelectiveDisclosureBuilder.buildPresentationWithKeyBinding(
            TEST_ISSUER_JWT, allDisclosures, selectedClaims, keyBindingJwt);
        
        assertNotNull(presentation);
        assertTrue(presentation.endsWith("~" + keyBindingJwt));
    }
    
    @Test
    public void testBuildPresentationWithKeyBinding_NoKeyBinding() throws Exception {
        String[] allDisclosures = {"WyJzYWx0MSIsIm5hbWUiLCJKb2huIl0"};
        Set<String> selectedClaims = new HashSet<>(Arrays.asList("name"));
        
        String presentation = SelectiveDisclosureBuilder.buildPresentationWithKeyBinding(
            TEST_ISSUER_JWT, allDisclosures, selectedClaims, null);
        
        assertNotNull(presentation);
        assertFalse(presentation.endsWith("~"));
    }
    
    @Test
    public void testBuildPresentationWithKeyBinding_EmptyKeyBinding() throws Exception {
        String[] allDisclosures = {"WyJzYWx0MSIsIm5hbWUiLCJKb2huIl0"};
        Set<String> selectedClaims = new HashSet<>(Arrays.asList("name"));
        
        String presentation = SelectiveDisclosureBuilder.buildPresentationWithKeyBinding(
            TEST_ISSUER_JWT, allDisclosures, selectedClaims, "");
        
        assertNotNull(presentation);
        assertFalse(presentation.endsWith("~"));
    }
    
    @Test
    public void testComputeSdHash() throws Exception {
        String[] disclosures = {
            "WyJzYWx0MSIsIm5hbWUiLCJKb2huIl0",
            "WyJzYWx0MiIsImFnZSIsIjMwIl0"
        };
        
        String sdHash = SelectiveDisclosureBuilder.computeSdHash(disclosures);
        
        assertNotNull(sdHash);
        assertFalse(sdHash.isEmpty());
        assertFalse(sdHash.contains("=")); // Base64url without padding
    }
    
    @Test
    public void testComputeSdHash_NoDisclosures() throws Exception {
        String[] disclosures = {};
        
        String sdHash = SelectiveDisclosureBuilder.computeSdHash(disclosures);
        
        assertEquals("", sdHash);
    }
    
    @Test
    public void testComputeSdHash_NullDisclosures() throws Exception {
        String sdHash = SelectiveDisclosureBuilder.computeSdHash(null);
        
        assertEquals("", sdHash);
    }
    
    @Test
    public void testComputeSdHash_Deterministic() throws Exception {
        String[] disclosures = {
            "WyJzYWx0MSIsIm5hbWUiLCJKb2huIl0",
            "WyJzYWx0MiIsImFnZSIsIjMwIl0"
        };
        
        String hash1 = SelectiveDisclosureBuilder.computeSdHash(disclosures);
        String hash2 = SelectiveDisclosureBuilder.computeSdHash(disclosures);
        
        assertEquals(hash1, hash2);
    }
    
    @Test
    public void testExtractDisclosures_WithDisclosures() {
        String presentation = TEST_ISSUER_JWT + "~" +
            "WyJzYWx0MSIsIm5hbWUiLCJKb2huIl0~" +
            "WyJzYWx0MiIsImFnZSIsIjMwIl0~" +
            "eyJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJ2ZXJpZmllciJ9.kb_sig";
        
        String[] disclosures = SelectiveDisclosureBuilder.extractDisclosures(presentation);
        
        assertEquals(2, disclosures.length);
        assertEquals("WyJzYWx0MSIsIm5hbWUiLCJKb2huIl0", disclosures[0]);
        assertEquals("WyJzYWx0MiIsImFnZSIsIjMwIl0", disclosures[1]);
    }
    
    @Test
    public void testExtractDisclosures_OnlyIssuerJwt() {
        String presentation = TEST_ISSUER_JWT;
        
        String[] disclosures = SelectiveDisclosureBuilder.extractDisclosures(presentation);
        
        assertEquals(0, disclosures.length);
    }
    
    @Test
    public void testExtractDisclosures_NullPresentation() {
        String[] disclosures = SelectiveDisclosureBuilder.extractDisclosures(null);
        
        assertEquals(0, disclosures.length);
    }
    
    @Test
    public void testExtractDisclosures_EmptyPresentation() {
        String[] disclosures = SelectiveDisclosureBuilder.extractDisclosures("");
        
        assertEquals(0, disclosures.length);
    }
    
    @Test
    public void testIsValidPresentation_Valid() {
        String presentation = TEST_ISSUER_JWT + "~WyJzYWx0MSIsIm5hbWUiLCJKb2huIl0";
        
        assertTrue(SelectiveDisclosureBuilder.isValidPresentation(presentation));
    }
    
    @Test
    public void testIsValidPresentation_OnlyIssuerJwt() {
        assertTrue(SelectiveDisclosureBuilder.isValidPresentation(TEST_ISSUER_JWT));
    }
    
    @Test
    public void testIsValidPresentation_Null() {
        assertFalse(SelectiveDisclosureBuilder.isValidPresentation(null));
    }
    
    @Test
    public void testIsValidPresentation_Empty() {
        assertFalse(SelectiveDisclosureBuilder.isValidPresentation(""));
    }
    
    @Test
    public void testIsValidPresentation_NoJwt() {
        String presentation = "WyJzYWx0MSIsIm5hbWUiLCJKb2huIl0";
        
        assertFalse(SelectiveDisclosureBuilder.isValidPresentation(presentation));
    }
    
    @Test
    public void testBuildPresentation_FiltersByClaimName() throws Exception {
        String[] allDisclosures = {
            "WyJzYWx0MSIsIm5hbWUiLCJKb2huIl0",
            "WyJzYWx0MiIsImFnZSIsIjMwIl0",
            "WyJzYWx0MyIsImVtYWlsIiwidGVzdEBleGFtcGxlLmNvbSJd"
        };
        
        Set<String> selectedClaims = new HashSet<>(Arrays.asList("name"));
        
        String presentation = SelectiveDisclosureBuilder.buildPresentation(
            TEST_ISSUER_JWT, allDisclosures, selectedClaims);
        
        String[] extractedDisclosures = SelectiveDisclosureBuilder.extractDisclosures(presentation);
        
        // Should only have 1 disclosure (name)
        assertEquals(1, extractedDisclosures.length);
    }
    
    @Test
    public void testBuildPresentation_AllClaims() throws Exception {
        String[] allDisclosures = {
            "WyJzYWx0MSIsIm5hbWUiLCJKb2huIl0",
            "WyJzYWx0MiIsImFnZSIsIjMwIl0"
        };
        
        Set<String> selectedClaims = new HashSet<>(Arrays.asList("name", "age"));
        
        String presentation = SelectiveDisclosureBuilder.buildPresentation(
            TEST_ISSUER_JWT, allDisclosures, selectedClaims);
        
        String[] extractedDisclosures = SelectiveDisclosureBuilder.extractDisclosures(presentation);
        
        // Should have all 2 disclosures
        assertEquals(2, extractedDisclosures.length);
    }
}

// Made with Bob