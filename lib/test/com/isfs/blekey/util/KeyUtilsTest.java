/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.util;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * Test class for KeyUtils functionality
 */
public class KeyUtilsTest {

    /**
     * Tests the EC key parameter extraction and reconstruction
     */
    public static void testECKeyReconstruction() {
        try {
            System.out.println("Testing EC key reconstruction...");
            
            // Generate a new EC key pair
            KeyPair originalKeyPair = KeyUtils.generateKeyPair("EC", 256);
            ECPrivateKey originalPrivateKey = (ECPrivateKey) originalKeyPair.getPrivate();
            ECPublicKey originalPublicKey = (ECPublicKey) originalKeyPair.getPublic();
            
            // Extract parameters
            Map<String, Object> keyParams = KeyUtils.getECPrivateKeyParameters(originalPrivateKey);
            System.out.println("Original key parameters:");
            System.out.println("  Curve: " + keyParams.get("c"));
            System.out.println("  Private value: " + keyParams.get("pv"));
            
            // Reconstruct the key
            PrivateKey reconstructedKey = KeyUtils.fromECPrivateKeyParameters(keyParams);
            ECPrivateKey reconstructedECKey = (ECPrivateKey) reconstructedKey;
            
            // Verify the reconstructed key
            boolean sameS = originalPrivateKey.getS().equals(reconstructedECKey.getS());
            boolean sameCurve = originalPrivateKey.getParams().getCurve().equals(
                reconstructedECKey.getParams().getCurve());
            
            System.out.println("Reconstruction results:");
            System.out.println("  Same S value: " + sameS);
            System.out.println("  Same curve: " + sameCurve);
            System.out.println("  Overall success: " + (sameS && sameCurve));
            
            // Generate public key from reconstructed private key
            ECPublicKey reconstructedPublicKey = KeyUtils.getPubKey(reconstructedECKey);
            
            // Verify the public key
            boolean sameX = originalPublicKey.getW().getAffineX().equals(
                reconstructedPublicKey.getW().getAffineX());
            boolean sameY = originalPublicKey.getW().getAffineY().equals(
                reconstructedPublicKey.getW().getAffineY());
            
            System.out.println("Public key verification:");
            System.out.println("  Same X coordinate: " + sameX);
            System.out.println("  Same Y coordinate: " + sameY);
            System.out.println("  Overall success: " + (sameX && sameY));
            
        } catch (Exception e) {
            System.err.println("Test failed with exception: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Tests manual reconstruction of an EC key with specific parameters
     */
    public static void testManualECKeyReconstruction() {
        try {
            System.out.println("\nTesting manual EC key reconstruction...");
            
            // Create parameters map with known values
            Map<String, Object> keyParams = new HashMap<>();
            keyParams.put("c", "secp256r1");
            
            // Example private key value (this would normally come from your application)
            // In a real scenario, this would be a specific value you want to reconstruct
            BigInteger privateValue = new BigInteger("42317523347834523489054322342342342342342354235423542354235423542", 10);
            keyParams.put("pv", privateValue);
            
            // Reconstruct the key
            PrivateKey reconstructedKey = KeyUtils.fromECPrivateKeyParameters(keyParams);
            ECPrivateKey reconstructedECKey = (ECPrivateKey) reconstructedKey;
            
            // Verify the reconstructed key
            boolean correctS = privateValue.equals(reconstructedECKey.getS());
            boolean correctCurve = "secp256r1".equals(KeyUtils.getCurveName(reconstructedECKey.getParams()));
            
            System.out.println("Manual reconstruction results:");
            System.out.println("  Correct S value: " + correctS);
            System.out.println("  Correct curve: " + correctCurve);
            System.out.println("  Overall success: " + (correctS && correctCurve));
            
            // Generate public key from reconstructed private key
            ECPublicKey publicKey = KeyUtils.getPubKey(reconstructedECKey);
            System.out.println("  Generated public key X: " + publicKey.getW().getAffineX());
            System.out.println("  Generated public key Y: " + publicKey.getW().getAffineY());
            
        } catch (Exception e) {
            System.err.println("Test failed with exception: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Main method to run the tests
     */
    public static void main(String[] args) {
        testECKeyReconstruction();
        testManualECKeyReconstruction();
    }
}

// Made with Bob
