/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.authenticator;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import com.isfs.blekey.util.CertUtils;

import jakarta.json.Json;
import jakarta.json.JsonObject;

/**
 * Helper class for FIDO2 Authenticator tests.
 * Provides common methods and fixtures used across test classes.
 */
public class TestHelper {

    /**
     * Creates a test key pair with the specified algorithm.
     *
     * @param algorithm The algorithm to use (e.g., "EC", "RSA")
     * @return A new key pair
     * @throws NoSuchAlgorithmException if the algorithm is not available
     */
    public static KeyPair createTestKeyPair(String algorithm) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);
        return keyGen.generateKeyPair();
    }
    
    /**
     * Creates a test certificate authority key pair and certificate.
     *
     * @return An array containing the key pair at index 0 and the certificate at index 1
     * @throws Exception if an error occurs during creation
     */
    public static Object[] createTestCA() throws Exception {
        KeyPair caKeyPair = createTestKeyPair("EC");
        X509Certificate caCert = CertUtils.generateCaCert("CN=Test CA", caKeyPair, 365, true );
        return new Object[] { caKeyPair, caCert };
    }
    
    /**
     * Creates a JSON string with credential creation options for testing.
     *
     * @return A JSON string with credential creation options
     */
    public static String createCredentialCreationOptionsJson() {
        return Json.createObjectBuilder()
                .add("rp", Json.createObjectBuilder()
                    .add("id", "example.com")
                    .add("name", "Example RP"))
                .add("user", Json.createObjectBuilder()
                    .add("id", "dXNlcjEyMw==") // Base64 encoded "user123"
                    .add("name", "testuser@example.com")
                    .add("displayName", "Test User"))
                .add("challenge", "Y2hhbGxlbmdlMTIz") // Base64 encoded "challenge123"
                .add("pubKeyCredParams", Json.createArrayBuilder()
                    .add(Json.createObjectBuilder()
                        .add("type", "public-key")
                        .add("alg", -7))) // ES256
                .add("timeout", 60000)
                .add("attestation", "direct")
                .build().toString();
    }
    
    /**
     * Creates a JSON string with assertion options for testing.
     *
     * @return A JSON string with assertion options
     */
    public static String createAssertionOptionsJson() {
        return Json.createObjectBuilder()
                .add("publicKey", Json.createObjectBuilder()
                    .add("rpId", "example.com")
                    .add("challenge", "Y2hhbGxlbmdlMTIz") // Base64 encoded "challenge123"
                    .add("timeout", 60000)
                    .add("allowCredentials", Json.createArrayBuilder()
                        .add(Json.createObjectBuilder()
                            .add("type", "public-key")
                            .add("id", "Y3JlZGVudGlhbElkMTIz")))) // Base64 encoded "credentialId123"
                .build().toString();
    }
    
    /**
     * Creates a map with public key parameters for testing.
     *
     * @param isAssertion true for assertion parameters, false for credential creation parameters
     * @return A map with public key parameters
     */
    public static Map<String, Object> createPublicKeyMap(boolean isAssertion) {
        Map<String, Object> publicKey = new HashMap<>();
        
        if (isAssertion) {
            publicKey.put("rpId", "example.com");
        } else {
            Map<String, Object> rp = new HashMap<>();
            rp.put("id", "example.com");
            rp.put("name", "Example RP");
            publicKey.put("rp", rp);
            publicKey.put("attestation", "none");
        }
        
        publicKey.put("challenge", "challenge123".getBytes());
        return publicKey;
    }
    
    /**
     * Creates a client data JSON object for testing.
     *
     * @param isAssertion true for assertion client data, false for credential creation client data
     * @return A client data JSON object
     */
    public static JsonObject createClientDataJson(boolean isAssertion) {
        String type = isAssertion ? "webauthn.get" : "webauthn.create";
        
        return Json.createObjectBuilder()
                .add("origin", "https://example.com")
                .add("challenge", "Y2hhbGxlbmdlMTIz") // Base64 encoded "challenge123"
                .add("type", type)
                .build();
    }
}

// Made with Bob
