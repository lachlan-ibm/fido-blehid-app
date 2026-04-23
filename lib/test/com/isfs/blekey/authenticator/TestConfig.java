/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Utility class for loading test configuration properties.
 */
public class TestConfig {
    
    private static final String CONFIG_FILE = "/test-config.properties";
    private static Properties properties;
    
    static {
        loadProperties();
    }
    
    /**
     * Loads the test configuration properties from the properties file.
     */
    private static void loadProperties() {
        properties = new Properties();
        try (InputStream input = TestConfig.class.getResourceAsStream(CONFIG_FILE)) {
            if (input != null) {
                properties.load(input);
            } else {
                System.err.println("Unable to find " + CONFIG_FILE);
            }
        } catch (IOException e) {
            System.err.println("Error loading test configuration: " + e.getMessage());
        }
    }
    
    /**
     * Gets a property value as a string.
     *
     * @param key The property key
     * @return The property value, or null if not found
     */
    public static String getProperty(String key) {
        return properties.getProperty(key);
    }
    
    /**
     * Gets a property value as a string, with a default value if not found.
     *
     * @param key The property key
     * @param defaultValue The default value to return if the property is not found
     * @return The property value, or the default value if not found
     */
    public static String getProperty(String key, String defaultValue) {
        return properties.getProperty(key, defaultValue);
    }
    
    /**
     * Gets a property value as an integer.
     *
     * @param key The property key
     * @param defaultValue The default value to return if the property is not found or not a valid integer
     * @return The property value as an integer, or the default value if not found or not a valid integer
     */
    public static int getIntProperty(String key, int defaultValue) {
        String value = getProperty(key);
        if (value == null) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }
    
    /**
     * Gets a property value as a boolean.
     *
     * @param key The property key
     * @param defaultValue The default value to return if the property is not found
     * @return The property value as a boolean, or the default value if not found
     */
    public static boolean getBooleanProperty(String key, boolean defaultValue) {
        String value = getProperty(key);
        if (value == null) {
            return defaultValue;
        }
        return Boolean.parseBoolean(value);
    }
    
    /**
     * Gets the test key algorithm.
     *
     * @return The test key algorithm
     */
    public static String getKeyAlgorithm() {
        return getProperty("test.key.algorithm", "EC");
    }
    
    /**
     * Gets the test key size.
     *
     * @return The test key size
     */
    public static int getKeySize() {
        return getIntProperty("test.key.size", 256);
    }
    
    /**
     * Gets the test attestation type.
     *
     * @return The test attestation type
     */
    public static String getAttestationType() {
        return getProperty("test.attestation.type", "packed");
    }
    
    /**
     * Gets the test relying party ID.
     *
     * @return The test relying party ID
     */
    public static String getRelyingPartyId() {
        return getProperty("test.rp.id", "example.com");
    }
    
    /**
     * Gets the test relying party name.
     *
     * @return The test relying party name
     */
    public static String getRelyingPartyName() {
        return getProperty("test.rp.name", "Example Relying Party");
    }
    
    /**
     * Gets the test user ID.
     *
     * @return The test user ID
     */
    public static String getUserId() {
        return getProperty("test.user.id", "user123");
    }
    
    /**
     * Gets the test user name.
     *
     * @return The test user name
     */
    public static String getUserName() {
        return getProperty("test.user.name", "testuser@example.com");
    }
    
    /**
     * Gets the test user display name.
     *
     * @return The test user display name
     */
    public static String getUserDisplayName() {
        return getProperty("test.user.displayName", "Test User");
    }
    
    /**
     * Gets the test challenge.
     *
     * @return The test challenge
     */
    public static String getChallenge() {
        return getProperty("test.challenge", "challenge123");
    }
    
    /**
     * Gets the test timeout in milliseconds.
     *
     * @return The test timeout in milliseconds
     */
    public static int getTimeout() {
        return getIntProperty("test.timeout", 60000);
    }
}

// Made with Bob
