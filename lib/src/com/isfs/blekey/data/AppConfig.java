/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.data;

/**
 * Application-wide configuration for HKDF key derivation parameters.
 *
 * <p>Owns the context string ("info" in RFC 5869 §3.2) used by
 * {@code KeyUtils.getPasskeySeed}.  The info string provides deployment-level
 * domain separation: credentials created under one value cannot be decrypted
 * by an authenticator using a different value.
 *
 * <p>Callers may construct a custom instance via {@link #AppConfig(String)} or
 * use the shared singleton {@link #getDefault()} which returns the built-in
 * {@value #DEFAULT_INFO} value.
 */
public class AppConfig {

    /** Default info string — matches the value hard-coded before this feature was added. */
    public static final String DEFAULT_INFO = "FIDO2-PASSKEY-SEED";

    /** Minimum acceptable length for the info string (characters, not bytes). */
    public static final int MIN_INFO_LENGTH = 8;

    private static final AppConfig DEFAULT = new AppConfig(null);

    private final String info;

    /**
     * Creates an AppConfig.  If {@code info} is null or shorter than
     * {@link #MIN_INFO_LENGTH} characters, {@link #DEFAULT_INFO} is used instead.
     */
    public AppConfig(String info) {
        this.info = (info != null && info.length() >= MIN_INFO_LENGTH) ? info : DEFAULT_INFO;
    }

    /**
     * Returns the UTF-8 info string for HKDF domain separation.
     *
     * @return a non-null string of at least {@value #MIN_INFO_LENGTH} characters
     */
    public String getInfo() {
        return info;
    }

    /** Returns the shared default instance backed by {@link #DEFAULT_INFO}. */
    public static AppConfig getDefault() {
        return DEFAULT;
    }
}
