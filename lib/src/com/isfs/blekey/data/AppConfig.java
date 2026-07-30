/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.data;

/**
 * Application-wide configuration for HKDF key derivation parameters and CTAP mode.
 *
 * <p>Owns the context string ("info" in RFC 5869 §3.2) used by
 * {@code KeyUtils.getPasskeySeed}.  The info string provides deployment-level
 * domain separation: credentials created under one value cannot be decrypted
 * by an authenticator using a different value.
 *
 * <p>Also controls whether the authenticator advertises CTAP1/U2F compatibility
 * in its {@code getInfo} response.
 *
 * <p>Callers may construct a custom instance via
 * {@link #AppConfig(String, boolean)} or use the shared singleton
 * {@link #getDefault()} which returns the built-in defaults.
 */
public class AppConfig {

    /** Default info string — matches the value hard-coded before this feature was added. */
    public static final String DEFAULT_INFO = "FIDO2-PASSKEY-SEED";

    /** Minimum acceptable length for the info string (characters, not bytes). */
    public static final int MIN_INFO_LENGTH = 8;

    /** Default CTAP mode: false = CTAP2 (FIDO_2_1). */
    public static final boolean DEFAULT_CTAP1_COMPAT = false;

    private static final AppConfig DEFAULT = new AppConfig(null, DEFAULT_CTAP1_COMPAT);

    private final String  info;
    private final boolean ctap1CompatMode;

    /**
     * Creates an AppConfig with the given HKDF info and CTAP mode.
     * If {@code info} is null or shorter than {@link #MIN_INFO_LENGTH} characters,
     * {@link #DEFAULT_INFO} is used instead.
     */
    public AppConfig(String info, boolean ctap1CompatMode) {
        this.info           = (info != null && info.length() >= MIN_INFO_LENGTH) ? info : DEFAULT_INFO;
        this.ctap1CompatMode = ctap1CompatMode;
    }

    /**
     * Convenience constructor that defaults {@code ctap1CompatMode} to
     * {@link #DEFAULT_CTAP1_COMPAT}.
     */
    public AppConfig(String info) {
        this(info, DEFAULT_CTAP1_COMPAT);
    }

    /**
     * Returns the UTF-8 info string for HKDF domain separation.
     *
     * @return a non-null string of at least {@value #MIN_INFO_LENGTH} characters
     */
    public String getInfo() {
        return info;
    }

    /**
     * Returns {@code true} when the CTAP1/U2F compatibility mode is active.
     * In this mode {@code getInfo} advertises {@code U2F_V2} / {@code FIDO_2_0}
     * without PIN/UV protocols.  Default is {@code false} (full CTAP2).
     */
    public boolean isCtap1CompatMode() {
        return ctap1CompatMode;
    }

    /** Returns the shared default instance backed by {@link #DEFAULT_INFO}. */
    public static AppConfig getDefault() {
        return DEFAULT;
    }
}
