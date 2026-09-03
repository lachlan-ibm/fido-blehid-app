# Copyright IBM 2025
#
# ProGuard / R8 rules for release builds.

# ============================================================
# java.beans — not present on Android, safe to suppress
# ============================================================
-dontwarn java.beans.ConstructorProperties
-dontwarn java.beans.Transient

# ============================================================
# BouncyCastle (bcprov-jdk18on:1.84, bcpkix-jdk18on:1.84)
#
# BC registers its algorithms through a static service table
# built from class names stored as plain strings.  R8 cannot
# see those references, so it strips the implementation
# classes.  Every KeyPairGenerator / Cipher / Signature /
# CertificateBuilder call then throws NoSuchAlgorithmException
# at runtime.  Keep the entire BC namespace by name.
# ============================================================
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# ============================================================
# SLF4J (slf4j-api:2.0.18)
# logback-android (tony19/logback-android:3.0.0)
#
# The SLF4J StaticLoggerBinder and the logback LogcatAppender
# are loaded by name from logback.xml (an asset).  R8 sees no
# code reference to these classes and removes them, which
# silently kills all library-level error logging in release.
# ============================================================
-keep class org.slf4j.** { *; }
-dontwarn org.slf4j.**
-keep class ch.qos.logback.** { *; }
-dontwarn ch.qos.logback.**

# ============================================================
# Jackson (tools.jackson.core:jackson-databind:3.1.4)
#
# Jackson uses reflection to discover fields and constructors
# on data model classes.  Keep the deserialiser infrastructure
# and suppress missing-class warnings for java.desktop types
# that are not present on Android.
# ============================================================
-keep class tools.jackson.** { *; }
-dontwarn tools.jackson.**
-keep @tools.jackson.annotation.JsonIgnoreProperties class * { *; }
-keepclassmembers class * {
    @tools.jackson.annotation.JsonProperty <fields>;
    @tools.jackson.annotation.JsonCreator <init>(...);
}

# ============================================================
# Gson (com.google.code.gson:gson:2.14.0)
# ============================================================
-keep class com.google.gson.** { *; }
-dontwarn com.google.gson.**
-keepclassmembers class * {
    @com.google.gson.annotations.SerializedName <fields>;
}

# ============================================================
# OkHttp3 (okhttp:4.12.0)
# ============================================================
-keep class okhttp3.** { *; }
-dontwarn okhttp3.**
-dontwarn okio.**

# ============================================================
# jose4j (org.bitbucket.b_c:jose4j:0.9.6)
#
# Loads algorithm implementations by string name via
# AlgorithmFactory.  Keep the whole package.
# ============================================================
-keep class org.jose4j.** { *; }
-dontwarn org.jose4j.**

# ============================================================
# COSE-Java (com.augustcellars.cose:cose-java:1.1.0)
# ============================================================
-keep class COSE.** { *; }
-dontwarn COSE.**

# ============================================================
# Titanium JSON-LD / Jakarta JSON
# ============================================================
-keep class com.apicatalog.** { *; }
-dontwarn com.apicatalog.**
-keep class org.glassfish.json.** { *; }
-dontwarn org.glassfish.**
-keep class jakarta.json.** { *; }
-dontwarn jakarta.**

# ============================================================
# App library — com.isfs.blekey (lib module)
#
# Passkey, KeyUtils, CertUtils, Cbor, StashCipher, FileUtils
# and the authenticator chain use:
#   - Unchecked casts on Map<?,?> decoded from CBOR
#   - instanceof checks on deserialized objects
#   - KeyStore.getKey() / getCertificate() by string alias
#   - Security.getProvider() / insertProviderAt() by name
# R8 must not rename or remove any of these classes.
# ============================================================
-keep class com.isfs.blekey.** { *; }
-dontwarn com.isfs.blekey.**