/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.credential.jwt;

import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for JWT operations (JwtBuilder, JwtParser, KeyBindingJwtBuilder).
 */
public class JwtOperationsTest {
    private KeyPair keyPair;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    @BeforeEach
    public void setUp() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        keyPair = keyGen.generateKeyPair();
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();
    }

    @Test
    public void testJwtBuilderBasicClaims() throws Exception {
        long now = System.currentTimeMillis() / 1000;
        
        String jwt = new JwtBuilder()
            .setIssuer("https://issuer.example.com")
            .setSubject("user123")
            .setAudience("https://audience.example.com")
            .setIssuedAt(now)
            .setExpirationTime(now + 3600)
            .setJwtId("jwt-id-123")
            .setSigningKey(privateKey)
            .build();

        assertNotNull(jwt);
        assertTrue(jwt.split("\\.").length == 3);
    }

    @Test
    public void testJwtBuilderCustomClaims() throws Exception {
        String jwt = new JwtBuilder()
            .setIssuer("https://issuer.example.com")
            .setIssuedAt(System.currentTimeMillis() / 1000)
            .setExpirationTime(System.currentTimeMillis() / 1000 + 3600)
            .setClaim("custom_claim", "custom_value")
            .setClaim("number_claim", 42)
            .setSigningKey(privateKey)
            .build();

        assertNotNull(jwt);
        
        JwtClaims claims = JwtParser.parseUnsecured(jwt);
        assertEquals("custom_value", claims.getStringClaimValue("custom_claim"));
        assertEquals(42, claims.getClaimValue("number_claim", Long.class).intValue());
    }

    @Test
    public void testJwtBuilderWithoutSigningKey() {
        JwtBuilder builder = new JwtBuilder()
            .setIssuer("https://issuer.example.com")
            .setIssuedAt(System.currentTimeMillis() / 1000)
            .setExpirationTime(System.currentTimeMillis() / 1000 + 3600);

        assertThrows(JwtException.class, builder::build);
    }

    @Test
    public void testJwtParserValidSignature() throws Exception {
        long now = System.currentTimeMillis() / 1000;
        
        String jwt = new JwtBuilder()
            .setIssuer("https://issuer.example.com")
            .setSubject("user123")
            .setIssuedAt(now)
            .setExpirationTime(now + 3600)
            .setSigningKey(privateKey)
            .build();

        JwtParser parser = new JwtParser(publicKey);
        JwtClaims claims = parser.parse(jwt);

        assertEquals("https://issuer.example.com", claims.getIssuer());
        assertEquals("user123", claims.getSubject());
    }

    @Test
    public void testJwtParserInvalidSignature() throws Exception {
        long now = System.currentTimeMillis() / 1000;
        
        String jwt = new JwtBuilder()
            .setIssuer("https://issuer.example.com")
            .setIssuedAt(now)
            .setExpirationTime(now + 3600)
            .setSigningKey(privateKey)
            .build();

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        KeyPair wrongKeyPair = keyGen.generateKeyPair();

        JwtParser parser = new JwtParser(wrongKeyPair.getPublic());
        assertThrows(JwtException.class, () -> parser.parse(jwt));
    }

    @Test
    public void testJwtParserExpiredToken() throws Exception {
        long now = System.currentTimeMillis() / 1000;
        
        String jwt = new JwtBuilder()
            .setIssuer("https://issuer.example.com")
            .setIssuedAt(now - 7200)
            .setExpirationTime(now - 3600)
            .setSigningKey(privateKey)
            .build();

        JwtParser parser = new JwtParser(publicKey);
        assertThrows(JwtException.class, () -> parser.parse(jwt));
    }

    @Test
    public void testJwtParserUnsecured() throws Exception {
        long now = System.currentTimeMillis() / 1000;
        
        String jwt = new JwtBuilder()
            .setIssuer("https://issuer.example.com")
            .setSubject("user123")
            .setClaim("custom", "value")
            .setIssuedAt(now)
            .setExpirationTime(now + 3600)
            .setSigningKey(privateKey)
            .build();

        JwtClaims claims = JwtParser.parseUnsecured(jwt);
        assertEquals("https://issuer.example.com", claims.getIssuer());
        assertEquals("user123", claims.getSubject());
        assertEquals("value", claims.getStringClaimValue("custom"));
    }

    @Test
    public void testJwtParserGetClaim() throws Exception {
        long now = System.currentTimeMillis() / 1000;
        
        String jwt = new JwtBuilder()
            .setIssuer("https://issuer.example.com")
            .setClaim("custom_claim", "test_value")
            .setIssuedAt(now)
            .setExpirationTime(now + 3600)
            .setSigningKey(privateKey)
            .build();

        JwtParser parser = new JwtParser(publicKey);
        Object claimValue = parser.getClaim(jwt, "custom_claim");
        assertEquals("test_value", claimValue);
    }

    @Test
    public void testJwtParserVerifySignature() throws Exception {
        long now = System.currentTimeMillis() / 1000;
        
        String jwt = new JwtBuilder()
            .setIssuer("https://issuer.example.com")
            .setIssuedAt(now)
            .setExpirationTime(now + 3600)
            .setSigningKey(privateKey)
            .build();

        JwtParser parser = new JwtParser(publicKey);
        assertTrue(parser.verifySignature(jwt));
    }

    @Test
    public void testKeyBindingJwtBuilder() throws Exception {
        String disclosure1 = "WyJzYWx0MSIsICJnaXZlbl9uYW1lIiwgIkpvaG4iXQ";
        String disclosure2 = "WyJzYWx0MiIsICJmYW1pbHlfbmFtZSIsICJEb2UiXQ";

        String kbJwt = new KeyBindingJwtBuilder()
            .setAudience("https://verifier.example.com")
            .setNonce("verifier-nonce-123")
            .setIssuedAtNow()
            .setExpirationTimeFromNow(300)
            .setSdHash(disclosure1, disclosure2)
            .setSigningKey(privateKey)
            .build();

        assertNotNull(kbJwt);
        
        JwtClaims claims = JwtParser.parseUnsecured(kbJwt);
        assertEquals("https://verifier.example.com", claims.getAudience().get(0));
        assertEquals("verifier-nonce-123", claims.getStringClaimValue("nonce"));
        assertNotNull(claims.getStringClaimValue("sd_hash"));
    }

    @Test
    public void testKeyBindingJwtSdHashComputation() throws Exception {
        String disclosure1 = "disclosure1";
        String disclosure2 = "disclosure2";

        KeyBindingJwtBuilder builder = new KeyBindingJwtBuilder()
            .setAudience("https://verifier.example.com")
            .setNonce("nonce")
            .setIssuedAtNow()
            .setSdHash(disclosure1, disclosure2)
            .setSigningKey(privateKey);

        String sdHash1 = builder.getSdHash();
        assertNotNull(sdHash1);

        KeyBindingJwtBuilder builder2 = new KeyBindingJwtBuilder()
            .setAudience("https://verifier.example.com")
            .setNonce("nonce")
            .setIssuedAtNow()
            .setSdHash(disclosure1, disclosure2)
            .setSigningKey(privateKey);

        String sdHash2 = builder2.getSdHash();
        assertEquals(sdHash1, sdHash2);
    }

    @Test
    public void testKeyBindingJwtCustomClaim() throws Exception {
        String kbJwt = new KeyBindingJwtBuilder()
            .setAudience("https://verifier.example.com")
            .setNonce("nonce")
            .setIssuedAtNow()
            .setExpirationTimeFromNow(300)
            .setClaim("custom", "value")
            .setSigningKey(privateKey)
            .build();

        JwtClaims claims = JwtParser.parseUnsecured(kbJwt);
        assertEquals("value", claims.getStringClaimValue("custom"));
    }

    @Test
    public void testKeyBindingJwtVerification() throws Exception {
        String kbJwt = new KeyBindingJwtBuilder()
            .setAudience("https://verifier.example.com")
            .setNonce("nonce")
            .setIssuedAtNow()
            .setExpirationTimeFromNow(300)
            .setSdHash("disclosure1")
            .setSigningKey(privateKey)
            .build();

        org.jose4j.jwt.consumer.JwtConsumer consumer = new org.jose4j.jwt.consumer.JwtConsumerBuilder()
            .setVerificationKey(publicKey)
            .setExpectedAudience("https://verifier.example.com")
            .setRequireExpirationTime()
            .setAllowedClockSkewInSeconds(30)
            .build();
        
        JwtParser parser = new JwtParser(consumer);
        JwtClaims claims = parser.parse(kbJwt);
        
        assertEquals("https://verifier.example.com", claims.getAudience().get(0));
        assertEquals("nonce", claims.getStringClaimValue("nonce"));
        assertNotNull(claims.getStringClaimValue("sd_hash"));
    }
}

// Made with Bob
