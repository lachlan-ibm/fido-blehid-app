/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.authenticator.implapi.pin;

import com.isfs.blekey.util.KeyUtils;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for CTAP 2.3 PIN/UV auth protocols one (§6.5.6) and two (§6.5.7).
 * Expected values are computed independently of the code under test.
 */
public class PinUvAuthProtocolTest {

    private final PinUvAuthProtocol p1 = new PinUvAuthProtocolOne();
    private final PinUvAuthProtocol p2 = new PinUvAuthProtocolTwo();

    // ---- helpers ----

    private static byte[] hmac(byte[] key, byte[] msg) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(msg);
    }

    /** RFC 5869 HKDF-SHA-256, salt = 32 zero bytes, L = 32 (single block). */
    private static byte[] hkdf32(byte[] ikm, String info) throws Exception {
        byte[] prk = hmac(new byte[32], ikm);
        byte[] infoBytes = info.getBytes(StandardCharsets.US_ASCII);
        byte[] in = Arrays.copyOf(infoBytes, infoBytes.length + 1);
        in[in.length - 1] = 0x01;
        return hmac(prk, in);
    }

    private static byte[] rawEcdh(KeyPair mine, KeyPair peer) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(mine.getPrivate());
        ka.doPhase(peer.getPublic(), true);
        return ka.generateSecret();
    }

    private static byte[] filled(int len, int v) {
        byte[] b = new byte[len];
        Arrays.fill(b, (byte) v);
        return b;
    }

    // ---- forId ----

    @Test
    public void forId_returnsMatchingProtocol() {
        assertEquals(1, PinUvAuthProtocol.forId(1).id());
        assertEquals(2, PinUvAuthProtocol.forId(2).id());
    }

    @Test
    public void forId_rejectsUnsupportedOrWrongType() {
        assertNull(PinUvAuthProtocol.forId(0));
        assertNull(PinUvAuthProtocol.forId(3));
        assertNull(PinUvAuthProtocol.forId(null));
        assertNull(PinUvAuthProtocol.forId("2"));
    }

    // ---- decapsulate / kdf ----

    @Test
    public void protocolOne_decapsulate_isSha256OfZ_andSymmetric() throws Exception {
        KeyPair a = KeyUtils.generateKeyPair("EC", 256);
        KeyPair b = KeyUtils.generateKeyPair("EC", 256);

        byte[] s1 = p1.decapsulate(b.getPublic(), a.getPrivate());
        byte[] s2 = p1.decapsulate(a.getPublic(), b.getPrivate());

        assertArrayEquals(s1, s2);
        assertArrayEquals(MessageDigest.getInstance("SHA-256").digest(rawEcdh(a, b)), s1);
    }

    @Test
    public void protocolTwo_decapsulate_isTwoSeparateHkdfCalls_andSymmetric() throws Exception {
        KeyPair a = KeyUtils.generateKeyPair("EC", 256);
        KeyPair b = KeyUtils.generateKeyPair("EC", 256);

        byte[] s1 = p2.decapsulate(b.getPublic(), a.getPrivate());
        byte[] s2 = p2.decapsulate(a.getPublic(), b.getPrivate());

        assertEquals(64, s1.length);
        assertArrayEquals(s1, s2);

        byte[] z = rawEcdh(a, b);
        byte[] expected = new byte[64];
        System.arraycopy(hkdf32(z, "CTAP2 HMAC key"), 0, expected, 0, 32);
        System.arraycopy(hkdf32(z, "CTAP2 AES key"), 0, expected, 32, 32);
        assertArrayEquals(expected, s1);
    }

    // ---- encrypt / decrypt ----

    @Test
    public void protocolOne_encryptDecrypt_roundTrip_noIvPrefix() throws Exception {
        byte[] secret = filled(32, 0x11);
        byte[] plain = filled(32, 0x22);

        byte[] ct = p1.encrypt(secret, plain);

        assertEquals(32, ct.length);
        assertArrayEquals(ct, p1.encrypt(secret, plain));   // zero IV: deterministic
        assertArrayEquals(plain, p1.decrypt(secret, ct));
    }

    @Test
    public void protocolOne_decrypt_rejectsNonBlockMultiple() {
        assertThrows(GeneralSecurityException.class,
            () -> p1.decrypt(filled(32, 0x11), new byte[15]));
    }

    @Test
    public void protocolTwo_encryptDecrypt_roundTrip_withRandomIvPrefix() throws Exception {
        byte[] secret = filled(64, 0x11);
        byte[] plain = filled(32, 0x22);

        byte[] ct1 = p2.encrypt(secret, plain);
        byte[] ct2 = p2.encrypt(secret, plain);

        assertEquals(16 + 32, ct1.length);                  // iv || ct
        assertFalse(Arrays.equals(ct1, ct2));               // fresh random IV each call
        assertArrayEquals(plain, p2.decrypt(secret, ct1));
        assertArrayEquals(plain, p2.decrypt(secret, ct2));
    }

    @Test
    public void protocolTwo_encrypt_usesOnlyAesHalfOfSharedSecret() throws Exception {
        byte[] plain = filled(32, 0x22);
        byte[] secretA = filled(64, 0x11);
        byte[] secretB = secretA.clone();
        Arrays.fill(secretB, 0, 32, (byte) 0x77);           // change HMAC half only

        assertArrayEquals(plain, p2.decrypt(secretB, p2.encrypt(secretA, plain)));
    }

    @Test
    public void protocolTwo_decrypt_rejectsInputShorterThanIv() {
        assertThrows(GeneralSecurityException.class,
            () -> p2.decrypt(filled(64, 0x11), new byte[15]));
    }

    // ---- authenticate / verify ----

    @Test
    public void protocolOne_authenticate_isFirst16BytesOfHmac_andVerifies() throws Exception {
        byte[] key = filled(32, 0x33);
        byte[] msg = filled(32, 0x44);

        byte[] sig = p1.authenticate(key, msg);

        assertArrayEquals(Arrays.copyOf(hmac(key, msg), 16), sig);
        assertTrue(p1.verify(key, msg, sig));
    }

    @Test
    public void protocolOne_verify_rejectsWrongSignatureAndWrongLength() throws Exception {
        byte[] key = filled(32, 0x33);
        byte[] msg = filled(32, 0x44);

        assertFalse(p1.verify(key, msg, new byte[16]));
        assertFalse(p1.verify(key, msg, hmac(key, msg)));   // full 32 bytes not accepted
        assertFalse(p1.verify(key, msg, null));
    }

    @Test
    public void protocolTwo_authenticate_isFull32ByteHmac_andVerifies() throws Exception {
        byte[] key = filled(32, 0x33);
        byte[] msg = filled(32, 0x44);

        byte[] sig = p2.authenticate(key, msg);

        assertArrayEquals(hmac(key, msg), sig);
        assertTrue(p2.verify(key, msg, sig));
    }

    @Test
    public void protocolTwo_authenticate_truncatesKeyLongerThan32() throws Exception {
        byte[] sharedSecret = filled(64, 0x33);
        byte[] msg = filled(32, 0x44);

        assertArrayEquals(hmac(Arrays.copyOf(sharedSecret, 32), msg),
            p2.authenticate(sharedSecret, msg));
    }

    @Test
    public void protocolTwo_verify_rejectsTruncated16ByteSignature() throws Exception {
        byte[] key = filled(32, 0x33);
        byte[] msg = filled(32, 0x44);

        assertFalse(p2.verify(key, msg, Arrays.copyOf(hmac(key, msg), 16)));
        assertFalse(p2.verify(key, msg, new byte[32]));
        assertFalse(p2.verify(key, msg, null));
    }

    @Test
    public void protocols_doNotAcceptEachOthersSignatures() throws Exception {
        byte[] key = filled(32, 0x33);
        byte[] msg = filled(32, 0x44);

        assertFalse(p2.verify(key, msg, p1.authenticate(key, msg)));
        assertFalse(p1.verify(key, msg, p2.authenticate(key, msg)));
    }
}
