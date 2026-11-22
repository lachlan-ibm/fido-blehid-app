/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.authenticator.implapi.pin;

import com.isfs.blekey.util.KeyUtils;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** CTAP 2.3 §6.5.4 authenticator-side PIN/UV auth protocol interface. */
interface PinUvAuthProtocol {
    /* protocol implemented; currently 1 or 2 */
    int id();

    /** ecdh + kdf. Throws on a bad peer key. */
    byte[] decapsulate(PublicKey peer, PrivateKey mine) throws GeneralSecurityException;

    byte[] encrypt(byte[] sharedSecret, byte[] plaintext) throws GeneralSecurityException;

    byte[] decrypt(byte[] sharedSecret, byte[] ciphertext) throws GeneralSecurityException;

    byte[] authenticate(byte[] key, byte[] message) throws GeneralSecurityException;

    boolean verify(byte[] key, byte[] message, byte[] signature);

    /** @return the protocol, or null if {@code id} is not an Integer 1 or 2. */
    static PinUvAuthProtocol forId(Object id) {
        if (!(id instanceof Integer)) return null;
        switch ((Integer) id) {
            case 1:  return new PinUvAuthProtocolOne();
            case 2:  return new PinUvAuthProtocolTwo();
            default: return null;
        }
    }
}

abstract class PinAuthProtocolCommon {
    static byte[] aesCbc(int mode, byte[] key32, byte[] iv, byte[] data)
            throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("AES/CBC/NoPadding");   // throws on non-multiple-of-16
        c.init(mode, new SecretKeySpec(key32, "AES"), new IvParameterSpec(iv));
        return c.doFinal(data);
    }

    static byte[] hmac(byte[] key, byte[] message) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(message);
    }
}

/** §6.5.6 */
class PinUvAuthProtocolOne extends PinAuthProtocolCommon implements PinUvAuthProtocol {

    @Override public int id() { return 1; }

    @Override
    public byte[] decapsulate(PublicKey peer, PrivateKey mine) {
        return KeyUtils.decapsulate(peer, mine);          // SHA-256(Z)
    }

    @Override
    public byte[] encrypt(byte[] sharedSecret, byte[] plaintext) throws GeneralSecurityException {
        return aesCbc(Cipher.ENCRYPT_MODE, sharedSecret, new byte[16], plaintext);
    }

    @Override
    public byte[] decrypt(byte[] sharedSecret, byte[] ciphertext) throws GeneralSecurityException {
        return aesCbc(Cipher.DECRYPT_MODE, sharedSecret, new byte[16], ciphertext);
    }

    @Override
    public byte[] authenticate(byte[] key, byte[] message) throws GeneralSecurityException {
        return Arrays.copyOf(hmac(key, message), 16);
    }

    @Override
    public boolean verify(byte[] key, byte[] message, byte[] signature) {
        try {
            return signature != null && signature.length == 16
                && MessageDigest.isEqual(signature, authenticate(key, message));
        } catch (GeneralSecurityException e) {
            return false;
        }
    }
}

/** §6.5.7 — overrides kdf, encrypt, decrypt, authenticate, verify. */
class PinUvAuthProtocolTwo extends PinAuthProtocolCommon implements PinUvAuthProtocol {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final byte[] ZERO_SALT = new byte[32];

    @Override public int id() { return 2; }

    @Override
    public byte[] decapsulate(PublicKey peer, PrivateKey mine) throws GeneralSecurityException {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(mine);
        ka.doPhase(peer, true);
        byte[] z = ka.generateSecret();                   // raw 32-byte x-coordinate
        if (z.length != 32) {
            throw new GeneralSecurityException("unexpected ECDH secret length " + z.length);
        }
        // Two separate HKDF calls, NOT one call with L=64.
        byte[] hmacKey = KeyUtils.hkdf(z, ZERO_SALT,
            "CTAP2 HMAC key".getBytes(StandardCharsets.US_ASCII), 32);
        byte[] aesKey = KeyUtils.hkdf(z, ZERO_SALT,
            "CTAP2 AES key".getBytes(StandardCharsets.US_ASCII), 32);
        byte[] out = new byte[64];
        System.arraycopy(hmacKey, 0, out, 0, 32);
        System.arraycopy(aesKey, 0, out, 32, 32);
        return out;
    }

    @Override
    public byte[] encrypt(byte[] sharedSecret, byte[] plaintext) throws GeneralSecurityException {
        byte[] aesKey = Arrays.copyOfRange(sharedSecret, 32, 64);
        byte[] iv = new byte[16];
        RANDOM.nextBytes(iv);
        byte[] ct = aesCbc(Cipher.ENCRYPT_MODE, aesKey, iv, plaintext);
        byte[] out = new byte[16 + ct.length];
        System.arraycopy(iv, 0, out, 0, 16);
        System.arraycopy(ct, 0, out, 16, ct.length);
        return out;
    }

    @Override
    public byte[] decrypt(byte[] sharedSecret, byte[] ciphertext) throws GeneralSecurityException {
        if (ciphertext == null || ciphertext.length < 16) {
            throw new GeneralSecurityException("ciphertext shorter than IV");
        }
        byte[] aesKey = Arrays.copyOfRange(sharedSecret, 32, 64);
        return aesCbc(Cipher.DECRYPT_MODE, aesKey,
            Arrays.copyOfRange(ciphertext, 0, 16),
            Arrays.copyOfRange(ciphertext, 16, ciphertext.length));
    }

    @Override
    public byte[] authenticate(byte[] key, byte[] message) throws GeneralSecurityException {
        byte[] hmacKey = key.length > 32 ? Arrays.copyOf(key, 32) : key;
        return hmac(hmacKey, message);                    // full 32 bytes
    }

    @Override
    public boolean verify(byte[] key, byte[] message, byte[] signature) {
        try {
            return signature != null
                && MessageDigest.isEqual(signature, authenticate(key, message));
        } catch (GeneralSecurityException e) {
            return false;
        }
    }
}