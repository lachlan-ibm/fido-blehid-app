/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator;

import com.isfs.blekey.authenticator.implapi.CredentialSeedDeriver;
import com.isfs.blekey.ctap.CtapTxn;
import com.isfs.blekey.util.CertUtils;
import com.isfs.blekey.util.KeyUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Handles all CTAP1 / U2F commands (§6f — all U2F logic in one file).
 *
 * <p>Owns: {@code u2fRegister()}, {@code u2fAuthenticate()},
 * {@code u2fCheckKeyHandle()}, {@code encryptKeyHandle()},
 * {@code decryptAndVerifyKeyHandle()}, {@code deriveU2fKeyHandleKey()},
 * {@code normalizeTo32()}, and {@code buildU2fAttestationCert()}.</p>
 */
public class U2fHandler {

    private static final Logger logger = LoggerFactory.getLogger(U2fHandler.class);

    /**
     * Key handle prefix: "U2FH" in ASCII (4 bytes).
     * Analogous to the CTAP2 "F1D0" cred-id prefix.
     */
    private static final byte[] U2F_KH_PREFIX =
        new byte[]{ (byte)'U', (byte)'2', (byte)'F', (byte)'H' };

    /** Length of the AES-CBC IV prepended to every U2F key handle ciphertext (16 bytes). */
    private static final int U2F_KH_IV_LEN = 16;

    /**
     * Length of the plaintext inside the U2F key handle:
     * appParam(32) || privKeyMaterial(32) = 64 bytes.
     */
    private static final int U2F_KH_PLAINTEXT_LEN = 64;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private U2fHandler() {}

    // -------------------------------------------------------------------------
    // u2fRegister
    // -------------------------------------------------------------------------

    /**
     * U2F_REGISTER — creates a new U2F credential and returns the registration response.
     *
     * @param txn            CTAP transaction carrying bio-state and CID
     * @param challengeParam clientDataHash (32 bytes)
     * @param appParam       SHA-256(rpId) (32 bytes)
     * @return response bytes (registration body + 90 00), or SW error bytes on failure
     */
    public static byte[] u2fRegister(CtapTxn txn, byte[] challengeParam, byte[] appParam) {
        logger.info("u2fRegister: starting");

        PrivateKey platformKey = KeyUtils.getPlatformKey();
        if (platformKey == null) {
            logger.error("u2fRegister: platform key unavailable");
            return SW_COMMAND_NOT_ALLOWED;
        }

        String seed = CredentialSeedDeriver.derivePasskeySeed(
            txn, platformKey, appParam, AuthenticatorAPI.getAppConfig());
        if (seed == null) {
            logger.error("u2fRegister: seed derivation failed");
            return SW_COMMAND_NOT_ALLOWED;
        }

        try {
            byte[] khKey = deriveU2fKeyHandleKey(txn);
            if (khKey == null) {
                logger.error("u2fRegister: could not derive key-handle key");
                return SW_COMMAND_NOT_ALLOWED;
            }

            KeyPair credKp = KeyUtils.getKeyPair("ECDSA");
            byte[] keyHandle = encryptKeyHandle(khKey, appParam, credKp.getPrivate());
            if (keyHandle == null) {
                logger.error("u2fRegister: key handle encryption failed");
                return SW_COMMAND_NOT_ALLOWED;
            }

            ECPublicKey ecPub = (ECPublicKey) credKp.getPublic();
            ECPoint w = ecPub.getW();
            byte[] x = normalizeTo32(w.getAffineX().toByteArray());
            byte[] y = normalizeTo32(w.getAffineY().toByteArray());

            // Registration signed message (§4.3):
            // 0x00 || appParam(32) || challengeParam(32) || keyHandle || 04||X||Y
            ByteArrayOutputStream sigMsg = new ByteArrayOutputStream();
            sigMsg.write(0x00);
            sigMsg.write(appParam);
            sigMsg.write(challengeParam);
            sigMsg.write(keyHandle);
            sigMsg.write(0x04);
            sigMsg.write(x);
            sigMsg.write(y);
            byte[] sig = KeyUtils.sign(sigMsg.toByteArray(), credKp.getPrivate());

            byte[] certDer = buildU2fAttestationCert(txn, credKp);

            ByteArrayOutputStream body = new ByteArrayOutputStream();
            body.write(0x05);   // reserved
            body.write(0x04);   // uncompressed point prefix
            body.write(x);
            body.write(y);
            body.write(keyHandle.length & 0xFF);
            body.write(keyHandle);
            body.write(certDer);
            body.write(sig);
            body.write(0x90);
            body.write(0x00);

            logger.info("u2fRegister: success, key handle {} bytes, response {} bytes",
                keyHandle.length, body.size());
            return body.toByteArray();
        } catch (Exception e) {
            logger.error("u2fRegister failed", e);
            return SW_COMMAND_NOT_ALLOWED;
        }
    }

    // -------------------------------------------------------------------------
    // u2fAuthenticate
    // -------------------------------------------------------------------------

    /**
     * U2F_AUTHENTICATE — signs a U2F authentication challenge with the credential key.
     *
     * @param txn            CTAP transaction (IKM cached here on success)
     * @param challengeParam clientDataHash (32 bytes)
     * @param appParam       SHA-256(rpId) (32 bytes)
     * @param keyHandle      raw key handle from the APDU
     * @param requireUP      true for normal sign (P1=0x03), false for no-UP (P1=0x08)
     * @return response bytes, or SW error bytes on failure
     */
    public static byte[] u2fAuthenticate(CtapTxn txn, byte[] challengeParam, byte[] appParam,
                                          byte[] keyHandle, boolean requireUP) {
        logger.info("u2fAuthenticate: requireUP={}", requireUP);

        PrivateKey platformKey = KeyUtils.getPlatformKey();
        if (platformKey == null) return SW_WRONG_DATA;

        String seed = CredentialSeedDeriver.derivePasskeySeed(
            txn, platformKey, appParam, AuthenticatorAPI.getAppConfig());
        if (seed == null) {
            logger.error("u2fAuthenticate: seed derivation failed");
            return SW_COMMAND_NOT_ALLOWED;
        }

        try {
            byte[] khKey = deriveU2fKeyHandleKey(txn);
            if (khKey == null) {
                logger.error("u2fAuthenticate: could not derive key-handle key");
                return SW_WRONG_DATA;
            }

            KeyPair credKp = decryptAndVerifyKeyHandle(khKey, appParam, keyHandle);
            if (credKp == null) {
                logger.warn("u2fAuthenticate: unknown or invalid key handle");
                return SW_WRONG_DATA;
            }

            byte userPresence = requireUP ? (byte) 0x01 : (byte) 0x00;
            // Time-based counter: monotonically increasing, satisfies U2F spec.
            int counter = (int) (System.currentTimeMillis() / 1000L);
            byte[] counterBytes = ByteBuffer.allocate(4).putInt(counter).array();

            ByteArrayOutputStream sigMsg = new ByteArrayOutputStream();
            sigMsg.write(appParam);
            sigMsg.write(userPresence);
            sigMsg.write(counterBytes);
            sigMsg.write(challengeParam);
            byte[] sig = KeyUtils.sign(sigMsg.toByteArray(), credKp.getPrivate());

            ByteArrayOutputStream body = new ByteArrayOutputStream();
            body.write(userPresence);
            body.write(counterBytes);
            body.write(sig);
            body.write(0x90);
            body.write(0x00);

            logger.info("u2fAuthenticate: success, counter={}", counter);
            return body.toByteArray();
        } catch (Exception e) {
            logger.error("u2fAuthenticate failed", e);
            return SW_COMMAND_NOT_ALLOWED;
        }
    }

    // -------------------------------------------------------------------------
    // u2fCheckKeyHandle
    // -------------------------------------------------------------------------

    /**
     * Checks whether a key handle is valid for the given {@code appParam} without
     * triggering user presence.
     */
    public static boolean u2fCheckKeyHandle(CtapTxn txn, byte[] appParam, byte[] keyHandle) {
        byte[] khKey = deriveU2fKeyHandleKey(txn);
        if (khKey == null) return false;
        return decryptAndVerifyKeyHandle(khKey, appParam, keyHandle) != null;
    }

    // -------------------------------------------------------------------------
    // Key handle crypto
    // -------------------------------------------------------------------------

    private static byte[] deriveU2fKeyHandleKey(CtapTxn txn) {
        byte[] ikm = com.isfs.blekey.authenticator.UxInteractionLock.get().getCachedIkm();
        if (ikm == null) return null;
        try {
            byte[] info = "U2F-KEY-HANDLE".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            return KeyUtils.hkdf(ikm, new byte[32], info, 32);
        } catch (Exception e) {
            logger.error("deriveU2fKeyHandleKey: HKDF failed", e);
            return null;
        }
    }

    private static byte[] encryptKeyHandle(byte[] khKey, byte[] appParam, PrivateKey privKey) {
        try {
            byte[] keyMat = KeyUtils.extractKeyMaterial(privKey); // 32 bytes
            byte[] plaintext = new byte[U2F_KH_PLAINTEXT_LEN];
            System.arraycopy(appParam, 0, plaintext,  0, 32);
            System.arraycopy(keyMat,   0, plaintext, 32, 32);

            byte[] iv = new byte[U2F_KH_IV_LEN];
            SECURE_RANDOM.nextBytes(iv);

            SecretKeySpec keySpec = new SecretKeySpec(khKey, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            byte[] ciphertext = cipher.doFinal(plaintext);

            byte[] kh = new byte[U2F_KH_PREFIX.length + U2F_KH_IV_LEN + ciphertext.length];
            int off = 0;
            System.arraycopy(U2F_KH_PREFIX, 0, kh, off, U2F_KH_PREFIX.length); off += U2F_KH_PREFIX.length;
            System.arraycopy(iv,            0, kh, off, U2F_KH_IV_LEN);        off += U2F_KH_IV_LEN;
            System.arraycopy(ciphertext,    0, kh, off, ciphertext.length);
            return kh;
        } catch (Exception e) {
            logger.error("encryptKeyHandle: failed", e);
            return null;
        }
    }

    private static KeyPair decryptAndVerifyKeyHandle(byte[] khKey, byte[] appParam, byte[] keyHandle) {
        try {
            int minLen = U2F_KH_PREFIX.length + U2F_KH_IV_LEN + U2F_KH_PLAINTEXT_LEN;
            if (keyHandle == null || keyHandle.length < minLen) return null;
            for (int i = 0; i < U2F_KH_PREFIX.length; i++) {
                if (keyHandle[i] != U2F_KH_PREFIX[i]) return null;
            }
            int off = U2F_KH_PREFIX.length;
            byte[] iv         = Arrays.copyOfRange(keyHandle, off, off + U2F_KH_IV_LEN);
            off += U2F_KH_IV_LEN;
            byte[] ciphertext = Arrays.copyOfRange(keyHandle, off, off + U2F_KH_PLAINTEXT_LEN);

            SecretKeySpec keySpec = new SecretKeySpec(khKey, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            byte[] plaintext = cipher.doFinal(ciphertext); // 64 bytes

            byte[] embeddedApp = Arrays.copyOfRange(plaintext, 0, 32);
            if (!MessageDigest.isEqual(embeddedApp, appParam)) return null;

            byte[] keyMat = Arrays.copyOfRange(plaintext, 32, 64);
            return KeyUtils.reconstructKeyPair(-7 /* ES256 */, keyMat);
        } catch (Exception e) {
            logger.debug("decryptAndVerifyKeyHandle: failed: {}", e.getMessage());
            return null;
        }
    }

    private static byte[] normalizeTo32(byte[] raw) {
        byte[] out = new byte[32];
        int src = Math.max(0, raw.length - 32);
        int dst = Math.max(0, 32 - raw.length);
        System.arraycopy(raw, src, out, dst, raw.length - src);
        return out;
    }

    private static byte[] buildU2fAttestationCert(CtapTxn txn, KeyPair credKp) throws Exception {
        X509Certificate caCert = (txn != null && txn.getPasskey() != null)
            ? txn.getPasskey().getCertificate() : null;
        return CertUtils.generateU2FCertificate(caCert, "CN=Aye.Bt.Key U2F", credKp, 9999)
                        .getEncoded();
    }

    // -------------------------------------------------------------------------
    // SW status bytes
    // -------------------------------------------------------------------------
    private static final byte[] SW_COMMAND_NOT_ALLOWED = new byte[]{ (byte) 0x69, (byte) 0x00 };
    private static final byte[] SW_WRONG_DATA          = new byte[]{ (byte) 0x6A, (byte) 0x80 };
}
