/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.data;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;

import com.isfs.blekey.util.KeyUtils;
import com.isfs.blekey.util.KeystoreManager;

/**
 * Encrypts and decrypts the upperHash stored in a {@code .stash} file.
 *
 * <p>Obtain an instance via {@link #create(KeystoreManager, PublicKey, PrivateKey)}.
 *
 * <p>The platform key is chosen once at construction time:
 * <ul>
 *   <li>TEE/KSM available → TEE backed key with well knowen handle.</li>
 *   <li>No TEE/KSM → file-based platform key pair used.</li>
 * </ul>
 */
public abstract class StashCipher {

    /**
     * Returns a {@code StashCipher} backed by the TEE when available, otherwise
     * by the supplied file-based platform key pair.
     *
     * @param ksm        platform keystore manager (may be null)
     * @param publicKey  file-based platform public key (used only when ksm unavailable)
     * @param privateKey file-based platform private key (used only when ksm unavailable)
     */
    public static StashCipher create(
            KeystoreManager ksm,
            PublicKey publicKey,
            PrivateKey privateKey) {

        if (ksm != null && ksm.isKeystoreAvailable()) {
            return new TeeStashCipher(ksm);
        }
        return new FileStashCipher(publicKey, privateKey);
    }

    /** Encrypts {@code plaintext} (the upperHash) for storage in the {@code .stash} file. */
    public abstract byte[] encrypt(byte[] plaintext) throws IOException;

    /** Decrypts {@code ciphertext} read from the {@code .stash} file. */
    public abstract byte[] decrypt(byte[] ciphertext) throws Exception;

    // -------------------------------------------------------------------------

    private static final class TeeStashCipher extends StashCipher {
        private final KeystoreManager ksm;

        TeeStashCipher(KeystoreManager ksm) {
            this.ksm = ksm;
        }

        @Override
        public byte[] encrypt(byte[] plaintext) throws IOException {
            try {
                return KeyUtils.ecdhEncrypt(plaintext, ksm.getEC256PublicKey());
            } catch (Exception e) {
                throw new IOException("TEE stash encryption failed", e);
            }
        }

        @Override
        public byte[] decrypt(byte[] ciphertext) throws Exception {
            return KeyUtils.ecdhDecrypt(ciphertext, ksm.getEC256PrivateKey());
        }
    }

    // -------------------------------------------------------------------------

    private static final class FileStashCipher extends StashCipher {
        private final PublicKey publicKey;
        private final PrivateKey privateKey;

        FileStashCipher(PublicKey publicKey, PrivateKey privateKey) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        @Override
        public byte[] encrypt(byte[] plaintext) throws IOException {
            try {
                return KeyUtils.ecdhEncrypt(plaintext, publicKey);
            } catch (Exception e) {
                throw new IOException("File-key stash encryption failed", e);
            }
        }

        @Override
        public byte[] decrypt(byte[] ciphertext) throws Exception {
            return KeyUtils.ecdhDecrypt(ciphertext, privateKey);
        }
    }
}
