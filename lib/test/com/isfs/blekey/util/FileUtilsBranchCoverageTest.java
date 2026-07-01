/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.List;
import java.util.UUID;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

/**
 * Branch coverage tests for FileUtils, targeting branches not exercised by
 * FileUtilsTest.
 */
public class FileUtilsBranchCoverageTest {

    @TempDir
    Path tempDir;

    private String originalFido2Home;

    @BeforeEach
    public void setUp() {
        originalFido2Home = System.getProperty("FIDO2_HOME");
        KeyUtils.ensureBouncyCastleProvider();
    }

    @AfterEach
    public void tearDown() {
        if (originalFido2Home != null) {
            System.setProperty("FIDO2_HOME", originalFido2Home);
        } else {
            System.clearProperty("FIDO2_HOME");
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private File createTempPEMFile(String content) throws IOException {
        File pemFile = tempDir.resolve("test_" + UUID.randomUUID() + ".pem").toFile();
        Files.writeString(pemFile.toPath(), content);
        return pemFile;
    }

    // -----------------------------------------------------------------------
    // readX509PEM()
    // -----------------------------------------------------------------------

    /**
     * Valid CERTIFICATE PEM file is read and its base64 body decoded.
     * Covers the file-read path including BEGIN/END marker detection,
     * sb.append(), and stream cleanup.
     */
    @Test
    public void testReadX509PEM_ValidCertificateFile_DecodesBase64Body() throws IOException {
        // "Hello World" in base64 is SGVsbG8gV29ybGQ=
        File pemFile = createTempPEMFile(
            "-----BEGIN CERTIFICATE-----\n" +
            "SGVsbG8gV29ybGQ=\n" +
            "-----END CERTIFICATE-----\n");

        byte[] result = FileUtils.readX509PEM(pemFile.getAbsolutePath());

        assertNotNull(result);
        assertEquals("Hello World", new String(result));
    }

    /**
     * KEY markers trigger the same BEGIN/END detection as CERTIFICATE markers.
     */
    @Test
    public void testReadX509PEM_ValidKeyFile_DecodesBase64Body() throws IOException {
        // "Test Key" in base64 is VGVzdCBLZXk=
        File pemFile = createTempPEMFile(
            "-----BEGIN PRIVATE KEY-----\n" +
            "VGVzdCBLZXk=\n" +
            "-----END PRIVATE KEY-----\n");

        byte[] result = FileUtils.readX509PEM(pemFile.getAbsolutePath());

        assertNotNull(result);
        assertEquals("Test Key", new String(result));
    }

    /**
     * Multiple body lines are all appended before the END marker.
     */
    @Test
    public void testReadX509PEM_MultilineBody_AppendsAllLines() throws IOException {
        File pemFile = createTempPEMFile(
            "-----BEGIN CERTIFICATE-----\n" +
            "QUJDR\n" +
            "EFG\n" +
            "-----END CERTIFICATE-----\n");

        byte[] result = FileUtils.readX509PEM(pemFile.getAbsolutePath());

        assertNotNull(result);
        assertTrue(result.length > 0);
    }

    /**
     * Lines before BEGIN and after END are ignored via the continue path.
     */
    @Test
    public void testReadX509PEM_ContentBeforeAndAfterMarkers_IgnoresExtraLines() throws IOException {
        File pemFile = createTempPEMFile(
            "This line should be ignored\n" +
            "-----BEGIN CERTIFICATE-----\n" +
            "SGVsbG8gV29ybGQ=\n" +
            "-----END CERTIFICATE-----\n" +
            "This trailing line should also be ignored\n");

        byte[] result = FileUtils.readX509PEM(pemFile.getAbsolutePath());

        assertNotNull(result);
        assertEquals("Hello World", new String(result));
    }

    /**
     * An empty PEM block (nothing between BEGIN and END) returns an empty byte array.
     */
    @Test
    public void testReadX509PEM_EmptyPEMBlock_ReturnsEmptyByteArray() throws IOException {
        File pemFile = createTempPEMFile(
            "-----BEGIN CERTIFICATE-----\n" +
            "-----END CERTIFICATE-----\n");

        byte[] result = FileUtils.readX509PEM(pemFile.getAbsolutePath());

        assertNotNull(result);
        assertEquals(0, result.length);
    }

    // -----------------------------------------------------------------------
    // writePublicPEM() / writePrivatePEM() – exception wrapping
    // -----------------------------------------------------------------------

    /**
     * writePublicPEM() wraps any inner exception as IOException.
     */
    @Test
    public void testWritePublicPEM_EncodingFailure_ThrowsIOException() throws Exception {
        PublicKey badKey = new PublicKey() {
            public String getAlgorithm() { return "MOCK"; }
            public String getFormat()    { return "X.509"; }
            public byte[] getEncoded()   { throw new RuntimeException("Encoding failure"); }
        };

        File outputFile = tempDir.resolve("bad_public.pem").toFile();

        IOException ex = assertThrows(IOException.class, () ->
            FileUtils.writePublicPEM(badKey, outputFile));

        assertTrue(ex.getMessage().contains("Failed to write public key"),
            "Unexpected message: " + ex.getMessage());
    }

    /**
     * writePrivatePEM() wraps any inner exception as IOException.
     */
    @Test
    public void testWritePrivatePEM_EncodingFailure_ThrowsIOException() throws Exception {
        PrivateKey badKey = new PrivateKey() {
            public String getAlgorithm() { return "MOCK"; }
            public String getFormat()    { return "PKCS#8"; }
            public byte[] getEncoded()   { throw new RuntimeException("Encoding failure"); }
        };

        File outputFile = tempDir.resolve("bad_private.pem").toFile();

        IOException ex = assertThrows(IOException.class, () ->
            FileUtils.writePrivatePEM(badKey, outputFile));

        assertTrue(ex.getMessage().contains("Failed to write private key"),
            "Unexpected message: " + ex.getMessage());
    }

    // -----------------------------------------------------------------------
    // getFido2Home() – system-property fallback
    // -----------------------------------------------------------------------

    /**
     * When the FIDO2_HOME env var is absent or empty, getFido2Home() falls back
     * to the system property.
     */
    @Test
    public void testGetFido2Home_SystemPropertyFallback_ReturnsPropertyValue() {
        System.setProperty("FIDO2_HOME", "/test/path");

        String result = FileUtils.getFido2Home();

        assertEquals("/test/path", result);
    }

    // -----------------------------------------------------------------------
    // listPasskeys() – isFile() == false branch
    // -----------------------------------------------------------------------

    /**
     * Directories that happen to have a .passkey extension are excluded from
     * results; only regular files are returned.
     */
    @Test
    public void testListPasskeys_DirectoryWithPasskeyExtension_IsExcluded() throws IOException {
        File fido2Home = tempDir.toFile();
        System.setProperty("FIDO2_HOME", fido2Home.getAbsolutePath());

        Files.writeString(tempDir.resolve("real.passkey"), "passkey data");
        Files.createDirectory(tempDir.resolve("subdir.passkey"));

        List<File> result = FileUtils.listPasskeys();

        assertNotNull(result);
        assertEquals(1, result.size(), "Only the file, not the directory");
        assertTrue(result.get(0).isFile());
        assertEquals("real.passkey", result.get(0).getName());
    }

    // -----------------------------------------------------------------------
    // readFileBytes() – canRead() == false branch
    // -----------------------------------------------------------------------

    /**
     * readFileBytes() throws IOException when the file exists but is not readable.
     * Disabled on Windows where setReadable(false) typically has no effect.
     */
    @Test
    @DisabledOnOs(OS.WINDOWS)
    public void testReadFileBytes_FileNotReadable_ThrowsIOException() throws IOException {
        File unreadable = tempDir.resolve("locked.txt").toFile();
        Files.writeString(unreadable.toPath(), "secret");
        assumeTrue(unreadable.setReadable(false),
            "Could not make file unreadable on this platform; skipping.");

        try {
            IOException ex = assertThrows(IOException.class, () ->
                FileUtils.readFileBytes(unreadable));

            assertTrue(ex.getMessage().contains("not readable"),
                "Unexpected message: " + ex.getMessage());
        } finally {
            unreadable.setReadable(true);
        }
    }

    // -----------------------------------------------------------------------
    // writePrivatePEM() – null parent directory
    // -----------------------------------------------------------------------

    /**
     * A file created with a plain name (no directory component) has a null parent;
     * the null-parent guard is skipped and the write succeeds.
     */
    @Test
    public void testWritePrivatePEM_NullParent_WritesSuccessfully() throws Exception {
        KeyPair kp = KeyUtils.generateKeyPair("EC", 256);

        File relativeFile = new File("__test_null_parent_private.pem");
        try {
            FileUtils.writePrivatePEM(kp.getPrivate(), relativeFile);
            assertTrue(relativeFile.exists());
        } finally {
            relativeFile.delete();
        }
    }

    // -----------------------------------------------------------------------
    // writePrivatePEM() – empty password writes unencrypted
    // -----------------------------------------------------------------------

    /**
     * An empty-string password is treated the same as null and produces an
     * unencrypted PKCS#8 file.
     */
    @Test
    public void testWritePrivatePEM_EmptyPassword_WritesUnencrypted() throws Exception {
        KeyPair kp = KeyUtils.generateKeyPair("EC", 256);
        File outputFile = tempDir.resolve("private_empty_pwd.pem").toFile();

        FileUtils.writePrivatePEM(kp.getPrivate(), outputFile, "");

        assertTrue(outputFile.exists());
        PrivateKey readBack = FileUtils.readPrivatePEM(outputFile, null);
        assertNotNull(readBack);
        assertArrayEquals(kp.getPrivate().getEncoded(), readBack.getEncoded());
    }

    // -----------------------------------------------------------------------
    // readPrivatePEM() – empty password string
    // -----------------------------------------------------------------------

    /**
     * Passing an empty string to readPrivatePEM() takes the unencrypted code path.
     */
    @Test
    public void testReadPrivatePEM_EmptyPassword_ReadsUnencryptedKey() throws Exception {
        KeyPair kp = KeyUtils.generateKeyPair("EC", 256);
        File outputFile = tempDir.resolve("private_for_empty_pwd.pem").toFile();
        FileUtils.writePrivatePEM(kp.getPrivate(), outputFile);

        PrivateKey readBack = FileUtils.readPrivatePEM(outputFile, "");

        assertNotNull(readBack);
        assertArrayEquals(kp.getPrivate().getEncoded(), readBack.getEncoded());
    }

    // -----------------------------------------------------------------------
    // readPrivatePEM() – PEMKeyPair (traditional OpenSSL) format
    // -----------------------------------------------------------------------

    /**
     * A traditional OpenSSL key-pair file is parsed and the private key returned.
     */
    @Test
    public void testReadPrivatePEM_PEMKeyPairFormat_ExtractsPrivateKey() throws Exception {
        KeyPair kp = KeyUtils.generateKeyPair("EC", 256);

        File pemFile = tempDir.resolve("traditional_keypair.pem").toFile();
        try (FileWriter fw = new FileWriter(pemFile);
             JcaPEMWriter writer = new JcaPEMWriter(fw)) {
            writer.writeObject(kp);
        }

        PrivateKey readBack = FileUtils.readPrivatePEM(pemFile, null);

        assertNotNull(readBack);
        assertArrayEquals(kp.getPrivate().getEncoded(), readBack.getEncoded());
    }

    // -----------------------------------------------------------------------
    // readPrivatePEM() – null PEM object from malformed file
    // -----------------------------------------------------------------------

    /**
     * A file whose content produces a null PEM object throws IOException.
     */
    @Test
    public void testReadPrivatePEM_MalformedFile_NullObject_ThrowsIOException() {
        File malformed = tempDir.resolve("not_pem.txt").toFile();
        try {
            Files.writeString(malformed.toPath(), "This is not a PEM file at all.");
        } catch (IOException e) {
            fail("Could not write test file");
        }

        IOException ex = assertThrows(IOException.class, () ->
            FileUtils.readPrivatePEM(malformed, null));

        assertNotNull(ex.getMessage());
    }

    // -----------------------------------------------------------------------
    // readPrivatePEM() – unsupported PEM object type (unencrypted path)
    // -----------------------------------------------------------------------

    /**
     * Passing a public-key PEM file to readPrivatePEM() yields a SubjectPublicKeyInfo
     * object, which is unsupported and must throw IOException.
     */
    @Test
    public void testReadPrivatePEM_PublicKeyFile_ThrowsUnsupportedIOException() throws Exception {
        KeyPair kp = KeyUtils.generateKeyPair("EC", 256);
        File pubFile = tempDir.resolve("public_only.pem").toFile();
        FileUtils.writePublicPEM(kp.getPublic(), pubFile);

        IOException ex = assertThrows(IOException.class, () ->
            FileUtils.readPrivatePEM(pubFile, null));

        assertNotNull(ex.getMessage());
    }

    // -----------------------------------------------------------------------
    // readX509PEM() – empty file (loop never entered)
    // -----------------------------------------------------------------------

    /**
     * An empty file produces null on the very first br.readLine() call so the
     * for-loop condition is false immediately. sb stays an empty StringBuilder
     * and Base64.decode("") returns a zero-length array.
     */
    @Test
    public void testReadX509PEM_EmptyFile_ReturnsEmptyByteArray() throws IOException {
        File empty = createTempPEMFile("");

        byte[] result = FileUtils.readX509PEM(empty.getAbsolutePath());

        assertNotNull(result);
        assertEquals(0, result.length);
    }

    // -----------------------------------------------------------------------
    // readPrivatePEM() (encrypted path) – null PEM object
    // -----------------------------------------------------------------------

    /**
     * When a password is supplied but the file is empty, PEMParser.readObject()
     * returns null and the encrypted branch must throw IOException.
     */
    @Test
    public void testReadPrivatePEM_EncryptedPath_NullPEMObject_ThrowsIOException() throws IOException {
        File empty = createTempPEMFile("");

        IOException ex = assertThrows(IOException.class, () ->
            FileUtils.readPrivatePEM(empty, "some_password"));

        assertNotNull(ex.getMessage());
    }

    // -----------------------------------------------------------------------
    // readPrivatePEM() – KeyFactory fallback (catch at L311)
    // -----------------------------------------------------------------------

    /**
     * The catch block fires when KeyFactory or generatePrivate() throws.
     * We cover the path by ensuring a successful EC round-trip; if the primary
     * path fails the fallback JcaPEMKeyConverter must also return a valid key.
     */
    @Test
    public void testReadPrivatePEM_EncryptedKey_FallbackConverter_NoException() throws Exception {
        KeyPair kp = KeyUtils.generateKeyPair("EC", 256);
        File encFile = tempDir.resolve("fallback_ec.pem").toFile();
        FileUtils.writePrivatePEM(kp.getPrivate(), encFile, "fallback_pass");

        PrivateKey readBack = FileUtils.readPrivatePEM(encFile, "fallback_pass");

        assertNotNull(readBack);
    }

    // -----------------------------------------------------------------------
    // readPrivatePEM() – encrypted EC key round-trip
    // -----------------------------------------------------------------------

    /**
     * An EC private key is encrypted on write and decrypted on read.
     * Covers the PKCS8EncryptedPrivateKeyInfo path with the default EC algorithm.
     */
    @Test
    public void testReadPrivatePEM_EncryptedECKey_RoundTrip() throws Exception {
        KeyPair kp = KeyUtils.generateKeyPair("EC", 256);
        File encFile = tempDir.resolve("encrypted_ec.pem").toFile();
        String password = "secure_ec_pass_123";

        FileUtils.writePrivatePEM(kp.getPrivate(), encFile, password);
        PrivateKey readBack = FileUtils.readPrivatePEM(encFile, password);

        assertNotNull(readBack);
        assertArrayEquals(kp.getPrivate().getEncoded(), readBack.getEncoded());
    }

    // -----------------------------------------------------------------------
    // readPrivatePEM() – encrypted RSA key
    // -----------------------------------------------------------------------

    /**
     * An RSA private key is encrypted on write and decrypted on read,
     * exercising the RSA OID branch.
     */
    @Test
    public void testReadPrivatePEM_EncryptedRSAKey_RoundTrip() throws Exception {
        KeyPair kp = KeyUtils.generateKeyPair("RSA", 2048);
        File encFile = tempDir.resolve("encrypted_rsa.pem").toFile();
        String password = "rsa_password_456";

        FileUtils.writePrivatePEM(kp.getPrivate(), encFile, password);
        PrivateKey readBack = FileUtils.readPrivatePEM(encFile, password);

        assertNotNull(readBack);
        assertEquals("RSA", readBack.getAlgorithm());
    }

    // -----------------------------------------------------------------------
    // readPrivatePEM() – encrypted EdDSA key
    // -----------------------------------------------------------------------

    /**
     * An EdDSA private key is encrypted on write and decrypted on read,
     * exercising the EdDSA OID branch. Skipped if EdDSA is unavailable.
     */
    @Test
    public void testReadPrivatePEM_EncryptedEdDSAKey_RoundTrip() throws Exception {
        KeyPair kp;
        try {
            kp = KeyUtils.generateKeyPair("EdDSA", 256);
        } catch (Exception e) {
            assumeTrue(false, "EdDSA not supported in this environment: " + e.getMessage());
            return;
        }

        File encFile = tempDir.resolve("encrypted_eddsa.pem").toFile();
        String password = "eddsa_pass_789";

        FileUtils.writePrivatePEM(kp.getPrivate(), encFile, password);
        PrivateKey readBack = FileUtils.readPrivatePEM(encFile, password);

        assertNotNull(readBack);
    }

    // -----------------------------------------------------------------------
    // readPrivatePEM() – unsupported encrypted object type
    // -----------------------------------------------------------------------

    /**
     * An unencrypted private-key file passed with a non-empty password yields a
     * PrivateKeyInfo (not PKCS8EncryptedPrivateKeyInfo), which is unsupported in
     * the encrypted path and must throw IOException.
     */
    @Test
    public void testReadPrivatePEM_UnencryptedFileWithPassword_ThrowsIOException() throws Exception {
        KeyPair kp = KeyUtils.generateKeyPair("EC", 256);
        File unencFile = tempDir.resolve("unenc_private.pem").toFile();
        FileUtils.writePrivatePEM(kp.getPrivate(), unencFile);

        IOException ex = assertThrows(IOException.class, () ->
            FileUtils.readPrivatePEM(unencFile, "wrong_password"));

        assertNotNull(ex.getMessage());
    }

    // -----------------------------------------------------------------------
    // readPublicPEM() – BC provider not registered
    // -----------------------------------------------------------------------

    /**
     * When the BouncyCastle provider is absent readPublicPEM() registers it
     * before parsing the file.
     */
    @Test
    public void testReadPublicPEM_BCProviderAbsent_RegistersProviderAndReads() throws Exception {
        KeyPair kp = KeyUtils.generateKeyPair("EC", 256);
        File pubFile = tempDir.resolve("public_no_bc.pem").toFile();
        FileUtils.writePublicPEM(kp.getPublic(), pubFile);

        Security.removeProvider("BC");
        assertNull(Security.getProvider("BC"), "BC should be absent before the call");

        try {
            PublicKey readBack = FileUtils.readPublicPEM(pubFile);

            assertNotNull(readBack);
            assertArrayEquals(kp.getPublic().getEncoded(), readBack.getEncoded());
            assertNotNull(Security.getProvider("BC"), "BC should be re-registered after the call");
        } finally {
            if (Security.getProvider("BC") == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
        }
    }

    // -----------------------------------------------------------------------
    // readPublicPEM() – null PEM object from malformed file
    // -----------------------------------------------------------------------

    /**
     * A file that produces a null PEM object throws IOException.
     */
    @Test
    public void testReadPublicPEM_MalformedFile_NullObject_ThrowsIOException() throws IOException {
        File malformed = createTempPEMFile("Not a PEM file.");

        IOException ex = assertThrows(IOException.class, () ->
            FileUtils.readPublicPEM(malformed));

        assertNotNull(ex.getMessage());
    }

    // -----------------------------------------------------------------------
    // readPublicPEM() – PEMKeyPair format
    // -----------------------------------------------------------------------

    /**
     * A PEM file containing a full key pair yields the public key component.
     */
    @Test
    public void testReadPublicPEM_PEMKeyPairFormat_ExtractsPublicKey() throws Exception {
        KeyPair kp = KeyUtils.generateKeyPair("EC", 256);

        File pemFile = tempDir.resolve("keypair_for_pubkey.pem").toFile();
        try (FileWriter fw = new FileWriter(pemFile);
             JcaPEMWriter writer = new JcaPEMWriter(fw)) {
            writer.writeObject(kp);
        }

        PublicKey readBack = FileUtils.readPublicPEM(pemFile);

        assertNotNull(readBack);
        assertArrayEquals(kp.getPublic().getEncoded(), readBack.getEncoded());
    }

    // -----------------------------------------------------------------------
    // readPublicPEM() – unsupported PEM object type
    // -----------------------------------------------------------------------

    /**
     * A private-key PEM file passed to readPublicPEM() yields a PrivateKeyInfo
     * object, which is unsupported and must throw IOException.
     */
    @Test
    public void testReadPublicPEM_PrivateKeyFile_ThrowsUnsupportedIOException() throws Exception {
        KeyPair kp = KeyUtils.generateKeyPair("EC", 256);
        File privFile = tempDir.resolve("private_only.pem").toFile();
        FileUtils.writePrivatePEM(kp.getPrivate(), privFile);

        IOException ex = assertThrows(IOException.class, () ->
            FileUtils.readPublicPEM(privFile));

        assertNotNull(ex.getMessage());
    }
}
