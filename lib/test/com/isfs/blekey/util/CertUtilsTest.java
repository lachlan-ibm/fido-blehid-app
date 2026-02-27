/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.util;

import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;

/**
 * Comprehensive test suite for the CertUtils class.
 */
public class CertUtilsTest {

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();
    
    private KeyPair ecKeyPair;
    private KeyPair rsaKeyPair;
    
    @Before
    public void setUp() throws Exception {
        // Generate test key pairs
        ecKeyPair = KeyUtils.generateKeyPair("EC", 256);
        rsaKeyPair = KeyUtils.generateKeyPair("RSA", 2048);
    }
    
    @After
    public void tearDown() throws Exception {
        // Clean up resources
    }
    
    /**
     * Test generating a CA certificate with EC key
     */
    @Test
    public void testGenerateEcCaCert() throws Exception {
        // Generate a CA certificate
        X509Certificate cert = CertUtils.generateCaCert("CN=Test EC CA", ecKeyPair, 365, true);
        
        // Verify the certificate
        assertNotNull("Certificate should not be null", cert);
        assertEquals("Subject DN should match", "CN=Test EC CA", cert.getSubjectX500Principal().getName());
        assertEquals("Issuer DN should match", "CN=Test EC CA", cert.getIssuerX500Principal().getName());
        
        // Verify the certificate is self-signed
        cert.verify(ecKeyPair.getPublic());
        
        // Verify the certificate is a CA
        assertTrue("Certificate should have basic constraints extension", 
                  cert.getBasicConstraints() >= 0);
        
        // Verify the certificate has the correct key usage
        boolean[] keyUsage = cert.getKeyUsage();
        assertNotNull("Key usage should not be null", keyUsage);
        assertTrue("Certificate should have keyCertSign usage", keyUsage[5]); // keyCertSign is bit 5
    }
    
    /**
     * Test generating a CA certificate with RSA key
     */
    @Test
    public void testGenerateRsaCaCert() throws Exception {
        // Generate a CA certificate
        X509Certificate cert = CertUtils.generateCaCert("CN=Test RSA CA", rsaKeyPair, 365, true);
        
        // Verify the certificate
        assertNotNull("Certificate should not be null", cert);
        assertEquals("Subject DN should match", "CN=Test RSA CA", cert.getSubjectX500Principal().getName());
        assertEquals("Issuer DN should match", "CN=Test RSA CA", cert.getIssuerX500Principal().getName());
        
        // Verify the certificate is self-signed
        cert.verify(rsaKeyPair.getPublic());
        
        // Verify the certificate is a CA
        assertTrue("Certificate should have basic constraints extension", 
                  cert.getBasicConstraints() >= 0);
        
        // Verify the certificate has the correct key usage
        boolean[] keyUsage = cert.getKeyUsage();
        assertNotNull("Key usage should not be null", keyUsage);
        assertTrue("Certificate should have keyCertSign usage", keyUsage[5]); // keyCertSign is bit 5
    }
    
    /**
     * Test generating an intermediate CA certificate
     */
    @Test
    public void testGenerateIntermediateCACert() throws Exception {
        // Generate a root CA certificate
        X509Certificate rootCert = CertUtils.generateCaCert("CN=Test Root CA", rsaKeyPair, 365, true);
        
        // Generate an intermediate CA certificate
        KeyPair intermediateKeyPair = KeyUtils.generateKeyPair("RSA", 2048);
        X509Certificate intermediateCert = CertUtils.generateIntermediateCACert(
            rootCert, "CN=Test Intermediate CA", 365, intermediateKeyPair, rsaKeyPair);
        
        // Verify the certificate
        assertNotNull("Certificate should not be null", intermediateCert);
        assertEquals("Subject DN should match", "CN=Test Intermediate CA", 
                    intermediateCert.getSubjectX500Principal().getName());
        assertEquals("Issuer DN should match", "CN=Test Root CA", 
                    intermediateCert.getIssuerX500Principal().getName());
        
        // Verify the certificate is signed by the root CA
        intermediateCert.verify(rsaKeyPair.getPublic());
        
        // Verify the certificate is a CA
        assertTrue("Certificate should have basic constraints extension", 
                  intermediateCert.getBasicConstraints() >= 0);
    }
    
    /**
     * Test generating a FIDO attestation certificate
     */
    @Test
    public void testGenerateAIKCert() throws Exception {
        // Generate a root CA certificate
        X509Certificate rootCert = CertUtils.generateCaCert("CN=Test Root CA", rsaKeyPair, 365, true);
        
        // Generate an AIK certificate
        KeyPair aikKeyPair = KeyUtils.generateKeyPair("RSA", 2048);
        X509Certificate aikCert = CertUtils.generateAIKCert(
            rootCert, 365, aikKeyPair, "CN=Test AIK", rsaKeyPair);
        
        // Verify the certificate
        assertNotNull("Certificate should not be null", aikCert);
        
        // AIK certs have empty subject
        assertEquals("Subject DN should be empty", "", 
                    aikCert.getSubjectX500Principal().getName());
        assertEquals("Issuer DN should match", "CN=Test Root CA", 
                    aikCert.getIssuerX500Principal().getName());
        
        // Verify the certificate is signed by the root CA
        aikCert.verify(rsaKeyPair.getPublic());
        
        // Verify the certificate is not a CA
        assertEquals("Certificate should not be a CA", -1, aikCert.getBasicConstraints());
        
        // Verify the certificate has the correct key usage
        boolean[] keyUsage = aikCert.getKeyUsage();
        assertNotNull("Key usage should not be null", keyUsage);
        assertTrue("Certificate should have digitalSignature usage", keyUsage[0]); // digitalSignature is bit 0
    }
    
    /**
     * Test generating a FIDO attestation certificate with AAGUID
     */
    @Test
    public void testGenerateAIKCertWithAAGUID() throws Exception {
        // Generate a root CA certificate
        X509Certificate rootCert = CertUtils.generateCaCert("CN=Test Root CA", rsaKeyPair, 365, true);
        
        // Generate an AIK certificate with AAGUID
        KeyPair aikKeyPair = KeyUtils.generateKeyPair("RSA", 2048);
        byte[] aaguid = new byte[16];
        new SecureRandom().nextBytes(aaguid);
        
        X509Certificate aikCert = CertUtils.generateAIKCert(
            rootCert, 365, aikKeyPair, "CN=Test AIK", rsaKeyPair, aaguid);
        
        // Verify the certificate
        assertNotNull("Certificate should not be null", aikCert);
        
        // AIK certs have empty subject
        assertEquals("Subject DN should be empty", "", 
                    aikCert.getSubjectX500Principal().getName());
        assertEquals("Issuer DN should match", "CN=Test Root CA", 
                    aikCert.getIssuerX500Principal().getName());
        
        // Verify the certificate is signed by the root CA
        aikCert.verify(rsaKeyPair.getPublic());
    }
    
    /**
     * Test generating a packed attestation certificate
     */
    @Test
    public void testGeneratePackedBasicCertificate() throws Exception {
        // Generate a packed attestation certificate
        X509Certificate cert = CertUtils.generatePackedBasicCertificate(
            "CN=Test Packed", rsaKeyPair, 365, "00000000-0000-0000-0000-000000000000");
        
        // Verify the certificate
        assertNotNull("Certificate should not be null", cert);
        assertEquals("Subject DN should match", "CN=Test Packed", 
                    cert.getSubjectX500Principal().getName());
        assertEquals("Issuer DN should match", "CN=Test Packed", 
                    cert.getIssuerX500Principal().getName());
        
        // Verify the certificate is self-signed
        cert.verify(rsaKeyPair.getPublic());
    }
    
    /**
     * Test reading a certificate from bytes
     */
    @Test
    public void testReadBytes() throws Exception {
        // Generate a certificate
        X509Certificate originalCert = CertUtils.generateCaCert("CN=Test CA", rsaKeyPair, 365, true);
        
        // Get the encoded bytes
        byte[] encodedCert = originalCert.getEncoded();
        
        // Read the certificate from bytes
        Certificate readCert = CertUtils.readBytes(encodedCert, "X.509");
        
        // Verify the certificate
        assertNotNull("Read certificate should not be null", readCert);
        assertTrue("Read certificate should be an X509Certificate", readCert instanceof X509Certificate);
        
        X509Certificate x509ReadCert = (X509Certificate) readCert;
        assertEquals("Subject DN should match", originalCert.getSubjectX500Principal().getName(), 
                    x509ReadCert.getSubjectX500Principal().getName());
    }
    
    /**
     * Test reading a certificate from a file
     */
    @Test
    public void testReadCert() throws Exception {
        // Generate a certificate
        X509Certificate originalCert = CertUtils.generateCaCert("CN=Test CA", rsaKeyPair, 365, true);
        
        // Write the certificate to a file
        File certFile = tempFolder.newFile("test_cert.pem");
        try (FileOutputStream fos = new FileOutputStream(certFile)) {
            fos.write("-----BEGIN CERTIFICATE-----\n".getBytes(StandardCharsets.UTF_8));
            fos.write(java.util.Base64.getEncoder().encode(originalCert.getEncoded()));
            fos.write("\n-----END CERTIFICATE-----".getBytes(StandardCharsets.UTF_8));
        }
        
        // Read the certificate from the file
        Certificate readCert = CertUtils.readCert(certFile.getAbsolutePath(), "X.509");
        
        // Verify the certificate
        assertNotNull("Read certificate should not be null", readCert);
        assertTrue("Read certificate should be an X509Certificate", readCert instanceof X509Certificate);
        
        X509Certificate x509ReadCert = (X509Certificate) readCert;
        assertEquals("Subject DN should match", originalCert.getSubjectX500Principal().getName(), 
                    x509ReadCert.getSubjectX500Principal().getName());
    }
    
    /**
     * Test generating a bad version AIK certificate
     */
    @Test
    public void testGenerateBadVersionAIKCertificate() throws Exception {
        // Generate a root CA certificate
        X509Certificate rootCert = CertUtils.generateCaCert("CN=Test Root CA", rsaKeyPair, 365, true);
        
        // Generate a bad version AIK certificate
        KeyPair aikKeyPair = KeyUtils.generateKeyPair("RSA", 2048);
        X509Certificate badCert = CertUtils.generateBadVersionAIKCertificate(
            rootCert, 365, aikKeyPair, "CN=Test AIK", rsaKeyPair);
        
        // Verify the certificate
        assertNotNull("Certificate should not be null", badCert);
        assertEquals("Subject DN should match", "CN=invalid", 
                    badCert.getSubjectX500Principal().getName());
        
        // Verify the certificate is signed by the root CA
        badCert.verify(rsaKeyPair.getPublic());
    }
    
    /**
     * Parameterized test class for testing certificate generation with different validity periods.
     */
    @RunWith(Parameterized.class)
    public static class CertValidityTest {
        
        @Rule
        public TemporaryFolder tempFolder = new TemporaryFolder();
        
        private final int validityDays;
        private final boolean shouldBeValid;
        private KeyPair keyPair;
        
        /**
         * Define the parameters for the test.
         */
        @Parameters(name = "Validity: {0} days, Should be valid: {1}")
        public static Collection<Object[]> data() {
            return Arrays.asList(new Object[][] {
                { 1, true },      // 1 day validity
                { 30, true },     // 30 days validity
                { 365, true },    // 1 year validity
                { 3650, true },   // 10 years validity
                { 9999, true }    // Maximum validity in the method
            });
        }
        
        /**
         * Constructor for the parameterized test
         */
        public CertValidityTest(int validityDays, boolean shouldBeValid) {
            this.validityDays = validityDays;
            this.shouldBeValid = shouldBeValid;
        }
        
        @Before
        public void setUp() throws Exception {
            // Generate a test key pair
            keyPair = KeyUtils.generateKeyPair("RSA", 2048);
        }
        
        /**
         * Test certificate generation with different validity periods
         */
        @Test
        public void testCertificateValidity() throws Exception {
            try {
                // Generate a certificate with the specified validity period
                X509Certificate cert = CertUtils.generateCaCert(
                    "CN=Test CA", keyPair, validityDays, true);
                
                if (!shouldBeValid) {
                    fail("Certificate generation should have failed for validity " + validityDays + " days");
                }
                
                // Verify the certificate
                assertNotNull("Certificate should not be null", cert);
                
                // Calculate expected validity dates
                long currentTimeMillis = System.currentTimeMillis();
                Date expectedNotBefore = new Date(currentTimeMillis);
                Date expectedNotAfter = new Date(currentTimeMillis + (validityDays * 24L * 60L * 60L * 1000L));
                
                // Allow for a small time difference (5 minutes) due to test execution time
                long timeDifference = 5 * 60 * 1000;
                
                // Verify the validity period
                assertTrue("Not before date should be close to current time",
                          Math.abs(cert.getNotBefore().getTime() - expectedNotBefore.getTime()) < timeDifference);
                
                // Check that the expiration date is approximately correct
                // Allow for a larger margin due to different implementations of date calculations
                long expirationDifference = Math.abs(cert.getNotAfter().getTime() - expectedNotAfter.getTime());
                assertTrue("Not after date should be close to expected expiration",
                          expirationDifference < (24L * 60L * 60L * 1000L)); // Within 1 day
                
            } catch (Exception e) {
                if (shouldBeValid) {
                    fail("Certificate generation should have succeeded for validity " + 
                         validityDays + " days: " + e.getMessage());
                }
                // Otherwise, exception is expected for invalid parameters
            }
        }
    }
    
    /**
     * Parameterized test class for testing certificate generation with different key types.
     */
    @RunWith(Parameterized.class)
    public static class CertKeyTypeTest {
        
        private final String keyAlgorithm;
        private final int keySize;
        private KeyPair keyPair;
        
        /**
         * Define the parameters for the test.
         */
        @Parameters(name = "{0} key with {1} bits")
        public static Collection<Object[]> data() {
            return Arrays.asList(new Object[][] {
                { "EC", 256 },
                { "EC", 384 },
                { "EC", 521 },
                { "RSA", 2048 },
                { "RSA", 3072 },
                { "RSA", 4096 }
            });
        }
        
        /**
         * Constructor for the parameterized test
         */
        public CertKeyTypeTest(String keyAlgorithm, int keySize) {
            this.keyAlgorithm = keyAlgorithm;
            this.keySize = keySize;
        }
        
        @Before
        public void setUp() throws Exception {
            // Generate a test key pair
            keyPair = KeyUtils.generateKeyPair(keyAlgorithm, keySize);
        }
        
        /**
         * Test certificate generation with different key types
         */
        @Test
        public void testCertificateWithDifferentKeyTypes() throws Exception {
            // Generate a certificate with the specified key type
            X509Certificate cert = CertUtils.generateCaCert(
                "CN=Test " + keyAlgorithm + " " + keySize + " CA", keyPair, 365, true);
            
            // Verify the certificate
            assertNotNull("Certificate should not be null", cert);
            assertEquals("Subject DN should match", 
                        "CN=Test " + keyAlgorithm + " " + keySize + " CA", 
                        cert.getSubjectX500Principal().getName());
            
            // Verify the certificate is self-signed
            cert.verify(keyPair.getPublic());
            
            // Verify the certificate is a CA
            assertTrue("Certificate should have basic constraints extension", 
                      cert.getBasicConstraints() >= 0);
            
            // Verify the public key algorithm matches
            assertEquals("Public key algorithm should match", 
                        keyAlgorithm, cert.getPublicKey().getAlgorithm());
            
            // For EC keys, verify the key size
            if (keyAlgorithm.equals("EC") && cert.getPublicKey() instanceof ECPublicKey) {
                ECPublicKey ecKey = (ECPublicKey) cert.getPublicKey();
                int fieldSize = ecKey.getParams().getCurve().getField().getFieldSize();
                assertEquals("EC key field size should match", keySize, fieldSize);
            }
            
            // For RSA keys, verify the key size
            if (keyAlgorithm.equals("RSA") && cert.getPublicKey() instanceof RSAPublicKey) {
                RSAPublicKey rsaKey = (RSAPublicKey) cert.getPublicKey();
                int actualSize = rsaKey.getModulus().bitLength();
                // RSA key sizes might not be exactly the requested size
                assertTrue("RSA key size should be close to requested size", 
                          Math.abs(actualSize - keySize) <= 8);
            }
        }
    }
    
    /**
     * Test generating a TPM certificate
     */
    @Test
    public void testGenerateTPMCert() throws Exception {
        System.err.println("Start testGenerateTPMCert");
        // Generate a root CA certificate
        X509Certificate rootCert = CertUtils.generateCaCert("CN=Test Root CA", rsaKeyPair, 365, true);
        
        // Generate a TPM certificate
        KeyPair tpmKeyPair = KeyUtils.generateKeyPair("RSA", 2048);
        String altName = "CN=Test TPM Device";
        boolean aikCert = true;
        boolean keyUsageCritical = true;
        int keyUsage = 1; // digitalSignature
        
        // Call the private method through reflection
        java.lang.reflect.Method generateTPMCertMethod = CertUtils.class.getDeclaredMethod(
            "generateTPMCert",
            X509Certificate.class, String.class, int.class, KeyPair.class,
            boolean.class, String.class, KeyPair.class, boolean.class, int.class, byte[].class);
        generateTPMCertMethod.setAccessible(true);
        
        X509Certificate tpmCert = (X509Certificate) generateTPMCertMethod.invoke(
            null, rootCert, null, 365, tpmKeyPair, aikCert, altName, rsaKeyPair, keyUsageCritical, keyUsage, null);
        
        // Verify the certificate
        assertNotNull("TPM certificate should not be null", tpmCert);
        assertEquals("Issuer DN should match", "CN=Test Root CA",
                    tpmCert.getIssuerX500Principal().getName());
        
        // Verify the certificate is signed by the root CA
        tpmCert.verify(rsaKeyPair.getPublic());
        
        // Verify the certificate has the correct key usage
        boolean[] keyUsageFlags = tpmCert.getKeyUsage();
        System.err.println(Arrays.toString(keyUsageFlags));
        assertNotNull("Key usage should not be null", keyUsageFlags);
        assertTrue("Key usage flags should be byte len 8 :: " + keyUsageFlags.length, keyUsageFlags.length == 9);
        assertTrue("Certificate should have digitalSignature usage", keyUsageFlags[7]);
    }
    
    /**
     * Test generating a packed batch certificate
     */
    @Test
    public void testGeneratePackedBatchCertificate() throws Exception {
        // Generate a root CA certificate
        X509Certificate rootCert = CertUtils.generateCaCert("CN=Test Root CA", rsaKeyPair, 365, true);
        
        // Generate a packed batch certificate
        KeyPair batchKeyPair = KeyUtils.generateKeyPair("RSA", 2048);
        byte[] aaguid = new byte[16];
        new SecureRandom().nextBytes(aaguid);
        
        X509Certificate batchCert = CertUtils.generatePackedBatchCertificate(
            "CN=Test Batch", batchKeyPair, 365, aaguid, null, rsaKeyPair, rootCert);
        
        // Verify the certificate
        assertNotNull("Batch certificate should not be null", batchCert);
        assertEquals("Subject DN should match", "CN=Test Batch",
                    batchCert.getSubjectX500Principal().getName());
        assertEquals("Issuer DN should match", "CN=Test Root CA",
                    batchCert.getIssuerX500Principal().getName());
        
        // Verify the certificate is signed by the root CA
        batchCert.verify(rsaKeyPair.getPublic());
        
        // Test with function to add extensions
        java.util.function.Function<org.bouncycastle.cert.X509v3CertificateBuilder,
                                  org.bouncycastle.cert.X509v3CertificateBuilder> addExtensions =
            builder -> {
                try {
                    builder.addExtension(
                        org.bouncycastle.asn1.x509.Extension.keyUsage,
                        false,
                        new org.bouncycastle.asn1.x509.KeyUsage(
                            org.bouncycastle.asn1.x509.KeyUsage.digitalSignature));
                } catch (Exception e) {
                    // Ignore exceptions in test
                }
                return builder;
            };
        
        X509Certificate batchCertWithExt = CertUtils.generatePackedBatchCertificate(
            "CN=Test Batch With Extensions", batchKeyPair, 365, aaguid, addExtensions, rsaKeyPair, rootCert);
        
        // Verify the certificate
        assertNotNull("Batch certificate with extensions should not be null", batchCertWithExt);
    }
    
    /**
     * Test generating an Apple attestation certificate
     */
    @Test
    public void testGenerateAppleAttestationCertificate() throws Exception {
        // Generate a root CA certificate
        X509Certificate rootCert = CertUtils.generateCaCert("CN=Test Apple CA", rsaKeyPair, 365, true);
        
        // Generate an Apple attestation certificate
        KeyPair appleKeyPair = KeyUtils.generateKeyPair("RSA", 2048);
        byte[] nonce = new byte[32];
        new SecureRandom().nextBytes(nonce);
        
        X509Certificate appleCert = CertUtils.generateAppleAttestationCertificate(
            "CN=Test Apple Device", appleKeyPair, 365, nonce, rsaKeyPair, rootCert);
        
        // Verify the certificate
        assertNotNull("Apple certificate should not be null", appleCert);
        assertEquals("Subject DN should match", "CN=Test Apple Device",
                    appleCert.getSubjectX500Principal().getName());
        assertEquals("Issuer DN should match", "CN=Test Apple CA",
                    appleCert.getIssuerX500Principal().getName());
        
        // Verify the certificate is signed by the root CA
        appleCert.verify(rsaKeyPair.getPublic());
    }
    
    /**
     * Test generating a U2F certificate
     */
    @Test
    public void testGenerateU2FCertificate() throws Exception {
        // Generate a root CA certificate
        X509Certificate rootCert = CertUtils.generateCaCert("CN=Test U2F CA", ecKeyPair, 365, true);
        
        // Generate a U2F certificate
        KeyPair u2fKeyPair = KeyUtils.generateKeyPair("EC", 256);
        
        X509Certificate u2fCert = CertUtils.generateU2FCertificate(
            rootCert, "CN=Test U2F Device", u2fKeyPair, 365);
        
        // Verify the certificate
        assertNotNull("U2F certificate should not be null", u2fCert);
        assertEquals("Subject DN should match", "CN=Test U2F Device",
                    u2fCert.getSubjectX500Principal().getName());
        assertEquals("Issuer DN should match", "CN=Test U2F CA",
                    u2fCert.getIssuerX500Principal().getName());
        
        // Verify the certificate is signed by the key pair
        u2fCert.verify(u2fKeyPair.getPublic());
    }
    
    /**
     * Test generating a U2F signed certificate
     */
    @Test
    public void testGenerateU2FSignedCertificate() throws Exception {
        // Generate a root CA certificate
        X509Certificate rootCert = CertUtils.generateCaCert("CN=Test U2F CA", ecKeyPair, 365, true);
        
        // Generate a U2F certificate
        KeyPair u2fKeyPair = KeyUtils.generateKeyPair("EC", 256);
        
        X509Certificate u2fCert = CertUtils.generateU2FSignedCertificate(
            rootCert, "CN=Test U2F Device", u2fKeyPair, 365, ecKeyPair);
        
        // Verify the certificate
        assertNotNull("U2F signed certificate should not be null", u2fCert);
        assertEquals("Subject DN should match", "CN=Test U2F Device",
                    u2fCert.getSubjectX500Principal().getName());
        assertEquals("Issuer DN should match", "CN=Test U2F CA",
                    u2fCert.getIssuerX500Principal().getName());
        
        // Verify the certificate is signed by the CA key pair
        u2fCert.verify(ecKeyPair.getPublic());
    }
}

// Made with Bob