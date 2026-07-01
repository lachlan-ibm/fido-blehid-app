/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.util;

import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class CertUtilsBranchCoverageTest {

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    private KeyPair rsaCaKeyPair;
    private KeyPair rsaLeafKeyPair;
    private X509Certificate rsaCaCert;

    @Before
    public void setUp() throws Exception {
        rsaCaKeyPair = KeyUtils.generateKeyPair("RSA", 2048);
        rsaLeafKeyPair = KeyUtils.generateKeyPair("RSA", 2048);
        rsaCaCert = CertUtils.generateCaCert("CN=RSA Test CA", rsaCaKeyPair, 365, true);
    }

    @Test
    public void testReadCertFallsBackToPemStringWhenFileDoesNotExist() throws Exception {
        X509Certificate originalCert = CertUtils.generateCaCert("CN=Inline Cert", rsaLeafKeyPair, 365, true);
        String pem = toPem(originalCert.getEncoded(), "CERTIFICATE");

        X509Certificate parsedCert = (X509Certificate) CertUtils.readCert(pem, "X.509");

        assertEquals(originalCert.getSubjectX500Principal(), parsedCert.getSubjectX500Principal());
        parsedCert.verify(rsaLeafKeyPair.getPublic());
    }

    @Test
    public void testGeneratePackedBatchCertificateOmitsAaguidWhenNull() throws Exception {
        X509Certificate cert = CertUtils.generatePackedBatchCertificate(
                "CN=Packed Batch Null AAGUID", rsaLeafKeyPair, 365, null, null, rsaCaKeyPair,
                rsaCaCert);

        assertNull(cert.getExtensionValue("1.3.6.1.4.1.45724.1.1.4"));
        cert.verify(rsaCaKeyPair.getPublic());
    }

    @Test
    public void testGenerateCaCertWithoutSkiForRsaKey() throws Exception {
        KeyPair rsaKeyPair = KeyUtils.generateKeyPair("RSA", 2048);

        X509Certificate cert = CertUtils.generateCaCert("CN=RSA No SKI", rsaKeyPair, 365, false);

        assertNull(cert.getExtensionValue(Extension.subjectKeyIdentifier.getId()));
        assertTrue(cert.getBasicConstraints() >= 0);
        cert.verify(rsaKeyPair.getPublic());
    }

    @Test
    public void testGenerateCaCertWithoutSkiForEcKey() throws Exception {
        KeyPair ecKeyPair = KeyUtils.generateKeyPair("EC", 256);

        X509Certificate cert = CertUtils.generateCaCert("CN=EC No SKI", ecKeyPair, 365, false);

        assertNull(cert.getExtensionValue(Extension.subjectKeyIdentifier.getId()));
        assertTrue(cert.getBasicConstraints() >= 0);
        cert.verify(ecKeyPair.getPublic());
    }

    @Test
    public void testGenerateCaCertRejectsUnsupportedKeyType() throws Exception {
        PublicKey unsupportedPublicKey = new StubPublicKey("DSA");
        PrivateKey unsupportedPrivateKey = new StubPrivateKey("DSA");
        KeyPair unsupportedKeyPair = new KeyPair(unsupportedPublicKey, unsupportedPrivateKey);

        Exception exception = assertThrows(Exception.class,
                () -> CertUtils.generateCaCert("CN=Unsupported", unsupportedKeyPair, 365, true));

        assertEquals("Invalid keypair found", exception.getMessage());
    }

    @Test
    public void testGenerateIntermediateCACertOmitsSubjectAlternativeName() throws Exception {
        KeyPair intermediateKeyPair = KeyUtils.generateKeyPair("RSA", 2048);

        X509Certificate cert = CertUtils.generateIntermediateCACert(rsaCaCert, "CN=Intermediate No SAN",
                365, intermediateKeyPair, rsaCaKeyPair);

        assertNull(cert.getExtensionValue(Extension.subjectAlternativeName.getId()));
        assertTrue(cert.getBasicConstraints() >= 0);
        cert.verify(rsaCaKeyPair.getPublic());
    }

    @Test
    public void testGenerateAikCertOmitsSubjectAlternativeNameWhenAltNameNull() throws Exception {
        KeyPair aikKeyPair = KeyUtils.generateKeyPair("RSA", 2048);

        X509Certificate cert = CertUtils.generateAIKCert(rsaCaCert, 365, aikKeyPair, null, rsaCaKeyPair);

        assertNull(cert.getExtensionValue(Extension.subjectAlternativeName.getId()));
        assertEquals(-1, cert.getBasicConstraints());
        cert.verify(rsaCaKeyPair.getPublic());
    }

    @Test
    public void testGenerateAikCertWithoutAaguidOmitsAaguidExtension() throws Exception {
        KeyPair aikKeyPair = KeyUtils.generateKeyPair("RSA", 2048);

        X509Certificate cert = CertUtils.generateAIKCert(rsaCaCert, 365, aikKeyPair, "CN=AIK Device",
                rsaCaKeyPair);

        assertNull(cert.getExtensionValue(CertUtils.AAGUID_OID.getId()));
        cert.verify(rsaCaKeyPair.getPublic());
    }

    @Test
    public void testGenerateBadSNAikCertUsesNonEmptySubject() throws Exception {
        KeyPair aikKeyPair = KeyUtils.generateKeyPair("RSA", 2048);

        X509Certificate cert = CertUtils.generateBadSNAIKCert(rsaCaCert, 365, aikKeyPair, "CN=AIK Device",
                rsaCaKeyPair);

        assertEquals("CN=bad", cert.getSubjectX500Principal().getName());
        cert.verify(rsaCaKeyPair.getPublic());
    }

    @Test
    public void testGenerateMissingAikCertificateExtensionOmitsTcgAikExtendedKeyUsage() throws Exception {
        KeyPair aikKeyPair = KeyUtils.generateKeyPair("RSA", 2048);

        X509Certificate cert = CertUtils.generateMissingAIKCertificateExtension(rsaCaCert, 365, aikKeyPair,
                "CN=AIK Device", rsaCaKeyPair);

        assertFalse(cert.getExtendedKeyUsage().contains(KeyPurposeId.getInstance(
                CertUtils.TCG_KP_AIK_CERTIFICATE_ATTRIBUTE).getId()));
        assertNotNull(cert.getExtensionValue(Extension.subjectAlternativeName.getId()));
        cert.verify(rsaCaKeyPair.getPublic());
    }

    @Test
    public void testGenerateAkiCertWithBasicConstraintsAddsInvalidBasicConstraintsExtension()
            throws Exception {
        KeyPair aikKeyPair = KeyUtils.generateKeyPair("RSA", 2048);

        X509Certificate cert = CertUtils.generateAKICertWithBasicConstraints(rsaCaCert, 365, aikKeyPair,
                "CN=AIK Device", rsaCaKeyPair);

        byte[] extensionValue = cert.getExtensionValue(Extension.basicConstraints.getId());
        assertNotNull(extensionValue);
        BasicConstraints constraints = BasicConstraints.fromExtensions(
                new org.bouncycastle.asn1.x509.Extensions(new Extension[] {
                        new Extension(Extension.basicConstraints, false,
                                ASN1OctetString.getInstance(extensionValue).getOctets()) }));
        assertTrue(constraints.isCA());
        cert.verify(rsaCaKeyPair.getPublic());
    }

    @Test
    public void testGenerateAkiCertWithBadAaguidAddsRandomSizedAaguidExtension() throws Exception {
        KeyPair aikKeyPair = KeyUtils.generateKeyPair("RSA", 2048);

        X509Certificate cert = CertUtils.generateAKICertWithBadAAGUID(rsaCaCert, 365, aikKeyPair,
                "CN=AIK Device", rsaCaKeyPair);

        byte[] extensionValue = cert.getExtensionValue(CertUtils.AAGUID_OID.getId());
        assertNotNull(extensionValue);
        assertEquals(16, ASN1OctetString.getInstance(extensionValue).getOctets().length);
        cert.verify(rsaCaKeyPair.getPublic());
    }

    private static String toPem(byte[] encoded, String type) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.write(("-----BEGIN " + type + "-----\n").getBytes(StandardCharsets.UTF_8));
        output.write(java.util.Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                .encode(encoded));
        output.write(("\n-----END " + type + "-----\n").getBytes(StandardCharsets.UTF_8));
        return output.toString(StandardCharsets.UTF_8.name());
    }

    private static final class StubPublicKey implements PublicKey {
        private final String algorithm;

        private StubPublicKey(String algorithm) {
            this.algorithm = algorithm;
        }

        @Override
        public String getAlgorithm() {
            return algorithm;
        }

        @Override
        public String getFormat() {
            return "X.509";
        }

        @Override
        public byte[] getEncoded() {
            return new byte[] { 1, 2, 3 };
        }
    }

    private static final class StubPrivateKey implements PrivateKey {
        private final String algorithm;

        private StubPrivateKey(String algorithm) {
            this.algorithm = algorithm;
        }

        @Override
        public String getAlgorithm() {
            return algorithm;
        }

        @Override
        public String getFormat() {
            return "PKCS#8";
        }

        @Override
        public byte[] getEncoded() {
            return new byte[] { 4, 5, 6 };
        }
    }
}
