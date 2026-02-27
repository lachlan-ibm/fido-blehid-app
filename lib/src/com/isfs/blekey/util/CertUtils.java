/*
 * Copyright IBM 2025
 */
/*IBM Confidential
* OCO Source Materials
* 5725-V89 5725-V90
*
* Copyright IBM Corp. 2019, 2025
*
* The source code for this program is not published or otherwise divested of its trade secrets,
* irrespective of what has been deposited with the U.S. Copyright Office.
*/
package com.isfs.blekey.util;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.function.Function;

public class CertUtils implements java.io.Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = 5384670213712592314L;

    private static String b64String(byte[] in) {
        return Base64.getEncoder().encodeToString(in);
    }


    public static final ASN1ObjectIdentifier TCG_KP_AIK_CERTIFICATE_ATTRIBUTE = new ASN1ObjectIdentifier(
            "2.23.133.8.3");

    public static final ASN1ObjectIdentifier AAGUID_OID = new ASN1ObjectIdentifier(
            "1.3.6.1.4.1.45724.1.1.4");

    public static Certificate readCert(String fileName, String alg)
            throws FileNotFoundException, CertificateException, IOException,
            InvalidKeySpecException {
        InputStream inStream = null;
        try {
            inStream = new FileInputStream(fileName);
        } catch (IOException ioe) {
            inStream = new ByteArrayInputStream(fileName.getBytes());
        }
        CertificateFactory certFactory = CertificateFactory.getInstance(alg);
        Certificate cert = certFactory.generateCertificate(inStream);
        inStream.close();
        return cert;
    }

    public static Certificate readBytes(byte[] certBytes, String alg)
            throws CertificateException, IOException, InvalidKeySpecException {
        CertificateFactory certFactory = CertificateFactory.getInstance(alg);
        return certFactory.generateCertificate(new ByteArrayInputStream(certBytes));
    }

    /**
     * 
     * @param X509Certificate trust chain certificate
     * @param dn              Subject
     * @param pubKey          Public Key to sign certificate
     * @param expiry          Expiry of certificate
     * @return X509v3CertificateBuilder certificate builder with provided params,
     *         can add extensions as required
     */
    private static X509v3CertificateBuilder certificateBuilder(X509Certificate caCert,
            String dn, PublicKey pubKey, int expiry) {
        Calendar valid = Calendar.getInstance();
        valid.add(Calendar.DAY_OF_YEAR, expiry);
        X500Name subject = (dn == null) ? new X500Name(new RDN[0]) : new X500Name(dn);
        X509v3CertificateBuilder certBuilder = null;
        if (caCert == null) {
            certBuilder = new JcaX509v3CertificateBuilder(subject,
                    BigInteger.valueOf(System.currentTimeMillis()),
                    new Date(System.currentTimeMillis()), valid.getTime(), subject, pubKey);
        } else {
            certBuilder = new JcaX509v3CertificateBuilder(caCert,
                    BigInteger.valueOf(System.currentTimeMillis()),
                    new Date(System.currentTimeMillis()), valid.getTime(), subject, pubKey);
        }
        return certBuilder;
    }

    private static X509v3CertificateBuilder certificateBuilder(String dn, PublicKey pubKey,
            int expiry) {
        return certificateBuilder(null, dn, pubKey, expiry);
    }

    public static X509Certificate generateAppleAttestationCertificate(String dn, KeyPair keyPair,
            int days, byte[] nonce, KeyPair signKeyPair, X509Certificate signCert) throws Exception {
        ASN1ObjectIdentifier appleOid = new ASN1ObjectIdentifier("1.2.840.113635.100.8.2");
        ASN1Sequence nonceEncoded = (ASN1Sequence) new DERSequence(
                new DERTaggedObject(true, 0, new DEROctetString(nonce))).toASN1Primitive();
        X509v3CertificateBuilder certBuilder = certificateBuilder(signCert, dn, keyPair.getPublic(),
                days);
        certBuilder.addExtension(appleOid, false, nonceEncoded);
        
        X509Certificate result = new JcaX509CertificateConverter()
                .getCertificate(certBuilder.build(new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(signKeyPair.getPrivate())));
        return result;        
    }
    
    public static X509Certificate generatePackedBatchCertificate(String dn, KeyPair keyPair,
            int days, byte[] aaguid,
            Function<X509v3CertificateBuilder, X509v3CertificateBuilder> addExtensions, KeyPair signKP, X509Certificate caCert)
            throws IOException, OperatorCreationException, CertificateException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        X509Certificate result = null;

        X509v3CertificateBuilder certBuilder = certificateBuilder(caCert, dn, keyPair.getPublic(),
                days);


        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4");
        // value must be a double encoded octet stream
        if (aaguid != null) {
        ASN1OctetString value = new DEROctetString(aaguid);

        certBuilder.addExtension(oid, false, value);
        }
        if (addExtensions != null) {
            certBuilder = addExtensions.apply(certBuilder);
        }
        result = new JcaX509CertificateConverter()
                .getCertificate(certBuilder.build(new JcaContentSignerBuilder("SHA256withRSA")
                        .setProvider("BC").build(signKP.getPrivate())));

        return result;
    }

    public static X509Certificate generatePackedBasicCertificate(String dn, KeyPair keyPair,
            int days, String aaguid)
            throws IOException, OperatorCreationException, CertificateException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        X509Certificate result = null;

        X509v3CertificateBuilder certBuilder = certificateBuilder(dn, keyPair.getPublic(),
                days);
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4");
        // value must be a double encoded octet stream
        ASN1OctetString value = new DEROctetString(new byte[16]);
        certBuilder.addExtension(oid, false, value);
        result = new JcaX509CertificateConverter()
                .getCertificate(certBuilder.build(new JcaContentSignerBuilder("SHA256withRSA")
                        .setProvider("BC").build(keyPair.getPrivate())));

        return result;
    }

    public static X509Certificate gereatePackedAttCACertificate(X509Certificate caCert,
            String dn, KeyPair keyPair, int days, byte[] aaguid, KeyPair signKeyPair)
            throws IOException, OperatorCreationException, CertificateException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        X509Certificate result = null;

        X509v3CertificateBuilder certBuilder = certificateBuilder(caCert, dn,
                keyPair.getPublic(), days);

        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4");
        // value must be a double encoded octet stream
        ASN1OctetString value = new DEROctetString(aaguid);
        certBuilder.addExtension(oid, false, value);
        String javaAglName = "SHA256withRSA";
        if(signKeyPair.getPrivate() instanceof ECPrivateKey) {
                javaAglName = "SHA256withECDSA";
        }
        result = new JcaX509CertificateConverter().getCertificate(certBuilder.build(
                new JcaContentSignerBuilder(javaAglName).build(signKeyPair.getPrivate())));

        return result;
    }


    public static X509Certificate generateU2FCertificate(X509Certificate caCert, String dn,
            KeyPair keyPair, int days) throws CertificateException, OperatorCreationException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        X509Certificate result = null;

        X509v3CertificateBuilder certBuilder = certificateBuilder(caCert, dn,
                keyPair.getPublic(), days);

        result = new JcaX509CertificateConverter()
                .getCertificate(certBuilder.build(new JcaContentSignerBuilder("SHA256withECDSA")
                        .setProvider("BC").build(keyPair.getPrivate())));

        return result;
    }

    public static X509Certificate generateU2FSignedCertificate(X509Certificate caCert,
            String dn, KeyPair keyPair, int days, KeyPair caKeyPair)
            throws CertificateException, OperatorCreationException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        X509Certificate result = null;

        X509v3CertificateBuilder certBuilder = certificateBuilder(caCert, dn,
                keyPair.getPublic(), days);

        result = new JcaX509CertificateConverter()
                .getCertificate(certBuilder.build(new JcaContentSignerBuilder("SHA256withECDSA")
                        .setProvider("BC").build(caKeyPair.getPrivate())));

        return result;
    }

    public static X509Certificate generateCaCert(String dn, KeyPair keyPair, int days,
            boolean addSki) throws Exception {
        PublicKey pubKey = keyPair.getPublic();
        if (pubKey instanceof RSAPublicKey) {
            return generateRsaCaCert(dn, keyPair, days, addSki);
        } else if (pubKey instanceof ECPublicKey) {
            return generateEcCaCert(dn, keyPair, days, addSki);
        } else {
            throw new Exception("Invalid keypair found");
        }
    }

    private static X509Certificate generateRsaCaCert(String dn, KeyPair keyPair, int days,
            boolean addSki) throws CertificateEncodingException, CertIOException,
            OperatorCreationException, CertificateException, NoSuchAlgorithmException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        X509Certificate result = null;

        X509v3CertificateBuilder certBuilder = certificateBuilder(dn, keyPair.getPublic(),
                days);
        // usage restrictions
        certBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(
                KeyUsage.cRLSign | KeyUsage.keyCertSign | KeyUsage.digitalSignature));
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        if (addSki) {
            SubjectKeyIdentifier ski = extUtils.createSubjectKeyIdentifier(keyPair.getPublic());
            System.err.println("ski: " + b64String(ski.getKeyIdentifier()).toString());
            certBuilder.addExtension(Extension.subjectKeyIdentifier, false, ski);
        }
        certBuilder.addExtension(Extension.basicConstraints, false, new BasicConstraints(true));
        // build certificate
        result = new JcaX509CertificateConverter().getCertificate(certBuilder.build(
                new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate())));
        return result;
    }

    private static X509Certificate generateEcCaCert(String dn, KeyPair keyPair, int days,
            boolean addSki) throws CertificateEncodingException, CertIOException,
            OperatorCreationException, CertificateException, NoSuchAlgorithmException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        X509Certificate result = null;

        X509v3CertificateBuilder certBuilder = certificateBuilder(dn, keyPair.getPublic(),
                days);
        // usage restrictions
        certBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.keyCertSign));
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        if (addSki) {
            SubjectKeyIdentifier ski = extUtils.createSubjectKeyIdentifier(keyPair.getPublic());
            System.err.println("ski: " + b64String(ski.getKeyIdentifier()).toString());
            certBuilder.addExtension(Extension.subjectKeyIdentifier, false, ski);
        }
        certBuilder.addExtension(Extension.basicConstraints, false, new BasicConstraints(true));
        // build certificate
        result = new JcaX509CertificateConverter().getCertificate(certBuilder.build(
                new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate())));
        return result;
    }

    private static X509Certificate generateTPMCert(X509Certificate caCert, String dn, int days,
            KeyPair keyPair, boolean aikCert, String altName, KeyPair signKeyPair,
            boolean keyUsageCritical, int keyUsage, byte[] aaguid)
            throws CertIOException, OperatorCreationException, CertificateException {
        X509Certificate result = null;
        X509v3CertificateBuilder certBuilder = certificateBuilder(caCert, dn,
                keyPair.getPublic(), days);

        certBuilder.addExtension(Extension.keyUsage, keyUsageCritical, new KeyUsage(keyUsage));
        certBuilder.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(new KeyPurposeId[] { KeyPurposeId
                        .getInstance(CertUtils.TCG_KP_AIK_CERTIFICATE_ATTRIBUTE) }));
        certBuilder.addExtension(Extension.basicConstraints, false,
                new BasicConstraints(!aikCert));
        if (aikCert && altName != null) {
            List<GeneralName> altNames = new ArrayList<GeneralName>();
            altNames.add(new GeneralName(GeneralName.directoryName, altName));
            GeneralNames subjectAltNames = GeneralNames.getInstance(
                    new DERSequence((GeneralName[]) altNames.toArray(new GeneralName[] {})));
            certBuilder.addExtension(Extension.subjectAlternativeName, true, subjectAltNames);
        }
        if(aaguid != null) {
            certBuilder.addExtension(AAGUID_OID, false,
                    aaguid);
        }

        result = new JcaX509CertificateConverter()
                .getCertificate(certBuilder.build(new JcaContentSignerBuilder("SHA256withRSA")
                        .setProvider("BC").build(signKeyPair.getPrivate())));
        return result;
    }


    
    public static X509Certificate generateIntermediateCACert(X509Certificate caCert, String dn,
            int days, KeyPair keyPair, KeyPair caKeyPair)
            throws CertIOException, OperatorCreationException, CertificateException {
        return generateTPMCert(caCert, dn, days, keyPair, false, null, caKeyPair, false,
                (KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign), null);
    }

    public static X509Certificate generateAIKCert(X509Certificate caCert, int days,
            KeyPair keyPair, String altNames, KeyPair caKeyPair)
            throws CertIOException, OperatorCreationException, CertificateException {
        return generateTPMCert(caCert, null, days, keyPair, true, altNames, caKeyPair, true,
                KeyUsage.digitalSignature, null);
    }
    
    public static X509Certificate generateAIKCert(X509Certificate caCert, int days,
            KeyPair keyPair, String altNames, KeyPair caKeyPair, byte[] aaguid)
            throws CertIOException, OperatorCreationException, CertificateException {
        return generateTPMCert(caCert, null, days, keyPair, true, altNames, caKeyPair, true,
                KeyUsage.digitalSignature, aaguid);
    }

    public static X509Certificate generateBadSNAIKCert(X509Certificate caCert, int days,
            KeyPair keyPair, String altNames, KeyPair caKeyPair)
            throws CertIOException, OperatorCreationException, CertificateException {
        // bad AIK cert has subjectName not empty
        return generateTPMCert(caCert, "CN=bad", days, keyPair, true, altNames, caKeyPair, true,
                KeyUsage.digitalSignature, null);
    }

    public static X509Certificate generateBadVersionAIKCertificate(X509Certificate caCert,
            int days, KeyPair keyPair, String altNames, KeyPair caKeyPair)
            throws CertIOException, OperatorCreationException, CertificateException {
        // bad AIK cert has subjectName not empty
        X509Certificate result = null;
        Calendar valid = Calendar.getInstance();
        valid.add(Calendar.DAY_OF_YEAR, days);
        X500Name subject = new X500Name("CN=invalid");
        X509v1CertificateBuilder certBuilder = new JcaX509v1CertificateBuilder(subject,
                BigInteger.valueOf(System.currentTimeMillis()),
                new Date(System.currentTimeMillis()), valid.getTime(), subject,
                keyPair.getPublic());

        result = new JcaX509CertificateConverter()
                .getCertificate(certBuilder.build(new JcaContentSignerBuilder("SHA256withRSA")
                        .setProvider("BC").build(caKeyPair.getPrivate())));
        return result;
    }

    public static X509Certificate generateMissingAIKCertificateExtension(X509Certificate caCert,
            int days, KeyPair keyPair, String altName, KeyPair caKeyPair)
            throws CertIOException, OperatorCreationException, CertificateException {
        X509Certificate result = null;
        X509v3CertificateBuilder certBuilder = certificateBuilder(caCert, null,
                keyPair.getPublic(), days);

        certBuilder.addExtension(Extension.keyUsage, false,
                new KeyUsage(KeyUsage.digitalSignature));
        certBuilder.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(new KeyPurposeId[0]));
        List<GeneralName> altNames = new ArrayList<GeneralName>();
        altNames.add(new GeneralName(GeneralName.directoryName, altName));
        GeneralNames subjectAltNames = GeneralNames.getInstance(
                new DERSequence((GeneralName[]) altNames.toArray(new GeneralName[] {})));
        certBuilder.addExtension(Extension.subjectAlternativeName, true, subjectAltNames);

        result = new JcaX509CertificateConverter()
                .getCertificate(certBuilder.build(new JcaContentSignerBuilder("SHA256withRSA")
                        .setProvider("BC").build(caKeyPair.getPrivate())));
        return result;
    }

    public static X509Certificate generateAKICertWithBasicConstraints(X509Certificate caCert,
            int days, KeyPair keyPair, String altName, KeyPair caKeyPair)
            throws CertIOException, OperatorCreationException, CertificateException {
        X509Certificate result = null;
        X509v3CertificateBuilder certBuilder = certificateBuilder(caCert, null,
                keyPair.getPublic(), days);

        certBuilder.addExtension(Extension.keyUsage, false,
                new KeyUsage(KeyUsage.digitalSignature));
        certBuilder.addExtension(Extension.basicConstraints, false, new BasicConstraints(
                KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));
        certBuilder.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(new KeyPurposeId[] { KeyPurposeId
                        .getInstance(CertUtils.TCG_KP_AIK_CERTIFICATE_ATTRIBUTE) }));
        List<GeneralName> altNames = new ArrayList<GeneralName>();
        altNames.add(new GeneralName(GeneralName.directoryName, altName));
        GeneralNames subjectAltNames = GeneralNames.getInstance(
                new DERSequence((GeneralName[]) altNames.toArray(new GeneralName[] {})));
        certBuilder.addExtension(Extension.subjectAlternativeName, true, subjectAltNames);

        result = new JcaX509CertificateConverter()
                .getCertificate(certBuilder.build(new JcaContentSignerBuilder("SHA256withRSA")
                        .setProvider("BC").build(caKeyPair.getPrivate())));
        return result;
    }

    public static X509Certificate generateAKICertWithBadAAGUID(X509Certificate caCert, int days,
            KeyPair keyPair, String altNames, KeyPair caKeyPair)
            throws CertIOException, OperatorCreationException, CertificateException {
        byte[] randBytes = new byte[16];
        new SecureRandom().nextBytes(randBytes);
        return generateTPMCert(caCert, null, days, keyPair, true, altNames, caKeyPair, true,
                KeyUsage.digitalSignature, randBytes);
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: CertUtils pemfile");
            System.exit(1);
        }
        String pemFile = args[0];
        try {
            X509Certificate cert = (X509Certificate) CertUtils.readCert(pemFile, "X.509");
            PublicKey pk = cert.getPublicKey();
            System.out.println("X509 Public Key:");
            System.out.println(pk.getAlgorithm() + " " + pk.getFormat());
            System.out.println(Base64.getEncoder().encodeToString(pk.getEncoded()));
            System.exit(0);
        } catch (Exception e) {
            System.out.println("Failed to get X509 Public key");
//            e.printStackTrace();
        }

        try {
            ECPublicKey cert = (ECPublicKey) FileUtils.readPublicPEM(new File(pemFile));
            System.out.println("EC Public Key:");
            ECPoint point = cert.getW();
            String x = point.getAffineX().toString(16);
            String y = point.getAffineY().toString(16);
            System.out.println("X = " + x + ", Y = " + y);
            System.exit(0);
        } catch (Exception e) {
            System.out.println("Failed to get EC Public key");
//            e.printStackTrace();
        }

        try {
            PrivateKey pk = FileUtils.readPrivatePEM(new File(pemFile));
            System.out.println("RSA Private Key:");
            System.out.println(pk.getAlgorithm() + " " + pk.getFormat());
            System.out.println(Base64.getEncoder().encodeToString(pk.getEncoded()));
            System.exit(0);
        } catch (Exception e) {
            System.out.println("Failed to get RSA private key");
//            e.printStackTrace();
        }

        try {
            PrivateKey pk = FileUtils.readPrivatePEM(new File(pemFile));
            System.out.println("EC Private Key:");
            System.out.println(pk.getAlgorithm() + " " + pk.getFormat());
            System.out.println(Base64.getEncoder().encodeToString(pk.getEncoded()));
            System.exit(0);
        } catch (Exception e) {
            System.out.println("Failed to get EC private key");
            e.printStackTrace();
        }
    }
}
