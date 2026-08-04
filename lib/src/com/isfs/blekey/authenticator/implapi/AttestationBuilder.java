/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator.implapi;

import com.isfs.blekey.authenticator.CredentialType;
import com.isfs.blekey.authenticator.Fido2Authenticator;
import com.isfs.blekey.ctap.Ctap2StatusCode;
import com.isfs.blekey.ctap.CtapTxn;
import com.isfs.blekey.util.Cbor;
import com.isfs.blekey.util.KeyUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.util.Map;

/**
 * Builds the attestation data for a {@code makeCredential} response.
 *
 * <p>Owns: {@code buildAuthenticatorData()}, {@code createAttestationStatement()},
 * {@code buildMakeCredentialResponse()}, {@code loadAttestationMaterial()},
 * {@code loadAttestationKeyPair()}, {@code loadAnonCA()}, {@code buildCredentialData()},
 * and {@code extractClientDataHash()}.</p>
 *
 * <p>{@link AttestationMaterial} lives as a package-private top-level class at the
 * bottom of this file (§6g).</p>
 */
public class AttestationBuilder {

    private static final Logger logger = LoggerFactory.getLogger(AttestationBuilder.class);

    private AttestationBuilder() {}

    // -------------------------------------------------------------------------
    // loadAttestationMaterial
    // -------------------------------------------------------------------------

    /**
     * Loads the key pair and anonymous CA certificate for attestation.
     */
    public static AttestationMaterial loadAttestationMaterial(
            CredentialType credentialType, CtapTxn txn) throws Exception {
        KeyPair keyPair = loadAttestationKeyPair(credentialType, txn);
        X509Certificate anonCA = loadAnonCA(txn);
        return new AttestationMaterial(keyPair, anonCA);
    }

    private static KeyPair loadAttestationKeyPair(
            CredentialType credentialType, CtapTxn txn) throws Exception {
        if (credentialType == CredentialType.PASSKEY || credentialType == CredentialType.RESIDENT) {
            PrivateKey passkeyPrivateKey = txn.getPasskey().getPrivateKey();
            PublicKey passkeyPublicKey = KeyUtils.getPubKey((ECPrivateKey) passkeyPrivateKey);
            logger.info("loadAttestationKeyPair: UV verified — using passkey file key");
            return new KeyPair(passkeyPublicKey, passkeyPrivateKey);
        }
        PrivateKey platformKey = KeyUtils.getPlatformKey();
        PublicKey platformPublicKey = KeyUtils.getPubKey((ECPrivateKey) platformKey);
        return new KeyPair(platformPublicKey, platformKey);
    }

    static X509Certificate loadAnonCA(CtapTxn txn) {
        // TODO: generate correct anon CA cert from spec
        return (txn.getPasskey() == null) ? null : txn.getPasskey().getCertificate();
    }

    // -------------------------------------------------------------------------
    // buildCredentialData
    // -------------------------------------------------------------------------

    /**
     * Builds authenticator data and attestation statement, returning them as a
     * {@link CredentialCreationResult}.
     */
    public static CredentialCreationResult buildCredentialData(
            Map<Integer, Object> req,
            Fido2Authenticator authenticator,
            AttestationMaterial attestation) throws Exception {

        byte[] clientDataHash = extractClientDataHash(req);
        if (clientDataHash == null) {
            logger.error("buildCredentialData: clientDataHash is null");
            return new CredentialCreationResult(Ctap2StatusCode.MISSING_PARAMETER);
        }

        byte[] authenticatorData = buildAuthenticatorData(req, authenticator);
        if (authenticatorData == null) {
            logger.error("buildCredentialData: authenticatorData is null");
            return new CredentialCreationResult(Ctap2StatusCode.OTHER);
        }

        Map<String, Object> attestationStatement = createAttestationStatement(
            clientDataHash, authenticatorData, authenticator,
            attestation.keyPair, attestation.anonCA);
        if (attestationStatement == null) {
            logger.error("buildCredentialData: attestationStatement is null");
            return new CredentialCreationResult(Ctap2StatusCode.OTHER);
        }
        logger.debug("buildCredentialData: attestationStatement keys: {}",
                     attestationStatement.keySet());
        logger.debug("=== buildCredentialData SUCCESS ===");
        return new CredentialCreationResult(authenticatorData, attestationStatement);
    }

    // -------------------------------------------------------------------------
    // Inner builders
    // -------------------------------------------------------------------------

    static byte[] buildAuthenticatorData(
            Map<Integer, Object> req,
            Fido2Authenticator authenticator) throws Exception {
        Object rpValue = req.get(0x02);
        logger.debug("RP value from request: {}", rpValue);
        Map<String, Object> options = Map.of("rp", rpValue, "attestation", true);
        return authenticator.buildAuthenticatorData(
            options, "packed", null, null, authenticator.getKeyPair());
    }

    /**
     * Creates the packed or packed-self attestation statement.
     */
    public static Map<String, Object> createAttestationStatement(
            byte[] clientDataHash,
            byte[] authenticatorData,
            Fido2Authenticator authenticator,
            KeyPair attestationKeyPair,
            X509Certificate akiCert) throws Exception {

        logger.debug("=== createAttestationStatement START ===");
        logger.debug("clientDataHash length: {}", clientDataHash != null ? clientDataHash.length : "null");
        logger.debug("authenticatorData length: {}", authenticatorData != null ? authenticatorData.length : "null");
        logger.debug("credId length: {}", authenticator.getCredId() != null ? authenticator.getCredId().length : "null");
        logger.debug("attestationKeyPair: {}", attestationKeyPair != null ? "present" : "null");
        logger.debug("akiCert: {}", akiCert != null ? "present" : "null");

        String format = (akiCert == null) ? "packed-self" : "packed";
        logger.debug("createAttestationStatement: using format '{}' (akiCert {})",
                     format, akiCert != null ? "present" : "null");

        Map<String, Object> result = authenticator.processAttestationStatement(
            format, clientDataHash, authenticatorData,
            authenticator.getCredId(), authenticator.getKeyPair(),
            attestationKeyPair, akiCert);

        logger.debug("attestationStatement result: {}", result != null ? result.keySet() : "null");
        logger.debug("=== createAttestationStatement END ===");
        return result;
    }

    /**
     * Encodes and prepends the CTAP success byte to produce the wire response.
     */
    public static byte[] buildMakeCredentialResponse(
            byte[] authenticatorData,
            Map<String, Object> attestationStatement) {

        logger.debug("=== buildMakeCredentialResponse START ===");
        Map<Integer, Object> response = Map.of(
            0x01, "packed",
            0x02, authenticatorData,
            0x03, attestationStatement
        );
        byte[] encoded = Cbor.encode(response);
        if (encoded == null || encoded.length == 0) {
            logger.error("CBOR encoding returned empty or null result!");
        }
        ByteBuffer bb = ByteBuffer.allocate(encoded.length + 1);
        bb.put((byte) Ctap2StatusCode.SUCCESS.getCode());
        bb.put(encoded);
        return bb.array();
    }

    static byte[] extractClientDataHash(Map<Integer, Object> req) {
        byte[] clientDataHash = (byte[]) req.get(0x01);
        if (clientDataHash == null) {
            logger.error("Missing required clientDataHash (0x01) in request");
        }
        return clientDataHash;
    }
}

// ---------------------------------------------------------------------------
// Result type co-located with AttestationBuilder (§6g)
// ---------------------------------------------------------------------------

/** Container for attestation material: key pair + anonymous CA certificate. */
class AttestationMaterial {
    final KeyPair keyPair;
    final X509Certificate anonCA;

    AttestationMaterial(KeyPair keyPair, X509Certificate anonCA) {
        this.keyPair = keyPair;
        this.anonCA = anonCA;
    }
}
