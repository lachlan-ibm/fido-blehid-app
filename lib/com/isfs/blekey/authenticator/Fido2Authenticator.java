/*IBM Confidential
* OCO Source Materials
* 5725-V89 5725-V90
*
* Copyright IBM Corp. 2019, 2025
*
* The source code for this program is not published or otherwise divested of its trade secrets,
* irrespective of what has been deposited with the U.S. Copyright Office.
*/
package com.isfs.blekey.authenticator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPoint;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;

import com.isfs.blekey.data.Passkey;
import com.isfs.blekey.util.Cbor;
import com.isfs.blekey.util.CertUtils;
import com.isfs.blekey.util.KeyUtils;
import com.macasaet.fernet.Key;
import com.macasaet.fernet.Token;
import com.isfs.blekey.util.DataMapper;

/**
 * Core implementation of the FIDO2 authenticator functionality.
 * This class handles credential creation, assertion generation, and attestation
 * for FIDO2 WebAuthn operations.
 */
@SuppressWarnings("unchecked")
public class Fido2Authenticator implements java.io.Serializable {

    /**
     * Serial version UID for serialization.
     */
    private static final long serialVersionUID = -7830063672721389698L;

    /**
     * The key pair used for signing operations.
     */
    private KeyPair keyPair;

    /**
     * Counter used for signature operations to prevent replay attacks.
     */
    private long counter = 0;

    /**
     * The certificate authority key pair used for attestation.
     */
    private KeyPair caKeyPair;

    /**
     * The certificate authority certificate used for attestation.
     */
    private X509Certificate caCert;

    /**
     * Key used for encryption/decryption operations.
     */
    private Key fKey;


    /**
     * User verification bit in the Authenticator Data output buffer
     */
    private boolean userVerified = true;

    /**
     * Set of valid authenticator extensions supported by this implementation.
     */
    private static Set<String> validAuthenticatorExtensions = new HashSet<String>(
            Arrays.asList("txAuthSimple", "txAuthGeneric"));

    /**
     * Vendor ID for IBM TPM chip.
     */
    protected static final byte[] TPM_VENDOR_ID_CONFORMANCE = new BigInteger("fffff1d0", 16)
            .toByteArray();

    /**
     * Test AAGUID (Authenticator Attestation GUID) used for attestation.
     * Currently set to all zeros.
     */
    protected byte[] TEST_AAGUID = new byte[16];
    
    /**
     * Subject alternative name OID for TPM manufacturer.
     */
    protected static final String TPM_MANUFACTURER = "2.23.133.2.1";
    
    /**
     * Subject alternative name OID for TPM vendor.
     */
    protected static final String TPM_VENDOR = "2.23.133.2.2";
    
    /**
     * Subject alternative name OID for TPM firmware version.
     */
    protected static final String TPM_FW_VERSION = "2.23.133.2.3";

    /**
     * Constructs a new Fido2Authenticator with an EC key pair.
     */
    public Fido2Authenticator() {
        try {
            this.keyPair = KeyUtils.getKeyPair("EC");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Constructs a new Fido2Authenticator with a key pair of the specified algorithm.
     *
     * @param alg The algorithm to use for the key pair (e.g., "EC", "RSA")
     * @throws Exception if an error occurs while generating the key pair
     */
    public Fido2Authenticator(String alg) throws Exception {
        this.keyPair = KeyUtils.getKeyPair(alg);
    }
    
    /**
     * Constructs a new Fido2Authenticator with a key pair of the specified algorithm and size.
     *
     * @param alg The algorithm to use for the key pair (e.g., "EC", "RSA")
     * @param keySize The key size in bits
     * @throws NoSuchAlgorithmException if the specified algorithm is not available
     */
    public Fido2Authenticator(String alg, int keySize) throws NoSuchAlgorithmException {
        this.keyPair = KeyUtils.generateKeyPair(alg, keySize);
    }

    /**
     * Creates a Fido2Authenticator from an existing Passkey.
     *
     * @param pkey The passkey to use
     * @return A new Fido2Authenticator initialized with the passkey's data
     * @throws Exception if an error occurs during initialization
     */
    public static Fido2Authenticator fromPasskey(Passkey pkey) throws Exception {
        Fido2Authenticator a = new Fido2Authenticator();
        a.caCert = pkey.getCertificate();
        PublicKey caPub = KeyUtils.getPubKey((ECPrivateKey) pkey.getPrivateKey());
        a.caKeyPair = new KeyPair(caPub,pkey.getPrivateKey());
        a.fKey = new Key(pkey.getSeed());
        return a;
    }

    /**
     * Gets the key pair used for signing operations.
     *
     * @return The key pair
     */
    public KeyPair getKeyPair() {
        return this.keyPair;
    }

    /**
     * Gets the certificate authority key pair used for attestation.
     *
     * @return The certificate authority key pair
     */
    public KeyPair getCaKeyPair() {
        return this.caKeyPair;
    }

    /**
     * Gets the certificate authority certificate used for attestation.
     *
     * @return The certificate authority certificate
     */
    public X509Certificate getCaCert() {
        return this.caCert;
    }

    /**
     * Sets the key pair used for signing operations.
     *
     * @param kp The key pair to use
     * @return This Fido2Authenticator instance for method chaining
     */
    public Fido2Authenticator setKeyPair(KeyPair kp) {
        this.keyPair = kp;
        return this;
    }

    /**
     * Gets the current value of the signature counter.
     *
     * @return The signature counter value
     */
    public long getCounter() {
        return counter;
    }

    /**
     * Sets the signature counter to a specific value.
     *
     * @param c The new counter value
     */
    public void setCounter(long c) {
        counter = c;
    }

    /**
     * Gets the public key used for signing operations.
     *
     * @return The public key
     */
    public final PublicKey getPubKey() {
        return this.keyPair.getPublic();
    }

    /**
     * Gets the private key used for signing operations.
     *
     * @return The private key
     */
    public final PrivateKey getPrivKey() {
        return this.keyPair.getPrivate();
    }

    /**
     * Converts an EC BigInteger coordinate to a byte array, removing any leading zero
     * that might be present for negative values.
     *
     * @param point The BigInteger coordinate to convert
     * @return The byte array representation of the coordinate
     */
    private byte[] ECBigIntegerToByteArray(BigInteger point) {
        byte[] result = point.toByteArray();
        if (result.length == 33) { // Remove leading zero, added if coordinate is negative
            result = Arrays.copyOfRange(result, 1, result.length);
        }
        return result;
    }

    /**
     * Generates credential ID bytes for the current key pair.
     * If a CA key pair is available, encrypts the private key using the fKey.
     * Otherwise, uses the SHA-256 hash of the public key.
     *
     * @return The credential ID bytes
     * @throws Exception if an error occurs during generation
     */
    protected byte[] getCredIdBytes() throws Exception {
        if(this.caKeyPair == null) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(this.keyPair.getPublic().getEncoded());
        } else {
            byte[] pkBytes = this.keyPair.getPrivate().getEncoded();
            Token t = Token.generate(this.fKey, pkBytes);    
            return Base64.getUrlEncoder().encode( t.toString().getBytes() );
        }
    }

    /**
     * Creates a credential using the default attestation type and key pair.
     *
     * @param jsonOptions The credential creation options as a JSON string
     * @return The credential creation response as a JSON string
     * @throws Exception if an error occurs during credential creation
     */
    public String credentialCreate(String jsonOptions) throws Exception {
        return credentialCreate(jsonOptions, "none", this.getKeyPair());
    }

    /**
     * Creates a credential using the specified attestation type and the default key pair.
     *
     * @param jsonOptions The credential creation options as a JSON string
     * @param attestation The attestation type to use (e.g., "none", "packed", "fido-u2f")
     * @return The credential creation response as a JSON string
     * @throws Exception if an error occurs during credential creation
     */
    public String credentialCreate(String jsonOptions, String attestation)
            throws Exception {
        return credentialCreate(jsonOptions, attestation, this.getKeyPair());
    }

    /**
     * Creates a credential using the specified attestation type and key pair.
     *
     * @param jsonOptions The credential creation options as a JSON string
     * @param attestation The attestation type to use (e.g., "none", "packed", "fido-u2f")
     * @param kp The key pair to use for the credential
     * @return The credential creation response as a JSON string
     * @throws Exception if an error occurs during credential creation
     */
    public String credentialCreate(String jsonOptions, String attestation, KeyPair kp)
            throws Exception {
        JsonReader jr = Json.createReader(new StringReader(jsonOptions));
        JsonObject jo = jr.readObject();
        Map<String, Object> options = DataMapper.jsonToMap(jo);
        Map<String, Object> result = credentialCreate(options, attestation, kp, null, null);
        return DataMapper.objectToJson(result).toString();
    }

    /**
     * Creates a credential using the specified parameters.
     *
     * @param jsonOptions The credential creation options as a JSON string
     * @param attestation The attestation type to use (e.g., "none", "packed", "fido-u2f")
     * @param kp The key pair to use for the credential
     * @param caKeyPair The certificate authority key pair for attestation
     * @param akiCert The authority key identifier certificate
     * @return The credential creation response as a JSON string
     * @throws Exception if an error occurs during credential creation
     */
    public String credentialCreate(String jsonOptions, String attestation, KeyPair kp,
            KeyPair caKeyPair, X509Certificate akiCert) throws Exception {
        JsonReader jr = Json.createReader(new StringReader(jsonOptions));
        JsonObject jo = jr.readObject();
        Map<String, Object> options = DataMapper.jsonToMap(jo);
        Map<String, Object> result = credentialCreate(options, attestation, kp, caKeyPair,
                akiCert);
        return DataMapper.objectToJson(result).toString();
    }

    /**
     * Creates a credential using the specified parameters.
     *
     * @param options The credential creation options as a map
     * @param attestation The attestation type to use (e.g., "none", "packed", "fido-u2f")
     * @param kp The key pair to use for the credential
     * @param caKeyPair The certificate authority key pair for attestation
     * @param akiCert The authority key identifier certificate
     * @return The credential creation response as a map
     * @throws Exception if an error occurs during credential creation
     */
    public Map<String, Object> credentialCreate(Map<String, Object> options, String attestation,
            KeyPair kp, KeyPair caKeyPair, X509Certificate akiCert)
            throws Exception {
        Map<String, Map<String, Object>> cco = this
                .attestationOptionsResponeToCredentialCreationOptions(options);
        return processCredentialCreationOptions(cco, attestation, kp, caKeyPair, akiCert);
    }

    /**
     * Generates an assertion using the default key pair.
     *
     * @param jsonOptions The assertion options as a JSON string
     * @return The assertion response as a JSON string
     * @throws Exception if an error occurs during assertion generation
     */
    public String credentialRequest(String jsonOptions) throws Exception {
        return credentialRequest(jsonOptions, this.getKeyPair());
    }

    /**
     * Generates an assertion using the specified key pair.
     *
     * @param jsonOptions The assertion options as a JSON string
     * @param kp The key pair to use for the assertion
     * @return The assertion response as a JSON string
     * @throws Exception if an error occurs during assertion generation
     */
    public String credentialRequest(String jsonOptions, KeyPair kp)
            throws Exception {
        JsonReader jr = Json.createReader(new StringReader(jsonOptions));
        JsonObject jo = jr.readObject();
        Map<String, Object> options = DataMapper.jsonToMap(jo);
        Map<String, Object> result = credentialRequest(options, kp);
        return DataMapper.objectToJson(result).toString();
    }

    /**
     * Generates an assertion using the specified parameters.
     *
     * @param options The assertion options as a map
     * @param kp The key pair to use for the assertion
     * @return The assertion response as a map
     * @throws Exception if an error occurs during assertion generation
     */
    public Map<String, Object> credentialRequest(Map<String, Object> options, KeyPair kp)
            throws Exception {
        Map<String, Object> cro = assertionOptionsResponseToCredentialRequestOptions(options);
        return processCredentialRequestOptions(cro, kp);
    }

    /**
     * Builds the authenticator data for a credential or assertion.
     *
     * @param clientDataJSON The client data JSON object
     * @param publicKey The public key parameters
     * @param attestation The attestation type, or null for assertions
     * @param extensions The extensions requested by the client
     * @param extensionResults The extension results to include
     * @param kp The key pair to use
     * @return The authenticator data as a byte array
     * @throws Exception if an error occurs during construction
     */
    public byte[] buildAuthenticatorData(JsonObject clientDataJSON,
            Map<String, Object> publicKey, String attestation, Map<String, Object> extensions,
            Map<String, Object> extensionResults, KeyPair kp) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        // Lets work out if we need to set authenticator extension data
        Map<String, Object> authenticatorExtensions = null;
        if (extensionResults != null) {
            // this object may or may not contain keys of extensions which must be set by
            // the authenticator
            for (String key : extensionResults.keySet()) {
                if (validAuthenticatorExtensions.contains(key)) {
                    if (authenticatorExtensions == null) {
                        authenticatorExtensions = new HashMap<String, Object>();
                    }
                    authenticatorExtensions.put(key, extensionResults.get(key));
                }
            }
        }

        // Construct Attestation Object https://w3c.github.io/webauthn/#sctn-attestation
        ByteArrayOutputStream authDataBytes = new ByteArrayOutputStream();

        // If this key is present we are doing attestation, otherwise do an assertion
        boolean performAttestation = publicKey.containsKey("attestation");

        // I've arbitrarily decided to make the credential ID the sha256 bytes of the
        // public key
        byte[] credIdBytes = digest.digest(kp.getPublic().getEncoded());

        String rpId = null;
        if (performAttestation) {
            rpId = (String) ((Map<String, Object>) publicKey.get("rp")).get("id");
        } else {
            if (extensions != null && extensions.get("appid") != null) {
                rpId = (String) extensions.get("appid");
            } else {
                rpId = (String) publicKey.get("rpId");
            }
        }
        byte[] rpIdHash = digest.digest(rpId.getBytes());
        authDataBytes.write(rpIdHash);

        int flags = 0x01; // UP
        if (performAttestation) {
            flags |= 0x40; // AT
        }
        if (self.userVerified == true) {
            flags |= 0x04; // UV
        }
        if (authenticatorExtensions != null) {
            flags |= 0x80; // ED
        }
        // Flags
        authDataBytes.write(flags);
        // Signature counter
        authDataBytes.write(getCounterBytes());
        if (performAttestation) {
            byte[] attestedCredData = processAttestedCredentialData(kp.getPublic(),
                    credIdBytes);
            authDataBytes.write(attestedCredData);
        }
        if (authenticatorExtensions != null) { // If we have extensions write to the end of
                                               // authenticator data
            // ED flag set previously
            authDataBytes.write(Cbor.encode(authenticatorExtensions));
        }
        byte[] authData = authDataBytes.toByteArray();

        return authData;
    }

    /**
     * Builds the client data JSON object for a credential or assertion.
     *
     * @param publicKey The public key parameters
     * @return The client data JSON object
     */
    public JsonObject buildClientDataJson(Map<String, Object> publicKey) {
        String rp = (String) publicKey.get("rpId");
        String type = "webauthn.get";
        if (rp == null) {
            rp = (String) ((Map<String, Object>) publicKey.get("rp")).get("id");
            type = "webauthn.create";
        }
        String origin = "https://" + rp;
        if(publicKey.keySet().contains("origin")) {
            origin = (String) publicKey.get("origin");
        }
        JsonObject clientDataJSON = Json.createObjectBuilder().add("origin", origin)
                .add("challenge",
                        new String(Base64.getUrlEncoder()
                                .encode((byte[]) publicKey.get("challenge"))))
                .add("type", type).build();
        return clientDataJSON;
    }
