/*
 * Copyright IBM 2025, 2026
 */

package com.isfs.blekey.authenticator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
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
import java.nio.charset.StandardCharsets;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.isfs.blekey.util.CertUtils;
import com.isfs.blekey.util.KeyUtils;
import com.isfs.blekey.util.Cbor;
import com.isfs.blekey.util.JsonUtils;
import com.isfs.blekey.data.SymmetricKey;

@SuppressWarnings("unchecked")
public class Fido2Authenticator implements java.io.Serializable {

    private static final Logger logger = LoggerFactory.getLogger(Fido2Authenticator.class);

    /**
     * Serial version UID for serialization compatibility
     */
    private static final long serialVersionUID = -7830063672721389698L;

    protected KeyPair keyPair;
    protected X509Certificate authnCert;
    protected SymmetricKey aesKey;
    protected String fKey;

    private long counter = 0;

    private Set<String> validAuthenticatorExtensions = new HashSet<>(
            Arrays.asList("txAuthSimple", "txAuthGeneric"));

    // Vendor ID for IBM TMP chip
    protected static final byte[] TPM_VENDOR_ID_CONFORMANCE = new BigInteger("fffff1d0", 16)
            .toByteArray();

    // TODO change aaguid from zero's
    //protected byte[] TEST_AAGUID = new byte[] { 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F,
    //        0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F };
    protected byte[] TEST_AAGUID = new byte[16];

    protected byte[] credId = null;
    // TPM OID's
    protected static final String TPM_MANUFACTURER = "2.23.133.2.1";
    protected static final String TPM_VENDOR = "2.23.133.2.2";
    protected static final String TPM_FW_VERSION = "2.23.133.2.3";

    public Fido2Authenticator() {
        try {
            this.keyPair = KeyUtils.getKeyPair("ECDSA");
            if (this.keyPair == null) {
                throw new IllegalStateException("Failed to generate EC KeyPair - KeyUtils.getKeyPair returned null");
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Failed to initialize Fido2Authenticator: " + e.getMessage(), e);
        }
    }

    public Fido2Authenticator(String alg) throws Exception {
        this.keyPair = KeyUtils.getKeyPair(alg);
    }

    public Fido2Authenticator(String alg, int keySize) 
            throws NoSuchAlgorithmException, NoSuchProviderException {
        this.keyPair = KeyUtils.generateKeyPair(alg, keySize);
    }

    public void setCredId(byte[] credentialId) {
        this.credId = credentialId;
    }

    /**
     * Generate the credential id for this authenticator. The original implementation
     * of this was simply the SHA256 of the authenticator public key.
     *
     * If the Fido2Authenticator has a AES Symmetric key then the credential id is
     * the encrypted serialization of the authenticator's private key.
     *
     * @return The credential ID as a byte array, either from an existing ID, an encrypted private key,
     *         or a SHA-256 hash of the public key
     */
    public byte[] getCredId() {
        if(this.credId != null) {
            return this.credId;
        }
        if(aesKey != null) {
            try {
                byte[] encoded = this.keyPair.getPrivate().getEncoded();
                String cred = aesKey.encrypt(encoded); // b64url
                this.credId = cred.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                logger.debug("CredID generated: len={}, hash={}", this.credId.length, Integer.toHexString(cred.hashCode()));
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            try { // Fall back to default impl
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                digest.update(this.keyPair.getPublic().getEncoded());
                this.credId = digest.digest();
                logger.debug("getCredId() - SHA-256 fallback: {}", this.credId.length);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }
        return this.credId;
    }

    /**
     * Initialize authenticator from a credential ID received during getAssertion.
     *
     * Clients sends credential IDs as UTF-8 bytes of base64url strings.
     * We need to convert these bytes to a string for decryption.
     *
     * @param credId The credential ID as UTF-8 bytes of base64url string from Client
     * @throws Exception if decryption or key initialization fails
     */
    public void initFromCredId(byte[] credId) throws Exception {
        this.credId = credId;
        // Convert UTF-8 bytes to base64url string
        String credIdStr = new String(credId, java.nio.charset.StandardCharsets.UTF_8);
        
        // Log credential ID details with hash for debugging
        logger.debug("CredID init: len={}, strLen={}, hash={}, validB64url={}",
                     credId.length, credIdStr.length(),
                     Integer.toHexString(credIdStr.hashCode()),
                     credIdStr.matches("[A-Za-z0-9_-]*"));
        
        // Decrypt the token
        byte[] asn1Bytes = aesKey.decrypt(credIdStr, null);
        // Generate the key pair from the parameters
        ECPrivateKey key = (ECPrivateKey) KeyUtils.getPrivate(asn1Bytes, "EC");
        this.keyPair = new KeyPair(KeyUtils.getPubKey(key), key);
    }

    public void setSymKeys(String seed) {
        logger.debug("SymKeys set: seedLen={}, hash={}", seed.length(), Integer.toHexString(seed.hashCode()));
        this.aesKey = new SymmetricKey(seed);
        this.fKey = seed;
    }

    protected String getSymKeySeed() {
        return this.fKey;
    }
    
    public void setAuthnCert(X509Certificate cert) {
        this.authnCert = cert;
    }
    
    public X509Certificate getAuthnCert() {
        return this.authnCert;
    }

    public KeyPair getKeyPair() {
        return this.keyPair;
    }

    public Fido2Authenticator setKeyPair(KeyPair kp) {
        this.keyPair = kp;
        return this;
    }

    public long getCounter() {
        return counter;
    }

    public void setCounter(long c) {
        counter = c;
    }

    public final PublicKey getPubKey() {
        return this.keyPair.getPublic();
    }

    public final PrivateKey getPrivKey() {
        return this.keyPair.getPrivate();
    }

    /**
     * Converts a BigInteger EC point coordinate to a byte array.
     * Removes the leading zero byte if present (added when the coordinate is negative).
     *
     * @param point The BigInteger representing an EC point coordinate
     * @return The byte array representation of the coordinate
     */
    protected byte[] ECBigIntegerToByteArray(BigInteger point) {
        byte[] result = point.toByteArray();
        if (result.length == 33) { // Remove leading zero, added if coordinate is negative
            result = Arrays.copyOfRange(result, 1, result.length);
        }
        return result;
    }
    
    /**
     * Sets the Authenticator Attestation GUID (AAGUID) bytes.
     * The AAGUID is a 16-byte identifier that indicates the type of the authenticator.
     *
     * @param aaguid The 16-byte AAGUID
     */
    public void setAAGUIDBytes(byte[] aaguid) {
        this.TEST_AAGUID = aaguid;
    }
    
    /**
     * Gets the Authenticator Attestation GUID (AAGUID) bytes.
     *
     * @return The 16-byte AAGUID
     */
    public byte[] getAAGUIDBytes() {
        return this.TEST_AAGUID;
    }
    
    /**
     * Gets the Authenticator Attestation GUID (AAGUID) as a formatted string.
     * The format follows the standard UUID representation with hyphens.
     *
     * @return The AAGUID as a formatted string
     */
    public String getAAGUID() {
        StringBuilder sb = new StringBuilder(32 + 4);
        for(int i = 0; i < this.TEST_AAGUID.length; i++) {
            sb.append(String.format("%02x",  this.TEST_AAGUID[i]));
            if((i == 3) || (i == 5) || (i == 7) || (i == 9)) {
                sb.append("-");
            }
            
        }
        return sb.toString();
    }
    
    /**
     * Sets the allowed authenticator extensions.
     * These extensions determine which client extensions can be processed by the authenticator.
     *
     * @param exts Set of extension identifiers that the authenticator supports
     */
    public void setAllowedAuthenticatorExtensions(Set<String> exts) {
        this.validAuthenticatorExtensions = exts;
    }


    /**
     * Gets the counter value as a 4-byte array and increments the counter.
     * This method is called during attestation or assertion operations to provide
     * a unique counter value for each operation, helping prevent replay attacks.
     *
     * @return A 4-byte array representing the current counter value
     */
    public byte[] getCounterBytes() {
        // we store as a long, but only use the least significant 4 bytes
        byte[] result = new byte[4];
        long x = counter;
        for (int i = 3; i >= 0; i--) {
            result[i] = (byte) (x & 0xFF);
            x >>= 8;
        }
        counter += 1;
        return result;
    }

    /**
     * Creates a credential using default "none" attestation and the authenticator's key pair.
     *
     * @param jsonOptions JSON string containing WebAuthn credential creation options
     * @return JSON string containing the credential creation response
     * @throws Exception if credential creation fails
     */
    public String credentialCreate(String jsonOptions) throws Exception {
        return credentialCreate(jsonOptions, "none", this.getKeyPair());
    }

    /**
     * Creates a credential using the specified attestation type and the authenticator's key pair.
     *
     * @param jsonOptions JSON string containing WebAuthn credential creation options
     * @param attestation The attestation type to use (e.g., "none", "packed", "fido-u2f")
     * @return JSON string containing the credential creation response
     * @throws Exception if credential creation fails
     */
    public String credentialCreate(String jsonOptions, String attestation)
            throws Exception {
        return credentialCreate(jsonOptions, attestation, this.getKeyPair());
    }

    /**
     * Creates a credential using the specified attestation type and key pair.
     *
     * @param jsonOptions JSON string containing WebAuthn credential creation options
     * @param attestation The attestation type to use (e.g., "none", "packed", "fido-u2f")
     * @param kp The key pair to use for credential creation
     * @return JSON string containing the credential creation response
     * @throws Exception if credential creation fails
     */
    public String credentialCreate(String jsonOptions, String attestation, KeyPair kp)
            throws Exception {
        Map<String, Object> options = (HashMap<String, Object>) JsonUtils.decode(jsonOptions, HashMap.class);
        Map<String, Object> result = credentialCreate(options, attestation, kp, null, null);
        return JsonUtils.encode(result);
    }

    /**
     * Creates a credential using the specified attestation type, key pair, CA key pair, and AKI certificate.
     *
     * @param jsonOptions JSON string containing WebAuthn credential creation options
     * @param attestation The attestation type to use (e.g., "none", "packed", "fido-u2f")
     * @param kp The key pair to use for credential creation
     * @param caKeyPair The CA key pair for attestation certificate generation
     * @param akiCert The Authority Key Identifier certificate
     * @return JSON string containing the credential creation response
     * @throws Exception if credential creation fails
     */
    public String credentialCreate(String jsonOptions, String attestation, KeyPair kp,
            KeyPair caKeyPair, X509Certificate akiCert) throws Exception {
        Map<String, Object> options = (HashMap<String, Object>) JsonUtils.decode(jsonOptions, HashMap.class);
        Map<String, Object> result = credentialCreate(options, attestation, kp, caKeyPair,
                akiCert);
        return JsonUtils.encode(result);
    }

    /**
     * Creates a credential using the specified options, attestation type, key pair, CA key pair, and AKI certificate.
     *
     * @param options Map containing WebAuthn credential creation options
     * @param attestation The attestation type to use (e.g., "none", "packed", "fido-u2f")
     * @param kp The key pair to use for credential creation
     * @param caKeyPair The CA key pair for attestation certificate generation
     * @param akiCert The Authority Key Identifier certificate
     * @return Map containing the credential creation response
     * @throws Exception if credential creation fails
     */
    public Map<String, Object> credentialCreate(Map<String, Object> options, String attestation,
            KeyPair kp, KeyPair caKeyPair, X509Certificate akiCert)
            throws Exception {
        Map<String, Map<String, Object>> cco = this
                .attestationOptionsResponeToCredentialCreationOptions(options);
        return processCredentialCreationOptions(cco, attestation, kp, caKeyPair, akiCert);
    }

    /**
     * Processes a credential request (assertion) using the authenticator's key pair.
     *
     * @param jsonOptions JSON string containing WebAuthn assertion options
     * @return JSON string containing the assertion response
     * @throws Exception if assertion processing fails
     */
    public String credentialRequest(String jsonOptions) throws Exception {
        return credentialRequest(jsonOptions, this.getKeyPair());
    }

    /**
     * Processes a credential request (assertion) using the specified key pair.
     *
     * @param jsonOptions JSON string containing WebAuthn assertion options
     * @param kp The key pair to use for assertion
     * @return JSON string containing the assertion response
     * @throws Exception if assertion processing fails
     */
    public String credentialRequest(String jsonOptions, KeyPair kp)
            throws Exception {
        Map<String, Object> options = (HashMap<String, Object>) JsonUtils.decode(jsonOptions, HashMap.class);
        Map<String, Object> result = credentialRequest(options, kp);
        return JsonUtils.encode(result);
    }

    /**
     * Processes a credential request (assertion) using the specified options and key pair.
     *
     * @param options Map containing WebAuthn assertion options
     * @param kp The key pair to use for assertion
     * @return Map containing the assertion response
     * @throws Exception if assertion processing fails
     */
    public Map<String, Object> credentialRequest(Map<String, Object> options, KeyPair kp)
            throws Exception {
        Map<String, Object> cro = assertionOptionsResponseToCredentialRequestOptions(options);
        return processCredentialRequestOptions(cro, kp);
    }

    /**
     * Builds the authenticator data structure according to the WebAuthn specification.
     * This includes the RP ID hash, flags, counter, attested credential data (for attestation),
     * and extension data (if applicable).
     *
     * @param publicKey The public key credential data
     * @param attestation The attestation type being used
     * @param extensions The client extensions
     * @param extensionResults The extension processing results
     * @param kp The key pair to use
     * @return The authenticator data as a byte array
     * @throws Exception if building the authenticator data fails
     */
    public byte[] buildAuthenticatorData(Map<String, Object> publicKey, String attestation,
            Map<String, Object> extensions, Map<String, Object> extensionResults,
            KeyPair kp) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        // Lets work out if we need to set authenticator extension data
        Map<String, Object> authenticatorExtensions = null;
        if (extensionResults != null) {
            // this object may or may not contain keys of extensions which must be set by
            // the authenticator
            for (String key : extensionResults.keySet()) {
                if (this.validAuthenticatorExtensions.contains(key)) {
                    if (authenticatorExtensions == null) {
                        authenticatorExtensions = new HashMap<>();
                    }
                    authenticatorExtensions.put(key, extensionResults.get(key));
                }
            }
        }

        // Construct Attestation Object https://w3c.github.io/webauthn/#sctn-attestation
        ByteArrayOutputStream authDataBytes = new ByteArrayOutputStream();

        // If this key is present we are doing attestation, otherwise do an assertion
        boolean performAttestation = publicKey.containsKey("attestation");

        byte[] credIdBytes = getCredId();

        String rpId = null;
        logger.debug("publicKey: {}", publicKey);
        if (performAttestation) {
            rpId = (String) ((Map<String, Object>) publicKey.get("rp")).get("id");
        } else {
            if (extensions != null && extensions.get("appid") != null) {
                rpId = (String) extensions.get("appid");
            } else {
                rpId = (String) publicKey.get("rpId");
            }
        }
        logger.debug("rpId string: '{}', length: {}", rpId, rpId.length());
        byte[] rpIdBytes = rpId.getBytes(StandardCharsets.UTF_8);
        StringBuilder hexString = new StringBuilder();
        for (byte b : rpIdBytes) {
            hexString.append(String.format("%02x", b));
        }
        logger.debug("rpId bytes (hex): {}", hexString.toString());
        byte[] rpIdHash = digest.digest(rpIdBytes);
        hexString = new StringBuilder();
        for (byte b : rpIdHash) {
            hexString.append(String.format("%02x", b));
        }
        logger.debug("rpIdHash (hex): {}", hexString.toString());
        authDataBytes.write(rpIdHash);

        int flags = 0x01; // UP
        if (performAttestation) {
            flags |= 0x40; // AT
        }
        if (attestation != null && !attestation.equalsIgnoreCase("fido-u2f")) {
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
     * Builds the client data JSON object according to the WebAuthn specification.
     * This includes the origin, challenge, and type (create or get).
     *
     * @param publicKey The public key credential data
     * @return The client data as a JsonObject
     */
    public JsonObject buildClientDataJson(Map<String, Object> publicKey) {
        String rp = null;
        String type = "webauthn.get";
        if (publicKey.containsKey("origin")) {
            rp = (String) publicKey.get("origin");
        } else if (publicKey.containsKey("rpId")) {
            rp = "https://" + (String) publicKey.get("rpId");
        } else if (publicKey.containsKey("rp")) {
            rp = "https://" + (String) ((Map<String, Object>) publicKey.get("rp")).get("id");
            type = "webauthn.create";
        }
        JsonObject clientDataJSON = Json.createObjectBuilder().add("origin", rp)
                .add("challenge",
                        new String(Base64.getUrlEncoder()
                                .encode((byte[]) publicKey.get("challenge"))))
                .add("type", type).build();
        return clientDataJSON;
    }

    /**
     * Signs data using the specified private key and algorithm.
     *
     * @param toSign The data to sign
     * @param key The private key to use for signing
     * @param alg The signature algorithm to use (e.g., "SHA256withECDSA", "SHA256withRSA")
     * @return The signature as a byte array
     * @throws NoSuchAlgorithmException if the algorithm is not available
     * @throws InvalidKeyException if the key is invalid
     * @throws SignatureException if signing fails
     */
    public byte[] signData(byte[] toSign, PrivateKey key, String alg)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signer = Signature.getInstance(alg);
        signer.initSign(key);
        signer.update(toSign);
        byte[] result = signer.sign();
        return result;
    }

    
    /**
     * Processes client extensions and returns the extension results as a CBOR-encoded byte array.
     *
     * @param extensionInputs The client extension inputs
     * @param authenticatorExtensionOutputs The authenticator extension outputs
     * @param saar The server authentication attestation response
     * @return CBOR-encoded extension results
     * @throws Exception if extension processing fails
     */
    public byte[] processClientExtensions(Map<String, Object> extensionInputs,
            Map<String, Object> authenticatorExtensionOutputs, Map<String, String> saar) throws Exception {
        Map<String, Object> result = new HashMap<String, Object>();
        if (authenticatorExtensionOutputs != null && !authenticatorExtensionOutputs.keySet().isEmpty()) {
            for (String key: authenticatorExtensionOutputs.keySet()) {
                result.put(key, authenticatorExtensionOutputs.get(key));
            }
        }
        return Cbor.encode(result);
    }
    
    /**
     * Processes WebAuthn extensions and returns the extension results.
     * This method handles both attestation and assertion extensions.
     *
     * @param extensions The extensions to process
     * @param type The type of extensions to process ("attestation" or "assertion")
     * @return Map of extension results or null if no extensions to process
     * @throws Exception if extension processing fails
     */
    public Map<String, Object> processExtensions(Map<String, Object> extensions, String type)
            throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        Map<String, Object> extensionResults = null;
        // process registration extensions
        if (extensions != null) {
            // process attestation and assertion extensions
            extensionResults = new HashMap<>();

            if (type.equals("attestation")) {
                // process attestation extensions
                if (extensions.get("authnSel") != null) {
                    boolean authnSel = true;
                    // byte[][] aaguidList = (byte[][]) extensions.get("authnSel");
                    // System.out.println(Arrays.toString(aaguidList));
                    /*
                     * for(byte[] aaguidString: aaguidList) { byte[] aaguid = aaguidString;
                     * System.out.println(Arrays.toString(aaguid)); if(Arrays.equals(aaguid, new
                     * byte[16])) { authnSel = true; } }
                     */

                    extensionResults.put("authnSel", authnSel);
                }

                if (extensions.get("exts") != null
                        && ((boolean) extensions.get("exts")) == true) {
                    String[] exts = new String[] { "appid", "txAuthSimple" };
                    extensionResults.put("exts", exts);
                }
            }
            if (type.equals("assertion")) {
                // process assertion extensions
                if (extensions.get("txAuthSimple") != null) {
                    extensionResults.put("txAuthSimple",
                            extensions.get("txAuthSimple"));
                    // System.err.println("txAuthSimple = " + (String)
                    // extensions.get("txAuthSimple"));
                }
                if (extensions.get("txAuthGeneric") != null) {
                    Map<String, Object> txAuthGeneric = (Map<String, Object>) extensions
                            .get("txAuthGeneric");
                    extensionResults.put("txAuthGeneric",
                            digest.digest(((String) txAuthGeneric.get("content")).getBytes()));
                    // System.err.println("txAuthGeneric = " + Arrays.toString(
                    // ((String) txAuthGeneric.get("content")).getBytes() ));
                }
                if (extensions.get("appid") != null) {
                    extensionResults.put("appid", true);

                }
            }
        }
        return extensionResults;
    }

    /*
     * Credentail Create helpers
     */

    /**
     * Converts attestation options response to credential creation options format.
     * This transforms the server response format into the format expected by the WebAuthn API.
     *
     * @param options The attestation options from the server
     * @return The credential creation options in the format expected by WebAuthn
     */
    public Map<String, Map<String, Object>> attestationOptionsResponeToCredentialCreationOptions(
            Map<String, Object> options) {
        // Public Key Credential Create Option
        // https://w3c.github.io/webauthn/#dictdef-publickeycredentialcreationoptions
        Map<String, Object> pkcco = new HashMap<>();
        pkcco.put("rp", options.get("rp"));
        Map<String, Object> user = new HashMap<>();
        user.put("id", Base64.getUrlDecoder()
                .decode((String) ((Map<String, Object>) options.get("user")).get("id")));
        pkcco.put("user", user);
        pkcco.put("challenge",
                Base64.getUrlDecoder().decode((String) options.get("challenge")));
        pkcco.put("pubKeyCredParams", options.get("pubKeyCredParams"));

        if (options.get("timeout") != null) {
            if (options.get("timeout") instanceof String) {
                pkcco.put("timeout", Long.valueOf((String) options.get("timeout")));
            } else
                pkcco.put("timeout", Long.valueOf((Integer) options.get("timeout")));
        }
        if (options.get("excludeCredentials") != null) {
            pkcco.put("excludeCredentials", options.get("excludeCredentials"));
        }
        if (options.get("authenticatorSelector") != null) {
            pkcco.put("authenticatorSelector", options.get("authenticatorSelector"));
        }
        if (options.get("attestation") != null) {
            pkcco.put("attestation", options.get("attestation"));
        }
        if (options.get("extensions") != null) {
            pkcco.put("extensions", options.get("extensions"));
        }

        // Credential Create Option
        // https://w3c.github.io/webauthn/#credentialcreationoptions-extension
        Map<String, Map<String, Object>> cco = new HashMap<>();
        cco.put("publicKey", pkcco);

        return cco;
    }

    public byte[] processAttestedCredentialData(PublicKey pubKey, byte[] credIdBytes)
            throws IOException, NoSuchAlgorithmException {
        ByteArrayOutputStream attestedCredDataBytes = new ByteArrayOutputStream();
        attestedCredDataBytes.write(TEST_AAGUID);
        byte[] length = ByteBuffer.allocate(2).putShort((short) credIdBytes.length).array();
        attestedCredDataBytes.write(length[0]);
        attestedCredDataBytes.write(length[1]);
        attestedCredDataBytes.write(credIdBytes);

        // COSE Dict of key parameters
        Map<Number, Object> credPublicKeyCOSE = new HashMap<>();
        if (pubKey instanceof ECPublicKey) {
            ECPoint point = ((ECPublicKey) pubKey).getW();
            credPublicKeyCOSE.put(1, 2); // kty
            credPublicKeyCOSE.put(3, -7); // alg
            credPublicKeyCOSE.put(-1, 1); // crv
            credPublicKeyCOSE.put(-2, ECBigIntegerToByteArray(point.getAffineX())); // x
                                                                                      // coordinate
            credPublicKeyCOSE.put(-3, ECBigIntegerToByteArray(point.getAffineY())); // y
                                                                                      // coordinate
        } else if (pubKey instanceof RSAPublicKey) {
            credPublicKeyCOSE.put(1, 3); // kty
            credPublicKeyCOSE.put(3, -257); // alg
            credPublicKeyCOSE.put(-1, ((RSAPublicKey) pubKey).getModulus()); // modulus
            credPublicKeyCOSE.put(-2, ((RSAPublicKey) pubKey).getPublicExponent()); // exponent
        }
        attestedCredDataBytes.write(Cbor.encode(credPublicKeyCOSE));
        return attestedCredDataBytes.toByteArray();
    }

    public Map<String, Object> processAttestationStatement(String attestation,
            byte[] clientDataHash, byte[] authData, byte[] credIdBytes, KeyPair kp,
            KeyPair caKeyPair, X509Certificate akiCert) throws Exception {
        Map<String, Object> attStmt = null;
        if (attestation == null || attestation.equalsIgnoreCase("none")) {
            attStmt = new HashMap<>();
        } else if (attestation.equalsIgnoreCase("fido-u2f")) {
            attStmt = buildFIDOU2FAttestationStatement(clientDataHash, authData, credIdBytes,
                    kp, akiCert);
        } else if (attestation.equalsIgnoreCase("packed")) {
            attStmt = buildPackedAttestationStatement(clientDataHash, authData, credIdBytes,
                    null, caKeyPair, akiCert);
        } else if (attestation.equalsIgnoreCase("packed-self")) {
            attStmt = buildPackedAttestationStatement(clientDataHash, authData, credIdBytes, kp,
                    null, null);
        } else if (attestation.equalsIgnoreCase("tpm")) {
            attStmt = buildTPMAttestationStatement(clientDataHash, authData, credIdBytes,
                    akiCert, caKeyPair, kp);
        } else if (attestation.equalsIgnoreCase("android-safetynet")) {
            attStmt = buildAndroidSafetynetAttestation(clientDataHash, authData, kp, caKeyPair, akiCert);
        } else if (attestation.equalsIgnoreCase("apple")) {
            attStmt = buildAppleAttestation(clientDataHash, authData, kp, caKeyPair, akiCert);
        } else {
            throw new Exception("Invalid attestation type specified: " + attestation);
        }
        return attStmt;
    }

    public Map<String, Object> processCredentialCreationOptions(
            Map<String, Map<String, Object>> cco, String attestation, KeyPair kp,
            KeyPair caKeyPair, X509Certificate akiCert)
            throws NoSuchAlgorithmException, IOException, Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        Map<String, Object> publicKey = cco.get("publicKey");
        Map<String, Object> extensions = null;
        if (publicKey.get("extensions") != null) {
            extensions = (Map<String, Object>) publicKey.get("extensions");
        }
        Map<String, Object> extensionResults = processExtensions(extensions, "attestation");

        JsonObject clientDataJSON = buildClientDataJson(publicKey);
        byte[] clientDataBytes = clientDataJSON.toString().getBytes();
        byte[] clientDataHash = digest.digest(clientDataBytes);
        String clientDataString = Base64.getUrlEncoder().encodeToString(clientDataBytes);

        byte[] credIdBytes = getCredId();
        String id = new String(Base64.getUrlEncoder().encode(credIdBytes));

        byte[] authData = buildAuthenticatorData(publicKey, attestation,
                extensions, extensionResults, kp);
        Map<String, Object> attStmt = processAttestationStatement(attestation, clientDataHash,
                authData, credIdBytes, kp, caKeyPair, akiCert);
        Map<String, Object> attestationObject = new HashMap<>();
        attestationObject.put("authData", authData);
        attestationObject.put("fmt",
                attestation.equalsIgnoreCase("packed-self") ? "packed" : attestation);
        attestationObject.put("attStmt", attStmt);

        // Server Authentication Attestation Response
        // https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#example-authenticator-attestation-response
        Map<String, String> saar = new HashMap<>();
        saar.put("clientDataJSON", clientDataString);
        // add the base64 URL of the CBOR encoding of the attestationObject to the
        // response
        saar.put("attestationObject", new String(
                Base64.getUrlEncoder().encode(Cbor.encode(attestationObject))));

        // Server Public Key Creadential
        // https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#serverpublickeycredential
        Map<String, Object> spkc = new HashMap<>();
        spkc.put("id", id);
        spkc.put("rawId", id);
        spkc.put("response", saar);
        spkc.put("type", "public-key");
        spkc.put("getClientExtensionResults", processClientExtensions(extensions, extensionResults, saar));
        return spkc;
    }
    
    /**
     * Builds an Apple attestation statement.
     * This creates an Apple-specific attestation certificate and includes it in the attestation statement.
     *
     * @param clientDataHash The hash of the client data
     * @param authData The authenticator data
     * @param authenticatorKeyPair The authenticator key pair
     * @param caKeyPair The CA key pair for certificate generation
     * @param caCert The CA certificate
     * @return The Apple attestation statement as a Map
     * @throws Exception if building the attestation statement fails
     */
    public Map<String, Object> buildAppleAttestation(byte[] clientDataHash, byte[] authData,
            KeyPair authenticatorKeyPair, KeyPair caKeyPair, X509Certificate caCert) throws Exception {
        Map<String, Object> result = new HashMap<String, Object>();
        ByteArrayOutputStream nonceBuffer = new ByteArrayOutputStream();
        nonceBuffer.write(authData);
        nonceBuffer.write(clientDataHash);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] nonceHash = digest.digest(nonceBuffer.toByteArray());
        X509Certificate appleCert = CertUtils.generateAppleAttestationCertificate("CN=apple.attestation.test",
                authenticatorKeyPair, 365, nonceHash, caKeyPair, caCert);
        result.put("x5c", new byte[][] {appleCert.getEncoded(), caCert.getEncoded()});
        return result;
    }
    
    
    /**
     * Builds an Android SafetyNet attestation statement.
     * This creates a JWS token with the nonce derived from the client data hash and authenticator data.
     *
     * @param clientDataHash The hash of the client data
     * @param authData The authenticator data
     * @param authenticatorKeyPair The authenticator key pair
     * @param caKeyPair The CA key pair for signing the JWS
     * @param caCert The CA certificate
     * @return The Android SafetyNet attestation statement as a Map
     * @throws Exception if building the attestation statement fails
     */
    public Map<String, Object> buildAndroidSafetynetAttestation(byte[] clientDataHash, byte[] authData,
            KeyPair authenticatorKeyPair, KeyPair caKeyPair, X509Certificate caCert) throws Exception {
        Map<String, Object> result = new HashMap<String, Object>();
        JwtClaims claims = new JwtClaims();
        //nonce == client data hash + authData
        ByteArrayOutputStream nonceBuffer = new ByteArrayOutputStream();
        nonceBuffer.write(authData);
        nonceBuffer.write(clientDataHash);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] nonceHash = digest.digest(nonceBuffer.toByteArray());
        claims.setClaim("nonce", Base64.getEncoder().encodeToString(nonceHash));
        claims.setClaim("ctsProfileMatch", true);
        claims.setClaim("timestampMs", System.currentTimeMillis());
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(caKeyPair.getPrivate());
        jws.setKeyIdHeaderValue(caKeyPair.getPrivate().getAlgorithm());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        //X509Certificate leafCert = CertUtils.generatePackedBatchCertificate(
        //        "C=AU,O=IBM,OU=Authenticator Attestation,CN=attest.android.com",
        //        authenticatorKeyPair, 365, new BigInteger(TEST_AAGUID).toByteArray(), null, caKeyPair);
        jws.setCertificateChainHeaderValue(caCert);
        //jws.setHeader("x5c", Arrays.asList(leafCert.getEncoded(), caCert.getEncoded()));
        byte[] jwtArray = jws.getCompactSerialization().getBytes();
        result.put("ver", 1234567);
        //result.put("response", new BigInteger(jwtArray).toString(16));
        result.put("response", jwtArray);
        return result;
    }

    /**
     * Builds the RSA public area structure for TPM attestation.
     * This structure contains the RSA public key parameters in TPM format.
     *
     * @param aikKeyPair The Attestation Identity Key pair containing the RSA public key
     * @return The TPM public area structure as a byte array
     * @throws IOException if an I/O error occurs
     */
    public byte[] buildRsaPubArea(KeyPair aikKeyPair) throws IOException {
        // build pubArea
        ByteArrayOutputStream pubAreaByteStream = new ByteArrayOutputStream();
        pubAreaByteStream.write(new byte[] { 0, 1 }); // type TMP_ALG_ID = TMP_ALG_RSA
        pubAreaByteStream.write(new byte[] { 0, 11 }); // name_alg (used to generate
                                                       // attested_name in certInfo) =
                                                       // TMP_ALG_SHA256
        pubAreaByteStream.write(new byte[4]); // TPMA_OBJECT bits
        pubAreaByteStream.write(new byte[2]); // authPolicy, set length = 0 and ignore
        // RSA key params
        pubAreaByteStream.write(new byte[] { 0, 0x10 }); // symetric = TMP_ALG_NULL
        pubAreaByteStream.write(new byte[] { 1, 4 }); // scheme = TMP_ALG_RSASSA (PKCS1-v1.5)
        pubAreaByteStream.write(new byte[] { 4, 0 }); // key size = 1024
        pubAreaByteStream.write(new byte[4]); // exponent
        byte[] unique = ((RSAPublicKey) aikKeyPair.getPublic()).getModulus().toByteArray();
        byte[] uniqueLength = ByteBuffer.allocate(2).putShort((short) unique.length).array();
        pubAreaByteStream.write(uniqueLength[0]);
        pubAreaByteStream.write(uniqueLength[1]);
        pubAreaByteStream.write(unique); // unique (n - coefficient)

        byte[] pubArea = pubAreaByteStream.toByteArray();
        return pubArea;
    }

    /**
     * Builds the EC public area structure for TPM attestation.
     * This structure contains the EC public key parameters in TPM format.
     *
     * @param aikKeyPair The Attestation Identity Key pair containing the EC public key
     * @return The TPM public area structure as a byte array
     * @throws IOException if an I/O error occurs
     */
    public byte[] buildEcPubArea(KeyPair aikKeyPair) throws IOException {
        ByteArrayOutputStream pubAreaByteStream = new ByteArrayOutputStream();
        pubAreaByteStream.write(new byte[] { 0, 0x23 }); // type TMP_ALG_ID = TMP_ALG_ECC
        // name_alg (used to generate attested_name in certInfo) == TMP_ALG_SHA256
        pubAreaByteStream.write(new byte[] { 0, 0x0B });
        pubAreaByteStream.write(new byte[4]); // TPMA_OBJECT
        pubAreaByteStream.write(new byte[2]); // auth policy, set length = 0 and ignore key params
        pubAreaByteStream.write(new byte[] { 0x00, 0x10 }); // symetric == TPM__ALG_NULL
        pubAreaByteStream.write(new byte[] { 0x00, 0x10 }); // scheme == TPM_ALG_NULL
        pubAreaByteStream.write(new byte[] { 0x00, 0x03 }); // curve_id == TPM_ECC_NIST_P256
        pubAreaByteStream.write(new byte[] { 0x00, 0x10 }); // kdf == TPM_ALG_NULL
        ECPoint point = ((ECPublicKey) aikKeyPair.getPublic()).getW();
        byte[] x = ECBigIntegerToByteArray(point.getAffineX()); // x coordinate
        byte[] y = ECBigIntegerToByteArray(point.getAffineY()); // y coordinate
        byte[] xLen = ByteBuffer.allocate(2).putShort((short) x.length).array();
        byte[] yLen = ByteBuffer.allocate(2).putShort((short) y.length).array();
        pubAreaByteStream.write(xLen[0]);
        pubAreaByteStream.write(xLen[1]);
        pubAreaByteStream.write(x); // x-coordinate
        pubAreaByteStream.write(yLen[0]);
        pubAreaByteStream.write(yLen[1]);
        pubAreaByteStream.write(y); // x-coordinate      
        byte[] pubArea = pubAreaByteStream.toByteArray();
        return pubArea;
    }

    /**
     * Builds the TPM certInfo structure for TPM attestation.
     * This structure contains the certification information for the TPM attestation.
     *
     * @param attsToSign The data to be signed (typically authData + clientDataHash)
     * @param pubInfo The public area information
     * @return The TPM certInfo structure as a byte array
     * @throws IOException if an I/O error occurs
     * @throws NoSuchAlgorithmException if a required algorithm is not available
     */
    public byte[] buildCertInfo(byte[] attsToSign, byte[] pubInfo)
            throws IOException, NoSuchAlgorithmException {
        // build certInfo
        ByteArrayOutputStream certInfoByteStream = new ByteArrayOutputStream();
        certInfoByteStream.write(new byte[] { (byte) 0xFF, 0x54, 0x43, 0x47 }); // magic, 4 byte
                                                                                // constant
                                                                                // specifying
                                                                                // TPM_GENERATED
        certInfoByteStream.write(new byte[] { (byte) 0x80, 0x17 }); // attestation type, 2 byte
                                                                    // TPM_ST_ATTEST_CERTIFY
        certInfoByteStream.write(new byte[2]); // qualified signer length, 0 = Ignore
        // calculate hash of attsToBeSigned
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] sigHash = digest.digest(attsToSign);
        int[] sigHashLength = { (sigHash.length - (sigHash.length & 0xFF)) / 256,
                sigHash.length & 0xFF };
        certInfoByteStream.write(sigHashLength[0]); // write sigHash to certInfo
        certInfoByteStream.write(sigHashLength[1]); // goes in extraData field
        certInfoByteStream.write(sigHash);
        // write clock Info, arbitrarily set to zero
        certInfoByteStream.write(new byte[17]); // uint64 clock, uint32 resetCount, uint32
                                                // restartCount, safe
        logger.debug("Vendor Id = {}", Arrays.toString(TPM_VENDOR_ID_CONFORMANCE));
        certInfoByteStream.write((new byte[8 - TPM_VENDOR_ID_CONFORMANCE.length])); // pad with
                                                                                    // correct
                                                                                    // number of
                                                                                    // 0 bytes
        certInfoByteStream.write(TPM_VENDOR_ID_CONFORMANCE); // write Vendor ID, must pad to 8
                                                             // bytes
        // hash of pubInfo = attestedName
        ByteArrayOutputStream attestedNameByteStream = new ByteArrayOutputStream();
        attestedNameByteStream.write(new byte[] { 0x00, 0x0B }); // name_alg from pubInfo field
        byte[] pubInfoHash = digest.digest(pubInfo);
        attestedNameByteStream.write(pubInfoHash);
        byte[] attestedName = attestedNameByteStream.toByteArray();
        byte[] attestedNameLength = ByteBuffer.allocate(2).putShort((short) attestedName.length)
                .array();
        certInfoByteStream.write(attestedNameLength[0]);
        certInfoByteStream.write(attestedNameLength[1]);
        certInfoByteStream.write(attestedName);
        // attested qualified name, can ignore
        certInfoByteStream.write(new byte[] { 0x00, 0x00 }); // length = 0 === ignore
        byte[] certInfo = certInfoByteStream.toByteArray();

        return certInfo;

    }

    /**
     * Builds a TPM attestation statement according to the WebAuthn specification.
     * This includes generating certificates, creating TPM structures, and signing the data.
     *
     * @param clientDataHash The hash of the client data
     * @param authData The authenticator data
     * @param credId The credential ID
     * @param caCert The CA certificate
     * @param caKeyPair The CA key pair
     * @param aikKeyPair The Attestation Identity Key pair
     * @return The TPM attestation statement as a Map
     * @throws Exception if building the attestation statement fails
     */
    public Map<String, Object> buildTPMAttestationStatement(byte[] clientDataHash,
            byte[] authData, byte[] credId, X509Certificate caCert, KeyPair caKeyPair,
            KeyPair aikKeyPair) throws Exception {
        Map<String, Object> result = new HashMap<>();
        // Generate intermediate key pair matching the CA key type
        String keyAlgorithm = caKeyPair.getPublic().getAlgorithm();
        int keySize = keyAlgorithm.equals("EC") ? 256 : 2048;
        KeyPair intermediateKeyPair = KeyUtils.generateKeyPair(keyAlgorithm, keySize);
        X509Certificate intermediateCert = CertUtils.generateIntermediateCACert(caCert,
                "CN=intermediateCA", 365, intermediateKeyPair, caKeyPair);
        String altNames = Fido2Authenticator.TPM_VENDOR + "=IBMTPM+"
                + Fido2Authenticator.TPM_MANUFACTURER + "=id:"
                + new BigInteger(Fido2Authenticator.TPM_VENDOR_ID_CONFORMANCE).toString(16)
                + "+" + Fido2Authenticator.TPM_FW_VERSION + "=id:1";
        X509Certificate aikCert = CertUtils.generateAIKCert(intermediateCert, 365, aikKeyPair,
                altNames, intermediateKeyPair);
        result.put("ver", "2.0");
        result.put("alg", -257); // SHA256 with RSA
        result.put("x5c", new byte[][] { aikCert.getEncoded(), intermediateCert.getEncoded(),
                caCert.getEncoded() });

        // build attsToSign
        ByteArrayOutputStream sigByteStream = new ByteArrayOutputStream();
        sigByteStream.write(authData);
        sigByteStream.write(clientDataHash);
        byte[] attsToSign = sigByteStream.toByteArray();

        byte[] pubInfo = null;
        String javaAlgId = null;
        if(aikKeyPair.getPublic() instanceof RSAPublicKey) {
            pubInfo = buildRsaPubArea(aikKeyPair);
            javaAlgId = "SHA256withRSA";
        } else if(aikKeyPair.getPublic() instanceof ECPublicKey) {
            pubInfo = buildEcPubArea(aikKeyPair);
            javaAlgId = "SHA256withECDSA";
        } else {
            throw new RuntimeException(
                    "Unsupported key type" + aikKeyPair.getPublic().getClass().getName());
        }
        result.put("pubArea", pubInfo);

        byte[] certInfo = buildCertInfo(attsToSign, pubInfo);
        result.put("certInfo", certInfo);

        // add sig of certInfo
        byte[] sig = signData(certInfo, aikKeyPair.getPrivate(), javaAlgId);
        result.put("sig", sig);

        return result;
    }

    /**
     * Builds a FIDO U2F attestation statement according to the WebAuthn specification.
     * This includes formatting the data according to the U2F specification and signing it.
     *
     * @param clientDataHash The hash of the client data
     * @param authData The authenticator data
     * @param credId The credential ID
     * @param caKeyPair The CA key pair for signing
     * @param caCert The CA certificate
     * @return The FIDO U2F attestation statement as a Map
     * @throws Exception if building the attestation statement fails
     */
    public Map<String, Object> buildFIDOU2FAttestationStatement(byte[] clientDataHash,
            byte[] authData, byte[] credId, KeyPair caKeyPair, X509Certificate caCert)
            throws Exception {
        Map<String, Object> result = new HashMap<>();

        ECPoint point = ((ECPublicKey) caKeyPair.getPublic()).getW();
        ByteArrayOutputStream pubKeyU2FStream = new ByteArrayOutputStream();
        pubKeyU2FStream.write(0x04);
        pubKeyU2FStream.write(ECBigIntegerToByteArray(point.getAffineX())); // x coordinate
        pubKeyU2FStream.write(ECBigIntegerToByteArray(point.getAffineY())); // y coordinate
        byte[] pubKeyU2F = pubKeyU2FStream.toByteArray();
        result.put("x5c", new byte[][] { caCert.getEncoded() });

        byte[] rpidHashBytes = Arrays.copyOfRange(authData, 0, 32);

        ByteArrayOutputStream sigByteStream = new ByteArrayOutputStream();
        sigByteStream.write(0x00);
        sigByteStream.write(rpidHashBytes);
        sigByteStream.write(clientDataHash);
        sigByteStream.write(credId);
        sigByteStream.write(pubKeyU2F);
        byte[] signature = signData(sigByteStream.toByteArray(), caKeyPair.getPrivate(),
                "SHA256withECDSA");
        result.put("sig", signature);

        return result;
    }


    /**
     * Get the java standard name of the given key and hashing algorithm as per
     * https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html
     * 
     * Add the corresponding COSE key type id to the result map
     * 
     * @param key instance of PrivateKey to get alg for
     * @param result Attestation response map
     * @return The java standard name of the given key and hashing algorithm.
     * @throws Exception if the given PrivateKey is not supported
     */
    private String getJavaAlgString(PrivateKey key, HashMap<String, Object> result) throws Exception{
        String alg = null;
        if (key instanceof ECPrivateKey) {
            alg = "SHA256withECDSA";
            result.put("alg", -7);
        } else if (key instanceof RSAPrivateKey) {
            alg = "SHA256withRSA";
            result.put("alg", -257);
        } else {
            throw new Exception("Unsuported Key Type: " + key.getClass().getName());
        }
        return alg;
    }

    /**
     * Builds a Packed attestation statement according to the WebAuthn specification.
     * This supports self attestation, basic/batch attestation, and attCA attestation.
     *
     * @param clientDataHash The hash of the client data
     * @param authData The authenticator data
     * @param credId The credential ID
     * @param attestKeyPair The attestation key pair (for self attestation)
     * @param caKeyPair The CA key pair (for basic/batch and attCA attestation)
     * @param akiCert The Authority Key Identifier certificate (for attCA attestation)
     * @return The Packed attestation statement as a Map
     * @throws Exception if building the attestation statement fails
     */
    public Map<String, Object> buildPackedAttestationStatement(byte[] clientDataHash,
            byte[] authData, byte[] credId, KeyPair attestKeyPair, KeyPair caKeyPair,
            X509Certificate akiCert) throws Exception {
        HashMap<String, Object> result = new HashMap<>();
        String alg = "";

        if (attestKeyPair != null) {
            // we are doing self
            alg = getJavaAlgString(attestKeyPair.getPrivate(), result);
        } else {
            attestKeyPair = getKeyPair();
            alg = getJavaAlgString(attestKeyPair.getPrivate(), result);
            if (caKeyPair == null) {
                // we are doing basic/batch
                if(this.authnCert == null) {
                    this.authnCert = CertUtils.generatePackedBatchCertificate(
                            "C=AU,O=IBM,OU=Authenticator Attestation,CN=packedBasic",
                            attestKeyPair, 365, this.TEST_AAGUID, null, caKeyPair, null);
                }
                result.put("x5c", new byte[][] { this.authnCert.getEncoded() });
            } else {
                // we are doing attCA
                byte[] caCert = akiCert.getEncoded();
                byte[] attestnCert = CertUtils
                        .gereatePackedAttCACertificate(akiCert,
                                "C=AU,O=IBM,OU=Authenticator Attestation,CN=packedBasicLeaf",
                                attestKeyPair, 365,
                                this.TEST_AAGUID, caKeyPair)
                        .getEncoded();
                if(this.authnCert != null) {
                    attestnCert = this.authnCert.getEncoded();
                }
                result.put("x5c", new byte[][] { attestnCert, caCert });
                
            }
        }
        ByteArrayOutputStream sigByteStream = new ByteArrayOutputStream();
        sigByteStream.write(authData);
        sigByteStream.write(clientDataHash);
        byte[] signature = signData(sigByteStream.toByteArray(), attestKeyPair.getPrivate(),
                alg);
        result.put("sig", signature);
        return result;
    }

    /*
     * Credential request helpers
     */
    /**
     * Converts assertion options response to credential request options format.
     * This transforms the server response format into the format expected by the WebAuthn API.
     *
     * @param options The assertion options from the server
     * @return The credential request options in the format expected by WebAuthn
     */
    public static Map<String, Object> assertionOptionsResponseToCredentialRequestOptions(
            Map<String, Object> options) {
        // Credential Request Options
        Map<String, Object> cro = new HashMap<>();
        // https://w3c.github.io/webauthn/#dictdef-publickeycredentialrequestoptions
        Map<String, Object> pkcro = new HashMap<>();

        pkcro.put("challenge",
                Base64.getUrlDecoder().decode((String) options.get("challenge")));
        if (options.get("timeout") != null) {
            if (options.get("timeout") instanceof String) {
                pkcro.put("timeout", Long.valueOf((String) options.get("timeout")));
            } else
                pkcro.put("timeout", Long.valueOf((Integer) options.get("timeout")));
        }
        if (options.get("rpId") != null) {
            pkcro.put("rpId", options.get("rpId"));
        }
        if (options.get("allowedCredentials") != null) {
            Map<String, Object>[] allowedCreds = (Map<String, Object>[]) options
                    .get("allowedCredentials");
            pkcro.put("allowedCredentails",
                    new Map[(allowedCreds.length)]);
            int pos = 0;
            for (Map<String, Object> c : allowedCreds) {
                Map<String, Object> cred = new HashMap<>();
                cred.put("type", c.get("type"));
                cred.put("id", Base64.getUrlDecoder().decode((String) c.get("id")));
                if (c.get("transports") != null) {
                    cred.put("transports", c.get("transports"));
                }
                ((Map<String, Object>[]) pkcro.get("allowedCredentails"))[pos++] = cred;
            }

        }
        if (options.get("userVerification") != null) {
            pkcro.put("userVerification", options.get("userVerification"));
        }
        if (options.get("extensions") != null) {
            pkcro.put("extensions", options.get("extensions"));
        }
        cro.put("publicKey", pkcro);

        return cro;
    }

    /**
     * Processes credential request options to generate a credential request response.
     * This is the core method that handles the WebAuthn assertion process.
     *
     * @param cro The credential request options
     * @param kp The key pair to use for assertion
     * @return The credential request response
     * @throws Exception if assertion processing fails
     */
    public Map<String, Object> processCredentialRequestOptions(Map<String, Object> cro,
            KeyPair kp) throws Exception {
        Map<String, Object> spkc = new HashMap<>();
        Map<String, Object> saar = new HashMap<>();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        Map<String, Object> publicKey = (Map<String, Object>) cro.get("publicKey");
        Map<String, Object> extensions = null;

        if (publicKey.get("extensions") != null) {
            extensions = (Map<String, Object>) publicKey.get("extensions");
        }
        Map<String, Object> extensionResults = processExtensions(extensions, "assertion");

        JsonObject clientDataJSON = buildClientDataJson(publicKey);
        byte[] clientDataBytes = clientDataJSON.toString().getBytes();
        String clientDataString = Base64.getUrlEncoder().encodeToString(clientDataBytes);
        saar.put("clientDataJSON", clientDataString);

        // Construct Attestation Object https://w3c.github.io/webauthn/#sctn-attestation
        byte[] authData = buildAuthenticatorData(publicKey, "set uv", extensions,
                extensionResults, kp);

        saar.put("authenticatorData", Base64.getUrlEncoder().encode(authData));

        // credential information
        byte[] clientDataHash = digest.digest(clientDataBytes);

        ByteArrayOutputStream sigByteStream = new ByteArrayOutputStream();
        sigByteStream.write(authData);
        sigByteStream.write(clientDataHash);
        String alg = ((kp.getPublic() instanceof ECPublicKey) ? "SHA256withECDSA"
                : "SHA256withRSA");
        byte[] signature = signData(sigByteStream.toByteArray(), kp.getPrivate(), alg);

        saar.put("signature", Base64.getUrlEncoder().encode(signature));
        saar.put("userHandle", "");

        spkc.put("id", Base64.getUrlEncoder().encodeToString(getCredId()));
        spkc.put("rawId", spkc.get("id"));
        spkc.put("response", saar);
        // type (from Credential defined here:
        // https://w3c.github.io/webappsec-credential-management/#credential)
        spkc.put("type", "public-key");
        if (extensionResults != null) {
            spkc.put("getClientExtensionResults", Cbor.encode(extensionResults));
        } else {
            spkc.put("getClientExtensionResults",
                    Cbor.encode(new HashMap<String, Object>()));
        }

        return spkc;
    }

}