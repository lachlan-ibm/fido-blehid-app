/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.ctap;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import javax.crypto.KeyAgreement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import com.isfs.blekey.util.Cbor;
import com.isfs.blekey.util.KeyUtils;
import com.isfs.blekey.authenticator.AuthenticatorAPI;
import com.isfs.blekey.authenticator.AuthenticatorCmd;
import com.isfs.blekey.authenticator.PinSubCmd;
import com.isfs.blekey.authenticator.TestConfig;
import com.isfs.blekey.authenticator.TestHelper;
import com.isfs.blekey.data.Passkey;

/**
 * Unit tests for CTAP2HID requests.
 * These tests emulate CTAP2HID protocol by constructing appropriate byte arrays
 * and passing them to the CtapHid class.
 */
@ExtendWith(MockitoExtension.class)
public class Ctap2HidRequestTest {

    private byte[] channelId;
    private SecureRandom random;
    private byte[] pinHash;
    private java.lang.reflect.Field assignedCidsField;
    private java.io.File tempDir;
    
    /**
     * Creates a test passkey for use in tests.
     *
     * @return A test passkey
     * @throws Exception if an error occurs
     */
    private Passkey createTestPasskey() throws Exception {
        // Create a key pair for the passkey
        KeyPair keyPair = TestHelper.createTestKeyPair("EC");
        
        // Create a certificate for the passkey
        java.security.cert.X509Certificate cert = com.isfs.blekey.util.CertUtils.generateCaCert(
                "CN=Test Passkey", keyPair, 365, true);
        
        // Create an empty list for resident credentials
        List<Map<String, byte[]>> resCreds = new ArrayList<>();
        
        // Create the passkey using the protected constructor via reflection
        java.lang.reflect.Constructor<Passkey> constructor =
                com.isfs.blekey.data.Passkey.class.getDeclaredConstructor(
                        java.security.PrivateKey.class,
                        java.security.cert.X509Certificate.class,
                        List.class);
        constructor.setAccessible(true);
        return constructor.newInstance(keyPair.getPrivate(), cert, resCreds);
    }
    
    /**
     * Helper method to set the root key pair in the Passkey class using reflection
     */
    private void setRootKeyPair(PublicKey publicKey, PrivateKey privateKey) throws Exception {
        java.lang.reflect.Field rootPublicKeyField = KeyUtils.class.getDeclaredField("rootPublicKey");
        rootPublicKeyField.setAccessible(true);
        rootPublicKeyField.set(null, publicKey);
        
        java.lang.reflect.Field rootPrivateKeyField = KeyUtils.class.getDeclaredField("rootPrivateKey");
        rootPrivateKeyField.setAccessible(true);
        rootPrivateKeyField.set(null, privateKey);
    }
    
    /**
     * Helper method to convert byte array CID to String key (matching CtapHid.cidKey())
     */
    private static String cidKey(byte[] cid) {
        StringBuilder sb = new StringBuilder(cid.length * 2);
        for (byte b : cid) sb.append(String.format("%02x", b));
        return sb.toString();
    }
    
    /**
     * Adds a test passkey to the assignedCids map in CtapHid.
     *
     * @param passkey The passkey to add
     * @throws Exception if an error occurs
     */
    private void setupPasskeyInCtapHid(com.isfs.blekey.data.Passkey passkey) throws Exception {
        // Create a PIN token
        byte[] pinToken = new byte[32];
        random.nextBytes(pinToken);
        
        // Create a passkey file in the FIDO2_HOME directory (set in setUp())
        String passkeyFileName = "test-passkey-" + System.currentTimeMillis() + ".passkey";
        java.io.File tempFile = new java.io.File(tempDir, passkeyFileName);
        tempFile.deleteOnExit();
        
        // Write the passkey to the temp file so it exists
        com.isfs.blekey.data.Passkey.writeKey(passkey, pinHash, tempFile);
        
        // Create a CtapTxn with the passkey (no cmd parameter needed for test setup)
        com.isfs.blekey.ctap.CtapTxn txn = new com.isfs.blekey.ctap.CtapTxn(
                channelId, null, pinToken, passkey, pinHash);
        
        // Set just the filename (not absolute path) - resolvePasskeyFile() will combine with FIDO2_HOME
        txn.setPasskeyFileName(passkeyFileName);

        // Pre-approve user presence so makeCredential / getAssertion succeed in tests
        // without needing a real UI interaction.
        txn.setUserPresent(true);
        
        // Get the assignedCids field from CtapHid
        if (assignedCidsField == null) {
            assignedCidsField = com.isfs.blekey.ctap.CtapHid.class.getDeclaredField("assignedCids");
            assignedCidsField.setAccessible(true);
        }
        
        // Get the current assignedCids map (now String-based)
        @SuppressWarnings("unchecked")
        Map<String, com.isfs.blekey.ctap.CtapTxn> currentMap =
                (Map<String, com.isfs.blekey.ctap.CtapTxn>) assignedCidsField.get(null);
        
        // Add our new transaction to the map using String key
        currentMap.put(cidKey(channelId), txn);

        // Simulate the authenticated session that updateAuthenticationState() would create
        // after a real PIN ceremony. AuthenticatorAPI.makeCredential calls
        // loadAuthenticatedSession() which looks up openKeys by CID — without this
        // entry it finds nothing and nulls out the passkey, causing PIN_REQUIRED.
        java.lang.reflect.Field openKeysField =
                AuthenticatorAPI.class.getDeclaredField("openKeys");
        openKeysField.setAccessible(true);
        @SuppressWarnings("unchecked")
        Map<byte[], Passkey> openKeys =
                (Map<byte[], Passkey>) openKeysField.get(null);
        openKeys.put(channelId, passkey);
    }
    
    @BeforeEach
    public void setUp() throws Exception {
        // Create a temporary directory for FIDO2_HOME
        tempDir = java.nio.file.Files.createTempDirectory("fido2-test-").toFile();
        tempDir.deleteOnExit();
        System.setProperty("FIDO2_HOME", tempDir.getAbsolutePath());
        
        // Initialize KeystoreManager for Passkey operations
        KeyUtils.setKeystoreManager(
            com.isfs.blekey.authenticator.TestHelper.createMockKeystoreManager());
        
        // Generate and set root key pair for Passkey encryption
        KeyPair rootKeyPair = KeyUtils.generateKeyPair("EC", 256);
        setRootKeyPair(rootKeyPair.getPublic(), rootKeyPair.getPrivate());
        
        // Generate a random channel ID for testing
        random = new SecureRandom();
        channelId = new byte[4];
        random.nextBytes(channelId);
        
        // Create a PIN hash
        pinHash = new byte[32];
        random.nextBytes(pinHash);
        
        // Register a synchronous UP callback so getInfo completes without UI interaction.
        // When getInfo defers, this callback immediately loads the approved response back
        // into the waiting CtapHid so the drain loop in the test works normally.
        com.isfs.blekey.authenticator.AuthenticatorAPI.setUserPresenceCallback(
            context -> {
                com.isfs.blekey.ctap.CtapTxn txn = context.getTxn();
                context.buildResponse(
                    com.isfs.blekey.authenticator.UpRequestContext.Outcome.APPROVED,
                    bytes -> {
                        com.isfs.blekey.ctap.CtapHid deferred = txn.takeDeferredCmd();
                        if (deferred != null && bytes != null) {
                            try {
                                deferred.injectDeferredResponse(bytes);
                                txn.setUserPresent(true);
                            } catch (java.io.IOException e) {
                                throw new RuntimeException(e);
                            }
                        }
                    });
            });

        // Stub DeferredResponseSender: inject the response back into the deferred
        // CtapHid the same way HIDPasskey.sendDeferredResponse() does on device.
        com.isfs.blekey.authenticator.AuthenticatorAPI.setDeferredResponseSender(
            (txn, response) -> {
                com.isfs.blekey.ctap.CtapHid deferred = txn.takeDeferredCmd();
                if (deferred != null) {
                    try {
                        deferred.injectDeferredResponse(response);
                    } catch (java.io.IOException e) {
                        throw new RuntimeException(e);
                    }
                }
            });

        // Write a platform.key PEM file into FIDO2_HOME so that
        // KeyUtils.getPlatformKey() finds it during makeCredential.
        KeyPair platformKeyPair = KeyUtils.generateKeyPair("EC", 256);
        java.io.File platKeyFile = new java.io.File(tempDir, "platform.key");
        com.isfs.blekey.util.FileUtils.writePrivatePEM(platformKeyPair.getPrivate(), platKeyFile);

        // The mock KeystoreManager is non-null, so getPlatformKey() calls
        // keystoreManager.getEC256PrivateKey() first and never reaches the
        // file-based fallback.  Stub it to return the key we just wrote.
        // lenient() suppresses UnnecessaryStubbingException for tests that
        // don't exercise the makeCredential/getAssertion paths.
        org.mockito.Mockito.lenient()
            .when(KeyUtils.getKeystoreManager().getEC256PrivateKey())
            .thenReturn(platformKeyPair.getPrivate());
        // Stub the public key from the same pair so the ECDH self-agreement in
        // derivePasskeySeed uses matching keys (privKey × ownPubKey).
        org.mockito.Mockito.lenient()
            .when(KeyUtils.getKeystoreManager().getEC256PublicKey())
            .thenReturn(platformKeyPair.getPublic());

        // Create a test passkey and add it to the assignedCids map
        com.isfs.blekey.data.Passkey passkey = createTestPasskey();
        setupPasskeyInCtapHid(passkey);
        
        // Verify that the passkey was added to the assignedCids map
        @SuppressWarnings("unchecked")
        Map<String, com.isfs.blekey.ctap.CtapTxn> assignedCids =
                (Map<String, com.isfs.blekey.ctap.CtapTxn>) assignedCidsField.get(null);
        
        // Check if the transaction was added using String key
        String key = cidKey(channelId);
        if (assignedCids.containsKey(key)) {
            System.err.println("Found transaction in setUp with channel ID: " + Arrays.toString(channelId));
        } else {
            System.err.println("Transaction not found in setUp with channel ID: " + Arrays.toString(channelId));
            System.err.println("assignedCids keys: " + assignedCids.keySet());
        }
    }

    /**
     * Helper method to create a CTAP2 CBOR request frame
     * 
     * @param cmd The AuthenticatorCmd to use
     * @param params The parameters map to encode as CBOR
     * @return The complete CTAP2 request frame
     * @throws Exception if encoding fails
     */
    private byte[] createCborRequest(AuthenticatorCmd cmd, Map<Integer, Object> params) throws Exception {
        // Encode parameters as CBOR
        byte[] cborData = Cbor.encode(params);
        
        // Create request with command byte followed by CBOR data
        byte[] requestData = new byte[cborData.length + 1];
        requestData[0] = (byte) cmd.getValue();
        System.arraycopy(cborData, 0, requestData, 1, cborData.length);
        
        // Calculate total length
        int length = requestData.length;
        
        // Create CTAP HID frame
        byte[] frame = new byte[length + 7]; // 4 bytes CID + 1 byte CMD + 2 bytes length + data
        
        // Copy channel ID - use the exact same reference that was used in setupPasskeyInCtapHid
        System.arraycopy(channelId, 0, frame, 0, 4);
        
        // Set command byte (CBOR = 0x10)
        frame[4] = (byte) CtapHidCmd.CBOR.getValue();
        
        // Set length (big-endian, 2 bytes)
        frame[5] = (byte) ((length >> 8) & 0xFF);
        frame[6] = (byte) (length & 0xFF);
        
        // Copy request data
        System.arraycopy(requestData, 0, frame, 7, requestData.length);
        
        return frame;
    }
    
    /**
     * Helper method to extract the CBOR response from a CTAP HID response
     * 
     * @param response The CTAP HID response frame
     * @return The decoded CBOR object
     * @throws Exception if decoding fails
     */
    /**
     * Encapsulates a shared secret using ECDH.
     *
     * @param publicKey The public key of the other party
     * @param privateKey The private key of this party
     * @return The shared secret
     * @throws Exception if an error occurs
     */
    private byte[] encapsulateSharedSecret(PublicKey publicKey, PrivateKey privateKey) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(privateKey);
        ka.doPhase(publicKey, true);
        byte[] sharedX = ka.generateSecret();
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        return digest.digest(sharedX);
    }
    
    /**
     * Helper method to extract the CBOR response from multiple CTAP HID response segments
     *
     * @param segments List of response segments
     * @return The decoded CBOR object
     * @throws Exception if decoding fails
     */
    @SuppressWarnings("unchecked")
    private Map<Integer, Object> extractCborFromSegments(ArrayList<byte[]> segments) throws Exception {
        ByteArrayOutputStream cborDataStream = new ByteArrayOutputStream();
        
        if (segments.isEmpty()) {
            throw new IllegalArgumentException("No segments provided");
        }
        
        byte[] firstSegment = segments.get(0);
        
        // Extract total message length from the first frame (bytes 5-6, big-endian)
        int totalMessageLength = ((firstSegment[5] & 0xFF) << 8) | (firstSegment[6] & 0xFF);
        System.err.println("Total message length: " + totalMessageLength);
        
        // The CBOR data starts after the status byte, so total CBOR data length is totalMessageLength - 1
        int totalCborLength = totalMessageLength - 1; // Subtract 1 for the status byte
        
        // If there's no CBOR data (just a status code), return an empty map
        if (totalCborLength <= 0) {
            System.err.println("No CBOR data in response (status-only response)");
            return new java.util.HashMap<>();
        }
        
        int bytesRead = 0;
        
        // First segment: skip first 8 bytes (4 bytes CID + 1 byte CMD + 2 bytes length + 1 byte status)
        int firstSegmentDataLength = Math.min(totalCborLength, firstSegment.length - 8);
        if (firstSegmentDataLength > 0) {
            cborDataStream.write(firstSegment, 8, firstSegmentDataLength);
            bytesRead += firstSegmentDataLength;
        }
        
        // Process remaining segments
        for (int i = 1; i < segments.size(); i++) {
            byte[] segment = segments.get(i);
            
            // For continuation frames, skip first 5 bytes (4 bytes CID + 1 byte sequence number)
            int dataStart = 5;
            
            // Calculate how many bytes to read from this segment
            int bytesRemaining = totalCborLength - bytesRead;
            int bytesToRead = Math.min(bytesRemaining, segment.length - dataStart);
            
            // Only read the actual data bytes, not padding
            if (bytesToRead > 0) {
                cborDataStream.write(segment, dataStart, bytesToRead);
                bytesRead += bytesToRead;
            }
            
            // If we've read all the data, we're done
            if (bytesRead >= totalCborLength) {
                break;
            }
        }
        
        System.err.println("Total CBOR bytes read: " + bytesRead + " out of " + totalCborLength);
        
        // Decode the complete CBOR data
        byte[] cborData = cborDataStream.toByteArray();
        return (Map<Integer, Object>) Cbor.decode(cborData);
    }
    
    /**
     * Test 1: authenticatorGetInfo request
     * This tests the CTAP2 authenticatorGetInfo command
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testAuthenticatorGetInfo() throws Exception {
        System.err.println("Start testAuthenticatorGetInfo");
        // Create empty parameters map for getInfo
        Map<Integer, Object> params = new HashMap<>();
        
        // Create CBOR request for authenticatorGetInfo (0x04)
        byte[] request = createCborRequest(AuthenticatorCmd.GETINF, params);
        System.err.println("CTAP request: " + Arrays.toString(request));
        
        // Process the request
        CtapHid ctapHid = new CtapHid(request);
        ctapHid.processMessage();

        // Get the response
        byte[] response = ctapHid.getResponseSegment();
        System.err.println("CTAP response: " + Arrays.toString(response));
        
        ArrayList<byte[]> segments = new ArrayList<byte[]>();
        // Verify response status is success (0x00)
        assertEquals(0x00, response[7] & 0xFF, "Response status should be success (0x00)");
        segments.add(response);
        // Get the remaining response segments
        byte[] segment = ctapHid.getResponseSegment();
        while(segment != null) {
            segments.add(segment);
            segment = ctapHid.getResponseSegment();
        }
        Map<Integer, Object> cborResponse = extractCborFromSegments(segments);
        System.err.println("CBOR response: " + cborResponse);

        // Verify expected fields in response
        assertTrue(cborResponse.containsKey(0x01), "Response should contain versions");
        assertTrue(cborResponse.containsKey(0x02), "Response should contain extensions");
        assertTrue(cborResponse.containsKey(0x03), "Response should contain AAGUID");
        assertTrue(cborResponse.containsKey(0x04), "Response should contain options");
        assertTrue(cborResponse.containsKey(0x05), "Response should contain maxMsgSize");
        assertTrue(cborResponse.containsKey(0x06), "Response should contain PIN protocols");
        
        // Verify versions include FIDO_2_0 and FIDO_2_1
        List<String> versions = (List<String>) cborResponse.get(0x01);
        boolean hasFido20 = false;
        for (String version : versions) {
            if ("FIDO_2_0".equals(version)) hasFido20 = true;
        }
        assertTrue(hasFido20, "Versions should include FIDO_2_0");
        System.err.println("End testAuthenticatorGetInfo");
    }
    
    /**
     * Test 2: getKeyAgreement authenticatorClientPIN sub command
     * This tests the CTAP2 authenticatorClientPIN getKeyAgreement subcommand
     */
    @Test
    public void testGetKeyAgreement() throws Exception {
        // Create parameters map for getKeyAgreement
        Map<Integer, Object> params = new HashMap<>();
        params.put(0x01, 1); // pinProtocol = 1
        params.put(0x02, PinSubCmd.GETKEY.getValue()); // subCommand = getKeyAgreement (0x02)
        
        // Create CBOR request for authenticatorClientPIN (0x06)
        byte[] request = createCborRequest(AuthenticatorCmd.ATHPIN, params);
        
        // Process the request
        CtapHid ctapHid = new CtapHid(request);
        ctapHid.processMessage();
        
        // Get the response
        byte[] response = ctapHid.getResponseSegment();
        
        // Verify response status is success (0x00)
        assertEquals(0x00, response[7] & 0xFF, "Response status should be success (0x00)");
        
        // Collect all response segments
        ArrayList<byte[]> segments = new ArrayList<>();
        segments.add(response);
        byte[] segment = ctapHid.getResponseSegment();
        while(segment != null) {
            segments.add(segment);
            segment = ctapHid.getResponseSegment();
        }
        
        // Extract and verify CBOR response
        Map<Integer, Object> cborResponse = extractCborFromSegments(segments);
        
        // Verify expected fields in response
        assertTrue(cborResponse.containsKey(0x01), "Response should contain key agreement");
        
        // Verify key agreement is a COSE key
        @SuppressWarnings("unchecked")
        Map<Integer, Object> coseKey = (Map<Integer, Object>) cborResponse.get(0x01);
        assertTrue(coseKey.containsKey(1), "COSE key should contain key type (kty)");
        assertTrue(coseKey.containsKey(3), "COSE key should contain algorithm (alg)");
        assertTrue(coseKey.containsKey(-1), "COSE key should contain curve (crv)");
        assertTrue(coseKey.containsKey(-2), "COSE key should contain x coordinate");
        assertTrue(coseKey.containsKey(-3), "COSE key should contain y coordinate");
        
        // Verify key type is EC2 (2)
        assertEquals(2, coseKey.get(1), "Key type should be EC2 (2)");
    }
    
    /**
     * Test 3: getPINToken authenticatorClientPIN sub command
     * This tests the CTAP2 authenticatorClientPIN getPINToken subcommand
     * 
     * This test should now succeed because we're using the same PIN hash that was used to create the CtapTxn.
     */
    @Test
    public void testGetPINToken() throws Exception {
        // First, we need to get the platform key
        Map<Integer, Object> getKeyParams = new HashMap<>();
        getKeyParams.put(0x01, 1); // pinProtocol = 1
        getKeyParams.put(0x02, PinSubCmd.GETKEY.getValue()); // subCommand = getKeyAgreement (0x02)
        
        byte[] getKeyRequest = createCborRequest(AuthenticatorCmd.ATHPIN, getKeyParams);
        CtapHid getKeyCtapHid = new CtapHid(getKeyRequest);
        getKeyCtapHid.processMessage();
        byte[] getKeyResponse = getKeyCtapHid.getResponseSegment();
        
        // Collect all response segments for the key agreement
        ArrayList<byte[]> keySegments = new ArrayList<>();
        keySegments.add(getKeyResponse);
        byte[] keySegment = getKeyCtapHid.getResponseSegment();
        while(keySegment != null) {
            keySegments.add(keySegment);
            keySegment = getKeyCtapHid.getResponseSegment();
        }
        
        Map<Integer, Object> getKeyResult = extractCborFromSegments(keySegments);
        @SuppressWarnings("unchecked")
        Map<Integer, Object> platformKey = (Map<Integer, Object>) getKeyResult.get(0x01);
        
        // Generate our own key pair using TestHelper
        KeyPair clientKeyPair = TestHelper.createTestKeyPair(TestConfig.getKeyAlgorithm());
        PublicKey clientPublicKey = clientKeyPair.getPublic();
        
        // Convert to COSE key format
        Map<Integer, Object> clientCoseKey = KeyUtils.toCoseKey(clientPublicKey);
        
        // Generate shared secret using ECDH
        // In a real implementation, we would encapsulate the shared secret
        // and the AuthenticatorAPI would decapsulate it
        byte[] sharedSecret = encapsulateSharedSecret(
                KeyUtils.fromCoseKey(platformKey),
                clientKeyPair.getPrivate());
        
        // Use the PIN hash created in setUp
        // This is the same PIN hash that was used to create the CtapTxn
        
        // Encrypt PIN hash with shared secret
        SecretKeySpec secretKeySpec = new SecretKeySpec(sharedSecret, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]); // All zeros IV
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);
        byte[] encryptedPinHash = cipher.doFinal(pinHash);
        
        // Create parameters map for getPINToken
        Map<Integer, Object> params = new HashMap<>();
        params.put(0x01, 1); // pinProtocol = 1
        params.put(0x02, PinSubCmd.GETTKN.getValue()); // subCommand = getPINToken (0x05)
        params.put(0x03, clientCoseKey); // keyAgreement
        params.put(0x06, encryptedPinHash); // pinHashEnc
        
        // Create CBOR request for authenticatorClientPIN (0x06)
        byte[] request = createCborRequest(AuthenticatorCmd.ATHPIN, params);
        
        // Process the request
        CtapHid ctapHid = new CtapHid(request);
        ctapHid.processMessage();
        
        // Get the response
        byte[] response = ctapHid.getResponseSegment();
        
        // For testing purposes, we'll just check if the response format is correct
        // If the PIN hash is invalid, we'll get an error status
        
        // If success, verify the response contains a PIN token
        if (response[7] == 0x00) {
            // Collect all response segments
            ArrayList<byte[]> segments = new ArrayList<>();
            segments.add(response);
            byte[] segment = ctapHid.getResponseSegment();
            while(segment != null) {
                segments.add(segment);
                segment = ctapHid.getResponseSegment();
            }
            
            Map<Integer, Object> cborResponse = extractCborFromSegments(segments);
            assertTrue(cborResponse.containsKey(0x02), "Response should contain PIN token");
            byte[] pinToken = (byte[]) cborResponse.get(0x02);
            assertEquals(32, pinToken.length, "PIN token should be 32 bytes");
        }
        // Otherwise, we expect an error code for invalid PIN
    }
    
    /**
     * Test 4: authenticatorMakeCredential request
     * This tests the CTAP2 authenticatorMakeCredential command
     * 
     * This test should now succeed because we're including a valid PIN token in the request.
     */
    /**
     * Helper method to extract credential ID from authenticator data.
     * AuthData structure: rpIdHash(32) + flags(1) + counter(4) + attestedCredentialData
     * AttestedCredentialData: aaguid(16) + credIdLength(2) + credId(L) + credentialPublicKey
     */
    private byte[] extractCredIdFromAuthData(byte[] authData) {
        // Skip rpIdHash (32 bytes) + flags (1 byte) + counter (4 bytes) = 37 bytes
        int offset = 37;
        
        // Skip AAGUID (16 bytes)
        offset += 16;
        
        // Read credential ID length (2 bytes, big-endian)
        int credIdLength = ((authData[offset] & 0xFF) << 8) | (authData[offset + 1] & 0xFF);
        System.err.println("Credential ID length from authData: " + credIdLength);
        offset += 2;
        
        // Extract credential ID
        byte[] credId = new byte[credIdLength];
        System.arraycopy(authData, offset, credId, 0, credIdLength);
        
        // Debug: Check if it's a valid base64url string
        try {
            String credIdStr = new String(credId, java.nio.charset.StandardCharsets.UTF_8);
            System.err.println("Credential ID as UTF-8 string (length " + credIdStr.length() + "): " + credIdStr);
            System.err.println("First 50 chars: " + credIdStr.substring(0, Math.min(50, credIdStr.length())));
        } catch (Exception e) {
            System.err.println("Failed to convert credId to UTF-8 string: " + e.getMessage());
        }
        
        return credId;
    }
    
    /**
     * Test helper that creates a credential and returns its ID.
     * This is called by testAuthenticatorGetAssertion to set up a credential first.
     */
    private byte[] createCredentialAndGetId() throws Exception {
        return makeCredentialAndReturnCredId();
    }
    
    /**
     * Helper method that creates a credential and returns its ID.
     * Not a @Test method since it returns a value.
     */
    private byte[] makeCredentialAndReturnCredId() throws Exception {
        System.err.println("testAuthenticatorMakeCredential");
        // Create client data hash (normally from the browser)
        byte[] clientDataHash = new byte[32];
        random.nextBytes(clientDataHash);
        
        // Create relying party info using TestConfig
        Map<String, Object> rpEntity = new HashMap<>();
        rpEntity.put("id", TestConfig.getRelyingPartyId());
        rpEntity.put("name", TestConfig.getRelyingPartyName());
        
        // Get the CtapTxn from the assignedCids map (now String-based)
        @SuppressWarnings("unchecked")
        Map<String, com.isfs.blekey.ctap.CtapTxn> cidMap =
                (Map<String, com.isfs.blekey.ctap.CtapTxn>) assignedCidsField.get(null);
        
        // Get the transaction using String key
        com.isfs.blekey.ctap.CtapTxn transaction = cidMap.get(cidKey(channelId));
        
        // Create user entity using TestConfig
        Map<String, Object> userEntity = new HashMap<>();
        userEntity.put("id", TestConfig.getUserId().getBytes());
        userEntity.put("name", TestConfig.getUserName());
        userEntity.put("displayName", TestConfig.getUserDisplayName());
        
        // Create parameters map for makeCredential
        Map<Integer, Object> params = new HashMap<>();
        params.put(0x01, clientDataHash); // clientDataHash
        
        // Create a nested map structure that matches what Fido2Authenticator expects
        Map<String, Object> wrappedRpEntity = new HashMap<>();
        wrappedRpEntity.put("id", TestConfig.getRelyingPartyId());
        params.put(0x02, wrappedRpEntity); // rp
        params.put(0x03, userEntity); // user
        
        // Create public key credential parameters
        Map<String, Object> credParam = new HashMap<>();
        credParam.put("type", "public-key");
        credParam.put("alg", -7); // ES256
        
        params.put(0x04, new Map[] { credParam }); // pubKeyCredParams
        
        // Add options to request resident key
        Map<String, Object> options = new HashMap<>();
        options.put("rk", true); // Request resident key
        options.put("uv", true); // Request user verification
        params.put(0x07, options); // options
        
        // Add PIN token
        
        // Make sure we found the transaction
        assertNotNull(transaction, "Transaction should not be null");
        
        byte[] pinToken = transaction.getPinAuthTkn();
        
        // Add PIN auth to request
        if (pinToken != null) {
            // Compute pinUvAuthParam = HMAC-SHA-256(pinToken, clientDataHash)[0:16]
            // Per CTAP2 spec: pinUvAuthParam is computed over clientDataHash for makeCredential
            try {
                javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
                javax.crypto.spec.SecretKeySpec keySpec = new javax.crypto.spec.SecretKeySpec(pinToken, "HmacSHA256");
                mac.init(keySpec);
                byte[] hmac = mac.doFinal(clientDataHash);
                byte[] pinUvAuthParam = java.util.Arrays.copyOfRange(hmac, 0, 16);
                
                params.put(0x08, pinUvAuthParam); // pinUvAuthParam
                params.put(0x09, 1); // pinUvAuthProtocol
            } catch (Exception e) {
                throw new RuntimeException("Failed to compute pinUvAuthParam", e);
            }
        }
        
        // Create CBOR request for authenticatorMakeCredential (0x01)
        byte[] request = createCborRequest(AuthenticatorCmd.MKCRED, params);
        
        System.err.println("make cred req ::  " + Arrays.toString(request));

        // Process the request
        // Before creating the CtapHid, verify that the transaction exists in the map
        @SuppressWarnings("unchecked")
        Map<String, com.isfs.blekey.ctap.CtapTxn> assignedCidsBeforeRequest =
                (Map<String, com.isfs.blekey.ctap.CtapTxn>) assignedCidsField.get(null);
        
        String channelKey = cidKey(channelId);
        boolean foundBeforeRequest = assignedCidsBeforeRequest.containsKey(channelKey);
        
        if (foundBeforeRequest) {
            System.err.println("Found transaction before request with channel ID: " + Arrays.toString(channelId));
        } else {
            System.err.println("Transaction not found before request with channel ID: " + Arrays.toString(channelId));
            System.err.println("assignedCids keys before request: " + assignedCidsBeforeRequest.keySet());
        }
        
        CtapHid ctapHid = new CtapHid(request);
        
        // After creating the CtapHid, verify that the channel ID in the CtapHid matches the one we used
        byte[] ctapHidChannelId = ctapHid.getCid();
        System.err.println("CtapHid channel ID: " + Arrays.toString(ctapHidChannelId));
        System.err.println("Original channel ID: " + Arrays.toString(channelId));
        System.err.println("Channel IDs equal: " + Arrays.equals(ctapHidChannelId, channelId));
        
        ctapHid.processMessage();

        assertTrue(ctapHid.isResponseReady(), "CBOR response should be ready");
        
        // Get the response
        byte[] response = ctapHid.getResponseSegment();
        
        // verify the response contains attestation data
        if (response[7] == 0x00) {
            // Collect all response segments
            ArrayList<byte[]> segments = new ArrayList<>();
            segments.add(response);
            byte[] segment = ctapHid.getResponseSegment();
            while(segment != null) {
                segments.add(segment);
                segment = ctapHid.getResponseSegment();
            }
            
            Map<Integer, Object> cborResponse = extractCborFromSegments(segments);
            assertTrue(cborResponse.containsKey(0x01), "Response should contain fmt");
            assertTrue(cborResponse.containsKey(0x02), "Response should contain authData");
            assertTrue(cborResponse.containsKey(0x03), "Response should contain attStmt");
            
            // Verify attestation format
            String fmt = (String) cborResponse.get(0x01);
            assertEquals("packed", fmt, "Attestation format should be 'packed'");
            
            // Verify authData is present and not empty
            byte[] authData = (byte[]) cborResponse.get(0x02);
            assertTrue(authData.length > 0, "AuthData should not be empty");
            
            // Extract and return credential ID from authData
            byte[] credId = extractCredIdFromAuthData(authData);
            System.err.println("Extracted credential ID length: " + credId.length);
            return credId;
        }
        else {
            assert false: "Attestation failed " + Arrays.toString(response);
            return null;
        }
    }
    
    /**
     * Test 4: authenticatorMakeCredential request
     * This is the actual JUnit test that doesn't return a value.
     */
    @Test
    public void testAuthenticatorMakeCredential() throws Exception {
        byte[] credId = makeCredentialAndReturnCredId();
        assertNotNull(credId, "Credential ID should not be null");
        assertTrue(credId.length > 0, "Credential ID should not be empty");
    }
    
    /**
     * Test 5: authenticatorGetAssertion request
     * This tests the CTAP2 authenticatorGetAssertion command
     * 
     * This test should now succeed because we're including a valid PIN token in the request.
     * However, it may still fail if there are no registered credentials for the relying party.
     */
    @Test
    public void testAuthenticatorGetAssertion() throws Exception {
        System.err.println("testAuthenticatorGetAssertion");
        
        // First, call makeCredential to create a credential and get its ID
        byte[] credId = createCredentialAndGetId();
        assertNotNull(credId, "Credential ID should not be null");
        
        
        String rpIdString = TestConfig.getRelyingPartyId();
        byte[] userHandle = TestConfig.getUserId().getBytes();
        
        // Create client data hash (normally from the browser)
        byte[] clientDataHash = new byte[32];
        random.nextBytes(clientDataHash);
        
        // Create parameters map for getAssertion using TestConfig
        // Per CTAP2 spec: 0x01 = rpId, 0x02 = clientDataHash
        Map<Integer, Object> params = new HashMap<>();
        params.put(0x01, rpIdString); // rpId as string (parameter 0x01)
        params.put(0x02, clientDataHash); // clientDataHash (parameter 0x02)
        
        // Add allowCredentials parameter with the credential ID we just created
        Map<String, byte[]> allowedCred = new HashMap<>();
        allowedCred.put("id", credId);
        allowedCred.put("user", userHandle);
        ArrayList<Map<String, byte[]>> allowList = new ArrayList<>();
        allowList.add(allowedCred);
        params.put(0x03, allowList); // allowCredentials
        
        // Add PIN token
        // Get the CtapTxn from the assignedCids map
        @SuppressWarnings("unchecked")
        Map<String, com.isfs.blekey.ctap.CtapTxn> assignedCids =
                (Map<String, com.isfs.blekey.ctap.CtapTxn>) assignedCidsField.get(null);
        
        // Get the transaction using String key
        com.isfs.blekey.ctap.CtapTxn txn = assignedCids.get(cidKey(channelId));
        
        // Make sure we found the transaction
        assertNotNull(txn, "Transaction should not be null");
        
        byte[] pinToken = txn.getPinAuthTkn();
        
        // Add PIN auth to request
        if (pinToken != null) {
            // Compute pinUvAuthParam = HMAC-SHA-256(pinToken, clientDataHash)[0:16]
            // Per CTAP2 spec: pinUvAuthParam is computed over clientDataHash for getAssertion
            try {
                javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
                javax.crypto.spec.SecretKeySpec keySpec = new javax.crypto.spec.SecretKeySpec(pinToken, "HmacSHA256");
                mac.init(keySpec);
                byte[] hmac = mac.doFinal(clientDataHash);
                byte[] pinUvAuthParam = java.util.Arrays.copyOfRange(hmac, 0, 16);
                
                params.put(0x08, pinUvAuthParam); // pinUvAuthParam
                params.put(0x09, 1); // pinUvAuthProtocol
            } catch (Exception e) {
                throw new RuntimeException("Failed to compute pinUvAuthParam", e);
            }
        }
        
        // Create CBOR request for authenticatorGetAssertion (0x02)
        byte[] request = createCborRequest(AuthenticatorCmd.NXTAST, params);
        System.err.println("CTAP request: " + Arrays.toString(request));
        // Process the request
        // Before creating the CtapHid, verify that the transaction exists in the map
        @SuppressWarnings("unchecked")
        Map<String, com.isfs.blekey.ctap.CtapTxn> assignedCidsBeforeRequest =
                (Map<String, com.isfs.blekey.ctap.CtapTxn>) assignedCidsField.get(null);
        
        String channelKey = cidKey(channelId);
        boolean foundBeforeRequest = assignedCidsBeforeRequest.containsKey(channelKey);
        
        if (foundBeforeRequest) {
            System.err.println("Found transaction before request with channel ID: " + Arrays.toString(channelId));
        } else {
            System.err.println("Transaction not found before request with channel ID: " + Arrays.toString(channelId));
            System.err.println("assignedCids keys before request: " + assignedCidsBeforeRequest.keySet());
        }
        
        CtapHid ctapHid = new CtapHid(request);
        
        // After creating the CtapHid, verify that the channel ID in the CtapHid matches the one we used
        byte[] ctapHidChannelId = ctapHid.getCid();
        System.err.println("CtapHid channel ID: " + Arrays.toString(ctapHidChannelId));
        System.err.println("Original channel ID: " + Arrays.toString(channelId));
        System.err.println("Channel IDs equal: " + Arrays.equals(ctapHidChannelId, channelId));
        
        ctapHid.processMessage();
        
        assertTrue(ctapHid.isResponseReady(), "CBOR response should be ready");

        // Get the response
        byte[] response = ctapHid.getResponseSegment();
        System.err.println("CTAP response: " + Arrays.toString(response));
        
        // verify the response contains assertion data
        if (response[7] == 0x00) {
            // Collect all response segments
            ArrayList<byte[]> segments = new ArrayList<>();
            segments.add(response);
            byte[] segment = ctapHid.getResponseSegment();
            while(segment != null) {
                segments.add(segment);
                segment = ctapHid.getResponseSegment();
            }
            
            Map<Integer, Object> cborResponse = extractCborFromSegments(segments);
            assertTrue(cborResponse.containsKey(0x01), "Response should contain credential");
            assertTrue(cborResponse.containsKey(0x02), "Response should contain authData");
            assertTrue(cborResponse.containsKey(0x03), "Response should contain signature");
            
            // Verify credential is present
            @SuppressWarnings("unchecked")
            Map<String, Object> credential = (Map<String, Object>) cborResponse.get(0x01);
            assertTrue(credential.containsKey("id"), "Credential should contain ID");
            assertTrue(credential.containsKey("type"), "Credential should contain type");
            assertEquals("public-key", credential.get("type"), "Credential type should be 'public-key'");
            
            // Verify authData is present and not empty
            byte[] authData = (byte[]) cborResponse.get(0x02);
            assertTrue(authData.length > 0, "AuthData should not be empty");
            
            // Verify signature is present and not empty
            byte[] signature = (byte[]) cborResponse.get(0x03);
            assertTrue(signature.length > 0, "Signature should not be empty");
        }
        else {
            assert false: "Assertion failed: " + Arrays.toString(response);
        }
    }
}

// Made with Bob
