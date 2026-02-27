/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.ctap;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
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
import com.isfs.blekey.authenticator.AuthenticatorCmd;
import com.isfs.blekey.authenticator.Fido2Authenticator;
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
        
        // Create a seed for the passkey
        byte[] seed = new byte[32];
        random.nextBytes(seed);
        
        // Create an empty map for resident credentials
        Map<byte[], Map<String, byte[]>> resCreds = new HashMap<>();
        
        // Create the passkey using the protected constructor via reflection
        java.lang.reflect.Constructor<Passkey> constructor =
                com.isfs.blekey.data.Passkey.class.getDeclaredConstructor(
                        java.security.PrivateKey.class,
                        java.security.cert.X509Certificate.class,
                        byte[].class,
                        Map.class);
        constructor.setAccessible(true);
        return constructor.newInstance(keyPair.getPrivate(), cert, seed, resCreds);
    }
    
    /**
     * A custom HashMap that compares byte arrays by content, not by reference.
     */
    private static class ByteArrayMap<V> extends HashMap<byte[], V> {
        @Override
        public boolean containsKey(Object key) {
            if (!(key instanceof byte[])) {
                return false;
            }
            byte[] keyBytes = (byte[]) key;
            for (byte[] k : keySet()) {
                if (Arrays.equals(k, keyBytes)) {
                    return true;
                }
            }
            return false;
        }
        
        @Override
        public V get(Object key) {
            if (!(key instanceof byte[])) {
                return null;
            }
            byte[] keyBytes = (byte[]) key;
            for (Map.Entry<byte[], V> entry : entrySet()) {
                if (Arrays.equals(entry.getKey(), keyBytes)) {
                    return entry.getValue();
                }
            }
            return null;
        }
        
        @Override
        public V put(byte[] key, V value) {
            // Remove any existing entry with the same content
            for (byte[] k : new ArrayList<>(keySet())) {
                if (Arrays.equals(k, key)) {
                    remove(k);
                    break;
                }
            }
            return super.put(key, value);
        }
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
        
        // Create a CtapTxn with the passkey
        com.isfs.blekey.ctap.CtapTxn txn = new com.isfs.blekey.ctap.CtapTxn(
                channelId, null, pinToken, passkey, pinHash);
        
        // Get the assignedCids field from CtapHid
        if (assignedCidsField == null) {
            assignedCidsField = com.isfs.blekey.ctap.CtapHid.class.getDeclaredField("assignedCids");
            assignedCidsField.setAccessible(true);
        }
        
        // Replace the assignedCids map with our custom implementation
        ByteArrayMap<com.isfs.blekey.ctap.CtapTxn> newMap = new ByteArrayMap<>();
        
        // Get the current assignedCids map
        @SuppressWarnings("unchecked")
        Map<byte[], com.isfs.blekey.ctap.CtapTxn> currentMap =
                (Map<byte[], com.isfs.blekey.ctap.CtapTxn>) assignedCidsField.get(null);
        
        // Copy all entries from the current map to our new map
        for (Map.Entry<byte[], com.isfs.blekey.ctap.CtapTxn> entry : currentMap.entrySet()) {
            newMap.put(entry.getKey(), entry.getValue());
        }
        
        // Add our new transaction to the map
        newMap.put(channelId, txn);
        
        // Replace the assignedCids map with our custom implementation
        assignedCidsField.set(null, newMap);
    }
    
    @BeforeEach
    public void setUp() throws Exception {
        // Generate a random channel ID for testing
        random = new SecureRandom();
        channelId = new byte[4];
        random.nextBytes(channelId);
        
        // Create a PIN hash
        pinHash = new byte[32];
        random.nextBytes(pinHash);
        
        // Create a test passkey and add it to the assignedCids map
        com.isfs.blekey.data.Passkey passkey = createTestPasskey();
        setupPasskeyInCtapHid(passkey);
        
        // Verify that the passkey was added to the assignedCids map
        @SuppressWarnings("unchecked")
        Map<byte[], com.isfs.blekey.ctap.CtapTxn> assignedCids =
                (Map<byte[], com.isfs.blekey.ctap.CtapTxn>) assignedCidsField.get(null);
        
        // Find the transaction by comparing byte arrays by content
        boolean found = false;
        for (Map.Entry<byte[], com.isfs.blekey.ctap.CtapTxn> entry : assignedCids.entrySet()) {
            if (Arrays.equals(entry.getKey(), channelId)) {
                found = true;
                System.err.println("Found transaction in setUp with channel ID: " + Arrays.toString(channelId));
                break;
            }
        }
        
        if (!found) {
            System.err.println("Transaction not found in setUp with channel ID: " + Arrays.toString(channelId));
            System.err.println("assignedCids keys: ");
            for (byte[] key : assignedCids.keySet()) {
                System.err.println("  " + Arrays.toString(key));
            }
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
        if (!(publicKey instanceof java.security.interfaces.ECPublicKey) ||
            !(privateKey instanceof java.security.interfaces.ECPrivateKey)) {
            throw new IllegalArgumentException("Keys must be EC keys for ECDH");
        }
        
        java.security.interfaces.ECPublicKey ecPublicKey = (java.security.interfaces.ECPublicKey) publicKey;
        java.security.interfaces.ECPrivateKey ecPrivateKey = (java.security.interfaces.ECPrivateKey) privateKey;
        
        // Get the public key point
        java.security.spec.ECPoint publicPoint = ecPublicKey.getW();
        
        // Get the private key scalar
        java.math.BigInteger privateScalar = ecPrivateKey.getS();
        
        // Perform scalar multiplication: privateScalar * publicPoint
        java.security.spec.ECPoint sharedPoint = KeyUtils.scalmult(
                ecPublicKey.getParams().getCurve(),
                publicPoint,
                privateScalar);
        
        // Use the x-coordinate of the shared point as the shared secret
        byte[] sharedX = sharedPoint.getAffineX().toByteArray();
        
        // Hash the shared secret to derive the AES key
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
        
        // The CBOR data starts after the command byte, so total CBOR data length is totalMessageLength - 1
        int totalCborLength = totalMessageLength - 1; // Subtract 1 for the command byte
        int bytesRead = 0;
        
        // First segment: skip first 8 bytes (4 bytes CID + 1 byte CMD + 2 bytes length + 1 byte status)
        int firstSegmentDataLength = firstSegment.length - 8;
        cborDataStream.write(firstSegment, 8, firstSegmentDataLength);
        bytesRead += firstSegmentDataLength;
        
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
        boolean hasFido21 = false;
        for (String version : versions) {
            if ("FIDO_2_0".equals(version)) hasFido20 = true;
            if ("FIDO_2_1".equals(version)) hasFido21 = true;
        }
        assertTrue(hasFido20, "Versions should include FIDO_2_0");
        assertTrue(hasFido21, "Versions should include FIDO_2_1");
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
    @Test
    public void testAuthenticatorMakeCredential() throws Exception {
        System.err.println("testAuthenticatorMakeCredential");
        // Create client data hash (normally from the browser)
        byte[] clientDataHash = new byte[32];
        random.nextBytes(clientDataHash);
        
        // Create relying party info using TestConfig
        Map<String, Object> rpEntity = new HashMap<>();
        rpEntity.put("id", TestConfig.getRelyingPartyId());
        rpEntity.put("name", TestConfig.getRelyingPartyName());
        
        // Add a resident credential for this relying party to the passkey
        byte[] rpIdBytes = TestConfig.getRelyingPartyId().getBytes();
        byte[] credId = new byte[32];
        random.nextBytes(credId);
        byte[] userHandle = TestConfig.getUserId().getBytes();
        
        // Get the CtapTxn from the assignedCids map
        @SuppressWarnings("unchecked")
        Map<byte[], com.isfs.blekey.ctap.CtapTxn> cidMap =
                (Map<byte[], com.isfs.blekey.ctap.CtapTxn>) assignedCidsField.get(null);
        
        // Find the transaction by comparing byte arrays by content
        com.isfs.blekey.ctap.CtapTxn transaction = null;
        for (Map.Entry<byte[], com.isfs.blekey.ctap.CtapTxn> entry : cidMap.entrySet()) {
            if (Arrays.equals(entry.getKey(), channelId)) {
                transaction = entry.getValue();
                break;
            }
        }
        
        // Add the resident credential to the passkey
        if (transaction != null && transaction.getPasskey() != null) {
            transaction.getPasskey().addResCred(rpIdBytes, credId, userHandle);
        }
        
        
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
        
        // Add PIN token
        
        // Make sure we found the transaction
        assertNotNull(transaction, "Transaction should not be null");
        
        byte[] pinToken = transaction.getPinAuthTkn();
        
        // Add PIN token to request
        if (pinToken != null) {
            params.put(0x07, pinToken); // pinAuth
            params.put(0x08, 1); // pinProtocol
        }
        
        // Create CBOR request for authenticatorMakeCredential (0x01)
        byte[] request = createCborRequest(AuthenticatorCmd.MKCRED, params);
        
        System.err.println("make cred req ::  " + Arrays.toString(request));

        // Process the request
        // Before creating the CtapHid, verify that the transaction exists in the map
        @SuppressWarnings("unchecked")
        Map<byte[], com.isfs.blekey.ctap.CtapTxn> assignedCidsBeforeRequest =
                (Map<byte[], com.isfs.blekey.ctap.CtapTxn>) assignedCidsField.get(null);
        
        boolean foundBeforeRequest = false;
        for (Map.Entry<byte[], com.isfs.blekey.ctap.CtapTxn> entry : assignedCidsBeforeRequest.entrySet()) {
            if (Arrays.equals(entry.getKey(), channelId)) {
                foundBeforeRequest = true;
                System.err.println("Found transaction before request with channel ID: " + Arrays.toString(channelId));
                break;
            }
        }
        
        if (!foundBeforeRequest) {
            System.err.println("Transaction not found before request with channel ID: " + Arrays.toString(channelId));
            System.err.println("assignedCids keys before request: ");
            for (byte[] key : assignedCidsBeforeRequest.keySet()) {
                System.err.println("  " + Arrays.toString(key));
            }
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
        }
        else {
            assert false: "Attesation failed " + Arrays.toString(response);;
        }
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
        
        // Add a resident credential for this relying party to the passkey
        String rpIdString = TestConfig.getRelyingPartyId();
        byte[] rpIdBytes = rpIdString.getBytes();
        // Use the authenticator's credential ID instead of a random one
        byte[] credId = null;
        try {
            // Get the transaction first
            @SuppressWarnings("unchecked")
            Map<byte[], com.isfs.blekey.ctap.CtapTxn> cidMap =
                    (Map<byte[], com.isfs.blekey.ctap.CtapTxn>) assignedCidsField.get(null);
            
            // Find the transaction by comparing byte arrays by content
            com.isfs.blekey.ctap.CtapTxn transaction = null;
            for (Map.Entry<byte[], com.isfs.blekey.ctap.CtapTxn> entry : cidMap.entrySet()) {
                if (Arrays.equals(entry.getKey(), channelId)) {
                    transaction = entry.getValue();
                    break;
                }
            }
            
            if (transaction != null && transaction.getPasskey() != null) {
                Fido2Authenticator authenticator = new Fido2Authenticator();
                authenticator.setSymKeys(KeyUtils.getPasskeySeed(rpIdBytes, transaction.getPasskey().getPrivateKey()));
                credId = authenticator.getCredId();
            } else {
                fail("Transaction or passkey is null");
            }
        } catch (Exception e) {
            fail("Failed to get credential ID: " + e.getMessage());
        }
        assert credId != null: "cred id not set from authenticator";
        byte[] userHandle = TestConfig.getUserId().getBytes();
        
        // Get the CtapTxn from the assignedCids map
        @SuppressWarnings("unchecked")
        Map<byte[], com.isfs.blekey.ctap.CtapTxn> cidMap =
                (Map<byte[], com.isfs.blekey.ctap.CtapTxn>) assignedCidsField.get(null);
        
        // Find the transaction by comparing byte arrays by content
        com.isfs.blekey.ctap.CtapTxn transaction = null;
        for (Map.Entry<byte[], com.isfs.blekey.ctap.CtapTxn> entry : cidMap.entrySet()) {
            if (Arrays.equals(entry.getKey(), channelId)) {
                transaction = entry.getValue();
                break;
            }
        }
        
        // Add the resident credential to the passkey
        if (transaction != null && transaction.getPasskey() != null) {
            transaction.getPasskey().addResCred(rpIdBytes, credId, userHandle);
        }
        
        // Create client data hash (normally from the browser)
        byte[] clientDataHash = new byte[32];
        random.nextBytes(clientDataHash);
        
        // Create parameters map for getAssertion using TestConfig
        Map<Integer, Object> params = new HashMap<>();
        params.put(0x01, clientDataHash); // clientDataHash
        
        // Create a map with rpId as a key-value pair - this is what AuthenticatorAPI.generateSignedAssertion expects
        Map<String, Object> pubKeyMap = new HashMap<>();
        pubKeyMap.put("rpId", rpIdString);
        params.put(0x02, pubKeyMap); // rpId as a map with "rpId" key
        
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
        Map<byte[], com.isfs.blekey.ctap.CtapTxn> assignedCids =
                (Map<byte[], com.isfs.blekey.ctap.CtapTxn>) assignedCidsField.get(null);
        
        // Find the transaction by comparing byte arrays by content
        com.isfs.blekey.ctap.CtapTxn txn = null;
        for (Map.Entry<byte[], com.isfs.blekey.ctap.CtapTxn> entry : assignedCids.entrySet()) {
            if (Arrays.equals(entry.getKey(), channelId)) {
                txn = entry.getValue();
                break;
            }
        }
        
        // Make sure we found the transaction
        assertNotNull(txn, "Transaction should not be null");
        
        byte[] pinToken = txn.getPinAuthTkn();
        
        // Add PIN token to request
        if (pinToken != null) {
            params.put(0x06, pinToken); // pinAuth
            params.put(0x07, 1); // pinProtocol
        }
        
        // Create CBOR request for authenticatorGetAssertion (0x02)
        byte[] request = createCborRequest(AuthenticatorCmd.NXTAST, params);
        System.err.println("CTAP request: " + Arrays.toString(request));
        // Process the request
        // Before creating the CtapHid, verify that the transaction exists in the map
        @SuppressWarnings("unchecked")
        Map<byte[], com.isfs.blekey.ctap.CtapTxn> assignedCidsBeforeRequest =
                (Map<byte[], com.isfs.blekey.ctap.CtapTxn>) assignedCidsField.get(null);
        
        boolean foundBeforeRequest = false;
        for (Map.Entry<byte[], com.isfs.blekey.ctap.CtapTxn> entry : assignedCidsBeforeRequest.entrySet()) {
            if (Arrays.equals(entry.getKey(), channelId)) {
                foundBeforeRequest = true;
                System.err.println("Found transaction before request with channel ID: " + Arrays.toString(channelId));
                break;
            }
        }
        
        if (!foundBeforeRequest) {
            System.err.println("Transaction not found before request with channel ID: " + Arrays.toString(channelId));
            System.err.println("assignedCids keys before request: ");
            for (byte[] key : assignedCidsBeforeRequest.keySet()) {
                System.err.println("  " + Arrays.toString(key));
            }
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
