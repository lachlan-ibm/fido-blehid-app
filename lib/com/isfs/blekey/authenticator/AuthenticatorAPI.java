package com.isfs.blekey.authenticator;

import com.isfs.blekey.util.Cbor;
import com.isfs.blekey.ctap.Ctap2StatusCode;
import com.isfs.blekey.ctap.CtapTxn;
import com.isfs.blekey.util.KeyUtils;

import jakarta.json.JsonObject;

import com.isfs.blekey.data.Passkey;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

/**
 * Implements the FIDO2 Client to Authenticator Protocol (CTAP2) API.
 * This class handles CTAP2 commands and generates appropriate responses,
 * interfacing with the Fido2Authenticator to perform cryptographic operations.
 */
public class AuthenticatorAPI {

    /**
     * Number of PIN retry attempts allowed before lockout.
     */
    private static int pinRetries = 5;

    /**
     * Key pair used for platform authentication.
     */
    private static KeyPair platKeyPair = KeyUtils.getKeyPair("EC");
    
    /**
     * Map of channel IDs to their associated platform keys and passkeys.
     * Maps CID to a map containing the passkey and platform public key.
     */
    private static Map<byte[], Map<String, Object>> openKeys = new HashMap<byte[], Map<String, Object>>();

    /**
     * Creates an error response with the specified status code.
     *
     * @param code The CTAP2 status code for the error
     * @return A byte array containing the error response
     */
    private static byte[] error(Ctap2StatusCode code) {
        return new byte[] {(byte) code.getCode()};
    }

    /**
     * Creates a success response with the specified payload.
     *
     * @param rsp The response payload to include
     * @return A byte array containing the success response with the payload
     */
    private static byte[] success(byte[] rsp) {
        ByteBuffer bb = ByteBuffer.allocate(rsp.length + 1);
        bb.put((byte) Ctap2StatusCode.SUCCESS.getCode()); bb.put(rsp);
        return bb.array(); //[SUCCESS, *cbor]
    }

    /**
     * Creates an error response for an invalid command.
     *
     * @param txn The CTAP transaction
     * @param req The request parameters
     * @return A byte array containing the error response
     */
    protected static byte[] err(CtapTxn txn, Map<Integer, Object> req) {
        return error(Ctap2StatusCode.INVALID_COMMAND);
    }

    /**
     * Processes a makeCredential request (CTAP2 authenticatorMakeCredential command).
     * Creates a new credential and returns an attestation object.
     *
     * @param txn The CTAP transaction
     * @param req The request parameters
     * @return A byte array containing the response
     */
    protected static byte[] makeCredential(CtapTxn txn, Map<Integer, Object> req) {
        Fido2Authenticator pkey = Fido2Authenticator(txn.getPasskey());
        if(pkey == null) {
            return error(Ctap2StatusCode.NOT_ALLOWED); //No open key
        }
        try {
            Map<String, Object> rp = Map.of("rp", req.get(0x02));
            byte[] cdh = (byte[]) req.get(0x01);
            JsonObject cdj = pkey.buildClientDataJson(rp);
            byte[] authData = pkey.buildAuthenticatorData(cdj, rp, "packed", 
                        (Map) new HashMap<String, String>(), (Map) new HashMap<String, String>(), pkey.getKeyPair());
            Map<String, Object> attStmt = pkey.processAttestationStatement("packed", cdh, authData, 
                        pkey.getCredIdBytes(), pkey.getKeyPair(), pkey.getCaKeyPair(), pkey.getCaCert());
            Map<Integer, Object> rsp = Map.of(0x01, "packed",
                                            0x02, authData, 0x03, attStmt);
            return success(Cbor.encode(rsp));
        } catch (Exception e) {
            return error(Ctap2StatusCode.OTHER);
        }
    }

    /**
     * Processes a getAssertion request (CTAP2 authenticatorGetAssertion command).
     * Signs a challenge using an existing credential.
     *
     * @param txn The CTAP transaction
     * @param req The request parameters
     * @return A byte array containing the response
     */
    protected static byte[] getAssertion(CtapTxn txn, Map<Integer, Object> req) {
        Fido2Authenticator pkey = Fido2Authenticator(txn.getPasskey());
        if(pkey == null) {
            return error(Ctap2StatusCode.NOT_ALLOWED);
        }
        try {
            Map<String, Object> cred = Map.of("id", pkey.getCredIdBytes(),
                        "type", "public-key");
            byte[] authData = pkey.buildAuthenticatorData(clientDataJSON, pubKeyMap, "packed", 
                        (Map) new HashMap<String, String>(), (Map) new HashMap<String, String>(), pkey.getKeyPair());
            byte[] clientDataHash = (byte[]) req.get(0x01);
            ByteBuffer bb = ByteBuffer.allocate(authData.length + clientDataHash.length);
            bb.put(authData);
            bb.put(clientDataHash);
            byte[] sig = pkey.signData(bb.array(), pkey.getPrivKey(), "SHA256withECDSA"); 
            Map<Integer, Object> rsp = Map.of(
                        0x01, cred, 0x02, authData, 0x03, sig);
            return success(Cbor.encode(rsp));
        } catch (Exception e) {
            return error(Ctap2StatusCode.OTHER);
        }
    }

    /**
     * Processes a getInfo request (CTAP2 authenticatorGetInfo command).
     * Returns information about the authenticator's capabilities.
     *
     * @param txn The CTAP transaction
     * @param req The request parameters
     * @return A byte array containing the response
     */
    protected static byte[] getInfo(CtapTxn txn, Map<Integer, Object> req) {
        Map<String, Boolean> capabilities = Map.of("rk", true,
                                                   "plat", true, //XD
                                                   "clientPint", true);
        Map<Integer, Object> info = Map.of(
            0x01, new String[] {"FIDO_2_1", "FIDO_2_0"},
            0x02, new String[] {"hmac-secret"}, //extensions
            0x03, new int[] {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, //AAGUID
            0x04, capabilities, //capabilities
            0x05, 4096, // maxMsgSize
            0x06, new int[] {1} //PIN/UV Auth Protocol One
        );  
        return success(Cbor.encode(info));
    }

    /**
     * Processes a PIN request (CTAP2 authenticatorClientPIN command).
     * Handles PIN-related operations such as getting retries, keys, and tokens.
     *
     * @param txn The CTAP transaction
     * @param req The request parameters
     * @return A byte array containing the response
     */
    protected static byte[] pinRequest(CtapTxn txn, Map<Integer, Object> req) {
        PinSubCmd cmd = PinSubCmd.fromInt((int) req.getOrDefault(2, 0));
        switch(cmd)
        {
            case GETRETRY:
                return pinRty(txn, req);
            case GETKEY:
                return getKey(txn, req);
            case GETTKN:
                return getTkn(txn, req);
            default:
                return error(Ctap2StatusCode.INVALID_COMMAND);
        }
    }

    /**
     * Handles the getKey PIN subcommand.
     * Returns the platform public key in COSE format.
     *
     * @param txn The CTAP transaction
     * @param req The request parameters
     * @return A byte array containing the response
     */
    private static byte[] getKey(CtapTxn txn, Map<Integer, Object> req) {
        Map<Integer, Object> rsp = Map.of(0x01, 
                KeyUtils.toCoseKey(AuthenticatorAPI.platKeyPair.getPublic()));
        byte[] key = Cbor.encode(rsp);
        return success(key);
    }

    /**
     * Handles the getToken PIN subcommand.
     * Verifies the PIN and returns an authentication token.
     *
     * @param txn The CTAP transaction
     * @param req The request parameters
     * @return A byte array containing the response
     */
    private static byte[] getTkn(CtapTxn txn, Map<Integer, Object> req) {
        //Decapsulate shared secret
        byte[] pinHashEnc = (byte[]) req.get(0x06);
        PublicKey theirKey = KeyUtils.fromCoseKey((Map<Integer, Object>) req.get(0x03));
        byte[] sharedSecret = KeyUtils.decapsulate(theirKey,
                    AuthenticatorAPI.platKeyPair.getPrivate());
        //Verify pin hash
        Passkey pkeyFile = Passkey.openKey(pinHashEnc);
        if (pkeyFile == null) {
            return AuthenticatorAPI.error(Ctap2StatusCode.PIN_AUTH_INVALID);
        }
        try {
            Fido2Authenticator pkey = Fido2Authenticator.fromPasskey(pkeyFile);
            //Return pin auth token
            byte[] pinTkn = new byte[32];
            SecureRandom random = new SecureRandom();
            random.nextBytes(pinTkn);
            openKeys.put(txn.getCid(), Map.of("passkey", pkey, "plat", theirKey));
            pinRetries = 5;
            Map<Integer, Object> rsp = Map.of(0x02, pinTkn);
            txn.setPinAuthTkn(pinTkn);
            return success(Cbor.encode(rsp));
        } catch (Exception e) {
            return error(Ctap2StatusCode.INVALID_PARAMETER);
        }
    }

    /**
     * Handles the getRetries PIN subcommand.
     * Returns the number of PIN retry attempts remaining.
     *
     * @param txn The CTAP transaction
     * @param req The request parameters
     * @return A byte array containing the response
     */
    private static byte[] pinRty(CtapTxn txn, Map<Integer, Object> req) {
        Map<Integer, Object> rsp = Map.of(0x03, pinRetries--);
        return success(Cbor.encode(rsp));
    }

    /**
     * Main entry point for processing CTAP2 commands.
     * Routes the request to the appropriate handler based on the command type.
     *
     * @param txn The CTAP transaction
     * @param api The CTAP2 command identifier
     * @param request The request parameters
     * @return A byte array containing the response
     */
    public static byte[] process(CtapTxn txn, int api, Map<Integer, Object> request) {
        AuthenticatorCmd cmd = AuthenticatorCmd.fromInt(api);
        switch(cmd)
        {
            case MKCRED:
                return makeCredential(txn, request);
            case NXTAST:
                return getAssertion(txn, request);
            case GETINF:
                return getInfo(txn, request);
            case ATHPIN:
                return pinRequest(txn, request);
            default:
                return error(Ctap2StatusCode.INVALID_COMMAND);
        }
    }
}

// Made with Bob
