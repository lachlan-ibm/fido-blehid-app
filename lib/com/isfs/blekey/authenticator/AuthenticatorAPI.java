package com.isfs.blekey.authenticator;

import com.isfs.blekey.util.Cbor;
import com.isfs.blekey.ctap.Ctap2StatusCode;
import com.isfs.blekey.util.KeyUtils;

import jakarta.json.JsonObject;

import com.isfs.blekey.data.Passkey;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;


public class AuthenticatorAPI {

    private static int pinRetries = 5;

    private static KeyPair platKeyPair = KeyUtils.getKeyPair("EC");
    // cid and associated platform public key, 
    private static Map<byte[], Map<String, Object>> openKeys = new HashMap<byte[], Map<String, Object>>();


    private static byte[] error(Ctap2StatusCode code) {
        return new byte[] {(byte) code.getCode()};
    }

    private static byte[] success(byte[] rsp) {
        ByteBuffer bb = ByteBuffer.allocate(rsp.length + 1);
        bb.put((byte) Ctap2StatusCode.SUCCESS.getCode()); bb.put(rsp);
        return bb.array(); //[SUCCESS, *cbor]
    }

    protected static byte[] err(byte[] cid, Map<Integer, Object> req) {
        return error(Ctap2StatusCode.INVALID_COMMAND);
    }

    private static Fido2Authenticator getAuthenticator(byte[]cid) {
        Map<String, Object> openChannel = openKeys.getOrDefault(cid, null);
        if(openChannel == null) {
            return null;//No open key
        }
        return (Fido2Authenticator) openChannel.get("passkey");
    }

    protected static byte[] makeCredential(byte[] cid, Map<Integer, Object> req) {
        Fido2Authenticator pkey = getAuthenticator(cid);
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

    protected static byte[] getAssertion(byte[] cid, Map<Integer, Object> req) {
        Fido2Authenticator pkey = getAuthenticator(cid);
        if(pkey == null) {
            return error(Ctap2StatusCode.NOT_ALLOWED);
        }
        try {
            Map<String, Object> cred = Map.of("id", pkey.getCredIdBytes(),
                        "type", "public-key");
            Map<String, Object> pubKeyMap = Map.of("rpID", req.getOrDefault(0x02, "NULL"));
            JsonObject clientDataJSON = pkey.buildClientDataJson(pubKeyMap);
            byte[] authData = pkey.buildAuthenticatorData(clientDataJSON, pubKeyMap, "packed", 
                        (Map) new HashMap<String, String>(), (Map) new HashMap<String, String>(), pkey.getKeyPair());
            byte[] sig = pkey.signData(authData, pkey.getPrivKey(), "SHA256withECDSA"); 
            Map<Integer, Object> rsp = (Map<Integer, Object>) Map.of(
                        0x01, cred, 0x02, authData, 0x03, sig);
            return success(Cbor.encode(rsp));
        } catch (Exception e) {
            return error(Ctap2StatusCode.OTHER);
        }
    }

    protected static byte[] getInfo(byte[] cid, Map<Integer, Object> req) {
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


    protected static byte[] pinRequest(byte[] cid, Map<Integer, Object> req) {
        PinSubCmd cmd = PinSubCmd.fromInt((int) req.getOrDefault(2, 0));
        switch(cmd)
        {
            case GETRETRY:
                return pinRty(cid, req);
            case GETKEY:
                return getKey(cid, req);
            case GETTKN:
                return getTkn(cid, req);
            default:
                return error(Ctap2StatusCode.INVALID_COMMAND);
        }
    }

    private static byte[] getKey(byte[] cid, Map<Integer, Object> req) {
        Map<Integer, Object> rsp = Map.of(0x01, 
                KeyUtils.toCoseKey(AuthenticatorAPI.platKeyPair.getPublic()));
        byte[] key = Cbor.encode(rsp);
        return success(key);
    }

    private static byte[] getTkn(byte[] cid, Map<Integer, Object> req) {
        //Decapsulate shared secret
        byte[] pinHashEnc = (byte[]) req.get(0x06);
        PublicKey theirKey = KeyUtils.fromCoseKey((Map<Integer, Object>) req.get(0x03));
        byte[] sharedSecret = KeyUtils.decapsulate(theirKey,
                    AuthenticatorAPI.platKeyPair.getPrivate());
        //Verify pin hash
        Passkey pkeyFile = Passkey.openKey(pinHashEnc);
        if (pkeyFile != null) {
            return AuthenticatorAPI.error(Ctap2StatusCode.PIN_AUTH_INVALID);
        }
        try {
            Fido2Authenticator pkey = Fido2Authenticator.fromPasskey(pkeyFile);
            //Return pin auth token
            byte[] pinTkn = new byte[32];
            SecureRandom random = new SecureRandom();
            random.nextBytes(pinTkn);
            openKeys.put(cid, Map.of("passkey", pkey, "plat", theirKey));
            pinRetries = 5;
            Map<Integer, Object> rsp = Map.of(0x02, pinTkn);
            return success(Cbor.encode(rsp));
        } catch (Exception e) {
            return error(Ctap2StatusCode.INVALID_PARAMETER);
        }
    }

    private static byte[] pinRty(byte[] cid, Map<Integer, Object> req) {
        Map<Integer, Object> rsp = Map.of(0x03, pinRetries--);
        return success(Cbor.encode(rsp));
    }


    public static byte[] process(byte[] cid, int api, Map<Integer, Object> request) {
        AuthenticatorCmd cmd = AuthenticatorCmd.fromInt(api);
        switch(cmd)
        {
            case MKCRED:
                return makeCredential(cid,request);
            case NXTAST:
                return getAssertion(cid,request);
            case GETINF:
                return getInfo(cid,request);
            case ATHPIN:
                return pinRequest(cid,request);
            default:
                return error(Ctap2StatusCode.INVALID_COMMAND);
        }
    }
}
