package com.isfs.blekey.data;

import java.io.File;
import java.io.FileInputStream;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.isfs.blekey.util.FileUtils;


public class Passkey {

    private PrivateKey pk;
    private X509Certificate ca;
    private List<Map<byte[], Object>> resCreds;
    private byte[] seed;

    private static final Logger logger = LoggerFactory.getLogger(Passkey.class);

    Passkey(PrivateKey key, X509Certificate cert, byte[] seed, List<Map<byte[], Object>> creds) {
        this.pk = key;
        this.ca = cert;
        this.resCreds = creds;
        this.seed = seed;
    }

    public PrivateKey getPrivateKey() {
        return pk;
    }

    public X509Certificate getCertificate() {
        return ca;
    }

    public byte[] getSeed() {
        return seed;
    }

    public void addResCred(byte[] rpId, byte[] credId, byte[] userHandle) {
        Map<String, Object> cred = Map.of("credId", credId, "userHandle", userHandle);
        resCreds.add(Map.of(rpId, cred));
    }

    public static void writeKey(Passkey key) {
        return;
    }

    public static Passkey openKey(byte[] pinHash) {

        for(File maybePasskey: FileUtils.listPasskeys()) {
            try {
                Passkey passkey = decryptKey(maybePasskey, pinHash);
                if (passkey != null) {
                    return passkey;
                }
            } catch (Exception e) {
                logger.error("Error decrypting key", e);
            }
        }
        return null;
    }
    
    private static Passkey decryptKey(File maybePasskey, byte[] pinHash) throws Exception {
        FileInputStream fis = new FileInputStream(maybePasskey);
        byte[] data = fis.readAllBytes();
        fis.close();
        byte[] iv = new byte[16];
        byte[] tag = new byte[16];
        System.arraycopy(data, 0, iv, 0, 16);
        System.arraycopy(data, 16, tag, 0, 16);
        //TODO
        return null;
    }
}
