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

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;
import java.security.KeyFactory;

public class KeyUtils {
    
    private KeyUtils() { }

    
    public static KeyPair getKeyPair(String alg) {
        try {
            if (alg == "RSA") {
                return getRSAKeyPair();
            }
            else if (alg == "EC") {
                return getECKeyPair();
            }
            else if (alg == "E25519") {
                return getE25519KeyPair();
            }
        } catch (Exception e) {
            //logging.error("Error generating key pair: " + e.getMessage());
        }
        return null;
    }

    public static Map<Integer, Object> toCoseKey(PublicKey pubkey) {
        return null;
    }

    public static PublicKey fromCoseKey(Map<Integer, Object> coseKey) {
        return null;
    }

    public static byte[] decapsulate(PublicKey theirKey, PrivateKey myKey) {
        return null;
    }

    public static PublicKey readPublic(String fileName, String alg)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] rawKey = FileUtils.readPEMFile(fileName);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(rawKey);
        KeyFactory kf = KeyFactory.getInstance(alg);
        return kf.generatePublic(spec);
    }

    public static PrivateKey readPrivate(String fileName, String alg)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] rawKey = FileUtils.readPEMFile(fileName);
        KeyFactory kf = KeyFactory.getInstance(alg);
        PrivateKey pk = (PrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(rawKey));
        return pk;
    }

    public static PrivateKey readPrivate(byte[] raw, String alg)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory kf = KeyFactory.getInstance(alg);
        PrivateKey pk = (PrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(raw));
        return pk;
    }

    private static class FieldP {
        final static BigInteger _2 = BigInteger.valueOf(2);
        final static BigInteger _3 = BigInteger.valueOf(3);
    }

    private static ECPoint doublePoint(final BigInteger p, final BigInteger a,
            final ECPoint R) {
        if (R.equals(ECPoint.POINT_INFINITY)) {
            return R;
        }
        BigInteger slope = (R.getAffineX().pow(2)).multiply(FieldP._3);
        slope = slope.add(a);
        slope = slope.multiply((R.getAffineY().multiply(FieldP._2)).modInverse(p));
        final BigInteger Xout = slope.pow(2).subtract(R.getAffineX().multiply(FieldP._2))
                .mod(p);
        final BigInteger Yout = (R.getAffineY().negate())
                .add(slope.multiply(R.getAffineX().subtract(Xout))).mod(p);
        return new ECPoint(Xout, Yout);
    }

    private static ECPoint addPoint(final BigInteger p, final BigInteger a, final ECPoint r,
            final ECPoint g) {
        if (r.equals(ECPoint.POINT_INFINITY)) {
            return g;
        }
        if (g.equals(ECPoint.POINT_INFINITY)) {
            return r;
        }
        if (r == g || r.equals(g)) {
            return doublePoint(p, a, r);
        }
        final BigInteger gX = g.getAffineX();
        final BigInteger sY = g.getAffineY();
        final BigInteger rX = r.getAffineX();
        final BigInteger rY = r.getAffineY();
        final BigInteger slope = (rY.subtract(sY)).multiply(rX.subtract(gX).modInverse(p))
                .mod(p);
        final BigInteger Xout = (slope.modPow(FieldP._2, p).subtract(rX)).subtract(gX).mod(p);
        BigInteger Yout = sY.negate().mod(p);
        Yout = Yout.add(slope.multiply(gX.subtract(Xout))).mod(p);
        return new ECPoint(Xout, Yout);
    }

    public static ECPoint scalmult(final EllipticCurve curve, final ECPoint g,
            final BigInteger kin) {
        final ECField field = curve.getField();
        if (!(field instanceof ECFieldFp)) {
            throw new UnsupportedOperationException(field.getClass().getCanonicalName());
        }
        final BigInteger p = ((ECFieldFp) field).getP();
        final BigInteger a = curve.getA();
        ECPoint R = ECPoint.POINT_INFINITY;
        BigInteger k = kin.mod(p);
        final int length = k.bitLength();
        final byte[] binarray = new byte[length];
        for (int i = 0; i <= length - 1; i++) {
            binarray[i] = k.mod(FieldP._2).byteValue();
            k = k.shiftRight(1);
        }
        for (int i = length - 1; i >= 0; i--) {
            R = doublePoint(p, a, R);
            if (binarray[i] == 1) {
                R = addPoint(p, a, R, g);
            }
        }
        return R;
    }

    public static ECPublicKey getPubKey(final ECPrivateKey pk)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        ECParameterSpec spec = pk.getParams();
        ECPoint w = scalmult(spec.getCurve(), pk.getParams().getGenerator(), pk.getS());
        KeyFactory kf = KeyFactory.getInstance("EC");
        return (ECPublicKey) kf.generatePublic(new ECPublicKeySpec(w, spec));
    }

    public static RSAPublicKey getPubKey(final RSAPrivateCrtKey pk)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        RSAPublicKeySpec spec = new RSAPublicKeySpec(pk.getModulus(), pk.getPublicExponent());
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) kf.generatePublic(spec);
    }

    public static KeyPair generateKeyPair(String alg, int keySize)
            throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg);
        kpg.initialize(keySize);
        return kpg.genKeyPair();
    }

    public static KeyPair getCAKeyPair(String alg) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        PrivateKey privateKey = null;
        PublicKey publicKey = null;
        if (alg == "EC") {
            privateKey = generatePrivate(alg, 256);
            publicKey = getPubKey((ECPrivateKey) privateKey);
        }
        else if (alg == "RSA") {
            privateKey = generatePrivate(alg, 2048);
            publicKey =  getPubKey((RSAPrivateCrtKey) privateKey);
        }
        else {
            throw new NoSuchAlgorithmException(String.format("Invalid alg:  %s", alg));
        }
        return new KeyPair(publicKey, privateKey);      
    }
    
    public static PrivateKey generatePrivate(String alg, int keySize)
            throws NoSuchAlgorithmException {
        return generateKeyPair(alg, keySize).getPrivate();
    }
    
    
    private static KeyPair getRSAKeyPair() throws Exception {
        return generateKeyPair("RSA", 2048);
    }
    
    
    private static KeyPair getECKeyPair() throws Exception {
        return generateKeyPair("EC", 521);
    }
    
    
    private static KeyPair getE25519KeyPair() throws Exception {
        return generateKeyPair("E25519", 512);
    }
}
