/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.mdl;

import com.isfs.blekey.util.Cbor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

/**
 * Integration tests for {@link DeviceEngagement} and {@link SessionTranscript} working together.
 */
class DeviceEngagementIntegrationTest {

    private KeyPair deviceKeyPair;
    private KeyPair readerKeyPair;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        deviceKeyPair = keyGen.generateKeyPair();
        readerKeyPair = keyGen.generateKeyPair();
    }

    // -------------------------------------------------------------------------
    // End-to-end QR code flow
    // -------------------------------------------------------------------------

    @Test
    void testEndToEndQrCodeFlow() throws Exception {
        // 1. Device creates engagement
        DeviceEngagement de = DeviceEngagement.create(deviceKeyPair.getPublic());

        // 2. Emit as QR payload
        String qrPayload = de.toQrCodePayload();
        assertTrue(qrPayload.startsWith("mdoc:"));

        // 3. Reader parses QR payload
        DeviceEngagement parsedDe = DeviceEngagement.fromQrCodePayload(qrPayload);
        assertEquals(de.getVersion(), parsedDe.getVersion());
        assertEquals(de.getCipherSuite(), parsedDe.getCipherSuite());

        // 4. Create session transcript using device engagement bytes and reader key bytes
        byte[] deBytes = parsedDe.toCbor();
        byte[] readerKeyBytes = Cbor.encode(
                com.isfs.blekey.util.KeyUtils.toCoseKey(readerKeyPair.getPublic()));

        SessionTranscript sessionTranscript = SessionTranscript.create(deBytes, readerKeyBytes);
        assertNotNull(sessionTranscript);
        assertArrayEquals(deBytes, sessionTranscript.getDeviceEngagementBytes());
    }

    @Test
    void testMultipleDeviceEngagements() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);

        for (int i = 0; i < 3; i++) {
            KeyPair kp = keyGen.generateKeyPair();
            DeviceEngagement de = DeviceEngagement.create(kp.getPublic());
            String qr = de.toQrCodePayload();
            DeviceEngagement decoded = DeviceEngagement.fromQrCodePayload(qr);
            assertEquals("1.0", decoded.getVersion());
            assertEquals(1, decoded.getCipherSuite());
            assertNotNull(decoded.getDevicePublicKey());
        }
    }

    @Test
    void testSessionTranscriptWithRealDeviceEngagement() throws Exception {
        DeviceEngagement de = DeviceEngagement.create(deviceKeyPair.getPublic());
        byte[] deBytes = de.toCbor();

        byte[] readerKeyBytes = Cbor.encode(
                com.isfs.blekey.util.KeyUtils.toCoseKey(readerKeyPair.getPublic()));
        byte[] handoverBytes = new byte[]{0x10, 0x20, 0x30};

        SessionTranscript st = new SessionTranscript(deBytes, readerKeyBytes, handoverBytes);

        // Round-trip through CBOR
        byte[] stCbor = st.toCbor();
        SessionTranscript decoded = SessionTranscript.fromCbor(stCbor);

        assertArrayEquals(st.getDeviceEngagementBytes(), decoded.getDeviceEngagementBytes());
        assertArrayEquals(st.getEReaderKeyBytes(), decoded.getEReaderKeyBytes());
        assertArrayEquals(st.getHandover(), decoded.getHandover());
    }

    @Test
    void testCborCompatibility() throws Exception {
        // Verify the encoded CBOR map from DeviceEngagement contains expected ISO 18013-5 keys
        DeviceEngagement de = new DeviceEngagement("1.0", deviceKeyPair.getPublic(), 1);
        byte[] cbor = de.toCbor();

        Object obj = Cbor.decode(cbor);
        assertTrue(obj instanceof java.util.Map);
        @SuppressWarnings("unchecked")
        java.util.Map<String, Object> map = (java.util.Map<String, Object>) obj;

        assertTrue(map.containsKey("version"));
        assertTrue(map.containsKey("security"));
        assertTrue(map.containsKey("deviceRetrievalMethods"));

        @SuppressWarnings("unchecked")
        java.util.Map<Integer, Object> security = (java.util.Map<Integer, Object>) map.get("security");
        assertTrue(security.containsKey(1)); // cipher suite
        assertTrue(security.containsKey(2)); // COSE_Key bytes
    }

    @Test
    void testKeyUtilsIntegration() throws Exception {
        // Test with a P-256 key (only curve supported by KeyUtils.toCoseKey for EC)
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        KeyPair kp = keyGen.generateKeyPair();

        DeviceEngagement de = DeviceEngagement.create(kp.getPublic());
        byte[] cbor = de.toCbor();
        DeviceEngagement decoded = DeviceEngagement.fromCbor(cbor);

        assertNotNull(decoded.getDevicePublicKey());
        assertEquals("EC", decoded.getDevicePublicKey().getAlgorithm());
    }
}
