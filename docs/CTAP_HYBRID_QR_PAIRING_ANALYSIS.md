# CTAP Hybrid Transport QR Code Pairing Analysis

## Executive Summary

This document analyzes the QR Code pairing mechanism in CTAP 2.3's Hybrid Transport (Section 11.5) and evaluates whether it can be leveraged to establish true BLE pairing instead of the tunnel service approach.

**Key Finding**: The QR Code pairing mechanism **CANNOT directly replace true BLE pairing**, but it **CAN be adapted** to establish a secure local BLE connection without the tunnel service. However, this requires significant modifications to the spec's intended architecture.

---

## 1. Understanding Hybrid Transport Architecture

### 1.1 What is Hybrid Transport?

From CTAP 2.3 §11.5:

> "Hybrid transports decouple the proof that the client platform is physically close to the authenticator or credential manager hosting device (CMHD), from the transport of messages (CTAP2, JSON etc.) between them."

**Key Components**:
1. **Proximity Proof**: BLE advertisements prove physical proximity
2. **Data Transfer Channel**: Either:
   - **Tunnel Service** (network-based, via internet)
   - **Local Communication** (BLE, UWB, etc.)

### 1.2 Current "Hacked" Tunnel Service

The spec's default approach uses a **tunnel service** - a cloud-based relay:

```
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│   Client     │         │   Tunnel     │         │Authenticator │
│  (Browser)   │◄───────►│   Server     │◄───────►│   (Phone)    │
└──────────────┘         └──────────────┘         └──────────────┘
      │                                                    │
      └────────────── BLE (proximity only) ───────────────┘
```

**Why "Hacked"?**
- BLE is only used for **advertising** (proximity proof)
- Actual CTAP messages go through **internet** via tunnel server
- Requires network connectivity on both sides
- Adds latency and complexity
- Privacy concerns (messages route through third party)

---

## 2. QR Code Pairing Mechanism

### 2.1 QR Code Contents

The QR code encodes a CBOR map with these keys:

```go
// From CTAP 2.3 spec example code
func encodeQRContents(compressedPublicKey *[33]byte, qrSecret *[16]byte) string {
    cbor := map[int]interface{}{
        0: compressedPublicKey,  // 33-byte P-256 public key (compressed)
        1: qrSecret,              // 16-byte random secret
        2: numTunnelDomains,      // Number of known tunnel servers
        3: timestamp,             // Current Unix timestamp
        4: true,                  // Flag (purpose unclear)
        5: "mc",                  // Mode/capability indicator
        6: [2]int{0, 1},         // Supported protocol versions
    }
    return "FIDO:/" + digitEncode(cbor)
}
```

**Critical Elements**:
- **Key 0**: Authenticator's ephemeral ECDH public key (P-256)
- **Key 1**: 16-byte shared secret (`qrSecret`)
- **Key 2**: Tunnel server domain count (for tunnel service routing)

### 2.2 Cryptographic Handshake

After scanning the QR code, the client performs a **Noise NKpsk0** handshake:

```go
func doQRHandshake(socketConn *socket.Conn, advertPlaintext [16]byte) {
    // Derive PSK from QR secret and BLE advertisement data
    var psk [32]byte
    derive(psk[:], qrSecret[:], advertPlaintext[:], keyPurposePSK)
    
    // Perform Noise handshake with PSK and identity keys
    conn, handshakeHash := doHandshake(socketConn, psk, identityKey, nil)
    
    // Read post-handshake message
    readPostHandshakeMessage(conn, handshakeHash)
}
```

**Handshake Flow**:
1. **PSK Derivation**: Combine `qrSecret` (from QR) + `advertPlaintext` (from BLE) → PSK
2. **Noise NKpsk0**: Authenticated key exchange using:
   - PSK (pre-shared key from step 1)
   - Authenticator's identity key (from QR code)
   - Client's ephemeral key (generated)
3. **Result**: Encrypted channel with mutual authentication

### 2.3 Security Properties

The QR pairing provides:

✅ **Authentication**: Client knows it's talking to the device that showed the QR code  
✅ **Confidentiality**: Noise protocol provides encryption  
✅ **Forward Secrecy**: Ephemeral keys used in handshake  
✅ **Proximity Proof**: BLE advertisement data mixed into PSK  
✅ **Replay Protection**: Timestamp in QR code (key 3)

---

## 3. Can QR Pairing Replace True BLE Pairing?

### 3.1 What is "True BLE Pairing"?

Standard Bluetooth LE pairing (per CTAP 2.3 §11.4.2):

```
┌──────────────┐                    ┌──────────────┐
│   Client     │                    │Authenticator │
│  (Computer)  │                    │   (Phone)    │
└──────────────┘                    └──────────────┘
       │                                    │
       │  1. BLE Connection                 │
       ├───────────────────────────────────►│
       │                                    │
       │  2. LE Secure Connections Pairing  │
       │     (Just Works or Numeric Compare)│
       │◄──────────────────────────────────►│
       │                                    │
       │  3. LTK (Long Term Key) Created    │
       │     - Stored in both devices       │
       │     - Used for future connections  │
       │                                    │
       │  4. Encrypted GATT Communication   │
       │     (LE Security Mode 1, Level 3+) │
       │◄──────────────────────────────────►│
```

**Key Properties**:
- Creates **Long Term Key (LTK)** stored in OS
- Devices are "bonded" - automatic reconnection
- OS-level security enforcement
- Works with standard BLE stack

### 3.2 Comparison: QR Pairing vs True BLE Pairing

| Aspect | QR Code Pairing | True BLE Pairing |
|--------|-----------------|------------------|
| **Key Storage** | Application-level (ephemeral) | OS-level (persistent LTK) |
| **Reconnection** | Requires new handshake | Automatic (bonded devices) |
| **OS Integration** | None (app handles crypto) | Full (OS enforces security) |
| **User Experience** | Scan QR each time | Pair once, use forever |
| **Security Level** | Application-layer encryption | Link-layer encryption + app |
| **Standard Compliance** | FIDO-specific | Bluetooth SIG standard |
| **Browser Support** | Requires custom implementation | Native WebBluetooth API |

### 3.3 The Fundamental Problem

**QR pairing is NOT a replacement for BLE pairing because:**

1. **Different Security Layers**:
   - QR pairing: Application-layer security (Noise protocol over GATT)
   - BLE pairing: Link-layer security (LE Secure Connections)

2. **No LTK Creation**:
   - QR handshake creates session keys, not persistent LTK
   - OS doesn't know devices are "paired"
   - No automatic reconnection

3. **Tunnel Service Dependency**:
   - QR code includes tunnel server info (key 2)
   - Spec assumes data goes through tunnel, not local BLE
   - BLE is only for proximity proof

---

## 4. Can We Adapt QR Pairing for Local BLE?

### 4.1 YES - With Modifications

**The QR pairing mechanism CAN be adapted** to establish a secure local BLE connection without the tunnel service. Here's how:

#### Modified Architecture

```
┌──────────────┐                    ┌──────────────┐
│   Client     │                    │Authenticator │
│  (Browser)   │                    │   (Phone)    │
└──────────────┘                    └──────────────┘
       │                                    │
       │  1. Scan QR Code                   │
       │     - Get public key               │
       │     - Get qrSecret                 │
       │◄───────────────────────────────────┤
       │                                    │
       │  2. BLE Connection                 │
       ├───────────────────────────────────►│
       │                                    │
       │  3. Read BLE Advertisement Data    │
       │     (advertPlaintext)              │
       │◄───────────────────────────────────┤
       │                                    │
       │  4. Derive PSK                     │
       │     psk = HKDF(qrSecret,           │
       │               advertPlaintext)     │
       │                                    │
       │  5. Noise NKpsk0 Handshake         │
       │     over GATT characteristics      │
       │◄──────────────────────────────────►│
       │                                    │
       │  6. Encrypted CTAP over BLE        │
       │     (using Noise session keys)     │
       │◄──────────────────────────────────►│
```

#### Key Changes from Spec

1. **Remove Tunnel Service**:
   - Don't use key 2 (tunnel domain count)
   - Don't establish WebSocket connection
   - Use BLE GATT for all data transfer

2. **Use FIDO GATT Service (0xFFFD)**:
   - Perform Noise handshake over `fidoControlPoint` characteristic
   - Send encrypted CTAP messages over same characteristic
   - Use `fidoStatus` for responses

3. **Session Management**:
   - Store Noise session keys in application
   - Require QR scan for each session (or implement key persistence)

### 4.2 Implementation Approach

#### Step 1: QR Code Generation (Authenticator)

```java
public class HybridQRPairing {
    private ECPublicKey identityPublicKey;
    private byte[] qrSecret;
    
    public String generateQRCode() {
        // Generate ephemeral identity key
        KeyPair identityKey = generateP256KeyPair();
        this.identityPublicKey = (ECPublicKey) identityKey.getPublic();
        
        // Generate random secret
        this.qrSecret = new byte[16];
        new SecureRandom().nextBytes(qrSecret);
        
        // Encode QR contents (simplified - no tunnel server)
        Map<Integer, Object> qrData = new HashMap<>();
        qrData.put(0, compressPublicKey(identityPublicKey)); // 33 bytes
        qrData.put(1, qrSecret);                             // 16 bytes
        qrData.put(3, System.currentTimeMillis() / 1000);    // timestamp
        qrData.put(5, "mc");                                 // mode
        qrData.put(6, new int[]{0, 1});                      // versions
        
        byte[] cborData = encodeCBOR(qrData);
        return "FIDO:/" + digitEncode(cborData);
    }
}
```

#### Step 2: BLE Advertisement (Authenticator)

```java
public void startHybridAdvertising() {
    // Generate random advertisement data (changes periodically)
    byte[] advertPlaintext = new byte[16];
    new SecureRandom().nextBytes(advertPlaintext);
    
    // Advertise with FIDO service UUID
    AdvertiseData advertiseData = new AdvertiseData.Builder()
        .addServiceUuid(ParcelUuid.fromString("0000FFFD-..."))
        .addServiceData(
            ParcelUuid.fromString("0000FFFD-..."),
            advertPlaintext  // Include in advertisement
        )
        .build();
    
    bleAdvertiser.startAdvertising(settings, advertiseData, callback);
}
```

#### Step 3: Client Handshake (Browser/Client)

```javascript
// After scanning QR code
async function connectToAuthenticator(qrData) {
    // Extract from QR
    const identityPublicKey = qrData[0];  // 33 bytes
    const qrSecret = qrData[1];            // 16 bytes
    
    // Connect to BLE device
    const device = await navigator.bluetooth.requestDevice({
        filters: [{ services: ['0000fffd-0000-1000-8000-00805f9b34fb'] }]
    });
    const server = await device.gatt.connect();
    const service = await server.getPrimaryService('0000fffd-...');
    
    // Read advertisement data from service
    const advertChar = await service.getCharacteristic('...');
    const advertData = await advertChar.readValue();
    const advertPlaintext = new Uint8Array(advertData.buffer);
    
    // Derive PSK
    const psk = await derivePSK(qrSecret, advertPlaintext);
    
    // Perform Noise NKpsk0 handshake
    const noiseSession = await performNoiseHandshake(
        service,
        psk,
        identityPublicKey
    );
    
    // Now use noiseSession for encrypted CTAP communication
    return new SecureCTAPChannel(service, noiseSession);
}
```

#### Step 4: Encrypted CTAP Communication

```java
public class SecureBLEChannel {
    private NoiseSession noiseSession;
    private BluetoothGattCharacteristic controlPoint;
    
    public byte[] sendCTAPRequest(byte[] ctapRequest) {
        // Encrypt with Noise session keys
        byte[] encrypted = noiseSession.encrypt(ctapRequest);
        
        // Send over BLE GATT
        controlPoint.setValue(encrypted);
        gatt.writeCharacteristic(controlPoint);
        
        // Wait for encrypted response
        byte[] encryptedResponse = waitForNotification();
        
        // Decrypt with Noise session keys
        return noiseSession.decrypt(encryptedResponse);
    }
}
```

### 4.3 Advantages of This Approach

✅ **No Tunnel Service**: All communication stays local over BLE  
✅ **Strong Security**: Noise protocol provides authenticated encryption  
✅ **QR Code UX**: Simple pairing - just scan QR code  
✅ **Proximity Proof**: BLE advertisement data ensures physical proximity  
✅ **No Internet Required**: Works offline  
✅ **Privacy**: No third-party servers involved

### 4.4 Disadvantages vs True BLE Pairing

❌ **Not OS-Level Pairing**: Doesn't create LTK, no bonding  
❌ **No Auto-Reconnect**: Must scan QR for each session (unless you persist keys)  
❌ **Application-Layer Only**: No link-layer encryption (though Noise provides app-layer)  
❌ **Non-Standard**: Deviates from CTAP spec's intended tunnel service approach  
❌ **Browser Support**: Requires custom WebBluetooth implementation

---

## 5. Hybrid Approach: QR + True BLE Pairing

### 5.1 CRITICAL LIMITATION: Who Can Initiate Pairing?

**⚠️ IMPORTANT**: The **peripheral (GATT server) CANNOT initiate BLE pairing**. Only the **central (client) can initiate pairing**.

In your architecture:
- **Authenticator (Phone)** = Peripheral/GATT Server ❌ Cannot call `createBond()`
- **Client (Computer/Browser)** = Central/GATT Client ✅ Can initiate pairing

**Why This Matters**:
- Your Android app (peripheral) **cannot programmatically trigger** OS-level BLE pairing
- The client (browser/computer) **must initiate** the pairing process
- Your Android app can only **respond** to pairing requests initiated by the client

### 5.2 Corrected Approach: Trigger Pairing from Client

You can **combine** QR pairing with true BLE pairing, but the client must initiate:

```
Session 1 (Initial):
1. User scans QR code on authenticator (phone)
2. Client (browser) connects to authenticator via BLE
3. Perform Noise handshake over BLE GATT
4. Client initiates OS-level BLE pairing (NOT authenticator!)
5. Authenticator responds to pairing request
6. Store Noise session keys + LTK (on both sides)

Session 2+ (Subsequent):
1. BLE auto-reconnects (using LTK)
2. Reuse stored Noise session keys OR perform new handshake
3. No QR scan needed
```

#### Implementation (Corrected)

**On Authenticator (Peripheral/Server) - Cannot Initiate Pairing**:

```java
public class HybridPairingManager {
    private BluetoothGattServerCallback gattCallback = new BluetoothGattServerCallback() {
        @Override
        public void onConnectionStateChange(BluetoothDevice device, int status, int newState) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                // Check if device is already bonded
                if (device.getBondState() == BluetoothDevice.BOND_BONDED) {
                    Log.d(TAG, "Device already bonded");
                } else {
                    // CANNOT initiate pairing from peripheral!
                    // Must wait for client to initiate
                    Log.d(TAG, "Waiting for client to initiate pairing...");
                }
            }
        }
        
        @Override
        public void onCharacteristicReadRequest(BluetoothDevice device, int requestId,
                                                int offset, BluetoothGattCharacteristic characteristic) {
            // If characteristic requires encryption and device not bonded,
            // Android will automatically trigger pairing dialog on CLIENT side
            if (requiresEncryption(characteristic) &&
                device.getBondState() != BluetoothDevice.BOND_BONDED) {
                // Return error - this will trigger pairing on client
                gattServer.sendResponse(device, requestId,
                    BluetoothGatt.GATT_INSUFFICIENT_AUTHENTICATION, offset, null);
                return;
            }
            
            // Handle normal read
            handleCharacteristicRead(device, requestId, offset, characteristic);
        }
    };
    
    public void setupSecureCharacteristic() {
        // Set characteristic to require encryption
        // This will trigger pairing when client tries to access it
        BluetoothGattCharacteristic characteristic = new BluetoothGattCharacteristic(
            FIDO_CONTROL_POINT_UUID,
            BluetoothGattCharacteristic.PROPERTY_WRITE |
            BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_WRITE_ENCRYPTED |  // Requires pairing!
            BluetoothGattCharacteristic.PERMISSION_READ_ENCRYPTED
        );
    }
}
```

**On Client (Central) - Can Initiate Pairing**:

```javascript
// Client side (browser/computer) - CAN initiate pairing
async function connectAndPair(qrData) {
    // Connect to device
    const device = await navigator.bluetooth.requestDevice({
        filters: [{ services: ['0000fffd-0000-1000-8000-00805f9b34fb'] }]
    });
    const server = await device.gatt.connect();
    
    // Try to access encrypted characteristic
    // This will trigger pairing if not already paired
    const service = await server.getPrimaryService('0000fffd-...');
    const characteristic = await service.getCharacteristic('...');
    
    try {
        // Attempting to read/write encrypted characteristic
        // will trigger OS-level pairing dialog
        await characteristic.readValue();
    } catch (error) {
        if (error.name === 'SecurityError') {
            // Pairing required - OS will show pairing dialog
            console.log('Pairing initiated by OS');
            // User must accept pairing on both devices
        }
    }
    
    // After pairing, perform Noise handshake
    const noiseSession = await performNoiseHandshake(service, qrData);
    return new SecureCTAPChannel(service, noiseSession);
}
```

**Alternative: Automatic Pairing Trigger**:

```java
public class HybridPairingManager {
    // Peripheral can trigger pairing indirectly by requiring encrypted access
    public void performInitialPairing(QRData qrData, BluetoothDevice device) {
        // 1. Perform Noise handshake (from QR)
        NoiseSession session = performNoiseHandshake(qrData);
        
        // 2. CANNOT call device.createBond() from peripheral!
        // Instead, set up encrypted characteristics that will
        // trigger pairing when client tries to access them
        
        // 3. Store Noise session
        storeNoiseSession(device.getAddress(), session);
        // LTK will be stored automatically by OS when client initiates pairing
    }
    
    public SecureBLEChannel reconnect(BluetoothDevice device) {
        // Device already bonded (LTK exists)
        if (device.getBondState() == BluetoothDevice.BOND_BONDED) {
            // Try to reuse stored Noise session
            NoiseSession session = loadNoiseSession(device.getAddress());
            if (session != null && !session.isExpired()) {
                return new SecureBLEChannel(device, session);
            }
            
            // Session expired - perform new handshake (no QR needed)
            // Use stored identity keys
            return performRehandshake(device);
        }
        
        throw new NotPairedException("Device not paired");
    }
}
```

### 5.2 Advantages of Hybrid Approach

✅ **Initial Security**: QR provides strong initial authentication  
✅ **Persistent Pairing**: OS-level LTK enables auto-reconnect  
✅ **Best UX**: Scan QR once, use forever  
✅ **Layered Security**: Both link-layer (BLE) and app-layer (Noise) encryption  
✅ **Standard Compliance**: Uses standard BLE pairing + FIDO security

---

## 6. Comparison with Spec's Tunnel Service

### 6.1 Why Spec Uses Tunnel Service

The CTAP spec's hybrid transport uses tunnel service because:

1. **Cross-Platform**: Works even when client and authenticator are on different networks
2. **Firewall Traversal**: No NAT/firewall issues
3. **Reliability**: Internet more reliable than local BLE in some environments
4. **Range**: Not limited by BLE range (10-100m)

### 6.2 Why Local BLE is Better (For Your Use Case)

For a local authenticator (phone as FIDO key):

✅ **Privacy**: No data leaves local network  
✅ **Latency**: Direct BLE faster than internet round-trip  
✅ **Offline**: Works without internet  
✅ **Simplicity**: No tunnel server infrastructure  
✅ **Cost**: No server hosting costs

---

## 7. Recommendations

### 7.1 For Your Implementation

**Recommended Approach**: **Hybrid QR + True BLE Pairing**

1. **Phase 1**: Implement standard BLE FIDO (§11.4)
   - Use true BLE pairing (LE Secure Connections)
   - Standard GATT service (0xFFFD)
   - Works with Chrome/Edge

2. **Phase 2**: Add QR-based initial pairing (optional enhancement)
   - Generate QR code on authenticator
   - Client scans QR, performs Noise handshake
   - Client triggers OS-level BLE pairing (via encrypted characteristic access)
   - Store session keys for future use

3. **Phase 3**: Implement local BLE data channel (optional)
   - Use Noise-encrypted CTAP over BLE GATT
   - Skip tunnel service entirely
   - Fallback to standard BLE FIDO if Noise fails

### 7.2 Implementation Priority

**High Priority** (Do First):
- ✅ Standard BLE FIDO (§11.4) - works with browsers
- ✅ True BLE pairing (LE Secure Connections)
- ✅ GATT service (0xFFFD) with standard characteristics

**Medium Priority** (Nice to Have):
- 🔶 QR code generation for easy pairing
- 🔶 Noise protocol implementation
- 🔶 Local BLE data channel (skip tunnel)

**Low Priority** (Future Enhancement):
- 🔽 Full hybrid transport with tunnel service
- 🔽 caBLE protocol support

### 7.3 Code Structure

```
com.isfs.blekey.hybrid/
├── HybridQRPairing.java         // QR code generation
├── NoiseProtocol.java           // Noise NKpsk0 implementation
├── HybridBLEChannel.java        // Encrypted BLE communication
├── HybridPairingManager.java    // Combines QR + BLE pairing
└── HybridAdvertiser.java        // BLE advertising with QR data
```

---

## 8. Conclusion

### 8.1 Direct Answer to Your Question

> "Is there any way to leverage this pairing to establish a true BLE pairing instead of the hacked tunnel service?"

**Answer**: 

**YES and NO**:

- ❌ **NO**: QR pairing cannot **directly replace** true BLE pairing (different security layers)
- ✅ **YES**: QR pairing **CAN be adapted** to establish secure local BLE communication without tunnel service
- ✅ **BEST**: QR pairing **CAN be combined** with true BLE pairing for optimal security and UX

### 8.2 The "Hacked" Tunnel Service

The tunnel service is "hacked" in the sense that:
- BLE is underutilized (only for proximity proof)
- Adds unnecessary internet dependency
- Introduces latency and privacy concerns

**But it's not technically "hacked"** - it's a deliberate design choice for:
- Cross-network operation
- Firewall traversal
- Reliability in poor BLE environments

### 8.3 Your Best Path Forward

1. **Implement standard BLE FIDO first** (§11.4)
   - True BLE pairing with LTK
   - Standard GATT service
   - Works with Chrome/Edge

2. **Add QR-based enhancement** (optional)
   - Easier initial pairing
   - Stronger authentication
   - Can skip tunnel service

3. **Use local BLE for data** (instead of tunnel)
   - Encrypt with Noise protocol
   - Keep all data local
   - Better privacy and latency

This gives you the best of both worlds: standard compliance + enhanced security + local operation.

---

**Document Version**: 1.0  
**Date**: 2026-03-11  
**Status**: Analysis Complete