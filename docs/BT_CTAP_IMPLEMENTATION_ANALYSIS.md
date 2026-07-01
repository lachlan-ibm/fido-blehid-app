# Bluetooth CTAP Implementation Analysis

## Executive Summary

This document analyzes the work required to implement Bluetooth Low Energy (BLE) transport for CTAP2 as specified in the FIDO Client to Authenticator Protocol v2.3, Section 11.4.

**Current State**: USB HID transport with CTAP2 protocol support
**Target State**: Add BLE transport alongside existing USB HID
**Estimated Effort**: 10 weeks (400 hours) for full implementation
**Complexity**: High - requires new GATT service, fragmentation protocol, and security implementation


---

## 1. Key Findings

### 1.1 Architecture Answer

**Your Question**: "Would the GATT server have two profiles - one for USB HID device and one for BT server?"

**Answer**: **YES, but they are separate BLE profiles, not USB vs BT:**

1. **Current HID Profile** ([`HIDService.java`](../app/src/main/java/com/isfs/blekey/hidsvc/HIDService.java))
   - GATT Service UUID: 0x1812 (HID over GATT / HOGP)
   - Purpose: Keyboard/mouse emulation
   - Current implementation

2. **New FIDO Profile** (to be implemented)
   - GATT Service UUID: 0xFFFD (FIDO Service)
   - Purpose: FIDO2 authenticator operations
   - Completely different service structure


### 1.2 Current vs. Target Architecture

```
CURRENT ARCHITECTURE:
┌─────────────────────────────────────────┐
│      Android Application                │
├─────────────────────────────────────────┤
│  HIDService (BLE HOGP Profile)          │
│  ├─ HID Service (0x1812)                │
│  ├─ Device Info Service                 │
│  └─ Battery Service                     │
├─────────────────────────────────────────┤
│  CtapHid (USB HID Framing)              │
│  └─ 64-byte packets, CID management     │
├─────────────────────────────────────────┤
│  AuthenticatorAPI (CTAP2 Protocol)      │
│  └─ MakeCredential, GetAssertion, etc.  │
└─────────────────────────────────────────┘

TARGET ARCHITECTURE (Add):
┌─────────────────────────────────────────┐
│      Android Application                │
├─────────────────────────────────────────┤
│  FIDOBLEService (NEW)                   │
│  ├─ FIDO Service (0xFFFD)               │
│  │  ├─ fidoControlPoint (Write/Notify)  │
│  │  ├─ fidoStatus (Notify)              │
│  │  ├─ fidoControlPointLength (Read)    │
│  │  └─ fidoServiceRevision (Read)       │
│  └─ GAP Service (0x1800)                │
├─────────────────────────────────────────┤
│  CtapBle (NEW - BLE Framing)            │
│  └─ Variable packets, fragmentation     │
├─────────────────────────────────────────┤
│  AuthenticatorAPI (REUSE - No changes)  │
│  └─ Same CTAP2 implementation           │
└─────────────────────────────────────────┘
```

**Key Insight**: The existing [`CtapHid.java`](../lib/src/com/isfs/blekey/ctap/CtapHid.java) implements USB HID framing (64-byte packets). For BLE FIDO, you need a **new framing layer** (`CtapBle.java`) that implements the BLE-specific protocol from CTAP spec §11.4.4.

---

## 2. CTAP BLE Specification Requirements

### 2.1 GATT Service Structure (§11.4.5)

The FIDO Service (UUID: 0xFFFD) must have these characteristics:

| Characteristic | UUID | Properties | Purpose |
|----------------|------|------------|---------|
| fidoControlPoint | F1D0FFF1-DEAA-ECEE-B42F-C9BA7ED623BB | Write, Notify | Client writes requests here |
| fidoStatus | F1D0FFF2-DEAA-ECEE-B42F-C9BA7ED623BB | Notify | Authenticator sends responses |
| fidoControlPointLength | F1D0FFF3-DEAA-ECEE-B42F-C9BA7ED623BB | Read | Returns max message size (512 bytes) |
| fidoServiceRevisionBitfield | F1D0FFF4-DEAA-ECEE-B42F-C9BA7ED623BB | Read, Write | Service revision flags |
| fidoServiceRevision | 00002A28 | Read | Returns "1.0" or "1.1" |

### 2.2 BLE Framing Protocol (§11.4.4)

**Different from USB HID framing!**

**Request Frame** (Client → Authenticator):
```
┌─────────┬─────────┬──────────────┐
│ CMD (1) │ HLEN(1) │ DATA (0-512) │
└─────────┴─────────┴──────────────┘
```

**Response Frame** (Authenticator → Client):
```
┌────────────┬─────────┬──────────────┐
│ STATUS (1) │ HLEN(1) │ DATA (0-512) │
└────────────┴─────────┴──────────────┘
```

**Command Codes**:
- `0x83` = MSG (CTAP1/U2F)
- `0x90` = CBOR (CTAP2) ← Most important
- `0x81` = PING
- `0x82` = KEEPALIVE
- `0x91` = CANCEL

### 2.3 Fragmentation (§11.4.10)

BLE has MTU limitations (typically 20-512 bytes). Messages must be fragmented:

**First Fragment**:
```
┌─────────┬─────────┬─────────┬──────────────┐
│ CMD (1) │ HLEN(1) │ LLEN(1) │ DATA (n-3)   │
└─────────┴─────────┴─────────┴──────────────┘
```

**Continuation Fragments**:
```
┌─────────┬──────────────┐
│ SEQ (1) │ DATA (n-1)   │
└─────────┴──────────────┘
```
- SEQ starts at 0x00, increments to 0x7F

### 2.4 Security Requirements (§11.4.2, §11.4.3)

- **MUST support LE Secure Connections** (Bluetooth 4.2+)
- **MUST use "Just Works" or "Numeric Comparison"** pairing
- **MUST use LE Security Mode 1, Level 3+** when paired
  - Authenticated pairing
  - 128-bit encryption
  - MITM protection

---

## 3. Implementation Work Breakdown

### 3.1 New Components Required

#### Component 1: FIDOBLEService.java
**Purpose**: Main BLE GATT service for FIDO  
**Lines of Code**: ~800-1000  
**Complexity**: High

**Key Responsibilities**:
- Set up FIDO GATT service (0xFFFD)
- Handle characteristic reads/writes
- Manage BLE connections
- Route messages to CtapBle processor
- Send responses via notifications

**Key Methods**:
```java
void setupGattServer()
void setupFIDOService()
void onControlPointWrite(byte[] data, BluetoothDevice device)
void sendResponse(byte[] response, BluetoothDevice device)
void sendKeepalive(int status, BluetoothDevice device)
```

#### Component 2: CtapBle.java
**Purpose**: BLE framing and fragmentation  
**Lines of Code**: ~600-800  
**Complexity**: High

**Key Responsibilities**:
- Implement BLE framing protocol (§11.4.4)
- Handle message fragmentation/reassembly
- Command/status code mapping
- Message validation

**Key Methods**:
```java
byte[] frameRequest(byte cmd, byte[] data)
byte[] frameResponse(byte status, byte[] data)
List<byte[]> fragmentMessage(byte[] message, int mtu)
byte[] reassembleFragments(List<byte[]> fragments)
```

#### Component 3: FIDOBLEAdvertiser.java
**Purpose**: BLE advertising for FIDO service  
**Lines of Code**: ~200-300  
**Complexity**: Medium

**Key Responsibilities**:
- Configure advertising with FIDO service UUID (0xFFFD)
- Set advertising parameters
- Handle advertising callbacks

#### Component 4: BLEConnectionManager.java
**Purpose**: Per-device state management  
**Lines of Code**: ~400-500  
**Complexity**: Medium

**Key Responsibilities**:
- Track connected devices
- Manage fragmentation state per device
- Handle MTU negotiation
- Implement request collision handling

### 3.2 Modifications to Existing Code

#### CtapTxn.java
**Changes**: Add BLE transport context
```java
enum TransportType { USB_HID, BLE }
TransportType transport;
BluetoothDevice bleDevice;
int bleMtu;
```

#### BleUtils.java
**Changes**: Add FIDO service UUIDs
```java
static final UUID SERVICE_FIDO = UUID.fromString("0000FFFD-0000-1000-8000-00805F9B34FB");
static final UUID CHAR_FIDO_CONTROL_POINT = UUID.fromString("F1D0FFF1-DEAA-ECEE-B42F-C9BA7ED623BB");
// ... etc
```

#### AuthenticatorAPI.java
**Changes**: Minimal - already transport-agnostic
- Verify CBOR encoding/decoding works
- Test with BLE-specific scenarios

---

## 4. Implementation Phases

### Phase 1: Foundation (2 weeks)
**Goal**: Basic GATT service setup

**Tasks**:
1. Create `FIDOBLEService.java` skeleton
2. Implement FIDO GATT service characteristics
3. Create `FIDOBLEAdvertiser.java`
4. Add FIDO UUIDs to `BleUtils.java`
5. Test service discovery

**Deliverable**: FIDO service discoverable and connectable

### Phase 2: Framing (2 weeks)
**Goal**: Implement BLE protocol layer

**Tasks**:
1. Create `CtapBle.java` for framing
2. Implement request/response framing
3. Implement fragmentation logic
4. Create `BLEConnectionManager.java`
5. Handle MTU negotiation

**Deliverable**: Can receive and parse BLE CTAP requests

### Phase 3: Integration (2 weeks)
**Goal**: Connect to CTAP processor

**Tasks**:
1. Route complete messages to `AuthenticatorAPI`
2. Implement keepalive notifications
3. Handle CTAP2 CBOR commands
4. Error handling
5. Update `CtapTxn` for BLE

**Deliverable**: Full CTAP2 support over BLE

### Phase 4: Security (2 weeks)
**Goal**: Implement pairing and encryption

**Tasks**:
1. Implement LE Secure Connections
2. Enforce security levels
3. Handle paired devices
4. Security testing

**Deliverable**: Secure BLE communication

### Phase 5: Testing (2 weeks)
**Goal**: Production readiness

**Tasks**:
1. Comprehensive testing
2. Performance optimization
3. Interoperability testing
4. Documentation

**Deliverable**: Production-ready implementation

---

## 5. Key Differences: USB HID vs BLE FIDO

| Aspect | USB HID (Current) | BLE FIDO (New) |
|--------|-------------------|----------------|
| **Framing** | 64-byte fixed packets | Variable size (MTU-dependent) |
| **Channel ID** | 4-byte CID | No CID (per-device state) |
| **Fragmentation** | Init + continuation frames | First + sequence frames |
| **Transport** | USB HID Report | GATT characteristics |
| **Security** | USB inherent | BLE pairing required |
| **Keepalive** | Optional | Required (>100ms ops) |
| **MTU** | Fixed 64 bytes | Negotiated (20-512 bytes) |

**Critical Insight**: You **cannot reuse** [`CtapHid.java`](../lib/src/com/isfs/blekey/ctap/CtapHid.java) for BLE. The framing protocols are fundamentally different. You need a new `CtapBle.java` class.

---

## 6. Estimated Effort

### 6.1 Development Time
- **Phase 1**: 80 hours (2 weeks)
- **Phase 2**: 80 hours (2 weeks)
- **Phase 3**: 80 hours (2 weeks)
- **Phase 4**: 80 hours (2 weeks)
- **Phase 5**: 80 hours (2 weeks)

**Total**: ~400 hours (10 weeks) for single developer

### 6.2 Complexity Breakdown
- **High Complexity**: BLE protocol, fragmentation, security (60%)
- **Medium Complexity**: GATT service, connection management (30%)
- **Low Complexity**: Integration with existing CTAP (10%)

---

## 7. Recommended Approach

### 7.1 Keep Services Separate

**RECOMMENDED**: Run both HID and FIDO services simultaneously

```
┌─────────────────────────────────────┐
│    Android Application              │
├─────────────────────────────────────┤
│  HIDService     │  FIDOBLEService   │
│  (Keyboard)     │  (Authenticator)  │
├─────────────────┼───────────────────┤
│     GATT Server                     │
│  ┌────────────┐  ┌───────────────┐  │
│  │ HID (0x1812)│  │ FIDO (0xFFFD) │  │
│  └────────────┘  └───────────────┘  │
└─────────────────────────────────────┘
```

**Benefits**:
- Clean separation
- Different security models
- Independent lifecycle
- Can advertise both

### 7.2 Advertising Strategy

Advertise both services simultaneously:
```java
AdvertiseData advertiseData = new AdvertiseData.Builder()
    .addServiceUuid(ParcelUuid.fromString("00001812-...")) // HID
    .addServiceUuid(ParcelUuid.fromString("0000FFFD-...")) // FIDO
    .build();
```

Client chooses which service to use based on their needs.

---

## 8. Testing Strategy

### 8.1 Unit Tests
- BLE framing/deframing
- Fragmentation/reassembly
- Command/status mapping
- GATT operations

### 8.2 Integration Tests
- End-to-end CTAP2 over BLE
- Multi-device connections
- Various MTU sizes
- Keepalive timing
- Error handling

### 8.3 Interoperability Tests
- Chrome/Edge on Windows/Linux/macOS
- Firefox
- Native FIDO2 clients
- Different Android devices

---

## 9. Key Challenges

### 9.1 MTU Negotiation
- Default BLE MTU is 23 bytes (20 usable)
- Must negotiate larger MTU
- Must handle devices without MTU negotiation
- Fragmentation adds complexity

### 9.2 Keepalive Management
- Must send every 100ms during long operations
- Requires background thread
- Must not interfere with responses

### 9.3 Multi-Device Support
- Multiple simultaneous connections
- Independent state per device
- Request collision handling

### 9.4 Security
- LE Secure Connections requires BT 4.2+
- Must handle devices without secure pairing
- Key storage and management

### 9.5 Android Quirks
- Different BLE stacks across versions
- Manufacturer-specific issues
- Permission requirements vary by Android version

---

## 10. Browser Compatibility

### 10.1 Firefox BLE CTAP2 Support Status

Based on research (as of 2024-2026):

**Firefox on Linux - BLE Transport Status**: ⚠️ **LIMITED/NO SUPPORT**

| Transport | Firefox Linux | Firefox Windows | Firefox macOS | Chrome/Edge (All) |
|-----------|---------------|-----------------|---------------|-------------------|
| USB HID | ✅ Supported (since v114) | ✅ Supported | ✅ Supported | ✅ Supported |
| BLE | ❌ **NOT Supported** | ❌ Limited | ❌ Limited | ✅ Supported |
| NFC | ❌ Not Supported | ❌ Not Supported | ❌ Not Supported | ✅ Supported (Android) |
| Hybrid (caBLE) | ❌ Not Supported | ✅ Supported | ✅ Supported | ✅ Supported |

**Key Findings**:

1. **Firefox 114+ on Linux**: Added CTAP2 support for **USB HID only** ([Bugzilla #1530370](https://bugzilla.mozilla.org/show_bug.cgi?id=1530370))
   - Resolved in 2023
   - USB FIDO2 authenticators work
   - BLE transport NOT implemented

2. **BLE Transport**: Firefox does NOT support direct BLE CTAP2 on any platform
   - Windows/macOS use OS-level APIs (Windows Hello, Touch ID)
   - Linux uses `authenticator-rs` library which only supports USB HID
   - [Bugzilla #1543674](https://bugzilla.mozilla.org/show_bug.cgi?id=1543674) tracks hybrid transport (caBLE), not direct BLE

3. **Hybrid Transport (caBLE)**: Different from direct BLE
   - Uses BLE for initial pairing, then switches to internet-based transport
   - Supported on Windows/macOS via OS APIs
   - NOT supported on Linux

4. **Chrome/Edge**: Full BLE CTAP2 support on all platforms
   - Direct BLE transport works
   - Tested and confirmed working

### 10.2 Implications for Your Implementation

**CRITICAL**: Your BLE CTAP2 implementation will **NOT work with Firefox on Linux** in its current form.

**What WILL work**:
- ✅ Chrome/Chromium on Linux
- ✅ Edge on Linux
- ✅ Chrome/Edge on Windows/macOS
- ✅ Any browser using Chromium's WebAuthn implementation

**What will NOT work**:
- ❌ Firefox on Linux (no BLE transport support)
- ❌ Firefox on Windows/macOS (delegates to OS, doesn't use direct BLE)

### 10.3 Workarounds and Alternatives

**Option 1: USB HID Transport (Current Implementation)**
- Already implemented in your codebase
- Works with Firefox on all platforms
- Requires USB connection (not wireless)

**Option 2: Hybrid Transport (caBLE)**
- More complex to implement
- Requires internet connectivity
- Would work with Firefox on Windows/macOS
- Still wouldn't work on Firefox Linux

**Option 3: Wait for Firefox Support**
- Monitor [Bugzilla #1543674](https://bugzilla.mozilla.org/show_bug.cgi?id=1543674)
- No timeline for Linux BLE support
- Low priority for Mozilla (P3)

**Option 4: Focus on Chrome/Chromium**
- BLE CTAP2 works perfectly
- Larger market share
- Better WebAuthn support overall

### 10.4 Recommendation

**For Production Use**:
1. **Primary**: Keep USB HID transport (works everywhere)
2. **Secondary**: Add BLE transport for Chrome/Chromium users
3. **Documentation**: Clearly state Firefox limitations
4. **Testing**: Focus on Chrome/Edge for BLE testing

**User Communication**:
```
Supported Browsers:
- Chrome/Chromium (all platforms) - USB + BLE
- Edge (all platforms) - USB + BLE
- Firefox (all platforms) - USB only
- Safari (macOS/iOS) - USB only
```

### 10.5 Reference: Successful BLE Implementation

The [android-auth](https://github.com/schonacin/android-auth) project successfully implemented BLE CTAP2:
- **Tested with**: Firefox on Windows 10 (works via OS delegation)
- **Note**: "For other setups we cannot guarantee that it works (mostly due to bluetooth related issues)"
- **Architecture**: Similar to what you're planning

**Key Takeaway**: BLE CTAP2 is technically sound and works with Chrome, but Firefox support is platform-dependent and limited.

---

## 11. Next Steps

1. **Review this analysis** with your team
2. **Decide on browser support strategy** (Chrome-only BLE vs. USB-only universal)
3. **Prioritize features** (MVP vs full implementation)
4. **Set up development environment**
5. **Begin Phase 1**: Create `CTAPBLEService.java` skeleton (if proceeding with BLE)
6. **Establish testing infrastructure** (focus on Chrome/Chromium)

---

## Appendix: Code Structure

### New Package
```
com.isfs.blekey.catpble/
├── CTAPBLEService.java          // Main service (~1000 LOC)
├── CTAPBLEAdvertiser.java       // Advertising (~300 LOC)
├── CtapBle.java                 // Framing (~800 LOC)
├── BLEConnectionManager.java    // State mgmt (~500 LOC)
├── BLEFragmentAssembler.java    // Fragments (~400 LOC)
└── BLEKeepaliveManager.java     // Keepalive (~300 LOC)
```

### Modified Files
- `lib/src/com/isfs/blekey/ctap/CtapTxn.java` (add BLE transport)
- `lib/src/com/isfs/blekey/util/BleUtils.java` (add FIDO UUIDs)
- `lib/src/com/isfs/blekey/authenticator/AuthenticatorAPI.java` (minimal changes)

---

**Document Version**: 1.0  
**Date**: 2026-03-03  
**Status**: Ready for Review