<!--
 Copyright IBM 2026
-->
# CTAP2 MakeCredential Implementation Plan

## Overview

This document outlines the implementation plan for refactoring the `AuthenticatorAPI.makeCredential` method to fully comply with the CTAP2 specification while supporting:
- **Transport**: USB only (no NFC initially)
- **Attestation**: Packed-self attestation
- **Extensions**: None initially (to be added later)
- **Key Generation**: Deterministic using RP ID hash as entropy
- **Storage**: Passkey file in FIDO2_HOME directory

## Project Structure

```
lib/src/com/isfs/blekey/
├── authenticator/
│   ├── AuthenticatorAPI.java          # Main CTAP2 API handler
│   ├── Fido2Authenticator.java        # Credential operations
│   ├── CredentialType.java            # Credential type enum
│   ├── AuthenticatorCmd.java          # CTAP command enum
│   └── PinSubCmd.java                 # PIN subcommand enum
├── ctap/
│   ├── Ctap2StatusCode.java           # CTAP error codes
│   └── CtapTxn.java                   # Transaction context
├── data/
│   └── Passkey.java                   # Passkey storage
└── util/
    ├── KeyUtils.java                  # Cryptographic utilities
    └── Cbor.java                      # CBOR encoding/decoding
```

## Implementation Phases

### Phase 1: Refactor Core Structure

#### 1.1 Update `_makeCredential` Method Structure

**File**: `lib/src/com/isfs/blekey/authenticator/AuthenticatorAPI.java`

**Current State**: Lines 308-328 contain a simplified implementation

**Target State**: Break down into CTAP2 specification steps

```java
private static byte[] _makeCredential(
        CredentialValidationResult validation, 
        CtapTxn txn, 
        Map<Integer, Object> req) throws Exception {
    
    // Step 1: Validate inputs (already done in _canMakeCredential)
    
    // Step 2: Process PIN/UV Authentication
    PinUvAuthResult pinUvResult = processPinUvAuth(req, txn);
    if (pinUvResult.errorCode != null) {
        return error(pinUvResult.errorCode);
    }
    
    // Step 3: Collect User Presence (USB transport)
    UserPresenceResult upResult = collectUserPresence(req, txn);
    if (upResult.errorCode != null) {
        return error(upResult.errorCode);
    }
    
    // Step 4: Generate Credential Key Pair
    KeyPair credentialKeyPair = generateCredentialKeyPair(req, txn);
    
    // Step 5: Generate Credential ID
    byte[] credentialId = generateCredentialId(credentialKeyPair);
    
    // Step 6: Store Credential (if resident)
    if (validation.type == CredentialType.RESIDENT) {
        Ctap2StatusCode storeResult = storeResidentCredential(
            req, credentialId, credentialKeyPair, txn.getPasskey());
        if (storeResult != null) {
            return error(storeResult);
        }
    }
    
    // Step 7: Build Authenticator Data
    byte[] authenticatorData = buildAuthenticatorData(
        req, credentialId, credentialKeyPair, 
        pinUvResult.userVerified, upResult.userPresent);
    
    // Step 8: Create Attestation Statement (packed-self)
    Map<String, Object> attStmt = createPackedSelfAttestation(
        req, authenticatorData, credentialKeyPair);
    
    // Step 9: Build Response
    Map<Integer, Object> response = Map.of(
        0x01, "packed",           // fmt
        0x02, authenticatorData,  // authData
        0x03, attStmt             // attStmt
    );
    
    return success(Cbor.encode(response));
}
```

**Dependencies**:
- New helper classes: `PinUvAuthResult`, `UserPresenceResult`
- New methods: `processPinUvAuth`, `collectUserPresence`, `generateCredentialKeyPair`, etc.

---

### Phase 2: Implement Helper Methods

#### 2.1 PIN/UV Authentication Verification

**File**: `lib/src/com/isfs/blekey/authenticator/AuthenticatorAPI.java`

**Purpose**: Verify PIN/UV authentication token according to CTAP2 spec

```java
/**
 * Result class for PIN/UV authentication processing.
 */
private static class PinUvAuthResult {
    final boolean userVerified;
    final Ctap2StatusCode errorCode;
    
    PinUvAuthResult(boolean userVerified, Ctap2StatusCode errorCode) {
        this.userVerified = userVerified;
        this.errorCode = errorCode;
    }
}

/**
 * Processes PIN/UV authentication according to CTAP2 spec.
 * 
 * Algorithm (from CTAP_Attestation_Summary.md lines 136-151):
 * 1. Check if UV is required (options.uv OR alwaysUv)
 * 2. If pinUvAuthParam provided, verify it
 * 3. If UV required but no auth provided, return error
 * 4. Return userVerified status
 *
 * @param req The request parameters
 * @param txn The CTAP transaction
 * @return PinUvAuthResult with verification status or error
 */
private static PinUvAuthResult processPinUvAuth(
        Map<Integer, Object> req, 
        CtapTxn txn) {
    
    // Parse options
    @SuppressWarnings("unchecked")
    Map<String, Object> options = 
        (Map<String, Object>) req.getOrDefault(0x07, new HashMap<>());
    
    boolean uvRequested = (boolean) options.getOrDefault("uv", false);
    boolean alwaysUv = false; // TODO: Read from authenticator config
    boolean requireUserVerification = uvRequested || alwaysUv;
    
    // Check if pinUvAuthParam is provided (0x08)
    byte[] pinUvAuthParam = (byte[]) req.get(0x08);
    Integer pinUvAuthProtocol = (Integer) req.get(0x09);
    
    if (pinUvAuthParam != null) {
        // Verify PIN/UV auth token
        byte[] clientDataHash = (byte[]) req.get(0x01);
        
        if (!verifyPinUvAuthToken(
                pinUvAuthParam, clientDataHash, 
                pinUvAuthProtocol, txn)) {
            logger.error("PIN/UV auth token verification failed");
            return new PinUvAuthResult(false, Ctap2StatusCode.PIN_AUTH_INVALID);
        }
        
        // Auth token verified successfully
        return new PinUvAuthResult(true, null);
        
    } else if (requireUserVerification) {
        // UV required but no auth provided
        
        // Check if PIN is set or biometric available
        if (!isUserVerificationAvailable()) {
            logger.error("User verification required but not available");
            return new PinUvAuthResult(false, Ctap2StatusCode.PIN_NOT_SET);
        }
        
        logger.error("User verification required but no auth token provided");
        return new PinUvAuthResult(false, Ctap2StatusCode.PIN_REQUIRED);
        
    } else {
        // UV not required and no auth provided
        return new PinUvAuthResult(false, null);
    }
}

/**
 * Verifies the PIN/UV authentication token.
 *
 * @param pinUvAuthParam The authentication parameter
 * @param clientDataHash The client data hash
 * @param protocol The PIN/UV protocol version
 * @param txn The CTAP transaction
 * @return true if verification succeeds
 */
private static boolean verifyPinUvAuthToken(
        byte[] pinUvAuthParam,
        byte[] clientDataHash,
        Integer protocol,
        CtapTxn txn) {
    
    // Get the PIN auth token from transaction
    byte[] pinAuthToken = txn.getPinAuthTkn();
    if (pinAuthToken == null) {
        logger.error("No PIN auth token in transaction");
        return false;
    }
    
    // Verify using HMAC-SHA256
    // pinUvAuthParam = HMAC-SHA256(pinAuthToken, clientDataHash)
    try {
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        javax.crypto.spec.SecretKeySpec keySpec = 
            new javax.crypto.spec.SecretKeySpec(pinAuthToken, "HmacSHA256");
        mac.init(keySpec);
        
        byte[] expectedAuth = mac.doFinal(clientDataHash);
        
        // Compare first 16 bytes (CTAP2 spec)
        byte[] expectedAuth16 = Arrays.copyOf(expectedAuth, 16);
        
        return Arrays.equals(pinUvAuthParam, expectedAuth16);
        
    } catch (Exception e) {
        logger.error("Error verifying PIN/UV auth token", e);
        return false;
    }
}
```

**Testing**:
- Unit test with valid PIN auth token
- Unit test with invalid PIN auth token
- Unit test with missing PIN auth token when UV required
- Unit test with UV not required

---

#### 2.2 User Presence Collection

**File**: `lib/src/com/isfs/blekey/authenticator/AuthenticatorAPI.java`

**Purpose**: Collect user presence for USB transport

```java
/**
 * Result class for user presence collection.
 */
private static class UserPresenceResult {
    final boolean userPresent;
    final Ctap2StatusCode errorCode;
    
    UserPresenceResult(boolean userPresent, Ctap2StatusCode errorCode) {
        this.userPresent = userPresent;
        this.errorCode = errorCode;
    }
}

/**
 * Collects user presence according to CTAP2 spec.
 * For USB transport, this is typically automatic (no user gesture required).
 * 
 * Algorithm (from CTAP_Attestation_Summary.md lines 154-171):
 * 1. Check if UP is required (options.up, default true)
 * 2. For USB: User presence is implicit (always true)
 * 3. For NFC: Check NFC userPresent flag (not implemented yet)
 *
 * @param req The request parameters
 * @param txn The CTAP transaction
 * @return UserPresenceResult with presence status or error
 */
private static UserPresenceResult collectUserPresence(
        Map<Integer, Object> req,
        CtapTxn txn) {
    
    // Parse options
    @SuppressWarnings("unchecked")
    Map<String, Object> options = 
        (Map<String, Object>) req.getOrDefault(0x07, new HashMap<>());
    
    boolean upRequired = (boolean) options.getOrDefault("up", true);
    
    if (!upRequired) {
        // UP not required (rare case)
        return new UserPresenceResult(false, null);
    }
    
    // For USB transport, user presence is implicit
    // The fact that the request arrived means the user is present
    logger.debug("User presence collected (USB transport)");
    return new UserPresenceResult(true, null);
    
    // TODO: For NFC transport, implement flag checking:
    // if (transport == NFC) {
    //     if (nfcUserPresentFlag) {
    //         nfcUserPresentFlag = false;
    //         return new UserPresenceResult(true, null);
    //     } else {
    //         return new UserPresenceResult(false, Ctap2StatusCode.UP_REQUIRED);
    //     }
    // }
}
```

**Testing**:
- Unit test with UP required (default)
- Unit test with UP not required
- Future: NFC transport test

---

#### 2.3 Credential Key Generation

**File**: `lib/src/com/isfs/blekey/authenticator/AuthenticatorAPI.java`

**Purpose**: Generate credential key pair using deterministic seed from RP ID hash

```java
/**
 * Generates a credential key pair using deterministic seed.
 * 
 * Algorithm:
 * 1. Extract RP ID from request
 * 2. Hash RP ID using SHA-256
 * 3. Use KeyUtils.getPasskeySeed(rpIdHash, passkeyPrivateKey) to get seed
 * 4. Generate EC key pair from seed
 *
 * @param req The request parameters
 * @param txn The CTAP transaction
 * @return The generated key pair
 * @throws Exception if key generation fails
 */
private static KeyPair generateCredentialKeyPair(
        Map<Integer, Object> req,
        CtapTxn txn) throws Exception {
    
    // Extract RP ID
    @SuppressWarnings("unchecked")
    Map<String, Object> rp = (Map<String, Object>) req.get(0x02);
    String rpId = (String) rp.get("id");
    
    // Hash RP ID
    java.security.MessageDigest digest = 
        java.security.MessageDigest.getInstance("SHA-256");
    byte[] rpIdHash = digest.digest(rpId.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    
    // Get passkey private key for seed generation
    PrivateKey passkeyPrivateKey;
    if (txn.getPasskey() != null) {
        // Resident credential: use passkey private key
        passkeyPrivateKey = txn.getPasskey().getPrivateKey();
    } else {
        // Non-resident credential: use platform key
        passkeyPrivateKey = KeyUtils.getPlatformKey();
    }
    
    // Generate deterministic seed
    String seed = KeyUtils.getPasskeySeed(rpIdHash, passkeyPrivateKey);
    
    // Generate key pair from seed
    // Use the seed to initialize SecureRandom for deterministic generation
    java.security.SecureRandom secureRandom = 
        java.security.SecureRandom.getInstance("SHA1PRNG");
    secureRandom.setSeed(seed.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    
    java.security.KeyPairGenerator keyGen = 
        java.security.KeyPairGenerator.getInstance("EC");
    java.security.spec.ECGenParameterSpec ecSpec = 
        new java.security.spec.ECGenParameterSpec("secp256r1");
    keyGen.initialize(ecSpec, secureRandom);
    
    KeyPair credentialKeyPair = keyGen.generateKeyPair();
    
    logger.debug("Generated credential key pair for RP ID: {}", rpId);
    return credentialKeyPair;
}
```

**Testing**:
- Unit test: Same RP ID + passkey → same key pair (deterministic)
- Unit test: Different RP ID → different key pair
- Unit test: Different passkey → different key pair
- Unit test: Resident vs non-resident credential generation

---

#### 2.4 Credential ID Generation

**File**: `lib/src/com/isfs/blekey/authenticator/AuthenticatorAPI.java`

**Purpose**: Generate unique credential ID

```java
/**
 * Generates a credential ID.
 * For now, uses a random 32-byte ID.
 * 
 * Future enhancement: Could encrypt credential data for stateless operation.
 *
 * @param credentialKeyPair The credential key pair
 * @return The credential ID
 */
private static byte[] generateCredentialId(KeyPair credentialKeyPair) {
    // Generate random 32-byte credential ID
    byte[] credentialId = new byte[32];
    java.security.SecureRandom random = new java.security.SecureRandom();
    random.nextBytes(credentialId);
    
    logger.debug("Generated credential ID: {} bytes", credentialId.length);
    return credentialId;
}
```

**Testing**:
- Unit test: Credential ID is 32 bytes
- Unit test: Credential IDs are unique

---

#### 2.5 Resident Credential Storage

**File**: `lib/src/com/isfs/blekey/authenticator/AuthenticatorAPI.java`

**Purpose**: Store resident credential in Passkey

```java
/**
 * Stores a resident credential in the passkey.
 * 
 * Algorithm (from CTAP_Attestation_Summary.md lines 178-196):
 * 1. Check storage capacity
 * 2. Extract user and RP information
 * 3. Store credential with metadata
 * 4. Persist passkey to file
 *
 * @param req The request parameters
 * @param credentialId The credential ID
 * @param credentialKeyPair The credential key pair
 * @param passkey The passkey to store in
 * @return Error code if storage fails, null on success
 */
private static Ctap2StatusCode storeResidentCredential(
        Map<Integer, Object> req,
        byte[] credentialId,
        KeyPair credentialKeyPair,
        Passkey passkey) {
    
    if (passkey == null) {
        logger.error("Cannot store resident credential: passkey is null");
        return Ctap2StatusCode.OTHER;
    }
    
    // Check storage capacity
    List<Map<String, byte[]>> resCreds = passkey.getResCreds();
    int currentCount = (resCreds != null) ? resCreds.size() : 0;
    
    if (currentCount >= MAX_RESIDENT_CREDENTIALS) {
        logger.error("Resident credential storage full: {}/{}", 
                    currentCount, MAX_RESIDENT_CREDENTIALS);
        return Ctap2StatusCode.KEY_STORE_FULL;
    }
    
    // Extract RP information
    @SuppressWarnings("unchecked")
    Map<String, Object> rp = (Map<String, Object>) req.get(0x02);
    String rpId = (String) rp.get("id");
    byte[] rpIdBytes = rpId.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    
    // Extract user information
    @SuppressWarnings("unchecked")
    Map<String, Object> user = (Map<String, Object>) req.get(0x03);
    byte[] userId = (byte[]) user.get("id");
    
    // Add resident credential to passkey
    passkey.addResCred(rpIdBytes, credentialId, userId);
    
    logger.debug("Stored resident credential for RP: {}", rpId);
    
    // TODO: Persist passkey to file
    // This requires the PIN hash, which should be available in the transaction
    // For now, the credential is stored in memory only
    
    return null; // Success
}
```

**Testing**:
- Unit test: Store resident credential successfully
- Unit test: Storage full error
- Unit test: Credential retrieval after storage
- Integration test: Persist and reload from file

---

#### 2.6 Authenticator Data Building

**File**: `lib/src/com/isfs/blekey/authenticator/AuthenticatorAPI.java`

**Purpose**: Build authenticator data structure according to CTAP2 spec

```java
/**
 * Builds the authenticator data structure.
 * 
 * Structure (from CTAP_Attestation_Summary.md lines 219-243):
 * - RP ID hash (32 bytes)
 * - Flags byte (UP, UV, AT, ED bits)
 * - Signature counter (4 bytes, big-endian)
 * - Attested credential data:
 *   - AAGUID (16 bytes)
 *   - Credential ID length (2 bytes, big-endian)
 *   - Credential ID (variable)
 *   - Credential public key (COSE format)
 * - Extensions data (if present) - NOT IMPLEMENTED YET
 *
 * @param req The request parameters
 * @param credentialId The credential ID
 * @param credentialKeyPair The credential key pair
 * @param userVerified Whether user was verified
 * @param userPresent Whether user is present
 * @return The authenticator data bytes
 * @throws Exception if building fails
 */
private static byte[] buildAuthenticatorData(
        Map<Integer, Object> req,
        byte[] credentialId,
        KeyPair credentialKeyPair,
        boolean userVerified,
        boolean userPresent) throws Exception {
    
    java.io.ByteArrayOutputStream authDataBytes = 
        new java.io.ByteArrayOutputStream();
    
    // 1. RP ID hash (32 bytes)
    @SuppressWarnings("unchecked")
    Map<String, Object> rp = (Map<String, Object>) req.get(0x02);
    String rpId = (String) rp.get("id");
    
    java.security.MessageDigest digest = 
        java.security.MessageDigest.getInstance("SHA-256");
    byte[] rpIdHash = digest.digest(
        rpId.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    authDataBytes.write(rpIdHash);
    
    // 2. Flags byte
    int flags = 0x00;
    if (userPresent) flags |= 0x01;  // UP bit
    if (userVerified) flags |= 0x04;  // UV bit
    flags |= 0x40;  // AT (Attested Credential Data) bit - always set for makeCredential
    // ED bit (0x80) not set - no extensions yet
    
    authDataBytes.write(flags);
    
    // 3. Signature counter (4 bytes, big-endian)
    long counter = getAndIncrementCounter();
    java.nio.ByteBuffer counterBuffer = java.nio.ByteBuffer.allocate(4);
    counterBuffer.putInt((int) counter);
    authDataBytes.write(counterBuffer.array());
    
    // 4. Attested credential data
    byte[] attestedCredData = buildAttestedCredentialData(
        credentialId, credentialKeyPair.getPublic());
    authDataBytes.write(attestedCredData);
    
    // 5. Extensions data (not implemented yet)
    // if (extensionOutput != null && !extensionOutput.isEmpty()) {
    //     authDataBytes.write(Cbor.encode(extensionOutput));
    // }
    
    return authDataBytes.toByteArray();
}

/**
 * Builds the attested credential data structure.
 *
 * @param credentialId The credential ID
 * @param publicKey The credential public key
 * @return The attested credential data bytes
 * @throws Exception if building fails
 */
private static byte[] buildAttestedCredentialData(
        byte[] credentialId,
        PublicKey publicKey) throws Exception {
    
    java.io.ByteArrayOutputStream attestedCredDataBytes = 
        new java.io.ByteArrayOutputStream();
    
    // 1. AAGUID (16 bytes) - use zeros for now
    byte[] aaguid = new byte[16];
    attestedCredDataBytes.write(aaguid);
    
    // 2. Credential ID length (2 bytes, big-endian)
    java.nio.ByteBuffer lengthBuffer = java.nio.ByteBuffer.allocate(2);
    lengthBuffer.putShort((short) credentialId.length);
    attestedCredDataBytes.write(lengthBuffer.array());
    
    // 3. Credential ID
    attestedCredDataBytes.write(credentialId);
    
    // 4. Credential public key (COSE format)
    Map<Integer, Object> coseKey = KeyUtils.toCoseKey(publicKey);
    byte[] coseKeyBytes = Cbor.encode(coseKey);
    attestedCredDataBytes.write(coseKeyBytes);
    
    return attestedCredDataBytes.toByteArray();
}

/**
 * Gets and increments the signature counter.
 * 
 * @return The current counter value
 */
private static long getAndIncrementCounter() {
    // TODO: Implement persistent counter storage
    // For now, use a simple in-memory counter
    return signatureCounter++;
}

// Add field to class
private static long signatureCounter = 0;
```

**Testing**:
- Unit test: Authenticator data structure format
- Unit test: Flags byte values (UP, UV, AT)
- Unit test: Counter increments
- Unit test: COSE key encoding

---

#### 2.7 Packed-Self Attestation Statement

**File**: `lib/src/com/isfs/blekey/authenticator/AuthenticatorAPI.java`

**Purpose**: Create packed-self attestation statement

```java
/**
 * Creates a packed-self attestation statement.
 * 
 * Algorithm (from CTAP_Attestation_Summary.md lines 267-282):
 * 1. Sign (authenticatorData || clientDataHash) with credential private key
 * 2. Return attestation statement with algorithm and signature
 * 3. No certificate chain (self-attestation)
 *
 * @param req The request parameters
 * @param authenticatorData The authenticator data
 * @param credentialKeyPair The credential key pair
 * @return The attestation statement map
 * @throws Exception if signing fails
 */
private static Map<String, Object> createPackedSelfAttestation(
        Map<Integer, Object> req,
        byte[] authenticatorData,
        KeyPair credentialKeyPair) throws Exception {
    
    // Get client data hash
    byte[] clientDataHash = (byte[]) req.get(0x01);
    
    // Concatenate authenticatorData || clientDataHash
    java.io.ByteArrayOutputStream sigData = 
        new java.io.ByteArrayOutputStream();
    sigData.write(authenticatorData);
    sigData.write(clientDataHash);
    
    // Sign with credential private key
    java.security.Signature signature = 
        java.security.Signature.getInstance("SHA256withECDSA");
    signature.initSign(credentialKeyPair.getPrivate());
    signature.update(sigData.toByteArray());
    byte[] sig = signature.sign();
    
    // Build attestation statement
    Map<String, Object> attStmt = new HashMap<>();
    attStmt.put("alg", -7);  // ES256 (ECDSA with SHA-256)
    attStmt.put("sig", sig);
    // No x5c for self-attestation
    
    logger.debug("Created packed-self attestation statement");
    return attStmt;
}
```

**Testing**:
- Unit test: Attestation statement format
- Unit test: Signature verification
- Unit test: Algorithm identifier

---

### Phase 3: Integration and Testing

#### 3.1 Unit Tests

**File**: `lib/test/com/isfs/blekey/authenticator/MakeCredentialTest.java` (new)

```java
package com.isfs.blekey.authenticator;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class MakeCredentialTest {
    
    @Test
    public void testPinUvAuthVerification() {
        // Test PIN/UV auth token verification
    }
    
    @Test
    public void testUserPresenceCollection() {
        // Test user presence for USB transport
    }
    
    @Test
    public void testCredentialKeyGeneration() {
        // Test deterministic key generation
    }
    
    @Test
    public void testResidentCredentialStorage() {
        // Test storing resident credential
    }
    
    @Test
    public void testAuthenticatorDataBuilding() {
        // Test authenticator data structure
    }
    
    @Test
    public void testPackedSelfAttestation() {
        // Test attestation statement creation
    }
    
    @Test
    public void testMakeCredentialFlow() {
        // End-to-end test of makeCredential
    }
}
```

Valid authentication with correct pinUvAuthParam
Invalid HMAC (wrong pinUvAuthParam)
Missing pinAuthToken in transaction
UV required without auth token
Invalid protocol version
Missing RP ID parameter


#### 3.2 Integration Tests

**File**: `lib/test/com/isfs/blekey/authenticator/MakeCredentialIntegrationTest.java` (new)

```java
package com.isfs.blekey.authenticator;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class MakeCredentialIntegrationTest {
    
    @Test
    public void testMakeCredentialWithPasskeyStorage() {
        // Test full flow with Passkey file storage
    }
    
    @Test
    public void testResidentCredentialPersistence() {
        // Test that resident credentials persist across sessions
    }
    
    @Test
    public void testMultipleCredentialsForSameRP() {
        // Test creating multiple credentials for same RP
    }
}
```

---

## Implementation Order

1. **Phase 1**: Refactor `_makeCredential` structure (1-2 hours)
2. **Phase 2.1**: Implement PIN/UV auth verification (2-3 hours)
3. **Phase 2.2**: Implement user presence collection (1 hour)
4. **Phase 2.3**: Implement credential key generation (2-3 hours)
5. **Phase 2.4**: Implement credential ID generation (30 minutes)
6. **Phase 2.5**: Implement resident credential storage (2-3 hours)
7. **Phase 2.6**: Implement authenticator data building (2-3 hours)
8. **Phase 2.7**: Implement packed-self attestation (1-2 hours)
9. **Phase 3.1**: Write unit tests (3-4 hours)
10. **Phase 3.2**: Write integration tests (2-3 hours)

**Total Estimated Time**: 18-26 hours

---

## Key Design Decisions

### 1. Deterministic Key Generation
- **Entropy Source**: SHA-256 hash of RP ID
- **Seed Generation**: `KeyUtils.getPasskeySeed(rpIdHash, passkeyPrivateKey)`
- **Algorithm**: EC P-256 (secp256r1)
- **Rationale**: Allows credential recovery from passkey + RP ID

### 2. Credential Storage
- **Resident Credentials**: Stored in Passkey file
- **Non-Resident Credentials**: Not stored (stateless)
- **Storage Format**: CBOR-encoded map with `cred.id`, `user.id`, `rp.id`

### 3. Attestation Type
- **Default**: Packed-self attestation
- **Rationale**: Privacy-preserving, no certificate management
- **Future**: Support packed-basic with certificates

### 4. User Presence
- **USB Transport**: Implicit (always true)
- **Rationale**: USB connection implies user presence
- **Future**: Add explicit user gesture for enhanced security

### 5. Signature Counter
- **Storage**: In-memory for now
- **Future**: Persist in Passkey file or separate counter file

---

## Error Handling

All CTAP2 error codes from `Ctap2StatusCode.java` should be properly handled:

- `MISSING_PARAMETER`: Required parameter missing
- `INVALID_PARAMETER`: Parameter validation failed
- `UNSUPPORTED_ALGORITHM`: No supported algorithm in pubKeyCredParams
- `CREDENTIAL_EXCLUDED`: Credential already exists
- `KEY_STORE_FULL`: No space for resident credential
- `PIN_AUTH_INVALID`: PIN/UV auth verification failed
- `PIN_NOT_SET`: UV required but PIN not set
- `PIN_REQUIRED`: UV required but no auth token provided
- `UP_REQUIRED`: User presence required but not collected
- `UNSUPPORTED_OPTION`: Unsupported option requested
- `INVALID_OPTION`: Invalid option value
- `OTHER`: Generic error

---

## Future Enhancements

1. **Extensions Support**
   - credProtect
   - hmac-secret
   - largeBlobKey

2. **UX**
   - User presence flag checking
   - Timeout handling

3. **Persistent Counter**
   - Store counter in Passkey file
   - Atomic increment operations

4. **Platform attestation**
   - Use platform pin cache key to generate packed attestation statement
   - Do not requrie user interation to provide assertions
   - second factor authentication use case; credential id always provided
   - decrypt credential id with platform pin cache key

---

## References

- CTAP2 Specification: `Client to Authenticator Protocol (CTAP) - fido-client-to-authenticator-protocol-v2.3-rd-20251023.pdf`
- Attestation Summary: `lib/src/com/isfs/blekey/authenticator/CTAP_Attestation_Summary.md`
- Existing Implementation: `lib/src/com/isfs/blekey/authenticator/AuthenticatorAPI.java`
- Key Utilities: `lib/src/com/isfs/blekey/util/KeyUtils.java`
- Passkey Storage: `lib/src/com/isfs/blekey/data/Passkey.java`