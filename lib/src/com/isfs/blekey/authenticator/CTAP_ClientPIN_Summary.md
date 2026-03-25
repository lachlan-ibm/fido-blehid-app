<!--
 Copyright IBM 2026
-->
# CTAP ClientPIN Sub-Commands Summary

Based on the FIDO Client to Authenticator Protocol (CTAP) v2.3 specification, here is a summary of the authenticatorClientPIN command and its sub-commands for PIN/UV authentication operations.

## ClientPIN Overview

The authenticatorClientPIN command (0x06) exists so that plaintext PINs are not sent to the authenticator. Instead, a PIN/UV auth protocol ensures that PINs are encrypted when sent to an authenticator and are exchanged for a pinUvAuthToken that serves to authenticate subsequent commands. Additionally, authenticators supporting built-in user verification methods can provide a pinUvAuthToken upon user verification.

## Key Concepts

### pinUvAuthToken
- Randomly-generated, opaque bytestring that is large enough to be effectively unguessable
- Used to authenticate subsequent authenticator commands
- Has associated state variables including permissions, RP ID, usage timer, and flags
- Can be obtained via PIN entry or built-in user verification

### persistentPinUvAuthToken
- Similar to pinUvAuthToken but persists across power cycles
- Used for specific long-term operations

### PIN/UV Auth Protocols
Two protocols are defined:
- **Protocol One (version 1)**: Uses HMAC-SHA-256 for authentication
- **Protocol Two (version 2)**: Enhanced security protocol

## PIN Composition Requirements

### Platform Requirements
- **Minimum PIN Length**: 4 Unicode characters
- **Maximum PIN Length**: UTF-8 representation MUST NOT exceed 63 bytes
- PINs are in Unicode normalization form C
- PIN MUST NOT end in a 0x00 byte

### Authenticator Requirements
- **Minimum PIN Length**: 4 code points (authenticators can enforce greater minimum)
- **Maximum PIN Length**: 63 bytes
- PIN storage must provide same or better security as private keys

## PIN Sub-Commands

The following sub-commands are defined in [`PinSubCmd.java`](PinSubCmd.java):

| Sub-Command | Value | Description |
|-------------|-------|-------------|
| GETRETRY | 0x01 | Get PIN retry count |
| GETKEY | 0x02 | Get key agreement key |
| SETPIN | 0x03 | Set new PIN |
| CHANGEPIN | 0x04 | Change existing PIN |
| GETTKN | 0x05 | Get PIN token (superseded) |
| GETTKNUV | 0x06 | Get PIN token using UV |
| GETUVRETRY | 0x07 | Get UV retry count |

## Sub-Command Details

### 1. GETRETRY (0x01) - Get PIN Retry Count

**Purpose**: Query the number of PIN attempts remaining before lockout

**Algorithm**:
```pseudocode
FUNCTION getPinRetries() RETURNS response OR error
BEGIN
    // Return current PIN retry counter
    response = {
        retries: pinRetries  // Number of attempts remaining
    }
    
    RETURN response
END FUNCTION
```

**Response Structure**:
- `retries` (0x03): Unsigned integer representing attempts remaining

**Key Points**:
- Authenticators MUST allow no more than 8 retries but MAY set lower maximum
- Once pinRetries reaches 0, both ClientPin and built-in UV are disabled
- Can only be re-enabled by authenticator reset

---

### 2. GETKEY (0x02) - Get Key Agreement Key

**Purpose**: Obtain the authenticator's public key for establishing shared secret

**Algorithm**:
```pseudocode
FUNCTION getKeyAgreement(pinUvAuthProtocol) RETURNS response OR error
BEGIN
    // Step 1: Validate protocol version
    IF pinUvAuthProtocol NOT IN [1, 2] THEN
        RETURN CTAP1_ERR_INVALID_PARAMETER
    END IF
    
    // Step 2: Generate or retrieve public key for protocol
    publicKey = getPublicKey(pinUvAuthProtocol)
    
    // Step 3: Return key in COSE format
    response = {
        keyAgreement: publicKey  // COSE_Key structure
    }
    
    RETURN response
END FUNCTION
```

**Input Parameters**:
- `pinUvAuthProtocol` (0x01): Protocol version (1 or 2)

**Response Structure**:
- `keyAgreement` (0x01): COSE_Key structure containing authenticator's public key

**Key Points**:
- Platform uses this key to establish shared secret via ECDH
- Shared secret is used to encrypt PIN and decrypt pinUvAuthToken

---

### 3. SETPIN (0x03) - Set New PIN

**Purpose**: Set a new PIN on an authenticator that doesn't have one

**Algorithm**:
```pseudocode
FUNCTION setPin(
    pinUvAuthProtocol,
    keyAgreement,      // Platform's public key
    newPinEnc,         // Encrypted new PIN
    pinUvAuthParam     // Authentication parameter
) RETURNS success OR error
BEGIN
    // Step 1: Validate protocol
    IF pinUvAuthProtocol NOT IN [1, 2] THEN
        RETURN CTAP1_ERR_INVALID_PARAMETER
    END IF
    
    // Step 2: Check if PIN already set
    IF clientPin IS SET THEN
        RETURN CTAP2_ERR_PIN_AUTH_INVALID
    END IF
    
    // Step 3: Establish shared secret
    sharedSecret = decapsulate(keyAgreement)
    IF sharedSecret IS error THEN
        RETURN CTAP2_ERR_PIN_AUTH_INVALID
    END IF
    
    // Step 4: Verify authentication parameter
    expectedAuth = authenticate(sharedSecret, newPinEnc)
    IF NOT constantTimeCompare(pinUvAuthParam, expectedAuth) THEN
        RETURN CTAP2_ERR_PIN_AUTH_INVALID
    END IF
    
    // Step 5: Decrypt and validate new PIN
    newPin = decrypt(sharedSecret, newPinEnc)
    IF length(newPin) < 4 OR length(newPin) > 63 THEN
        RETURN CTAP2_ERR_PIN_POLICY_VIOLATION
    END IF
    
    // Step 6: Store PIN securely
    storePin(newPin)
    
    // Step 7: Reset retry counters
    pinRetries = MAX_PIN_RETRIES
    uvRetries = maxUvRetries
    
    // Step 8: Generate new pinUvAuthToken
    resetPinUvAuthToken()
    
    RETURN CTAP2_OK
END FUNCTION
```

**Input Parameters**:
- `pinUvAuthProtocol` (0x01): Protocol version
- `keyAgreement` (0x02): Platform's public key (COSE_Key)
- `newPinEnc` (0x03): Encrypted new PIN
- `pinUvAuthParam` (0x04): HMAC of newPinEnc

**Key Points**:
- Can only be called when PIN is not set
- PIN must meet composition requirements
- Resets all retry counters
- Generates fresh pinUvAuthToken

---

### 4. CHANGEPIN (0x04) - Change Existing PIN

**Purpose**: Change an existing PIN to a new value

**Algorithm**:
```pseudocode
FUNCTION changePin(
    pinUvAuthProtocol,
    keyAgreement,
    pinHashEnc,        // Encrypted hash of current PIN
    newPinEnc,         // Encrypted new PIN
    pinUvAuthParam
) RETURNS success OR error
BEGIN
    // Step 1: Validate protocol
    IF pinUvAuthProtocol NOT IN [1, 2] THEN
        RETURN CTAP1_ERR_INVALID_PARAMETER
    END IF
    
    // Step 2: Check if PIN is set
    IF clientPin IS NOT SET THEN
        RETURN CTAP2_ERR_PIN_NOT_SET
    END IF
    
    // Step 3: Check retry counter
    IF pinRetries == 0 THEN
        RETURN CTAP2_ERR_PIN_BLOCKED
    END IF
    
    // Step 4: Establish shared secret
    sharedSecret = decapsulate(keyAgreement)
    IF sharedSecret IS error THEN
        RETURN CTAP2_ERR_PIN_AUTH_INVALID
    END IF
    
    // Step 5: Verify authentication parameter
    expectedAuth = authenticate(sharedSecret, newPinEnc || pinHashEnc)
    IF NOT constantTimeCompare(pinUvAuthParam, expectedAuth) THEN
        RETURN CTAP2_ERR_PIN_AUTH_INVALID
    END IF
    
    // Step 6: Decrypt and verify current PIN
    pinHash = decrypt(sharedSecret, pinHashEnc)
    IF NOT verifyPinHash(pinHash) THEN
        pinRetries = pinRetries - 1
        IF pinRetries == 0 THEN
            RETURN CTAP2_ERR_PIN_BLOCKED
        END IF
        RETURN CTAP2_ERR_PIN_INVALID
    END IF
    
    // Step 7: Decrypt and validate new PIN
    newPin = decrypt(sharedSecret, newPinEnc)
    IF length(newPin) < 4 OR length(newPin) > 63 THEN
        RETURN CTAP2_ERR_PIN_POLICY_VIOLATION
    END IF
    
    // Step 8: Store new PIN
    storePin(newPin)
    
    // Step 9: Reset counters and tokens
    pinRetries = MAX_PIN_RETRIES
    uvRetries = maxUvRetries
    resetPinUvAuthToken()
    
    RETURN CTAP2_OK
END FUNCTION
```

**Input Parameters**:
- `pinUvAuthProtocol` (0x01): Protocol version
- `keyAgreement` (0x02): Platform's public key
- `pinHashEnc` (0x03): Encrypted hash of current PIN (first 16 bytes of SHA-256)
- `newPinEnc` (0x04): Encrypted new PIN
- `pinUvAuthParam` (0x05): HMAC of (newPinEnc || pinHashEnc)

**Key Points**:
- Requires correct current PIN
- Decrements pinRetries on incorrect PIN
- Resets all counters on success
- Invalidates existing pinUvAuthToken

---

### 5. GETTKN (0x05) - Get PIN Token (Superseded)

**Purpose**: Obtain pinUvAuthToken using PIN (legacy method)

**Status**: **SUPERSEDED** - Use getPinUvAuthTokenUsingPinWithPermissions instead

**Algorithm**:
```pseudocode
FUNCTION getPinToken(
    pinUvAuthProtocol,
    keyAgreement,
    pinHashEnc
) RETURNS response OR error
BEGIN
    // Step 1: Validate protocol
    IF pinUvAuthProtocol NOT IN [1, 2] THEN
        RETURN CTAP1_ERR_INVALID_PARAMETER
    END IF
    
    // Step 2: Check if PIN is set
    IF clientPin IS NOT SET THEN
        RETURN CTAP2_ERR_PIN_NOT_SET
    END IF
    
    // Step 3: Check retry counter
    IF pinRetries == 0 THEN
        RETURN CTAP2_ERR_PIN_BLOCKED
    END IF
    
    // Step 4: Establish shared secret
    sharedSecret = decapsulate(keyAgreement)
    
    // Step 5: Decrypt and verify PIN
    pinHash = decrypt(sharedSecret, pinHashEnc)
    IF NOT verifyPinHash(pinHash) THEN
        pinRetries = pinRetries - 1
        IF pinRetries == 0 THEN
            RETURN CTAP2_ERR_PIN_BLOCKED
        END IF
        RETURN CTAP2_ERR_PIN_INVALID
    END IF
    
    // Step 6: Reset counters
    pinRetries = MAX_PIN_RETRIES
    uvRetries = maxUvRetries
    
    // Step 7: Prepare pinUvAuthToken
    beginUsingPinUvAuthToken(userIsPresent = false)
    
    // Step 8: Encrypt and return token
    pinUvAuthTokenEnc = encrypt(sharedSecret, pinUvAuthToken)
    
    response = {
        pinUvAuthToken: pinUvAuthTokenEnc
    }
    
    RETURN response
END FUNCTION
```

**Input Parameters**:
- `pinUvAuthProtocol` (0x01): Protocol version
- `keyAgreement` (0x02): Platform's public key
- `pinHashEnc` (0x06): Encrypted PIN hash

**Response Structure**:
- `pinUvAuthToken` (0x02): Encrypted pinUvAuthToken

**Key Points**:
- **Superseded by getPinUvAuthTokenUsingPinWithPermissions**
- Does not support permissions or RP ID scoping
- Maintained for CTAP 2.0 backwards compatibility

---

### 6. GETTKNUV (0x06) - Get PIN Token Using UV

**Purpose**: Obtain pinUvAuthToken using built-in user verification with permissions

**Sub-Commands**:
- `getPinUvAuthTokenUsingUvWithPermissions` (0x06)
- `getPinUvAuthTokenUsingPinWithPermissions` (0x09)

#### getPinUvAuthTokenUsingUvWithPermissions (0x06)

**Algorithm**:
```pseudocode
FUNCTION getPinUvAuthTokenUsingUvWithPermissions(
    pinUvAuthProtocol,
    keyAgreement,
    permissions,       // Requested permissions bitmap
    rpId              // Optional RP ID
) RETURNS response OR error
BEGIN
    // Step 1: Validate protocol
    IF pinUvAuthProtocol NOT IN [1, 2] THEN
        RETURN CTAP1_ERR_INVALID_PARAMETER
    END IF
    
    // Step 2: Check UV support
    IF NOT supportsBuiltInUV() THEN
        RETURN CTAP2_ERR_INVALID_OPTION
    END IF
    
    // Step 3: Check UV retry counter
    IF uvRetries == 0 THEN
        RETURN CTAP2_ERR_UV_BLOCKED
    END IF
    
    // Step 4: Validate permissions
    IF permissions == 0 THEN
        RETURN CTAP2_ERR_INVALID_PARAMETER
    END IF
    
    // Step 5: Perform built-in user verification
    uvState = performBuiltInUv(internalRetry = false)
    IF uvState IS error THEN
        IF uvRetries == 0 THEN
            RETURN CTAP2_ERR_UV_BLOCKED
        END IF
        RETURN CTAP2_ERR_OPERATION_DENIED
    END IF
    
    // Step 6: Reset UV counter on success
    uvRetries = maxUvRetries
    
    // Step 7: Establish shared secret
    sharedSecret = decapsulate(keyAgreement)
    
    // Step 8: Set pinUvAuthToken permissions
    setPinUvAuthTokenPermissions(permissions)
    IF rpId IS PROVIDED THEN
        setPinUvAuthTokenRpId(rpId)
    END IF
    
    // Step 9: Prepare token for use
    beginUsingPinUvAuthToken(userIsPresent = true)
    
    // Step 10: Encrypt and return token
    pinUvAuthTokenEnc = encrypt(sharedSecret, pinUvAuthToken)
    
    response = {
        pinUvAuthToken: pinUvAuthTokenEnc
    }
    
    RETURN response
END FUNCTION
```

**Input Parameters**:
- `pinUvAuthProtocol` (0x01): Protocol version
- `keyAgreement` (0x02): Platform's public key
- `permissions` (0x09): Permissions bitmap
- `rpId` (0x0A): Optional RP ID for permission scoping

**Response Structure**:
- `pinUvAuthToken` (0x02): Encrypted pinUvAuthToken

#### getPinUvAuthTokenUsingPinWithPermissions (0x09)

**Algorithm**:
```pseudocode
FUNCTION getPinUvAuthTokenUsingPinWithPermissions(
    pinUvAuthProtocol,
    keyAgreement,
    pinHashEnc,
    permissions,
    rpId
) RETURNS response OR error
BEGIN
    // Step 1: Validate protocol
    IF pinUvAuthProtocol NOT IN [1, 2] THEN
        RETURN CTAP1_ERR_INVALID_PARAMETER
    END IF
    
    // Step 2: Check if PIN is set
    IF clientPin IS NOT SET THEN
        RETURN CTAP2_ERR_PIN_NOT_SET
    END IF
    
    // Step 3: Check retry counter
    IF pinRetries == 0 THEN
        RETURN CTAP2_ERR_PIN_BLOCKED
    END IF
    
    // Step 4: Validate permissions
    IF permissions == 0 THEN
        RETURN CTAP2_ERR_INVALID_PARAMETER
    END IF
    
    // Step 5: Establish shared secret
    sharedSecret = decapsulate(keyAgreement)
    
    // Step 6: Decrypt and verify PIN
    pinHash = decrypt(sharedSecret, pinHashEnc)
    IF NOT verifyPinHash(pinHash) THEN
        pinRetries = pinRetries - 1
        IF pinRetries == 0 THEN
            RETURN CTAP2_ERR_PIN_BLOCKED
        END IF
        RETURN CTAP2_ERR_PIN_INVALID
    END IF
    
    // Step 7: Reset counters
    pinRetries = MAX_PIN_RETRIES
    uvRetries = maxUvRetries
    
    // Step 8: Set permissions
    setPinUvAuthTokenPermissions(permissions)
    IF rpId IS PROVIDED THEN
        setPinUvAuthTokenRpId(rpId)
    END IF
    
    // Step 9: Prepare token
    beginUsingPinUvAuthToken(userIsPresent = false)
    
    // Step 10: Encrypt and return
    pinUvAuthTokenEnc = encrypt(sharedSecret, pinUvAuthToken)
    
    response = {
        pinUvAuthToken: pinUvAuthTokenEnc
    }
    
    RETURN response
END FUNCTION
```

**Input Parameters**:
- `pinUvAuthProtocol` (0x01): Protocol version
- `keyAgreement` (0x02): Platform's public key
- `pinHashEnc` (0x06): Encrypted PIN hash
- `permissions` (0x09): Permissions bitmap
- `rpId` (0x0A): Optional RP ID

**Response Structure**:
- `pinUvAuthToken` (0x02): Encrypted pinUvAuthToken

---

### 7. GETUVRETRY (0x07) - Get UV Retry Count

**Purpose**: Query the number of UV attempts remaining

**Algorithm**:
```pseudocode
FUNCTION getUvRetries() RETURNS response OR error
BEGIN
    // Return current UV retry counter
    response = {
        uvRetries: uvRetries  // Number of UV attempts remaining
    }
    
    RETURN response
END FUNCTION
```

**Response Structure**:
- `uvRetries` (0x05): Unsigned integer representing UV attempts remaining

**Key Points**:
- uvRetries range: 1 to 25 (inclusive)
- Once uvRetries reaches 0, built-in UV is disabled
- Can be re-enabled by authenticator reset or correct PIN entry

---

## pinUvAuthToken Permissions

The permissions bitmap defines what operations the pinUvAuthToken can authorize:

| Permission | Value | Description |
|------------|-------|-------------|
| mc | 0x01 | MakeCredential permission |
| ga | 0x02 | GetAssertion permission |
| cm | 0x04 | Credential Management permission |
| be | 0x08 | Bio Enrollment permission |
| lbw | 0x10 | Large Blob Write permission |
| acfg | 0x20 | Authenticator Config permission |
| pcmr | 0x40 | Credential Management Read-Only permission |

## pinUvAuthToken State Variables

Each pinUvAuthToken maintains:

1. **Permissions RP ID**: Optional RP ID for permission scoping
2. **Permissions Set**: Bitmap of granted permissions
3. **Usage Timer**: Tracks token lifetime
4. **In Use Flag**: Whether token is currently active
5. **Initial Usage Time Limit**: Transport-specific timeout (default 30s for USB)
6. **User Present Time Limit**: How long UP flag remains valid
7. **Max Usage Time Period**: Maximum token lifetime (default 10 minutes)
8. **userVerified Flag**: Whether user was verified
9. **userPresent Flag**: Whether user presence was collected

## Retry Counters

### PIN Retry Counter (pinRetries)
- Maximum: 8 attempts (authenticators MAY set lower)
- Decremented on each incorrect PIN entry
- Reset to maximum on correct PIN entry
- When reaches 0: Both ClientPin and built-in UV disabled
- Recovery: Only via authenticator reset

### UV Retry Counter (uvRetries)
- Range: 1 to 25 attempts (authenticator-configured)
- Decremented on each failed UV attempt
- Reset to maximum on successful UV or correct PIN entry
- When reaches 0: Built-in UV disabled
- Recovery: Authenticator reset or correct PIN entry

## Error Codes

| Error Code | Value | Condition |
|------------|-------|-----------|
| CTAP2_ERR_PIN_REQUIRED | 0x36 | PIN authentication needed |
| CTAP2_ERR_PIN_AUTH_INVALID | 0x31 | Invalid PIN auth parameter |
| CTAP2_ERR_PIN_INVALID | 0x31 | Incorrect PIN provided |
| CTAP2_ERR_PIN_BLOCKED | 0x32 | PIN retry counter reached 0 |
| CTAP2_ERR_PIN_NOT_SET | 0x35 | PIN not configured |
| CTAP2_ERR_PIN_POLICY_VIOLATION | 0x33 | PIN doesn't meet requirements |
| CTAP2_ERR_UV_BLOCKED | 0x34 | UV retry counter reached 0 |
| CTAP2_ERR_OPERATION_DENIED | 0x27 | User denied operation |
| CTAP2_ERR_USER_ACTION_TIMEOUT | 0x3A | User didn't respond in time |
| CTAP2_ERR_UNAUTHORIZED_PERMISSION | 0x3B | Requested permission not granted |

## Security Considerations

1. **PIN Encryption**: PINs are always encrypted using shared secret from ECDH
2. **Token Lifetime**: pinUvAuthToken has limited lifetime (default 10 minutes max)
3. **Permission Scoping**: Tokens can be scoped to specific RPs and operations
4. **Retry Limits**: Both PIN and UV have retry limits to prevent brute force
5. **Constant-Time Comparison**: Use constant-time comparison for PIN/token verification
6. **Secure Storage**: PIN storage must provide same security as private keys
7. **Token Invalidation**: Tokens invalidated on PIN change, timeout, or certain errors
8. **User Presence**: Separate from user verification, tracked independently

## Platform Integration

### Obtaining Shared Secret
1. Platform calls `getKeyAgreement` to get authenticator's public key
2. Platform generates its own key pair
3. Platform performs ECDH to derive shared secret
4. Shared secret used to encrypt PIN and decrypt pinUvAuthToken

### Using pinUvAuthToken
1. Platform obtains pinUvAuthToken via appropriate sub-command
2. Platform creates pinUvAuthParam: `HMAC-SHA-256(pinUvAuthToken, data)[0:16]`
3. Platform includes pinUvAuthParam in subsequent commands
4. Authenticator verifies pinUvAuthParam and checks permissions

### Token Lifecycle
1. **Obtain**: Via getPinUvAuthTokenUsing* sub-commands
2. **Use**: Include pinUvAuthParam in authenticator commands
3. **Expire**: After timeout, PIN change, or certain errors
4. **Renew**: Obtain new token when expired

## Implementation Notes

### For Authenticators
- Implement secure PIN storage (same level as private keys)
- Enforce retry limits strictly
- Use constant-time comparisons for security-sensitive operations
- Properly manage token state and timeouts
- Support at least Protocol One (version 1)

### For Platforms
- Always encrypt PINs before sending to authenticator
- Request minimal necessary permissions
- Scope tokens to specific RPs when possible
- Handle token expiration gracefully
- Erase tokens from memory when no longer needed

## References

- CTAP 2.3 Specification: Section 6.5 (authenticatorClientPIN)
- PIN/UV Auth Protocol One: Section 6.5.6
- PIN/UV Auth Protocol Two: Section 6.5.7
- Existing Implementation: [`AuthenticatorAPI.java`](AuthenticatorAPI.java)
- PIN Sub-Commands Enum: [`PinSubCmd.java`](PinSubCmd.java)
- PIN/UV Auth Parameters: [`PinUvAuthParams.java`](PinUvAuthParams.java)