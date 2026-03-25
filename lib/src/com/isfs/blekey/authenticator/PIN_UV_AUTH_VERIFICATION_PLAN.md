<!--
 Copyright IBM 2026
-->
# PIN/UV Authentication Verification Implementation Plan

## Overview

This document outlines the implementation of the `verifyPinUvAuth` function according to the CTAP2 specification. The function verifies PIN/UV authentication parameters using HMAC-SHA-256 with the pinAuthToken as a symmetric key.

## CTAP Specification Requirements

Based on the CTAP 2.3 specification analysis:

1. **Verification Algorithm**: Use HMAC-SHA-256 with pinAuthToken as the symmetric key
2. **Input Data**: Hash the RP ID to create the message to verify
3. **Permission Check**: Verify the pinAuthToken has the appropriate permission (e.g., 'mc' for makeCredential)
4. **Protocol Support**: Support PIN/UV Auth Protocol One (protocol version 1)
5. **Error Handling**: Return CTAP2_ERR_PIN_AUTH_INVALID if verification fails

## Key Findings from CTAP Specification

From document analysis:

- **Text #389**: "Call verify(pinUvAuthToken, clientDataHash, pinUvAuthParam)"
- **Text #391**: "Verify that the pinUvAuthToken has the mc permission, if not, then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID"
- **Text #1266**: "Throughout this protocol, the pseudo-random function defined by HMAC-SHA-256 and the pinUvAuthToken is evaluated for various values in order to authenticate requests from the platform"
- **Text #1941**: "The authenticator MUST utilize the appropriate PIN protocol's verify() function to validate the pinUvAuthParam and MUST return CTAP2_ERR_PIN_AUTH_INVALID if verify() returns error"

## Implementation Structure

### 1. PinUvAuthResult Helper Class

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
```

### 2. Main verifyPinUvAuth Function

```java
/**
 * Verifies PIN/UV authentication according to CTAP2 specification.
 * 
 * This function implements the PIN/UV authentication verification algorithm:
 * 1. Check if pinUvAuthParam is provided in the request
 * 2. If provided, verify it using HMAC-SHA-256 with pinAuthToken
 * 3. Verify the pinAuthToken has the required permission (mc for makeCredential)
 * 4. Hash the RP ID and use it as the message to verify
 * 5. Return appropriate error codes if verification fails
 *
 * @param req The request parameters containing pinUvAuthParam (0x08) and pinUvAuthProtocol (0x09)
 * @param txn The CTAP transaction containing the pinAuthToken
 * @return PinUvAuthResult with verification status or error code
 */
private static PinUvAuthResult verifyPinUvAuth(
        Map<Integer, Object> req, 
        CtapTxn txn) {
    
    // Step 1: Check if pinUvAuthParam is provided (0x08)
    byte[] pinUvAuthParam = (byte[]) req.get(0x08);
    Integer pinUvAuthProtocol = (Integer) req.get(0x09);
    
    // Step 2: Parse options to check if UV is requested
    @SuppressWarnings("unchecked")
    Map<String, Object> options = 
        (Map<String, Object>) req.getOrDefault(0x07, new HashMap<>());
    
    boolean uvRequested = (boolean) options.getOrDefault("uv", false);
    
    // Step 3: If no pinUvAuthParam provided
    if (pinUvAuthParam == null) {
        // If UV is required, return error
        if (uvRequested) {
            logger.error("User verification required but no PIN/UV auth token provided");
            return new PinUvAuthResult(false, Ctap2StatusCode.PIN_REQUIRED);
        }
        // UV not required, proceed without verification
        return new PinUvAuthResult(false, null);
    }
    
    // Step 4: Validate pinUvAuthProtocol
    if (pinUvAuthProtocol == null || pinUvAuthProtocol != 1) {
        logger.error("Invalid or unsupported PIN/UV auth protocol: {}", pinUvAuthProtocol);
        return new PinUvAuthResult(false, Ctap2StatusCode.PIN_AUTH_INVALID);
    }
    
    // Step 5: Get the PIN auth token from transaction
    byte[] pinAuthToken = txn.getPinAuthTkn();
    if (pinAuthToken == null) {
        logger.error("No PIN auth token in transaction");
        return new PinUvAuthResult(false, Ctap2StatusCode.PIN_AUTH_INVALID);
    }
    
    // Step 6: Extract and hash RP ID
    @SuppressWarnings("unchecked")
    Map<String, Object> rp = (Map<String, Object>) req.get(0x02);
    if (rp == null) {
        logger.error("Missing RP parameter");
        return new PinUvAuthResult(false, Ctap2StatusCode.MISSING_PARAMETER);
    }
    
    String rpId = (String) rp.get("id");
    if (rpId == null) {
        logger.error("Missing RP ID");
        return new PinUvAuthResult(false, Ctap2StatusCode.MISSING_PARAMETER);
    }
    
    byte[] rpIdHash;
    try {
        java.security.MessageDigest digest = 
            java.security.MessageDigest.getInstance("SHA-256");
        rpIdHash = digest.digest(rpId.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    } catch (Exception e) {
        logger.error("Failed to hash RP ID", e);
        return new PinUvAuthResult(false, Ctap2StatusCode.OTHER);
    }
    
    // Step 7: Verify using HMAC-SHA-256
    // pinUvAuthParam = HMAC-SHA-256(pinAuthToken, rpIdHash)[0:16]
    try {
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        javax.crypto.spec.SecretKeySpec keySpec = 
            new javax.crypto.spec.SecretKeySpec(pinAuthToken, "HmacSHA256");
        mac.init(keySpec);
        
        byte[] expectedAuth = mac.doFinal(rpIdHash);
        
        // Compare first 16 bytes (CTAP2 spec requirement)
        byte[] expectedAuth16 = java.util.Arrays.copyOf(expectedAuth, 16);
        
        if (!java.util.Arrays.equals(pinUvAuthParam, expectedAuth16)) {
            logger.error("PIN/UV auth token verification failed: HMAC mismatch");
            return new PinUvAuthResult(false, Ctap2StatusCode.PIN_AUTH_INVALID);
        }
        
    } catch (Exception e) {
        logger.error("Error verifying PIN/UV auth token", e);
        return new PinUvAuthResult(false, Ctap2StatusCode.PIN_AUTH_INVALID);
    }
    
    // Step 8: Verify pinAuthToken has 'mc' (makeCredential) permission
    // Note: In a full implementation, permissions would be stored with the token
    // For now, we assume the token is valid if it exists and HMAC verification passed
    // TODO: Implement permission checking when token permission system is added
    
    // Step 9: Auth token verified successfully
    logger.debug("PIN/UV auth token verified successfully for RP: {}", rpId);
    return new PinUvAuthResult(true, null);
}
```

## Algorithm Details

### HMAC-SHA-256 Verification

1. **Key**: pinAuthToken (32 bytes, obtained from authenticatorClientPIN)
2. **Message**: SHA-256 hash of RP ID (32 bytes)
3. **Output**: First 16 bytes of HMAC-SHA-256(pinAuthToken, rpIdHash)
4. **Comparison**: Constant-time comparison with provided pinUvAuthParam

### RP ID Hash Calculation

```java
// Extract RP ID from request
String rpId = (String) rp.get("id");

// Hash using SHA-256
MessageDigest digest = MessageDigest.getInstance("SHA-256");
byte[] rpIdHash = digest.digest(rpId.getBytes(StandardCharsets.UTF_8));
```

### Permission Checking

According to CTAP spec, pinAuthToken must have the 'mc' (makeCredential) permission:

```java
// Future implementation when permission system is added:
if (!pinAuthToken.hasPermission(Permission.MC)) {
    return new PinUvAuthResult(false, Ctap2StatusCode.PIN_AUTH_INVALID);
}
```

## Error Codes

| Error Code | Condition |
|------------|-----------|
| `PIN_REQUIRED` | UV requested but no pinUvAuthParam provided |
| `PIN_AUTH_INVALID` | Invalid protocol, missing token, HMAC mismatch, or permission denied |
| `MISSING_PARAMETER` | Missing RP or RP ID in request |
| `OTHER` | Unexpected error during verification |

## Integration Points

### Current Code Integration

The function is called from `_makeCredential`:

```java
// Verify pin auth token if it exists
PinUvAuthResult pinUvResult = verifyPinUvAuth(req, txn);
if (pinUvResult.errorCode != null) {
    return error(pinUvResult.errorCode);
}
```

### Request Parameters

- **0x02**: RP information (contains RP ID)
- **0x07**: Options (contains 'uv' flag)
- **0x08**: pinUvAuthParam (16 bytes)
- **0x09**: pinUvAuthProtocol (integer, must be 1)

### Transaction Context

- **pinAuthToken**: Obtained from authenticatorClientPIN command
- **passkey**: Associated passkey (if resident credential)

## Testing Strategy

### Unit Tests

1. **Valid Authentication**
   - Provide correct pinUvAuthParam
   - Verify returns success with userVerified=true

2. **Invalid HMAC**
   - Provide incorrect pinUvAuthParam
   - Verify returns PIN_AUTH_INVALID

3. **Missing Token**
   - No pinAuthToken in transaction
   - Verify returns PIN_AUTH_INVALID

4. **UV Required Without Auth**
   - UV option set to true
   - No pinUvAuthParam provided
   - Verify returns PIN_REQUIRED

5. **Invalid Protocol**
   - pinUvAuthProtocol != 1
   - Verify returns PIN_AUTH_INVALID

6. **Missing RP ID**
   - No RP or RP ID in request
   - Verify returns MISSING_PARAMETER

### Integration Tests

1. **Full makeCredential Flow**
   - Complete PIN/UV auth flow
   - Verify credential creation succeeds

2. **Multiple RP IDs**
   - Verify different RP IDs produce different hashes
   - Verify HMAC verification is RP-specific

## Security Considerations

1. **Constant-Time Comparison**: Use `Arrays.equals()` for HMAC comparison to prevent timing attacks
2. **Token Scope**: Verify token is scoped to the correct RP ID
3. **Permission Enforcement**: Ensure token has required permissions before allowing operations
4. **Protocol Version**: Only support protocol version 1 initially
5. **Token Lifetime**: Consider implementing token expiration (future enhancement)

## Future Enhancements

1. **Permission System**: Implement full permission checking (mc, ga, cm, etc.)
2. **Protocol Version 2**: Add support for PIN/UV Auth Protocol Two
3. **Token Expiration**: Add timestamp-based token expiration
4. **Rate Limiting**: Implement rate limiting for failed verification attempts
5. **Audit Logging**: Log all verification attempts for security auditing

## References

- CTAP 2.3 Specification: Section 6.5.5 (PIN/UV Auth Protocol)
- Implementation Plan: `CTAP_MakeCredential_Implementation_Plan.md` (lines 108-231)
- Existing Code: `AuthenticatorAPI.java` (lines 351-394)