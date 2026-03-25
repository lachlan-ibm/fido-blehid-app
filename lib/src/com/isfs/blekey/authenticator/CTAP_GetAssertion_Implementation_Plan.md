<!--
 Copyright IBM 2026
-->
# CTAP2 GetAssertion Implementation Plan

## Overview

This document outlines the required changes to implement the CTAP2 `authenticatorGetAssertion` operation according to the CTAP v2.3 specification. The current implementation in `AuthenticatorAPI.java` (lines 873-894) is minimal and missing critical specification requirements.

## Current Implementation Analysis

### Existing Code (lines 873-894)
```java
protected static byte[] getAssertion(CtapTxn txn, Map<Integer, Object> req) {
    logger.debug("getAssertion");
    Fido2Authenticator authenticator = createAuthenticator(txn, req);
    if (authenticator == null) {
        return error(Ctap2StatusCode.OTHER);
    }
    // Process credentials from allowList and resident credentials
    ArrayList<Map<String, byte[]>> credentials = processCredentials(req, txn.getPasskey());
    if (credentials.isEmpty()) {
        return error(Ctap2StatusCode.NO_CREDENTIALS);
    }
    // Initialize authenticator with a valid credential
    if (!initializeAuthenticatorWithCredential(authenticator, credentials)) {
        return error(Ctap2StatusCode.NO_CREDENTIALS);
    }
    // Generate and sign assertion
    return generateSignedAssertion(req, authenticator);
}
```

### Issues with Current Implementation
1. **No input validation** - Missing validation for clientDataHash, rpId, allowList, options
2. **No PIN/UV authentication** - Missing verification of PIN/UV auth tokens
3. **Incomplete credential discovery** - No RP ID filtering, doesn't distinguish allowList vs discoverable scenarios
5. **No multiple credential handling** - Only uses first credential, no support for getNextAssertion
6. **No user presence collection** - Missing UP flag verification
8. **Incomplete authenticator data** - Missing UV and ED flags, no extension data
9. **Incomplete response** - Missing user info for discoverable credentials, numberOfCredentials field
10. **No permission verification** - verifyPinUvAuth checks "mc" instead of "ga" permission

## Required Changes

### 1. Input Validation (HIGH PRIORITY)

**Location:** Start of `getAssertion()` method

**Implementation:**
```java
// Validate clientDataHash (must be 32 bytes)
byte[] clientDataHash = (byte[]) req.get(0x01);
Ctap2StatusCode error = validateClientDataHash(clientDataHash);
if (error != null) {
    return error(error);
}

// Validate rpId exists
error = validateRequiredParameter(req, 0x01, "clientDataHash");
if (error != null) {
    return error(error);
}

// Extract and validate rpId from request
@SuppressWarnings("unchecked")
Map<String, Object> rp = (Map<String, Object>) req.get(0x02);
if (rp == null || rp.get("id") == null) {
    logger.error("Missing RP ID in getAssertion request");
    return error(Ctap2StatusCode.MISSING_PARAMETER);
}
String rpId = (String) rp.get("id");

// Parse and validate options
CredentialOptions options = parseOptions(req);
```

**Reference:** CTAP_Assertion_Summary.md lines 79-86

---

### 2. PIN/UV Authentication (HIGH PRIORITY)

**Location:** After input validation

**Implementation:**
```java
// Verify PIN/UV authentication
PinUvAuthResult pinUvResult = verifyPinUvAuthForAssertion(req, txn);
if (pinUvResult.errorCode != null) {
    return error(pinUvResult.errorCode);
}
boolean userVerified = pinUvResult.userVerified;
```

**New Method Required:**
```java
/**
 * Verifies PIN/UV authentication for getAssertion operation.
 * Similar to verifyPinUvAuth but checks "ga" permission instead of "mc".
 *
 * @param req The request parameters
 * @param txn The CTAP transaction
 * @return PinUvAuthResult with verification status
 */
private static PinUvAuthResult verifyPinUvAuthForAssertion(
        Map<Integer, Object> req,
        CtapTxn txn) {
    
    PinUvAuthParams params = PinUvAuthParams.parse(req);
    if (!params.isValid()) {
        return new PinUvAuthResult(false, params.errorCode);
    }
    
    // Handle zero-length pinUvAuthParam (PIN status check)
    if (params.pinUvAuthParam != null && params.pinUvAuthParam.length == 0) {
        // Check if PIN is set
        if (txn.getPasskey() != null) {
            return new PinUvAuthResult(false, Ctap2StatusCode.PIN_INVALID);
        } else {
            return new PinUvAuthResult(false, Ctap2StatusCode.PIN_NOT_SET);
        }
    }
    
    if (params.pinUvAuthParam == null) {
        if (params.uvRequested) {
            return errorResult("User verification required but no PIN/UV auth token provided",
                             Ctap2StatusCode.PIN_REQUIRED);
        }
        return PinUvAuthResult.NO_VERIFICATION;
    }
    
    // Validate protocol
    Ctap2StatusCode protocolError = validatePinUvAuthProtocol(params.pinUvAuthProtocol);
    if (protocolError != null) {
        return new PinUvAuthResult(false, protocolError);
    }
    
    // Verify token with clientDataHash (not rpIdHash for getAssertion)
    try {
        byte[] pinAuthToken = retrievePinAuthToken(txn);
        byte[] clientDataHash = (byte[]) req.get(0x01);
        
        PinUvAuthResult result = verifyPinAuthToken(pinAuthToken, params.pinUvAuthParam, 
                                                     clientDataHash, params.pinUvAuthProtocol);
        if (result.errorCode != Ctap2StatusCode.SUCCESS) {
            return result;
        }
        
        // TODO: Check token has "ga" (getAssertion) permission
        // For now, assume valid if HMAC verification passed
        
    } catch (PinAuthException e) {
        return errorResult(e.getMessage(), e.code);
    } catch (InvalidKeyException e) {
        return errorResult("Invalid key during PIN/UV auth token verification",
                         Ctap2StatusCode.PIN_AUTH_INVALID, e);
    }
    
    return PinUvAuthResult.SUCCESS;
}

/**
 * Verifies PIN auth token using clientDataHash (for getAssertion).
 * Different from makeCredential which uses rpIdHash.
 */
private static PinUvAuthResult verifyPinAuthToken(byte[] pinAuthToken, byte[] pinUvAuthParam,
                                                   byte[] clientDataHash, Integer protocol)
        throws InvalidKeyException {
    
    javax.crypto.Mac mac = HMAC_SHA256.get();
    javax.crypto.spec.SecretKeySpec keySpec =
        new javax.crypto.spec.SecretKeySpec(pinAuthToken, "HmacSHA256");
    mac.init(keySpec);
    byte[] expectedAuth = mac.doFinal(clientDataHash);
    
    // Protocol 1: first 16 bytes, Protocol 2: full 32 bytes
    int length = (protocol == 1) ? 16 : 32;
    byte[] expectedAuthTruncated = Arrays.copyOf(expectedAuth, length);
    
    if (!MessageDigest.isEqual(pinUvAuthParam, expectedAuthTruncated)) {
        logger.error("PIN/UV auth token verification failed: HMAC mismatch");
        return new PinUvAuthResult(false, Ctap2StatusCode.PIN_AUTH_INVALID);
    }
    
    return new PinUvAuthResult(true, Ctap2StatusCode.SUCCESS);
}
```

**Reference:** CTAP_Assertion_Summary.md lines 138-169

---

### 3. Enhanced Credential Discovery (HIGH PRIORITY)

**Location:** Replace `processCredentials()` method

**Implementation:**
```java
/**
 * Discovers and filters credentials for getAssertion.
 * Handles two scenarios: with allowList and without (discoverable).
 *
 * @param req The request parameters
 * @param passkey The passkey containing resident credentials
 * @param rpId The RP ID to filter by
 * @return List of matching credentials
 */
private static ArrayList<Map<String, byte[]>> discoverCredentials(
        Map<Integer, Object> req,
        Passkey passkey,
        String rpId) {
    
    ArrayList<Map<String, byte[]>> matchingCredentials = new ArrayList<>();
    
    // Get allowList from request (0x03)
    @SuppressWarnings("unchecked")
    ArrayList<Map<String, byte[]>> allowList = 
            (ArrayList<Map<String, byte[]>>) req.get(0x03);
    
    if (allowList != null && !allowList.isEmpty()) {
        // Scenario 1: With allowList - search for credentials in the list
        logger.debug("Searching credentials from allowList for RP: {}", rpId);
        
        for (Map<String, byte[]> credDescriptor : allowList) {
            byte[] credId = credDescriptor.get("id");
            if (credId != null) {
                // Check if this credential exists for this RP
                if (isCredentialValid(credId, rpId, passkey)) {
                    matchingCredentials.add(credDescriptor);
                }
            }
        }
    } else {
        // Scenario 2: Without allowList - search discoverable credentials
        logger.debug("Searching discoverable credentials for RP: {}", rpId);
        
        if (passkey != null) {
            List<Map<String, byte[]>> resCreds = passkey.getResCreds();
            if (resCreds != null) {
                byte[] rpIdBytes = rpId.getBytes(StandardCharsets.UTF_8);
                
                for (Map<String, byte[]> cred : resCreds) {
                    byte[] credRpId = cred.get("rp.id");
                    if (credRpId != null && Arrays.equals(credRpId, rpIdBytes)) {
                        matchingCredentials.add(Map.of(
                            "id", cred.get("cred.id"),
                            "user", cred.get("user.id")
                        ));
                    }
                }
            }
        }
    }
    
    logger.debug("Found {} matching credentials for RP: {}", matchingCredentials.size(), rpId);
    return matchingCredentials;
}

/**
 * Validates if a credential exists and belongs to the specified RP.
 */
private static boolean isCredentialValid(byte[] credId, String rpId, Passkey passkey) {
    // For resident credentials, check against stored credentials
    if (passkey != null) {
        List<Map<String, byte[]>> resCreds = passkey.getResCreds();
        if (resCreds != null) {
            byte[] rpIdBytes = rpId.getBytes(StandardCharsets.UTF_8);
            for (Map<String, byte[]> cred : resCreds) {
                byte[] storedCredId = cred.get("cred.id");
                byte[] storedRpId = cred.get("rp.id");
                if (Arrays.equals(credId, storedCredId) && 
                    Arrays.equals(rpIdBytes, storedRpId)) {
                    return true;
                }
            }
        }
    }
    
    // For non-resident credentials, try to decrypt/validate the credential ID
    // This would use the platform key or passkey to validate
    // TODO: Implement stateless credential validation
    
    return false;
}
```

**Reference:** CTAP_Assertion_Summary.md lines 88-106


---

### 5. Multiple Credential Handling (MEDIUM PRIORITY)

**Location:** After credential filtering

**Implementation:**
```java
/**
 * State storage for getNextAssertion support.
 */
private static class AssertionState {
    List<Map<String, byte[]>> remainingCredentials;
    String rpId;
    byte[] clientDataHash;
    boolean userPresent;
    boolean userVerified;
    
    AssertionState(List<Map<String, byte[]>> credentials, String rpId,
                   byte[] clientDataHash, boolean up, boolean uv) {
        this.remainingCredentials = new ArrayList<>(credentials);
        this.rpId = rpId;
        this.clientDataHash = clientDataHash;
        this.userPresent = up;
        this.userVerified = uv;
    }
}

// Add to class fields
private static Map<byte[], AssertionState> assertionStates = new HashMap<>();

/**
 * Selects credential and stores remaining for getNextAssertion.
 *
 * @param credentials List of matching credentials
 * @param allowListProvided Whether allowList was provided
 * @param txn The CTAP transaction
 * @return Selected credential and number of total credentials
 */
private static class CredentialSelection {
    final Map<String, byte[]> credential;
    final int numberOfCredentials;
    
    CredentialSelection(Map<String, byte[]> cred, int count) {
        this.credential = cred;
        this.numberOfCredentials = count;
    }
}

private static CredentialSelection selectCredential(
        ArrayList<Map<String, byte[]>> credentials,
        boolean allowListProvided,
        CtapTxn txn) {
    
    if (credentials.size() == 1) {
        return new CredentialSelection(credentials.get(0), 1);
    }
    
    // Multiple credentials found
    Map<String, byte[]> selected;
    
    if (!allowListProvided) {
        // Discoverable credentials - may need user selection
        // For now, use first credential
        // TODO: Implement user selection UI
        logger.warn("Multiple discoverable credentials found, using first one");
        selected = credentials.get(0);
    } else {
        // Use first matching credential from allowList
        selected = credentials.get(0);
    }
    
    // Store remaining credentials for getNextAssertion
    if (credentials.size() > 1) {
        List<Map<String, byte[]>> remaining = credentials.subList(1, credentials.size());
        // Store state keyed by channel ID
        // Note: Need to also store rpId, clientDataHash, UP/UV flags
        logger.debug("Stored {} remaining credentials for getNextAssertion", remaining.size());
    }
    
    return new CredentialSelection(selected, credentials.size());
}
```

**Reference:** CTAP_Assertion_Summary.md lines 172-191

---

### 6. User Presence Collection (HIGH PRIORITY)

**Location:** After credential selection

**Implementation:**
```java
/**
 * Collects user presence for getAssertion.
 *
 * @param options The parsed credential options
 * @param txn The CTAP transaction
 * @return true if user presence collected, false otherwise
 */
private static Ctap2StatusCode collectUserPresenceForAssertion(
        CredentialOptions options,
        CtapTxn txn) {
    
    if (!options.up) {
        // UP not required (pre-flight check or silent authentication)
        logger.debug("User presence not required");
        return null;
    }
    
    // For USB transport, user presence is implicit
    // The fact that the request arrived means the user is present
    logger.debug("User presence collected (USB transport)");
    
    // TODO: For NFC transport, check NFC userPresent flag
    // if (transport == NFC) {
    //     if (!nfcUserPresentFlag) {
    //         return Ctap2StatusCode.UP_REQUIRED;
    //     }
    //     nfcUserPresentFlag = false;
    // }
    
    return null; // Success
}
```

**Reference:** CTAP_Assertion_Summary.md lines 194-212

---

### 7. Extension Processing (LOWER PRIORITY)

**Location:** Before authenticator data building

**Implementation:**
```java
/**
 * Processes extensions for getAssertion.
 *
 * @param req The request parameters
 * @param credential The selected credential
 * @param txn The CTAP transaction
 * @return Map of extension outputs
 */
private static Map<String, Object> processAssertionExtensions(
        Map<Integer, Object> req,
        Map<String, byte[]> credential,
        CtapTxn txn) {
    
    Map<String, Object> extensionsOutput = new HashMap<>();
    
    @SuppressWarnings("unchecked")
    Map<String, Object> extensions = (Map<String, Object>) req.get(0x06);
    
    if (extensions == null || extensions.isEmpty()) {
        return extensionsOutput;
    }
    
    // Process hmac-secret extension
    if (extensions.containsKey("hmac-secret")) {
        // TODO: Implement hmac-secret processing
        // 1. Get hmac-secret key for credential
        // 2. Decrypt salt inputs using shared secret
        // 3. Generate HMAC-SHA256 outputs
        // 4. Encrypt outputs before returning
        logger.debug("hmac-secret extension requested but not implemented");
    }
    
    // Process largeBlobKey extension
    if (extensions.containsKey("largeBlobKey") && 
        Boolean.TRUE.equals(extensions.get("largeBlobKey"))) {
        // TODO: Implement largeBlobKey retrieval
        logger.debug("largeBlobKey extension requested but not implemented");
    }
    
    // Process credBlob extension
    if (extensions.containsKey("credBlob") && 
        Boolean.TRUE.equals(extensions.get("credBlob"))) {
        // TODO: Implement credBlob retrieval
        logger.debug("credBlob extension requested but not implemented");
    }
    
    return extensionsOutput;
}
```

**Reference:** CTAP_Assertion_Summary.md lines 214-255

---

### 8. Enhanced Authenticator Data Building (HIGH PRIORITY)

**Location:** Replace `generateSignedAssertion()` method

**Implementation:**
```java
/**
 * Builds authenticator data for getAssertion with proper flags.
 *
 * @param rpId The RP ID
 * @param userPresent Whether user is present
 * @param userVerified Whether user was verified
 * @param extensionsOutput Extension outputs
 * @param authenticator The authenticator instance
 * @return Authenticator data bytes
 */
private static byte[] buildAssertionAuthenticatorData(
        String rpId,
        boolean userPresent,
        boolean userVerified,
        Map<String, Object> extensionsOutput,
        Fido2Authenticator authenticator) throws Exception {
    
    ByteArrayOutputStream authDataBytes = new ByteArrayOutputStream();
    
    // 1. RP ID hash (32 bytes)
    MessageDigest digest = SHA256_DIGEST.get();
    digest.reset();
    byte[] rpIdHash = digest.digest(rpId.getBytes(StandardCharsets.UTF_8));
    authDataBytes.write(rpIdHash);
    
    // 2. Flags byte
    int flags = 0x00;
    if (userPresent) flags |= 0x01;  // UP bit
    if (userVerified) flags |= 0x04;  // UV bit
    if (extensionsOutput != null && !extensionsOutput.isEmpty()) {
        flags |= 0x80;  // ED bit
    }
    // Note: AT bit (0x40) is NOT set for getAssertion
    
    authDataBytes.write(flags);
    
    // 3. Signature counter (4 bytes, big-endian)
    byte[] counterBytes = authenticator.getCounterBytes();
    authDataBytes.write(counterBytes);
    
    // 4. Extensions data (if present)
    if (extensionsOutput != null && !extensionsOutput.isEmpty()) {
        byte[] extensionsCbor = Cbor.encode(extensionsOutput);
        authDataBytes.write(extensionsCbor);
    }
    
    return authDataBytes.toByteArray();
}
```

**Reference:** CTAP_Assertion_Summary.md lines 257-273

---

### 9. Enhanced Response Construction (MEDIUM PRIORITY)

**Location:** Replace `generateSignedAssertion()` method

**Implementation:**
```java
/**
 * Generates complete assertion response with all required fields.
 *
 * @param req The request parameters
 * @param authenticator The authenticator instance
 * @param credential The selected credential
 * @param numberOfCredentials Total number of matching credentials
 * @param userPresent Whether user is present
 * @param userVerified Whether user was verified
 * @param extensionsOutput Extension outputs
 * @return Assertion response bytes
 */
private static byte[] buildAssertionResponse(
        Map<Integer, Object> req,
        Fido2Authenticator authenticator,
        Map<String, byte[]> credential,
        int numberOfCredentials,
        boolean userPresent,
        boolean userVerified,
        Map<String, Object> extensionsOutput) {
    
    try {
        // Extract RP ID
        @SuppressWarnings("unchecked")
        Map<String, Object> rp = (Map<String, Object>) req.get(0x02);
        String rpId = (String) rp.get("id");
        
        // Build authenticator data
        byte[] authData = buildAssertionAuthenticatorData(
            rpId, userPresent, userVerified, extensionsOutput, authenticator);
        
        // Generate signature
        byte[] clientDataHash = (byte[]) req.get(0x01);
        ByteBuffer bb = ByteBuffer.allocate(authData.length + clientDataHash.length);
        bb.put(authData);
        bb.put(clientDataHash);
        byte[] sig = authenticator.signData(
            bb.array(), authenticator.getPrivKey(), "SHA256withECDSA");
        
        // Build credential descriptor
        Map<String, Object> credDescriptor = Map.of(
            "type", "public-key",
            "id", credential.get("id")
        );
        
        // Build response map
        Map<Integer, Object> response = new HashMap<>();
        response.put(0x01, credDescriptor);  // credential
        response.put(0x02, authData);         // authData
        response.put(0x03, sig);              // signature
        
        // Include user info for discoverable credentials
        byte[] userId = credential.get("user");
        if (userId != null) {
            Map<String, Object> user = Map.of("id", userId);
            // TODO: Add user.name and user.displayName if available
            response.put(0x04, user);
        }
        
        // Include numberOfCredentials if multiple found
        if (numberOfCredentials > 1) {
            response.put(0x05, numberOfCredentials);
        }
        
        return success(Cbor.encode(response));
        
    } catch (Exception e) {
        logger.error("Failed to build assertion response", e);
        return error(Ctap2StatusCode.OTHER);
    }
}
```

**Reference:** CTAP_Assertion_Summary.md lines 284-309

---

### 10. GetNextAssertion Implementation (LOWER PRIORITY)

**Location:** New method in AuthenticatorAPI

**Implementation:**
```java
/**
 * Processes getNextAssertion request (CTAP2 command 0x08).
 * Returns the next assertion from stored credentials.
 *
 * @param txn The CTAP transaction
 * @param req The request parameters (empty for getNextAssertion)
 * @return Assertion response bytes
 */
protected static byte[] getNextAssertion(CtapTxn txn, Map<Integer, Object> req) {
    logger.debug("getNextAssertion");
    
    // Retrieve assertion state for this channel
    AssertionState state = assertionStates.get(txn.getCid());
    
    if (state == null || state.remainingCredentials.isEmpty()) {
        logger.error("No remaining credentials for getNextAssertion");
        return error(Ctap2StatusCode.NOT_ALLOWED);
    }
    
    // Get next credential
    Map<String, byte[]> nextCredential = state.remainingCredentials.remove(0);
    
    // Create authenticator
    Fido2Authenticator authenticator = createAuthenticator(txn, req);
    if (authenticator == null) {
        return error(Ctap2StatusCode.OTHER);
    }
    
    // Initialize with credential
    try {
        authenticator.initFromCredId(nextCredential.get("id"));
    } catch (Exception e) {
        logger.error("Failed to initialize authenticator with credential", e);
        return error(Ctap2StatusCode.NO_CREDENTIALS);
    }
    
    // Build response (no user presence needed, use stored flags)
    Map<Integer, Object> mockReq = Map.of(
        0x01, state.clientDataHash,
        0x02, Map.of("id", state.rpId)
    );
    
    return buildAssertionResponse(
        mockReq,
        authenticator,
        nextCredential,
        1, // numberOfCredentials not included for getNextAssertion
        state.userPresent,
        state.userVerified,
        null // No extensions for getNextAssertion
    );
}
```

**Reference:** CTAP_Assertion_Summary.md lines 314-367

---

## Refactored getAssertion Method

### Complete Implementation

```java
/**
 * Processes a getAssertion request (CTAP2 authenticatorGetAssertion command).
 * Signs a challenge using an existing credential.
 *
 * @param txn The CTAP transaction
 * @param req The request parameters
 * @return A byte array containing the response
 */
protected static byte[] getAssertion(CtapTxn txn, Map<Integer, Object> req) {
    logger.debug("getAssertion");
    
    // Step 1: Input Validation
    byte[] clientDataHash = (byte[]) req.get(0x01);
    Ctap2StatusCode error = validateClientDataHash(clientDataHash);
    if (error != null) {
        return error(error);
    }
    
    @SuppressWarnings("unchecked")
    Map<String, Object> rp = (Map<String, Object>) req.get(0x02);
    if (rp == null || rp.get("id") == null) {
        logger.error("Missing RP ID in getAssertion request");
        return error(Ctap2StatusCode.MISSING_PARAMETER);
    }
    String rpId = (String) rp.get("id");
    
    CredentialOptions options = parseOptions(req);
    
    // Step 2: PIN/UV Authentication
    PinUvAuthResult pinUvResult = verifyPinUvAuthForAssertion(req, txn);
    if (pinUvResult.errorCode != null) {
        return error(pinUvResult.errorCode);
    }
    boolean userVerified = pinUvResult.userVerified;
    
    // Step 3: Credential Discovery
    ArrayList<Map<String, byte[]>> credentials = 
        discoverCredentials(req, txn.getPasskey(), rpId);
    
    if (credentials.isEmpty()) {
        logger.debug("No credentials found for RP: {}", rpId);
        return error(Ctap2StatusCode.NO_CREDENTIALS);
    }
    
    // Step 4: Apply Credential Protection Policies
    boolean allowListProvided = req.get(0x03) != null;
    credentials = filterByCredProtect(credentials, allowListProvided, userVerified);
    
    if (credentials.isEmpty()) {
        logger.debug("All credentials filtered by credProtect policies");
        return error(Ctap2StatusCode.NO_CREDENTIALS);
    }
    
    // Step 5: Select Credential
    CredentialSelection selection = selectCredential(credentials, allowListProvided, txn);
    Map<String, byte[]> selectedCredential = selection.credential;
    
    // Step 6: Collect User Presence
    error = collectUserPresenceForAssertion(options, txn);
    if (error != null) {
        return error(error);
    }
    boolean userPresent = options.up;
    
    // Step 7: Process Extensions
    Map<String, Object> extensionsOutput = 
        processAssertionExtensions(req, selectedCredential, txn);
    
    // Step 8: Create Authenticator and Initialize
    Fido2Authenticator authenticator = createAuthenticator(txn, req);
    if (authenticator == null) {
        logger.error("Failed to create authenticator");
        return error(Ctap2StatusCode.OTHER);
    }
    
    try {
        authenticator.initFromCredId(selectedCredential.get("id"));
    } catch (Exception e) {
        logger.error("Failed to initialize authenticator with credential", e);
        return error(Ctap2StatusCode.NO_CREDENTIALS);
    }
    
    // Step 9: Build and Return Response
    return buildAssertionResponse(
        req,
        authenticator,
        selectedCredential,
        selection.numberOfCredentials,
        userPresent,
        userVerified,
        extensionsOutput
    );
}
```

---

## Implementation Priority

### Phase 1: Core Functionality (HIGH PRIORITY)
1. Input validation
2. PIN/UV authentication for getAssertion
3. Enhanced credential discovery with RP filtering
4. User presence collection
5. Enhanced authenticator data building
6. Enhanced response construction

**Estimated Time:** 12-16 hours

### Phase 2: Compliance (MEDIUM PRIORITY)
7. Credential protection filtering
8. Multiple credential handling
9. Response with user info and numberOfCredentials

**Estimated Time:** 8-10 hours

### Phase 3: Advanced Features (LOWER PRIORITY)
11. GetNextAssertion implementation
12. User selection for multiple discoverable credentials

**Estimated Time:** 10-12 hours

**Total Estimated Time:** 30-38 hours

---

## Testing Strategy

### Unit Tests

1. **Input Validation Tests**
   - Valid clientDataHash (32 bytes)
   - Invalid clientDataHash (wrong length)
   - Missing RP ID
   - Valid options parsing

2. **PIN/UV Authentication Tests**
   - Valid authentication with correct pinUvAuthParam
   - Invalid HMAC (wrong pinUvAuthParam)
   - Zero-length pinUvAuthParam (PIN status check)
   - UV required without auth token
   - Invalid protocol version

3. **Credential Discovery Tests**
   - With allowList: find matching credentials
   - Without allowList: find discoverable credentials
   - RP ID filtering
   - No credentials found

4. **Credential Protection Tests**
   - userVerificationOptional: no filtering
   - userVerificationOptionalWithCredentialIDList: requires allowList
   - userVerificationRequired: requires UV

5. **Multiple Credential Tests**
   - Single credential selection
   - Multiple credentials with allowList
   - Multiple discoverable credentials
   - GetNextAssertion flow

6. **Authenticator Data Tests**
   - Proper flag setting (UP, UV, ED)
   - Counter increment
   - Extension data inclusion

7. **Response Construction Tests**
   - Basic response structure
   - User info for discoverable credentials
   - numberOfCredentials field
   - Extension outputs

### Integration Tests

1. **Full getAssertion Flow**
   - Complete flow with PIN/UV auth
   - Resident credential assertion
   - Non-resident credential assertion

2. **Multiple Credentials Flow**
   - getAssertion with multiple matches
   - getNextAssertion calls
   - State management

3. **Cross-RP Tests**
   - Credentials isolated by RP ID
   - No credential leakage between RPs

---

## Error Handling

All CTAP2 error codes should be properly handled:

- `NO_CREDENTIALS` (0x2E): No matching credentials found
- `PIN_REQUIRED` (0x36): PIN authentication needed
- `PIN_AUTH_INVALID` (0x33): Invalid PIN auth
- `PIN_INVALID` (0x31): PIN check failed (zero-length param)
- `PIN_NOT_SET` (0x35): PIN not set (zero-length param)
- `UP_REQUIRED` (0x3B): User presence required
- `USER_ACTION_TIMEOUT` (0x3A): User didn't respond in time
- `NOT_ALLOWED` (0x30): No more credentials (getNextAssertion)
- `MISSING_PARAMETER` (0x14): Required parameter missing
- `INVALID_PARAMETER` (0x02): Parameter validation failed
- `OTHER` (0x7F): Generic error

---

## Key Differences from MakeCredential

1. **No Credential Creation**: Uses existing credentials
2. **Credential Discovery**: Must find matching credentials
3. **Multiple Credentials**: May return multiple assertions
4. **User Selection**: May require user to select credential
5. **Credential Protection**: Must respect credProtect policies
6. **No Attestation**: Returns signature, not attestation statement
7. **Extension Outputs**: Different extensions (hmac-secret outputs, largeBlobKey retrieval)
8. **PIN/UV Verification**: Uses clientDataHash instead of rpIdHash
9. **Permission Check**: Requires "ga" permission instead of "mc"

---

## Security Considerations

1. **Credential Isolation**: Only return credentials for the correct RP ID
2. **Counter Management**: Properly increment signature counters to detect cloning
3. **User Verification**: Validate PIN/UV auth tokens correctly
4. **User Presence**: Ensure genuine user interaction
5. **Credential Protection**: Enforce credProtect policies
6. **Timing Attacks**: Use constant-time comparisons for sensitive data
7. **Extension Security**: Properly encrypt/decrypt extension data (hmac-secret)
8. **Multiple Credentials**: Securely store state between getAssertion and getNextAssertion

---

## References

- CTAP 2.3 Specification: `Client to Authenticator Protocol (CTAP) - fido-client-to-authenticator-protocol-v2.3-rd-20251023.pdf`
- Assertion Summary: `lib/src/com/isfs/blekey/authenticator/CTAP_Assertion_Summary.md`
- Existing Implementation: `lib/src/com/isfs/blekey/authenticator/AuthenticatorAPI.java` (lines 873-894)
- MakeCredential Plan: `lib/src/com/isfs/blekey/authenticator/CTAP_MakeCredential_Implementation_Plan.md`
- PIN/UV Auth Plan: `lib/src/com/isfs/blekey/authenticator/PIN_UV_AUTH_VERIFICATION_PLAN.md`