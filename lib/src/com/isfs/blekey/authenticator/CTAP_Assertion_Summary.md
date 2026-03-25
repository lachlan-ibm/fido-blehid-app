<!--
 Copyright IBM 2026
-->
# CTAP Assertion Steps Summary

Based on the FIDO Client to Authenticator Protocol (CTAP) v2.3 specification, here is a summary of the assertion steps and a pseudocode algorithm for authenticating with a credential.

## Assertion Overview

Assertion in CTAP occurs during the **authenticatorGetAssertion** operation (command 0x02). This operation generates a cryptographic signature proving possession of a private key associated with a previously registered credential, thereby authenticating the user.

## Key Assertion Steps in authenticatorGetAssertion

### 1. **Input Validation**
- Validate rpId (Relying Party identifier)
- Validate clientDataHash (32 bytes)
- Validate allowList (list of acceptable credential IDs)
- Process options (up, uv)
- Validate extensions

### 2. **Credential Discovery**
Two scenarios:
- **With allowList**: Search for matching credentials from the provided list
- **Without allowList** (discoverable credentials): Search stored credentials for the RP ID

### 3. **User Verification & Presence**
- Check if user verification (uv) is required
- Verify PIN/UV auth token if provided
- Collect evidence of user interaction (user presence)
- For NFC: Check NFC userPresent flag and timer
- For other transports: Collect user gesture interactively

### 4. **Credential Selection**
- If multiple credentials found, may require user selection
- Platform may call authenticatorGetNextAssertion for additional credentials
- Apply credential protection policies (credProtect extension)

### 5. **Signature Generation**
The authenticator creates an assertion containing:

#### a. **Authenticator Data Structure**
- RP ID hash (32 bytes)
- Flags byte (UP, UV, ED bits)
- Signature counter (4 bytes)
- Extensions data (if present)

#### b. **Assertion Signature**
- Sign over (authenticatorData || clientDataHash) using credential private key
- Signature format depends on algorithm (ECDSA, RSA, EdDSA)

### 6. **Response Construction**
Return assertion object containing:
- credential: Credential descriptor {type, id}
- authData: Authenticator data bytes
- signature: Cryptographic signature
- user: User information (if discoverable credential)
- numberOfCredentials: Count of matching credentials (if multiple)

### 7. **Extension Processing**
- Handle hmac-secret (generate HMAC outputs)
- Handle largeBlobKey (return large blob key)
- Handle credBlob (return credential blob)
- Other extension outputs

## Pseudocode Algorithm for Generating an Assertion

```pseudocode
FUNCTION authenticatorGetAssertion(
    rpId,                // Relying Party identifier
    clientDataHash,      // 32-byte hash from platform
    allowList,           // Optional list of credential descriptors
    extensions,          // Optional extensions
    options,             // {up, uv} flags
    pinUvAuthParam,      // PIN/UV auth parameter
    pinUvAuthProtocol    // PIN/UV protocol version
) RETURNS assertionResponse OR error

BEGIN
    // Step 1: Validate Inputs
    IF length(clientDataHash) != 32 THEN
        RETURN CTAP2_ERR_INVALID_CBOR
    END IF
    
    IF NOT isValidRpId(rpId) THEN
        RETURN CTAP2_ERR_INVALID_PARAMETER
    END IF
    
    // Step 2: Find Matching Credentials
    matchingCredentials = []
    
    IF allowList IS PROVIDED AND NOT EMPTY THEN
        // Search for credentials in allowList
        FOR EACH credDescriptor IN allowList DO
            credential = findCredential(rpId, credDescriptor.id)
            IF credential EXISTS THEN
                matchingCredentials.append(credential)
            END IF
        END FOR
    ELSE
        // Search for discoverable credentials for this RP
        matchingCredentials = findDiscoverableCredentials(rpId)
    END IF
    
    IF matchingCredentials IS EMPTY THEN
        RETURN CTAP2_ERR_NO_CREDENTIALS
    END IF
    
    // Step 3: Apply Credential Protection Policies
    filteredCredentials = []
    FOR EACH credential IN matchingCredentials DO
        protectionLevel = getCredProtectLevel(credential)
        
        SWITCH protectionLevel DO
            CASE userVerificationOptional:
                // No filtering needed
                filteredCredentials.append(credential)
                
            CASE userVerificationOptionalWithCredentialIDList:
                // Only allow if credential was in allowList
                IF allowList IS PROVIDED THEN
                    filteredCredentials.append(credential)
                END IF
                
            CASE userVerificationRequired:
                // Only allow if user verification will be performed
                IF options.uv OR pinUvAuthParam IS PROVIDED THEN
                    filteredCredentials.append(credential)
                END IF
        END SWITCH
    END FOR
    
    IF filteredCredentials IS EMPTY THEN
        RETURN CTAP2_ERR_NO_CREDENTIALS
    END IF
    
    matchingCredentials = filteredCredentials
    
    // Step 4: Process PIN/UV Authentication
    requireUserVerification = options.uv OR alwaysUv
    
    IF pinUvAuthParam IS PROVIDED THEN
        // Verify PIN/UV auth token
        IF length(pinUvAuthParam) == 0 THEN
            // Zero-length param is a check for PIN status
            IF clientPinSet THEN
                RETURN CTAP2_ERR_PIN_INVALID
            ELSE
                RETURN CTAP2_ERR_PIN_NOT_SET
            END IF
        END IF
        
        IF NOT verifyPinUvAuthToken(pinUvAuthParam, clientDataHash, pinUvAuthProtocol) THEN
            RETURN CTAP2_ERR_PIN_AUTH_INVALID
        END IF
        
        // Check if token has required permissions
        IF NOT hasPermission(pinUvAuthToken, "ga") THEN  // "ga" = getAssertion
            RETURN CTAP2_ERR_PIN_AUTH_INVALID
        END IF
        
        userVerified = true
    ELSE IF requireUserVerification THEN
        IF NOT (clientPinSet OR builtInUvAvailable) THEN
            RETURN CTAP2_ERR_PIN_NOT_SET
        END IF
        RETURN CTAP2_ERR_PIN_REQUIRED
    ELSE
        userVerified = false
    END IF
    
    // Step 5: Select Credential
    IF length(matchingCredentials) > 1 THEN
        // Multiple credentials found
        IF allowList IS NOT PROVIDED THEN
            // Discoverable credentials - may need user selection
            selectedCredential = selectCredentialWithUserInteraction(matchingCredentials)
            IF selectedCredential IS NULL THEN
                RETURN CTAP2_ERR_USER_ACTION_TIMEOUT
            END IF
        ELSE
            // Use first matching credential from allowList
            selectedCredential = matchingCredentials[0]
        END IF
        
        // Store remaining credentials for getNextAssertion
        storeRemainingCredentials(matchingCredentials[1:])
        numberOfCredentials = length(matchingCredentials)
    ELSE
        selectedCredential = matchingCredentials[0]
        numberOfCredentials = 1
    END IF
    
    // Step 6: Collect User Presence
    IF options.up == true THEN
        IF transport == NFC THEN
            IF nfcUserPresentFlag == true THEN
                userPresent = true
                nfcUserPresentFlag = false
            ELSE
                RETURN CTAP2_ERR_UP_REQUIRED
            END IF
        ELSE
            // Wait for user gesture (touch, button press)
            IF NOT waitForUserGesture(timeout=30s) THEN
                RETURN CTAP2_ERR_USER_ACTION_TIMEOUT
            END IF
            userPresent = true
        END IF
    ELSE
        // Pre-flight check or silent authentication
        userPresent = false
    END IF
    
    // Step 7: Process Extensions
    extensionsOutput = {}
    
    IF extensions.hmacSecret IS PROVIDED THEN
        hmacSecretKey = getHmacSecretKey(selectedCredential)
        IF hmacSecretKey EXISTS THEN
            // Decrypt salt inputs using shared secret
            salt1 = decryptSalt(extensions.hmacSecret.salt1, sharedSecret)
            
            IF extensions.hmacSecret.salt2 EXISTS THEN
                salt2 = decryptSalt(extensions.hmacSecret.salt2, sharedSecret)
                output2 = HMAC-SHA256(hmacSecretKey, salt2)
            ELSE
                output2 = NULL
            END IF
            
            output1 = HMAC-SHA256(hmacSecretKey, salt1)
            
            // Encrypt outputs
            encryptedOutput1 = encrypt(output1, sharedSecret)
            IF output2 EXISTS THEN
                encryptedOutput2 = encrypt(output2, sharedSecret)
                extensionsOutput.hmacSecret = encryptedOutput1 || encryptedOutput2
            ELSE
                extensionsOutput.hmacSecret = encryptedOutput1
            END IF
        END IF
    END IF
    
    IF extensions.largeBlobKey == true THEN
        largeBlobKey = getLargeBlobKey(selectedCredential)
        IF largeBlobKey EXISTS THEN
            extensionsOutput.largeBlobKey = largeBlobKey
        END IF
    END IF
    
    IF extensions.credBlob == true THEN
        credBlob = getCredBlob(selectedCredential)
        IF credBlob EXISTS THEN
            extensionsOutput.credBlob = credBlob
        END IF
    END IF
    
    // Step 8: Build Authenticator Data
    rpIdHash = SHA256(rpId)
    
    flags = 0x00
    IF userPresent THEN flags |= 0x01  // UP bit
    IF userVerified THEN flags |= 0x04  // UV bit
    IF extensionsOutput NOT EMPTY THEN flags |= 0x80  // ED bit
    
    signatureCounter = getAndIncrementCounter(selectedCredential)
    
    authenticatorData = rpIdHash || 
                       bytes(flags) || 
                       uint32BE(signatureCounter)
    
    IF extensionsOutput NOT EMPTY THEN
        authenticatorData ||= encodeCBOR(extensionsOutput)
    END IF
    
    // Step 9: Generate Signature
    signatureBase = authenticatorData || clientDataHash
    
    signature = sign(
        signatureBase,
        selectedCredential.privateKey,
        selectedCredential.algorithm
    )
    
    // Step 10: Build Response
    response = {
        credential: {
            type: "public-key",
            id: selectedCredential.credentialId
        },
        authData: authenticatorData,
        signature: signature
    }
    
    // Include user info for discoverable credentials
    IF selectedCredential.isDiscoverable THEN
        response.user = {
            id: selectedCredential.userId,
            name: selectedCredential.userName,
            displayName: selectedCredential.userDisplayName
        }
    END IF
    
    // Include credential count if multiple found
    IF numberOfCredentials > 1 THEN
        response.numberOfCredentials = numberOfCredentials
    END IF
    
    // Step 11: Return Success
    RETURN response
    
END FUNCTION

// Helper Function for Getting Next Assertion
FUNCTION authenticatorGetNextAssertion() RETURNS assertionResponse OR error
BEGIN
    // Retrieve next credential from stored list
    remainingCredentials = getRemainingCredentials()
    
    IF remainingCredentials IS EMPTY THEN
        RETURN CTAP2_ERR_NOT_ALLOWED
    END IF
    
    nextCredential = remainingCredentials[0]
    removeFromRemainingCredentials(nextCredential)
    
    // Build authenticator data (no user presence needed)
    rpIdHash = SHA256(getCurrentRpId())
    
    flags = 0x00
    // UP and UV flags are set based on original request
    IF originalRequestHadUserPresence THEN flags |= 0x01
    IF originalRequestHadUserVerification THEN flags |= 0x04
    
    signatureCounter = getAndIncrementCounter(nextCredential)
    
    authenticatorData = rpIdHash || 
                       bytes(flags) || 
                       uint32BE(signatureCounter)
    
    // Generate signature
    signatureBase = authenticatorData || getStoredClientDataHash()
    signature = sign(
        signatureBase,
        nextCredential.privateKey,
        nextCredential.algorithm
    )
    
    // Build response
    response = {
        credential: {
            type: "public-key",
            id: nextCredential.credentialId
        },
        authData: authenticatorData,
        signature: signature
    }
    
    IF nextCredential.isDiscoverable THEN
        response.user = {
            id: nextCredential.userId,
            name: nextCredential.userName,
            displayName: nextCredential.userDisplayName
        }
    END IF
    
    RETURN response
END FUNCTION

// Helper Functions

FUNCTION findCredential(rpId, credentialId) RETURNS credential OR null
BEGIN
    // Search for credential by RP ID and credential ID
    // May decrypt credential ID if using stateless approach
    credential = lookupCredential(rpId, credentialId)
    RETURN credential
END FUNCTION

FUNCTION findDiscoverableCredentials(rpId) RETURNS list<credential>
BEGIN
    // Search stored discoverable credentials for this RP
    credentials = queryStoredCredentials(rpId)
    RETURN credentials
END FUNCTION

FUNCTION getCredProtectLevel(credential) RETURNS protectionLevel
BEGIN
    // Get credential protection level
    // Default is userVerificationOptional if not set
    level = credential.credProtectLevel
    IF level IS NULL THEN
        RETURN userVerificationOptional
    END IF
    RETURN level
END FUNCTION

FUNCTION selectCredentialWithUserInteraction(credentials) RETURNS credential OR null
BEGIN
    // Display credential list to user
    // User selects which credential to use
    // May show user names/display names
    
    displayCredentialList(credentials)
    selectedIndex = waitForUserSelection(timeout=30s)
    
    IF selectedIndex IS NULL THEN
        RETURN null
    END IF
    
    RETURN credentials[selectedIndex]
END FUNCTION

FUNCTION sign(data, privateKey, algorithm) RETURNS signature
BEGIN
    SWITCH algorithm DO
        CASE ES256:  // ECDSA with P-256 and SHA-256
            RETURN ECDSA-SHA256(data, privateKey)
        CASE ES384:  // ECDSA with P-384 and SHA-384
            RETURN ECDSA-SHA384(data, privateKey)
        CASE ES512:  // ECDSA with P-521 and SHA-512
            RETURN ECDSA-SHA512(data, privateKey)
        CASE RS256:  // RSA with SHA-256
            RETURN RSA-PKCS1-SHA256(data, privateKey)
        CASE EdDSA:  // EdDSA
            RETURN EdDSA-Sign(data, privateKey)
        DEFAULT:
            RETURN error
    END SWITCH
END FUNCTION

FUNCTION verifyPinUvAuthToken(pinUvAuthParam, clientDataHash, protocol) RETURNS boolean
BEGIN
    // Verify the PIN/UV auth token
    // Check HMAC over clientDataHash using pinUvAuthToken
    
    IF protocol == 1 THEN
        // PIN/UV Auth Protocol One
        expectedHmac = HMAC-SHA256(pinUvAuthToken, clientDataHash)[0:16]
    ELSE IF protocol == 2 THEN
        // PIN/UV Auth Protocol Two
        expectedHmac = HMAC-SHA256(pinUvAuthToken, clientDataHash)[0:32]
    ELSE
        RETURN false
    END IF
    
    RETURN constantTimeCompare(pinUvAuthParam, expectedHmac)
END FUNCTION

FUNCTION getAndIncrementCounter(credential) RETURNS uint32
BEGIN
    // Get current counter value and increment
    // Counter may be global or per-credential
    
    IF useGlobalCounter THEN
        counter = globalSignatureCounter
        globalSignatureCounter = globalSignatureCounter + 1
    ELSE
        counter = credential.signatureCounter
        credential.signatureCounter = credential.signatureCounter + 1
        updateStoredCredential(credential)
    END IF
    
    RETURN counter
END FUNCTION
```

## Key Differences from MakeCredential

1. **No Credential Creation**: Uses existing credentials instead of creating new ones
2. **Credential Discovery**: Must find matching credentials (via allowList or discoverable storage)
3. **Multiple Credentials**: May return multiple assertions via getNextAssertion
4. **User Selection**: May require user to select from multiple credentials
5. **Credential Protection**: Must respect credProtect policies
6. **No Attestation**: Returns signature, not attestation statement
7. **Extension Outputs**: Different extensions (hmac-secret outputs, largeBlobKey retrieval)

## Assertion Flow Diagram

```
Platform Request
    ↓
Input Validation
    ↓
Credential Discovery ←→ allowList or Discoverable Search
    ↓
Apply credProtect Policies
    ↓
PIN/UV Authentication (if required)
    ↓
Credential Selection (if multiple)
    ↓
User Presence Collection
    ↓
Extension Processing
    ↓
Build Authenticator Data
    ↓
Generate Signature
    ↓
Return Assertion Response
    ↓
(Optional) getNextAssertion for additional credentials
```

## Key Security Considerations

1. **Credential Isolation**: Only return credentials for the correct RP ID
2. **Counter Management**: Properly increment signature counters to detect cloning
3. **User Verification**: Validate PIN/UV auth tokens correctly
4. **User Presence**: Ensure genuine user interaction
5. **Credential Protection**: Enforce credProtect policies
6. **Timing Attacks**: Use constant-time comparisons for sensitive data
7. **Extension Security**: Properly encrypt/decrypt extension data (hmac-secret)
8. **Multiple Credentials**: Securely store state between getAssertion and getNextAssertion

## Common Error Codes

- `CTAP2_ERR_NO_CREDENTIALS` (0x2E): No matching credentials found
- `CTAP2_ERR_PIN_REQUIRED` (0x36): PIN authentication needed
- `CTAP2_ERR_PIN_AUTH_INVALID` (0x31): Invalid PIN auth
- `CTAP2_ERR_UP_REQUIRED` (0x30): User presence required
- `CTAP2_ERR_USER_ACTION_TIMEOUT` (0x3A): User didn't respond in time
- `CTAP2_ERR_OPERATION_DENIED` (0x27): Operation not permitted
- `CTAP2_ERR_NOT_ALLOWED` (0x30): No more credentials (getNextAssertion)
- `CTAP2_ERR_PIN_INVALID` (0x31): PIN check failed

## Extension Handling

### hmac-secret Extension
- Decrypts salt inputs using shared secret from PIN/UV protocol
- Generates HMAC-SHA256 outputs using credential's hmac-secret key
- Encrypts outputs before returning
- Supports one or two salts

### largeBlobKey Extension
- Returns the large blob key associated with credential
- Used to encrypt/decrypt large blob data
- Only available if credential was created with largeBlobKey

### credBlob Extension
- Returns small blob data stored with credential
- Limited to maxCredBlobLength bytes
- Stored during credential creation

## Credential Protection Levels

1. **userVerificationOptional** (0x01): No restrictions
2. **userVerificationOptionalWithCredentialIDList** (0x02): Requires allowList
3. **userVerificationRequired** (0x03): Requires user verification

## References

- FIDO Client to Authenticator Protocol (CTAP) v2.3
- Section 6.2: authenticatorGetAssertion
- Section 6.2.2: authenticatorGetAssertion Algorithm
- Section 6.3: authenticatorGetNextAssertion
- Section 12: Defined Extensions