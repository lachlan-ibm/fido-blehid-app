<!--
 Copyright IBM 2026
-->
# CTAP Attestation Steps Summary

Based on the FIDO Client to Authenticator Protocol (CTAP) v2.3 specification, here is a summary of the attestation steps and a pseudocode algorithm for issuing a credential.

## Attestation Overview

Attestation in CTAP occurs during the **authenticatorMakeCredential** operation (command 0x01). This operation creates a new public key credential and returns an attestation statement that cryptographically proves the credential was created by a specific authenticator model.

## Key Attestation Steps in authenticatorMakeCredential

### 1. **Input Validation**
- Validate clientDataHash (32 bytes)
- Validate RP (Relying Party) information
- Validate user information
- Validate pubKeyCredParams (supported algorithms)
- Check excludeList for existing credentials
- Process options (rk, uv, up)
- Validate extensions

### 2. **User Verification & Presence**
- Check if user verification (uv) is required
- Verify PIN/UV auth token if provided
- Collect evidence of user interaction (user presence)
- For NFC: Check NFC userPresent flag and timer
- For other transports: Collect user gesture interactively

### 3. **Credential Generation**
- Generate new credential key pair (public/private keys)
- Create credential ID
- Generate credential source data structure
- If discoverable credential (rk=true): Store credential with user info
- Associate credential with RP ID

### 4. **Attestation Statement Creation**
The authenticator creates an attestation object containing:

#### a. **Authenticator Data Structure**
- RP ID hash (32 bytes)
- Flags byte (UP, UV, AT, ED bits)
- Signature counter (4 bytes)
- Attested credential data:
  - AAGUID (16 bytes) - Authenticator model identifier
  - Credential ID length (2 bytes)
  - Credential ID (variable length)
  - Credential public key (COSE format)
- Extensions data (if present)

#### b. **Attestation Statement**
Depending on attestation type:

**Basic/AttCA Attestation:**
- Algorithm identifier (alg)
- Signature over (authenticatorData || clientDataHash)
- X.509 certificate chain (x5c)
- May include AAGUID in certificate

**Self Attestation:**
- Algorithm identifier
- Signature using credential private key
- No certificate chain

**None Attestation:**
- Empty attestation statement
- Used for privacy-preserving scenarios

**Enterprise Attestation:**
- Similar to Basic but with enterprise-specific certificates
- Requires platform permission and authenticator configuration

### 5. **Response Construction**
Return attestation object containing:
- fmt: Attestation format identifier
- authData: Authenticator data bytes
- attStmt: Attestation statement (format-specific)

### 6. **Additional Processing**
- Handle extensions (credProtect, hmac-secret, etc.)
- Update signature counter
- Set credential protection level if requested
- Generate large blob key if requested

## Pseudocode Algorithm for Issuing a Credential

```pseudocode
FUNCTION authenticatorMakeCredential(
    clientDataHash,      // 32-byte hash from platform
    rp,                  // Relying Party info {id, name}
    user,                // User info {id, name, displayName}
    pubKeyCredParams,    // List of supported algorithms
    excludeList,         // List of credential IDs to exclude
    extensions,          // Optional extensions
    options,             // {rk, uv, up} flags
    pinUvAuthParam,      // PIN/UV auth parameter
    pinUvAuthProtocol    // PIN/UV protocol version
) RETURNS attestationObject OR error

BEGIN
    // Step 1: Validate Inputs
    IF length(clientDataHash) != 32 THEN
        RETURN CTAP2_ERR_INVALID_CBOR
    END IF
    
    IF NOT isValidRpId(rp.id) THEN
        RETURN CTAP2_ERR_INVALID_PARAMETER
    END IF
    
    IF length(user.id) > 64 THEN
        RETURN CTAP2_ERR_INVALID_PARAMETER
    END IF
    
    // Step 2: Check Algorithm Support
    supportedAlg = NULL
    FOR EACH alg IN pubKeyCredParams DO
        IF authenticatorSupports(alg) THEN
            supportedAlg = alg
            BREAK
        END IF
    END FOR
    
    IF supportedAlg == NULL THEN
        RETURN CTAP2_ERR_UNSUPPORTED_ALGORITHM
    END IF
    
    // Step 3: Check Exclude List (prevent duplicate credentials)
    FOR EACH credId IN excludeList DO
        IF credentialExists(rp.id, credId) THEN
            IF options.up == true THEN
                // Collect user presence before returning error
                waitForUserPresence()
            END IF
            RETURN CTAP2_ERR_CREDENTIAL_EXCLUDED
        END IF
    END FOR
    
    // Step 4: Process PIN/UV Authentication
    requireUserVerification = options.uv OR alwaysUv
    
    IF pinUvAuthParam IS PROVIDED THEN
        // Verify PIN/UV auth token
        IF NOT verifyPinUvAuthToken(pinUvAuthParam, clientDataHash, pinUvAuthProtocol) THEN
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
    
    // Step 5: Collect User Presence
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
        userPresent = false
    END IF
    
    // Step 6: Generate Credential
    credentialKeyPair = generateKeyPair(supportedAlg)
    credentialId = generateCredentialId()
    
    // Step 7: Store Credential (if discoverable)
    IF options.rk == true THEN
        IF NOT hasStorageSpace() THEN
            RETURN CTAP2_ERR_KEY_STORE_FULL
        END IF
        
        storeCredential({
            rpId: rp.id,
            rpName: rp.name,
            userId: user.id,
            userName: user.name,
            userDisplayName: user.displayName,
            credentialId: credentialId,
            privateKey: credentialKeyPair.private,
            publicKey: credentialKeyPair.public,
            algorithm: supportedAlg,
            creationTime: currentTime(),
            signatureCounter: 0
        })
    END IF
    
    // Step 8: Process Extensions
    extensionsOutput = {}
    IF extensions.credProtect IS PROVIDED THEN
        credProtectLevel = extensions.credProtect
        associateCredProtect(credentialId, credProtectLevel)
        extensionsOutput.credProtect = credProtectLevel
    END IF
    
    IF extensions.hmacSecret == true THEN
        hmacSecretKey = generateHmacSecret()
        associateHmacSecret(credentialId, hmacSecretKey)
        extensionsOutput.hmacSecret = true
    END IF
    
    IF extensions.largeBlobKey == true THEN
        largeBlobKey = generateLargeBlobKey()
        associateLargeBlobKey(credentialId, largeBlobKey)
        extensionsOutput.largeBlobKey = largeBlobKey
    END IF
    
    // Step 9: Build Authenticator Data
    rpIdHash = SHA256(rp.id)
    
    flags = 0x00
    IF userPresent THEN flags |= 0x01  // UP bit
    IF userVerified THEN flags |= 0x04  // UV bit
    flags |= 0x40  // AT (Attested Credential Data) bit
    IF extensionsOutput NOT EMPTY THEN flags |= 0x80  // ED bit
    
    signatureCounter = getAndIncrementCounter()
    
    attestedCredData = encode({
        aaguid: getAuthenticatorAAGUID(),  // 16 bytes
        credentialIdLength: length(credentialId),  // 2 bytes
        credentialId: credentialId,
        credentialPublicKey: encodeCOSE(credentialKeyPair.public, supportedAlg)
    })
    
    authenticatorData = rpIdHash || 
                       bytes(flags) || 
                       uint32BE(signatureCounter) ||
                       attestedCredData
    
    IF extensionsOutput NOT EMPTY THEN
        authenticatorData ||= encodeCBOR(extensionsOutput)
    END IF
    
    // Step 10: Create Attestation Statement
    attestationType = determineAttestationType()
    
    SWITCH attestationType DO
        CASE "packed-basic":
            // Basic or AttCA attestation
            signature = sign(
                authenticatorData || clientDataHash,
                attestationPrivateKey,
                supportedAlg
            )
            
            attestationObject = {
                fmt: "packed",
                authData: authenticatorData,
                attStmt: {
                    alg: supportedAlg,
                    sig: signature,
                    x5c: [attestationCertificate, ...caCertificates]
                }
            }
            
        CASE "packed-self":
            // Self attestation
            signature = sign(
                authenticatorData || clientDataHash,
                credentialKeyPair.private,
                supportedAlg
            )
            
            attestationObject = {
                fmt: "packed",
                authData: authenticatorData,
                attStmt: {
                    alg: supportedAlg,
                    sig: signature
                }
            }
            
        CASE "none":
            // Privacy-preserving (no attestation)
            attestationObject = {
                fmt: "none",
                authData: authenticatorData,
                attStmt: {}
            }
            
        CASE "enterprise":
            // Enterprise attestation (requires permission)
            IF NOT enterpriseAttestationEnabled THEN
                RETURN CTAP2_ERR_OPERATION_DENIED
            END IF
            
            signature = sign(
                authenticatorData || clientDataHash,
                enterpriseAttestationKey,
                supportedAlg
            )
            
            attestationObject = {
                fmt: "packed",
                authData: authenticatorData,
                attStmt: {
                    alg: supportedAlg,
                    sig: signature,
                    x5c: [enterpriseCertificate, ...caCertificates]
                }
            }
    END SWITCH
    
    // Step 11: Return Success
    RETURN {
        fmt: attestationObject.fmt,
        authData: attestationObject.authData,
        attStmt: attestationObject.attStmt
    }
    
END FUNCTION

// Helper Functions

FUNCTION generateKeyPair(algorithm) RETURNS {public, private}
BEGIN
    SWITCH algorithm DO
        CASE ES256:  // ECDSA with P-256
            RETURN generateECDSAKeyPair(curve=P-256)
        CASE ES384:  // ECDSA with P-384
            RETURN generateECDSAKeyPair(curve=P-384)
        CASE ES512:  // ECDSA with P-521
            RETURN generateECDSAKeyPair(curve=P-521)
        CASE RS256:  // RSA with SHA-256
            RETURN generateRSAKeyPair(keySize=2048)
        CASE EdDSA:  // EdDSA
            RETURN generateEdDSAKeyPair()
        DEFAULT:
            RETURN error
    END SWITCH
END FUNCTION

FUNCTION generateCredentialId() RETURNS bytes
BEGIN
    // Generate random credential ID (typically 16-32 bytes)
    // Or encrypt credential data for stateless authenticators
    RETURN randomBytes(32)
END FUNCTION

FUNCTION encodeCOSE(publicKey, algorithm) RETURNS coseKey
BEGIN
    // Encode public key in COSE format
    // Format depends on key type (EC2, RSA, OKP)
    RETURN coseEncodePublicKey(publicKey, algorithm)
END FUNCTION

FUNCTION determineAttestationType() RETURNS string
BEGIN
    IF enterpriseAttestationRequested AND enterpriseAttestationEnabled THEN
        RETURN "enterprise"
    ELSE IF attestationCertificateAvailable THEN
        RETURN "packed-basic"
    ELSE IF privacyMode THEN
        RETURN "none"
    ELSE
        RETURN "packed-self"
    END IF
END FUNCTION
```

## Key Security Considerations

1. **Credential ID Security**: Must be unpredictable and unique
2. **Private Key Protection**: Never expose private keys outside secure boundary
3. **User Verification**: Properly validate PIN/UV auth tokens
4. **User Presence**: Ensure genuine user interaction
5. **Attestation Privacy**: Use appropriate attestation type for privacy
6. **Counter Management**: Properly maintain and increment signature counters
7. **Extension Validation**: Validate all extension inputs
8. **Timeout Handling**: Implement proper timeouts for user actions

## Common Error Codes

- `CTAP2_ERR_CREDENTIAL_EXCLUDED` (0x19): Credential already exists
- `CTAP2_ERR_UNSUPPORTED_ALGORITHM` (0x26): No supported algorithm
- `CTAP2_ERR_KEY_STORE_FULL` (0x17): No storage space
- `CTAP2_ERR_PIN_REQUIRED` (0x36): PIN authentication needed
- `CTAP2_ERR_PIN_AUTH_INVALID` (0x31): Invalid PIN auth
- `CTAP2_ERR_UP_REQUIRED` (0x30): User presence required
- `CTAP2_ERR_USER_ACTION_TIMEOUT` (0x3A): User didn't respond in time
- `CTAP2_ERR_OPERATION_DENIED` (0x27): Operation not permitted

## References

- FIDO Client to Authenticator Protocol (CTAP) v2.3
- Section 6.1: authenticatorMakeCredential
- Section 6.1.2: authenticatorMakeCredential Algorithm
- Section 7.1: Enterprise Attestation
- Section 8: Message Encoding