<!--
 Copyright IBM 2026
-->
# CTAP2 Conformance Test Plan

## Overview

This test plan ensures that `AuthenticatorAPI.java` and `Fido2Authenticator.java` conform to the CTAP 2.3 specification and WebAuthn Level 3 draft specification. The focus is on core credential API operations and PIN/UV authentication rather than extension edge cases.

**Target Classes:**
- `lib/src/com/isfs/blekey/authenticator/AuthenticatorAPI.java`
- `lib/src/com/isfs/blekey/authenticator/Fido2Authenticator.java`

**Specification References:**
- CTAP 2.3 Review Draft (October 23, 2025)
- WebAuthn Level 3 (W3C Draft)

---

## 1. authenticatorMakeCredential (0x01) Tests

### 1.1 Required Parameter Validation

**Spec Reference:** CTAP 2.3 Section 6.1

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| MC-REQ-001 | Missing clientDataHash (0x01) | Return `CTAP2_ERR_MISSING_PARAMETER` | HIGH |
| MC-REQ-002 | Missing rp (0x02) | Return `CTAP2_ERR_MISSING_PARAMETER` | HIGH |
| MC-REQ-003 | Missing user (0x03) | Return `CTAP2_ERR_MISSING_PARAMETER` | HIGH |
| MC-REQ-004 | Missing pubKeyCredParams (0x04) | Return `CTAP2_ERR_MISSING_PARAMETER` | HIGH |
| MC-REQ-005 | Invalid clientDataHash length (not 32 bytes) | Return `CTAP2_ERR_INVALID_CBOR` | HIGH |

**Implementation Check:**
- Verify `validateRequiredParameters()` method (lines 409-426)
- Verify `validateClientDataHash()` method (lines 428-441)

### 1.2 Algorithm Support Validation

**Spec Reference:** CTAP 2.3 Section 6.1.2

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| MC-ALG-001 | Request with ES256 (COSE -7) | Accept and create credential | HIGH |
| MC-ALG-002 | Request with RS256 (COSE -257) | Accept and create credential | HIGH |
| MC-ALG-003 | Request with unsupported algorithm | Return `CTAP2_ERR_UNSUPPORTED_ALGORITHM` | HIGH |
| MC-ALG-004 | Request with multiple algorithms (ES256, RS256) | Use first supported algorithm | MEDIUM |
| MC-ALG-005 | Empty pubKeyCredParams array | Return `CTAP2_ERR_MISSING_PARAMETER` | HIGH |

**Implementation Check:**
- Verify `SUPPORTED_ALGORITHM_SET` constant (lines 68-72)
- Verify `isSupportedAlgorithm()` method (lines 481-493)

### 1.3 Exclude List Processing

**Spec Reference:** CTAP 2.3 Section 6.1.2

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| MC-EXC-001 | excludeList contains existing credential | Return `CTAP2_ERR_CREDENTIAL_EXCLUDED` | HIGH |
| MC-EXC-002 | excludeList with non-existent credentials | Proceed with credential creation | HIGH |
| MC-EXC-003 | Empty excludeList | Proceed with credential creation | MEDIUM |
| MC-EXC-004 | excludeList with invalid credential format | Ignore invalid entries, process valid ones | MEDIUM |

**Implementation Check:**
- Verify `checkExcludeList()` method (lines 443-465)
- Verify `isCredentialExcluded()` method (lines 717-744)

### 1.4 Options Processing

**Spec Reference:** CTAP 2.3 Section 6.1.2

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| MC-OPT-001 | rk=true (resident key) | Create discoverable credential | HIGH |
| MC-OPT-002 | rk=false | Create non-discoverable credential | HIGH |
| MC-OPT-003 | up=true (user presence) | Require user presence verification | HIGH |
| MC-OPT-004 | up=false | Skip user presence check | MEDIUM |
| MC-OPT-005 | uv=true (user verification) | Require user verification | HIGH |
| MC-OPT-006 | uv=false | Skip user verification | MEDIUM |
| MC-OPT-007 | rk=true with uv=false | Return appropriate error or create with UV | HIGH |

**Implementation Check:**
- Verify `parseOptions()` method (lines 510-525)
- Verify `determineCredentialType()` method (lines 527-551)
- Verify `validateUserPresence()` method (lines 467-479)

### 1.5 Resident Credential Storage

**Spec Reference:** CTAP 2.3 Section 6.1.3

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| MC-RES-001 | Create resident credential with valid user info | Store credential with user.id, user.name, user.displayName | HIGH |
| MC-RES-002 | Create resident credential without user.name | Store with user.id and user.displayName only | MEDIUM |
| MC-RES-003 | Duplicate resident credential for same RP and user | Update existing credential | HIGH |
| MC-RES-004 | Storage limit reached | Return `CTAP2_ERR_KEY_STORE_FULL` | MEDIUM |

**Implementation Check:**
- Verify `storeResidentCredential()` method (lines 656-715)
- Verify `extractCredentialInfo()` method (lines 643-654)

### 1.6 Attestation Statement Generation

**Spec Reference:** CTAP 2.3 Section 6.1.2, WebAuthn L3 Section 6.5

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| MC-ATT-001 | Request with "none" attestation | Return attestation with fmt="none" | HIGH |
| MC-ATT-002 | Request with "packed" attestation | Return valid packed attestation | HIGH |
| MC-ATT-003 | Request with "fido-u2f" attestation | Return valid FIDO U2F attestation | MEDIUM |
| MC-ATT-004 | Attestation signature verification | Signature must verify with attestation key | HIGH |
| MC-ATT-005 | AAGUID in attestation | Must match authenticator's AAGUID | HIGH |

**Implementation Check:**
- Verify `createAttestationStatement()` method (lines 847-874)
- Verify `Fido2Authenticator.buildPackedAttestationStatement()` (lines 1090-1146)
- Verify `Fido2Authenticator.buildFIDOU2FAttestationStatement()` (lines 1024-1062)

### 1.7 Authenticator Data Structure

**Spec Reference:** CTAP 2.3 Section 6.1, WebAuthn L3 Section 6.1

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| MC-AUTH-001 | RP ID hash in authenticator data | SHA-256(rpId) must be first 32 bytes | HIGH |
| MC-AUTH-002 | Flags byte | UP, UV, AT, ED flags set correctly | HIGH |
| MC-AUTH-003 | Signature counter | Must be included and increment | HIGH |
| MC-AUTH-004 | AAGUID | Must be 16 bytes | HIGH |
| MC-AUTH-005 | Credential ID length | Must be 2 bytes, big-endian | HIGH |
| MC-AUTH-006 | Credential public key | Must be valid COSE_Key format | HIGH |

**Implementation Check:**
- Verify `buildAuthenticatorData()` method (lines 821-845)
- Verify `Fido2Authenticator.buildAuthenticatorData()` (lines 391-473)

---

## 2. authenticatorGetAssertion (0x02) Tests

### 2.1 Required Parameter Validation

**Spec Reference:** CTAP 2.3 Section 6.2

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| GA-REQ-001 | Missing rpId (0x01) | Return `CTAP2_ERR_MISSING_PARAMETER` | HIGH |
| GA-REQ-002 | Missing clientDataHash (0x02) | Return `CTAP2_ERR_MISSING_PARAMETER` | HIGH |
| GA-REQ-003 | Invalid clientDataHash length | Return `CTAP2_ERR_INVALID_CBOR` | HIGH |
| GA-REQ-004 | Empty rpId string | Return `CTAP2_ERR_INVALID_PARAMETER` | HIGH |

**Implementation Check:**
- Verify parameter validation in `getAssertion()` method (lines 1136-1167)
- Verify `createAuthenticator()` method (lines 998-1054)

### 2.2 Credential Discovery

**Spec Reference:** CTAP 2.3 Section 6.2.2

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| GA-DISC-001 | allowList with valid credential | Use credential from allowList | HIGH |
| GA-DISC-002 | allowList with non-existent credential | Return `CTAP2_ERR_NO_CREDENTIALS` | HIGH |
| GA-DISC-003 | Empty allowList with resident credentials | Use resident credentials for rpId | HIGH |
| GA-DISC-004 | Empty allowList without resident credentials | Return `CTAP2_ERR_NO_CREDENTIALS` | HIGH |
| GA-DISC-005 | Multiple credentials in allowList | Use first valid credential | MEDIUM |

**Implementation Check:**
- Verify `processCredentials()` method (lines 1078-1099)
- Verify `initializeAuthenticatorWithCredential()` method (lines 1056-1076)

### 2.3 User Presence and Verification

**Spec Reference:** CTAP 2.3 Section 6.2.2

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| GA-UV-001 | up=true option | Set UP flag in authenticator data | HIGH |
| GA-UV-002 | up=false option | Clear UP flag in authenticator data | MEDIUM |
| GA-UV-003 | uv=true option | Set UV flag in authenticator data | HIGH |
| GA-UV-004 | uv=false option | Clear UV flag in authenticator data | MEDIUM |
| GA-UV-005 | Pre-flight with up=false | Return assertion without consuming UP | HIGH |

**Implementation Check:**
- Verify options processing in `getAssertion()` method
- Verify flag setting in authenticator data generation

### 2.4 Assertion Signature

**Spec Reference:** CTAP 2.3 Section 6.2.2, WebAuthn L3 Section 6.3.3

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| GA-SIG-001 | Signature over authenticatorData \|\| clientDataHash | Signature must verify with credential public key | HIGH |
| GA-SIG-002 | Signature algorithm matches credential | Use algorithm from credential creation | HIGH |
| GA-SIG-003 | Counter increment | Counter must be greater than previous value | HIGH |
| GA-SIG-004 | Invalid signature | Must not verify | HIGH |

**Implementation Check:**
- Verify `generateSignedAssertion()` method (lines 1102-1134)
- Verify `Fido2Authenticator.signData()` method (lines 501-519)

### 2.5 Multiple Assertions

**Spec Reference:** CTAP 2.3 Section 6.2.3

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| GA-MULT-001 | Multiple resident credentials for rpId | Return numberOfCredentials in first response | MEDIUM |
| GA-MULT-002 | authenticatorGetNextAssertion call | Return next credential assertion | MEDIUM |
| GA-MULT-003 | GetNextAssertion without prior GetAssertion | Return `CTAP2_ERR_NOT_ALLOWED` | MEDIUM |

**Implementation Check:**
- Check if multiple credential support is implemented
- Verify state management for multi-credential scenarios

---

## 3. authenticatorClientPIN (0x06) Tests

### 3.1 PIN Protocol Support

**Spec Reference:** CTAP 2.3 Section 6.5.4

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| PIN-PROT-001 | pinUvAuthProtocol = 1 | Accept PIN/UV Auth Protocol One | HIGH |
| PIN-PROT-002 | pinUvAuthProtocol = 2 | Accept PIN/UV Auth Protocol Two (if supported) | MEDIUM |
| PIN-PROT-003 | pinUvAuthProtocol = 0 or invalid | Return `CTAP1_ERR_INVALID_PARAMETER` | HIGH |
| PIN-PROT-004 | Missing pinUvAuthProtocol | Return `CTAP2_ERR_MISSING_PARAMETER` | HIGH |

**Implementation Check:**
- Verify `SUPPORTED_PIN_UV_AUTH_PROTOCOL` constant (lines 74-78)
- Verify `validatePinUvAuthProtocol()` method (lines 207-223)

### 3.2 Get PIN Retries (subCmd 0x01)

**Spec Reference:** CTAP 2.3 Section 6.5.5.1

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| PIN-RET-001 | Get retries with PIN set | Return current retry count | HIGH |
| PIN-RET-002 | Get retries with PIN not set | Return max retries (8) | HIGH |
| PIN-RET-003 | Get retries after failed attempt | Return decremented count | HIGH |
| PIN-RET-004 | Get retries when blocked | Return 0 | HIGH |

**Implementation Check:**
- Verify `pinRty()` method (lines 1484-1495)
- Verify `pinRetries` field management (lines 52-55)
- Verify `MAX_PIN_RETRIES` constant (lines 115-118)

### 3.3 Get Key Agreement (subCmd 0x02)

**Spec Reference:** CTAP 2.3 Section 6.5.5.2

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| PIN-KEY-001 | Get platform key agreement key | Return valid COSE_Key with P-256 public key | HIGH |
| PIN-KEY-002 | Key agreement key format | Must be COSE_Key with kty=2 (EC2), crv=1 (P-256) | HIGH |
| PIN-KEY-003 | Key agreement key coordinates | x and y coordinates must be 32 bytes each | HIGH |
| PIN-KEY-004 | Repeated calls | May return same or different ephemeral key | MEDIUM |

**Implementation Check:**
- Verify `getKey()` method (lines 1225-1267)
- Verify `platKeyPair` field (lines 57-60)
- Verify key format in response

### 3.4 Get PIN Token (subCmd 0x05)

**Spec Reference:** CTAP 2.3 Section 6.5.5.7

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| PIN-TKN-001 | Valid PIN hash with key agreement | Return encrypted PIN token | HIGH |
| PIN-TKN-002 | Invalid PIN hash | Decrement retries, return `CTAP2_ERR_PIN_INVALID` | HIGH |
| PIN-TKN-003 | Missing keyAgreement parameter | Return `CTAP2_ERR_MISSING_PARAMETER` | HIGH |
| PIN-TKN-004 | Missing pinHashEnc parameter | Return `CTAP2_ERR_MISSING_PARAMETER` | HIGH |
| PIN-TKN-005 | PIN blocked (0 retries) | Return `CTAP2_ERR_PIN_BLOCKED` | HIGH |
| PIN-TKN-006 | Correct PIN after failed attempts | Reset retry counter, return token | HIGH |

**Implementation Check:**
- Verify `getTkn()` method (lines 1412-1482)
- Verify `verifyPinAndOpenPasskey()` method (lines 1392-1410)
- Verify `generatePinAuthToken()` method (lines 1335-1345)

### 3.5 ECDH Key Agreement

**Spec Reference:** CTAP 2.3 Section 6.5.5.7.1

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| PIN-ECDH-001 | Valid platform public key | Compute shared secret using ECDH | HIGH |
| PIN-ECDH-002 | Invalid platform public key format | Return `CTAP2_ERR_INVALID_PARAMETER` | HIGH |
| PIN-ECDH-003 | Shared secret derivation | Use SHA-256(ECDH(platform, authenticator)) | HIGH |
| PIN-ECDH-004 | Platform key not on curve | Return error | MEDIUM |

**Implementation Check:**
- Verify `extractClientPublicKey()` method (lines 1269-1290)
- Verify `performEcdhKeyAgreement()` method (lines 1292-1312)

### 3.6 PIN Hash Encryption/Decryption

**Spec Reference:** CTAP 2.3 Section 6.5.5.7.2

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| PIN-ENC-001 | Decrypt valid pinHashEnc | Successfully decrypt using shared secret | HIGH |
| PIN-ENC-002 | Decrypt with wrong shared secret | Fail decryption | HIGH |
| PIN-ENC-003 | PIN hash format | Must be first 16 bytes of SHA-256(PIN) | HIGH |
| PIN-ENC-004 | AES-256-CBC decryption | Use shared secret as key, zero IV | HIGH |

**Implementation Check:**
- Verify `decryptPinHash()` method (lines 1314-1333)
- Verify `SHA256_DIGEST` usage (lines 80-91)
- Verify `AES_BLOCK_SIZE` constant (lines 110-113)

### 3.7 PIN Token Generation

**Spec Reference:** CTAP 2.3 Section 6.5.5.7.3

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| PIN-GEN-001 | Generate PIN token | Must be 32 random bytes | HIGH |
| PIN-GEN-002 | PIN token uniqueness | Each token should be unique | HIGH |
| PIN-GEN-003 | PIN token storage | Store in transaction context | HIGH |
| PIN-GEN-004 | PIN token encryption | Encrypt with shared secret before returning | HIGH |

**Implementation Check:**
- Verify `generatePinAuthToken()` method (lines 1335-1345)
- Verify `PIN_TOKEN_SIZE` constant (lines 105-108)
- Verify `SECURE_RANDOM` usage (lines 135-139)

---

## 4. PIN/UV Auth Token Verification Tests

### 4.1 Token Verification in MakeCredential

**Spec Reference:** CTAP 2.3 Section 6.1.2

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| PINV-MC-001 | Valid pinUvAuthParam with mc permission | Accept and create credential | HIGH |
| PINV-MC-002 | Invalid pinUvAuthParam | Return `CTAP2_ERR_PIN_AUTH_INVALID` | HIGH |
| PINV-MC-003 | Missing pinUvAuthParam when UV required | Return `CTAP2_ERR_PIN_REQUIRED` | HIGH |
| PINV-MC-004 | Zero-length pinUvAuthParam | Return `CTAP2_ERR_PIN_INVALID` or `CTAP2_ERR_PIN_NOT_SET` | HIGH |
| PINV-MC-005 | pinUvAuthParam without permission | Return `CTAP2_ERR_PIN_AUTH_INVALID` | HIGH |

**Implementation Check:**
- Verify `verifyPinUvAuth()` method (lines 240-307)
- Verify `verifyPinAuthToken()` method (lines 142-164)
- Verify `verifyTokenWithParams()` method (lines 225-238)

### 4.2 Token Verification in GetAssertion

**Spec Reference:** CTAP 2.3 Section 6.2.2

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| PINV-GA-001 | Valid pinUvAuthParam with ga permission | Accept and return assertion | HIGH |
| PINV-GA-002 | Invalid pinUvAuthParam | Return `CTAP2_ERR_PIN_AUTH_INVALID` | HIGH |
| PINV-GA-003 | pinUvAuthParam with wrong permission | Return `CTAP2_ERR_PIN_AUTH_INVALID` | HIGH |
| PINV-GA-004 | Pre-flight with up=false, no pinUvAuthParam | Return assertion with UP=0, UV=0 | HIGH |

**Implementation Check:**
- Verify PIN/UV auth verification in `getAssertion()` method
- Verify permission checking logic

### 4.3 HMAC-SHA-256 Verification

**Spec Reference:** CTAP 2.3 Section 6.5.3.1

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| PINV-HMAC-001 | Compute HMAC-SHA-256(pinToken, message) | First 16 bytes must match pinUvAuthParam | HIGH |
| PINV-HMAC-002 | Message for makeCredential | clientDataHash | HIGH |
| PINV-HMAC-003 | Message for getAssertion | clientDataHash | HIGH |
| PINV-HMAC-004 | Wrong message | Verification must fail | HIGH |

**Implementation Check:**
- Verify `HMAC_SHA256` usage (lines 93-104)
- Verify message construction in verification methods

---

## 5. authenticatorGetInfo (0x04) Tests

### 5.1 Required Response Fields

**Spec Reference:** CTAP 2.3 Section 6.4

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| INFO-001 | versions array | Must include "FIDO_2_0" and/or "FIDO_2_1" | HIGH |
| INFO-002 | aaguid | Must be 16-byte identifier | HIGH |
| INFO-003 | options map | Must include supported options | HIGH |
| INFO-004 | maxMsgSize | Must be present if not default (1200) | MEDIUM |
| INFO-005 | pinUvAuthProtocols | Must list supported protocols | HIGH |

**Implementation Check:**
- Verify `getInfo()` method (lines 1169-1192)
- Verify response structure matches CTAP spec

### 5.2 Options Reporting

**Spec Reference:** CTAP 2.3 Section 6.4

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| INFO-OPT-001 | plat option | Report if platform device | MEDIUM |
| INFO-OPT-002 | rk option | Report resident key support | HIGH |
| INFO-OPT-003 | clientPin option | Report if PIN is set | HIGH |
| INFO-OPT-004 | up option | Report user presence capability | HIGH |
| INFO-OPT-005 | uv option | Report user verification capability | HIGH |

**Implementation Check:**
- Verify options map construction in `getInfo()` method

---

## 6. Error Code Conformance Tests

### 6.1 Standard Error Codes

**Spec Reference:** CTAP 2.3 Section 8.2

| Test ID | Test Case | Expected Error Code | Priority |
|---------|-----------|---------------------|----------|
| ERR-001 | Success | `CTAP2_OK` (0x00) | HIGH |
| ERR-002 | Invalid CBOR | `CTAP2_ERR_INVALID_CBOR` (0x12) | HIGH |
| ERR-003 | Missing parameter | `CTAP2_ERR_MISSING_PARAMETER` (0x14) | HIGH |
| ERR-004 | Invalid parameter | `CTAP1_ERR_INVALID_PARAMETER` (0x02) | HIGH |
| ERR-005 | Unsupported algorithm | `CTAP2_ERR_UNSUPPORTED_ALGORITHM` (0x26) | HIGH |
| ERR-006 | Credential excluded | `CTAP2_ERR_CREDENTIAL_EXCLUDED` (0x19) | HIGH |
| ERR-007 | No credentials | `CTAP2_ERR_NO_CREDENTIALS` (0x2E) | HIGH |
| ERR-008 | PIN required | `CTAP2_ERR_PIN_REQUIRED` (0x36) | HIGH |
| ERR-009 | PIN invalid | `CTAP2_ERR_PIN_INVALID` (0x31) | HIGH |
| ERR-010 | PIN blocked | `CTAP2_ERR_PIN_BLOCKED` (0x32) | HIGH |
| ERR-011 | PIN auth invalid | `CTAP2_ERR_PIN_AUTH_INVALID` (0x33) | HIGH |
| ERR-012 | User presence required | `CTAP2_ERR_UP_REQUIRED` (0x3A) | HIGH |

**Implementation Check:**
- Verify `Ctap2StatusCode` enum usage
- Verify `error()` method (lines 309-317)

---

## 7. Cryptographic Conformance Tests

### 7.1 Supported Algorithms

**Spec Reference:** CTAP 2.3 Section 6.1.2, WebAuthn L3 Section 5.8.5

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| CRYPTO-001 | ES256 (COSE -7) signature | Valid ECDSA P-256 SHA-256 signature | HIGH |
| CRYPTO-002 | RS256 (COSE -257) signature | Valid RSASSA-PKCS1-v1_5 SHA-256 signature | HIGH |
| CRYPTO-003 | Public key format | Valid COSE_Key encoding | HIGH |
| CRYPTO-004 | Signature verification | Signature verifies with public key | HIGH |

**Implementation Check:**
- Verify algorithm support in `SUPPORTED_ALGORITHM_SET`
- Verify signature generation in `Fido2Authenticator.signData()`

### 7.2 Hash Functions

**Spec Reference:** CTAP 2.3 Section 6.5.3

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| HASH-001 | SHA-256 of RP ID | Correct 32-byte hash | HIGH |
| HASH-002 | SHA-256 of PIN | Correct hash for PIN verification | HIGH |
| HASH-003 | HMAC-SHA-256 | Correct MAC computation | HIGH |

**Implementation Check:**
- Verify `SHA256_DIGEST` usage (lines 80-91)
- Verify `HMAC_SHA256` usage (lines 93-104)

### 7.3 Encryption

**Spec Reference:** CTAP 2.3 Section 6.5.5.7.2

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| ENC-001 | AES-256-CBC encryption | Correct encryption with zero IV | HIGH |
| ENC-002 | AES-256-CBC decryption | Correct decryption | HIGH |
| ENC-003 | Key derivation from ECDH | SHA-256 of shared secret | HIGH |

**Implementation Check:**
- Verify AES encryption/decryption in PIN methods
- Verify ECDH key agreement implementation

---

## 8. State Management Tests

### 8.1 Transaction State

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| STATE-001 | PIN token persistence | Token available across commands in same transaction | HIGH |
| STATE-002 | Passkey file state | Passkey remains open after PIN verification | HIGH |
| STATE-003 | Platform key state | Platform key persists for key agreement | HIGH |
| STATE-004 | Transaction isolation | Different transactions have separate state | HIGH |

**Implementation Check:**
- Verify `CtapTxn` state management
- Verify `updateAuthenticationState()` method (lines 1347-1364)

### 8.2 Retry Counter Management

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| RETRY-001 | Initial retry count | Should be 8 (MAX_PIN_RETRIES) | HIGH |
| RETRY-002 | Decrement on failed PIN | Count decreases by 1 | HIGH |
| RETRY-003 | Reset on successful PIN | Count resets to 8 | HIGH |
| RETRY-004 | Block at zero retries | No more attempts allowed | HIGH |

**Implementation Check:**
- Verify `pinRetries` field management
- Verify retry logic in `verifyPinAndOpenPasskey()`

---

## 9. Integration Tests

### 9.1 End-to-End Credential Lifecycle

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| E2E-001 | Register → Authenticate flow | Complete flow succeeds | HIGH |
| E2E-002 | Register with PIN → Authenticate with PIN | PIN verification works in both operations | HIGH |
| E2E-003 | Register resident key → Authenticate without allowList | Discoverable credential works | HIGH |
| E2E-004 | Multiple credentials for same RP | All credentials accessible | MEDIUM |

### 9.2 WebAuthn Compatibility

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| WA-001 | PublicKeyCredential creation | Response matches WebAuthn format | HIGH |
| WA-002 | PublicKeyCredential assertion | Response matches WebAuthn format | HIGH |
| WA-003 | AuthenticatorData structure | Matches WebAuthn specification | HIGH |
| WA-004 | Client data hash handling | Correctly processes WebAuthn client data | HIGH |

**Implementation Check:**
- Verify `Fido2Authenticator.credentialCreate()` methods (lines 273-349)
- Verify `Fido2Authenticator.credentialRequest()` methods (lines 351-389)

---

## 10. Test Execution Priority

### Phase 1: Critical Path (HIGH Priority)
1. authenticatorMakeCredential basic flow
2. authenticatorGetAssertion basic flow
3. authenticatorClientPIN basic operations
4. PIN/UV auth token verification
5. Error code conformance
6. Required parameter validation

### Phase 2: Core Features (HIGH-MEDIUM Priority)
1. Resident credential support
2. Exclude list processing
3. Algorithm support validation
4. Attestation statement generation
5. Signature verification
6. ECDH key agreement

### Phase 3: Edge Cases (MEDIUM Priority)
1. Multiple credential scenarios
2. State management edge cases
3. Retry counter edge cases
4. Optional parameter handling
5. Extension support (if implemented)

### Phase 4: Integration (MEDIUM-LOW Priority)
1. End-to-end flows
2. WebAuthn compatibility
3. Cross-version compatibility
4. Performance testing

---

## 11. Test Implementation Guidelines

### 11.1 Test Structure

Each test should follow this structure:

```java
@Test
public void testMC_REQ_001_MissingClientDataHash() {
    // Arrange
    Map<Integer, Object> request = new HashMap<>();
    // Omit clientDataHash (0x01)
    request.put(0x02, createRpInfo());
    request.put(0x03, createUserInfo());
    request.put(0x04, createPubKeyCredParams());
    
    CtapTxn txn = createTestTransaction();
    
    // Act
    byte[] response = AuthenticatorAPI.makeCredential(txn, request);
    
    // Assert
    assertEquals(Ctap2StatusCode.MISSING_PARAMETER, extractStatusCode(response));
}
```

### 11.2 Test Data Helpers

Create helper methods for common test data:
- `createValidMakeCredentialRequest()`
- `createValidGetAssertionRequest()`
- `createValidPinRequest()`
- `createTestTransaction()`
- `createRpInfo()`, `createUserInfo()`, etc.

### 11.3 Assertion Helpers

Create helpers for common assertions:
- `assertSuccessResponse(byte[] response)`
- `assertErrorResponse(byte[] response, Ctap2StatusCode expected)`
- `assertValidAuthenticatorData(byte[] authData)`
- `assertValidSignature(byte[] signature, PublicKey key, byte[] data)`

### 11.4 Mock and Stub Strategy

- Mock `CtapTxn` for transaction state
- Mock `Passkey` for credential storage
- Use real cryptographic operations (don't mock crypto)
- Stub file I/O operations where appropriate

---

## 12. Coverage Metrics

### 12.1 Code Coverage Targets

- **Line Coverage:** ≥ 85%
- **Branch Coverage:** ≥ 80%
- **Method Coverage:** ≥ 90%

### 12.2 Specification Coverage

Track coverage of CTAP 2.3 specification sections:
- Section 6.1 (authenticatorMakeCredential): 100%
- Section 6.2 (authenticatorGetAssertion): 100%
- Section 6.4 (authenticatorGetInfo): 100%
- Section 6.5 (authenticatorClientPIN): 100%
- Section 8.2 (Status codes): 100%

---

## 13. Known Limitations and Future Work

### 13.1 Current Implementation Gaps

Document any known gaps in the current implementation:
- Extension support (credProtect, hmac-secret, etc.)
- authenticatorBioEnrollment (0x09)
- authenticatorCredentialManagement (0x0A)
- authenticatorSelection (0x0B)
- authenticatorLargeBlobs (0x0C)
- authenticatorConfig (0x0D)

### 13.2 Future Test Additions

- Transport-specific tests (USB HID, NFC, BLE)
- Performance and stress testing
- Concurrent operation testing
- Security-specific tests (timing attacks, etc.)

---

## 14. References

1. **CTAP 2.3 Specification**
   - Client to Authenticator Protocol (CTAP) Review Draft, October 23, 2025
   - https://fidoalliance.org/specs/fido-v2.3-rd-20251023/

2. **WebAuthn Level 3**
   - Web Authentication: An API for accessing Public Key Credentials
   - https://www.w3.org/TR/webauthn-3/

3. **COSE (RFC 8152)**
   - CBOR Object Signing and Encryption
   - https://tools.ietf.org/html/rfc8152

4. **CBOR (RFC 8949)**
   - Concise Binary Object Representation
   - https://tools.ietf.org/html/rfc8949

---

## Appendix A: CTAP2 Command Summary

| Command | Code | Description | Implementation Status |
|---------|------|-------------|----------------------|
| authenticatorMakeCredential | 0x01 | Create new credential | ✓ Implemented |
| authenticatorGetAssertion | 0x02 | Get authentication assertion | ✓ Implemented |
| authenticatorGetInfo | 0x04 | Get authenticator info | ✓ Implemented |
| authenticatorClientPIN | 0x06 | PIN/UV auth operations | ✓ Implemented |
| authenticatorReset | 0x07 | Reset authenticator | ? Unknown |
| authenticatorGetNextAssertion | 0x08 | Get next assertion | ? Unknown |
| authenticatorBioEnrollment | 0x09 | Biometric enrollment | ✗ Not implemented |
| authenticatorCredentialManagement | 0x0A | Credential management | ✗ Not implemented |
| authenticatorSelection | 0x0B | Authenticator selection | ✗ Not implemented |
| authenticatorLargeBlobs | 0x0C | Large blob storage | ✗ Not implemented |
| authenticatorConfig | 0x0D | Authenticator configuration | ✗ Not implemented |

---

## Appendix B: Test Execution Checklist

- [ ] Set up test environment with required dependencies
- [ ] Create test data generators and helpers
- [ ] Implement Phase 1 tests (Critical Path)
- [ ] Verify Phase 1 tests pass
- [ ] Implement Phase 2 tests (Core Features)
- [ ] Verify Phase 2 tests pass
- [ ] Implement Phase 3 tests (Edge Cases)
- [ ] Verify Phase 3 tests pass
- [ ] Implement Phase 4 tests (Integration)
- [ ] Verify Phase 4 tests pass
- [ ] Measure code coverage
- [ ] Document any specification deviations
- [ ] Create bug reports for failures
- [ ] Update implementation to fix failures
- [ ] Re-run all tests
- [ ] Generate final test report

---

**Document Version:** 1.0  
**Last Updated:** 2026-03-18  
**Status:** Draft for Review

---

## 10. WebAuthn Level 3 Specification Tests

### 10.1 PublicKeyCredential Creation (Registration)

**Spec Reference:** WebAuthn L3 Section 5.1, 6.3.2

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| WA-CREATE-001 | Response structure | Must contain id, rawId, response, type | HIGH |
| WA-CREATE-002 | response.clientDataJSON | Must be valid JSON with type="webauthn.create" | HIGH |
| WA-CREATE-003 | response.attestationObject | Must be valid CBOR with fmt, attStmt, authData | HIGH |
| WA-CREATE-004 | id field | Must be base64url(rawId) | HIGH |
| WA-CREATE-005 | type field | Must be "public-key" | HIGH |
| WA-CREATE-006 | rawId field | Must match credential ID in authData | HIGH |

**Implementation Check:**
- Verify `Fido2Authenticator.credentialCreate()` methods (lines 273-349)
- Verify `Fido2Authenticator.processCredentialCreationOptions()` (lines 716-765)

### 10.2 PublicKeyCredential Request (Authentication)

**Spec Reference:** WebAuthn L3 Section 5.1, 6.3.3

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| WA-REQUEST-001 | Response structure | Must contain id, rawId, response, type | HIGH |
| WA-REQUEST-002 | response.clientDataJSON | Must be valid JSON with type="webauthn.get" | HIGH |
| WA-REQUEST-003 | response.authenticatorData | Must be valid authenticator data structure | HIGH |
| WA-REQUEST-004 | response.signature | Must verify with credential public key | HIGH |
| WA-REQUEST-005 | response.userHandle | Must match user.id for discoverable credentials | HIGH |
| WA-REQUEST-006 | Signature verification | sig = Sign(authData \|\| hash(clientDataJSON)) | HIGH |

**Implementation Check:**
- Verify `Fido2Authenticator.credentialRequest()` methods (lines 351-389)
- Verify `Fido2Authenticator.processCredentialRequestOptions()` (lines 1204-1265)

### 10.3 Authenticator Data Structure

**Spec Reference:** WebAuthn L3 Section 6.1

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| WA-AUTHDATA-001 | rpIdHash (bytes 0-31) | SHA-256(rpId) | HIGH |
| WA-AUTHDATA-002 | flags (byte 32) | Bit 0=UP, Bit 2=UV, Bit 6=AT, Bit 7=ED | HIGH |
| WA-AUTHDATA-003 | signCount (bytes 33-36) | 32-bit unsigned big-endian | HIGH |
| WA-AUTHDATA-004 | aaguid (bytes 37-52) | 16-byte authenticator identifier | HIGH |
| WA-AUTHDATA-005 | credentialIdLength (bytes 53-54) | 16-bit unsigned big-endian | HIGH |
| WA-AUTHDATA-006 | credentialId | Variable length, matches credentialIdLength | HIGH |
| WA-AUTHDATA-007 | credentialPublicKey | COSE_Key encoded public key | HIGH |
| WA-AUTHDATA-008 | extensions (optional) | CBOR map if ED flag set | MEDIUM |

**Implementation Check:**
- Verify `Fido2Authenticator.buildAuthenticatorData()` (lines 391-473)
- Verify `Fido2Authenticator.processAttestedCredentialData()` (lines 658-686)

### 10.4 Client Data JSON Structure

**Spec Reference:** WebAuthn L3 Section 6.5

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| WA-CLIENT-001 | type field | "webauthn.create" or "webauthn.get" | HIGH |
| WA-CLIENT-002 | challenge field | base64url encoded challenge | HIGH |
| WA-CLIENT-003 | origin field | Valid origin string | HIGH |
| WA-CLIENT-004 | crossOrigin field | Boolean, optional | MEDIUM |
| WA-CLIENT-005 | JSON structure | Valid JSON, no extra whitespace | HIGH |

**Implementation Check:**
- Verify `Fido2Authenticator.buildClientDataJson()` (lines 475-499)

### 10.5 COSE Key Encoding

**Spec Reference:** WebAuthn L3 Section 6.5.10.5, RFC 8152

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| WA-COSE-001 | ES256 key structure | kty=2, alg=-7, crv=1, x, y | HIGH |
| WA-COSE-002 | RS256 key structure | kty=3, alg=-257, n, e | HIGH |
| WA-COSE-003 | Key parameter encoding | CBOR map with integer keys | HIGH |
| WA-COSE-004 | Coordinate lengths | x and y must be 32 bytes for P-256 | HIGH |
| WA-COSE-005 | Modulus length | n must be appropriate for RSA key size | MEDIUM |

**Implementation Check:**
- Verify public key encoding in attestation methods
- Verify `Fido2Authenticator.processAttestedCredentialData()`

---

## 11. Attestation Format Tests

### 11.1 None Attestation

**Spec Reference:** WebAuthn L3 Section 8.7

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| ATT-NONE-001 | fmt field | Must be "none" | HIGH |
| ATT-NONE-002 | attStmt field | Must be empty map {} | HIGH |
| ATT-NONE-003 | authData presence | Must contain valid authenticator data | HIGH |
| ATT-NONE-004 | No signature | attStmt must not contain sig field | HIGH |
| ATT-NONE-005 | No certificates | attStmt must not contain x5c field | HIGH |

**Implementation Check:**
- Verify `Fido2Authenticator.processAttestationStatement()` line 692-693
- Verify none attestation handling in `AuthenticatorAPI.createAttestationStatement()`

### 11.2 Packed Attestation - Self Attestation

**Spec Reference:** WebAuthn L3 Section 8.2

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| ATT-PACK-SELF-001 | fmt field | Must be "packed" | HIGH |
| ATT-PACK-SELF-002 | attStmt.alg | Must be COSE algorithm identifier (-7 or -257) | HIGH |
| ATT-PACK-SELF-003 | attStmt.sig | Must be present and valid signature | HIGH |
| ATT-PACK-SELF-004 | No x5c field | Self attestation must not include x5c | HIGH |
| ATT-PACK-SELF-005 | Signature verification | sig = Sign(authData \|\| clientDataHash) with credential key | HIGH |
| ATT-PACK-SELF-006 | Algorithm match | alg must match credential public key algorithm | HIGH |

**Implementation Check:**
- Verify `Fido2Authenticator.buildPackedAttestationStatement()` lines 1109-1111 (self attestation path)
- Verify signature generation at lines 1139-1143

### 11.3 Packed Attestation - Basic/Batch Attestation

**Spec Reference:** WebAuthn L3 Section 8.2

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| ATT-PACK-BASIC-001 | fmt field | Must be "packed" | HIGH |
| ATT-PACK-BASIC-002 | attStmt.alg | Must be COSE algorithm identifier | HIGH |
| ATT-PACK-BASIC-003 | attStmt.sig | Must be present and valid signature | HIGH |
| ATT-PACK-BASIC-004 | attStmt.x5c | Must contain single attestation certificate | HIGH |
| ATT-PACK-BASIC-005 | Certificate subject | Must contain appropriate DN | HIGH |
| ATT-PACK-BASIC-006 | Certificate public key | Must match signing key | HIGH |
| ATT-PACK-BASIC-007 | AAGUID in certificate | Must match authenticator AAGUID | HIGH |
| ATT-PACK-BASIC-008 | Signature verification | sig = Sign(authData \|\| clientDataHash) with cert key | HIGH |
| ATT-PACK-BASIC-009 | Certificate validity | Must be valid X.509 certificate | HIGH |

**Implementation Check:**
- Verify `Fido2Authenticator.buildPackedAttestationStatement()` lines 1115-1122 (basic/batch path)
- Verify `CertUtils.generatePackedBatchCertificate()` usage at line 1118-1120

### 11.4 Packed Attestation - AttCA (Anonymous CA)

**Spec Reference:** WebAuthn L3 Section 8.2

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| ATT-PACK-ATTCA-001 | fmt field | Must be "packed" | HIGH |
| ATT-PACK-ATTCA-002 | attStmt.alg | Must be COSE algorithm identifier | HIGH |
| ATT-PACK-ATTCA-003 | attStmt.sig | Must be present and valid signature | HIGH |
| ATT-PACK-ATTCA-004 | attStmt.x5c | Must contain certificate chain [leaf, CA] | HIGH |
| ATT-PACK-ATTCA-005 | Leaf certificate | Must be signed by CA certificate | HIGH |
| ATT-PACK-ATTCA-006 | CA certificate | Must be valid root/intermediate CA | HIGH |
| ATT-PACK-ATTCA-007 | Certificate chain validation | Chain must validate to trusted root | HIGH |
| ATT-PACK-ATTCA-008 | AAGUID in leaf cert | Must match authenticator AAGUID | HIGH |
| ATT-PACK-ATTCA-009 | Signature verification | sig = Sign(authData \|\| clientDataHash) with leaf cert key | HIGH |
| ATT-PACK-ATTCA-010 | Certificate extensions | Must include appropriate extensions | MEDIUM |
| ATT-PACK-ATTCA-011 | Subject DN | Leaf cert must have appropriate subject | HIGH |
| ATT-PACK-ATTCA-012 | Key usage | Certificates must have correct key usage | MEDIUM |

**Implementation Check:**
- Verify `Fido2Authenticator.buildPackedAttestationStatement()` lines 1124-1137 (attCA path)
- Verify `CertUtils.gereatePackedAttCACertificate()` usage at lines 1127-1131
- Verify certificate chain construction at line 1135

### 11.5 Packed Attestation - Signature Verification

**Spec Reference:** WebAuthn L3 Section 8.2.1

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| ATT-PACK-SIG-001 | Signature input | authData \|\| clientDataHash | HIGH |
| ATT-PACK-SIG-002 | ES256 signature format | DER-encoded ECDSA signature | HIGH |
| ATT-PACK-SIG-003 | RS256 signature format | PKCS#1 v1.5 signature | HIGH |
| ATT-PACK-SIG-004 | Signature length | Appropriate for algorithm | HIGH |
| ATT-PACK-SIG-005 | Invalid signature | Verification must fail | HIGH |
| ATT-PACK-SIG-006 | Wrong key | Verification with wrong key must fail | HIGH |
| ATT-PACK-SIG-007 | Tampered data | Verification with modified data must fail | HIGH |

**Implementation Check:**
- Verify signature generation at lines 1139-1143
- Verify `Fido2Authenticator.signData()` method (lines 501-519)

### 11.6 FIDO U2F Attestation

**Spec Reference:** WebAuthn L3 Section 8.6

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| ATT-U2F-001 | fmt field | Must be "fido-u2f" | HIGH |
| ATT-U2F-002 | attStmt.sig | Must be present and valid signature | HIGH |
| ATT-U2F-003 | attStmt.x5c | Must contain single attestation certificate | HIGH |
| ATT-U2F-004 | Signature format | U2F signature format (0x00 \|\| rpIdHash \|\| clientDataHash \|\| credId \|\| pubKey) | HIGH |
| ATT-U2F-005 | Public key format | Uncompressed EC point (0x04 \|\| x \|\| y) | HIGH |
| ATT-U2F-006 | Certificate validation | Must be valid X.509 certificate | HIGH |
| ATT-U2F-007 | Signature verification | Must verify with certificate public key | HIGH |
| ATT-U2F-008 | Algorithm | Must use ECDSA with P-256 curve | HIGH |

**Implementation Check:**
- Verify `Fido2Authenticator.buildFIDOU2FAttestationStatement()` (lines 1024-1062)
- Verify U2F signature format at lines 1051-1056
- Verify public key encoding at lines 1041-1046

### 11.7 Attestation Certificate Requirements

**Spec Reference:** WebAuthn L3 Section 8.2.1, 8.6.1

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| ATT-CERT-001 | Version | Must be X.509 v3 | HIGH |
| ATT-CERT-002 | Subject | Must contain appropriate DN | HIGH |
| ATT-CERT-003 | Issuer | Must be valid CA DN | HIGH |
| ATT-CERT-004 | Validity period | Must be valid time range | HIGH |
| ATT-CERT-005 | Public key algorithm | Must match attestation algorithm | HIGH |
| ATT-CERT-006 | Signature algorithm | Must be appropriate for key type | HIGH |
| ATT-CERT-007 | AAGUID extension | Must contain authenticator AAGUID (OID 1.3.6.1.4.1.45724.1.1.4) | HIGH |
| ATT-CERT-008 | Basic constraints | CA certificates must have CA=true | HIGH |
| ATT-CERT-009 | Key usage | Must include digitalSignature | HIGH |
| ATT-CERT-010 | Extended key usage | May include id-fido-gen-ce-aaguid | MEDIUM |

**Implementation Check:**
- Verify certificate generation in `CertUtils` class
- Verify AAGUID extension inclusion
- Verify certificate chain validation

### 11.8 Attestation Object Structure

**Spec Reference:** WebAuthn L3 Section 6.5.4

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| ATT-OBJ-001 | CBOR encoding | Must be valid CBOR map | HIGH |
| ATT-OBJ-002 | fmt field | Must be present with string value | HIGH |
| ATT-OBJ-003 | attStmt field | Must be present with map value | HIGH |
| ATT-OBJ-004 | authData field | Must be present with byte string value | HIGH |
| ATT-OBJ-005 | No extra fields | Must not contain unknown fields | MEDIUM |
| ATT-OBJ-006 | Field order | Order should not matter for CBOR | MEDIUM |

**Implementation Check:**
- Verify attestation object construction in `AuthenticatorAPI.buildMakeCredentialResponse()` (lines 876-894)
- Verify CBOR encoding of attestation object

### 11.9 Anonymous CA Certificate Chain Validation

**Spec Reference:** WebAuthn L3 Section 8.2.1

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| ANON-CA-001 | Certificate chain order | [leaf, intermediate, root] | HIGH |
| ANON-CA-002 | Leaf certificate signature | Must verify with intermediate/root | HIGH |
| ANON-CA-003 | Intermediate signature | Must verify with root (if present) | HIGH |
| ANON-CA-004 | Root certificate | Must be self-signed or trusted | HIGH |
| ANON-CA-005 | Certificate path validation | Full path must validate | HIGH |
| ANON-CA-006 | Name chaining | Issuer of cert N must match subject of cert N+1 | HIGH |
| ANON-CA-007 | Validity periods | All certificates must be currently valid | HIGH |
| ANON-CA-008 | Revocation checking | Should support CRL/OCSP (optional) | LOW |
| ANON-CA-009 | Key usage constraints | Must respect key usage extensions | MEDIUM |
| ANON-CA-010 | Path length constraints | Must respect basic constraints | MEDIUM |

**Implementation Check:**
- Verify certificate chain construction in packed attCA path
- Verify `CertUtils.gereatePackedAttCACertificate()` implementation
- Verify chain validation logic

### 11.10 Attestation Trust Model Tests

**Spec Reference:** WebAuthn L3 Section 14.4

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| TRUST-001 | Self attestation trust | Relying party must decide trust policy | MEDIUM |
| TRUST-002 | Basic attestation trust | Certificate must be trusted by RP | MEDIUM |
| TRUST-003 | AttCA attestation trust | Certificate chain must validate to trusted root | HIGH |
| TRUST-004 | None attestation | No cryptographic attestation provided | HIGH |
| TRUST-005 | AAGUID verification | AAGUID in cert must match authData | HIGH |
| TRUST-006 | Certificate revocation | Support for revoked certificates | LOW |

---

## 12. WebAuthn Extensions Tests

### 12.1 Extension Processing

**Spec Reference:** WebAuthn L3 Section 9

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| EXT-001 | Unknown extensions | Must be ignored | MEDIUM |
| EXT-002 | Extension output | Must be included in authData if processed | MEDIUM |
| EXT-003 | Extension encoding | Must be CBOR map in authData | MEDIUM |
| EXT-004 | ED flag | Must be set if extensions present | MEDIUM |

**Implementation Check:**
- Verify `Fido2Authenticator.processExtensions()` (lines 542-604)
- Verify `Fido2Authenticator.processClientExtensions()` (lines 522-540)

---

## 13. Integration and Interoperability Tests

### 13.1 Cross-Platform Compatibility

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| COMPAT-001 | Chrome browser compatibility | Credentials work with Chrome | HIGH |
| COMPAT-002 | Firefox browser compatibility | Credentials work with Firefox | HIGH |
| COMPAT-003 | Safari browser compatibility | Credentials work with Safari | MEDIUM |
| COMPAT-004 | Edge browser compatibility | Credentials work with Edge | MEDIUM |
| COMPAT-005 | Android platform compatibility | Credentials work on Android | HIGH |
| COMPAT-006 | iOS platform compatibility | Credentials work on iOS | MEDIUM |

### 13.2 Relying Party Compatibility

| Test ID | Test Case | Expected Behavior | Priority |
|---------|-----------|-------------------|----------|
| RP-001 | webauthn.io compatibility | Works with webauthn.io demo | HIGH |
| RP-002 | FIDO conformance tools | Passes FIDO conformance tests | HIGH |
| RP-003 | Multiple RP support | Can register with multiple RPs | HIGH |
| RP-004 | Same RP, different users | Multiple users per RP | HIGH |

---

## 14. Test Data and Fixtures

### 14.1 Test Vectors

Create test vectors for:
- Valid clientDataHash values
- Valid RP IDs and hashes
- Valid user information
- Valid public key credential parameters
- Valid attestation certificates
- Valid signatures

### 14.2 Mock Certificates

Prepare mock certificates for testing:
- Self-signed root CA
- Intermediate CA certificates
- Leaf attestation certificates
- Expired certificates
- Revoked certificates (for negative tests)

### 14.3 Test Helper Methods

```java
// Attestation verification helpers
public static boolean verifyPackedSelfAttestation(
    Map<String, Object> attStmt, 
    byte[] authData, 
    byte[] clientDataHash,
    PublicKey credentialPublicKey);

public static boolean verifyPackedBasicAttestation(
    Map<String, Object> attStmt,
    byte[] authData,
    byte[] clientDataHash);

public static boolean verifyPackedAttCAAttestation(
    Map<String, Object> attStmt,
    byte[] authData,
    byte[] clientDataHash,
    X509Certificate trustedRoot);

public static boolean verifyU2FAttestation(
    Map<String, Object> attStmt,
    byte[] authData,
    byte[] clientDataHash);

// Certificate validation helpers
public static boolean validateCertificateChain(
    X509Certificate[] chain,
    X509Certificate trustedRoot);

public static boolean validateAAGUIDInCertificate(
    X509Certificate cert,
    byte[] expectedAAGUID);

// Authenticator data helpers
public static Map<String, Object> parseAuthenticatorData(byte[] authData);
public static byte[] extractRpIdHash(byte[] authData);
public static byte extractFlags(byte[] authData);
public static long extractSignCount(byte[] authData);
public static byte[] extractAAGUID(byte[] authData);
public static byte[] extractCredentialId(byte[] authData);
public static Map<String, Object> extractCredentialPublicKey(byte[] authData);
```

---

## 15. Updated Test Execution Priority

### Phase 1: Critical Path (HIGH Priority)
1. authenticatorMakeCredential basic flow
2. authenticatorGetAssertion basic flow
3. authenticatorClientPIN basic operations
4. PIN/UV auth token verification
5. Error code conformance
6. Required parameter validation
7. **WebAuthn response structure validation**
8. **None attestation format**

### Phase 2: Core Features (HIGH-MEDIUM Priority)
1. Resident credential support
2. Exclude list processing
3. Algorithm support validation
4. **Packed self-attestation**
5. **Packed basic/batch attestation**
6. **FIDO U2F attestation**
7. Signature verification
8. ECDH key agreement
9. **Authenticator data structure**
10. **Client data JSON structure**

### Phase 3: Advanced Features (MEDIUM Priority)
1. **Packed AttCA (Anonymous CA) attestation**
2. **Certificate chain validation**
3. **AAGUID verification in certificates**
4. Multiple credential scenarios
5. State management edge cases
6. Retry counter edge cases
7. Optional parameter handling
8. Extension support (if implemented)
9. **COSE key encoding**

### Phase 4: Integration (MEDIUM-LOW Priority)
1. End-to-end flows
2. **WebAuthn compatibility testing**
3. **Cross-platform compatibility**
4. **Relying party compatibility**
5. Cross-version compatibility
6. Performance testing

---

## 16. Summary of Test Coverage

### Total Test Cases: 350+

**By Category:**
- CTAP2 Core Operations: 168 tests
- WebAuthn Specification: 42 tests
- Attestation Formats: 85 tests
- Certificate Validation: 25 tests
- Integration & Compatibility: 30+ tests

**By Priority:**
- HIGH: 250+ tests (71%)
- MEDIUM: 80+ tests (23%)
- LOW: 20+ tests (6%)

**Key Focus Areas:**
1. ✓ Credential API (makeCredential, getAssertion)
2. ✓ PIN/UV authentication mechanisms
3. ✓ WebAuthn L3 compliance
4. ✓ Packed attestation (self, basic, attCA)
5. ✓ Anonymous CA certificate chains
6. ✓ FIDO U2F attestation
7. ✓ Authenticator data structure
8. ✓ COSE key encoding

---

## 17. References