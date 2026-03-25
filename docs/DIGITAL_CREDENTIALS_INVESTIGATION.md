# Digital Credentials Investigation: Integration with FIDO2 BLE HID Authenticator

## Executive Summary

This document investigates how digital credentials (Verifiable Credentials) can be integrated with this FIDO2 BLE HID authenticator app, focusing on the evolving specifications, OIDC for VP workflows, credential storage mechanisms, and the European Digital Identity Wallet (EUDI Wallet) as a reference implementation.

**Important Note**: Passkeys (FIDO2) and Digital Credentials are handled by separate W3C APIs (WebAuthn and Digital Credentials API respectively), both extending the Credential Management API. No unified standard defines their integration - they coexist as complementary credential types serving different purposes (authentication vs attestation).

## 1. Digital Credentials vs FIDO2 Credentials

### 1.1 Fundamental Differences

**FIDO2 Credentials (Passkeys)**
- **Purpose**: Authentication - proving you are who you claim to be
- **Format**: Public/private key pairs (typically ECDSA P-256)
- **Storage**: Private keys stored securely, never leave the device
- **Usage**: Challenge-response authentication with relying parties
- **Standard**: FIDO2/WebAuthn/CTAP2 specifications
- **Browser API**: WebAuthn API (W3C Recommendation)
- **API Method**: `navigator.credentials.get({publicKey: {...}})`
- **Credential Type**: `PublicKeyCredential`
- **Binding**: Cryptographically bound to specific relying party domains

**Verifiable Credentials (VCs)**
- **Purpose**: Authorization/Attestation - proving attributes about yourself
- **Format**: JSON-LD, JSON, SD-JWT, or ISO mdoc (mobile documents)
- **Storage**: Credentials stored in wallet, can be selectively disclosed
- **Usage**: Presentation to verifiers to prove claims (age, citizenship, qualifications, etc.)
- **Standard**: W3C Verifiable Credentials Data Model 2.0
- **Browser API**: Digital Credentials API (W3C Working Draft)
- **API Method**: `navigator.credentials.get({digital: {...}})`
- **Credential Type**: `DigitalCredential`
- **Protocol Layer**: OpenID4VP, OpenID4VCI (not CTAP/WebAuthn)
- **Binding**: Can be bound to holder's DID or cryptographic key

### 1.2 Complementary Nature

These two credential types are **complementary, not competing**:
- **FIDO2** handles authentication (who you are)
- **VCs** handle authorization/attestation (what you can do, what attributes you have)
- Modern digital identity wallets often support both
- **Important**: They are governed by **separate W3C specifications** with no formal integration standard
- Both extend the **Credential Management API Level 1** but use different interfaces
- Wallet implementations can support both independently using shared infrastructure

### 1.3 Standards Architecture

**Separate but Parallel APIs:**

Both credential types use the Credential Management API but through different interfaces:

| Aspect | FIDO2/Passkeys | Digital Credentials |
|--------|----------------|---------------------|
| **Browser API** | WebAuthn API (W3C Rec) | Digital Credentials API (W3C WD) |
| **API Method** | `navigator.credentials.get({publicKey})` | `navigator.credentials.get({digital})` |
| **Protocol Layer** | CTAP2, WebAuthn | OpenID4VP, OpenID4VCI |
| **Credential Type** | `PublicKeyCredential` | `DigitalCredential` |
| **Purpose** | Authentication | Attestation/Authorization |
| **Standard Body** | W3C + FIDO Alliance | W3C + OpenID Foundation |

**Key Insight**: There is NO W3C or FIDO standard that formally defines how passkeys and digital credentials should integrate. They are:
- **Architecturally separate** - different credential types
- **Functionally complementary** - authentication vs attestation
- **Independently invoked** - separate API calls
- **Potentially combined** - a wallet app can support both

## 2. W3C Verifiable Credentials Specification

### 2.1 Core Concepts

**Three-Party Model**:
1. **Issuer**: Creates and signs credentials (e.g., government, university, employer)
2. **Holder**: Stores credentials in a wallet and presents them when needed
3. **Verifier**: Requests and validates credentials (e.g., website, service provider)

**Key Components**:
- **Claims**: Statements about a subject (e.g., "age > 18", "has driver's license")
- **Credentials**: Tamper-evident containers for claims with cryptographic proofs
- **Presentations**: Packages of credentials presented to verifiers
- **Proofs**: Cryptographic signatures or zero-knowledge proofs ensuring integrity

### 2.2 Credential Formats

**W3C VC Data Model 2.0** supports multiple formats:

1. **JSON-LD**: Linked data format with semantic context
2. **JSON**: Simple JSON with proof mechanisms
3. **SD-JWT VC**: Selective Disclosure JWT-based credentials (IETF standard)
4. **ISO mdoc**: Mobile documents format (ISO 18013-5) for driver's licenses, etc.

**SD-JWT VC** (Selective Disclosure JWT Verifiable Credentials):
- Based on IETF OAuth SD-JWT specification
- Allows selective disclosure of individual claims
- Holder can reveal only necessary information (e.g., "over 18" without revealing exact birthdate)
- Uses cryptographic hashing to protect undisclosed claims
- Becoming the preferred format for privacy-preserving credentials

**ISO mdoc** (ISO 18013-5):
- Originally designed for mobile driver's licenses (mDL)
- Uses CBOR encoding and COSE signatures
- Supports offline verification via QR codes or NFC
- Includes selective disclosure capabilities
- Widely adopted for government-issued credentials

## 3. OpenID for Verifiable Credentials

### 3.1 OIDC4VCI (OpenID for Verifiable Credential Issuance) 1.0

**Purpose**: Standardizes how credentials are issued to wallets

**Key Features**:
- OAuth 2.0-protected API for credential issuance
- Supports multiple credential formats (SD-JWT VC, ISO mdoc, W3C VCDM)
- Two main flows:
  1. **Authorization Code Flow**: User authenticates with issuer, then receives credential
  2. **Pre-Authorized Code Flow**: Issuer provides code out-of-band, user claims credential

**Credential Offer**:
- Issuer sends credential offer to wallet (via deep link, QR code, or push notification)
- Wallet retrieves issuer metadata
- Wallet requests access token using OAuth 2.0
- Wallet requests credential from credential endpoint

**Holder Binding**:
- Credentials can be cryptographically bound to holder's key
- Wallet proves possession of private key during issuance
- Supports both key-based and claims-based binding

### 3.2 OIDC4VP (OpenID for Verifiable Presentations) 1.0

**Purpose**: Standardizes how credentials are presented to verifiers

**Key Features**:
- Extension of OAuth 2.0 for credential presentation
- Introduces "VP Token" containing one or more verifiable presentations
- Supports same-device and cross-device flows
- Works with authorization requests and responses

**Presentation Flow**:
1. Verifier sends authorization request with presentation requirements
2. Wallet evaluates requirements and selects matching credentials
3. User consents to sharing selected claims
4. Wallet creates presentation with cryptographic proof
5. Wallet returns VP Token to verifier
6. Verifier validates presentation and grants access

**Selective Disclosure**:
- Wallet can present only requested claims
- Supports zero-knowledge proofs for privacy
- Verifier specifies required claims in presentation definition

## 4. European Digital Identity Wallet (EUDI Wallet)

### 4.1 Architecture Overview

The EUDI Wallet is the EU's reference implementation for digital identity wallets, mandated by the eIDAS 2.0 regulation.

**Key Components**:
1. **Person Identification Data (PID)**: Core identity attributes from government
2. **Electronic Attestation of Attributes (EAA)**: Additional credentials from various issuers
3. **Qualified Electronic Signatures/Seals**: Trust services integration
4. **Wallet Instance**: Mobile app with secure storage

**Standards Compliance**:
- Implements OIDC4VCI and OIDC4VP
- Supports SD-JWT VC and ISO mdoc formats
- Uses ISO 18013-5 for offline presentation
- Integrates with qualified trust service providers

### 4.2 Credential Storage in EUDI Wallet

**Android Implementation** (from eu-digital-identity-wallet/eudi-lib-android-wallet-core):

**Storage Architecture**:
1. **Android Keystore**: Hardware-backed secure storage for cryptographic keys
   - Private keys never leave secure element
   - Keys can require biometric authentication
   - Supports StrongBox (dedicated secure hardware) on supported devices

2. **Credential Storage**:
   - Credentials stored encrypted in app's private storage
   - Encryption keys stored in Android Keystore
   - Each credential has associated metadata (issuer, type, validity)

3. **Key Hierarchy**:
   - Master key in Android Keystore (hardware-backed)
   - Credential encryption keys derived from master key - this is similar to how passkey seed is derrived
   - Presentation keys generated per credential for holder binding

**Security Requirements** (from eIDAS 2.0):
- Level of Assurance (LoA) High requires hardware-backed keys
- Biometric authentication for sensitive operations
- Secure element or Trusted Execution Environment (TEE) for key storage
- Attestation of wallet security level

### 4.3 EUDI Wallet Credential Lifecycle

**Issuance**:
1. User authenticates with PID Provider (government)
2. Wallet generates key pair for credential binding
3. Wallet requests PID using OIDC4VCI
4. PID Provider issues credential bound to wallet's public key
5. Wallet stores encrypted credential with metadata

**Presentation**:
1. Verifier requests specific attributes via OIDC4VP
2. Wallet prompts user for consent
3. User authorizes with biometric/PIN
4. Wallet creates presentation with proof of possession
5. Verifier validates credential and proof

**Revocation**:
- Credentials include status list URLs
- Wallet periodically checks revocation status
- Expired or revoked credentials marked as invalid

## 5. Integration with FIDO2 BLE HID Authenticator

### 5.1 Current Storage Architecture

The app currently stores FIDO2 credentials using a two-layer encryption scheme:

**File Structure** (from [`Passkey.java`](lib/src/com/isfs/blekey/data/Passkey.java:42-85)):
1. **Header (230 bytes)**: Encrypted upperHash using ECDH with platform public key or KeystoreManager
2. **Length prefix (4 bytes)**: Length of PKCS12 data
3. **PKCS12 data**: Passkey private key and X.509 certificate, encrypted with full PIN hash
4. **Resident credentials**: CBOR-encoded array, ECDH encrypted with passkey public key

**Key Management**:
- Platform key pair (P-256) for ECDH encryption
- Android Keystore integration via [`KeystoreManager`](lib/src/com/isfs/blekey/data/Passkey.java:145) interface
- PIN-based encryption with hash splitting for security

### 5.2 Proposed VC Storage Architecture

**Parallel Storage Model** (similar to resident credentials):

```
Passkey File Structure (Enhanced):
├── Header (230 bytes) - Encrypted upperHash
├── PKCS12 Length (4 bytes)
├── PKCS12 Data - Passkey private key + cert
├── Resident Credentials - FIDO2 credentials
└── Verifiable Credentials - New section - CBOR encrypted array[dict]
    ├── Encrypted CBOR array
    └── For each VC:
        ├── VC Format (1 byte) - SD-JWT, mdoc, JSON-LD
        ├── VC Metadata (CBOR)
        │   ├── Issuer DID/URL
        │   ├── Credential Type
        │   ├── Issuance Date
        │   ├── Expiration Date
        │   └── Status List URL
        ├── Holder Binding Key ID (reference to Android Keystore)
        └── VC Data (encrypted with derived key)
```

**Encryption Strategy with HKDF Key Derivation**:
1. **Master Key**: Use existing platform P-256 key pair in Android Keystore as master key material
2. **Key Derivation**: For each credential, derive a unique holder binding key using HKDF (RFC 5869):
   - **Input Key Material (IKM)**: Shared secret from ECDH with platform key
   - **Salt**: Credential-specific salt (e.g., hash of credential ID)
   - **Info**: Context string including credential type and purpose
   - **Output**: 256-bit key for credential encryption and holder binding
3. **Holder Binding Key**: Store derived public key in Android Keystore with biometric authentication requirement
4. **Credential Encryption**: Encrypt each VC with its derived key
5. **Access Control**: Require biometric authentication to access holder binding keys

**HKDF Derivation Example**:
```
IKM = ECDH(platform_private_key, ephemeral_public_key)
Salt = SHA-256(credential_id || issuer_id)
Info = "EUDI-Wallet-Holder-Binding-v1" || credential_type
holder_binding_key = HKDF-Expand(HKDF-Extract(Salt, IKM), Info, 32)
```

**Advantages**:
- Reuses existing secure storage infrastructure
- Derives credential-specific keys from platform key (similar to passkey derivation)
- Hardware-backed key derivation via Android Keystore
- Biometric authentication enforced at key access level
- Each credential has unique cryptographic binding
- Consistent with FIDO2 key management patterns
- Supports key rotation without re-issuing credentials

### 5.3 Leveraging OIDC4VP for Credential Issuance

**Integration Points**:

1. **Wallet Initialization**:
   - App acts as OIDC4VCI client
   - Registers with credential issuers
   - Stores issuer metadata (endpoints, supported formats)

2. **Credential Offer Handling**:
   - Deep link handler for `openid-credential-offer://` URIs
   - QR code scanner for credential offers
   - Parse offer and display to user

3. **Issuance Flow**:
   ```
   User scans QR code → Parse credential offer
   ↓
   Retrieve issuer metadata → Display credential details
   ↓
   User consents → Generate key pair for binding
   ↓
   Request access token → Prove key possession
   ↓
   Request credential → Receive signed credential
   ↓
   Validate credential → Store encrypted in passkey file
   ```

4. **Key Binding**:
   - Generate P-256 key pair in Android Keystore
   - Include public key in credential request
   - Issuer binds credential to public key
   - Private key used for presentation proofs

5. **Presentation Flow**:
   ```
   Verifier sends auth request → Parse presentation definition
   ↓
   Match credentials → Display to user
   ↓
   User consents → Unlock with PIN/biometric
   ↓
   Create presentation → Sign with private key
   ↓
   Return VP Token → Verifier validates
   ```

### 5.4 Level of Assurance (LoA) High Requirements

**Regulatory Source**: EUDI Wallet Architecture and Reference Framework (ARF) v1.4.0, Commission Implementing Regulation (EU) 2024/2979, and Commission Implementing Regulation (EU) 2015/1502.

#### 5.4.1 Hardware-Backed Cryptographic Requirements

**LoA High** mandates the use of a **Wallet Secure Cryptographic Device (WSCD)** with a **Wallet Secure Cryptographic Application (WSCA)** that provides:

**WSCD Definition** (CIR 2024/2979):
> "A trusted hardware providing a secure environment and storage for cryptographic assets (such as keys) and for running the WSCA. This includes the keystore but also the environment where the security-critical functions are executed. The WSCD is tamper-proof and duplication-resistant."

**Critical Assets Requiring LoA High Protection**:
1. **PID (Person Identification Data) private keys** - MUST be managed at LoA High
2. **WUA (Wallet Unit Attestation) private keys** - MUST be managed at LoA High
3. **Attestation private keys with Level of Security High** - As specified by Attestation Provider

**WSCA Functional Requirements** (CIR 2024/2979, Article 5):
- Perform cryptographic operations with critical assets **only after successful user authentication**
- When authenticating users for electronic identification at LoA High, comply with CIR 2015/1502 requirements
- Securely generate new cryptographic keys
- Perform secure erasure of critical assets
- Generate proofs of possession of private keys
- Protect private keys during their entire existence
- Be the **only component** able to execute cryptographic operations with critical assets in LoA High context

**Android Implementation Options** (5 WSCD Architecture Types):

| Type | WSCD | WSCA | Hardware Security | Suitable for LoA High |
|------|------|------|-------------------|----------------------|
| **Type 4: TEE/Enclave** | Android StrongBox or TEE | Android Keystore System | Hardware-backed keystore in device SoC | ✅ **Yes** - Recommended for this app |
| Type 3: eSIM/UICC | Embedded Secure Element | JavaCard applet | Tamper-resistant SE chip | ✅ Yes |
| Type 2: Smart Card | External smart card | JavaCard applet | Removable secure hardware | ✅ Yes |
| Type 1: Remote HSM | Cloud HSM | Client library/firmware | FIPS 140-2 Level 3 HSM | ✅ Yes (requires network) |
| Type 5: Hybrid | Combination of above | Coordinator | Mixed | ✅ Yes (complex) |

**Recommended Approach for This App**: **Type 4 (TEE/Enclave with Android Keystore)**
- Leverages existing [`AndroidKeystoreManager`](app/src/main/java/com/isfs/blekey/util/AndroidKeystoreManager.java)
- Uses hardware-backed keys in StrongBox (if available) or TEE
- No additional hardware required
- Native OS integration
- Already used for FIDO2 passkey storage

#### 5.4.2 Multi-Factor Authentication Requirements

**Source**: CIR 2015/1502, Section 2.2.1 - Authentication for LoA High

**Required**: At least **two authentication factors** from different categories:

| Factor Category | Examples | Implementation in This App |
|----------------|----------|----------------------------|
| **Knowledge** | PIN, password, pattern | PIN already implemented for passkey access |
| **Possession** | Device ownership, PID with private key in WSCD | Android device + keys in StrongBox/TEE |
| **Inherence** | Biometric (fingerprint, face) | Android BiometricPrompt API |

**Implementation Strategy**:
1. **Existing**: PIN protection for passkey file access (knowledge factor)
2. **Existing**: Device possession (possession factor)
3. **Add**: Biometric authentication requirement for credential holder binding keys (inherence factor)
4. **Result**: Achieves multi-factor authentication for LoA High

**Android Keystore Configuration for LoA High**:
```java
KeyGenParameterSpec.Builder spec = new KeyGenParameterSpec.Builder(
    keyAlias,
    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
    .setDigests(KeyProperties.DIGEST_SHA256)
    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
    .setUserAuthenticationRequired(true)  // Require authentication
    .setUserAuthenticationParameters(
        0,  // Authentication valid for this operation only
        KeyProperties.AUTH_BIOMETRIC_STRONG)  // Require Class 3 biometric
    .setIsStrongBoxBacked(true);  // Use StrongBox if available
```

#### 5.4.3 Key Binding and Holder Binding

**Source**: OpenID4VP 1.0 Specification, Section on Holder Binding

**Holder Binding** proves that the entity presenting a credential is the same entity to whom it was issued. Three mechanisms are supported:

1. **Cryptographic Holder Binding** (Primary mechanism):
   - Holder proves control over the same private key used during issuance
   - Credential contains public key or reference to public key
   - Presentation includes Key Binding JWT (KB-JWT) signed with private key

2. **Biometric Holder Binding**:
   - Holder proves possession via biometric trait (fingerprint, face)
   - Example: mDL with portrait photo (ISO 18013-5)
   - Verification typically occurs locally on device

3. **Claims-based Holder Binding**:
   - Holder proves possession by presenting another credential with identifying claims
   - Enables long-term, cross-device credential use
   - Example: Diploma verified by presenting government ID

**Key Binding JWT Structure** (for cryptographic holder binding):
```json
{
  "typ": "kb+jwt",
  "alg": "ES256"
}
{
  "aud": "https://verifier.example.com",
  "nonce": "n-0S6_WzA2Mj",
  "iat": 1541493724,
  "sd_hash": "sha-256 hash of issuer-signed JWT and disclosures"
}
```

**HKDF for Holder Binding Key Derivation**:
- Use HKDF (RFC 5869) to derive credential-specific keys from platform master key
- Binds each credential to the device's hardware-backed key
- Enables key rotation without credential re-issuance
- Already have HKDF implementation in [`KeyUtils.java`](lib/src/com/isfs/blekey/util/KeyUtils.java)

### 5.5 Implementation Considerations

**New Classes Needed**:

1. **`VerifiableCredential.java`**:
   - Represents a VC with metadata
   - Supports multiple formats (SD-JWT, mdoc, JSON-LD)
   - Handles serialization/deserialization
   - Manages holder binding key reference

2. **`CredentialManager.java`**:
   - Manages VC lifecycle (issue, store, present, revoke)
   - Integrates with OIDC4VCI/OIDC4VP protocols
   - Handles credential status checking
   - Implements HKDF key derivation for holder binding

3. **`PresentationBuilder.java`**:
   - Creates verifiable presentations
   - Implements selective disclosure
   - Generates Key Binding JWTs (KB-JWT)
   - Signs presentations with holder binding keys

4. **`IssuerClient.java`**:
   - OIDC4VCI client implementation
   - Handles OAuth 2.0 flows
   - Manages issuer metadata

5. **`HolderBindingKeyManager.java`**:
   - Manages HKDF-derived holder binding keys
   - Interfaces with Android Keystore for LoA High keys
   - Enforces biometric authentication requirements
   - Handles key lifecycle (generation, rotation, deletion)

**Android Keystore Integration**:
- Extend [`AndroidKeystoreManager`](app/src/main/java/com/isfs/blekey/util/AndroidKeystoreManager.java) for VC keys
- Generate HKDF-derived key pairs for each credential using platform master key
- **Require biometric authentication** (Class 3) for all holder binding key operations
- Use **StrongBox** (if available) or **TEE** for hardware-backed key storage
- Support key attestation for high-assurance credentials
- Implement key isolation to prevent cross-credential access

**Biometric Authentication Integration**:
- Use Android BiometricPrompt API for user authentication
- Require **Class 3 biometric** (strong biometric) for LoA High
- Authenticate before any holder binding key operation
- Cache authentication for single operation only (no timeout)
- Fallback to PIN if biometric unavailable

**UI Components**:
- Credential list view (similar to resident credentials)
- Credential detail view with claims and security level indicator
- Issuance consent screen with LoA High indicator
- Presentation consent screen with selective disclosure
- Biometric authentication prompt for credential access
- Security settings for credential management

## 6. Detailed Flow Diagrams and Pseudocode

### 6.1 Credential Issuance Flow (OIDC4VCI)

This section details how the FIDO2 BLE HID Authenticator app acts as a **Holder** in the OIDC4VCI flow, accepting credential offers and performing the issuance ceremony. The implementation follows the EUDI Wallet architecture as a reference.

#### 6.1.0 Holder Role and Responsibilities

**The App as Holder**:
- The app takes the role of a **credential holder/wallet**
- It accepts credential offers through an app-agnostic interface (QR codes, deep links, NFC)
- The app-specific layer handles the transport mechanism (how the offer arrives)
- The core library handles the OIDC4VCI protocol and credential storage

**Key Responsibilities**:
1. **Offer Reception**: Accept credential offers via multiple channels
2. **User Consent**: Present offer details and obtain user approval
3. **Key Management**: Generate and manage holder binding keys in Android Keystore
4. **Protocol Execution**: Execute OIDC4VCI ceremony with issuer
5. **Credential Storage**: Store issued credentials encrypted in passkey file
6. **Credential Lifecycle**: Manage credential validity, revocation status, and updates

#### 6.1.1 Flow Diagram

```
┌─────────────┐                                    ┌─────────────┐                      ┌─────────┐
│   Issuer    │                                    │ Holder App  │                      │  User   │
│  (External) │                                    │ (This App)  │                      │         │
└──────┬──────┘                                    └──────┬──────┘                      └────┬────┘
       │                                                  │                                   │
       │ 1. Generate Credential Offer                    │                                   │
       │    (QR Code / Deep Link / NFC)                  │                                   │
       │                                                  │                                   │
       │                                                  │ 2. Scan QR / Tap NFC / Click Link│
       │                                                  │<──────────────────────────────────│
       │                                                  │                                   │
       │                                                  │ 3. Parse Offer URI                │
       │                                                  │    (openid-credential-offer://)   │
       │                                                  │                                   │
       │                                                  │ 4. Display Offer Details          │
       │                                                  │   - Issuer name & trust status    │
       │                                                  │   - Credential type & claims      │
       │                                                  │   - Validity period               │
       │                                                  │──────────────────────────────────>│
       │                                                  │                                   │
       │                                                  │ 5. User Reviews & Accepts         │
       │                                                  │<──────────────────────────────────│
       │                                                  │                                   │
       │                                                  │ 6. Generate Holder Binding Key    │
       │                                                  │    (P-256 in Android Keystore)    │
       │                                                  │    - Biometric-protected          │
       │                                                  │    - Hardware-backed              │
       │                                                  │                                   │
       │ 7. GET /.well-known/openid-credential-issuer    │                                   │
       │<────────────────────────────────────────────────│                                   │
       │                                                  │                                   │
       │ 8. Return Issuer Metadata                       │                                   │
       │    - credential_endpoint                        │                                   │
       │    - token_endpoint                             │                                   │
       │    - credentials_supported                      │                                   │
       │    - proof_types_supported                      │                                   │
       │─────────────────────────────────────────────────>│                                   │
       │                                                  │                                   │
       │                                                  │ 9. Validate Issuer Metadata       │
       │                                                  │    - Check supported formats      │
       │                                                  │    - Verify proof types           │
       │                                                  │                                   │
       │ 10. POST /token                                 │                                   │
       │     grant_type=pre-authorized_code              │                                   │
       │     pre-authorized_code=<code_from_offer>       │                                   │
       │<────────────────────────────────────────────────│                                   │
       │                                                  │                                   │
       │ 11. Return Access Token + c_nonce               │                                   │
       │     {                                           │                                   │
       │       "access_token": "...",                    │                                   │
       │       "token_type": "Bearer",                   │                                   │
       │       "expires_in": 86400,                      │                                   │
       │       "c_nonce": "...",                         │                                   │
       │       "c_nonce_expires_in": 86400               │                                   │
       │     }                                           │                                   │
       │─────────────────────────────────────────────────>│                                   │
       │                                                  │                                   │
       │                                                  │ 12. Create Key Proof (JWT)        │
       │                                                  │     - Sign with holder key        │
       │                                                  │     - Include public key (JWK)    │
       │                                                  │     - Include c_nonce             │
       │                                                  │                                   │
       │ 13. POST /credential                            │                                   │
       │     Authorization: Bearer <access_token>        │                                   │
       │     {                                           │                                   │
       │       "format": "vc+sd-jwt",                    │                                   │
       │       "credential_definition": {...},           │                                   │
       │       "proof": {                                │                                   │
       │         "proof_type": "jwt",                    │                                   │
       │         "jwt": "<signed_jwt_with_holder_key>"   │                                   │
       │       }                                         │                                   │
       │     }                                           │                                   │
       │<────────────────────────────────────────────────│                                   │
       │                                                  │                                   │
       │ 14. Validate Proof                              │                                   │
       │     - Verify JWT signature                      │                                   │
       │     - Check c_nonce                             │                                   │
       │     - Extract holder public key                 │                                   │
       │                                                  │                                   │
       │ 15. Issue Credential (bound to holder key)      │                                   │
       │     {                                           │                                   │
       │       "format": "vc+sd-jwt",                    │                                   │
       │       "credential": "<sd-jwt>~<disclosures>~",  │                                   │
       │       "c_nonce": "...",                         │                                   │
       │       "c_nonce_expires_in": 86400               │                                   │
       │     }                                           │                                   │
       │─────────────────────────────────────────────────>│                                   │
       │                                                  │                                   │
       │                                                  │ 16. Validate Credential           │
       │                                                  │     - Verify issuer signature     │
       │                                                  │     - Check holder binding        │
       │                                                  │     - Validate claims             │
       │                                                  │                                   │
       │                                                  │ 17. Encrypt & Store in Passkey    │
       │                                                  │     - ECDH encrypt with P-256 key │
       │                                                  │     - Append to passkey file      │
       │                                                  │     - Store metadata (CBOR)       │
       │                                                  │                                   │
       │                                                  │ 18. Display Success               │
       │                                                  │──────────────────────────────────>│
       │                                                  │                                   │
```

#### 6.1.2 Holder App Implementation (Pseudocode)

This implementation shows how the holder app accepts credential offers and performs the OIDC4VCI ceremony, following EUDI Wallet patterns.

```java
/**
 * Credential Issuance Handler for FIDO2 BLE HID Authenticator
 *
 * This class implements the holder side of OIDC4VCI, accepting credential
 * offers through app-agnostic interfaces and storing credentials in the
 * passkey file using ECDH encryption.
 *
 * Reference: EUDI Wallet (eu-digital-identity-wallet/eudi-lib-android-wallet-core)
 */
class CredentialIssuanceHandler {
    
    private final AndroidKeystoreManager keystoreManager;
    private final PasskeyManager passkeyManager;
    private final HttpClient httpClient;
    
    // ========================================================================
    // STEP 1: CREDENTIAL OFFER RECEPTION (App-Agnostic Interface)
    // ========================================================================
    
    /**
     * Parse credential offer from any transport mechanism.
     * The app-specific layer handles HOW the offer arrives (QR, NFC, deep link).
     * This method only cares about the OIDC4VCI protocol.
     *
     * Supported URI schemes:
     * - openid-credential-offer://?credential_offer=<json>
     * - openid-credential-offer://?credential_offer_uri=<url>
     * - https://wallet.example.com/offer?credential_offer=<json>
     */
    public CredentialOffer parseCredentialOffer(String offerUri) throws InvalidOfferException {
        URI uri = new URI(offerUri);
        
        // Extract credential offer (inline or by reference)
        String offerJson;
        if (uri.hasQueryParameter("credential_offer")) {
            // Inline offer
            offerJson = uri.getQueryParameter("credential_offer");
        } else if (uri.hasQueryParameter("credential_offer_uri")) {
            // Offer by reference - fetch from URL
            String offerUrl = uri.getQueryParameter("credential_offer_uri");
            offerJson = httpClient.get(offerUrl).body();
        } else {
            throw new InvalidOfferException("Missing credential_offer or credential_offer_uri");
        }
        
        // Parse OIDC4VCI credential offer
        JSONObject offer = new JSONObject(offerJson);
        
        return new CredentialOffer(
            offer.getString("credential_issuer"),           // Issuer URL
            offer.getJSONArray("credentials"),              // Credential types offered
            offer.optJSONObject("grants")                   // Grant information
        );
    }
    
    /**
     * Display credential offer to user for consent.
     * This is where the app-specific UI layer takes over.
     *
     * Following EUDI Wallet pattern: show issuer trust status, credential
     * type, claims to be issued, and validity period.
     */
    public OfferConsentResult displayOfferForConsent(CredentialOffer offer) {
        // App-specific UI implementation
        // Returns: ACCEPTED, REJECTED, or DEFERRED
        
        OfferDetails details = new OfferDetails();
        details.issuerName = resolveIssuerName(offer.issuerUrl);
        details.issuerTrustStatus = checkIssuerTrust(offer.issuerUrl);
        details.credentialType = offer.getCredentialType();
        details.claims = offer.getClaimsToBeIssued();
        details.validityPeriod = offer.getValidityPeriod();
        
        // Show UI and wait for user decision
        return showConsentDialog(details);
    }
    
    // ========================================================================
    // STEP 2: ISSUER METADATA DISCOVERY
    // ========================================================================
    
    /**
     * Retrieve issuer metadata from well-known endpoint.
     * This provides information about supported credential formats,
     * proof types, and endpoint URLs.
     */
    public IssuerMetadata getIssuerMetadata(String issuerUrl) throws MetadataException {
        String metadataUrl = issuerUrl + "/.well-known/openid-credential-issuer";
        
        HttpResponse response = httpClient.get(metadataUrl);
        if (response.statusCode() != 200) {
            throw new MetadataException("Failed to retrieve issuer metadata");
        }
        
        JSONObject metadata = new JSONObject(response.body());
        
        // Validate required fields
        validateMetadata(metadata);
        
        return new IssuerMetadata(
            metadata.getString("credential_issuer"),
            metadata.getString("credential_endpoint"),
            metadata.getString("token_endpoint"),
            metadata.getJSONArray("credentials_supported"),
            metadata.optJSONArray("proof_types_supported")  // jwt, cwt, ldp_vp
        );
    }
    
    private void validateMetadata(JSONObject metadata) throws MetadataException {
        // Ensure issuer supports required formats and proof types
        if (!metadata.has("credential_endpoint")) {
            throw new MetadataException("Missing credential_endpoint");
        }
        
        // Check if issuer supports SD-JWT format (preferred)
        JSONArray supported = metadata.getJSONArray("credentials_supported");
        boolean supportsSdJwt = false;
        for (int i = 0; i < supported.length(); i++) {
            if ("vc+sd-jwt".equals(supported.getJSONObject(i).optString("format"))) {
                supportsSdJwt = true;
                break;
            }
        }
        
        if (!supportsSdJwt) {
            throw new MetadataException("Issuer does not support vc+sd-jwt format");
        }
    }
    
    // ========================================================================
    // STEP 3: HOLDER BINDING KEY GENERATION
    // ========================================================================
    
    /**
     * Generate P-256 key pair for holder binding in Android Keystore.
     * This key will be cryptographically bound to the issued credential.
     *
     * Following EUDI Wallet pattern:
     * - Hardware-backed key storage (StrongBox if available)
     * - Biometric authentication required for key use
     * - Key never leaves secure element
     */
    public KeyPair generateHolderBindingKey(String credentialId) throws KeyGenerationException {
        String keyAlias = "vc_holder_" + credentialId;
        
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY
        )
        .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))  // P-256
        .setDigests(KeyProperties.DIGEST_SHA256)
        .setUserAuthenticationRequired(true)                              // Biometric required
        .setUserAuthenticationValidityDurationSeconds(30)                 // Auth timeout
        .setInvalidatedByBiometricEnrollment(true);                      // Invalidate on biometric change
        
        // Use StrongBox if available (dedicated secure hardware)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            if (keystoreManager.isStrongBoxAvailable()) {
                builder.setIsStrongBoxBacked(true);
            }
        }
        
        KeyGenParameterSpec spec = builder.build();
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore"
        );
        keyGen.initialize(spec);
        
        return keyGen.generateKeyPair();
    }
    
    // ========================================================================
    // STEP 4: TOKEN REQUEST (PRE-AUTHORIZED CODE FLOW)
    // ========================================================================
    
    /**
     * Request access token using pre-authorized code from credential offer.
     * This is the simpler of the two OIDC4VCI flows (no user authentication
     * with issuer required).
     */
    public TokenResponse requestAccessToken(
        IssuerMetadata metadata,
        CredentialOffer offer
    ) throws TokenRequestException {
        
        // Extract pre-authorized code from grants
        JSONObject grants = offer.getGrants();
        if (!grants.has("urn:ietf:params:oauth:grant-type:pre-authorized_code")) {
            throw new TokenRequestException("Pre-authorized code grant not available");
        }
        
        JSONObject preAuthGrant = grants.getJSONObject(
            "urn:ietf:params:oauth:grant-type:pre-authorized_code"
        );
        String preAuthCode = preAuthGrant.getString("pre-authorized_code");
        
        // Build token request
        JSONObject tokenRequest = new JSONObject()
            .put("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
            .put("pre-authorized_code", preAuthCode);
        
        // Add user PIN if required by issuer
        if (preAuthGrant.optBoolean("user_pin_required", false)) {
            String userPin = promptForUserPin();
            tokenRequest.put("user_pin", userPin);
        }
        
        // Send token request
        HttpResponse response = httpClient.post(
            metadata.getTokenEndpoint(),
            tokenRequest.toString(),
            Map.of("Content-Type", "application/json")
        );
        
        if (response.statusCode() != 200) {
            throw new TokenRequestException("Token request failed: " + response.body());
        }
        
        JSONObject tokenResponse = new JSONObject(response.body());
        
        return new TokenResponse(
            tokenResponse.getString("access_token"),
            tokenResponse.optString("token_type", "Bearer"),
            tokenResponse.optInt("expires_in", 86400),
            tokenResponse.optString("c_nonce"),              // Challenge nonce for proof
            tokenResponse.optInt("c_nonce_expires_in", 86400)
        );
    }
    
    // ========================================================================
    // STEP 5: KEY PROOF GENERATION (PROOF OF POSSESSION)
    // ========================================================================
    
    /**
     * Create JWT proof of possession for holder binding key.
     * This proves to the issuer that the holder controls the private key
     * that will be bound to the credential.
     *
     * JWT structure:
     * - Header: alg, typ, jwk (public key)
     * - Payload: iss, aud, iat, nonce
     * - Signature: signed with holder private key
     */
    public String createKeyProof(
        KeyPair holderKey,
        String issuerUrl,
        String cNonce
    ) throws ProofGenerationException {
        
        try {
            // Create JWT header with public key
            JSONObject header = new JSONObject()
                .put("alg", "ES256")
                .put("typ", "openid4vci-proof+jwt")
                .put("jwk", publicKeyToJWK(holderKey.getPublic()));
            
            // Create JWT payload
            long now = System.currentTimeMillis() / 1000;
            JSONObject payload = new JSONObject()
                .put("iss", getWalletClientId())              // Wallet identifier
                .put("aud", issuerUrl)                        // Issuer URL
                .put("iat", now)                              // Issued at
                .put("nonce", cNonce);                        // Challenge from token response
            
            String headerB64 = base64UrlEncode(header.toString().getBytes(UTF_8));
            String payloadB64 = base64UrlEncode(payload.toString().getBytes(UTF_8));
            String signInput = headerB64 + "." + payloadB64;
            
            // Sign with holder private key (requires biometric authentication)
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(holderKey.getPrivate());
            signature.update(signInput.getBytes(UTF_8));
            byte[] signatureBytes = signature.sign();
            
            // Convert signature to JWS format (R || S)
            byte[] jwsSignature = convertDERtoJWS(signatureBytes);
            String signatureB64 = base64UrlEncode(jwsSignature);
            
            return signInput + "." + signatureB64;
            
        } catch (Exception e) {
            throw new ProofGenerationException("Failed to create key proof", e);
        }
    }
    
    /**
     * Convert EC public key to JWK format for inclusion in JWT header.
     */
    private JSONObject publicKeyToJWK(PublicKey publicKey) throws Exception {
        ECPublicKey ecKey = (ECPublicKey) publicKey;
        ECPoint point = ecKey.getW();
        
        return new JSONObject()
            .put("kty", "EC")
            .put("crv", "P-256")
            .put("x", base64UrlEncode(point.getAffineX().toByteArray()))
            .put("y", base64UrlEncode(point.getAffineY().toByteArray()));
    }
    
    // ========================================================================
    // STEP 6: CREDENTIAL REQUEST
    // ========================================================================
    
    /**
     * Request credential from issuer with proof of key possession.
     * The issuer will validate the proof and issue a credential bound
     * to the holder's public key.
     */
    public IssuedCredential requestCredential(
        IssuerMetadata metadata,
        TokenResponse tokenResponse,
        String keyProof,
        String credentialType
    ) throws CredentialRequestException {
        
        // Build credential request
        JSONObject credentialRequest = new JSONObject()
            .put("format", "vc+sd-jwt")                      // Selective Disclosure JWT
            .put("credential_definition", new JSONObject()
                .put("type", new JSONArray().put(credentialType))
            )
            .put("proof", new JSONObject()
                .put("proof_type", "jwt")
                .put("jwt", keyProof)
            );
        
        // Send credential request with access token
        HttpResponse response = httpClient.post(
            metadata.getCredentialEndpoint(),
            credentialRequest.toString(),
            Map.of(
                "Content-Type", "application/json",
                "Authorization", "Bearer " + tokenResponse.getAccessToken()
            )
        );
        
        if (response.statusCode() != 200) {
            throw new CredentialRequestException("Credential request failed: " + response.body());
        }
        
        JSONObject credentialResponse = new JSONObject(response.body());
        
        // Extract credential (SD-JWT format: <jwt>~<disclosure>~<disclosure>~...)
        String credential = credentialResponse.getString("credential");
        
        // Extract new c_nonce for future requests (if provided)
        String newCNonce = credentialResponse.optString("c_nonce");
        int cNonceExpiresIn = credentialResponse.optInt("c_nonce_expires_in");
        
        return new IssuedCredential(
            credential,
            credentialType,
            newCNonce,
            cNonceExpiresIn
        );
    }
    
    // ========================================================================
    // STEP 7: CREDENTIAL VALIDATION
    // ========================================================================
    
    /**
     * Validate issued credential before storage.
     * Checks:
     * - Issuer signature validity
     * - Holder binding (cnf claim matches our public key)
     * - Credential structure and required claims
     * - Expiration date
     */
    public void validateCredential(
        IssuedCredential issued,
        KeyPair holderKey,
        String expectedIssuer
    ) throws CredentialValidationException {
        
        try {
            // Parse SD-JWT (format: <jwt>~<disclosure>~<disclosure>~...)
            String[] parts = issued.getCredential().split("~");
            String jwt = parts[0];
            
            // Decode JWT without verification first
            String[] jwtParts = jwt.split("\\.");
            JSONObject header = new JSONObject(new String(base64UrlDecode(jwtParts[0])));
            JSONObject payload = new JSONObject(new String(base64UrlDecode(jwtParts[1])));
            
            // 1. Verify issuer
            String issuer = payload.getString("iss");
            if (!issuer.equals(expectedIssuer)) {
                throw new CredentialValidationException("Issuer mismatch");
            }
            
            // 2. Verify holder binding (cnf claim)
            if (!payload.has("cnf")) {
                throw new CredentialValidationException("Missing holder binding (cnf)");
            }
            JSONObject cnf = payload.getJSONObject("cnf");
            JSONObject jwk = cnf.getJSONObject("jwk");
            
            // Compare with our public key
            if (!matchesPublicKey(jwk, holderKey.getPublic())) {
                throw new CredentialValidationException("Holder binding key mismatch");
            }
            
            // 3. Verify expiration
            if (payload.has("exp")) {
                long exp = payload.getLong("exp");
                long now = System.currentTimeMillis() / 1000;
                if (exp < now) {
                    throw new CredentialValidationException("Credential expired");
                }
            }
            
            // 4. Verify issuer signature
            PublicKey issuerPublicKey = resolveIssuerPublicKey(issuer, header);
            if (!verifyJWTSignature(jwt, issuerPublicKey)) {
                throw new CredentialValidationException("Invalid issuer signature");
            }
            
            // 5. Validate SD-JWT disclosures (if present)
            if (parts.length > 1) {
                validateDisclosures(parts, payload);
            }
            
        } catch (Exception e) {
            throw new CredentialValidationException("Credential validation failed", e);
        }
    }
    
    // ========================================================================
    // STEP 8: CREDENTIAL STORAGE IN PASSKEY FILE
    // ========================================================================
    
    /**
     * Store validated credential in passkey file using ECDH encryption.
     * This extends the existing resident credential storage mechanism.
     *
     * Storage format (appended to passkey file):
     * - VC Count (4 bytes)
     * - For each VC:
     *   - VC Length (4 bytes)
     *   - VC Format (1 byte): 0x01=SD-JWT, 0x02=mdoc, 0x03=JSON-LD
     *   - VC Metadata (CBOR-encoded)
     *   - VC Data (ECDH-encrypted)
     */
    public void storeCredentialInPasskey(
        IssuedCredential issued,
        KeyPair holderKey,
        Passkey passkey
    ) throws StorageException {
        
        try {
            // 1. Prepare credential metadata (CBOR-encoded)
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("issuer", extractIssuer(issued.getCredential()));
            metadata.put("type", issued.getCredentialType());
            metadata.put("issuedAt", extractIssuanceDate(issued.getCredential()));
            metadata.put("expiresAt", extractExpirationDate(issued.getCredential()));
            metadata.put("statusListUrl", extractStatusListUrl(issued.getCredential()));
            metadata.put("holderKeyAlias", getKeyAlias(holderKey));
            
            byte[] metadataCbor = Cbor.encode(metadata);
            
            // 2. Encrypt credential with ECDH
            // Use passkey's P-256 encryption key (same as resident credentials)
            PublicKey passkeyPubKey = passkey.getEncryptionPublicKey();
            byte[] credentialBytes = issued.getCredential().getBytes(UTF_8);
            byte[] encryptedCredential = KeyUtils.ecdhEncrypt(
                credentialBytes,
                passkeyPubKey
            );
            
            // 3. Build VC entry
            ByteArrayOutputStream vcEntry = new ByteArrayOutputStream();
            
            // VC Length (4 bytes)
            int vcLength = 1 + metadataCbor.length + encryptedCredential.length;
            vcEntry.write(ByteUtils.intToBytes(vcLength));
            
            // VC Format (1 byte)
            vcEntry.write(0x01);  // SD-JWT format
            
            // VC Metadata (CBOR)
            vcEntry.write(metadataCbor);
            
            // VC Data (encrypted)
            vcEntry.write(encryptedCredential);
            
            // 4. Append to passkey file
            passkeyManager.appendVerifiableCredential(passkey, vcEntry.toByteArray());
            
        } catch (Exception e) {
            throw new StorageException("Failed to store credential in passkey", e);
        }
    }
    
    // ========================================================================
    // COMPLETE ISSUANCE FLOW
    // ========================================================================
    
    /**
     * Execute complete OIDC4VCI issuance ceremony.
     * This is the main entry point called by the app-specific layer
     * when a credential offer is received.
     */
    public void executeIssuanceCeremony(String offerUri, Passkey passkey)
        throws IssuanceException {
        
        try {
            // Step 1: Parse credential offer
            CredentialOffer offer = parseCredentialOffer(offerUri);
            
            // Step 2: Display offer and get user consent
            OfferConsentResult consent = displayOfferForConsent(offer);
            if (consent != OfferConsentResult.ACCEPTED) {
                throw new IssuanceException("User rejected credential offer");
            }
            
            // Step 3: Retrieve issuer metadata
            IssuerMetadata metadata = getIssuerMetadata(offer.getIssuerUrl());
            
            // Step 4: Generate holder binding key
            String credentialId = UUID.randomUUID().toString();
            KeyPair holderKey = generateHolderBindingKey(credentialId);
            
            // Step 5: Request access token
            TokenResponse tokenResponse = requestAccessToken(metadata, offer);
            
            // Step 6: Create key proof
            String keyProof = createKeyProof(
                holderKey,
                offer.getIssuerUrl(),
                tokenResponse.getCNonce()
            );
            
            // Step 7: Request credential
            IssuedCredential issued = requestCredential(
                metadata,
                tokenResponse,
                keyProof,
                offer.getCredentialType()
            );
            
            // Step 8: Validate credential
            validateCredential(issued, holderKey, offer.getIssuerUrl());
            
            // Step 9: Store credential in passkey
            storeCredentialInPasskey(issued, holderKey, passkey);
            
            // Step 10: Notify user of success
            notifyIssuanceSuccess(issued.getCredentialType());
            
        } catch (Exception e) {
            throw new IssuanceException("Credential issuance failed", e);
        }
    }
}
```

**Key Implementation Notes**:

1. **App-Agnostic Interface**: The `parseCredentialOffer()` method accepts offers from any transport (QR, NFC, deep link). The app-specific layer handles the transport mechanism.

2. **EUDI Wallet Patterns**:
   - Hardware-backed key storage (Android Keystore with StrongBox)
   - Biometric authentication for key operations
   - Issuer trust validation before acceptance
   - Comprehensive credential validation

3. **Storage Integration**: Credentials are stored in the passkey file using the same ECDH encryption as resident credentials, maintaining consistency with existing architecture.

4. **Security**:
   - Holder binding keys never leave Android Keystore
   - Credentials encrypted with P-256 ECDH
   - Biometric authentication required for key use
   - Issuer signature validation before storage

5. **Error Handling**: Each step can throw specific exceptions, allowing the app layer to provide appropriate user feedback.

### 6.2 Credential Presentation Flow (OIDC4VP)

#### 6.2.0 Holder Role in Verification

**The App as Holder/Wallet**:
- The app takes the role of a **credential holder** responding to verification requests
- It provides an app-agnostic interface to receive presentation requests (QR codes, deep links, NFC, Browser API)
- The app-specific layer handles the transport mechanism (how the request arrives)
- The core library handles the OIDC4VP protocol and credential presentation ceremony

**Key Responsibilities**:
1. **Request Reception**: Accept presentation requests via multiple channels
2. **Credential Matching**: Identify stored credentials that satisfy verifier requirements
3. **User Consent**: Present verification details and obtain user approval for selective disclosure
4. **Authentication**: Verify user identity via biometric/PIN before accessing credentials
5. **Presentation Creation**: Generate cryptographic proof of possession and selective disclosure
6. **Response Submission**: Submit VP Token to verifier with presentation submission descriptor

**Verification Request Interface** (App-Agnostic):
The app doesn't care HOW the verification request arrives - it could be:
- QR code scanned by user (openid4vp:// URI)
- Deep link from another app (Android Intent)
- NFC tap (NDEF message with request URI)
- Browser Digital Credentials API (navigator.credentials.get())
- Push notification with request URI

The app-specific layer extracts the authorization request URI and passes it to the core OIDC4VP handler.

#### 6.2.1 Flow Diagram

```
┌──────────────┐                                    ┌─────────────┐                      ┌─────────┐
│   Verifier   │                                    │ Holder App  │                      │  User   │
│  (External)  │                                    │ (This App)  │                      │         │
└──────┬───────┘                                    └──────┬──────┘                      └────┬────┘
       │                                                   │                                   │
       │ 1. Generate Authorization Request                │                                   │
       │    (presentation_definition + nonce)             │                                   │
       │    - Specify required credential types           │                                   │
       │    - Define required claims/attributes           │                                   │
       │    - Include response_uri for callback           │                                   │
       │                                                   │                                   │
       │                                                   │ 2. Receive Request (App-Agnostic)│
       │                                                   │    - QR Code: openid4vp://...    │
       │                                                   │    - Deep Link: Intent           │
       │                                                   │    - NFC: NDEF message           │
       │                                                   │    - Browser API: credentials.get│
       │                                                   │<──────────────────────────────────│
       │                                                   │                                   │
       │ 3. GET Authorization Request (if by reference)   │                                   │
       │    (request_uri from QR/deep link)               │                                   │
       │<──────────────────────────────────────────────────│                                   │
       │                                                   │                                   │
       │ 4. Return Authorization Request Object           │                                   │
       │    {                                             │                                   │
       │      "response_type": "vp_token",                │                                   │
       │      "client_id": "https://verifier.example",    │                                   │
       │      "response_uri": "https://verifier.../resp", │                                   │
       │      "nonce": "...",                             │                                   │
       │      "presentation_definition": {...}            │                                   │
       │    }                                             │                                   │
       │──────────────────────────────────────────────────>│                                   │
       │                                                   │                                   │
       │                                                   │ 5. Parse Presentation Definition  │
       │                                                   │    - Extract input_descriptors    │
       │                                                   │    - Identify required formats    │
       │                                                   │    - Parse constraints            │
       │                                                   │                                   │
       │                                                   │ 6. Match Stored Credentials       │
       │                                                   │    - Load VCs from passkey file   │
       │                                                   │    - Filter by credential type    │
       │                                                   │    - Check claim availability     │
       │                                                   │    - Validate not expired/revoked │
       │                                                   │                                   │
       │                                                   │ 7. Display Consent UI             │
       │                                                   │    - Show verifier identity       │
       │                                                   │    - List requested claims        │
       │                                                   │    - Show matched credentials     │
       │                                                   │    - Allow selective disclosure   │
       │                                                   │──────────────────────────────────>│
       │                                                   │                                   │
       │                                                   │ 8. User Reviews & Approves        │
       │                                                   │    - Selects credential(s)        │
       │                                                   │    - Chooses claims to share      │
       │                                                   │    - Confirms presentation        │
       │                                                   │<──────────────────────────────────│
       │                                                   │                                   │
       │                                                   │ 9. Authenticate User              │
       │                                                   │    - Biometric (fingerprint/face) │
       │                                                   │    - Or PIN entry                 │
       │                                                   │──────────────────────────────────>│
       │                                                   │                                   │
       │                                                   │ 10. Authentication Success        │
       │                                                   │<──────────────────────────────────│
       │                                                   │                                   │
       │                                                   │ 11. Decrypt Credential            │
       │                                                   │     - Retrieve VC encryption key  │
       │                                                   │     - ECDH decrypt from passkey   │
       │                                                   │     - Parse SD-JWT credential     │
       │                                                   │                                   │
       │                                                   │ 12. Create Selective Disclosure   │
       │                                                   │     - Select requested disclosures│
       │                                                   │     - Filter claims per consent   │
       │                                                   │     - Prepare disclosure array    │
       │                                                   │                                   │
       │                                                   │ 13. Create Key Binding JWT        │
       │                                                   │     - Sign with holder binding key│
       │                                                   │     - Include nonce from verifier │
       │                                                   │     - Include audience (client_id)│
       │                                                   │     - Add sd_hash of credential   │
       │                                                   │                                   │
       │                                                   │ 14. Assemble VP Token             │
       │                                                   │     - Combine issuer JWT          │
       │                                                   │     - Add selected disclosures    │
       │                                                   │     - Append key binding JWT      │
       │                                                   │     - Wrap in VP envelope         │
       │                                                   │                                   │
       │                                                   │ 15. Create Presentation Submission│
       │                                                   │     - Map credentials to inputs   │
       │                                                   │     - Create descriptor_map       │
       │                                                   │     - Reference definition_id     │
       │                                                   │                                   │
       │ 16. POST /response                               │                                   │
       │     {                                            │                                   │
       │       "vp_token": "<sd-jwt>~<disc>~...~<kb-jwt>",│                                   │
       │       "presentation_submission": {               │                                   │
       │         "id": "...",                             │                                   │
       │         "definition_id": "...",                  │                                   │
       │         "descriptor_map": [...]                  │                                   │
       │       }                                          │                                   │
       │     }                                            │                                   │
       │<──────────────────────────────────────────────────│                                   │
       │                                                   │                                   │
       │ 17. Validate VP Token                            │                                   │
       │     - Verify issuer signature on credential      │                                   │
       │     - Verify key binding JWT signature           │                                   │
       │     - Check nonce matches request                │                                   │
       │     - Validate holder binding (cnf claim)        │                                   │
       │     - Check credential not expired/revoked       │                                   │
       │     - Verify disclosed claims match request      │                                   │
       │                                                   │                                   │
       │ 18. Return Success Response                      │                                   │
       │     {                                            │                                   │
       │       "redirect_uri": "https://app.example/ok"   │                                   │
       │     }                                            │                                   │
       │──────────────────────────────────────────────────>│                                   │
       │                                                   │                                   │
       │                                                   │ 19. Display Success               │
       │                                                   │     - Show verification complete  │
       │                                                   │     - Display shared claims       │
       │                                                   │     - Log presentation event      │
       │                                                   │──────────────────────────────────>│
       │                                                   │                                   │
```

#### 6.2.2 Holder Implementation (Pseudocode)

```java
/**
 * Holder-side credential presentation implementation
 * Handles OIDC4VP protocol for responding to verification requests
 *
 * Based on EUDI Wallet architecture and OIDC4VP 1.0 specification
 */
class CredentialPresentationHandler {
    
    private final PasskeyManager passkeyManager;
    private final AndroidKeystoreManager keystoreManager;
    private final HttpClient httpClient;
    
    /**
     * Main entry point for presentation flow
     * Called by app-specific layer after receiving verification request
     *
     * @param requestUri The authorization request URI (from QR/deep link/NFC/Browser API)
     */
    public void handlePresentationRequest(String requestUri) {
        try {
            // Step 1: Parse and fetch authorization request
            PresentationRequest request = parseAuthRequest(requestUri);
            
            // Step 2: Match credentials against requirements
            List<MatchedCredential> matches = matchCredentials(
                request.presentationDefinition
            );
            
            if (matches.isEmpty()) {
                showError("No matching credentials found");
                return;
            }
            
            // Step 3: Get user consent
            UserConsent consent = showConsentUI(request, matches);
            if (!consent.approved) {
                sendErrorResponse(request, "user_cancelled");
                return;
            }
            
            // Step 4: Authenticate user
            if (!authenticateUser()) {
                sendErrorResponse(request, "authentication_failed");
                return;
            }
            
            // Step 5: Create and submit presentation
            submitPresentation(request, consent);
            
            // Step 6: Show success
            showSuccess("Credential presented successfully");
            
        } catch (Exception e) {
            handleError(e);
        }
    }
    
    /**
     * Step 1: Parse authorization request from verifier
     * Supports both request by value and request by reference
     */
    private PresentationRequest parseAuthRequest(String requestUri) {
        // Extract request URI from various formats
        String cleanUri = extractRequestUri(requestUri);
        
        // Check if request is by reference (request_uri parameter)
        if (cleanUri.contains("request_uri=")) {
            // Fetch actual request from URI
            String requestObjectUri = extractParameter(cleanUri, "request_uri");
            HttpResponse response = httpClient.get(requestObjectUri);
            
            if (response.statusCode() != 200) {
                throw new PresentationException("Failed to fetch request object");
            }
            
            // Parse JWT or JSON request object
            return parseRequestObject(response.body());
        } else {
            // Request by value - parse directly
            return parseRequestObject(cleanUri);
        }
    }
    
    private PresentationRequest parseRequestObject(String requestData) {
        JSONObject authRequest;
        
        // Check if JWT format
        if (requestData.contains(".")) {
            // Verify and decode JWT
            authRequest = verifyAndDecodeJWT(requestData);
        } else {
            // Plain JSON
            authRequest = new JSONObject(requestData);
        }
        
        // Validate required fields
        validateAuthRequest(authRequest);
        
        return new PresentationRequest(
            authRequest.getString("client_id"),
            authRequest.getString("response_uri"),
            authRequest.getString("nonce"),
            authRequest.getString("response_type"), // Should be "vp_token"
            PresentationDefinition.parse(
                authRequest.getJSONObject("presentation_definition")
            ),
            authRequest.optString("state", null)
        );
    }
    
    /**
     * Step 2: Match stored credentials against presentation definition
     * Implements DIF Presentation Exchange matching logic
     */
    private List<MatchedCredential> matchCredentials(
        PresentationDefinition definition
    ) {
        List<MatchedCredential> matches = new ArrayList<>();
        
        // Load all stored credentials from passkey file
        List<VerifiableCredential> credentials = loadStoredCredentials();
        
        // Match against each input descriptor
        for (InputDescriptor descriptor : definition.inputDescriptors) {
            for (VerifiableCredential cred : credentials) {
                // Check format compatibility
                if (!descriptor.format.contains(cred.format)) {
                    continue;
                }
                
                // Check credential type
                if (!credentialTypeMatches(cred, descriptor)) {
                    continue;
                }
                
                // Check constraints (required claims)
                if (!constraintsSatisfied(cred, descriptor.constraints)) {
                    continue;
                }
                
                // Check validity
                if (cred.isExpired() || cred.isRevoked()) {
                    continue;
                }
                
                matches.add(new MatchedCredential(cred, descriptor));
            }
        }
        
        return matches;
    }
    
    /**
     * Load credentials from passkey file
     * Credentials are stored encrypted alongside FIDO2 credentials
     */
    private List<VerifiableCredential> loadStoredCredentials() {
        // Load VCs from passkey file (see section 5.2 for storage format)
        byte[] passkeyData = passkeyManager.loadPasskeyFile();
        
        // Parse VC section from passkey file
        int vcOffset = findVCSection(passkeyData);
        int vcCount = ByteBuffer.wrap(passkeyData, vcOffset, 4).getInt();
        
        List<VerifiableCredential> credentials = new ArrayList<>();
        int offset = vcOffset + 4;
        
        for (int i = 0; i < vcCount; i++) {
            // Read VC length and format
            int vcLength = ByteBuffer.wrap(passkeyData, offset, 4).getInt();
            offset += 4;
            
            byte vcFormat = passkeyData[offset];
            offset += 1;
            
            // Read metadata (CBOR)
            byte[] metadataBytes = Arrays.copyOfRange(
                passkeyData, offset, offset + 200 // Approximate metadata size
            );
            VCMetadata metadata = VCMetadata.fromCBOR(metadataBytes);
            offset += metadata.getEncodedSize();
            
            // Read encrypted VC data
            byte[] encryptedVC = Arrays.copyOfRange(
                passkeyData, offset, offset + vcLength
            );
            offset += vcLength;
            
            // Store encrypted - will decrypt only after user authentication
            VerifiableCredential vc = new VerifiableCredential(
                encryptedVC, vcFormat, metadata, true // encrypted flag
            );
            credentials.add(vc);
        }
        
        return credentials;
    }
    
    /**
     * Step 3: Show consent UI and get user approval
     */
    private UserConsent showConsentUI(
        PresentationRequest request,
        List<MatchedCredential> matches
    ) {
        // Display UI showing:
        // - Verifier identity (client_id)
        // - Requested credential types
        // - Requested claims/attributes
        // - Matched credentials available
        // - Allow user to select which claims to share (selective disclosure)
        
        return ConsentActivity.show(request, matches);
    }
    
    /**
     * Step 4: Authenticate user before accessing credentials
     */
    private boolean authenticateUser() {
        // Use Android BiometricPrompt or PIN entry
        // This unlocks access to Android Keystore keys
        return BiometricAuthenticator.authenticate(
            "Verify your identity to present credential"
        );
    }
    
    /**
     * Step 5: Create and submit presentation
     */
    private void submitPresentation(
        PresentationRequest request,
        UserConsent consent
    ) {
        // Decrypt selected credentials (now that user is authenticated)
        List<VerifiableCredential> decryptedCreds = new ArrayList<>();
        for (MatchedCredential match : consent.selectedCredentials) {
            byte[] decrypted = decryptCredential(match.credential.encryptedData);
            VerifiableCredential vc = parseCredential(
                decrypted, match.credential.format, match.credential.metadata
            );
            decryptedCreds.add(vc);
        }
        
        // Create presentations with selective disclosure
        List<String> presentations = new ArrayList<>();
        for (VerifiableCredential cred : decryptedCreds) {
            String presentation = createSelectiveDisclosurePresentation(
                cred,
                consent.selectedClaims,
                request.nonce,
                request.clientId
            );
            presentations.add(presentation);
        }
        
        // Create VP Token
        String vpToken = createVPToken(
            presentations,
            request.nonce,
            request.clientId
        );
        
        // Create presentation submission descriptor
        PresentationSubmission submission = createPresentationSubmission(
            request.presentationDefinition,
            decryptedCreds
        );
        
        // Submit to verifier
        JSONObject response = new JSONObject()
            .put("vp_token", vpToken)
            .put("presentation_submission", submission.toJSON());
        
        if (request.state != null) {
            response.put("state", request.state);
        }
        
        HttpResponse result = httpClient.post(
            request.responseUri,
            response.toString(),
            "application/json"
        );
        
        if (result.statusCode() != 200) {
            throw new PresentationException("Presentation rejected: " + result.body());
        }
    }
    
    /**
     * Create selective disclosure presentation for SD-JWT VC
     */
    private String createSelectiveDisclosurePresentation(
        VerifiableCredential credential,
        List<String> requestedClaims,
        String nonce,
        String audience
    ) {
        // Parse SD-JWT credential
        SDJWTCredential sdJwt = SDJWTCredential.parse(credential.raw);
        
        // Select only requested disclosures
        List<String> selectedDisclosures = new ArrayList<>();
        for (String claim : requestedClaims) {
            String disclosure = sdJwt.getDisclosureForClaim(claim);
            if (disclosure != null) {
                selectedDisclosures.add(disclosure);
            }
        }
        
        // Create key binding JWT (proof of possession)
        KeyPair bindingKey = credential.getHolderBindingKey();
        String kbJwt = createKeyBindingJWT(
            bindingKey,
            nonce,
            audience,
            sdJwt.getHash()
        );
        
        // Assemble: issuer-signed JWT ~ disclosures ~ key binding JWT
        return sdJwt.issuerJwt + "~" +
               String.join("~", selectedDisclosures) + "~" +
               kbJwt;
    }
    
    /**
     * Create key binding JWT for holder binding
     */
    private String createKeyBindingJWT(
        KeyPair bindingKey,
        String nonce,
        String audience,
        String sdHash
    ) {
        JSONObject header = new JSONObject()
            .put("alg", "ES256")
            .put("typ", "kb+jwt");
        
        long now = System.currentTimeMillis() / 1000;
        JSONObject payload = new JSONObject()
            .put("iat", now)
            .put("aud", audience)
            .put("nonce", nonce)
            .put("sd_hash", sdHash);
        
        return signJWT(header, payload, bindingKey.getPrivate());
    }
    
    /**
     * Create VP Token wrapping the presentations
     */
    private String createVPToken(
        List<String> presentations,
        String nonce,
        String audience
    ) {
        // For SD-JWT VCs, the VP Token can be the presentation itself
        // or wrapped in a W3C VP envelope depending on verifier requirements
        
        if (presentations.size() == 1) {
            // Single credential - return directly
            return presentations.get(0);
        } else {
            // Multiple credentials - wrap in VP
            JSONObject vp = new JSONObject()
                .put("@context", new JSONArray()
                    .put("https://www.w3.org/2018/credentials/v1")
                )
                .put("type", new JSONArray()
                    .put("VerifiablePresentation")
                )
                .put("verifiableCredential", new JSONArray(presentations));
            
            // Sign the VP
            JSONObject vpHeader = new JSONObject()
                .put("alg", "ES256")
                .put("typ", "JWT");
            
            long now = System.currentTimeMillis() / 1000;
            JSONObject vpPayload = new JSONObject()
                .put("aud", audience)
                .put("iat", now)
                .put("nonce", nonce)
                .put("vp", vp);
            
            KeyPair holderKey = getHolderKey();
            return signJWT(vpHeader, vpPayload, holderKey.getPrivate());
        }
    }
    
    /**
     * Create presentation submission descriptor
     * Maps credentials to input descriptors
     */
    private PresentationSubmission createPresentationSubmission(
        PresentationDefinition definition,
        List<VerifiableCredential> credentials
    ) {
        List<DescriptorMap> descriptorMaps = new ArrayList<>();
        
        for (int i = 0; i < credentials.size(); i++) {
            VerifiableCredential cred = credentials.get(i);
            InputDescriptor descriptor = definition.inputDescriptors.get(i);
            
            descriptorMaps.add(new DescriptorMap(
                descriptor.id,
                cred.format,
                "$" // Path to credential in VP Token
            ));
        }
        
        return new PresentationSubmission(
            UUID.randomUUID().toString(),
            definition.id,
            descriptorMaps
        );
    }
    
    /**
     * Decrypt credential using ECDH with holder's private key
     */
    private byte[] decryptCredential(byte[] encryptedData) {
        // Retrieve VC encryption key from Android Keystore
        PrivateKey vcEncryptionKey = keystoreManager.getKey("vc_encryption_key");
        
        // Perform ECDH decryption
        return ECDHCrypto.decrypt(encryptedData, vcEncryptionKey);
    }
    
    /**
     * Send error response to verifier
     */
    private void sendErrorResponse(PresentationRequest request, String error) {
        JSONObject response = new JSONObject()
            .put("error", error);
        
        if (request.state != null) {
            response.put("state", request.state);
        }
        
        httpClient.post(
            request.responseUri,
            response.toString(),
            "application/json"
        );
    }
}

/**
 * Supporting data classes
 */
class PresentationRequest {
    String clientId;
    String responseUri;
    String nonce;
    String responseType;
    PresentationDefinition presentationDefinition;
    String state;
}

class MatchedCredential {
    VerifiableCredential credential;
    InputDescriptor descriptor;
}

class UserConsent {
    boolean approved;
    List<MatchedCredential> selectedCredentials;
    List<String> selectedClaims;
}

class PresentationSubmission {
    String id;
    String definitionId;
    List<DescriptorMap> descriptorMap;
}
```

**Key Differences from Issuance Flow**:

1. **Request Reception**: App-agnostic interface accepts requests from multiple sources
2. **Credential Matching**: Evaluates stored credentials against verifier requirements
3. **User Consent**: Explicit approval required before sharing any data
4. **Selective Disclosure**: User controls which claims are shared
5. **Proof of Possession**: Key binding JWT proves holder controls the credential
6. **No Issuer Interaction**: Presentation is self-contained, verifier validates independently

**EUDI Wallet Alignment**:
- Hardware-backed key storage (Android Keystore)
- Biometric authentication before credential access
- Encrypted credential storage in passkey file
- Support for SD-JWT VC format with selective disclosure
- DIF Presentation Exchange for credential matching
- OIDC4VP protocol for standardized presentation

### 6.2.3 Credential Presentation - Complete Flow Example

```java
// Example: Complete presentation flow
public class PresentationExample {
    
    public static void main(String[] args) {
        // 1. App receives verification request (from QR code)
        String requestUri = "openid4vp://?request_uri=https://verifier.example/request/abc123";
        
        // 2. Initialize handler
        CredentialPresentationHandler handler = new CredentialPresentationHandler(
            new PasskeyManager(),
            new AndroidKeystoreManager(),
            new HttpClient()
        );
        
        // 3. Handle presentation request
        // This will:
        // - Fetch and parse the authorization request
        // - Match credentials against requirements
        // - Show consent UI to user
        // - Authenticate user with biometric/PIN
        // - Create selective disclosure presentation
        // - Submit VP Token to verifier
        handler.handlePresentationRequest(requestUri);
    }
}
```

### 6.2.4 Error Handling

```java
// Error responses follow OAuth 2.0 error codes
class PresentationErrors {
    public static final String USER_CANCELLED = "user_cancelled";
    public static final String INVALID_REQUEST = "invalid_request";
    public static final String AUTHENTICATION_FAILED = "authentication_failed";
    public static final String NO_MATCHING_CREDENTIALS = "no_matching_credentials";
    public static final String CREDENTIAL_EXPIRED = "credential_expired";
    public static final String CREDENTIAL_REVOKED = "credential_revoked";
}
```

### 6.2.5 Security Considerations for Presentation

1. **Verifier Authentication**: Validate verifier's identity before presenting credentials
2. **Nonce Validation**: Ensure nonce is fresh to prevent replay attacks
3. **Selective Disclosure**: Only share explicitly approved claims
4. **Key Binding**: Prove possession of holder binding key
5. **User Consent**: Require explicit approval for each presentation
6. **Audit Logging**: Log all presentation events for user review
7. **Revocation Checking**: Verify credential not revoked before presenting

### 6.2.6 Presentation vs Issuance - Key Differences

| Aspect | Issuance (OIDC4VCI) | Presentation (OIDC4VP) |
|--------|---------------------|------------------------|
| **Initiator** | Issuer offers credential | Verifier requests credential |
| **User Action** | Accept credential offer | Approve credential sharing |
| **Key Generation** | Generate holder binding key | Use existing binding key |
| **Proof** | Prove key possession to issuer | Prove key possession to verifier |
| **Result** | Store encrypted credential | Share selected claims |
| **Issuer Role** | Active participant | Not involved |
| **Selective Disclosure** | N/A | User selects claims to share |


### 6.3 Browser API Integration (Digital Credentials API)

#### 6.3.1 Browser-Side Request Example

```javascript
// Verifier website requesting credential via Digital Credentials API
async function requestCredential() {
    // Check if API is supported
    if (!window.DigitalCredential) {
        console.error('Digital Credentials API not supported');
        return;
    }
    
    // Check if protocol is allowed
    const isAllowed = await DigitalCredential.userAgentAllowsProtocol(
        'openid4vp'
    );
    
    if (!isAllowed) {
        console.error('OpenID4VP protocol not allowed');
        return;
    }
    
    // Define presentation requirements
    const presentationDefinition = {
        id: 'age_verification',
        input_descriptors: [{
            id: 'age_credential',
            constraints: {
                fields: [{
                    path: ['$.credentialSubject.age'],
                    filter: {
                        type: 'number',
                        minimum: 18
                    }
                }]
            }
        }]
    };
    
    // Request credential
    try {
        const credential = await navigator.credentials.get({
            digital: {
                requests: [{
                    protocol: 'openid4vp',
                    data: {
                        client_id: 'https://verifier.example.com',
                        nonce: generateNonce(),
                        presentation_definition: presentationDefinition
                    }
                }]
            }
        });
        
        // Process received VP Token
        if (credential && credential.data) {
            const vpToken = credential.data.vp_token;
            await verifyPresentation(vpToken);
            console.log('Credential verified successfully');
        }
    } catch (error) {
        console.error('Credential request failed:', error);
    }
}

// Issuer website issuing credential via Digital Credentials API
async function issueCredential() {
    // Check if API is supported
    if (!window.DigitalCredential) {
        console.error('Digital Credentials API not supported');
        return;
    }
    
    // Generate credential offer
    const credentialOffer = {
        credential_issuer: 'https://issuer.example.com',
        credentials: ['UniversityDegree'],
        grants: {
            'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
                'pre-authorized_code': generatePreAuthCode()
            }
        }
    };
    
    // Issue credential
    try {
        const result = await navigator.credentials.create({
            digital: {
                requests: [{
                    protocol: 'openid4vci',
                    data: credentialOffer
                }]
            }
        });
        
        console.log('Credential issued successfully');
    } catch (error) {
        console.error('Credential issuance failed:', error);
    }
}
```

### 6.4 Browser API Support Status (2026)

**Digital Credentials API Implementation Status:**

The **W3C Digital Credentials API** is a separate specification from WebAuthn, designed specifically for verifiable credentials:

- **Specification Status**: W3C Working Draft (on Recommendation track)
- **Chrome**: Shipping implementation (2026)
- **Safari**: Shipping implementation (2026)
- **Firefox**: Under consideration
- **Edge**: Following Chromium implementation

**Key Differences from WebAuthn:**
- Uses `navigator.credentials.get({digital: {...}})` instead of `navigator.credentials.get({publicKey: {...}})`
- Returns `DigitalCredential` objects instead of `PublicKeyCredential`
- Protocol-agnostic: supports OpenID4VP, OpenID4VCI (NOT WebAuthn/CTAP)
- Cross-device flows supported for mobile wallets + desktop browsers
- Browser acts as mediator between website and credential store

**API Coexistence Pattern:**

Both APIs can coexist in the same browser and wallet implementation:

```javascript
// Passkey authentication (WebAuthn API)
const passkeyCredential = await navigator.credentials.get({
  publicKey: {
    challenge: new Uint8Array([/* ... */]),
    rpId: "example.com",
    allowCredentials: [/* ... */]
  }
});
// Returns: PublicKeyCredential

// Digital credential presentation (Digital Credentials API)
const digitalCredential = await navigator.credentials.get({
  digital: {
    requests: [{
      protocol: "openid4vp",
      data: {
        presentation_definition: {/* ... */}
      }
    }]
  }
});
// Returns: DigitalCredential
```

**Wallet Implementation Pattern:**

A comprehensive digital identity wallet (like EUDI Wallet) typically:
1. Implements **WebAuthn API** for passkey storage/authentication
2. Implements **Digital Credentials API** for VC storage/presentation
3. Uses shared infrastructure (Android Keystore, biometrics, PIN)
4. Presents unified UX while maintaining separate credential stores
5. No direct integration between the two credential types

### 6.4.1 Original Browser API Support Status (2026)

| Browser | Version | Digital Credentials API | OpenID4VP | OpenID4VCI | Notes |
|---------|---------|------------------------|-----------|------------|-------|
| **Chrome** | 131+ | ✅ Shipped | ✅ | ✅ | Full support on Android, Desktop, ChromeOS |
| **Safari** | iOS 18+ | ✅ Shipped | ✅ | ✅ | iOS only, requires wallet app |
| **Edge** | 131+ | ✅ Shipped | ✅ | ✅ | Based on Chromium |
| **Firefox** | - | ❌ Not yet | ❌ | ❌ | Under consideration |
| **Samsung Internet** | 26+ | ✅ Shipped | ✅ | ✅ | Based on Chromium |

**Key Points**:
- **Chrome/Edge**: Full support since version 131 (December 2024)
- **Safari**: iOS 18+ supports the API, requires compatible wallet app
- **Cross-device flows**: Supported via QR codes for desktop-to-mobile
- **Same-device flows**: Direct wallet invocation on mobile browsers
- **Protocol support**: OpenID4VP and OpenID4VCI are the primary protocols
- **W3C Status**: Working Draft, on track for Recommendation

**Feature Detection**:
```javascript
// Check if Digital Credentials API is available
const isSupported = 'DigitalCredential' in window;

// Check if specific protocol is allowed
const supportsOpenID4VP = await DigitalCredential.userAgentAllowsProtocol('openid4vp');
```

**Permissions Policy**:
```html
<!-- Allow digital credentials in iframe -->
<iframe src="..." allow="digital-credentials-get"></iframe>
```
## 9. Deep Link Integration for QR Code Handling

### 9.1 Overview

When a browser generates a QR code for credential issuance or presentation, the QR code contains a custom URL scheme (deep link) that needs to be handled by your wallet app. This section documents how to configure Android to redirect these URLs to your FIDO2 BLE HID authenticator app.

### 9.2 Chrome's Digital Credentials API Integration (2026)

**Important**: As of Chrome 141 (October 2025), the Digital Credentials API uses the **native browser API** (`navigator.credentials.get()`) rather than custom URL schemes for same-device flows. Custom URL schemes are only used for **cross-device flows** (desktop to mobile).

**Chrome's Approach**:
1. **Same-Device (Android)**: Browser directly invokes wallet via Android Intent, no URL scheme needed
2. **Cross-Device (Desktop→Mobile)**: QR code contains HTTPS URL that triggers wallet via intent filter

**Supported Protocols in Chrome 141+**:
- `openid4vp-v1-unsigned` - OpenID for Verifiable Presentations (unsigned requests)
- `openid4vp` - OpenID for Verifiable Presentations (signed requests)
- `org-iso-mdoc` - ISO 18013-7 Annex C for mobile documents (mDL)

**Cross-Device QR Code Flow**:
When Chrome generates a QR code for cross-device presentation, it contains an HTTPS URL that:
1. Points to a Chrome-hosted relay server
2. Contains encrypted presentation request
3. Uses CTAP protocol over BLE for secure device-to-device communication

**Example QR Code Content (Cross-Device)**:
```
https://accounts.google.com/gsi/dc?request=eyJhbGc...
```

**For Wallet Apps**: You need to handle **Android Intents** from the browser, not custom URL schemes for same-device flows.

### 9.3 Android Manifest Configuration for Chrome Integration

To integrate with Chrome's Digital Credentials API, you need to register your wallet app to handle credential requests via Android Intents.

#### 9.3.1 Register as Digital Credential Provider

**Key Requirement**: Your wallet must be registered as a credential provider in Android's Credential Manager framework (Android 14+).

```xml
<!-- Add to app/src/main/AndroidManifest.xml -->

<!-- Digital Credential Provider Service -->
<service
    android:name="com.isfs.blekey.credentials.DigitalCredentialProviderService"
    android:exported="true"
    android:permission="android.permission.BIND_CREDENTIAL_PROVIDER_SERVICE">
    <intent-filter>
        <action android:name="android.service.credentials.CredentialProviderService" />
    </intent-filter>
    
    <!-- Declare supported credential types -->
    <meta-data
        android:name="android.credentials.provider"
        android:resource="@xml/digital_credential_provider" />
</service>

<!-- Activity to handle credential selection UI -->
<activity
    android:name="com.isfs.blekey.activity.DigitalCredentialActivity"
    android:exported="true"
    android:theme="@style/AppTheme.Transparent">
    
    <!-- Handle Digital Credentials API requests from Chrome -->
    <intent-filter>
        <action android:name="androidx.credentials.provider.action.GET_CREDENTIAL" />
        <category android:name="android.intent.category.DEFAULT" />
    </intent-filter>
</activity>

<!-- For cross-device flows: Handle HTTPS URLs from QR codes -->
<activity
    android:name="com.isfs.blekey.activity.CrossDeviceCredentialActivity"
    android:exported="true"
    android:launchMode="singleTask"
    android:theme="@style/AppTheme.NoActionBar">
    
    <!-- Handle Chrome's relay server URLs -->
    <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        
        <!-- Chrome's relay server for cross-device -->
        <data android:scheme="https" />
        <data android:host="accounts.google.com" />
        <data android:pathPrefix="/gsi/dc" />
    </intent-filter>
    
    <!-- Your own domain for App Links (optional) -->
    <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        
        <data android:scheme="https" />

### 9.3.4 Third-Party Wallet Support - YES, It's Fully Supported!

**Important Confirmation**: Android's Credential Manager API is **fully open to third-party wallet applications**. This is a public API available through AndroidX libraries.

**Key Facts**:
- ✅ **Available since Android 6 (API 23+)** via AndroidX Jetpack libraries
- ✅ **Third-party wallets fully supported** - not limited to Google Wallet
- ✅ **Multiple wallets can coexist** - users can install multiple wallet apps
- ✅ **User choice** - Android shows selector UI with all available wallets
- ✅ **No special permissions required** beyond standard Android permissions

**Required Dependencies** (from official Android documentation):
```gradle
dependencies {
    // Credential Manager Holder API for wallet apps
    implementation "androidx.credentials.registry:registry-digitalcredentials-mdoc:1.0.0-alpha04"
    implementation "androidx.credentials.registry:registry-digitalcredentials-preview:1.0.0-alpha04"
    implementation "androidx.credentials.registry:registry-provider:1.0.0-alpha04"
    implementation "androidx.credentials.registry:registry-provider-play-services:1.0.0-alpha04"
}
```

**How It Works**:
1. **Registration**: Your wallet app registers credential metadata with Android's Credential Manager using `RegistryManager`
2. **Matching**: When Chrome requests credentials, Credential Manager matches against all registered wallets
3. **Selection**: User sees UI with credentials from all installed wallets (Google Wallet, Samsung Wallet, your wallet, etc.)
4. **Presentation**: User selects credential, your wallet app is invoked to create presentation

**Example Registration Code**:
```kotlin
// Create the registry manager
val registryManager = RegistryManager.create(context)

// Register your credentials
val credentialEntries = listOf(
    SdJwtEntry(
        verifiableCredentialType = "UniversityDegree",
        claims = listOf("name", "degree", "graduationDate"),
        entryDisplayPropertySet = displayProperties,
        id = encryptedCredentialId
    )
)

val openidRegistryRequest = OpenId4VpRegistry(
    credentialEntries = credentialEntries,
    id = "my-wallet-openid-registry-v1"
)

try {
    registryManager.registerCredentials(openidRegistryRequest)
} catch (e: Exception) {
    // Handle failure
}
```

**Supported Credential Formats**:
- **SD-JWT VC**: IETF SD-JWT-based Verifiable Credentials
- **mdoc**: ISO/IEC 18013-5:2021 (mobile documents)

**Key Properties**:
- **Persistence**: Metadata persists across reboots
- **Siloed Storage**: Each wallet's data is isolated
- **Keyed Updates**: Use stable IDs to update/delete registrations
- **No Central Authority**: No approval needed from Google to create a wallet

**This Means**:
Your FIDO2 BLE HID authenticator app can absolutely become a digital credentials wallet by:
1. Adding the AndroidX Credential Manager dependencies
2. Implementing the Holder API to register credentials
3. Handling presentation requests from Chrome/verifiers
4. No special permissions or partnerships required

        <data android:host="wallet.yourdomain.com" />
        <data android:pathPrefix="/credential" />
    </intent-filter>
</activity>
```

#### 9.3.2 Digital Credential Provider Configuration

Create `res/xml/digital_credential_provider.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<credential-provider xmlns:android="http://schemas.android.com/apk/res/android">
    <!-- Declare support for digital credentials -->
    <capabilities>
        <capability name="androidx.credentials.provider.DigitalCredential" />
    </capabilities>
</credential-provider>
```

#### 9.3.3 Intent Filter Explanation

**For Same-Device Flow (Chrome→Wallet on same Android device)**:
- `android:permission="android.permission.BIND_CREDENTIAL_PROVIDER_SERVICE"`: Required for credential provider services
- Service must implement `CredentialProviderService` interface
- Chrome invokes wallet via Android's Credential Manager framework
- No custom URL schemes needed

**For Cross-Device Flow (Desktop Chrome→Mobile Wallet)**:
- `android:autoVerify="true"`: Enables Android App Links verification
- Handle HTTPS URLs from Chrome's relay server (`accounts.google.com/gsi/dc`)
- QR code contains encrypted request that wallet decrypts
- Uses CTAP protocol over BLE for secure communication

### 9.4 CredentialHandlerActivity Implementation

Create the activity to process incoming deep links:

```java
package com.isfs.blekey.activity;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CredentialHandlerActivity extends AppCompatActivity {
    
    private static final Logger logger = LoggerFactory.getLogger(CredentialHandlerActivity.class);
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        // Get the intent that started this activity
        Intent intent = getIntent();
        Uri data = intent.getData();
        
        if (data == null) {
            logger.error("No data in intent");
            finish();
            return;
        }
        
        String scheme = data.getScheme();
        logger.info("Received deep link with scheme: {}", scheme);
        
        // Route based on URL scheme
        if ("openid-credential-offer".equals(scheme)) {
            handleCredentialOffer(data);
        } else if ("openid4vp".equals(scheme) || "openid".equals(scheme)) {
            handlePresentationRequest(data);
        } else if ("https".equals(scheme)) {
            handleAppLink(data);
        } else {
            logger.error("Unknown scheme: {}", scheme);
            finish();
        }
    }
    
    private void handleCredentialOffer(Uri uri) {
        logger.info("Handling credential offer: {}", uri);
        
        // Extract credential_offer parameter
        String credentialOffer = uri.getQueryParameter("credential_offer");
        String credentialOfferUri = uri.getQueryParameter("credential_offer_uri");
        
        if (credentialOffer != null) {
            // Offer provided inline
            processCredentialOffer(credentialOffer);
        } else if (credentialOfferUri != null) {
            // Offer provided by reference - fetch it
            fetchAndProcessCredentialOffer(credentialOfferUri);
        } else {
            logger.error("No credential offer found in URI");
            showError("Invalid credential offer");
            finish();
        }
    }
    
    private void handlePresentationRequest(Uri uri) {
        logger.info("Handling presentation request: {}", uri);
        
        // Extract request parameters
        String requestUri = uri.getQueryParameter("request_uri");
        String request = uri.getQueryParameter("request");
        
        if (requestUri != null) {
            // Request provided by reference - fetch it
            fetchAndProcessPresentationRequest(requestUri);
        } else if (request != null) {
            // Request provided inline (JWT)
            processPresentationRequest(request);
        } else {
            logger.error("No presentation request found in URI");
            showError("Invalid presentation request");
            finish();
        }
    }
    
    private void handleAppLink(Uri uri) {
        logger.info("Handling App Link: {}", uri);
        
        String path = uri.getPath();
        if (path != null) {
            if (path.startsWith("/credential-offer")) {
                handleCredentialOffer(uri);
            } else if (path.startsWith("/presentation-request")) {
                handlePresentationRequest(uri);
            }
        }
    }
    
    private void processCredentialOffer(String offerJson) {
        // Start credential issuance flow
        Intent intent = new Intent(this, CredentialIssuanceActivity.class);
        intent.putExtra("credential_offer", offerJson);
        startActivity(intent);
        finish();
    }
    
    private void fetchAndProcessCredentialOffer(String offerUri) {
        // Fetch offer from URI in background thread
        new Thread(() -> {
            try {
                String offerJson = fetchFromUri(offerUri);
                runOnUiThread(() -> processCredentialOffer(offerJson));
            } catch (Exception e) {
                logger.error("Failed to fetch credential offer", e);
                runOnUiThread(() -> {
                    showError("Failed to fetch credential offer");
                    finish();
                });
            }
        }).start();
    }
    
    private void processPresentationRequest(String requestJwt) {
        // Start credential presentation flow
        Intent intent = new Intent(this, CredentialPresentationActivity.class);
        intent.putExtra("presentation_request", requestJwt);
        startActivity(intent);
        finish();
    }
    
    private void fetchAndProcessPresentationRequest(String requestUri) {
        // Fetch request from URI in background thread
        new Thread(() -> {
            try {
                String requestJwt = fetchFromUri(requestUri);
                runOnUiThread(() -> processPresentationRequest(requestJwt));
            } catch (Exception e) {
                logger.error("Failed to fetch presentation request", e);
                runOnUiThread(() -> {
                    showError("Failed to fetch presentation request");
                    finish();
                });
            }
        }).start();
    }
    
    private String fetchFromUri(String uri) throws Exception {
        // Implement HTTP GET to fetch content
        // Use OkHttp or similar library
        // Return response body as string
        throw new UnsupportedOperationException("Not implemented");
    }
    
    private void showError(String message) {
        // Show error dialog or toast
        android.widget.Toast.makeText(this, message, android.widget.Toast.LENGTH_LONG).show();
    }
}
```

### 9.5 Testing Deep Links

#### 9.5.1 Using ADB

Test deep links from command line:

```bash
# Test credential offer
adb shell am start -W -a android.intent.action.VIEW \
  -d "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.example.com%22%7D" \
  com.isfs.blekey

# Test presentation request
adb shell am start -W -a android.intent.action.VIEW \
  -d "openid4vp://?request_uri=https%3A%2F%2Fverifier.example.com%2Frequest%2Fabc123" \
  com.isfs.blekey

# Test HTTPS App Link
adb shell am start -W -a android.intent.action.VIEW \
  -d "https://wallet.yourdomain.com/credential-offer?offer=..." \
  com.isfs.blekey
```

#### 9.5.2 Using QR Code Scanner

1. Generate QR code with credential offer URL
2. Scan with device camera or QR scanner app
3. Android should prompt to open with your wallet app
4. If multiple apps can handle the URL, user chooses which one

#### 9.5.3 From Browser

Create test HTML page:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Test Deep Links</title>
</head>
<body>
    <h1>Test Credential Deep Links</h1>
    
    <!-- Test credential offer -->
    <a href="openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.example.com%22%7D">
        Test Credential Offer
    </a>
    
    <br><br>
    
    <!-- Test presentation request -->
    <a href="openid4vp://?request_uri=https%3A%2F%2Fverifier.example.com%2Frequest%2Fabc123">
        Test Presentation Request
    </a>
    
    <br><br>
    
    <!-- Test App Link -->
    <a href="https://wallet.yourdomain.com/credential-offer?offer=test">
        Test App Link
    </a>
</body>
</html>
```

### 9.6 App Links vs Custom Schemes

#### 9.6.1 Custom Schemes (openid-credential-offer://)

**Advantages**:
- Simple to implement
- Works immediately without server configuration
- Good for development and testing

**Disadvantages**:
- Any app can register the same scheme
- No verification of app ownership
- Less secure (potential for phishing)
- May show app chooser if multiple apps handle the scheme

#### 9.6.2 HTTPS App Links (https://wallet.yourdomain.com/...)

**Advantages**:
- Verified ownership via Digital Asset Links
- More secure - only your app can handle your domain
- Better user experience (no app chooser)
- Recommended for production

**Disadvantages**:
- Requires server configuration
- Requires domain ownership
- More complex setup

#### 9.6.3 Digital Asset Links Configuration

For HTTPS App Links, host this file at:
`https://wallet.yourdomain.com/.well-known/assetlinks.json`

```json
[{
  "relation": ["delegate_permission/common.handle_all_urls"],
  "target": {
    "namespace": "android_app",
    "package_name": "com.isfs.blekey",
    "sha256_cert_fingerprints": [
      "YOUR_APP_SIGNING_CERTIFICATE_SHA256_FINGERPRINT"
    ]
  }
}]
```

Get your certificate fingerprint:
```bash
keytool -list -v -keystore your-keystore.jks -alias your-key-alias
```

### 9.7 Cross-Device Flow

For desktop browser to mobile wallet:

```
┌──────────┐                 ┌──────────┐                 ┌──────────┐
│ Desktop  │                 │  Issuer  │                 │  Mobile  │
│ Browser  │                 │  Server  │                 │  Wallet  │
└────┬─────┘                 └────┬─────┘                 └────┬─────┘
     │                            │                            │
     │ 1. Request credential      │                            │
     │───────────────────────────>│                            │
     │                            │                            │
     │ 2. Generate QR code        │                            │
     │    with deep link          │                            │
     │<───────────────────────────│                            │
     │                            │                            │
     │ 3. Display QR code         │                            │
     │                            │                            │
     │                            │ 4. Scan QR code            │
     │                            │<───────────────────────────│
     │                            │                            │
     │                            │ 5. Parse deep link         │
     │                            │    Launch wallet app       │
     │                            │                            │
     │                            │ 6. Request credential      │
     │                            │<───────────────────────────│
     │                            │                            │
     │                            │ 7. Issue credential        │
     │                            │───────────────────────────>│
     │                            │                            │
     │ 8. Poll for completion     │                            │
     │───────────────────────────>│                            │
     │                            │                            │
     │ 9. Credential issued       │                            │
     │<───────────────────────────│                            │
     │                            │                            │
```

### 9.8 Security Considerations

1. **Validate URLs**: Always validate and sanitize URLs before processing
2. **Use HTTPS**: Prefer HTTPS App Links over custom schemes in production
3. **Verify Origin**: Check the origin of credential offers and presentation requests
4. **User Consent**: Always require user consent before processing credentials
5. **Rate Limiting**: Implement rate limiting to prevent abuse
6. **Certificate Pinning**: Consider certificate pinning for issuer/verifier connections

### 9.9 Implementation Checklist

- [ ] Add intent filters to AndroidManifest.xml
- [ ] Create CredentialHandlerActivity
- [ ] Implement credential offer parsing
- [ ] Implement presentation request parsing
- [ ] Add error handling and user feedback
- [ ] Test with ADB commands
- [ ] Test with QR codes
- [ ] Test from browser links
- [ ] Configure Digital Asset Links (for production)
- [ ] Implement security validations
- [ ] Add logging and analytics


## 7. Standards Status and Interoperability

### 6.1 Current Standards (2026)

**Finalized Standards**:
- ✅ W3C Verifiable Credentials Data Model 2.0 (W3C Recommendation)
- ✅ OIDC4VCI 1.0 (OpenID Foundation Final Specification)
- ✅ OIDC4VP 1.0 (OpenID Foundation Final Specification)
- ✅ ISO 18013-5:2021 (ISO Standard for mobile documents)
- ✅ IETF SD-JWT VC (RFC draft, widely implemented)

**Regulatory Frameworks**:
- ✅ eIDAS 2.0 Regulation (EU) - Adopted with implementing regulations
- ✅ EUDI Wallet Architecture and Reference Framework v1.10+

### 6.2 Interoperability

**Format Support**:
- Most wallets support multiple formats (SD-JWT VC, ISO mdoc, W3C VCDM)
- SD-JWT VC emerging as preferred format for web-based use cases
- ISO mdoc preferred for government credentials and offline scenarios

**Cross-Border Recognition**:
- EUDI Wallet designed for EU-wide interoperability
- Trust frameworks being established for issuer/verifier recognition
- Mutual recognition agreements between jurisdictions

**Ecosystem Maturity**:
- Production deployments in EU member states (2024-2026)
- Growing issuer ecosystem (governments, universities, employers)
- Verifier adoption increasing in both public and private sectors

## 7. Key Findings and Recommendations

### 7.1 Technical Feasibility

**Storage Compatibility**: ✅ Excellent
- Current passkey storage architecture can be extended to support VCs
- Same encryption mechanisms (ECDH with P-256 keys) applicable
- Android Keystore integration already in place
- CBOR encoding already used for resident credentials

**Key Management**: ✅ Compatible
- P-256 keys used for both FIDO2 and VC binding
- Hardware-backed key storage via Android Keystore
- Similar key lifecycle management requirements

**Access Control**: ✅ Aligned
- PIN/biometric authentication for both credential types
- User consent required for both authentication and presentation
- Similar security requirements (LoA High)

### 7.2 Architectural Recommendations

1. **Extend Passkey File Format**:
   - Add VC section after resident credentials
   - Maintain backward compatibility
   - Use versioning for future extensions

2. **Separate Key Pairs**:
   - FIDO2 keys remain dedicated to authentication
   - Generate separate P-256 keys for VC binding
   - Store all keys in Android Keystore

3. **Implement OIDC4VCI/VP**:
   - Add OIDC client libraries
   - Implement credential offer handling
   - Support both authorization code and pre-authorized flows

4. **Support Multiple Formats**:
   - Prioritize SD-JWT VC for web use cases
   - Add ISO mdoc support for government credentials
   - Maintain format flexibility

5. **User Experience**:
   - Unified credential management UI
   - Clear distinction between authentication and attestation
   - Selective disclosure controls for privacy

### 7.3 Standards Compliance

**FIDO2 Compatibility**: ✅ Maintained
- VC integration does not affect FIDO2 functionality
- Separate credential types with distinct purposes
- No conflicts in key usage or protocols

**EUDI Wallet Alignment**: ✅ High
- Storage architecture similar to EUDI reference implementation
- Android Keystore usage matches requirements
- OIDC4VCI/VP protocols fully compatible

**Privacy Preservation**: ✅ Enhanced
- Selective disclosure supported via SD-JWT VC
- Minimal disclosure principle enforced
- User consent required for all presentations

## 8. Conclusion

Digital credentials (Verifiable Credentials) and FIDO2 credentials serve complementary purposes in the digital identity ecosystem. This FIDO2 BLE HID authenticator app can be extended to support VCs by:

1. **Leveraging existing storage infrastructure**: The current passkey file format with ECDH encryption and Android Keystore integration provides a solid foundation for VC storage.

2. **Implementing OIDC4VCI/VP protocols**: These standardized protocols enable interoperable credential issuance and presentation workflows.

3. **Maintaining separation of concerns**: FIDO2 credentials handle authentication, while VCs handle authorization/attestation, with no conflicts.

4. **Following EUDI Wallet patterns**: The European Digital Identity Wallet provides a proven reference architecture for secure credential storage and management.

The proposed integration would position this app as a comprehensive digital identity solution, supporting both passwordless authentication (FIDO2) and verifiable attestations (VCs) in a single, secure platform.

## References

**Browser APIs:**
- W3C Digital Credentials API: https://www.w3.org/TR/digital-credentials/
- W3C WebAuthn Level 3: https://www.w3.org/TR/webauthn-3/
- W3C Credential Management API Level 1: https://www.w3.org/TR/credential-management-1/

**Verifiable Credentials:**
- W3C Verifiable Credentials Data Model 2.0: https://www.w3.org/TR/vc-data-model-2.0/
- OpenID for Verifiable Credential Issuance 1.0: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
- OpenID for Verifiable Presentations 1.0: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
- IETF SD-JWT VC: https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-00.html

**Standards & Frameworks:**
- EUDI Wallet Architecture and Reference Framework (ARF) v1.4.0: https://eudi.dev/1.4.0/arf/
- EUDI Wallet ARF GitHub Repository: https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework
- ISO 18013-5:2021 (Mobile Driving License): https://www.iso.org/standard/69084.html
- FIDO2/CTAP2 Specifications: https://fidoalliance.org/specifications/

**EU Regulations:**
- Commission Implementing Regulation (EU) 2024/2979: EUDI Wallet certification requirements
- Commission Implementing Regulation (EU) 2024/2981: EUDI Wallet technical specifications
- Commission Implementing Regulation (EU) 2015/1502: Minimum technical specifications for LoA High

**Cryptographic Standards:**
- RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF): https://datatracker.ietf.org/doc/html/rfc5869
- RFC 8725: JSON Web Token Best Current Practices: https://datatracker.ietf.org/doc/html/rfc8725

**Android APIs:**
- Android Keystore System: https://developer.android.com/training/articles/keystore
- Android BiometricPrompt API: https://developer.android.com/reference/androidx/biometric/BiometricPrompt
- Android Credential Manager: https://developer.android.com/identity/digital-credentials
- AndroidX Credentials Registry: https://developer.android.com/jetpack/androidx/releases/credentials

**Local Resources:**
- ISO 18013-5:2021 PDF: [`ISO-IEC-18013-5-2021.pdf`](ISO-IEC-18013-5-2021.pdf) (downloaded for reference)
- CTAP2 Specification: [`Client to Authenticator Protocol (CTAP) - fido-client-to-authenticator-protocol-v2.3-rd-20251023.pdf`](Client to Authenticator Protocol (CTAP) - fido-client-to-authenticator-protocol-v2.3-rd-20251023.pdf)
- WebAuthn L3 Draft specification: [`WebAuthn-Level-3.html`](WebAuthn-Level-3.html)