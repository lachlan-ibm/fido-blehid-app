# Digital Credentials MVP Implementation Plan

## Overview

This document outlines a phased implementation plan for adding Digital Credentials support to the FIDO2 BLE HID Authenticator. The plan is structured to allow iterative development with each phase delivering functional value that can be tested before proceeding to the next phase.

## MVP Scope

The Minimum Viable Product will include:

1. **Storage Layer** - Secure storage for Verifiable Credentials in the existing passkey file format
2. **OIDC4VCI API** - Credential issuance protocol implementation (lib project)
3. **OIDC4VP API** - Credential presentation protocol implementation (lib project)
4. **Generation & Binding** - Holder binding key generation and management (lib project)
5. **Android Integration** - Activities and services to handle credential requests (app project)
6. **QR Code Interception** - Android app intercepts digital credential requests via deep links (final integration)

## Architecture Split

### Library Project (`lib/`)
Core protocol implementations that are platform-agnostic:
- OIDC4VCI client implementation
- OIDC4VP presentation handler
- Credential storage format extensions
- Key derivation (HKDF) for holder binding
- Cryptographic operations (JWT signing, verification)
- Credential validation and parsing

### App Project (`app/`)
Android-specific implementations:
- Biometric authentication UI
- Credential management activities
- Android Keystore integration
- Android Credential Manager integration
- Deep link handlers for QR code scanning (final integration)
- Intent filters and manifest configuration

---

## Phase 1: Foundation & Storage Layer

**Goal**: Extend storage architecture to support Verifiable Credentials alongside FIDO2 credentials.

**Deliverables**:
- Extended passkey file format with VC section
- Data models for Verifiable Credentials
- Encryption/decryption for VC storage
- Basic CRUD operations for credentials
- digital credential section is not required for passkey file...should be optional

### Phase 1.1: Data Models (lib)

**Files to Create** (all in `lib/src/com/isfs/blekey/credential/` package):

1. **`lib/src/com/isfs/blekey/credential/VerifiableCredential.java`**
   - Represents a VC with metadata
   - **MVP Scope**: SD-JWT format only (defer mdoc/JSON-LD to post-MVP)
   - Serialization/deserialization methods
   - Holder binding key seed

2. **`lib/src/com/isfs/blekey/credential/DigitalCredentialFormat.java`**
   - Enum for credential formats
   - **MVP**: SD_JWT_VC only
   - **Post-MVP**: ISO_MDOC, JSON_LD

3. **`lib/src/com/isfs/blekey/credential/DigitalCredentialMetadata.java`**
   - Issuer information (DID/URL)
   - Credential type
   - Issuance/expiration dates
   - Status list URL
   - Display properties

**Implementation Details**:
```java
// VerifiableCredential structure
class VerifiableCredential {
    private String id;                    // Unique credential ID
    private CredentialFormat format;      // SD-JWT, mdoc, JSON-LD
    private CredentialMetadata metadata;  // Issuer, type, dates
    private byte[] holderBindingKeySeed;  // Random seed for deriving binding key via HKDF with master key signature
    private byte[] encryptedData;         // Encrypted credential data
    private byte[] salt;                  // For HKDF key derivation
}
```

**Testing**:
- Unit tests for serialization/deserialization
- Validation of credential metadata
- Format-specific parsing tests

**Success Criteria**:
- [ ] All data models compile without errors
- [ ] Regenerate binding key with master key and persisted seed
- [ ] Unit tests pass with >80% coverage
- [ ] CBOR encoding/decoding works correctly

---

### Phase 1.2: Storage Format Extension (lib)

**Files to Modify**:

1. **`lib/src/com/isfs/blekey/data/Passkey.java`**
   - Add VC section after resident credentials
   - Maintain backward compatibility
   - Version field for future extensions

**New Structure**:
```
Passkey File (Enhanced):
├── Header (230 bytes) - Encrypted upperHash
├── PKCS12 Length (4 bytes)
├── PKCS12 Data - Passkey private key + cert
├── Resident Credentials - FIDO2 credentials (existing)
├── VC Section Length (4 bytes) - NEW
└── Verifiable Credentials - NEW
    └── CBOR array of VerifiableCredential objects
```

**Implementation Details**:
- Add `readVerifiableCredentials()` method
- Add `writeVerifiableCredentials()` method
- Ensure backward compatibility (handle files without VC section)
- Use ECDH encryption with platform P-256 key

**Testing**:
- Test reading old passkey files (without VC section)
- Test writing and reading new format
- Test encryption/decryption of VC data
- Test file corruption handling

**Success Criteria**:
- [ ] Backward compatibility maintained
- [ ] VCs can be stored and retrieved
- [ ] Encryption works correctly
- [ ] No data loss on read/write cycles

---

### Phase 1.3: Holder Binding Key Management (lib + app)

**Architecture Overview**:

This implementation uses a **single master key** stored in Android Keystore with biometric authentication, combined with **per-credential seeds** to derive individual binding keys. This approach:
- ✅ Meets EUDI hardware-backed vault requirements (master key in Keystore)
- ✅ Reduces keystore management overhead (one key vs. many)
- ✅ Maintains strong security through KDF-based derivation
- ✅ Enables credential managability (seeds stored with passkey data)

**Files to Create**:

1. **`lib/src/com/isfs/blekey/util/HolderBindingKeyManager.java`**
   - HKDF-based key derivation from master key + credential seed
   - Key lifecycle management (generation, rotation, deletion)
   - Interface for platform-specific keystore operations
   - Seed generation and management

2. **`app/src/main/java/com/isfs/blekey/AndroidHolderBindingKeyManager.java`**
   - Android Keystore implementation for master key
   - Biometric authentication enforcement
   - StrongBox/TEE key generation for master key
   - Master key access control

**Implementation Details**:

**Master Key Generation (One-time, in Android Keystore)**:
```java
// Generate single master key in Android Keystore with biometric auth
KeyGenParameterSpec.Builder spec = new KeyGenParameterSpec.Builder(
    "digital_credentials_master_key",
    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
    .setUserAuthenticationRequired(true)
    .setUserAuthenticationParameters(
        0,  // Auth valid for this operation only
        KeyProperties.AUTH_BIOMETRIC_STRONG)
    .setIsStrongBoxBacked(true);  // Use StrongBox if available
```

**Per-Credential Binding Key Derivation**:
```java
// Generate random seed for each credential (stored with passkey)
byte[] credential_seed = new byte[32];
SecureRandom.getInstanceStrong().nextBytes(credential_seed);

// Derive binding key using HKDF with master key signature
byte[] master_key_signature = masterKey.sign(credential_seed);
Salt = SHA-256(credential_id || issuer_id)
Info = "AYE BLE KEY DIGITAL CREDENTIAL MASTER SEED" || credential_type
holder_binding_key = HKDF-Expand(
    HKDF-Extract(Salt, master_key_signature),
    Info,
    32
)
```

**Credential Seed Storage**:
- Seeds stored in passkey's `digitalCredentialData` field
- Seeds encrypted with passkey's existing encryption
- Seeds required to regenerate binding keys on demand

**Key Derivation Flow**:
1. User initiates credential operation (issuance/presentation)
2. Biometric authentication triggered to access master key
3. Retrieve credential seed from passkey storage
4. Master key signs the seed (requires biometric auth)
5. HKDF derives binding key from signature + credential metadata
6. Binding key used for credential operation
7. Derived key discarded after use (not stored)

**Testing**:
- Test master key generation in Android Keystore
- Test biometric authentication requirement for master key access
- Test seed generation and storage
- Test HKDF key derivation consistency
- Test key isolation between credentials (different seeds)
- Test master key rotation scenario
- Test seed recovery and key re-derivation

**Success Criteria**:
- [ ] Single master key generated in hardware-backed storage
- [ ] Biometric authentication enforced for master key access
- [ ] Per-credential seeds generated and stored securely
- [ ] HKDF derivation produces consistent binding keys
- [ ] Binding keys properly isolated per credential
- [ ] No binding keys stored permanently (derived on-demand)
- [ ] Meets EUDI ARF hardware-backed requirements


#### Architectural Justification: Master Key + Seed Derivation

**Why This Approach is Superior:**

1. **EUDI ARF Compliance**
   - EUDI ARF requires holder binding keys to be "protected by hardware-backed vault"
   - Our master key resides in Android Keystore with StrongBox/TEE backing
   - Derived keys inherit hardware-backed security through cryptographic binding
   - **Meets requirement**: Keys are cryptographically bound to hardware-protected master key

2. **Scalability & Management**
   - Traditional approach: N credentials = N keystore entries
   - Our approach: N credentials = 1 keystore entry + N lightweight seeds
   - Android Keystore has practical limits (~100-200 keys depending on device)
   - **Benefit**: Support unlimited credentials without keystore exhaustion

3. **Performance**
   - Keystore operations are expensive (hardware security module access)
   - Traditional: Each credential operation requires separate keystore access
   - Our approach: Single keystore access per session, derive all needed keys
   - **Benefit**: Faster credential operations, better battery life

4. **Backup & Recovery**
   - Seeds are small (32 bytes) and stored with passkey data
   - Master key never leaves the device (hardware-bound)
   - Seeds can be backed up/restored with passkey file
   - **Benefit**: Credential portability without compromising master key security

5. **Security Properties**
   - HKDF is cryptographically secure for key derivation (RFC 5869)
   - Each credential gets unique salt (credential_id || issuer_id)
   - Master key signature provides entropy from hardware-backed source
   - Seeds are random, preventing correlation between credentials
   - **Guarantee**: Derived keys are cryptographically independent and secure

6. **Regulatory Alignment**
   - eIDAS 2.0 requires "qualified electronic signature creation device" (QSCD)
   - Hardware-backed master key satisfies QSCD requirements
   - Derived keys maintain chain of trust to hardware
   - **Compliance**: Meets EU regulatory requirements for digital identity

**Alternative Approaches Considered:**

| Approach | Hardware-Backed | Scalable | Performance | Verdict |
|----------|----------------|----------|-------------|---------|
| One key per credential | ✅ Yes | ❌ No (~100 limit) | ❌ Slow | Rejected |
| Software-only keys | ❌ No | ✅ Yes | ✅ Fast | Rejected (non-compliant) |
| Master key + derivation | ✅ Yes | ✅ Yes | ✅ Fast | **Selected** |

**Risk Mitigation:**

- **Risk**: Master key compromise affects all credentials
  - **Mitigation**: Master key requires biometric auth per operation (not cached)
  - **Mitigation**: Master key never leaves hardware security module
  - **Mitigation**: Seeds are encrypted at rest with passkey encryption

- **Risk**: Seed theft allows key regeneration
  - **Mitigation**: Seeds alone are useless without master key access
  - **Mitigation**: Master key access requires biometric authentication
  - **Mitigation**: Seeds encrypted with passkey's existing security

**Conclusion:**

This architecture provides the optimal balance of security, compliance, scalability, and performance. It meets EUDI ARF requirements while avoiding the practical limitations of per-credential keystore entries.

---

## Phase 2: OIDC Protocol Implementation (lib)

**Goal**: Implement OIDC4VCI and OIDC4VP protocols for credential issuance and presentation.

**Deliverables**:
- OIDC4VCI client for credential issuance
- OIDC4VP handler for credential presentation
- JWT signing and verification
- HTTP client for issuer/verifier communication

### Phase 2.1: HTTP Client & JSON Utilities (lib)

**Files to Create**:

1. **`lib/src/com/isfs/blekey/util/http/HttpClient.java`**
   - Simple HTTP GET/POST client
   - JSON request/response handling
   - Comprehensive error handling and retries
   - Short timeout configuration for app responsiveness

2. **`lib/src/com/isfs/blekey/util/http/HttpResponse.java`**
   - Response wrapper with status code, headers, body

**Dependencies to Add** (`lib/build.gradle`):
```gradle
dependencies {
    // HTTP client - OkHttp chosen for Android optimization, HTTP/2 support, and interceptor pattern
    // Alternative considered: Apache HttpClient 5 (more features but 2x size, slower on Android)
    implementation 'com.squareup.okhttp3:okhttp:4.12.0'
    
    // JSON parsing (already have JsonUtils, but may need updates)
    implementation 'com.google.code.gson:gson:2.10.1'
}
```

#### Network Error Handling & Timeouts

**Timeout Configuration** (keep app responsive):
```java
// Short timeouts - total time includes connection + transfer
class HttpClientConfig {
    public static final int CONNECT_TIMEOUT_MS = 5000;    // 5 seconds to establish connection
    public static final int READ_TIMEOUT_MS = 10000;      // 10 seconds for data transfer
    public static final int WRITE_TIMEOUT_MS = 10000;     // 10 seconds for upload
    
    // Total operation must complete within 15 seconds
    // Prevents app hanging on slow/unresponsive servers
}
```

**Retry Policies** (operation-specific):
```java
class RetryPolicy {
    // Issuance: Retry on network errors, not on auth errors
    public static final RetryConfig ISSUANCE = new RetryConfig(
        maxRetries: 2,
        backoffMs: [1000, 2000],  // 1s, 2s exponential backoff
        retryableErrors: [NETWORK_ERROR, TIMEOUT]
    );
    
    // Presentation: No retries (time-sensitive, verifier waiting)
    public static final RetryConfig PRESENTATION = new RetryConfig(
        maxRetries: 0,
        backoffMs: [],
        retryableErrors: []
    );
    
    // Status check: Retry with exponential backoff
    public static final RetryConfig STATUS_CHECK = new RetryConfig(
        maxRetries: 3,
        backoffMs: [2000, 4000, 8000],  // 2s, 4s, 8s
        retryableErrors: [NETWORK_ERROR, TIMEOUT, SERVER_ERROR_5XX]
    );
}
```

**Transaction Rollback** (prevent partial state):
```java
class IssuanceTransaction {
    public void execute() {
        try {
            // 1. Generate holder binding key
            // 2. Request credential from issuer
            // 3. Validate credential signature
            // 4. Store credential in passkey file
            commit();
        } catch (Exception e) {
            rollback();  // Delete generated keys, clear partial state
            throw new IssuanceException("Issuance failed", e);
        }
    }
}
```

**Error Categories & User Messages**:
```java
class ErrorMessageProvider {
    public String getUserMessage(Exception e) {
        if (e instanceof NetworkException) {
            return "Network error. Check your connection and try again.";
        } else if (e instanceof TimeoutException) {
            return "Request timed out. Please try again.";
        } else if (e instanceof ValidationException) {
            return "Credential validation failed. Contact issuer.";
        } else if (e instanceof AuthException) {
            return "Authentication failed. Please try again.";
        }
        return "An error occurred. Please try again later.";
    }
}
```

**Testing**:
- Mock HTTP server for testing
- Test GET/POST requests
- Test timeout behavior (connection + transfer)
- Test retry logic for each operation type
- Test transaction rollback on failures
- Test error message generation

**Success Criteria**:
- [ ] HTTP client works reliably
- [ ] Timeouts prevent app hanging (15s max)
- [ ] Retry policies appropriate per operation
- [ ] Transaction rollback prevents partial state
- [ ] JSON parsing handles all OIDC responses
- [ ] Error messages clear and actionable
- [ ] Tests pass with mocked server

---

### Phase 2.2: JWT Operations (lib)

**Files to Create**:

1. **`lib/src/com/isfs/blekey/credential/jwt/JwtBuilder.java`**
   - Create and sign JWTs
   - Support ES256 algorithm
   - Add standard claims (iat, exp, aud, nonce)

2. **`lib/src/com/isfs/blekey/credential/jwt/JwtParser.java`**
   - Parse and validate JWTs
   - Verify signatures
   - Extract claims

3. **`lib/src/com/isfs/blekey/credential/jwt/KeyBindingJwtBuilder.java`**
   - Create KB-JWT for holder binding
   - Include sd_hash for SD-JWT credentials

**Dependencies to Add**:
```gradle
dependencies {
    // JWT library - jose4j chosen for familiarity and Apache 2.0 license
    // Alternative: nimbus-jose-jwt (similar features, slightly faster token generation)
    implementation 'org.bitbucket.b_c:jose4j:0.9.6'
}
```

**Testing**:
- Test JWT creation and signing
- Test JWT parsing and validation
- Test signature verification
- Test claim extraction

**Success Criteria**:
- [ ] JWTs created correctly
- [ ] Signatures verify successfully
- [ ] Claims parsed accurately
- [ ] KB-JWT format matches spec

---

### Phase 2.2.5: Common OIDC Authorization Code Flow (lib)

**Rationale**: Both OIDC4VCI and OIDC4VP use OAuth 2.0 authorization code flow for obtaining access tokens. This shared infrastructure avoids code duplication and ensures consistent implementation across both protocols.

**Files to Create**:

1. **`lib/src/com/isfs/blekey/oidc/OidcAuthorizationClient.java`**
   - Common OAuth 2.0 authorization code flow implementation
   - Authorization request generation (with PKCE)
   - Token exchange (authorization code for access token)
   - Token refresh handling
   - State and nonce management

2. **`lib/src/com/isfs/blekey/oidc/OidcTokenResponse.java`**
   - Parse token endpoint responses
   - Extract access_token, refresh_token, expires_in
   - Handle token errors

3. **`lib/src/com/isfs/blekey/oidc/PkceGenerator.java`**
   - Generate code_verifier (random string)
   - Generate code_challenge (SHA-256 hash of verifier)
   - Support S256 challenge method

**Implementation Details**:
```java
// Common authorization code flow that both OIDC4VCI and OIDC4VP can use
class OidcAuthorizationClient {
    // Generate authorization request URL with PKCE
    public String buildAuthorizationUrl(
        String authorizationEndpoint,
        String clientId,
        String redirectUri,
        String scope,
        String state,
        String codeChallenge
    );
    
    // Exchange authorization code for access token
    public OidcTokenResponse exchangeCodeForToken(
        String tokenEndpoint,
        String authorizationCode,
        String codeVerifier,
        String redirectUri,
        String clientId
    );
    
    // Refresh access token
    public OidcTokenResponse refreshToken(
        String tokenEndpoint,
        String refreshToken,
        String clientId
    );
}
```

**Usage by OIDC4VCI**:
- Pre-authorized code grant (simpler, no user auth with issuer)
- Authorization code grant (when user must authenticate with issuer)

**Usage by OIDC4VP**:
- Authorization code flow for verifier authentication
- Token used to submit presentation

**Testing**:
- Test PKCE generation (code_verifier and code_challenge)
- Test authorization URL generation
- Test token exchange with mock server
- Test token refresh
- Test error handling (invalid code, expired token, etc.)

**Success Criteria**:
- [ ] PKCE implementation follows RFC 7636
- [ ] Authorization URLs generated correctly
- [ ] Token exchange works reliably
- [ ] Both OIDC4VCI and OIDC4VP can reuse this code
- [ ] Unit tests pass with >85% coverage

---

### Phase 2.3: OIDC4VCI Client (lib)

**Files to Create**:

1. **`lib/src/com/isfs/blekey/oidc/CredentialOffer.java`**
   - Parse credential offer from URI
   - Extract issuer URL, credential types, grants

2. **`lib/src/com/isfs/blekey/oidc/IssuerMetadata.java`**
   - Fetch and parse issuer metadata
   - Store endpoints (token, credential)
   - Store supported formats and proof types

3. **`lib/src/com/isfs/blekey/oidc/Oidc4VciClient.java`**
   - Execute issuance flow
   - Request access token
   - Create key proof JWT
   - Request credential
   - Validate issued credential

**Implementation Flow**:
```
1. Parse credential offer
2. Fetch issuer metadata
3. Request access token (pre-authorized code grant)
4. Generate credential seed and derive holder binding key (requires biometric auth)
5. Create key proof JWT
6. Request credential with proof
7. Validate and store credential
```

**Testing**:
- Mock issuer server
- Test each step of issuance flow
- Test error handling
- Test credential validation

**Success Criteria**:
- [ ] Credential offers parsed correctly
- [ ] Issuer metadata fetched successfully
- [ ] Access tokens obtained
- [ ] Credentials issued and validated
- [ ] Integration test passes end-to-end

---

### Phase 2.4: OIDC4VP Handler (lib)

**Files to Create**:

1. **`lib/src/com/isfs/blekey/oidc/PresentationDefinition.java`**
   - Parse presentation definition
   - Extract input descriptors
   - Parse constraints

2. **`lib/src/com/isfs/blekey/oidc/PresentationSubmission.java`**
   - Create presentation submission
   - Map credentials to input descriptors
   - Generate descriptor_map

3. **`lib/src/com/isfs/blekey/oidc/Oidc4VpHandler.java`**
   - Parse authorization request
   - Match stored credentials
   - Create selective disclosure
   - Build VP token with KB-JWT
   - Submit presentation

**Implementation Flow**:
```
1. Parse authorization request
2. Fetch request object (if by reference)
3. Parse presentation definition
4. Match stored credentials
5. Get user consent for disclosure
6. Authenticate user (biometric/PIN)
7. Create selective disclosure
8. Create key binding JWT
9. Assemble VP token
10. Submit to verifier
```

#### SD-JWT Selective Disclosure Implementation

**Research Summary** (from IETF draft-ietf-oauth-selective-disclosure-jwt-08):

**Core Concepts**:
1. **Disclosures**: Base64url-encoded JSON arrays containing `[salt, claim_name, claim_value]`
2. **Digest Embedding**: SHA-256 hash of disclosure embedded in `_sd` array in JWT
3. **Holder Selection**: Holder chooses which disclosures to include in presentation
4. **Verifier Validation**: Verifier recomputes hashes to verify disclosed claims

**Additional Files to Create**:

4. **`lib/src/com/isfs/blekey/credential/sdjwt/DisclosureParser.java`**
   - Parse base64url-encoded disclosures
   - Extract salt, claim name, claim value
   - Validate disclosure format

5. **`lib/src/com/isfs/blekey/credential/sdjwt/DisclosureHasher.java`**
   - Compute SHA-256 hash of disclosures
   - Verify disclosure hashes match JWT `_sd` array
   - Handle hash algorithm selection (`_sd_alg` claim)

6. **`lib/src/com/isfs/blekey/credential/sdjwt/SelectiveDisclosureBuilder.java`**
   - Build presentation with selected disclosures
   - Filter disclosures based on user consent
   - Assemble SD-JWT presentation format

**Implementation Details**:
```java
// Disclosure format: base64url([salt, claim_name, claim_value])
class DisclosureParser {
    public Disclosure parse(String base64urlDisclosure) {
        // 1. Base64url decode
        // 2. Parse JSON array
        // 3. Extract [salt, name, value]
        // 4. Validate format
        return new Disclosure(salt, claimName, claimValue);
    }
}

// Hash computation per IETF spec
class DisclosureHasher {
    public byte[] computeHash(String disclosure) {
        // SHA-256(disclosure_base64url_string)
        return MessageDigest.getInstance("SHA-256")
            .digest(disclosure.getBytes(StandardCharsets.US_ASCII));
    }
    
    public boolean verifyHash(String disclosure, byte[] expectedHash) {
        return Arrays.equals(computeHash(disclosure), expectedHash);
    }
}

// Selective disclosure builder
class SelectiveDisclosureBuilder {
    public String buildPresentation(
        String issuerJwt,
        List<String> allDisclosures,
        Set<String> selectedClaimNames
    ) {
        // 1. Filter disclosures by selected claim names
        // 2. Assemble: issuer_jwt~disclosure1~disclosure2~...~kb_jwt
        // 3. Return combined presentation
    }
}
```

**Claim Selection UI** (app):
```java
// In CredentialPresentationActivity
class ClaimSelectionDialog {
    // Show checkboxes for each selectively-disclosable claim
    // User selects which claims to share with verifier
    // Return selected claim names
}
```

**Key Binding JWT with sd_hash**:
```java
// KB-JWT payload includes hash of disclosed claims for integrity
{
  "iat": 1234567890,
  "aud": "https://verifier.example.com",
  "nonce": "verifier_nonce",
  "sd_hash": "SHA-256(disclosures_concatenated)"  // Integrity protection
}
```

**Testing**:
- Mock verifier server
- Test presentation definition parsing
- Test credential matching
- Test disclosure parsing and validation
- Test hash computation and verification
- Test selective disclosure filtering
- Test KB-JWT with sd_hash
- Test VP token creation with multiple disclosure combinations
- Test submission

**Success Criteria**:
- [ ] Presentation requests parsed correctly
- [ ] Credentials matched accurately
- [ ] Disclosures parsed correctly
- [ ] Hashes verified successfully
- [ ] User can select claims to disclose
- [ ] Presentation format matches IETF spec
- [ ] KB-JWT includes sd_hash
- [ ] VP tokens created correctly
- [ ] Verifier accepts presentations
- [ ] Integration test passes end-to-end

**References**:
- IETF draft-ietf-oauth-selective-disclosure-jwt-08
- https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-08.html

---

### Phase 2.5: Credential Status Checking (lib)

**Goal**: Implement Status List 2021 for credential revocation checking

**Files to Create**:

1. **`lib/src/com/isfs/blekey/credential/status/StatusList2021.java`**
   - Fetch and parse Status List 2021 bitstring
   - Check credential status (valid/revoked/suspended)
   - Cache status lists with TTL
   - Handle status list updates

2. **`lib/src/com/isfs/blekey/credential/status/StatusListFetcher.java`**
   - HTTP client for fetching status lists
   - Verify status list JWT signatures
   - Handle network errors and retries

3. **`lib/src/com/isfs/blekey/credential/status/CredentialStatusChecker.java`**
   - Main interface for status checking
   - Coordinate fetching and parsing
   - Return status results

**Implementation Details**:
```java
// Status List 2021 format (RFC 9102)
class StatusList2021 {
    private String statusListUrl;      // URL to fetch status list
    private int statusListIndex;       // Bit position in list
    private byte[] bitstringCache;     // Cached bitstring
    private long cacheExpiry;          // Cache TTL
    
    public CredentialStatus checkStatus() {
        // 1. Fetch status list JWT from URL
        // 2. Verify JWT signature
        // 3. Decode base64url bitstring
        // 4. Check bit at statusListIndex
        // 5. Return VALID/REVOKED/SUSPENDED
    }
}

enum CredentialStatus {
    VALID,
    REVOKED,
    SUSPENDED,
    UNKNOWN
}
```

**Background Service** (app):
- Create `StatusCheckService` for periodic checks
- Check status every 24 hours for stored credentials
- Update credential metadata with status
- Notify user if credential revoked

**Testing**:
- Mock status list server
- Test valid/revoked/suspended states
- Test network failures and retries
- Test cache expiry and refresh
- Test background service scheduling

**Success Criteria**:
- [ ] Status List 2021 parsing works
- [ ] Revoked credentials detected
- [ ] Background checks run periodically
- [ ] Network errors handled gracefully
- [ ] Cache reduces network calls
- [ ] User notified of revoked credentials

**Dependencies**: Phase 2.1 (HTTP Client)
**Duration**: 1 week

---

## Phase 3: Android UI & Core Integration (app)

**Goal**: Build user interface and core Android integration for credential management.

**Deliverables**:
- Credential management UI
- Biometric authentication flows
- Android Keystore integration
- Basic credential operations

### Phase 3.1a: Digital Credentials Data Layer (app)

**Goal**: Extend data loading to support digital credentials alongside passkeys

**Files to Modify**:

1. **`lib/src/com/isfs/blekey/data/Passkey.java`**
   - Add `readVerifiableCredentials()` method
   - Add `writeVerifiableCredentials()` method
   - Handle files without VC section (backward compatibility)

**Implementation**:
```java
public class Passkey {
    // Existing fields...
    
    public List<VerifiableCredential> readVerifiableCredentials() {
        // 1. Check if VC section exists (file length check)
        // 2. If not present, return empty list (backward compatible)
        // 3. If present, read VC section length
        // 4. Decrypt and parse CBOR array of VCs
        // 5. Return list of VerifiableCredential objects
    }
    
    public void writeVerifiableCredentials(List<VerifiableCredential> vcs) {
        // 1. Serialize VCs to CBOR array
        // 2. Encrypt with platform P-256 key
        // 3. Write VC section length (4 bytes)
        // 4. Write encrypted VC data
    }
}
```

**Testing**:
- Test reading passkey files without VC section
- Test reading passkey files with VC section
- Test writing and reading VCs
- Test empty VC list handling

**Success Criteria**:
- [ ] Backward compatibility maintained
- [ ] VCs loaded correctly
- [ ] Empty VC section handled gracefully
- [ ] No data corruption

**Duration**: 3 days

---

### Phase 3.1b: Digital Credentials UI with Tabs (app)

**Goal**: Add tab-based UI for viewing digital credentials

**Files to Modify**:

1. **`app/src/main/java/com/isfs/blekey/activity/ResidentCredentialsActivity.java`**
   - Add TabLayout with "Passkeys" and "Digital Credentials" tabs
   - Add ViewPager2 for tab content
   - Load digital credentials using Phase 3.1a methods
   - Disable "Digital Credentials" tab if no credentials exist

**Files to Create**:

2. **`app/src/main/res/layout/digital_credentials_tab.xml`**
   - RecyclerView for digital credentials list
   - Empty state view when no credentials
   - Pull-to-refresh for status updates

3. **`app/src/main/res/layout/digital_credential_list_item.xml`**
   - Credential type icon (driver's license, diploma, etc.)
   - Issuer name and logo
   - Credential type label
   - Expiration date
   - Status indicator (valid/expired/revoked)
   - Associated passkey indicator

**Implementation Details**:
- **Tab Structure**:
  - Tab 1: "Passkeys" - existing resident credentials view (default)
  - Tab 2: "Digital Credentials" - new digital credentials view
- Load both FIDO2 and digital credentials from same passkey file
- Show which passkey each digital credential is associated with
- On click: show credential details (issuer, type, claims, expiration)
- On long press: show delete option
- Refresh credential status periodically (check revocation)
- Show credential count badge on tabs

**UI Flow**:
```
ResidentCredentialsActivity
├── TabLayout
│   ├── Tab: "Passkeys (3)" ← default view
│   └── Tab: "Digital Credentials (2)"
├── ViewPager/Container
│   ├── Passkeys Fragment (existing)
│   │   └── List of FIDO2 resident credentials
│   └── Digital Credentials Fragment (new)
│       └── List of digital credentials
│           ├── Item: Driver's License (DMV)
│           │   ├── Issuer: State DMV
│           │   ├── Expires: 2028-12-31
│           │   ├── Status: Valid ✓
│           │   └── Passkey: example.com
│           └── Item: University Degree (MIT)
│               ├── Issuer: MIT
│               ├── Expires: Never
│               ├── Status: Valid ✓
│               └── Passkey: mit.edu
```

**Testing**:
- Test tab switching between Passkeys and Digital Credentials
- Test with multiple digital credentials
- Test delete operation
- Test status checking and refresh
- Test empty state for both tabs
- Test credential count badges

**Success Criteria**:
- [ ] Tabs switch smoothly between views
- [ ] Digital credentials listed correctly with metadata
- [ ] Details displayed accurately
- [ ] Delete works properly
- [ ] Status updates correctly
- [ ] UI responsive and consistent with existing design
- [ ] Passkey association shown clearly

---

### Phase 3.2: Credential Issuance UI (app)

**Files to Create**:

1. **`app/src/main/java/com/isfs/blekey/activity/CredentialIssuanceActivity.java`**
   - Display credential offer details
   - Show issuer information
   - Get user consent
   - Execute issuance flow
   - Display success/error

2. **`app/src/main/res/layout/activity_credential_issuance.xml`**
   - Issuer name and trust indicator
   - Credential type and claims
   - Validity period
   - Accept/Decline buttons

**Implementation Details**:
- Parse credential offer from intent
- Fetch issuer metadata
- Display offer details
- On accept: generate key, request credential
- On success: store credential, show confirmation
- On error: show error message

**Testing**:
- Test with mock issuer
- Test user consent flow
- Test biometric authentication
- Test error scenarios

**Success Criteria**:
- [ ] Offer details displayed correctly
- [ ] User can accept/decline
- [ ] Biometric auth works
- [ ] Credentials stored successfully
- [ ] Error messages clear

---

### Phase 3.3: Biometric Authentication Integration (app)

**Files to Create**:

1. **`app/src/main/java/com/isfs/blekey/util/BiometricAuthHelper.java`**
   - Wrapper for BiometricPrompt API
   - Handle authentication callbacks
   - Fallback to PIN if biometric unavailable

**Implementation Details**:
```java
// Configure biometric prompt for LoA High
BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
    .setTitle("Authenticate to access credential")
    .setSubtitle("Use fingerprint or face to continue")
    .setAllowedAuthenticators(
        BiometricManager.Authenticators.BIOMETRIC_STRONG |
        BiometricManager.Authenticators.DEVICE_CREDENTIAL)
    .build();
```

**Testing**:
- Test with fingerprint
- Test with face unlock
- Test fallback to PIN
- Test cancellation
- Test multiple attempts

**Success Criteria**:
- [ ] Biometric auth works reliably
- [ ] Fallback to PIN works
- [ ] Error handling robust
- [ ] User experience smooth

---

### Phase 3.4: Credential Presentation UI (app)

**Files to Create**:

1. **`app/src/main/java/com/isfs/blekey/activity/CredentialPresentationActivity.java`**
   - Display presentation request
   - Show verifier information
   - List matched credentials
   - Allow selective disclosure
   - Execute presentation flow

2. **`app/src/main/res/layout/activity_credential_presentation.xml`**
   - Verifier name
   - Requested claims
   - Matched credentials list
   - Selective disclosure checkboxes
   - Share/Cancel buttons

**Implementation Details**:
- Parse presentation request from intent
- Match stored credentials
- Display verifier and requested claims
- Allow user to select what to share
- On share: authenticate, create VP, submit
- On success: show confirmation
- On error: show error message

**Testing**:
- Test with mock verifier
- Test credential matching
- Test selective disclosure
- Test biometric authentication
- Test error scenarios

**Success Criteria**:
- [ ] Request details displayed correctly
- [ ] Credentials matched accurately
- [ ] User can select what to share
- [ ] Biometric auth works
- [ ] Presentations submitted successfully
- [ ] Error messages clear

---

---

## Phase 4: Deep Link & QR Code Integration (app)

**Goal**: Implement QR code scanning and deep link handling as the final integration layer.

**Deliverables**:
- Deep link handlers for credential offers and presentation requests
- QR code interception
- Intent filters and routing
- Android Credential Manager integration

### Phase 4.1: Deep Link Handling (app)

**Files to Create**:

1. **`app/src/main/java/com/isfs/blekey/activity/CredentialHandlerActivity.java`**
   - Handle deep links from QR codes
   - Route to issuance or presentation flow
   - Parse URI schemes (openid-credential-offer://, openid4vp://)

**Manifest Changes** (`app/src/main/AndroidManifest.xml`):
```xml
<activity
    android:name=".activity.CredentialHandlerActivity"
    android:exported="true"
    android:launchMode="singleTask">
    
    <!-- Credential Offer -->
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="openid-credential-offer" />
    </intent-filter>
    
    <!-- Presentation Request -->
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="openid4vp" />
        <data android:scheme="openid" />
    </intent-filter>
</activity>
```

**Testing**:
- Test with ADB: `adb shell am start -a android.intent.action.VIEW -d "openid-credential-offer://..."`
- Test QR code scanning
- Test deep link routing

**Success Criteria**:
- [ ] Deep links intercepted correctly
- [ ] URIs parsed successfully
- [ ] Routing to correct flow works
- [ ] Error handling is robust

---

### Phase 4.2: Android Credential Manager Integration (app)

**Files to Create**:

1. **`app/src/main/java/com/isfs/blekey/DigitalCredentialProviderService.java`**
   - Implement CredentialProviderService
   - Register credentials with Android
   - Handle credential requests from Chrome

2. **`app/src/main/res/xml/digital_credential_provider.xml`**
   - Declare supported credential types

**Dependencies to Add** (`app/build.gradle`):
```gradle
dependencies {
    // Android Credential Manager
    implementation 'androidx.credentials:credentials:1.3.0'
    implementation 'androidx.credentials:credentials-play-services-auth:1.3.0'
    
    // Digital Credentials Registry
    implementation 'androidx.credentials.registry:registry-digitalcredentials-mdoc:1.0.0-alpha04'
    implementation 'androidx.credentials.registry:registry-digitalcredentials-preview:1.0.0-alpha04'
    implementation 'androidx.credentials.registry:registry-provider:1.0.0-alpha04'
}
```

**Manifest Changes**:
```xml
<service
    android:name=".credentials.DigitalCredentialProviderService"
    android:exported="true"
    android:permission="android.permission.BIND_CREDENTIAL_PROVIDER_SERVICE">
    <intent-filter>
        <action android:name="android.service.credentials.CredentialProviderService" />
    </intent-filter>
    <meta-data
        android:name="android.credentials.provider"
        android:resource="@xml/digital_credential_provider" />
</service>
```

**Testing**:
- Test registration with Credential Manager
- Test Chrome integration
- Test credential selection UI
- Test presentation flow from browser

**Success Criteria**:
- [ ] Service registered successfully
- [ ] Credentials visible in Chrome
- [ ] Selection UI works
- [ ] Presentations work from browser
- [ ] Integration with Chrome complete

---

## Phase 5: Testing & Refinement

**Goal**: Comprehensive testing and refinement of all components.

### Phase 5.1: Unit Testing

**Test Coverage Goals**:
- lib project: >80% coverage
- app project: >60% coverage

**Test Files to Create**:
- `lib/test/com/isfs/blekey/VerifiableCredentialTest.java`
- `lib/test/com/isfs/blekey/HolderBindingKeyManagerTest.java`
- `lib/test/com/isfs/blekey/oidc/Oidc4VciClientTest.java`
- `lib/test/com/isfs/blekey/oidc/Oidc4VpHandlerTest.java`
- `lib/test/com/isfs/blekey/jwt/JwtBuilderTest.java`

**Testing Strategy**:
- Mock external dependencies (HTTP, Keystore)
- Test happy paths and error cases
- Test edge cases and boundary conditions
- Test backward compatibility

**Success Criteria**:
- [ ] All unit tests pass
- [ ] Coverage goals met
- [ ] No critical bugs found

---

### Phase 5.2: Integration Testing

**Test Scenarios**:

1. **End-to-End Issuance**:
   - Scan QR code → Accept offer → Receive credential → Store credential

2. **End-to-End Presentation**:
   - Scan QR code → Select credential → Authenticate → Share → Success

3. **Chrome Integration**:
   - Browser requests credential → Wallet shows UI → User shares → Browser receives

4. **Error Scenarios**:
   - Network failures
   - Invalid credentials
   - Expired credentials
   - Revoked credentials
   - User cancellation

**Testing Tools**:
- Mock issuer server
- Mock verifier server
- ADB for deep link testing
- Chrome DevTools for browser testing

**Success Criteria**:
- [ ] All integration tests pass
- [ ] Error handling works correctly
- [ ] User experience is smooth
- [ ] No crashes or hangs

---

### Phase 5.3: Security Review

**Security Checklist**:

1. **Key Management**:
   - [ ] Master key stored in hardware-backed storage (Android Keystore)
   - [ ] Biometric authentication enforced for master key access
   - [ ] Credential seeds properly isolated and encrypted
   - [ ] Key derivation secure (HKDF with master key signature)
   - [ ] Binding keys derived on-demand, not stored permanently

2. **Credential Storage**:
   - [ ] Credentials encrypted at rest
   - [ ] Encryption keys protected
   - [ ] No plaintext credentials in logs
   - [ ] Secure deletion implemented

3. **Network Security**:
   - [ ] HTTPS enforced for all connections
   - [ ] Certificate pinning considered
   - [ ] TLS 1.2+ required
   - [ ] No sensitive data in URLs

4. **Input Validation**:
   - [ ] All inputs validated
   - [ ] JWT signatures verified
   - [ ] Credential signatures verified
   - [ ] Nonce validation implemented

5. **Privacy**:
   - [ ] Selective disclosure works
   - [ ] Minimal disclosure enforced
   - [ ] User consent required
   - [ ] No tracking without consent

**Success Criteria**:
- [ ] All security checks pass
- [ ] No critical vulnerabilities found
- [ ] Privacy requirements met
- [ ] Compliance with EUDI ARF

---

## Phase 6: Documentation & Deployment

**Goal**: Complete documentation and prepare for deployment.

### Phase 6.1: Documentation

**Documents to Create/Update**:

1. **`docs/DIGITAL_CREDENTIALS_USER_GUIDE.md`**
   - How to receive credentials
   - How to present credentials
   - How to manage credentials
   - Troubleshooting guide

2. **`docs/DIGITAL_CREDENTIALS_DEVELOPER_GUIDE.md`**
   - Architecture overview
   - API documentation
   - Integration guide
   - Testing guide

3. **`README.md`** (update)
   - Add Digital Credentials features
   - Update screenshots
   - Add usage examples

4. **`CHANGELOG.md`** (update)
   - Document new features
   - List breaking changes
   - Migration guide

**Success Criteria**:
- [ ] All documentation complete
- [ ] Examples work correctly
- [ ] Screenshots up to date
- [ ] Migration guide clear

---

### Phase 6.2: Deployment Preparation

**Tasks**:

1. **Version Bump**:
   - Update version in `build.gradle`
   - Tag release in git

2. **Build Configuration**:
   - Configure ProGuard rules
   - Optimize APK size
   - Test release build

3. **Testing**:
   - Test on multiple devices
   - Test on different Android versions
   - Test with real issuers/verifiers

4. **Release Notes**:
   - Write release notes
   - Highlight new features
   - Document known issues

**Success Criteria**:
- [ ] Release build works correctly
- [ ] APK size acceptable
- [ ] Tested on target devices
- [ ] Release notes complete

---

## Phase 7: Emulated Device Testing & End-to-End Verification (app)

**Goal**: Deploy the complete application to an Android emulator and verify the full end-to-end flow including UX, QR code scanning, system response, and credential handoff.

### Phase 7.1: Emulator Setup & Deployment

**Tasks**:

1. **Emulator Configuration**:
   - Create Android Virtual Device (AVD) with appropriate API level
   - Configure emulator with camera support for QR code scanning
   - Enable Google Play Services if needed for Credential Manager
   - Configure network settings for OIDC communication

2. **Application Installation**:
   - Build debug APK with all Digital Credentials features
   - Install APK on emulator via ADB
   - Verify app permissions (camera, biometric, network)
   - Configure app settings and initialize authenticator

3. **Test Environment Setup**:
   - Set up test issuer endpoint (local or remote)
   - Set up test verifier endpoint (local or remote)
   - Prepare test QR codes for issuance and presentation
   - Configure deep link handlers

**Success Criteria**:
- [ ] Emulator running with camera support
- [ ] App installed and launches successfully
- [ ] All permissions granted
- [ ] Test endpoints accessible from emulator

---

### Phase 7.2: QR Code Scanning Verification

**Tasks**:

1. **Issuance QR Code Testing**:
   - Display test issuance QR code on host machine
   - Use emulator camera to scan QR code
   - Verify deep link triggers app
   - Verify OIDC4VCI flow initiates correctly

2. **Presentation QR Code Testing**:
   - Display test presentation QR code on host machine
   - Use emulator camera to scan QR code
   - Verify deep link triggers app
   - Verify OIDC4VP flow initiates correctly

3. **QR Code Error Handling**:
   - Test invalid QR codes
   - Test malformed deep links
   - Test network timeout scenarios
   - Verify appropriate error messages

**Success Criteria**:
- [ ] QR codes scan successfully
- [ ] Deep links trigger correct app flows
- [ ] Error cases handled gracefully
- [ ] User feedback clear and actionable

---

### Phase 7.3: UX Flow Verification

**Tasks**:

1. **Credential Issuance UX**:
   - Scan issuance QR code
   - Verify authorization prompt displays
   - Complete OAuth flow (if required)
   - Verify biometric authentication prompt
   - Confirm credential received and stored
   - Verify success message and credential details

2. **Credential Management UX**:
   - Navigate to credential list
   - Verify credential displays correctly
   - Test credential details view
   - Test credential deletion flow
   - Verify empty state handling

3. **Credential Presentation UX**:
   - Scan presentation QR code
   - Verify credential selection prompt
   - Select credential to present
   - Verify biometric authentication prompt
   - Confirm presentation success
   - Verify verifier receives credential

4. **Navigation & Transitions**:
   - Test back button behavior
   - Test activity transitions
   - Test app backgrounding/foregrounding
   - Verify state preservation

**Success Criteria**:
- [ ] All UX flows complete without errors
- [ ] Biometric prompts appear at correct times
- [ ] User feedback clear at each step
- [ ] Navigation intuitive and consistent
- [ ] No UI glitches or crashes

---

### Phase 7.4: System Response & Integration Testing

**Tasks**:

1. **Android System Integration**:
   - Verify Android Credential Manager integration
   - Test system credential picker (if applicable)
   - Verify notification handling
   - Test app switching and task management

2. **Deep Link Handling**:
   - Test `openid-credential-offer://` scheme
   - Test `openid4vp://` scheme
   - Test HTTP/HTTPS fallback URLs
   - Verify intent filter priority

3. **Network Communication**:
   - Monitor OIDC protocol exchanges
   - Verify TLS/SSL connections
   - Test with different network conditions
   - Verify timeout handling

4. **Storage & Persistence**:
   - Verify credentials persist after app restart
   - Test storage encryption
   - Verify key material protection
   - Test storage limits and cleanup

**Success Criteria**:
- [ ] System integration works correctly
- [ ] Deep links handled reliably
- [ ] Network communication secure and robust
- [ ] Data persists correctly across sessions

---

### Phase 7.5: End-to-End Scenario Testing

**Tasks**:

1. **Complete Issuance Scenario**:
   - User scans issuer QR code
   - App intercepts and processes request
   - User authenticates with biometric
   - Credential issued and stored
   - User views credential in app

2. **Complete Presentation Scenario**:
   - User scans verifier QR code
   - App shows credential selection
   - User selects credential
   - User authenticates with biometric
   - Credential presented to verifier
   - Verifier confirms receipt

3. **Multi-Credential Scenario**:
   - Issue multiple credentials
   - Verify credential list displays all
   - Present different credentials
   - Delete specific credentials
   - Verify remaining credentials intact

4. **Error Recovery Scenarios**:
   - Network failure during issuance
   - Network failure during presentation
   - Biometric authentication failure
   - Invalid credential request
   - Verify app recovers gracefully

**Success Criteria**:
- [ ] Complete issuance flow works end-to-end
- [ ] Complete presentation flow works end-to-end
- [ ] Multiple credentials handled correctly
- [ ] Error scenarios handled gracefully
- [ ] User never left in inconsistent state

---


### Phase 7.6: Documentation & Test Report

**Tasks**:

1. **Test Execution Documentation**:
   - Document test environment setup
   - Record test execution results
   - Capture screenshots of key flows
   - Record screen videos of complete scenarios

2. **Issue Tracking**:
   - Document any bugs found
   - Prioritize issues (critical/high/medium/low)
   - Create bug reports with reproduction steps
   - Track issue resolution

3. **Test Report**:
   - Create `docs/EMULATOR_TEST_REPORT.md`
   - Summarize test coverage
   - Document pass/fail results
   - Include performance metrics
   - List known issues and workarounds

4. **User Acceptance Criteria**:
   - Verify all MVP requirements met
   - Confirm UX meets expectations
   - Validate security requirements
   - Confirm performance acceptable

**Success Criteria**:
- [ ] All tests documented
- [ ] Test report complete
- [ ] Critical issues resolved
- [ ] MVP acceptance criteria met

---

## Implementation Timeline

**Estimated Duration**: 12-16 weeks (revised from 10-14 weeks)

| Phase | Duration | Dependencies |
|-------|----------|--------------|
| Phase 1.1: Data Models | 1 week | None |
| Phase 1.2: Storage Extension | 1 week | Phase 1.1 |
| Phase 1.3: Key Management | 1 week | Phase 1.1 |
| Phase 2.1: HTTP & JSON + Error Handling | 1 week | None |
| Phase 2.2: JWT Operations | 1 week | Phase 2.1 |
| Phase 2.2.5: Common OIDC Auth Flow | 3 days | Phase 2.2 |
| Phase 2.3: OIDC4VCI | 2 weeks | Phase 1.3, 2.2.5 |
| Phase 2.4: OIDC4VP + SD-JWT | 2 weeks | Phase 1.3, 2.2.5 |
| Phase 2.5: Credential Status Checking | 1 week | Phase 2.1 |
| Phase 3.1a: Data Layer | 3 days | Phase 1.2 |
| Phase 3.1b: UI with Tabs | 4 days | Phase 3.1a |
| Phase 3.2: Issuance UI | 1 week | Phase 2.3 |
| Phase 3.3: Biometric Auth | 1 week | None |
| Phase 3.4: Presentation UI | 1 week | Phase 2.4, 3.3 |
| Phase 4.1: Deep Links | 1 week | Phase 3.2, 3.4 |
| Phase 4.2: Credential Manager | 1 week | Phase 2.4, 4.1 |
| Phase 5.1: Unit Testing | 1 week | All phases |
| Phase 5.2: Integration Testing | 1 week | All phases |
| Phase 5.3: Security Review | 1 week | All phases |
| Phase 6.1: Documentation | 1 week | All phases |
| Phase 6.2: Deployment | 1 week | All phases |
| Phase 7.1: Emulator Setup | 2 days | Phase 6.2 |
| Phase 7.2: QR Code Verification | 2 days | Phase 7.1 |
| Phase 7.3: UX Flow Verification | 3 days | Phase 7.2 |
| Phase 7.4: System Integration | 2 days | Phase 7.3 |
| Phase 7.5: E2E Scenarios | 3 days | Phase 7.4 |
| Phase 7.6: Test Documentation | 2 days | Phase 7.5 |

**Critical Path**: Phase 1 → Phase 2 → Phase 3 → Phase 4 → Phase 5 → Phase 6 → Phase 7

**Key Changes from Original Plan**:
- **Phase 2.1**: Added comprehensive error handling and timeout specifications
- **Phase 2.4**: Expanded to include SD-JWT selective disclosure implementation
- **Phase 2.5**: NEW - Credential status checking (Status List 2021)
- **Phase 3.1**: Split into 3.1a (data layer, 3 days) and 3.1b (UI, 4 days)
- **Phase 3.3**: Expanded biometric auth with device capability detection
- **Timeline**: Extended to 12-16 weeks to account for additional complexity
- QR code/deep link handling moved to Phase 4 (second-to-last) as it's the final integration layer
- Phase 7 added for comprehensive emulated device testing

---

## Risk Management

### Technical Risks

1. **Android Keystore Compatibility**
   - Risk: Not all devices support StrongBox
   - Mitigation: Fallback to TEE, test on multiple devices

2. **OIDC Protocol Complexity**
   - Risk: Protocol implementation errors
   - Mitigation: Follow specs closely, extensive testing

3. **Backward Compatibility**
   - Risk: Breaking existing FIDO2 functionality
   - Mitigation: Comprehensive regression testing

4. **Performance**
   - Risk: Slow credential operations
   - Mitigation: Optimize crypto operations, async processing

### Mitigation Strategies

- **Incremental Development**: Each phase delivers testable functionality
- **Continuous Testing**: Test after each phase completion
- **Code Reviews**: Review all security-critical code
- **Fallback Mechanisms**: Graceful degradation when features unavailable

---

## Success Metrics

### Functional Metrics
- [ ] Credentials can be issued successfully
- [ ] Credentials can be presented successfully
- [ ] Chrome integration works
- [ ] All tests pass

### Performance Metrics
- [ ] Credential issuance < 5 seconds
- [ ] Credential presentation < 3 seconds
- [ ] UI responsive (< 100ms)
- [ ] APK size increase < 5MB

### Quality Metrics
- [ ] Unit test coverage > 80% (lib)
- [ ] Unit test coverage > 60% (app)
- [ ] Zero critical security issues
- [ ] Zero crashes in testing

### User Experience Metrics
- [ ] Clear error messages
- [ ] Intuitive UI flow
- [ ] Biometric auth smooth
- [ ] Minimal user friction

---

## Dependencies

### External Libraries

**lib/build.gradle**:
```gradle
dependencies {
    // HTTP client - OkHttp for Android optimization and HTTP/2 support
    implementation 'com.squareup.okhttp3:okhttp:4.12.0'  // ✓ Stable
    
    // JSON parsing
    implementation 'com.google.code.gson:gson:2.10.1'  // ✓ Stable
    
    // JWT operations - jose4j for Apache 2.0 license
    implementation 'org.bitbucket.b_c:jose4j:0.9.6'  // ✓ Stable
    
    // Existing dependencies
    // ... (keep existing)
}
```

**app/build.gradle**:
```gradle
dependencies {
    // Android Credential Manager
    implementation 'androidx.credentials:credentials:1.3.0'  // ✓ Stable
    implementation 'androidx.credentials:credentials-play-services-auth:1.3.0'  // ✓ Stable
    
    // Digital Credentials Registry (bleeding edge - alpha versions)
    implementation 'androidx.credentials.registry:registry-digitalcredentials-mdoc:1.0.0-alpha04'  // ⚠️ Alpha
    implementation 'androidx.credentials.registry:registry-digitalcredentials-preview:1.0.0-alpha04'  // ⚠️ Alpha
    implementation 'androidx.credentials.registry:registry-provider:1.0.0-alpha04'  // ⚠️ Alpha
    
    // Biometric authentication
    implementation 'androidx.biometric:biometric:1.2.0-alpha05'  // ⚠️ Alpha
    
    // Existing dependencies
    // ... (keep existing)
}
```

**Dependency Management**:
- Run `./gradlew dependencies` to verify all dependencies compile together
- Monitor alpha versions for API changes
- Document any dependency conflicts and resolutions

### Minimum Android Version
- Target: Android 14 (API 34) for full Credential Manager support
- Minimum: Android 6 (API 23) with limited functionality

---

## Next Steps

1. **Review this plan** with the team
2. **Set up development environment** with required dependencies
3. **Create feature branch** for Digital Credentials work
4. **Start Phase 1.1** with data model implementation
5. **Iterate through phases** with testing after each phase

---

## References

- [Digital Credentials Investigation](DIGITAL_CREDENTIALS_INVESTIGATION.md)
- [EUDI Wallet ARF v1.4.0](https://eudi.dev/1.4.0/arf/)
- [OpenID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [Android Credential Manager](https://developer.android.com/identity/digital-credentials)
- [W3C Digital Credentials API](https://www.w3.org/TR/digital-credentials/)

---

## Appendix: File Structure

```
fido_blehid_app/
├── lib/
│   └── src/com/isfs/blekey/
│       ├── credential/                     # NEW - Digital Credentials
│       │   ├── VerifiableCredential.java      # NEW
│       │   ├── DigitalCredentialFormat.java   # NEW
│       │   ├── DigitalCredentialMetadata.java # NEW
│       │   ├── status/                   # NEW - Credential status checking
│       │   │   ├── StatusList2021.java
│       │   │   ├── StatusListFetcher.java
│       │   │   └── CredentialStatusChecker.java
│       │   ├── jwt/                      # NEW - JWT operations
│       │   │   ├── JwtBuilder.java
│       │   │   ├── JwtParser.java
│       │   │   └── KeyBindingJwtBuilder.java
│       │   └── sdjwt/                    # NEW - SD-JWT selective disclosure
│       │       ├── DisclosureParser.java
│       │       ├── DisclosureHasher.java
│       │       └── SelectiveDisclosureBuilder.java
│       ├── data/                     # Data models (existing)
│       │   └── Passkey.java          # MODIFIED
│       ├── util/                     # Utilities (existing + NEW)
│       │   ├── HolderBindingKeyManager.java   # NEW
│       │   └── http/                 # NEW - HTTP utilities
│       │       ├── HttpClient.java       # NEW - HTTP client
│       │       └── HttpResponse.java     # NEW - HTTP response
│       └── oidc/                     # NEW - OIDC protocols
│           ├── OidcAuthorizationClient.java
│           ├── OidcTokenResponse.java
│           ├── PkceGenerator.java
│           ├── CredentialOffer.java
│           ├── IssuerMetadata.java
│           ├── Oidc4VciClient.java
│           ├── PresentationDefinition.java
│           ├── PresentationSubmission.java
│           └── Oidc4VpHandler.java
│
└── app/
    └── src/main/
        ├── AndroidManifest.xml       # MODIFIED
        ├── java/com/isfs/blekey/
        │   ├── activity/
        │   │   ├── CredentialHandlerActivity.java      # NEW
        │   │   ├── CredentialIssuanceActivity.java     # NEW
        │   │   ├── CredentialPresentationActivity.java # NEW
        │   │   └── CredentialListActivity.java         # NEW
        │   └── credentials/
        │       ├── AndroidHolderBindingKeyManager.java # NEW
        │       └── DigitalCredentialProviderService.java # NEW
        └── res/
            ├── layout/
            │   ├── activity_credential_issuance.xml    # NEW
            │   ├── activity_credential_presentation.xml # NEW
            │   ├── activity_credential_list.xml        # NEW
            │   └── credential_list_item.xml            # NEW
            └── xml/

**Key UX Integration**:
- `ResidentCredentialsActivity` - Extended with TabLayout (not replaced)
- Tab 1: "Passkeys" (default) - existing FIDO2 resident credentials
- Tab 2: "Digital Credentials" - new digital credentials view
- Issuance and presentation activities remain separate (launched from QR codes)
- All credentials stored in same passkey file, accessed through modified `Passkey.java`
                └── digital_credential_provider.xml     # NEW