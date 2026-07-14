<!--
 Copyright IBM 2025
-->
# Android App Passkey Authenticator

A FIDO2 authenticator implementation that works over Bluetooth (BT) using the Human Interface Device (HID) protocol. This project enables passkey authentication on mobile devices, allowing them to act as security keys for passwordless authentication.

## Overview / Why use this app

This project implements a FIDO2 authenticator that can be used for passwordless authentication using the WebAuthn/CTAP2 standards.

Key features:
- FIDO2 WebAuthn authenticator implementation
- BLE transport layer (FIDO GATT)
- Support for resident keys
- Attestation format support (packed, anon-ca, tpm)
- Digital Credentials Prototype
  - Receive and store verifiable credentials (SD-JWT format)
  - Present credentials with selective disclosure
  - Biometric-protected credential management
  - OIDC4VCI and OIDC4VP protocol support
  - Bind credentials to passkey/attestation

The android application communicates with relying parties (websites/services) using the CTAP2 (Client to Authenticator Protocol) over BT HID transport; or using the FIDO GATT profile from the CTAP2 specification.

The allows an android device to connect to a large number of browsers/clients and offer Passkey authentication without a user having to set-up their device/OS to support Passkeys. By 

## Project Structure

The project is organized into the following main components:

### Library (`lib/`)

Core implementation of the FIDO2 authenticator and digital credentials:


### Android App (`app/`)

Android application that implements the BT HID and FIDO GATT services:


## Development

The project uses Gradle for building:

- `build.gradle`: Main build configuration
- `lib/build.gradle`: Library module configuration
- `app/build.gradle`: Android app configuration
- `copyright-hook.gradle`: Copyright header management

### CI/CD Integration

The project includes GitHub Actions workflows for continuous integration:

- `.github/workflows/copyright-check.yml`: Checks and enforces copyright headers
- `.github/workflows/lib-tests.yml`: Runs unit tests for the library

## Getting Started

### Prerequisites

- Java Development Kit (JDK) 17 or higher
- Android Studio (for app development)
- Gradle 8.1.1 or higher
- Android SDK with API level 34 installed

### IDE Setup

Configuring the Java Language Server to properly recognize the Android project can be tricky/fragile:

#### Fixing "Missing system library" Error

If you encounter `java.lang.IllegalStateException: Missing system library` errors, follow these steps:

**Run the Classpath Regeneration Script**:
   ```bash
   cd app && bash regenrate_classpath.sh
   ```
   
   This script will:
   - Extract AAR dependencies from Gradle cache
   - Manually write `.classpath` with proper JRE container and Android SDK paths
   - Add AAR classes.jar files to the classpath
   - Verify the build succeeds
   
   **Important**: The Gradle `eclipse` plugin is disabled in `app/build.gradle` to prevent automatic regeneration of `.classpath` on file edits, which was overwriting manual configurations.

**CRITICAL: Reload VS Code Window**: Press `Ctrl+Shift+P` → "Developer: Reload Window"
   
   **⚠️ IMPORTANT**: The Java Language Server will NOT pick up classpath changes until you reload the VS Code window. Even though the Gradle build succeeds, IDE errors will persist until you perform this reload step. This is a required breakpoint in the troubleshooting process.

**If Errors Persist After Reload**: Clean the Java Language Server workspace cache
   
   If you still see errors like "Cannot find the class file for java.lang.invoke.StringConcatFactory" or references to non-existent library paths after reloading:
   
   1. Press `Ctrl+Shift+P`
   2. Type "Java: Clean Java Language Server Workspace"
   3. Select it and confirm
   4. Reload VS Code window again (`Ctrl+Shift+P` → "Developer: Reload Window")
   
   This clears stale cache entries that may reference old or incorrect library paths. The Language Server will rebuild its cache using the corrected `.classpath` file.

This configuration ensures the Java Language Server can properly resolve Java system libraries and Android dependencies while keeping the project managed by Gradle (not in "unmanaged" mode).

#### Building the Project

To build the entire project:

```bash
./gradlew build
```

To build just the library:

```bash
./gradlew :lib:build
```

To build the Android app:

```bash
./gradlew :app:build
```

#### Unit Tests

To run the unit tests:

```bash
./gradlew :lib:test
```

#### Digital Credentials UX Tests

The project includes automated UX tests for the digital credentials feature that run on Android emulators or physical devices. These tests verify the complete credential lifecycle including deep link handling, credential issuance, and presentation flows.

**Available test tasks:**

```bash
# Run complete E2E digital credentials flow test
./gradlew testE2ECompleteFlow

# Run all UX verification tests
./gradlew testUXAll

# Run specific test suites
./gradlew testDeepLinks              # Deep link handling
./gradlew testCredentialManager      # Credential Manager integration
./gradlew testE2EIssuance           # Credential issuance flow

# Install app and run E2E tests
./gradlew installAndTestE2E
```

**Test with specific device:**

```bash
# Use custom emulator
./gradlew testE2ECompleteFlow -PdeviceId=emulator-5556

# Use physical device via WiFi
./gradlew testE2ECompleteFlow -PdeviceId=192.168.1.100:5555
```

**Test results location:**

All UX test results are saved to `app/build/ux-test-results/` and are automatically cleaned by the `clean` task:

```bash
# View complete E2E test report
cat app/build/ux-test-results/e2e-complete-flow/E2E_COMPLETE_FLOW_REPORT.md

# View test logs
tail -f app/build/ux-test-results/e2e-complete-flow/logs/credential-flow-complete.log

# View screenshots
ls app/build/ux-test-results/e2e-complete-flow/screenshots/
```

**Prerequisites for UX tests:**
- Android emulator running (API 33+) or physical device connected
- ADB installed and configured
- App permissions granted (Bluetooth, notifications)

For detailed information about the UX testing framework, see:
- [`app/PHASE4_TESTING_README.md`](app/PHASE4_TESTING_README.md) - Complete testing guide
- [`app/UX_TESTING_AUTOMATION_PLAN.md`](app/UX_TESTING_AUTOMATION_PLAN.md) - Automation plan

#### Network Security Configuration for Testing

The app uses a debug-only network security configuration to allow HTTP testing with local mock servers while maintaining secure defaults for release builds.

Configuration Strategy
----------------------

**Debug Build Only:**
- File: [`app/src/debug/res/xml/network_security_config.xml`](app/src/debug/res/xml/network_security_config.xml)
- Cleartext traffic to localhost: **ALLOWED**
- Purpose: Enable testing with local HTTP mock servers
- Domains allowed: `localhost`, `127.0.0.1`

**Release Build:**
- No custom config needed - Android's default security applies
- Cleartext traffic: **BLOCKED** (Android 9+ default)
- Trust anchors: System certificates only (default)

How It Works
-------------

Android's build system automatically selects the correct configuration:
- **Debug builds** (`./gradlew assembleDebug`): Uses debug-specific config allowing localhost HTTP
- **Release builds** (`./gradlew assembleRelease`): Uses Android's secure defaults (HTTPS-only)

The [`AndroidManifest.xml`](app/src/main/AndroidManifest.xml) references `@xml/network_security_config`, which resolves to:
- `app/src/debug/res/xml/network_security_config.xml` for debug builds
- Android's default secure policy for release builds (no file needed)

Security Considerations
----------------------

1. **Debug builds only** - Cleartext exception only applies to debug builds
2. **Release builds are secure by default** - Android 9+ blocks cleartext traffic automatically
3. **No production risk** - Release builds cannot accidentally use insecure connections
4. **Localhost only** - Only local testing servers are affected, not production APIs


- [`app/test-e2e-complete-flow.sh`](app/test-e2e-complete-flow.sh) - Main test script

### Copyright Management

The project includes a system for managing copyright headers in source files. To check and update copyright headers:

```bash
./check-copyright.sh
```

To see what changes would be made without actually making them:

```bash
./check-copyright.sh --dry-run
```

For more information about the copyright management system, see [COPYRIGHT.md](COPYRIGHT.md).


## Usage

### As a Library

#### FIDO2 Authenticator

To use the FIDO2 authenticator as a library in your own project:

```java
import com.isfs.blekey.authenticator.Fido2Authenticator;

// Create a new authenticator
Fido2Authenticator authenticator = new Fido2Authenticator();

// Create a credential
String credentialJson = authenticator.credentialCreate(jsonOptions);

// Generate an assertion
String assertionJson = authenticator.credentialRequest(jsonOptions);
```

#### Digital Credentials

To issue and present digital credentials:

```java
import com.isfs.blekey.oidc.Oidc4VciClient;
import com.isfs.blekey.oidc.Oidc4VpHandler;
import com.isfs.blekey.credential.VerifiableCredential;

// Issue a credential
Oidc4VciClient client = new Oidc4VciClient();
VerifiableCredential credential = client.issueCredential(
    credentialOfferUri,
    credentialId,
    issuerId,
    credentialType,
    masterPrivateKey
);

// Present a credential with selective disclosure
Oidc4VpHandler handler = new Oidc4VpHandler();
Set<String> selectedClaims = Set.of("given_name", "age_over_18");
String response = handler.presentCredential(
    authorizationRequestUri,
    credential,
    selectedClaims,
    masterPrivateKey
);
```

For detailed API documentation, see the [Digital Credentials Developer Guide](docs/DIGITAL_CREDENTIALS_DEVELOPER_GUIDE.md).

### As an Android App

#### FIDO2 Security Key

1. Install the app on your Android device
2. Enable the FIDO HID service
3. Use your device as a security key for websites that support WebAuthn

#### Digital Credentials Wallet

1. Navigate to "Manage Credentials" in the app
2. Select the "Digital Credentials" tab
3. Scan QR codes to receive credentials from issuers
4. Present credentials to verifiers when requested
5. Manage your credential collection

For detailed usage instructions, see the [Digital Credentials User Guide](docs/DIGITAL_CREDENTIALS_USER_GUIDE.md).

## Contributing

Contributions are welcome! Please make sure to:

1. Run the copyright check before submitting code
2. Add unit tests for new functionality
3. Follow the existing code style
