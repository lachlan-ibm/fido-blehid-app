<!--
 Copyright IBM 2025
-->
# FIDO BLE HID Authenticator

A FIDO2 authenticator implementation that works over Bluetooth Low Energy (BLE) using the Human Interface Device (HID) protocol. This project enables passkey authentication on mobile devices, allowing them to act as security keys for passwordless authentication.

## Overview

This project implements a FIDO2 authenticator that can be used for passwordless authentication using the WebAuthn standard. The authenticator communicates with relying parties (websites/services) using the CTAP2 (Client to Authenticator Protocol) over BLE HID transport.

Key features:
- FIDO2 WebAuthn authenticator implementation
- BLE HID transport layer
- Android application for mobile devices
- Support for resident keys (passkeys)
- Attestation support
- Digital Credentials
  - Receive and store verifiable credentials (SD-JWT format)
  - Present credentials with selective disclosure
  - Biometric-protected credential management
  - OIDC4VCI and OIDC4VP protocol support

## Project Structure

The project is organized into the following main components:

### Library (`lib/`)

Core implementation of the FIDO2 authenticator and digital credentials:

- `com.isfs.blekey.authenticator`: Core authenticator implementation
  - `Fido2Authenticator.java`: Main authenticator class
  - `AuthenticatorAPI.java`: API interface
  - `AuthenticatorCmd.java`: Command handling
  - `PinSubCmd.java`: PIN protocol implementation

- `com.isfs.blekey.ctap`: CTAP protocol implementation
  - `CtapHid.java`: HID transport layer
  - `CtapTxn.java`: Transaction handling
  - `CtapHidCmd.java`: Command definitions
  - `Ctap2StatusCode.java`: Status codes

- `com.isfs.blekey.credential`: Digital credentials (NEW)
  - `VerifiableCredential.java`: Credential data model
  - `DigitalCredentialFormat.java`: Format definitions
  - `DigitalCredentialMetadata.java`: Credential metadata
  - `jwt/`: JWT operations (builder, parser, key binding)
  - `sdjwt/`: Selective Disclosure JWT support
  - `status/`: Credential status checking

- `com.isfs.blekey.oidc`: OIDC protocol implementation (NEW)
  - `Oidc4VciClient.java`: Credential issuance client
  - `Oidc4VpHandler.java`: Credential presentation handler
  - `OidcAuthorizationClient.java`: Authorization flow
  - `PresentationDefinition.java`: Presentation requests

- `com.isfs.blekey.data`: Data models
  - `Passkey.java`: Passkey representation

- `com.isfs.blekey.util`: Utility classes
  - `Cbor.java`: CBOR encoding/decoding
  - `KeyUtils.java`: Cryptographic key utilities
  - `CertUtils.java`: Certificate utilities
  - `DataMapper.java`: Data conversion utilities
  - `BleUtils.java`: Bluetooth utilities
  - `FileUtils.java`: File handling utilities
  - `HolderBindingKeyManager.java`: Holder binding key derivation (NEW)
  - `http/`: HTTP client with retry support (NEW)

### Android App (`app/`)

Android application that implements the BLE HID service:

- `com.isfs.blekey`: Main application
  - `MainActivity.java`: Main activity
  - `ForegroundNotificationService.java`: Background service

- `com.isfs.blekey.activity`: UI activities
  - `ManageActivity.java`: Credential management
  - `ResidentCredentialsActivity.java`: Passkey management
  - `CredentialIssuanceActivity.java`: Credential issuance UI (NEW)
  - `CredentialPresentationActivity.java`: Credential presentation UI (NEW)
  - `CredentialHandlerActivity.java`: Deep link handler (NEW)

- `com.isfs.blekey.hidsvc`: HID service implementation
  - `HIDService.java`: BLE service
  - `HIDPasskey.java`: FIDO HID implementation

- `com.isfs.blekey.util`: Android utilities
  - `AndroidHolderBindingKeyManager.java`: Android Keystore integration (NEW)
  - `AndroidKeystoreManager.java`: Keystore operations (NEW)
  - `BiometricAuthHelper.java`: Biometric authentication (NEW)

### Tests (`lib/test/`)

Unit tests for the authenticator implementation:

- `com.isfs.blekey.authenticator`: Test classes
  - `Fido2AuthenticatorTest.java`: Basic tests
  - `Fido2AuthenticatorMockTest.java`: Tests with mocks
  - `Fido2AuthenticatorIntegrationTest.java`: Integration tests

## Build System

The project uses Gradle for building:

- `build.gradle`: Main build configuration
- `lib/build.gradle`: Library module configuration
- `app/build.gradle`: Android app configuration
- `copyright-hook.gradle`: Copyright header management

## CI/CD Integration

The project includes GitHub Actions workflows for continuous integration:

- `.github/workflows/copyright-check.yml`: Checks and enforces copyright headers
- `.github/workflows/lib-tests.yml`: Runs unit tests for the library

## Getting Started

### Prerequisites

- Java Development Kit (JDK) 17 or higher
- Android Studio (for app development)
- Gradle 8.1.1 or higher
- Android SDK with API level 34 installed

### VS Code / Bob IDE Setup

If you're using VS Code or Bob IDE for development, you need to configure the Java Language Server to properly recognize the Android project:

#### Fixing "Missing system library" Error

If you encounter `java.lang.IllegalStateException: Missing system library` errors, follow these steps:

1. **Enable Android Support** in `.vscode/settings.json`:
   ```json
   {
     "java.jdt.ls.androidSupport.enabled": "on"
   }
   ```

2. **Configure Eclipse Plugin** in `app/build.gradle`:
   ```gradle
   apply plugin: 'eclipse'

   eclipse {
       classpath {
           containers 'org.eclipse.jdt.launching.JRE_CONTAINER/org.eclipse.jdt.internal.debug.ui.launcher.StandardVMType/JavaSE-17'
           file.whenMerged { cp ->
               def entries = cp.entries
               
               // Add main source directory
               def src = new org.gradle.plugins.ide.eclipse.model.SourceFolder('src/main/java', null)
               entries.add(src)
               
               // Add Android SDK android.jar
               def androidJar = new org.gradle.plugins.ide.eclipse.model.Library(
                   fileReferenceFactory.fromPath("${android.sdkDirectory}/platforms/${android.compileSdkVersion}/android.jar")
               )
               androidJar.sourcePath = fileReferenceFactory.fromPath("${android.sdkDirectory}/sources/${android.compileSdkVersion}")
               entries.add(androidJar)
           }
       }
   }
   ```

3. **Run the Classpath Regeneration Script**:
   ```bash
   cd app && bash regenrate_classpath.sh
   ```
   
   This script will:
   - Extract AAR dependencies from Gradle cache
   - Manually write `.classpath` with proper JRE container and Android SDK paths
   - Add AAR classes.jar files to the classpath
   - Verify the build succeeds
   
   **Important**: The Gradle `eclipse` plugin is disabled in `app/build.gradle` to prevent automatic regeneration of `.classpath` on file edits, which was overwriting manual configurations.

4. **Verify .classpath Structure**:
   
   The generated `app/.classpath` should have this structure:
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <classpath>
       <classpathentry kind="output" path="bin/default"/>
       <classpathentry kind="con" path="org.eclipse.jdt.launching.JRE_CONTAINER/org.eclipse.jdt.internal.debug.ui.launcher.StandardVMType/JavaSE-17"/>
       <classpathentry kind="src" path="src/main/java"/>
       <classpathentry sourcepath="/home/lowkey/Android/sources/android-34" kind="lib" path="/home/lowkey/Android/platforms/android-34/android.jar"/>
       <classpathentry kind="con" path="org.eclipse.buildship.core.gradleclasspathcontainer"/>
   </classpath>
   ```
   
   **Key points**:
   - Remove any duplicate `JRE_CONTAINER` entries
   - Ensure the JRE path does NOT have a trailing slash (`/JavaSE-17` not `/JavaSE-17/`)
   - Keep the Gradle classpath container at the end

5. **CRITICAL: Reload VS Code Window**: Press `Ctrl+Shift+P` → "Developer: Reload Window"
   
   **⚠️ IMPORTANT**: The Java Language Server will NOT pick up classpath changes until you reload the VS Code window. Even though the Gradle build succeeds, IDE errors will persist until you perform this reload step. This is a required breakpoint in the troubleshooting process.

6. **If Errors Persist After Reload**: Clean the Java Language Server workspace cache
   
   If you still see errors like "Cannot find the class file for java.lang.invoke.StringConcatFactory" or references to non-existent library paths after reloading:
   
   1. Press `Ctrl+Shift+P`
   2. Type "Java: Clean Java Language Server Workspace"
   3. Select it and confirm
   4. Reload VS Code window again (`Ctrl+Shift+P` → "Developer: Reload Window")
   
   This clears stale cache entries that may reference old or incorrect library paths. The Language Server will rebuild its cache using the corrected `.classpath` file.

This configuration ensures the Java Language Server can properly resolve Java system libraries and Android dependencies while keeping the project managed by Gradle (not in "unmanaged" mode).

### Building the Project

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

### Running Tests

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

### Network Security Configuration for Testing

The app uses a debug-only network security configuration to allow HTTP testing with local mock servers while maintaining secure defaults for release builds.

#### Configuration Strategy

**Debug Build Only:**
- File: [`app/src/debug/res/xml/network_security_config.xml`](app/src/debug/res/xml/network_security_config.xml)
- Cleartext traffic to localhost: **ALLOWED**
- Purpose: Enable testing with local HTTP mock servers
- Domains allowed: `localhost`, `127.0.0.1`

**Release Build:**
- No custom config needed - Android's default security applies
- Cleartext traffic: **BLOCKED** (Android 9+ default)
- Trust anchors: System certificates only (default)

#### How It Works

Android's build system automatically selects the correct configuration:
- **Debug builds** (`./gradlew assembleDebug`): Uses debug-specific config allowing localhost HTTP
- **Release builds** (`./gradlew assembleRelease`): Uses Android's secure defaults (HTTPS-only)

The [`AndroidManifest.xml`](app/src/main/AndroidManifest.xml) references `@xml/network_security_config`, which resolves to:
- `app/src/debug/res/xml/network_security_config.xml` for debug builds
- Android's default secure policy for release builds (no file needed)

#### Security Considerations

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

## Important Changes

### HKDF-Based Passkey Seed Generation

**Version 1.0.0+** introduces a breaking change to passkey seed generation:

- **What Changed**: Replaced non-standard cryptographic construction with RFC 5869 HKDF (HMAC-based Key Derivation Function)
- **Impact**: Existing credentials encrypted with old seeds cannot be decrypted with new seeds
- **Action Required**: Users must re-register all credentials after upgrading

This change improves security by using a standardized, well-reviewed key derivation function instead of the previous custom implementation.

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
