<!--
 Copyright IBM 2025
-->
# Android App Passkey Authenticator

A FIDO2 authenticator implementation that works over Bluetooth (BT) using the Human Interface Device (HID) protocol. This app enables passkey authentication from android mobile devices, allowing it to act as security key for passwordless authentication.

## Overview / Why use this app

This app implements a FIDO2 authenticator that can be used for passwordless authentication using the WebAuthn/CTAP2 standards.

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

The allows an android device to connect to a large number of browsers/clients and offer Passkey authentication without a user having to set-up their device/OS to support Passkeys.

## Project Structure

The project is organized into the following main components:

### Library (`lib/`)

Core implementation of the CTAP2, WebAuthn and various draft digital credentials specifications:


### Android App (`app/`)

Android application that implements the BT HID and FIDO GATT services.

Manages User interaction and storage of key material in TEE or Strongbox, depending on device avaliability.


## Development

The project uses Gradle for building:

- `build.gradle`: Project (common) build configuration
- `lib/build.gradle`: Library module configuration
- `app/build.gradle`: Android app configuration
- `copyright-hook.gradle`: Copyright header management

### CI/CD Integration

The project includes GitHub Actions workflows for continuous integration:

- `.github/workflows/copyright-check.yml`: Checks and enforces copyright headers
- `.github/workflows/lib-tests.yml`: Runs unit tests for the library
- `.github/workflows/release-build.yml`: Build and upload the APK to a new GitHub release tag

## Getting Started

### As an Android App

#### FIDO2 Security Key

1. Install the app on your Android device via the app store
2. Enable the FIDO HID service + permit notifications from the app
3. Connect your mobile device to your laptop
   - You can now use the mobile device as a security key for websites/app on your laptop that support WebAuthn

#### Digital Credentials Wallet

1. Navigate to "Manage Credentials" in the app
2. Select the "Digital Credentials" tab
3. Scan QR codes to receive credentials from issuers
4. Present credentials to verifiers when requested
5. Manage your credential collection

For an overview of specification support, see the [Digital Credentials](docs/DIGITAL_CREDENTIALS.md).


### Prerequisites

- Java Development Kit (JDK) 17 or higher
- Android Studio (for app development)
- Gradle 8.1.1 or higher
- Android SDK with API level 34 installed

### IDE Setup

see [troubleshooting](docs/TROUBLESHOOT.md) for help in setting up VSCode and related IDE

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


### Copyright Management

The project includes a helper for managing copyright headers in source files. To check and update copyright headers:

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



## Contributing

Contributions are welcome! Please make sure to:

1. Run the copyright check before submitting code
2. Add unit tests for new functionality
3. Follow the existing code style
