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

## Project Structure

The project is organized into the following main components:

### Library (`lib/`)

Core implementation of the FIDO2 authenticator:

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

- `com.isfs.blekey.data`: Data models
  - `Passkey.java`: Passkey representation

- `com.isfs.blekey.util`: Utility classes
  - `Cbor.java`: CBOR encoding/decoding
  - `KeyUtils.java`: Cryptographic key utilities
  - `CertUtils.java`: Certificate utilities
  - `DataMapper.java`: Data conversion utilities
  - `BleUtils.java`: Bluetooth utilities
  - `FileUtils.java`: File handling utilities

### Android App (`app/`)

Android application that implements the BLE HID service:

- `com.isfs.blekey`: Main application
  - `MainActivity.java`: Main activity
  - `PasskeyActivity.java`: Passkey management
  - `ForegroundNotificationService.java`: Background service

- `com.isfs.blekey.hidsvc`: HID service implementation
  - `HIDService.java`: BLE service
  - `HIDPasskey.java`: FIDO HID implementation

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

To run the unit tests:

```bash
./gradlew :lib:test
```

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

### As an Android App

1. Install the app on your Android device
2. Enable the FIDO HID service
3. Use your device as a security key for websites that support WebAuthn

## Contributing

Contributions are welcome! Please make sure to:

1. Run the copyright check before submitting code
2. Add unit tests for new functionality
3. Follow the existing code style
