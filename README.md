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

3. **Generate Eclipse Project Files**:
   ```bash
   cd app && ./gradlew eclipse
   ```

4. **Update the Generated `.classpath`** file to ensure proper JRE and Gradle container:
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <classpath>
       <classpathentry kind="output" path="bin/default"/>
       <classpathentry kind="con" path="org.eclipse.jdt.launching.JRE_CONTAINER/org.eclipse.jdt.internal.debug.ui.launcher.StandardVMType/JavaSE-17/"/>
       <classpathentry kind="src" path="src/main/java"/>
       <classpathentry sourcepath="/home/lowkey/Android/sources/android-34" kind="lib" path="/home/lowkey/Android/platforms/android-34/android.jar"/>
       <classpathentry kind="con" path="org.eclipse.buildship.core.gradleclasspathcontainer"/>
   </classpath>
   ```

5. **Reload VS Code Window**: Press `Ctrl+Shift+P` → "Developer: Reload Window"

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

## Important Changes

### HKDF-Based Passkey Seed Generation

**Version 1.0.0+** introduces a breaking change to passkey seed generation:

- **What Changed**: Replaced non-standard cryptographic construction with RFC 5869 HKDF (HMAC-based Key Derivation Function)
- **Impact**: Existing credentials encrypted with old seeds cannot be decrypted with new seeds
- **Action Required**: Users must re-register all credentials after upgrading

This change improves security by using a standardized, well-reviewed key derivation function instead of the previous custom implementation.

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
