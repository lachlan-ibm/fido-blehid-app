/*
 * Copyright IBM 2025
 */

# FIDO2 Authenticator Tests

This directory contains JUnit tests for the FIDO2 Authenticator implementation.

## Test Structure

The tests are organized into three main classes:

1. **Fido2AuthenticatorTest.java**: Basic unit tests for individual methods
2. **Fido2AuthenticatorIntegrationTest.java**: Integration tests for end-to-end functionality
3. **Fido2AuthenticatorMockTest.java**: Mock-based tests that isolate the class from its dependencies

## Running the Tests

To run the tests, use the Gradle test task:

```bash
./gradlew :lib:test
```

To run a specific test class:

```bash
./gradlew :lib:test --tests "com.isfs.blekey.authenticator.Fido2AuthenticatorTest"
```

## Test Reports

After running the tests, HTML reports will be available at:

```
lib/build/reports/tests/test/index.html
```

## Adding New Tests

When adding new tests:

1. Place them in the appropriate package under `lib/test/`
2. Follow the naming convention `*Test.java` for test classes
3. Use JUnit 5 annotations and assertions
4. Use Mockito for mocking dependencies when appropriate

## Test Dependencies

The tests use the following dependencies:

- JUnit 5 for test framework
- Mockito for mocking
- Mockito Inline for mocking static methods

These dependencies are configured in the `lib/build.gradle` file.

## Directory Structure

The test directory structure follows the same package structure as the main code:

```
lib/test/com/isfs/blekey/authenticator/
```

This keeps the tests separate from the main code while maintaining the same package structure.