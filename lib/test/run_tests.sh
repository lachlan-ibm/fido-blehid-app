#!/bin/bash
#
# Copyright IBM 2025
#

# Script to run the FIDO2 Authenticator tests

# Change to the project root directory
cd "$(dirname "$0")/../.."

# Run all tests
if [ "$1" == "all" ]; then
  echo "Running all tests..."
  ./gradlew :lib:test
  exit $?
fi

# Run a specific test class
if [ "$1" == "unit" ]; then
  echo "Running unit tests..."
  ./gradlew :lib:test --tests "com.isfs.blekey.authenticator.Fido2AuthenticatorTest"
  exit $?
fi

if [ "$1" == "integration" ]; then
  echo "Running integration tests..."
  ./gradlew :lib:test --tests "com.isfs.blekey.authenticator.Fido2AuthenticatorIntegrationTest"
  exit $?
fi

if [ "$1" == "mock" ]; then
  echo "Running mock tests..."
  ./gradlew :lib:test --tests "com.isfs.blekey.authenticator.Fido2AuthenticatorMockTest"
  exit $?
fi

if [ "$1" == "ctap" ]; then
  echo "Running CTAP2 HID request tests..."
  ./gradlew :lib:test --tests "com.isfs.blekey.ctap.Ctap2HidRequestTest"
  exit $?
fi

if [ "$1" == "crypto" ]; then
  echo "Running cryptography data tests..."
  ./gradlew :lib:test --tests "com.isfs.blekey.data.SymmetricKeyTest com.isfs.blekey.data.FernetKeyTest"
  exit $?
fi

if [ "$1" == "util" ]; then
  echo "Running utility tests..."
  ./gradlew :lib:test --tests "com.isfs.blekey.util.JsonTest com.isfs.blekey.util.KeyUtilsTest"
  exit $?
fi

if [ ! -z "$1" ]; then
  echo "Running specific tests..."
  ./gradlew :lib:test --tests "$1"
  exit $?
fi

# If we get here, the argument was not recognized
echo "Usage: $0 [all|unit|integration|mock|ctap|crypto|util]"
echo "  all                 - Run all tests (default)"
echo "  unit                - Run only unit tests"
echo "  integration         - Run only integration tests"
echo "  mock                - Run only mock tests"
echo "  ctap                - Run only CTAP2 HID request tests"
echo "  crypto              - Run only the AES symmetric key tests"
echo "  util                - Run only the utility class tests"
echo "  <test.class.path>   - Run only the specific given tests"
exit 1

# Made with Bob
