#!/bin/bash
#
# Copyright IBM 2025
#

# Script to run the FIDO2 Authenticator tests

# Change to the project root directory
cd "$(dirname "$0")/../.."

# Run all tests
if [ "$1" == "all" ] || [ -z "$1" ]; then
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

# If we get here, the argument was not recognized
echo "Usage: $0 [all|unit|integration|mock]"
echo "  all         - Run all tests (default)"
echo "  unit        - Run only unit tests"
echo "  integration - Run only integration tests"
echo "  mock        - Run only mock tests"
exit 1

# Made with Bob
