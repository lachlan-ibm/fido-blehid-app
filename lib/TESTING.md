<!--
 Copyright IBM 2026
-->
# Testing Guide

This document captures lessons learned, common traps, debugging strategies, and development patterns for writing and fixing tests in this project.

## Table of Contents

- [Common Test Failures and Solutions](#common-test-failures-and-solutions)
- [Debugging Strategies](#debugging-strategies)
- [Testing Best Practices](#testing-best-practices)
- [Critical Bug Patterns](#critical-bug-patterns)
- [Mock Configuration](#mock-configuration)
- [Algorithm and Cryptography Issues](#algorithm-and-cryptography-issues)

## Common Test Failures and Solutions

### PKCS12 Serialization Issues

**Problem:** EC private key encoding changes after PKCS12 serialization (67 bytes → 79 bytes), causing seed generation mismatches.

**Symptoms:**
- `NO_CREDENTIALS` error (0x2E) in CTAP2 operations
- "Tag mismatch" errors during decryption
- Different seeds from same key after reload

**Root Cause:** PKCS12 normalizes ASN.1 DER encoding. Both encodings represent the same mathematical key, but `privateKey.getEncoded()` returns different bytes.

**Solution:** Use deterministic ECDSA (RFC 6979) in [`KeyUtils.getPasskeySeed()`](lib/src/com/isfs/blekey/util/KeyUtils.java:1306):
- Change from `"SHA256withECDSA"` to `"SHA256withDETECDSA"`
- Ensures same key + entropy always produces same seed

### Static Field Pollution Between Tests

**Problem:** Static fields persist between test runs, causing unpredictable failures.

**Symptoms:**
- Tests pass individually but fail when run together
- Inconsistent test results
- Null pointer exceptions in subsequent tests

**Solution:** Clean up static fields in `@After` methods using reflection:
```java
@After
public void tearDown() throws Exception {
    Field rootPublicKeyField = Passkey.class.getDeclaredField("rootPublicKey");
    rootPublicKeyField.setAccessible(true);
    rootPublicKeyField.set(null, null);
}
```

**Example:** [`PasskeyMainTest.java:68-89`](lib/test/com/isfs/blekey/data/PasskeyMainTest.java:68-89)

### Mock Scope Timing Issues

**Problem:** MockedStatic scope ends before code execution completes, leaving fields uninitialized.

**Symptoms:**
- NullPointerException in production code during tests
- Methods return null unexpectedly
- File operations appear to succeed but objects are null

**Root Cause:** Static fields accessed after mock scope closes revert to null.

**Solution:** Ensure mock scope encompasses entire operation or use reflection to set static fields directly.

**Example:** [`PasskeyMainTest.java:169`](lib/test/com/isfs/blekey/data/PasskeyMainTest.java:169)

### CTAP Parameter Type Mismatches

**Problem:** CTAP2 parameters have different types in different operations.

**Symptoms:**
- ClassCastException when processing CTAP requests
- Incorrect parameter extraction

**Example:** In `getAssertion`, parameter 0x02 is `rpId` as String, but in `makeCredential` it's a Map.

**Solution:** Check CTAP specification for parameter types per operation:
```java
// getAssertion: rpId is String
String rpId = (String) params.get(0x02);
Map<String, Object> pubKeyMap = new HashMap<>();
pubKeyMap.put("rpId", rpId);

// makeCredential: rp is Map
Map<String, Object> rp = (Map<String, Object>) params.get(0x02);
```

**Fixed in:** [`AuthenticatorAPI.java:1108`](lib/src/com/isfs/blekey/authenticator/AuthenticatorAPI.java:1108)

## Debugging Strategies

### Run Tests with Full Output First

**Don't filter output prematurely:**
```bash
# Bad: Filters hide critical information
./gradlew test 2>&1 | grep -A 5 "FAILED"

# Good: See complete output first
./gradlew test 2>&1 | tee test-output.log
```

**Why:** Stack traces and error context are often hidden by filtering. One complete output is more valuable than multiple filtered runs.

### Capture Stack Traces Immediately

**Always preserve full stack traces:**
- Don't use `head`, `tail`, or `grep` until you've reviewed the complete error
- Save full output to a file for reference
- The actual error is often several lines above the failure message

### Verify Dependencies Before Assuming

**Problem:** Misdiagnosing which components use which dependencies.

**Example:** Assumed `Fido2Authenticator` used `KeystoreManager` based on null errors, but it actually uses `KeyUtils.getKeyPair()` directly.

**Solution:**
1. Read the actual implementation code
2. Trace the call stack from the error
3. Don't assume based on error messages alone

### Check Algorithm Naming Inconsistencies

**Java cryptography has inconsistent algorithm names:**
- `KeyPairGenerator.getInstance("EC")` - Standard name
- `AlgorithmParameters.getInstance("ECDSA")` - Fails
- `AlgorithmParameters.getInstance("EC", "BC")` - Works with BouncyCastle
- `Signature.getInstance("SHA256withECDSA")` - Standard name

**Solution:** Always specify provider when using BouncyCastle: `getInstance("EC", "BC")`

## Testing Best Practices

### Use Mockito Strict Mode

**Benefit:** Catches unnecessary stubbing that indicates test design issues.

**Example:**
```java
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.STRICT_STUBS)
public class MyTest {
    // Unused stubs will cause test failure
}
```

### Parameterized Tests Reveal Algorithm Issues

**Use parameterized tests for cryptographic operations:**
```java
@ParameterizedTest
@MethodSource("algorithmProvider")
void testWithMultipleAlgorithms(String algorithm, int keySize) {
    // Test with EC-256, EC-384, EC-521, RSA-2048, etc.
}
```

**Why:** Algorithm-specific bugs (like hardcoded curve sizes) only appear with multiple algorithms.

### Integration Tests Need Proper Fixtures

**Requirements:**
1. Initialize all infrastructure (KeystoreManager, file paths)
2. Set up test data in correct order
3. Clean up static state between tests
4. Mock external dependencies consistently

**Example:** [`PasskeyTest.setUp()`](lib/test/com/isfs/blekey/data/PasskeyTest.java:65)

### File I/O Tests Need Careful Stream Handling

**Common issues:**
- Resource leaks (unclosed streams)
- Closing System.in/System.out
- File locks preventing cleanup

**Solution:**
```java
// Don't close System.in
Scanner scanner = new Scanner(System.in);
// Use scanner but don't call scanner.close()

// Use try-with-resources for file streams
try (FileInputStream fis = new FileInputStream(file)) {
    // Use stream
}
```

**Fixed in:** [`Passkey.java:834-848`](lib/src/com/isfs/blekey/data/Passkey.java:834-848)

## Critical Bug Patterns

### Inverted Logic Bugs

**Pattern:** Condition checks the opposite of intended behavior.

**Example:**
```java
// Bug: Tries to read when file DOESN'T exist
if (!platKeyFile.exists()) {
    return readKeyFromFile(platKeyFile);
}

// Fix: Read when file DOES exist
if (platKeyFile.exists()) {
    return readKeyFromFile(platKeyFile);
}
```

**Why hard to spot:** Code reads naturally but logic is backwards.

**Fixed in:** [`KeyUtils.getPlatformKey()`](lib/src/com/isfs/blekey/util/KeyUtils.java:1357)

### Hardcoded Size Assumptions

**Pattern:** Code assumes specific sizes for variable-length data.

**Examples:**

1. **ECDH encryption curve matching:**
   - Bug: Always generated P-256 ephemeral keys
   - Fix: Detect recipient's curve size and match it
   - Fixed in: [`KeyUtils.ecdhEncrypt()`](lib/src/com/isfs/blekey/util/KeyUtils.java:987)

2. **ECDH decryption PEM validation:**
   - Bug: Hardcoded P-256 PEM size (178 bytes)
   - Fix: Support P-384 (215 bytes) and P-521 (268 bytes)
   - Fixed in: [`KeyUtils.ecdhDecrypt()`](lib/src/com/isfs/blekey/util/KeyUtils.java:1101)

**Solution:** Always detect actual sizes from data, never hardcode.

### Constructor Parameter Order

**Problem:** Constructor parameters in wrong order cause subtle bugs.

**Symptoms:**
- Tests fail with confusing errors
- Objects initialized with swapped values
- Type system doesn't catch if types are compatible

**Solution:**
- Use builder pattern for complex constructors
- Validate parameters in constructor
- Use descriptive parameter names

**Fixed in:** [`Ctap2HidRequestTest`](lib/test/com/isfs/blekey/ctap/Ctap2HidRequestTest.java)

### Empty Collection Validation

**Problem:** Code doesn't validate empty collections before processing.

**Example:**
```java
// Bug: Doesn't check if list is empty
List<Object> params = (List<Object>) request.get("pubKeyCredParams");
Object firstParam = params.get(0); // IndexOutOfBoundsException

// Fix: Validate before access
if (params == null || params.isEmpty()) {
    return Ctap2StatusCode.CTAP2_ERR_MISSING_PARAMETER;
}
```

**Fixed in:** [`AuthenticatorAPI.java:807`](lib/src/com/isfs/blekey/authenticator/AuthenticatorAPI.java:807)

## Mock Configuration

### KeystoreManager Mock Consistency

**Problem:** Mock reported as available, causing variable encryption output sizes.

**Impact:** Header sizes varied between tests, breaking assertions.

**Solution:** Mock as unavailable to force consistent ECDH encryption:
```java
when(mockKeystoreManager.isAvailable()).thenReturn(false);
```

**Result:** Consistent 230-byte headers in all tests.

**Fixed in:** [`TestHelper.createMockKeystoreManager()`](lib/test/com/isfs/blekey/authenticator/TestHelper.java:147)

### Remove Unnecessary Mock Stubbings

**Problem:** Mockito strict mode fails on unused stubs.

**Solution:** Only stub methods that are actually called:
```java
// Remove unused stubs
// when(mock.unusedMethod()).thenReturn(value);

// Keep only necessary stubs
when(mock.actuallyCalledMethod()).thenReturn(value);
```

**Fixed in:** [`TestHelper.java:149-180`](lib/test/com/isfs/blekey/authenticator/TestHelper.java:149)

## Algorithm and Cryptography Issues

### BouncyCastle Provider Requirements

**Pattern:** BouncyCastle requires explicit provider specification.

**Examples:**
```java
// Fails
AlgorithmParameters params = AlgorithmParameters.getInstance("ECDSA");

// Works
AlgorithmParameters params = AlgorithmParameters.getInstance("EC", "BC");
```

**Fixed in:** [`KeyUtils.createECParameterSpec()`](lib/src/com/isfs/blekey/util/KeyUtils.java:536)

### Ed25519 Key Detection

**Problem:** Ed25519 keys have provider-specific class names.

**Solution:** Detect by class name pattern:
```java
String className = publicKey.getClass().getSimpleName();
if (className.contains("EdDSA")) {
    // Handle Ed25519
}
```

### CA KeyPair Algorithm Validation

**Problem:** KeyPair algorithm name varies ("EC" vs "ECDSA").

**Solution:** Accept both names:
```java
String algorithm = keyPair.getPrivate().getAlgorithm();
if (!"EC".equals(algorithm) && !"ECDSA".equals(algorithm)) {
    throw new IllegalArgumentException("Expected EC key");
}
```

**Fixed in:** [`KeyUtils.getCAKeyPair()`](lib/src/com/isfs/blekey/util/KeyUtils.java:903)

### Signature Algorithm Consistency

**Problem:** Inconsistent signature algorithm names across codebase.

**Solution:** Standardize on "SHA256withECDSA" for EC keys:
```java
Signature signature = Signature.getInstance("SHA256withECDSA");
```

**Fixed in:** [`KeyUtils.getKeyPair()`](lib/src/com/isfs/blekey/util/KeyUtils.java:1354)

## Code Quality Fixes

### Logger Format Strings

**Problem:** Incorrect logger parameter format.

**Example:**
```java
// Bug: Second parameter not used as placeholder
logger.error("Error message", e.getMessage());

// Fix: Use placeholder
logger.error("Error message: {}", e.getMessage());
```

**Fixed in:** [`AuthenticatorAPI.java:1082`](lib/src/com/isfs/blekey/authenticator/AuthenticatorAPI.java:1082)

### Resource Leak Prevention

**Problem:** Closing System.in prevents further input.

**Solution:** Don't close Scanner wrapping System.in:
```java
Scanner scanner = new Scanner(System.in);
String input = scanner.nextLine();
// Don't call scanner.close()
```

**Fixed in:** [`Passkey.java:834-848`](lib/src/com/isfs/blekey/data/Passkey.java:834-848)

## Summary

Key principles for successful testing:

1. **Understand dependencies** - Verify actual implementation, don't assume
2. **Preserve context** - Capture full output before filtering
3. **Clean up state** - Reset static fields between tests
4. **Validate assumptions** - Check sizes, types, and nulls
5. **Use strict mocking** - Catch unnecessary stubs early
6. **Test multiple algorithms** - Reveal hardcoded assumptions
7. **Handle resources carefully** - Prevent leaks and locks
8. **Check logic carefully** - Inverted conditions are easy to miss

These patterns and practices resulted in fixing 37 test failures and achieving 100% test success rate.