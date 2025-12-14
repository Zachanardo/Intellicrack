# Production Test Suite for Serial Generator

## Overview

This test suite provides comprehensive production-ready validation of the `SerialNumberGenerator` module's offensive capability against real software licensing protections. All 71 tests validate genuine licensing cracking functionality with NO mocks, stubs, or placeholders.

## Test File

**Location:** `D:\Intellicrack\tests\core\test_serial_generator_production.py`

**Total Tests:** 71 comprehensive tests

## Test Coverage Summary

### 1. Serial Key Algorithm Detection (7 tests)

Tests real algorithm detection from commercial software protection patterns:

- Luhn algorithm detection (credit card-style protections)
- CRC32 algorithm detection (Windows product keys)
- Microsoft product key format detection
- UUID license format detection
- Serial structure analysis with grouped patterns
- Date-based expiration pattern detection
- Hash-based license pattern detection

### 2. Key Format Pattern Recognition (4 tests)

Validates recognition of various commercial license key formats:

- XXXX-XXXX-XXXX-XXXX pattern recognition
- Adobe-style 24-character format
- Base32-encoded license patterns
- Custom alphabet anti-piracy patterns

### 3. Checksum Algorithm Identification (10 tests)

Tests identification of checksum algorithms in real protections:

- Luhn checksum in shareware protection
- CRC16 checksum in embedded licenses
- CRC32 checksum in software activation
- mod97 (IBAN-style) checksum
- Verhoeff algorithm checksum
- Damm algorithm checksum
- Fletcher-16 and Fletcher-32 checksums
- Adler-32 checksum
- mod11 and mod37 checksums

### 4. Key Validation Routine Reverse Engineering (3 tests)

Tests reverse engineering of license validation logic:

- Luhn validation routine reversal
- Custom validation with constraints
- Checksum position and length detection
- Mathematical relationship reversal

### 5. Keygen Generation for Various Algorithms (5 tests)

Tests generation of valid keys for different protection schemes:

- Luhn-protected software keygen
- Polynomial LFSR-based protection keygen
- Feistel network-based protection keygen
- Hash chain-based protection keygen
- Blacklist pattern avoidance

### 6. RSA-Signed License Analysis (3 tests)

Tests RSA-signed license generation and analysis:

- RSA-signed license with feature flags
- RSA signature cryptographic verification
- License data extraction and decoding

### 7. ECC-Signed License Analysis (2 tests)

Tests ECC-signed license generation:

- Hardware-bound ECC license generation
- ECC signature cryptographic verification

### 8. Hardware-Bound Key Generation (2 tests)

Tests hardware-locked license generation:

- ECC licenses locked to hardware IDs
- Machine fingerprint embedding

### 9. Time-Based Key Generation (4 tests)

Tests time-based and expiring licenses:

- Trial license with expiration
- HMAC validation for time-based licenses
- Deterministic generation same-day
- Multiple expiration period handling

### 10. Feature Flag Encoding/Decoding (4 tests)

Tests feature flag encoding in licenses:

- Single feature flag encoding
- Multiple feature flag encoding
- Different feature sets producing different encodings
- Feature flag decoding from serials

### 11. License File Format Analysis (2 tests)

Tests analysis of various license file formats:

- JSON-based license format analysis
- Base32-encoded license format analysis

### 12. Cryptographic Key Extraction (2 tests)

Tests extraction of cryptographic keys from binaries:

- RSA public key parameter extraction
- ECC curve parameter extraction

### 13. Blacklist Detection and Avoidance (3 tests)

Tests detection and avoidance of blacklisted patterns:

- Blacklisted pattern avoidance in generation
- Sequential pattern avoidance
- Commonly blacklisted serial detection

### 14. Integration with Binary Analysis (4 tests)

Tests integration with binary analysis workflows:

- Z3 constraint solver integration
- Batch generation for brute force testing
- Mathematical serial determinism
- Blackbox algorithm for unknown protections

### 15. Property-Based Serial Generation (4 tests using Hypothesis)

Tests algorithmic correctness with property-based testing:

- Luhn serial validity across all lengths
- Blackbox algorithm consistency
- Mathematical Fibonacci determinism
- CRC32 checksum format validation

### 16. Brute Force Checksum Recovery (2 tests)

Tests brute force recovery of missing checksums:

- CRC32 checksum recovery
- Limited search space brute forcing

### 17. Edge Cases and Robustness (5 tests)

Tests edge cases and error handling:

- Empty serial list handling
- Single character serial handling
- Very long serial generation (256 characters)
- Impossible constraint combinations
- Conflicting constraint handling

### 18. Complete End-to-End Workflows (4 tests)

Tests complete licensing cracking workflows:

- Analyze unknown protection and generate keys
- Crack RSA-signed license system
- Generate hardware-locked licenses for multiple machines
- Trial reset with time-based licenses

## Key Features

### Real Offensive Capability Validation

- Every test validates actual cryptographic operations
- Tests work with real algorithm implementations
- No mocked binary data or fake protections
- Tests MUST FAIL if implementation doesn't work

### Complete Type Annotations

- All test functions have full type hints
- All parameters have explicit type checking
- All return types are annotated
- Fixtures are properly typed

### Production Standards

- Follows pytest best practices
- Uses pytest fixtures appropriately
- Property-based testing with Hypothesis
- Clear, descriptive test names
- Comprehensive docstrings

### Real-World Testing

- Tests against actual protection schemes
- Validates cryptographic correctness
- Tests hardware binding mechanisms
- Validates time-based expiration
- Tests blacklist avoidance

## Running the Tests

### Run All Tests

```bash
pixi run pytest tests/core/test_serial_generator_production.py -v
```

### Run Specific Test Class

```bash
pixi run pytest tests/core/test_serial_generator_production.py::TestRSASignedLicenseAnalysis -v
```

### Run with Coverage

```bash
pixi run pytest tests/core/test_serial_generator_production.py --cov=intellicrack.core.serial_generator --cov-report=term-missing
```

### Run Property-Based Tests Only

```bash
pixi run pytest tests/core/test_serial_generator_production.py::TestPropertyBasedSerialGeneration -v
```

## Test Validation Criteria

### Tests MUST FAIL When:

- Serial generation algorithms don't produce valid keys
- Cryptographic signatures are invalid
- Checksum calculations are incorrect
- Algorithm detection fails
- Constraint solver produces invalid serials
- Feature flags aren't properly encoded
- Hardware binding doesn't embed machine codes
- Time-based licenses don't calculate expiration correctly

### Tests MUST PASS When:

- Generated serials pass validation for their algorithm
- RSA/ECC signatures are cryptographically valid
- Checksums are correctly calculated
- Algorithms are properly detected from samples
- Constraints are satisfied in generated serials
- Feature flags are correctly encoded/decoded
- Hardware IDs are properly embedded
- Expiration times are accurately calculated

## Dependencies

- pytest >= 9.0.1
- hypothesis >= 6.148.7
- cryptography (for RSA/ECC operations)
- z3-solver (for constraint solving)
- Standard library: base64, hashlib, hmac, json, struct, time, zlib

## Coverage Goals

- **Minimum Line Coverage:** 85%
- **Minimum Branch Coverage:** 80%
- **All Critical Paths:** 100% coverage of key generation, validation, and cryptographic operations

## Notes

- Tests use real cryptographic operations (no mocks)
- Property-based tests use Hypothesis for algorithmic validation
- Hardware binding tests generate actual machine fingerprints
- Time-based tests validate real TOTP-like algorithms
- All tests are deterministic where possible
- Brute force tests may take longer due to actual computation
