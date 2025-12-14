# Production-Grade Tests for Protection Bypass Modules

## Overview

This directory contains comprehensive, production-ready tests for Intellicrack's protection bypass capabilities. These tests validate **REAL offensive functionality** against actual protected binaries with NO MOCKS.

## Test Files

### test_dongle_emulator_production.py

**Total Tests:** 44

**Purpose:** Validates hardware dongle emulation capabilities against real HASP/Sentinel/WibuKey protected binaries.

**Test Categories:**

1. **DongleMemoryProduction** (4 tests)
    - Real memory read/write operations
    - Protection enforcement validation
    - Bounds checking
    - Protected area detection

2. **CryptoEngineProduction** (6 tests)
    - AES/DES/DES3 encryption/decryption roundtrips
    - Sentinel challenge-response validation
    - WibuKey challenge-response algorithm
    - RSA signature generation

3. **USBEmulatorProduction** (4 tests)
    - USB descriptor serialization
    - Control transfer handling
    - Configuration descriptor generation
    - String descriptor retrieval

4. **HASPDongleProduction** (3 tests)
    - Dongle initialization
    - Feature map structure
    - RSA key generation

5. **HardwareDongleEmulatorProduction** (9 tests)
    - Virtual dongle creation
    - Memory configuration
    - USB emulation setup
    - Challenge processing
    - Memory read/write operations
    - Emulation status reporting
    - Frida script generation
    - Binary patching identification

6. **HASPProtocolImplementation** (6 tests)
    - Login/logout operations
    - Encrypt/decrypt commands
    - Memory read/write operations

7. **SentinelProtocolImplementation** (4 tests)
    - Query operations
    - Read/write operations
    - Encryption operations

8. **WibuKeyProtocolImplementation** (4 tests)
    - Open operations
    - Access validation
    - Encryption
    - Challenge-response

9. **RealBinaryCompatibility** (3 tests)
    - HASP protected binary structure validation
    - Emulator handles real binary paths
    - Patch location identification

10. **EmulatorClearAndReset** (1 test)
    - State cleanup validation

**Key Features:**

- Uses real PE binaries from `tests/fixtures/binaries/`
- Validates actual protocol implementations
- Tests cryptographic operations with real algorithms
- Verifies USB protocol compliance
- Tests against HASP/Sentinel/CodeMeter protected applications

### test_integrity_check_defeat_production.py

**Total Tests:** 43

**Purpose:** Validates integrity check detection, bypass, and defeat capabilities against real protected binaries.

**Test Categories:**

1. **ChecksumRecalculatorProduction** (12 tests)
    - CRC32/CRC64 calculation accuracy
    - MD5/SHA1/SHA256/SHA512 hash validation
    - HMAC signature calculation
    - PE checksum recalculation
    - Section hash calculation
    - HMAC key extraction
    - Checksum location identification
    - Patched binary recalculation

2. **IntegrityCheckDetectorProduction** (5 tests)
    - Real binary check detection
    - API import scanning
    - Inline check pattern detection
    - Anti-tamper detection
    - Entropy calculation

3. **IntegrityBypassEngineProduction** (4 tests)
    - Bypass strategy loading
    - Script generation
    - Script customization
    - Strategy selection

4. **BinaryPatcherProduction** (4 tests)
    - Binary patching and output generation
    - Patch history tracking
    - PE checksum recalculation after patching
    - RVA to offset conversion

5. **IntegrityCheckDefeatSystemProduction** (8 tests)
    - System initialization
    - Embedded checksum finding
    - HMAC key extraction
    - Bypass script generation
    - Checksum recalculation
    - Detection-only workflow
    - Patching workflow
    - Embedded checksum patching

6. **ChecksumAlgorithmAccuracy** (3 tests)
    - Empty data handling
    - Known value validation
    - Algorithm stability

7. **RealBinaryIntegration** (2 tests)
    - Complete workflow on protected binaries
    - Functionality preservation

8. **EdgeCases** (5 tests)
    - Invalid path handling
    - Corrupted PE handling
    - Empty binary handling
    - Large binary performance

**Key Features:**

- Uses real protected binaries (Denuvo, HASP, Sentinel, etc.)
- Validates checksum algorithms against known values
- Tests real PE binary structure manipulation
- Verifies Frida script generation
- Tests embedded checksum identification and patching

## Running the Tests

### Run all production tests:

```bash
pixi run pytest tests/core/protection_bypass/test_dongle_emulator_production.py tests/core/protection_bypass/test_integrity_check_defeat_production.py -v
```

### Run specific test suite:

```bash
# Dongle emulator tests
pixi run pytest tests/core/protection_bypass/test_dongle_emulator_production.py -v

# Integrity check defeat tests
pixi run pytest tests/core/protection_bypass/test_integrity_check_defeat_production.py -v
```

### Run specific test class:

```bash
pixi run pytest tests/core/protection_bypass/test_dongle_emulator_production.py::TestHASPProtocolImplementation -v
```

### Run with coverage:

```bash
pixi run pytest tests/core/protection_bypass/ --cov=intellicrack.core.protection_bypass --cov-report=html
```

## Test Data Requirements

Tests use real binaries from:

- `tests/fixtures/binaries/pe/protected/` - Protected executables
- `tests/fixtures/binaries/pe/legitimate/` - Legitimate PE files for structural testing
- `tests/integration/real_binary_tests/binaries/hasp/` - HASP/Sentinel protected samples

Required binaries:

- `hasp_sentinel_protected.exe`
- `dongle_protected_app.exe`
- `7zip.exe`
- `notepadpp.exe`

## Success Criteria

Tests prove offensive capabilities work when:

1. **Dongle Emulator:**
    - Virtual dongles respond to authentication challenges
    - Cryptographic operations produce correct results
    - USB protocol emulation matches specification
    - Memory operations respect protection boundaries
    - Protocol implementations match HASP/Sentinel/WibuKey specs

2. **Integrity Check Defeat:**
    - Checksums match reference implementations
    - Integrity checks detected in real binaries
    - Frida scripts generate valid JavaScript
    - Binary patching produces working executables
    - Embedded checksums correctly identified and updated

## Design Principles

1. **NO MOCKS** - All tests use real data and validate actual functionality
2. **Real Binaries** - Tests operate on actual protected applications
3. **Algorithm Validation** - Cryptographic operations verified against standards
4. **Protocol Compliance** - USB and dongle protocols match specifications
5. **Production Ready** - Every test validates deployment-ready code

## Coverage Goals

- Line coverage: 85%+
- Branch coverage: 80%+
- All critical paths tested
- Edge cases validated
- Error handling verified

## Continuous Integration

These tests are designed for CI/CD pipelines:

- Fast execution (< 5 minutes total)
- No external dependencies required
- Deterministic results
- Clear failure messages
- Parallel execution supported

## Contributing

When adding new tests:

1. Follow production-grade principles (see CLAUDE.md)
2. Use real binaries and real data
3. Include complete type hints
4. Write descriptive test names
5. Add docstrings explaining validation purpose
6. Ensure tests fail when code is broken
7. Verify tests pass with working code

## License

Copyright (C) 2025 Zachary Flint
SPDX-License-Identifier: GPL-3.0-or-later
