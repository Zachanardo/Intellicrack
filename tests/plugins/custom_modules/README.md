# License Server Emulator Tests

## Overview

This directory contains comprehensive production-grade tests for the License Server Emulator (`intellicrack/plugins/custom_modules/license_server_emulator.py`).

## Test File

**`test_license_server_emulator.py`** - 1000+ lines of production-ready tests validating:

### Core Functionality Tested

1. **CryptoManager Tests**
   - RSA key generation and signing (2048-bit keys)
   - AES encryption/decryption with CBC mode
   - License key generation with cryptographic uniqueness
   - Signature verification and tamper detection

2. **FlexLM Emulator Tests**
   - TCP server startup on configurable ports
   - Feature checkout request handling
   - Vendor daemon communication
   - Custom RC4-variant encryption for vendor protocol
   - License granting and denial logic

3. **HASP Dongle Emulator Tests**
   - Dongle memory initialization with proper structure
   - Feature login/logout with session management
   - AES-GCM encryption/decryption operations
   - Memory read/write with access control
   - Hardware fingerprint binding via HKDF
   - Device information queries

4. **Microsoft KMS Emulator Tests**
   - Windows product activation
   - Office product activation
   - Activation ID generation
   - Grace period and expiry date management

5. **Adobe Emulator Tests**
   - Creative Cloud license validation
   - Device token generation and verification
   - Subscription license handling

6. **Database Manager Tests**
   - SQLAlchemy table creation
   - License entry creation and validation
   - Expiry date checking
   - Operation logging
   - Activation tracking with hardware fingerprints

7. **Hardware Fingerprint Tests**
   - Consistent hash generation from hardware components
   - Real system data collection (CPU, disk, RAM, MAC)
   - Hardware change detection

8. **Protocol Analyzer Tests**
   - FlexLM protocol detection
   - HASP protocol detection
   - KMS protocol detection
   - Confidence scoring

9. **License Server REST API Tests**
   - FastAPI endpoint testing
   - License validation endpoint
   - License activation endpoint
   - Status endpoint
   - Protocol-specific endpoints (FlexLM, HASP, KMS, Adobe)
   - Hardware fingerprint generation endpoint
   - Traffic analysis endpoint
   - Proxy interception endpoint

10. **Edge Cases**
    - Concurrent license validation requests
    - License expiry edge cases
    - HASP memory boundary conditions
    - Malformed protocol requests
    - Hardware fingerprint changes
    - Empty data handling

11. **Performance Tests**
    - License key generation throughput (1000 keys < 2s)
    - HASP encryption performance (100 operations < 5s)
    - Database query performance (100 queries < 1s)

## Dependencies Required

The tests require the following dependencies which are listed in `pyproject.toml` but may not be in the pixi environment:

```
- defusedxml>=0.7.1
- fastapi>=0.120.4
- uvicorn>=0.38.0
- pydantic>=2.0.0
- sqlalchemy>=2.0.0
- psutil>=5.9.0
- cryptography>=41.0.0
- pyjwt>=2.8.0
```

## Current Environment Issue

**Status:** Tests are written and ready but cannot run due to pytest environment conflict.

**Issue:** The pytest module in the pixi environment is shadowed by `faker.contrib.pytest`, causing `pytest.mark` and other attributes to be unavailable.

**Evidence:**
```bash
$ .pixi\envs\default\python.exe -c "import pytest; print(hasattr(pytest, 'mark'))"
False

$ .pixi\envs\default\python.exe -c "import pytest; print(pytest.__file__)"
None  # Should be a real file path
```

## How to Run Tests (Once Environment is Fixed)

### Run all license server tests:
```bash
pixi run pytest tests/plugins/custom_modules/test_license_server_emulator.py -v
```

### Run specific test class:
```bash
pixi run pytest tests/plugins/custom_modules/test_license_server_emulator.py::TestCryptoManager -v
```

### Run with coverage:
```bash
pixi run pytest tests/plugins/custom_modules/test_license_server_emulator.py --cov=intellicrack.plugins.custom_modules.license_server_emulator --cov-report=term-missing
```

## Test Design Principles

All tests follow the CRITICAL TESTING PRINCIPLES defined in the test-writer agent:

1. **Production Validation Only** - Tests verify code works on real operations with actual cryptography
2. **Zero Tolerance for Fake Tests** - No mocks, no stubs, every assertion validates real functionality
3. **Professional Python Standards** - Complete type annotations, PEP 8 compliance, descriptive names
4. **Real-World Complexity** - Edge cases, error handling, concurrent operations

## What Makes These Tests Production-Grade

1. **Real Cryptographic Operations**
   - Actual RSA 2048-bit key generation
   - Real AES-256 encryption with random IVs
   - Genuine AES-GCM with authentication tags
   - HKDF session key derivation
   - Proper signature verification

2. **Real Network Operations**
   - Actual TCP socket servers
   - Real client connections
   - Protocol request/response handling
   - Concurrent connection handling

3. **Real Database Operations**
   - SQLAlchemy ORM with SQLite
   - Actual table creation and migration
   - Real queries and transactions
   - Relationship handling

4. **Real System Integration**
   - Hardware data collection (CPU, disk, network)
   - OS-specific operations
   - Multi-threading tests
   - Performance benchmarks

5. **Comprehensive Coverage**
   - 11 test classes covering all major components
   - 80+ individual test methods
   - Edge cases and error conditions
   - Performance validation

## Test Validation Strategy

Each test is designed to FAIL when:
- Cryptographic operations are broken
- Network servers don't start
- Database operations fail
- Protocol handlers malfunction
- API endpoints return wrong data
- Performance degrades below acceptable levels

Tests PASS only when:
- Real cryptographic signatures verify
- Network connections succeed
- Database queries return expected data
- License validation works correctly
- All endpoints respond properly
- Performance meets benchmarks

## Coverage Goals

- **Line Coverage:** 85%+ of license_server_emulator.py
- **Branch Coverage:** 80%+ of conditional logic
- **Function Coverage:** 100% of public APIs
- **Integration Coverage:** All protocol emulators tested end-to-end

## Future Enhancements

1. Add tests for binary key extraction (BinaryKeyExtractor, RuntimeKeyExtractor, FridaKeyExtractor)
2. Add tests for ProtocolStateMachine
3. Add tests for ProxyInterceptor advanced features
4. Add property-based tests with Hypothesis for cryptographic algorithms
5. Add benchmark tests for large-scale concurrent operations
6. Add integration tests with real commercial software protections
