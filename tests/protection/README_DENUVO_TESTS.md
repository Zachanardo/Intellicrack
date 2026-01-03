# Denuvo Protection Testing Documentation

## Overview

This directory contains comprehensive production-ready tests for Denuvo protection analysis capabilities in Intellicrack. Tests validate real offensive security research capabilities for analyzing Denuvo-protected binaries.

## Test Files

### 1. test_denuvo_ticket_analyzer_comprehensive.py

**Purpose**: Tests ticket/token parsing, cryptographic operations, and offline activation bypass.

**Coverage**:
- Ticket parsing and validation (v4, v5, v6, v7)
- Token structure parsing and signature verification
- Activation response generation for offline bypass
- Token forging with perpetual licenses
- Trial-to-full license conversion
- Machine ID extraction and spoofing
- PCAP traffic analysis for activation capture
- AES/GCM encryption/decryption operations
- HMAC signature generation and verification
- Complete offline activation workflows

**Key Features**:
- Uses real cryptographic operations (PyCryptodome)
- Creates valid ticket structures with proper encryption
- Tests signature validation and forgery
- Validates license manipulation capabilities

### 2. test_denuvo_trigger_detection_production.py

**Purpose**: Tests binary analysis and protection mechanism detection on real Denuvo-protected binaries.

**Coverage**:
- Activation trigger detection (Steam, Origin, Epic, Uplay integration points)
- Integrity check routine identification (CRC32/64, MD5, SHA1/256, custom hashing)
- Timing validation detection (RDTSC, QueryPerformanceCounter, GetTickCount, NTP sync)
- Ticket flow tracing (generation and validation workflows)
- Machine fingerprinting detection (CPU ID, GPU ID, disk serial, MAC address, motherboard ID)
- Anti-tamper mechanism detection (code signing, section hashing)
- Denuvo version differentiation (v4.x, v5.x, v6.x, v7.x)
- Online vs offline activation mode detection
- Steam API wrapper analysis
- Protection density assessment
- Obfuscation level evaluation

**Key Features**:
- Scans `tests/test_binaries/` directory for Denuvo-protected samples
- Works on ANY protected binary placed in test directory
- Validates real detection capabilities on actual game executables
- Tests FAIL if detection algorithms don't work properly
- No mocks or stubs - only real binary analysis
- Comprehensive edge case coverage

## Test Organization

### Test Classes in test_denuvo_trigger_detection_production.py

1. **TestActivationTriggerDetection** - DRM platform integration point detection
2. **TestIntegrityCheckDetection** - Code/data integrity validation routines
3. **TestTimingValidationDetection** - Anti-debugging timing checks
4. **TestTicketFlowTracing** - Complete activation flow analysis
5. **TestMachineFingerprintingDetection** - Hardware ID collection
6. **TestAntiTamperDetection** - Code signing and section hashing
7. **TestDenuvoVersionDetection** - Version-specific signatures (v4/v5/v6)
8. **TestOnlineVsOfflineActivation** - Activation mode identification
9. **TestSteamAPIWrapperDetection** - Wrapped Steam API analysis
10. **TestEdgeCases** - Error handling and boundary conditions
11. **TestPerformance** - Analysis speed benchmarks

## Usage

### Running All Denuvo Tests

```bash
pixi run pytest tests/protection/test_denuvo_*.py -v
```

### Running Only Binary Analysis Tests

```bash
pixi run pytest tests/protection/test_denuvo_trigger_detection_production.py -v
```

### Running Only Ticket/Token Tests

```bash
pixi run pytest tests/protection/test_denuvo_ticket_analyzer_comprehensive.py -v
```

### Running Specific Test Categories

```bash
# Activation trigger detection only
pixi run pytest tests/protection/test_denuvo_trigger_detection_production.py::TestActivationTriggerDetection -v

# Integrity check detection only
pixi run pytest tests/protection/test_denuvo_trigger_detection_production.py::TestIntegrityCheckDetection -v

# Machine fingerprinting detection only
pixi run pytest tests/protection/test_denuvo_trigger_detection_production.py::TestMachineFingerprintingDetection -v
```

### Running with Coverage

```bash
pixi run pytest tests/protection/test_denuvo_*.py --cov=intellicrack.protection.denuvo_ticket_analyzer --cov-report=term-missing
```

## Adding Test Binaries

To enable comprehensive testing:

1. Place Denuvo-protected game executables in `tests/test_binaries/`
2. Supported formats: `.exe`, `.dll`, `.bin`
3. Tests automatically discover and analyze all binaries
4. No configuration needed - tests adapt to available samples

### Recommended Test Samples

For maximum coverage, include binaries with:
- **Different Denuvo versions**: v4, v5, v6, v7
- **Different DRM platforms**: Steam, Origin, Epic Games, Uplay
- **Different activation modes**: Online-only, offline-capable
- **Steam API wrappers**: `steam_api.dll`, `steam_api64.dll`
- **Various protection densities**: Light, moderate, heavy

## Test Validation Criteria

### Tests PASS When:
- Detection algorithms successfully identify protection mechanisms
- All required fields are populated with valid data
- Confidence scores fall within expected ranges (0.0 - 1.0)
- Version detection correctly identifies Denuvo variant
- Cryptographic operations produce verifiable results
- License manipulation creates functionally valid tickets/tokens

### Tests FAIL When:
- Detection returns empty results on known protected binaries
- Required fields contain invalid/nonsensical data
- Confidence scores exceed valid ranges
- Version detection misidentifies protection variant
- Cryptographic operations fail or produce garbage
- License manipulation creates non-functional outputs

## Dependencies

### Required
- `pytest` - Test framework
- `lief` - Binary parsing (for trigger detection tests)
- `pycryptodome` - Cryptography (for ticket/token tests)

### Optional
- `capstone` - Disassembly engine (enhanced detection accuracy)
- `dpkt` - PCAP parsing (for traffic analysis tests)
- `pytest-benchmark` - Performance testing
- `pytest-cov` - Coverage reporting

## Expected Behavior

### Detection Accuracy

**Activation Triggers**:
- Detects Steam initialization calls
- Identifies Origin/EA authentication hooks
- Finds Epic Games Store integration points
- Locates license validation routines

**Integrity Checks**:
- Identifies CRC32/CRC64 validation loops
- Detects SHA256 section hashing
- Finds custom hash algorithm implementations
- Determines check frequency (startup, periodic, continuous)

**Timing Validation**:
- Detects RDTSC anti-debugging sequences
- Identifies QueryPerformanceCounter usage
- Finds system clock manipulation checks
- Locates NTP synchronization requirements

**Machine Fingerprinting**:
- Detects CPUID instruction sequences
- Identifies GPU enumeration calls
- Finds disk serial number queries
- Locates MAC address collection
- Detects composite hardware ID generation

**Anti-Tamper**:
- Identifies authenticode signature validation
- Detects PE section hash verification
- Finds code modification detection routines
- Assesses bypass difficulty levels

### Version-Specific Behavior

**Denuvo v4.x**:
- Header size: 64 bytes
- Magic: `DNV4`
- Encryption: AES-128-CBC

**Denuvo v5.x**:
- Header size: 80 bytes
- Magic: `DNV5`
- Encryption: AES-256-CBC
- Enhanced integrity checks

**Denuvo v6.x**:
- Header size: 96 bytes
- Magic: `DNV6`
- Encryption: AES-256-GCM
- Hardware fingerprinting

**Denuvo v7.x**:
- Header size: 128 bytes
- Magic: `DNV7`
- Encryption: AES-256-GCM + ChaCha20
- Advanced obfuscation

## Performance Benchmarks

Expected analysis times for various binary sizes:

- **Small (< 10 MB)**: < 5 seconds
- **Medium (10-50 MB)**: < 15 seconds
- **Large (50-100 MB)**: < 30 seconds
- **Very Large (> 100 MB)**: < 60 seconds

Tests enforce these timeouts to ensure acceptable performance.

## Troubleshooting

### No Binaries Found

If tests skip due to missing binaries:
1. Verify `tests/test_binaries/` directory exists
2. Add Denuvo-protected samples (see "Adding Test Binaries")
3. Ensure files have `.exe`, `.dll`, or `.bin` extensions
4. Check file permissions (readable by test process)

### LIEF Import Errors

If tests fail with "LIEF required":
```bash
pixi install lief
```

### Crypto Import Errors

If tests fail with "Crypto library required":
```bash
pixi install pycryptodome
```

### All Tests Skipping

Check pytest output for skip reasons:
```bash
pixi run pytest tests/protection/test_denuvo_trigger_detection_production.py -v -rs
```

## Contributing

When adding new detection capabilities:

1. Add corresponding test methods to appropriate test class
2. Ensure tests validate REAL functionality, not just execution
3. Include edge cases and error handling
4. Add performance benchmarks for expensive operations
5. Update this README with new coverage details

## Security Research Context

These tests validate Intellicrack's capabilities as a **defensive security research tool** for software developers to:

- **Test their own licensing protection robustness**
- **Identify weaknesses before attackers do**
- **Validate protection effectiveness**
- **Improve anti-tamper mechanisms**

All testing must occur in **controlled, authorized environments** on **proprietary software** you have **legal rights** to analyze.
