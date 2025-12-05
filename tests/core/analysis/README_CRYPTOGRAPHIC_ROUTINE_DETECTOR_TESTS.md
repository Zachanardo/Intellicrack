# Cryptographic Routine Detector Production Tests

## Overview

Comprehensive production-ready tests for `CryptographicRoutineDetector` that validate REAL cryptographic detection capabilities on actual binary data with embedded crypto constants, algorithms, and patterns.

**File:** `test_cryptographic_routine_detector_production.py`

**Total Tests:** 53

## Test Philosophy

### NO MOCKS, STUBS, OR SIMULATED DATA

All tests use REAL PE binaries with actual cryptographic constants embedded:
- Real AES S-boxes (forward and inverse)
- Real SHA-256/SHA-1/MD5 constants
- Real RSA public exponents
- Real ECC curve parameters
- Real hardware instruction opcodes
- Real crypto implementation patterns

### Test-Driven Development Approach

Tests are designed to FAIL if Intellicrack doesn't work effectively:
- Tests verify genuine offensive capability
- Detection confidence scores are validated
- Algorithm fingerprinting accuracy is checked
- No false positives tolerated

## Test Coverage Categories

### 1. Symmetric Cryptography Detection (18 tests)

**AES Detection:**
- `test_detect_aes_forward_sbox_in_real_binary` - Detects AES forward S-box with 99%+ confidence
- `test_detect_aes_inverse_sbox_in_real_binary` - Detects AES inverse S-box
- `test_detect_aes_round_constants` - Identifies AES RCON round constants
- `test_detect_aes_ni_aesenc_instruction` - Detects AES-NI hardware instructions
- `test_detect_aes_ni_multiple_instructions` - Finds multiple AES-NI opcodes
- `test_detect_obfuscated_aes_sbox_fuzzy_matching` - Fuzzy matching for obfuscated S-boxes

**Stream Ciphers:**
- `test_detect_rc4_state_array_initialization` - RC4 state array pattern
- `test_detect_rc4_ksa_pattern_nearby` - RC4 Key Scheduling Algorithm detection
- `test_detect_chacha20_constant_string` - ChaCha20 "expand 32-byte k" constant
- `test_detect_chacha20_quarter_round_function` - ChaCha20 quarter round operations

**Block Ciphers:**
- `test_detect_blowfish_pi_subkeys` - Blowfish Pi-based subkeys
- `test_detect_des_sboxes_all_eight` - DES S-box detection

### 2. Hash Algorithm Detection (6 tests)

- `test_detect_sha256_round_constants_big_endian` - SHA-256 K constants
- `test_detect_sha1_initialization_vectors` - SHA-1 H values
- `test_detect_md5_sine_table_constants` - MD5 T table
- `test_detect_sha_hardware_instructions` - SHA-NI detection
- `test_algorithm_fingerprinting_enhances_hash_detection` - Implementation mode detection

### 3. Public Key Cryptography (7 tests)

**RSA:**
- `test_detect_rsa_public_exponent_65537` - Most common RSA exponent
- `test_detect_rsa_with_modular_operations_nearby` - Modular arithmetic validation

**ECC:**
- `test_detect_ecc_secp256k1_field_prime` - Bitcoin curve (secp256k1)
- `test_detect_ecc_secp256r1_field_prime` - NIST P-256 curve

### 4. Custom Crypto Detection (5 tests)

- `test_detect_feistel_network_structure` - Feistel cipher patterns
- `test_detect_custom_high_entropy_crypto_table` - Entropy analysis
- `test_fuzzy_matching_handles_partial_pattern_matches` - Fuzzy matching threshold
- `test_entropy_calculation_identifies_high_entropy_data` - Shannon entropy
- `test_lookup_table_detection_identifies_crypto_tables` - Substitution table detection

### 5. Multi-Algorithm Detection (4 tests)

- `test_detect_multiple_algorithms_in_single_binary` - Detects 4+ algorithms
- `test_detector_finds_multiple_occurrences_of_same_constant` - Duplicate detection
- `test_protection_likelihood_increases_with_algorithm_diversity` - Risk scoring

### 6. Usage Analysis & Reporting (6 tests)

- `test_analyze_crypto_usage_provides_comprehensive_analysis` - Usage patterns
- `test_analyze_crypto_usage_identifies_hardware_acceleration` - HW vs SW detection
- `test_analyze_crypto_usage_identifies_obfuscation` - Obfuscation detection
- `test_export_yara_rules_generates_valid_rules` - YARA rule generation
- `test_export_yara_rules_includes_aes_patterns` - AES YARA patterns
- `test_export_yara_rules_includes_chacha20_patterns` - ChaCha20 YARA patterns

### 7. Performance & Edge Cases (7 tests)

- `test_quick_mode_skips_expensive_analysis` - Quick scan mode
- `test_crypto_constant_caching_improves_performance` - Caching efficiency
- `test_detector_handles_corrupted_binary_gracefully` - Error resilience
- `test_detector_handles_very_large_binary_efficiently` - Large file handling
- `test_empty_binary_returns_no_detections` - Empty binary
- `test_binary_without_crypto_returns_no_detections` - No false positives
- `test_detector_works_with_real_system_binary` - Real-world validation

## RealCryptoBinaryBuilder

Custom binary builder that creates real PE executables with embedded crypto:

```python
RealCryptoBinaryBuilder.create_aes_sbox_binary()
RealCryptoBinaryBuilder.create_sha256_binary()
RealCryptoBinaryBuilder.create_rsa_binary()
RealCryptoBinaryBuilder.create_ecc_binary()
RealCryptoBinaryBuilder.create_multi_crypto_binary()
```

Each builder method:
1. Creates valid PE header
2. Embeds real cryptographic constants
3. Adds surrounding code patterns
4. Returns bytes ready for detection

## Key Validation Points

### Detection Confidence
- Exact matches: >= 99% confidence
- Fuzzy matches: >= 85% confidence
- Obfuscated: >= 85% confidence with obfuscation flag

### Algorithm Coverage
- AES (S-boxes, RCON, AES-NI)
- DES/3DES (S-boxes)
- RSA (public exponents, Montgomery multiplication)
- ECC (secp256k1, secp256r1, secp384r1)
- RC4 (state array, KSA, PRGA)
- Blowfish (Pi subkeys, S-boxes)
- Twofish (Q tables)
- ChaCha20 (constant, quarter round)
- SHA-1 (H values, SHA-NI)
- SHA-256 (K constants, SHA-NI)
- MD5 (T table)

### Data Structure Validation
- CryptoDetection dataclass fields populated correctly
- CryptoConstant dataclass fields validated
- DataFlowNode structures for analysis

## Running Tests

```bash
Run all tests:
pixi run pytest tests/core/analysis/test_cryptographic_routine_detector_production.py -v

Run specific category:
pixi run pytest tests/core/analysis/test_cryptographic_routine_detector_production.py -k "aes" -v

Run with coverage:
pixi run pytest tests/core/analysis/test_cryptographic_routine_detector_production.py --cov=intellicrack.core.analysis.cryptographic_routine_detector --cov-report=html

Quick validation:
pixi run pytest tests/core/analysis/test_cryptographic_routine_detector_production.py -x --tb=short
```

## Success Criteria

Tests pass when:
1. All crypto constants detected with correct confidence scores
2. Algorithm fingerprinting identifies implementation details
3. Hardware acceleration properly detected
4. Obfuscated crypto identified through fuzzy matching
5. YARA rules exported successfully
6. Usage analysis provides accurate protection likelihood
7. No false positives on non-crypto binaries
8. Performance acceptable on large binaries
9. Real system binaries analyzed without errors

## Production Readiness

These tests validate that CryptographicRoutineDetector is ready for:
- Analyzing real-world protected software
- Identifying licensing crypto implementations
- Detecting anti-piracy mechanisms
- Security research and reverse engineering
- Automated malware analysis pipelines
- Threat intelligence gathering
