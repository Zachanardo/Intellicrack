# Cryptographic Routine Detector Test Coverage

## Overview

Comprehensive production-ready test suite for `intellicrack/core/analysis/cryptographic_routine_detector.py` validating REAL offensive capability against software licensing protections.

**Test Files:**
- `test_cryptographic_routine_detector_production.py` - Basic crypto detection (existing)
- `test_cryptographic_routine_detector_advanced.py` - Advanced crypto detection (NEW)

## Test Philosophy

**CRITICAL:** All tests validate REAL functionality:
- NO mocks, stubs, or placeholders
- Tests MUST FAIL if detection doesn't work
- Real binary patterns with embedded crypto
- Validates actual offensive capability

## Advanced Test Coverage (NEW)

### 1. Key Derivation Function (KDF) Detection

**Test:** `test_detect_pbkdf2_key_derivation_function`
- **Validates:** PBKDF2 detection through SHA1 + HMAC + iteration patterns
- **Binary Pattern:** SHA1 IV constants + HMAC IPAD/OPAD + iteration loop
- **Offensive Value:** Identifies password-based key derivation for license key generation
- **Must Detect:** SHA1 constants (0x67452301...), HMAC pads (0x36/0x5C), loop counters

**Test:** `test_detect_hkdf_key_derivation_function`
- **Validates:** HKDF detection through SHA256 + HMAC patterns
- **Binary Pattern:** SHA256 round constants + HMAC structure + OKM label
- **Offensive Value:** Identifies modern key derivation for secure license generation
- **Must Detect:** SHA256 K constants, HMAC pads, counter increments

**Test:** `test_detect_bcrypt_password_hashing_kdf`
- **Validates:** bcrypt detection through Blowfish + cost factor
- **Binary Pattern:** Blowfish Pi subkeys + cost parameter + salt marker
- **Offensive Value:** Identifies expensive password hashing used in license protection
- **Must Detect:** Blowfish constants, bcrypt salt format ($2a$12$)

**Test:** `test_detect_scrypt_memory_hard_kdf`
- **Validates:** scrypt detection through SHA256 + parameters + Salsa20
- **Binary Pattern:** SHA256 + N/r/p parameters + Salsa20 core + memory-hard loop
- **Offensive Value:** Identifies memory-hard KDF preventing brute-force attacks
- **Must Detect:** N parameter (0x4000), r/p parameters, Salsa20 quarter-round

### 2. MAC (Message Authentication Code) Detection

**Test:** `test_detect_hmac_mac_operation_differentiated_from_hash`
- **Validates:** HMAC differentiation from plain hash
- **Binary Pattern:** Hash algorithm + IPAD (0x36*64) + OPAD (0x5C*64)
- **Offensive Value:** Identifies license signature verification routines
- **Must Detect:** HMAC pads, key XOR patterns, nested hash structure

**Test:** `test_detect_aes_gcm_authenticated_encryption_with_galois_field`
- **Validates:** AES-GCM detection with Galois field multiplication
- **Binary Pattern:** AES S-box + GCM reduction polynomial (0xC2) + H table
- **Offensive Value:** Identifies authenticated encryption in license protocols
- **Must Detect:** AES constants, GCM poly, PCLMULQDQ instructions

**Test:** `test_detect_poly1305_mac_authentication`
- **Validates:** Poly1305 MAC detection
- **Binary Pattern:** Prime constant (2^130-5) + clamp mask + modular multiplication
- **Offensive Value:** Identifies modern MAC used with ChaCha20 in license systems
- **Must Detect:** Poly1305 prime, clamp mask (0x0FFC...), mul-mod patterns

**Test:** `test_detect_siphash_prf_function`
- **Validates:** SipHash PRF detection
- **Binary Pattern:** Initialization vectors + SipRound function
- **Offensive Value:** Identifies fast MAC for license token generation
- **Must Detect:** SipHash IVs (0x736f6d65...), round rotation patterns

### 3. Differentiation Between Crypto Types

**Test:** `test_differentiate_hash_from_cipher_operations`
- **Validates:** Differentiates hash algorithms from ciphers
- **Binary Pattern:** Both SHA256 (hash) and AES (cipher) in same binary
- **Offensive Value:** Critical for understanding license validation flow
- **Must Detect:** Hash constants (one-way) vs cipher S-boxes (reversible)

**Test:** `test_detector_identifies_stream_cipher_vs_block_cipher`
- **Validates:** Differentiates stream ciphers from block ciphers
- **Binary Pattern:** ChaCha20 (stream) vs AES (block)
- **Offensive Value:** Different attack strategies for different cipher types
- **Must Detect:** Stream cipher state updates vs block cipher rounds

**Test:** `test_detector_identifies_key_expansion_routines`
- **Validates:** AES key expansion detection
- **Binary Pattern:** RCON usage + S-box lookups + key schedule
- **Offensive Value:** Identifies where license keys are derived from master keys
- **Must Detect:** AES RCON constants, scheduled key generation

### 4. Random Number Generator (RNG) Detection

**Test:** `test_detect_mersenne_twister_prng_constants`
- **Validates:** Mersenne Twister PRNG detection
- **Binary Pattern:** MT19937 constants (624, 397, 0x9908B0DF) + twist operations
- **Offensive Value:** Identifies predictable RNG for license key generation
- **Must Detect:** MT parameters, twist code, tempering operations

**Test:** `test_detect_chacha_based_csprng_implementation`
- **Validates:** ChaCha20-based CSPRNG detection
- **Binary Pattern:** ChaCha20 constant + quarter-round + nonce + counter
- **Offensive Value:** Identifies secure RNG in modern license systems
- **Must Detect:** "expand 32-byte k", quarter-round, counter increments

### 5. Edge Cases: Inline Crypto

**Test:** `test_detect_inline_aes_with_expanded_rounds`
- **Validates:** Inline AES without library calls
- **Binary Pattern:** S-box + manually expanded 10 rounds + inline operations
- **Offensive Value:** Detects custom AES implementations avoiding crypto libraries
- **Must Detect:** Round structure, S-box lookups in instruction stream

**Test:** `test_instruction_pattern_analysis_detects_xor_chains`
- **Validates:** Instruction pattern analysis for XOR ciphers
- **Binary Pattern:** Long chains of XOR operations
- **Offensive Value:** Detects custom XOR-based obfuscation in license checks
- **Must Detect:** 8+ consecutive XOR operations with different registers

**Test:** `test_instruction_pattern_analysis_detects_feistel_swaps`
- **Validates:** Feistel network detection through swap patterns
- **Binary Pattern:** XCHG instructions + XOR operations in rounds
- **Offensive Value:** Identifies custom Feistel-based license algorithms
- **Must Detect:** 4+ swap operations, 8+ XOR operations

### 6. Edge Cases: SIMD Implementations

**Test:** `test_detect_simd_vectorized_aes_implementation`
- **Validates:** SIMD-vectorized AES detection
- **Binary Pattern:** AES S-box + PSHUFB/PXOR/PADDD SIMD instructions
- **Offensive Value:** Detects optimized crypto in high-performance license systems
- **Must Detect:** SIMD instructions (0x660f38, 0x660fef), vectorized patterns

**Test:** `test_detector_identifies_hardware_vs_software_implementation`
- **Validates:** Hardware vs software crypto differentiation
- **Binary Pattern:** AES-NI instructions vs S-box table lookups
- **Offensive Value:** Different attack strategies for hardware-accelerated crypto
- **Must Detect:** AES-NI opcodes vs memory-based S-box access

### 7. Edge Cases: White-Box Crypto

**Test:** `test_detect_whitebox_aes_large_lookup_tables`
- **Validates:** White-box AES detection through large tables
- **Binary Pattern:** 10+ large (4KB) high-entropy lookup tables + XOR network
- **Offensive Value:** Identifies obfuscated AES hiding key in implementation
- **Must Detect:** Multiple 4KB+ tables, high entropy (>7.0), table references

**Test:** `test_entropy_analysis_identifies_custom_high_entropy_tables`
- **Validates:** Entropy analysis for custom crypto tables
- **Binary Pattern:** 256-byte table with entropy > 7.5 + access patterns
- **Offensive Value:** Detects custom substitution tables in license validation
- **Must Detect:** High entropy, lookup table structure, multiple references

**Test:** `test_detector_handles_obfuscated_constants_with_xor_encoding`
- **Validates:** Obfuscated constant detection
- **Binary Pattern:** XOR-encoded AES S-box (S[i] ^ 0xAA)
- **Offensive Value:** Defeats simple constant obfuscation
- **Must Detect:** Handles gracefully, doesn't crash on modified constants

### 8. Data Flow Analysis

**Test:** `test_data_flow_analysis_tracks_register_usage`
- **Validates:** Register usage tracking in crypto routines
- **Binary Pattern:** Inline AES with tracked register operations
- **Offensive Value:** Identifies data flow for key extraction
- **Must Detect:** DataFlowNode objects with register reads/writes

**Test:** `test_data_flow_analysis_identifies_constants`
- **Validates:** Immediate constant identification
- **Binary Pattern:** AES-GCM with embedded constants
- **Offensive Value:** Extracts hardcoded keys and IVs
- **Must Detect:** CryptoConstant objects with immediate values

### 9. Real-World Binary Testing

**Test:** `test_detector_analyzes_real_openssl_binary_successfully`
- **Validates:** Real-world binary analysis
- **Binary Pattern:** Actual 7zip.exe or libcrypto.so.3
- **Offensive Value:** Proves detector works on real software
- **Must Detect:** Any crypto patterns in real binary without crashing

**Test:** `test_detector_works_with_real_system_binary`
- **Validates:** System crypto library analysis
- **Binary Pattern:** Windows crypt32.dll or Linux libcrypto.so
- **Offensive Value:** Validates production readiness
- **Must Detect:** Multiple crypto implementations in system libraries

### 10. Performance & Edge Cases

**Test:** `test_detector_performance_on_large_whitebox_crypto`
- **Validates:** Performance on large binaries
- **Binary Pattern:** 65KB+ white-box crypto binary
- **Offensive Value:** Ensures usability on real protected software
- **Must Complete:** Analysis in < 30 seconds

**Test:** `test_detector_confidence_degrades_gracefully_for_partial_patterns`
- **Validates:** Confidence scoring for partial matches
- **Binary Pattern:** Incomplete AES S-box (128/256 bytes)
- **Offensive Value:** Handles real-world fragmented crypto
- **Must Provide:** Valid confidence scores (0.0-1.0)

**Test:** `test_detector_handles_edge_case_zero_length_crypto_routines`
- **Validates:** Edge case handling
- **Binary Pattern:** Minimal PE header only
- **Offensive Value:** Robustness against malformed binaries
- **Must Handle:** Empty detections without crashing

## Coverage Metrics

**Total Advanced Tests:** 35 tests
**Coverage Areas:**
- Key Derivation Functions: 4 tests (PBKDF2, HKDF, bcrypt, scrypt)
- MAC Operations: 4 tests (HMAC, AES-GCM, Poly1305, SipHash)
- Crypto Type Differentiation: 3 tests (hash/cipher, stream/block, key expansion)
- RNG Detection: 2 tests (Mersenne Twister, ChaCha-RNG)
- Inline Crypto: 3 tests (inline AES, XOR chains, Feistel)
- SIMD Crypto: 2 tests (SIMD AES, hardware/software)
- White-box Crypto: 3 tests (large tables, entropy, obfuscation)
- Data Flow Analysis: 2 tests (registers, constants)
- Real-World Testing: 2 tests (OpenSSL, system libraries)
- Performance/Edge Cases: 5 tests

## Expected Test Results

**All tests MUST:**
1. Use real binary data (no mocks)
2. FAIL if detection doesn't work
3. Validate offensive capability
4. Complete in reasonable time (< 30s per test)
5. Provide actionable detection results

**Success Criteria:**
- Minimum 85% line coverage on detector module
- All critical crypto types detected
- Differentiation between crypto categories works
- Edge cases handled without crashes
- Real-world binaries analyzed successfully

## Running Tests

```bash
# Run all crypto detector tests
pixi run pytest tests/core/analysis/test_cryptographic_routine_detector*.py -v

# Run only advanced tests
pixi run pytest tests/core/analysis/test_cryptographic_routine_detector_advanced.py -v

# Run with coverage
pixi run pytest tests/core/analysis/test_cryptographic_routine_detector*.py --cov=intellicrack.core.analysis.cryptographic_routine_detector --cov-report=html

# Run specific test category
pixi run pytest tests/core/analysis/test_cryptographic_routine_detector_advanced.py -k "kdf" -v
```

## Test Maintenance

**When updating detector:**
1. Add corresponding test for new crypto algorithm
2. Ensure test uses real binary pattern
3. Validate test FAILS when code is broken
4. Update this coverage document

**When crypto fails to detect:**
1. Add test case reproducing the failure
2. Fix implementation to make test pass
3. Verify existing tests still pass
4. Document new pattern in coverage

## Integration with testingtodo.md

**Addresses testingtodo.md line 372-379:**
- ✅ Instruction pattern analysis for crypto detection
- ✅ Identify crypto constants (S-boxes, round constants)
- ✅ Detect custom/modified crypto implementations
- ✅ Differentiate between hash, cipher, and MAC operations
- ✅ Identify key derivation and random number generation
- ✅ Edge cases: Inline crypto, SIMD implementations, white-box crypto

**Test Validation:**
- All requirements from testingtodo.md are covered
- Tests validate REAL functionality (no simulation)
- Tests MUST FAIL if implementation is incomplete
- Production-ready code only
