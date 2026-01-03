# Constant Extraction Production Tests

## Overview
This test suite validates the complete hardcoded constant extraction capability from binary files. The tests ensure Intellicrack can extract, identify, and utilize validation constants for license key generation.

## Test File
**Location:** `D:\Intellicrack\tests\core\license\test_constant_extraction_production.py`

## What These Tests Validate

### 1. Immediate Value Constant Extraction
Tests extraction of constants embedded directly in assembly instructions:

- **CRC32 Polynomials** (0xEDB88320, 0x04C11DB7)
  - Validates detection in `mov` immediate instructions
  - Tests x86 and x64 code variants
  - Ensures high confidence scoring (≥0.8)

- **MD5 Initialization Constants** (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)
  - Detects all four MD5 init values from sequential instructions
  - Validates multi-constant detection in single routine

- **SHA256 Constants** (0x6A09E667, etc.)
  - Identifies SHA256 hash initialization values
  - Validates high confidence detection (≥0.9)

- **RSA Exponents** (65537, 17, 3)
  - Detects common RSA public exponents
  - Validates cryptographic primitive classification

### 2. Data Section Constant Extraction
Tests extraction from binary data sections:

- **Lookup Tables**
  - Extracts CRC32 lookup tables (256 entries)
  - Identifies polynomial from table structure
  - Validates table-based algorithm detection

- **Magic Numbers**
  - Detects magic number sequences (0xDEADBEEF, 0xCAFEBABE, etc.)
  - Identifies license validation markers

- **ASCII Strings**
  - Extracts license-related string constants
  - Validates string constant identification in binary data

### 3. Obfuscated Constant Handling
Tests detection of obfuscated and computed constants:

- **Split Constants**
  - Reconstructs constants split across multiple register operations
  - Validates shift-and-combine constant assembly

- **XOR Chains**
  - Detects constants generated through XOR obfuscation
  - Identifies XOR-based constant derivation patterns
  - Minimum confidence ≥0.5 for XOR detection

- **Runtime Computation**
  - Identifies polynomials computed at runtime
  - Detects algorithmic constant generation

### 4. Constant Usage Tracking
Tests tracking constants through validation routines:

- **Definition to Usage Flow**
  - Tracks where constants are defined
  - Identifies how constants are used in validation
  - Provides offset information for usage points

- **Comparison Operations**
  - Correlates constants with validation comparisons
  - Identifies patch points at comparison instructions
  - Validates constraint extraction from comparisons

- **Data Flow Analysis**
  - Tracks constants through register transfers
  - Follows constant propagation across instructions

### 5. Keygen Template Integration
Tests updating keygen templates with extracted constants:

- **CRC Polynomial Extraction**
  - Extracts polynomial for CRC-based keygen
  - Ensures confidence ≥0.7 for template usage

- **Algorithm Building**
  - Constructs complete algorithm definitions
  - Populates parameters (polynomial, modulus, etc.)
  - Validates algorithm correctness

- **Key Generation**
  - Generates valid keys using extracted constants
  - Validates validation function creation
  - Tests key format specification

### 6. Runtime-Generated Constants (Edge Cases)
Tests challenging edge cases:

- **Time-Dependent Constants**
  - Detects constants generated from system time
  - Identifies timestamp-based validation

- **Environment Variables**
  - Identifies constants from environment data
  - Tracks environment-based derivation

- **Hardware IDs**
  - Handles constants from CPUID and hardware IDs
  - Validates hardware-binding detection

### 7. Complex Multi-Algorithm Scenarios
Tests real-world complexity:

- **Multiple Algorithms**
  - Extracts constants from multi-algorithm validation
  - Detects ≥2 different algorithm types simultaneously
  - Validates MD5 + CRC32 + RSA combinations

- **Length Constraints**
  - Extracts license key length requirements
  - Validates length from comparison operations

- **Checksum Position**
  - Identifies checksum location in key format
  - Determines checksum offset from validation code

### 8. Real Binary Testing
Tests against actual system binaries:

- **Windows System DLLs**
  - Analyzes kernel32.dll, ntdll.dll
  - Extracts constants from production code
  - Validates PE file .text section analysis

### 9. Confidence Scoring
Tests quality assessment:

- **Known Constants**: High confidence (≥0.85)
- **Ambiguous Constants**: Lower confidence (<1.0)
- **Overall Analysis**: Normalized confidence [0.0, 1.0]

### 10. Integration Workflows
Tests complete end-to-end flows:

- **Binary → Keygen Workflow**
  - Validates complete extraction pipeline
  - Generates actionable recommendations
  - Provides algorithm type determination

- **Format Specification**
  - Extracts complete key format (length, separators, charset)
  - Validates separator detection (dash, underscore, etc.)

- **Error Handling**
  - Gracefully handles empty input
  - Processes all-zero/all-one binaries
  - Handles non-binary input without crashing

## Expected Behavior Validation

### ✅ MUST Extract All Validation Constants
- CRC polynomials from immediate values
- Hash initialization constants from data sections
- Checksum values from comparisons
- Length constraints from validation logic

### ✅ MUST Identify Constant Sources
- Immediate operands in MOV/LEA instructions
- Data section embedded tables and values
- .rodata section string constants
- Stack-based temporary constants

### ✅ MUST Handle Constant Obfuscation
- Split constants across multiple registers
- XOR-chain obfuscated values
- Shift-and-add computed polynomials
- Runtime-generated constants

### ✅ MUST Track Constant Usage
- From definition to first use
- Through data flow transformations
- In validation comparison operations
- Across function boundaries

### ✅ MUST Update Keygen Templates
- Extract polynomial values for CRC
- Populate hash algorithm parameters
- Define key format specifications
- Generate validation functions

### ✅ MUST Handle Edge Cases
- Runtime-generated constants (time, HWID)
- Environment-dependent values
- Multi-algorithm validation
- Corrupted/invalid input

## Test Execution

```bash
# Run all constant extraction tests
pixi run pytest tests/core/license/test_constant_extraction_production.py -v

# Run specific test class
pixi run pytest tests/core/license/test_constant_extraction_production.py::TestImmediateValueConstantExtraction -v

# Run with coverage
pixi run pytest tests/core/license/test_constant_extraction_production.py --cov=intellicrack.core.license.keygen --cov-report=term-missing
```

## Success Criteria

### All Tests Must Pass
- Zero failures when code is functional
- Tests MUST fail if constant extraction is broken
- Tests MUST fail if confidence scoring is incorrect

### Coverage Requirements
- Minimum 85% line coverage for keygen.py
- Minimum 80% branch coverage
- All public methods tested

### Performance
- Single constant extraction: <100ms
- Full binary analysis: <5 seconds
- Real DLL analysis: <30 seconds

## Failure Scenarios (Tests Must Fail)

These tests are designed to FAIL when:

1. **Constant detection broken**: Missing CRC/MD5/SHA constants
2. **Confidence too low**: Detection confidence below thresholds
3. **Obfuscation not handled**: Split/XOR constants missed
4. **Usage tracking broken**: Cannot track constant flow
5. **Template update fails**: Cannot build algorithm from constants
6. **Edge cases crash**: Runtime/environment constants cause errors
7. **Real binary fails**: Cannot analyze actual system DLLs
8. **Integration broken**: End-to-end workflow incomplete

## Integration with Intellicrack

These tests validate the core capability required for:

- **Automated Keygen Creation**: Extract algorithms from protected software
- **License Analysis**: Understand validation mechanisms
- **Crack Development**: Identify patchable validation points
- **Protection Research**: Analyze licensing protection schemes

## Dependencies

- `capstone`: Disassembly engine for instruction analysis
- `pytest`: Test framework
- `struct`: Binary data parsing
- `hashlib/zlib`: Cryptographic function validation

## Notes

- All tests use **REAL** assembly code and binary data
- **NO MOCKS** - tests validate actual capability
- Tests designed for **Windows platform** (x86/x64)
- Skips gracefully when system DLLs unavailable
- Tests prove code works on **real-world binaries**
