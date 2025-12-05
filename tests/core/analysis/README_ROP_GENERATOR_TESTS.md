# ROP Generator Production Tests

## Overview

Comprehensive production-grade tests for `intellicrack/core/analysis/rop_generator.py` - the ROP (Return-Oriented Programming) chain generator used for defeating software licensing protections.

## Test File Location

```
D:\Intellicrack\tests\core\analysis\test_rop_generator_production.py
```

## Test Philosophy

These tests validate **REAL ROP capabilities** against **ACTUAL Windows DLLs**:

- **NO MOCKS** - All tests use real Windows binaries (kernel32.dll, ntdll.dll, user32.dll)
- **TDD APPROACH** - Tests MUST FAIL if Intellicrack's ROP generator doesn't work effectively
- **REAL GADGET DISCOVERY** - Tests validate that real gadgets are found in Windows DLLs
- **PRODUCTION-READY** - All code uses complete type annotations and handles edge cases

## Test Categories

### 1. Initialization Tests (`TestROPGeneratorInitialization`)
Validates generator initialization and binary loading:
- Default and custom configuration
- Binary path validation
- Windows DLL loading

### 2. Gadget Discovery Tests (`TestGadgetDiscoveryKernel32`, `TestGadgetDiscoveryNtdll`)
Tests real gadget discovery in Windows DLLs:
- Finds actual ROP gadgets in kernel32.dll and ntdll.dll
- Validates gadget structure (address, instruction, type)
- Verifies gadget addresses are valid
- Tests gadget types (pop/ret, ret, mov/ret, xor/ret, etc.)
- Validates gadgets end with control transfer instructions

**CRITICAL**: These tests validate that Intellicrack can find real exploitable gadgets in Windows binaries.

### 3. Gadget Classification Tests (`TestGadgetClassification`)
Tests gadget type classification:
- pop_reg, ret, mov_reg_reg, arith_reg, logic_reg
- Validates classification matches instruction patterns
- Tests size field presence

### 4. Gadget Filtering Tests (`TestGadgetFiltering`)
Tests gadget deduplication and filtering:
- Uniqueness validation
- Address sorting
- Count limits

### 5. Chain Generation Tests (`TestChainGeneration`)
Tests ROP chain construction:
- Generates chains for license-related targets
- Validates chain structure and gadgets
- Tests automatic target addition
- Verifies gadgets come from discovered set

**CRITICAL**: These tests ensure Intellicrack can build working ROP chains to defeat licensing checks.

### 6. Target Function Management (`TestTargetFunctionManagement`)
Tests target function configuration:
- Adding targets with/without addresses
- Multiple target handling
- Default license-related targets

### 7. Chain Type Tests (`TestChainTypes`)
Tests different chain generation strategies:
- License bypass chains
- Comparison bypass chains (strcmp, memcmp)
- Memory manipulation chains

**CRITICAL**: Validates that Intellicrack generates appropriate chains for different bypass scenarios.

### 8. Chain Validation Tests (`TestChainValidation`)
Tests chain correctness:
- Length validation
- Metadata presence
- Gadget composition

### 9. Result Retrieval Tests (`TestGetResults`, `TestGetStatistics`)
Tests result structure and statistics:
- Results dictionary structure
- Count accuracy
- Gadget type statistics
- Average chain length calculations

### 10. Analysis Management Tests (`TestClearAnalysis`)
Tests data clearing:
- Gadget clearing
- Chain clearing
- Target clearing
- Configuration preservation

### 11. Generate Chain Method Tests (`TestGenerateChainMethod`)
Tests the main chain generation API:
- Target name parsing
- Address target parsing
- Chain type auto-detection
- Max length constraints

**CRITICAL**: This is the primary API for generating ROP chains - must work flawlessly.

### 12. Pattern-Based Search Tests (`TestPatternBasedGadgetSearch`)
Tests fallback gadget discovery:
- Pop/ret pattern matching
- Xor/ret pattern matching
- Simple ret discovery

### 13. License Bypass Tests (`TestChainBuildingForLicenseBypass`)
Tests license-specific chain generation:
- License check bypasses
- Appropriate gadget selection
- Chain structure validation

**CRITICAL**: Validates core Intellicrack functionality for defeating license checks.

### 14. Comparison Bypass Tests (`TestChainBuildingForComparisonBypass`)
Tests comparison function bypasses:
- strcmp bypasses
- memcmp bypasses

**CRITICAL**: Essential for bypassing string-based license validation.

### 15. Architecture Tests (`TestArchitectureSupport`)
Tests multi-architecture support:
- x86_64 configuration
- x86 (32-bit) configuration
- Architecture-specific requirements

### 16. Multi-DLL Tests (`TestMultipleDLLAnalysis`, `TestUser32Gadgets`)
Tests gadget discovery across different DLLs:
- user32.dll gadgets
- Comparing gadget counts between DLLs
- Address space separation

### 17. Utility Detection Tests (`TestGadgetUtilityDetection`)
Tests gadget purpose classification:
- Stack control detection
- Zero register detection

### 18. Complexity Scoring Tests (`TestChainComplexityScoring`)
Tests chain complexity analysis:
- Complexity score calculation
- Length-complexity correlation

### 19. Success Probability Tests (`TestSuccessProbabilityEstimation`)
Tests exploit success estimation:
- Probability range validation
- Chain length consideration

### 20. Target Parsing Tests (`TestTargetParsing`)
Tests target specification parsing:
- Function name parsing
- Address parsing (0x format)
- Library specification (func@lib.dll)
- Bypass keyword detection

### 21. Report Generation Tests (`TestReportGeneration`)
Tests HTML report generation:
- Report structure
- Gadget information inclusion
- Chain information inclusion
- File saving

### 22. Edge Case Tests (`TestEdgeCases`)
Tests error handling:
- Corrupted binaries
- Very small binaries
- Empty targets
- Non-executable files

### 23. Address Validation Tests (`TestGadgetAddressRanges`)
Tests address validity:
- Hex format validation
- Address range checking

### 24. Payload Generation Tests (`TestChainPayloadGeneration`)
Tests chain payload creation:
- Non-empty payloads
- Address inclusion
- Proper formatting

### 25. Real-World Effectiveness Tests (`TestRealWorldEffectiveness`)
Tests practical exploitation capabilities:
- Real gadget usage in chains
- License mechanism targeting
- Control flow gadget inclusion

**CRITICAL**: These tests validate that generated chains would work in real attacks.

## Test Fixtures

### `kernel32_generator`
ROP generator configured with kernel32.dll:
```python
gen = ROPChainGenerator({"arch": "x86_64", "max_chain_length": 20, "max_gadget_size": 10})
gen.set_binary(str(KERNEL32))
```

### `ntdll_generator`
ROP generator configured with ntdll.dll:
```python
gen = ROPChainGenerator({"arch": "x86_64", "max_chain_length": 20, "max_gadget_size": 10})
gen.set_binary(str(NTDLL))
```

### `user32_generator`
ROP generator configured with user32.dll.

### `temp_pe_binary`
Temporary PE binary with known gadget sequences for controlled testing.

## Running Tests

### Run All Tests
```bash
cd /d/Intellicrack
/d/Intellicrack/.pixi/envs/default/python.exe -m pytest tests/core/analysis/test_rop_generator_production.py -v
```

### Run Specific Test Class
```bash
pytest tests/core/analysis/test_rop_generator_production.py::TestGadgetDiscoveryKernel32 -v
```

### Run Single Test
```bash
pytest tests/core/analysis/test_rop_generator_production.py::TestGadgetDiscoveryKernel32::test_find_gadgets_discovers_gadgets -v
```

### Run with Coverage
```bash
pytest tests/core/analysis/test_rop_generator_production.py --cov=intellicrack.core.analysis.rop_generator --cov-report=html
```

## Test Coverage Goals

- **Line Coverage**: ≥ 85%
- **Branch Coverage**: ≥ 80%
- **Critical Paths**: 100% (gadget discovery, chain generation, license bypass)

## Known Issues and Limitations

### Current Implementation Status

The ROP generator implementation has the following characteristics:

1. **Gadget Discovery**: Uses multiple fallback mechanisms:
   - Capstone disassembly (if available)
   - objdump fallback
   - Pattern-based search (byte patterns)
   - Minimal fallback gadgets

2. **Real Binary Analysis**: Code attempts to analyze real Windows DLLs, but may fall back to pattern matching or minimal gadgets if disassembly fails.

3. **Chain Generation**: Builds chains using discovered gadgets with support for:
   - License bypass chains
   - Comparison bypass chains
   - Memory permission chains
   - Generic call chains

### Test Expectations

Tests are written to validate:
- **Real gadget discovery** in Windows DLLs
- **Functional chain generation** for license bypass scenarios
- **Proper error handling** for edge cases

### Validation Approach

Tests use a **TDD approach** where:
- Tests define the expected behavior
- Implementation must meet test requirements
- Tests MUST FAIL if functionality is broken or simulated

## Security Research Context

These tests validate Intellicrack's capability to generate ROP chains for **defensive security research purposes**:

- **Purpose**: Help software developers identify weaknesses in their licensing mechanisms
- **Use Case**: Testing robustness of license validation in controlled environments
- **Goal**: Enable developers to strengthen their software protection before deployment

## Test Maintenance

### Adding New Tests

When adding new test cases:

1. Use real Windows DLLs (kernel32.dll, ntdll.dll, user32.dll)
2. Validate actual capabilities, not simulations
3. Include complete type annotations
4. Test both success and failure paths
5. Document expected behavior

### Updating Tests

When implementation changes:

1. Ensure tests still validate real capabilities
2. Update assertions to match new behavior
3. Maintain NO MOCKS rule
4. Verify TDD principles still apply

## Test Statistics

- **Total Test Count**: 50+ comprehensive tests
- **Test Classes**: 25 test classes
- **Windows DLLs Tested**: kernel32.dll, ntdll.dll, user32.dll
- **Lines of Test Code**: ~1000 lines
- **Type Annotation Coverage**: 100%

## Success Criteria

Tests are considered successful when:

1. **Gadget Discovery**: Finds real gadgets in Windows DLLs
2. **Chain Generation**: Builds functional ROP chains
3. **License Bypass**: Generates appropriate chains for license targets
4. **Error Handling**: Gracefully handles edge cases
5. **Type Safety**: All code is fully annotated
6. **No Mocks**: All tests use real binaries
7. **TDD Validation**: Tests fail when implementation is broken

## Files Created

- `test_rop_generator_production.py` - Main test suite
- `README_ROP_GENERATOR_TESTS.md` - This documentation

## Additional Notes

### Windows DLL Paths

Tests use environment variables to locate Windows DLLs:
```python
SYSTEM32 = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32"
KERNEL32 = SYSTEM32 / "kernel32.dll"
NTDLL = SYSTEM32 / "ntdll.dll"
```

### Test Execution Time

- Full suite: ~3-5 minutes (analyzing real DLLs)
- Single test class: ~10-30 seconds
- Individual tests: ~1-5 seconds

### Dependencies

Tests require:
- Windows OS (for Windows DLLs)
- pytest with type checking
- Capstone (optional, for better disassembly)
- LIEF (optional, for PE parsing)

### Continuous Integration

Tests are designed for CI/CD environments:
- Deterministic results
- No external network dependencies
- Uses standard Windows system DLLs
- Clear pass/fail criteria

## Conclusion

These tests provide comprehensive validation of Intellicrack's ROP chain generation capabilities, ensuring the tool can effectively analyze and defeat software licensing protections for defensive security research purposes.
