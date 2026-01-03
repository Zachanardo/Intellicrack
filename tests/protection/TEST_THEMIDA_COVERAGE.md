# Themida Analyzer Test Coverage

## Production-Ready Test Suite

This test suite validates genuine offensive capability against Themida/WinLicense protected binaries.

## Test Files

### test_themida_analyzer_comprehensive.py
**Scope:** General Themida detection and analysis validation
- Analyzer initialization and configuration
- Version detection (Themida 1.x, 2.x, 3.x, WinLicense variants)
- Protection presence detection via signatures and section names
- VM architecture detection (CISC, RISC, FISH)
- VM section and entry point discovery
- Handler table location identification
- VM context extraction and register mapping
- Encryption key extraction and entropy validation
- Anti-debug check detection (PEB, API calls)
- Anti-dump mechanism detection
- Devirtualization with confidence scoring
- Analysis report generation
- Edge cases (corrupted, empty, tiny, large binaries)
- Integration scenarios (full analysis workflows)

**Coverage:** ~90 tests validating foundational Themida analysis capabilities

### test_themida_cisc_handlers_production.py
**Scope:** CISC handler detection for complete opcode range 0x00-0xFF
- **CRITICAL:** Validates ALL CISC VM handlers (0x00-0xFF range)
- CISC handler detection in 8 ranges:
  - 0x00-0x0F (16 opcodes)
  - 0x10-0x1F (16 opcodes)
  - 0x20-0x3F (32 opcodes)
  - 0x40-0x5F (32 opcodes)
  - 0x60-0x7F (32 opcodes)
  - 0x80-0x9F (32 opcodes)
  - 0xA0-0xFF (96 opcodes)
- Complete RISC VM handler semantic lifting (0x00-0x61)
- Complete FISH VM handler semantic lifting (0x00-0xAF)
- VM dispatcher entry point tracing
- Handler table location accuracy
- VM context extraction with register mapping
- Themida version distinction (2.x vs 3.x)
- Code extraction accuracy (>90% confidence threshold)
- Devirtualized code validation (native code, assembly, confidence)
- Anti-analysis technique handling:
  - Junk code around handlers
  - PEB anti-debug checks
  - API-based anti-debug (IsDebuggerPresent)
  - Anti-dump (VirtualProtect)
  - High-entropy encryption key extraction
- Edge cases:
  - Encrypted handlers
  - Version-specific variations
  - Multi-layer virtualization
- Real binary analysis from tests/test_binaries/
- Handler semantic categorization:
  - Arithmetic operations
  - Logical operations
  - Data transfer
  - Comparison
  - Control flow
  - Stack operations
  - Complex operations
- Handler complexity scoring (1-10 scale)
- Handler reference tracking
- Failure mode testing:
  - Incomplete handlers reduce confidence
  - Missing VM entry points reduce confidence
  - Corrupted patterns handled gracefully

**Coverage:** ~45 tests validating CISC/RISC/FISH handler detection across full opcode range

## Expected Behavior Validation

### MUST Pass Criteria

1. **Complete Handler Range Detection**
   - Detects ALL Themida CISC VM handlers (0x00-0xFF)
   - Detects ALL Themida RISC VM handlers (0x00-0x61)
   - Detects ALL Themida FISH VM handlers (0x00-0xAF)
   - Missing any handler in defined ranges = TEST FAILS

2. **Handler Semantic Lifting**
   - Each handler assigned valid category (arithmetic, logical, etc.)
   - Complexity score 1-10 for each handler
   - Handler references tracked accurately
   - Invalid semantics = TEST FAILS

3. **Version Detection Accuracy**
   - Correctly identifies Themida 2.x/3.x/3.1
   - Distinguishes WinLicense from Themida
   - Version UNKNOWN on clean binaries only
   - Wrong version = TEST FAILS

4. **VM Dispatcher Tracing**
   - Locates VM entry points accurately
   - Identifies handler table addresses
   - Entry points sorted and validated
   - Missing dispatcher components = TEST FAILS

5. **Code Extraction Accuracy**
   - Devirtualized code confidence >= 70% on real binaries
   - Native code generated for virtualized sections
   - Assembly instructions extracted and valid
   - Accuracy < 70% = TEST FAILS

6. **Anti-Analysis Handling**
   - Detects junk code without false negatives
   - Identifies PEB anti-debug checks
   - Finds API-based anti-debug mechanisms
   - Locates anti-dump techniques
   - Missed anti-analysis = TEST FAILS

7. **Real Binary Validation**
   - Works on ANY Themida binary in tests/test_binaries/
   - Handler coverage >= 50 handlers (CISC), 30 (RISC), 40 (FISH)
   - Confidence >= 40% on real binaries
   - Real binary failure = TEST FAILS

## Adding Test Binaries

To test against real Themida-protected binaries:

1. Create directory: `tests/test_binaries/`
2. Add Themida/WinLicense protected executables:
   - Name files with descriptive pattern (e.g., `app_themida_3x.exe`)
   - Include various versions (2.x, 3.x, 3.1)
   - Include CISC, RISC, and FISH variants if available
3. Tests automatically discover and validate all binaries

**Real Binary Test Requirements:**
- Protection detected: `is_protected == True`
- Version identified: `version != UNKNOWN`
- VM architecture detected: `vm_architecture != UNKNOWN`
- Handler count >= minimum threshold
- Confidence >= 40%
- Devirtualization accuracy >= 70% (if sections present)

## Running Tests

```bash
# Run all Themida tests
pixi run pytest tests/protection/test_themida*.py -v

# Run only CISC handler tests
pixi run pytest tests/protection/test_themida_cisc_handlers_production.py -v

# Run with coverage
pixi run pytest tests/protection/test_themida*.py --cov=intellicrack.protection.themida_analyzer --cov-report=term-missing

# Run specific test class
pixi run pytest tests/protection/test_themida_cisc_handlers_production.py::TestThemidaCISCHandlerDetectionComprehensive -v

# Run real binary tests only
pixi run pytest tests/protection/test_themida_cisc_handlers_production.py::TestThemidaRealBinaryAnalysis -v
```

## Test Failure Interpretation

### If tests fail, it means functionality is BROKEN:

**Missing Handlers:**
```
AssertionError: Handler 0x42 not detected
```
→ CISC handler pattern matching is incomplete or broken

**Low Confidence:**
```
AssertionError: Average devirtualization confidence 45.2% below 70% threshold
```
→ Devirtualization algorithm not working correctly

**Version Detection Failure:**
```
AssertionError: Failed to detect version in themida_3x_sample.exe
```
→ Version signature database incomplete or detection logic broken

**Handler Semantic Errors:**
```
AssertionError: handler.category not in valid_categories
```
→ Semantic lifting not implemented or categorization broken

## Coverage Requirements

- **Line Coverage:** >= 85%
- **Branch Coverage:** >= 80%
- **Handler Detection:** 100% of defined patterns
- **Real Binary Success:** 100% of test binaries analyzed successfully

## Notes

- Tests use synthetic binaries when no real binaries available
- Synthetic binaries test pattern matching and structure
- Real binaries test production capability
- All assertions validate REAL functionality, not just execution
- No mocks, no stubs - all tests validate offensive capability
