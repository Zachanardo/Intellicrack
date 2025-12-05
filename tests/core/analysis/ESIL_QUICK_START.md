# Radare2 ESIL Tests - Quick Start Guide

## 1. Prerequisites

### Install Radare2
```bash
# Windows (Chocolatey)
choco install radare2

# Or download installer from:
# https://github.com/radareorg/radare2/releases
```

### Install r2pipe
```bash
pip install r2pipe
```

### Verify Installation
```bash
radare2 -v
python -c "import r2pipe; print('r2pipe OK')"
```

## 2. Run Tests

### Quick Run (No Coverage)
```bash
cd D:\Intellicrack
pytest tests/core/analysis/test_radare2_esil_production.py -v --no-cov
```

### With Coverage Report
```bash
pytest tests/core/analysis/test_radare2_esil_production.py \
  --cov=intellicrack.core.analysis.radare2_esil \
  --cov-report=html
```

### Run Specific Test Category
```bash
# Test ESIL VM initialization
pytest tests/core/analysis/test_radare2_esil_production.py::TestESILVMInitialization -v

# Test function emulation
pytest tests/core/analysis/test_radare2_esil_production.py::TestFunctionEmulation -v

# Test license detection
pytest tests/core/analysis/test_radare2_esil_production.py::TestLicenseCheckDetection -v
```

### Run Performance Benchmarks
```bash
pytest tests/core/analysis/test_radare2_esil_production.py::TestESILPerformance -v --benchmark-only
```

## 3. Expected Output

### Success
```
tests/core/analysis/test_radare2_esil_production.py::TestESILVMInitialization::test_esil_vm_initializes_successfully PASSED [1%]
tests/core/analysis/test_radare2_esil_production.py::TestFunctionEmulation::test_emulate_function_returns_complete_results PASSED [2%]
...
====== 62 passed in 45.23s ======
```

### Coverage
```
---------- coverage: platform win32, python 3.12.x -----------
Name                                            Stmts   Miss  Cover
-------------------------------------------------------------------
intellicrack/core/analysis/radare2_esil.py        189     15    92%
-------------------------------------------------------------------
TOTAL                                             189     15    92%
```

## 4. Common Issues

### "RuntimeError: r2pipe not available"
**Fix**: `pip install r2pipe`

### "radare2 not found"
**Fix**: Install radare2 and add to PATH

### "Test binary not found"
**Fix**: Ensure Windows binaries exist:
- `C:\Windows\System32\notepad.exe`
- `C:\Windows\System32\kernel32.dll`

### Tests Taking Too Long
**Fix**: Run without coverage: `pytest --no-cov`

## 5. Test Categories

62 tests across 15 categories:

1. **ESIL VM Initialization** (4 tests) - VM setup validation
2. **Function Emulation** (11 tests) - Core emulation testing
3. **License Check Detection** (4 tests) - License pattern analysis
4. **Execution Pattern Analysis** (4 tests) - Code flow analysis
5. **Anti-Analysis Detection** (3 tests) - Protection detection
6. **Vulnerability Detection** (1 test) - Security analysis
7. **Multiple Function Emulation** (4 tests) - Batch processing
8. **Binary ESIL Analysis** (4 tests) - High-level API
9. **Branch Type Extraction** (3 tests) - Branch classification
10. **Memory Access Type Extraction** (3 tests) - Memory operations
11. **Function Exit Detection** (4 tests) - Return identification
12. **API Call Sequence Analysis** (2 tests) - API tracking
13. **Error Handling** (3 tests) - Error resilience
14. **Performance Benchmarks** (3 tests) - Speed validation
15. **Caching Behavior** (2 tests) - Cache testing

## 6. Files Locations

- **Tests**: `D:\Intellicrack\tests\core\analysis\test_radare2_esil_production.py`
- **README**: `D:\Intellicrack\tests\core\analysis\README_RADARE2_ESIL_PRODUCTION_TESTS.md`
- **Summary**: `D:\Intellicrack\tests\core\analysis\RADARE2_ESIL_TEST_SUMMARY.md`
- **Implementation**: `D:\Intellicrack\intellicrack\core\analysis\radare2_esil.py`

## 7. Next Steps

After successful test run:
1. Review coverage report: `htmlcov/index.html`
2. Check benchmark results
3. Run with parallel execution: `pytest -n auto`
4. Integrate with CI/CD
