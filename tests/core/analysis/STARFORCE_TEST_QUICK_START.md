# StarForce Analyzer Tests - Quick Start Guide

## Test File

`tests/core/analysis/test_starforce_analyzer_production.py`

## Quick Test Commands

### Run All Tests (Recommended)

```bash
pytest tests/core/analysis/test_starforce_analyzer_production.py -v
```

**Result**: 79 tests (77 passing, 2 skipped), ~67 seconds

### Run Without Coverage (Faster)

```bash
pytest tests/core/analysis/test_starforce_analyzer_production.py --no-cov
```

**Result**: Same coverage, ~50 seconds (no coverage overhead)

### Run Specific Test Category

```bash
# IOCTL Detection (6 tests)
pytest tests/core/analysis/test_starforce_analyzer_production.py::TestStarForceIOCTLDetection -v

# Anti-Debugging (7 tests)
pytest tests/core/analysis/test_starforce_analyzer_production.py::TestStarForceAntiDebuggingDetection -v

# VM Detection (9 tests)
pytest tests/core/analysis/test_starforce_analyzer_production.py::TestStarForceVMDetection -v

# License Validation (7 tests)
pytest tests/core/analysis/test_starforce_analyzer_production.py::TestStarForceLicenseValidation -v

# Performance Benchmarks (4 tests)
pytest tests/core/analysis/test_starforce_analyzer_production.py::TestStarForcePerformance --benchmark-only
```

### Run Single Test

```bash
pytest tests/core/analysis/test_starforce_analyzer_production.py::TestStarForceIOCTLDetection::test_detect_known_ioctls_v5 -v
```

## What Gets Tested

### ✅ Core Detection Capabilities

- **10 Known IOCTL Codes**: All StarForce IOCTL commands detected
- **4 Anti-Debug Techniques**: Kernel checks, timing, INT 2D, hardware breakpoints
- **7 VM Detection Methods**: VMware, VirtualBox, QEMU, Hyper-V, CPUID, SIDT/SGDT, Registry
- **6 Disc Auth Mechanisms**: SCSI, TOC, capacity, sectors, geometry, subchannel
- **14+ Kernel Hooks**: File ops, IOCTL, queries, callbacks

### ✅ Version Detection

- StarForce v3/v4/v5 driver identification
- Real Windows binary version extraction
- Graceful handling of missing/corrupted files

### ✅ Advanced Analysis

- Custom IOCTL discovery through pattern matching
- License validation flow analysis
- Cryptographic algorithm identification (MD5, SHA-1, SHA-256, AES)
- Bypass recommendation generation

### ✅ Edge Cases

- Nonexistent files
- Empty files
- Corrupted PE structures
- Partial protection signatures
- Real Windows system binaries

### ✅ Performance

- IOCTL detection: ~268 μs
- Anti-debug detection: ~280 μs
- Full driver analysis: ~1 second

## Test Results Summary

```
79 tests collected
77 tests passed
2 tests skipped (require C:\Windows\System32\drivers access)
0 tests failed

Execution time: ~67 seconds
```

## Understanding Test Output

### Successful Test

```
tests/core/analysis/test_starforce_analyzer_production.py::TestStarForceIOCTLDetection::test_detect_known_ioctls_v5 PASSED [50%]
```

✅ Analyzer successfully detected all 10 known StarForce IOCTLs

### Skipped Test

```
tests/core/analysis/test_starforce_analyzer_production.py::TestStarForceRealBinaries::test_analyze_multiple_system_drivers SKIPPED [100%]
```

⚠️ Test skipped because `C:\Windows\System32\drivers` directory not accessible

## Common Issues

### Issue: Coverage Failure

```
ERROR: Coverage failure: total of 0.00 is less than fail-under=80.00
```

**Solution**: Run with `--no-cov` to skip coverage:

```bash
pytest tests/core/analysis/test_starforce_analyzer_production.py --no-cov
```

### Issue: Pixi Environment Error

```
failed to copy file: The process cannot access the file because it is being used by another process
```

**Solution**: Use direct Python interpreter:

```bash
D:\Intellicrack\.pixi\envs\default\python.exe -m pytest tests/core/analysis/test_starforce_analyzer_production.py --no-cov
```

### Issue: Tests Timeout

**Solution**: Tests are designed to complete quickly. If timeout occurs, check system resources.

## Viewing Detailed Output

### Show All Assertions

```bash
pytest tests/core/analysis/test_starforce_analyzer_production.py -v --tb=short
```

### Show Only Test Names

```bash
pytest tests/core/analysis/test_starforce_analyzer_production.py --collect-only -q
```

### Show Performance Statistics

```bash
pytest tests/core/analysis/test_starforce_analyzer_production.py::TestStarForcePerformance -v
```

## Test Categories

| Category            | Tests | What It Validates                                      |
| ------------------- | ----- | ------------------------------------------------------ |
| Initialization      | 5     | Analyzer setup, configuration, pattern definitions     |
| Version Detection   | 6     | Driver version extraction, error handling              |
| IOCTL Detection     | 6     | Known/custom IOCTL code detection                      |
| Anti-Debugging      | 7     | Anti-debug technique detection, bypass recommendations |
| VM Detection        | 9     | Virtual machine detection methods                      |
| Disc Authentication | 8     | Disc protection mechanism detection                    |
| Kernel Hooks        | 6     | Kernel function hook detection                         |
| License Validation  | 7     | License validation flow analysis                       |
| Comprehensive       | 6     | End-to-end analysis validation                         |
| Edge Cases          | 7     | Error handling, real binary support                    |
| Crypto Detection    | 5     | Cryptographic algorithm identification                 |
| Performance         | 4     | Speed benchmarks                                       |
| Real Binaries       | 4     | Windows system binary analysis                         |

## Interpreting Performance Results

### Benchmark Output

```
test_ioctl_detection_performance          268.5040 (1.0)     3,724.3393 (1.0)
test_anti_debug_detection_performance     280.9480 (1.05)    3,559.3775 (0.96)
test_analyze_performance_large_driver  1,047,951.8400       0.9542 (0.00)
test_analyze_performance_small_driver  1,093,169.6600       0.9148 (0.00)
```

**Interpretation**:

- Mean time in microseconds (μs)
- Operations per second (OPS)
- Lower time = better performance
- Higher OPS = better throughput

## Production Validation

These tests validate **genuine offensive capability**:

✅ **Real Detection** - No mocks, actual binary pattern matching
✅ **Real Binaries** - Tests against Windows system files
✅ **Real Performance** - Benchmark actual analysis speed
✅ **Real Errors** - Tests fail if analyzer breaks

## Next Steps

1. **Run Tests**: `pytest tests/core/analysis/test_starforce_analyzer_production.py --no-cov`
2. **Review README**: See `README_STARFORCE_ANALYZER_PRODUCTION_TESTS.md` for detailed documentation
3. **Check Coverage**: Run with `--cov=intellicrack.core.analysis.starforce_analyzer --cov-report=html`
4. **Add Tests**: When adding analyzer features, add corresponding tests

## Documentation

- **Full Documentation**: `README_STARFORCE_ANALYZER_PRODUCTION_TESTS.md`
- **Source Code**: `intellicrack/core/analysis/starforce_analyzer.py`
- **Test Code**: `tests/core/analysis/test_starforce_analyzer_production.py`
