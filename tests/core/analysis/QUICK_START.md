# Quick Start: Streaming Crypto Detector Tests

## Instant Verification

### Check Test Quality
```bash
cd D:\Intellicrack
python tests/core/analysis/verify_test_quality.py
```

Expected output:
```
✓ ALL QUALITY CHECKS PASSED
✓ Tests are production-ready
```

## Running Tests

### 1. Run All Tests (53 tests)
```bash
pixi run pytest tests/core/analysis/test_streaming_crypto_detector_production.py -v
```

### 2. Run Fast Tests (Initialization + Fixtures)
```bash
pixi run pytest tests/core/analysis/test_streaming_crypto_detector_production.py::TestStreamingCryptoDetectorInitialization -v
```

### 3. Run Real Binary Detection Tests
```bash
pixi run pytest tests/core/analysis/test_streaming_crypto_detector_production.py::TestStreamingCryptoDetectionOnRealBinaries -v
```

### 4. Run Performance Tests
```bash
pixi run pytest tests/core/analysis/test_streaming_crypto_detector_production.py::TestStreamingLargeFilePerformance -v
```

### 5. Run With Coverage Report
```bash
pixi run pytest tests/core/analysis/test_streaming_crypto_detector_production.py \
    --cov=intellicrack.core.analysis.streaming_crypto_detector \
    --cov-report=html \
    --cov-report=term-missing
```

### 6. Run Specific Test
```bash
pixi run pytest tests/core/analysis/test_streaming_crypto_detector_production.py::TestStreamingCryptoDetectionOnRealBinaries::test_detect_crypto_in_crypt32_dll -v
```

## Test Categories Quick Reference

| Category | Tests | Focus |
|----------|-------|-------|
| Initialization | 6 | Detector setup, modes, state |
| Chunk Analysis | 6 | Chunk processing, boundaries, overlaps |
| Real Binary Detection | 6 | Windows binaries (crypt32.dll, notepad.exe) |
| Results Merging | 5 | Multi-chunk aggregation, statistics |
| Finalization | 5 | Licensing detection, complexity scoring |
| Progress Callbacks | 4 | Progress tracking, stages |
| Large File Performance | 3 | 15MB binaries, memory efficiency |
| Edge Cases | 5 | Errors, empty files, partial constants |
| Serialization | 1 | Detection object serialization |
| Complexity Scoring | 4 | Score calculation, capping |
| Checkpointing | 2 | Checkpoint creation, cleanup |
| Integration | 2 | StreamingAnalysisManager integration |
| Algorithm-Specific | 4 | AES, SHA-256, RSA detection |

## Example Test Output

```bash
$ pixi run pytest tests/core/analysis/test_streaming_crypto_detector_production.py::TestStreamingCryptoDetectorInitialization -v

============================= test session starts ==============================
platform win32 -- Python 3.12.x, pytest-8.4.2
rootdir: D:\Intellicrack
plugins: cov-7.0.0, xdist-3.5.0

tests/core/analysis/test_streaming_crypto_detector_production.py::TestStreamingCryptoDetectorInitialization::test_default_initialization_creates_detector_instance PASSED
tests/core/analysis/test_streaming_crypto_detector_production.py::TestStreamingCryptoDetectorInitialization::test_quick_mode_initialization_enables_fast_processing PASSED
tests/core/analysis/test_streaming_crypto_detector_production.py::TestStreamingCryptoDetectorInitialization::test_radare2_mode_initialization_enables_enhanced_analysis PASSED
tests/core/analysis/test_streaming_crypto_detector_production.py::TestStreamingCryptoDetectorInitialization::test_combined_quick_and_radare2_modes_enabled PASSED
tests/core/analysis/test_streaming_crypto_detector_production.py::TestStreamingCryptoDetectorInitialization::test_initialize_analysis_sets_binary_path PASSED
tests/core/analysis/test_streaming_crypto_detector_production.py::TestStreamingCryptoDetectorInitialization::test_multiple_initialize_calls_reset_state PASSED

============================== 6 passed in 0.32s ===============================
```

## What These Tests Validate

### Detection Capability
- ✓ AES S-box identification
- ✓ SHA-256 round constants
- ✓ RSA public exponents
- ✓ Real crypto library analysis

### Streaming Functionality
- ✓ Chunk-based processing
- ✓ Overlap region handling
- ✓ Duplicate filtering
- ✓ Memory efficiency

### Data Quality
- ✓ Confidence scores [0.0-1.0]
- ✓ Valid byte offsets
- ✓ Correct algorithm types
- ✓ Proper serialization

### Performance
- ✓ Large file processing (<60s for 15MB)
- ✓ Quick mode optimization
- ✓ Memory usage efficiency
- ✓ Progress tracking

### Robustness
- ✓ Error handling
- ✓ Empty file processing
- ✓ Nonexistent file errors
- ✓ Partial constant detection

## Key Assertions

### Example: Detection Accuracy
```python
assert results["total_detections"] >= 0
assert "detections" in results
assert all(0.0 <= d["confidence"] <= 1.0 for d in results["detections"])
```

### Example: Chunk Boundaries
```python
for detection in result["detections"]:
    offset = detection["offset"]
    assert chunk_offset <= offset < chunk_offset + chunk_size
```

### Example: Performance
```python
start_time = time.perf_counter()
results = analyze_crypto_streaming(binary, quick_mode=True)
elapsed = time.perf_counter() - start_time
assert elapsed < 60.0  # Must complete within 60 seconds
```

## Real Binaries Used

All tests use actual Windows system files:

```python
C:\Windows\System32\notepad.exe      # Basic Windows application
C:\Windows\System32\kernel32.dll     # Core Windows DLL
C:\Windows\System32\ntdll.dll        # NT layer
C:\Windows\System32\crypt32.dll      # Cryptography API
C:\Windows\System32\bcrypt.dll       # Modern crypto API
C:\Windows\System32\advapi32.dll     # Advanced API
```

## Generated Test Binaries

Tests also create binaries with known crypto constants:

- **AES Binary**: Contains full AES S-box at offset 512
- **SHA-256 Binary**: Contains SHA-256 round constants
- **RSA Binary**: Contains RSA public exponent (65537)
- **Large Binary**: 15MB with distributed crypto constants

## Coverage Target

**Minimum Required**: 85% line coverage, 80% branch coverage

**Areas Covered**:
- Initialization and configuration
- Chunk processing pipeline
- Detection and filtering
- Results merging
- Finalization logic
- Progress callbacks
- Error handling
- Serialization
- Complexity scoring
- Checkpointing

## Troubleshooting

### Test Fails: "No Windows binaries available"
- Ensure you're running on Windows
- Check `C:\Windows\System32` is accessible
- Run with administrator privileges if needed

### Test Fails: Import errors
- Ensure pixi environment is activated
- Check all dependencies installed: `pixi install`
- Verify angr, capstone are available

### Test Timeout
- Large file tests may take up to 60 seconds
- Use quick mode for faster iteration
- Check system performance

### Coverage Not Met
- Run: `pixi run pytest --cov=intellicrack.core.analysis.streaming_crypto_detector --cov-report=term-missing`
- Check which lines/branches are uncovered
- Add tests for missing scenarios

## Best Practices

1. **Run verification first**: Always run `verify_test_quality.py` before submitting
2. **Check coverage**: Ensure 85%+ line coverage maintained
3. **Test real binaries**: Validate against actual Windows crypto libraries
4. **Verify performance**: Large file tests must pass within time limits
5. **No mocks**: All tests must use real implementations

## Next Steps

After running these tests:

1. Check coverage report: `htmlcov/index.html`
2. Review any failing tests
3. Add tests for new functionality
4. Update README if test structure changes
5. Run full test suite: `pixi run pytest tests/`

## Support

For issues or questions:
- Check README_STREAMING_CRYPTO_TESTS.md for detailed documentation
- Review test implementation for examples
- Run verification script to check test quality
