# How to Run Protection-Aware Script Generation Tests

## Quick Start

### 1. Fix pytest Installation (if needed)

If pytest is corrupted, reinstall it:

```bash
cd D:\Intellicrack
pixi remove pytest
pixi add pytest pytest-cov pytest-xdist hypothesis pytest-benchmark
```

### 2. Install Missing Dependencies

```bash
pixi add defusedxml
```

### 3. Run All Tests

```bash
cd D:\Intellicrack
pixi run python -m pytest tests/ai/test_protection_aware_script_gen.py -v --tb=short
```

## Test Execution Options

### Run Specific Test Classes

**Initialization Tests**:
```bash
pixi run python -m pytest tests/ai/test_protection_aware_script_gen.py::TestProtectionAwareScriptGeneratorInitialization -v
```

**Frida Script Generation**:
```bash
pixi run python -m pytest tests/ai/test_protection_aware_script_gen.py::TestFridaScriptGeneration -v
```

**Ghidra Script Generation**:
```bash
pixi run python -m pytest tests/ai/test_protection_aware_script_gen.py::TestGhidraScriptGeneration -v
```

**Protection Detection**:
```bash
pixi run python -m pytest tests/ai/test_protection_aware_script_gen.py::TestProtectionDetectionIntegration -v
```

**Template Completeness**:
```bash
pixi run python -m pytest tests/ai/test_protection_aware_script_gen.py::TestScriptTemplateCompleteness -v
```

### Run Individual Tests

**Test VMProtect Script Generation**:
```bash
pixi run python -m pytest tests/ai/test_protection_aware_script_gen.py::TestFridaScriptGeneration::test_generate_vmprotect_bypass_frida_script -v
```

**Test HASP Script Generation**:
```bash
pixi run python -m pytest tests/ai/test_protection_aware_script_gen.py::TestFridaScriptGeneration::test_generate_hasp_bypass_frida_script_with_api_hooks -v
```

**Test All Templates**:
```bash
pixi run python -m pytest tests/ai/test_protection_aware_script_gen.py::TestScriptTemplateCompleteness::test_all_templates_generate_valid_frida_scripts -v
```

### Run with Coverage

**Generate Coverage Report**:
```bash
pixi run python -m pytest tests/ai/test_protection_aware_script_gen.py \
    --cov=intellicrack.ai.protection_aware_script_gen \
    --cov-report=html \
    --cov-report=term-missing \
    -v
```

**View Coverage HTML Report**:
```bash
start htmlcov/index.html
```

### Run in Parallel

**Speed up execution with pytest-xdist**:
```bash
pixi run python -m pytest tests/ai/test_protection_aware_script_gen.py -n auto -v
```

### Run with Detailed Output

**Show all print statements**:
```bash
pixi run python -m pytest tests/ai/test_protection_aware_script_gen.py -v -s
```

**Show local variables on failure**:
```bash
pixi run python -m pytest tests/ai/test_protection_aware_script_gen.py -v -l
```

### Run Only Failed Tests

**Rerun last failed tests**:
```bash
pixi run python -m pytest tests/ai/test_protection_aware_script_gen.py --lf -v
```

## Filtering Tests

### Run Tests by Keyword

**Run all VMProtect-related tests**:
```bash
pixi run python -m pytest tests/ai/test_protection_aware_script_gen.py -k vmprotect -v
```

**Run all HASP-related tests**:
```bash
pixi run python -m pytest tests/ai/test_protection_aware_script_gen.py -k hasp -v
```

**Run all template tests**:
```bash
pixi run python -m pytest tests/ai/test_protection_aware_script_gen.py -k template -v
```

### Run Tests by Marker

If markers are added to tests:

```python
@pytest.mark.slow
def test_large_binary_generation(self):
    ...
```

Run with:
```bash
pixi run python -m pytest tests/ai/test_protection_aware_script_gen.py -m "not slow" -v
```

## Debugging Tests

### Run with Debugger

**Drop into debugger on failure**:
```bash
pixi run python -m pytest tests/ai/test_protection_aware_script_gen.py --pdb -v
```

**Drop into debugger on first failure**:
```bash
pixi run python -m pytest tests/ai/test_protection_aware_script_gen.py --pdb -x -v
```

### Run with Verbose Logging

**Enable all logging**:
```bash
pixi run python -m pytest tests/ai/test_protection_aware_script_gen.py -v -s --log-cli-level=DEBUG
```

**Show specific module logs**:
```bash
pixi run python -m pytest tests/ai/test_protection_aware_script_gen.py -v -s \
    --log-cli-level=DEBUG \
    --log-cli-format="%(levelname)s %(name)s: %(message)s"
```

## Performance Testing

### Benchmark Tests

**Run with timing information**:
```bash
pixi run python -m pytest tests/ai/test_protection_aware_script_gen.py --durations=10 -v
```

**Run performance tests with benchmark plugin**:
```bash
pixi run python -m pytest tests/ai/test_protection_aware_script_gen.py::TestPerformanceWithLargeBinaries --benchmark-only -v
```

## Test Output Formats

### JUnit XML Report

**Generate JUnit XML for CI/CD**:
```bash
pixi run python -m pytest tests/ai/test_protection_aware_script_gen.py \
    --junitxml=test-results/protection_aware_tests.xml -v
```

### JSON Report

**Generate JSON report**:
```bash
pixi run python -m pytest tests/ai/test_protection_aware_script_gen.py \
    --json-report \
    --json-report-file=test-results/protection_aware_tests.json -v
```

## Continuous Integration

### GitHub Actions Example

```yaml
name: Protection-Aware Script Generation Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install dependencies
        run: |
          pixi install
      - name: Run tests
        run: |
          pixi run python -m pytest tests/ai/test_protection_aware_script_gen.py \
            --cov=intellicrack.ai.protection_aware_script_gen \
            --cov-report=xml \
            --junitxml=test-results.xml \
            -v
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage.xml
```

## Troubleshooting

### Common Issues

**Issue**: `ImportError: cannot import name 'console_main' from 'pytest'`
**Solution**: Reinstall pytest:
```bash
pixi remove pytest && pixi add pytest
```

**Issue**: `ImportError: cannot import name 'ElementTree' from 'defusedxml'`
**Solution**: Install defusedxml:
```bash
pixi add defusedxml
```

**Issue**: `FileNotFoundError: Test binary not found`
**Solution**: Generate test binaries or skip missing tests:
```bash
pixi run python -m pytest tests/ai/test_protection_aware_script_gen.py -v --ignore-missing
```

**Issue**: Tests run but all skip
**Solution**: Check that test binaries exist in `tests/fixtures/binaries/`

### Verify Test Environment

**Check pytest installation**:
```bash
pixi run python -c "import pytest; print(pytest.__version__)"
```

**Check module imports**:
```bash
pixi run python -c "from intellicrack.ai.protection_aware_script_gen import ProtectionAwareScriptGenerator; print('OK')"
```

**List available fixtures**:
```bash
dir tests\fixtures\binaries\pe\protected\
```

## Expected Test Results

### Successful Run Output

```
tests/ai/test_protection_aware_script_gen.py::TestProtectionAwareScriptGeneratorInitialization::test_generator_initializes_with_all_protection_templates PASSED [  2%]
tests/ai/test_protection_aware_script_gen.py::TestProtectionAwareScriptGeneratorInitialization::test_generator_has_functional_unified_engine PASSED [  4%]
tests/ai/test_protection_aware_script_gen.py::TestProtectionAwareScriptGeneratorInitialization::test_generator_has_functional_knowledge_base PASSED [  6%]
tests/ai/test_protection_aware_script_gen.py::TestFridaScriptGeneration::test_generate_vmprotect_bypass_frida_script PASSED [  8%]
...
====================================== 45 passed in 23.45s =======================================
```

### Coverage Report

```
Name                                                    Stmts   Miss  Cover   Missing
-------------------------------------------------------------------------------------
intellicrack/ai/protection_aware_script_gen.py          1247     87    93%   234-245, 567-589
-------------------------------------------------------------------------------------
TOTAL                                                   1247     87    93%
```

## Best Practices

### Before Running Tests

1. **Ensure environment is set up**:
   ```bash
   pixi install
   ```

2. **Check test binaries exist**:
   ```bash
   dir tests\fixtures\binaries\pe\protected\
   ```

3. **Verify dependencies**:
   ```bash
   pixi list
   ```

### During Development

1. **Run tests frequently** - After each change
2. **Focus on failing tests** - Use `--lf` to rerun failures
3. **Check coverage** - Aim for 85%+ line coverage
4. **Use verbose output** - Understand what's being tested

### After Making Changes

1. **Run full test suite** - Ensure nothing broke
2. **Generate coverage report** - Check for regressions
3. **Update tests** - If adding new functionality
4. **Document changes** - Update test documentation

## Test Maintenance

### Adding New Tests

When adding new protection templates:

1. **Add test binary** to `tests/fixtures/binaries/pe/protected/`
2. **Create test method** in appropriate test class
3. **Validate script generation** for new protection
4. **Update template completeness tests**

### Updating Existing Tests

When protection detection improves:

1. **Update confidence thresholds** if needed
2. **Add new API hooks** to validation
3. **Update expected script content**
4. **Regenerate test fixtures** if format changes

## Contact

For issues with tests:
- Check this documentation first
- Review test file comments
- Check TEST_COVERAGE_SUMMARY.md
- Verify environment setup with pixi

---

**Last Updated**: 2025-11-23
**Test Suite Version**: 1.0
**Total Tests**: 45
**Expected Coverage**: 85%+
