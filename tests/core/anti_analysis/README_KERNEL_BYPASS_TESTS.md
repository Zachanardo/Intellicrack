# Kernel Bypass Tests - Quick Reference

## Quick Start

### Run All Kernel Bypass Tests
```bash
cd D:\Intellicrack
pytest tests/core/anti_analysis/test_kernel_bypass_*.py -v
```

### Expected Output
```
tests/core/anti_analysis/test_kernel_bypass_documentation_validation.py::TestKernelBypassDocumentation::test_advanced_bypass_documents_user_mode_limitation PASSED
tests/core/anti_analysis/test_kernel_bypass_documentation_validation.py::TestKernelBypassDocumentation::test_user_mode_hooker_documents_ring3_operation PASSED
...
========== 102 passed in X.XXs ==========
```

## Test Files

### 1. Documentation Validation (57 tests)
**File:** `test_kernel_bypass_documentation_validation.py`

Tests that validate:
- Kernel bypass approach is documented
- User-mode vs kernel-mode distinction is clear
- Platform limitations are stated
- Windows version compatibility is documented
- Driver signing requirements are mentioned
- HVCI/VBS/Secure Boot handling is addressed

**Run:** `pytest tests/core/anti_analysis/test_kernel_bypass_documentation_validation.py -v`

### 2. Implementation Validation (45 tests)
**File:** `test_kernel_bypass_implementation_validation.py`

Tests that validate:
- User-mode NT API hooks generate valid shellcode
- Hypervisor debugging support works
- Timing attack neutralization functions
- Bypass techniques combine correctly
- Performance meets requirements
- Reliability is consistent

**Run:** `pytest tests/core/anti_analysis/test_kernel_bypass_implementation_validation.py -v`

## Common Test Scenarios

### Test Documentation Completeness
```bash
pytest tests/core/anti_analysis/test_kernel_bypass_documentation_validation.py::TestKernelBypassDocumentation -v
```

### Test User-Mode Implementation
```bash
pytest tests/core/anti_analysis/test_kernel_bypass_implementation_validation.py::TestUserModeNTAPIHookingImplementation -v
```

### Test Hypervisor Support
```bash
pytest tests/core/anti_analysis/test_kernel_bypass_implementation_validation.py::TestHypervisorDebuggingImplementation -v
```

### Test Timing Neutralization
```bash
pytest tests/core/anti_analysis/test_kernel_bypass_implementation_validation.py::TestTimingNeutralizationImplementation -v
```

### Test Frida Integration
```bash
pytest tests/core/anti_analysis/test_kernel_bypass_documentation_validation.py::TestFridaKernelBypassIntegration -v
```

## Coverage Analysis

### Generate Coverage Report
```bash
pytest tests/core/anti_analysis/test_kernel_bypass_*.py --cov=intellicrack.core.anti_analysis --cov-report=html
```

**Output:** `htmlcov/index.html` - Open in browser

### Show Coverage in Terminal
```bash
pytest tests/core/anti_analysis/test_kernel_bypass_*.py --cov=intellicrack.core.anti_analysis --cov-report=term-missing
```

## Platform-Specific Tests

### Windows-Only Tests
```bash
# On Windows
pytest tests/core/anti_analysis/test_kernel_bypass_implementation_validation.py -v

# Skip Windows tests on Linux
pytest tests/core/anti_analysis/test_kernel_bypass_*.py -v  # Automatically skips Windows-only
```

### Cross-Platform Documentation Tests
```bash
# These run on all platforms
pytest tests/core/anti_analysis/test_kernel_bypass_documentation_validation.py -v
```

## Debugging Test Failures

### Run Single Test with Full Output
```bash
pytest tests/core/anti_analysis/test_kernel_bypass_documentation_validation.py::TestKernelBypassDocumentation::test_advanced_bypass_documents_user_mode_limitation -vv -s
```

### Show Full Traceback
```bash
pytest tests/core/anti_analysis/test_kernel_bypass_*.py --tb=long
```

### Stop on First Failure
```bash
pytest tests/core/anti_analysis/test_kernel_bypass_*.py -x
```

### Run Failed Tests Only
```bash
pytest tests/core/anti_analysis/test_kernel_bypass_*.py --lf
```

## Test Categories

### By Test Class

**Documentation Tests:**
- `TestKernelBypassDocumentation` - Kernel bypass approach documentation
- `TestUserModeVsKernelModeDistinction` - Operation level clarity
- `TestPlatformLimitationDocumentation` - Platform limitations
- `TestWindowsVersionCompatibility` - Windows version support
- `TestDriverSigningDocumentation` - Driver signing requirements
- `TestHVCIVBSSecureBootHandling` - Security feature handling
- `TestMaximumUserModeCoverage` - User-mode coverage documentation
- `TestFridaKernelBypassIntegration` - Frida integration documentation
- `TestCommercialProtectionDefeatDocumentation` - Protection defeat docs
- `TestImplementationCompletenessValidation` - Completeness validation
- `TestEdgeCaseDocumentation` - Edge case handling
- `TestProductionReadinessValidation` - Production readiness
- `TestIntegrationWithFridaBypass` - Frida integration

**Implementation Tests:**
- `TestUserModeNTAPIHookingImplementation` - NT API hook functionality
- `TestHypervisorDebuggingImplementation` - Hypervisor support
- `TestTimingNeutralizationImplementation` - Timing attack defense
- `TestAdvancedBypassIntegration` - Complete bypass integration
- `TestConvenienceFunctionImplementation` - Convenience functions
- `TestRealWorldBypassScenarios` - Real-world scenarios
- `TestPerformanceAndReliability` - Performance testing

### By Feature

**User-Mode Hooks:**
```bash
pytest tests/core/anti_analysis/test_kernel_bypass_implementation_validation.py::TestUserModeNTAPIHookingImplementation -v
```

**Hypervisor:**
```bash
pytest tests/core/anti_analysis/test_kernel_bypass_implementation_validation.py::TestHypervisorDebuggingImplementation -v
```

**Timing:**
```bash
pytest tests/core/anti_analysis/test_kernel_bypass_implementation_validation.py::TestTimingNeutralizationImplementation -v
```

**Documentation:**
```bash
pytest tests/core/anti_analysis/test_kernel_bypass_documentation_validation.py::TestKernelBypassDocumentation -v
```

## What Tests Validate

### ✅ Tests PASS When:
- Documentation exists and is comprehensive
- User-mode vs kernel-mode distinction is clear
- Platform limitations are explicitly stated
- Implementations are functional (not placeholders)
- Performance meets requirements (<0.5s for checks)
- Reliability is consistent (≥3/5 success rate)
- All edge cases are documented

### ❌ Tests FAIL When:
- Documentation is missing or incomplete
- Operation level (Ring 3 vs Ring 0) is unclear
- Platform limitations are not stated
- Implementations are placeholders (TODO, FIXME)
- Performance is poor (>0.5s for simple checks)
- Reliability is inconsistent (<3/5 success rate)
- Edge cases are not documented

## Continuous Integration

### GitHub Actions Example
```yaml
name: Kernel Bypass Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.12'
      - name: Install dependencies
        run: |
          pip install pytest pytest-cov
          pip install -e .
      - name: Run tests
        run: |
          pytest tests/core/anti_analysis/test_kernel_bypass_*.py -v --cov --cov-report=xml
      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

## Expected Test Results

### All Tests Pass (Success)
```
tests/core/anti_analysis/test_kernel_bypass_documentation_validation.py ... 57 passed
tests/core/anti_analysis/test_kernel_bypass_implementation_validation.py ... 45 passed

========== 102 passed in 5.23s ==========
```

### Documentation Missing (Failure)
```
tests/core/anti_analysis/test_kernel_bypass_documentation_validation.py::test_kernel_bypass_implementation_documentation_exists FAILED

AssertionError: KERNEL_MODE_ANTIDEBUG_IMPLEMENTATION.md must exist
```

### Implementation Broken (Failure)
```
tests/core/anti_analysis/test_kernel_bypass_implementation_validation.py::test_ntquery_information_process_hook_generates_valid_shellcode FAILED

AssertionError: Shellcode must be substantial (>16 bytes)
```

## Performance Benchmarks

Expected performance for implementation tests:

- **Shellcode generation:** <0.005s per generation (100 in <0.5s)
- **Virtualization check:** <0.05s per check (10 in <0.5s)
- **Bypass installation:** <2s total
- **Full test suite:** <10s total

## Troubleshooting

### Tests Skip on Linux
**Expected:** Windows-specific implementation tests skip automatically
**Solution:** Run on Windows for full test coverage

### Documentation Tests Fail
**Cause:** Missing or incomplete documentation
**Solution:** Check KERNEL_MODE_ANTIDEBUG_IMPLEMENTATION.md exists and is comprehensive

### Implementation Tests Fail
**Cause:** Non-functional code or placeholders
**Solution:** Ensure implementations are complete (no TODO/FIXME)

### Performance Tests Fail
**Cause:** Slow operations
**Solution:** Optimize shellcode generation or virtualization checks

## Test Maintenance

### Adding New Bypass Technique

1. **Implement functionality** in `advanced_debugger_bypass.py`
2. **Add documentation test** in `test_kernel_bypass_documentation_validation.py`:
   ```python
   def test_new_technique_documented(self) -> None:
       """New technique must be documented."""
       # Check source file for documentation
       assert "new_technique" in content
   ```
3. **Add implementation test** in `test_kernel_bypass_implementation_validation.py`:
   ```python
   def test_new_technique_works(self) -> None:
       """New technique must function correctly."""
       # Validate actual functionality
       assert result is True
   ```
4. **Run tests** to ensure they FAIL without implementation
5. **Implement functionality** to make tests PASS

### Modifying Existing Tests

1. **Update test** to match new behavior
2. **Ensure test still validates real functionality** (no mocks)
3. **Verify test FAILS with broken code**
4. **Update documentation** if behavior changes

## Quick Test Commands

```bash
# All tests
pytest tests/core/anti_analysis/test_kernel_bypass_*.py -v

# Documentation only
pytest tests/core/anti_analysis/test_kernel_bypass_documentation_validation.py -v

# Implementation only
pytest tests/core/anti_analysis/test_kernel_bypass_implementation_validation.py -v

# With coverage
pytest tests/core/anti_analysis/test_kernel_bypass_*.py --cov=intellicrack.core.anti_analysis --cov-report=html

# Specific test
pytest tests/core/anti_analysis/test_kernel_bypass_documentation_validation.py::TestKernelBypassDocumentation::test_advanced_bypass_documents_user_mode_limitation -v

# Stop on first failure
pytest tests/core/anti_analysis/test_kernel_bypass_*.py -x

# Show full output
pytest tests/core/anti_analysis/test_kernel_bypass_*.py -vv -s
```

## Resources

- **Test Coverage Report:** `TEST_COVERAGE_KERNEL_BYPASS.md`
- **Test Summary:** `KERNEL_BYPASS_TEST_SUMMARY.md`
- **Implementation Documentation:** `KERNEL_MODE_ANTIDEBUG_IMPLEMENTATION.md`
- **Source Code:** `intellicrack/core/anti_analysis/advanced_debugger_bypass.py`
- **Frida Bypass:** `intellicrack/core/analysis/frida_protection_bypass.py`
