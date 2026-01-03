# Themida Kernel Anti-Debug Tests - Quick Start Guide

## Overview

Production-ready tests for Themida unpacker with kernel-mode anti-debug bypass.

**Test File**: `test_themida_unpacker_kernel_antidebug_production.py`
**Test Count**: 18 comprehensive test methods
**Binary Directory**: `../../test_binaries/themida/`

## Quick Run

```bash
# Run all tests
pixi run pytest test_themida_unpacker_kernel_antidebug_production.py -v

# Run specific test class
pixi run pytest test_themida_unpacker_kernel_antidebug_production.py::TestThemidaKernelAntiDebugBypass -v

# Run with coverage
pixi run pytest test_themida_unpacker_kernel_antidebug_production.py --cov=intellicrack.core.analysis.frida_protection_bypass
```

## Adding Test Binaries

1. Place Themida-protected binaries:
   ```
   tests/test_binaries/themida/sample.exe
   tests/test_binaries/themida/custom/custom_build.exe
   tests/test_binaries/themida/themida_vmprotect/layered.exe
   ```

2. Run tests - they automatically discover all .exe and .dll files

## Test Structure

### Kernel Anti-Debug (6 tests)
- ProcessDebugPort blocking
- Debug object handle spoofing
- Debug flags manipulation
- ThreadHideFromDebugger blocking
- Kernel debugger info spoofing
- Invalid handle detection bypass

### SecureEngine Detection (2 tests)
- Section detection (.themida, .secureng)
- Exception handler detection (SEH, VEH)

### VM Handler Detection (3 tests)
- RISC VM handler tracing
- FISH VM handler detection
- VM exit/OEP identification

### Code Unpacking (3 tests)
- Executable allocation monitoring
- Code unpacking detection
- Unpacked code dumping

### Integrity Checks (1 test)
- Self-read detection

### Edge Cases (3 tests)
- Custom Themida builds
- Themida+VMProtect combinations
- Comprehensive validation

## Expected Outcomes

**With binaries**: All tests PASS (18/18)
**Without binaries**: All tests SKIP (18 skipped)
**Implementation broken**: Tests FAIL with specific error messages

## Common Commands

```bash
# Parallel execution
pixi run pytest test_themida_unpacker_kernel_antidebug_production.py -n auto

# Detailed output
pixi run pytest test_themida_unpacker_kernel_antidebug_production.py -vv

# Stop on first failure
pixi run pytest test_themida_unpacker_kernel_antidebug_production.py -x

# Run only kernel anti-debug tests
pixi run pytest test_themida_unpacker_kernel_antidebug_production.py -k "kernel_antidebug"

# Run only edge case tests
pixi run pytest test_themida_unpacker_kernel_antidebug_production.py::TestThemidaEdgeCases -v
```

## Interpreting Results

**PASSED**: Feature implemented correctly, all validations successful
**SKIPPED**: No test binaries provided (expected without samples)
**FAILED**: Implementation incomplete or non-functional - review error message

## Troubleshooting

**Tests skip unexpectedly**:
- Check `tests/test_binaries/themida/` exists
- Verify .exe/.dll files present
- Ensure file permissions allow reading

**Tests fail with binaries**:
- Review specific assertion failure
- Check if kernel anti-debug hooks present in script
- Verify info class constants (0x07, 0x1E, 0x1F, 0x23, 0x11) in code

**Coverage below 85%**:
- Add missing test cases
- Ensure all code paths exercised
- Check branch coverage for conditional logic

## Documentation

- `THEMIDA_KERNEL_ANTIDEBUG_TEST_SUMMARY.md` - Detailed test documentation
- `THEMIDA_KERNEL_ANTIDEBUG_IMPLEMENTATION_COMPLETE.md` - Implementation summary
- `../../test_binaries/themida/README.md` - Binary sample requirements

## Requirements Validated

✅ Kernel-mode debug port blocking
✅ Driver-level anti-debugging bypass
✅ SecureEngine kernel callback detection
✅ Process handle enumeration defeat
✅ Kernel debug object/handle spoofing
✅ NtQuerySystemInformation bypass
✅ Custom Themida builds handling
✅ Themida+VMProtect combinations

**All 8 requirements from testingtodo.md lines 167-175 are validated.**
