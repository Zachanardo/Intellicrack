# Running VM Protection Unwrapper Tests

## Quick Start

```bash
cd D:\Intellicrack
pixi run pytest tests/plugins/custom_modules/test_vm_protection_unwrapper_production.py -v
```

## Detailed Test Execution

### Run All Tests with Verbose Output

```bash
pixi run pytest tests/plugins/custom_modules/test_vm_protection_unwrapper_production.py -v --tb=short
```

### Run Specific Test Class

```bash
# Test opcode emulation only
pixi run pytest tests/plugins/custom_modules/test_vm_protection_unwrapper_production.py::TestCompleteVirtualCPUOpcodeEmulation -v

# Test VMProtect/Themida handling
pixi run pytest tests/plugins/custom_modules/test_vm_protection_unwrapper_production.py::TestVMProtectThemidaInstructionHandling -v

# Test state tracking
pixi run pytest tests/plugins/custom_modules/test_vm_protection_unwrapper_production.py::TestVirtualRegisterMemoryStateTracking -v

# Test edge cases
pixi run pytest tests/plugins/custom_modules/test_vm_protection_unwrapper_production.py::TestEdgeCasesMixedCodeSelfModifying -v
```

### Run Individual Test

```bash
pixi run pytest tests/plugins/custom_modules/test_vm_protection_unwrapper_production.py::TestCompleteVirtualCPUOpcodeEmulation::test_all_arithmetic_opcodes_execute_correctly -v
```

### Generate Coverage Report

```bash
pixi run pytest tests/plugins/custom_modules/test_vm_protection_unwrapper_production.py --cov=intellicrack.plugins.custom_modules.vm_protection_unwrapper --cov-report=term-missing
```

### Run Tests with Detailed Output

```bash
pixi run pytest tests/plugins/custom_modules/test_vm_protection_unwrapper_production.py -v -s
```

### Run Tests and Show Failures Only

```bash
pixi run pytest tests/plugins/custom_modules/test_vm_protection_unwrapper_production.py --tb=short --maxfail=1
```

## Expected Results

### Successful Test Run

```
test_vm_protection_unwrapper_production.py::TestCompleteVirtualCPUOpcodeEmulation::test_all_arithmetic_opcodes_execute_correctly PASSED
test_vm_protection_unwrapper_production.py::TestCompleteVirtualCPUOpcodeEmulation::test_all_logical_opcodes_execute_correctly PASSED
test_vm_protection_unwrapper_production.py::TestCompleteVirtualCPUOpcodeEmulation::test_all_stack_opcodes_execute_correctly PASSED
...
================================ 38 passed in X.XXs ================================
```

### Test Failures Indicate

- **Incomplete opcode implementation:** VM instructions not fully emulated
- **Broken state tracking:** Registers/memory/flags not maintained
- **Decryption failures:** Key schedules or decryption algorithms broken
- **Missing architecture support:** x86/x64 VM not implemented
- **Edge case failures:** Obfuscation or mixed code not handled

## Interpreting Results

### PASS = Production Ready

- All VM opcodes correctly emulated
- State tracking maintains accuracy
- VMProtect/Themida signatures detected
- Bytecode successfully decrypted
- Native x86 code generated
- Edge cases handled

### FAIL = Implementation Incomplete

- Review test output for specific failures
- Check which functionality is missing
- Implement missing features
- Re-run tests until all pass

## Coverage Targets

- **Minimum Line Coverage:** 85%
- **Minimum Branch Coverage:** 80%
- **Critical Path Coverage:** 100%

### Check Coverage

```bash
pixi run pytest tests/plugins/custom_modules/test_vm_protection_unwrapper_production.py \
    --cov=intellicrack.plugins.custom_modules.vm_protection_unwrapper \
    --cov-report=html \
    --cov-report=term
```

View HTML report: `D:\Intellicrack\htmlcov\index.html`

## Debugging Failed Tests

### Enable Debug Logging

```bash
pixi run pytest tests/plugins/custom_modules/test_vm_protection_unwrapper_production.py -v -s --log-cli-level=DEBUG
```

### Run Single Failing Test

```bash
pixi run pytest tests/plugins/custom_modules/test_vm_protection_unwrapper_production.py::TestClassName::test_name -v -s
```

### Use PDB Debugger

```bash
pixi run pytest tests/plugins/custom_modules/test_vm_protection_unwrapper_production.py --pdb
```

## Test Categories

1. **Opcode Emulation (7 tests)** - All VM instruction types
2. **Instruction Handling (7 tests)** - VMProtect/Themida/Code Virtualizer
3. **State Tracking (7 tests)** - Registers, memory, flags, stack
4. **Obfuscation Detection (4 tests)** - Handler tables, junk code
5. **Native Code Generation (3 tests)** - VM to x86 conversion
6. **Architecture Support (3 tests)** - x86 and x64 VMs
7. **Edge Cases (4 tests)** - Mixed code, self-modifying handlers
8. **Integration (3 tests)** - End-to-end workflows
9. **Key Schedules (4 tests)** - VMProtect version-specific keys

## Common Issues

### Import Errors

```
ImportError: cannot import name 'VMProtectionUnwrapper'
```

**Solution:** Check that `intellicrack.plugins.custom_modules.vm_protection_unwrapper` exports all required classes.

### Fixture Errors

```
fixture 'vm_context' not found
```

**Solution:** Ensure pytest is discovering fixtures correctly. Run with `-v` to see fixture resolution.

### Assertion Failures

```
AssertionError: assert 100 == 125
```

**Solution:** VM instruction implementation is incorrect. Review the failing opcode emulation logic.

### Keystone Errors

```
Exception: Keystone assembler initialization failed
```

**Solution:** Ensure Keystone Engine is installed: `pixi add keystone-engine`

## Validation Checklist

- [ ] All 38 tests pass
- [ ] Coverage ≥ 85% line coverage
- [ ] No test uses mocks/stubs
- [ ] All tests validate real functionality
- [ ] Edge cases covered
- [ ] Integration tests pass
- [ ] No placeholder assertions

## Performance Benchmarks

### Expected Test Runtime

- **Fast:** < 5 seconds (unit tests)
- **Medium:** 5-15 seconds (integration tests)
- **Slow:** > 15 seconds (complete workflow tests)

### Run Performance Tests

```bash
pixi run pytest tests/plugins/custom_modules/test_vm_protection_unwrapper_production.py --durations=10
```

## Continuous Integration

### Pre-Commit Testing

```bash
pixi run pytest tests/plugins/custom_modules/test_vm_protection_unwrapper_production.py --exitfirst
```

### Full Validation

```bash
pixi run pytest tests/plugins/custom_modules/test_vm_protection_unwrapper_production.py \
    -v \
    --cov=intellicrack.plugins.custom_modules.vm_protection_unwrapper \
    --cov-fail-under=85 \
    --tb=short
```

---

**Test File:** `D:\Intellicrack\tests\plugins\custom_modules\test_vm_protection_unwrapper_production.py`

**Total Tests:** 38 production-ready validation tests

**Purpose:** Validate real offensive VM unwrapping capability
