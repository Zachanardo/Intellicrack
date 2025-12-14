# Radare2 Emulator Tests - Quick Start Guide

## Test File Location

```
tests/core/analysis/test_radare2_emulator_production.py
```

## Quick Run Commands

### Run All 48 Tests

```bash
pytest tests/core/analysis/test_radare2_emulator_production.py -v
```

### Run Specific Categories

```bash
# ESIL emulation (5 tests)
pytest tests/core/analysis/test_radare2_emulator_production.py::TestESILEmulationInitialization -v

# Register management (4 tests)
pytest tests/core/analysis/test_radare2_emulator_production.py::TestRegisterStateManagement -v

# Memory operations (4 tests)
pytest tests/core/analysis/test_radare2_emulator_production.py::TestMemoryReadWriteEmulation -v

# Instruction execution (5 tests)
pytest tests/core/analysis/test_radare2_emulator_production.py::TestInstructionSteppingExecution -v

# License validation patterns (4 tests)
pytest tests/core/analysis/test_radare2_emulator_production.py::TestLicenseValidationRoutineEmulation -v

# Unicorn engine (5 tests)
pytest tests/core/analysis/test_radare2_emulator_production.py::TestUnicornEngineIntegration -v

# Symbolic execution (3 tests)
pytest tests/core/analysis/test_radare2_emulator_production.py::TestSymbolicExecution -v

# Exploit generation (5 tests)
pytest tests/core/analysis/test_radare2_emulator_production.py::TestExploitGeneration -v
```

## Test Statistics

- **Total Tests**: 48
- **Test Categories**: 19
- **Lines of Code**: 1,200+
- **Coverage Target**: 85%+ line, 80%+ branch

## Test Requirements

### Real Binaries Used

All tests run on **REAL Windows system binaries**:

- `C:\Windows\System32\notepad.exe`
- `C:\Windows\System32\kernel32.dll`
- `C:\Windows\System32\ntdll.dll`
- `C:\Windows\System32\calc.exe`

### Dependencies

- `r2pipe` - Radare2 Python bindings
- `unicorn` - CPU emulator engine
- `z3-solver` - SMT constraint solver
- `pytest` - Testing framework

## Test Breakdown by Category

| Category                | Tests | Focus Area                                            |
| ----------------------- | ----- | ----------------------------------------------------- |
| ESIL Initialization     | 5     | Binary opening, VM setup, architecture detection      |
| Register Management     | 4     | Register read/write, state tracking                   |
| Memory Operations       | 4     | Memory read/write, stack initialization               |
| Instruction Stepping    | 5     | Code execution, path tracking                         |
| License Validation      | 4     | CMP, XOR, conditional branches                        |
| Stack Operations        | 4     | PUSH, POP, CALL, RET                                  |
| Conditional Branches    | 3     | Jump detection, constraint extraction                 |
| Loop Detection          | 2     | Loop identification, infinite loop prevention         |
| Unicorn Engine          | 5     | Engine setup, section mapping, execution              |
| Symbolic Execution      | 3     | Path discovery, constraint generation                 |
| Taint Analysis          | 2     | Taint propagation, register tracking                  |
| Constraint Solving      | 3     | Z3 solver integration                                 |
| Vulnerability Detection | 3     | Dangerous functions, overflow patterns                |
| Exploit Generation      | 5     | Buffer overflow, format string, UAF, integer overflow |
| Performance             | 3     | Execution time benchmarks                             |
| Edge Cases              | 6     | Error handling, invalid inputs                        |
| Memory Mapping          | 2     | Section mapping, access control                       |
| State Snapshots         | 2     | State capture, metadata preservation                  |
| Complex Scenarios       | 3     | Multi-branch, loops+calls, optimized code             |

## Critical Test Highlights

### Most Important Tests

1. **test_emulator_opens_real_binary_successfully**
    - Validates core functionality works
    - Tests radare2 integration
    - Verifies binary loading

2. **test_esil_steps_through_instructions**
    - Proves emulation actually executes code
    - Tracks execution path
    - Validates instruction-by-instruction stepping

3. **test_unicorn_emulation_executes_instructions**
    - Validates Unicorn engine integration
    - Tests alternative emulation backend
    - Proves multi-engine support

4. **test_generates_buffer_overflow_exploit**
    - Validates exploit generation works
    - Creates real exploit primitives
    - Tests shellcode generation

5. **test_symbolic_execution_finds_paths**
    - Validates symbolic execution works
    - Tests Z3 integration
    - Proves path discovery capability

## Expected Test Results

### All Tests Pass Scenario

```
==================== 48 passed in 120.45s ====================
```

### Typical Failures

**Binary Not Found**:

```
AssertionError: notepad.exe must exist
```

→ Run on Windows with standard system directories

**Radare2 Not Installed**:

```
ModuleNotFoundError: No module named 'r2pipe'
```

→ Install radare2 and r2pipe: `pip install r2pipe`

**Timeout Exceeded**:

```
Test exceeded timeout
```

→ Performance regression - check emulation implementation

## Test Validation Approach

### How Tests Prove Functionality

**NO MOCKS** - Every test validates REAL capability:

1. ✓ Opens real Windows binaries
2. ✓ Executes actual instructions
3. ✓ Modifies real registers
4. ✓ Reads/writes real memory
5. ✓ Generates real exploit payloads
6. ✓ Solves real constraints with Z3

### What Tests Verify

- **ESIL VM**: Initializes and executes ESIL instructions
- **Unicorn Engine**: Maps sections and emulates code
- **Symbolic Execution**: Discovers paths and generates constraints
- **Taint Analysis**: Tracks data propagation
- **Exploit Generation**: Creates buffer overflow, format string, UAF, integer overflow exploits
- **Performance**: Completes within specified timeouts

## Test Performance

### Expected Execution Times

- **Fast Tests** (< 1s): Register management, constraint solving
- **Medium Tests** (1-3s): Instruction stepping, stack operations
- **Slow Tests** (3-10s): Symbolic execution, exploit generation
- **Benchmark Tests** (10-20s): Performance validation

**Total Suite**: ~90-180 seconds

## Coverage Report

### Generate Coverage

```bash
pytest tests/core/analysis/test_radare2_emulator_production.py \
    --cov=intellicrack.core.analysis.radare2_emulator \
    --cov-report=html \
    --cov-report=term-missing
```

### View Coverage

```bash
# Open HTML report
start htmlcov/index.html  # Windows
```

### Expected Coverage

- **Line Coverage**: 85%+
- **Branch Coverage**: 80%+
- **Function Coverage**: 90%+

## Debugging Failed Tests

### Enable Verbose Output

```bash
pytest tests/core/analysis/test_radare2_emulator_production.py -vv -s
```

### Run Single Failing Test

```bash
pytest tests/core/analysis/test_radare2_emulator_production.py::TestClassName::test_method_name -vv
```

### Enable Pytest Debugging

```bash
pytest tests/core/analysis/test_radare2_emulator_production.py --pdb
```

### Check Test Logs

```bash
pytest tests/core/analysis/test_radare2_emulator_production.py -v --log-cli-level=DEBUG
```

## Common Test Issues

### Issue 1: Radare2 Analysis Timeout

**Symptom**: Tests hang during binary analysis
**Solution**: Reduce analysis depth or use smaller binaries

### Issue 2: Unicorn Engine Crash

**Symptom**: Segmentation fault during Unicorn emulation
**Solution**: Check section mapping alignment (must be page-aligned)

### Issue 3: Z3 Solver Timeout

**Symptom**: Symbolic execution tests timeout
**Solution**: Reduce max_paths parameter or constraint complexity

### Issue 4: Memory Access Violation

**Symptom**: Tests crash with memory errors
**Solution**: Verify memory regions are properly mapped before access

## CI/CD Integration

### GitHub Actions

```yaml
- name: Run Radare2 Emulator Tests
  run: |
      pytest tests/core/analysis/test_radare2_emulator_production.py \
        -v \
        --cov=intellicrack.core.analysis.radare2_emulator \
        --cov-report=xml \
        --junit-xml=test-results.xml
```

### Jenkins

```groovy
stage('Radare2 Emulator Tests') {
    steps {
        sh '''
            pytest tests/core/analysis/test_radare2_emulator_production.py \
                -v \
                --cov \
                --junit-xml=results.xml
        '''
    }
}
```

## Test Fixtures Reference

### Available Fixtures

```python
emulator_notepad: Radare2Emulator     # notepad.exe
emulator_kernel32: Radare2Emulator    # kernel32.dll
emulator_ntdll: Radare2Emulator       # ntdll.dll
emulator_calc: Radare2Emulator        # calc.exe
```

### Fixture Usage

```python
def test_example(emulator_notepad: Radare2Emulator) -> None:
    """Test using notepad.exe fixture."""
    result = emulator_notepad.emulate_esil(0x1000, 10)
    assert result.success
```

## Test Code Quality

### Standards Enforced

- ✓ Complete type annotations
- ✓ Descriptive test names
- ✓ No mocks or stubs
- ✓ Real binary operations only
- ✓ Concrete value assertions
- ✓ Performance guarantees

### Code Review Checklist

- [ ] All functions have type hints
- [ ] All tests use real binaries
- [ ] No `unittest.mock` imports
- [ ] Assertions check actual values
- [ ] Test names describe expected behavior
- [ ] Performance timeouts specified

## Maintenance

### When to Update Tests

- **New emulation features**: Add corresponding test
- **New exploit types**: Add generation test
- **Performance improvements**: Update timeout expectations
- **Bug fixes**: Add regression test

### Adding New Tests

```python
def test_new_feature_validates_correctly(emulator_notepad: Radare2Emulator) -> None:
    """Test description: what and why."""
    # Arrange
    start_addr: int = 0x1000

    # Act
    result: EmulationResult = emulator_notepad.emulate_esil(start_addr, 10)

    # Assert
    assert result.success
    assert len(result.execution_path) > 0
```

## Quick Reference Commands

```bash
# Run all tests
pytest tests/core/analysis/test_radare2_emulator_production.py -v

# Run with coverage
pytest tests/core/analysis/test_radare2_emulator_production.py --cov --cov-report=html

# Run specific category
pytest tests/core/analysis/test_radare2_emulator_production.py::TestExploitGeneration -v

# Run single test
pytest tests/core/analysis/test_radare2_emulator_production.py::TestESILEmulationInitialization::test_emulator_opens_real_binary_successfully -v

# Debug failing test
pytest tests/core/analysis/test_radare2_emulator_production.py::TestName::test_name --pdb

# Parallel execution
pytest tests/core/analysis/test_radare2_emulator_production.py -n 4
```

## Success Criteria

Tests prove production-readiness when:

- ✓ All 48 tests pass
- ✓ Coverage ≥ 85% line, ≥ 80% branch
- ✓ Total runtime < 180 seconds
- ✓ No memory leaks detected
- ✓ All exploits generate valid payloads
- ✓ Emulation completes on real binaries

## Support

For test failures or questions:

1. Check this quick start guide
2. Review full documentation: `README_RADARE2_EMULATOR_TESTS.md`
3. Examine test implementation
4. Verify radare2 installation
5. Confirm Windows binaries exist

**Remember**: These tests use REAL binaries and validate REAL functionality. If tests pass, the emulator works.
