# Runtime Utility Tests

## Overview

This directory contains comprehensive production-grade tests for runtime execution and subprocess management functionality in `intellicrack/utils/runtime/additional_runners.py`.

## Files

- `test_additional_runners.py` - Main test file (1,100+ lines, 75+ tests)
- `TEST_COVERAGE_SUMMARY.md` - Detailed coverage analysis and validation results
- `__init__.py` - Package marker

## Test Philosophy

### NO MOCKS POLICY

All tests in this directory use **real execution**:
- Real subprocess calls (`subprocess.run()`)
- Real file system operations
- Real process enumeration
- Real binary analysis
- Real pattern matching

### Production Validation

Tests validate that functions work on real data:
- Hash computation matches Python's hashlib
- Subprocess execution captures actual output
- Timeouts terminate real processes
- Pattern detection finds actual binary patterns
- Verification analyzes real PE/ELF headers

## Running Tests

### All Tests
```bash
python -m pytest tests/utils/runtime/test_additional_runners.py -v
```

### Specific Test Class
```bash
python -m pytest tests/utils/runtime/test_additional_runners.py::TestExternalCommandExecution -v
```

### With Coverage
```bash
python -m pytest tests/utils/runtime/test_additional_runners.py --cov=intellicrack.utils.runtime.additional_runners --cov-report=html
```

### Single Test
```bash
python -m pytest tests/utils/runtime/test_additional_runners.py::TestFileHashComputation::test_compute_file_hash_sha256 -v
```

## Test Categories

1. **External Command Execution** - subprocess management and output capture
2. **Process Management** - PID retrieval and process monitoring
3. **File Hash Computation** - SHA256/MD5 computation and verification
4. **Dataset Validation** - binary/JSON dataset validation
5. **Hardware Dongle Detection** - USB/process/driver/network dongle detection
6. **Verification Functions** - crack verification and integrity checking
7. **Analysis Runners** - comprehensive binary analysis workflows
8. **Pattern Analysis** - license check pattern detection
9. **Patch Suggestions** - automated patch suggestion generation
10. **Weak Crypto Detection** - weak algorithm and hardcoded key detection
11. **Tool Output Parsing** - external tool output processing
12. **Error Handling** - exception and error condition handling
13. **Concurrent Execution** - simultaneous subprocess management
14. **Resource Cleanup** - file handle and process cleanup
15. **Output Capture** - multiline and large output handling
16. **Real-World Scenarios** - end-to-end workflow testing
17. **Platform-Specific Behavior** - Windows/Unix command execution

## Manual Testing

Critical functions have been manually validated:

### Hash Computation
```bash
cd D:\Intellicrack
.pixi/envs/default/python.exe -c "
import sys; sys.path.insert(0, '.')
from intellicrack.utils.runtime.additional_runners import compute_file_hash
import tempfile, hashlib

f = tempfile.NamedTemporaryFile(delete=False)
f.write(b'test data')
f.close()

computed = compute_file_hash(f.name, 'sha256')
expected = hashlib.sha256(b'test data').hexdigest()
print(f'Match: {computed == expected}')
"
```

### Command Execution
```bash
cd D:\Intellicrack
.pixi/envs/default/python.exe -c "
import sys; sys.path.insert(0, '.')
from intellicrack.utils.runtime.additional_runners import run_external_command

result = run_external_command('cmd /c echo test', timeout=5)
print(f'Success: {result[\"success\"]}')
print(f'Output: {result[\"stdout\"]}')
"
```

### Pattern Analysis
```bash
cd D:\Intellicrack
.pixi/envs/default/python.exe -c "
import sys; sys.path.insert(0, '.')
from intellicrack.utils.runtime.additional_runners import _identify_license_related_calls

calls = ['CheckLicense', 'ValidateKey', 'NormalFunc']
count = _identify_license_related_calls(calls)
print(f'License calls: {count}')
"
```

## Expected Behavior

### Tests MUST Pass
- Hash computation produces correct hashes
- Subprocess execution captures output
- Timeouts terminate processes within limits
- Pattern detection finds actual patterns
- Verification functions analyze real binaries

### Tests MUST Fail When
- Subprocess execution is broken
- Output capture is incomplete
- Timeouts don't work
- Pattern matching is incorrect
- Hash computation is wrong
- Error handling is missing

## Coverage Targets

- Line Coverage: 85%+
- Branch Coverage: 80%+
- Function Coverage: 95%+

## Contributing

When adding new tests:

1. **Use Real Execution** - No mocks for subprocess/file operations
2. **Validate Outputs** - Check actual results, not just "runs without error"
3. **Test Failures** - Ensure tests fail when code is broken
4. **Test Errors** - Include error handling test cases
5. **Test Performance** - Validate timeouts and resource cleanup
6. **Document Expected Behavior** - Use clear docstrings

## Dependencies

Tests require:
- pytest
- pytest-timeout (for timeout testing)
- tempfile (for temporary file creation)
- subprocess (for command execution)
- hashlib (for hash validation)

All dependencies are included in the standard Intellicrack environment.
