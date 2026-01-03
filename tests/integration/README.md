# Intellicrack Integration Tests

Comprehensive integration test suite validating complete end-to-end workflows for defeating software licensing protections.

## Overview

These integration tests verify that Intellicrack's major components work together correctly to achieve real-world license cracking goals. Unlike unit tests that test individual functions, these tests validate complete workflows from binary analysis through successful bypass.

## Test Philosophy

**Production Validation Only:**
- Tests MUST validate against real protected binaries or actual system resources
- Tests MUST fail if any component in the workflow is broken
- NO mocks, stubs, or placeholder assertions
- Tests prove Intellicrack actually works

## Test Structure

```
tests/integration/
├── conftest.py                              # Shared fixtures and utilities
├── test_complete_workflows_production.py    # End-to-end workflow tests
├── test_cross_component_integration.py      # Multi-component integration
├── test_error_recovery_integration.py       # Error handling and edge cases
├── test_real_world_scenarios.py            # Real-world usage scenarios
└── real_binary_tests/                       # Real protected binaries
    ├── binaries/
    │   ├── vmprotect/
    │   ├── themida/
    │   ├── hasp/
    │   ├── flexlm/
    │   └── ...
    └── README.md
```

## Test Categories

### 1. Complete Workflows (`test_complete_workflows_production.py`)

Tests validating complete end-to-end workflows:

**Binary Analysis → Keygen Generation:**
- VMProtect detection → algorithm extraction → key generation → validation
- Themida analysis → license check identification → patching
- Custom algorithm reverse engineering → constraint solving → keygen

**Network Protocol → License Server Emulation:**
- FlexLM protocol parsing → response generation → client acceptance
- HASP dongle emulation → command processing → session management
- SSL interception → traffic modification → license injection

**Hardware Spoofing → License Bypass:**
- Hardware fingerprint collection → spoofing → bypass validation
- Combined dongle emulation + hardware spoofing
- Trial period detection → reset → time freezing

**Performance & Scalability:**
- Bulk keygen generation (1000 keys in <60s)
- Concurrent license server requests (100 simultaneous)
- Large binary analysis (>10MB in <30s)

### 2. Cross-Component Integration (`test_cross_component_integration.py`)

Tests validating integration between different subsystems:

**Static ↔ Dynamic Analysis Integration:**
- Static analysis identifies functions → dynamic instrumentation targets them
- Protection detection guides bypass strategy selection
- Crypto detection informs keygen algorithm configuration

**Network Protocol Component Integration:**
- Protocol parser → response generator → interceptor chain
- License server emulation → client verification
- SSL interception → protocol modification

**Hardware Bypass Integration:**
- Hardware spoofing coordinates with dongle emulation
- Trial reset + hardware spoof combined bypass
- Hardware fingerprint consistency across components

**Patching & Analysis Integration:**
- Analysis identifies patch targets → patcher applies modifications
- Keygen fallback to patching when algorithm extraction fails

### 3. Error Recovery (`test_error_recovery_integration.py`)

Tests validating graceful error handling:

**Binary Analysis Error Recovery:**
- Corrupted PE headers handled safely
- Truncated binaries don't cause crashes
- Binaries with no algorithms handled gracefully
- Re-patching doesn't corrupt binaries

**Network Protocol Error Recovery:**
- Malformed protocol requests handled
- Invalid API sequences managed
- Connection failures recovered from

**Hardware Spoofing Error Recovery:**
- Permission denied handled gracefully
- State restored after partial failures
- Concurrent operations don't conflict

**Trial Reset Error Recovery:**
- Missing registry keys handled
- Restore failures managed
- Non-existent processes handled

**Edge Cases:**
- Zero-length binaries
- Extremely large binaries (100MB+)
- Unicode paths and filenames
- Concurrent multi-binary analysis

### 4. Real-World Scenarios (`test_real_world_scenarios.py`)

Tests simulating actual usage patterns:

**Standalone Application Cracking:**
- Crack shareware with simple serial validation
- Crack VMProtect-protected commercial software
- Extend trial period via registry manipulation

**Network-Licensed Application Cracking:**
- Emulate FlexLM server for engineering software
- MITM HTTPS license validation for cloud licensing

**Dongle-Protected Software Cracking:**
- Emulate HASP dongle for professional software
- Combined hardware spoofing + dongle emulation

**Multi-Layer Protection:**
- Defeat applications with multiple protection layers
- Prioritized bypass strategy execution

## Running Tests

### All Integration Tests
```bash
pytest tests/integration/ -v
```

### Specific Test File
```bash
pytest tests/integration/test_complete_workflows_production.py -v
```

### Specific Test Class
```bash
pytest tests/integration/test_complete_workflows_production.py::TestBinaryAnalysisToKeygenWorkflow -v
```

### Specific Test Method
```bash
pytest tests/integration/test_complete_workflows_production.py::TestBinaryAnalysisToKeygenWorkflow::test_vmprotect_analysis_extraction_keygen_generation -v
```

### With Coverage
```bash
pytest tests/integration/ -v --cov=intellicrack --cov-report=html
```

### Skip Slow Tests
```bash
pytest tests/integration/ -v -m "not slow_integration"
```

### Run Only Tests With Real Binaries
```bash
pytest tests/integration/ -v -m "requires_real_binaries"
```

### Parallel Execution
```bash
pytest tests/integration/ -v -n auto
```

## Test Markers

Tests are marked with pytest markers for selective execution:

- `@pytest.mark.requires_real_binaries` - Needs real protected binaries
- `@pytest.mark.requires_admin` - Needs administrator privileges
- `@pytest.mark.requires_frida` - Needs Frida framework
- `@pytest.mark.slow_integration` - Takes >10 seconds
- `@pytest.mark.network_dependent` - Requires network connectivity

### Skip Tests Requiring Real Binaries
```bash
pytest tests/integration/ -v -m "not requires_real_binaries"
```

### Skip Tests Requiring Admin
```bash
pytest tests/integration/ -v -m "not requires_admin"
```

## Fixtures

### Common Fixtures (from `conftest.py`)

**Binary and Data:**
- `real_binary_root` - Path to real protected binaries
- `test_data_root` - Path to test data files
- `temp_workspace` - Auto-cleaning temporary workspace
- `sample_pe_binary` - Minimal valid PE binary

**Network:**
- `dynamic_port` - Dynamically allocated TCP port
- `network_protocol_samples` - Sample protocol packets
- `sample_flexlm_license` - Sample FlexLM license file
- `sample_hasp_commands` - Sample HASP dongle commands

**Hardware:**
- `mock_hardware_profile` - Mock hardware identifiers
- `test_license_keys` - Collection of test license keys

**Utilities:**
- `binary_hash_validator` - Validates binary integrity
- `license_protocol_validator` - Validates protocol responses
- `skip_if_no_real_binaries` - Skip if no binaries available
- `skip_if_no_admin_privileges` - Skip if not admin

## Test Data Requirements

### Real Protected Binaries

Integration tests work best with real protected binaries. Place protected executables in:

```
tests/integration/real_binary_tests/binaries/
├── vmprotect/
│   ├── v1/
│   ├── v2/
│   └── v3/
├── themida/
├── hasp/
├── flexlm/
└── ...
```

See `tests/integration/real_binary_tests/README.md` for:
- Legal sources for obtaining protected binaries
- How to structure binary directories
- Creating binary manifests

**Without Real Binaries:**
- Tests automatically skip with clear messages
- Basic functionality still validated with minimal test binaries
- CI/CD pipelines can run without real binaries

## Coverage Requirements

Integration tests must achieve:
- **Minimum 85% line coverage** of integrated components
- **Minimum 80% branch coverage** of workflow paths
- **100% critical path coverage** for main workflows

## Performance Benchmarks

Integration tests validate performance meets thresholds:

| Operation | Threshold | Test |
|-----------|-----------|------|
| Binary analysis | < 5s | `test_large_binary_analysis_performance` |
| Keygen single | < 0.5s | Per-key generation time |
| Keygen bulk (100) | < 10s | `test_bulk_keygen_performance` |
| Protection detection | < 2s | Per binary |
| License server response | < 0.1s | Per request |
| Hardware spoof apply | < 1s | Spoof operation |

## CI/CD Integration

### GitHub Actions Example

```yaml
- name: Run Integration Tests
  run: |
    pytest tests/integration/ \
      -v \
      -m "not requires_real_binaries and not requires_admin" \
      --cov=intellicrack \
      --cov-report=xml \
      --junitxml=integration-results.xml
```

### With Real Binaries (Secure Environment)

```yaml
- name: Run Full Integration Tests
  run: |
    pytest tests/integration/ \
      -v \
      --cov=intellicrack \
      --cov-report=xml
  env:
    INTELLICRACK_BINARIES_PATH: ${{ secrets.BINARIES_PATH }}
```

## Troubleshooting

### Tests Skip Due to Missing Binaries

**Issue:** Tests skip with "No real binaries available"

**Solution:** Place protected executables in `tests/integration/real_binary_tests/binaries/`

### Tests Skip Due to Missing Admin Privileges

**Issue:** Tests skip with "Test requires administrator privileges"

**Solution:** Run test suite with elevated privileges:
```bash
# Windows (as Administrator)
pytest tests/integration/ -v -m requires_admin
```

### Tests Fail on Hardware Spoofing

**Issue:** Hardware spoofing tests fail with permission errors

**Solution:**
1. Run tests as administrator
2. Or skip hardware tests: `pytest -m "not requires_admin"`
3. Check Windows UAC settings

### Tests Timeout on Large Binaries

**Issue:** Large binary tests timeout

**Solution:**
1. Increase timeout: `pytest --timeout=60`
2. Or skip slow tests: `pytest -m "not slow_integration"`

## Contributing New Integration Tests

When adding new integration tests:

1. **Test Real Capability:** Validate actual offensive capability, not just execution
2. **Use Real Data:** Test against real binaries or real system resources
3. **Complete Workflows:** Test entire workflows, not isolated components
4. **Fail Correctly:** Tests MUST fail if functionality is broken
5. **Document Scenario:** Explain what real-world scenario the test validates
6. **Add Markers:** Mark tests appropriately (requires_binaries, slow, etc.)

### Example Integration Test Template

```python
def test_specific_workflow_integration(self, fixtures) -> None:
    """Validate [specific workflow description].

    Workflow:
    1. [Step 1]
    2. [Step 2]
    3. [Step 3]
    4. [Verification]

    This test FAILS if [failure condition].
    """
    # Setup
    resource = setup_test_resource()

    # Execute workflow
    result = execute_complete_workflow(resource)

    # Validate real capability
    assert result.success, "Workflow failed"
    assert verify_real_bypass_works(result), "Bypass doesn't work"
```

## License

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
