# Hardware ID Spoofer Production Tests

## Overview

This test suite validates REAL hardware ID spoofing capabilities for defeating hardware-locked license checks. All tests use actual Windows APIs (registry, WMI, ctypes) with NO MOCKS OR STUBS.

**Test File**: `test_hardware_id_spoofer_production.py`
**Module Under Test**: `intellicrack/core/protection_bypass/hardware_id_spoofer.py`
**Total Tests**: 75 comprehensive production-ready tests

## Test Structure

### Test Classes and Coverage

1. **TestHardwareIDSpooferInitialization** (4 tests)
   - Validates spoofer initialization with WMI connection
   - Tests Windows API DLL handle creation
   - Verifies tracking dictionary initialization
   - Confirms driver path configuration

2. **TestCPUIDCollection** (3 tests)
   - Tests real CPU identification via WMI
   - Validates processor signature extraction
   - Tests assembly-level CPUID instruction execution

3. **TestMotherboardInfoCollection** (2 tests)
   - Validates motherboard manufacturer/serial collection
   - Tests system information from registry

4. **TestDiskSerialCollection** (3 tests)
   - Tests physical disk serial enumeration
   - Validates GetVolumeInformationW API usage
   - Verifies volume serial number format

5. **TestMACAddressCollection** (3 tests)
   - Tests network adapter enumeration
   - Validates MAC address format
   - Verifies adapter name extraction

6. **TestBIOSAndSystemInfo** (3 tests)
   - Tests BIOS firmware data collection
   - Validates system UUID retrieval
   - Tests machine GUID from registry

7. **TestGPUAndUSBCollection** (2 tests)
   - Tests GPU/video controller enumeration
   - Validates USB device identification

8. **TestCompleteHardwareCollection** (2 tests)
   - Validates complete hardware info gathering
   - Ensures non-empty real data returned

9. **TestCPUIDSpoofing** (4 tests)
   - Tests custom CPU vendor spoofing
   - Validates random CPU ID generation
   - Verifies spoofed value tracking

10. **TestMACAddressSpoofing** (4 tests)
    - Tests MAC address generation (locally administered)
    - Validates registry NetworkAddress modification
    - Tests adapter selection logic

11. **TestDiskSerialSpoofing** (4 tests)
    - Tests disk serial number generation
    - Validates spoofing to C: drive
    - Verifies spoofed value tracking

12. **TestMotherboardSpoofing** (4 tests)
    - Tests motherboard manufacturer spoofing
    - Validates product/serial generation
    - Tests random value generation

13. **TestSystemUUIDSpoofing** (3 tests)
    - Tests system UUID modification
    - Validates MachineGuid registry updates
    - Tests random UUID generation

14. **TestProfileGeneration** (5 tests)
    - Tests complete profile generation
    - Validates CPU vendor selection
    - Tests MAC/disk serial inclusion
    - Verifies profile uniqueness

15. **TestProfilePersistence** (5 tests)
    - Tests encrypted profile saving
    - Validates profile loading/decryption
    - Tests directory creation
    - Verifies encryption non-reversibility

16. **TestSpoofAllOperation** (4 tests)
    - Tests complete hardware spoofing workflow
    - Validates result status tracking
    - Tests profile application

17. **TestRestoreOperations** (2 tests)
    - Tests hardware ID restoration
    - Validates registry override removal

18. **TestCleanupOperations** (2 tests)
    - Tests driver handle cleanup
    - Validates multiple cleanup calls

19. **TestEdgeCasesAndErrorHandling** (4 tests)
    - Tests invalid vendor handling
    - Tests nonexistent adapter handling
    - Tests invalid drive paths
    - Tests corrupted profile files

20. **TestIntegrationScenarios** (3 tests)
    - Tests complete collect/spoof/restore workflow
    - Tests profile save/load/apply roundtrip
    - Validates hardware ID changes are detectable

21. **TestSecurityAndValidation** (3 tests)
    - Validates MAC addresses never have multicast bit
    - Ensures locally administered bit is set
    - Tests consistent encryption key derivation

22. **TestDriverCodeGeneration** (2 tests)
    - Tests x64 assembly code generation
    - Validates alignment function

23. **TestRandomnessAndUnpredictability** (4 tests)
    - Tests CPU ID uniqueness
    - Tests disk serial uniqueness
    - Tests MAC address uniqueness
    - Validates profile component uniqueness

## Fixtures

### `real_hardware_baseline` (session scope)
Captures baseline hardware information from real system for comparison testing.

### `temp_profile_dir` (function scope)
Provides temporary directory for profile storage testing.

### `hardware_spoofer` (function scope)
Provides fresh HardwareIDSpoofer instance for each test with automatic cleanup.

## Test Execution Requirements

### Windows Platform
All tests require Windows platform:
```python
WINDOWS_ONLY: bool = platform.system() == "Windows"
```

### Administrator Privileges
Some tests require admin privileges:
```python
ADMIN_REQUIRED: bool = not is_admin()
```

Tests requiring admin are marked:
```python
@pytest.mark.skipif(not WINDOWS_ONLY or ADMIN_REQUIRED, reason="Requires Windows admin privileges")
```

### WMI Service
Tests require Windows Management Instrumentation (WMI) service running:
- Service name: `winmgmt`
- If WMI is unavailable, tests gracefully skip with informative message

### Required Windows Components
- Windows Registry access
- Network adapter enumeration
- Disk volume information APIs
- BIOS/SMBIOS data access

## Running the Tests

### Run All Tests
```bash
pixi run pytest tests/core/protection_bypass/test_hardware_id_spoofer_production.py -v
```

### Run Specific Test Class
```bash
pixi run pytest tests/core/protection_bypass/test_hardware_id_spoofer_production.py::TestCPUIDSpoofing -v
```

### Run Tests Requiring Admin
```bash
pixi run pytest tests/core/protection_bypass/test_hardware_id_spoofer_production.py -v -m "not admin_required"
```

### Run with Coverage
```bash
pixi run pytest tests/core/protection_bypass/test_hardware_id_spoofer_production.py --cov=intellicrack.core.protection_bypass.hardware_id_spoofer --cov-report=html
```

## Test Validation Approach

### Real Hardware API Testing
Tests validate actual Windows API functionality:
- WMI queries return real hardware data
- Registry operations modify real system values
- ctypes calls execute real Windows functions

### No Mocks or Stubs
Following CLAUDE.md principles:
- Zero use of unittest.mock or MagicMock
- No simulated hardware responses
- All operations use real system APIs

### Failure Conditions
Tests FAIL when:
- Spoofing doesn't modify actual hardware IDs
- Generated values don't meet format requirements
- Registry/WMI operations don't execute
- Encryption doesn't produce non-plaintext output

### Success Conditions
Tests PASS when:
- Real hardware data is collected successfully
- Spoofing operations complete (when privileges allow)
- Generated values meet format/uniqueness requirements
- Profile save/load roundtrips successfully

## Key Test Scenarios

### Hardware Collection Validation
Tests verify collection of:
- CPU vendor, family, model, stepping, processor ID
- Motherboard manufacturer, product, serial
- Disk drive model, serial number, signature
- Network adapter MAC addresses
- BIOS manufacturer, version, serial
- System UUID, machine GUID
- GPU device IDs
- USB device identification

### Spoofing Capability Validation
Tests verify spoofing of:
- CPU vendor string and processor ID
- MAC addresses with registry modification
- Disk serial numbers via diskpart
- Motherboard data via SMBIOS/WMI
- System UUID and machine GUID

### Profile Management Validation
Tests verify:
- Random profile generation with all components
- Encrypted profile persistence to disk
- Profile decryption and loading
- Profile application across all hardware components

### Error Handling Validation
Tests verify graceful handling of:
- Invalid hardware identifiers
- Nonexistent adapters/drives
- Corrupted profile files
- Missing WMI service
- Insufficient privileges

## Coverage Metrics

### Line Coverage Target
Minimum 85% line coverage of hardware_id_spoofer.py

### Branch Coverage Target
Minimum 80% branch coverage

### Critical Paths Covered
- All hardware collection methods
- All spoofing operations (kernel and usermode)
- Profile generation and persistence
- Restore and cleanup operations

## Type Annotations

All test code includes complete type annotations:
- Function parameters typed
- Return types specified
- Variables annotated where necessary
- Type hints for fixtures

Example:
```python
def test_spoof_cpu_id_accepts_custom_vendor(self, hardware_spoofer: HardwareIDSpoofer) -> None:
    vendor: str = "GenuineIntel"
    processor_id: str = "0000000000000001"
    result: bool = hardware_spoofer.spoof_cpu_id(vendor=vendor, processor_id=processor_id)
```

## Production Readiness Validation

### Tests Prove Real Functionality
- Hardware IDs are actually collected from system
- Spoofing operations modify real registry/system values
- Changes persist across function calls
- Restored values return to original state

### Tests Fail with Broken Code
- Removing collection logic causes test failures
- Breaking spoofing operations causes failures
- Corrupting encryption causes failures
- Invalid formats cause validation failures

### No False Positives
- Tests don't pass with placeholder implementations
- Tests require actual system API calls
- Tests validate real output formats
- Tests verify actual value changes

## Security Considerations

### Locally Administered MACs
Tests verify generated MAC addresses:
- Have locally administered bit set (0x02)
- Don't have multicast bit set (0x01)
- Follow proper 6-octet format

### Encryption Validation
Tests verify profile encryption:
- Produces non-plaintext output
- Uses consistent key derivation
- Supports successful decryption roundtrip

### Privilege Escalation Prevention
Tests appropriately skip when:
- Administrator privileges not available
- WMI service not accessible
- System resources unavailable

## Known Limitations

### WMI Service Dependency
Tests require WMI service (`winmgmt`) running. If unavailable:
- Tests gracefully skip with informative message
- No test failures occur
- Partial functionality still tested via direct registry access

### Administrator Requirements
Some operations require admin privileges:
- Registry modifications (HKLM)
- Service management
- Driver loading
- Network adapter configuration

### Platform Specificity
Tests are Windows-specific:
- Use Windows registry APIs
- Use Windows Management Instrumentation
- Use Windows ctypes structures
- Skip automatically on non-Windows platforms

## Test Maintenance

### Adding New Tests
When adding tests:
1. Follow existing naming convention: `test_<feature>_<scenario>_<expected_outcome>`
2. Include complete type annotations
3. Add descriptive docstring
4. Use real Windows APIs, no mocks
5. Handle privilege/service requirements appropriately

### Updating Tests
When updating tests:
1. Ensure backward compatibility
2. Maintain real API usage (no mocks)
3. Update documentation
4. Verify coverage metrics maintained

## Troubleshooting

### All Tests Skipped
**Symptom**: All tests show "SKIPPED" status

**Cause**: WMI service not available

**Solution**:
```cmd
net start winmgmt
```

### Tests Fail with Permission Errors
**Symptom**: OSError or access denied errors

**Cause**: Insufficient privileges

**Solution**: Run tests as administrator:
```cmd
runas /user:Administrator "pixi run pytest tests/core/protection_bypass/test_hardware_id_spoofer_production.py"
```

### Import Errors
**Symptom**: ImportError for wmi or other modules

**Cause**: Dependencies not installed

**Solution**:
```bash
pixi install
```

## Related Documentation

- **Module Documentation**: `intellicrack/core/protection_bypass/hardware_id_spoofer.py`
- **Project Guidelines**: `CLAUDE.md`
- **Project Standards**: `intellicrack/CLAUDE.md`
