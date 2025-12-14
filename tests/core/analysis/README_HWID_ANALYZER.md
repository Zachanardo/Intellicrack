# Hardware ID Analyzer Production Tests

## Overview

Comprehensive production-grade tests for `intellicrack/core/analysis/hardware_id_analyzer.py` - validates REAL hardware ID analysis capabilities against actual binaries with HWID protection.

**ZERO MOCKS** - All tests use real PE binaries, real system hardware extraction, and genuine pattern detection.

## Test Statistics

- **Total Test Functions**: 43
- **Total Test Classes**: 15
- **Lines of Test Code**: 1,138
- **Lines of Analyzer Code**: 863

## Test Coverage

### 1. TestHardwareIDAnalyzerInitialization (4 tests)

- Validates PE binary loading and parsing
- Tests 32-bit vs 64-bit architecture detection
- Verifies YARA rules initialization

### 2. TestCPUIDDetection (3 tests)

- Detects CPUID instructions (0F A2 opcode) in real binaries
- Validates CPUID check details for bypass planning
- Tests multiple CPUID instruction detection

### 3. TestWMIQueryDetection (4 tests)

- Detects WMI Win32_Processor queries
- Identifies Win32_BaseBoard queries for motherboard serial
- Finds Win32_BIOS queries for BIOS serial
- Verifies correct HWID type identification from WQL queries

### 4. TestRegistryAccessDetection (3 tests)

- Detects MachineGuid registry path access
- Identifies ComputerHardwareId registry queries
- Validates file offsets for registry access points

### 5. TestDiskSerialDetection (3 tests)

- Detects IOCTL_STORAGE_QUERY_PROPERTY (0x002D1400)
- Finds multiple IOCTL codes for disk queries
- Verifies disk serial HWID type identification

### 6. TestNodeLockDetection (3 tests)

- Detects node-locked license patterns (multiple HWID types)
- Identifies distinct HWID types in node-lock patterns
- Assesses protection strength (weak/medium/strong)

### 7. TestSystemHardwareExtraction (4 tests)

- **Extracts REAL CPU ID from current system via WMI**
- **Extracts REAL MAC address from network adapters**
- **Extracts REAL volume serial number from C: drive**
- **Extracts REAL Windows Machine GUID from registry**

### 8. TestValidationPatternDetection (3 tests)

- Detects HWID comparison/validation code patterns
- Validates file offsets for bypass patching
- Assesses code obfuscation level (0-10 scale)

### 9. TestBypassReportGeneration (3 tests)

- Generates actionable bypass strategy reports
- Identifies specific API functions to hook
- Suggests HWID spoofing for node-locked binaries

### 10. TestEntropyCalculation (2 tests)

- Calculates Shannon entropy for encrypted data detection
- Distinguishes high entropy (encrypted) from low entropy (plain)

### 11. TestObfuscationAssessment (2 tests)

- Detects junk/NOP instructions in obfuscated code
- Scores plain code vs obfuscated code correctly

### 12. TestCryptoConstantDetection (3 tests)

- Detects MD5 initialization constants
- Detects SHA1 initialization constants
- No false positives on random data

### 13. TestAnalyzerResourceCleanup (2 tests)

- Verifies proper PE handle cleanup
- Tests multiple analyzer instances on same binary

### 14. TestEdgeCases (2 tests)

- Handles empty/minimal binaries gracefully
- Correctly reports no HWID protection for clean binaries

### 15. TestComprehensiveAnalysis (2 tests)

- **Full end-to-end analysis workflow validation**
- **Tests analysis results consistency across multiple runs**

## Binary Test Fixtures

The tests create REAL PE binaries using Keystone assembler:

1. **cpuid_test.exe** - Contains CPUID instructions for CPU ID testing
2. **wmi_query_test.exe** - Contains WMI query strings (Win32_Processor, Win32_BaseBoard, Win32_BIOS)
3. **registry_test.exe** - Contains registry paths (MachineGuid, ComputerHardwareId)
4. **ioctl_disk_test.exe** - Contains IOCTL codes for disk serial queries
5. **node_locked_test.exe** - Contains multiple HWID checks for node-locking

## Running the Tests

```bash
# Run all HWID analyzer tests
pixi run pytest tests/core/analysis/test_hardware_id_analyzer_production.py -v

# Run specific test class
pixi run pytest tests/core/analysis/test_hardware_id_analyzer_production.py::TestCPUIDDetection -v

# Run with coverage
pixi run pytest tests/core/analysis/test_hardware_id_analyzer_production.py --cov=intellicrack.core.analysis.hardware_id_analyzer --cov-report=html
```

## Hardware ID Analyzer Capabilities

The `HardwareIDAnalyzer` detects:

### HWID Collection Methods

- **CPUID Instructions** - Direct CPU ID extraction via 0F A2 opcode
- **WMI Queries** - Win32_Processor, Win32_BaseBoard, Win32_BIOS
- **Registry Access** - MachineGuid, ComputerHardwareId
- **DeviceIoControl** - Disk serial queries via IOCTL codes
- **SMBIOS Tables** - BIOS/firmware information access
- **Network APIs** - MAC address collection

### HWID Types Detected

- CPU ID (ProcessorId, CPUID signature)
- Disk Serial Numbers
- MAC Addresses
- Motherboard Serial Numbers
- BIOS Serial Numbers
- Volume Serial Numbers
- GPU IDs
- System UUIDs
- Machine GUIDs
- USB Device IDs

### Analysis Features

- **Node-Lock Detection** - Identifies binaries checking multiple HWID types
- **Validation Pattern Detection** - Finds comparison/validation routines
- **Obfuscation Assessment** - Scores code obfuscation level (0-10)
- **Entropy Calculation** - Detects encrypted HWID data
- **Crypto Constant Detection** - Identifies MD5/SHA1/SHA256 hashing
- **Bypass Report Generation** - Provides actionable bypass strategies

## License

Copyright (C) 2025 Zachary Flint
SPDX-License-Identifier: GPL-3.0-or-later
