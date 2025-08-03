# 📦 Test Fixtures Documentation

## Overview
This directory contains all test data, software samples, and fixtures used for testing Intellicrack's capabilities. Everything here uses REAL software and data - no mocks or placeholders.

## Directory Structure

### 🛠️ PORTABLE_SANDBOX/
**Purpose**: Zero-installation analysis tools for validating Intellicrack's output
- **Process Hacker**: System monitoring and process analysis
- **PEStudio**: Binary structure verification  
- **ExeinfoPE**: Protection scheme detection validation
- **Total Size**: 19.1MB of portable tools

### 💾 binaries/
**Purpose**: Real software samples organized by type and protection

#### pe/ (Portable Executable - Windows)
- **legitimate/**: Clean software (Firefox, VLC, Notepad++, 7-Zip)
- **protected/**: DRM-protected samples with various schemes
- **real_protected/**: 361MB of real commercial software
  - WinRAR Trial (3.5MB)
  - IDA Free (105MB)
  - CCleaner (73MB)
  - Steam Client (2.3MB)
  - Epic Games (178MB)
  - UPX Packer (598KB)

#### architectures/
- **arm32/**: ARM 32-bit samples
- **arm64/**: ARM 64-bit samples
- **mips/**: MIPS architecture samples
- **powerpc/**: PowerPC samples
- **riscv/**: RISC-V samples

#### mobile/
- **android/**: APK samples with protection
- **ios/**: iOS app samples

#### size_categories/
- **tiny_4kb/**: Minimal executables
- **small_1mb/**: Small utilities
- **medium_100mb/**: Standard applications
- **large_1gb/**: Enterprise software
- **massive_10gb/**: Large games/suites

### 🌐 network_captures/
**Purpose**: Real DRM protocol communications in PCAP format
- Adobe activation sequences
- Denuvo authentication
- FlexLM license validation
- HASP dongle communication
- Steam DRM protocols
- Custom DRM implementations

### 🔧 exploitation_tests/
**Purpose**: Safe exploit samples for testing detection
- **buffer_overflow/**: Stack/heap overflow patterns
- **rop_jop_chains/**: Return-oriented programming
- **kernel_exploits/**: Privilege escalation samples
- **protection_bypass/**: Anti-debug/anti-tamper bypasses

### 🤖 ai_tests/
**Purpose**: AI model testing scenarios
- **multi_model_consensus/**: Cross-model validation
- **obfuscated_code_analysis/**: Deobfuscation tests
- **large_binary_analysis/**: Performance benchmarks
- **cross_architecture_scripts/**: Multi-arch generation

### 🔒 vulnerable_samples/
**Purpose**: Intentionally vulnerable binaries for testing
- Buffer overflow vulnerabilities
- Format string bugs
- Integer overflows
- Race conditions
- Heap corruption

## Usage Guidelines

### Running Portable Tools
```bash
# From PORTABLE_SANDBOX directory
RUN_processhacker_portable.bat
RUN_pestudio_portable.bat
RUN_exeinfope_portable.bat
```

### Accessing Test Binaries
```python
# In test code
from tests.base_test import BaseTest

class TestProtection(BaseTest):
    def test_winrar_trial(self):
        path = self.get_fixture_path('binaries/pe/real_protected/winrar_trial.exe')
        # Test with real 3.5MB WinRAR trial
```

### Network Capture Analysis
```python
# Analyzing DRM protocols
pcap_path = self.get_fixture_path('network_captures/steam_drm.pcap')
packets = parse_pcap(pcap_path)
# Validate DRM handshake
```

## File Naming Conventions

### Binary Files
- `{software}_trial.exe` - Trial/demo versions
- `{software}_protected.exe` - DRM protected
- `{software}_packed.exe` - Packed/compressed
- `{software}_free.exe` - Feature-limited freeware

### Network Captures
- `{protocol}_capture.pcap` - Standard capture
- `{protocol}_activation.pcap` - Activation sequence
- `{protocol}_validation.pcap` - License check

### Exploit Samples
- `{type}_overflow_{n}.exe` - Overflow variants
- `{technique}_{target}.bin` - Exploit techniques
- `bypass_{protection}.exe` - Bypass samples

## Maintenance

### Adding New Fixtures
1. Place file in appropriate category
2. Document protection/purpose
3. Update size totals
4. Add test case
5. Verify isolation

### Validation Checklist
- [ ] Real software/data only
- [ ] Properly categorized
- [ ] Documentation included
- [ ] Test case exists
- [ ] No system modifications

## Security Notes

⚠️ **IMPORTANT**: All samples are for testing only
- Run in isolated environment
- Do not execute exploit samples directly
- Commercial software for analysis only
- Respect software licenses

## Statistics

| Category | Count | Total Size |
|----------|-------|------------|
| Portable Tools | 3 | 19.1MB |
| Commercial Software | 6 | 361MB |
| Network Captures | 12 | 2.3MB |
| Exploit Samples | 20+ | 5MB |
| **TOTAL** | **41+** | **387.4MB** |

---
Last Updated: 2024-01-25