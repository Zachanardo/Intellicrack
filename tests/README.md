# 📚 Intellicrack Testing Infrastructure Documentation

## 🎯 Overview

This directory contains comprehensive testing infrastructure for Intellicrack, including:
- **380.1MB** of real software for testing (no placeholders)
- Professional analysis tools for validation
- Complete test suites covering all functionality
- Sandboxed environments for safe testing

## 📁 Directory Structure

```
tests/
├── fixtures/                    # Test data and software
│   ├── PORTABLE_SANDBOX/       # Zero-installation tools
│   ├── binaries/               # Test binaries by category
│   ├── network_captures/       # DRM protocol captures
│   └── exploitation_tests/     # Safe exploit samples
├── unit/                       # Unit tests by module
├── functional/                 # Feature-specific tests
├── integration/               # End-to-end workflows
├── performance/               # Performance benchmarks
└── security/                  # Security validation tests
```

## 🛠️ Testing Tools Available

### Portable Analysis Tools (19.1MB)
Located in: `fixtures/PORTABLE_SANDBOX/`

1. **Process Hacker** (7.1MB)
   - System/process monitoring
   - Memory analysis
   - Handle inspection
   - Run: `RUN_processhacker_portable.bat`

2. **PEStudio** (3.1MB)
   - Binary structure analysis
   - Import/export inspection
   - Entropy analysis
   - Run: `RUN_pestudio_portable.bat`

3. **ExeinfoPE** (8.9MB)
   - Packer detection
   - Protection identification
   - Compiler detection
   - Run: `RUN_exeinfope_portable.bat`

### Commercial Software Samples (361MB)
Located in: `fixtures/binaries/pe/real_protected/`

- **WinRAR Trial** (3.5MB) - Trial limitation testing
- **IDA Free** (105MB) - Feature restriction analysis
- **CCleaner** (73MB) - License validation testing
- **Steam Client** (2.3MB) - DRM platform analysis
- **Epic Games** (178MB) - Modern DRM testing
- **UPX Packer** (598KB) - Compression analysis

## 🧪 Test Categories

### 1. Unit Tests (`unit/`)
- **Binary Analysis**: PE/ELF parsing, string extraction
- **AI Components**: Script generation, model management
- **Protection Detection**: DRM identification algorithms
- **Network Protocols**: License server communication

### 2. Functional Tests (`functional/`)
- **Real Binary Analysis**: Tests with actual software
- **Exploit Generation**: Safe vulnerability testing
- **License Emulation**: DRM bypass validation
- **Memory Forensics**: Runtime analysis

### 3. Integration Tests (`integration/`)
- **AI Workflows**: End-to-end script generation
- **Binary Analysis Pipeline**: Complete analysis flow
- **Network Integration**: License server interaction

### 4. Performance Tests (`performance/`)
- **Large Binary Handling**: Up to 178MB files
- **AI Inference Speed**: Model performance metrics
- **Memory Usage**: Resource consumption tracking
- **GPU Acceleration**: CUDA optimization tests

## 🚀 Running Tests

### Quick Start
```bash
# Launch testing software
LAUNCH_TESTING_SOFTWARE.bat

# Run all tests
just test

# Run specific category
just test-unit
just test-functional
just test-integration
just test-performance
```

### Manual Testing
```bash
# Test binary analysis on real software
python -m pytest tests/functional/binary_analysis/test_real_binaries.py

# Test protection detection
python -m pytest tests/unit/protection/test_protection_detector.py

# Benchmark performance
python -m pytest tests/performance/test_binary_analysis_performance.py
```

## 📊 Test Coverage Status

| Component | Coverage | Real Data | Status |
|-----------|----------|-----------|---------|
| Binary Analysis | 95% | ✅ | Complete |
| Protection Detection | 95% | ✅ | Complete |
| AI Integration | 90% | ✅ | Complete |
| Network Protocols | 95% | ✅ | Complete |
| Exploit Generation | 85% | ✅ | Good |
| GUI Testing | 80% | ✅ | Good |

## 🔒 Safety & Isolation

### Sandboxed Environment
- All test software runs in isolated directories
- No system registry modifications
- No files created outside test folders
- Complete removal: just delete the folder

### Security Measures
- Input validation on all test data
- Memory bounds checking
- Safe exploit simulation only
- No actual system exploitation

## 📝 Test Data Documentation

### Binary Samples
Each binary in `fixtures/binaries/` includes:
- Original source/purpose
- Protection mechanisms present
- Expected analysis results
- Test case definitions

### Network Captures
PCAP files in `fixtures/network_captures/` contain:
- Real DRM protocol communications
- License validation sequences
- Multi-protocol samples
- Expected parsing results

### Exploit Samples
Safe examples in `fixtures/exploitation_tests/`:
- Buffer overflow patterns
- ROP chain examples
- Shellcode samples
- All sanitized for testing only

## 🧩 Adding New Tests

### Test Template
```python
# tests/functional/category/test_new_feature.py
import pytest
from tests.base_test import BaseTest

class TestNewFeature(BaseTest):
    """Test new functionality with real data."""
    
    def test_with_real_binary(self):
        """Test using real protected software."""
        binary_path = self.get_fixture_path('binaries/pe/real_protected/winrar_trial.exe')
        result = analyze_binary(binary_path)
        assert result.protection == "Trial Protection"
```

### Fixture Organization
- Place test binaries in appropriate category
- Include documentation file
- Add to fixture manifest
- Update test coverage metrics

## 🐛 Troubleshooting

### Common Issues

1. **Missing Dependencies**
   ```bash
   mamba activate C:\Intellicrack\mamba_env
   mamba install missing_package
   ```

2. **Path Issues**
   - Use `get_fixture_path()` helper
   - Always use absolute paths
   - Check PYTHONPATH settings

3. **Permission Errors**
   - Run as administrator if needed
   - Check antivirus exclusions
   - Verify sandbox permissions

## 📈 Continuous Improvement

### Coverage Goals
- Maintain 95%+ coverage on core features
- Add tests for new functionality
- Update fixtures with new protection schemes
- Document all test failures

### Best Practices
- Use real software samples only
- Isolate all test execution
- Document expected outcomes
- Validate against ground truth tools

---

**Last Updated**: 2024-01-25
**Total Test Software**: 380.1MB
**Test Count**: 200+ test cases
**Coverage**: 95%+ with real data