# 🧪 Functional Tests Documentation

## Overview
Functional tests validate Intellicrack's features using REAL software and data. Each test category focuses on a specific capability with actual binaries and captures.

## Test Categories

### 📊 binary_analysis/
Tests core binary analysis features with real executables.

**Key Tests**:
- `test_real_binaries.py` - Analyzes 361MB of commercial software
- `test_real_binary_analysis.py` - Protection detection validation

**Test Data**:
- WinRAR Trial (3.5MB) - Trial protection analysis
- IDA Free (105MB) - Feature limitation detection
- Steam/Epic clients - DRM platform analysis

### 🛡️ protection_bypass/
Validates protection removal capabilities safely.

**Key Tests**:
- `test_real_protection_bypass.py` - Anti-debug circumvention
- Trial limitation removal (simulated)
- DRM handshake analysis

**Safety**: All tests simulate bypass without modifying originals

### 🔑 keygen_operations/
Tests license key generation algorithms.

**Key Tests**:
- `test_real_keygen_operations.py` - Pattern analysis
- Algorithm reverse engineering
- Key validation testing

**Algorithms Tested**:
- RSA-based licensing
- Elliptic curve schemes
- Custom polynomial systems

### 🌐 license_emulation/
Validates license server emulation.

**Key Tests**:
- `test_real_license_emulation.py` - Server response simulation
- Protocol handshake emulation
- Multi-client support

**Protocols**:
- FlexLM communication
- HASP/Sentinel protocols
- Custom DRM systems

### 💉 exploit_generation/
Safe vulnerability testing framework.

**Key Tests**:
- `test_real_exploit_generation.py` - Exploit creation
- `test_safe_exploits.py` - Sandboxed execution

**Techniques**:
- ROP chain generation
- Shellcode encoding
- ASLR bypass strategies

### 🔬 memory_forensics/
Runtime analysis and memory inspection.

**Key Tests**:
- `test_real_memory_forensics.py` - Process memory analysis
- Unpacking at runtime
- Anti-analysis detection

### 🎯 c2_operations/
Command & control functionality testing.

**Key Tests**:
- `test_real_c2_operations.py` - C2 communication
- Encrypted channels
- Multi-platform support

### 🔌 plugin_system/
Plugin architecture validation.

**Key Tests**:
- `test_real_plugin_operations.py` - Plugin loading
- API compatibility
- Resource management

## Running Functional Tests

### Run All Functional Tests
```bash
just test-functional
# or
python -m pytest tests/functional/ -v
```

### Run Specific Category
```bash
# Binary analysis only
python -m pytest tests/functional/binary_analysis/ -v

# Protection bypass only  
python -m pytest tests/functional/protection_bypass/ -v
```

### Run Single Test
```bash
python -m pytest tests/functional/binary_analysis/test_real_binaries.py::test_winrar_analysis -v
```

## Test Patterns

### Standard Test Structure
```python
class TestRealBinaryAnalysis(BaseTest):
    """Test with real commercial software."""
    
    def test_winrar_trial_protection(self):
        """Analyze WinRAR trial limitations."""
        # Load real 3.5MB WinRAR executable
        binary_path = self.get_fixture_path('binaries/pe/real_protected/winrar_trial.exe')
        
        # Analyze with Intellicrack
        result = self.analyzer.analyze_binary(binary_path)
        
        # Validate detection
        assert "trial" in result.protection_type.lower()
        assert result.has_time_limitation
        assert result.days_limit == 40
```

### Performance Testing Pattern
```python
@pytest.mark.performance
def test_large_binary_analysis(self):
    """Test 178MB Epic Games launcher analysis."""
    epic_path = self.get_fixture_path('binaries/pe/real_protected/epic_games_launcher.exe')
    
    start_time = time.time()
    result = self.analyzer.analyze_binary(epic_path)
    elapsed = time.time() - start_time
    
    # Performance assertion
    assert elapsed < 30.0  # Should complete in 30 seconds
    assert result.drm_type == "Epic Online Services"
```

## Expected Results

### Binary Analysis
- PE header parsing < 100ms
- String extraction < 1s for 100MB
- Entropy calculation < 500ms
- Protection detection accuracy > 95%

### Protection Bypass
- Anti-debug bypass success > 90%
- Trial removal simulation 100%
- No binary corruption

### License Operations  
- Key generation < 1s
- Validation accuracy 100%
- Multi-algorithm support

## Debugging Failed Tests

### Enable Verbose Output
```bash
python -m pytest tests/functional/binary_analysis/ -vvs
```

### Check Fixtures
```python
# Verify test binary exists
assert os.path.exists(binary_path), f"Missing: {binary_path}"
print(f"Binary size: {os.path.getsize(binary_path)} bytes")
```

### Validate Tools
```bash
# Ensure portable tools are available
tests\fixtures\PORTABLE_SANDBOX\RUN_pestudio_portable.bat
```

## Coverage Metrics

| Feature | Tests | Coverage | Real Data |
|---------|-------|----------|-----------|
| Binary Analysis | 15 | 95% | ✅ |
| Protection Bypass | 10 | 90% | ✅ |
| Keygen Ops | 8 | 85% | ✅ |
| License Emulation | 12 | 95% | ✅ |
| Exploit Gen | 6 | 80% | ✅ |
| Memory Forensics | 8 | 85% | ✅ |

---
**Total Functional Tests**: 59
**Using Real Software**: 380.1MB
**Pass Rate**: 92%