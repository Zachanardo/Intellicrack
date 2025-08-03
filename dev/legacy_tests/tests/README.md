# Intellicrack Test Suite

Comprehensive testing framework for Intellicrack, ensuring reliability, security, and performance across all components.

## Test Architecture

The test suite is organized into multiple layers:
- **Unit Tests** - Individual component testing
- **Integration Tests** - Component interaction testing
- **System Tests** - End-to-end functionality testing
- **Performance Tests** - Benchmarking and optimization
- **Security Tests** - Vulnerability and penetration testing

## Directory Structure

```
tests/
├── README.md                           # This file
├── __init__.py                         # Test package initialization
├── simple_test.py                      # Basic functionality test
├── run_comprehensive_tests.py          # Test runner script
├── unit/                              # Unit tests
│   ├── __init__.py
│   ├── ai/
│   │   └── test_script_validation.py
│   ├── core/
│   │   └── __init__.py
│   └── ui/
│       └── __init__.py
├── integration/                       # Integration tests
│   ├── __init__.py
│   ├── test_full_ai_workflow.py      # Complete AI analysis workflow
│   ├── test_qemu_optional_testing.py # QEMU integration testing
│   └── test_script_refinement.py     # Script generation and refinement
├── core/                             # Core component tests
│   ├── __init__.py
│   ├── analysis/
│   │   ├── __init__.py
│   │   └── test_vulnerability_engine.py
│   └── network/
│       ├── __init__.py
│       └── test_traffic_analyzer.py
├── ai/                              # AI component tests
│   └── test_exploit_chain_builder.py
├── utils/                           # Utility tests
│   ├── __init__.py
│   └── test_binary_utils.py
└── [Specialized Test Files]
    ├── test_ai_complex_analysis_integration.py
    ├── test_component_validation.py
    ├── test_core_components.py
    ├── test_current_acceleration.py
    ├── test_directory_analysis.py
    ├── test_example.py
    ├── test_exploitation_integration.py
    ├── test_export_dialog.py
    ├── test_fixed_imports.py
    ├── test_frida_integration.py
    ├── test_frida_performance_benchmark.py
    ├── test_frida_script_regression.py
    ├── test_frida_windows_compatibility.py
    ├── test_gui_components.py
    ├── test_hexviewer_standalone.py
    ├── test_imports.py
    ├── test_imports_and_integrations.py
    ├── test_intel_gpu.py
    ├── test_isolated_components.py
    ├── test_lazy_loading.py
    ├── test_license_file_search_integration.py
    ├── test_license_pattern_integration.py
    ├── test_minimal_functions.py
    ├── test_model_validation.py
    ├── test_multi_format_analyzer.py
    ├── test_network_standalone.py
    ├── test_patching_standalone.py
    ├── test_protection_ui_display.py
    ├── test_radare2_integration.py
    ├── test_radare2_integration_advanced.py
    ├── test_real_world_multi_format_analyzer.py
    ├── test_script_execution_manager.py
    ├── test_signature_editor.py
    ├── test_smart_program_selector.py
    ├── validate_real_model_deployment.py
    ├── icp_backend_standalone_test.py
    ├── icp_direct_test.py
    ├── icp_integration_tester.py
    ├── icp_integration_tester_focused.py
    └── icp_isolated_test.py
```

## Test Categories

### Unit Tests (`unit/`)
Test individual components in isolation:

```python
import unittest
from intellicrack.core.analysis import VulnerabilityEngine

class TestVulnerabilityEngine(unittest.TestCase):
    def setUp(self):
        self.engine = VulnerabilityEngine()

    def test_buffer_overflow_detection(self):
        # Test buffer overflow detection
        result = self.engine.detect_buffer_overflow("test_binary.exe")
        self.assertTrue(result['detected'])

    def test_format_string_detection(self):
        # Test format string vulnerability detection
        result = self.engine.detect_format_string("vulnerable_app.exe")
        self.assertIsInstance(result, dict)
```

### Integration Tests (`integration/`)
Test component interactions and workflows:

```python
import unittest
from intellicrack.ai.ai_script_generator import AIScriptGenerator
from intellicrack.core.frida_manager import FridaManager

class TestAIWorkflow(unittest.TestCase):
    def test_full_ai_analysis_workflow(self):
        # Test complete AI-driven analysis
        generator = AIScriptGenerator()
        manager = FridaManager()

        # Generate script
        script = generator.generate_frida_script("target.exe")
        self.assertIsNotNone(script)

        # Execute script
        result = manager.execute_script(script, "target.exe")
        self.assertTrue(result['success'])
```

### Core Component Tests (`core/`)
Test core analysis engines:

```python
def test_vulnerability_engine():
    """Test vulnerability detection engine"""
    from intellicrack.core.analysis.vulnerability_engine import VulnerabilityEngine

    engine = VulnerabilityEngine()
    results = engine.scan_binary("test_samples/vulnerable.exe")

    assert len(results) > 0
    assert any(vuln.type == "buffer_overflow" for vuln in results)
```

### Performance Tests
Benchmark critical operations:

```python
import time
import unittest

class TestPerformance(unittest.TestCase):
    def test_analysis_speed(self):
        """Ensure analysis completes within reasonable time"""
        start_time = time.time()

        # Perform analysis
        result = analyze_binary("large_binary.exe")

        elapsed = time.time() - start_time
        self.assertLess(elapsed, 300)  # Should complete within 5 minutes
```

## Running Tests

### All Tests
```bash
# Run complete test suite
python -m pytest tests/

# Run with coverage
python -m pytest tests/ --cov=intellicrack

# Run comprehensive test script
python tests/run_comprehensive_tests.py
```

### Specific Test Categories
```bash
# Unit tests only
python -m pytest tests/unit/

# Integration tests only
python -m pytest tests/integration/

# Core component tests
python -m pytest tests/core/

# AI component tests
python -m pytest tests/ai/
```

### Individual Test Files
```bash
# Run specific test file
python -m pytest tests/test_frida_integration.py

# Run specific test method
python -m pytest tests/test_core_components.py::TestAnalysisEngine::test_pe_analysis

# Run with verbose output
python -m pytest tests/test_imports.py -v
```

### Performance Testing
```bash
# Run performance benchmarks
python tests/test_frida_performance_benchmark.py

# GPU acceleration tests
python tests/test_intel_gpu.py
python tests/test_current_acceleration.py

# Memory usage tests
python tests/test_lazy_loading.py
```

## Test Configuration

### Environment Setup
```python
# tests/conftest.py
import pytest
import tempfile
import os

@pytest.fixture
def temp_binary_dir():
    """Create temporary directory for test binaries"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir

@pytest.fixture
def sample_binary():
    """Provide sample binary for testing"""
    return os.path.join("tests", "samples", "test_binary.exe")

@pytest.fixture
def mock_config():
    """Provide mock configuration for testing"""
    return {
        'analysis': {'timeout': 60},
        'logging': {'level': 'DEBUG'}
    }
```

### Test Data
```
tests/
├── samples/           # Test binary samples
│   ├── simple.exe     # Basic executable
│   ├── packed.exe     # Packed binary
│   ├── malware.exe    # Malware sample (sanitized)
│   └── library.dll    # Dynamic library
├── fixtures/          # Test fixtures and mock data
│   ├── config.json    # Test configuration
│   ├── responses.json # Mock API responses
│   └── signatures.yara # Test signatures
└── expected/          # Expected test results
    ├── analysis_results.json
    └── vulnerability_reports.json
```

## Specialized Tests

### AI Integration Tests
```python
def test_ai_script_generation():
    """Test AI-powered script generation"""
    from intellicrack.ai.ai_script_generator import AIScriptGenerator

    generator = AIScriptGenerator()
    script = generator.generate_frida_script(
        binary_path="test.exe",
        analysis_type="license_bypass"
    )

    assert "Java.perform" in script
    assert "hook" in script.lower()
```

### Frida Integration Tests
```python
def test_frida_script_execution():
    """Test Frida script execution and management"""
    from intellicrack.core.frida_manager import FridaManager

    manager = FridaManager()

    # Test script loading
    script_path = "tests/samples/test_script.js"
    result = manager.load_script(script_path)
    assert result['success']

    # Test script execution
    execution_result = manager.execute_on_process("notepad.exe")
    assert execution_result['status'] == 'completed'
```

### ICP Backend Tests
```python
def test_icp_integration():
    """Test ICP engine integration"""
    from intellicrack.protection.icp_backend import ICPBackend

    backend = ICPBackend()
    result = backend.analyze_binary("test_samples/protected.exe")

    assert 'protections' in result
    assert len(result['protections']) > 0
```

### Network Analysis Tests
```python
def test_network_traffic_analysis():
    """Test network traffic capture and analysis"""
    from intellicrack.core.network.traffic_analyzer import NetworkTrafficAnalyzer

    analyzer = NetworkTrafficAnalyzer()

    # Start capture
    analyzer.start_capture(interface="eth0")

    # Simulate network activity
    # ... network operations ...

    # Stop and analyze
    packets = analyzer.stop_capture()
    analysis = analyzer.analyze_packets(packets)

    assert len(packets) > 0
    assert 'protocols' in analysis
```

## Mock Objects and Fixtures

### Mock Binary Analysis
```python
from unittest.mock import Mock, patch

@patch('intellicrack.core.analysis.CoreAnalyzer')
def test_analysis_with_mock(mock_analyzer):
    """Test analysis with mocked components"""
    # Configure mock
    mock_analyzer.return_value.analyze_binary.return_value = {
        'file_type': 'PE',
        'architecture': 'x86_64',
        'vulnerabilities': []
    }

    # Test with mock
    result = analyze_binary_wrapper("test.exe")
    assert result['file_type'] == 'PE'
```

### Test Fixtures
```python
@pytest.fixture
def vulnerability_sample():
    """Provide sample vulnerability data"""
    return {
        'type': 'buffer_overflow',
        'severity': 'high',
        'location': '0x401000',
        'description': 'Stack buffer overflow in main function'
    }

@pytest.fixture
def frida_script_template():
    """Provide basic Frida script template"""
    return """
    Java.perform(function() {
        console.log("[+] Frida script loaded");
    });
    """
```

## Continuous Integration

### GitHub Actions Integration
```yaml
# .github/workflows/test.yml
name: Test Suite
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: 3.11
    - name: Install dependencies
      run: |
        pip install -r requirements/requirements.txt
        pip install -r requirements/test.txt
    - name: Run tests
      run: |
        python -m pytest tests/ --cov=intellicrack
```

### Test Automation
```bash
#!/bin/bash
# scripts/run_tests.sh

echo "Running Intellicrack test suite..."

# Unit tests
echo "Running unit tests..."
python -m pytest tests/unit/ -v

# Integration tests
echo "Running integration tests..."
python -m pytest tests/integration/ -v

# Performance tests
echo "Running performance tests..."
python tests/test_frida_performance_benchmark.py

# Generate coverage report
echo "Generating coverage report..."
python -m pytest tests/ --cov=intellicrack --cov-report=html

echo "Test suite completed!"
```

## Test Best Practices

### Writing Effective Tests
1. **Descriptive Names** - Use clear, descriptive test names
2. **Single Responsibility** - Each test should test one thing
3. **Independent Tests** - Tests should not depend on each other
4. **Comprehensive Coverage** - Test both success and failure cases
5. **Performance Awareness** - Consider test execution time

### Test Data Management
1. **Isolated Data** - Use temporary directories for test data
2. **Clean State** - Reset state between tests
3. **Realistic Samples** - Use representative test samples
4. **Security** - Don't include actual malware in repository

### Error Handling
```python
def test_error_handling():
    """Test proper error handling"""
    with pytest.raises(ValueError):
        invalid_operation()

    # Test graceful degradation
    result = operation_with_fallback()
    assert result['status'] == 'fallback_used'
```

## Security Testing

### Vulnerability Testing
```python
def test_input_validation():
    """Test input validation and sanitization"""
    malicious_inputs = [
        "../../../etc/passwd",
        "<script>alert('xss')</script>",
        "'; DROP TABLE users; --"
    ]

    for malicious_input in malicious_inputs:
        with pytest.raises(ValueError):
            process_user_input(malicious_input)
```

### Permission Testing
```python
def test_file_permissions():
    """Test file access permissions"""
    restricted_path = "/etc/shadow"

    with pytest.raises(PermissionError):
        read_file(restricted_path)
```

## Performance Monitoring

### Benchmark Tests
```python
import time
import psutil

def test_memory_usage():
    """Monitor memory usage during analysis"""
    process = psutil.Process()
    initial_memory = process.memory_info().rss

    # Perform memory-intensive operation
    analyze_large_binary("huge_binary.exe")

    final_memory = process.memory_info().rss
    memory_increase = final_memory - initial_memory

    # Ensure memory usage is reasonable
    assert memory_increase < 1024 * 1024 * 1024  # 1GB limit
```

### Speed Tests
```python
@pytest.mark.performance
def test_analysis_speed():
    """Benchmark analysis speed"""
    import time

    start_time = time.time()
    result = quick_analysis("test_binary.exe")
    elapsed = time.time() - start_time

    assert elapsed < 30  # Should complete in 30 seconds
    assert result['status'] == 'completed'
```

## Debugging Tests

### Debug Mode
```python
# Enable debug logging for tests
import logging
logging.basicConfig(level=logging.DEBUG)

def test_with_debug():
    """Test with debug output enabled"""
    logger = logging.getLogger(__name__)
    logger.debug("Starting test")

    result = complex_operation()
    logger.debug(f"Result: {result}")

    assert result['success']
```

### Test Isolation
```python
@pytest.fixture(autouse=True)
def isolate_tests():
    """Ensure tests are properly isolated"""
    # Setup
    original_config = get_config()
    set_test_config()

    yield

    # Cleanup
    set_config(original_config)
    clear_cache()
```

## Contributing to Tests

### Adding New Tests
1. Place tests in appropriate category directory
2. Follow naming conventions (`test_*.py`)
3. Include docstrings explaining test purpose
4. Add to CI pipeline if appropriate
5. Update this README if adding new test categories

### Test Coverage Goals
- **Unit Tests**: >90% code coverage
- **Integration Tests**: All major workflows covered
- **Performance Tests**: Key operations benchmarked
- **Security Tests**: All input paths validated

### Review Checklist
- [ ] Test names are descriptive
- [ ] Tests are independent and isolated
- [ ] Both success and failure cases covered
- [ ] Performance implications considered
- [ ] Security aspects tested
- [ ] Documentation updated

For more information, see the [Contributing Guide](../CONTRIBUTING.md).

## Troubleshooting Tests

### Common Issues
1. **Test Failures** - Check dependencies and environment
2. **Slow Tests** - Use appropriate test markers and timeouts
3. **Flaky Tests** - Improve test isolation and determinism
4. **Missing Dependencies** - Ensure all test requirements installed

### Test Environment
```bash
# Setup test environment
python -m venv test_env
source test_env/bin/activate  # Linux/Mac
# test_env\Scripts\activate    # Windows

pip install -r requirements/test.txt
```

The test suite is continuously evolving to ensure Intellicrack maintains high quality, security, and performance standards.
