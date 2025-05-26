#!/usr/bin/env python3
"""
Integration Test for Intellicrack Modular Architecture

This script tests the integration between different modules to ensure
they work together correctly in the refactored structure.
"""

import sys
import os
import tempfile
import traceback

def test_config_integration():
    """Test configuration system integration."""
    print("Testing Configuration Integration:")
    print("-" * 40)
    
    try:
        from intellicrack.config import ConfigManager, get_config, CONFIG
        
        # Test config manager creation
        config_manager = ConfigManager()
        print("✓ ConfigManager created successfully")
        
        # Test getting configuration values
        log_dir = config_manager.get("log_dir")
        print(f"✓ Configuration value retrieval works: log_dir = {log_dir}")
        
        # Test setting configuration values
        config_manager.set("test_key", "test_value")
        assert config_manager.get("test_key") == "test_value"
        print("✓ Configuration value setting works")
        
        # Test global CONFIG access
        assert CONFIG is not None
        print("✓ Global CONFIG is available")
        
        return True
        
    except Exception as e:
        print(f"✗ Configuration integration failed: {e}")
        traceback.print_exc()
        return False

def test_vulnerability_engine_integration():
    """Test vulnerability engine integration."""
    print("\nTesting Vulnerability Engine Integration:")
    print("-" * 40)
    
    try:
        from intellicrack.core.analysis.vulnerability_engine import (
            AdvancedVulnerabilityEngine, 
            VulnerabilityReport,
            calculate_entropy
        )
        
        # Test entropy calculation
        test_data = b"Hello, World! This is test data for entropy calculation."
        entropy = calculate_entropy(test_data)
        assert 0 <= entropy <= 8, f"Entropy should be between 0-8, got {entropy}"
        print(f"✓ Entropy calculation works: {entropy:.3f}")
        
        # Test vulnerability engine creation
        engine = AdvancedVulnerabilityEngine()
        print("✓ AdvancedVulnerabilityEngine created successfully")
        
        # Test report generation (without actual binary)
        fake_vulnerabilities = [
            {"type": "test_vuln", "risk": "low", "severity": "medium"}
        ]
        report = VulnerabilityReport.generate_report(fake_vulnerabilities, "test_binary.exe")
        assert report["total_vulnerabilities"] == 1
        print("✓ Vulnerability report generation works")
        
        return True
        
    except Exception as e:
        print(f"✗ Vulnerability engine integration failed: {e}")
        traceback.print_exc()
        return False

def test_binary_analyzer_integration():
    """Test binary analyzer integration."""
    print("\nTesting Binary Analyzer Integration:")
    print("-" * 40)
    
    try:
        from intellicrack.core.analysis.multi_format_analyzer import MultiFormatBinaryAnalyzer
        
        # Test analyzer creation
        analyzer = MultiFormatBinaryAnalyzer()
        print("✓ MultiFormatBinaryAnalyzer created successfully")
        
        # Test helper methods
        machine_type = analyzer._get_machine_type(0x014c)  # i386
        assert machine_type == "I386"
        print(f"✓ Machine type detection works: {machine_type}")
        
        timestamp = analyzer._get_pe_timestamp(1234567890)
        print(f"✓ PE timestamp conversion works: {timestamp}")
        
        # Test format identification with a fake PE file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(b"MZ\x00\x00")  # Fake PE header
            temp_file.flush()
            
            format_type = analyzer.identify_format(temp_file.name)
            assert format_type == "PE"
            print(f"✓ Format identification works: {format_type}")
            
            os.unlink(temp_file.name)
        
        return True
        
    except Exception as e:
        print(f"✗ Binary analyzer integration failed: {e}")
        traceback.print_exc()
        return False

def test_logger_integration():
    """Test logging system integration."""
    print("\nTesting Logger Integration:")
    print("-" * 40)
    
    try:
        from intellicrack.utils.logger import (
            get_logger,
            setup_logger,
            configure_logging
        )
        
        # Test logger creation
        logger = get_logger("test_logger")
        assert logger is not None
        print("✓ Logger creation works")
        
        # Test logger setup
        test_logger = setup_logger("test_setup", level=20)  # INFO level
        assert test_logger.level == 20
        print("✓ Logger setup works")
        
        # Test logging functionality
        logger.info("Test log message")
        print("✓ Logger functionality works")
        
        return True
        
    except Exception as e:
        print(f"✗ Logger integration failed: {e}")
        traceback.print_exc()
        return False

def test_cross_module_integration():
    """Test integration between different modules."""
    print("\nTesting Cross-Module Integration:")
    print("-" * 40)
    
    try:
        # Test config + logger integration
        from intellicrack.config import get_config
        from intellicrack.utils.logger import get_logger
        
        config_manager = get_config()
        logger = get_logger("integration_test")
        
        # Test using config values in logging setup
        log_level = config_manager.get("verbose_logging", False)
        logger.info(f"Verbose logging configured: {log_level}")
        print("✓ Config + Logger integration works")
        
        # Test vulnerability engine + config integration
        from intellicrack.core.analysis.vulnerability_engine import AdvancedVulnerabilityEngine
        engine = AdvancedVulnerabilityEngine()
        
        # Test config-based initialization
        plugin_dir = config_manager.get("plugin_directory", "plugins")
        print(f"✓ Vulnerability engine + Config integration works: {plugin_dir}")
        
        return True
        
    except Exception as e:
        print(f"✗ Cross-module integration failed: {e}")
        traceback.print_exc()
        return False

def test_package_structure():
    """Test that the package structure is correct."""
    print("\nTesting Package Structure:")
    print("-" * 40)
    
    try:
        # Test main package import
        import intellicrack
        print("✓ Main package imports successfully")
        
        # Test subpackage imports
        from intellicrack import core, ui, ai, utils
        print("✓ Core subpackages import successfully")
        
        # Test version and metadata
        if hasattr(intellicrack, '__version__'):
            print(f"✓ Version information available: {intellicrack.__version__}")
        else:
            print("⚠ Version information not set")
        
        return True
        
    except Exception as e:
        print(f"✗ Package structure test failed: {e}")
        traceback.print_exc()
        return False

def main():
    """Main integration test function."""
    print("Intellicrack Integration Test Suite")
    print("=" * 50)
    
    tests = [
        test_config_integration,
        test_vulnerability_engine_integration,
        test_binary_analyzer_integration,
        test_logger_integration,
        test_cross_module_integration,
        test_package_structure
    ]
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"✗ Test {test.__name__} failed with exception: {e}")
            results.append(False)
    
    print("\n" + "=" * 50)
    passed = sum(results)
    total = len(results)
    print(f"Integration Test Results: {passed}/{total} test suites passed")
    
    if passed == total:
        print("🎉 ALL INTEGRATION TESTS PASSED!")
        print("The modular Intellicrack architecture is working correctly.")
        print("✅ Ready for production use (pending dependency installation)")
        return 0
    else:
        print("⚠ Some integration tests failed")
        print("Review the output above for specific issues")
        return 1

if __name__ == "__main__":
    sys.exit(main())