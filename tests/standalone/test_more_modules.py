"""Additional standalone tests for increased coverage"""
import os
import sys
import json
import tempfile
from pathlib import Path

# Disable GPU initialization
os.environ['INTELLICRACK_NO_GPU'] = '1'
os.environ['CUDA_VISIBLE_DEVICES'] = '-1'

# Add project to path
sys.path.insert(0, 'C:\\Intellicrack')

def run_test_entropy_analyzer():
    """Test entropy analysis module directly"""
    print("\n=== Running Entropy Analyzer Test ===")
    
    try:
        from intellicrack.core.analysis.entropy_analyzer import EntropyAnalyzer
        
        # Create analyzer
        analyzer = EntropyAnalyzer()
        
        # Test with sample data
        test_data = b'Hello World! This is a test string with some repetition... repetition... repetition...'
        
        # Calculate entropy
        entropy = analyzer.calculate_entropy(test_data)
        assert entropy is not None, "Entropy calculation returned None"
        assert 0 <= entropy <= 8, f"Invalid entropy value: {entropy}"
        print(f"Calculated entropy: {entropy}")
        
        # Test entropy distribution
        distribution = analyzer.get_byte_distribution(test_data)
        assert distribution is not None, "Distribution returned None"
        assert len(distribution) > 0, "Empty distribution"
        print(f"Unique bytes in data: {len(distribution)}")
        
        # Test chunked entropy analysis
        chunks = analyzer.analyze_chunks(test_data, chunk_size=16)
        assert chunks is not None, "Chunk analysis returned None"
        assert len(chunks) > 0, "No chunks analyzed"
        print(f"Analyzed {len(chunks)} chunks")
        
        print("✓ Test PASSED!")
        return True
        
    except Exception as e:
        print(f"✗ Test FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_test_config_manager():
    """Test configuration management"""
    print("\n=== Running Config Manager Test ===")
    
    try:
        from intellicrack.core.config_manager import ConfigManager
        
        # Create config manager
        config = ConfigManager()
        
        # Test default values
        defaults = config.get_defaults()
        assert defaults is not None, "Defaults returned None"
        assert isinstance(defaults, dict), "Defaults must be a dictionary"
        print(f"Default config sections: {list(defaults.keys())}")
        
        # Test get/set operations
        test_key = 'test_key'
        test_value = 'test_value'
        
        # Set value
        config.set_value('testing', test_key, test_value)
        
        # Get value
        retrieved = config.get_value('testing', test_key)
        assert retrieved == test_value, f"Expected {test_value}, got {retrieved}"
        print(f"Config get/set working correctly")
        
        # Test section operations
        sections = config.get_sections()
        assert sections is not None, "Sections returned None"
        assert 'testing' in sections, "Testing section not found"
        print(f"Available sections: {sections}")
        
        print("✓ Test PASSED!")
        return True
        
    except Exception as e:
        print(f"✗ Test FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_test_yara_pattern_engine():
    """Test YARA pattern engine"""
    print("\n=== Running YARA Pattern Engine Test ===")
    
    try:
        from intellicrack.core.analysis.yara_pattern_engine import YaraPatternEngine
        
        # Create engine
        engine = YaraPatternEngine()
        
        # Test pattern compilation
        test_rule = '''
        rule TestRule {
            meta:
                description = "Test rule for unit testing"
                author = "Test"
            strings:
                $a = "Hello"
                $b = { 48 65 6c 6c 6f }
            condition:
                any of them
        }
        '''
        
        # Compile rule
        success = engine.compile_rule(test_rule, 'test_rule')
        assert success, "Failed to compile YARA rule"
        print("Successfully compiled YARA rule")
        
        # Test pattern matching
        test_data = b'Hello World! This is a test.'
        matches = engine.scan_data(test_data)
        assert matches is not None, "Scan returned None"
        
        if len(matches) > 0:
            print(f"Found {len(matches)} matches")
            for match in matches:
                print(f"  Rule: {match.get('rule', 'unknown')}")
        else:
            print("No matches found (this is OK for basic test)")
        
        # Test built-in patterns
        patterns = engine.get_builtin_patterns()
        assert patterns is not None, "Built-in patterns returned None"
        print(f"Available pattern categories: {list(patterns.keys())}")
        
        print("✓ Test PASSED!")
        return True
        
    except Exception as e:
        print(f"✗ Test FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_test_tool_discovery():
    """Test tool discovery functionality"""
    print("\n=== Running Tool Discovery Test ===")
    
    try:
        from intellicrack.core.tool_discovery import ToolDiscovery
        
        # Create tool discovery instance
        discovery = ToolDiscovery()
        
        # Test tool detection
        tools = discovery.discover_tools()
        assert tools is not None, "Tool discovery returned None"
        assert isinstance(tools, dict), "Tools must be a dictionary"
        print(f"Discovered tool categories: {list(tools.keys())}")
        
        # Check for common tools
        common_tools = ['python', 'pip']
        for tool in common_tools:
            found = discovery.is_tool_available(tool)
            print(f"  {tool}: {'Found' if found else 'Not found'}")
        
        # Test tool paths
        python_path = discovery.get_tool_path('python')
        if python_path:
            assert os.path.exists(python_path), f"Python path invalid: {python_path}"
            print(f"Python path: {python_path}")
        
        print("✓ Test PASSED!")
        return True
        
    except Exception as e:
        print(f"✗ Test FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_test_app_context():
    """Test application context"""
    print("\n=== Running App Context Test ===")
    
    try:
        from intellicrack.core.app_context import AppContext
        
        # Create context
        context = AppContext()
        
        # Test initialization
        context.initialize()
        assert context.is_initialized(), "Context not initialized"
        print("Context initialized successfully")
        
        # Test component access
        components = context.get_available_components()
        assert components is not None, "Components returned None"
        assert isinstance(components, list), "Components must be a list"
        print(f"Available components: {len(components)}")
        
        # Test settings
        test_setting = context.get_setting('app_name')
        assert test_setting is not None, "App name setting not found"
        print(f"App name: {test_setting}")
        
        # Test resource paths
        resources = context.get_resource_paths()
        assert resources is not None, "Resources returned None"
        assert 'config' in resources, "Config path not found"
        assert 'data' in resources, "Data path not found"
        print(f"Resource paths configured: {list(resources.keys())}")
        
        print("✓ Test PASSED!")
        return True
        
    except Exception as e:
        print(f"✗ Test FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_test_frida_constants():
    """Test Frida constants and templates"""
    print("\n=== Running Frida Constants Test ===")
    
    try:
        from intellicrack.core.frida_constants import FridaConstants
        
        # Get constants
        constants = FridaConstants()
        
        # Test hook templates
        templates = constants.get_hook_templates()
        assert templates is not None, "Templates returned None"
        assert isinstance(templates, dict), "Templates must be a dictionary"
        print(f"Available hook templates: {list(templates.keys())}")
        
        # Test common hooks
        common_hooks = ['function_hook', 'api_hook', 'memory_hook']
        for hook_type in common_hooks:
            template = constants.get_template(hook_type)
            if template:
                assert len(template) > 0, f"Empty template for {hook_type}"
                print(f"  {hook_type}: {len(template)} chars")
        
        # Test bypass scripts
        bypass_scripts = constants.get_bypass_scripts()
        assert bypass_scripts is not None, "Bypass scripts returned None"
        print(f"Available bypass scripts: {len(bypass_scripts)}")
        
        print("✓ Test PASSED!")
        return True
        
    except Exception as e:
        print(f"✗ Test FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_test_multi_format_analyzer():
    """Test multi-format binary analyzer"""
    print("\n=== Running Multi-Format Analyzer Test ===")
    
    try:
        from intellicrack.core.analysis.multi_format_analyzer import MultiFormatAnalyzer
        
        # Create analyzer
        analyzer = MultiFormatAnalyzer()
        
        # Test format detection
        test_samples = [
            (b'MZ\x90\x00', 'PE'),
            (b'\x7fELF', 'ELF'),
            (b'dex\n', 'DEX'),
            (b'PK\x03\x04', 'ZIP')
        ]
        
        for sample_data, expected_format in test_samples:
            detected = analyzer.detect_format(sample_data)
            print(f"Sample {expected_format}: detected as {detected}")
            assert detected is not None, f"Failed to detect {expected_format}"
        
        # Test analyzer registration
        analyzers = analyzer.get_registered_analyzers()
        assert analyzers is not None, "Analyzers returned None"
        assert len(analyzers) > 0, "No analyzers registered"
        print(f"Registered analyzers: {list(analyzers.keys())}")
        
        print("✓ Test PASSED!")
        return True
        
    except Exception as e:
        print(f"✗ Test FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_test_security_utils():
    """Test security utilities"""
    print("\n=== Running Security Utils Test ===")
    
    try:
        from intellicrack.core.security_utils import SecurityUtils
        
        # Create utils instance
        utils = SecurityUtils()
        
        # Test permission checks
        test_file = __file__
        perms = utils.check_file_permissions(test_file)
        assert perms is not None, "Permission check returned None"
        print(f"File permissions: {perms}")
        
        # Test hash calculation
        test_data = b'Test data for hashing'
        hash_md5 = utils.calculate_hash(test_data, 'md5')
        hash_sha256 = utils.calculate_hash(test_data, 'sha256')
        
        assert hash_md5 is not None, "MD5 hash returned None"
        assert hash_sha256 is not None, "SHA256 hash returned None"
        assert len(hash_md5) == 32, "Invalid MD5 hash length"
        assert len(hash_sha256) == 64, "Invalid SHA256 hash length"
        
        print(f"MD5: {hash_md5}")
        print(f"SHA256: {hash_sha256}")
        
        # Test input validation
        safe_input = utils.sanitize_input("test_input_123")
        unsafe_input = utils.sanitize_input("test<script>alert()</script>")
        
        assert safe_input == "test_input_123", "Safe input was modified"
        assert unsafe_input != "test<script>alert()</script>", "Unsafe input not sanitized"
        print("Input sanitization working correctly")
        
        print("✓ Test PASSED!")
        return True
        
    except Exception as e:
        print(f"✗ Test FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_test_payload_generator():
    """Test payload generation"""
    print("\n=== Running Payload Generator Test ===")
    
    try:
        from intellicrack.core.patching.payload_generator import PayloadGenerator
        
        # Create generator
        generator = PayloadGenerator()
        
        # Test NOP sled generation
        nop_sled = generator.generate_nop_sled(100)
        assert nop_sled is not None, "NOP sled generation failed"
        assert len(nop_sled) == 100, f"NOP sled wrong size: {len(nop_sled)}"
        print(f"Generated NOP sled: {len(nop_sled)} bytes")
        
        # Test shellcode templates
        templates = generator.get_shellcode_templates()
        assert templates is not None, "Templates returned None"
        assert isinstance(templates, dict), "Templates must be dictionary"
        print(f"Available shellcode templates: {list(templates.keys())}")
        
        # Test basic payload generation
        payload_config = {
            'type': 'messagebox',
            'architecture': 'x86',
            'message': 'Test'
        }
        
        payload = generator.generate_payload(payload_config)
        assert payload is not None, "Payload generation failed"
        assert len(payload) > 0, "Empty payload generated"
        print(f"Generated payload: {len(payload)} bytes")
        
        print("✓ Test PASSED!")
        return True
        
    except Exception as e:
        print(f"✗ Test FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_test_network_capture():
    """Test network capture functionality"""
    print("\n=== Running Network Capture Test ===")
    
    try:
        from intellicrack.core.network_capture import NetworkCapture
        
        # Create capture instance
        capture = NetworkCapture()
        
        # Test interface listing
        interfaces = capture.list_interfaces()
        assert interfaces is not None, "Interface listing returned None"
        assert isinstance(interfaces, list), "Interfaces must be a list"
        print(f"Found {len(interfaces)} network interfaces")
        
        # Test filter compilation
        test_filter = "tcp port 80"
        valid = capture.validate_filter(test_filter)
        assert valid is not None, "Filter validation returned None"
        print(f"Filter '{test_filter}' is {'valid' if valid else 'invalid'}")
        
        # Test capture configuration
        config = capture.get_default_config()
        assert config is not None, "Default config returned None"
        assert 'buffer_size' in config, "Missing buffer_size in config"
        assert 'timeout' in config, "Missing timeout in config"
        print(f"Default capture config: buffer={config['buffer_size']}, timeout={config['timeout']}")
        
        print("✓ Test PASSED!")
        return True
        
    except Exception as e:
        print(f"✗ Test FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all additional tests"""
    print("Starting additional standalone tests...")
    
    tests = [
        run_test_entropy_analyzer,
        run_test_config_manager,
        run_test_yara_pattern_engine,
        run_test_tool_discovery,
        run_test_app_context,
        run_test_frida_constants,
        run_test_multi_format_analyzer,
        run_test_security_utils,
        run_test_payload_generator,
        run_test_network_capture
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        result = test()
        if result:
            passed += 1
        else:
            failed += 1
    
    print(f"\n{'='*50}")
    print(f"Additional Test Results:")
    print(f"  Passed: {passed}")
    print(f"  Failed: {failed}")
    print(f"  Total: {len(tests)}")
    print(f"{'='*50}")
    
    return failed == 0

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)