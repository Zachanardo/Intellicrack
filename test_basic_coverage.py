#!/usr/bin/env python3
"""
Basic coverage test script to analyze core module coverage.
This script imports and exercises basic functionality from core modules.
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

def test_core_imports():
    """Test core module imports."""
    results = []
    
    try:
        from intellicrack.core.app_context import AppContext
        ctx = AppContext()
        ctx.initialize()
        results.append("✓ AppContext imported and initialized")
    except Exception as e:
        results.append(f"✗ AppContext failed: {e}")
    
    try:
        from intellicrack.utils.secrets_manager import SecretsManager
        sm = SecretsManager()
        results.append("✓ SecretsManager imported")
    except Exception as e:
        results.append(f"✗ SecretsManager failed: {e}")
    
    try:
        from intellicrack.utils.binary.certificate_extractor import CertificateExtractor
        ce = CertificateExtractor()
        results.append("✓ CertificateExtractor imported")
    except Exception as e:
        results.append(f"✗ CertificateExtractor failed: {e}")
    
    try:
        from intellicrack.utils.binary.binary_io import BinaryIO
        bio = BinaryIO()
        results.append("✓ BinaryIO imported")
    except Exception as e:
        results.append(f"✗ BinaryIO failed: {e}")
    
    try:
        from intellicrack.utils.system.file_resolution import FileResolver
        fr = FileResolver()
        results.append("✓ FileResolver imported")
    except Exception as e:
        results.append(f"✗ FileResolver failed: {e}")
    
    return results

def test_basic_functionality():
    """Test basic functionality of imported modules."""
    results = []
    
    # Test binary operations
    try:
        import tempfile
        import os
        
        # Create test file
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"MZ\x90\x00\x03\x00\x00\x00")
            tmp_path = tmp.name
        
        from intellicrack.utils.binary.binary_io import BinaryIO
        bio = BinaryIO()
        
        # Test read
        read_result = bio.read_binary_file(tmp_path)
        if read_result and 'data' in read_result:
            results.append("✓ BinaryIO read_binary_file works")
        else:
            results.append("✗ BinaryIO read_binary_file failed")
        
        # Cleanup
        os.unlink(tmp_path)
        
    except Exception as e:
        results.append(f"✗ Binary operations failed: {e}")
    
    # Test secrets management
    try:
        from intellicrack.utils.secrets_manager import SecretsManager
        sm = SecretsManager()
        
        # Test basic functionality
        test_key = "test_key"
        test_value = "test_value"
        
        store_result = sm.store_secret(test_key, test_value)
        if store_result and store_result.get('success'):
            retrieved = sm.get_secret(test_key)
            if retrieved == test_value:
                results.append("✓ SecretsManager store/retrieve works")
            else:
                results.append("✗ SecretsManager retrieve failed")
        else:
            results.append("✗ SecretsManager store failed")
            
    except Exception as e:
        results.append(f"✗ Secrets management failed: {e}")
    
    return results

if __name__ == "__main__":
    print("=== Basic Coverage Test ===")
    
    print("\n--- Testing Core Imports ---")
    import_results = test_core_imports()
    for result in import_results:
        print(result)
    
    print("\n--- Testing Basic Functionality ---")
    func_results = test_basic_functionality()
    for result in func_results:
        print(result)
    
    print("\n=== Test Complete ===")