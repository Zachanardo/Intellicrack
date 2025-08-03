#!/usr/bin/env python3
"""
Test script for enhanced cross-tool coordination features
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

def test_function_boundary_dataclass():
    """Test the FunctionBoundary dataclass"""
    try:
        from intellicrack.core.analysis.analysis_orchestrator import FunctionBoundary
        
        # Create test boundary
        boundary = FunctionBoundary(
            address=0x401000,
            size=100,
            name='test_license_check',
            priority=0.8,
            calls_count=5,
            complexity=8,
            matched_keywords=['license', 'check'],
            source_tool='radare2'
        )
        
        print(f"✅ FunctionBoundary created successfully")
        print(f"   Name: {boundary.name}")
        print(f"   Address: 0x{boundary.address:x}")
        print(f"   Priority: {boundary.priority}")
        print(f"   Keywords: {boundary.matched_keywords}")
        
        # Test dict conversion
        boundary_dict = boundary.to_dict()
        boundary_restored = FunctionBoundary.from_dict(boundary_dict)
        
        assert boundary_restored.name == boundary.name
        assert boundary_restored.address == boundary.address
        assert boundary_restored.priority == boundary.priority
        
        print(f"✅ Dict conversion test passed")
        return True
        
    except Exception as e:
        print(f"❌ FunctionBoundary test failed: {e}")
        return False

def test_cross_tool_validator():
    """Test the CrossToolValidator"""
    try:
        from intellicrack.core.analysis.analysis_orchestrator import CrossToolValidator
        import logging
        
        logger = logging.getLogger('test')
        validator = CrossToolValidator(logger)
        
        # Test valid boundaries
        valid_boundaries = [
            {'address': 0x401000, 'size': 100, 'name': 'func1', 'priority': 0.8},
            {'address': 0x402000, 'size': 50, 'name': 'func2', 'priority': 0.5}
        ]
        
        result = validator.validate_function_boundaries(valid_boundaries)
        assert result.is_valid
        assert result.valid_items == 2
        assert result.invalid_items == 0
        
        print(f"✅ CrossToolValidator test passed")
        print(f"   Valid: {result.valid_items}/{result.total_items}")
        print(f"   Validity rate: {result.validity_rate:.1%}")
        
        # Test invalid boundaries
        invalid_boundaries = [
            {'address': -1, 'size': 100, 'name': 'bad_func', 'priority': 1.5}  # Invalid address and priority
        ]
        
        result = validator.validate_function_boundaries(invalid_boundaries)
        assert not result.is_valid
        assert result.invalid_items == 1
        
        print(f"✅ Invalid boundary detection works")
        
        return True
        
    except Exception as e:
        print(f"❌ CrossToolValidator test failed: {e}")
        return False

def test_ghidra_decompiler_enhancements():
    """Test the enhanced GhidraDecompiler methods"""
    try:
        from intellicrack.core.analysis.ghidra_decompiler import GhidraDecompiler
        
        # Check if new methods exist
        assert hasattr(GhidraDecompiler, 'decompile_at_address')
        assert hasattr(GhidraDecompiler, 'analyze_targeted_functions')
        assert hasattr(GhidraDecompiler, '_validate_address_in_memory')
        assert hasattr(GhidraDecompiler, '_analyze_decompiled_patterns')
        
        print(f"✅ GhidraDecompiler enhancements verified")
        print(f"   New methods available:")
        print(f"   - decompile_at_address")
        print(f"   - analyze_targeted_functions") 
        print(f"   - _validate_address_in_memory")
        print(f"   - _analyze_decompiled_patterns")
        
        return True
        
    except Exception as e:
        print(f"❌ GhidraDecompiler enhancement test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("🔧 Testing Enhanced Cross-tool Coordination Features\n")
    
    tests = [
        ("FunctionBoundary DataClass", test_function_boundary_dataclass),
        ("CrossToolValidator", test_cross_tool_validator),
        ("GhidraDecompiler Enhancements", test_ghidra_decompiler_enhancements)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n📋 Running test: {test_name}")
        print("-" * 50)
        
        if test_func():
            passed += 1
            print(f"✅ {test_name} - PASSED")
        else:
            print(f"❌ {test_name} - FAILED")
    
    print(f"\n📊 Test Results: {passed}/{total} passed")
    
    if passed == total:
        print("🎉 All tests passed! Enhanced cross-tool coordination is working correctly.")
        return True
    else:
        print("⚠️  Some tests failed. Please check the implementation.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)