#!/usr/bin/env python3
"""
Quick test for advanced protection detection integration
"""

import os
import sys
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))

def test_import():
    """Test importing the new modules"""
    try:
        from intellicrack.protection.advanced_detection_engine import (
            AdvancedDetectionEngine,
            AdvancedEntropyAnalyzer,
            ModernProtectionSignatures,
            ImportTableAnalyzer,
            AntiAnalysisDetector,
            BehavioralHeuristicsEngine
        )
        print("✓ Advanced detection engine modules imported successfully")
        return True
    except Exception as e:
        print(f"✗ Import failed: {e}")
        return False

def test_unified_integration():
    """Test unified engine integration"""
    try:
        from intellicrack.protection.unified_protection_engine import (
            UnifiedProtectionEngine,
            AnalysisSource
        )
        
        # Check if ADVANCED_ENGINE source was added
        if hasattr(AnalysisSource, 'ADVANCED_ENGINE'):
            print("✓ Advanced engine integrated into unified protection engine")
            return True
        else:
            print("✗ Advanced engine not found in analysis sources")
            return False
    except Exception as e:
        print(f"✗ Unified engine integration test failed: {e}")
        return False

def test_basic_functionality():
    """Test basic functionality with system file"""
    try:
        from intellicrack.protection.advanced_detection_engine import AdvancedDetectionEngine
        
        engine = AdvancedDetectionEngine()
        
        # Test with a small system file
        test_file = "C:\\Windows\\System32\\notepad.exe"
        if not os.path.exists(test_file):
            test_file = "C:\\Windows\\System32\\calc.exe"
            
        if not os.path.exists(test_file):
            print("✗ No test file available")
            return False
            
        print(f"Testing with: {test_file}")
        
        # Quick analysis
        result = engine.analyze(test_file, deep_analysis=False)
        
        print(f"✓ Analysis completed")
        print(f"  - Overall confidence: {result.overall_confidence:.1f}%")
        print(f"  - Protection layers: {result.protection_layers}")
        print(f"  - Detections: {len(result.detections)}")
        print(f"  - Analysis time: {result.analysis_time:.2f}s")
        
        return True
        
    except Exception as e:
        print(f"✗ Basic functionality test failed: {e}")
        return False

def main():
    """Run tests"""
    print("Advanced Protection Detection - Quick Integration Test")
    print("=" * 55)
    
    tests = [
        ("Module Import", test_import),
        ("Unified Integration", test_unified_integration),
        ("Basic Functionality", test_basic_functionality)
    ]
    
    passed = 0
    for test_name, test_func in tests:
        print(f"\n{test_name}:")
        if test_func():
            passed += 1
            
    print(f"\n{'='*55}")
    print(f"Results: {passed}/{len(tests)} tests passed")
    
    if passed == len(tests):
        print("✓ All tests passed - Advanced detection engine ready!")
    else:
        print("✗ Some tests failed - check the output above")
        
    return passed == len(tests)

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)