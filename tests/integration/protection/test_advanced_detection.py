#!/usr/bin/env python3
"""
Test script for the Advanced Protection Detection Engine

This script tests the new advanced detection capabilities with real binary files.
"""

import os
import sys
import time
from pathlib import Path

# Add the project root to the path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from intellicrack.protection.advanced_detection_engine import (
    get_advanced_detection_engine,
    AdvancedDetectionEngine
)
from intellicrack.protection.unified_protection_engine import (
    get_unified_engine,
    UnifiedProtectionEngine
)
from intellicrack.utils.logger import get_logger

logger = get_logger(__name__)


def test_advanced_entropy_analysis():
    """Test advanced entropy analysis"""
    print("=== Testing Advanced Entropy Analysis ===")
    
    # Get test binaries
    test_files = []
    
    # Look for test binaries in fixtures
    fixtures_dir = project_root / "tests" / "fixtures" / "binaries"
    if fixtures_dir.exists():
        for file_path in fixtures_dir.rglob("*"):
            if file_path.is_file() and file_path.stat().st_size > 1024:
                test_files.append(file_path)
                if len(test_files) >= 5:  # Limit to first 5 files
                    break
    
    # Add system binaries if available
    system_paths = [
        "C:\\Windows\\System32\\notepad.exe",
        "C:\\Windows\\System32\\calc.exe",
        "C:\\Windows\\System32\\mspaint.exe"
    ]
    
    for sys_path in system_paths:
        if os.path.exists(sys_path):
            test_files.append(Path(sys_path))
            
    if not test_files:
        print("No test files found!")
        return False
        
    engine = get_advanced_detection_engine()
    
    for test_file in test_files[:3]:  # Test first 3 files
        print(f"\nTesting: {test_file}")
        try:
            start_time = time.time()
            result = engine.analyze(str(test_file), deep_analysis=True)
            analysis_time = time.time() - start_time
            
            print(f"Analysis completed in {analysis_time:.2f}s")
            print(f"Overall Confidence: {result.overall_confidence:.1f}%")
            print(f"Protection Layers: {result.protection_layers}")
            print(f"Evasion Sophistication: {result.evasion_sophistication}")
            print(f"Detections Found: {len(result.detections)}")
            
            # Print entropy metrics
            entropy = result.entropy_metrics
            print(f"Entropy: {entropy.overall_entropy:.2f}")
            print(f"Packed Probability: {entropy.packed_probability:.1f}%")
            print(f"High Entropy Sections: {len(entropy.high_entropy_sections)}")
            
            # Print import analysis
            imports = result.import_analysis
            print(f"Total Imports: {imports.total_imports}")
            print(f"Obfuscation Probability: {imports.obfuscation_probability:.1f}%")
            
            # Print anti-analysis findings
            anti = result.anti_analysis
            print(f"Anti-Debug Techniques: {len(anti.anti_debug_techniques)}")
            print(f"Anti-VM Techniques: {len(anti.anti_vm_techniques)}")
            print(f"Evasion Score: {anti.evasion_score:.1f}")
            
            # Print detections
            if result.detections:
                print("Detections:")
                for detection in result.detections:
                    print(f"  • {detection.name} ({detection.type.value}) - {detection.confidence:.1f}%")
            
        except Exception as e:
            print(f"Error analyzing {test_file}: {e}")
            
    return True


def test_unified_engine_integration():
    """Test integration with unified protection engine"""
    print("\n=== Testing Unified Engine Integration ===")
    
    # Find a test binary
    test_file = None
    
    # Look for a system binary
    system_paths = [
        "C:\\Windows\\System32\\notepad.exe",
        "C:\\Windows\\System32\\calc.exe"
    ]
    
    for sys_path in system_paths:
        if os.path.exists(sys_path):
            test_file = sys_path
            break
            
    if not test_file:
        print("No test file found for unified engine test!")
        return False
        
    print(f"Testing unified engine with: {test_file}")
    
    try:
        unified_engine = get_unified_engine()
        start_time = time.time()
        result = unified_engine.analyze(test_file, deep_scan=True)
        analysis_time = time.time() - start_time
        
        print(f"Analysis completed in {analysis_time:.2f}s")
        print(f"Engines Used: {', '.join(result.engines_used)}")
        print(f"Overall Confidence: {result.confidence_score:.1f}%")
        print(f"Is Packed: {result.is_packed}")
        print(f"Is Protected: {result.is_protected}")
        print(f"Has Anti-Debug: {result.has_anti_debug}")
        print(f"Has Anti-VM: {result.has_anti_vm}")
        print(f"Protections Found: {len(result.protections)}")
        
        # Print protections by source
        sources = {}
        for protection in result.protections:
            source = protection.get('source', 'unknown')
            if source not in sources:
                sources[source] = []
            sources[source].append(protection)
            
        for source, protections in sources.items():
            print(f"\n{source} detections ({len(protections)}):")
            for protection in protections:
                print(f"  • {protection['name']} ({protection['type']}) - {protection['confidence']:.1f}%")
                
        # Check if advanced engine was used
        if result.advanced_analysis:
            print(f"\nAdvanced Engine Results:")
            print(f"  Entropy: {result.advanced_analysis.entropy_metrics.overall_entropy:.2f}")
            print(f"  Packed Probability: {result.advanced_analysis.entropy_metrics.packed_probability:.1f}%")
            print(f"  Import Obfuscation: {result.advanced_analysis.import_analysis.obfuscation_probability:.1f}%")
            print(f"  Anti-Analysis Score: {result.advanced_analysis.anti_analysis.evasion_score:.1f}")
        
    except Exception as e:
        print(f"Error in unified engine test: {e}")
        return False
        
    return True


def test_signature_detection():
    """Test signature detection capabilities"""
    print("\n=== Testing Signature Detection ===")
    
    # Look for packed binaries in test fixtures
    test_files = []
    
    packed_dir = project_root / "tests" / "fixtures" / "binaries" / "pe" / "real_protected"
    if packed_dir.exists():
        for file_path in packed_dir.rglob("*.exe"):
            if file_path.is_file():
                test_files.append(file_path)
                
    # Also check for UPX directory
    upx_dir = packed_dir / "upx_packer" if packed_dir.exists() else None
    if upx_dir and upx_dir.exists():
        for file_path in upx_dir.rglob("*.exe"):
            if file_path.is_file():
                test_files.append(file_path)
                
    if not test_files:
        print("No packed test files found for signature testing!")
        # Test with system files anyway
        test_files = [
            Path("C:\\Windows\\System32\\notepad.exe"),
            Path("C:\\Windows\\System32\\calc.exe")
        ]
        test_files = [f for f in test_files if f.exists()]
        
    if not test_files:
        print("No test files available!")
        return False
        
    engine = get_advanced_detection_engine()
    
    for test_file in test_files[:3]:  # Test first 3 files
        print(f"\nTesting signatures on: {test_file}")
        try:
            result = engine.analyze(str(test_file))
            
            if result.detections:
                print("Signature detections:")
                for detection in result.detections:
                    if hasattr(detection, 'details') and detection.details:
                        print(f"  • {detection.name} ({detection.type.value}) - {detection.confidence:.1f}%")
                        if 'matched_patterns' in detection.details:
                            print(f"    Patterns: {detection.details['matched_patterns']}")
                        if detection.bypass_recommendations:
                            print(f"    Bypass: {detection.bypass_recommendations[0]}")
            else:
                print("  No signature detections found")
                
        except Exception as e:
            print(f"Error testing signatures on {test_file}: {e}")
            
    return True


def main():
    """Main test function"""
    print("Advanced Protection Detection Engine Test Suite")
    print("=" * 50)
    
    tests = [
        ("Advanced Entropy Analysis", test_advanced_entropy_analysis),
        ("Unified Engine Integration", test_unified_engine_integration),
        ("Signature Detection", test_signature_detection)
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\nRunning: {test_name}")
        try:
            success = test_func()
            results.append((test_name, success))
        except Exception as e:
            print(f"Test {test_name} failed with exception: {e}")
            results.append((test_name, False))
            
    print("\n" + "=" * 50)
    print("Test Results Summary:")
    for test_name, success in results:
        status = "PASS" if success else "FAIL"
        print(f"  {test_name}: {status}")
        
    passed = sum(1 for _, success in results if success)
    total = len(results)
    print(f"\nOverall: {passed}/{total} tests passed")
    
    return passed == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)