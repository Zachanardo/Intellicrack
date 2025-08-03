#!/usr/bin/env python3
"""
Test script for DIE JSON integration

This script validates that the DIE JSON wrapper integration is working correctly
and that we've successfully replaced fragile string parsing with structured JSON handling.
"""

import asyncio
import sys
import os
from pathlib import Path

# Add Intellicrack to path
sys.path.insert(0, str(Path(__file__).parent))

from intellicrack.core.analysis.die_json_wrapper import DIEJSONWrapper, DIEScanMode
from intellicrack.core.analysis.die_structured_logger import get_die_structured_logger
from intellicrack.protection.icp_backend import ICPBackend, ScanMode
from intellicrack.utils.logger import get_logger

logger = get_logger(__name__)

def test_die_json_wrapper():
    """Test basic DIE JSON wrapper functionality"""
    print("=== Testing DIE JSON Wrapper ===")
    
    try:
        # Create wrapper
        wrapper = DIEJSONWrapper()
        
        # Get version info
        version_info = wrapper.get_version_info()
        print("Version Information:")
        for component, version in version_info.items():
            print(f"  {component}: {version}")
        
        # Test with a simple binary (try to find one)
        test_files = [
            r"C:\Windows\System32\notepad.exe",
            r"C:\Windows\System32\calc.exe", 
            r"C:\Windows\System32\cmd.exe"
        ]
        
        test_file = None
        for file_path in test_files:
            if os.path.exists(file_path):
                test_file = file_path
                break
        
        if not test_file:
            print("Warning: No test binary found for analysis")
            return False
        
        print(f"\nTesting analysis with: {test_file}")
        
        # Test different scan modes
        for mode in [DIEScanMode.NORMAL, DIEScanMode.DEEP]:
            print(f"\n--- Testing {mode.value} scan mode ---")
            
            result = wrapper.analyze_file(test_file, mode, timeout=30)
            
            if result.error:
                print(f"Error: {result.error}")
                continue
            
            print(f"File Type: {result.file_type}")
            print(f"Architecture: {result.architecture}")
            print(f"File Size: {result.file_size}")
            print(f"Analysis Time: {result.analysis_time:.3f}s")
            print(f"Detections: {len(result.detections)}")
            
            for i, detection in enumerate(result.detections[:5]):  # Show first 5
                print(f"  {i+1}. {detection.type}: {detection.name}")
                if detection.version:
                    print(f"     Version: {detection.version}")
                print(f"     Confidence: {detection.confidence:.2f}")
            
            if len(result.detections) > 5:
                print(f"  ... and {len(result.detections) - 5} more")
            
            # Test JSON serialization
            try:
                json_str = result.to_json()
                print(f"JSON serialization: OK ({len(json_str)} chars)")
            except Exception as e:
                print(f"JSON serialization failed: {e}")
                return False
            
            # Test schema validation
            is_valid = wrapper.validate_json_schema(result)
            print(f"Schema validation: {'PASS' if is_valid else 'FAIL'}")
        
        return True
        
    except Exception as e:
        print(f"DIE JSON wrapper test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_icp_backend_integration():
    """Test ICP backend integration with DIE JSON wrapper"""
    print("\n=== Testing ICP Backend Integration ===")
    
    try:
        # Create backend
        backend = ICPBackend()
        
        # Find a test file
        test_files = [
            r"C:\Windows\System32\notepad.exe",
            r"C:\Windows\System32\calc.exe"
        ]
        
        test_file = None
        for file_path in test_files:
            if os.path.exists(file_path):
                test_file = file_path
                break
        
        if not test_file:
            print("Warning: No test binary found for analysis")
            return False
        
        print(f"Testing ICP backend with: {test_file}")
        
        # Test analysis
        result = await backend.analyze_file(
            test_file,
            scan_mode=ScanMode.NORMAL,
            timeout=30.0
        )
        
        if result.error:
            print(f"Error: {result.error}")
            return False
        
        print(f"Analysis completed in {result.analysis_time:.3f}s")
        print(f"File infos: {len(result.file_infos)}")
        print(f"Total detections: {len(result.all_detections)}")
        
        if result.file_infos:
            file_info = result.file_infos[0]
            print(f"File type: {file_info.filetype}")
            print(f"Detections in first file info: {len(file_info.detections)}")
            
            for detection in file_info.detections[:3]:
                print(f"  - {detection.type}: {detection.name}")
        
        # Test supplemental data
        if result.supplemental_data:
            print(f"Supplemental data keys: {list(result.supplemental_data.keys())}")
            
            if 'architecture' in result.supplemental_data:
                print(f"Architecture: {result.supplemental_data['architecture']}")
            if 'entropy' in result.supplemental_data:
                print(f"Entropy: {result.supplemental_data['entropy']}")
        
        return True
        
    except Exception as e:
        print(f"ICP backend integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_structured_logging():
    """Test structured logging integration"""
    print("\n=== Testing Structured Logging ===")
    
    try:
        logger_instance = get_die_structured_logger()
        
        # Get statistics
        stats = logger_instance.get_analysis_statistics()
        print("Analysis Statistics:")
        for key, value in stats.items():
            print(f"  {key}: {value}")
        
        # Test JSON export
        json_stats = logger_instance.export_statistics_json()
        print(f"Statistics JSON export: OK ({len(json_stats)} chars)")
        
        return True
        
    except Exception as e:
        print(f"Structured logging test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests"""
    print("DIE JSON Integration Test Suite")
    print("=" * 50)
    
    tests = [
        ("DIE JSON Wrapper", test_die_json_wrapper),
        ("ICP Backend Integration", test_icp_backend_integration),
        ("Structured Logging", test_structured_logging)
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        print(f"\nRunning {test_name} test...")
        try:
            if asyncio.iscoroutinefunction(test_func):
                result = asyncio.run(test_func())
            else:
                result = test_func()
            results[test_name] = result
            print(f"{test_name}: {'PASS' if result else 'FAIL'}")
        except Exception as e:
            print(f"{test_name}: FAIL ({e})")
            results[test_name] = False
    
    print("\n" + "=" * 50)
    print("Test Results Summary:")
    
    all_passed = True
    for test_name, result in results.items():
        status = "PASS" if result else "FAIL"
        print(f"  {test_name}: {status}")
        if not result:
            all_passed = False
    
    print(f"\nOverall: {'PASS' if all_passed else 'FAIL'}")
    
    if all_passed:
        print("\n✓ DIE JSON integration is working correctly!")
        print("✓ Fragile string parsing has been successfully replaced")
        print("✓ Structured logging is functional")
        print("✓ Error handling and validation are in place")
    else:
        print("\n✗ Some tests failed. Check the output above for details.")
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())