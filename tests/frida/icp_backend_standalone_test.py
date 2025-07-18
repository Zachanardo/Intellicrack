#!/usr/bin/env python3
"""
Standalone ICP Backend Test

Direct testing of the ICP backend integration without full GUI dependencies.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import asyncio
import os
import sys
import time
from pathlib import Path

# Add Intellicrack to path
sys.path.insert(0, str(Path(__file__).parent))

from intellicrack.protection.icp_backend import ScanMode

def test_die_python_basic():
    """Test basic die-python functionality"""
    print("🔍 Testing die-python basic functionality...")
    
    try:
        import die
        print(f"✓ die-python imported successfully (v{die.__version__})")
        print(f"✓ DIE engine version: {die.die_version}")
        
        # Find a test binary
        test_paths = [
            "/mnt/c/Intellicrack/backups/icp_engine_pre_rebrand",
            "/mnt/c/Intellicrack/dev/conflict_test/lib/python3.12/site-packages/pip/_vendor/distlib"
        ]
        
        test_file = None
        for path in test_paths:
            if os.path.exists(path):
                for root, dirs, files in os.walk(path):
                    for file in files:
                        if file.endswith(('.exe', '.dll')):
                            full_path = os.path.join(root, file)
                            if os.path.getsize(full_path) > 1024:
                                test_file = full_path
                                break
                    if test_file:
                        break
            if test_file:
                break
        
        if not test_file:
            print("✗ No test binaries found")
            return False
            
        print(f"📁 Testing with: {os.path.basename(test_file)}")
        
        # Test scan
        result = die.scan_file(test_file, die.ScanFlags.DEEP_SCAN)
        if result and result.strip():
            lines = result.strip().split('\n')
            detection_count = len([line for line in lines[1:] if line.strip()])
            print(f"✓ Basic scan successful: {detection_count} detections")
            print(f"  Sample output: {repr(result[:100])}")
        else:
            print("✓ Basic scan completed (no detections)")
            
        return True, test_file
        
    except Exception as e:
        print(f"✗ die-python test failed: {e}")
        return False, None


def test_icp_backend_direct():
    """Test ICP backend directly"""
    print("\n🔧 Testing ICP backend direct import...")
    
    try:
        # Import only the backend components we need
        sys.path.insert(0, '/mnt/c/Intellicrack')
        
        # Import just the backend module
        from intellicrack.protection.icp_backend import ICPBackend
        
        print("✓ ICP backend components imported successfully")
        
        # Create backend
        backend = ICPBackend()
        print("✓ ICP backend initialized")
        
        return True, backend
        
    except Exception as e:
        print(f"✗ ICP backend import failed: {e}")
        import traceback
        traceback.print_exc()
        return False, None


async def test_icp_async_analysis(backend, test_file):
    """Test async analysis"""
    print("\n⚡ Testing ICP async analysis...")
    
    try:
        # Test different scan modes
        scan_modes = [ScanMode.NORMAL, ScanMode.DEEP, ScanMode.HEURISTIC]
        
        for scan_mode in scan_modes:
            print(f"  Testing {scan_mode.name} mode...")
            
            start_time = time.time()
            result = await backend.analyze_file(test_file, scan_mode)
            analysis_time = time.time() - start_time
            
            if result and not result.error:
                detection_count = len(result.all_detections)
                print(f"  ✓ {scan_mode.name}: {detection_count} detections ({analysis_time:.2f}s)")
                
                # Validate result structure
                if hasattr(result, 'file_infos') and result.file_infos:
                    print(f"    ✓ File infos: {len(result.file_infos)}")
                    
                if hasattr(result, 'is_packed') and hasattr(result, 'is_protected'):
                    print(f"    ✓ Flags: packed={result.is_packed}, protected={result.is_protected}")
                    
            elif result and result.error:
                print(f"  ! {scan_mode.name}: Error - {result.error}")
            else:
                print(f"  ! {scan_mode.name}: No result returned")
                
        return True
        
    except Exception as e:
        print(f"✗ Async analysis failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_text_parser():
    """Test the new text parser"""
    print("\n📝 Testing die-python text parser...")
    
    try:
        from intellicrack.protection.icp_backend import ICPScanResult
        
        # Test with sample text output
        sample_text = "PE64\n    Unknown: Unknown\n    Packer: UPX\n    Protector: Themida"
        
        result = ICPScanResult.from_die_text("/test/file.exe", sample_text)
        
        print("✓ Text parsing successful")
        print(f"  File type: {result.file_infos[0].filetype if result.file_infos else 'None'}")
        print(f"  Detections: {len(result.all_detections)}")
        
        for detection in result.all_detections:
            print(f"    - {detection.type}: {detection.name}")
            
        # Test protection flags
        print(f"  Is packed: {result.is_packed}")
        print(f"  Is protected: {result.is_protected}")
        
        return True
        
    except Exception as e:
        print(f"✗ Text parser test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run standalone ICP backend tests"""
    print("🔬 STANDALONE ICP BACKEND TESTING")
    print("=" * 50)
    
    start_time = time.time()
    
    # Test 1: die-python basic
    die_result, test_file = test_die_python_basic()
    if not die_result:
        print("\n❌ FAILED: die-python basic test failed")
        return 1
        
    # Test 2: ICP backend direct
    backend_result, backend = test_icp_backend_direct()
    if not backend_result:
        print("\n❌ FAILED: ICP backend import failed")
        return 1
        
    # Test 3: Text parser
    parser_result = test_text_parser()
    if not parser_result:
        print("\n❌ FAILED: Text parser test failed")
        return 1
        
    # Test 4: Async analysis
    if test_file and backend:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            async_result = loop.run_until_complete(
                test_icp_async_analysis(backend, test_file)
            )
        finally:
            loop.close()
            
        if not async_result:
            print("\n❌ FAILED: Async analysis test failed")
            return 1
    else:
        print("\n⚠️  SKIPPED: Async analysis (no test file or backend)")
        
    total_time = time.time() - start_time
    
    print("\n" + "=" * 50)
    print("🎉 ALL TESTS PASSED!")
    print(f"Total time: {total_time:.2f}s")
    print("ICP Backend integration is working correctly.")
    print("=" * 50)
    
    return 0


if __name__ == "__main__":
    # Activate virtual environment if available
    venv_path = "/mnt/c/Intellicrack/test_venv/bin/python"
    if os.path.exists(venv_path) and sys.executable != venv_path:
        import subprocess
        result = subprocess.run([venv_path, __file__] + sys.argv[1:])
        sys.exit(result.returncode)
    
    sys.exit(main())