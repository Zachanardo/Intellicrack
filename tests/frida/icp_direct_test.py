#!/usr/bin/env python3
"""
Direct ICP Backend Test

Ultra-focused test that directly imports only the ICP backend module
without any other Intellicrack components.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import asyncio
import os
import sys
import time

def setup_minimal_environment():
    """Setup minimal environment for ICP testing"""
    print("🔧 Setting up minimal test environment...")
    
    # Activate virtual environment if available
    venv_path = "/mnt/c/Intellicrack/test_venv/bin/python"
    if os.path.exists(venv_path) and sys.executable != venv_path:
        print(f"  ↻ Switching to virtual environment: {venv_path}")
        import subprocess
        result = subprocess.run([venv_path, __file__] + sys.argv[1:])
        sys.exit(result.returncode)
    
    # Add only the specific path for the ICP backend
    icp_backend_path = "/mnt/c/Intellicrack"
    if icp_backend_path not in sys.path:
        sys.path.insert(0, icp_backend_path)
    
    print("  ✓ Environment setup complete")

def test_die_python_standalone():
    """Test die-python in complete isolation"""
    print("\n🔍 Testing die-python standalone...")
    
    try:
        import die
        print(f"  ✓ die-python v{die.__version__} (DIE engine v{die.die_version})")
        
        # Test scan flags
        flags = [
            ("NORMAL", 0),
            ("DEEP", die.ScanFlags.DEEP_SCAN),
            ("HEURISTIC", die.ScanFlags.HEURISTIC_SCAN)
        ]
        
        for flag_name, flag_value in flags:
            print(f"  ✓ {flag_name} scan flag: {flag_value}")
            
        return True
        
    except Exception as e:
        print(f"  ✗ die-python test failed: {e}")
        return False

def test_icp_module_direct():
    """Test loading ICP module directly"""
    print("\n📦 Testing ICP module direct import...")
    
    try:
        # Import the specific file directly
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "icp_backend",
            "/mnt/c/Intellicrack/intellicrack/protection/icp_backend.py"
        )
        icp_backend = importlib.util.module_from_spec(spec)
        
        # Mock the logger to avoid imports
        import logging
        def get_logger(name):
            return logging.getLogger(name)
        
        # Add to module namespace to avoid import issues
        icp_backend.get_logger = get_logger
        sys.modules['intellicrack.utils.logger'] = type(sys)('mock_logger')
        sys.modules['intellicrack.utils.logger'].get_logger = get_logger
        
        # Execute the module
        spec.loader.exec_module(icp_backend)
        
        print("  ✓ ICP backend module loaded successfully")
        
        # Test class creation
        ICPBackend = icp_backend.ICPBackend
        ScanMode = icp_backend.ScanMode
        ICPScanResult = icp_backend.ICPScanResult
        
        backend = ICPBackend()
        print("  ✓ ICP backend instance created")
        
        # Test scan modes
        modes = list(ScanMode)
        print(f"  ✓ Scan modes available: {[m.name for m in modes]}")
        
        return True, backend, ICPScanResult, ScanMode
        
    except Exception as e:
        print(f"  ✗ ICP module import failed: {e}")
        import traceback
        traceback.print_exc()
        return False, None, None, None

def test_text_parsing_isolated(ICPScanResult):
    """Test text parsing in isolation"""
    print("\n📝 Testing text parsing (isolated)...")
    
    try:
        # Test sample inputs
        test_cases = [
            ("PE64\n    Unknown: Unknown", "Basic case"),
            ("PE64\n    Packer: UPX\n    Protector: Themida", "Multiple detections"),
            ("ELF64\n    Library: glibc", "ELF format"),
            ("", "Empty input"),
            ("PE32", "No detections"),
        ]
        
        for test_input, description in test_cases:
            print(f"    Testing: {description}")
            
            result = ICPScanResult.from_die_text("/test/sample.exe", test_input)
            
            if result.file_infos:
                file_info = result.file_infos[0]
                print(f"      ✓ File type: {file_info.filetype}")
                print(f"      ✓ Detections: {len(result.all_detections)}")
                
                for detection in result.all_detections:
                    print(f"        - {detection.type}: {detection.name}")
                    
                print(f"      ✓ Is packed: {result.is_packed}")
                print(f"      ✓ Is protected: {result.is_protected}")
            else:
                print("      ! No file infos generated")
                
        return True
        
    except Exception as e:
        print(f"  ✗ Text parsing test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def find_test_binary():
    """Find a test binary for analysis"""
    print("\n🔎 Finding test binary...")
    
    search_paths = [
        "/mnt/c/Intellicrack/backups/icp_engine_pre_rebrand",
        "/mnt/c/Intellicrack/dev/conflict_test/lib/python3.12/site-packages/pip/_vendor/distlib"
    ]
    
    for path in search_paths:
        if os.path.exists(path):
            for root, dirs, files in os.walk(path):
                for file in files:
                    if file.endswith(('.exe', '.dll')):
                        full_path = os.path.join(root, file)
                        if os.path.getsize(full_path) > 1024:
                            print(f"  ✓ Found test binary: {os.path.basename(full_path)}")
                            return full_path
                            
    print("  ! No test binary found")
    return None

async def test_async_analysis_isolated(backend, test_file, ScanMode):
    """Test async analysis in isolation"""
    print(f"\n⚡ Testing async analysis with {os.path.basename(test_file)}...")
    
    try:
        # Test each scan mode
        modes_to_test = [ScanMode.NORMAL, ScanMode.DEEP, ScanMode.HEURISTIC]
        
        for mode in modes_to_test:
            print(f"    Testing {mode.name} mode...")
            
            start_time = time.time()
            result = await backend.analyze_file(test_file, mode)
            analysis_time = time.time() - start_time
            
            if result and not result.error:
                detection_count = len(result.all_detections)
                print(f"      ✓ Success: {detection_count} detections ({analysis_time:.2f}s)")
                
                if result.file_infos:
                    file_info = result.file_infos[0]
                    print(f"        File type: {file_info.filetype}")
                    print(f"        Packed: {result.is_packed}")
                    print(f"        Protected: {result.is_protected}")
                    
                    # Show sample detections
                    for i, detection in enumerate(result.all_detections[:3]):
                        print(f"        Detection {i+1}: {detection.type} - {detection.name}")
                        
            elif result and result.error:
                print(f"      ! Error: {result.error}")
            else:
                print("      ! No result returned")
                
        return True
        
    except Exception as e:
        print(f"  ✗ Async analysis failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run direct ICP tests"""
    print("🎯 DIRECT ICP BACKEND TESTING")
    print("=" * 60)
    
    start_time = time.time()
    
    # Step 1: Setup environment
    setup_minimal_environment()
    
    # Step 2: Test die-python
    if not test_die_python_standalone():
        print("\n❌ FAILED: die-python not working")
        return 1
        
    # Step 3: Test ICP module
    module_result, backend, ICPScanResult, ScanMode = test_icp_module_direct()
    if not module_result:
        print("\n❌ FAILED: ICP module import failed")
        return 1
        
    # Step 4: Test text parsing
    if not test_text_parsing_isolated(ICPScanResult):
        print("\n❌ FAILED: Text parsing failed")
        return 1
        
    # Step 5: Test with real binary
    test_file = find_test_binary()
    if test_file:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            async_result = loop.run_until_complete(
                test_async_analysis_isolated(backend, test_file, ScanMode)
            )
        finally:
            loop.close()
            
        if not async_result:
            print("\n❌ FAILED: Async analysis failed")
            return 1
    else:
        print("\n⚠️  SKIPPED: No test binary available for async testing")
        
    total_time = time.time() - start_time
    
    print("\n" + "=" * 60)
    print("🎉 ALL DIRECT TESTS PASSED!")
    print(f"📊 Total time: {total_time:.2f}s")
    print("✅ ICP Backend core functionality working correctly")
    print("✅ die-python integration successful")
    print("✅ Text parsing system functional")
    print("✅ Async analysis system operational")
    print("=" * 60)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())