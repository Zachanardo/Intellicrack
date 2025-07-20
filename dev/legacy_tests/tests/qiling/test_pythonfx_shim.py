#!/usr/bin/env python3
"""
Comprehensive test suite for python-fx shim
Tests all functionality to ensure nothing is lost
"""
import sys
import os
import tempfile
import json
import subprocess

def test_shim_before_install():
    """Test what python-fx provides before we replace it"""
    print("=== Testing original python-fx functionality ===")
    
    # First reinstall the original python-fx
    print("Installing original python-fx...")
    result = subprocess.run([sys.executable, "-m", "pip", "install", "python-fx==0.3.2"], 
                          capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error installing: {result.stderr}")
        return False
    
    tests_passed = 0
    tests_failed = 0
    
    # Test 1: Import main module
    try:
        import pyfx
        print("✓ Test 1: pyfx module imports")
        tests_passed += 1
    except Exception as e:
        print(f"✗ Test 1: Failed to import pyfx: {e}")
        tests_failed += 1
        return False
    
    # Test 2: Check main exports
    expected_attrs = ['PyfxApp', 'app', 'config', 'error', 'model', 'service', 'view']
    missing = []
    for attr in expected_attrs:
        if not hasattr(pyfx, attr):
            missing.append(attr)
    
    if not missing:
        print(f"✓ Test 2: All main exports present: {expected_attrs}")
        tests_passed += 1
    else:
        print(f"✗ Test 2: Missing exports: {missing}")
        tests_failed += 1
    
    # Test 3: Check submodules
    submodules = [
        'pyfx.app', 'pyfx.cli', 'pyfx.error', 'pyfx.model', 
        'pyfx.service', 'pyfx.view', 'pyfx.config'
    ]
    for module in submodules:
        try:
            __import__(module)
            print(f"✓ Test 3.{module}: {module} imports")
            tests_passed += 1
        except Exception as e:
            print(f"✗ Test 3.{module}: Failed to import {module}: {e}")
            tests_failed += 1
    
    # Test 4: Check version
    try:
        import pyfx.__version__
        version = getattr(pyfx.__version__, '__version__', None)
        if version == "0.3.2":
            print(f"✓ Test 4: Version correct: {version}")
            tests_passed += 1
        else:
            print(f"✗ Test 4: Version mismatch: {version}")
            tests_failed += 1
    except Exception as e:
        print(f"✗ Test 4: Version check failed: {e}")
        tests_failed += 1
    
    # Test 5: CLI entry point
    try:
        result = subprocess.run([sys.executable, "-m", "pyfx.cli", "--help"], 
                              capture_output=True, text=True)
        if result.returncode == 0 or "Usage:" in result.stdout or "Usage:" in result.stderr:
            print("✓ Test 5: CLI entry point works")
            tests_passed += 1
        else:
            print(f"✗ Test 5: CLI failed: {result.stderr}")
            tests_failed += 1
    except Exception as e:
        print(f"✗ Test 5: CLI test failed: {e}")
        tests_failed += 1
    
    # Test 6: Test with qiling
    try:
        import qiling
        print("✓ Test 6: qiling imports with python-fx")
        tests_passed += 1
    except Exception as e:
        print(f"✗ Test 6: qiling import failed: {e}")
        tests_failed += 1
    
    print(f"\n=== Original python-fx: {tests_passed} passed, {tests_failed} failed ===")
    
    # Save the test results
    with open("original_pythonfx_test_results.txt", "w") as f:
        f.write(f"Tests passed: {tests_passed}\n")
        f.write(f"Tests failed: {tests_failed}\n")
    
    return tests_failed == 0

def test_shim_functionality():
    """Test the shim in isolation before installing"""
    print("\n=== Testing shim functionality in isolation ===")
    
    # Create a temporary directory for testing
    import tempfile
    import shutil
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Copy the shim creation script
        shutil.copy("create_full_pythonfx_shim.py", temp_dir)
        
        # Modify sys.path to test in isolation
        old_path = sys.path.copy()
        sys.path.insert(0, temp_dir)
        
        # Create a fake site-packages in temp
        fake_site = os.path.join(temp_dir, "site-packages")
        os.makedirs(fake_site, exist_ok=True)
        
        # Temporarily override site.getsitepackages
        import site
        old_getsitepackages = site.getsitepackages
        site.getsitepackages = lambda: [fake_site]
        
        try:
            # Run the shim creation in the temp directory
            os.chdir(temp_dir)
            
            # Read and execute the shim creation script with proper globals
            with open("create_full_pythonfx_shim.py", 'r') as f:
                shim_code = f.read()
            
            # Create a proper globals dict with necessary imports
            exec_globals = {
                '__name__': '__main__',
                '__file__': 'create_full_pythonfx_shim.py',
                'os': os,
                'site': site,
                'sys': sys
            }
            
            exec(shim_code, exec_globals)
            
            # Add fake site-packages to path
            sys.path.insert(0, fake_site)
            
            # Test the shim
            tests_passed = 0
            tests_failed = 0
            
            # Import tests
            try:
                import pyfx
                print("✓ Shim test: pyfx imports")
                tests_passed += 1
                
                # Check all expected attributes
                for attr in ['PyfxApp', 'app', 'config', 'error', 'model', 'service', 'view']:
                    if hasattr(pyfx, attr):
                        print(f"✓ Shim test: {attr} present")
                        tests_passed += 1
                    else:
                        print(f"✗ Shim test: {attr} missing")
                        tests_failed += 1
                        
            except Exception as e:
                print(f"✗ Shim test: Import failed: {e}")
                tests_failed += 1
                import traceback
                traceback.print_exc()
                
        finally:
            # Restore
            sys.path = old_path
            site.getsitepackages = old_getsitepackages
            os.chdir("C:\\Intellicrack")
    
    print(f"\n=== Shim isolation test: {tests_passed} passed, {tests_failed} failed ===")
    return tests_failed == 0

if __name__ == "__main__":
    print("Starting comprehensive python-fx shim testing...\n")
    
    # Test original
    original_ok = test_shim_before_install()
    
    # Test shim in isolation
    shim_ok = test_shim_functionality()
    
    if original_ok and shim_ok:
        print("\n✓ All tests passed! Safe to install shim.")
    else:
        print("\n✗ Tests failed! Do not install shim.")
        sys.exit(1)