"""
Windows Compatibility Tests for Intellicrack

Tests to ensure the application works correctly on Windows systems.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import sys
import os
import platform
import subprocess
from pathlib import Path


def test_platform_detection():
    """Test that we can detect Windows platform correctly"""
    print(f"Platform: {platform.system()}")
    print(f"Python version: {sys.version}")
    
    # Check if we're on Windows or WSL
    is_windows = platform.system() == "Windows"
    is_wsl = "microsoft" in platform.uname().release.lower()
    
    print(f"Is Windows: {is_windows}")
    print(f"Is WSL: {is_wsl}")
    
    assert is_windows or is_wsl, "Not running on Windows or WSL"


def test_path_handling():
    """Test Windows path handling"""
    # Test various path formats
    paths_to_test = [
        r"C:\Intellicrack\test.exe",
        "C:/Intellicrack/test.exe",
        "/mnt/c/Intellicrack/test.exe",
        Path("C:/Intellicrack/test.exe")
    ]
    
    for path in paths_to_test:
        print(f"Testing path: {path}")
        # Convert to Path object
        path_obj = Path(path) if not isinstance(path, Path) else path
        print(f"  Resolved: {path_obj}")
        print(f"  Parts: {path_obj.parts}")


def test_pyqt6_import():
    """Test PyQt6 imports work correctly"""
    try:
        from PyQt6.QtWidgets import QApplication
        from PyQt6.QtCore import Qt
        from PyQt6.QtGui import QFont
        print("PyQt6 imports successful")
        
        # Test Qt namespace (common issue)
        print(f"Qt.WindowType.Window = {Qt.WindowType.Window}")
        print(f"Qt.AlignmentFlag.AlignCenter = {Qt.AlignmentFlag.AlignCenter}")
        
    except ImportError as e:
        print(f"PyQt6 import error: {e}")
        raise


def test_file_operations():
    """Test file operations on Windows"""
    test_file = Path("test_windows_file.tmp")
    
    try:
        # Write test
        with open(test_file, 'w') as f:
            f.write("Windows test file\n")
        print(f"Created test file: {test_file}")
        
        # Read test
        with open(test_file, 'r') as f:
            content = f.read()
        print(f"Read content: {content.strip()}")
        
        # Binary write/read test
        binary_data = b"\x4D\x5A\x90\x00"  # PE header start
        with open(test_file, 'wb') as f:
            f.write(binary_data)
        
        with open(test_file, 'rb') as f:
            read_data = f.read()
        
        assert read_data == binary_data, "Binary data mismatch"
        print("Binary file operations successful")
        
    finally:
        # Cleanup
        if test_file.exists():
            test_file.unlink()
            print(f"Cleaned up test file")


def test_process_execution():
    """Test process execution on Windows"""
    # Test running basic commands
    if platform.system() == "Windows":
        commands = [
            ["cmd", "/c", "echo", "Hello from Windows"],
            ["powershell", "-Command", "Write-Host 'PowerShell test'"]
        ]
    else:
        commands = [
            ["echo", "Hello from WSL"],
            ["ls", "-la"]
        ]
    
    for cmd in commands:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            print(f"Command: {' '.join(cmd)}")
            print(f"  Output: {result.stdout.strip()}")
            print(f"  Return code: {result.returncode}")
        except Exception as e:
            print(f"  Error: {e}")


def test_dll_loading():
    """Test that we can handle Windows DLLs"""
    import ctypes
    
    try:
        # Try to load a common Windows DLL
        if platform.system() == "Windows":
            kernel32 = ctypes.windll.kernel32
            print("Successfully loaded kernel32.dll")
            
            # Test a simple function
            pid = kernel32.GetCurrentProcessId()
            print(f"Current process ID: {pid}")
        else:
            print("Skipping DLL test on non-Windows platform")
            
    except Exception as e:
        print(f"DLL loading error: {e}")


def test_intellicrack_imports():
    """Test Intellicrack module imports"""
    modules_to_test = [
        "intellicrack.logger",
        "intellicrack.core.app_context",
        "intellicrack.core.task_manager",
        "intellicrack.ui.main_app",
        "intellicrack.ui.tabs.base_tab"
    ]
    
    for module in modules_to_test:
        try:
            __import__(module)
            print(f"✓ Successfully imported {module}")
        except ImportError as e:
            print(f"✗ Failed to import {module}: {e}")
            # Don't raise, just report


def test_gpu_detection():
    """Test GPU detection on Windows"""
    try:
        # Check for NVIDIA GPU
        if platform.system() == "Windows":
            result = subprocess.run(
                ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                print(f"NVIDIA GPU detected: {result.stdout.strip()}")
            else:
                print("No NVIDIA GPU detected")
        
        # Check for Intel Arc
        try:
            import pyopencl as cl
            platforms = cl.get_platforms()
            for platform in platforms:
                print(f"OpenCL platform: {platform.name}")
                devices = platform.get_devices()
                for device in devices:
                    print(f"  Device: {device.name}")
        except:
            print("PyOpenCL not available")
            
    except Exception as e:
        print(f"GPU detection error: {e}")


def main():
    """Run all Windows compatibility tests"""
    print("=" * 60)
    print("Intellicrack Windows Compatibility Tests")
    print("=" * 60)
    print()
    
    tests = [
        ("Platform Detection", test_platform_detection),
        ("Path Handling", test_path_handling),
        ("PyQt6 Import", test_pyqt6_import),
        ("File Operations", test_file_operations),
        ("Process Execution", test_process_execution),
        ("DLL Loading", test_dll_loading),
        ("Intellicrack Imports", test_intellicrack_imports),
        ("GPU Detection", test_gpu_detection)
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        print(f"\n[TEST] {test_name}")
        print("-" * 40)
        try:
            test_func()
            print(f"✓ {test_name} PASSED")
            passed += 1
        except Exception as e:
            print(f"✗ {test_name} FAILED: {e}")
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"Test Results: {passed} passed, {failed} failed")
    print("=" * 60)
    
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())