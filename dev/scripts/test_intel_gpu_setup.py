#!/usr/bin/env python3
"""
Test Intel GPU Setup for Intellicrack
Tests if Intel Extension for PyTorch is properly configured
"""

import sys
import os
import subprocess
import platform

def test_conda_ipex():
    """Test if conda environment with IPEX is available"""
    print("\n=== Testing Conda Environment with Intel Extension for PyTorch ===")

    # Check CONDA_PREFIX
    conda_prefix = os.environ.get('CONDA_PREFIX')
    if conda_prefix:
        print(f"✓ Current conda environment: {conda_prefix}")
    else:
        print("✗ No conda environment activated")
        print("  Please activate your conda environment with: conda activate <env_name>")
        return False

    # Test Python imports in current environment
    print("\nTesting imports in current Python:")
    try:
        import torch
        print(f"✓ PyTorch version: {torch.__version__}")

        try:
            import intel_extension_for_pytorch as ipex
            print(f"✓ Intel Extension for PyTorch version: {ipex.__version__}")

            # Check XPU availability
            if hasattr(torch, 'xpu') and torch.xpu.is_available():
                print(f"✓ Intel XPU is available!")
                print(f"  Device count: {torch.xpu.device_count()}")
                print(f"  Device name: {torch.xpu.get_device_name(0)}")

                # Test simple operation
                print("\nTesting XPU operation:")
                x = torch.randn(2, 2).to('xpu')
                y = torch.randn(2, 2).to('xpu')
                z = x + y
                print("✓ XPU tensor operation successful!")

                return True
            else:
                print("✗ Intel XPU is not available")
                print("  This might be a driver issue or GPU not detected")

        except ImportError as e:
            print(f"✗ Intel Extension for PyTorch not found: {e}")
            print("  Install with: conda install -c intel intel-extension-for-pytorch")

    except ImportError as e:
        print(f"✗ PyTorch not found: {e}")

    return False

def check_intel_gpu_drivers():
    """Check if Intel GPU drivers are installed"""
    print("\n=== Checking Intel GPU Drivers ===")

    if platform.system() == "Windows":
        # Check for Intel GPU in device manager
        try:
            result = subprocess.run(
                ['wmic', 'path', 'win32_VideoController', 'get', 'name'],
                capture_output=True,
                text=True
            )
            if 'Intel' in result.stdout:
                print("✓ Intel GPU detected in system")
                print(result.stdout)
            else:
                print("✗ No Intel GPU detected")
        except:
            print("✗ Could not check GPU devices")

        # Check Intel GPU driver
        try:
            result = subprocess.run(
                ['powershell', '-Command', 'Get-WmiObject Win32_PnPSignedDriver | Where-Object {$_.DeviceName -like "*Intel*Arc*" -or $_.DeviceName -like "*Intel*Graphics*"} | Select-Object DeviceName, DriverVersion'],
                capture_output=True,
                text=True
            )
            if result.stdout.strip():
                print("\nIntel GPU Driver Info:")
                print(result.stdout)
        except:
            pass

def suggest_setup_steps():
    """Suggest steps to set up Intel GPU properly"""
    print("\n=== Setup Instructions ===")
    print("1. Create and activate a conda environment:")
    print("   conda create -n intellicrack_gpu python=3.10")
    print("   conda activate intellicrack_gpu")
    print()
    print("2. Install PyTorch with Intel GPU support:")
    print("   conda install pytorch torchvision torchaudio -c pytorch")
    print()
    print("3. Install Intel Extension for PyTorch:")
    print("   conda install -c intel intel-extension-for-pytorch")
    print()
    print("4. Install Intellicrack in the conda environment:")
    print("   cd /mnt/c/Intellicrack")
    print("   pip install -e .")
    print()
    print("5. Set environment variable to use conda env:")
    print("   export INTELLICRACK_USE_CONDA=1")
    print("   export CONDA_DEFAULT_ENV=intellicrack_gpu")

def test_intellicrack_gpu():
    """Test Intellicrack GPU detection"""
    print("\n=== Testing Intellicrack GPU Detection ===")

    try:
        # Add Intellicrack to path
        sys.path.insert(0, '/mnt/c/Intellicrack')

        from intellicrack.utils.gpu_autoloader import gpu_autoloader, get_gpu_info

        # Setup GPU
        success = gpu_autoloader.setup()

        if success:
            print("✓ GPU setup successful!")
            info = get_gpu_info()
            print(f"  GPU Type: {info['type']}")
            print(f"  Device: {info['device']}")
            for key, value in info['info'].items():
                print(f"  {key}: {value}")
        else:
            print("✗ GPU setup failed")

    except Exception as e:
        print(f"✗ Error testing Intellicrack GPU: {e}")

def main():
    """Main test function"""
    print("=== Intel GPU Setup Test for Intellicrack ===")
    print(f"Python: {sys.version}")
    print(f"Platform: {platform.platform()}")

    # Test conda IPEX
    ipex_available = test_conda_ipex()

    # Check drivers
    check_intel_gpu_drivers()

    # Test Intellicrack
    if ipex_available:
        test_intellicrack_gpu()
    else:
        print("\n✗ Intel Extension for PyTorch not available")
        suggest_setup_steps()

if __name__ == "__main__":
    main()
