#!/usr/bin/env python3
"""
This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
Hybrid launcher that detects and uses appropriate environment for GPU acceleration
"""
import os
import sys
import subprocess
import importlib.util

def check_intel_gpu_available():
    """Check if Intel GPU packages are available"""
    try:
        import torch
        if hasattr(torch, 'xpu') and torch.xpu.is_available():
            return True, "Intel XPU"
    except:
        pass

    try:
        import torch_directml
        return True, "DirectML"
    except:
        pass

    return False, None

def setup_gpu_environment():
    """Setup GPU environment based on what's available"""
    # Check if we're in conda env with Intel GPU support
    if 'CONDA_PREFIX' in os.environ:
        conda_env = os.environ['CONDA_PREFIX']
        ipex_path = os.path.join(conda_env, 'lib', 'site-packages', 'intel_extension_for_pytorch')
        if os.path.exists(ipex_path):
            print("✓ Intel Extension for PyTorch found in Conda environment")
            return True

    # Check UV environment
    gpu_available, gpu_type = check_intel_gpu_available()
    if gpu_available:
        print(f"✓ GPU acceleration available via {gpu_type}")
        return True

    print("⚠ No GPU acceleration found, running in CPU mode")
    return False

def merge_environments():
    """Merge UV and Conda environments for comprehensive package access"""
    paths_to_add = []

    # Add UV packages
    uv_site_packages = os.path.join(os.path.dirname(__file__), '.venv', 'Lib', 'site-packages')
    if os.path.exists(uv_site_packages):
        paths_to_add.append(uv_site_packages)

    # Add to Python path
    for path in paths_to_add:
        if path not in sys.path:
            sys.path.insert(0, path)

    print(f"✓ Added {len(paths_to_add)} paths to Python environment")

def main():
    print("=== Intellicrack GPU Launcher ===")
    print(f"Python: {sys.version}")
    print(f"Executable: {sys.executable}")
    print()

    # Setup environment
    gpu_enabled = setup_gpu_environment()
    merge_environments()

    # Set environment variables
    os.environ['INTELLICRACK_GPU_ENABLED'] = '1' if gpu_enabled else '0'

    # Import and run Intellicrack
    try:
        print("\nLaunching Intellicrack...")
        import launch_intellicrack
        launch_intellicrack.main()
    except ImportError as e:
        print(f"Error importing Intellicrack: {e}")
        print("\nTrying alternative launch method...")
        subprocess.run([sys.executable, "launch_intellicrack.py"])

if __name__ == "__main__":
    main()
