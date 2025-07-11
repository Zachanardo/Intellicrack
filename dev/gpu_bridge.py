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
GPU Bridge - Uses Conda for Intel GPU, UV for everything else
"""
import sys
import os

# Add UV's site-packages to Python path
uv_site_packages = r"C:\Intellicrack\.venv\Lib\site-packages"
if os.path.exists(uv_site_packages) and uv_site_packages not in sys.path:
    sys.path.insert(0, uv_site_packages)
    print(f"✓ Added UV packages from: {uv_site_packages}")

# Verify Intel GPU is available
try:
    import torch
    import intel_extension_for_pytorch as ipex
    print(f"✓ PyTorch version: {torch.__version__}")
    print(f"✓ IPEX version: {ipex.__version__}")
    
    if hasattr(torch, 'xpu') and torch.xpu.is_available():
        print(f"✓ Intel GPU detected: {torch.xpu.get_device_name(0)}")
        print(f"✓ XPU device count: {torch.xpu.device_count()}")
    else:
        print("⚠ XPU not available")
except ImportError as e:
    print(f"❌ Error loading Intel GPU support: {e}")

# Now you can import from UV packages
try:
    import intellicrack
    print("✓ Intellicrack loaded successfully")
except ImportError as e:
    print(f"⚠ Could not load Intellicrack: {e}")

# Run your code here or import launch_intellicrack
if __name__ == "__main__":
    # Example: Launch Intellicrack with GPU support
    import launch_intellicrack
    launch_intellicrack.main()