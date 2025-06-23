#!/usr/bin/env python3
"""
Smart dependency installer for Intellicrack that handles Python version compatibility.

This script attempts to install dependencies in order of importance, 
gracefully handling failures for optional packages.
"""

import subprocess
import sys
import platform
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def run_pip_install(packages, description="packages", optional=False):
    """Install packages with error handling."""
    logger.info(f"Installing {description}...")
    
    if isinstance(packages, str):
        packages = [packages]
    
    for package in packages:
        try:
            cmd = [sys.executable, "-m", "pip", "install", package]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            logger.info(f"✓ Successfully installed: {package}")
        except subprocess.CalledProcessError as e:
            if optional:
                logger.warning(f"⚠ Optional package failed: {package} - {e.stderr.strip()}")
            else:
                logger.error(f"✗ Failed to install: {package} - {e.stderr.strip()}")
                return False
    return True

def main():
    """Main installation routine."""
    logger.info(f"Installing Intellicrack dependencies for Python {sys.version}")
    logger.info(f"Platform: {platform.system()} {platform.machine()}")
    
    # Core packages (essential for basic functionality)
    core_packages = [
        "PyQt5>=5.15.0",
        "requests>=2.31.0", 
        "click>=8.1.0",
        "rich>=13.0.0",
        "pyyaml>=6.0.0",
        "pefile>=2023.2.7",
        "pyelftools>=0.29",
        "cryptography>=41.0.0",
        "setuptools>=60.0.0"
    ]
    
    # Install core packages
    if not run_pip_install(core_packages, "core packages"):
        logger.error("Failed to install core packages. Aborting.")
        return 1
    
    # Optional ML packages (may fail on some systems)
    ml_packages = [
        "numpy>=1.24.0,<2.2.0",
        "pandas>=2.0.0,<2.3.0",
        "matplotlib>=3.7.0,<3.10.0",
        "numba>=0.58.0,<0.62.0",
        "scikit-learn>=1.3.0,<1.8.0"
    ]
    
    run_pip_install(ml_packages, "basic ML packages", optional=True)
    
    # Advanced ML packages (more likely to fail)
    advanced_ml = [
        "torch>=2.0.0,<2.8.0",
        "transformers>=4.35.0,<4.50.0",
        "tensorflow>=2.15.0,<2.20.0"
    ]
    
    run_pip_install(advanced_ml, "advanced ML packages", optional=True)
    
    # Platform-specific packages
    if platform.system() == "Windows":
        windows_packages = ["pywin32>=305", "wmi>=1.5.0"]
        run_pip_install(windows_packages, "Windows-specific packages", optional=True)
    
    # GPU/CUDA packages (often fail)
    gpu_packages = ["triton>=3.0.0"] if platform.system() == "Linux" else []
    if gpu_packages:
        run_pip_install(gpu_packages, "GPU packages", optional=True)
    
    logger.info("✓ Dependency installation completed!")
    logger.info("Note: Some optional packages may have failed - this is normal.")
    logger.info("Core Intellicrack functionality should work with installed packages.")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())