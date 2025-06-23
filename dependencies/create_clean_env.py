#!/usr/bin/env python3
"""
Create clean virtual environment for Intellicrack with compatible dependencies
"""

import os
import sys
import subprocess
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def create_clean_environment():
    """Create a clean virtual environment with compatible dependencies."""
    project_root = Path("/mnt/c/Intellicrack")
    venv_path = project_root / "venv_clean"
    
    # Remove existing venv if it exists
    if venv_path.exists():
        logger.info(f"Removing existing virtual environment at {venv_path}")
        import shutil
        shutil.rmtree(venv_path)
    
    # Create new virtual environment
    try:
        subprocess.run([
            sys.executable, "-m", "venv", str(venv_path)
        ], check=True, capture_output=True, text=True)
        logger.info(f"✅ Virtual environment created at {venv_path}")
    except subprocess.CalledProcessError as e:
        logger.error(f"❌ Failed to create virtual environment: {e}")
        return False
    
    # Get pip path for the virtual environment
    if os.name == 'nt':  # Windows
        pip_path = venv_path / "Scripts" / "pip.exe"
        python_path = venv_path / "Scripts" / "python.exe"
    else:  # Unix-like
        pip_path = venv_path / "bin" / "pip"
        python_path = venv_path / "bin" / "python"
    
    # Upgrade pip first
    try:
        subprocess.run([
            str(python_path), "-m", "pip", "install", "--upgrade", "pip"
        ], check=True, capture_output=True, text=True)
        logger.info("✅ pip upgraded")
    except subprocess.CalledProcessError as e:
        logger.error(f"❌ Failed to upgrade pip: {e}")
        return False
    
    # Install compatible packages
    compatible_packages = [
        "numpy>=1.24.0,<2.0.0",
        "lief>=0.13.0", 
        "pyelftools>=0.29",
        "click>=8.0.0",
        "PyQt5>=5.15.0",
        "requests>=2.28.0",
        "cryptography>=40.0.0",
    ]
    
    for package in compatible_packages:
        try:
            logger.info(f"Installing {package}...")
            subprocess.run([
                str(pip_path), "install", package
            ], check=True, capture_output=True, text=True, timeout=300)
            logger.info(f"✅ Installed {package}")
        except subprocess.CalledProcessError as e:
            logger.error(f"❌ Failed to install {package}: {e}")
        except subprocess.TimeoutExpired:
            logger.error(f"❌ Installation of {package} timed out")
    
    # Create activation script
    activate_script = project_root / "activate_clean_env.sh"
    with open(activate_script, 'w') as f:
        f.write(f'''#!/bin/bash
echo "Activating clean Intellicrack environment..."
source "{venv_path}/bin/activate"
echo "Environment activated. Ready to run Intellicrack!"
echo "To launch: python launch_intellicrack.py"
''')
    os.chmod(activate_script, 0o755)
    
    logger.info("🎉 Clean environment setup complete!")
    logger.info(f"To activate: source {activate_script}")
    
    return True

if __name__ == '__main__':
    create_clean_environment()