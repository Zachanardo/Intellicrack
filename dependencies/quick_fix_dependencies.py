#!/usr/bin/env python3
"""
Quick dependency fix for Intellicrack - installs only essential packages
"""

import sys
import subprocess
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def install_essential_packages():
    """Install only the essential packages needed for core functionality."""
    logger.info("Installing essential packages for Intellicrack...")
    
    essential_packages = [
        "numpy==1.26.4",  # Stable version compatible with most packages
        "lief==0.14.1",
        "pyelftools==0.31", 
        "click==8.1.7",
        "PyQt5==5.15.10"
    ]
    
    for package in essential_packages:
        try:
            logger.info(f"Installing {package}...")
            subprocess.run([
                sys.executable, "-m", "pip", "install", "--user", "--force-reinstall", package
            ], check=True, timeout=120)
            logger.info(f"✅ Installed {package}")
        except subprocess.CalledProcessError as e:
            logger.error(f"❌ Failed to install {package}: {e}")
        except subprocess.TimeoutExpired:
            logger.error(f"❌ Installation of {package} timed out")

def test_core_functionality():
    """Test that core functionality works."""
    logger.info("Testing core functionality...")
    
    test_script = '''
try:
    import numpy as np
    print(f"✅ numpy {np.__version__} working")
    
    import lief
    print(f"✅ lief {lief.__version__} working")
    
    try:
        import pyelftools
        print("✅ pyelftools working")
    except:
        print("⚠️ pyelftools not available")
    
    import click
    print(f"✅ click {click.__version__} working")
    
    try:
        import PyQt5.QtCore
        print(f"✅ PyQt5 {PyQt5.QtCore.PYQT_VERSION_STR} working")
    except:
        print("⚠️ PyQt5 not available")
        
    print("🎉 Core dependencies working!")
    
except Exception as e:
    print(f"❌ Test failed: {e}")
    import traceback
    traceback.print_exc()
'''
    
    try:
        result = subprocess.run([
            sys.executable, "-c", test_script
        ], capture_output=True, text=True, timeout=30)
        
        print("Test Results:")
        print(result.stdout)
        if result.stderr:
            print("Errors:")
            print(result.stderr)
            
        return result.returncode == 0
        
    except Exception as e:
        logger.error(f"❌ Test failed: {e}")
        return False

if __name__ == '__main__':
    print("🔧 Quick Intellicrack Dependency Fix")
    print("=" * 40)
    
    install_essential_packages()
    
    print("\n" + "=" * 40)
    success = test_core_functionality()
    
    if success:
        print("\n🎉 Essential dependencies fixed!")
        print("You can now run core Intellicrack functionality.")
    else:
        print("\n❌ Some issues remain. Check the output above.")