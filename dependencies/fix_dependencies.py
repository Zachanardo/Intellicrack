#!/usr/bin/env python3
"""
Comprehensive dependency conflict resolver for Intellicrack
Addresses numpy/pandas compatibility issues and creates working environment
"""

import os
import sys
import subprocess
import logging
import shutil
from pathlib import Path

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class DependencyFixer:
    """Fixes dependency conflicts and creates working environment."""
    
    def __init__(self):
        self.project_root = Path("/mnt/c/Intellicrack")
        self.venv_path = self.project_root / "venv_fixed"
        self.backup_path = self.project_root / "backup_deps"
        
    def check_current_environment(self):
        """Check current dependency status without triggering imports."""
        logger.info("Checking current dependency environment...")
        
        issues = []
        
        # Check using subprocess to avoid import conflicts
        test_script = '''
import sys
issues = []

try:
    import numpy
    print(f"numpy:{numpy.__version__}:{numpy.__file__}")
except ImportError as e:
    issues.append("numpy not available")
    print(f"numpy_error:{e}")
except Exception as e:
    issues.append("numpy import error")
    print(f"numpy_error:{e}")

try:
    import pandas
    print(f"pandas:{pandas.__version__}:{pandas.__file__}")
except ImportError as e:
    issues.append("pandas not available") 
    print(f"pandas_error:{e}")
except Exception as e:
    issues.append("pandas import error")
    print(f"pandas_error:{e}")

try:
    import sklearn
    print(f"sklearn:{sklearn.__version__}")
except ImportError as e:
    issues.append("sklearn not available")
    print(f"sklearn_error:{e}")
except Exception as e:
    issues.append("sklearn import error")
    print(f"sklearn_error:{e}")

# Test compatibility
try:
    import numpy
    import pandas
    df = pandas.DataFrame([1, 2, 3])
    print("compatibility:success")
except Exception as e:
    if "numpy.dtype size changed" in str(e):
        issues.append("numpy/pandas compatibility conflict")
    else:
        issues.append("general compatibility issue")
    print(f"compatibility_error:{e}")

print(f"issues_count:{len(issues)}")
for issue in issues:
    print(f"issue:{issue}")
'''
        
        try:
            result = subprocess.run([
                sys.executable, "-c", test_script
            ], capture_output=True, text=True, timeout=30)
            
            # Parse the output
            for line in result.stdout.split('\n'):
                if line.startswith('numpy:'):
                    _, version, path = line.split(':', 2)
                    logger.info(f"numpy {version} found at {path}")
                elif line.startswith('pandas:'):
                    _, version, path = line.split(':', 2)
                    logger.info(f"pandas {version} found at {path}")
                elif line.startswith('sklearn:'):
                    _, version = line.split(':', 1)
                    logger.info(f"scikit-learn {version} found")
                elif line.startswith('compatibility:success'):
                    logger.info("✅ numpy/pandas compatibility test passed")
                elif line.startswith('issue:'):
                    issue = line.split(':', 1)[1]
                    issues.append(issue)
                elif line.startswith('numpy_error:') or line.startswith('pandas_error:') or line.startswith('compatibility_error:'):
                    error = line.split(':', 1)[1]
                    logger.error(f"❌ {error}")
                    
        except subprocess.TimeoutExpired:
            logger.error("❌ Environment check timed out")
            issues.append("environment check timeout")
        except Exception as e:
            logger.error(f"❌ Environment check failed: {e}")
            issues.append("environment check failed")
            
        return issues
    
    def create_clean_environment(self):
        """Create a clean virtual environment with compatible dependencies."""
        logger.info("Creating clean virtual environment...")
        
        # Remove existing venv if it exists
        if self.venv_path.exists():
            logger.info(f"Removing existing virtual environment at {self.venv_path}")
            shutil.rmtree(self.venv_path)
            
        # Create new virtual environment
        try:
            subprocess.run([
                sys.executable, "-m", "venv", str(self.venv_path)
            ], check=True, capture_output=True, text=True)
            logger.info(f"✅ Virtual environment created at {self.venv_path}")
        except subprocess.CalledProcessError as e:
            logger.error(f"❌ Failed to create virtual environment: {e}")
            return False
            
        return True
    
    def install_compatible_dependencies(self):
        """Install compatible versions of all dependencies."""
        logger.info("Installing compatible dependencies...")
        
        # Get pip path for the virtual environment
        if os.name == 'nt':  # Windows
            pip_path = self.venv_path / "Scripts" / "pip.exe"
            python_path = self.venv_path / "Scripts" / "python.exe"
        else:  # Unix-like
            pip_path = self.venv_path / "bin" / "pip"
            python_path = self.venv_path / "bin" / "python"
            
        # Upgrade pip first
        try:
            subprocess.run([
                str(python_path), "-m", "pip", "install", "--upgrade", "pip"
            ], check=True, capture_output=True, text=True)
            logger.info("✅ pip upgraded")
        except subprocess.CalledProcessError as e:
            logger.error(f"❌ Failed to upgrade pip: {e}")
            return False
            
        # Install compatible package versions
        compatible_packages = [
            # Core scientific computing stack - compatible versions
            "numpy>=1.24.0,<2.0.0",
            "pandas>=2.0.0,<2.3.0", 
            "scikit-learn>=1.3.0,<1.5.0",
            "scipy>=1.10.0,<1.15.0",
            
            # Core Intellicrack dependencies
            "PyQt5>=5.15.0",
            "lief>=0.13.0", 
            "pyelftools>=0.29",
            "click>=8.0.0",
            "matplotlib>=3.7.0",
            "requests>=2.28.0",
            "cryptography>=40.0.0",
            "joblib>=1.2.0",
            
            # Optional ML dependencies
            "threadpoolctl>=3.1.0",
            "packaging>=21.0",
            
            # Development tools
            "pytest>=7.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0"
        ]
        
        for package in compatible_packages:
            try:
                logger.info(f"Installing {package}...")
                subprocess.run([
                    str(pip_path), "install", package
                ], check=True, capture_output=True, text=True, timeout=300)
                logger.info(f"✅ Installed {package}")
            except subprocess.CalledProcessError as e:
                logger.error(f"❌ Failed to install {package}: {e.stderr}")
                return False
            except subprocess.TimeoutExpired:
                logger.error(f"❌ Installation of {package} timed out")
                return False
                
        return True
        
    def test_fixed_environment(self):
        """Test that the fixed environment works correctly."""
        logger.info("Testing fixed environment...")
        
        # Get python path for the virtual environment
        if os.name == 'nt':  # Windows
            python_path = self.venv_path / "Scripts" / "python.exe"
        else:  # Unix-like
            python_path = self.venv_path / "bin" / "python"
            
        # Test script to run in the virtual environment
        test_script = '''
import sys
print(f"Python: {sys.version}")

# Test numpy/pandas compatibility
try:
    import numpy as np
    print(f"numpy: {np.__version__}")
    
    import pandas as pd
    print(f"pandas: {pd.__version__}")
    
    # Test compatibility
    df = pd.DataFrame({"test": [1, 2, 3]})
    arr = np.array([1, 2, 3])
    print("✅ numpy/pandas compatibility test passed")
    
except Exception as e:
    print(f"❌ Compatibility test failed: {e}")
    sys.exit(1)
    
# Test scikit-learn
try:
    import sklearn
    print(f"scikit-learn: {sklearn.__version__}")
    
    from sklearn.ensemble import RandomForestClassifier
    clf = RandomForestClassifier(n_estimators=10)
    print("✅ scikit-learn import test passed")
    
except Exception as e:
    print(f"❌ scikit-learn test failed: {e}")
    sys.exit(1)

# Test other dependencies
try:
    import lief
    print(f"lief: {lief.__version__}")
    
    import PyQt5
    print(f"PyQt5: {PyQt5.QtCore.PYQT_VERSION_STR}")
    
    import click
    print(f"click: {click.__version__}")
    
    print("✅ All core dependencies working")
    
except Exception as e:
    print(f"❌ Dependency test failed: {e}")
    sys.exit(1)
    
print("🎉 Environment test completed successfully!")
'''
        
        try:
            result = subprocess.run([
                str(python_path), "-c", test_script
            ], check=True, capture_output=True, text=True, timeout=60)
            
            logger.info("✅ Environment test passed!")
            logger.info("Output:")
            for line in result.stdout.split('\n'):
                if line.strip():
                    logger.info(f"  {line}")
                    
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"❌ Environment test failed: {e}")
            logger.error(f"STDERR: {e.stderr}")
            return False
        except subprocess.TimeoutExpired:
            logger.error("❌ Environment test timed out")
            return False
            
    def create_activation_script(self):
        """Create convenient activation script."""
        logger.info("Creating activation script...")
        
        # Create activation script for Unix-like systems
        activate_script = self.project_root / "activate_fixed_env.sh"
        
        with open(activate_script, 'w') as f:
            f.write(f'''#!/bin/bash
# Activate fixed Intellicrack environment

echo "Activating fixed Intellicrack environment..."
source "{self.venv_path}/bin/activate"

echo "Environment activated. Dependencies available:"
python -c "
import numpy, pandas, sklearn, lief, PyQt5, click
print(f'  numpy: {{numpy.__version__}}')
print(f'  pandas: {{pandas.__version__}}')
print(f'  scikit-learn: {{sklearn.__version__}}')
print(f'  lief: {{lief.__version__}}')
print(f'  PyQt5: {{PyQt5.QtCore.PYQT_VERSION_STR}}')
print(f'  click: {{click.__version__}}')
print('Ready to run Intellicrack!')
"

echo ""
echo "To launch Intellicrack:"
echo "  python launch_intellicrack.py"
echo "  python -m intellicrack"
echo ""
echo "To deactivate:"
echo "  deactivate"
''')
            
        # Make executable
        os.chmod(activate_script, 0o755)
        
        # Create Windows batch script
        if os.name == 'nt':
            activate_batch = self.project_root / "activate_fixed_env.bat"
            with open(activate_batch, 'w') as f:
                f.write(f'''@echo off
REM Activate fixed Intellicrack environment

echo Activating fixed Intellicrack environment...
call "{self.venv_path}\\Scripts\\activate.bat"

echo Environment activated. Testing dependencies...
python -c "import numpy, pandas, sklearn, lief, PyQt5, click; print('All dependencies available!')"

echo.
echo To launch Intellicrack:
echo   python launch_intellicrack.py
echo   python -m intellicrack
echo.
echo To deactivate:
echo   deactivate
''')
                
        logger.info(f"✅ Created activation script: {activate_script}")
        return True
        
    def create_launcher_with_venv(self):
        """Create launcher that automatically uses the fixed environment."""
        logger.info("Creating launcher with fixed environment...")
        
        launcher_script = self.project_root / "launch_intellicrack_fixed.py"
        
        with open(launcher_script, 'w') as f:
            f.write('''#!/usr/bin/env python3
"""
Intellicrack launcher with fixed dependencies
Automatically uses the fixed virtual environment
"""

import os
import sys
import subprocess
from pathlib import Path

# Get the correct python executable from fixed venv
project_root = Path(__file__).parent
venv_path = project_root / "venv_fixed"

if os.name == 'nt':  # Windows
    python_exe = venv_path / "Scripts" / "python.exe"
else:  # Unix-like
    python_exe = venv_path / "bin" / "python"

if not python_exe.exists():
    print("❌ Fixed virtual environment not found!")
    print("Please run: python fix_dependencies.py")
    sys.exit(1)

# Set environment variables
env = os.environ.copy()
env['PYTHONPATH'] = str(project_root)

# Launch Intellicrack with fixed environment
try:
    print("🚀 Starting Intellicrack with fixed dependencies...")
    subprocess.run([
        str(python_exe), 
        str(project_root / "launch_intellicrack.py")
    ], env=env, check=True)
except subprocess.CalledProcessError as e:
    print(f"❌ Failed to launch Intellicrack: {e}")
    sys.exit(1)
except KeyboardInterrupt:
    print("\\n👋 Intellicrack terminated by user")
''')
            
        # Make executable
        os.chmod(launcher_script, 0o755)
        
        logger.info(f"✅ Created fixed launcher: {launcher_script}")
        return True
        
    def fix_all_dependencies(self):
        """Run complete dependency fixing process."""
        logger.info("🔧 Starting comprehensive dependency fix...")
        
        # Step 1: Check current environment
        issues = self.check_current_environment()
        if issues:
            logger.warning(f"Found {len(issues)} dependency issues:")
            for issue in issues:
                logger.warning(f"  - {issue}")
        else:
            logger.info("✅ No dependency issues found in current environment")
            return True
            
        # Step 2: Create clean environment
        if not self.create_clean_environment():
            logger.error("❌ Failed to create clean environment")
            return False
            
        # Step 3: Install compatible dependencies
        if not self.install_compatible_dependencies():
            logger.error("❌ Failed to install compatible dependencies")
            return False
            
        # Step 4: Test the fixed environment
        if not self.test_fixed_environment():
            logger.error("❌ Fixed environment failed tests")
            return False
            
        # Step 5: Create convenience scripts
        if not self.create_activation_script():
            logger.error("❌ Failed to create activation script")
            return False
            
        if not self.create_launcher_with_venv():
            logger.error("❌ Failed to create fixed launcher")
            return False
            
        logger.info("🎉 Dependency fixing completed successfully!")
        logger.info("")
        logger.info("Next steps:")
        logger.info("1. Activate fixed environment: source activate_fixed_env.sh")
        logger.info("2. Launch Intellicrack: python launch_intellicrack_fixed.py")
        logger.info("3. Or use: python launch_intellicrack.py (within activated environment)")
        
        return True

def main():
    """Main execution function."""
    print("🔧 Intellicrack Dependency Fixer")
    print("=" * 50)
    
    fixer = DependencyFixer()
    
    try:
        success = fixer.fix_all_dependencies()
        if success:
            print("\n🎉 All dependency issues have been resolved!")
            print("Intellicrack is now ready for full functionality.")
        else:
            print("\n❌ Some issues could not be resolved automatically.")
            print("Please check the logs above for details.")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n👋 Dependency fixing interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"❌ Unexpected error during dependency fixing: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()