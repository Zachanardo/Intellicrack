import subprocess
import sys
import os

# Install python-fx temporarily
print("Installing python-fx to examine it...")
subprocess.run([sys.executable, "-m", "pip", "install", "python-fx==0.3.2"], check=True)

# Now examine what it provides
try:
    import pyfx
    print("\n=== python-fx/pyfx module found ===")
    print(f"Module location: {pyfx.__file__}")
    print(f"Module attributes: {dir(pyfx)}")

    # Check for main functionality
    if hasattr(pyfx, '__main__'):
        print("\nHas __main__ module")

    # Check what's in the package
    pyfx_dir = os.path.dirname(pyfx.__file__)
    print(f"\nFiles in pyfx directory:")
    for file in os.listdir(pyfx_dir):
        print(f"  {file}")

except ImportError:
    print("pyfx module not found")

# Check if it's a different import name
try:
    import python_fx
    print("\n=== python_fx module found ===")
    print(f"Module attributes: {dir(python_fx)}")
except ImportError:
    print("\npython_fx module not found")

# Check installed files
print("\n=== Checking installed files ===")
result = subprocess.run([sys.executable, "-m", "pip", "show", "-f", "python-fx"],
                       capture_output=True, text=True)
print(result.stdout)
