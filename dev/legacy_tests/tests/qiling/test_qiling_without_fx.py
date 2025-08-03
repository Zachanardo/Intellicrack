import subprocess
import sys

# First uninstall python-fx
print("Uninstalling python-fx...")
subprocess.run([sys.executable, "-m", "pip", "uninstall", "python-fx", "-y"], check=True)

# Now test qiling
print("\nTesting qiling without python-fx...")
try:
    import qiling
    print("✓ qiling imported successfully without python-fx")

    # Test basic functionality
    from qiling import Qiling
    from qiling.const import QL_ARCH, QL_OS

    print("✓ Qiling classes imported successfully")
    print(f"Available architectures: {[attr for attr in dir(QL_ARCH) if not attr.startswith('_')][:5]}...")
    print(f"Available OS types: {[attr for attr in dir(QL_OS) if not attr.startswith('_')][:5]}...")

except ImportError as e:
    print(f"✗ qiling import failed: {e}")
except Exception as e:
    print(f"✗ Error: {e}")

# Check if qiling lists python-fx as a dependency
print("\n\nChecking qiling's stated requirements...")
result = subprocess.run([sys.executable, "-m", "pip", "show", "qiling"],
                       capture_output=True, text=True)
lines = result.stdout.split('\n')
for line in lines:
    if line.startswith('Requires:'):
        print(line)
        break
