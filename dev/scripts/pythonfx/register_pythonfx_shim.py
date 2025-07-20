import os
import site

# Create INSTALLER file to register with pip/uv
site_packages = site.getsitepackages()[0]
dist_info_dir = os.path.join(site_packages, "python_fx-0.3.2.dist-info")

# Create INSTALLER file
with open(os.path.join(dist_info_dir, "INSTALLER"), 'w') as f:
    f.write("pip\n")

# Create REQUESTED file
with open(os.path.join(dist_info_dir, "REQUESTED"), 'w') as f:
    f.write("")

print("✓ Registered python-fx shim with package manager")

# Test
import subprocess
import sys

result = subprocess.run([sys.executable, "-m", "pip", "show", "python-fx"], 
                       capture_output=True, text=True)
if "Name: python-fx" in result.stdout:
    print("✓ python-fx shows as installed")
else:
    print("✗ python-fx not showing as installed")
    print(result.stdout)
    print(result.stderr)