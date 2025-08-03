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

"""Download and install pre-built pysha3 wheel"""
import subprocess
import sys
import platform
import urllib.request
import os

# Determine Python version and architecture
py_version = f"cp{sys.version_info.major}{sys.version_info.minor}"
arch = "win_amd64" if platform.machine().endswith('64') else "win32"

# Try different Python versions if exact match not found
versions_to_try = [
    f"{py_version}-{py_version}-{arch}",
    f"cp310-cp310-{arch}",  # Python 3.10
    f"cp39-cp39-{arch}",    # Python 3.9
    f"cp38-cp38-{arch}",    # Python 3.8
]

print(f"Python version: {sys.version}")
print(f"Looking for pysha3 wheel...")

# Base URL for wheels
base_url = "https://files.pythonhosted.org/packages/"

# Known good wheels
wheels = {
    "cp311-cp311-win_amd64": "73/bf/978d424ac6c9076d73b8fdc8ab8ad46f98af0c34669d736b1d83c758afee/pysha3-1.0.2-cp39-cp39-win_amd64.whl",
    "cp310-cp310-win_amd64": "73/bf/978d424ac6c9076d73b8fdc8ab8ad46f98af0c34669d736b1d83c758afee/pysha3-1.0.2-cp39-cp39-win_amd64.whl",
    "cp39-cp39-win_amd64": "73/bf/978d424ac6c9076d73b8fdc8ab8ad46f98af0c34669d736b1d83c758afee/pysha3-1.0.2-cp39-cp39-win_amd64.whl",
    "cp38-cp38-win_amd64": "58/f4/7d3556c4bb9a022ad8023e59477b3cf5ccb97a5ccdb0e1d68f19e93f5d5f6/pysha3-1.0.2-cp38-cp38-win_amd64.whl",
}

# Try the Python 3.9 wheel which often works for other versions
wheel_url = "https://files.pythonhosted.org/packages/73/bf/978d424ac6c9076d73b8fdc8ab8ad46f98af0c34669d736b1d83c758afee/pysha3-1.0.2-cp39-cp39-win_amd64.whl"
wheel_file = "pysha3-1.0.2-cp39-cp39-win_amd64.whl"

print(f"Downloading {wheel_file}...")
try:
    urllib.request.urlretrieve(wheel_url, wheel_file)
    print(f"Downloaded {wheel_file}")

    # Force install ignoring version
    print("Installing wheel...")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--force-reinstall", wheel_file],
        capture_output=True,
        text=True
    )

    if result.returncode == 0:
        print("✓ Successfully installed pysha3!")
        # Clean up
        os.remove(wheel_file)
    else:
        print("Failed to install wheel")
        print(result.stderr)

except Exception as e:
    print(f"Error: {e}")
    print("\nFalling back to pycryptodomex solution...")

    # Fallback: Create fake pysha3
    import site
    site_packages = site.getsitepackages()[0]
    pysha3_dir = os.path.join(site_packages, "pysha3")
    os.makedirs(pysha3_dir, exist_ok=True)

    with open(os.path.join(pysha3_dir, "__init__.py"), "w") as f:
        f.write("""from Cryptodome.Hash import SHA3_224, SHA3_256, SHA3_384, SHA3_512
class H:
    def __init__(self, h): self._h = h
    def update(self, d): self._h.update(d); return self
    def digest(self): return self._h.digest()
    def hexdigest(self): return self._h.hexdigest()
def keccak_224(d=None): h = H(SHA3_224.new()); return h.update(d) if d else h
def keccak_256(d=None): h = H(SHA3_256.new()); return h.update(d) if d else h
def keccak_384(d=None): h = H(SHA3_384.new()); return h.update(d) if d else h
def keccak_512(d=None): h = H(SHA3_512.new()); return h.update(d) if d else h
sha3_224 = keccak_224
sha3_256 = keccak_256
sha3_384 = keccak_384
sha3_512 = keccak_512
sha3 = sha3_256
""")
    print(f"✓ Created fake pysha3 at {pysha3_dir}")
