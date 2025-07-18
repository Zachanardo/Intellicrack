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
Fix pysha3 installation by creating a compatibility layer using pycryptodomex
"""
import os
import sys
import subprocess
import site

def main():
    # First install pycryptodomex
    print("Installing pycryptodomex...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pycryptodomex"])

    # Get the site-packages directory
    site_packages = site.getsitepackages()[0]
    print(f"Site-packages directory: {site_packages}")

    # Create pysha3 directory
    pysha3_dir = os.path.join(site_packages, "pysha3")
    os.makedirs(pysha3_dir, exist_ok=True)
    print(f"Created directory: {pysha3_dir}")

    # Create __init__.py with compatibility layer
    init_content = '''# pysha3 compatibility layer using pycryptodomex
from Cryptodome.Hash import SHA3_224, SHA3_256, SHA3_384, SHA3_512
from Cryptodome.Hash import SHAKE128, SHAKE256

class _SHA3:
    def __init__(self, hashfn):
        self._h = hashfn

    def update(self, data):
        self._h.update(data)
        return self

    def digest(self):
        return self._h.digest()

    def hexdigest(self):
        return self._h.hexdigest()

    def copy(self):
        new_h = _SHA3(self._h.copy())
        return new_h

def keccak_224(data=None):
    h = _SHA3(SHA3_224.new())
    if data:
        h.update(data)
    return h

def keccak_256(data=None):
    h = _SHA3(SHA3_256.new())
    if data:
        h.update(data)
    return h

def keccak_384(data=None):
    h = _SHA3(SHA3_384.new())
    if data:
        h.update(data)
    return h

def keccak_512(data=None):
    h = _SHA3(SHA3_512.new())
    if data:
        h.update(data)
    return h

def sha3_224(data=None):
    return keccak_224(data)

def sha3_256(data=None):
    return keccak_256(data)

def sha3_384(data=None):
    return keccak_384(data)

def sha3_512(data=None):
    return keccak_512(data)

# Aliases
sha3 = sha3_256

# SHAKE support
def shake_128(data=None):
    h = SHAKE128.new()
    if data:
        h.update(data)
    return h

def shake_256(data=None):
    h = SHAKE256.new()
    if data:
        h.update(data)
    return h
'''

    init_path = os.path.join(pysha3_dir, "__init__.py")
    with open(init_path, 'w') as f:
        f.write(init_content)
    print(f"Created: {init_path}")

    # Create dist-info directory
    dist_info_dir = os.path.join(site_packages, "pysha3-1.0.2.dist-info")
    os.makedirs(dist_info_dir, exist_ok=True)
    print(f"Created directory: {dist_info_dir}")

    # Create METADATA file
    metadata_content = '''Metadata-Version: 2.1
Name: pysha3
Version: 1.0.2
Summary: SHA-3 wrapper (using pycryptodomex)
Home-page: UNKNOWN
Author: UNKNOWN
Author-email: UNKNOWN
License: UNKNOWN
Platform: UNKNOWN

UNKNOWN
'''
    metadata_path = os.path.join(dist_info_dir, "METADATA")
    with open(metadata_path, 'w') as f:
        f.write(metadata_content)
    print(f"Created: {metadata_path}")

    # Create WHEEL file
    wheel_content = '''Wheel-Version: 1.0
Generator: fake-pysha3-installer
Root-Is-Purelib: true
Tag: py3-none-any
'''
    wheel_path = os.path.join(dist_info_dir, "WHEEL")
    with open(wheel_path, 'w') as f:
        f.write(wheel_content)
    print(f"Created: {wheel_path}")

    # Create top_level.txt
    top_level_path = os.path.join(dist_info_dir, "top_level.txt")
    with open(top_level_path, 'w') as f:
        f.write("pysha3\n")
    print(f"Created: {top_level_path}")

    # Create RECORD file
    record_content = '''pysha3/__init__.py,,
pysha3-1.0.2.dist-info/METADATA,,
pysha3-1.0.2.dist-info/WHEEL,,
pysha3-1.0.2.dist-info/top_level.txt,,
pysha3-1.0.2.dist-info/RECORD,,
'''
    record_path = os.path.join(dist_info_dir, "RECORD")
    with open(record_path, 'w') as f:
        f.write(record_content)
    print(f"Created: {record_path}")

    # Create INSTALLER file
    installer_path = os.path.join(dist_info_dir, "INSTALLER")
    with open(installer_path, 'w') as f:
        f.write("pip\n")
    print(f"Created: {installer_path}")

    print("\n✓ pysha3 compatibility layer installed successfully!")
    print("\nTesting installation...")

    try:
        import pysha3
        h = pysha3.sha3_256(b"test")
        print(f"✓ Test successful! SHA3-256 of 'test': {h.hexdigest()}")
        print("\nYou can now install manticore with:")
        print("pip install manticore --no-deps")
    except Exception as e:
        print(f"✗ Test failed: {e}")
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())
