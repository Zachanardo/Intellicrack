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
Create a proper pysha3 wheel that uv will accept
"""
import os
import sys
import tempfile
import zipfile
import hashlib
import base64
from pathlib import Path

def create_pysha3_wheel():
    """Create a pysha3 wheel file that redirects to pycryptodome"""

    # Wheel metadata
    wheel_name = "pysha3-1.0.2-py3-none-any.whl"

    # Create a temporary directory for building
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create pysha3 package directory
        pkg_dir = Path(tmpdir) / "pysha3"
        pkg_dir.mkdir()

        # Create __init__.py with our shim
        init_content = '''"""pysha3 compatibility shim using pycryptodome"""
try:
    from Cryptodome.Hash import SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256
except ImportError:
    from Crypto.Hash import SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256

class _SHA3Wrapper:
    def __init__(self, hash_obj):
        self._hash = hash_obj
    
    def update(self, data):
        self._hash.update(data)
        return self
    
    def digest(self):
        return self._hash.digest()
    
    def hexdigest(self):
        return self._hash.hexdigest()
    
    def copy(self):
        return _SHA3Wrapper(self._hash.copy())

def keccak_224(data=None):
    h = _SHA3Wrapper(SHA3_224.new())
    if data:
        h.update(data)
    return h

def keccak_256(data=None):
    h = _SHA3Wrapper(SHA3_256.new())
    if data:
        h.update(data)
    return h

def keccak_384(data=None):
    h = _SHA3Wrapper(SHA3_384.new())
    if data:
        h.update(data)
    return h

def keccak_512(data=None):
    h = _SHA3Wrapper(SHA3_512.new())
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

# SHAKE functions
def shake_128(data=None, length=None):
    h = SHAKE128.new()
    if data:
        h.update(data)
    return h

def shake_256(data=None, length=None):
    h = SHAKE256.new()
    if data:
        h.update(data)
    return h

__all__ = ['keccak_224', 'keccak_256', 'keccak_384', 'keccak_512',
           'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512', 'sha3',
           'shake_128', 'shake_256']
'''

        (pkg_dir / "__init__.py").write_text(init_content)

        # Create dist-info directory
        dist_info = Path(tmpdir) / "pysha3-1.0.2.dist-info"
        dist_info.mkdir()

        # Create METADATA
        metadata = '''Metadata-Version: 2.1
Name: pysha3
Version: 1.0.2
Summary: SHA-3 (Keccak) for Python (compatibility shim)
Home-page: https://github.com/tiran/pysha3
Author: Christian Heimes
Author-email: christian@python.org
License: PSFL (Keccak: CC0 1.0 Universal)
Platform: UNKNOWN
Classifier: Development Status :: 5 - Production/Stable
Classifier: Intended Audience :: Developers
Classifier: License :: OSI Approved :: Python Software Foundation License
Classifier: License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication
Classifier: Natural Language :: English
Classifier: Operating System :: OS Independent
Classifier: Programming Language :: Python :: 3
Requires-Dist: pycryptodome (>=3.9.0)

SHA-3 (Keccak) for Python - Compatibility shim using pycryptodome
'''
        (dist_info / "METADATA").write_text(metadata)

        # Create WHEEL
        wheel_info = '''Wheel-Version: 1.0
Generator: pysha3-shim 1.0
Root-Is-Purelib: true
Tag: py3-none-any
'''
        (dist_info / "WHEEL").write_text(wheel_info)

        # Create top_level.txt
        (dist_info / "top_level.txt").write_text("pysha3\n")

        # Create RECORD (will be updated later)
        record_path = dist_info / "RECORD"

        # Create the wheel
        wheel_path = Path.cwd() / wheel_name

        with zipfile.ZipFile(wheel_path, 'w', zipfile.ZIP_DEFLATED) as whl:
            # Add all files and calculate their hashes for RECORD
            record_lines = []

            for root, dirs, files in os.walk(tmpdir):
                for file in files:
                    file_path = Path(root) / file
                    arcname = file_path.relative_to(tmpdir).as_posix()

                    # Read file content
                    content = file_path.read_bytes()

                    # Calculate hash
                    hash_digest = hashlib.sha256(content).digest()
                    hash_b64 = base64.urlsafe_b64encode(hash_digest).decode('ascii').rstrip('=')

                    # Add to wheel
                    whl.write(file_path, arcname)

                    # Add to RECORD (except RECORD itself)
                    if file != "RECORD":
                        record_lines.append(f"{arcname},sha256={hash_b64},{len(content)}")

            # Add RECORD file
            record_content = '\n'.join(record_lines) + '\n'
            record_lines.append(f"pysha3-1.0.2.dist-info/RECORD,,")
            final_record = '\n'.join(record_lines) + '\n'

            whl.writestr("pysha3-1.0.2.dist-info/RECORD", final_record)

    return wheel_path

if __name__ == "__main__":
    print("Creating pysha3 wheel...")
    wheel_path = create_pysha3_wheel()
    print(f"Created: {wheel_path}")
    print("\nNow install it with:")
    print(f"uv pip install {wheel_path}")
