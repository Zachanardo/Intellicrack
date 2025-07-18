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
Compatibility shim for pysha3 using pycryptodomex
"""
try:
    from pysha3 import *
except ImportError:
    # Fallback to pycryptodomex
    from Cryptodome.Hash import SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256

    # Create compatibility layer
    def keccak_224(data=None):
        h = SHA3_224.new()
        if data:
            h.update(data)
        return h

    def keccak_256(data=None):
        h = SHA3_256.new()
        if data:
            h.update(data)
        return h

    def keccak_384(data=None):
        h = SHA3_384.new()
        if data:
            h.update(data)
        return h

    def keccak_512(data=None):
        h = SHA3_512.new()
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

    # Alias for compatibility
    sha3 = sha3_256
