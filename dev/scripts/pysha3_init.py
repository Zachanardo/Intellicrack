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

from Cryptodome.Hash import SHA3_224, SHA3_256, SHA3_384, SHA3_512

class H:
    def __init__(self, h):
        self._h = h
    def update(self, d):
        self._h.update(d)
        return self
    def digest(self):
        return self._h.digest()
    def hexdigest(self):
        return self._h.hexdigest()

def keccak_224(d=None):
    h = H(SHA3_224.new())
    return h.update(d) if d else h

def keccak_256(d=None):
    h = H(SHA3_256.new())
    return h.update(d) if d else h

def keccak_384(d=None):
    h = H(SHA3_384.new())
    return h.update(d) if d else h

def keccak_512(d=None):
    h = H(SHA3_512.new())
    return h.update(d) if d else h

sha3_224 = keccak_224
sha3_256 = keccak_256
sha3_384 = keccak_384
sha3_512 = keccak_512
sha3 = sha3_256
