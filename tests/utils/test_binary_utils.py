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
Test module for binary utility functions.

This module contains unit tests for the binary_utils module, testing
functions related to binary analysis, file handling, and format detection.
"""

import os
import shutil
import tempfile
import unittest

try:
    from intellicrack.utils.binary.binary_utils import (
        calculate_entropy,
        disassemble_address,
        extract_strings,
        find_binary_patterns,
        get_binary_info,
        get_file_hash,
        get_section_info,
        is_elf_file,
        is_macho_file,
        is_pe_file,
    )
except ImportError:
    # Graceful fallback if module not available
    is_pe_file = None
    is_elf_file = None
    is_macho_file = None
    get_file_hash = None
    extract_strings = None
    get_binary_info = None
    disassemble_address = None
    find_binary_patterns = None
    calculate_entropy = None
    get_section_info = None


class TestBinaryUtils(unittest.TestCase):
    """Test cases for binary utility functions."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.test_dir, "test_binary.bin")

        # Create a test binary file
        with open(self.test_file, 'wb') as f:
            # Write some test data
            f.write(b'MZ' + b'\x00' * 58 + b'\x3c\x00\x00\x00')  # PE header start
            f.write(b'PE\x00\x00')  # PE signature
            f.write(b'\x00' * 100)  # Some padding
            f.write(b'Hello World!\x00Test String\x00')  # Test strings

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.test_dir)

    @unittest.skipIf(is_pe_file is None, "binary_utils module not available")
    def test_is_pe_file(self):
        """Test PE file detection."""
        self.assertTrue(is_pe_file(self.test_file))

        # Test non-PE file
        non_pe_file = os.path.join(self.test_dir, "not_pe.txt")
        with open(non_pe_file, 'w') as f:
            f.write("This is not a PE file")
        self.assertFalse(is_pe_file(non_pe_file))

    @unittest.skipIf(is_elf_file is None, "binary_utils module not available")
    def test_is_elf_file(self):
        """Test ELF file detection."""
        # Create a test ELF file
        elf_file = os.path.join(self.test_dir, "test.elf")
        with open(elf_file, 'wb') as f:
            f.write(b'\x7fELF')  # ELF magic
            f.write(b'\x00' * 100)

        self.assertTrue(is_elf_file(elf_file))
        self.assertFalse(is_elf_file(self.test_file))

    @unittest.skipIf(is_macho_file is None, "binary_utils module not available")
    def test_is_macho_file(self):
        """Test Mach-O file detection."""
        # Create a test Mach-O file
        macho_file = os.path.join(self.test_dir, "test.macho")
        with open(macho_file, 'wb') as f:
            f.write(b'\xfe\xed\xfa\xce')  # Mach-O magic (32-bit)
            f.write(b'\x00' * 100)

        self.assertTrue(is_macho_file(macho_file))
        self.assertFalse(is_macho_file(self.test_file))

    @unittest.skipIf(get_file_hash is None, "binary_utils module not available")
    def test_get_file_hash(self):
        """Test file hash calculation."""
        # Test MD5
        md5_hash = get_file_hash(self.test_file, algorithm='md5')
        self.assertIsNotNone(md5_hash)
        self.assertEqual(len(md5_hash), 32)  # MD5 is 32 hex chars

        # Test SHA256
        sha256_hash = get_file_hash(self.test_file, algorithm='sha256')
        self.assertIsNotNone(sha256_hash)
        self.assertEqual(len(sha256_hash), 64)  # SHA256 is 64 hex chars

        # Test consistency
        self.assertEqual(get_file_hash(self.test_file), get_file_hash(self.test_file))

    @unittest.skipIf(extract_strings is None, "binary_utils module not available")
    def test_extract_strings(self):
        """Test string extraction from binary."""
        strings = extract_strings(self.test_file, min_length=5)
        self.assertIsInstance(strings, list)
        self.assertIn("Hello World!", strings)
        self.assertIn("Test String", strings)

    @unittest.skipIf(get_binary_info is None, "binary_utils module not available")
    def test_get_binary_info(self):
        """Test binary information extraction."""
        info = get_binary_info(self.test_file)
        self.assertIsInstance(info, dict)
        self.assertIn('size', info)
        self.assertIn('type', info)
        self.assertEqual(info['type'], 'PE')

    @unittest.skipIf(calculate_entropy is None, "binary_utils module not available")
    def test_calculate_entropy(self):
        """Test entropy calculation."""
        # Test with low entropy data (zeros)
        low_entropy_data = b'\x00' * 1000
        low_entropy = calculate_entropy(low_entropy_data)
        self.assertLess(low_entropy, 1.0)

        # Test with high entropy data (random)
        import random
        high_entropy_data = bytes([random.randint(0, 255) for _ in range(1000)])
        high_entropy = calculate_entropy(high_entropy_data)
        self.assertGreater(high_entropy, 7.0)

    @unittest.skipIf(find_binary_patterns is None, "binary_utils module not available")
    def test_find_binary_patterns(self):
        """Test binary pattern searching."""
        # Search for PE signature
        patterns = find_binary_patterns(self.test_file, [b'PE\x00\x00'])
        self.assertIsInstance(patterns, list)
        self.assertGreater(len(patterns), 0)
        self.assertEqual(patterns[0]['pattern'], b'PE\x00\x00')
        self.assertIsInstance(patterns[0]['offset'], int)


class TestBinaryUtilsIntegration(unittest.TestCase):
    """Integration tests for binary utils with real binary analysis."""

    def setUp(self):
        """Set up integration test fixtures."""
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up integration test fixtures."""
        shutil.rmtree(self.test_dir)

    @unittest.skipIf(get_binary_info is None, "binary_utils module not available")
    @unittest.skipIf(not os.path.exists('/bin/ls'), "No system binary available for testing")
    def test_real_binary_analysis(self):
        """Test analysis of a real system binary."""
        info = get_binary_info('/bin/ls')
        self.assertIsInstance(info, dict)
        self.assertIn('size', info)
        self.assertIn('type', info)
        self.assertIn(info['type'], ['ELF', 'Mach-O'])  # Depending on OS


if __name__ == '__main__':
    unittest.main()
