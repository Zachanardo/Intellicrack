"""
Unit tests for Binary Utils with REAL binary operations.
Tests REAL binary manipulation, parsing, and analysis utilities.
NO MOCKS - ALL TESTS USE REAL BINARY DATA AND PRODUCE REAL RESULTS.
"""

import pytest
from pathlib import Path
import struct
import tempfile

from intellicrack.utils.binary_utils import BinaryUtils
from tests.base_test import IntellicrackTestBase


class TestBinaryUtils(IntellicrackTestBase):
    """Test binary utilities with REAL binary operations."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test with real binary utils."""
        self.utils = BinaryUtils()
        self.temp_dir = Path(tempfile.mkdtemp())
        
    def teardown_method(self):
        """Clean up temp files."""
        import shutil
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
            
    def test_binary_reading(self):
        """Test binary file reading utilities."""
        # Create test binary
        test_file = self.temp_dir / "test.bin"
        test_data = struct.pack('<IHHQ', 0x12345678, 0xABCD, 0xEF01, 0x123456789ABCDEF0)
        test_file.write_bytes(test_data)
        
        # Read as different types
        reader = self.utils.create_reader(test_file)
        
        # Read DWORD
        dword = reader.read_dword()
        self.assert_real_output(dword)
        assert dword == 0x12345678
        
        # Read WORD
        word1 = reader.read_word()
        assert word1 == 0xABCD
        
        word2 = reader.read_word()
        assert word2 == 0xEF01
        
        # Read QWORD
        qword = reader.read_qword()
        assert qword == 0x123456789ABCDEF0
        
    def test_binary_writing(self):
        """Test binary file writing utilities."""
        test_file = self.temp_dir / "write_test.bin"
        
        writer = self.utils.create_writer(test_file)
        
        # Write various types
        writer.write_dword(0xDEADBEEF)
        writer.write_word(0xCAFE)
        writer.write_byte(0x42)
        writer.write_qword(0xFEDCBA9876543210)
        writer.write_string(b"Hello\x00")
        
        writer.close()
        
        # Verify written data
        data = test_file.read_bytes()
        self.assert_real_output(data)
        
        assert data[:4] == b'\xEF\xBE\xAD\xDE'  # Little endian DWORD
        assert data[4:6] == b'\xFE\xCA'  # Little endian WORD
        assert data[6] == 0x42  # Byte
        assert data[7:15] == b'\x10\x32\x54\x76\x98\xBA\xDC\xFE'  # QWORD
        assert data[15:21] == b'Hello\x00'
        
    def test_endianness_conversion(self):
        """Test endianness conversion utilities."""
        # Test data
        le_data = b'\x01\x02\x03\x04'
        be_data = b'\x04\x03\x02\x01'
        
        # Convert little to big endian
        converted = self.utils.swap_endian(le_data)
        self.assert_real_output(converted)
        assert converted == be_data
        
        # Convert back
        converted_back = self.utils.swap_endian(converted)
        assert converted_back == le_data
        
        # Test with different sizes
        word_le = b'\x34\x12'
        word_be = self.utils.swap_endian_word(word_le)
        assert word_be == b'\x12\x34'
        
    def test_bit_manipulation(self):
        """Test bit manipulation utilities."""
        value = 0b11010010  # 210 decimal
        
        # Test bit operations
        assert self.utils.get_bit(value, 1) == 1
        assert self.utils.get_bit(value, 2) == 0
        assert self.utils.get_bit(value, 4) == 1
        
        # Set bit
        new_value = self.utils.set_bit(value, 2, 1)
        assert new_value == 0b11010110  # Bit 2 set
        
        # Clear bit
        cleared = self.utils.clear_bit(new_value, 4)
        assert cleared == 0b11000110  # Bit 4 cleared
        
        # Toggle bit
        toggled = self.utils.toggle_bit(value, 0)
        assert toggled == 0b11010011  # Bit 0 toggled
        
        # Extract bit field
        field = self.utils.extract_bits(value, start=2, length=3)
        self.assert_real_output(field)
        assert field == 0b100  # Bits 2-4
        
    def test_checksum_calculation(self):
        """Test checksum calculation utilities."""
        test_data = b"Test data for checksum"
        
        # CRC32
        crc32 = self.utils.calculate_crc32(test_data)
        self.assert_real_output(crc32)
        assert isinstance(crc32, int)
        assert crc32 > 0
        
        # CRC16
        crc16 = self.utils.calculate_crc16(test_data)
        assert 0 <= crc16 <= 0xFFFF
        
        # Simple checksum
        checksum = self.utils.calculate_checksum(test_data)
        assert isinstance(checksum, int)
        
        # Fletcher checksum
        fletcher = self.utils.calculate_fletcher32(test_data)
        assert isinstance(fletcher, int)
        
    def test_pattern_search(self):
        """Test binary pattern searching."""
        # Create test data with patterns
        test_data = b'\x00' * 100 + b'\xDE\xAD\xBE\xEF' + b'\x00' * 50 + b'\xCA\xFE\xBA\xBE' + b'\x00' * 100
        test_file = self.temp_dir / "pattern_test.bin"
        test_file.write_bytes(test_data)
        
        # Search for pattern
        pattern = b'\xDE\xAD\xBE\xEF'
        offsets = self.utils.find_pattern(test_file, pattern)
        
        self.assert_real_output(offsets)
        assert len(offsets) == 1
        assert offsets[0] == 100
        
        # Search with wildcard
        wildcard_pattern = b'\xCA\xFE\x??\xBE'  # ?? as wildcard
        wildcard_offsets = self.utils.find_pattern_wildcard(test_file, wildcard_pattern)
        assert len(wildcard_offsets) == 1
        assert wildcard_offsets[0] == 154
        
    def test_binary_diff(self):
        """Test binary diff generation."""
        # Create two similar binaries
        original = self.temp_dir / "original.bin"
        modified = self.temp_dir / "modified.bin"
        
        orig_data = b'ABCDEFGHIJKLMNOP'
        mod_data = b'ABCDXXGHIJKLMNZZ'
        
        original.write_bytes(orig_data)
        modified.write_bytes(mod_data)
        
        # Generate diff
        diff = self.utils.binary_diff(original, modified)
        
        self.assert_real_output(diff)
        assert len(diff) == 2  # Two changes
        
        # Check diff entries
        assert diff[0]['offset'] == 4
        assert diff[0]['original'] == b'EF'
        assert diff[0]['modified'] == b'XX'
        
        assert diff[1]['offset'] == 14
        assert diff[1]['original'] == b'OP'
        assert diff[1]['modified'] == b'ZZ'
        
    def test_binary_patch_creation(self):
        """Test binary patch creation and application."""
        # Create original and target files
        original = self.temp_dir / "orig.bin"
        target = self.temp_dir / "target.bin"
        
        original.write_bytes(b'Hello World!')
        target.write_bytes(b'Hello Patch!')
        
        # Create patch
        patch = self.utils.create_patch(original, target)
        
        self.assert_real_output(patch)
        assert 'patches' in patch
        assert len(patch['patches']) > 0
        
        # Apply patch
        patched = self.temp_dir / "patched.bin"
        result = self.utils.apply_patch(original, patch, patched)
        
        assert result == True
        assert patched.read_bytes() == target.read_bytes()
        
    def test_data_encoding(self):
        """Test various data encoding methods."""
        test_data = b'Test\x00Data\xFF'
        
        # Base64
        b64_encoded = self.utils.encode_base64(test_data)
        self.assert_real_output(b64_encoded)
        b64_decoded = self.utils.decode_base64(b64_encoded)
        assert b64_decoded == test_data
        
        # Hex
        hex_encoded = self.utils.encode_hex(test_data)
        assert all(c in '0123456789abcdef' for c in hex_encoded)
        hex_decoded = self.utils.decode_hex(hex_encoded)
        assert hex_decoded == test_data
        
        # URL encoding
        url_encoded = self.utils.encode_url(test_data)
        url_decoded = self.utils.decode_url(url_encoded)
        assert url_decoded == test_data
        
    def test_compression(self):
        """Test binary compression utilities."""
        # Create compressible data
        test_data = b'A' * 1000 + b'B' * 1000 + b'C' * 1000
        
        # Compress with different algorithms
        algorithms = ['zlib', 'gzip', 'bz2', 'lzma']
        
        for algo in algorithms:
            compressed = self.utils.compress(test_data, algorithm=algo)
            self.assert_real_output(compressed)
            
            # Should be smaller
            assert len(compressed) < len(test_data)
            
            # Decompress
            decompressed = self.utils.decompress(compressed, algorithm=algo)
            assert decompressed == test_data
            
    def test_structure_parsing(self):
        """Test binary structure parsing."""
        # Define structure
        struct_def = {
            'magic': 'I',  # DWORD
            'version': 'H',  # WORD
            'flags': 'H',  # WORD
            'size': 'Q',  # QWORD
            'name': '16s'  # 16-byte string
        }
        
        # Create structured data
        test_file = self.temp_dir / "struct.bin"
        data = struct.pack('<IHHQ16s',
            0xDEADBEEF,  # magic
            0x0100,      # version
            0x0042,      # flags
            0x123456789ABCDEF0,  # size
            b'TestStruct\x00\x00\x00\x00\x00\x00'  # name
        )
        test_file.write_bytes(data)
        
        # Parse structure
        parsed = self.utils.parse_structure(test_file, struct_def)
        
        self.assert_real_output(parsed)
        assert parsed['magic'] == 0xDEADBEEF
        assert parsed['version'] == 0x0100
        assert parsed['flags'] == 0x0042
        assert parsed['size'] == 0x123456789ABCDEF0
        assert parsed['name'].rstrip(b'\x00') == b'TestStruct'
        
    def test_entropy_calculation(self):
        """Test entropy calculation for binary data."""
        # Low entropy (repeated data)
        low_entropy_data = b'A' * 1000
        low_entropy = self.utils.calculate_entropy(low_entropy_data)
        
        self.assert_real_output(low_entropy)
        assert low_entropy < 1.0  # Very low entropy
        
        # High entropy (random data)
        import os
        high_entropy_data = os.urandom(1000)
        high_entropy = self.utils.calculate_entropy(high_entropy_data)
        
        assert high_entropy > 7.0  # High entropy
        
        # Medium entropy
        medium_data = b'ABCD' * 250
        medium_entropy = self.utils.calculate_entropy(medium_data)
        assert 1.0 < medium_entropy < 3.0
        
    def test_binary_statistics(self):
        """Test binary statistics generation."""
        test_file = self.temp_dir / "stats.bin"
        test_data = b'\x00' * 50 + b'\xFF' * 50 + b'ABC' * 100
        test_file.write_bytes(test_data)
        
        # Generate statistics
        stats = self.utils.generate_statistics(test_file)
        
        self.assert_real_output(stats)
        assert 'size' in stats
        assert 'entropy' in stats
        assert 'byte_frequency' in stats
        assert 'null_bytes' in stats
        assert 'printable_chars' in stats
        
        assert stats['size'] == len(test_data)
        assert stats['null_bytes'] == 50
        assert stats['byte_frequency'][0x00] == 50
        assert stats['byte_frequency'][0xFF] == 50
        
    def test_hex_string_conversion(self):
        """Test hex string conversion utilities."""
        # Binary to hex string
        binary = b'\xDE\xAD\xBE\xEF'
        hex_str = self.utils.binary_to_hex_string(binary, separator=' ')
        
        self.assert_real_output(hex_str)
        assert hex_str == 'DE AD BE EF'
        
        # Hex string to binary
        binary_back = self.utils.hex_string_to_binary(hex_str)
        assert binary_back == binary
        
        # C-style array
        c_array = self.utils.binary_to_c_array(binary, name='data')
        assert 'unsigned char data[]' in c_array
        assert '0xDE' in c_array
        assert '0xAD' in c_array
        
    def test_binary_obfuscation(self):
        """Test binary obfuscation utilities."""
        original = b'SensitiveData123'
        
        # XOR obfuscation
        key = 0xAA
        obfuscated = self.utils.xor_obfuscate(original, key)
        
        self.assert_real_output(obfuscated)
        assert obfuscated != original
        
        # Deobfuscate
        deobfuscated = self.utils.xor_obfuscate(obfuscated, key)
        assert deobfuscated == original
        
        # Rolling XOR
        rolling_key = b'\x01\x02\x03\x04'
        rolling_obf = self.utils.rolling_xor(original, rolling_key)
        assert rolling_obf != original
        
        rolling_deobf = self.utils.rolling_xor(rolling_obf, rolling_key)
        assert rolling_deobf == original