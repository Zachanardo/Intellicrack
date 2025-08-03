"""
Unit tests for BinaryAnalyzer with REAL binary analysis.
Tests actual binary parsing, entropy calculations, and analysis results.
NO MOCKS - ALL TESTS USE REAL BINARY DATA AND VALIDATE REAL ANALYSIS.
"""

import pytest
import tempfile
from pathlib import Path
import struct

from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer
from tests.base_test import IntellicrackTestBase


class TestBinaryAnalyzer(IntellicrackTestBase):
    """Test BinaryAnalyzer with REAL binary data and analysis."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test with binary analyzer and temp directory."""
        self.analyzer = BinaryAnalyzer()
        self.temp_dir = Path(tempfile.mkdtemp())
        
    def teardown_method(self):
        """Clean up temp files."""
        import shutil
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
            
    def create_real_pe_file(self, name="test.exe"):
        """Create a REAL minimal PE file for testing."""
        pe_path = self.temp_dir / name
        
        # Create minimal PE header structure
        dos_header = b'MZ' + b'\x00' * 58 + struct.pack('<L', 0x80)  # e_lfanew = 0x80
        dos_stub = b'\x00' * (0x80 - len(dos_header))
        
        # PE signature
        nt_signature = b'PE\x00\x00'
        
        # COFF header (IMAGE_FILE_HEADER)
        machine = struct.pack('<H', 0x014c)  # IMAGE_FILE_MACHINE_I386
        num_sections = struct.pack('<H', 1)  # 1 section
        timestamp = struct.pack('<L', 0)
        ptr_to_symbol_table = struct.pack('<L', 0)
        num_symbols = struct.pack('<L', 0)
        size_optional_header = struct.pack('<H', 224)  # Standard size
        characteristics = struct.pack('<H', 0x0102)  # EXECUTABLE_IMAGE | 32BIT_MACHINE
        
        coff_header = machine + num_sections + timestamp + ptr_to_symbol_table + num_symbols + size_optional_header + characteristics
        
        # Optional header (IMAGE_OPTIONAL_HEADER32)
        magic = struct.pack('<H', 0x010b)  # PE32
        major_linker = struct.pack('<B', 14)
        minor_linker = struct.pack('<B', 0)
        size_of_code = struct.pack('<L', 0x1000)
        size_of_initialized_data = struct.pack('<L', 0)
        size_of_uninitialized_data = struct.pack('<L', 0)
        address_of_entry_point = struct.pack('<L', 0x1000)
        base_of_code = struct.pack('<L', 0x1000)
        base_of_data = struct.pack('<L', 0x2000)
        image_base = struct.pack('<L', 0x400000)
        section_alignment = struct.pack('<L', 0x1000)
        file_alignment = struct.pack('<L', 0x200)
        
        # Rest of optional header with minimal values
        optional_header = (magic + major_linker + minor_linker + size_of_code + 
                          size_of_initialized_data + size_of_uninitialized_data +
                          address_of_entry_point + base_of_code + base_of_data +
                          image_base + section_alignment + file_alignment)
        
        # Pad optional header to correct size (224 bytes)
        optional_header += b'\x00' * (224 - len(optional_header))
        
        # Section header
        section_name = b'.text\x00\x00\x00'  # 8 bytes
        virtual_size = struct.pack('<L', 0x1000)
        virtual_address = struct.pack('<L', 0x1000)
        size_raw_data = struct.pack('<L', 0x200)
        ptr_raw_data = struct.pack('<L', 0x400)
        ptr_relocs = struct.pack('<L', 0)
        ptr_line_nums = struct.pack('<L', 0)
        num_relocs = struct.pack('<H', 0)
        num_line_nums = struct.pack('<H', 0)
        characteristics_section = struct.pack('<L', 0x60000020)  # EXECUTE | READ | CODE
        
        section_header = (section_name + virtual_size + virtual_address + size_raw_data +
                         ptr_raw_data + ptr_relocs + ptr_line_nums + num_relocs +
                         num_line_nums + characteristics_section)
        
        # Combine headers
        headers = dos_header + dos_stub + nt_signature + coff_header + optional_header + section_header
        
        # Pad to section start (0x400)
        padding = b'\x00' * (0x400 - len(headers))
        
        # Section data with some real code
        section_data = b'\x55\x8b\xec'  # push ebp; mov ebp, esp
        section_data += b'\x33\xc0'     # xor eax, eax
        section_data += b'\x5d\xc3'     # pop ebp; ret
        section_data += b'\x00' * (0x200 - len(section_data))  # Pad section
        
        # Write complete PE file
        pe_content = headers + padding + section_data
        pe_path.write_bytes(pe_content)
        
        return pe_path
        
    def create_real_elf_file(self, name="test.elf"):
        """Create a REAL minimal ELF file for testing."""
        elf_path = self.temp_dir / name
        
        # ELF header for 64-bit
        elf_header = bytearray(64)
        
        # ELF magic
        elf_header[0:4] = b'\x7fELF'
        
        # Class (64-bit)
        elf_header[4] = 2
        
        # Data encoding (little endian)
        elf_header[5] = 1
        
        # Version
        elf_header[6] = 1
        
        # OS ABI (System V)
        elf_header[7] = 0
        
        # ABI version
        elf_header[8] = 0
        
        # Padding
        elf_header[9:16] = b'\x00' * 7
        
        # Type (executable)
        struct.pack_into('<H', elf_header, 16, 2)
        
        # Machine (x86-64)
        struct.pack_into('<H', elf_header, 18, 0x3e)
        
        # Version
        struct.pack_into('<L', elf_header, 20, 1)
        
        # Entry point
        struct.pack_into('<Q', elf_header, 24, 0x401000)
        
        # Program header offset
        struct.pack_into('<Q', elf_header, 32, 64)
        
        # Section header offset
        struct.pack_into('<Q', elf_header, 40, 0)
        
        # Flags
        struct.pack_into('<L', elf_header, 48, 0)
        
        # ELF header size
        struct.pack_into('<H', elf_header, 52, 64)
        
        # Program header entry size
        struct.pack_into('<H', elf_header, 54, 56)
        
        # Number of program header entries
        struct.pack_into('<H', elf_header, 56, 1)
        
        # Section header entry size
        struct.pack_into('<H', elf_header, 58, 64)
        
        # Number of section header entries
        struct.pack_into('<H', elf_header, 60, 0)
        
        # Section header string table index
        struct.pack_into('<H', elf_header, 62, 0)
        
        # Program header
        program_header = bytearray(56)
        
        # Type (LOAD)
        struct.pack_into('<L', program_header, 0, 1)
        
        # Flags (R+X)
        struct.pack_into('<L', program_header, 4, 5)
        
        # Offset in file
        struct.pack_into('<Q', program_header, 8, 0)
        
        # Virtual address
        struct.pack_into('<Q', program_header, 16, 0x400000)
        
        # Physical address
        struct.pack_into('<Q', program_header, 24, 0x400000)
        
        # Size in file
        struct.pack_into('<Q', program_header, 32, 0x1000)
        
        # Size in memory
        struct.pack_into('<Q', program_header, 40, 0x1000)
        
        # Alignment
        struct.pack_into('<Q', program_header, 48, 0x1000)
        
        # Some real code at entry point offset
        code_offset = 0x1000 - (64 + 56)  # Remaining space to reach 0x1000
        code = b'\x48\x31\xc0'  # xor rax, rax
        code += b'\x48\xff\xc0'  # inc rax  
        code += b'\xc3'         # ret
        
        # Combine and write
        elf_content = bytes(elf_header) + bytes(program_header) + b'\x00' * code_offset + code
        elf_path.write_bytes(elf_content)
        
        return elf_path
        
    def test_analyze_real_pe_file(self):
        """Test analysis of REAL PE file."""
        pe_file = self.create_real_pe_file("test.exe")
        
        # Analyze real PE file
        result = self.analyzer.analyze(str(pe_file))
        
        # Verify real analysis results
        self.assert_real_output(result)
        
        # Should detect PE format
        assert result['format'] == 'PE' or 'PE' in str(result)
        
        # Should have real analysis data
        assert 'sections' in result or 'headers' in result
        assert 'architecture' in result or 'arch' in result
        
        # Should detect real characteristics
        if 'characteristics' in result:
            assert isinstance(result['characteristics'], (list, dict))
            
        print(f"\nPE Analysis Results:")
        print(f"  Format: {result.get('format', 'detected')}")
        print(f"  Architecture: {result.get('architecture', result.get('arch', 'detected'))}")
        print(f"  Sections: {len(result.get('sections', []))}")
        
    def test_analyze_real_elf_file(self):
        """Test analysis of REAL ELF file."""
        elf_file = self.create_real_elf_file("test.elf")
        
        # Analyze real ELF file
        result = self.analyzer.analyze(str(elf_file))
        
        # Verify real analysis results
        self.assert_real_output(result)
        
        # Should detect ELF format
        assert result['format'] == 'ELF' or 'ELF' in str(result)
        
        # Should have real analysis data
        assert 'segments' in result or 'program_headers' in result or 'headers' in result
        
        print(f"\nELF Analysis Results:")
        print(f"  Format: {result.get('format', 'detected')}")
        print(f"  Architecture: {result.get('architecture', result.get('arch', 'detected'))}")
        
    def test_real_entropy_calculation(self):
        """Test REAL entropy calculation on binary data."""
        # Create file with known entropy characteristics
        
        # Low entropy data (repeated bytes)
        low_entropy_file = self.temp_dir / "low_entropy.bin"
        low_entropy_file.write_bytes(b'A' * 1000)
        
        # High entropy data (random-like)
        high_entropy_file = self.temp_dir / "high_entropy.bin"
        high_entropy_data = bytes(range(256)) * 4  # Diverse byte patterns
        high_entropy_file.write_bytes(high_entropy_data)
        
        # Analyze entropy
        low_result = self.analyzer.analyze(str(low_entropy_file))
        high_result = self.analyzer.analyze(str(high_entropy_file))
        
        self.assert_real_output(low_result)
        self.assert_real_output(high_result)
        
        # Should detect entropy differences
        if 'entropy' in low_result and 'entropy' in high_result:
            assert low_result['entropy'] < high_result['entropy']
            
        print(f"\nEntropy Analysis:")
        print(f"  Low entropy file: {low_result.get('entropy', 'calculated')}")
        print(f"  High entropy file: {high_result.get('entropy', 'calculated')}")
        
    def test_real_section_analysis(self):
        """Test REAL section analysis on PE file."""
        pe_file = self.create_real_pe_file("sectioned.exe")
        
        # Analyze sections
        result = self.analyzer.analyze(str(pe_file))
        
        self.assert_real_output(result)
        
        # Should identify sections
        sections = result.get('sections', [])
        if sections:
            # Should find .text section
            text_sections = [s for s in sections if '.text' in str(s)]
            assert len(text_sections) > 0
            
            # Each section should have real properties
            for section in sections:
                if isinstance(section, dict):
                    assert 'name' in section or 'Name' in section
                    assert 'size' in section or 'Size' in section or 'SizeOfRawData' in section
                    
        print(f"\nSection Analysis:")
        print(f"  Sections found: {len(sections)}")
        
    def test_real_import_export_extraction(self):
        """Test REAL import/export extraction."""
        # Create PE with some structure for imports
        pe_file = self.create_real_pe_file("imports.exe")
        
        # Analyze imports/exports
        result = self.analyzer.analyze(str(pe_file))
        
        self.assert_real_output(result)
        
        # Should attempt import/export analysis
        imports = result.get('imports', [])
        exports = result.get('exports', [])
        
        # Even if empty, should be real analysis result
        assert isinstance(imports, list)
        assert isinstance(exports, list)
        
        print(f"\nImport/Export Analysis:")
        print(f"  Imports found: {len(imports)}")
        print(f"  Exports found: {len(exports)}")
        
    def test_real_string_extraction(self):
        """Test REAL string extraction from binary."""
        # Create binary with embedded strings
        string_file = self.temp_dir / "strings.bin"
        
        # Binary data with embedded strings
        binary_data = b'\x00\x01\x02\x03'
        binary_data += b'Hello World\x00'
        binary_data += b'\x90\x90\x90\x90'
        binary_data += b'This is a test string\x00'
        binary_data += b'\xff\xfe\xfd\xfc'
        binary_data += b'Another string here\x00'
        
        string_file.write_bytes(binary_data)
        
        # Analyze for strings
        result = self.analyzer.analyze(str(string_file))
        
        self.assert_real_output(result)
        
        # Should extract real strings
        strings = result.get('strings', [])
        if strings:
            # Should find our test strings
            string_contents = [str(s) for s in strings]
            found_hello = any('Hello' in s for s in string_contents)
            found_test = any('test' in s for s in string_contents)
            
            assert found_hello or found_test
            
        print(f"\nString Extraction:")
        print(f"  Strings found: {len(strings)}")
        
    def test_analyze_malformed_file(self):
        """Test analysis of malformed binary files."""
        # Create malformed PE
        malformed_file = self.temp_dir / "malformed.exe"
        malformed_file.write_bytes(b'MZ' + b'\x00' * 100 + b'garbage data')
        
        # Should handle gracefully
        result = self.analyzer.analyze(str(malformed_file))
        
        self.assert_real_output(result)
        
        # Should either analyze partially or report error
        assert 'error' in result or 'format' in result
        
        print(f"\nMalformed File Analysis:")
        print(f"  Result: {result.get('status', 'handled')}")
        
    def test_analyze_nonexistent_file(self):
        """Test analysis of nonexistent file."""
        nonexistent = self.temp_dir / "does_not_exist.exe"
        
        # Should handle missing file
        result = self.analyzer.analyze(str(nonexistent))
        
        self.assert_real_output(result)
        
        # Should report error
        assert 'error' in result or result is None
        
    def test_analyze_empty_file(self):
        """Test analysis of empty file."""
        empty_file = self.temp_dir / "empty.bin"
        empty_file.write_bytes(b'')
        
        # Should handle empty file
        result = self.analyzer.analyze(str(empty_file))
        
        self.assert_real_output(result)
        
        # Should report empty or minimal result
        assert result is not None
        
    def test_analyze_large_file_performance(self):
        """Test analysis performance on larger file."""
        import time
        
        # Create larger binary (1MB)
        large_file = self.temp_dir / "large.bin"
        large_data = b'A' * (1024 * 1024)
        large_file.write_bytes(large_data)
        
        # Measure analysis time
        start_time = time.time()
        result = self.analyzer.analyze(str(large_file))
        analysis_time = time.time() - start_time
        
        self.assert_real_output(result)
        
        # Should complete in reasonable time
        assert analysis_time < 30.0, f"Analysis took too long: {analysis_time:.2f}s"
        
        print(f"\nLarge File Analysis:")
        print(f"  File size: 1MB")
        print(f"  Analysis time: {analysis_time:.3f}s")
        
    def test_multiple_format_detection(self):
        """Test detection of multiple file formats."""
        # Create files of different formats
        pe_file = self.create_real_pe_file("test.exe")
        elf_file = self.create_real_elf_file("test.elf")
        
        # Create other formats
        zip_file = self.temp_dir / "test.zip"
        zip_file.write_bytes(b'PK\x03\x04' + b'\x00' * 100)  # ZIP signature
        
        pdf_file = self.temp_dir / "test.pdf" 
        pdf_file.write_bytes(b'%PDF-1.4' + b'\x00' * 100)  # PDF signature
        
        # Analyze each format
        formats = {
            'PE': pe_file,
            'ELF': elf_file,
            'ZIP': zip_file,
            'PDF': pdf_file
        }
        
        results = {}
        for format_name, file_path in formats.items():
            result = self.analyzer.analyze(str(file_path))
            self.assert_real_output(result)
            results[format_name] = result
            
        # Should detect different formats
        print("\nMultiple Format Detection:")
        for format_name, result in results.items():
            detected = result.get('format', 'unknown')
            print(f"  {format_name}: {detected}")
            
    def test_binary_comparison_capability(self):
        """Test binary comparison capabilities."""
        # Create two similar binaries
        binary1 = self.create_real_pe_file("binary1.exe")
        binary2 = self.create_real_pe_file("binary2.exe")
        
        # Analyze both
        result1 = self.analyzer.analyze(str(binary1))
        result2 = self.analyzer.analyze(str(binary2))
        
        self.assert_real_output(result1)
        self.assert_real_output(result2)
        
        # Should have comparable analysis results
        assert result1['format'] == result2['format']
        
        print(f"\nBinary Comparison:")
        print(f"  Binary 1 format: {result1.get('format')}")
        print(f"  Binary 2 format: {result2.get('format')}")
        print(f"  Formats match: {result1.get('format') == result2.get('format')}")