"""
Unit tests for BinaryAnalyzer with REAL binary analysis.
Tests REAL PE/ELF header parsing and analysis functionality.
NO MOCKS - ALL TESTS USE REAL BINARIES AND PRODUCE REAL RESULTS.
"""

import pytest
import os
import struct
from pathlib import Path

from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer
from tests.base_test import IntellicrackTestBase


class TestBinaryAnalyzer(IntellicrackTestBase):
    """Test binary analyzer with REAL binaries and REAL analysis results."""
    
    @pytest.fixture(autouse=True)
    def setup(self, real_pe_binary, real_elf_binary):
        """Set up test with real binaries."""
        self.analyzer = BinaryAnalyzer()
        self.pe_binary = real_pe_binary
        self.elf_binary = real_elf_binary
        
    def test_pe_header_parsing_real(self):
        """Test REAL PE header parsing with actual PE file."""
        # Analyze real PE binary
        result = self.analyzer.analyze(self.pe_binary)
        
        # Validate this is REAL analysis output
        self.assert_real_output(result)
        
        # Check real PE characteristics
        assert result['file_type'] == 'PE'
        assert 'headers' in result
        assert 'dos_header' in result['headers']
        assert 'nt_headers' in result['headers']
        assert 'sections' in result
        
        # Verify DOS header magic bytes (MZ)
        dos_header = result['headers']['dos_header']
        assert dos_header['e_magic'] == 0x5A4D  # 'MZ'
        
        # Verify PE signature
        nt_headers = result['headers']['nt_headers']
        assert nt_headers['Signature'] == 0x4550  # 'PE\0\0'
        
        # Verify sections have real data
        assert len(result['sections']) > 0
        for section in result['sections']:
            assert 'Name' in section
            assert 'VirtualAddress' in section
            assert 'SizeOfRawData' in section
            assert section['SizeOfRawData'] > 0  # Real section has size
            
    def test_elf_header_parsing_real(self):
        """Test REAL ELF header parsing with actual ELF file."""
        # Analyze real ELF binary
        result = self.analyzer.analyze(self.elf_binary)
        
        # Validate this is REAL analysis output
        self.assert_real_output(result)
        
        # Check real ELF characteristics
        assert result['file_type'] == 'ELF'
        assert 'headers' in result
        assert 'elf_header' in result['headers']
        assert 'segments' in result
        assert 'sections' in result
        
        # Verify ELF magic bytes
        elf_header = result['headers']['elf_header']
        assert elf_header['e_ident'][0:4] == b'\x7fELF'  # ELF magic
        
        # Verify real segments
        assert len(result['segments']) > 0
        for segment in result['segments']:
            assert 'p_type' in segment
            assert 'p_offset' in segment
            assert 'p_vaddr' in segment
            assert 'p_filesz' in segment
            
    def test_imports_extraction_real(self):
        """Test REAL import table extraction from PE binary."""
        # Extract imports from real PE
        imports = self.analyzer.extract_imports(self.pe_binary)
        
        # Validate real imports
        self.assert_real_output(imports)
        assert isinstance(imports, dict)
        assert len(imports) > 0  # Real PE has imports
        
        # Check import structure
        for dll, functions in imports.items():
            assert dll.endswith('.dll')  # Real DLL name
            assert isinstance(functions, list)
            assert len(functions) > 0  # Real DLL has functions
            
            # Verify function names are real
            for func in functions:
                assert isinstance(func, str)
                assert len(func) > 0
                # Real Windows API functions follow patterns
                assert not func.startswith('mock_')
                assert not func.startswith('fake_')
                
    def test_exports_extraction_real(self):
        """Test REAL export table extraction."""
        # For testing, we'll use a DLL (many PEs export functions)
        # First check if our test binary has exports
        exports = self.analyzer.extract_exports(self.pe_binary)
        
        # Validate output format (may be empty for EXEs)
        assert isinstance(exports, list)
        
        # If exports exist, validate they're real
        if exports:
            self.assert_real_output(exports)
            for export in exports:
                assert 'name' in export
                assert 'ordinal' in export
                assert 'address' in export
                assert export['address'] > 0  # Real export has address
                
    def test_entropy_calculation_real(self):
        """Test REAL entropy calculation on binary sections."""
        # Calculate entropy for real binary
        entropy_map = self.analyzer.calculate_entropy(self.pe_binary)
        
        # Validate real entropy values
        self.assert_real_output(entropy_map)
        assert isinstance(entropy_map, dict)
        assert len(entropy_map) > 0
        
        # Check entropy values are realistic
        for section, entropy in entropy_map.items():
            assert isinstance(entropy, float)
            assert 0.0 <= entropy <= 8.0  # Entropy range
            # Real binaries rarely have exactly 0 or 8 entropy
            assert entropy != 0.0
            assert entropy != 8.0
            
    def test_strings_extraction_real(self):
        """Test REAL string extraction from binary."""
        # Extract strings from real binary
        strings = self.analyzer.extract_strings(self.pe_binary, min_length=4)
        
        # Validate real strings
        self.assert_real_output(strings)
        assert isinstance(strings, list)
        assert len(strings) > 10  # Real binaries have many strings
        
        # Check string characteristics
        ascii_count = 0
        unicode_count = 0
        
        for string_info in strings:
            assert 'offset' in string_info
            assert 'string' in string_info
            assert 'encoding' in string_info
            
            string = string_info['string']
            assert len(string) >= 4  # Min length respected
            assert not string.startswith('MOCK_')
            assert not string.startswith('FAKE_')
            
            if string_info['encoding'] == 'ascii':
                ascii_count += 1
            elif string_info['encoding'] == 'unicode':
                unicode_count += 1
                
        # Real binaries have both ASCII and Unicode strings
        assert ascii_count > 0
        assert unicode_count > 0
        
    def test_certificate_extraction_real(self):
        """Test REAL certificate extraction from signed PE."""
        # Extract certificate from PE (may not exist)
        cert_info = self.analyzer.extract_certificate(self.pe_binary)
        
        # Validate output format
        assert isinstance(cert_info, dict) or cert_info is None
        
        # If certificate exists, validate it's real
        if cert_info:
            self.assert_real_output(cert_info)
            assert 'subject' in cert_info
            assert 'issuer' in cert_info
            assert 'serial_number' in cert_info
            assert 'not_before' in cert_info
            assert 'not_after' in cert_info
            
            # Real certificates have these fields populated
            assert len(cert_info['subject']) > 0
            assert len(cert_info['issuer']) > 0
            
    def test_architecture_detection_real(self):
        """Test REAL architecture detection."""
        # Detect architecture of real binaries
        pe_arch = self.analyzer.get_architecture(self.pe_binary)
        elf_arch = self.analyzer.get_architecture(self.elf_binary)
        
        # Validate real architectures
        self.assert_real_output(pe_arch)
        self.assert_real_output(elf_arch)
        
        # Check valid architecture values
        valid_archs = ['x86', 'x64', 'ARM', 'ARM64', 'MIPS', 'PowerPC']
        assert pe_arch in valid_archs
        assert elf_arch in valid_archs
        
    def test_checksum_verification_real(self):
        """Test REAL checksum calculation and verification."""
        # Calculate checksums for real binary
        checksums = self.analyzer.calculate_checksums(self.pe_binary)
        
        # Validate real checksums
        self.assert_real_output(checksums)
        assert 'md5' in checksums
        assert 'sha1' in checksums
        assert 'sha256' in checksums
        
        # Verify checksum formats
        assert len(checksums['md5']) == 32  # MD5 is 32 hex chars
        assert len(checksums['sha1']) == 40  # SHA1 is 40 hex chars
        assert len(checksums['sha256']) == 64  # SHA256 is 64 hex chars
        
        # Verify they're different (not placeholder values)
        assert checksums['md5'] != checksums['sha1']
        assert checksums['md5'] != checksums['sha256']
        assert checksums['sha1'] != checksums['sha256']
        
    def test_overlay_detection_real(self):
        """Test REAL overlay data detection."""
        # Check for overlay in real binary
        overlay_info = self.analyzer.detect_overlay(self.pe_binary)
        
        # Validate output format
        assert isinstance(overlay_info, dict)
        assert 'has_overlay' in overlay_info
        assert 'offset' in overlay_info
        assert 'size' in overlay_info
        
        # If overlay exists, validate it's real
        if overlay_info['has_overlay']:
            self.assert_real_output(overlay_info)
            assert overlay_info['offset'] > 0
            assert overlay_info['size'] > 0
            
    def test_resource_extraction_real(self):
        """Test REAL resource extraction from PE."""
        # Extract resources from real PE
        resources = self.analyzer.extract_resources(self.pe_binary)
        
        # Validate output format
        assert isinstance(resources, list)
        
        # If resources exist, validate they're real
        if resources:
            self.assert_real_output(resources)
            for resource in resources:
                assert 'type' in resource
                assert 'name' in resource
                assert 'language' in resource
                assert 'offset' in resource
                assert 'size' in resource
                
                # Real resources have positive size
                assert resource['size'] > 0
                
    def test_tls_callback_detection_real(self):
        """Test REAL TLS callback detection."""
        # Detect TLS callbacks in real binary
        tls_info = self.analyzer.detect_tls_callbacks(self.pe_binary)
        
        # Validate output format
        assert isinstance(tls_info, dict)
        assert 'has_tls' in tls_info
        assert 'callbacks' in tls_info
        
        # If TLS exists, validate it's real
        if tls_info['has_tls']:
            self.assert_real_output(tls_info)
            assert isinstance(tls_info['callbacks'], list)
            for callback in tls_info['callbacks']:
                assert isinstance(callback, int)
                assert callback > 0  # Real callback address
                
    def test_section_characteristics_real(self):
        """Test REAL section characteristics analysis."""
        # Analyze sections of real binary
        sections = self.analyzer.analyze_sections(self.pe_binary)
        
        # Validate real section data
        self.assert_real_output(sections)
        assert isinstance(sections, list)
        assert len(sections) > 0  # Real PE has sections
        
        # Check each section
        for section in sections:
            assert 'name' in section
            assert 'virtual_address' in section
            assert 'virtual_size' in section
            assert 'raw_size' in section
            assert 'characteristics' in section
            assert 'entropy' in section
            
            # Validate section names (common real sections)
            name = section['name'].strip('\x00')
            common_sections = ['.text', '.data', '.rdata', '.rsrc', '.reloc', '.idata']
            # Real sections often have standard names
            assert any(name.startswith(s) for s in common_sections + ['UPX', '.edata', '.tls'])
            
    def test_packer_detection_real(self):
        """Test REAL packer/protector detection."""
        # Detect packers in real binary
        packer_info = self.analyzer.detect_packers(self.pe_binary)
        
        # Validate output format
        assert isinstance(packer_info, dict)
        assert 'packed' in packer_info
        assert 'packers' in packer_info
        assert 'indicators' in packer_info
        
        # If packed, validate detection is real
        if packer_info['packed']:
            self.assert_real_output(packer_info)
            assert len(packer_info['packers']) > 0
            assert len(packer_info['indicators']) > 0
            
            # Check for real packer names
            known_packers = ['UPX', 'ASPack', 'PECompact', 'Themida', 'VMProtect']
            for packer in packer_info['packers']:
                # Real packer detection returns known names or patterns
                assert isinstance(packer, str)
                assert len(packer) > 0