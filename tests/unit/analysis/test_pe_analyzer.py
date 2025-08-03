"""
Unit tests for PE analyzer with REAL PE binary analysis.
Tests REAL PE header parsing, section analysis, and import/export extraction.
NO MOCKS - ALL TESTS USE REAL BINARIES AND PRODUCE REAL RESULTS.
"""

import pytest
import struct
from pathlib import Path

from intellicrack.core.analysis.pe_analyzer import PEAnalyzer
from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer
from tests.base_test import IntellicrackTestBase


class TestPEAnalyzer(IntellicrackTestBase):
    """Test PE analyzer with REAL PE binaries."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test with real PE binaries."""
        self.analyzer = PEAnalyzer()
        self.test_dir = Path(__file__).parent.parent.parent / 'fixtures' / 'binaries'
        
        # Use real binaries we generated
        self.simple_pe = self.test_dir / 'pe' / 'simple_hello_world.exe'
        self.protected_dir = self.test_dir / 'protected'
        self.upx_pe = self.protected_dir / 'upx_packed_0.exe'
        self.dotnet_pe = self.protected_dir / 'dotnet_assembly_0.exe'
        self.themida_pe = self.protected_dir / 'themida_protected.exe'
        
    def test_pe_header_parsing_simple(self):
        """Test PE header parsing on simple executable."""
        result = self.analyzer.analyze_pe(self.simple_pe)
        
        # Validate real PE analysis
        self.assert_real_output(result)
        
        # Check DOS header
        assert 'dos_header' in result
        dos = result['dos_header']
        assert dos['e_magic'] == 0x5A4D  # 'MZ'
        assert dos['e_lfanew'] > 0  # Points to PE header
        
        # Check PE header
        assert 'pe_header' in result
        pe = result['pe_header']
        assert pe['Signature'] == 0x4550  # 'PE\0\0'
        
        # Check COFF header
        assert 'coff_header' in result
        coff = result['coff_header']
        assert coff['Machine'] in [0x014C, 0x8664]  # x86 or x64
        assert coff['NumberOfSections'] > 0
        
        # Check Optional header
        assert 'optional_header' in result
        opt = result['optional_header']
        assert opt['Magic'] in [0x010B, 0x020B]  # PE32 or PE32+
        assert opt['AddressOfEntryPoint'] > 0
        assert opt['ImageBase'] > 0
        
    def test_section_analysis_real(self):
        """Test section analysis with real PE sections."""
        result = self.analyzer.analyze_sections(self.simple_pe)
        
        self.assert_real_output(result)
        assert isinstance(result, list)
        assert len(result) > 0
        
        # Common PE sections
        section_names = [s['Name'] for s in result]
        
        # At least one of these should exist
        common_sections = ['.text', '.data', '.rdata', '.rsrc', '.reloc']
        assert any(name in section_names for name in common_sections)
        
        # Validate each section
        for section in result:
            assert 'Name' in section
            assert 'VirtualAddress' in section
            assert 'VirtualSize' in section
            assert 'SizeOfRawData' in section
            assert 'PointerToRawData' in section
            assert 'Characteristics' in section
            assert 'Entropy' in section
            
            # Real sections have valid data
            assert section['VirtualAddress'] >= 0
            assert section['VirtualSize'] >= 0
            assert 0.0 <= section['Entropy'] <= 8.0
            
            # Check characteristics flags
            chars = section['Characteristics']
            if section['Name'].startswith('.text'):
                assert chars & 0x20000000  # IMAGE_SCN_CNT_CODE
                assert chars & 0x20000000  # IMAGE_SCN_MEM_EXECUTE
                
    def test_import_table_extraction(self):
        """Test import table extraction from real PE."""
        imports = self.analyzer.extract_imports(self.simple_pe)
        
        self.assert_real_output(imports)
        assert isinstance(imports, dict)
        
        # Windows executables always import from kernel32.dll
        assert any('kernel32' in dll.lower() for dll in imports.keys())
        
        # Check import structure
        for dll_name, functions in imports.items():
            assert dll_name.endswith('.dll') or dll_name.endswith('.DLL')
            assert isinstance(functions, list)
            assert len(functions) > 0
            
            for func in functions:
                assert isinstance(func, dict)
                assert 'name' in func or 'ordinal' in func
                assert 'address' in func
                assert func['address'] > 0
                
    def test_export_table_extraction(self):
        """Test export table extraction from real DLL."""
        # Most EXEs don't have exports, so we check handling
        exports = self.analyzer.extract_exports(self.simple_pe)
        
        assert isinstance(exports, list)
        # If exports exist, validate them
        if exports:
            self.assert_real_output(exports)
            for export in exports:
                assert 'name' in export or 'ordinal' in export
                assert 'address' in export
                assert export['address'] > 0
                
    def test_resource_extraction(self):
        """Test resource extraction from real PE."""
        resources = self.analyzer.extract_resources(self.simple_pe)
        
        assert isinstance(resources, list)
        if resources:
            self.assert_real_output(resources)
            for resource in resources:
                assert 'type' in resource
                assert 'name' in resource
                assert 'language' in resource
                assert 'offset' in resource
                assert 'size' in resource
                assert resource['size'] > 0
                
    def test_upx_packed_detection(self):
        """Test UPX packed binary detection."""
        if not self.upx_pe.exists():
            pytest.skip("UPX packed binary not found")
            
        result = self.analyzer.analyze_pe(self.upx_pe)
        self.assert_real_output(result)
        
        # Check for UPX indicators
        sections = result.get('sections', [])
        section_names = [s['Name'] for s in sections]
        
        # UPX creates specific section names
        upx_sections = ['UPX0', 'UPX1', 'UPX2']
        has_upx = any(name in section_names for name in upx_sections)
        
        # Check packer detection
        packers = self.analyzer.detect_packers(self.upx_pe)
        assert isinstance(packers, list)
        if has_upx:
            assert any('upx' in p.lower() for p in packers)
            
    def test_dotnet_assembly_detection(self):
        """Test .NET assembly detection and analysis."""
        if not self.dotnet_pe.exists():
            pytest.skip(".NET assembly not found")
            
        result = self.analyzer.analyze_pe(self.dotnet_pe)
        self.assert_real_output(result)
        
        # Check for .NET indicators
        assert 'clr_header' in result or 'is_dotnet' in result
        
        # .NET assemblies have specific characteristics
        opt_header = result.get('optional_header', {})
        data_dirs = opt_header.get('DataDirectory', [])
        
        # CLR Runtime Header should be present
        if len(data_dirs) > 14:  # COM+ Runtime header index
            clr_header = data_dirs[14]
            if clr_header['VirtualAddress'] > 0:
                assert clr_header['Size'] > 0
                
    def test_themida_protected_analysis(self):
        """Test Themida protected binary analysis."""
        if not self.themida_pe.exists():
            pytest.skip("Themida protected binary not found")
            
        result = self.analyzer.analyze_pe(self.themida_pe)
        self.assert_real_output(result)
        
        # Themida creates specific sections
        sections = result.get('sections', [])
        section_names = [s['Name'] for s in sections]
        
        # Check for protection indicators
        protection = self.analyzer.detect_protection(self.themida_pe)
        assert isinstance(protection, dict)
        assert 'protector' in protection
        assert 'confidence' in protection
        assert 'indicators' in protection
        
        # High entropy in protected sections
        for section in sections:
            if 'themida' in section['Name'].lower():
                assert section['Entropy'] > 6.0  # Encrypted/compressed
                
    def test_certificate_extraction(self):
        """Test digital certificate extraction."""
        cert_info = self.analyzer.extract_certificate(self.simple_pe)
        
        # Most test binaries won't be signed
        assert cert_info is None or isinstance(cert_info, dict)
        
        if cert_info:
            self.assert_real_output(cert_info)
            assert 'subject' in cert_info
            assert 'issuer' in cert_info
            assert 'serial_number' in cert_info
            assert 'not_before' in cert_info
            assert 'not_after' in cert_info
            assert 'signature_algorithm' in cert_info
            
    def test_relocation_table_parsing(self):
        """Test relocation table parsing."""
        relocations = self.analyzer.parse_relocations(self.simple_pe)
        
        assert isinstance(relocations, list)
        if relocations:
            self.assert_real_output(relocations)
            for reloc in relocations:
                assert 'page_rva' in reloc
                assert 'block_size' in reloc
                assert 'entries' in reloc
                assert isinstance(reloc['entries'], list)
                
    def test_tls_callback_detection(self):
        """Test TLS callback detection."""
        tls_info = self.analyzer.detect_tls_callbacks(self.simple_pe)
        
        assert isinstance(tls_info, dict)
        assert 'has_tls' in tls_info
        assert 'callbacks' in tls_info
        
        if tls_info['has_tls']:
            self.assert_real_output(tls_info)
            assert isinstance(tls_info['callbacks'], list)
            for callback in tls_info['callbacks']:
                assert isinstance(callback, int)
                assert callback > 0
                
    def test_debug_directory_parsing(self):
        """Test debug directory parsing."""
        debug_info = self.analyzer.parse_debug_directory(self.simple_pe)
        
        assert isinstance(debug_info, list)
        if debug_info:
            self.assert_real_output(debug_info)
            for entry in debug_info:
                assert 'type' in entry
                assert 'timestamp' in entry
                assert 'size' in entry
                
                # PDB info is common
                if entry['type'] == 'CODEVIEW':
                    assert 'pdb_path' in entry
                    assert 'guid' in entry
                    
    def test_load_config_parsing(self):
        """Test load configuration parsing."""
        load_config = self.analyzer.parse_load_config(self.simple_pe)
        
        assert load_config is None or isinstance(load_config, dict)
        
        if load_config:
            self.assert_real_output(load_config)
            # Check for security features
            if 'SecurityCookie' in load_config:
                assert isinstance(load_config['SecurityCookie'], int)
            if 'GuardFlags' in load_config:
                assert isinstance(load_config['GuardFlags'], int)
                
    def test_anomaly_detection(self):
        """Test PE anomaly detection."""
        anomalies = self.analyzer.detect_anomalies(self.simple_pe)
        
        assert isinstance(anomalies, list)
        # Normal PE shouldn't have many anomalies
        
        # Test with protected binary for more anomalies
        if self.themida_pe.exists():
            protected_anomalies = self.analyzer.detect_anomalies(self.themida_pe)
            assert isinstance(protected_anomalies, list)
            # Protected binaries often have anomalies
            if protected_anomalies:
                self.assert_real_output(protected_anomalies)
                for anomaly in protected_anomalies:
                    assert 'type' in anomaly
                    assert 'description' in anomaly
                    assert 'severity' in anomaly
                    
    def test_entropy_analysis(self):
        """Test entropy analysis of PE sections."""
        entropy_map = self.analyzer.calculate_section_entropy(self.simple_pe)
        
        self.assert_real_output(entropy_map)
        assert isinstance(entropy_map, dict)
        
        for section_name, entropy in entropy_map.items():
            assert isinstance(entropy, float)
            assert 0.0 <= entropy <= 8.0
            
            # Typical entropy ranges
            if section_name == '.text':
                assert 4.0 <= entropy <= 7.0  # Code has medium-high entropy
            elif section_name == '.data':
                assert entropy <= 6.0  # Data usually lower entropy
                
    def test_checksum_verification(self):
        """Test PE checksum calculation and verification."""
        checksum_info = self.analyzer.verify_checksum(self.simple_pe)
        
        self.assert_real_output(checksum_info)
        assert isinstance(checksum_info, dict)
        assert 'stored_checksum' in checksum_info
        assert 'calculated_checksum' in checksum_info
        assert 'is_valid' in checksum_info
        
        # Both should be integers
        assert isinstance(checksum_info['stored_checksum'], int)
        assert isinstance(checksum_info['calculated_checksum'], int)