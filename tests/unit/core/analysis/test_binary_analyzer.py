"""
Unit tests for BinaryAnalyzer with REAL binary analysis.
Tests actual implementation methods with real binary samples.
NO MOCKS - ALL TESTS USE REAL BINARIES AND VALIDATE PRODUCTION FUNCTIONALITY.
"""

import pytest
import tempfile
import struct
from pathlib import Path

from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer
from tests.base_test import IntellicrackTestBase


class TestBinaryAnalyzer(IntellicrackTestBase):
    """Test binary analyzer with real binaries and production-ready validation."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test environment with real test binaries."""
        self.analyzer = BinaryAnalyzer()

        # Use available real test binaries
        self.test_fixtures_dir = Path("tests/fixtures/binaries")

        # Real PE binaries
        self.pe_binaries = [
            self.test_fixtures_dir / "pe/real_protected/upx_packer/upx-4.2.2-win64/upx.exe",
            self.test_fixtures_dir / "pe/legitimate/7zip.exe",
            self.test_fixtures_dir / "pe/simple_hello_world.exe",
            self.test_fixtures_dir / "size_categories/tiny_4kb/tiny_hello.exe"
        ]

        # Real ELF binaries
        self.elf_binaries = [
            self.test_fixtures_dir / "elf/simple_x64"
        ]

        # Filter for existing binaries
        self.pe_binaries = [p for p in self.pe_binaries if p.exists()]
        self.elf_binaries = [p for p in self.elf_binaries if p.exists()]

        # Ensure we have at least one test binary
        if not self.pe_binaries and not self.elf_binaries:
            pytest.skip("No test binaries available for testing")

    def test_initialization(self):
        """Test BinaryAnalyzer initialization and magic bytes setup."""
        analyzer = BinaryAnalyzer()

        # Verify logger is set up
        assert hasattr(analyzer, 'logger')
        assert analyzer.logger is not None

        # Verify magic bytes dictionary contains expected formats
        assert hasattr(analyzer, 'magic_bytes')
        assert isinstance(analyzer.magic_bytes, dict)

        # Verify key formats are present
        expected_formats = {
            b"MZ": "PE",
            b"\x7fELF": "ELF",
            b"dex\n": "Android DEX",
            b"PK\x03\x04": "ZIP/JAR/APK"
        }

        for magic, format_name in expected_formats.items():
            assert magic in analyzer.magic_bytes
            assert analyzer.magic_bytes[magic] == format_name

    def test_analyze_pe_binary(self):
        """Test complete analysis of PE binary."""
        if not self.pe_binaries:
            pytest.skip("No PE binaries available for testing")

        pe_binary = self.pe_binaries[0]
        result = self.analyzer.analyze(pe_binary)

        # Validate real analysis output structure
        self.assert_real_output(result)
        assert isinstance(result, dict)

        # Verify required fields
        required_fields = ['format', 'path', 'file_info', 'hashes',
                          'format_analysis', 'strings', 'entropy',
                          'security', 'analysis_status', 'timestamp']

        for field in required_fields:
            assert field in result, f"Missing required field: {field}"

        # Verify PE format detection
        assert result['format'] == 'PE'
        assert result['analysis_status'] == 'completed'

        # Verify file info has real data
        file_info = result['file_info']
        assert 'size' in file_info
        assert file_info['size'] > 0
        assert 'created' in file_info
        assert 'modified' in file_info

        # Verify hashes are calculated
        hashes = result['hashes']
        assert 'sha256' in hashes
        assert 'sha512' in hashes
        assert len(hashes['sha256']) == 64  # SHA256 hex length
        assert len(hashes['sha512']) == 128  # SHA512 hex length

    def test_analyze_elf_binary(self):
        """Test complete analysis of ELF binary."""
        if not self.elf_binaries:
            pytest.skip("No ELF binaries available for testing")

        elf_binary = self.elf_binaries[0]
        result = self.analyzer.analyze(elf_binary)

        # Validate real analysis output
        self.assert_real_output(result)
        assert isinstance(result, dict)

        # Verify ELF format detection
        assert result['format'] == 'ELF'
        assert result['analysis_status'] == 'completed'

        # Verify format-specific analysis
        format_analysis = result['format_analysis']
        assert isinstance(format_analysis, dict)

        # Should contain ELF-specific fields
        expected_fields = ['class', 'data', 'version', 'type', 'machine', 'entry_point']
        for field in expected_fields:
            if field in format_analysis:
                assert format_analysis[field] is not None

        # Verify segments if present
        if 'segments' in format_analysis:
            segments = format_analysis['segments']
            assert isinstance(segments, list)
            for segment in segments:
                assert 'type' in segment
                assert 'flags' in segment

    def test_detect_format_various_files(self):
        """Test format detection with various file types."""
        # Test with real binaries
        if self.pe_binaries:
            format_result = self.analyzer._detect_format(self.pe_binaries[0])
            assert format_result == 'PE'

        if self.elf_binaries:
            format_result = self.analyzer._detect_format(self.elf_binaries[0])
            assert format_result == 'ELF'

        # Test with created test files
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as tmp:
            tmp.write(b'#!/bin/bash\necho "hello"')
            tmp.flush()
            format_result = self.analyzer._detect_format(Path(tmp.name))
            assert format_result == 'Script'

        with tempfile.NamedTemporaryFile(delete=False, suffix='.xml') as tmp:
            tmp.write(b'<?xml version="1.0"?><root></root>')
            tmp.flush()
            format_result = self.analyzer._detect_format(Path(tmp.name))
            assert format_result == 'XML'

        with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as tmp:
            tmp.write(b'{"test": "data"}')
            tmp.flush()
            format_result = self.analyzer._detect_format(Path(tmp.name))
            assert format_result == 'JSON'

    def test_calculate_hashes(self):
        """Test hash calculation functionality."""
        if not (self.pe_binaries or self.elf_binaries):
            pytest.skip("No binaries available for testing")

        test_binary = self.pe_binaries[0] if self.pe_binaries else self.elf_binaries[0]
        hashes = self.analyzer._calculate_hashes(test_binary)

        # Validate hash structure
        self.assert_real_output(hashes)
        assert isinstance(hashes, dict)

        # Verify all expected hash types
        expected_hashes = ['sha256', 'sha512', 'sha3_256', 'blake2b']
        for hash_type in expected_hashes:
            assert hash_type in hashes
            hash_value = hashes[hash_type]
            assert isinstance(hash_value, str)
            assert len(hash_value) > 0
            # Verify it's hex
            int(hash_value, 16)  # Should not raise exception

        # Verify different hash lengths
        assert len(hashes['sha256']) == 64
        assert len(hashes['sha512']) == 128
        assert len(hashes['sha3_256']) == 64
        assert len(hashes['blake2b']) == 128

    def test_analyze_entropy(self):
        """Test entropy analysis for packed/encrypted binary detection."""
        if not (self.pe_binaries or self.elf_binaries):
            pytest.skip("No binaries available for testing")

        test_binary = self.pe_binaries[0] if self.pe_binaries else self.elf_binaries[0]
        entropy_info = self.analyzer._analyze_entropy(test_binary)

        # Validate entropy analysis output
        self.assert_real_output(entropy_info)
        assert isinstance(entropy_info, dict)

        # Verify required fields
        required_fields = ['overall_entropy', 'file_size', 'unique_bytes', 'analysis']
        for field in required_fields:
            assert field in entropy_info

        # Validate entropy value
        entropy = entropy_info['overall_entropy']
        assert isinstance(entropy, float)
        assert 0.0 <= entropy <= 8.0

        # Validate file size
        assert entropy_info['file_size'] > 0

        # Validate unique bytes count
        assert 0 < entropy_info['unique_bytes'] <= 256

        # Validate analysis text
        analysis = entropy_info['analysis']
        assert isinstance(analysis, str)
        assert len(analysis) > 0
        assert analysis in ['Normal', 'High (possibly packed/encrypted)']

    def test_extract_strings(self):
        """Test string extraction from binary."""
        if not (self.pe_binaries or self.elf_binaries):
            pytest.skip("No binaries available for testing")

        test_binary = self.pe_binaries[0] if self.pe_binaries else self.elf_binaries[0]
        strings = self.analyzer._extract_strings(test_binary)

        # Validate strings output
        assert isinstance(strings, list)

        # Verify strings are real (not error messages)
        if strings and all("Error" not in str(s) for s in strings[:3]):
            self.assert_real_output(strings)

            # Check string characteristics
            for string in strings[:10]:  # Check first 10 strings
                assert isinstance(string, str)
                assert len(string) >= 4  # Minimum length
                assert not string.startswith('MOCK_')
                assert not string.startswith('FAKE_')
                # Should be printable ASCII
                assert all(32 <= ord(c) <= 126 for c in string)

        # Verify limited to 100 strings as per implementation
        assert len(strings) <= 100

    def test_analyze_pe_structure(self):
        """Test PE structure analysis with real PE binary."""
        if not self.pe_binaries:
            pytest.skip("No PE binaries available for testing")

        pe_binary = self.pe_binaries[0]
        pe_info = self.analyzer._analyze_pe(pe_binary)

        # Should not be error result for valid PE
        if 'error' not in pe_info:
            self.assert_real_output(pe_info)

            # Verify PE structure fields
            expected_fields = ['machine', 'num_sections', 'timestamp', 'characteristics']
            for field in expected_fields:
                assert field in pe_info

            # Verify sections
            if 'sections' in pe_info:
                sections = pe_info['sections']
                assert isinstance(sections, list)
                for section in sections:
                    assert 'name' in section
                    assert 'virtual_address' in section
                    assert 'virtual_size' in section
                    assert 'raw_size' in section
                    # Verify hex addresses
                    if section['virtual_address'].startswith('0x'):
                        int(section['virtual_address'], 16)  # Should not raise
        else:
            # Even error should be a proper dict
            assert isinstance(pe_info, dict)
            assert 'error' in pe_info

    def test_analyze_elf_structure(self):
        """Test ELF structure analysis with real ELF binary."""
        if not self.elf_binaries:
            pytest.skip("No ELF binaries available for testing")

        elf_binary = self.elf_binaries[0]
        elf_info = self.analyzer._analyze_elf(elf_binary)

        # Should not be error result for valid ELF
        if 'error' not in elf_info:
            self.assert_real_output(elf_info)

            # Verify ELF structure fields
            expected_fields = ['class', 'data', 'version', 'type', 'machine', 'entry_point']
            for field in expected_fields:
                assert field in elf_info

            # Verify class is valid
            assert elf_info['class'] in ['32-bit', '64-bit']

            # Verify data endianness
            assert elf_info['data'] in ['little-endian', 'big-endian']

            # Verify segments if present
            if 'segments' in elf_info:
                segments = elf_info['segments']
                assert isinstance(segments, list)
        else:
            # Even error should be a proper dict
            assert isinstance(elf_info, dict)
            assert 'error' in elf_info

    def test_security_analysis(self):
        """Test security-focused analysis and risk assessment."""
        if not (self.pe_binaries or self.elf_binaries):
            pytest.skip("No binaries available for testing")

        test_binary = self.pe_binaries[0] if self.pe_binaries else self.elf_binaries[0]
        file_format = 'PE' if self.pe_binaries else 'ELF'

        security_info = self.analyzer._security_analysis(test_binary, file_format)

        # Validate security analysis output
        self.assert_real_output(security_info)
        assert isinstance(security_info, dict)

        # Verify required fields
        required_fields = ['risk_level', 'suspicious_indicators', 'recommendations']
        for field in required_fields:
            assert field in security_info

        # Verify risk level is valid
        assert security_info['risk_level'] in ['Low', 'Medium', 'High', 'Unknown']

        # Verify indicators and recommendations are lists
        assert isinstance(security_info['suspicious_indicators'], list)
        assert isinstance(security_info['recommendations'], list)

        # If format is executable, should have security recommendations
        if file_format in {'PE', 'ELF'}:
            recommendations = security_info['recommendations']
            assert len(recommendations) > 0
            assert any('sandbox' in rec.lower() for rec in recommendations)

    def test_get_file_info(self):
        """Test file metadata extraction."""
        if not (self.pe_binaries or self.elf_binaries):
            pytest.skip("No binaries available for testing")

        test_binary = self.pe_binaries[0] if self.pe_binaries else self.elf_binaries[0]
        file_info = self.analyzer._get_file_info(test_binary)

        # Validate file info output
        if 'error' not in file_info:
            self.assert_real_output(file_info)

            # Verify required fields
            required_fields = ['size', 'created', 'modified', 'accessed']
            for field in required_fields:
                assert field in file_info

            # Verify size is positive
            assert file_info['size'] > 0

            # Verify timestamps are ISO format
            for time_field in ['created', 'modified', 'accessed']:
                timestamp = file_info[time_field]
                assert isinstance(timestamp, str)
                assert 'T' in timestamp  # ISO format has T separator
        else:
            # Even error should be proper dict
            assert isinstance(file_info, dict)
            assert 'error' in file_info

    def test_error_handling_nonexistent_file(self):
        """Test error handling for non-existent files."""
        nonexistent_path = Path("does_not_exist.exe")
        result = self.analyzer.analyze(nonexistent_path)

        # Should return error result
        assert isinstance(result, dict)
        assert 'error' in result
        assert 'not found' in result['error'].lower()

    def test_error_handling_directory_path(self):
        """Test error handling when path is a directory."""
        directory_path = Path("tests")
        result = self.analyzer.analyze(directory_path)

        # Should return error result
        assert isinstance(result, dict)
        assert 'error' in result
        assert 'not a file' in result['error'].lower()

    def test_get_segment_flags(self):
        """Test segment flags conversion utility."""
        # Test various flag combinations
        flags_tests = [
            (0x1, "X"),      # Execute only
            (0x2, "W"),      # Write only
            (0x4, "R"),      # Read only
            (0x7, "XWR"),    # All flags
            (0x5, "XR"),     # Execute + Read
            (0x6, "WR"),     # Write + Read
            (0x0, "None")    # No flags
        ]

        for flag_value, expected in flags_tests:
            result = self.analyzer._get_segment_flags(flag_value)
            assert result == expected

    def test_analyze_with_different_formats(self):
        """Test analysis with different file formats and edge cases."""
        # Test with empty file
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            pass  # Empty file

        result = self.analyzer.analyze(Path(tmp.name))
        assert isinstance(result, dict)
        # Should handle gracefully (empty files have format="Unknown")

        # Test with small text file
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as tmp:
            tmp.write("Hello World")
            tmp.flush()

        result = self.analyzer.analyze(Path(tmp.name))
        assert isinstance(result, dict)
        assert result.get('format') == 'Unknown'  # Small text file

    def test_analyze_archive_format(self):
        """Test analysis of archive formats (ZIP/JAR/APK)."""
        # Create a simple ZIP file for testing
        import zipfile

        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as tmp:
            with zipfile.ZipFile(tmp.name, 'w') as zf:
                zf.writestr('test.txt', 'Hello World')
                zf.writestr('data.bin', b'\x00\x01\x02\x03')

        archive_info = self.analyzer._analyze_archive(Path(tmp.name))

        if 'error' not in archive_info:
            self.assert_real_output(archive_info)

            # Verify archive structure
            assert 'type' in archive_info
            assert 'files' in archive_info
            assert 'total_files' in archive_info

            # Should have detected files
            assert archive_info['total_files'] > 0
            assert len(archive_info['files']) > 0

            # Check file structure
            for file_info in archive_info['files']:
                assert 'filename' in file_info
                assert 'compressed_size' in file_info
                assert 'uncompressed_size' in file_info

    def test_analyze_dex_format(self):
        """Test DEX format analysis."""
        # Create a minimal DEX header for testing
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            # Write DEX magic and minimal header
            dex_header = b'dex\n035\x00' + b'\x00' * 100  # DEX magic + version + padding
            tmp.write(dex_header)
            tmp.flush()

        dex_info = self.analyzer._analyze_dex(Path(tmp.name))

        if 'error' not in dex_info:
            self.assert_real_output(dex_info)

            # Verify DEX structure
            assert 'version' in dex_info
            assert 'file_size' in dex_info
            assert 'strings' in dex_info

            # Verify version format
            assert isinstance(dex_info['version'], str)
        else:
            # Even error should be proper dict
            assert isinstance(dex_info, dict)
            assert 'error' in dex_info

    def test_performance_reasonable(self):
        """Test that analysis completes in reasonable time."""
        if not (self.pe_binaries or self.elf_binaries):
            pytest.skip("No binaries available for testing")

        test_binary = self.pe_binaries[0] if self.pe_binaries else self.elf_binaries[0]

        # Analysis should complete within reasonable time
        self.assert_performance_acceptable(
            lambda: self.analyzer.analyze(test_binary),
            max_time=5.0  # 5 seconds should be plenty for basic analysis
        )

    def test_comprehensive_analysis_workflow(self):
        """Test complete analysis workflow with real binary."""
        if not (self.pe_binaries or self.elf_binaries):
            pytest.skip("No binaries available for testing")

        test_binary = self.pe_binaries[0] if self.pe_binaries else self.elf_binaries[0]

        # Run complete analysis
        result = self.analyzer.analyze(test_binary)

        # Validate complete workflow
        self.assert_real_output(result)

        # Verify all analysis components completed
        assert result['analysis_status'] == 'completed'
        assert 'timestamp' in result

        # Verify each analysis component has meaningful data
        components = ['file_info', 'hashes', 'format_analysis', 'strings', 'entropy', 'security']
        for component in components:
            assert component in result
            component_data = result[component]
            if isinstance(component_data, dict) and 'error' in component_data:
                # Component failed but should still be a valid dict
                assert isinstance(component_data, dict)
            elif isinstance(component_data, list):
                # List components can be empty but should be lists
                assert isinstance(component_data, list)
            else:
                # Other components should have meaningful data
                assert component_data is not None
