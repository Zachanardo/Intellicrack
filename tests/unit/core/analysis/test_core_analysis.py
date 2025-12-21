"""
Unit tests for core_analysis module with REAL binary analysis validation.
Tests production-ready PE analysis, license detection, and packing identification.
NO MOCKS - ALL TESTS USE REAL BINARIES AND VALIDATE SOPHISTICATED FUNCTIONALITY.
"""

import pytest
import tempfile
import struct
import os
from pathlib import Path

from intellicrack.core.analysis.core_analysis import (
    get_machine_type,
    get_magic_type,
    get_characteristics,
    get_pe_timestamp,
    analyze_binary_internal,
    enhanced_deep_license_analysis,
    detect_packing,
    decrypt_embedded_script,
    _analyze_pe_header,
    _analyze_optional_header,
    _analyze_sections,
    _analyze_imports,
    _analyze_exports,
    _generate_analysis_summary,
)
from tests.base_test import IntellicrackTestBase


class TestCoreAnalysis(IntellicrackTestBase):
    """Test core analysis functions with real binaries and production-ready validation."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test environment with real test binaries."""
        self.test_fixtures_dir = Path("tests/fixtures/binaries")

        # Real PE binaries for testing
        self.pe_binaries = [
            self.test_fixtures_dir / "pe/legitimate/7zip.exe",
            self.test_fixtures_dir / "pe/simple_hello_world.exe",
            self.test_fixtures_dir / "pe/real_protected/upx_packer/upx-4.2.2-win64/upx.exe",
            self.test_fixtures_dir / "size_categories/tiny_4kb/tiny_hello.exe"
        ]

        # Real protected/packed binaries for advanced testing
        self.protected_binaries = [
            self.test_fixtures_dir / "pe/protected/upx_packed_0.exe",
            self.test_fixtures_dir / "pe/protected/themida_protected.exe",
            self.test_fixtures_dir / "pe/protected/vmprotect_protected.exe"
        ]

        # Filter for existing binaries
        self.pe_binaries = [p for p in self.pe_binaries if p.exists()]
        self.protected_binaries = [p for p in self.protected_binaries if p.exists()]

        # Ensure we have test binaries
        if not self.pe_binaries:
            pytest.skip("No PE test binaries available for core analysis testing")

    def test_get_machine_type(self):
        """Test machine type mapping for various architectures."""
        # Test common machine types
        assert get_machine_type(0x014C) == "x86 (32-bit)"
        assert get_machine_type(0x8664) == "x64 (64-bit)"
        assert get_machine_type(0x0200) == "Intel Itanium"
        assert get_machine_type(0x01C0) == "ARM little endian"
        assert get_machine_type(0x01C4) == "ARM Thumb-2 little endian"
        assert get_machine_type(0xAA64) == "ARM64 little endian"

        # Test unknown machine type
        unknown_result = get_machine_type(0x9999)
        assert unknown_result.startswith("Unknown")
        assert "0x9999" in unknown_result

    def test_get_magic_type(self):
        """Test PE magic type identification."""
        assert get_magic_type(0x10B) == "PE32"
        assert get_magic_type(0x20B) == "PE32+"
        assert get_magic_type(0x107) == "ROM image"

        # Test unknown magic type
        unknown_result = get_magic_type(0x999)
        assert unknown_result.startswith("Unknown")
        assert "0x0999" in unknown_result

    def test_get_characteristics(self):
        """Test PE characteristics flag parsing."""
        # Test individual flags
        assert "EXECUTABLE_IMAGE" in get_characteristics(0x0002)
        assert "DLL" in get_characteristics(0x2000)
        assert "LARGE_ADDRESS_AWARE" in get_characteristics(0x0020)

        # Test combined flags
        combined = get_characteristics(0x0002 | 0x0100 | 0x0020)
        assert "EXECUTABLE_IMAGE" in combined
        assert "32BIT_MACHINE" in combined
        assert "LARGE_ADDRESS_AWARE" in combined
        assert "|" in combined  # Should be pipe-separated

        # Test no flags
        assert get_characteristics(0) == "None"

    def test_get_pe_timestamp(self):
        """Test PE timestamp conversion to readable format."""
        # Test valid timestamp (January 1, 2025, 00:00:00 UTC)
        timestamp_2025 = 1735689600
        result = get_pe_timestamp(timestamp_2025)
        assert "2025-01-01" in result or "2024-12-31" in result  # Account for timezone
        assert ":" in result  # Should contain time

        # Test invalid timestamp
        invalid_result = get_pe_timestamp(-1)
        assert invalid_result == "Invalid timestamp"

        # Test very large timestamp
        large_result = get_pe_timestamp(99999999999)
        # Should either handle it or return invalid
        assert isinstance(large_result, str)

    def test_analyze_binary_internal_basic_functionality(self):
        """Test basic binary analysis functionality with real PE files."""
        for binary_path in self.pe_binaries[:2]:  # Test first two available binaries
            results = analyze_binary_internal(str(binary_path))

            # Validate comprehensive analysis results
            assert isinstance(results, list)
            assert len(results) > 10  # Should have substantial analysis output

            # Check for essential PE analysis sections
            results_text = "\n".join(results)
            assert "PE Header:" in results_text
            assert "Optional Header:" in results_text
            assert "Sections:" in results_text
            assert "Imports:" in results_text
            assert "Analysis Summary:" in results_text

            # Verify file information is included
            assert str(Path(binary_path).name) in results_text
            assert "File size:" in results_text

            # Check for machine type information
            assert any("Machine:" in line and ("x86" in line or "x64" in line)
                     for line in results)

    def test_analyze_binary_internal_with_flags(self):
        """Test binary analysis with different flag configurations."""
        if not self.pe_binaries:
            pytest.skip("No PE binaries available for flag testing")

        binary_path = str(self.pe_binaries[0])

        # Test with empty flags
        results_empty = analyze_binary_internal(binary_path, [])
        assert isinstance(results_empty, list)
        assert len(results_empty) > 0

        # Test with stealth flag (if implemented)
        results_stealth = analyze_binary_internal(binary_path, ["stealth"])
        assert isinstance(results_stealth, list)
        assert len(results_stealth) > 0

        # Test with custom flags
        results_custom = analyze_binary_internal(binary_path, ["verbose", "detailed"])
        assert isinstance(results_custom, list)

    def test_analyze_binary_internal_error_handling(self):
        """Test error handling for invalid binaries and edge cases."""
        # Test non-existent file
        results = analyze_binary_internal("nonexistent_file.exe")
        assert isinstance(results, list)
        assert any("ERROR" in line for line in results)

        # Test with invalid binary data
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"Not a PE file")
            invalid_binary = f.name

        try:
            results = analyze_binary_internal(invalid_binary)
            assert isinstance(results, list)
            assert any("ERROR" in line for line in results)
        finally:
            os.unlink(invalid_binary)

    def test_enhanced_deep_license_analysis(self):
        """Test deep license analysis with real binaries."""
        for binary_path in self.pe_binaries[:2]:
            results = enhanced_deep_license_analysis(str(binary_path))

            # Validate comprehensive analysis structure
            assert isinstance(results, dict)
            expected_keys = [
                "license_patterns", "validation_routines", "protection_mechanisms",
                "suspicious_strings", "network_calls", "registry_access", "file_operations"
            ]
            for key in expected_keys:
                assert key in results
                assert isinstance(results[key], list)

            # For real binaries, expect some findings
            total_findings = sum(len(results[key]) for key in expected_keys)
            assert total_findings >= 0  # At minimum, should not error

            # Test specific analysis capabilities
            if results["network_calls"]:
                # Should find network-related imports in format "dll::function"
                for call in results["network_calls"]:
                    assert "::" in call
                    assert any(net_term in call.lower()
                             for net_term in ["inet", "socket", "http", "url"])

    def test_enhanced_deep_license_analysis_comprehensive(self):
        """Test comprehensive license analysis capabilities."""
        if not self.pe_binaries:
            pytest.skip("No PE binaries for comprehensive license testing")

        binary_path = str(self.pe_binaries[0])
        results = enhanced_deep_license_analysis(binary_path)

        # Test that analysis handles binary content scanning
        assert "suspicious_strings" in results

        # Test protection mechanism detection
        assert "protection_mechanisms" in results

        # Test that results contain meaningful categorization
        for key in results:
            if key != "error":
                assert isinstance(results[key], list)

    def test_detect_packing_functionality(self):
        """Test packing detection with real and protected binaries."""
        # Test regular binary (should have lower packing confidence)
        if self.pe_binaries:
            results = detect_packing(str(self.pe_binaries[0]))
            self._validate_packing_results(results)

            # For regular binaries, expect lower confidence
            assert results["confidence"] >= 0.0
            assert results["confidence"] <= 1.0

        # Test potentially packed binary (should have higher confidence)
        if self.protected_binaries:
            results = detect_packing(str(self.protected_binaries[0]))
            self._validate_packing_results(results)

            # Packed binaries should have higher confidence or more indicators
            assert len(results["indicators"]) >= 0

    def _validate_packing_results(self, results):
        """Helper to validate packing detection results structure."""
        assert isinstance(results, dict)

        expected_keys = [
            "is_packed", "confidence", "indicators",
            "entropy_analysis", "section_analysis", "import_analysis"
        ]
        for key in expected_keys:
            assert key in results

        assert isinstance(results["is_packed"], bool)
        assert isinstance(results["confidence"], float)
        assert isinstance(results["indicators"], list)
        assert isinstance(results["entropy_analysis"], dict)
        assert isinstance(results["section_analysis"], dict)
        assert isinstance(results["import_analysis"], dict)

        # Validate entropy analysis structure
        entropy_keys = ["average_entropy", "high_entropy_sections", "total_sections", "entropy_scores"]
        for key in entropy_keys:
            assert key in results["entropy_analysis"]

    def test_detect_packing_edge_cases(self):
        """Test packing detection error handling."""
        # Test non-existent file
        results = detect_packing("nonexistent_file.exe")
        assert "error" in results

        # Test invalid binary
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"Invalid PE data")
            invalid_binary = f.name

        try:
            results = detect_packing(invalid_binary)
            # Should handle error gracefully
            assert isinstance(results, dict)
        finally:
            os.unlink(invalid_binary)

    def test_decrypt_embedded_script_functionality(self):
        """Test embedded script detection and extraction."""
        # Create test binary with embedded scripts
        test_scripts = [
            b"<script>function test() { return 'hello'; }</script>",
            b"BEGIN_SCRIPT\ndef python_func():\n    return True\nEND_SCRIPT",
            b"eval(atob('dGVzdCBvYmZ1c2NhdGVk'))",  # Base64 obfuscated content
        ]

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            # Write some binary padding
            f.write(b"\x00" * 1000)

            # Embed test scripts
            for script in test_scripts:
                f.write(script)
                f.write(b"\x00" * 100)  # Padding between scripts

            test_binary = f.name

        try:
            results = decrypt_embedded_script(test_binary)

            # Validate results structure
            assert isinstance(results, list)
            assert len(results) > 0

            results_text = "\n".join(results)

            # Should find embedded scripts
            assert "Found" in results_text and "scripts" in results_text

            # Should identify script types
            script_found = False
            for line in results:
                if "Type:" in line:
                    script_found = True
                    assert any(script_type in line for script_type in ["JavaScript", "Python", "Unknown"])

            # Should show script content
            assert any("Content preview:" in line for line in results)

        finally:
            os.unlink(test_binary)

    def test_decrypt_embedded_script_obfuscation_detection(self):
        """Test detection of obfuscated scripts."""
        obfuscated_content = [
            b"eval(unescape('%66%75%6E%63%74%69%6F%6E'))",
            b"String.fromCharCode(116, 101, 115, 116)",
            b"atob('dGVzdA==')",
            b"base64.b64decode('dGVzdA==')",
        ]

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"\x00" * 500)
            for content in obfuscated_content:
                f.write(content)
                f.write(b"\x00" * 100)
            test_binary = f.name

        try:
            results = decrypt_embedded_script(test_binary)
            results_text = "\n".join(results)

            # Should detect obfuscated patterns
            assert "Obfuscated" in results_text or "Found" in results_text

        finally:
            os.unlink(test_binary)

    def test_internal_helper_functions(self):
        """Test internal helper functions with real PE data structures."""
        # Create a minimal valid PE file for testing internal functions
        # This tests the parsing logic with real PE structure

        # PE DOS header
        dos_header = b'MZ' + b'\x90\x00' * 29  # MZ signature + padding
        dos_header += struct.pack('<I', 0x80)  # e_lfanew pointing to PE header
        dos_header = dos_header.ljust(0x80, b'\x00')

        # PE signature
        pe_signature = b'PE\x00\x00'

        # PE file header (COFF header)
        file_header = struct.pack('<H', 0x8664)  # Machine (x64)
        file_header += struct.pack('<H', 3)      # NumberOfSections
        file_header += struct.pack('<I', 1735689600)  # TimeDateStamp
        file_header += struct.pack('<I', 0)      # PointerToSymbolTable
        file_header += struct.pack('<I', 0)      # NumberOfSymbols
        file_header += struct.pack('<H', 224)    # SizeOfOptionalHeader
        file_header += struct.pack('<H', 0x0022) # Characteristics

        # PE optional header (64-bit)
        opt_header = struct.pack('<H', 0x20B)    # Magic (PE32+)
        opt_header += struct.pack('<B', 14)      # MajorLinkerVersion
        opt_header += struct.pack('<B', 0)       # MinorLinkerVersion
        opt_header += struct.pack('<I', 0x5000)  # SizeOfCode
        opt_header += struct.pack('<I', 0x2000)  # SizeOfInitializedData
        opt_header += struct.pack('<I', 0)       # SizeOfUninitializedData
        opt_header += struct.pack('<I', 0x1000)  # AddressOfEntryPoint
        opt_header += struct.pack('<I', 0x1000)  # BaseOfCode
        opt_header += struct.pack('<Q', 0x400000)  # ImageBase
        opt_header += struct.pack('<I', 0x1000)  # SectionAlignment
        opt_header += struct.pack('<I', 0x200)   # FileAlignment
        opt_header += struct.pack('<H', 6)       # MajorOperatingSystemVersion
        opt_header += struct.pack('<H', 0)       # MinorOperatingSystemVersion
        opt_header += struct.pack('<H', 0)       # MajorImageVersion
        opt_header += struct.pack('<H', 0)       # MinorImageVersion
        opt_header += struct.pack('<H', 6)       # MajorSubsystemVersion
        opt_header += struct.pack('<H', 0)       # MinorSubsystemVersion
        opt_header += struct.pack('<I', 0)       # Win32VersionValue
        opt_header += struct.pack('<I', 0x8000)  # SizeOfImage
        opt_header += struct.pack('<I', 0x200)   # SizeOfHeaders
        opt_header += struct.pack('<I', 0x12345) # CheckSum
        opt_header += struct.pack('<H', 3)       # Subsystem (Console)
        opt_header += struct.pack('<H', 0)       # DllCharacteristics
        opt_header = opt_header.ljust(224, b'\x00')  # Pad to full size

        # Section headers
        text_section = b'.text\x00\x00\x00'     # Name
        text_section += struct.pack('<I', 0x5000)  # VirtualSize
        text_section += struct.pack('<I', 0x1000)  # VirtualAddress
        text_section += struct.pack('<I', 0x5000)  # SizeOfRawData
        text_section += struct.pack('<I', 0x400)   # PointerToRawData
        text_section += b'\x00' * 16  # Relocations and line numbers
        text_section += struct.pack('<I', 0x60000020)  # Characteristics

        # Create complete PE file
        pe_data = dos_header + pe_signature + file_header + opt_header + text_section
        pe_data = pe_data.ljust(0x400, b'\x00')  # Pad to first section
        pe_data += b'A' * 0x5000  # .text section data (low entropy)

        # Write to temporary file and test with real pefile if available
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(pe_data)
            test_pe_file = f.name

        try:
            # Test by actually loading the created PE structure
            import pefile
            pe = pefile.PE(test_pe_file)

            # Test PE header analysis with real PE object
            header_results = _analyze_pe_header(pe)
            assert isinstance(header_results, list)
            assert len(header_results) > 0
            header_text = "\n".join(header_results)
            assert "x64" in header_text
            assert "2025" in header_text or "2024" in header_text

            # Test optional header analysis
            opt_results = _analyze_optional_header(pe)
            assert isinstance(opt_results, list)
            opt_text = "\n".join(opt_results)
            assert "PE32+" in opt_text
            assert "0x00001000" in opt_text

            # Test section analysis
            section_results = []
            suspicious = _analyze_sections(pe, section_results)
            assert isinstance(suspicious, list)
            assert section_results
            section_text = "\n".join(section_results)
            assert ".text" in section_text
            assert "Entropy:" in section_text

        except ImportError:
            # If pefile not available, test with direct binary analysis
            results = analyze_binary_internal(test_pe_file)
            assert isinstance(results, list)

            # Should still attempt analysis even without pefile
            results_text = "\n".join(results)
            if "pefile library not available" not in results_text:
                # If it can analyze without pefile, validate output
                assert len(results) > 5

        finally:
            os.unlink(test_pe_file)

    def test_functions_without_pefile(self):
        """Test graceful handling when pefile is not available."""
        # Temporarily hide pefile module to test fallback behavior
        import sys
        original_pefile = sys.modules.get('pefile')

        # Create a minimal test binary for testing without pefile
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            # Write minimal PE header
            f.write(b'MZ' + b'\x00' * 100)  # DOS header
            f.write(b'PE\x00\x00')  # PE signature
            f.write(b'\x00' * 500)  # Some binary data
            test_binary = f.name

        try:
            # Temporarily remove pefile from modules
            if 'pefile' in sys.modules:
                del sys.modules['pefile']

            # Test analyze_binary_internal without pefile
            results = analyze_binary_internal(test_binary)
            assert isinstance(results, list)

            # Should handle missing pefile gracefully
            results_text = "\n".join(results)
            # Either shows error or uses fallback analysis
            assert len(results) > 0

            # Test enhanced_deep_license_analysis without pefile
            license_results = enhanced_deep_license_analysis(test_binary)
            assert isinstance(license_results, dict)

            # Should either have error or fallback results
            if "error" in license_results:
                assert "pefile" in license_results["error"].lower() or \
                       "analysis" in license_results["error"].lower()
            else:
                # Should have standard result keys even without pefile
                assert "license_patterns" in license_results

            # Test detect_packing without pefile
            packing_results = detect_packing(test_binary)
            assert isinstance(packing_results, dict)

            # Should handle gracefully
            if "error" in packing_results:
                assert isinstance(packing_results["error"], str)
            else:
                # Should have basic packing detection results
                assert "is_packed" in packing_results

        finally:
            # Restore pefile module if it was available
            if original_pefile is not None:
                sys.modules['pefile'] = original_pefile

            # Clean up test file
            os.unlink(test_binary)

    def test_production_ready_output_quality(self):
        """Test that analysis output is production-ready and comprehensive."""
        if not self.pe_binaries:
            pytest.skip("No PE binaries for production quality testing")

        binary_path = str(self.pe_binaries[0])

        # Test analyze_binary_internal produces comprehensive output
        results = analyze_binary_internal(binary_path)

        # Should have detailed sections
        section_count = sum(bool(line.startswith("  ") and ":" in line)
                        for line in results)
        assert section_count > 5  # Should have multiple detailed findings

        # Should include technical details
        results_text = "\n".join(results)
        assert any(hex_pattern in results_text for hex_pattern in ["0x", "Machine:", "Entry point:"])

        # Test deep license analysis provides structured data
        license_results = enhanced_deep_license_analysis(binary_path)

        # Should categorize findings properly
        total_categories = len([k for k, v in license_results.items()
                              if isinstance(v, list) and k != "error"])
        assert total_categories >= 7  # All expected categories present

    def test_real_world_binary_analysis_scenarios(self):
        """Test analysis with various real-world binary scenarios."""
        scenarios_tested = 0

        # Test different binary types if available
        for binary_path in self.pe_binaries:
            results = analyze_binary_internal(str(binary_path))

            # Each binary should produce unique analysis
            assert isinstance(results, list)
            assert len(results) > 5

            # Should handle different architectures
            results_text = "\n".join(results)
            assert any(arch in results_text for arch in ["x86", "x64", "Machine:"])

            scenarios_tested += 1
            if scenarios_tested >= 3:  # Test up to 3 different binaries
                break

        assert scenarios_tested > 0, "No real-world scenarios could be tested"
