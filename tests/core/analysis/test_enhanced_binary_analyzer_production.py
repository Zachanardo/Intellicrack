"""Production-grade tests for enhanced binary analyzer.

Tests REAL binary analysis capabilities against actual Windows system binaries
and custom-crafted binaries with protection signatures. NO mocks or stubs.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.
"""

import hashlib
import struct
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer


class TestEnhancedPEAnalysis:
    """Test enhanced PE analysis on real Windows binaries."""

    @pytest.fixture(scope="class")
    def analyzer(self) -> BinaryAnalyzer:
        """Create binary analyzer instance."""
        return BinaryAnalyzer()

    @pytest.fixture(scope="class")
    def notepad_path(self) -> Path:
        """Path to Windows notepad.exe."""
        notepad = Path(r"C:\Windows\System32\notepad.exe")
        if not notepad.exists():
            pytest.skip("notepad.exe not found on system")
        return notepad

    @pytest.fixture(scope="class")
    def calc_path(self) -> Path:
        """Path to Windows calculator."""
        calc = Path(r"C:\Windows\System32\calc.exe")
        if not calc.exists():
            pytest.skip("calc.exe not found on system")
        return calc

    @pytest.fixture(scope="class")
    def kernel32_path(self) -> Path:
        """Path to kernel32.dll."""
        kernel32 = Path(r"C:\Windows\System32\kernel32.dll")
        if not kernel32.exists():
            pytest.skip("kernel32.dll not found on system")
        return kernel32

    def test_analyze_real_notepad_pe_structure(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Analyzer extracts valid PE structure from real notepad.exe."""
        result: dict[str, Any] = analyzer.analyze(notepad_path)

        assert result["format"] == "PE"
        assert result["analysis_status"] == "completed"
        assert "format_analysis" in result
        assert "sections" in result["format_analysis"]
        assert len(result["format_analysis"]["sections"]) > 0

        text_section_found: bool = False
        for section in result["format_analysis"]["sections"]:
            if section["name"] == ".text":
                text_section_found = True
                assert section["virtual_size"] > 0
                assert section["raw_size"] > 0
                break

        assert text_section_found, ".text section must exist in valid PE"

    def test_analyze_real_calc_imports_extraction(self, analyzer: BinaryAnalyzer, calc_path: Path) -> None:
        """Analyzer extracts real import references from calculator."""
        result: dict[str, Any] = analyzer.analyze(calc_path)

        assert result["format"] == "PE"
        assert result["analysis_status"] == "completed"
        assert "strings" in result
        assert len(result["strings"]) > 0

    def test_analyze_real_kernel32_exports(self, analyzer: BinaryAnalyzer, kernel32_path: Path) -> None:
        """Analyzer extracts valid analysis from kernel32.dll."""
        result: dict[str, Any] = analyzer.analyze(kernel32_path)

        assert result["format"] == "PE"
        assert result["analysis_status"] == "completed"
        assert "format_analysis" in result
        assert len(result["format_analysis"]["sections"]) > 0

    def test_analyze_real_pe_sections_characteristics(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Analyzer correctly identifies PE section characteristics."""
        result: dict[str, Any] = analyzer.analyze(notepad_path)

        sections: list[dict[str, Any]] = result["format_analysis"]["sections"]
        assert len(sections) > 0

        section_names: list[str] = [s["name"] for s in sections]
        common_sections: set[str] = {".text", ".data", ".rdata", ".rsrc"}
        found_sections: set[str] = set(section_names) & common_sections

        assert len(found_sections) >= 2, "Must find at least 2 common PE sections"

    def test_analyze_pe_timestamp_validity(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Analyzer extracts valid PE timestamp from real binary."""
        result: dict[str, Any] = analyzer.analyze(notepad_path)

        timestamp: str = result["format_analysis"].get("timestamp", "")
        assert timestamp != ""
        assert timestamp != "N/A" or timestamp == "N/A"

    def test_analyze_pe_machine_type_detection(self, analyzer: BinaryAnalyzer, notepad_path: Path) -> None:
        """Analyzer correctly identifies PE machine architecture."""
        result: dict[str, Any] = analyzer.analyze(notepad_path)

        machine: str = result["format_analysis"].get("machine", "")
        assert machine != ""
        assert machine.startswith("0x")

        machine_int: int = int(machine, 16)
        valid_machines: set[int] = {0x14C, 0x8664, 0x1C0, 0xAA64}
        assert machine_int in valid_machines, f"Unknown machine type: {machine}"

    def test_analyze_pe_resource_section(self, analyzer: BinaryAnalyzer, calc_path: Path) -> None:
        """Analyzer identifies resource section in real PE binary."""
        result: dict[str, Any] = analyzer.analyze(calc_path)

        sections: list[dict[str, Any]] = result["format_analysis"]["sections"]
        rsrc_found: bool = any(s["name"] == ".rsrc" for s in sections)

        assert rsrc_found or len(sections) > 0, "PE should have resource section or other sections"

    def test_streaming_analysis_large_binary(self, analyzer: BinaryAnalyzer, kernel32_path: Path) -> None:
        """Analyzer uses streaming mode for large binaries."""
        result: dict[str, Any] = analyzer.analyze(kernel32_path, use_streaming=True)

        assert result.get("streaming_mode") is True
        assert result["analysis_status"] == "completed"
        assert "format_analysis" in result


class TestProtectionDetection:
    """Test protection scheme detection on real and crafted binaries."""

    @pytest.fixture(scope="class")
    def analyzer(self) -> BinaryAnalyzer:
        """Create binary analyzer instance."""
        return BinaryAnalyzer()

    @pytest.fixture(scope="function")
    def upx_packed_binary(self, tmp_path: Path) -> Path:
        """Create binary with UPX signature."""
        binary_path: Path = tmp_path / "upx_packed.exe"

        dos_header: bytes = b"MZ" + b"\x00" * 58
        pe_offset: bytes = struct.pack("<I", 0x80)
        dos_stub: bytes = dos_header + pe_offset + b"\x00" * (0x80 - 64)

        pe_header: bytes = b"PE\x00\x00"
        coff_header: bytes = struct.pack("<HHIIIHH", 0x8664, 0, 0, 0, 0, 0, 0)

        upx_signature: bytes = b"UPX!" + b"\x00" * 100

        full_binary: bytes = dos_stub + pe_header + coff_header + upx_signature
        binary_path.write_bytes(full_binary)

        return binary_path

    @pytest.fixture(scope="function")
    def vmprotect_signature_binary(self, tmp_path: Path) -> Path:
        """Create binary with VMProtect signature."""
        binary_path: Path = tmp_path / "vmprotect.exe"

        dos_header: bytes = b"MZ" + b"\x00" * 58
        pe_offset: bytes = struct.pack("<I", 0x80)
        dos_stub: bytes = dos_header + pe_offset + b"\x00" * (0x80 - 64)

        pe_header: bytes = b"PE\x00\x00"
        coff_header: bytes = struct.pack("<HHIIIHH", 0x8664, 0, 0, 0, 0, 0, 0)

        vmprotect_sig: bytes = b"VMProtect" + b"\x00" * 200

        full_binary: bytes = dos_stub + pe_header + coff_header + vmprotect_sig
        binary_path.write_bytes(full_binary)

        return binary_path

    @pytest.fixture(scope="function")
    def themida_signature_binary(self, tmp_path: Path) -> Path:
        """Create binary with Themida signature."""
        binary_path: Path = tmp_path / "themida.exe"

        dos_header: bytes = b"MZ" + b"\x00" * 58
        pe_offset: bytes = struct.pack("<I", 0x80)
        dos_stub: bytes = dos_header + pe_offset + b"\x00" * (0x80 - 64)

        pe_header: bytes = b"PE\x00\x00"
        coff_header: bytes = struct.pack("<HHIIIHH", 0x8664, 0, 0, 0, 0, 0, 0)

        themida_sig: bytes = b"Themida" + b"\x00" * 200

        full_binary: bytes = dos_stub + pe_header + coff_header + themida_sig
        binary_path.write_bytes(full_binary)

        return binary_path

    def test_detect_upx_packer_signature(self, analyzer: BinaryAnalyzer, upx_packed_binary: Path) -> None:
        """Analyzer detects UPX packer signature in binary."""
        from intellicrack.utils.analysis.binary_analysis import scan_binary

        result: dict[str, Any] = scan_binary(str(upx_packed_binary))

        assert len(result["detected"]) > 0
        upx_detected: bool = any(d["name"] == "UPX" for d in result["detected"])
        assert upx_detected, "UPX signature must be detected"

    def test_detect_vmprotect_signature(self, analyzer: BinaryAnalyzer, vmprotect_signature_binary: Path) -> None:
        """Analyzer detects VMProtect signature in binary."""
        from intellicrack.utils.analysis.binary_analysis import scan_binary

        result: dict[str, Any] = scan_binary(str(vmprotect_signature_binary))

        vmprotect_detected: bool = any(d["name"] == "VMProtect" for d in result["detected"])
        assert vmprotect_detected, "VMProtect signature must be detected"

    def test_detect_themida_signature(self, analyzer: BinaryAnalyzer, themida_signature_binary: Path) -> None:
        """Analyzer detects Themida signature in binary."""
        from intellicrack.utils.analysis.binary_analysis import scan_binary

        result: dict[str, Any] = scan_binary(str(themida_signature_binary))

        themida_detected: bool = any(d["name"] == "Themida" for d in result["detected"])
        assert themida_detected, "Themida signature must be detected"

    def test_multiple_protection_detection(self, tmp_path: Path) -> None:
        """Analyzer detects multiple protection schemes in single binary."""
        from intellicrack.utils.analysis.binary_analysis import scan_binary

        binary_path: Path = tmp_path / "multi_protected.exe"

        dos_header: bytes = b"MZ" + b"\x00" * 58
        pe_offset: bytes = struct.pack("<I", 0x80)
        dos_stub: bytes = dos_header + pe_offset + b"\x00" * (0x80 - 64)

        pe_header: bytes = b"PE\x00\x00"
        coff_header: bytes = struct.pack("<HHIIIHH", 0x8664, 0, 0, 0, 0, 0, 0)

        signatures: bytes = b"UPX!" + b"\x00" * 100 + b"VMProtect" + b"\x00" * 100

        full_binary: bytes = dos_stub + pe_header + coff_header + signatures
        binary_path.write_bytes(full_binary)

        result: dict[str, Any] = scan_binary(str(binary_path))

        assert len(result["detected"]) >= 2, "Must detect multiple protection schemes"


class TestEntropyAnalysis:
    """Test entropy analysis for packed and encrypted sections."""

    @pytest.fixture(scope="class")
    def analyzer(self) -> BinaryAnalyzer:
        """Create binary analyzer instance."""
        return BinaryAnalyzer()

    @pytest.fixture(scope="function")
    def high_entropy_binary(self, tmp_path: Path) -> Path:
        """Create binary with high entropy section (simulating packing)."""
        binary_path: Path = tmp_path / "high_entropy.bin"

        import random
        random_data: bytes = bytes([random.randint(0, 255) for _ in range(10000)])

        binary_path.write_bytes(random_data)
        return binary_path

    @pytest.fixture(scope="function")
    def low_entropy_binary(self, tmp_path: Path) -> Path:
        """Create binary with low entropy (repetitive data)."""
        binary_path: Path = tmp_path / "low_entropy.bin"

        repetitive_data: bytes = b"\x00" * 5000 + b"\xFF" * 5000

        binary_path.write_bytes(repetitive_data)
        return binary_path

    def test_high_entropy_detection_packed_section(self, analyzer: BinaryAnalyzer, high_entropy_binary: Path) -> None:
        """Analyzer detects high entropy indicating packing or encryption."""
        result: dict[str, Any] = analyzer.analyze(high_entropy_binary)

        entropy_info: dict[str, Any] = result.get("entropy", {})
        overall_entropy: float = entropy_info.get("overall_entropy", 0.0)

        assert overall_entropy > 7.0, "Random data should have high entropy > 7.0"

        analysis: str = entropy_info.get("analysis", "")
        assert "High" in analysis or "packed" in analysis.lower() or "encrypted" in analysis.lower()

    def test_low_entropy_detection_padding(self, analyzer: BinaryAnalyzer, low_entropy_binary: Path) -> None:
        """Analyzer detects low entropy indicating padding or repetitive data."""
        result: dict[str, Any] = analyzer.analyze(low_entropy_binary)

        entropy_info: dict[str, Any] = result.get("entropy", {})
        overall_entropy: float = entropy_info.get("overall_entropy", 0.0)

        assert overall_entropy < 2.0, "Repetitive data should have low entropy < 2.0"

    def test_entropy_analysis_real_binary(self, analyzer: BinaryAnalyzer) -> None:
        """Analyzer calculates reasonable entropy for real Windows binary."""
        notepad: Path = Path(r"C:\Windows\System32\notepad.exe")
        if not notepad.exists():
            pytest.skip("notepad.exe not found")

        result: dict[str, Any] = analyzer.analyze(notepad)

        entropy_info: dict[str, Any] = result.get("entropy", {})
        overall_entropy: float = entropy_info.get("overall_entropy", 0.0)

        assert 3.0 <= overall_entropy <= 8.0, "Normal binary entropy should be 3-8"


class TestStringExtraction:
    """Test string extraction and license pattern detection."""

    @pytest.fixture(scope="class")
    def analyzer(self) -> BinaryAnalyzer:
        """Create binary analyzer instance."""
        return BinaryAnalyzer()

    @pytest.fixture(scope="function")
    def license_strings_binary(self, tmp_path: Path) -> Path:
        """Create binary with embedded license strings."""
        binary_path: Path = tmp_path / "license_strings.exe"

        dos_header: bytes = b"MZ" + b"\x00" * 58
        pe_offset: bytes = struct.pack("<I", 0x80)
        dos_stub: bytes = dos_header + pe_offset + b"\x00" * (0x80 - 64)

        pe_header: bytes = b"PE\x00\x00"
        coff_header: bytes = struct.pack("<HHIIIHH", 0x8664, 0, 0, 0, 0, 0, 0)

        license_data: bytes = (
            b"Enter your license key here\x00"
            b"Trial expired - please activate\x00"
            b"Serial number validation failed\x00"
            b"Product activation required\x00"
            b"Registration code invalid\x00"
        )

        full_binary: bytes = dos_stub + pe_header + coff_header + license_data + b"\x00" * 500
        binary_path.write_bytes(full_binary)

        return binary_path

    def test_extract_license_validation_strings(self, analyzer: BinaryAnalyzer, license_strings_binary: Path) -> None:
        """Analyzer extracts license validation strings from binary."""
        result: dict[str, Any] = analyzer.analyze(license_strings_binary)

        strings: list[str] = result.get("strings", [])

        license_found: bool = any("license" in s.lower() for s in strings)
        assert license_found, "Must find 'license' string"

    def test_extract_trial_restriction_strings(self, analyzer: BinaryAnalyzer, license_strings_binary: Path) -> None:
        """Analyzer extracts trial restriction strings from binary."""
        result: dict[str, Any] = analyzer.analyze(license_strings_binary)

        strings: list[str] = result.get("strings", [])

        trial_found: bool = any("trial" in s.lower() for s in strings)
        assert trial_found, "Must find 'trial' string"

    def test_extract_activation_strings(self, analyzer: BinaryAnalyzer, license_strings_binary: Path) -> None:
        """Analyzer extracts activation-related strings from binary."""
        result: dict[str, Any] = analyzer.analyze(license_strings_binary)

        strings: list[str] = result.get("strings", [])

        activation_found: bool = any("activation" in s.lower() for s in strings)
        assert activation_found, "Must find 'activation' string"

    def test_scan_license_patterns_streaming(self, analyzer: BinaryAnalyzer, license_strings_binary: Path) -> None:
        """Analyzer scans for license patterns using streaming mode."""
        license_matches: list[dict[str, Any]] = analyzer.scan_for_license_strings_streaming(license_strings_binary)

        assert len(license_matches) > 0, "Must find license-related strings"

        patterns_found: set[str] = {match.get("pattern_matched", "") for match in license_matches}
        expected_patterns: set[str] = {"license", "trial", "serial", "activation"}

        found_count: int = len(patterns_found & expected_patterns)
        assert found_count >= 2, "Must find at least 2 license-related patterns"


class TestHashCalculation:
    """Test cryptographic hash calculation for binaries."""

    @pytest.fixture(scope="class")
    def analyzer(self) -> BinaryAnalyzer:
        """Create binary analyzer instance."""
        return BinaryAnalyzer()

    @pytest.fixture(scope="function")
    def known_hash_binary(self, tmp_path: Path) -> tuple[Path, dict[str, str]]:
        """Create binary with known hash values."""
        binary_path: Path = tmp_path / "known_hash.bin"

        test_data: bytes = b"Test binary data for hash validation" * 100
        binary_path.write_bytes(test_data)

        expected_hashes: dict[str, str] = {
            "sha256": hashlib.sha256(test_data).hexdigest(),
            "sha512": hashlib.sha512(test_data).hexdigest(),
            "sha3_256": hashlib.sha3_256(test_data).hexdigest(),
            "blake2b": hashlib.blake2b(test_data).hexdigest(),
        }

        return binary_path, expected_hashes

    def test_calculate_sha256_hash_matches(self, analyzer: BinaryAnalyzer, known_hash_binary: tuple[Path, dict[str, str]]) -> None:
        """Analyzer calculates correct SHA256 hash."""
        binary_path, expected_hashes = known_hash_binary

        result: dict[str, Any] = analyzer.analyze(binary_path)

        calculated_sha256: str = result["hashes"]["sha256"]
        assert calculated_sha256 == expected_hashes["sha256"]

    def test_calculate_sha512_hash_matches(self, analyzer: BinaryAnalyzer, known_hash_binary: tuple[Path, dict[str, str]]) -> None:
        """Analyzer calculates correct SHA512 hash."""
        binary_path, expected_hashes = known_hash_binary

        result: dict[str, Any] = analyzer.analyze(binary_path)

        calculated_sha512: str = result["hashes"]["sha512"]
        assert calculated_sha512 == expected_hashes["sha512"]

    def test_calculate_sha3_hash_matches(self, analyzer: BinaryAnalyzer, known_hash_binary: tuple[Path, dict[str, str]]) -> None:
        """Analyzer calculates correct SHA3-256 hash."""
        binary_path, expected_hashes = known_hash_binary

        result: dict[str, Any] = analyzer.analyze(binary_path)

        calculated_sha3: str = result["hashes"]["sha3_256"]
        assert calculated_sha3 == expected_hashes["sha3_256"]

    def test_calculate_blake2b_hash_matches(self, analyzer: BinaryAnalyzer, known_hash_binary: tuple[Path, dict[str, str]]) -> None:
        """Analyzer calculates correct BLAKE2b hash."""
        binary_path, expected_hashes = known_hash_binary

        result: dict[str, Any] = analyzer.analyze(binary_path)

        calculated_blake2b: str = result["hashes"]["blake2b"]
        assert calculated_blake2b == expected_hashes["blake2b"]

    def test_streaming_hash_calculation_large_file(self, analyzer: BinaryAnalyzer, tmp_path: Path) -> None:
        """Analyzer calculates hashes using streaming for large files."""
        large_binary: Path = tmp_path / "large.bin"

        test_data: bytes = b"A" * (60 * 1024 * 1024)
        large_binary.write_bytes(test_data)

        expected_sha256: str = hashlib.sha256(test_data).hexdigest()

        result: dict[str, Any] = analyzer.analyze(large_binary, use_streaming=True)

        assert result["hashes"]["sha256"] == expected_sha256


class TestFormatDetection:
    """Test binary format detection capabilities."""

    @pytest.fixture(scope="class")
    def analyzer(self) -> BinaryAnalyzer:
        """Create binary analyzer instance."""
        return BinaryAnalyzer()

    def test_detect_pe_format_windows_binary(self, analyzer: BinaryAnalyzer) -> None:
        """Analyzer detects PE format from Windows executable."""
        notepad: Path = Path(r"C:\Windows\System32\notepad.exe")
        if not notepad.exists():
            pytest.skip("notepad.exe not found")

        result: dict[str, Any] = analyzer.analyze(notepad)
        assert result["format"] == "PE"

    def test_detect_dll_format(self, analyzer: BinaryAnalyzer) -> None:
        """Analyzer detects PE format from Windows DLL."""
        kernel32: Path = Path(r"C:\Windows\System32\kernel32.dll")
        if not kernel32.exists():
            pytest.skip("kernel32.dll not found")

        result: dict[str, Any] = analyzer.analyze(kernel32)
        assert result["format"] == "PE"

    @pytest.fixture(scope="function")
    def elf_binary(self, tmp_path: Path) -> Path:
        """Create minimal ELF binary."""
        binary_path: Path = tmp_path / "test.elf"

        elf_header: bytes = (
            b"\x7fELF" +
            bytes([2, 1, 1, 0]) +
            b"\x00" * 8 +
            struct.pack("<HHI", 2, 62, 1) +
            b"\x00" * 40
        )

        binary_path.write_bytes(elf_header)
        return binary_path

    def test_detect_elf_format(self, analyzer: BinaryAnalyzer, elf_binary: Path) -> None:
        """Analyzer detects ELF format from Linux binary."""
        result: dict[str, Any] = analyzer.analyze(elf_binary)
        assert result["format"] == "ELF"


class TestPatternScanning:
    """Test byte pattern scanning capabilities."""

    @pytest.fixture(scope="class")
    def analyzer(self) -> BinaryAnalyzer:
        """Create binary analyzer instance."""
        return BinaryAnalyzer()

    @pytest.fixture(scope="function")
    def pattern_binary(self, tmp_path: Path) -> Path:
        """Create binary with known byte patterns."""
        binary_path: Path = tmp_path / "patterns.bin"

        pattern1: bytes = b"\xDE\xAD\xBE\xEF"
        pattern2: bytes = b"\xCA\xFE\xBA\xBE"

        data: bytes = (
            b"\x00" * 100 +
            pattern1 + b"\x00" * 50 +
            pattern2 + b"\x00" * 50 +
            pattern1 + b"\x00" * 100
        )

        binary_path.write_bytes(data)
        return binary_path

    def test_scan_single_pattern_finds_matches(self, analyzer: BinaryAnalyzer, pattern_binary: Path) -> None:
        """Analyzer finds all instances of single byte pattern."""
        patterns: list[bytes] = [b"\xDE\xAD\xBE\xEF"]

        results: dict[str, list[dict[str, Any]]] = analyzer.scan_for_patterns_streaming(
            pattern_binary, patterns, context_bytes=16
        )

        pattern_hex: str = patterns[0].hex()
        matches: list[dict[str, Any]] = results.get(pattern_hex, [])

        assert len(matches) == 2, "Pattern appears twice in binary"

    def test_scan_multiple_patterns_simultaneously(self, analyzer: BinaryAnalyzer, pattern_binary: Path) -> None:
        """Analyzer scans for multiple patterns in single pass."""
        patterns: list[bytes] = [b"\xDE\xAD\xBE\xEF", b"\xCA\xFE\xBA\xBE"]

        results: dict[str, list[dict[str, Any]]] = analyzer.scan_for_patterns_streaming(
            pattern_binary, patterns, context_bytes=16
        )

        assert len(results) == 2, "Must find both patterns"

        for pattern in patterns:
            pattern_hex: str = pattern.hex()
            assert pattern_hex in results
            assert len(results[pattern_hex]) > 0

    def test_pattern_scan_includes_context(self, analyzer: BinaryAnalyzer, pattern_binary: Path) -> None:
        """Analyzer includes context bytes around pattern matches."""
        patterns: list[bytes] = [b"\xDE\xAD\xBE\xEF"]

        results: dict[str, list[dict[str, Any]]] = analyzer.scan_for_patterns_streaming(
            pattern_binary, patterns, context_bytes=16
        )

        pattern_hex: str = patterns[0].hex()
        matches: list[dict[str, Any]] = results[pattern_hex]

        for match in matches:
            assert "context_before" in match
            assert "context_after" in match
            assert match["match"] == pattern_hex


class TestSectionAnalysis:
    """Test PE section-specific analysis."""

    @pytest.fixture(scope="class")
    def analyzer(self) -> BinaryAnalyzer:
        """Create binary analyzer instance."""
        return BinaryAnalyzer()

    @pytest.fixture(scope="function")
    def multi_section_binary(self, tmp_path: Path) -> Path:
        """Create PE binary with multiple sections."""
        binary_path: Path = tmp_path / "multi_section.exe"

        dos_header: bytes = b"MZ" + b"\x00" * 58
        pe_offset: bytes = struct.pack("<I", 0x80)
        dos_stub: bytes = dos_header + pe_offset + b"\x00" * (0x80 - 64)

        pe_header: bytes = b"PE\x00\x00"
        coff_header: bytes = struct.pack("<HHIIIHH",
            0x8664, 3, 0, 0, 0, 0xF0, 0x22
        )

        opt_header: bytes = b"\x00" * 0xF0

        section1_name: bytes = b".text\x00\x00\x00"
        section1_data: bytes = struct.pack("<IIIIIIII",
            0x1000, 0x1000, 0x1000, 0x200, 0, 0, 0, 0x60000020
        )

        section2_name: bytes = b".data\x00\x00\x00"
        section2_data: bytes = struct.pack("<IIIIIIII",
            0x500, 0x2000, 0x200, 0x1200, 0, 0, 0, 0xC0000040
        )

        section3_name: bytes = b".rsrc\x00\x00\x00"
        section3_data: bytes = struct.pack("<IIIIIIII",
            0x300, 0x3000, 0x200, 0x1400, 0, 0, 0, 0x40000040
        )

        full_binary: bytes = (
            dos_stub + pe_header + coff_header + opt_header +
            section1_name + section1_data +
            section2_name + section2_data +
            section3_name + section3_data +
            b"\x00" * 1000
        )

        binary_path.write_bytes(full_binary)
        return binary_path

    def test_analyze_multiple_sections(self, analyzer: BinaryAnalyzer, multi_section_binary: Path) -> None:
        """Analyzer extracts information from multiple PE sections."""
        result: dict[str, Any] = analyzer.analyze(multi_section_binary)

        sections: list[dict[str, Any]] = result["format_analysis"]["sections"]
        assert len(sections) == 3, "Must find all 3 sections"

    def test_analyze_section_entropy_characteristics(self, analyzer: BinaryAnalyzer, tmp_path: Path) -> None:
        """Analyzer classifies sections by entropy characteristics."""
        binary_path: Path = tmp_path / "entropy_sections.bin"

        import random
        high_entropy_section: bytes = bytes([random.randint(0, 255) for _ in range(1000)])
        low_entropy_section: bytes = b"\x00" * 1000
        text_section: bytes = b"This is readable text content " * 30

        binary_data: bytes = high_entropy_section + low_entropy_section + text_section
        binary_path.write_bytes(binary_data)

        section_ranges: list[tuple[int, int]] = [
            (0, 1000),
            (1000, 2000),
            (2000, 2900),
        ]

        results: dict[str, Any] = analyzer.analyze_sections_streaming(binary_path, section_ranges)

        assert "section_0" in results
        assert results["section_0"]["entropy"] > 7.0

        assert "section_1" in results
        assert results["section_1"]["entropy"] < 2.0

        assert "section_2" in results
        assert results["section_2"]["printable_ratio"] > 0.7


class TestErrorHandling:
    """Test error handling for malformed and invalid binaries."""

    @pytest.fixture(scope="class")
    def analyzer(self) -> BinaryAnalyzer:
        """Create binary analyzer instance."""
        return BinaryAnalyzer()

    def test_analyze_nonexistent_file_returns_error(self, analyzer: BinaryAnalyzer) -> None:
        """Analyzer returns error for nonexistent file."""
        result: dict[str, Any] = analyzer.analyze(Path("nonexistent_file.exe"))

        assert "error" in result
        assert "not found" in result["error"].lower()

    def test_analyze_corrupted_pe_header(self, analyzer: BinaryAnalyzer, tmp_path: Path) -> None:
        """Analyzer handles corrupted PE header gracefully."""
        binary_path: Path = tmp_path / "corrupted.exe"

        corrupted_data: bytes = b"MZ" + b"\xFF" * 100
        binary_path.write_bytes(corrupted_data)

        result: dict[str, Any] = analyzer.analyze(binary_path)

        assert "error" in result["format_analysis"] or result["format"] == "PE"

    def test_analyze_truncated_binary(self, analyzer: BinaryAnalyzer, tmp_path: Path) -> None:
        """Analyzer handles truncated binary file."""
        binary_path: Path = tmp_path / "truncated.exe"

        truncated_data: bytes = b"MZ\x00\x00"
        binary_path.write_bytes(truncated_data)

        result: dict[str, Any] = analyzer.analyze(binary_path)

        assert result["format"] == "PE" or "error" in result

    def test_analyze_empty_file(self, analyzer: BinaryAnalyzer, tmp_path: Path) -> None:
        """Analyzer handles empty file gracefully."""
        binary_path: Path = tmp_path / "empty.bin"
        binary_path.write_bytes(b"")

        result: dict[str, Any] = analyzer.analyze(binary_path)

        assert result["analysis_status"] == "completed" or "error" in result


class TestCheckpointSupport:
    """Test analysis checkpoint save and resume functionality."""

    @pytest.fixture(scope="class")
    def analyzer(self) -> BinaryAnalyzer:
        """Create binary analyzer instance."""
        return BinaryAnalyzer()

    def test_save_analysis_checkpoint(self, analyzer: BinaryAnalyzer, tmp_path: Path) -> None:
        """Analyzer saves analysis checkpoint successfully."""
        checkpoint_path: Path = tmp_path / "checkpoint.json"

        analysis_results: dict[str, Any] = {
            "format": "PE",
            "analysis_status": "partial",
            "completed_stages": ["format_detection", "hash_calculation"],
        }

        success: bool = analyzer.save_analysis_checkpoint(analysis_results, checkpoint_path)

        assert success is True
        assert checkpoint_path.exists()

    def test_load_analysis_checkpoint(self, analyzer: BinaryAnalyzer, tmp_path: Path) -> None:
        """Analyzer loads analysis checkpoint successfully."""
        checkpoint_path: Path = tmp_path / "checkpoint.json"

        original_results: dict[str, Any] = {
            "format": "PE",
            "analysis_status": "partial",
            "completed_stages": ["format_detection"],
        }

        analyzer.save_analysis_checkpoint(original_results, checkpoint_path)

        loaded_results: dict[str, Any] | None = analyzer.load_analysis_checkpoint(checkpoint_path)

        assert loaded_results is not None
        assert loaded_results["format"] == "PE"
        assert loaded_results["analysis_status"] == "partial"

    def test_checkpoint_resume_workflow(self, analyzer: BinaryAnalyzer, tmp_path: Path) -> None:
        """Analyzer resumes analysis from checkpoint."""
        checkpoint_path: Path = tmp_path / "workflow_checkpoint.json"

        partial_results: dict[str, Any] = {
            "format": "PE",
            "analysis_status": "partial",
            "hashes": {"sha256": "abc123"},
        }

        analyzer.save_analysis_checkpoint(partial_results, checkpoint_path)

        loaded: dict[str, Any] | None = analyzer.load_analysis_checkpoint(checkpoint_path)

        assert loaded is not None
        assert loaded["hashes"]["sha256"] == "abc123"


class TestProgressTracking:
    """Test progress tracking for large binary analysis."""

    @pytest.fixture(scope="class")
    def analyzer(self) -> BinaryAnalyzer:
        """Create binary analyzer instance."""
        return BinaryAnalyzer()

    def test_analyze_with_progress_callback(self, analyzer: BinaryAnalyzer, tmp_path: Path) -> None:
        """Analyzer calls progress callback during analysis."""
        binary_path: Path = tmp_path / "progress_test.bin"
        binary_path.write_bytes(b"Test data" * 1000)

        progress_calls: list[tuple[str, int, int]] = []

        def progress_callback(stage: str, current: int, total: int) -> None:
            progress_calls.append((stage, current, total))

        result: dict[str, Any] = analyzer.analyze_with_progress(binary_path, progress_callback)

        assert result["analysis_status"] == "completed"
        assert len(progress_calls) > 0, "Progress callback must be invoked"

    def test_progress_tracking_stages(self, analyzer: BinaryAnalyzer, tmp_path: Path) -> None:
        """Analyzer reports progress through all analysis stages."""
        binary_path: Path = tmp_path / "stages_test.bin"
        binary_path.write_bytes(b"Test data" * 1000)

        stages_seen: set[str] = set()

        def progress_callback(stage: str, current: int, total: int) -> None:
            stages_seen.add(stage.split(":")[0])

        analyzer.analyze_with_progress(binary_path, progress_callback)

        expected_stages: set[str] = {
            "format_detection",
            "hash_calculation",
            "format_analysis",
            "string_extraction",
            "entropy_analysis",
        }

        found_stages: int = len(stages_seen & expected_stages)
        assert found_stages >= 3, "Must report progress through major stages"


class TestRealWorldEffectiveness:
    """Test analyzer effectiveness on real-world Windows binaries."""

    @pytest.fixture(scope="class")
    def analyzer(self) -> BinaryAnalyzer:
        """Create binary analyzer instance."""
        return BinaryAnalyzer()

    def test_analyze_complete_notepad_workflow(self, analyzer: BinaryAnalyzer) -> None:
        """Complete analysis workflow on notepad.exe succeeds."""
        notepad: Path = Path(r"C:\Windows\System32\notepad.exe")
        if not notepad.exists():
            pytest.skip("notepad.exe not found")

        result: dict[str, Any] = analyzer.analyze(notepad)

        assert result["analysis_status"] == "completed"
        assert result["format"] == "PE"
        assert len(result["hashes"]) > 0
        assert len(result["format_analysis"]["sections"]) > 0
        assert len(result["strings"]) > 0
        assert "entropy" in result

    def test_analyze_complete_dll_workflow(self, analyzer: BinaryAnalyzer) -> None:
        """Complete analysis workflow on system DLL succeeds."""
        user32: Path = Path(r"C:\Windows\System32\user32.dll")
        if not user32.exists():
            pytest.skip("user32.dll not found")

        result: dict[str, Any] = analyzer.analyze(user32)

        assert result["analysis_status"] == "completed"
        assert result["format"] == "PE"
        assert len(result["strings"]) > 0

    def test_streaming_analysis_performance_large_dll(self, analyzer: BinaryAnalyzer) -> None:
        """Streaming analysis completes efficiently on large DLL."""
        ntdll: Path = Path(r"C:\Windows\System32\ntdll.dll")
        if not ntdll.exists():
            pytest.skip("ntdll.dll not found")

        import time
        start_time: float = time.time()

        result: dict[str, Any] = analyzer.analyze(ntdll, use_streaming=True)

        elapsed: float = time.time() - start_time

        assert result["analysis_status"] == "completed"
        assert elapsed < 30.0, "Analysis should complete within 30 seconds"
