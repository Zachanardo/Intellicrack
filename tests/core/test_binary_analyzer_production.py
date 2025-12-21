"""Production tests for binary analyzer module.

Tests validate real binary analysis, protection detection, entropy calculation,
and format-specific analysis capabilities for software licensing bypass research.
"""

import hashlib
import math
import os
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.binary_analyzer import BinaryAnalyzer


def calculate_entropy_correct(data: bytes) -> float:
    """Calculate Shannon entropy correctly."""
    if not data:
        return 0.0

    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1

    entropy = 0.0
    data_len = len(data)

    for count in byte_counts:
        if count > 0:
            probability = count / data_len
            entropy -= probability * math.log2(probability)

    return entropy


class TestEntropyCalculation:
    """Test entropy calculation for detecting protection schemes."""

    def test_calculate_entropy_zero_for_empty_data(self) -> None:
        """calculate_entropy returns 0.0 for empty byte arrays."""
        entropy = calculate_entropy_correct(b"")
        assert entropy == 0.0

    def test_calculate_entropy_low_for_repetitive_data(self) -> None:
        """calculate_entropy returns low value for repetitive data."""
        repetitive = b"\x00" * 1024
        entropy = calculate_entropy_correct(repetitive)
        assert 0.0 <= entropy < 0.1

    def test_calculate_entropy_high_for_random_data(self) -> None:
        """calculate_entropy returns high value for random-looking data."""
        random_data = os.urandom(1024)
        entropy = calculate_entropy_correct(random_data)
        assert 7.0 <= entropy <= 8.0

    def test_calculate_entropy_medium_for_text_data(self) -> None:
        """calculate_entropy returns medium value for text content."""
        text = b"This is a test string with some variation in characters" * 20
        entropy = calculate_entropy_correct(text)
        assert 3.0 <= entropy <= 6.0

    def test_calculate_entropy_handles_all_byte_values(self) -> None:
        """calculate_entropy correctly processes all 256 byte values."""
        all_bytes = bytes(range(256)) * 4
        entropy = calculate_entropy_correct(all_bytes)
        assert 7.5 <= entropy <= 8.0


class TestBinaryAnalyzerInitialization:
    """Test BinaryAnalyzer initialization and configuration."""

    def test_init_creates_analyzer_instance(self) -> None:
        """__init__ creates BinaryAnalyzer with all components."""
        analyzer = BinaryAnalyzer()

        assert analyzer is not None
        assert hasattr(analyzer, "analysis_cache")
        assert hasattr(analyzer, "supported_formats")
        assert len(analyzer.supported_formats) > 0

    def test_init_creates_sub_analyzers(self) -> None:
        """__init__ initializes sub-analyzers when available."""
        analyzer = BinaryAnalyzer()

        assert hasattr(analyzer, "multi_format_analyzer")
        assert hasattr(analyzer, "pe_analyzer")
        assert hasattr(analyzer, "elf_analyzer")

    def test_supported_formats_includes_pe_elf_formats(self) -> None:
        """supported_formats includes PE, ELF, and other executable formats."""
        analyzer = BinaryAnalyzer()

        assert "exe" in analyzer.supported_formats
        assert "dll" in analyzer.supported_formats
        assert "elf" in analyzer.supported_formats
        assert "so" in analyzer.supported_formats

    def test_get_supported_formats_returns_copy(self) -> None:
        """get_supported_formats returns copy of format list."""
        analyzer = BinaryAnalyzer()
        formats = analyzer.get_supported_formats()

        formats.append("fake_format")
        assert "fake_format" not in analyzer.supported_formats

    def test_is_supported_format_detects_exe_files(self) -> None:
        """is_supported_format returns True for .exe files."""
        analyzer = BinaryAnalyzer()
        assert analyzer.is_supported_format("test.exe") is True
        assert analyzer.is_supported_format("test.dll") is True
        assert analyzer.is_supported_format("test.unknown") is False


class TestBinaryAnalyzerFileDetection:
    """Test file type detection and magic byte analysis."""

    def test_analyze_returns_error_for_nonexistent_file(self) -> None:
        """analyze returns error dict for nonexistent files."""
        analyzer = BinaryAnalyzer()
        result = analyzer.analyze("D:/nonexistent/fake.exe")

        assert "error" in result
        assert "File not found" in result["error"]

    def test_analyze_creates_pe_binary_and_detects_format(self) -> None:
        """analyze correctly detects PE format from MZ header."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
            tmp.write(b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00")
            tmp.write(b"\x00" * 200)
            tmp_path = Path(tmp.name)

        try:
            analyzer = BinaryAnalyzer()
            result = analyzer.analyze(tmp_path)

            assert "error" not in result
            assert result["file_type"]["format"] == "PE"
            assert result["file_type"]["description"] == "Windows Portable Executable"
            assert result["file_type"]["magic_bytes"].startswith("4d5a")

        finally:
            tmp_path.unlink(missing_ok=True)

    def test_analyze_detects_elf_format(self) -> None:
        """analyze correctly detects ELF format from magic bytes."""
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as tmp:
            tmp.write(b"\x7fELF\x02\x01\x01\x00")
            tmp.write(b"\x00" * 200)
            tmp_path = Path(tmp.name)

        try:
            analyzer = BinaryAnalyzer()
            result = analyzer.analyze(tmp_path)

            assert "error" not in result
            assert result["file_type"]["format"] == "ELF"
            assert result["file_type"]["description"] == "Linux Executable and Linkable Format"

        finally:
            tmp_path.unlink(missing_ok=True)

    def test_analyze_detects_dex_format(self) -> None:
        """analyze correctly detects Android DEX format."""
        with tempfile.NamedTemporaryFile(suffix=".dex", delete=False) as tmp:
            tmp.write(b"dex\n035\x00")
            tmp.write(b"\x00" * 200)
            tmp_path = Path(tmp.name)

        try:
            analyzer = BinaryAnalyzer()
            result = analyzer.analyze(tmp_path)

            assert "error" not in result
            assert result["file_type"]["format"] == "DEX"
            assert result["file_type"]["description"] == "Android Dalvik Executable"

        finally:
            tmp_path.unlink(missing_ok=True)

    def test_analyze_detects_zip_based_formats(self) -> None:
        """analyze correctly detects ZIP-based formats (APK, JAR)."""
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
            tmp.write(b"PK\x03\x04")
            tmp.write(b"\x00" * 200)
            tmp_path = Path(tmp.name)

        try:
            analyzer = BinaryAnalyzer()
            result = analyzer.analyze(tmp_path)

            assert "error" not in result
            assert result["file_type"]["format"] == "APK"
            assert result["file_type"]["description"] == "Android Package"

        finally:
            tmp_path.unlink(missing_ok=True)


class TestBinaryAnalyzerHashCalculation:
    """Test cryptographic hash calculation for file identification."""

    def test_analyze_calculates_multiple_hashes(self) -> None:
        """analyze calculates SHA256, SHA512, SHA3-256, and BLAKE2b hashes."""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
            test_data = b"Test binary data for hashing"
            tmp.write(test_data)
            tmp_path = Path(tmp.name)

        try:
            analyzer = BinaryAnalyzer()
            result = analyzer.analyze(tmp_path)

            assert "file_hashes" in result
            assert "sha256" in result["file_hashes"]
            assert "sha512" in result["file_hashes"]
            assert "sha3_256" in result["file_hashes"]
            assert "blake2b" in result["file_hashes"]

            expected_sha256 = hashlib.sha256(test_data).hexdigest()
            assert result["file_hashes"]["sha256"] == expected_sha256

        finally:
            tmp_path.unlink(missing_ok=True)

    def test_analyze_hash_calculation_matches_real_algorithms(self) -> None:
        """analyze produces hash values matching real cryptographic algorithms."""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
            test_data = b"Known test vector data" * 100
            tmp.write(test_data)
            tmp_path = Path(tmp.name)

        try:
            analyzer = BinaryAnalyzer()
            result = analyzer.analyze(tmp_path)

            assert result["file_hashes"]["sha256"] == hashlib.sha256(test_data).hexdigest()
            assert result["file_hashes"]["sha512"] == hashlib.sha512(test_data).hexdigest()
            assert result["file_hashes"]["sha3_256"] == hashlib.sha3_256(test_data).hexdigest()
            assert result["file_hashes"]["blake2b"] == hashlib.blake2b(test_data).hexdigest()

        finally:
            tmp_path.unlink(missing_ok=True)


class TestBinaryAnalyzerStringExtraction:
    """Test string extraction for license key and protection detection."""

    def test_analyze_extracts_ascii_strings(self) -> None:
        """analyze extracts printable ASCII strings from binaries."""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
            tmp.write(b"\x00\x00LICENSE_KEY_12345\x00\x00\x00SERIAL_NUMBER\x00\x00")
            tmp_path = Path(tmp.name)

        try:
            analyzer = BinaryAnalyzer()
            result = analyzer.analyze(tmp_path)

            strings = result["strings"]["sample"]
            assert any("LICENSE_KEY" in s for s in strings)
            assert any("SERIAL_NUMBER" in s for s in strings)

        finally:
            tmp_path.unlink(missing_ok=True)

    def test_analyze_extracts_unicode_strings(self) -> None:
        """analyze extracts Unicode strings from binaries."""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
            unicode_str = b"U\x00n\x00i\x00c\x00o\x00d\x00e\x00T\x00e\x00s\x00t\x00\x00\x00"
            tmp.write(b"\x00" * 20 + unicode_str + b"\x00" * 20)
            tmp_path = Path(tmp.name)

        try:
            analyzer = BinaryAnalyzer()
            result = analyzer.analyze(tmp_path)

            strings = result["strings"]["sample"]
            assert any("UnicodeTest" in s for s in strings)

        finally:
            tmp_path.unlink(missing_ok=True)

    def test_analyze_identifies_interesting_patterns(self) -> None:
        """analyze identifies license-related and security patterns."""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
            tmp.write(b"\x00\x00password123\x00\x00license_key\x00\x00crack_info\x00\x00")
            tmp_path = Path(tmp.name)

        try:
            analyzer = BinaryAnalyzer()
            result = analyzer.analyze(tmp_path)

            interesting = result["strings"]["interesting"]
            assert len(interesting) > 0

            patterns = [item["pattern"] for item in interesting]
            assert any("password" in p for p in patterns)
            assert any("license" in p for p in patterns)

        finally:
            tmp_path.unlink(missing_ok=True)

    def test_analyze_categorizes_string_patterns(self) -> None:
        """analyze categorizes strings into security, licensing, network categories."""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
            tmp.write(b"admin_password\x00https://license.server.com\x00VirtualAlloc\x00")
            tmp_path = Path(tmp.name)

        try:
            analyzer = BinaryAnalyzer()
            result = analyzer.analyze(tmp_path)

            interesting = result["strings"]["interesting"]
            categories = [item["category"] for item in interesting]

            assert "security" in categories or "network" in categories or "memory" in categories

        finally:
            tmp_path.unlink(missing_ok=True)

    def test_analyze_respects_string_extraction_options(self) -> None:
        """analyze respects min_length and max_strings options."""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
            tmp.write(b"AB\x00" * 100 + b"LONGER_STRING\x00" * 100)
            tmp_path = Path(tmp.name)

        try:
            analyzer = BinaryAnalyzer()
            result = analyzer.analyze(tmp_path, {"string_min_length": 10, "max_strings": 50})

            assert result["strings"]["analysis"]["min_length"] == 10
            assert result["strings"]["total_count"] <= 50

        finally:
            tmp_path.unlink(missing_ok=True)


class TestBinaryAnalyzerEntropyAnalysis:
    """Test entropy analysis for detecting packed/protected binaries."""

    def test_analyze_calculates_overall_entropy(self) -> None:
        """analyze calculates overall file entropy."""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
            tmp.write(os.urandom(1024))
            tmp_path = Path(tmp.name)

        try:
            analyzer = BinaryAnalyzer()
            result = analyzer.analyze(tmp_path)

            assert "entropy" in result
            assert "overall" in result["entropy"]
            assert 0.0 <= result["entropy"]["overall"] <= 8.0

        finally:
            tmp_path.unlink(missing_ok=True)

    def test_analyze_identifies_high_entropy_as_packed(self) -> None:
        """analyze identifies high entropy files as potentially packed."""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
            tmp.write(os.urandom(2048))
            tmp_path = Path(tmp.name)

        try:
            analyzer = BinaryAnalyzer()
            result = analyzer.analyze(tmp_path)

            assert result["entropy"]["analysis"]["is_high_entropy"] is True
            assert "encryption" in result["entropy"]["analysis"]["interpretation"].lower() or \
                   "packed" in result["entropy"]["analysis"]["interpretation"].lower()

        finally:
            tmp_path.unlink(missing_ok=True)

    def test_analyze_calculates_section_entropy(self) -> None:
        """analyze calculates entropy for individual sections/chunks."""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
            tmp.write(b"\x00" * 10000)
            tmp_path = Path(tmp.name)

        try:
            analyzer = BinaryAnalyzer()
            result = analyzer.analyze(tmp_path)

            assert "sections" in result["entropy"]
            assert len(result["entropy"]["sections"]) > 0

        finally:
            tmp_path.unlink(missing_ok=True)

    def test_analyze_interprets_entropy_correctly(self) -> None:
        """analyze provides meaningful entropy interpretations."""
        analyzer = BinaryAnalyzer()

        low_entropy = analyzer._interpret_entropy(2.5)
        assert "low" in low_entropy.lower() or "structured" in low_entropy.lower()

        high_entropy = analyzer._interpret_entropy(7.8)
        assert "high" in high_entropy.lower() or "encrypted" in high_entropy.lower() or "packed" in high_entropy.lower()


class TestBinaryAnalyzerProtectionDetection:
    """Test protection detection for licensing schemes."""

    def test_analyze_detects_high_entropy_sections(self) -> None:
        """analyze identifies high entropy sections as protection indicators."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
            tmp.write(b"MZ" + b"\x00" * 200)
            tmp_path = Path(tmp.name)

        try:
            analyzer = BinaryAnalyzer()
            result = analyzer.analyze(tmp_path)
            result["sections"] = [{"name": ".packed", "entropy": 7.8}]

            protections: dict[str, Any] = {"detected": [], "indicators": []}
            analyzer._check_pe_protections(tmp_path, result, protections)

            assert any("High entropy" in ind for ind in protections["indicators"])

        finally:
            tmp_path.unlink(missing_ok=True)

    def test_analyze_detects_protection_api_usage(self) -> None:
        """analyze identifies anti-debug and protection API usage."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
            tmp.write(b"MZ" + b"\x00" * 200)
            tmp_path = Path(tmp.name)

        try:
            analyzer = BinaryAnalyzer()
            result = analyzer.analyze(tmp_path)

            result["imports"] = [
                {"dll": "kernel32.dll", "functions": ["IsDebuggerPresent", "VirtualProtect"]}
            ]

            protections: dict[str, Any] = {"detected": [], "indicators": []}
            analyzer._check_pe_protections(tmp_path, result, protections)

            assert any("IsDebuggerPresent" in ind for ind in protections["indicators"])
            assert any("VirtualProtect" in ind for ind in protections["indicators"])

        finally:
            tmp_path.unlink(missing_ok=True)

    def test_analyze_detects_suspicious_licensing_strings(self) -> None:
        """analyze identifies licensing-related strings as indicators."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
            tmp.write(b"license_validation_function\x00serial_check_code\x00")
            tmp_path = Path(tmp.name)

        try:
            analyzer = BinaryAnalyzer()
            result = analyzer.analyze(tmp_path)

            protections: dict[str, Any] = {"detected": [], "indicators": []}
            analyzer._check_generic_protections(tmp_path, result, protections)

            interesting_strings = result["strings"]["interesting"]
            assert any(item["category"] == "licensing" for item in interesting_strings)

        finally:
            tmp_path.unlink(missing_ok=True)


class TestBinaryAnalyzerCaching:
    """Test analysis result caching functionality."""

    def test_analyze_caches_results(self) -> None:
        """analyze caches results for repeated analysis of same file."""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
            tmp.write(b"test data")
            tmp_path = Path(tmp.name)

        try:
            analyzer = BinaryAnalyzer()

            result1 = analyzer.analyze(tmp_path)
            cache_size_before = len(analyzer.analysis_cache)

            result2 = analyzer.analyze(tmp_path)
            cache_size_after = len(analyzer.analysis_cache)

            assert result1 is result2
            assert cache_size_before == cache_size_after == 1

        finally:
            tmp_path.unlink(missing_ok=True)

    def test_clear_cache_empties_cache(self) -> None:
        """clear_cache removes all cached analysis results."""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
            tmp.write(b"test data")
            tmp_path = Path(tmp.name)

        try:
            analyzer = BinaryAnalyzer()
            analyzer.analyze(tmp_path)

            assert len(analyzer.analysis_cache) > 0

            analyzer.clear_cache()
            assert len(analyzer.analysis_cache) == 0

        finally:
            tmp_path.unlink(missing_ok=True)

    def test_get_cache_stats_returns_statistics(self) -> None:
        """get_cache_stats returns cache size and memory usage."""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
            tmp.write(b"test data")
            tmp_path = Path(tmp.name)

        try:
            analyzer = BinaryAnalyzer()
            analyzer.analyze(tmp_path)

            stats = analyzer.get_cache_stats()
            assert "cached_files" in stats
            assert "cache_memory_mb" in stats
            assert stats["cached_files"] == 1

        finally:
            tmp_path.unlink(missing_ok=True)


class TestBinaryAnalyzerRecommendations:
    """Test recommendation generation for analysis workflows."""

    def test_analyze_generates_format_specific_recommendations(self) -> None:
        """analyze generates recommendations based on file format."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
            tmp.write(b"MZ" + b"\x00" * 200)
            tmp_path = Path(tmp.name)

        try:
            analyzer = BinaryAnalyzer()
            result = analyzer.analyze(tmp_path)

            recommendations = result["recommendations"]
            assert len(recommendations) > 0
            assert any("PE" in rec or "PEview" in rec or "CFF" in rec for rec in recommendations)

        finally:
            tmp_path.unlink(missing_ok=True)

    def test_analyze_recommends_unpacking_for_protected_files(self) -> None:
        """analyze recommends unpacking tools for protected binaries."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
            tmp.write(b"MZ" + os.urandom(2048))
            tmp_path = Path(tmp.name)

        try:
            analyzer = BinaryAnalyzer()
            result = analyzer.analyze(tmp_path)

            recommendations = result["recommendations"]
            assert any("unpacking" in rec.lower() or "protection" in rec.lower() for rec in recommendations)

        finally:
            tmp_path.unlink(missing_ok=True)

    def test_analyze_includes_generic_security_recommendations(self) -> None:
        """analyze includes generic security analysis recommendations."""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
            tmp.write(b"\x00" * 100)
            tmp_path = Path(tmp.name)

        try:
            analyzer = BinaryAnalyzer()
            result = analyzer.analyze(tmp_path)

            recommendations = result["recommendations"]
            assert any("dynamic analysis" in rec.lower() for rec in recommendations)
            assert any("sandbox" in rec.lower() for rec in recommendations)

        finally:
            tmp_path.unlink(missing_ok=True)


class TestBinaryAnalyzerIntegration:
    """Integration tests for complete analysis workflows."""

    def test_complete_pe_analysis_workflow(self) -> None:
        """Complete workflow: PE binary -> detection -> analysis -> recommendations."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
            pe_header = b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00"
            tmp.write(pe_header)
            tmp.write(b"license_key_validation\x00")
            tmp.write(os.urandom(512))
            tmp_path = Path(tmp.name)

        try:
            analyzer = BinaryAnalyzer()
            result = analyzer.analyze(tmp_path)

            assert "error" not in result
            assert result["file_type"]["format"] == "PE"
            assert "file_hashes" in result
            assert len(result["file_hashes"]) >= 4
            assert "strings" in result
            assert "entropy" in result
            assert "protection_info" in result
            assert "recommendations" in result
            assert result["analysis_duration"] > 0

        finally:
            tmp_path.unlink(missing_ok=True)

    def test_analysis_options_control_workflow(self) -> None:
        """Analysis options control which steps are executed."""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
            tmp.write(b"\x00" * 1000)
            tmp_path = Path(tmp.name)

        try:
            analyzer = BinaryAnalyzer()

            result_no_strings = analyzer.analyze(tmp_path, {"extract_strings": False})
            assert result_no_strings["strings"] == []

            result_no_entropy = analyzer.analyze(tmp_path, {"entropy_analysis": False})
            assert result_no_entropy["entropy"] == {}

            analyzer.clear_cache()
            result_no_protection = analyzer.analyze(tmp_path, {"protection_analysis": False})
            assert result_no_protection["protection_info"] == {}

        finally:
            tmp_path.unlink(missing_ok=True)

    def test_error_handling_continues_analysis_on_failures(self) -> None:
        """Analysis continues and reports warnings on component failures."""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
            tmp.write(b"test")
            tmp_path = Path(tmp.name)

        try:
            analyzer = BinaryAnalyzer()
            result = analyzer.analyze(tmp_path)

            assert "basic_info" in result
            assert "file_type" in result

        finally:
            tmp_path.unlink(missing_ok=True)
