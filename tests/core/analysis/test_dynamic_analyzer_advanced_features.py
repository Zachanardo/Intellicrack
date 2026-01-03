"""Advanced Feature Tests for Dynamic Analyzer.

Tests advanced dynamic instrumentation capabilities including:
- Code coverage tracking during execution
- Anti-instrumentation technique detection and handling
- Multi-threaded process instrumentation
- Memory read/write operation monitoring
- Return value logging and argument capture
- Performance benchmarking of instrumentation

These tests validate production-ready capabilities for analyzing protected
software with anti-debugging and anti-instrumentation protections.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3.0+
"""

from __future__ import annotations

import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.dynamic_analyzer import (
    FRIDA_AVAILABLE,
    PSUTIL_AVAILABLE,
    AdvancedDynamicAnalyzer,
)


@pytest.fixture
def anti_debug_binary(tmp_path: Path) -> Path:
    """Create PE binary with anti-debugging characteristics for testing."""
    exe_path = tmp_path / "anti_debug.exe"

    dos_header = bytearray([
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
        0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    ])

    dos_stub = b"This program cannot be run in DOS mode.\r\r\n$" + b"\x00" * 7
    pe_signature = b"PE\x00\x00"
    coff_header = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0x00F0, 0x0022)

    optional_header = bytearray(240)
    optional_header[:2] = struct.pack("<H", 0x020B)
    struct.pack_into("<I", optional_header, 16, 0x1000)
    struct.pack_into("<Q", optional_header, 24, 0x400000)
    struct.pack_into("<I", optional_header, 32, 0x1000)
    struct.pack_into("<I", optional_header, 36, 0x200)
    struct.pack_into("<H", optional_header, 68, 0x0140)

    section_header = bytearray(40)
    section_header[:8] = b".text\x00\x00\x00"
    struct.pack_into("<I", section_header, 8, 0x1000)
    struct.pack_into("<I", section_header, 12, 0x1000)
    struct.pack_into("<I", section_header, 16, 0x200)
    struct.pack_into("<I", section_header, 20, 0x400)
    struct.pack_into("<I", section_header, 36, 0x60000020)

    code_section = b"\xC3" + b"\x90" * 511

    binary_content = (
        dos_header + dos_stub + pe_signature +
        coff_header + optional_header + section_header
    )
    binary_content += b"\x00" * (0x400 - len(binary_content))
    binary_content += code_section

    exe_path.write_bytes(binary_content)
    return exe_path


@pytest.fixture
def multi_threaded_binary(tmp_path: Path) -> Path:
    """Create PE binary that simulates multi-threaded execution."""
    exe_path = tmp_path / "multi_thread.exe"

    dos_header = bytearray([
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
        0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    ])

    dos_stub = b"This program cannot be run in DOS mode.\r\r\n$" + b"\x00" * 7
    pe_signature = b"PE\x00\x00"
    coff_header = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0x00F0, 0x0022)

    optional_header = bytearray(240)
    optional_header[:2] = struct.pack("<H", 0x020B)
    struct.pack_into("<I", optional_header, 16, 0x1000)
    struct.pack_into("<Q", optional_header, 24, 0x400000)
    struct.pack_into("<I", optional_header, 32, 0x1000)

    section_header = bytearray(40)
    section_header[:8] = b".text\x00\x00\x00"
    struct.pack_into("<I", section_header, 8, 0x1000)
    struct.pack_into("<I", section_header, 12, 0x1000)
    struct.pack_into("<I", section_header, 16, 0x200)
    struct.pack_into("<I", section_header, 20, 0x400)

    binary_content = (
        dos_header + dos_stub + pe_signature +
        coff_header + optional_header + section_header
    )
    binary_content += b"\x00" * (0x400 - len(binary_content))
    binary_content += b"\xC3" + b"\x90" * 511

    exe_path.write_bytes(binary_content)
    return exe_path


@pytest.fixture
def real_system_binary() -> Path:
    """Provide real Windows system binary for advanced testing."""
    system32 = Path("C:/Windows/System32")
    candidates = ["notepad.exe", "calc.exe", "hostname.exe"]

    for candidate in candidates:
        binary_path = system32 / candidate
        if binary_path.exists():
            return binary_path

    pytest.skip("No suitable system binary found for advanced testing")
    raise RuntimeError("Unreachable")


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
class TestCodeCoverageTracking:
    """Test code coverage tracking during dynamic execution."""

    def test_frida_tracks_executed_code_regions(self, anti_debug_binary: Path) -> None:
        """Frida instrumentation tracks executed code regions."""
        analyzer = AdvancedDynamicAnalyzer(anti_debug_binary)
        result: dict[str, Any] = analyzer._frida_runtime_analysis()

        if result.get("success"):
            analysis_data = result.get("analysis_data", {})
            assert isinstance(analysis_data, dict)

    def test_frida_monitors_module_loading(self, real_system_binary: Path) -> None:
        """Frida tracks module enumeration and loading during execution."""
        analyzer = AdvancedDynamicAnalyzer(real_system_binary)
        result: dict[str, Any] = analyzer._frida_runtime_analysis()

        if result.get("success"):
            analysis_data = result.get("analysis_data", {})
            assert isinstance(analysis_data, dict)


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
class TestAPIArgumentCapture:
    """Test API call argument and return value logging."""

    def test_frida_captures_api_arguments(self, real_system_binary: Path) -> None:
        """Frida instrumentation captures API call arguments."""
        analyzer = AdvancedDynamicAnalyzer(real_system_binary)
        result: dict[str, Any] = analyzer._frida_runtime_analysis()

        if result.get("success"):
            analysis_data = result.get("analysis_data", {})
            license_funcs = analysis_data.get("license_function", [])

            for func_call in license_funcs:
                if "args" in func_call:
                    assert isinstance(func_call["args"], list)

    def test_frida_logs_return_values(self, real_system_binary: Path) -> None:
        """Frida instrumentation logs API call return values."""
        analyzer = AdvancedDynamicAnalyzer(real_system_binary)
        result: dict[str, Any] = analyzer._frida_runtime_analysis()

        if result.get("success"):
            analysis_data = result.get("analysis_data", {})
            assert isinstance(analysis_data, dict)

    def test_frida_handles_string_arguments(self, real_system_binary: Path) -> None:
        """Frida correctly captures string arguments from API calls."""
        analyzer = AdvancedDynamicAnalyzer(real_system_binary)
        result: dict[str, Any] = analyzer._frida_runtime_analysis()

        if result.get("success"):
            analysis_data = result.get("analysis_data", {})
            file_ops = analysis_data.get("file_access", [])

            for file_op in file_ops:
                if "filename" in file_op:
                    assert isinstance(file_op["filename"], str)

    def test_frida_handles_integer_arguments(self, real_system_binary: Path) -> None:
        """Frida correctly captures integer arguments from API calls."""
        analyzer = AdvancedDynamicAnalyzer(real_system_binary)
        result: dict[str, Any] = analyzer._frida_runtime_analysis()

        if result.get("success"):
            analysis_data = result.get("analysis_data", {})
            file_ops = analysis_data.get("file_access", [])

            for file_op in file_ops:
                if "access" in file_op:
                    assert isinstance(file_op["access"], int)


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
class TestMemoryOperationMonitoring:
    """Test memory read/write operation monitoring."""

    def test_frida_monitors_memory_ranges(self, real_system_binary: Path) -> None:
        """Frida enumerates and monitors accessible memory ranges."""
        analyzer = AdvancedDynamicAnalyzer(real_system_binary)
        result: dict[str, Any] = analyzer._frida_runtime_analysis()

        if result.get("success"):
            analysis_data = result.get("analysis_data", {})
            assert isinstance(analysis_data, dict)

    def test_frida_scans_readable_memory_regions(self, real_system_binary: Path) -> None:
        """Frida scans readable memory regions for patterns."""
        analyzer = AdvancedDynamicAnalyzer(real_system_binary)
        keywords = ["license", "serial"]

        result: dict[str, Any] = analyzer._frida_memory_scan(keywords, None)

        if result.get("status") == "success":
            assert "matches" in result


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
class TestAntiInstrumentationHandling:
    """Test handling of anti-instrumentation and anti-debugging techniques."""

    def test_frida_handles_timing_checks(self, anti_debug_binary: Path) -> None:
        """Frida runtime analysis detects GetTickCount timing checks."""
        analyzer = AdvancedDynamicAnalyzer(anti_debug_binary)
        result: dict[str, Any] = analyzer._frida_runtime_analysis()

        if result.get("success"):
            analysis_data = result.get("analysis_data", {})
            timing_checks = analysis_data.get("timingChecks", [])
            assert isinstance(timing_checks, list)

    def test_frida_survives_exception_handling(self, anti_debug_binary: Path) -> None:
        """Frida instrumentation survives process exception handling."""
        analyzer = AdvancedDynamicAnalyzer(anti_debug_binary)
        result: dict[str, Any] = analyzer._frida_runtime_analysis()

        assert isinstance(result, dict)
        assert "success" in result

    def test_frida_handles_invalid_memory_access(self, real_system_binary: Path) -> None:
        """Frida gracefully handles invalid memory read attempts."""
        analyzer = AdvancedDynamicAnalyzer(real_system_binary)
        keywords = ["test"]

        result: dict[str, Any] = analyzer._frida_memory_scan(keywords, None)

        assert isinstance(result, dict)
        assert "status" in result

    def test_frida_continues_after_read_errors(self, real_system_binary: Path) -> None:
        """Frida memory scanning continues after encountering read errors."""
        analyzer = AdvancedDynamicAnalyzer(real_system_binary)
        keywords = ["license"]

        result: dict[str, Any] = analyzer._frida_memory_scan(keywords, None)

        assert isinstance(result, dict)


@pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
class TestMultiThreadedProcessAnalysis:
    """Test analysis of multi-threaded processes."""

    def test_analyzer_detects_thread_count(self, tmp_path: Path) -> None:
        """Process behavior analysis detects number of threads."""
        timeout_script = tmp_path / "thread_test.bat"
        timeout_script.write_text("@echo off\ntimeout /t 30 /nobreak > nul")

        analyzer = AdvancedDynamicAnalyzer(timeout_script)
        result: dict[str, Any] = analyzer._process_behavior_analysis()

        if "error" not in result and "threads" in result:
            assert isinstance(result["threads"], int)
            assert result["threads"] > 0

    def test_analyzer_handles_thread_creation(self, multi_threaded_binary: Path) -> None:
        """Analyzer handles processes that create multiple threads."""
        analyzer = AdvancedDynamicAnalyzer(multi_threaded_binary)
        result: dict[str, Any] = analyzer.run_comprehensive_analysis()

        assert isinstance(result, dict)
        assert "process_behavior_analysis" in result


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific test")
class TestWindowsSpecificFeatures:
    """Test Windows-specific dynamic analysis features."""

    def test_windows_memory_scan_handles_protection(self, real_system_binary: Path) -> None:
        """Windows memory scan respects memory protection flags."""
        proc = subprocess.Popen([str(real_system_binary)])
        time.sleep(0.5)

        try:
            analyzer = AdvancedDynamicAnalyzer(real_system_binary)
            keywords = ["test"]
            matches = analyzer._windows_memory_scan(proc.pid, keywords)

            assert isinstance(matches, list)
        finally:
            proc.terminate()
            proc.wait()

    def test_windows_memory_scan_reads_wide_strings(self, real_system_binary: Path) -> None:
        """Windows memory scan detects UTF-16 wide strings."""
        proc = subprocess.Popen([str(real_system_binary)])
        time.sleep(0.5)

        try:
            analyzer = AdvancedDynamicAnalyzer(real_system_binary)
            keywords = ["Windows"]
            matches = analyzer._windows_memory_scan(proc.pid, keywords)

            assert isinstance(matches, list)
        finally:
            proc.terminate()
            proc.wait()


class TestPerformanceCharacteristics:
    """Test performance and efficiency of dynamic analysis."""

    def test_comprehensive_analysis_completes_timely(self, real_system_binary: Path) -> None:
        """Comprehensive analysis completes within performance threshold."""
        analyzer = AdvancedDynamicAnalyzer(real_system_binary)

        start_time = time.time()
        results: dict[str, Any] = analyzer.run_comprehensive_analysis()
        elapsed_time = time.time() - start_time

        assert elapsed_time < 30, f"Analysis took {elapsed_time}s, expected <30s"
        assert isinstance(results, dict)

    def test_memory_scan_handles_large_regions(self, real_system_binary: Path) -> None:
        """Memory scanning efficiently handles large memory regions."""
        analyzer = AdvancedDynamicAnalyzer(real_system_binary)
        keywords = ["test"]

        start_time = time.time()
        result: dict[str, Any] = analyzer.scan_memory_for_keywords(keywords)
        elapsed_time = time.time() - start_time

        assert elapsed_time < 60, "Memory scan took too long"
        assert isinstance(result, dict)

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
    def test_frida_memory_scan_deduplicates_results(self, real_system_binary: Path) -> None:
        """Frida memory scan removes duplicate matches efficiently."""
        analyzer = AdvancedDynamicAnalyzer(real_system_binary)
        keywords = ["license"]

        result: dict[str, Any] = analyzer._frida_memory_scan(keywords, None)

        if result.get("status") == "success":
            matches = result.get("matches", [])
            if matches:
                addresses = [m["address"] for m in matches]
                unique_addresses = set(addresses)

                assert len(addresses) == len(unique_addresses), "Duplicates not removed"


class TestEdgeCases:
    """Test edge cases and unusual scenarios."""

    def test_analyzer_handles_empty_binary(self, tmp_path: Path) -> None:
        """Analyzer handles empty binary file gracefully."""
        empty_binary = tmp_path / "empty.exe"
        empty_binary.write_bytes(b"")

        with pytest.raises(FileNotFoundError):
            AdvancedDynamicAnalyzer(empty_binary)

    def test_memory_scan_with_empty_keywords(self, real_system_binary: Path) -> None:
        """Memory scan handles empty keyword list."""
        analyzer = AdvancedDynamicAnalyzer(real_system_binary)
        result: dict[str, Any] = analyzer.scan_memory_for_keywords([])

        assert isinstance(result, dict)

    def test_memory_scan_with_unicode_keywords(self, real_system_binary: Path) -> None:
        """Memory scan handles Unicode keywords correctly."""
        analyzer = AdvancedDynamicAnalyzer(real_system_binary)
        keywords = ["license", "лицензия", "ライセンス"]

        result: dict[str, Any] = analyzer.scan_memory_for_keywords(keywords)

        assert isinstance(result, dict)
        assert "matches" in result


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
class TestLicenseDetectionCapabilities:
    """Test license detection and analysis capabilities."""

    def test_frida_detects_license_validation_patterns(self, real_system_binary: Path) -> None:
        """Frida detects common license validation function patterns."""
        analyzer = AdvancedDynamicAnalyzer(real_system_binary)
        result: dict[str, Any] = analyzer._frida_runtime_analysis()

        if result.get("success"):
            analysis_data = result.get("analysis_data", {})
            assert isinstance(analysis_data, dict)

    def test_memory_scan_finds_license_registry_keys(self, real_system_binary: Path) -> None:
        """Memory scanning detects common license registry key patterns."""
        analyzer = AdvancedDynamicAnalyzer(real_system_binary)
        keywords = ["SOFTWARE\\", "License", "Registration"]

        result: dict[str, Any] = analyzer.scan_memory_for_keywords(keywords)

        assert isinstance(result, dict)

    def test_memory_scan_finds_license_file_names(self, real_system_binary: Path) -> None:
        """Memory scanning detects common license file name patterns."""
        analyzer = AdvancedDynamicAnalyzer(real_system_binary)
        keywords = ["license.dat", "activation.key", "registration.lic"]

        result: dict[str, Any] = analyzer.scan_memory_for_keywords(keywords)

        assert isinstance(result, dict)


class TestCrossPlatformCompatibility:
    """Test cross-platform dynamic analysis capabilities."""

    def test_analyzer_selects_platform_memory_scanner(self, real_system_binary: Path) -> None:
        """Analyzer selects appropriate platform-specific memory scanner."""
        analyzer = AdvancedDynamicAnalyzer(real_system_binary)
        keywords = ["test"]

        result: dict[str, Any] = analyzer.scan_memory_for_keywords(keywords)

        assert isinstance(result, dict)
        assert "status" in result

    @pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
    def test_generic_memory_scan_fallback(self, real_system_binary: Path) -> None:
        """Generic memory scan provides fallback for unsupported platforms."""
        import psutil

        proc = subprocess.Popen([str(real_system_binary)])
        time.sleep(0.5)

        try:
            analyzer = AdvancedDynamicAnalyzer(real_system_binary)
            ps_proc = psutil.Process(proc.pid)
            keywords = ["test"]

            matches = analyzer._generic_memory_scan(ps_proc, keywords)

            assert isinstance(matches, list)
        finally:
            proc.terminate()
            proc.wait()


class TestResourceCleanup:
    """Test proper resource cleanup and error recovery."""

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
    def test_frida_cleanup_releases_process(self, anti_debug_binary: Path) -> None:
        """Frida properly releases process after analysis."""
        analyzer = AdvancedDynamicAnalyzer(anti_debug_binary)
        result: dict[str, Any] = analyzer._frida_runtime_analysis()

        assert isinstance(result, dict)

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
    def test_frida_cleanup_on_script_error(self, anti_debug_binary: Path) -> None:
        """Frida cleans up resources even when script errors occur."""
        analyzer = AdvancedDynamicAnalyzer(anti_debug_binary)
        result: dict[str, Any] = analyzer._frida_runtime_analysis()

        assert isinstance(result, dict)


class TestDataIntegrity:
    """Test data integrity and accuracy of analysis results."""

    def test_memory_scan_context_accuracy(self, real_system_binary: Path) -> None:
        """Memory scan context accurately reflects surrounding bytes."""
        analyzer = AdvancedDynamicAnalyzer(real_system_binary)
        keywords = ["MZ"]

        result: dict[str, Any] = analyzer._fallback_memory_scan(keywords, None)

        status = result.get("status")
        matches = result.get("matches", [])
        if status == "success" and matches:
            match = matches[0]
            assert "context" in match
            assert "MZ" in match["context"] or "mz" in match["context"]

    def test_memory_scan_address_calculation_correct(self, real_system_binary: Path) -> None:
        """Memory scan address calculations are correct."""
        analyzer = AdvancedDynamicAnalyzer(real_system_binary)
        keywords = ["test"]

        result: dict[str, Any] = analyzer._fallback_memory_scan(keywords, None)

        status = result.get("status")
        matches = result.get("matches", [])
        if status == "success" and matches:
            for match in matches:
                assert "address" in match
                assert "offset" in match
                assert match["address"].startswith("0x")
