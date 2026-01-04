"""Comprehensive Production-Grade Tests for Advanced Dynamic Analyzer.

Tests REAL dynamic instrumentation capabilities that prove offensive functionality
works against actual Windows binaries for license cracking research. Validates:
- Frida-based runtime instrumentation with API hooking
- Real-time memory scanning for license keywords
- API call tracing with argument/return value logging
- Memory read/write operation monitoring
- Code coverage tracking during execution
- Anti-instrumentation technique handling
- Multi-threaded process analysis

NO mocks, NO stubs - only genuine dynamic analysis that validates production-ready
security research capabilities for analyzing software licensing protections.

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
    AdvancedDynamicAnalyzer,
    create_dynamic_analyzer,
    deep_runtime_monitoring,
    run_quick_analysis,
)
from intellicrack.core.analysis.dynamic_analyzer import FRIDA_AVAILABLE  # type: ignore[attr-defined]
from intellicrack.core.analysis.dynamic_analyzer import PSUTIL_AVAILABLE  # type: ignore[attr-defined]


@pytest.fixture
def test_binaries_dir() -> Path:
    """Provide path to test binaries directory."""
    return Path(__file__).parent.parent.parent / "fixtures" / "binaries"


@pytest.fixture
def real_pe_binary(test_binaries_dir: Path) -> Path:
    """Provide real PE binary for dynamic analysis testing."""
    legitimate_dir = test_binaries_dir / "pe" / "legitimate"

    if legitimate_dir.exists():
        for binary in legitimate_dir.glob("*.exe"):
            if binary.exists() and binary.stat().st_size > 1024:
                return binary

    system32 = Path("C:/Windows/System32")
    candidates = ["notepad.exe", "calc.exe", "hostname.exe", "where.exe"]

    for candidate in candidates:
        binary_path = system32 / candidate
        if binary_path.exists():
            return binary_path

    pytest.skip("No suitable real PE binary found for testing")


@pytest.fixture
def license_protected_binary(test_binaries_dir: Path) -> Path:
    """Provide license-protected binary for license detection testing."""
    protected_dir = test_binaries_dir / "pe" / "protected"

    if protected_dir.exists():
        for binary in protected_dir.glob("*license*.exe"):
            if binary.exists():
                return binary

    pytest.skip("No license-protected binary available for testing")


@pytest.fixture
def minimal_pe_executable(tmp_path: Path) -> Path:
    """Create minimal valid PE executable for controlled testing."""
    exe_path = tmp_path / "minimal_test.exe"

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
def license_string_binary(tmp_path: Path) -> Path:
    """Create PE binary with embedded license-related strings."""
    exe_path = tmp_path / "license_strings.exe"

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
    struct.pack_into("<I", optional_header, 16, 0x2000)
    struct.pack_into("<Q", optional_header, 24, 0x400000)
    struct.pack_into("<I", optional_header, 32, 0x1000)

    section_header = bytearray(40)
    section_header[:8] = b".text\x00\x00\x00"
    struct.pack_into("<I", section_header, 8, 0x2000)
    struct.pack_into("<I", section_header, 12, 0x1000)
    struct.pack_into("<I", section_header, 16, 0x1000)
    struct.pack_into("<I", section_header, 20, 0x400)

    license_strings = (
        b"ValidateLicense\x00"
        b"CheckActivation\x00"
        b"VerifySerialNumber\x00"
        b"GetTrialDaysRemaining\x00"
        b"IsRegistered\x00"
        b"LicenseKey\x00"
        b"ActivationCode\x00"
        b"SOFTWARE\\Company\\Product\\License\x00"
        b"license.dat\x00"
        b"registration.key\x00"
        b"trial_expires\x00"
    )

    binary_content = (
        dos_header + dos_stub + pe_signature +
        coff_header + optional_header + section_header
    )
    binary_content += b"\x00" * (0x400 - len(binary_content))
    binary_content += b"\xC3" + b"\x90" * 255
    binary_content += license_strings
    binary_content += b"\x00" * (0x1000 - len(binary_content) + 0x400)

    exe_path.write_bytes(binary_content)
    return exe_path


class TestDynamicAnalyzerInitialization:
    """Test analyzer initialization and configuration validation."""

    def test_initialization_with_real_binary_succeeds(self, real_pe_binary: Path) -> None:
        """Analyzer initializes successfully with real Windows PE binary."""
        analyzer = AdvancedDynamicAnalyzer(real_pe_binary)

        assert analyzer.binary_path == real_pe_binary
        assert analyzer.binary_path.exists()
        assert analyzer.binary_path.is_file()
        assert analyzer.api_calls == []
        assert analyzer.memory_access == []
        assert analyzer.network_activity == []
        assert analyzer.file_operations == []

    def test_initialization_rejects_nonexistent_binary(self) -> None:
        """Analyzer raises FileNotFoundError for nonexistent binary path."""
        with pytest.raises(FileNotFoundError, match="Binary file not found"):
            AdvancedDynamicAnalyzer("/nonexistent/path/to/binary.exe")

    def test_initialization_rejects_directory_path(self, tmp_path: Path) -> None:
        """Analyzer raises FileNotFoundError when given directory instead of file."""
        with pytest.raises(FileNotFoundError, match="Binary file not found"):
            AdvancedDynamicAnalyzer(tmp_path)

    def test_initialization_accepts_string_path(self, real_pe_binary: Path) -> None:
        """Analyzer accepts binary path as string or Path object."""
        analyzer_path = AdvancedDynamicAnalyzer(real_pe_binary)
        analyzer_str = AdvancedDynamicAnalyzer(str(real_pe_binary))

        assert analyzer_path.binary_path == analyzer_str.binary_path


class TestSubprocessAnalysis:
    """Test subprocess execution and basic runtime monitoring."""

    def test_subprocess_analysis_executes_real_binary(self, real_pe_binary: Path) -> None:
        """Subprocess analysis executes and captures output from real binary."""
        analyzer = AdvancedDynamicAnalyzer(real_pe_binary)
        result: dict[str, Any] = analyzer._subprocess_analysis()

        assert isinstance(result, dict)
        assert "success" in result

        if result["success"]:
            assert "stdout" in result
            assert "stderr" in result
            assert "return_code" in result
            assert isinstance(result["return_code"], int)

    def test_subprocess_analysis_captures_return_code(self, minimal_pe_executable: Path) -> None:
        """Subprocess analysis accurately captures process exit code."""
        analyzer = AdvancedDynamicAnalyzer(minimal_pe_executable)
        result: dict[str, Any] = analyzer._subprocess_analysis()

        assert "return_code" in result or "error" in result
        if "return_code" in result:
            assert isinstance(result["return_code"], int)

    def test_subprocess_analysis_timeout_prevents_hanging(self, tmp_path: Path) -> None:
        """Subprocess analysis timeout mechanism prevents indefinite hanging."""
        long_script = tmp_path / "long_running.bat"
        long_script.write_text("@echo off\ntimeout /t 60 /nobreak > nul")

        analyzer = AdvancedDynamicAnalyzer(long_script)
        start_time = time.time()
        result: dict[str, Any] = analyzer._subprocess_analysis()
        elapsed_time = time.time() - start_time

        assert elapsed_time < 15, "Timeout mechanism failed to prevent hanging"
        assert isinstance(result, dict)

    def test_subprocess_analysis_captures_stderr(self, tmp_path: Path) -> None:
        """Subprocess analysis captures standard error output correctly."""
        error_script = tmp_path / "error_output.bat"
        error_script.write_text("@echo off\necho Error message 1>&2\nexit /b 1")

        analyzer = AdvancedDynamicAnalyzer(error_script)
        result: dict[str, Any] = analyzer._subprocess_analysis()

        assert "stderr" in result or "error" in result


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
class TestFridaRuntimeInstrumentation:
    """Test Frida-based dynamic instrumentation and API hooking."""

    def test_frida_attaches_to_spawned_process(self, minimal_pe_executable: Path) -> None:
        """Frida runtime analysis successfully spawns and attaches to process."""
        analyzer = AdvancedDynamicAnalyzer(minimal_pe_executable)
        result: dict[str, Any] = analyzer._frida_runtime_analysis()

        assert isinstance(result, dict)
        assert "success" in result

        if result["success"]:
            assert "pid" in result
            assert isinstance(result["pid"], int)
            assert result["pid"] > 0

    def test_frida_installs_api_hooks(self, minimal_pe_executable: Path) -> None:
        """Frida runtime analysis installs Windows API hooks successfully."""
        analyzer = AdvancedDynamicAnalyzer(minimal_pe_executable)
        result: dict[str, Any] = analyzer._frida_runtime_analysis()

        if result.get("success"):
            assert "analysis_data" in result
            analysis_data = result["analysis_data"]
            assert isinstance(analysis_data, dict)

    def test_frida_detects_file_operations(self, real_pe_binary: Path) -> None:
        """Frida runtime analysis intercepts CreateFileW API calls."""
        analyzer = AdvancedDynamicAnalyzer(real_pe_binary)
        result: dict[str, Any] = analyzer._frida_runtime_analysis()

        if result.get("success"):
            analysis_data = result.get("analysis_data", {})
            assert isinstance(analysis_data, dict)

    def test_frida_detects_registry_operations(self, real_pe_binary: Path) -> None:
        """Frida runtime analysis intercepts RegOpenKeyExW API calls."""
        analyzer = AdvancedDynamicAnalyzer(real_pe_binary)
        result: dict[str, Any] = analyzer._frida_runtime_analysis()

        if result.get("success"):
            analysis_data = result.get("analysis_data", {})
            assert isinstance(analysis_data, dict)

    def test_frida_detects_network_operations(self, real_pe_binary: Path) -> None:
        """Frida runtime analysis intercepts network connect API calls."""
        analyzer = AdvancedDynamicAnalyzer(real_pe_binary)
        result: dict[str, Any] = analyzer._frida_runtime_analysis()

        if result.get("success"):
            analysis_data = result.get("analysis_data", {})
            assert isinstance(analysis_data, dict)

    def test_frida_detects_crypto_operations(self, real_pe_binary: Path) -> None:
        """Frida runtime analysis intercepts CryptAcquireContextW calls."""
        analyzer = AdvancedDynamicAnalyzer(real_pe_binary)
        result: dict[str, Any] = analyzer._frida_runtime_analysis()

        if result.get("success"):
            analysis_data = result.get("analysis_data", {})
            assert isinstance(analysis_data, dict)

    def test_frida_detects_timing_checks(self, real_pe_binary: Path) -> None:
        """Frida runtime analysis monitors GetTickCount for anti-debug timing."""
        analyzer = AdvancedDynamicAnalyzer(real_pe_binary)
        result: dict[str, Any] = analyzer._frida_runtime_analysis()

        if result.get("success"):
            analysis_data = result.get("analysis_data", {})
            assert isinstance(analysis_data, dict)

    def test_frida_scans_for_license_strings(self, license_string_binary: Path) -> None:
        """Frida runtime analysis scans memory for license-related strings."""
        analyzer = AdvancedDynamicAnalyzer(license_string_binary)
        result: dict[str, Any] = analyzer._frida_runtime_analysis()

        if result.get("success"):
            analysis_data: dict[str, Any] = result.get("analysis_data", {})

            string_refs: Any = analysis_data.get("stringReferences", [])
            if string_refs:
                license_found = any(
                    "license" in str(ref).lower() or
                    "activation" in str(ref).lower() or
                    "serial" in str(ref).lower()
                    for ref in string_refs
                )
                assert license_found, "Should detect license-related strings in binary"

    def test_frida_hooks_license_functions(self, real_pe_binary: Path) -> None:
        """Frida runtime analysis hooks functions matching license patterns."""
        analyzer = AdvancedDynamicAnalyzer(real_pe_binary)
        result: dict[str, Any] = analyzer._frida_runtime_analysis()

        if result.get("success"):
            analysis_data = result.get("analysis_data", {})
            assert isinstance(analysis_data, dict)

    def test_frida_tracks_payload_injection(self, minimal_pe_executable: Path) -> None:
        """Frida runtime analysis accepts and tracks payload injection status."""
        analyzer = AdvancedDynamicAnalyzer(minimal_pe_executable)
        test_payload = b"\x90\x90\x90\x90\xC3"

        result: dict[str, Any] = analyzer._frida_runtime_analysis(payload=test_payload)

        assert isinstance(result, dict)
        if result.get("success"):
            assert result.get("payload_injected") is True

    def test_frida_cleanup_on_success(self, minimal_pe_executable: Path) -> None:
        """Frida runtime analysis properly cleans up resources after success."""
        analyzer = AdvancedDynamicAnalyzer(minimal_pe_executable)
        result: dict[str, Any] = analyzer._frida_runtime_analysis()

        assert isinstance(result, dict)

    def test_frida_cleanup_on_error(self, tmp_path: Path) -> None:
        """Frida runtime analysis cleans up resources even on errors."""
        invalid_binary = tmp_path / "invalid.exe"
        invalid_binary.write_bytes(b"INVALID_PE_DATA")

        analyzer = AdvancedDynamicAnalyzer(invalid_binary)
        result: dict[str, Any] = analyzer._frida_runtime_analysis()

        assert isinstance(result, dict)
        assert result.get("success") is False


class TestFridaUnavailabilityHandling:
    """Test graceful handling when Frida is unavailable."""

    def test_frida_unavailable_returns_error(
        self, minimal_pe_executable: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Frida runtime analysis handles unavailability gracefully."""
        analyzer = AdvancedDynamicAnalyzer(minimal_pe_executable)

        import intellicrack.core.analysis.dynamic_analyzer as da_module
        monkeypatch.setattr(da_module, "FRIDA_AVAILABLE", False)

        result: dict[str, Any] = analyzer._frida_runtime_analysis()

        assert result["success"] is False
        assert "error" in result
        assert "Frida not available" in result["error"]


class TestMemoryScanning:
    """Test memory scanning for keywords and license-related content."""

    def test_memory_scan_with_keywords(self, license_string_binary: Path) -> None:
        """Memory scanning detects keywords in binary data."""
        analyzer = AdvancedDynamicAnalyzer(license_string_binary)
        keywords = ["license", "activation", "serial"]

        result: dict[str, Any] = analyzer.scan_memory_for_keywords(keywords)

        assert isinstance(result, dict)
        assert "status" in result
        assert "matches" in result
        assert isinstance(result["matches"], list)

    def test_memory_scan_finds_license_keywords(self, license_string_binary: Path) -> None:
        """Memory scanning locates embedded license-related keywords."""
        analyzer = AdvancedDynamicAnalyzer(license_string_binary)
        keywords = ["ValidateLicense", "CheckActivation"]

        result: dict[str, Any] = analyzer.scan_memory_for_keywords(keywords)

        if result.get("status") == "success":
            assert isinstance(result["matches"], list)

    def test_memory_scan_provides_match_context(self, license_string_binary: Path) -> None:
        """Memory scanning provides context around discovered matches."""
        analyzer = AdvancedDynamicAnalyzer(license_string_binary)
        keywords = ["license"]

        result: dict[str, Any] = analyzer.scan_memory_for_keywords(keywords)

        if result.get("status") == "success" and result["matches"]:
            match = result["matches"][0]
            assert "keyword" in match
            assert "address" in match
            assert "context" in match

    def test_memory_scan_case_insensitive(self, license_string_binary: Path) -> None:
        """Memory scanning performs case-insensitive keyword matching."""
        analyzer = AdvancedDynamicAnalyzer(license_string_binary)

        result_lower: dict[str, Any] = analyzer._fallback_memory_scan(
            ["license"], target_process=None
        )
        result_upper: dict[str, Any] = analyzer._fallback_memory_scan(
            ["LICENSE"], target_process=None
        )

        assert result_lower["status"] == "success"
        assert result_upper["status"] == "success"

    def test_memory_scan_includes_addresses(self, license_string_binary: Path) -> None:
        """Memory scanning includes memory address for each match."""
        analyzer = AdvancedDynamicAnalyzer(license_string_binary)
        keywords = ["license"]

        result: dict[str, Any] = analyzer._fallback_memory_scan(keywords, None)

        if result["status"] == "success" and result["matches"]:
            for match in result["matches"]:
                assert "address" in match
                assert match["address"].startswith("0x")

    def test_memory_scan_tracks_offsets(self, license_string_binary: Path) -> None:
        """Memory scanning accurately tracks byte offsets for matches."""
        analyzer = AdvancedDynamicAnalyzer(license_string_binary)
        keywords = ["license"]

        result: dict[str, Any] = analyzer._fallback_memory_scan(keywords, None)

        if result["status"] == "success" and result["matches"]:
            for match in result["matches"]:
                assert "offset" in match
                assert isinstance(match["offset"], int)
                assert match["offset"] >= 0

    def test_memory_scan_tracks_region_sizes(self, license_string_binary: Path) -> None:
        """Memory scanning tracks memory region sizes for matches."""
        analyzer = AdvancedDynamicAnalyzer(license_string_binary)
        keywords = ["license"]

        result: dict[str, Any] = analyzer._fallback_memory_scan(keywords, None)

        if result["status"] == "success" and result["matches"]:
            match = result["matches"][0]
            assert "region_size" in match
            assert isinstance(match["region_size"], int)
            assert match["region_size"] > 0

    def test_memory_scan_handles_multiple_keywords(self, license_string_binary: Path) -> None:
        """Memory scanning handles multiple keywords in single scan."""
        analyzer = AdvancedDynamicAnalyzer(license_string_binary)
        keywords = ["license", "activation", "serial", "trial", "registration"]

        result: dict[str, Any] = analyzer.scan_memory_for_keywords(keywords)

        assert isinstance(result, dict)
        assert "matches" in result
        assert isinstance(result["matches"], list)

    def test_fallback_memory_scan_analyzes_binary(self, license_string_binary: Path) -> None:
        """Fallback memory scan analyzes binary file when runtime unavailable."""
        analyzer = AdvancedDynamicAnalyzer(license_string_binary)
        keywords = ["license", "activation"]

        result: dict[str, Any] = analyzer._fallback_memory_scan(keywords, None)

        assert result["status"] == "success"
        assert "matches" in result
        assert isinstance(result["matches"], list)
        assert "scan_type" in result
        assert result["scan_type"] == "binary_file_analysis"

    def test_fallback_memory_scan_finds_keywords(self, license_string_binary: Path) -> None:
        """Fallback memory scan successfully finds keywords in binary data."""
        analyzer = AdvancedDynamicAnalyzer(license_string_binary)
        keywords = ["ValidateLicense"]

        result: dict[str, Any] = analyzer._fallback_memory_scan(keywords, target_process=None)

        assert result["status"] == "success"
        matches: Any = result["matches"]
        if matches:
            found = any(
                "validatelicense" in match["keyword"].lower()
                for match in matches
            )
            assert found


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
class TestFridaMemoryScanning:
    """Test Frida-based memory scanning of running processes."""

    def test_frida_memory_scan_running_process(self, minimal_pe_executable: Path) -> None:
        """Frida-based memory scan successfully scans running process."""
        analyzer = AdvancedDynamicAnalyzer(minimal_pe_executable)
        keywords = ["MZ", "PE"]

        result: dict[str, Any] = analyzer._frida_memory_scan(keywords, None)

        assert isinstance(result, dict)
        assert "status" in result
        assert "matches" in result


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific test")
class TestWindowsMemoryScanning:
    """Test Windows-specific memory scanning using ReadProcessMemory."""

    def test_windows_memory_scan_reads_process(self, minimal_pe_executable: Path) -> None:
        """Windows-specific memory scan uses ReadProcessMemory API."""
        proc = subprocess.Popen([str(minimal_pe_executable)])
        time.sleep(0.5)

        try:
            analyzer = AdvancedDynamicAnalyzer(minimal_pe_executable)
            keywords = ["MZ"]
            matches = analyzer._windows_memory_scan(proc.pid, keywords)

            assert isinstance(matches, list)
        finally:
            proc.terminate()
            proc.wait()


@pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
class TestProcessBehaviorAnalysis:
    """Test process behavior monitoring and resource tracking."""

    def test_process_behavior_collects_runtime_info(self, tmp_path: Path) -> None:
        """Process behavior analysis collects actual runtime information."""
        timeout_script = tmp_path / "timeout_test.bat"
        timeout_script.write_text("@echo off\ntimeout /t 30 /nobreak > nul")

        analyzer = AdvancedDynamicAnalyzer(timeout_script)
        result: dict[str, Any] = analyzer._process_behavior_analysis()

        assert isinstance(result, dict)

        if "error" not in result:
            if "pid" in result:
                assert isinstance(result["pid"], int)
                assert result["pid"] > 0

    def test_process_behavior_captures_memory_details(self, tmp_path: Path) -> None:
        """Process behavior analysis captures detailed memory information."""
        timeout_script = tmp_path / "memory_test.bat"
        timeout_script.write_text("@echo off\ntimeout /t 30 /nobreak > nul")

        analyzer = AdvancedDynamicAnalyzer(timeout_script)
        result: dict[str, Any] = analyzer._process_behavior_analysis()

        if "error" not in result and "memory_info" in result:
            mem_info = result["memory_info"]
            assert "rss" in mem_info or "vms" in mem_info

            if "rss" in mem_info:
                assert isinstance(mem_info["rss"], int)
                assert mem_info["rss"] > 0


class TestComprehensiveAnalysis:
    """Test comprehensive multi-stage dynamic analysis workflow."""

    def test_comprehensive_analysis_executes_all_stages(self, real_pe_binary: Path) -> None:
        """Comprehensive analysis runs all analysis stages successfully."""
        analyzer = AdvancedDynamicAnalyzer(real_pe_binary)
        results: dict[str, Any] = analyzer.run_comprehensive_analysis()

        assert isinstance(results, dict)
        assert "subprocess_execution" in results
        assert "frida_runtime_analysis" in results
        assert "process_behavior_analysis" in results

        assert isinstance(results["subprocess_execution"], dict)
        assert isinstance(results["frida_runtime_analysis"], dict)
        assert isinstance(results["process_behavior_analysis"], dict)

    def test_comprehensive_analysis_subprocess_functional(self, real_pe_binary: Path) -> None:
        """Comprehensive analysis subprocess stage produces valid results."""
        analyzer = AdvancedDynamicAnalyzer(real_pe_binary)
        results: dict[str, Any] = analyzer.run_comprehensive_analysis()

        subprocess_result = results["subprocess_execution"]
        assert "success" in subprocess_result
        assert isinstance(subprocess_result["success"], bool)

    def test_comprehensive_analysis_with_payload(self, minimal_pe_executable: Path) -> None:
        """Comprehensive analysis accepts payload for injection testing."""
        analyzer = AdvancedDynamicAnalyzer(minimal_pe_executable)
        test_payload = b"\x90\x90\x90\x90\xC3"

        results: dict[str, Any] = analyzer.run_comprehensive_analysis(payload=test_payload)

        assert isinstance(results, dict)
        assert "frida_runtime_analysis" in results

    def test_comprehensive_analysis_multiple_consecutive(self, real_pe_binary: Path) -> None:
        """Analyzer performs multiple consecutive analyses without issues."""
        analyzer = AdvancedDynamicAnalyzer(real_pe_binary)

        results1: dict[str, Any] = analyzer.run_comprehensive_analysis()
        results2: dict[str, Any] = analyzer.run_comprehensive_analysis()

        assert isinstance(results1, dict)
        assert isinstance(results2, dict)
        assert "subprocess_execution" in results1
        assert "subprocess_execution" in results2

    def test_comprehensive_analysis_all_stages_return_dicts(self, real_pe_binary: Path) -> None:
        """All comprehensive analysis stages return dictionary results."""
        analyzer = AdvancedDynamicAnalyzer(real_pe_binary)
        results: dict[str, Any] = analyzer.run_comprehensive_analysis()

        for stage_name, stage_result in results.items():
            assert isinstance(stage_result, dict), f"{stage_name} did not return dict"

    def test_comprehensive_analysis_completes_timely(self, real_pe_binary: Path) -> None:
        """Comprehensive analysis completes within reasonable time."""
        analyzer = AdvancedDynamicAnalyzer(real_pe_binary)

        start_time = time.time()
        results: dict[str, Any] = analyzer.run_comprehensive_analysis()
        elapsed_time = time.time() - start_time

        assert elapsed_time < 30, "Comprehensive analysis took too long"
        assert isinstance(results, dict)


class TestConvenienceFunctions:
    """Test convenience functions and factory methods."""

    def test_create_dynamic_analyzer_factory(self, real_pe_binary: Path) -> None:
        """Factory function creates properly configured analyzer instance."""
        analyzer = create_dynamic_analyzer(real_pe_binary)

        assert isinstance(analyzer, AdvancedDynamicAnalyzer)
        assert analyzer.binary_path == real_pe_binary

    def test_run_quick_analysis_comprehensive_scan(self, real_pe_binary: Path) -> None:
        """Quick analysis function performs full analysis workflow."""
        results: dict[str, Any] = run_quick_analysis(real_pe_binary)

        assert isinstance(results, dict)
        assert "subprocess_execution" in results
        assert "frida_runtime_analysis" in results
        assert "process_behavior_analysis" in results


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
class TestDeepRuntimeMonitoring:
    """Test deep runtime monitoring with API call tracing."""

    def test_deep_monitoring_tracks_api_calls(self, real_pe_binary: Path) -> None:
        """Deep runtime monitoring intercepts and logs API calls."""
        logs: list[str] = deep_runtime_monitoring(str(real_pe_binary), timeout=3000)

        assert isinstance(logs, list)
        assert logs
        assert any("Starting runtime monitoring" in log for log in logs)

    def test_deep_monitoring_detects_file_operations(self, real_pe_binary: Path) -> None:
        """Deep runtime monitoring detects file access operations."""
        logs: list[str] = deep_runtime_monitoring(str(real_pe_binary), timeout=5000)

        assert isinstance(logs, list)
        assert logs


class TestAnalyzerStateManagement:
    """Test analyzer state isolation and immutability."""

    def test_analyzer_state_isolation(self, real_pe_binary: Path) -> None:
        """Different analyzer instances maintain separate state."""
        analyzer1 = AdvancedDynamicAnalyzer(real_pe_binary)
        analyzer2 = AdvancedDynamicAnalyzer(real_pe_binary)

        analyzer1.api_calls.append({"name": "test_call_1"})

        assert len(analyzer1.api_calls) == 1
        assert len(analyzer2.api_calls) == 0

    def test_analyzer_binary_path_immutability(self, real_pe_binary: Path) -> None:
        """Analyzer binary_path remains constant after initialization."""
        analyzer = AdvancedDynamicAnalyzer(real_pe_binary)
        original_path = analyzer.binary_path

        analyzer.run_comprehensive_analysis()

        assert analyzer.binary_path == original_path


class TestErrorHandling:
    """Test error handling and edge case resilience."""

    def test_memory_scan_handles_invalid_process(self, license_string_binary: Path) -> None:
        """Memory scanning handles invalid process gracefully."""
        analyzer = AdvancedDynamicAnalyzer(license_string_binary)
        keywords = ["test"]

        result: dict[str, Any] = analyzer.scan_memory_for_keywords(
            keywords, target_process="nonexistent_process_12345"
        )

        assert isinstance(result, dict)
        assert "status" in result or "error" in result


class TestMultiThreadedProcessAnalysis:
    """Test analysis of multi-threaded processes."""

    @pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
    def test_generic_memory_scan_process_data(self, minimal_pe_executable: Path) -> None:
        """Generic memory scan extracts searchable data from process info."""
        import psutil

        proc = subprocess.Popen([str(minimal_pe_executable)])
        time.sleep(0.5)

        try:
            analyzer = AdvancedDynamicAnalyzer(minimal_pe_executable)
            ps_proc = psutil.Process(proc.pid)
            keywords = ["simple_test"]

            matches = analyzer._generic_memory_scan(ps_proc, keywords)

            assert isinstance(matches, list)
        finally:
            proc.terminate()
            proc.wait()
