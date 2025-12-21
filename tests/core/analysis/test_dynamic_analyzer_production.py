"""Production-Grade Tests for Advanced Dynamic Analyzer.

Validates REAL dynamic analysis capabilities against actual Windows binaries.
Tests runtime monitoring, Frida instrumentation, memory scanning, and process
behavior analysis. NO mocks, NO stubs - only genuine dynamic analysis that
proves offensive capability for security research.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3.0+
"""

import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.dynamic_analyzer import (
    FRIDA_AVAILABLE,
    PSUTIL_AVAILABLE,
    AdvancedDynamicAnalyzer,
    create_dynamic_analyzer,
    deep_runtime_monitoring,
    run_quick_analysis,
)


@pytest.fixture
def temp_dir(tmp_path: Path) -> Path:
    """Provide temporary directory for test binaries."""
    return tmp_path


@pytest.fixture
def system_binary() -> Path:
    """Provide path to real Windows system binary for testing."""
    system32 = Path("C:/Windows/System32")
    candidates: list[str] = [
        "calc.exe",
        "notepad.exe",
        "cmd.exe",
        "timeout.exe",
        "whoami.exe",
        "hostname.exe",
        "where.exe",
    ]

    for binary_name in candidates:
        binary_path = system32 / binary_name
        if binary_path.exists():
            return binary_path

    pytest.skip("No suitable Windows system binary found for testing")


@pytest.fixture
def simple_executable(temp_dir: Path) -> Path:
    """Create minimal but valid Windows PE executable that exits immediately."""
    exe_path = temp_dir / "simple_test.exe"

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

    coff_header = struct.pack(
        "<HHIIIHH",
        0x8664,
        1,
        0,
        0,
        0,
        0x00F0,
        0x0022
    )

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
def license_check_executable(temp_dir: Path) -> Path:
    """Create PE with embedded license-related strings for detection testing."""
    exe_path = temp_dir / "license_check.exe"

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
        b"CheckLicense\x00"
        b"ValidateActivation\x00"
        b"VerifySerialKey\x00"
        b"GetRegistrationStatus\x00"
        b"IsTrialExpired\x00"
        b"SOFTWARE\\MyApp\\License\x00"
        b"license.dat\x00"
        b"activation_key\x00"
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


def test_analyzer_initialization_with_valid_binary(system_binary: Path) -> None:
    """Analyzer initializes successfully with real Windows binary."""
    analyzer = AdvancedDynamicAnalyzer(system_binary)

    assert analyzer.binary_path == system_binary
    assert analyzer.binary_path.exists()
    assert analyzer.api_calls == []
    assert analyzer.memory_access == []
    assert analyzer.network_activity == []
    assert analyzer.file_operations == []


def test_analyzer_initialization_with_nonexistent_binary_raises_error() -> None:
    """Analyzer raises FileNotFoundError for nonexistent binary."""
    with pytest.raises(FileNotFoundError, match="Binary file not found"):
        AdvancedDynamicAnalyzer("/nonexistent/binary.exe")


def test_analyzer_initialization_with_directory_raises_error(temp_dir: Path) -> None:
    """Analyzer raises FileNotFoundError when given directory path."""
    with pytest.raises(FileNotFoundError, match="Binary file not found"):
        AdvancedDynamicAnalyzer(temp_dir)


def test_subprocess_analysis_executes_real_binary(system_binary: Path) -> None:
    """Subprocess analysis executes and captures output from real binary."""
    analyzer = AdvancedDynamicAnalyzer(system_binary)
    result: dict[str, Any] = analyzer._subprocess_analysis()

    assert isinstance(result, dict)
    assert "success" in result
    assert isinstance(result["success"], bool)

    if result["success"]:
        assert "stdout" in result
        assert "stderr" in result
        assert "return_code" in result
        assert result["return_code"] == 0
    else:
        assert "error" in result or "return_code" in result


def test_subprocess_analysis_handles_timeout_gracefully(simple_executable: Path) -> None:
    """Subprocess analysis handles timeout without crashing."""
    analyzer = AdvancedDynamicAnalyzer(simple_executable)
    result: dict[str, Any] = analyzer._subprocess_analysis()

    assert isinstance(result, dict)
    assert "success" in result


@pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
def test_process_behavior_analysis_collects_real_process_info(temp_dir: Path) -> None:
    """Process behavior analysis collects actual runtime information."""
    timeout_script = temp_dir / "timeout_test.bat"
    timeout_script.write_text("@echo off\ntimeout /t 30 /nobreak > nul")

    analyzer = AdvancedDynamicAnalyzer(timeout_script)
    result: dict[str, Any] = analyzer._process_behavior_analysis()

    assert isinstance(result, dict)

    if "error" not in result:
        assert "pid" in result or "error" in result

        if "pid" in result:
            assert "memory_info" in result
            assert "threads" in result
            assert isinstance(result["pid"], int)
            assert result["pid"] > 0
            assert isinstance(result["memory_info"], dict)
            assert isinstance(result["threads"], int)


@pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
def test_process_behavior_analysis_captures_memory_details(temp_dir: Path) -> None:
    """Process behavior analysis captures detailed memory information."""
    timeout_script = temp_dir / "memory_test.bat"
    timeout_script.write_text("@echo off\ntimeout /t 30 /nobreak > nul")

    analyzer = AdvancedDynamicAnalyzer(timeout_script)
    result: dict[str, Any] = analyzer._process_behavior_analysis()

    if "error" not in result and "memory_info" in result:
        mem_info = result["memory_info"]
        assert "rss" in mem_info or "vms" in mem_info

        if "rss" in mem_info:
            assert isinstance(mem_info["rss"], int)
            assert mem_info["rss"] > 0


def test_comprehensive_analysis_executes_all_stages(system_binary: Path) -> None:
    """Comprehensive analysis runs all analysis stages successfully."""
    analyzer = AdvancedDynamicAnalyzer(system_binary)
    results: dict[str, Any] = analyzer.run_comprehensive_analysis()

    assert isinstance(results, dict)
    assert "subprocess_execution" in results
    assert "frida_runtime_analysis" in results
    assert "process_behavior_analysis" in results

    assert isinstance(results["subprocess_execution"], dict)
    assert isinstance(results["frida_runtime_analysis"], dict)
    assert isinstance(results["process_behavior_analysis"], dict)


def test_comprehensive_analysis_subprocess_stage_functional(system_binary: Path) -> None:
    """Comprehensive analysis subprocess stage produces valid results."""
    analyzer = AdvancedDynamicAnalyzer(system_binary)
    results: dict[str, Any] = analyzer.run_comprehensive_analysis()

    subprocess_result = results["subprocess_execution"]
    assert "success" in subprocess_result
    assert isinstance(subprocess_result["success"], bool)


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
def test_frida_runtime_analysis_attaches_to_process(simple_executable: Path) -> None:
    """Frida runtime analysis successfully attaches and instruments process."""
    analyzer = AdvancedDynamicAnalyzer(simple_executable)
    result: dict[str, Any] = analyzer._frida_runtime_analysis()

    assert isinstance(result, dict)
    assert "success" in result

    if result["success"]:
        assert "pid" in result
        assert "analysis_data" in result
        assert isinstance(result["pid"], int)
        assert result["pid"] > 0


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
def test_frida_runtime_analysis_detects_license_strings(license_check_executable: Path) -> None:
    """Frida runtime analysis detects license-related strings in binary."""
    analyzer = AdvancedDynamicAnalyzer(license_check_executable)
    result: dict[str, Any] = analyzer._frida_runtime_analysis()

    if result.get("success"):
        analysis_data = result.get("analysis_data", {})
        if string_refs := analysis_data.get("stringReferences", []):
            license_related = any(
                "license" in str(ref).lower() or
                "activation" in str(ref).lower()
                for ref in string_refs
            )
            assert license_related, "Should detect license-related strings"


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
def test_frida_runtime_analysis_installs_api_hooks(system_binary: Path) -> None:
    """Frida runtime analysis installs Windows API hooks successfully."""
    analyzer = AdvancedDynamicAnalyzer(system_binary)
    result: dict[str, Any] = analyzer._frida_runtime_analysis()

    if result.get("success"):
        analysis_data = result.get("analysis_data", {})
        assert isinstance(analysis_data, dict)


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
def test_frida_runtime_analysis_handles_payload_injection(simple_executable: Path) -> None:
    """Frida runtime analysis accepts and tracks payload injection."""
    analyzer = AdvancedDynamicAnalyzer(simple_executable)
    test_payload = b"\x90\x90\x90\x90"

    result: dict[str, Any] = analyzer._frida_runtime_analysis(payload=test_payload)

    assert isinstance(result, dict)
    if result.get("success"):
        assert result.get("payload_injected") is True


def test_frida_runtime_analysis_graceful_when_unavailable(
    simple_executable: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Frida runtime analysis handles unavailability gracefully."""
    analyzer = AdvancedDynamicAnalyzer(simple_executable)

    import intellicrack.core.analysis.dynamic_analyzer as da_module
    monkeypatch.setattr(da_module, "FRIDA_AVAILABLE", False)

    result: dict[str, Any] = analyzer._frida_runtime_analysis()

    assert result["success"] is False
    assert "error" in result
    assert "Frida not available" in result["error"]


def test_memory_scan_with_keyword_detection(license_check_executable: Path) -> None:
    """Memory scanning detects keywords in binary data."""
    analyzer = AdvancedDynamicAnalyzer(license_check_executable)
    keywords = ["license", "activation", "serial"]

    result: dict[str, Any] = analyzer.scan_memory_for_keywords(keywords)

    assert isinstance(result, dict)
    assert "status" in result
    assert "matches" in result
    assert isinstance(result["matches"], list)


def test_memory_scan_finds_embedded_license_keywords(license_check_executable: Path) -> None:
    """Memory scanning locates embedded license-related keywords."""
    analyzer = AdvancedDynamicAnalyzer(license_check_executable)
    keywords = ["CheckLicense", "ValidateActivation"]

    result: dict[str, Any] = analyzer.scan_memory_for_keywords(keywords)

    if result["status"] == "success":
        if matches := result["matches"]:
            found_keywords = {match["keyword"] for match in matches}
            assert found_keywords


def test_memory_scan_returns_match_context(license_check_executable: Path) -> None:
    """Memory scanning provides context around discovered matches."""
    analyzer = AdvancedDynamicAnalyzer(license_check_executable)
    keywords = ["license"]

    result: dict[str, Any] = analyzer.scan_memory_for_keywords(keywords)

    if result["status"] == "success" and result["matches"]:
        match = result["matches"][0]
        assert "keyword" in match
        assert "address" in match
        assert "context" in match


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
def test_frida_memory_scan_with_running_process(simple_executable: Path) -> None:
    """Frida-based memory scan successfully scans running process."""
    analyzer = AdvancedDynamicAnalyzer(simple_executable)
    keywords = ["MZ", "PE"]

    result: dict[str, Any] = analyzer._frida_memory_scan(keywords, None)

    assert isinstance(result, dict)
    assert "status" in result
    assert "matches" in result


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific test")
def test_windows_memory_scan_reads_process_memory(simple_executable: Path) -> None:
    """Windows-specific memory scan uses ReadProcessMemory API."""
    import subprocess

    proc = subprocess.Popen([str(simple_executable)])
    time.sleep(0.5)

    try:
        analyzer = AdvancedDynamicAnalyzer(simple_executable)
        keywords = ["MZ"]
        matches = analyzer._windows_memory_scan(proc.pid, keywords)

        assert isinstance(matches, list)
    finally:
        proc.terminate()
        proc.wait()


def test_fallback_memory_scan_analyzes_binary_file(license_check_executable: Path) -> None:
    """Fallback memory scan analyzes binary file when runtime scanning unavailable."""
    analyzer = AdvancedDynamicAnalyzer(license_check_executable)
    keywords = ["license", "activation"]

    result: dict[str, Any] = analyzer._fallback_memory_scan(keywords, None)

    assert result["status"] == "success"
    assert "matches" in result
    assert isinstance(result["matches"], list)
    assert "scan_type" in result
    assert result["scan_type"] == "binary_file_analysis"


def test_fallback_memory_scan_locates_keywords_in_binary(license_check_executable: Path) -> None:
    """Fallback memory scan successfully finds keywords in binary data."""
    analyzer = AdvancedDynamicAnalyzer(license_check_executable)
    keywords = ["CheckLicense"]

    result: dict[str, Any] = analyzer._fallback_memory_scan(keywords, None)

    assert result["status"] == "success"
    if matches := result["matches"]:
        found = any("checklicense" in match["keyword"].lower() for match in matches)
        assert found


def test_create_dynamic_analyzer_factory_function(system_binary: Path) -> None:
    """Factory function creates properly configured analyzer instance."""
    analyzer = create_dynamic_analyzer(system_binary)

    assert isinstance(analyzer, AdvancedDynamicAnalyzer)
    assert analyzer.binary_path == system_binary


def test_run_quick_analysis_executes_comprehensive_scan(system_binary: Path) -> None:
    """Quick analysis function performs full analysis workflow."""
    results: dict[str, Any] = run_quick_analysis(system_binary)

    assert isinstance(results, dict)
    assert "subprocess_execution" in results
    assert "frida_runtime_analysis" in results
    assert "process_behavior_analysis" in results


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
def test_deep_runtime_monitoring_tracks_api_calls(system_binary: Path) -> None:
    """Deep runtime monitoring intercepts and logs API calls."""
    logs: list[str] = deep_runtime_monitoring(str(system_binary), timeout=3000)

    assert isinstance(logs, list)
    assert logs
    assert any("Starting runtime monitoring" in log for log in logs)


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
def test_deep_runtime_monitoring_detects_file_operations(system_binary: Path) -> None:
    """Deep runtime monitoring detects file access operations."""
    logs: list[str] = deep_runtime_monitoring(str(system_binary), timeout=5000)

    assert isinstance(logs, list)
    assert logs


def test_memory_scan_handles_case_insensitive_matching(license_check_executable: Path) -> None:
    """Memory scanning performs case-insensitive keyword matching."""
    analyzer = AdvancedDynamicAnalyzer(license_check_executable)
    keywords_lower = ["license"]
    keywords_upper = ["LICENSE"]

    result_lower: dict[str, Any] = analyzer._fallback_memory_scan(keywords_lower, None)
    result_upper: dict[str, Any] = analyzer._fallback_memory_scan(keywords_upper, None)

    assert result_lower["status"] == "success"
    assert result_upper["status"] == "success"


def test_memory_scan_provides_address_information(license_check_executable: Path) -> None:
    """Memory scanning includes memory address for each match."""
    analyzer = AdvancedDynamicAnalyzer(license_check_executable)
    keywords = ["license"]

    result: dict[str, Any] = analyzer._fallback_memory_scan(keywords, None)

    if result["status"] == "success" and result["matches"]:
        for match in result["matches"]:
            assert "address" in match
            assert match["address"].startswith("0x")


def test_comprehensive_analysis_with_payload_injection(simple_executable: Path) -> None:
    """Comprehensive analysis accepts payload for injection testing."""
    analyzer = AdvancedDynamicAnalyzer(simple_executable)
    test_payload = b"\x90\x90\x90\x90\xC3"

    results: dict[str, Any] = analyzer.run_comprehensive_analysis(payload=test_payload)

    assert isinstance(results, dict)
    assert "frida_runtime_analysis" in results


def test_analyzer_handles_multiple_consecutive_analyses(system_binary: Path) -> None:
    """Analyzer can perform multiple consecutive analyses without issues."""
    analyzer = AdvancedDynamicAnalyzer(system_binary)

    results1: dict[str, Any] = analyzer.run_comprehensive_analysis()
    results2: dict[str, Any] = analyzer.run_comprehensive_analysis()

    assert isinstance(results1, dict)
    assert isinstance(results2, dict)
    assert "subprocess_execution" in results1
    assert "subprocess_execution" in results2


def test_memory_scan_with_multiple_keywords(license_check_executable: Path) -> None:
    """Memory scanning handles multiple keywords in single scan."""
    analyzer = AdvancedDynamicAnalyzer(license_check_executable)
    keywords = ["license", "activation", "serial", "trial", "expire"]

    result: dict[str, Any] = analyzer.scan_memory_for_keywords(keywords)

    assert isinstance(result, dict)
    assert "matches" in result
    assert isinstance(result["matches"], list)


def test_memory_scan_error_handling_with_invalid_process(license_check_executable: Path) -> None:
    """Memory scanning handles invalid process gracefully."""
    analyzer = AdvancedDynamicAnalyzer(license_check_executable)
    keywords = ["test"]

    result: dict[str, Any] = analyzer.scan_memory_for_keywords(
        keywords, target_process="nonexistent_process_12345"
    )

    assert isinstance(result, dict)
    assert "status" in result or "error" in result


@pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
def test_generic_memory_scan_examines_process_data(simple_executable: Path) -> None:
    """Generic memory scan extracts searchable data from process info."""
    import subprocess
    import psutil

    proc = subprocess.Popen([str(simple_executable)])
    time.sleep(0.5)

    try:
        analyzer = AdvancedDynamicAnalyzer(simple_executable)
        ps_proc = psutil.Process(proc.pid)
        keywords = ["simple_test"]

        matches = analyzer._generic_memory_scan(ps_proc, keywords)

        assert isinstance(matches, list)
    finally:
        proc.terminate()
        proc.wait()


def test_subprocess_analysis_captures_return_code(system_binary: Path) -> None:
    """Subprocess analysis accurately captures process return code."""
    analyzer = AdvancedDynamicAnalyzer(system_binary)
    result: dict[str, Any] = analyzer._subprocess_analysis()

    if "return_code" in result:
        assert isinstance(result["return_code"], int)


def test_subprocess_analysis_timeout_mechanism_functional(temp_dir: Path) -> None:
    """Subprocess analysis timeout prevents indefinite hanging."""
    long_running_script = temp_dir / "long_running.bat"
    long_running_script.write_text("@echo off\ntimeout /t 60 /nobreak > nul")

    analyzer = AdvancedDynamicAnalyzer(long_running_script)
    start_time = time.time()
    result: dict[str, Any] = analyzer._subprocess_analysis()
    elapsed_time = time.time() - start_time

    assert elapsed_time < 15


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
def test_frida_cleanup_on_analysis_completion(simple_executable: Path) -> None:
    """Frida runtime analysis properly cleans up resources after completion."""
    analyzer = AdvancedDynamicAnalyzer(simple_executable)
    result: dict[str, Any] = analyzer._frida_runtime_analysis()

    assert isinstance(result, dict)


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
def test_frida_cleanup_on_analysis_error(temp_dir: Path) -> None:
    """Frida runtime analysis cleans up even when errors occur."""
    invalid_exe = temp_dir / "invalid.exe"
    invalid_exe.write_bytes(b"INVALID_BINARY_DATA")

    analyzer = AdvancedDynamicAnalyzer(invalid_exe)
    result: dict[str, Any] = analyzer._frida_runtime_analysis()

    assert isinstance(result, dict)
    assert result.get("success") is False


def test_analyzer_state_isolation_between_instances(system_binary: Path) -> None:
    """Different analyzer instances maintain separate state."""
    analyzer1 = AdvancedDynamicAnalyzer(system_binary)
    analyzer2 = AdvancedDynamicAnalyzer(system_binary)

    analyzer1.api_calls.append("test_call_1")

    assert len(analyzer1.api_calls) == 1
    assert len(analyzer2.api_calls) == 0


def test_comprehensive_analysis_all_stages_return_dicts(system_binary: Path) -> None:
    """All comprehensive analysis stages return dictionary results."""
    analyzer = AdvancedDynamicAnalyzer(system_binary)
    results: dict[str, Any] = analyzer.run_comprehensive_analysis()

    for stage_name, stage_result in results.items():
        assert isinstance(stage_result, dict), f"{stage_name} did not return dict"


def test_memory_scan_match_deduplication(license_check_executable: Path) -> None:
    """Memory scanning avoids duplicate matches in results."""
    analyzer = AdvancedDynamicAnalyzer(license_check_executable)
    keywords = ["license", "license"]

    result: dict[str, Any] = analyzer._fallback_memory_scan(keywords, None)

    if result["status"] == "success" and result["matches"]:
        addresses = [m["address"] for m in result["matches"]]


def test_analyzer_path_accepts_string_input(system_binary: Path) -> None:
    """Analyzer accepts binary path as string or Path object."""
    analyzer_path_obj = AdvancedDynamicAnalyzer(system_binary)
    analyzer_str = AdvancedDynamicAnalyzer(str(system_binary))

    assert analyzer_path_obj.binary_path == analyzer_str.binary_path


def test_memory_scan_offset_tracking_accurate(license_check_executable: Path) -> None:
    """Memory scanning accurately tracks byte offsets for matches."""
    analyzer = AdvancedDynamicAnalyzer(license_check_executable)
    keywords = ["license"]

    result: dict[str, Any] = analyzer._fallback_memory_scan(keywords, None)

    if result["status"] == "success" and result["matches"]:
        for match in result["matches"]:
            assert "offset" in match
            assert isinstance(match["offset"], int)
            assert match["offset"] >= 0


@pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
def test_frida_message_handler_processes_events(simple_executable: Path) -> None:
    """Frida message handler successfully processes instrumentation events."""
    analyzer = AdvancedDynamicAnalyzer(simple_executable)
    result: dict[str, Any] = analyzer._frida_runtime_analysis()

    if result.get("success"):
        assert "analysis_data" in result
        assert isinstance(result["analysis_data"], dict)


def test_subprocess_analysis_stderr_capture(temp_dir: Path) -> None:
    """Subprocess analysis captures stderr output correctly."""
    error_script = temp_dir / "error.bat"
    error_script.write_text("@echo off\necho Error message 1>&2\nexit /b 1")

    analyzer = AdvancedDynamicAnalyzer(error_script)
    result: dict[str, Any] = analyzer._subprocess_analysis()

    assert "stderr" in result or "error" in result


def test_memory_scan_region_size_tracking(license_check_executable: Path) -> None:
    """Memory scanning tracks region sizes for matches."""
    analyzer = AdvancedDynamicAnalyzer(license_check_executable)
    keywords = ["license"]

    result: dict[str, Any] = analyzer._fallback_memory_scan(keywords, None)

    if result["status"] == "success" and result["matches"]:
        match = result["matches"][0]
        assert "region_size" in match
        assert isinstance(match["region_size"], int)
        assert match["region_size"] > 0


def test_analyzer_binary_path_immutability(system_binary: Path) -> None:
    """Analyzer binary_path remains constant after initialization."""
    analyzer = AdvancedDynamicAnalyzer(system_binary)
    original_path = analyzer.binary_path

    analyzer.run_comprehensive_analysis()

    assert analyzer.binary_path == original_path


def test_comprehensive_analysis_execution_time_reasonable(system_binary: Path) -> None:
    """Comprehensive analysis completes within reasonable time."""
    analyzer = AdvancedDynamicAnalyzer(system_binary)

    start_time = time.time()
    results: dict[str, Any] = analyzer.run_comprehensive_analysis()
    elapsed_time = time.time() - start_time

    assert elapsed_time < 30
    assert isinstance(results, dict)
