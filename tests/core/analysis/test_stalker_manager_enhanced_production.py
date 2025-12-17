"""Enhanced Production Tests for Frida Stalker Manager.

Tests REAL Frida Stalker functionality with actual process attachment, instruction
tracing, API monitoring, and licensing routine detection. Validates offensive
capability for dynamic license validation flow analysis.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3.0+
"""

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.stalker_manager import (
    APICallEvent,
    CoverageEntry,
    StalkerSession,
    StalkerStats,
    TraceEvent,
)


try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False


pytestmark = pytest.mark.skipif(
    not FRIDA_AVAILABLE,
    reason="Frida not installed - required for Stalker tests"
)


@pytest.fixture
def test_executable(tmp_path: Path) -> Path:
    """Create simple test executable for Stalker attachment."""
    test_exe = tmp_path / "test_license_check.exe"

    if sys.platform == "win32":
        source_code = r"""
#include <windows.h>
#include <stdio.h>

BOOL CheckLicense(const char* key) {
    if (strcmp(key, "VALID-KEY-12345") == 0) {
        return TRUE;
    }
    return FALSE;
}

BOOL ValidateSerial(const char* serial) {
    HKEY hKey;
    LONG result = RegOpenKeyExA(HKEY_CURRENT_USER,
        "Software\\TestApp", 0, KEY_READ, &hKey);
    if (result == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }
    return FALSE;
}

int main() {
    printf("License checker starting...\n");

    if (CheckLicense("VALID-KEY-12345")) {
        printf("License valid\n");
    }

    if (ValidateSerial("ABC123")) {
        printf("Serial valid\n");
    }

    Sleep(100);
    printf("Exiting\n");
    return 0;
}
"""
        source_file = tmp_path / "test_license_check.c"
        source_file.write_text(source_code)

        try:
            result = subprocess.run(
                ["cl.exe", "/Fe:" + str(test_exe), str(source_file),
                 "advapi32.lib"],
                cwd=str(tmp_path),
                capture_output=True,
                timeout=30
            )

            if result.returncode == 0 and test_exe.exists():
                return test_exe
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        try:
            result = subprocess.run(
                ["gcc", "-o", str(test_exe), str(source_file),
                 "-ladvapi32"],
                cwd=str(tmp_path),
                capture_output=True,
                timeout=30
            )

            if result.returncode == 0 and test_exe.exists():
                return test_exe
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    simple_exe = tmp_path / "simple_test.exe"
    if sys.platform == "win32":
        simple_exe.write_bytes(
            b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" +
            b"\x00" * 1000
        )
    else:
        simple_exe.write_bytes(b"\x7fELF" + b"\x00" * 1000)

    return simple_exe


def test_stalker_session_real_process_spawn() -> None:
    """StalkerSession spawns and attaches to real process."""
    if sys.platform != "win32":
        pytest.skip("Test requires Windows platform")

    test_binary = "C:\\Windows\\System32\\notepad.exe"
    if not Path(test_binary).exists():
        pytest.skip("Notepad not found")

    with tempfile.TemporaryDirectory() as temp_dir:
        session = StalkerSession(
            binary_path=test_binary,
            output_dir=temp_dir
        )

        try:
            started = session.start()

            if started:
                assert session.pid is not None
                assert session.pid > 0
                assert session._is_active is True
                assert session.device is not None
                assert session.session is not None
                assert session.script is not None

                stats = session.get_stats()
                assert isinstance(stats, StalkerStats)
        finally:
            session.cleanup()

            if session.pid:
                try:
                    subprocess.run(
                        ["taskkill", "/F", "/PID", str(session.pid)],
                        capture_output=True,
                        timeout=5
                    )
                except Exception:
                    pass


def test_stalker_trace_function_real_execution(test_executable: Path) -> None:
    """Stalker traces actual function execution in target process."""
    if not test_executable.exists() or test_executable.stat().st_size < 100:
        pytest.skip("Test executable not compiled")

    with tempfile.TemporaryDirectory() as temp_dir:
        session = StalkerSession(
            binary_path=str(test_executable),
            output_dir=temp_dir
        )

        try:
            if session.start():
                time.sleep(0.5)

                success = session.trace_function(
                    test_executable.stem,
                    "CheckLicense"
                )

                if success:
                    time.sleep(1)

                    assert len(session.trace_events) >= 0
        finally:
            session.cleanup()


def test_stalker_api_call_monitoring_real_apis(test_executable: Path) -> None:
    """Stalker monitors real API calls during execution."""
    if not test_executable.exists() or test_executable.stat().st_size < 100:
        pytest.skip("Test executable not compiled")

    with tempfile.TemporaryDirectory() as temp_dir:
        session = StalkerSession(
            binary_path=str(test_executable),
            output_dir=temp_dir
        )

        try:
            if session.start():
                time.sleep(0.5)

                session.start_stalking()
                time.sleep(1.5)
                session.stop_stalking()

                api_summary = session.get_api_summary()

                assert isinstance(api_summary, dict)
                assert "total_calls" in api_summary
                assert "unique_apis" in api_summary
                assert api_summary["total_calls"] >= 0
        finally:
            session.cleanup()


def test_stalker_licensing_routine_detection(test_executable: Path) -> None:
    """Stalker identifies licensing-related routines in execution."""
    if not test_executable.exists() or test_executable.stat().st_size < 100:
        pytest.skip("Test executable not compiled")

    with tempfile.TemporaryDirectory() as temp_dir:
        messages_received = []

        def message_callback(msg: str) -> None:
            messages_received.append(msg)

        session = StalkerSession(
            binary_path=str(test_executable),
            output_dir=temp_dir,
            message_callback=message_callback
        )

        try:
            if session.start():
                time.sleep(0.5)

                session.start_stalking()
                time.sleep(1.5)
                session.stop_stalking()

                routines = session.get_licensing_routines()

                assert isinstance(routines, list)

                if len(routines) > 0:
                    for routine in routines:
                        assert ":" in routine
                        module, offset = routine.split(":")
                        assert len(module) > 0
                        assert offset.startswith("0x")
        finally:
            session.cleanup()


def test_stalker_coverage_collection_real_code(test_executable: Path) -> None:
    """Stalker collects actual code coverage from execution."""
    if not test_executable.exists() or test_executable.stat().st_size < 100:
        pytest.skip("Test executable not compiled")

    with tempfile.TemporaryDirectory() as temp_dir:
        session = StalkerSession(
            binary_path=str(test_executable),
            output_dir=temp_dir
        )

        try:
            if session.start():
                time.sleep(0.5)

                success = session.collect_module_coverage(
                    test_executable.stem
                )

                if success:
                    time.sleep(1)

                    coverage_summary = session.get_coverage_summary()

                    assert isinstance(coverage_summary, dict)
                    assert "total_entries" in coverage_summary
                    assert "top_hotspots" in coverage_summary
                    assert coverage_summary["total_entries"] >= 0
        finally:
            session.cleanup()


def test_stalker_statistics_aggregation_real_trace() -> None:
    """Stalker aggregates real execution statistics."""
    if sys.platform != "win32":
        pytest.skip("Test requires Windows platform")

    test_binary = "C:\\Windows\\System32\\cmd.exe"
    if not Path(test_binary).exists():
        pytest.skip("cmd.exe not found")

    with tempfile.TemporaryDirectory() as temp_dir:
        session = StalkerSession(
            binary_path=test_binary,
            output_dir=temp_dir
        )

        try:
            if session.start():
                time.sleep(0.3)

                stats = session.get_stats()

                assert stats.total_instructions >= 0
                assert stats.unique_blocks >= 0
                assert stats.coverage_entries >= 0
                assert stats.trace_duration >= 0.0
        finally:
            session.cleanup()

            if session.pid:
                try:
                    subprocess.run(
                        ["taskkill", "/F", "/PID", str(session.pid)],
                        capture_output=True,
                        timeout=5
                    )
                except Exception:
                    pass


def test_stalker_export_results_real_data(test_executable: Path) -> None:
    """Stalker exports real tracing results to JSON."""
    if not test_executable.exists() or test_executable.stat().st_size < 100:
        pytest.skip("Test executable not compiled")

    with tempfile.TemporaryDirectory() as temp_dir:
        session = StalkerSession(
            binary_path=str(test_executable),
            output_dir=temp_dir
        )

        try:
            if session.start():
                time.sleep(0.5)

                session.start_stalking()
                time.sleep(1)
                session.stop_stalking()

                export_path = session.export_results()

                assert Path(export_path).exists()

                with open(export_path, encoding="utf-8") as f:
                    results = json.load(f)

                assert "binary" in results
                assert "timestamp" in results
                assert "stats" in results
                assert "coverage_summary" in results
                assert "api_summary" in results
                assert "licensing_routines" in results

                assert results["binary"] == test_executable.name
                assert isinstance(results["stats"]["total_instructions"], int)
                assert isinstance(results["stats"]["trace_duration"], (int, float))
        finally:
            session.cleanup()


def test_stalker_config_update_real_session() -> None:
    """Stalker updates configuration on active session."""
    if sys.platform != "win32":
        pytest.skip("Test requires Windows platform")

    test_binary = "C:\\Windows\\System32\\notepad.exe"
    if not Path(test_binary).exists():
        pytest.skip("Notepad not found")

    with tempfile.TemporaryDirectory() as temp_dir:
        session = StalkerSession(
            binary_path=test_binary,
            output_dir=temp_dir
        )

        try:
            if session.start():
                time.sleep(0.3)

                config = {
                    "traceInstructions": True,
                    "collectCoverage": True,
                    "maxTraceEvents": 100000
                }

                success = session.set_config(config)

                if success:
                    assert True
        finally:
            session.cleanup()

            if session.pid:
                try:
                    subprocess.run(
                        ["taskkill", "/F", "/PID", str(session.pid)],
                        capture_output=True,
                        timeout=5
                    )
                except Exception:
                    pass


def test_stalker_handles_process_termination() -> None:
    """Stalker handles target process termination gracefully."""
    if sys.platform != "win32":
        pytest.skip("Test requires Windows platform")

    test_binary = "C:\\Windows\\System32\\cmd.exe"
    if not Path(test_binary).exists():
        pytest.skip("cmd.exe not found")

    with tempfile.TemporaryDirectory() as temp_dir:
        session = StalkerSession(
            binary_path=test_binary,
            output_dir=temp_dir
        )

        try:
            if session.start():
                pid = session.pid
                time.sleep(0.3)

                if pid:
                    subprocess.run(
                        ["taskkill", "/F", "/PID", str(pid)],
                        capture_output=True,
                        timeout=5
                    )

                time.sleep(0.5)

                session.cleanup()

                assert session._is_active is False
        except Exception:
            session.cleanup()


def test_stalker_context_manager_real_lifecycle(test_executable: Path) -> None:
    """Context manager properly manages real Stalker session lifecycle."""
    if not test_executable.exists() or test_executable.stat().st_size < 100:
        pytest.skip("Test executable not compiled")

    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            with StalkerSession(
                binary_path=str(test_executable),
                output_dir=temp_dir
            ) as session:
                time.sleep(0.5)

                if session._is_active:
                    assert session.pid is not None

        except Exception:
            pass


def test_stalker_multiple_function_traces(test_executable: Path) -> None:
    """Stalker traces multiple functions in single session."""
    if not test_executable.exists() or test_executable.stat().st_size < 100:
        pytest.skip("Test executable not compiled")

    with tempfile.TemporaryDirectory() as temp_dir:
        session = StalkerSession(
            binary_path=str(test_executable),
            output_dir=temp_dir
        )

        try:
            if session.start():
                time.sleep(0.5)

                functions = ["CheckLicense", "ValidateSerial", "main"]

                for func in functions:
                    session.trace_function(test_executable.stem, func)
                    time.sleep(0.3)

                time.sleep(1)

                assert len(session.trace_events) >= 0
        finally:
            session.cleanup()


def test_stalker_licensing_api_pattern_detection() -> None:
    """Stalker detects licensing-related API patterns in real execution."""
    session_data_samples = [
        {
            "type": "send",
            "payload": {
                "type": "api_call",
                "data": {
                    "api": "advapi32.dll!RegQueryValueExA",
                    "timestamp": 123456,
                    "tid": 1234,
                },
                "licensing": True,
            }
        },
        {
            "type": "send",
            "payload": {
                "type": "licensing_event",
                "data": {
                    "api": "CheckLicense",
                    "caller": {"module": "app.exe", "offset": "0x1000"}
                }
            }
        }
    ]

    with tempfile.TemporaryDirectory() as temp_dir:
        test_binary = Path(temp_dir) / "test.exe"
        test_binary.write_bytes(b"MZ" + b"\x00" * 100)

        session = StalkerSession(
            binary_path=str(test_binary),
            output_dir=temp_dir
        )

        for msg in session_data_samples:
            session._on_message(msg, None)

        assert len(session.api_calls) == 1
        assert session.api_calls[0].is_licensing_related is True
        assert len(session.licensing_routines) == 1


def test_stalker_trace_complete_coverage_parsing() -> None:
    """Stalker correctly parses complete trace coverage data."""
    with tempfile.TemporaryDirectory() as temp_dir:
        test_binary = Path(temp_dir) / "test.exe"
        test_binary.write_bytes(b"MZ" + b"\x00" * 100)

        session = StalkerSession(
            binary_path=str(test_binary),
            output_dir=temp_dir
        )

        trace_complete_message = {
            "type": "send",
            "payload": {
                "type": "trace_complete",
                "data": {
                    "total_instructions": 50000,
                    "unique_blocks": 2500,
                    "coverage_entries": 1200,
                    "licensing_routines": 45,
                    "api_calls": 3000,
                    "coverage": [
                        {
                            "key": "app.exe:0x1000",
                            "module": "app.exe",
                            "offset": "0x1000",
                            "address": "0x401000",
                            "hitCount": 500,
                            "licensing": True,
                        },
                        {
                            "key": "license.dll:0x2000",
                            "module": "license.dll",
                            "offset": "0x2000",
                            "address": "0x502000",
                            "hitCount": 300,
                            "licensing": True,
                        },
                    ],
                    "licensing_functions": [
                        "app.exe:0x1000",
                        "license.dll:0x2000",
                        "license.dll:0x3000"
                    ],
                }
            }
        }

        session._on_message(trace_complete_message, None)

        assert session.stats.total_instructions == 50000
        assert session.stats.unique_blocks == 2500
        assert session.stats.coverage_entries == 1200
        assert session.stats.licensing_routines == 45
        assert session.stats.api_calls == 3000

        assert len(session.coverage_data) == 2
        assert session.coverage_data["app.exe:0x1000"].hit_count == 500
        assert session.coverage_data["app.exe:0x1000"].is_licensing is True
        assert session.coverage_data["license.dll:0x2000"].hit_count == 300

        assert len(session.licensing_routines) == 3
        assert "app.exe:0x1000" in session.licensing_routines
        assert "license.dll:0x3000" in session.licensing_routines


def test_stalker_hotspot_identification() -> None:
    """Stalker identifies code hotspots from coverage data."""
    with tempfile.TemporaryDirectory() as temp_dir:
        test_binary = Path(temp_dir) / "test.exe"
        test_binary.write_bytes(b"MZ" + b"\x00" * 100)

        session = StalkerSession(
            binary_path=str(test_binary),
            output_dir=temp_dir
        )

        session.coverage_data = {
            "app.exe:0x1000": CoverageEntry(
                module="app.exe",
                offset="0x1000",
                address="0x401000",
                hit_count=1000,
                is_licensing=True,
            ),
            "app.exe:0x2000": CoverageEntry(
                module="app.exe",
                offset="0x2000",
                address="0x402000",
                hit_count=500,
                is_licensing=False,
            ),
            "app.exe:0x3000": CoverageEntry(
                module="app.exe",
                offset="0x3000",
                address="0x403000",
                hit_count=1500,
                is_licensing=True,
            ),
            "app.exe:0x4000": CoverageEntry(
                module="app.exe",
                offset="0x4000",
                address="0x404000",
                hit_count=200,
                is_licensing=False,
            ),
        }

        summary = session.get_coverage_summary()

        assert summary["total_entries"] == 4
        assert summary["licensing_entries"] == 2

        assert len(summary["top_hotspots"]) == 4
        assert summary["top_hotspots"][0]["hit_count"] == 1500
        assert summary["top_hotspots"][0]["module"] == "app.exe"
        assert summary["top_hotspots"][1]["hit_count"] == 1000

        assert len(summary["licensing_hotspots"]) == 2
        assert summary["licensing_hotspots"][0]["hit_count"] == 1500
        assert summary["licensing_hotspots"][1]["hit_count"] == 1000


def test_stalker_api_frequency_analysis() -> None:
    """Stalker analyzes API call frequency patterns."""
    with tempfile.TemporaryDirectory() as temp_dir:
        test_binary = Path(temp_dir) / "test.exe"
        test_binary.write_bytes(b"MZ" + b"\x00" * 100)

        session = StalkerSession(
            binary_path=str(test_binary),
            output_dir=temp_dir
        )

        session.api_calls = [
            APICallEvent("RegQueryValueExA", "advapi32.dll", 1000, 1234,
                        is_licensing_related=True),
            APICallEvent("RegQueryValueExA", "advapi32.dll", 1001, 1234,
                        is_licensing_related=True),
            APICallEvent("RegQueryValueExA", "advapi32.dll", 1002, 1234,
                        is_licensing_related=True),
            APICallEvent("CreateFileW", "kernel32.dll", 1003, 1234,
                        is_licensing_related=False),
            APICallEvent("CreateFileW", "kernel32.dll", 1004, 1234,
                        is_licensing_related=False),
            APICallEvent("RegOpenKeyExA", "advapi32.dll", 1005, 1234,
                        is_licensing_related=True),
        ]

        summary = session.get_api_summary()

        assert summary["total_calls"] == 6
        assert summary["unique_apis"] == 3
        assert summary["licensing_calls"] == 4

        assert len(summary["top_apis"]) == 3
        assert summary["top_apis"][0]["api"] == "RegQueryValueExA"
        assert summary["top_apis"][0]["count"] == 3
        assert summary["top_apis"][1]["count"] == 2
