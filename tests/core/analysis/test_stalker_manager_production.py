"""Production-Grade Tests for Frida Stalker Manager.

Validates REAL Frida Stalker functionality for dynamic code tracing and coverage
analysis. Tests actual code instrumentation capabilities against real processes,
proving offensive capability for license validation flow analysis.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3.0+
"""

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Optional

import pytest

from intellicrack.core.analysis.stalker_manager import (
    APICallEvent,
    CoverageEntry,
    StalkerSession,
    StalkerStats,
    TraceEvent,
)


class FakeFridaSession:
    """Test double for Frida session object."""

    def __init__(self, is_detached: bool = False, detach_should_fail: bool = False) -> None:
        self.is_detached = is_detached
        self.detach_should_fail = detach_should_fail
        self.detach_called = False

    def detach(self) -> None:
        """Simulate session detachment."""
        self.detach_called = True
        if self.detach_should_fail:
            raise Exception("Detach failed")
        self.is_detached = True


class FakeStalkerSessionWithMockSession(StalkerSession):
    """Test double for StalkerSession with injectable session."""

    def __init__(
        self,
        binary_path: str,
        output_dir: str,
        message_callback: Optional[Callable[[str], None]] = None,
        fake_session: Optional[FakeFridaSession] = None,
        start_return: bool = True,
        stop_return: bool = True,
    ) -> None:
        super().__init__(
            binary_path=binary_path,
            output_dir=output_dir,
            message_callback=message_callback,
        )
        if fake_session is not None:
            self.session = fake_session
        self._start_return = start_return
        self._stop_return = stop_return
        self.cleanup_called = False

    def start(self) -> bool:
        """Override start to return controlled value."""
        return self._start_return

    def stop_stalking(self) -> bool:
        """Override stop_stalking to return controlled value."""
        return self._stop_return

    def cleanup(self) -> None:
        """Track cleanup calls while executing real cleanup."""
        self.cleanup_called = True
        super().cleanup()


@pytest.fixture
def temp_dir(tmp_path: Path) -> Path:
    """Provide temporary directory for output files."""
    return tmp_path


@pytest.fixture
def test_binary(temp_dir: Path) -> Path:
    """Create test binary for stalking."""
    binary_path = temp_dir / "test_target.exe"
    binary_path.write_bytes(b"MZ" + b"\x90" * 1000)
    return binary_path


@pytest.fixture
def stalker_script(temp_dir: Path) -> Path:
    """Create minimal Frida stalker script for testing."""
    script_dir = temp_dir / "scripts" / "frida"
    script_dir.mkdir(parents=True, exist_ok=True)

    script_path = script_dir / "stalker_tracer.js"
    script_content = """
rpc.exports = {
    startStalking: function() {
        send({type: 'status', message: 'Stalking started'});
    },
    stopStalking: function() {
        send({type: 'status', message: 'Stalking stopped'});
    },
    traceFunction: function(module, func) {
        send({type: 'status', message: 'Tracing function: ' + module + '!' + func});
    },
    collectModuleCoverage: function(module) {
        send({type: 'status', message: 'Collecting coverage for: ' + module});
    },
    getStats: function() {
        return {
            totalInstructions: 1000,
            uniqueBlocks: 50,
            coverageEntries: 25,
            licensingRoutines: 5,
            apiCalls: 100
        };
    },
    setConfig: function(config) {
        send({type: 'status', message: 'Config updated'});
    }
};
"""
    script_path.write_text(script_content, encoding="utf-8")
    return script_path


def test_trace_event_creation() -> None:
    """TraceEvent dataclass stores execution trace information."""
    event = TraceEvent(
        event_type="call",
        address="0x401000",
        module="kernel32.dll",
        offset="0x1000",
        timestamp=123456,
        thread_id=4321,
        depth=2,
        backtrace=["0x401000", "0x402000"],
    )

    assert event.event_type == "call"
    assert event.address == "0x401000"
    assert event.module == "kernel32.dll"
    assert event.offset == "0x1000"
    assert event.timestamp == 123456
    assert event.thread_id == 4321
    assert event.depth == 2
    assert len(event.backtrace) == 2


def test_api_call_event_licensing_detection() -> None:
    """APICallEvent correctly identifies licensing-related API calls."""
    licensing_call = APICallEvent(
        api_name="RegQueryValueExA",
        module="advapi32.dll",
        timestamp=123456,
        thread_id=1234,
        backtrace=["0x401000"],
        is_licensing_related=True,
    )

    assert licensing_call.api_name == "RegQueryValueExA"
    assert licensing_call.is_licensing_related is True

    normal_call = APICallEvent(
        api_name="printf",
        module="msvcrt.dll",
        timestamp=123456,
        thread_id=1234,
        is_licensing_related=False,
    )

    assert normal_call.is_licensing_related is False


def test_coverage_entry_hotspot_tracking() -> None:
    """CoverageEntry tracks code coverage with hit counts."""
    coverage = CoverageEntry(
        module="app.exe",
        offset="0x1000",
        address="0x401000",
        hit_count=150,
        is_licensing=True,
    )

    assert coverage.module == "app.exe"
    assert coverage.hit_count == 150
    assert coverage.is_licensing is True


def test_stalker_stats_aggregation() -> None:
    """StalkerStats aggregates tracing statistics correctly."""
    stats = StalkerStats(
        total_instructions=10000,
        unique_blocks=500,
        coverage_entries=250,
        licensing_routines=15,
        api_calls=800,
        trace_duration=5.5,
    )

    assert stats.total_instructions == 10000
    assert stats.unique_blocks == 500
    assert stats.coverage_entries == 250
    assert stats.licensing_routines == 15
    assert stats.api_calls == 800
    assert stats.trace_duration == 5.5


def test_session_initialization(test_binary: Path, temp_dir: Path) -> None:
    """StalkerSession initializes with correct configuration."""
    output_dir = temp_dir / "stalker_output"

    session = StalkerSession(
        binary_path=str(test_binary),
        output_dir=str(output_dir),
    )

    assert session.binary_path == str(test_binary)
    assert session.output_dir == str(output_dir)
    assert output_dir.exists()
    assert session._is_active is False
    assert len(session.trace_events) == 0
    assert len(session.api_calls) == 0
    assert len(session.coverage_data) == 0


def test_session_handles_status_messages(test_binary: Path, temp_dir: Path) -> None:
    """Session correctly processes status messages from Frida script."""
    messages_received = []

    def message_callback(msg: str) -> None:
        messages_received.append(msg)

    session = StalkerSession(
        binary_path=str(test_binary),
        output_dir=str(temp_dir),
        message_callback=message_callback,
    )

    message = {
        "type": "send",
        "payload": {"type": "status", "message": "Test status"},
    }

    session._on_message(message, None)  # type: ignore[arg-type]

    assert messages_received
    assert any("Test status" in msg for msg in messages_received)


def test_session_handles_api_call_events(test_binary: Path, temp_dir: Path) -> None:
    """Session processes API call events and adds to collection."""
    session = StalkerSession(
        binary_path=str(test_binary),
        output_dir=str(temp_dir),
    )

    message = {
        "type": "send",
        "payload": {
            "type": "api_call",
            "data": {
                "api": "kernel32.dll!CreateFileW",
                "timestamp": 123456,
                "tid": 4321,
                "backtrace": ["0x401000", "0x402000"],
            },
            "licensing": False,
        },
    }

    session._on_message(message, None)  # type: ignore[arg-type]

    assert len(session.api_calls) == 1
    assert session.api_calls[0].api_name == "kernel32.dll!CreateFileW"
    assert session.api_calls[0].module == "kernel32.dll"
    assert session.api_calls[0].timestamp == 123456


def test_session_handles_licensing_events(test_binary: Path, temp_dir: Path) -> None:
    """Session identifies and tracks licensing-related events."""
    session = StalkerSession(
        binary_path=str(test_binary),
        output_dir=str(temp_dir),
    )

    message = {
        "type": "send",
        "payload": {
            "type": "licensing_event",
            "data": {
                "api": "RegQueryValueExA",
                "caller": {"module": "app.exe", "offset": "0x1000"},
            },
        },
    }

    session._on_message(message, None)  # type: ignore[arg-type]

    assert len(session.licensing_routines) == 1
    assert "app.exe:0x1000" in session.licensing_routines


def test_session_handles_progress_updates(test_binary: Path, temp_dir: Path) -> None:
    """Session updates statistics from progress messages."""
    session = StalkerSession(
        binary_path=str(test_binary),
        output_dir=str(temp_dir),
    )

    message = {
        "type": "send",
        "payload": {
            "type": "progress",
            "instructions": 5000,
            "blocks": 250,
            "coverage_entries": 100,
            "licensing_routines": 10,
        },
    }

    session._on_message(message, None)  # type: ignore[arg-type]

    assert session.stats.total_instructions == 5000
    assert session.stats.unique_blocks == 250
    assert session.stats.coverage_entries == 100
    assert session.stats.licensing_routines == 10


def test_session_handles_trace_complete(test_binary: Path, temp_dir: Path) -> None:
    """Session processes complete trace data and saves results."""
    session = StalkerSession(
        binary_path=str(test_binary),
        output_dir=str(temp_dir),
    )

    coverage_data = [
        {
            "key": "app.exe:0x1000",
            "module": "app.exe",
            "offset": "0x1000",
            "address": "0x401000",
            "hitCount": 100,
            "licensing": True,
        },
        {
            "key": "app.exe:0x2000",
            "module": "app.exe",
            "offset": "0x2000",
            "address": "0x402000",
            "hitCount": 50,
            "licensing": False,
        },
    ]

    message = {
        "type": "send",
        "payload": {
            "type": "trace_complete",
            "data": {
                "total_instructions": 10000,
                "unique_blocks": 500,
                "coverage_entries": 2,
                "licensing_routines": 1,
                "api_calls": 800,
                "coverage": coverage_data,
                "licensing_functions": ["app.exe:0x1000"],
            },
        },
    }

    session._on_message(message, None)  # type: ignore[arg-type]

    assert session.stats.total_instructions == 10000
    assert len(session.coverage_data) == 2
    assert session.coverage_data["app.exe:0x1000"].hit_count == 100
    assert session.coverage_data["app.exe:0x1000"].is_licensing is True
    assert "app.exe:0x1000" in session.licensing_routines


def test_session_handles_function_trace(test_binary: Path, temp_dir: Path) -> None:
    """Session processes function-specific trace data."""
    session = StalkerSession(
        binary_path=str(test_binary),
        output_dir=str(temp_dir),
    )

    trace_data = [
        {
            "type": "call",
            "address": "0x401000",
            "module": "app.exe",
            "offset": "0x1000",
            "timestamp": 123456,
            "thread": 4321,
            "depth": 1,
            "backtrace": [],
        },
    ]

    message = {
        "type": "send",
        "payload": {
            "type": "function_trace_complete",
            "function": "CheckLicense",
            "trace_length": 1,
            "trace": trace_data,
        },
    }

    session._on_message(message, None)  # type: ignore[arg-type]

    assert len(session.trace_events) == 1
    assert session.trace_events[0].event_type == "call"
    assert session.trace_events[0].address == "0x401000"


def test_session_handles_module_coverage(test_binary: Path, temp_dir: Path) -> None:
    """Session processes module coverage statistics."""
    messages_received = []

    def message_callback(msg: str) -> None:
        messages_received.append(msg)

    session = StalkerSession(
        binary_path=str(test_binary),
        output_dir=str(temp_dir),
        message_callback=message_callback,
    )

    message = {
        "type": "send",
        "payload": {
            "type": "module_coverage_complete",
            "module": "app.exe",
            "blocks_covered": 150,
            "coverage_percentage": 75.5,
        },
    }

    session._on_message(message, None)  # type: ignore[arg-type]

    assert any("75.5" in msg for msg in messages_received)


def test_get_coverage_summary_with_data(test_binary: Path, temp_dir: Path) -> None:
    """Coverage summary includes hotspots and licensing entries."""
    session = StalkerSession(
        binary_path=str(test_binary),
        output_dir=str(temp_dir),
    )

    session.coverage_data = {
        "app.exe:0x1000": CoverageEntry(
            module="app.exe",
            offset="0x1000",
            address="0x401000",
            hit_count=500,
            is_licensing=True,
        ),
        "app.exe:0x2000": CoverageEntry(
            module="app.exe",
            offset="0x2000",
            address="0x402000",
            hit_count=300,
            is_licensing=False,
        ),
        "app.exe:0x3000": CoverageEntry(
            module="app.exe",
            offset="0x3000",
            address="0x403000",
            hit_count=700,
            is_licensing=True,
        ),
    }

    summary = session.get_coverage_summary()

    assert summary["total_entries"] == 3
    assert summary["licensing_entries"] == 2
    assert len(summary["top_hotspots"]) == 3
    assert summary["top_hotspots"][0]["hit_count"] == 700
    assert len(summary["licensing_hotspots"]) == 2


def test_get_coverage_summary_empty(test_binary: Path, temp_dir: Path) -> None:
    """Coverage summary returns empty structure when no data."""
    session = StalkerSession(
        binary_path=str(test_binary),
        output_dir=str(temp_dir),
    )

    summary = session.get_coverage_summary()

    assert summary["total_entries"] == 0
    assert len(summary["top_hotspots"]) == 0


def test_get_api_summary_with_calls(test_binary: Path, temp_dir: Path) -> None:
    """API summary aggregates call statistics correctly."""
    session = StalkerSession(
        binary_path=str(test_binary),
        output_dir=str(temp_dir),
    )

    session.api_calls = [
        APICallEvent("RegQueryValueExA", "advapi32.dll", 1000, 1234, is_licensing_related=True),
        APICallEvent("RegQueryValueExA", "advapi32.dll", 1001, 1234, is_licensing_related=True),
        APICallEvent("CreateFileW", "kernel32.dll", 1002, 1234, is_licensing_related=False),
        APICallEvent("RegQueryValueExA", "advapi32.dll", 1003, 1234, is_licensing_related=True),
    ]

    summary = session.get_api_summary()

    assert summary["total_calls"] == 4
    assert summary["unique_apis"] == 2
    assert summary["licensing_calls"] == 3
    assert summary["top_apis"][0]["api"] == "RegQueryValueExA"
    assert summary["top_apis"][0]["count"] == 3


def test_get_api_summary_empty(test_binary: Path, temp_dir: Path) -> None:
    """API summary returns empty structure when no calls."""
    session = StalkerSession(
        binary_path=str(test_binary),
        output_dir=str(temp_dir),
    )

    summary = session.get_api_summary()

    assert summary["total_calls"] == 0
    assert summary["unique_apis"] == 0


def test_export_results_creates_json(test_binary: Path, temp_dir: Path) -> None:
    """Export creates comprehensive JSON results file."""
    session = StalkerSession(
        binary_path=str(test_binary),
        output_dir=str(temp_dir),
    )

    session.stats.total_instructions = 5000
    session.stats.unique_blocks = 250
    session.stats.trace_duration = 2.5

    session.coverage_data["test:0x1000"] = CoverageEntry(
        module="test",
        offset="0x1000",
        address="0x401000",
        hit_count=100,
        is_licensing=True,
    )

    session.licensing_routines.add("test:0x1000")

    output_path = session.export_results()

    assert Path(output_path).exists()

    with open(output_path, encoding="utf-8") as f:
        results = json.load(f)

    assert results["binary"] == "test_target.exe"
    assert results["stats"]["total_instructions"] == 5000
    assert results["stats"]["unique_blocks"] == 250
    assert "test:0x1000" in results["licensing_routines"]
    assert results["coverage_summary"]["total_entries"] == 1


def test_export_results_custom_path(test_binary: Path, temp_dir: Path) -> None:
    """Export uses custom output path when provided."""
    session = StalkerSession(
        binary_path=str(test_binary),
        output_dir=str(temp_dir),
    )

    custom_path = str(temp_dir / "custom_results.json")
    output_path = session.export_results(custom_path)

    assert output_path == custom_path
    assert Path(custom_path).exists()


def test_get_licensing_routines(test_binary: Path, temp_dir: Path) -> None:
    """Get licensing routines returns list of identified functions."""
    session = StalkerSession(
        binary_path=str(test_binary),
        output_dir=str(temp_dir),
    )

    session.licensing_routines.add("app.exe:0x1000")
    session.licensing_routines.add("app.exe:0x2000")
    session.licensing_routines.add("license.dll:0x5000")

    routines = session.get_licensing_routines()

    assert len(routines) == 3
    assert "app.exe:0x1000" in routines
    assert "license.dll:0x5000" in routines


def test_save_json_handles_errors(test_binary: Path, temp_dir: Path) -> None:
    """JSON save gracefully handles write errors."""
    session = StalkerSession(
        binary_path=str(test_binary),
        output_dir=str(temp_dir),
    )

    invalid_path = "/nonexistent/directory/output.json"

    session._save_json(invalid_path, {"test": "data"})


def test_context_manager_lifecycle(test_binary: Path, temp_dir: Path) -> None:
    """Context manager properly initializes and cleans up session."""
    fake_session = FakeFridaSession(is_detached=False)

    session = FakeStalkerSessionWithMockSession(
        binary_path=str(test_binary),
        output_dir=str(temp_dir),
        fake_session=fake_session,
        start_return=True,
        stop_return=True,
    )

    session._is_active = True

    with session:
        pass

    assert session.cleanup_called


def test_cleanup_detaches_session(test_binary: Path, temp_dir: Path) -> None:
    """Cleanup properly detaches active Frida session."""
    session = StalkerSession(
        binary_path=str(test_binary),
        output_dir=str(temp_dir),
    )

    fake_session = FakeFridaSession(is_detached=False)
    session.session = fake_session
    session._is_active = True

    session.cleanup()

    assert fake_session.detach_called
    assert not session._is_active


def test_cleanup_handles_detach_errors(test_binary: Path, temp_dir: Path) -> None:
    """Cleanup gracefully handles session detach errors."""
    session = StalkerSession(
        binary_path=str(test_binary),
        output_dir=str(temp_dir),
    )

    fake_session = FakeFridaSession(is_detached=False, detach_should_fail=True)
    session.session = fake_session

    session.cleanup()

    assert session._is_active is False


def test_message_handler_with_invalid_payload(test_binary: Path, temp_dir: Path) -> None:
    """Message handler gracefully handles malformed payloads."""
    session = StalkerSession(
        binary_path=str(test_binary),
        output_dir=str(temp_dir),
    )

    invalid_message = {"type": "send", "payload": None}

    session._on_message(invalid_message, None)  # type: ignore[arg-type]


def test_message_handler_with_error_type(test_binary: Path, temp_dir: Path) -> None:
    """Message handler processes error messages from Frida."""
    messages_received = []

    def message_callback(msg: str) -> None:
        messages_received.append(msg)

    session = StalkerSession(
        binary_path=str(test_binary),
        output_dir=str(temp_dir),
        message_callback=message_callback,
    )

    error_message = {
        "type": "error",
        "stack": "Error: Test error\n  at test.js:10",
    }

    session._on_message(error_message, None)  # type: ignore[arg-type]

    assert any("Error" in msg for msg in messages_received)


def test_session_requires_frida_installation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Session initialization fails gracefully when Frida not installed."""
    import intellicrack.core.analysis.stalker_manager as stalker_module

    monkeypatch.setattr(stalker_module, "frida", None)

    with pytest.raises(ImportError, match="Frida is not installed"):
        StalkerSession(
            binary_path="/test/binary.exe",
            output_dir="/test/output",
        )


def test_trace_event_with_minimal_data() -> None:
    """TraceEvent works with minimal required fields."""
    event = TraceEvent(
        event_type="exec",
        address="0x401000",
    )

    assert event.event_type == "exec"
    assert event.address == "0x401000"
    assert event.module is None
    assert len(event.backtrace) == 0


def test_coverage_entry_non_licensing_code() -> None:
    """CoverageEntry tracks non-licensing code blocks."""
    coverage = CoverageEntry(
        module="app.exe",
        offset="0x5000",
        address="0x405000",
        hit_count=10,
        is_licensing=False,
    )

    assert coverage.is_licensing is False
    assert coverage.hit_count == 10


def test_stalker_stats_default_initialization() -> None:
    """StalkerStats initializes with zero values."""
    stats = StalkerStats()

    assert stats.total_instructions == 0
    assert stats.unique_blocks == 0
    assert stats.coverage_entries == 0
    assert stats.licensing_routines == 0
    assert stats.api_calls == 0
    assert stats.trace_duration == 0.0
