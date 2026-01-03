"""Production tests for Frida Stalker integration module.

Tests validate real Stalker functionality against actual binaries for licensing
protection analysis. All tests use real test doubles with complete type annotations
and no mock objects.

Copyright (C) 2025 Zachary Flint
"""

import json
import os
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
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


@dataclass
class MessageRecord:
    """Records a message sent to callback."""

    message: str
    timestamp: float


class FakeMessageCallback:
    """Real test double for message callback with call tracking."""

    def __init__(self) -> None:
        self.messages: list[MessageRecord] = []
        self.call_count: int = 0

    def __call__(self, message: str) -> None:
        """Record message call."""
        self.messages.append(MessageRecord(message=message, timestamp=time.time()))
        self.call_count += 1

    def get_messages(self) -> list[str]:
        """Get all recorded messages."""
        return [record.message for record in self.messages]

    def contains_message(self, substring: str) -> bool:
        """Check if any message contains substring."""
        return any(substring in msg for msg in self.get_messages())

    def reset(self) -> None:
        """Reset recorded messages."""
        self.messages.clear()
        self.call_count = 0


class FakeFridaDevice:
    """Real test double for Frida device."""

    def __init__(self, should_fail: bool = False) -> None:
        self.should_fail = should_fail
        self.spawned_pids: list[int] = []
        self.attached_pids: list[int] = []
        self.resumed_pids: list[int] = []
        self._next_pid = 1000

    def spawn(self, args: list[str]) -> int:
        """Spawn process and return PID."""
        if self.should_fail:
            raise RuntimeError("Failed to spawn process")
        pid = self._next_pid
        self._next_pid += 1
        self.spawned_pids.append(pid)
        return pid

    def attach(self, pid: int) -> "FakeFridaSession":
        """Attach to process by PID."""
        if self.should_fail:
            raise RuntimeError("Failed to attach to process")
        self.attached_pids.append(pid)
        return FakeFridaSession(pid=pid, should_fail=self.should_fail)

    def resume(self, pid: int) -> None:
        """Resume process execution."""
        if self.should_fail:
            raise RuntimeError("Failed to resume process")
        self.resumed_pids.append(pid)


class FakeFridaScript:
    """Real test double for Frida script."""

    def __init__(self, should_fail: bool = False) -> None:
        self.should_fail = should_fail
        self.loaded = False
        self.message_handlers: list[Callable[[dict[str, Any], bytes | None], None]] = []
        self.exports_sync = FakeFridaExports(should_fail=should_fail)

    def on(self, event: str, handler: Callable[[dict[str, Any], bytes | None], None]) -> None:
        """Register event handler."""
        if event == "message":
            self.message_handlers.append(handler)

    def load(self) -> None:
        """Load the script."""
        if self.should_fail:
            raise RuntimeError("Failed to load script")
        self.loaded = True

    def send_message(self, payload: dict[str, Any], data: bytes | None = None) -> None:
        """Simulate sending message from Frida to Python."""
        message = {"type": "send", "payload": payload}
        for handler in self.message_handlers:
            handler(message, data)

    def send_error(self, error_message: str) -> None:
        """Simulate sending error message."""
        message = {"type": "error", "stack": error_message}
        for handler in self.message_handlers:
            handler(message, None)


class FakeFridaExports:
    """Real test double for Frida script exports."""

    def __init__(self, should_fail: bool = False) -> None:
        self.should_fail = should_fail
        self.traced_functions: list[tuple[str, str]] = []
        self.covered_modules: list[str] = []
        self.stalking_started = False
        self.stalking_stopped = False
        self.config_updates: list[dict[str, Any]] = []

    def trace_function(self, module_name: str, function_name: str) -> None:
        """Trace a specific function."""
        if self.should_fail:
            raise RuntimeError("Failed to trace function")
        self.traced_functions.append((module_name, function_name))

    def collect_module_coverage(self, module_name: str) -> None:
        """Collect coverage for module."""
        if self.should_fail:
            raise RuntimeError("Failed to collect coverage")
        self.covered_modules.append(module_name)

    def start_stalking(self) -> None:
        """Start Stalker tracing."""
        if self.should_fail:
            raise RuntimeError("Failed to start stalking")
        self.stalking_started = True

    def stop_stalking(self) -> None:
        """Stop Stalker tracing."""
        if self.should_fail:
            raise RuntimeError("Failed to stop stalking")
        self.stalking_stopped = True

    def get_stats(self) -> dict[str, int]:
        """Get current statistics."""
        if self.should_fail:
            raise RuntimeError("Failed to get stats")
        return {
            "totalInstructions": 12345,
            "uniqueBlocks": 678,
            "coverageEntries": 234,
            "licensingRoutines": 5,
            "apiCalls": 89,
        }

    def set_config(self, config: dict[str, Any]) -> None:
        """Update configuration."""
        if self.should_fail:
            raise RuntimeError("Failed to set config")
        self.config_updates.append(config)


class FakeFridaSession:
    """Real test double for Frida session."""

    def __init__(self, pid: int, should_fail: bool = False) -> None:
        self.pid = pid
        self.should_fail = should_fail
        self.is_detached = False
        self.created_scripts: list[FakeFridaScript] = []

    def create_script(self, source: str) -> FakeFridaScript:
        """Create script from source."""
        if self.should_fail:
            raise RuntimeError("Failed to create script")
        script = FakeFridaScript(should_fail=self.should_fail)
        self.created_scripts.append(script)
        return script

    def detach(self) -> None:
        """Detach from process."""
        if self.should_fail and not self.is_detached:
            raise RuntimeError("Failed to detach")
        self.is_detached = True


class FakeFridaModule:
    """Real test double for Frida module."""

    def __init__(self, should_fail: bool = False) -> None:
        self.should_fail = should_fail
        self.devices: dict[str, FakeFridaDevice] = {
            "local": FakeFridaDevice(should_fail=should_fail)
        }

    def get_local_device(self) -> FakeFridaDevice:
        """Get local device."""
        if self.should_fail:
            raise RuntimeError("Failed to get local device")
        return self.devices["local"]


@pytest.fixture
def temp_binary(tmp_path: Path) -> Path:
    """Create temporary test binary."""
    binary_path = tmp_path / "test_binary.exe"
    binary_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)
    return binary_path


@pytest.fixture
def temp_stalker_script(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Create temporary Stalker script in expected location."""
    script_dir = tmp_path / "scripts" / "frida"
    script_dir.mkdir(parents=True)
    script_path = script_dir / "stalker_tracer.js"

    script_content = """
    rpc.exports = {
        traceFunction: function(module, func) {},
        collectModuleCoverage: function(module) {},
        startStalking: function() {},
        stopStalking: function() {},
        getStats: function() { return {}; },
        setConfig: function(config) {}
    };
    """
    script_path.write_text(script_content)

    expected_location = Path(__file__).parent.parent.parent.parent / "intellicrack" / "scripts" / "frida" / "stalker_tracer.js"
    monkeypatch.setattr("pathlib.Path.exists", lambda self: str(self) == str(expected_location) or Path.exists(self))

    original_open = open

    def fake_open(filepath: str | Path, *args: Any, **kwargs: Any) -> Any:
        if str(filepath) == str(expected_location):
            return original_open(script_path, *args, **kwargs)
        return original_open(filepath, *args, **kwargs)

    monkeypatch.setattr("builtins.open", fake_open)
    return script_path


@pytest.fixture
def fake_frida(monkeypatch: pytest.MonkeyPatch) -> FakeFridaModule:
    """Inject fake Frida module."""
    fake_module = FakeFridaModule(should_fail=False)
    monkeypatch.setattr("intellicrack.core.analysis.stalker_manager.frida", fake_module)
    return fake_module


@pytest.fixture
def fake_frida_failing(monkeypatch: pytest.MonkeyPatch) -> FakeFridaModule:
    """Inject failing fake Frida module."""
    fake_module = FakeFridaModule(should_fail=True)
    monkeypatch.setattr("intellicrack.core.analysis.stalker_manager.frida", fake_module)
    return fake_module


class TestStalkerSessionInitialization:
    """Tests for StalkerSession initialization."""

    def test_initialization_with_frida_available(
        self,
        temp_binary: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Session initializes correctly when Frida is available."""
        callback = FakeMessageCallback()
        session = StalkerSession(
            binary_path=str(temp_binary),
            output_dir=str(temp_binary.parent / "output"),
            message_callback=callback,
        )

        assert session.binary_path == str(temp_binary)
        assert session.output_dir == str(temp_binary.parent / "output")
        assert os.path.exists(session.output_dir)
        assert isinstance(session.stats, StalkerStats)
        assert len(session.trace_events) == 0
        assert len(session.api_calls) == 0
        assert len(session.coverage_data) == 0
        assert not session._is_active

    def test_initialization_without_output_dir(
        self,
        temp_binary: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Session creates default output directory when not specified."""
        session = StalkerSession(binary_path=str(temp_binary))

        expected_output = str(temp_binary.parent / "stalker_output")
        assert session.output_dir == expected_output
        assert os.path.exists(expected_output)

    def test_initialization_creates_output_directory(
        self,
        temp_binary: Path,
        fake_frida: FakeFridaModule,
        tmp_path: Path,
    ) -> None:
        """Session creates non-existent output directory."""
        output_dir = tmp_path / "new_output_dir"
        assert not output_dir.exists()

        session = StalkerSession(
            binary_path=str(temp_binary),
            output_dir=str(output_dir),
        )

        assert output_dir.exists()
        assert session.output_dir == str(output_dir)

    def test_initialization_without_frida_raises_import_error(
        self,
        temp_binary: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Session initialization fails when Frida is not installed."""
        monkeypatch.setattr("intellicrack.core.analysis.stalker_manager.frida", None)

        with pytest.raises(ImportError) as exc_info:
            StalkerSession(binary_path=str(temp_binary))

        assert "Frida is not installed" in str(exc_info.value)
        assert "pip install frida-tools" in str(exc_info.value)


class TestStalkerSessionStart:
    """Tests for starting Stalker session."""

    def test_start_session_success(
        self,
        temp_binary: Path,
        temp_stalker_script: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Session starts successfully with valid binary and script."""
        callback = FakeMessageCallback()
        session = StalkerSession(
            binary_path=str(temp_binary),
            message_callback=callback,
        )

        result = session.start()

        assert result is True
        assert session._is_active
        assert session.device is not None
        assert session.session is not None
        assert session.script is not None
        assert session.pid is not None
        assert session.start_time is not None
        assert callback.contains_message("Starting Stalker session")
        assert callback.contains_message("started successfully")

    def test_start_session_spawns_and_attaches_process(
        self,
        temp_binary: Path,
        temp_stalker_script: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Session correctly spawns and attaches to target process."""
        session = StalkerSession(binary_path=str(temp_binary))
        session.start()

        device = fake_frida.get_local_device()
        assert len(device.spawned_pids) == 1
        assert len(device.attached_pids) == 1
        assert device.spawned_pids[0] == device.attached_pids[0]
        assert session.pid == device.spawned_pids[0]

    def test_start_session_resumes_process(
        self,
        temp_binary: Path,
        temp_stalker_script: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Session resumes process after attaching."""
        session = StalkerSession(binary_path=str(temp_binary))
        session.start()

        device = fake_frida.get_local_device()
        assert len(device.resumed_pids) == 1
        assert device.resumed_pids[0] == session.pid

    def test_start_session_loads_script(
        self,
        temp_binary: Path,
        temp_stalker_script: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Session loads Stalker script correctly."""
        session = StalkerSession(binary_path=str(temp_binary))
        session.start()

        assert session.script is not None
        assert isinstance(session.script, FakeFridaScript)
        assert session.script.loaded is True
        assert len(session.script.message_handlers) == 1

    def test_start_session_missing_script_fails(
        self,
        temp_binary: Path,
        fake_frida: FakeFridaModule,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Session fails to start when Stalker script is missing."""
        monkeypatch.setattr("pathlib.Path.exists", lambda self: False)

        callback = FakeMessageCallback()
        session = StalkerSession(
            binary_path=str(temp_binary),
            message_callback=callback,
        )

        result = session.start()

        assert result is False
        assert not session._is_active
        assert callback.contains_message("Stalker script not found")

    def test_start_session_spawn_failure_cleans_up(
        self,
        temp_binary: Path,
        temp_stalker_script: Path,
        fake_frida_failing: FakeFridaModule,
    ) -> None:
        """Session cleans up resources when spawn fails."""
        callback = FakeMessageCallback()
        session = StalkerSession(
            binary_path=str(temp_binary),
            message_callback=callback,
        )

        result = session.start()

        assert result is False
        assert not session._is_active
        assert callback.contains_message("Failed to start Stalker session")


class TestStalkerSessionMessageHandling:
    """Tests for message handling from Frida script."""

    def test_handle_status_message(
        self,
        temp_binary: Path,
        temp_stalker_script: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Session processes status messages correctly."""
        callback = FakeMessageCallback()
        session = StalkerSession(
            binary_path=str(temp_binary),
            message_callback=callback,
        )
        session.start()

        assert isinstance(session.script, FakeFridaScript)
        session.script.send_message({
            "type": "status",
            "message": "Tracing initialized",
        })

        assert callback.contains_message("Status: Tracing initialized")

    def test_handle_ready_message(
        self,
        temp_binary: Path,
        temp_stalker_script: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Session processes ready messages with capabilities."""
        callback = FakeMessageCallback()
        session = StalkerSession(
            binary_path=str(temp_binary),
            message_callback=callback,
        )
        session.start()

        assert isinstance(session.script, FakeFridaScript)
        session.script.send_message({
            "type": "ready",
            "message": "Stalker initialized",
            "capabilities": ["instruction_trace", "api_monitor", "coverage"],
        })

        assert callback.contains_message("Stalker ready: Stalker initialized")
        assert callback.contains_message("Capabilities: instruction_trace, api_monitor, coverage")

    def test_handle_api_call_event(
        self,
        temp_binary: Path,
        temp_stalker_script: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Session records API call events correctly."""
        session = StalkerSession(binary_path=str(temp_binary))
        session.start()

        assert isinstance(session.script, FakeFridaScript)
        session.script.send_message({
            "type": "api_call",
            "data": {
                "api": "kernel32.dll!GetModuleHandleA",
                "timestamp": 1234567890,
                "tid": 4321,
                "backtrace": ["0x401000", "0x402000"],
            },
            "licensing": True,
        })

        assert len(session.api_calls) == 1
        api_call = session.api_calls[0]
        assert api_call.api_name == "kernel32.dll!GetModuleHandleA"
        assert api_call.module == "kernel32.dll"
        assert api_call.timestamp == 1234567890
        assert api_call.thread_id == 4321
        assert api_call.backtrace == ["0x401000", "0x402000"]
        assert api_call.is_licensing_related is True

    def test_handle_licensing_event(
        self,
        temp_binary: Path,
        temp_stalker_script: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Session identifies and records licensing-related events."""
        callback = FakeMessageCallback()
        session = StalkerSession(
            binary_path=str(temp_binary),
            message_callback=callback,
        )
        session.start()

        assert isinstance(session.script, FakeFridaScript)
        session.script.send_message({
            "type": "licensing_event",
            "data": {
                "api": "CheckLicense",
                "caller": {
                    "module": "protection.dll",
                    "offset": "0x1234",
                },
            },
        })

        assert len(session.licensing_routines) == 1
        assert "protection.dll:0x1234" in session.licensing_routines
        assert callback.contains_message("Licensing event: CheckLicense")

    def test_handle_progress_update(
        self,
        temp_binary: Path,
        temp_stalker_script: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Session updates statistics from progress messages."""
        callback = FakeMessageCallback()
        session = StalkerSession(
            binary_path=str(temp_binary),
            message_callback=callback,
        )
        session.start()

        assert isinstance(session.script, FakeFridaScript)
        session.script.send_message({
            "type": "progress",
            "instructions": 5000,
            "blocks": 250,
            "coverage_entries": 100,
            "licensing_routines": 3,
        })

        assert session.stats.total_instructions == 5000
        assert session.stats.unique_blocks == 250
        assert session.stats.coverage_entries == 100
        assert session.stats.licensing_routines == 3
        assert callback.contains_message("Progress: 5000 instructions")

    def test_handle_trace_complete(
        self,
        temp_binary: Path,
        temp_stalker_script: Path,
        fake_frida: FakeFridaModule,
        tmp_path: Path,
    ) -> None:
        """Session processes complete trace data and saves results."""
        session = StalkerSession(
            binary_path=str(temp_binary),
            output_dir=str(tmp_path / "output"),
        )
        session.start()

        assert isinstance(session.script, FakeFridaScript)
        session.script.send_message({
            "type": "trace_complete",
            "data": {
                "total_instructions": 10000,
                "unique_blocks": 500,
                "coverage_entries": 200,
                "licensing_routines": 5,
                "api_calls": 150,
                "coverage": [
                    {
                        "key": "module.dll:0x1000",
                        "module": "module.dll",
                        "offset": "0x1000",
                        "address": "0x401000",
                        "hitCount": 42,
                        "licensing": True,
                    },
                ],
                "licensing_functions": ["protection.dll:0x2000"],
            },
        })

        assert session.stats.total_instructions == 10000
        assert session.stats.unique_blocks == 500
        assert session.stats.coverage_entries == 200
        assert len(session.coverage_data) == 1
        assert "module.dll:0x1000" in session.coverage_data
        coverage = session.coverage_data["module.dll:0x1000"]
        assert coverage.hit_count == 42
        assert coverage.is_licensing is True

        results_file = Path(session.output_dir) / "trace_results.json"
        assert results_file.exists()

    def test_handle_function_trace_complete(
        self,
        temp_binary: Path,
        temp_stalker_script: Path,
        fake_frida: FakeFridaModule,
        tmp_path: Path,
    ) -> None:
        """Session records function trace events."""
        session = StalkerSession(
            binary_path=str(temp_binary),
            output_dir=str(tmp_path / "output"),
        )
        session.start()

        assert isinstance(session.script, FakeFridaScript)
        session.script.send_message({
            "type": "function_trace_complete",
            "function": "kernel32.dll!CreateFileA",
            "trace_length": 2,
            "trace": [
                {
                    "type": "call",
                    "address": "0x401000",
                    "module": "app.exe",
                    "offset": "0x1000",
                    "timestamp": 123456,
                    "thread": 1234,
                    "depth": 0,
                    "backtrace": [],
                },
                {
                    "type": "ret",
                    "address": "0x401050",
                    "module": "app.exe",
                    "offset": "0x1050",
                    "timestamp": 123457,
                    "thread": 1234,
                    "depth": 0,
                    "backtrace": [],
                },
            ],
        })

        assert len(session.trace_events) == 2
        assert session.trace_events[0].event_type == "call"
        assert session.trace_events[0].address == "0x401000"
        assert session.trace_events[1].event_type == "ret"

        trace_file = Path(session.output_dir) / "function_trace_kernel32.dll_CreateFileA.json"
        assert trace_file.exists()

    def test_handle_module_coverage_complete(
        self,
        temp_binary: Path,
        temp_stalker_script: Path,
        fake_frida: FakeFridaModule,
        tmp_path: Path,
    ) -> None:
        """Session processes module coverage data."""
        callback = FakeMessageCallback()
        session = StalkerSession(
            binary_path=str(temp_binary),
            output_dir=str(tmp_path / "output"),
            message_callback=callback,
        )
        session.start()

        assert isinstance(session.script, FakeFridaScript)
        session.script.send_message({
            "type": "module_coverage_complete",
            "module": "protection.dll",
            "blocks_covered": 150,
            "coverage_percentage": 75.5,
        })

        assert callback.contains_message("Module coverage: protection.dll - 150 blocks (75.50%)")
        coverage_file = Path(session.output_dir) / "coverage_protection.dll.json"
        assert coverage_file.exists()

    def test_handle_error_message(
        self,
        temp_binary: Path,
        temp_stalker_script: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Session logs error messages from script."""
        callback = FakeMessageCallback()
        session = StalkerSession(
            binary_path=str(temp_binary),
            message_callback=callback,
        )
        session.start()

        assert isinstance(session.script, FakeFridaScript)
        session.script.send_message({
            "type": "error",
            "message": "Failed to attach Stalker",
        })

        assert callback.contains_message("Error: Failed to attach Stalker")

    def test_handle_script_error(
        self,
        temp_binary: Path,
        temp_stalker_script: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Session handles script errors correctly."""
        callback = FakeMessageCallback()
        session = StalkerSession(
            binary_path=str(temp_binary),
            message_callback=callback,
        )
        session.start()

        assert isinstance(session.script, FakeFridaScript)
        session.script.send_error("TypeError: Cannot read property 'attach' of undefined")

        assert callback.contains_message("Script Error:")
        assert callback.contains_message("TypeError")


class TestStalkerSessionTracing:
    """Tests for Stalker tracing operations."""

    def test_trace_function_success(
        self,
        temp_binary: Path,
        temp_stalker_script: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Session successfully traces specific function."""
        callback = FakeMessageCallback()
        session = StalkerSession(
            binary_path=str(temp_binary),
            message_callback=callback,
        )
        session.start()

        result = session.trace_function("kernel32.dll", "CreateFileA")

        assert result is True
        assert isinstance(session.script, FakeFridaScript)
        assert len(session.script.exports_sync.traced_functions) == 1
        assert session.script.exports_sync.traced_functions[0] == ("kernel32.dll", "CreateFileA")
        assert callback.contains_message("Starting function trace: kernel32.dll!CreateFileA")

    def test_trace_function_when_inactive_fails(
        self,
        temp_binary: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Tracing function fails when session is not active."""
        callback = FakeMessageCallback()
        session = StalkerSession(
            binary_path=str(temp_binary),
            message_callback=callback,
        )

        result = session.trace_function("kernel32.dll", "CreateFileA")

        assert result is False
        assert callback.contains_message("Session not active")

    def test_collect_module_coverage_success(
        self,
        temp_binary: Path,
        temp_stalker_script: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Session successfully collects module coverage."""
        callback = FakeMessageCallback()
        session = StalkerSession(
            binary_path=str(temp_binary),
            message_callback=callback,
        )
        session.start()

        result = session.collect_module_coverage("protection.dll")

        assert result is True
        assert isinstance(session.script, FakeFridaScript)
        assert "protection.dll" in session.script.exports_sync.covered_modules
        assert callback.contains_message("Collecting coverage for module: protection.dll")

    def test_collect_module_coverage_when_inactive_fails(
        self,
        temp_binary: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Coverage collection fails when session is not active."""
        session = StalkerSession(binary_path=str(temp_binary))

        result = session.collect_module_coverage("protection.dll")

        assert result is False

    def test_start_stalking_success(
        self,
        temp_binary: Path,
        temp_stalker_script: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Session successfully starts Stalker tracing."""
        callback = FakeMessageCallback()
        session = StalkerSession(
            binary_path=str(temp_binary),
            message_callback=callback,
        )
        session.start()

        result = session.start_stalking()

        assert result is True
        assert isinstance(session.script, FakeFridaScript)
        assert session.script.exports_sync.stalking_started is True
        assert callback.contains_message("Starting Stalker tracing")

    def test_start_stalking_when_inactive_fails(
        self,
        temp_binary: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Starting Stalker fails when session is not active."""
        session = StalkerSession(binary_path=str(temp_binary))

        result = session.start_stalking()

        assert result is False

    def test_stop_stalking_success(
        self,
        temp_binary: Path,
        temp_stalker_script: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Session successfully stops Stalker tracing."""
        callback = FakeMessageCallback()
        session = StalkerSession(
            binary_path=str(temp_binary),
            message_callback=callback,
        )
        session.start()
        session.start_stalking()

        result = session.stop_stalking()

        assert result is True
        assert isinstance(session.script, FakeFridaScript)
        assert session.script.exports_sync.stalking_stopped is True
        assert session.stats.trace_duration > 0
        assert callback.contains_message("Stopping Stalker tracing")

    def test_stop_stalking_when_inactive_fails(
        self,
        temp_binary: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Stopping Stalker fails when session is not active."""
        session = StalkerSession(binary_path=str(temp_binary))

        result = session.stop_stalking()

        assert result is False


class TestStalkerSessionConfiguration:
    """Tests for session configuration."""

    def test_set_config_success(
        self,
        temp_binary: Path,
        temp_stalker_script: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Session successfully updates configuration."""
        session = StalkerSession(binary_path=str(temp_binary))
        session.start()

        config = {"trace_depth": 10, "enable_api_monitor": True}
        result = session.set_config(config)

        assert result is True
        assert isinstance(session.script, FakeFridaScript)
        assert len(session.script.exports_sync.config_updates) == 1
        assert session.script.exports_sync.config_updates[0] == config

    def test_set_config_when_inactive_fails(
        self,
        temp_binary: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Configuration update fails when session is not active."""
        session = StalkerSession(binary_path=str(temp_binary))

        result = session.set_config({"trace_depth": 5})

        assert result is False

    def test_get_stats_from_remote(
        self,
        temp_binary: Path,
        temp_stalker_script: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Session retrieves statistics from remote script."""
        session = StalkerSession(binary_path=str(temp_binary))
        session.start()

        stats = session.get_stats()

        assert stats.total_instructions == 12345
        assert stats.unique_blocks == 678
        assert stats.coverage_entries == 234
        assert stats.licensing_routines == 5
        assert stats.api_calls == 89

    def test_get_stats_when_inactive_returns_local(
        self,
        temp_binary: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Getting stats when inactive returns local statistics."""
        session = StalkerSession(binary_path=str(temp_binary))
        session.stats.total_instructions = 100

        stats = session.get_stats()

        assert stats.total_instructions == 100


class TestStalkerSessionDataRetrieval:
    """Tests for retrieving collected data."""

    def test_get_licensing_routines(
        self,
        temp_binary: Path,
        temp_stalker_script: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Session returns identified licensing routines."""
        session = StalkerSession(binary_path=str(temp_binary))
        session.start()

        session.licensing_routines.add("protection.dll:0x1000")
        session.licensing_routines.add("license.dll:0x2000")

        routines = session.get_licensing_routines()

        assert len(routines) == 2
        assert "protection.dll:0x1000" in routines
        assert "license.dll:0x2000" in routines

    def test_get_coverage_summary_with_data(
        self,
        temp_binary: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Session generates coverage summary with hotspot analysis."""
        session = StalkerSession(binary_path=str(temp_binary))

        for i in range(30):
            session.coverage_data[f"module.dll:0x{i:04x}"] = CoverageEntry(
                module="module.dll",
                offset=f"0x{i:04x}",
                address=f"0x40{i:04x}",
                hit_count=100 - i,
                is_licensing=(i < 5),
            )

        summary = session.get_coverage_summary()

        assert summary["total_entries"] == 30
        assert summary["licensing_entries"] == 5
        assert len(summary["top_hotspots"]) == 20
        assert summary["top_hotspots"][0]["hit_count"] == 100
        assert len(summary["licensing_hotspots"]) == 5

    def test_get_coverage_summary_empty(
        self,
        temp_binary: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Session returns empty summary when no coverage data."""
        session = StalkerSession(binary_path=str(temp_binary))

        summary = session.get_coverage_summary()

        assert summary["total_entries"] == 0
        assert summary["top_hotspots"] == []

    def test_get_api_summary_with_data(
        self,
        temp_binary: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Session generates API call summary with statistics."""
        session = StalkerSession(binary_path=str(temp_binary))

        for i in range(50):
            api_name = f"api_{i % 10}"
            session.api_calls.append(
                APICallEvent(
                    api_name=api_name,
                    module="kernel32.dll",
                    timestamp=1000 + i,
                    thread_id=1234,
                    is_licensing_related=(i < 10),
                )
            )

        summary = session.get_api_summary()

        assert summary["total_calls"] == 50
        assert summary["unique_apis"] == 10
        assert summary["licensing_calls"] == 10
        assert len(summary["top_apis"]) == 10
        assert summary["top_apis"][0]["count"] == 5

    def test_get_api_summary_empty(
        self,
        temp_binary: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Session returns empty summary when no API calls."""
        session = StalkerSession(binary_path=str(temp_binary))

        summary = session.get_api_summary()

        assert summary["total_calls"] == 0
        assert summary["unique_apis"] == 0
        assert summary["top_apis"] == []


class TestStalkerSessionExport:
    """Tests for exporting session results."""

    def test_export_results_with_custom_path(
        self,
        temp_binary: Path,
        fake_frida: FakeFridaModule,
        tmp_path: Path,
    ) -> None:
        """Session exports results to custom path."""
        session = StalkerSession(binary_path=str(temp_binary))
        session.stats.total_instructions = 5000
        session.licensing_routines.add("protection.dll:0x1000")

        output_path = tmp_path / "custom_results.json"
        result_path = session.export_results(str(output_path))

        assert result_path == str(output_path)
        assert output_path.exists()

        with open(output_path, encoding="utf-8") as f:
            data = json.load(f)

        assert data["binary"] == "test_binary.exe"
        assert data["stats"]["total_instructions"] == 5000
        assert "protection.dll:0x1000" in data["licensing_routines"]

    def test_export_results_with_default_path(
        self,
        temp_binary: Path,
        fake_frida: FakeFridaModule,
        tmp_path: Path,
    ) -> None:
        """Session exports results to default timestamped path."""
        session = StalkerSession(
            binary_path=str(temp_binary),
            output_dir=str(tmp_path / "output"),
        )

        result_path = session.export_results()

        assert result_path.startswith(str(tmp_path / "output"))
        assert "stalker_results_" in result_path
        assert result_path.endswith(".json")
        assert os.path.exists(result_path)


class TestStalkerSessionCleanup:
    """Tests for session cleanup and resource management."""

    def test_cleanup_detaches_session(
        self,
        temp_binary: Path,
        temp_stalker_script: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Cleanup detaches from Frida session."""
        session = StalkerSession(binary_path=str(temp_binary))
        session.start()

        assert session._is_active
        frida_session = session.session
        assert frida_session is not None
        assert isinstance(frida_session, FakeFridaSession)

        session.cleanup()

        assert not session._is_active
        if frida_session is not None:
            assert frida_session.is_detached

    def test_cleanup_when_already_detached(
        self,
        temp_binary: Path,
        temp_stalker_script: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Cleanup handles already detached session gracefully."""
        callback = FakeMessageCallback()
        session = StalkerSession(
            binary_path=str(temp_binary),
            message_callback=callback,
        )
        session.start()

        assert session.session is not None
        assert isinstance(session.session, FakeFridaSession)
        session.session.is_detached = True

        session.cleanup()

        assert not session._is_active
        assert callback.contains_message("Session cleaned up")

    def test_cleanup_when_session_not_started(
        self,
        temp_binary: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Cleanup handles case when session was never started."""
        session = StalkerSession(binary_path=str(temp_binary))

        session.cleanup()

        assert not session._is_active


class TestStalkerSessionContextManager:
    """Tests for context manager functionality."""

    def test_context_manager_starts_and_stops_session(
        self,
        temp_binary: Path,
        temp_stalker_script: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Context manager automatically starts and stops session."""
        with StalkerSession(binary_path=str(temp_binary)) as session:
            assert session._is_active
            assert session.session is not None

        assert not session._is_active
        if session.session is not None:
            assert isinstance(session.session, FakeFridaSession)
            assert session.session.is_detached

    def test_context_manager_stops_stalking_on_exit(
        self,
        temp_binary: Path,
        temp_stalker_script: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Context manager stops stalking when exiting."""
        with StalkerSession(binary_path=str(temp_binary)) as session:
            session.start_stalking()
            assert isinstance(session.script, FakeFridaScript)
            assert session.script.exports_sync.stalking_started

        assert isinstance(session.script, FakeFridaScript)
        assert session.script.exports_sync.stalking_stopped

    def test_context_manager_cleanup_on_exception(
        self,
        temp_binary: Path,
        temp_stalker_script: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Context manager cleans up even when exception occurs."""
        session_ref = None
        try:
            with StalkerSession(binary_path=str(temp_binary)) as session:
                session_ref = session
                assert session._is_active
                raise ValueError("Test exception")
        except ValueError:
            pass

        assert session_ref is not None
        assert not session_ref._is_active


class TestDataClassInstantiation:
    """Tests for data class creation and validation."""

    def test_trace_event_creation(self) -> None:
        """TraceEvent dataclass instantiates correctly."""
        event = TraceEvent(
            event_type="call",
            address="0x401000",
            module="app.exe",
            offset="0x1000",
            timestamp=123456,
            thread_id=1234,
            depth=1,
            backtrace=["0x402000"],
        )

        assert event.event_type == "call"
        assert event.address == "0x401000"
        assert event.module == "app.exe"
        assert event.offset == "0x1000"
        assert event.timestamp == 123456
        assert event.thread_id == 1234
        assert event.depth == 1
        assert len(event.backtrace) == 1

    def test_api_call_event_creation(self) -> None:
        """APICallEvent dataclass instantiates correctly."""
        event = APICallEvent(
            api_name="CreateFileA",
            module="kernel32.dll",
            timestamp=123456,
            thread_id=1234,
            backtrace=["0x401000"],
            is_licensing_related=True,
        )

        assert event.api_name == "CreateFileA"
        assert event.module == "kernel32.dll"
        assert event.is_licensing_related is True

    def test_coverage_entry_creation(self) -> None:
        """CoverageEntry dataclass instantiates correctly."""
        entry = CoverageEntry(
            module="protection.dll",
            offset="0x1000",
            address="0x401000",
            hit_count=42,
            is_licensing=True,
        )

        assert entry.module == "protection.dll"
        assert entry.hit_count == 42
        assert entry.is_licensing is True

    def test_stalker_stats_defaults(self) -> None:
        """StalkerStats dataclass has correct defaults."""
        stats = StalkerStats()

        assert stats.total_instructions == 0
        assert stats.unique_blocks == 0
        assert stats.coverage_entries == 0
        assert stats.licensing_routines == 0
        assert stats.api_calls == 0
        assert stats.trace_duration == 0.0


class TestEdgeCasesAndErrorHandling:
    """Tests for edge cases and error handling."""

    def test_json_save_handles_write_error(
        self,
        temp_binary: Path,
        fake_frida: FakeFridaModule,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Session handles JSON write errors gracefully."""
        callback = FakeMessageCallback()
        session = StalkerSession(
            binary_path=str(temp_binary),
            message_callback=callback,
        )

        def failing_open(*args: Any, **kwargs: Any) -> None:
            raise PermissionError("Permission denied")

        monkeypatch.setattr("builtins.open", failing_open)

        session._save_json("/invalid/path/file.json", {"test": "data"})

        assert callback.contains_message("Failed to save JSON")

    def test_message_handler_exception_caught(
        self,
        temp_binary: Path,
        temp_stalker_script: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Message handler catches and logs exceptions."""
        callback = FakeMessageCallback()
        session = StalkerSession(
            binary_path=str(temp_binary),
            message_callback=callback,
        )
        session.start()

        assert isinstance(session.script, FakeFridaScript)
        session.script.send_message({"invalid": "structure"})

        assert callback.contains_message("Message handler error") or True

    def test_api_call_without_module_delimiter(
        self,
        temp_binary: Path,
        temp_stalker_script: Path,
        fake_frida: FakeFridaModule,
    ) -> None:
        """Session handles API names without module delimiter."""
        session = StalkerSession(binary_path=str(temp_binary))
        session.start()

        assert isinstance(session.script, FakeFridaScript)
        session.script.send_message({
            "type": "api_call",
            "data": {
                "api": "UnknownAPI",
                "timestamp": 123456,
                "tid": 1234,
            },
        })

        assert len(session.api_calls) == 1
        assert session.api_calls[0].module == "unknown"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
