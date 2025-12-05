"""Production-ready tests for intellicrack/core/analysis/frida_analyzer.py

Tests validate REAL offensive capabilities against actual Windows processes:
- Frida script injection and execution on real binaries
- Process spawn, attach, and detachment lifecycle
- Script message handling and callback execution
- Session management and cleanup
- Stalker tracing integration for licensing analysis
- Function hooking and API interception
- Coverage collection and licensing routine detection
- Error handling for process failures
"""

import json
import os
import tempfile
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
import frida
import pytest

from intellicrack.core.analysis.frida_analyzer import (
    ANALYSIS_SCRIPTS_WHITELIST,
    active_frida_sessions,
    active_stalker_sessions,
    collect_module_coverage_stalker,
    get_licensing_routines_stalker,
    get_stalker_stats,
    on_frida_message,
    run_frida_script_thread,
    start_stalker_session,
    stop_frida_analysis,
    stop_stalker_session,
    trace_function_stalker,
)
from intellicrack.core.analysis.stalker_manager import (
    APICallEvent,
    CoverageEntry,
    StalkerSession,
    StalkerStats,
    TraceEvent,
)


NOTEPAD_PATH: str = "C:\\Windows\\System32\\notepad.exe"
CALC_PATH: str = "C:\\Windows\\System32\\calc.exe"


class MockApp:
    """Mock IntellicrackApp for testing without full UI."""

    def __init__(self) -> None:
        self.current_binary: str | None = None
        self.messages: list[str] = []
        self.update_output_calls: int = 0
        self.analysis_completed_calls: int = 0

    def update_output_emit(self, message: str) -> None:
        """Mock signal emit for output updates."""
        self.messages.append(message)
        self.update_output_calls += 1

    def analysis_completed_emit(self, analyzer_name: str) -> None:
        """Mock signal emit for analysis completion."""
        self.analysis_completed_calls += 1


class RealTestStalkerSession:
    """Real test double for StalkerSession - used for testing duplicate prevention."""

    def __init__(self, binary_path: str = "") -> None:
        self.binary_path: str = binary_path
        self.trace_events: list[TraceEvent] = []
        self.api_calls: list[APICallEvent] = []
        self.coverage_data: list[CoverageEntry] = []
        self._is_running: bool = True

    def stop(self) -> None:
        self._is_running = False

    def is_running(self) -> bool:
        return self._is_running

    def get_stats(self) -> StalkerStats:
        return StalkerStats(
            events_captured=len(self.trace_events),
            unique_addresses=0,
            api_calls=len(self.api_calls),
            coverage_blocks=len(self.coverage_data),
        )


class TestFridaMessageHandling:
    """Test Frida message handling and callback execution."""

    def test_on_frida_message_handles_send_payload(self) -> None:
        """Message handler extracts and logs send payload from Frida script."""
        app = MockApp()
        binary_path = NOTEPAD_PATH

        message: dict[str, Any] = {
            "type": "send",
            "payload": "License check detected at 0x401000",
        }

        on_frida_message(app, binary_path, message, None)

        assert app.update_output_calls == 1
        assert "notepad.exe" in app.messages[0]
        assert "License check detected at 0x401000" in app.messages[0]

    def test_on_frida_message_handles_error_with_stack_trace(self) -> None:
        """Message handler logs error messages with stack traces."""
        app = MockApp()
        binary_path = CALC_PATH

        message: dict[str, Any] = {
            "type": "error",
            "stack": "Error: Failed to intercept CreateMutexW\n    at <anonymous>:1:2",
        }

        on_frida_message(app, binary_path, message, None)

        assert app.update_output_calls == 1
        assert "[Frida Error]" in app.messages[0]
        assert "CreateMutexW" in app.messages[0]

    def test_on_frida_message_handles_error_without_stack(self) -> None:
        """Message handler provides fallback for errors without stack trace."""
        app = MockApp()
        binary_path = NOTEPAD_PATH

        message: dict[str, Any] = {"type": "error"}

        on_frida_message(app, binary_path, message, None)

        assert app.update_output_calls == 1
        assert "[Frida Error]" in app.messages[0]
        assert "No stack trace available" in app.messages[0]

    def test_on_frida_message_handles_empty_payload(self) -> None:
        """Message handler gracefully handles messages with no payload."""
        app = MockApp()
        binary_path = CALC_PATH

        message: dict[str, Any] = {"type": "send"}

        on_frida_message(app, binary_path, message, None)

        assert app.update_output_calls == 1
        assert "calc.exe" in app.messages[0]

    def test_on_frida_message_handles_malformed_message_gracefully(self) -> None:
        """Message handler catches exceptions from malformed messages."""
        app = MockApp()
        binary_path = NOTEPAD_PATH

        message: dict[str, Any] = {"invalid": "structure"}

        on_frida_message(app, binary_path, message, None)

        assert "[Frida Message Error]" in app.messages[-1]


class TestFridaProcessLifecycle:
    """Test Frida process spawning, attachment, and detachment."""

    def test_frida_spawns_and_attaches_to_notepad(self) -> None:
        """Frida successfully spawns and attaches to notepad.exe process."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        assert pid > 0
        assert isinstance(pid, int)

        try:
            session: frida.core.Session = device.attach(pid)
            assert not session.is_detached

            session.detach()
            assert session.is_detached

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_frida_attaches_to_running_calc_process(self) -> None:
        """Frida attaches to already-running calc.exe process."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        try:
            device.resume(pid)
            time.sleep(0.2)

            session: frida.core.Session = device.attach(pid)
            assert not session.is_detached

            processes = device.enumerate_processes()
            calc_proc = [p for p in processes if p.pid == pid]
            assert len(calc_proc) == 1
            assert "calc" in calc_proc[0].name.lower()

            session.detach()
            assert session.is_detached

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_frida_script_loads_and_executes_on_notepad(self) -> None:
        """Frida script loads and executes JavaScript code on target process."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        script_source = """
        send({type: 'ready', message: 'Script loaded successfully'});
        Process.enumerateModules().forEach(function(module) {
            if (module.name.toLowerCase().indexOf('kernel32') !== -1) {
                send({type: 'module_found', name: module.name, base: module.base.toString()});
            }
        });
        """

        messages: list[dict[str, Any]] = []

        def on_message(message: dict[str, Any], data: bytes | None) -> None:
            if message.get("type") == "send":
                messages.append(message["payload"])

        try:
            session: frida.core.Session = device.attach(pid)
            script: frida.core.Script = session.create_script(script_source)
            script.on("message", on_message)
            script.load()

            device.resume(pid)
            time.sleep(0.3)

            assert len(messages) >= 2
            assert messages[0]["type"] == "ready"
            assert messages[0]["message"] == "Script loaded successfully"

            kernel32_msg = [m for m in messages if m.get("type") == "module_found"]
            assert len(kernel32_msg) >= 1
            assert "kernel32" in kernel32_msg[0]["name"].lower()

            session.detach()

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_frida_detaches_cleanly_on_process_exit(self) -> None:
        """Frida session detaches cleanly when target process terminates."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            session: frida.core.Session = device.attach(pid)
            assert not session.is_detached

            device.kill(pid)
            time.sleep(0.2)

            assert session.is_detached

        except frida.ProcessNotFoundError:
            pass


class TestFridaScriptExecution:
    """Test Frida script injection and execution workflows."""

    def test_run_frida_script_thread_executes_simple_script(self) -> None:
        """Script thread spawns process, injects script, and executes successfully."""
        app = MockApp()
        app.current_binary = CALC_PATH

        script_source = """
        send({type: 'status', message: 'Analyzing calc.exe'});
        var moduleName = Process.enumerateModules()[0].name;
        send({type: 'result', module: moduleName});
        """

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".js", delete=False, encoding="utf-8"
        ) as f:
            f.write(script_source)
            script_path = f.name

        try:
            thread = threading.Thread(
                target=run_frida_script_thread,
                args=(app, app.current_binary, script_path),
                daemon=True,
            )
            thread.start()

            time.sleep(1.5)

            assert app.update_output_calls >= 3
            assert any("[Frida Runner] Starting script" in msg for msg in app.messages)
            assert any("Attached to PID:" in msg for msg in app.messages)

            if app.current_binary in active_frida_sessions:
                session = active_frida_sessions[app.current_binary]
                if session and not session.is_detached:
                    session.detach()

            thread.join(timeout=2.0)

        finally:
            os.unlink(script_path)
            active_frida_sessions.pop(app.current_binary, None)

    def test_run_frida_script_thread_handles_invalid_script_path(self) -> None:
        """Script thread handles missing script file gracefully."""
        app = MockApp()
        app.current_binary = NOTEPAD_PATH

        invalid_script_path = "D:\\nonexistent\\script.js"

        thread = threading.Thread(
            target=run_frida_script_thread,
            args=(app, app.current_binary, invalid_script_path),
            daemon=True,
        )
        thread.start()
        thread.join(timeout=2.0)

        assert any("[Frida Runner] An error occurred:" in msg for msg in app.messages)

    def test_run_frida_script_thread_handles_script_syntax_error(self) -> None:
        """Script thread detects and reports JavaScript syntax errors."""
        app = MockApp()
        app.current_binary = CALC_PATH

        script_source = """
        send({type: 'test'});
        this is invalid javascript syntax that will fail to parse
        """

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".js", delete=False, encoding="utf-8"
        ) as f:
            f.write(script_source)
            script_path = f.name

        try:
            thread = threading.Thread(
                target=run_frida_script_thread,
                args=(app, app.current_binary, script_path),
                daemon=True,
            )
            thread.start()
            thread.join(timeout=2.0)

            assert any("[Frida Runner] An error occurred:" in msg for msg in app.messages)

        finally:
            os.unlink(script_path)
            active_frida_sessions.pop(app.current_binary, None)


class TestFridaSessionManagement:
    """Test Frida session lifecycle and management."""

    def test_stop_frida_analysis_detaches_active_session(self) -> None:
        """Stop command successfully detaches from active Frida session."""
        app = MockApp()
        app.current_binary = NOTEPAD_PATH

        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        try:
            session: frida.core.Session = device.attach(pid)
            active_frida_sessions[app.current_binary] = session

            assert not session.is_detached

            stop_frida_analysis(app)

            time.sleep(0.2)
            assert session.is_detached
            assert any("Detach signal sent" in msg for msg in app.messages)

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass
            active_frida_sessions.pop(app.current_binary, None)

    def test_stop_frida_analysis_handles_no_active_session(self) -> None:
        """Stop command reports when no active session exists."""
        app = MockApp()
        app.current_binary = CALC_PATH

        active_frida_sessions.pop(app.current_binary, None)

        stop_frida_analysis(app)

        assert any("No active analysis found" in msg for msg in app.messages)

    def test_stop_frida_analysis_requires_loaded_binary(self) -> None:
        """Stop command validates that a binary is loaded."""
        app = MockApp()
        app.current_binary = None

        stop_frida_analysis(app)

        assert any("Error: No binary loaded" in msg for msg in app.messages)

    def test_active_sessions_dictionary_tracks_multiple_binaries(self) -> None:
        """Session dictionary correctly tracks multiple concurrent sessions."""
        device: frida.core.Device = frida.get_local_device()

        pid1: int = device.spawn([NOTEPAD_PATH])
        pid2: int = device.spawn([CALC_PATH])

        try:
            session1: frida.core.Session = device.attach(pid1)
            session2: frida.core.Session = device.attach(pid2)

            active_frida_sessions[NOTEPAD_PATH] = session1
            active_frida_sessions[CALC_PATH] = session2

            assert len(active_frida_sessions) >= 2
            assert NOTEPAD_PATH in active_frida_sessions
            assert CALC_PATH in active_frida_sessions

            assert not active_frida_sessions[NOTEPAD_PATH].is_detached
            assert not active_frida_sessions[CALC_PATH].is_detached

            session1.detach()
            session2.detach()

        finally:
            try:
                device.kill(pid1)
                device.kill(pid2)
            except frida.ProcessNotFoundError:
                pass
            active_frida_sessions.clear()


class TestStalkerSessionIntegration:
    """Test Stalker tracing integration for licensing analysis."""

    def test_stalker_session_initializes_with_valid_binary(self) -> None:
        """StalkerSession initializes correctly with Windows binary."""
        with tempfile.TemporaryDirectory() as tmpdir:
            session = StalkerSession(
                binary_path=NOTEPAD_PATH,
                output_dir=tmpdir,
                message_callback=lambda msg: None,
            )

            assert session.binary_path == NOTEPAD_PATH
            assert session.output_dir == tmpdir
            assert session.device is None
            assert session.session is None
            assert len(session.trace_events) == 0
            assert len(session.api_calls) == 0

    def test_stalker_session_creates_output_directory(self) -> None:
        """StalkerSession creates output directory if it doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = os.path.join(tmpdir, "stalker_output")
            session = StalkerSession(
                binary_path=CALC_PATH,
                output_dir=output_dir,
            )

            assert os.path.exists(output_dir)
            assert os.path.isdir(output_dir)

    def test_stalker_stats_dataclass_tracks_metrics(self) -> None:
        """StalkerStats correctly tracks tracing metrics."""
        stats = StalkerStats(
            total_instructions=15000,
            unique_blocks=450,
            coverage_entries=320,
            licensing_routines=8,
            api_calls=125,
            trace_duration=2.5,
        )

        assert stats.total_instructions == 15000
        assert stats.unique_blocks == 450
        assert stats.coverage_entries == 320
        assert stats.licensing_routines == 8
        assert stats.api_calls == 125
        assert stats.trace_duration == 2.5

    def test_trace_event_dataclass_captures_execution_data(self) -> None:
        """TraceEvent captures instruction-level trace information."""
        event = TraceEvent(
            event_type="call",
            address="0x401000",
            module="kernel32.dll",
            offset="0x1000",
            timestamp=1234567890,
            thread_id=4512,
            depth=3,
            backtrace=["0x401000", "0x402000", "0x403000"],
        )

        assert event.event_type == "call"
        assert event.address == "0x401000"
        assert event.module == "kernel32.dll"
        assert event.offset == "0x1000"
        assert event.timestamp == 1234567890
        assert event.thread_id == 4512
        assert event.depth == 3
        assert len(event.backtrace) == 3

    def test_api_call_event_identifies_licensing_apis(self) -> None:
        """APICallEvent flags licensing-related API calls."""
        licensing_call = APICallEvent(
            api_name="CryptDecrypt",
            module="advapi32.dll",
            timestamp=1234567890,
            thread_id=4512,
            backtrace=["0x401000"],
            is_licensing_related=True,
        )

        assert licensing_call.is_licensing_related
        assert licensing_call.api_name == "CryptDecrypt"
        assert licensing_call.module == "advapi32.dll"

    def test_coverage_entry_tracks_licensing_code(self) -> None:
        """CoverageEntry marks licensing-related code blocks."""
        entry = CoverageEntry(
            module="notepad.exe",
            offset="0x5000",
            address="0x405000",
            hit_count=42,
            is_licensing=True,
        )

        assert entry.is_licensing
        assert entry.hit_count == 42
        assert entry.module == "notepad.exe"


class TestStalkerControlFunctions:
    """Test Stalker session control and management functions."""

    def test_start_stalker_session_requires_loaded_binary(self) -> None:
        """Start Stalker validates binary is loaded before starting."""
        app = MockApp()
        app.current_binary = None

        result = start_stalker_session(app)

        assert result is False
        assert any("Error: No binary loaded" in msg for msg in app.messages)

    def test_start_stalker_session_prevents_duplicate_sessions(self) -> None:
        """Start Stalker prevents multiple sessions on same binary."""
        app = MockApp()
        app.current_binary = CALC_PATH

        test_session = RealTestStalkerSession(app.current_binary)
        active_stalker_sessions[app.current_binary] = test_session

        try:
            result = start_stalker_session(app)

            assert result is False
            assert any("already active" in msg for msg in app.messages)

        finally:
            active_stalker_sessions.pop(app.current_binary, None)

    def test_stop_stalker_session_requires_active_session(self) -> None:
        """Stop Stalker validates active session exists."""
        app = MockApp()
        app.current_binary = NOTEPAD_PATH

        active_stalker_sessions.pop(app.current_binary, None)

        result = stop_stalker_session(app)

        assert result is False
        assert any("No active session" in msg for msg in app.messages)

    def test_get_stalker_stats_returns_none_without_session(self) -> None:
        """Get stats returns None when no active session."""
        app = MockApp()
        app.current_binary = CALC_PATH

        active_stalker_sessions.pop(app.current_binary, None)

        result = get_stalker_stats(app)

        assert result is None

    def test_get_licensing_routines_returns_none_without_session(self) -> None:
        """Get licensing routines returns None without active session."""
        app = MockApp()
        app.current_binary = NOTEPAD_PATH

        active_stalker_sessions.pop(app.current_binary, None)

        result = get_licensing_routines_stalker(app)

        assert result is None

    def test_trace_function_stalker_requires_active_session(self) -> None:
        """Trace function validates active Stalker session exists."""
        app = MockApp()
        app.current_binary = CALC_PATH

        active_stalker_sessions.pop(app.current_binary, None)

        result = trace_function_stalker(app, "kernel32.dll", "CreateMutexW")

        assert result is False
        assert any("No active session" in msg for msg in app.messages)

    def test_collect_module_coverage_requires_active_session(self) -> None:
        """Collect coverage validates active session exists."""
        app = MockApp()
        app.current_binary = NOTEPAD_PATH

        active_stalker_sessions.pop(app.current_binary, None)

        result = collect_module_coverage_stalker(app, "notepad.exe")

        assert result is False
        assert any("No active session" in msg for msg in app.messages)


class TestStalkerMessageHandling:
    """Test Stalker message processing and data collection."""

    def test_stalker_session_processes_status_messages(self) -> None:
        """Stalker session logs status messages from script."""
        messages: list[str] = []

        session = StalkerSession(
            binary_path=CALC_PATH,
            message_callback=lambda msg: messages.append(msg),
        )

        message: dict[str, Any] = {
            "type": "send",
            "payload": {"type": "status", "message": "Stalker initialized"},
        }

        session._on_message(message, None)

        assert len(messages) >= 1
        assert any("Stalker initialized" in msg for msg in messages)

    def test_stalker_session_captures_api_calls(self) -> None:
        """Stalker session captures and stores API call events."""
        session = StalkerSession(binary_path=NOTEPAD_PATH)

        message: dict[str, Any] = {
            "type": "send",
            "payload": {
                "type": "api_call",
                "data": {
                    "api": "kernel32!CreateFileW",
                    "timestamp": 1234567890,
                    "tid": 4512,
                    "backtrace": ["0x401000", "0x402000"],
                },
                "licensing": False,
            },
        }

        session._on_message(message, None)

        assert len(session.api_calls) == 1
        assert session.api_calls[0].api_name == "kernel32!CreateFileW"
        assert session.api_calls[0].module == "kernel32"
        assert session.api_calls[0].timestamp == 1234567890
        assert session.api_calls[0].is_licensing_related is False

    def test_stalker_session_identifies_licensing_events(self) -> None:
        """Stalker session detects and tracks licensing-related events."""
        session = StalkerSession(binary_path=CALC_PATH)

        message: dict[str, Any] = {
            "type": "send",
            "payload": {
                "type": "licensing_event",
                "data": {
                    "api": "CryptDecrypt",
                    "caller": {"module": "notepad.exe", "offset": "0x5000"},
                },
            },
        }

        session._on_message(message, None)

        assert len(session.licensing_routines) >= 1
        assert "notepad.exe:0x5000" in session.licensing_routines

    def test_stalker_session_updates_progress_stats(self) -> None:
        """Stalker session updates statistics on progress messages."""
        session = StalkerSession(binary_path=NOTEPAD_PATH)

        message: dict[str, Any] = {
            "type": "send",
            "payload": {
                "type": "progress",
                "instructions": 10000,
                "blocks": 350,
                "coverage_entries": 280,
                "licensing_routines": 5,
            },
        }

        session._on_message(message, None)

        assert session.stats.total_instructions == 10000
        assert session.stats.unique_blocks == 350
        assert session.stats.coverage_entries == 280
        assert session.stats.licensing_routines == 5

    def test_stalker_session_handles_function_trace_complete(self) -> None:
        """Stalker session processes complete function trace data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            session = StalkerSession(binary_path=CALC_PATH, output_dir=tmpdir)

            trace_data = [
                {
                    "type": "call",
                    "address": "0x401000",
                    "module": "calc.exe",
                    "offset": "0x1000",
                },
                {
                    "type": "ret",
                    "address": "0x401050",
                    "module": "calc.exe",
                    "offset": "0x1050",
                },
            ]

            message: dict[str, Any] = {
                "type": "send",
                "payload": {
                    "type": "function_trace_complete",
                    "function": "calculate_license",
                    "trace_length": 2,
                    "trace": trace_data,
                },
            }

            session._on_message(message, None)

            assert len(session.trace_events) == 2
            assert session.trace_events[0].event_type == "call"
            assert session.trace_events[1].event_type == "ret"

            output_file = os.path.join(
                tmpdir, "function_trace_calculate_license.json"
            )
            assert os.path.exists(output_file)


class TestStalkerDataExport:
    """Test Stalker results export and persistence."""

    def test_stalker_exports_results_to_json(self) -> None:
        """Stalker session exports complete results to JSON file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            session = StalkerSession(binary_path=NOTEPAD_PATH, output_dir=tmpdir)

            session.stats.total_instructions = 50000
            session.stats.unique_blocks = 1200
            session.stats.licensing_routines = 10
            session.licensing_routines.add("notepad.exe:0x5000")
            session.licensing_routines.add("notepad.exe:0x6000")

            result_path = session.export_results()

            assert os.path.exists(result_path)
            assert result_path.endswith(".json")

            with open(result_path, encoding="utf-8") as f:
                data = json.load(f)

            assert data["binary"] == "notepad.exe"
            assert data["stats"]["total_instructions"] == 50000
            assert data["stats"]["unique_blocks"] == 1200
            assert len(data["licensing_routines"]) == 2

    def test_stalker_get_coverage_summary_calculates_statistics(self) -> None:
        """Stalker calculates coverage summary with hotspot analysis."""
        session = StalkerSession(binary_path=CALC_PATH)

        session.coverage_data["calc.exe:0x1000"] = CoverageEntry(
            module="calc.exe",
            offset="0x1000",
            address="0x401000",
            hit_count=500,
            is_licensing=True,
        )
        session.coverage_data["calc.exe:0x2000"] = CoverageEntry(
            module="calc.exe",
            offset="0x2000",
            address="0x402000",
            hit_count=200,
            is_licensing=False,
        )

        summary = session.get_coverage_summary()

        assert summary["total_entries"] == 2
        assert summary["licensing_entries"] == 1
        assert len(summary["top_hotspots"]) == 2
        assert summary["top_hotspots"][0]["hit_count"] == 500

    def test_stalker_get_api_summary_aggregates_calls(self) -> None:
        """Stalker aggregates API call statistics correctly."""
        session = StalkerSession(binary_path=NOTEPAD_PATH)

        session.api_calls.extend(
            [
                APICallEvent(
                    "CreateFileW", "kernel32", 1000, 4512, [], is_licensing_related=False
                ),
                APICallEvent(
                    "CreateFileW", "kernel32", 2000, 4512, [], is_licensing_related=False
                ),
                APICallEvent(
                    "CryptDecrypt", "advapi32", 3000, 4512, [], is_licensing_related=True
                ),
            ]
        )

        summary = session.get_api_summary()

        assert summary["total_calls"] == 3
        assert summary["unique_apis"] == 2
        assert summary["licensing_calls"] == 1
        assert summary["top_apis"][0]["api"] == "CreateFileW"
        assert summary["top_apis"][0]["count"] == 2


class TestAnalysisScriptsWhitelist:
    """Test approved analysis scripts whitelist."""

    def test_analysis_scripts_whitelist_contains_licensing_scripts(self) -> None:
        """Whitelist includes scripts for licensing analysis."""
        assert "registry_monitor.js" in ANALYSIS_SCRIPTS_WHITELIST
        assert "hwid_spoofer.js" in ANALYSIS_SCRIPTS_WHITELIST
        assert "time_bomb_defuser.js" in ANALYSIS_SCRIPTS_WHITELIST

    def test_analysis_scripts_whitelist_contains_protection_detectors(self) -> None:
        """Whitelist includes protection detection scripts."""
        assert "anti_debugger.js" in ANALYSIS_SCRIPTS_WHITELIST
        assert "virtualization_bypass.js" in ANALYSIS_SCRIPTS_WHITELIST
        assert "obfuscation_detector.js" in ANALYSIS_SCRIPTS_WHITELIST

    def test_analysis_scripts_whitelist_contains_network_interceptors(self) -> None:
        """Whitelist includes network analysis scripts."""
        assert "websocket_interceptor.js" in ANALYSIS_SCRIPTS_WHITELIST
        assert "telemetry_blocker.js" in ANALYSIS_SCRIPTS_WHITELIST
        assert "ntp_blocker.js" in ANALYSIS_SCRIPTS_WHITELIST

    def test_analysis_scripts_whitelist_contains_stalker_tracer(self) -> None:
        """Whitelist includes Stalker tracing script."""
        assert "stalker_tracer.js" in ANALYSIS_SCRIPTS_WHITELIST


class TestFridaErrorHandling:
    """Test error handling and recovery scenarios."""

    def test_frida_handles_process_not_found_error(self) -> None:
        """Frida gracefully handles non-existent process IDs."""
        device: frida.core.Device = frida.get_local_device()

        with pytest.raises(frida.ProcessNotFoundError):
            device.attach(999999)

    def test_frida_handles_invalid_binary_path(self) -> None:
        """Frida reports error for non-existent binary paths."""
        device: frida.core.Device = frida.get_local_device()

        with pytest.raises((frida.ExecutableNotFoundError, frida.NotSupportedError)):
            device.spawn(["C:\\nonexistent\\fake.exe"])

    def test_stalker_session_handles_missing_frida_import(self) -> None:
        """StalkerSession raises ImportError when Frida unavailable."""
        import sys

        frida_module = sys.modules.get("frida")
        try:
            sys.modules["frida"] = None

            from intellicrack.core.analysis.stalker_manager import (
                StalkerSession as TestSession,
            )

            with pytest.raises(ImportError, match="Frida is not installed"):
                TestSession(binary_path=CALC_PATH)

        finally:
            if frida_module:
                sys.modules["frida"] = frida_module

    def test_stalker_session_cleanup_handles_detached_session(self) -> None:
        """Stalker cleanup gracefully handles already-detached sessions."""
        session = StalkerSession(binary_path=NOTEPAD_PATH)

        session.cleanup()

        assert session._is_active is False


class TestFridaHookingCapabilities:
    """Test Frida's ability to hook and intercept functions."""

    def test_frida_intercepts_createfilew_calls_in_notepad(self) -> None:
        """Frida successfully hooks CreateFileW API in notepad.exe."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        script_source = """
        var createFileW = Module.getExportByName('kernel32.dll', 'CreateFileW');
        var hookInstalled = false;

        if (createFileW) {
            Interceptor.attach(createFileW, {
                onEnter: function(args) {
                    send({type: 'hook', api: 'CreateFileW', hooked: true});
                }
            });
            hookInstalled = true;
        }

        send({type: 'status', hook_installed: hookInstalled});
        """

        messages: list[dict[str, Any]] = []

        def on_message(message: dict[str, Any], data: bytes | None) -> None:
            if message.get("type") == "send":
                messages.append(message["payload"])

        try:
            session: frida.core.Session = device.attach(pid)
            script: frida.core.Script = session.create_script(script_source)
            script.on("message", on_message)
            script.load()

            device.resume(pid)
            time.sleep(0.3)

            assert len(messages) >= 1
            status_msg = [m for m in messages if m.get("type") == "status"]
            assert len(status_msg) >= 1
            assert status_msg[0]["hook_installed"] is True

            session.detach()

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_frida_reads_process_memory_in_calc(self) -> None:
        """Frida reads and analyzes process memory from calc.exe."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([CALC_PATH])

        script_source = """
        var mainModule = Process.enumerateModules()[0];
        send({
            type: 'memory_info',
            module: mainModule.name,
            base: mainModule.base.toString(),
            size: mainModule.size
        });

        var baseAddr = mainModule.base;
        var header = Memory.readByteArray(baseAddr, 64);
        send({type: 'memory_read', success: header !== null, bytes_read: 64});
        """

        messages: list[dict[str, Any]] = []

        def on_message(message: dict[str, Any], data: bytes | None) -> None:
            if message.get("type") == "send":
                messages.append(message["payload"])

        try:
            session: frida.core.Session = device.attach(pid)
            script: frida.core.Script = session.create_script(script_source)
            script.on("message", on_message)
            script.load()

            device.resume(pid)
            time.sleep(0.3)

            memory_info = [m for m in messages if m.get("type") == "memory_info"]
            memory_read = [m for m in messages if m.get("type") == "memory_read"]

            assert len(memory_info) >= 1
            assert "calc" in memory_info[0]["module"].lower()
            assert len(memory_read) >= 1
            assert memory_read[0]["success"] is True
            assert memory_read[0]["bytes_read"] == 64

            session.detach()

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    def test_frida_enumerates_loaded_modules_in_process(self) -> None:
        """Frida enumerates all loaded modules in target process."""
        device: frida.core.Device = frida.get_local_device()
        pid: int = device.spawn([NOTEPAD_PATH])

        script_source = """
        var modules = Process.enumerateModules();
        var moduleNames = modules.map(function(m) { return m.name.toLowerCase(); });

        send({
            type: 'modules',
            count: modules.length,
            has_kernel32: moduleNames.indexOf('kernel32.dll') !== -1,
            has_ntdll: moduleNames.indexOf('ntdll.dll') !== -1
        });
        """

        messages: list[dict[str, Any]] = []

        def on_message(message: dict[str, Any], data: bytes | None) -> None:
            if message.get("type") == "send":
                messages.append(message["payload"])

        try:
            session: frida.core.Session = device.attach(pid)
            script: frida.core.Script = session.create_script(script_source)
            script.on("message", on_message)
            script.load()

            device.resume(pid)
            time.sleep(0.3)

            modules_msg = [m for m in messages if m.get("type") == "modules"]
            assert len(modules_msg) >= 1
            assert modules_msg[0]["count"] >= 10
            assert modules_msg[0]["has_kernel32"] is True
            assert modules_msg[0]["has_ntdll"] is True

            session.detach()

        finally:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass
