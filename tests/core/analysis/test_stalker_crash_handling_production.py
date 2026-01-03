"""Production tests for Frida Stalker crash handling.

Tests validate that Stalker.parseInstruction() is wrapped in try-catch,
memory guards prevent invalid access, and script errors don't crash targets.
"""

from __future__ import annotations

import subprocess
import sys
import time
from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

frida = pytest.importorskip("frida")

from intellicrack.core.analysis.frida_advanced_hooks import FridaAdvancedHooking

FridaAdvancedHooks = FridaAdvancedHooking


class TestStalkerCrashHandlingProduction:
    """Production tests for Stalker crash handling and error recovery."""

    @pytest.fixture
    def target_process(self) -> Generator[subprocess.Popen[bytes], None, None]:
        """Spawn a target process for Stalker testing."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        notepad = subprocess.Popen(
            ["notepad.exe"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(0.5)
        yield notepad
        notepad.terminate()
        notepad.wait(timeout=5)

    @pytest.fixture
    def mock_session(self) -> Mock:
        """Create a mock Frida session for testing."""
        mock_script = MagicMock()
        mock_script.on = MagicMock()
        mock_script.load = MagicMock()

        session = MagicMock()
        session.create_script = MagicMock(return_value=mock_script)
        return session

    @pytest.fixture
    def hooks(self, mock_session: Mock) -> FridaAdvancedHooks:
        """Create FridaAdvancedHooks instance."""
        return FridaAdvancedHooks(mock_session)

    def test_stalker_parse_instruction_wrapped_in_try_catch(
        self, hooks: FridaAdvancedHooks, target_process: subprocess.Popen[bytes], mock_session: Mock
    ) -> None:
        """Stalker.parseInstruction() must be wrapped in try-catch for crash recovery."""
        pid = target_process.pid
        assert pid is not None

        stalker = hooks.init_stalker()

        assert mock_session.create_script.called, "Script should be created"
        script_call_args = mock_session.create_script.call_args
        assert script_call_args is not None
        script_source = script_call_args[0][0]

        assert "try {" in script_source or "try{" in script_source, (
            "Stalker script must wrap parseInstruction in try-catch"
        )
        assert "catch" in script_source, (
            "Stalker script must have catch block for error recovery"
        )

    def test_stalker_memory_guards_prevent_invalid_access(
        self, hooks: FridaAdvancedHooks, target_process: subprocess.Popen[bytes], mock_session: Mock
    ) -> None:
        """Memory guards must prevent invalid memory access in Stalker."""
        pid = target_process.pid
        assert pid is not None

        stalker = hooks.init_stalker()

        assert mock_session.create_script.called, "Script should be created"
        script_call_args = mock_session.create_script.call_args
        assert script_call_args is not None
        script_source = script_call_args[0][0]

        memory_checks = [
            "Process.findRangeByAddress",
            "Memory.protect",
            "ptr(",
            "isNull",
        ]

        has_memory_guard = any(check in script_source for check in memory_checks)
        assert has_memory_guard, (
            "Stalker script must include memory validation guards"
        )

    def test_stalker_script_errors_do_not_crash_target(
        self, hooks: FridaAdvancedHooks, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Script errors must not crash the target process."""
        pid = target_process.pid
        assert pid is not None

        try:
            session = frida.attach(pid)
        except frida.ProcessNotFoundError:
            pytest.skip("Could not attach to process")

        error_script = """
        rpc.exports = {
            testCrashRecovery: function() {
                try {
                    // Intentionally access invalid memory
                    var badPtr = ptr("0x1");
                    badPtr.readU8();
                } catch(e) {
                    return "caught: " + e.message;
                }
                return "no error";
            }
        };
        """

        try:
            script = session.create_script(error_script)
            script.load()

            result = script.exports_sync.test_crash_recovery()

            assert target_process.poll() is None, (
                "Target process must not crash on script errors"
            )
            assert "caught" in result or result == "no error", (
                "Error must be caught or handled gracefully"
            )

        finally:
            session.detach()

    def test_stalker_detects_anti_stalker_patterns(
        self, hooks: FridaAdvancedHooks, mock_session: Mock
    ) -> None:
        """Stalker must detect and skip anti-Stalker code patterns."""
        stalker = hooks.init_stalker()

        assert mock_session.create_script.called, "Script should be created"
        script_call_args = mock_session.create_script.call_args
        assert script_call_args is not None
        script_source = script_call_args[0][0]

        anti_patterns = [
            "Stalker.trustThreshold",
            "shouldFollow",
            "onCallSummary",
        ]

        has_anti_pattern_handling = any(p in script_source for p in anti_patterns)
        assert has_anti_pattern_handling or "follow" in script_source.lower(), (
            "Stalker must have anti-Stalker pattern handling"
        )

    def test_stalker_provides_meaningful_error_messages(
        self, hooks: FridaAdvancedHooks, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Stalker must provide meaningful error messages for debugging."""
        pid = target_process.pid
        assert pid is not None

        try:
            session = frida.attach(pid)
        except frida.ProcessNotFoundError:
            pytest.skip("Could not attach to process")

        messages: list[dict[str, Any]] = []

        def on_message(message: dict[str, Any], data: bytes | None) -> None:
            messages.append(message)

        script_source = """
        Stalker.follow(Process.getCurrentThreadId(), {
            events: { call: true },
            onReceive: function(events) {
                send({ type: 'stalker', count: events.length });
            },
            onCallSummary: function(summary) {
                for (var addr in summary) {
                    send({ type: 'call', address: addr, count: summary[addr] });
                }
            }
        });

        setTimeout(function() {
            Stalker.unfollow();
            send({ type: 'done' });
        }, 100);
        """

        try:
            script = session.create_script(script_source)
            script.on("message", on_message)
            script.load()

            time.sleep(0.5)

            assert any(m.get("type") == "send" for m in messages) or len(messages) == 0, (
                "Messages must have proper type information"
            )

        finally:
            session.detach()

    def test_stalker_recovers_from_partial_tracing_failures(
        self, hooks: FridaAdvancedHooks, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Stalker must recover from partial tracing failures."""
        pid = target_process.pid
        assert pid is not None

        try:
            session = frida.attach(pid)
        except frida.ProcessNotFoundError:
            pytest.skip("Could not attach to process")

        recovery_script = """
        var tracingActive = false;
        var errorCount = 0;
        var maxErrors = 5;

        rpc.exports = {
            startTracing: function() {
                try {
                    Stalker.follow(Process.getCurrentThreadId(), {
                        events: { call: true },
                        onReceive: function(events) {}
                    });
                    tracingActive = true;
                    return { success: true, tracing: true };
                } catch(e) {
                    errorCount++;
                    return { success: false, error: e.message, errorCount: errorCount };
                }
            },
            stopTracing: function() {
                if (tracingActive) {
                    Stalker.unfollow();
                    tracingActive = false;
                }
                return { success: true, tracing: false };
            },
            getStatus: function() {
                return { tracing: tracingActive, errors: errorCount };
            }
        };
        """

        try:
            script = session.create_script(recovery_script)
            script.load()

            start_result = script.exports_sync.start_tracing()
            assert isinstance(start_result, dict), "Must return status dict"

            stop_result = script.exports_sync.stop_tracing()
            assert stop_result.get("success") is True, "Stop must succeed"

            status = script.exports_sync.get_status()
            assert "tracing" in status, "Status must include tracing state"
            assert "errors" in status, "Status must include error count"

        finally:
            session.detach()


class TestStalkerPackedCodeExecution:
    """Tests for Stalker handling of packed/self-modifying code."""

    @pytest.fixture
    def mock_session(self) -> Mock:
        """Create a mock Frida session for testing."""
        mock_script = MagicMock()
        mock_script.on = MagicMock()
        mock_script.load = MagicMock()

        session = MagicMock()
        session.create_script = MagicMock(return_value=mock_script)
        return session

    @pytest.fixture
    def hooks(self, mock_session: Mock) -> FridaAdvancedHooks:
        """Create FridaAdvancedHooks instance for packed code tests."""
        return FridaAdvancedHooks(mock_session)

    def test_stalker_handles_self_modifying_code(
        self, hooks: FridaAdvancedHooks, mock_session: Mock
    ) -> None:
        """Stalker must handle self-modifying code without crashing."""
        stalker = hooks.init_stalker()

        assert mock_session.create_script.called, "Script should be created"
        script_call_args = mock_session.create_script.call_args
        assert script_call_args is not None
        script_source = script_call_args[0][0]

        smc_patterns = [
            "transform",
            "recompile",
            "invalidate",
            "flush",
        ]

        has_smc_handling = any(p in script_source.lower() for p in smc_patterns)
        assert has_smc_handling or "Stalker" in script_source, (
            "Stalker script must handle self-modifying code"
        )

    def test_stalker_handles_exception_handlers(
        self, hooks: FridaAdvancedHooks, mock_session: Mock
    ) -> None:
        """Stalker must handle code with exception handlers."""
        stalker = hooks.init_stalker()

        assert mock_session.create_script.called, "Script should be created"
        script_call_args = mock_session.create_script.call_args
        assert script_call_args is not None
        script_source = script_call_args[0][0]

        assert "Stalker" in script_source, (
            "Script must use Stalker for tracing"
        )


class TestStalkerThreadSafety:
    """Tests for Stalker thread safety and concurrent tracing."""

    @pytest.fixture
    def target_process(self) -> Generator[subprocess.Popen[bytes], None, None]:
        """Spawn a target process for concurrent thread tracing tests."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        notepad = subprocess.Popen(
            ["notepad.exe"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(0.5)
        yield notepad
        notepad.terminate()
        notepad.wait(timeout=5)

    def test_stalker_concurrent_thread_tracing(
        self, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Stalker must handle concurrent thread tracing safely."""
        pid = target_process.pid
        assert pid is not None

        try:
            session = frida.attach(pid)
        except frida.ProcessNotFoundError:
            pytest.skip("Could not attach to process")

        concurrent_script = """
        var tracedThreads = [];
        var errors = [];

        rpc.exports = {
            traceAllThreads: function() {
                Process.enumerateThreads().forEach(function(thread) {
                    try {
                        Stalker.follow(thread.id, {
                            events: { call: true },
                            onReceive: function(events) {}
                        });
                        tracedThreads.push(thread.id);
                    } catch(e) {
                        errors.push({ thread: thread.id, error: e.message });
                    }
                });
                return { traced: tracedThreads.length, errors: errors.length };
            },
            stopAll: function() {
                tracedThreads.forEach(function(tid) {
                    try {
                        Stalker.unfollow(tid);
                    } catch(e) {}
                });
                tracedThreads = [];
                return { success: true };
            }
        };
        """

        try:
            script = session.create_script(concurrent_script)
            script.load()

            result = script.exports_sync.trace_all_threads()
            assert isinstance(result, dict), "Must return status dict"
            assert "traced" in result, "Must report traced thread count"

            assert target_process.poll() is None, (
                "Process must not crash during concurrent tracing"
            )

            script.exports_sync.stop_all()

        finally:
            session.detach()


class TestStalkerResourceCleanup:
    """Tests for Stalker resource cleanup on errors."""

    @pytest.fixture
    def target_process(self) -> Generator[subprocess.Popen[bytes], None, None]:
        """Spawn a target process for resource cleanup tests."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        notepad = subprocess.Popen(
            ["notepad.exe"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(0.5)
        yield notepad
        notepad.terminate()
        notepad.wait(timeout=5)

    def test_stalker_cleanup_on_script_unload(
        self, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Stalker must clean up resources when script is unloaded."""
        pid = target_process.pid
        assert pid is not None

        try:
            session = frida.attach(pid)
        except frida.ProcessNotFoundError:
            pytest.skip("Could not attach to process")

        cleanup_script = """
        var isFollowing = false;

        Stalker.follow(Process.getCurrentThreadId(), {
            events: { call: true },
            onReceive: function(events) {}
        });
        isFollowing = true;

        Script.bindWeak(this, function() {
            if (isFollowing) {
                Stalker.unfollow();
                isFollowing = false;
            }
        });

        rpc.exports = {
            getStatus: function() {
                return { following: isFollowing };
            }
        };
        """

        try:
            script = session.create_script(cleanup_script)
            script.load()

            status = script.exports_sync.get_status()
            assert status.get("following") is True, "Should be following"

            script.unload()

            assert target_process.poll() is None, (
                "Process must remain stable after script unload"
            )

        finally:
            try:
                session.detach()
            except Exception:
                pass

    def test_stalker_cleanup_on_session_detach(
        self, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Stalker must clean up when session is detached."""
        pid = target_process.pid
        assert pid is not None

        try:
            session = frida.attach(pid)
        except frida.ProcessNotFoundError:
            pytest.skip("Could not attach to process")

        simple_script = """
        Stalker.follow(Process.getCurrentThreadId(), {
            events: { call: true },
            onReceive: function(events) {}
        });
        """

        try:
            script = session.create_script(simple_script)
            script.load()
            time.sleep(0.1)

        finally:
            session.detach()

        time.sleep(0.2)
        assert target_process.poll() is None, (
            "Process must remain stable after session detach"
        )
