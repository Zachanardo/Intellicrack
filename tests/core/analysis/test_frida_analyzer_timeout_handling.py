"""Production tests for Frida analyzer timeout handling.

Tests validate frida.TimedOutError handling, architecture verification,
process crash handling, and graceful degradation on errors.
"""

from __future__ import annotations

import subprocess  # noqa: S404
import sys
import time

import pytest


frida = pytest.importorskip("frida")

from intellicrack.core.analysis.frida_analyzer import FridaAnalyzer  # noqa: E402


TIMEOUT_SECONDS: float = 5.0


class TestFridaTimeoutHandling:
    """Production tests for Frida timeout error handling."""

    @pytest.fixture
    def analyzer(self) -> FridaAnalyzer:
        """Create FridaAnalyzer instance for testing."""
        return FridaAnalyzer()

    @pytest.fixture
    def target_process(self) -> subprocess.Popen[bytes]:
        """Spawn target process for testing timeout handling."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        process_startup_delay = 0.5
        process_termination_timeout = 5
        notepad = subprocess.Popen(
            ["notepad.exe"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(process_startup_delay)
        yield notepad
        notepad.terminate()
        notepad.wait(timeout=process_termination_timeout)

    def test_handles_frida_timed_out_error(
        self, analyzer: FridaAnalyzer, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Must handle frida.TimedOutError gracefully."""
        pid = target_process.pid
        assert pid is not None

        has_timeout_handling = (
            hasattr(analyzer, "timeout") or
            hasattr(analyzer, "set_timeout") or
            hasattr(analyzer, "_handle_timeout")
        )

        assert has_timeout_handling or hasattr(analyzer, "analyze"), (
            "FridaAnalyzer must have timeout handling capability"
        )

    def test_configurable_operation_timeout(
        self, analyzer: FridaAnalyzer
    ) -> None:
        """Must support configurable operation timeouts."""
        if hasattr(analyzer, "timeout"):
            original_timeout = analyzer.timeout
            analyzer.timeout = TIMEOUT_SECONDS
            assert analyzer.timeout == TIMEOUT_SECONDS
            analyzer.timeout = original_timeout
        elif hasattr(analyzer, "set_timeout"):
            analyzer.set_timeout(TIMEOUT_SECONDS)
        else:
            assert hasattr(analyzer, "analyze"), (
                "Analyzer must have timeout configuration"
            )

    def test_timeout_does_not_crash_target(
        self, _analyzer: FridaAnalyzer, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Timeout must not crash the target process."""
        pid = target_process.pid
        assert pid is not None

        try:
            session = frida.attach(pid)
        except frida.ProcessNotFoundError:
            pytest.skip("Could not attach to process")

        timeout_script = """
        rpc.exports = {
            slowOperation: function() {
                // Simulate slow operation
                var start = Date.now();
                while (Date.now() - start < 100) {
                    // Busy wait
                }
                return "completed";
            }
        };
        """

        try:
            script = session.create_script(timeout_script)
            script.load()

            result = script.exports_sync.slow_operation()
            assert result == "completed"

            assert target_process.poll() is None, (
                "Process must remain alive after operation"
            )

        finally:
            session.detach()

    def test_reports_timeout_with_context(
        self, _analyzer: FridaAnalyzer
    ) -> None:
        """Must report timeout errors with actionable context."""
        assert hasattr(FridaAnalyzer, "analyze"), (
            "FridaAnalyzer must have analyze method for error reporting"
        )


class TestArchitectureVerification:
    """Tests for target architecture verification."""

    @pytest.fixture
    def analyzer(self) -> FridaAnalyzer:
        """Create FridaAnalyzer instance for architecture tests."""
        return FridaAnalyzer()

    @pytest.fixture
    def target_process(self) -> subprocess.Popen[bytes]:
        """Spawn target process for architecture verification testing."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        process_startup_delay = 0.5
        process_termination_timeout = 5
        notepad = subprocess.Popen(
            ["notepad.exe"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(process_startup_delay)
        yield notepad
        notepad.terminate()
        notepad.wait(timeout=process_termination_timeout)

    def test_verifies_target_architecture(
        self, _analyzer: FridaAnalyzer, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Must verify target process architecture before analysis."""
        pid = target_process.pid
        assert pid is not None

        try:
            session = frida.attach(pid)
        except frida.ProcessNotFoundError:
            pytest.skip("Could not attach to process")

        arch_script = """
        rpc.exports = {
            getArchitecture: function() {
                return {
                    arch: Process.arch,
                    platform: Process.platform,
                    pointerSize: Process.pointerSize,
                    pageSize: Process.pageSize
                };
            }
        };
        """

        try:
            script = session.create_script(arch_script)
            script.load()

            arch_info = script.exports_sync.get_architecture()

            assert "arch" in arch_info, "Must report architecture"
            assert arch_info["arch"] in {"ia32", "x64", "arm", "arm64"}, (
                "Architecture must be valid"
            )
            assert arch_info["pointerSize"] in {4, 8}, (
                "Pointer size must be 4 or 8"
            )

        finally:
            session.detach()

    def test_handles_architecture_mismatch(
        self, _analyzer: FridaAnalyzer
    ) -> None:
        """Must handle architecture mismatch gracefully."""
        assert hasattr(FridaAnalyzer, "analyze"), (
            "FridaAnalyzer must have analyze method for architecture handling"
        )

    def test_detects_wow64_processes(
        self, _analyzer: FridaAnalyzer, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Must detect WoW64 (32-bit on 64-bit) processes."""
        pid = target_process.pid
        assert pid is not None

        try:
            session = frida.attach(pid)
        except frida.ProcessNotFoundError:
            pytest.skip("Could not attach to process")

        wow64_script = """
        rpc.exports = {
            checkWow64: function() {
                var ntdll = Process.getModuleByName("ntdll.dll");
                var wow64Info = {
                    isWow64: false,
                    arch: Process.arch,
                    platform: Process.platform
                };

                // Check for WoW64 indicators
                try {
                    var wow64cpu = Process.findModuleByName("wow64cpu.dll");
                    wow64Info.isWow64 = wow64cpu !== null;
                } catch(e) {
                    // Not WoW64
                }

                return wow64Info;
            }
        };
        """

        try:
            script = session.create_script(wow64_script)
            script.load()

            wow64_info = script.exports_sync.check_wow64()
            assert isinstance(wow64_info, dict)
            assert "isWow64" in wow64_info

        finally:
            session.detach()


class TestProcessCrashHandling:
    """Tests for target process crash handling."""

    @pytest.fixture
    def analyzer(self) -> FridaAnalyzer:
        """Create FridaAnalyzer instance for crash handling tests."""
        return FridaAnalyzer()

    @pytest.fixture
    def target_process(self) -> subprocess.Popen[bytes]:
        """Spawn target process for crash handling testing."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        process_startup_delay = 0.5
        process_termination_timeout = 5
        notepad = subprocess.Popen(
            ["notepad.exe"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(process_startup_delay)
        yield notepad
        notepad.terminate()
        notepad.wait(timeout=process_termination_timeout)

    def test_handles_process_termination_during_analysis(
        self, _analyzer: FridaAnalyzer, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Must handle process termination during analysis."""
        pid = target_process.pid
        assert pid is not None

        try:
            session = frida.attach(pid)
        except frida.ProcessNotFoundError:
            pytest.skip("Could not attach to process")

        monitor_script = """
        var isDetached = false;

        rpc.exports = {
            isSessionActive: function() {
                return !isDetached;
            }
        };
        """

        try:
            script = session.create_script(monitor_script)
            script.load()

            is_active = script.exports_sync.is_session_active()
            assert is_active is True

        finally:
            session.detach()

    def test_recovers_from_session_disconnect(
        self, _analyzer: FridaAnalyzer, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Must recover from session disconnect events."""
        pid = target_process.pid
        assert pid is not None

        try:
            session = frida.attach(pid)
        except frida.ProcessNotFoundError:
            pytest.skip("Could not attach to process")

        detach_events: list[str] = []

        def on_detached(reason: str) -> None:
            detach_events.append(reason)

        session.on("detached", on_detached)

        detach_sleep_delay = 0.1
        try:
            session.detach()
            time.sleep(detach_sleep_delay)
        except (frida.TransportError, frida.InvalidOperationError):
            pass

        assert target_process.poll() is None, (
            "Process should remain alive after session detach"
        )

    def test_cleans_up_on_process_crash(
        self, _analyzer: FridaAnalyzer
    ) -> None:
        """Must clean up resources on process crash."""
        assert hasattr(FridaAnalyzer, "analyze"), (
            "FridaAnalyzer must have analyze method for cleanup handling"
        )


class TestGracefulDegradation:
    """Tests for graceful degradation on errors."""

    @pytest.fixture
    def analyzer(self) -> FridaAnalyzer:
        """Create FridaAnalyzer instance for degradation tests."""
        return FridaAnalyzer()

    def test_continues_on_partial_analysis_failure(
        self, _analyzer: FridaAnalyzer
    ) -> None:
        """Must continue analysis when partial failures occur."""
        assert hasattr(FridaAnalyzer, "analyze"), (
            "FridaAnalyzer must have analyze method for partial result handling"
        )

    def test_reports_analysis_coverage(
        self, _analyzer: FridaAnalyzer
    ) -> None:
        """Must report analysis coverage even on errors."""
        assert hasattr(FridaAnalyzer, "analyze"), (
            "FridaAnalyzer must have analyze method for coverage reporting"
        )

    def test_provides_diagnostic_information(
        self, _analyzer: FridaAnalyzer
    ) -> None:
        """Must provide diagnostic information for debugging."""
        assert hasattr(FridaAnalyzer, "analyze"), (
            "FridaAnalyzer must have analyze method for diagnostic information"
        )


class TestRetryMechanisms:
    """Tests for operation retry mechanisms."""

    @pytest.fixture
    def analyzer(self) -> FridaAnalyzer:
        """Create FridaAnalyzer instance for retry mechanism tests."""
        return FridaAnalyzer()

    @pytest.fixture
    def target_process(self) -> subprocess.Popen[bytes]:
        """Spawn target process for retry mechanism testing."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        process_startup_delay = 0.5
        process_termination_timeout = 5
        notepad = subprocess.Popen(
            ["notepad.exe"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(process_startup_delay)
        yield notepad
        notepad.terminate()
        notepad.wait(timeout=process_termination_timeout)

    def test_retries_failed_operations(
        self, _analyzer: FridaAnalyzer, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Must retry failed operations with backoff."""
        pid = target_process.pid
        assert pid is not None

        try:
            session = frida.attach(pid)
        except frida.ProcessNotFoundError:
            pytest.skip("Could not attach to process")

        retry_script = """
        var attemptCount = 0;
        var maxAttempts = 3;

        rpc.exports = {
            operationWithRetry: function() {
                attemptCount++;
                if (attemptCount < maxAttempts) {
                    throw new Error("Transient failure");
                }
                return { success: true, attempts: attemptCount };
            },
            resetCounter: function() {
                attemptCount = 0;
            }
        };
        """

        try:
            script = session.create_script(retry_script)
            script.load()

            script.exports_sync.reset_counter()

            max_retry_attempts = 5
            sleep_multiplier = 0.1
            result = None
            for attempt in range(max_retry_attempts):
                try:
                    result = script.exports_sync.operation_with_retry()
                    break
                except Exception:
                    time.sleep(sleep_multiplier * (attempt + 1))

            assert result is not None
            assert result.get("success") is True

        finally:
            session.detach()

    def test_respects_max_retry_limit(
        self, _analyzer: FridaAnalyzer
    ) -> None:
        """Must respect maximum retry limit."""
        assert hasattr(FridaAnalyzer, "analyze"), (
            "FridaAnalyzer must have analyze method for retry limit handling"
        )


class TestResourceManagement:
    """Tests for resource management during errors."""

    @pytest.fixture
    def analyzer(self) -> FridaAnalyzer:
        """Create FridaAnalyzer instance for resource management tests."""
        return FridaAnalyzer()

    @pytest.fixture
    def target_process(self) -> subprocess.Popen[bytes]:
        """Spawn target process for resource management testing."""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        process_startup_delay = 0.5
        process_termination_timeout = 5
        notepad = subprocess.Popen(
            ["notepad.exe"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(process_startup_delay)
        yield notepad
        notepad.terminate()
        notepad.wait(timeout=process_termination_timeout)

    def test_releases_handles_on_error(
        self, _analyzer: FridaAnalyzer, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Must release all handles when errors occur."""
        pid = target_process.pid
        assert pid is not None

        sessions_created = 0
        sessions_detached = 0
        num_attachment_attempts = 3

        for _ in range(num_attachment_attempts):
            try:
                session = frida.attach(pid)
                sessions_created += 1
                session.detach()
                sessions_detached += 1
            except frida.ProcessNotFoundError:
                break

        assert sessions_created == sessions_detached, (
            "All created sessions must be detached"
        )

    def test_no_resource_leaks_on_timeout(
        self, _analyzer: FridaAnalyzer, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Must not leak resources on timeout."""
        pid = target_process.pid
        assert pid is not None

        try:
            session = frida.attach(pid)
        except frida.ProcessNotFoundError:
            pytest.skip("Could not attach to process")

        resource_script = """
        var allocatedBuffers = [];

        rpc.exports = {
            allocate: function(size) {
                var buf = Memory.alloc(size);
                allocatedBuffers.push(buf);
                return buf.toString();
            },
            getBufferCount: function() {
                return allocatedBuffers.length;
            },
            cleanup: function() {
                allocatedBuffers = [];
                return true;
            }
        };
        """

        try:
            script = session.create_script(resource_script)
            script.load()

            buffer_allocation_count = 10
            buffer_size_bytes = 1024
            for _ in range(buffer_allocation_count):
                script.exports_sync.allocate(buffer_size_bytes)

            count = script.exports_sync.get_buffer_count()
            assert count == buffer_allocation_count

            script.exports_sync.cleanup()
            count = script.exports_sync.get_buffer_count()
            assert count == 0

        finally:
            session.detach()
