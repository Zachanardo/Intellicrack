"""Tests for ProcessManager process tracking and cleanup.

Tests validate:
- Subprocess tracking with run_tracked and run_tracked_async
- External PID registration and termination
- Process cleanup during application shutdown
- Singleton behavior and thread safety
- Windows-specific process termination
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
import time
from collections.abc import Generator
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.process_manager import (
    ProcessManager,
    ProcessType,
    TrackedProcess,
)


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def process_manager() -> Generator[ProcessManager]:
    """Provide a fresh ProcessManager instance for each test."""
    ProcessManager.reset_instance()
    pm = ProcessManager.get_instance()
    yield pm
    pm.uninstall_handlers()
    ProcessManager.reset_instance()


class TestProcessManagerSingleton:
    """Test ProcessManager singleton pattern."""

    def test_singleton_returns_same_instance(self) -> None:
        """Verify ProcessManager always returns the same instance."""
        ProcessManager.reset_instance()
        pm1 = ProcessManager.get_instance()
        pm2 = ProcessManager.get_instance()
        pm3 = ProcessManager()

        assert pm1 is pm2
        assert pm1 is pm3

        ProcessManager.reset_instance()

    def test_reset_instance_clears_singleton(self) -> None:
        """Verify reset_instance creates a new instance."""
        ProcessManager.reset_instance()
        pm1 = ProcessManager.get_instance()
        ProcessManager.reset_instance()
        pm2 = ProcessManager.get_instance()

        assert pm1 is not pm2

        ProcessManager.reset_instance()


class TestRunTracked:
    """Test run_tracked subprocess execution with tracking."""

    def test_run_tracked_captures_stdout(
        self,
        process_manager: ProcessManager,
    ) -> None:
        """Verify run_tracked captures stdout from subprocess."""
        result = process_manager.run_tracked(
            [sys.executable, "-c", "print('hello world')"],
            name="test-stdout",
        )

        assert result.returncode == 0
        assert "hello world" in result.stdout

    def test_run_tracked_captures_stderr(
        self,
        process_manager: ProcessManager,
    ) -> None:
        """Verify run_tracked captures stderr from subprocess."""
        result = process_manager.run_tracked(
            [sys.executable, "-c", "import sys; sys.stderr.write('error msg')"],
            name="test-stderr",
        )

        assert "error msg" in result.stderr

    def test_run_tracked_returns_nonzero_exit_code(
        self,
        process_manager: ProcessManager,
    ) -> None:
        """Verify run_tracked returns correct exit code for failing process."""
        result = process_manager.run_tracked(
            [sys.executable, "-c", "import sys; sys.exit(42)"],
            name="test-exit-code",
        )

        assert result.returncode == 42

    def test_run_tracked_check_raises_on_failure(
        self,
        process_manager: ProcessManager,
    ) -> None:
        """Verify run_tracked raises CalledProcessError when check=True."""
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            process_manager.run_tracked(
                [sys.executable, "-c", "import sys; sys.exit(1)"],
                name="test-check-fail",
                check=True,
            )

        assert exc_info.value.returncode == 1

    def test_run_tracked_timeout_terminates_process(
        self,
        process_manager: ProcessManager,
    ) -> None:
        """Verify run_tracked terminates process on timeout."""
        with pytest.raises(subprocess.TimeoutExpired):
            process_manager.run_tracked(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                name="test-timeout",
                timeout=0.5,
            )

    def test_run_tracked_unregisters_after_completion(
        self,
        process_manager: ProcessManager,
    ) -> None:
        """Verify process is unregistered after successful completion."""
        initial_count = process_manager.process_count

        process_manager.run_tracked(
            [sys.executable, "-c", "print('done')"],
            name="test-unregister",
        )

        assert process_manager.process_count == initial_count

    def test_run_tracked_with_cwd(
        self,
        process_manager: ProcessManager,
        tmp_path: Path,
    ) -> None:
        """Verify run_tracked respects cwd parameter."""
        result = process_manager.run_tracked(
            [sys.executable, "-c", "import os; print(os.getcwd())"],
            name="test-cwd",
            cwd=str(tmp_path),
        )

        assert (
            str(tmp_path)
            in result.stdout.replace("\\", "/").replace(
                str(tmp_path).replace("\\", "/"),
                str(tmp_path),
            )
            or tmp_path.name in result.stdout
        )

    def test_run_tracked_with_env(
        self,
        process_manager: ProcessManager,
    ) -> None:
        """Verify run_tracked passes environment variables."""
        import os

        custom_env = os.environ.copy()
        custom_env["INTELLICRACK_TEST_VAR"] = "test_value_12345"

        result = process_manager.run_tracked(
            [
                sys.executable,
                "-c",
                "import os; print(os.environ.get('INTELLICRACK_TEST_VAR', ''))",
            ],
            name="test-env",
            env=custom_env,
        )

        assert "test_value_12345" in result.stdout

    def test_run_tracked_text_false_returns_bytes(
        self,
        process_manager: ProcessManager,
    ) -> None:
        """Verify run_tracked returns bytes when text=False."""
        result = process_manager.run_tracked(
            [sys.executable, "-c", "print('bytes test')"],
            name="test-bytes",
            text=False,
        )

        assert isinstance(result.stdout, bytes)
        assert b"bytes test" in result.stdout


class TestRunTrackedAsync:
    """Test run_tracked_async asynchronous subprocess execution."""

    @pytest.mark.asyncio
    async def test_run_tracked_async_captures_output(
        self,
        process_manager: ProcessManager,
    ) -> None:
        """Verify run_tracked_async captures stdout asynchronously."""
        result = await process_manager.run_tracked_async(
            [sys.executable, "-c", "print('async hello')"],
            name="test-async-stdout",
        )

        assert result.returncode == 0
        assert "async hello" in result.stdout

    @pytest.mark.asyncio
    async def test_run_tracked_async_timeout(
        self,
        process_manager: ProcessManager,
    ) -> None:
        """Verify run_tracked_async handles timeout correctly."""
        with pytest.raises(subprocess.TimeoutExpired):
            await process_manager.run_tracked_async(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                name="test-async-timeout",
                timeout=0.5,
            )

    @pytest.mark.asyncio
    async def test_run_tracked_async_check_raises(
        self,
        process_manager: ProcessManager,
    ) -> None:
        """Verify run_tracked_async raises on failure with check=True."""
        with pytest.raises(subprocess.CalledProcessError):
            await process_manager.run_tracked_async(
                [sys.executable, "-c", "import sys; sys.exit(1)"],
                name="test-async-check",
                check=True,
            )

    @pytest.mark.asyncio
    async def test_run_tracked_async_concurrent_execution(
        self,
        process_manager: ProcessManager,
    ) -> None:
        """Verify multiple async processes can run concurrently."""
        start_time = time.time()

        results = await asyncio.gather(
            process_manager.run_tracked_async(
                [sys.executable, "-c", "import time; time.sleep(0.5); print('a')"],
                name="test-concurrent-a",
            ),
            process_manager.run_tracked_async(
                [sys.executable, "-c", "import time; time.sleep(0.5); print('b')"],
                name="test-concurrent-b",
            ),
        )

        elapsed = time.time() - start_time

        assert len(results) == 2
        assert all(r.returncode == 0 for r in results)
        assert elapsed < 1.5


class TestExternalPidRegistration:
    """Test external PID registration and management."""

    def test_register_external_pid_stores_info(
        self,
        process_manager: ProcessManager,
    ) -> None:
        """Verify register_external_pid stores process information."""
        test_pid = 99999

        process_manager.register_external_pid(
            test_pid,
            name="test-external",
            process_type=ProcessType.SANDBOX,
            metadata={"test_key": "test_value"},
        )

        assert test_pid in process_manager._external_pids
        assert process_manager._external_pids[test_pid]["name"] == "test-external"
        assert process_manager._external_pids[test_pid]["process_type"] == ProcessType.SANDBOX
        assert process_manager._external_pids[test_pid]["metadata"]["test_key"] == "test_value"

    def test_unregister_external_pid_removes_entry(
        self,
        process_manager: ProcessManager,
    ) -> None:
        """Verify unregister_external_pid removes the registered PID."""
        test_pid = 99998

        process_manager.register_external_pid(test_pid, name="test-unregister")

        assert test_pid in process_manager._external_pids

        result = process_manager.unregister_external_pid(test_pid)

        assert result is True
        assert test_pid not in process_manager._external_pids

    def test_unregister_external_pid_returns_false_for_unknown(
        self,
        process_manager: ProcessManager,
    ) -> None:
        """Verify unregister_external_pid returns False for unknown PID."""
        result = process_manager.unregister_external_pid(12345)

        assert result is False

    def test_register_external_pid_skips_duplicate(
        self,
        process_manager: ProcessManager,
    ) -> None:
        """Verify register_external_pid does not overwrite existing entry."""
        test_pid = 99997

        process_manager.register_external_pid(test_pid, name="original-name")
        process_manager.register_external_pid(test_pid, name="new-name")

        assert process_manager._external_pids[test_pid]["name"] == "original-name"


class TestTerminateExternalPid:
    """Test external PID termination functionality."""

    def test_terminate_external_pid_handles_nonexistent_process(
        self,
        process_manager: ProcessManager,
    ) -> None:
        """Verify terminate_external_pid handles non-existent PID gracefully."""
        nonexistent_pid = 999999999

        process_manager.register_external_pid(nonexistent_pid, name="nonexistent")

        result = process_manager.terminate_external_pid(nonexistent_pid)

        assert result is False
        assert nonexistent_pid not in process_manager._external_pids

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific test")
    def test_terminate_external_pid_kills_real_process_windows(
        self,
        process_manager: ProcessManager,
    ) -> None:
        """Verify terminate_external_pid kills a real process on Windows."""
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        pid = proc.pid
        process_manager.register_external_pid(pid, name="test-kill-windows")

        time.sleep(0.2)

        result = process_manager.terminate_external_pid(pid, force=True)

        assert result is True

        exit_code = proc.wait(timeout=5)
        assert exit_code != 0

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix-specific test")
    def test_terminate_external_pid_kills_real_process_unix(
        self,
        process_manager: ProcessManager,
    ) -> None:
        """Verify terminate_external_pid kills a real process on Unix."""
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        pid = proc.pid
        process_manager.register_external_pid(pid, name="test-kill-unix")

        time.sleep(0.2)

        result = process_manager.terminate_external_pid(pid, force=True)

        assert result is True

        exit_code = proc.wait(timeout=5)
        assert exit_code != 0


class TestProcessCleanup:
    """Test process cleanup during shutdown."""

    def test_sync_cleanup_terminates_tracked_processes(
        self,
        process_manager: ProcessManager,
    ) -> None:
        """Verify _sync_cleanup terminates all tracked processes."""
        proc1 = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        proc2 = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        process_manager.register(proc1, name="cleanup-test-1")
        process_manager.register(proc2, name="cleanup-test-2")

        assert process_manager.process_count == 2

        time.sleep(0.2)

        process_manager._sync_cleanup()

        exit1 = proc1.wait(timeout=10)
        exit2 = proc2.wait(timeout=10)

        assert exit1 is not None
        assert exit2 is not None
        assert process_manager.process_count == 0

    def test_sync_cleanup_terminates_external_pids(
        self,
        process_manager: ProcessManager,
    ) -> None:
        """Verify _sync_cleanup terminates registered external PIDs."""
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        process_manager.register_external_pid(proc.pid, name="external-cleanup-test")

        time.sleep(0.2)

        process_manager._sync_cleanup()

        exit_code = proc.wait(timeout=10)

        assert exit_code is not None
        assert proc.pid not in process_manager._external_pids

    @pytest.mark.asyncio
    async def test_async_cleanup_terminates_all_processes(
        self,
        process_manager: ProcessManager,
    ) -> None:
        """Verify cleanup_all_async terminates all tracked processes."""
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        process_manager.register(proc, name="async-cleanup-test")
        process_manager.register_external_pid(99996, name="external-async-test")

        time.sleep(0.2)

        await process_manager.cleanup_all_async()

        exit_code = proc.wait(timeout=10)

        assert exit_code is not None
        assert process_manager.process_count == 0
        assert 99996 not in process_manager._external_pids


class TestTrackedProcess:
    """Test TrackedProcess dataclass functionality."""

    def test_tracked_process_is_running_for_active_process(self) -> None:
        """Verify is_running returns True for running process."""
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        tracked = TrackedProcess(
            process=proc,
            process_type=ProcessType.SUBPROCESS,
            name="test-is-running",
        )

        assert tracked.is_running is True
        assert tracked.pid == proc.pid

        proc.terminate()
        proc.wait()

    def test_tracked_process_is_running_false_after_completion(self) -> None:
        """Verify is_running returns False after process completes."""
        proc = subprocess.Popen(
            [sys.executable, "-c", "print('done')"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        proc.wait()

        tracked = TrackedProcess(
            process=proc,
            process_type=ProcessType.SUBPROCESS,
            name="test-completed",
        )

        assert tracked.is_running is False


class TestHandlerInstallation:
    """Test signal handler and atexit registration."""

    def test_install_handlers_registers_atexit(
        self,
        process_manager: ProcessManager,
    ) -> None:
        """Verify install_handlers registers atexit callback."""
        assert process_manager._atexit_registered is False

        process_manager.install_handlers()

        assert process_manager._atexit_registered is True

    def test_install_handlers_idempotent(
        self,
        process_manager: ProcessManager,
    ) -> None:
        """Verify install_handlers can be called multiple times safely."""
        process_manager.install_handlers()
        process_manager.install_handlers()
        process_manager.install_handlers()

        assert process_manager._atexit_registered is True

    def test_uninstall_handlers_clears_registration(
        self,
        process_manager: ProcessManager,
    ) -> None:
        """Verify uninstall_handlers clears atexit registration."""
        process_manager.install_handlers()
        assert process_manager._atexit_registered is True

        process_manager.uninstall_handlers()

        assert process_manager._atexit_registered is False

    def test_shutdown_event_initially_clear(
        self,
        process_manager: ProcessManager,
    ) -> None:
        """Verify shutdown event is initially not set."""
        assert process_manager.is_shutdown_requested() is False

    def test_shutdown_event_can_be_set_and_cleared(
        self,
        process_manager: ProcessManager,
    ) -> None:
        """Verify shutdown event can be set and cleared."""
        process_manager._shutdown_event.set()
        assert process_manager.is_shutdown_requested() is True

        process_manager.clear_shutdown_request()
        assert process_manager.is_shutdown_requested() is False


class TestProcessManagerProperties:
    """Test ProcessManager property methods."""

    def test_process_count_reflects_registered_processes(
        self,
        process_manager: ProcessManager,
    ) -> None:
        """Verify process_count returns correct count."""
        assert process_manager.process_count == 0

        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        process_manager.register(proc, name="count-test")

        assert process_manager.process_count == 1

        proc.terminate()
        proc.wait()
        process_manager.unregister(proc.pid)

    def test_running_count_reflects_active_processes(
        self,
        process_manager: ProcessManager,
    ) -> None:
        """Verify running_count returns count of active processes."""
        proc1 = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        proc2 = subprocess.Popen(
            [sys.executable, "-c", "print('done')"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        proc2.wait()

        process_manager.register(proc1, name="running-1")
        process_manager.register(proc2, name="completed-2")

        assert process_manager.process_count == 2
        assert process_manager.running_count == 1

        proc1.terminate()
        proc1.wait()

    def test_repr_includes_counts(
        self,
        process_manager: ProcessManager,
    ) -> None:
        """Verify __repr__ includes process counts."""
        repr_str = repr(process_manager)

        assert "ProcessManager" in repr_str
        assert "tracked=" in repr_str
        assert "running=" in repr_str

    def test_get_all_tracked_returns_list(
        self,
        process_manager: ProcessManager,
    ) -> None:
        """Verify get_all_tracked returns list of tracked processes."""
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        process_manager.register(proc, name="list-test")

        tracked_list = process_manager.get_all_tracked()

        assert len(tracked_list) == 1
        assert tracked_list[0].name == "list-test"

        proc.terminate()
        proc.wait()

    def test_get_running_processes_filters_completed(
        self,
        process_manager: ProcessManager,
    ) -> None:
        """Verify get_running_processes excludes completed processes."""
        proc1 = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        proc2 = subprocess.Popen(
            [sys.executable, "-c", "print('done')"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        proc2.wait()

        process_manager.register(proc1, name="running")
        process_manager.register(proc2, name="completed")

        running = process_manager.get_running_processes()

        assert len(running) == 1
        assert running[0].name == "running"

        proc1.terminate()
        proc1.wait()
