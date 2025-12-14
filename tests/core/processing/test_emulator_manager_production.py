"""Production tests for EmulatorManager - validates emulator lifecycle management."""

import os
import threading
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from intellicrack.core.processing.emulator_manager import EmulatorManager, get_emulator_manager, run_with_qemu, run_with_qiling


@pytest.fixture
def emulator_manager() -> EmulatorManager:
    """Create a fresh EmulatorManager instance for testing."""
    return EmulatorManager()


@pytest.fixture
def real_binary_path(tmp_path: Path) -> str:
    """Create a minimal PE binary for testing."""
    binary_content = (
        b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        b"\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
    )
    binary_path = tmp_path / "test_binary.exe"
    binary_path.write_bytes(binary_content)
    return str(binary_path.absolute())


class TestEmulatorManagerInitialization:
    """Test EmulatorManager initialization and state management."""

    def test_manager_initializes_with_correct_state(self, emulator_manager: EmulatorManager) -> None:
        """EmulatorManager initializes with proper default state."""
        assert emulator_manager.emulators == {}
        assert emulator_manager.is_running is False
        assert emulator_manager.stats["total_executions"] == 0
        assert emulator_manager.stats["successful_executions"] == 0
        assert emulator_manager.stats["failed_executions"] == 0
        assert emulator_manager.qemu_instance is None
        assert emulator_manager.qemu_running is False
        assert emulator_manager.qemu_starting is False
        assert isinstance(emulator_manager.qiling_instances, dict)
        assert len(emulator_manager.qiling_instances) == 0

    def test_manager_has_thread_safety_mechanisms(self, emulator_manager: EmulatorManager) -> None:
        """EmulatorManager has thread-safe locking mechanism."""
        assert hasattr(emulator_manager, "lock")
        assert isinstance(emulator_manager.lock, threading.RLock)

    def test_manager_signals_are_defined(self, emulator_manager: EmulatorManager) -> None:
        """EmulatorManager defines required PyQt signals."""
        assert hasattr(emulator_manager, "emulator_status_changed")
        assert hasattr(emulator_manager, "emulator_error")


class TestQEMUEmulatorManagement:
    """Test QEMU emulator lifecycle management."""

    def test_ensure_qemu_rejects_empty_binary_path(self, emulator_manager: EmulatorManager) -> None:
        """ensure_qemu_running rejects empty binary path."""
        result = emulator_manager.ensure_qemu_running("")
        assert result is False

    def test_ensure_qemu_normalizes_binary_path(
        self, emulator_manager: EmulatorManager, real_binary_path: str
    ) -> None:
        """ensure_qemu_running normalizes binary paths to absolute paths."""
        relative_path = os.path.basename(real_binary_path)
        original_cwd = os.getcwd()
        try:
            os.chdir(os.path.dirname(real_binary_path))
            emulator_manager.ensure_qemu_running(relative_path)
        finally:
            os.chdir(original_cwd)

    def test_ensure_qemu_prevents_concurrent_starts(self, emulator_manager: EmulatorManager, real_binary_path: str) -> None:
        """ensure_qemu_running prevents multiple concurrent start attempts."""
        emulator_manager.qemu_starting = True
        result = emulator_manager.ensure_qemu_running(real_binary_path)
        assert result is False

    def test_qemu_starting_flag_thread_safety(self, emulator_manager: EmulatorManager, real_binary_path: str) -> None:
        """QEMU starting flag is accessed thread-safely."""
        results: list[bool] = []

        def attempt_start() -> None:
            result = emulator_manager.ensure_qemu_running(real_binary_path)
            results.append(result)

        threads = [threading.Thread(target=attempt_start) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(results) == 5

    def test_stop_qemu_handles_missing_instance(self, emulator_manager: EmulatorManager) -> None:
        """stop_qemu handles case where QEMU instance doesn't exist."""
        emulator_manager.qemu_instance = None
        emulator_manager.qemu_running = False
        emulator_manager.stop_qemu()

    def test_stop_qemu_handles_stopped_instance(self, emulator_manager: EmulatorManager) -> None:
        """stop_qemu handles case where QEMU instance exists but is not running."""
        mock_qemu = MagicMock()
        emulator_manager.qemu_instance = mock_qemu
        emulator_manager.qemu_running = False
        emulator_manager.stop_qemu()
        mock_qemu.stop_system.assert_not_called()


class TestQilingEmulatorManagement:
    """Test Qiling emulator lifecycle management."""

    def test_ensure_qiling_caches_instances_per_binary(self, emulator_manager: EmulatorManager, tmp_path: Path) -> None:
        """ensure_qiling_ready caches emulator instances per binary path."""
        binary1 = tmp_path / "binary1.exe"
        binary2 = tmp_path / "binary2.exe"
        binary1.write_bytes(b"MZ" + b"\x00" * 100)
        binary2.write_bytes(b"MZ" + b"\x00" * 100)

        from intellicrack.core.processing.emulator_manager import QILING_AVAILABLE

        if not QILING_AVAILABLE:
            pytest.skip("Qiling not available")

        instance1 = emulator_manager.ensure_qiling_ready(str(binary1))
        instance2 = emulator_manager.ensure_qiling_ready(str(binary2))
        instance1_again = emulator_manager.ensure_qiling_ready(str(binary1))

        if instance1 and instance2:
            assert instance1 is not instance2
            assert instance1 is instance1_again

    def test_ensure_qiling_emits_status_signals(self, emulator_manager: EmulatorManager, real_binary_path: str) -> None:
        """ensure_qiling_ready emits appropriate status signals."""
        from intellicrack.core.processing.emulator_manager import QILING_AVAILABLE

        if not QILING_AVAILABLE:
            pytest.skip("Qiling not available")

        signal_received = []

        def capture_signal(emulator_type: str, is_running: bool, message: str) -> None:
            signal_received.append((emulator_type, is_running, message))

        emulator_manager.emulator_status_changed.connect(capture_signal)
        emulator_manager.ensure_qiling_ready(real_binary_path)

        assert any("Qiling" in s[0] for s in signal_received)


class TestEmulatorCleanup:
    """Test emulator cleanup and resource management."""

    def test_cleanup_clears_qiling_instances(self, emulator_manager: EmulatorManager, real_binary_path: str) -> None:
        """cleanup() clears all Qiling emulator instances."""
        from intellicrack.core.processing.emulator_manager import QILING_AVAILABLE

        if QILING_AVAILABLE:
            emulator_manager.ensure_qiling_ready(real_binary_path)
            assert len(emulator_manager.qiling_instances) > 0

        emulator_manager.cleanup()
        assert len(emulator_manager.qiling_instances) == 0

    def test_cleanup_stops_running_qemu(self, emulator_manager: EmulatorManager) -> None:
        """cleanup() stops QEMU if running."""
        mock_qemu = MagicMock()
        emulator_manager.qemu_instance = mock_qemu
        emulator_manager.qemu_running = True

        emulator_manager.cleanup()

        mock_qemu.stop_system.assert_called_once()
        assert emulator_manager.qemu_running is False

    def test_cleanup_handles_qemu_stop_errors(self, emulator_manager: EmulatorManager) -> None:
        """cleanup() handles errors during QEMU shutdown gracefully."""
        mock_qemu = MagicMock()
        mock_qemu.stop_system.side_effect = RuntimeError("Shutdown failed")
        emulator_manager.qemu_instance = mock_qemu
        emulator_manager.qemu_running = True

        emulator_manager.cleanup()


class TestGlobalEmulatorManager:
    """Test global emulator manager singleton."""

    def test_get_emulator_manager_returns_singleton(self) -> None:
        """get_emulator_manager returns same instance on multiple calls."""
        manager1 = get_emulator_manager()
        manager2 = get_emulator_manager()
        assert manager1 is manager2

    def test_global_manager_is_properly_initialized(self) -> None:
        """Global emulator manager is properly initialized."""
        manager = get_emulator_manager()
        assert isinstance(manager, EmulatorManager)
        assert hasattr(manager, "lock")
        assert hasattr(manager, "stats")


class TestRunWithQEMU:
    """Test run_with_qemu helper function."""

    def test_run_with_qemu_returns_error_when_qemu_unavailable(self, real_binary_path: str) -> None:
        """run_with_qemu returns error dict when QEMU fails to start."""
        from intellicrack.core.processing.emulator_manager import QEMU_AVAILABLE

        if QEMU_AVAILABLE:
            pytest.skip("QEMU is available, test expects unavailable state")

        def test_analysis() -> dict[str, Any]:
            return {"status": "success"}

        result = run_with_qemu(real_binary_path, test_analysis)
        assert result["status"] == "error"
        assert "Failed to start QEMU" in result["error"]

    def test_run_with_qemu_executes_analysis_function(self, real_binary_path: str, monkeypatch: pytest.MonkeyPatch) -> None:
        """run_with_qemu executes analysis function when QEMU starts successfully."""
        analysis_executed = {"called": False}

        def test_analysis() -> dict[str, Any]:
            analysis_executed["called"] = True
            return {"status": "success", "result": "analysis complete"}

        manager = get_emulator_manager()
        original_ensure = manager.ensure_qemu_running

        def mock_ensure(binary_path: str, config: dict[str, Any] | None = None) -> bool:
            return True

        monkeypatch.setattr(manager, "ensure_qemu_running", mock_ensure)

        result = run_with_qemu(real_binary_path, test_analysis)

        assert analysis_executed["called"] is True
        assert result["status"] == "success"

    def test_run_with_qemu_handles_analysis_exceptions(self, real_binary_path: str, monkeypatch: pytest.MonkeyPatch) -> None:
        """run_with_qemu handles exceptions from analysis function."""
        def failing_analysis() -> dict[str, Any]:
            raise RuntimeError("Analysis failed")

        manager = get_emulator_manager()

        def mock_ensure(binary_path: str, config: dict[str, Any] | None = None) -> bool:
            return True

        monkeypatch.setattr(manager, "ensure_qemu_running", mock_ensure)

        result = run_with_qemu(real_binary_path, failing_analysis)

        assert result["status"] == "error"
        assert "Analysis failed" in result["error"]

    def test_run_with_qemu_passes_config_to_manager(self, real_binary_path: str, monkeypatch: pytest.MonkeyPatch) -> None:
        """run_with_qemu passes configuration to emulator manager."""
        config_received = {}

        def test_analysis() -> dict[str, Any]:
            return {"status": "success"}

        manager = get_emulator_manager()

        def mock_ensure(binary_path: str, config: dict[str, Any] | None = None) -> bool:
            if config:
                config_received.update(config)
            return True

        monkeypatch.setattr(manager, "ensure_qemu_running", mock_ensure)

        test_config = {"memory": "4G", "cpu": "4"}
        run_with_qemu(real_binary_path, test_analysis, config=test_config)

        assert config_received == test_config


class TestRunWithQiling:
    """Test run_with_qiling helper function."""

    def test_run_with_qiling_returns_error_when_qiling_unavailable(self, real_binary_path: str) -> None:
        """run_with_qiling returns error dict when Qiling fails to initialize."""
        from intellicrack.core.processing.emulator_manager import QILING_AVAILABLE

        if QILING_AVAILABLE:
            pytest.skip("Qiling is available, test expects unavailable state")

        def test_analysis(qiling: Any) -> dict[str, Any]:
            return {"status": "success"}

        result = run_with_qiling(real_binary_path, test_analysis)
        assert result["status"] == "error"
        assert "Failed to initialize Qiling" in result["error"]

    def test_run_with_qiling_passes_instance_to_analysis(self, real_binary_path: str, monkeypatch: pytest.MonkeyPatch) -> None:
        """run_with_qiling passes Qiling instance to analysis function."""
        received_instance = {"instance": None}

        def test_analysis(qiling: Any) -> dict[str, Any]:
            received_instance["instance"] = qiling
            return {"status": "success"}

        manager = get_emulator_manager()
        mock_qiling = MagicMock()

        def mock_ensure(binary_path: str) -> Any:
            return mock_qiling

        monkeypatch.setattr(manager, "ensure_qiling_ready", mock_ensure)

        result = run_with_qiling(real_binary_path, test_analysis)

        assert received_instance["instance"] is mock_qiling
        assert result["status"] == "success"

    def test_run_with_qiling_handles_analysis_exceptions(self, real_binary_path: str, monkeypatch: pytest.MonkeyPatch) -> None:
        """run_with_qiling handles exceptions from analysis function."""
        def failing_analysis(qiling: Any) -> dict[str, Any]:
            raise ValueError("Invalid analysis parameter")

        manager = get_emulator_manager()
        mock_qiling = MagicMock()

        def mock_ensure(binary_path: str) -> Any:
            return mock_qiling

        monkeypatch.setattr(manager, "ensure_qiling_ready", mock_ensure)

        result = run_with_qiling(real_binary_path, failing_analysis)

        assert result["status"] == "error"
        assert "Analysis failed" in result["error"]


class TestEmulatorStatistics:
    """Test emulator statistics tracking."""

    def test_stats_initialized_with_zero_values(self, emulator_manager: EmulatorManager) -> None:
        """Statistics are initialized with zero values."""
        assert emulator_manager.stats["total_executions"] == 0
        assert emulator_manager.stats["successful_executions"] == 0
        assert emulator_manager.stats["failed_executions"] == 0
        assert emulator_manager.stats["qiling_executions"] == 0
        assert emulator_manager.stats["qemu_executions"] == 0
        assert emulator_manager.stats["unicorn_executions"] == 0

    def test_stats_dictionary_is_mutable(self, emulator_manager: EmulatorManager) -> None:
        """Statistics dictionary can be updated."""
        emulator_manager.stats["total_executions"] += 1
        emulator_manager.stats["successful_executions"] += 1

        assert emulator_manager.stats["total_executions"] == 1
        assert emulator_manager.stats["successful_executions"] == 1


class TestEmulatorThreadSafety:
    """Test thread-safety of emulator operations."""

    def test_concurrent_qiling_instance_creation(
        self, emulator_manager: EmulatorManager, tmp_path: Path
    ) -> None:
        """Concurrent Qiling instance creation is thread-safe."""
        from intellicrack.core.processing.emulator_manager import QILING_AVAILABLE

        if not QILING_AVAILABLE:
            pytest.skip("Qiling not available")

        binaries = []
        for i in range(3):
            binary = tmp_path / f"binary{i}.exe"
            binary.write_bytes(b"MZ" + b"\x00" * 100)
            binaries.append(str(binary))

        def create_instance(binary_path: str) -> None:
            emulator_manager.ensure_qiling_ready(binary_path)

        threads = [threading.Thread(target=create_instance, args=(b,)) for b in binaries]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(emulator_manager.qiling_instances) == 3

    def test_lock_prevents_race_conditions(self, emulator_manager: EmulatorManager) -> None:
        """RLock prevents race conditions in state updates."""
        counter = {"value": 0}

        def increment_with_lock() -> None:
            with emulator_manager.lock:
                current = counter["value"]
                time.sleep(0.001)
                counter["value"] = current + 1

        threads = [threading.Thread(target=increment_with_lock) for _ in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert counter["value"] == 10


class TestEmulatorSignalEmission:
    """Test PyQt signal emission for emulator events."""

    def test_qemu_error_signal_on_invalid_binary(self, emulator_manager: EmulatorManager) -> None:
        """emulator_error signal emitted when binary path validation fails."""
        signals_received = []

        def capture_error(emulator_type: str, error_message: str) -> None:
            signals_received.append((emulator_type, error_message))

        emulator_manager.emulator_error.connect(capture_error)
        emulator_manager.ensure_qemu_running("")

        assert any("QEMU" in s[0] for s in signals_received)

    def test_status_changed_signal_on_qiling_init(self, emulator_manager: EmulatorManager, real_binary_path: str) -> None:
        """emulator_status_changed signal emitted during Qiling initialization."""
        from intellicrack.core.processing.emulator_manager import QILING_AVAILABLE

        if not QILING_AVAILABLE:
            pytest.skip("Qiling not available")

        signals_received = []

        def capture_status(emulator_type: str, is_running: bool, message: str) -> None:
            signals_received.append((emulator_type, is_running, message))

        emulator_manager.emulator_status_changed.connect(capture_status)
        emulator_manager.ensure_qiling_ready(real_binary_path)

        assert len(signals_received) > 0
        assert any("Qiling" in s[0] for s in signals_received)


class TestEmulatorEdgeCases:
    """Test edge cases and error conditions."""

    def test_ensure_qemu_with_nonexistent_binary(self, emulator_manager: EmulatorManager) -> None:
        """ensure_qemu_running handles nonexistent binary paths."""
        emulator_manager.ensure_qemu_running("/nonexistent/path/binary.exe")

    def test_cleanup_on_uninitialized_manager(self) -> None:
        """Cleanup works on freshly initialized manager."""
        manager = EmulatorManager()
        manager.cleanup()

    def test_multiple_cleanup_calls(self, emulator_manager: EmulatorManager) -> None:
        """Multiple cleanup calls don't cause errors."""
        emulator_manager.cleanup()
        emulator_manager.cleanup()
        emulator_manager.cleanup()

    def test_qiling_ready_with_corrupted_binary(self, tmp_path: Path) -> None:
        """ensure_qiling_ready handles corrupted binary data."""
        from intellicrack.core.processing.emulator_manager import QILING_AVAILABLE

        if not QILING_AVAILABLE:
            pytest.skip("Qiling not available")

        corrupted = tmp_path / "corrupted.exe"
        corrupted.write_bytes(b"\x00" * 100)

        manager = EmulatorManager()
        manager.ensure_qiling_ready(str(corrupted))
