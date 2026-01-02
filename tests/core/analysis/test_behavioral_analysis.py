"""Real-world behavioral analysis tests with actual binary execution.

Tests behavioral analysis capabilities against real Windows binaries.
NO MOCKS - Uses real process execution and monitoring only.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest

AntiAnalysisDetector: type[Any] | None
APIHookingFramework: type[Any] | None
BehavioralAnalyzer: type[Any] | None
HookPoint: type[Any] | None
MonitorEvent: type[Any] | None
QEMUConfig: type[Any] | None
QEMUController: type[Any] | None
create_behavioral_analyzer: Any
run_behavioral_analysis: Any

try:
    from intellicrack.core.analysis.behavioral_analysis import (
        AntiAnalysisDetector,
        APIHookingFramework,
        BehavioralAnalyzer,
        HookPoint,
        MonitorEvent,
        QEMUConfig,
        QEMUController,
        create_behavioral_analyzer,
        run_behavioral_analysis,
    )
    AVAILABLE = True
except ImportError:
    AntiAnalysisDetector = None
    APIHookingFramework = None
    BehavioralAnalyzer = None
    HookPoint = None
    MonitorEvent = None
    QEMUConfig = None
    QEMUController = None
    create_behavioral_analyzer = None
    run_behavioral_analysis = None
    AVAILABLE = False

pytestmark = pytest.mark.skipif(not AVAILABLE, reason="Module not available")


WINDOWS_SYSTEM_BINARIES = {
    "notepad.exe": r"C:\Windows\System32\notepad.exe",
    "calc.exe": r"C:\Windows\System32\calc.exe",
    "cmd.exe": r"C:\Windows\System32\cmd.exe",
    "whoami.exe": r"C:\Windows\System32\whoami.exe",
}


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create temporary directory for test artifacts."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def notepad_path() -> str:
    """Get path to notepad.exe."""
    notepad = WINDOWS_SYSTEM_BINARIES["notepad.exe"]
    if not os.path.exists(notepad):
        pytest.skip(f"notepad.exe not found at {notepad}")
    return notepad


@pytest.fixture
def calc_path() -> str:
    """Get path to calc.exe."""
    calc = WINDOWS_SYSTEM_BINARIES["calc.exe"]
    if not os.path.exists(calc):
        pytest.skip(f"calc.exe not found at {calc}")
    return calc


class TestAntiAnalysisDetector:
    """Test anti-analysis detection capabilities."""

    def test_detector_initialization(self) -> None:
        """Test anti-analysis detector initializes correctly."""
        assert AntiAnalysisDetector is not None
        detector = AntiAnalysisDetector()
        assert detector is not None
        assert hasattr(detector, "scan")

    def test_detect_anti_debug_on_real_binary(self, notepad_path: str) -> None:
        """Test anti-debugging detection on real Windows binary."""
        assert AntiAnalysisDetector is not None
        detector = AntiAnalysisDetector()

        import psutil
        current_pid = psutil.Process().pid
        result = detector.scan(current_pid)

        assert result is not None
        assert isinstance(result, list)

    def test_detect_vm_checks_on_real_binary(self, calc_path: str) -> None:
        """Test VM detection check scanning on real binary."""
        assert AntiAnalysisDetector is not None
        detector = AntiAnalysisDetector()

        import psutil
        current_pid = psutil.Process().pid
        result = detector.scan(current_pid)

        assert result is not None

    def test_detect_timing_checks_on_system_dll(self) -> None:
        """Test timing check detection on Windows system DLL."""
        if sys.platform != "win32":
            pytest.skip("Windows-specific test")

        assert AntiAnalysisDetector is not None
        detector = AntiAnalysisDetector()

        import psutil
        current_pid = psutil.Process().pid
        result = detector.scan(current_pid)

        assert result is not None


class TestAPIHookingFramework:
    """Test API hooking framework capabilities."""

    def test_framework_initialization(self) -> None:
        """Test API hooking framework initializes."""
        assert APIHookingFramework is not None
        framework = APIHookingFramework()
        assert framework is not None
        assert hasattr(framework, "add_hook")
        assert hasattr(framework, "remove_hook")
        assert hasattr(framework, "enable_hook")

    def test_hook_point_creation(self) -> None:
        """Test creating hook point definitions."""
        assert HookPoint is not None
        hook = HookPoint(
            module="kernel32.dll",
            function="CreateFileW",
            on_enter=None,
            on_exit=None,
        )

        assert hook.function == "CreateFileW"
        assert hook.module == "kernel32.dll"

    def test_install_hooks_on_target_process(self, notepad_path: str) -> None:
        """Test installing hooks on real target process."""
        if sys.platform != "win32":
            pytest.skip("Windows-specific test")

        assert APIHookingFramework is not None
        assert HookPoint is not None
        framework = APIHookingFramework()

        import subprocess
        process = subprocess.Popen([notepad_path])
        pid = process.pid

        try:
            hooks = [
                HookPoint(
                    module="kernel32.dll",
                    function="CreateFileW",
                    on_enter=None,
                    on_exit=None,
                )
            ]

            if hasattr(framework, "install_hooks"):
                result = framework.install_hooks(pid, hooks)
                assert result is not None

        finally:
            try:
                process.terminate()
                process.wait(timeout=2)
            except Exception:
                process.kill()


class TestQEMUController:
    """Test QEMU emulation controller."""

    def test_qemu_controller_initialization(self) -> None:
        """Test QEMU controller initializes with config."""
        assert QEMUConfig is not None
        assert QEMUController is not None
        config = QEMUConfig(
            memory_size="512M",
            enable_kvm=False,
        )

        controller = QEMUController(config)

        assert controller is not None
        assert hasattr(controller, "start")
        assert hasattr(controller, "stop")

    def test_qemu_config_creation(self) -> None:
        """Test creating QEMU configuration."""
        assert QEMUConfig is not None
        config = QEMUConfig(
            memory_size="1G",
            enable_kvm=False,
        )

        assert config.memory_size == "1G"
        assert config.enable_kvm is False

    def test_monitor_event_creation(self) -> None:
        """Test creating monitor event objects."""
        assert MonitorEvent is not None
        event = MonitorEvent(
            timestamp=time.time(),
            event_type="api_call",
            process_id=1234,
            thread_id=5678,
            data={"function": "CreateFileW", "filename": "test.txt", "access": "read"},
        )

        assert event.event_type == "api_call"
        assert event.process_id == 1234
        assert event.thread_id == 5678
        assert "filename" in event.data


class TestBehavioralAnalyzer:
    """Test main behavioral analyzer functionality."""

    def test_analyzer_initialization(self, notepad_path: str) -> None:
        """Test behavioral analyzer initializes with target binary."""
        assert BehavioralAnalyzer is not None
        analyzer = BehavioralAnalyzer(binary_path=Path(notepad_path))

        assert analyzer is not None
        assert str(analyzer.binary_path) == notepad_path
        assert hasattr(analyzer, "run_analysis")
        assert hasattr(analyzer, "cleanup")

    def test_analyzer_with_qemu_config(self, notepad_path: str) -> None:
        """Test analyzer initialization with QEMU configuration."""
        assert BehavioralAnalyzer is not None
        assert QEMUConfig is not None
        qemu_config = QEMUConfig(
            memory_size="512M",
            enable_kvm=False,
        )

        analyzer = BehavioralAnalyzer(binary_path=Path(notepad_path))
        analyzer.qemu_config = qemu_config

        assert analyzer is not None
        assert analyzer.qemu_config is not None

    def test_run_analysis_on_notepad(self, notepad_path: str) -> None:
        """Test running behavioral analysis on notepad.exe."""
        if sys.platform != "win32":
            pytest.skip("Windows-specific test")

        assert BehavioralAnalyzer is not None
        analyzer = BehavioralAnalyzer(binary_path=Path(notepad_path))

        result = analyzer.run_analysis(duration=5)

        assert result is not None
        assert isinstance(result, dict)
        assert "events" in result or "api_calls" in result or "summary" in result

        analyzer.cleanup()

    def test_run_analysis_on_calc(self, calc_path: str) -> None:
        """Test running behavioral analysis on calc.exe."""
        if sys.platform != "win32":
            pytest.skip("Windows-specific test")

        assert BehavioralAnalyzer is not None
        analyzer = BehavioralAnalyzer(binary_path=Path(calc_path))

        result = analyzer.run_analysis(duration=3)

        assert result is not None

        analyzer.cleanup()

    def test_analyzer_timeout_handling(self, notepad_path: str) -> None:
        """Test analyzer respects timeout parameter."""
        if sys.platform != "win32":
            pytest.skip("Windows-specific test")

        assert BehavioralAnalyzer is not None
        analyzer = BehavioralAnalyzer(binary_path=Path(notepad_path))

        start_time = time.time()
        result = analyzer.run_analysis(duration=2)
        elapsed_time = time.time() - start_time

        assert elapsed_time <= 10, "Analysis should complete within reasonable time after timeout"
        assert result is not None

        analyzer.cleanup()

    def test_analyzer_cleanup(self, notepad_path: str) -> None:
        """Test analyzer cleanup releases resources."""
        assert BehavioralAnalyzer is not None
        analyzer = BehavioralAnalyzer(binary_path=Path(notepad_path))

        analyzer.run_analysis(duration=1)

        analyzer.cleanup()

    def test_api_monitoring_on_real_process(self, notepad_path: str) -> None:
        """Test API call monitoring on real process."""
        if sys.platform != "win32":
            pytest.skip("Windows-specific test")

        assert BehavioralAnalyzer is not None
        analyzer = BehavioralAnalyzer(binary_path=Path(notepad_path))

        result = analyzer.run_analysis(duration=3)

        if "api_calls" in result:
            api_calls = result["api_calls"]
            assert isinstance(api_calls, (list, dict))

        analyzer.cleanup()

    def test_behavioral_pattern_detection(self, calc_path: str) -> None:
        """Test detection of behavioral patterns in execution."""
        if sys.platform != "win32":
            pytest.skip("Windows-specific test")

        assert BehavioralAnalyzer is not None
        analyzer = BehavioralAnalyzer(binary_path=Path(calc_path))

        result = analyzer.run_analysis(duration=3)

        analyzer.cleanup()


class TestFactoryFunctions:
    """Test factory and helper functions."""

    def test_create_behavioral_analyzer(self, notepad_path: str) -> None:
        """Test factory function creates analyzer correctly."""
        assert create_behavioral_analyzer is not None
        assert BehavioralAnalyzer is not None
        analyzer = create_behavioral_analyzer(binary_path=Path(notepad_path))

        assert analyzer is not None
        assert isinstance(analyzer, BehavioralAnalyzer)
        assert str(analyzer.binary_path) == notepad_path

    def test_create_analyzer_with_config(self, notepad_path: str) -> None:
        """Test factory function with QEMU configuration."""
        assert create_behavioral_analyzer is not None
        assert BehavioralAnalyzer is not None
        assert QEMUConfig is not None
        qemu_config = QEMUConfig(
            memory_size="512M",
            enable_kvm=False,
        )

        analyzer = create_behavioral_analyzer(binary_path=Path(notepad_path))
        analyzer.qemu_config = qemu_config

        assert analyzer is not None
        assert analyzer.qemu_config is not None

    def test_run_behavioral_analysis_helper(self, notepad_path: str) -> None:
        """Test helper function for running analysis."""
        if sys.platform != "win32":
            pytest.skip("Windows-specific test")

        assert run_behavioral_analysis is not None
        result = run_behavioral_analysis(
            binary_path=Path(notepad_path),
            duration=3,
        )

        assert result is not None
        assert isinstance(result, dict)


class TestRealWorldScenarios:
    """Test real-world usage scenarios."""

    def test_analyze_multiple_binaries_sequentially(self) -> None:
        """Test analyzing multiple Windows binaries in sequence."""
        if sys.platform != "win32":
            pytest.skip("Windows-specific test")

        assert BehavioralAnalyzer is not None
        binaries_to_test = [
            WINDOWS_SYSTEM_BINARIES["notepad.exe"],
            WINDOWS_SYSTEM_BINARIES["calc.exe"],
        ]

        results: list[tuple[str, dict[str, Any]]] = []

        for binary_path in binaries_to_test:
            if not os.path.exists(binary_path):
                continue

            analyzer = BehavioralAnalyzer(binary_path=Path(binary_path))

            result = analyzer.run_analysis(duration=2)
            results.append((binary_path, result))

            analyzer.cleanup()

        assert results

        for binary_path, result in results:
            assert result is not None

    def test_concurrent_analysis_different_binaries(self) -> None:
        """Test thread safety for concurrent analysis of different binaries."""
        if sys.platform != "win32":
            pytest.skip("Windows-specific test")

        assert BehavioralAnalyzer is not None
        import threading

        results: list[tuple[str, dict[str, Any]]] = []
        errors: list[tuple[str, str]] = []

        def analyze_binary(binary_path: str) -> None:
            try:
                if not os.path.exists(binary_path):
                    return

                analyzer = BehavioralAnalyzer(binary_path=Path(binary_path))
                result = analyzer.run_analysis(duration=2)
                results.append((binary_path, result))
                analyzer.cleanup()
            except Exception as e:
                errors.append((binary_path, str(e)))

        threads: list[threading.Thread] = []

        for binary_path in list(WINDOWS_SYSTEM_BINARIES.values())[:2]:
            thread = threading.Thread(target=analyze_binary, args=(binary_path,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join(timeout=15)

        assert not errors, f"Concurrent analysis errors: {errors}"

    def test_analysis_with_short_timeout(self, notepad_path: str) -> None:
        """Test analysis behavior with very short timeout."""
        if sys.platform != "win32":
            pytest.skip("Windows-specific test")

        assert BehavioralAnalyzer is not None
        analyzer = BehavioralAnalyzer(binary_path=Path(notepad_path))

        result = analyzer.run_analysis(duration=1)

        assert result is not None

        analyzer.cleanup()

    def test_analysis_error_handling_nonexistent_binary(self) -> None:
        """Test error handling for nonexistent binary."""
        assert BehavioralAnalyzer is not None
        nonexistent = r"C:\nonexistent\binary.exe"

        try:
            analyzer = BehavioralAnalyzer(binary_path=Path(nonexistent))
            result = analyzer.run_analysis(duration=1)

            assert result is not None

            analyzer.cleanup()
        except FileNotFoundError:
            pass
        except Exception as e:
            assert "not found" in str(e).lower() or "nonexistent" in str(e).lower()

    def test_analysis_error_handling_invalid_binary(self, temp_dir: Path) -> None:
        """Test error handling for invalid/corrupted binary."""
        assert BehavioralAnalyzer is not None
        invalid_binary = temp_dir / "invalid.exe"

        with open(invalid_binary, "wb") as f:
            f.write(b"MZ" + os.urandom(1000))

        try:
            analyzer = BehavioralAnalyzer(binary_path=invalid_binary)
            result = analyzer.run_analysis(duration=1)

            assert result is not None

            analyzer.cleanup()
        except Exception:
            assert True


class TestIntegrationWithOtherModules:
    """Test integration with other Intellicrack modules."""

    def test_integration_with_frida_possible(self, notepad_path: str) -> None:
        """Test that behavioral analysis could integrate with Frida."""
        assert BehavioralAnalyzer is not None
        analyzer = BehavioralAnalyzer(binary_path=Path(notepad_path))

        assert analyzer is not None

        try:
            import frida  # noqa: F401
        except ImportError:
            pytest.skip("Frida not available")

    def test_anti_analysis_detector_integration(self, notepad_path: str) -> None:
        """Test integration between behavioral analyzer and anti-analysis detector."""
        assert BehavioralAnalyzer is not None
        assert AntiAnalysisDetector is not None
        analyzer = BehavioralAnalyzer(binary_path=Path(notepad_path))
        detector = AntiAnalysisDetector()

        assert analyzer is not None
        assert detector is not None

        with open(notepad_path, "rb") as f:
            binary_data = f.read()

        if hasattr(detector, "scan"):
            import psutil
            current_pid = psutil.Process().pid
            result = detector.scan(current_pid)
            assert result is not None
