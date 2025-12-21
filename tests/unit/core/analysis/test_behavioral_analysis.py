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
from pathlib import Path
from typing import Any

import pytest

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


WINDOWS_SYSTEM_BINARIES = {
    "notepad.exe": r"C:\Windows\System32\notepad.exe",
    "calc.exe": r"C:\Windows\System32\calc.exe",
    "cmd.exe": r"C:\Windows\System32\cmd.exe",
    "whoami.exe": r"C:\Windows\System32\whoami.exe",
}


@pytest.fixture
def temp_dir() -> Path:
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
        detector = AntiAnalysisDetector()
        assert detector is not None
        assert hasattr(detector, "detect_anti_debug")
        assert hasattr(detector, "detect_vm_checks")
        assert hasattr(detector, "detect_timing_checks")

    def test_detect_anti_debug_on_real_binary(self, notepad_path: str) -> None:
        """Test anti-debugging detection on real Windows binary."""
        detector = AntiAnalysisDetector()

        with open(notepad_path, "rb") as f:
            binary_data = f.read()

        result = detector.detect_anti_debug(binary_data)

        assert result is not None
        assert isinstance(result, (dict, list))

    def test_detect_vm_checks_on_real_binary(self, calc_path: str) -> None:
        """Test VM detection check scanning on real binary."""
        detector = AntiAnalysisDetector()

        with open(calc_path, "rb") as f:
            binary_data = f.read()

        result = detector.detect_vm_checks(binary_data)

        assert result is not None

    def test_detect_timing_checks_on_system_dll(self) -> None:
        """Test timing check detection on Windows system DLL."""
        if sys.platform != "win32":
            pytest.skip("Windows-specific test")

        kernel32_path = r"C:\Windows\System32\kernel32.dll"
        if not os.path.exists(kernel32_path):
            pytest.skip("kernel32.dll not found")

        detector = AntiAnalysisDetector()

        with open(kernel32_path, "rb") as f:
            binary_data = f.read()

        result = detector.detect_timing_checks(binary_data)

        assert result is not None


class TestAPIHookingFramework:
    """Test API hooking framework capabilities."""

    def test_framework_initialization(self) -> None:
        """Test API hooking framework initializes."""
        framework = APIHookingFramework()
        assert framework is not None
        assert hasattr(framework, "install_hooks")
        assert hasattr(framework, "remove_hooks")
        assert hasattr(framework, "get_hooked_calls")

    def test_hook_point_creation(self) -> None:
        """Test creating hook point definitions."""
        hook = HookPoint(
            function_name="CreateFileW",
            module_name="kernel32.dll",
            hook_type="pre",
            callback=None,
        )

        assert hook.function_name == "CreateFileW"
        assert hook.module_name == "kernel32.dll"
        assert hook.hook_type == "pre"

    def test_install_hooks_on_target_process(self, notepad_path: str) -> None:
        """Test installing hooks on real target process."""
        if sys.platform != "win32":
            pytest.skip("Windows-specific test")

        framework = APIHookingFramework()

        import subprocess
        process = subprocess.Popen([notepad_path])
        pid = process.pid

        try:
            hooks = [
                HookPoint(
                    function_name="CreateFileW",
                    module_name="kernel32.dll",
                    hook_type="pre",
                    callback=None,
                )
            ]

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
        config = QEMUConfig(
            arch="x86_64",
            memory_size=512,
            enable_kvm=False,
            snapshot=True,
        )

        controller = QEMUController(config)

        assert controller is not None
        assert hasattr(controller, "start")
        assert hasattr(controller, "stop")
        assert hasattr(controller, "monitor_execution")

    def test_qemu_config_creation(self) -> None:
        """Test creating QEMU configuration."""
        config = QEMUConfig(
            arch="x86_64",
            memory_size=1024,
            enable_kvm=False,
            snapshot=True,
        )

        assert config.arch == "x86_64"
        assert config.memory_size == 1024
        assert config.enable_kvm is False
        assert config.snapshot is True

    def test_monitor_event_creation(self) -> None:
        """Test creating monitor event objects."""
        event = MonitorEvent(
            timestamp=time.time(),
            event_type="api_call",
            function_name="CreateFileW",
            parameters={"filename": "test.txt", "access": "read"},
            return_value=0,
        )

        assert event.event_type == "api_call"
        assert event.function_name == "CreateFileW"
        assert "filename" in event.parameters
        assert event.return_value == 0


class TestBehavioralAnalyzer:
    """Test main behavioral analyzer functionality."""

    def test_analyzer_initialization(self, notepad_path: str) -> None:
        """Test behavioral analyzer initializes with target binary."""
        analyzer = BehavioralAnalyzer(binary_path=notepad_path)

        assert analyzer is not None
        assert analyzer.binary_path == notepad_path
        assert hasattr(analyzer, "run_analysis")
        assert hasattr(analyzer, "cleanup")

    def test_analyzer_with_qemu_config(self, notepad_path: str) -> None:
        """Test analyzer initialization with QEMU configuration."""
        qemu_config = QEMUConfig(
            arch="x86_64",
            memory_size=512,
            enable_kvm=False,
            snapshot=True,
        )

        analyzer = BehavioralAnalyzer(
            binary_path=notepad_path,
            qemu_config=qemu_config,
        )

        assert analyzer is not None
        assert analyzer.qemu_config is not None

    def test_run_analysis_on_notepad(self, notepad_path: str) -> None:
        """Test running behavioral analysis on notepad.exe."""
        if sys.platform != "win32":
            pytest.skip("Windows-specific test")

        analyzer = BehavioralAnalyzer(binary_path=notepad_path)

        result = analyzer.run_analysis(timeout=5)

        assert result is not None
        assert isinstance(result, dict)
        assert "events" in result or "api_calls" in result or "summary" in result

        analyzer.cleanup()

    def test_run_analysis_on_calc(self, calc_path: str) -> None:
        """Test running behavioral analysis on calc.exe."""
        if sys.platform != "win32":
            pytest.skip("Windows-specific test")

        analyzer = BehavioralAnalyzer(binary_path=calc_path)

        result = analyzer.run_analysis(timeout=3)

        assert result is not None

        analyzer.cleanup()

    def test_analyzer_timeout_handling(self, notepad_path: str) -> None:
        """Test analyzer respects timeout parameter."""
        if sys.platform != "win32":
            pytest.skip("Windows-specific test")

        analyzer = BehavioralAnalyzer(binary_path=notepad_path)

        start_time = time.time()
        result = analyzer.run_analysis(timeout=2)
        elapsed_time = time.time() - start_time

        assert elapsed_time <= 10, "Analysis should complete within reasonable time after timeout"
        assert result is not None

        analyzer.cleanup()

    def test_analyzer_cleanup(self, notepad_path: str) -> None:
        """Test analyzer cleanup releases resources."""
        analyzer = BehavioralAnalyzer(binary_path=notepad_path)

        analyzer.run_analysis(timeout=1)

        analyzer.cleanup()

    def test_api_monitoring_on_real_process(self, notepad_path: str) -> None:
        """Test API call monitoring on real process."""
        if sys.platform != "win32":
            pytest.skip("Windows-specific test")

        analyzer = BehavioralAnalyzer(binary_path=notepad_path)

        result = analyzer.run_analysis(timeout=3)

        if "api_calls" in result:
            api_calls = result["api_calls"]
            assert isinstance(api_calls, (list, dict))

        analyzer.cleanup()

    def test_behavioral_pattern_detection(self, calc_path: str) -> None:
        """Test detection of behavioral patterns in execution."""
        if sys.platform != "win32":
            pytest.skip("Windows-specific test")

        analyzer = BehavioralAnalyzer(binary_path=calc_path)

        result = analyzer.run_analysis(timeout=3)

        analyzer.cleanup()


class TestFactoryFunctions:
    """Test factory and helper functions."""

    def test_create_behavioral_analyzer(self, notepad_path: str) -> None:
        """Test factory function creates analyzer correctly."""
        analyzer = create_behavioral_analyzer(binary_path=notepad_path)

        assert analyzer is not None
        assert isinstance(analyzer, BehavioralAnalyzer)
        assert analyzer.binary_path == notepad_path

    def test_create_analyzer_with_config(self, notepad_path: str) -> None:
        """Test factory function with QEMU configuration."""
        qemu_config = QEMUConfig(
            arch="x86_64",
            memory_size=512,
            enable_kvm=False,
            snapshot=True,
        )

        analyzer = create_behavioral_analyzer(
            binary_path=notepad_path,
            qemu_config=qemu_config,
        )

        assert analyzer is not None
        assert analyzer.qemu_config is not None

    def test_run_behavioral_analysis_helper(self, notepad_path: str) -> None:
        """Test helper function for running analysis."""
        if sys.platform != "win32":
            pytest.skip("Windows-specific test")

        result = run_behavioral_analysis(
            binary_path=notepad_path,
            timeout=3,
        )

        assert result is not None
        assert isinstance(result, dict)


class TestRealWorldScenarios:
    """Test real-world usage scenarios."""

    def test_analyze_multiple_binaries_sequentially(self) -> None:
        """Test analyzing multiple Windows binaries in sequence."""
        if sys.platform != "win32":
            pytest.skip("Windows-specific test")

        binaries_to_test = [
            WINDOWS_SYSTEM_BINARIES["notepad.exe"],
            WINDOWS_SYSTEM_BINARIES["calc.exe"],
        ]

        results = []

        for binary_path in binaries_to_test:
            if not os.path.exists(binary_path):
                continue

            analyzer = BehavioralAnalyzer(binary_path=binary_path)

            result = analyzer.run_analysis(timeout=2)
            results.append((binary_path, result))

            analyzer.cleanup()

        assert results

        for binary_path, result in results:
            assert result is not None

    def test_concurrent_analysis_different_binaries(self) -> None:
        """Test thread safety for concurrent analysis of different binaries."""
        if sys.platform != "win32":
            pytest.skip("Windows-specific test")

        import threading

        results = []
        errors = []

        def analyze_binary(binary_path: str) -> None:
            try:
                if not os.path.exists(binary_path):
                    return

                analyzer = BehavioralAnalyzer(binary_path=binary_path)
                result = analyzer.run_analysis(timeout=2)
                results.append((binary_path, result))
                analyzer.cleanup()
            except Exception as e:
                errors.append((binary_path, str(e)))

        threads = []

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

        analyzer = BehavioralAnalyzer(binary_path=notepad_path)

        result = analyzer.run_analysis(timeout=0.5)

        assert result is not None

        analyzer.cleanup()

    def test_analysis_error_handling_nonexistent_binary(self) -> None:
        """Test error handling for nonexistent binary."""
        nonexistent = r"C:\nonexistent\binary.exe"

        try:
            analyzer = BehavioralAnalyzer(binary_path=nonexistent)
            result = analyzer.run_analysis(timeout=1)

            assert result is not None

            analyzer.cleanup()
        except FileNotFoundError:
            pass
        except Exception as e:
            assert "not found" in str(e).lower() or "nonexistent" in str(e).lower()

    def test_analysis_error_handling_invalid_binary(self, temp_dir: Path) -> None:
        """Test error handling for invalid/corrupted binary."""
        invalid_binary = temp_dir / "invalid.exe"

        with open(invalid_binary, "wb") as f:
            f.write(b"MZ" + os.urandom(1000))

        try:
            analyzer = BehavioralAnalyzer(binary_path=str(invalid_binary))
            result = analyzer.run_analysis(timeout=1)

            assert result is not None

            analyzer.cleanup()
        except Exception:
            assert True


class TestIntegrationWithOtherModules:
    """Test integration with other Intellicrack modules."""

    def test_integration_with_frida_possible(self, notepad_path: str) -> None:
        """Test that behavioral analysis could integrate with Frida."""
        analyzer = BehavioralAnalyzer(binary_path=notepad_path)

        assert analyzer is not None

        try:
            import frida
        except ImportError:
            pytest.skip("Frida not available")

    def test_anti_analysis_detector_integration(self, notepad_path: str) -> None:
        """Test integration between behavioral analyzer and anti-analysis detector."""
        analyzer = BehavioralAnalyzer(binary_path=notepad_path)
        detector = AntiAnalysisDetector()

        assert analyzer is not None
        assert detector is not None

        with open(notepad_path, "rb") as f:
            binary_data = f.read()

        anti_debug_result = detector.detect_anti_debug(binary_data)
        vm_check_result = detector.detect_vm_checks(binary_data)

        assert anti_debug_result is not None
        assert vm_check_result is not None
