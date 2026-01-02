"""
Comprehensive Unit Tests for AdvancedDynamicAnalyzer Module.

Tests real runtime analysis capabilities including subprocess execution,
Frida instrumentation, process behavior monitoring, and memory scanning.
Validates production-ready functionality for security research.
"""

import json
import logging
import os
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

try:
    from intellicrack.core.analysis.dynamic_analyzer import (
        AdvancedDynamicAnalyzer,
        DynamicAnalyzer,
        create_dynamic_analyzer,
        deep_runtime_monitoring,
        run_dynamic_analysis,
        run_quick_analysis,
    )
    AVAILABLE = True
except ImportError:
    AdvancedDynamicAnalyzer = None
    DynamicAnalyzer = None
    create_dynamic_analyzer = None
    deep_runtime_monitoring = None
    run_dynamic_analysis = None
    run_quick_analysis = None
    AVAILABLE = False

try:
    from intellicrack.utils.core.import_checks import FRIDA_AVAILABLE, PSUTIL_AVAILABLE
except ImportError:
    FRIDA_AVAILABLE = False
    PSUTIL_AVAILABLE = False

pytestmark = pytest.mark.skipif(not AVAILABLE, reason="Module not available")


class TestDynamicAnalysisApp:
    """Real test application harness to replace MagicMock app objects."""

    def __init__(self) -> None:
        """Initialize test app with tracking capabilities."""
        self.binary_path: Optional[Path] = None
        self.output_updates: List[str] = []
        self.analyze_results: List[Dict[str, Any]] = []
        self.update_output: TestSignalEmitter = TestSignalEmitter()

    def set_binary_path(self, path: Path) -> None:
        """Set binary path for analysis."""
        self.binary_path = path


class TestSignalEmitter:
    """Real signal emitter to replace MagicMock update_output signals."""

    def __init__(self) -> None:
        """Initialize signal emitter with call tracking."""
        self.emission_log: List[Dict[str, Any]] = []
        self.emit = self._emit_handler

    def _emit_handler(self, *args: Any, **kwargs: Any) -> None:
        """Track emit calls with real data."""
        self.emission_log.append({"args": args, "kwargs": kwargs})

    def was_called(self) -> bool:
        """Check if emit was called."""
        return len(self.emission_log) > 0

    def call_count(self) -> int:
        """Get number of emit calls."""
        return len(self.emission_log)

    def get_calls(self) -> List[Dict[str, Any]]:
        """Get all emit call data."""
        return self.emission_log


class FakeFridaSpawn:
    """Fake Frida spawn function that raises OSError."""

    def __init__(self, error_message: str) -> None:
        """Initialize with error message."""
        self.error_message: str = error_message

    def __call__(self, *args: Any, **kwargs: Any) -> None:
        """Raise OSError when called."""
        raise OSError(self.error_message)


class FakeFridaDevice:
    """Fake Frida device that raises exceptions."""

    def __init__(self, error_message: str) -> None:
        """Initialize with error message."""
        self.error_message: str = error_message

    def __call__(self, *args: Any, **kwargs: Any) -> None:
        """Raise exception when called."""
        raise Exception(self.error_message)


class FakePopen:
    """Fake Popen class that raises OSError."""

    def __init__(self, error_message: str) -> None:
        """Initialize with error message."""
        self.error_message: str = error_message

    def __call__(self, *args: Any, **kwargs: Any) -> None:
        """Raise OSError when called."""
        raise OSError(self.error_message)


class FakePsutilProcess:
    """Fake psutil Process that raises AccessDenied."""

    def __init__(self, pid: int) -> None:
        """Initialize with PID."""
        self.pid: int = pid

    def memory_info(self) -> None:
        """Raise AccessDenied when called."""
        import psutil
        raise psutil.AccessDenied("Access denied")


class FakeFileOpener:
    """Fake file opener that raises IOError."""

    def __init__(self, error_message: str) -> None:
        """Initialize with error message."""
        self.error_message: str = error_message

    def __call__(self, *args: Any, **kwargs: Any) -> None:
        """Raise IOError when called."""
        raise IOError(self.error_message)


class FakeAnalyzerMethod:
    """Fake analyzer method that raises exceptions."""

    def __init__(self, error_message: str) -> None:
        """Initialize with error message."""
        self.error_message: str = error_message

    def __call__(self, *args: Any, **kwargs: Any) -> None:
        """Raise exception when called."""
        raise Exception(self.error_message)


class TestAdvancedDynamicAnalyzer:
    """Comprehensive test suite for AdvancedDynamicAnalyzer."""

    @pytest.fixture
    def test_binary_path(self, tmp_path: Path) -> Path:
        """Create a test binary file for analysis."""
        if platform.system() == "Windows":
            test_file = tmp_path / "test_binary.bat"
            test_file.write_text("@echo off\necho Test Binary\nexit 0")
        else:
            test_file = tmp_path / "test_binary.sh"
            test_file.write_text("#!/bin/sh\necho 'Test Binary'\nexit 0")
            test_file.chmod(0o755)
        return test_file

    @pytest.fixture
    def corrupted_binary_path(self, tmp_path: Path) -> Path:
        """Create a corrupted binary file."""
        test_file = tmp_path / "corrupted.exe"
        test_file.write_bytes(b"\x00\x01\x02\x03\x04\x05")
        return test_file

    @pytest.fixture
    def real_system_binary(self) -> Path:
        """Get path to a real system binary for testing."""
        if platform.system() == "Windows":
            candidates = [
                r"C:\Windows\System32\ping.exe",
                r"C:\Windows\System32\hostname.exe",
                r"C:\Windows\System32\whoami.exe",
            ]
        else:
            candidates = ["/bin/echo", "/bin/ls", "/usr/bin/whoami"]

        for candidate in candidates:
            if Path(candidate).exists():
                return Path(candidate)

        return Path(sys.executable)

    @pytest.fixture
    def analyzer(self, test_binary_path: Path) -> AdvancedDynamicAnalyzer:
        """Create an analyzer instance with test binary."""
        return AdvancedDynamicAnalyzer(test_binary_path)

    def test_initialization_with_valid_binary(self, test_binary_path: Path) -> None:
        """Test analyzer initialization with valid binary path."""
        analyzer = AdvancedDynamicAnalyzer(test_binary_path)
        assert analyzer.binary_path == Path(test_binary_path)
        assert analyzer.logger is not None
        assert analyzer.api_calls == []
        assert analyzer.memory_access == []
        assert analyzer.network_activity == []
        assert analyzer.file_operations == []

    def test_initialization_with_string_path(self, test_binary_path: Path) -> None:
        """Test initialization with string path converts to Path object."""
        analyzer = AdvancedDynamicAnalyzer(str(test_binary_path))
        assert isinstance(analyzer.binary_path, Path)
        assert analyzer.binary_path == Path(test_binary_path)

    def test_initialization_with_nonexistent_file(self, tmp_path: Path) -> None:
        """Test initialization fails with nonexistent file."""
        nonexistent = tmp_path / "nonexistent.exe"
        with pytest.raises(FileNotFoundError, match="Binary file not found"):
            AdvancedDynamicAnalyzer(nonexistent)

    def test_initialization_with_directory(self, tmp_path: Path) -> None:
        """Test initialization fails when path is a directory."""
        with pytest.raises(FileNotFoundError, match="Binary file not found"):
            AdvancedDynamicAnalyzer(tmp_path)

    def test_subprocess_analysis_success(self, analyzer: AdvancedDynamicAnalyzer, test_binary_path: Path) -> None:
        """Test successful subprocess execution analysis."""
        result = analyzer._subprocess_analysis()

        assert isinstance(result, dict)
        assert "success" in result
        assert "stdout" in result or "error" in result

        if result.get("success"):
            assert "return_code" in result
            assert result["return_code"] == 0
            assert "stderr" in result

    def test_subprocess_analysis_with_real_binary(self, real_system_binary: Path) -> None:
        """Test subprocess analysis with real system binary."""
        analyzer = AdvancedDynamicAnalyzer(real_system_binary)
        result = analyzer._subprocess_analysis()

        assert isinstance(result, dict)
        assert "success" in result

        if result.get("success"):
            assert result["return_code"] >= 0
            assert "stdout" in result
            assert "stderr" in result

    def test_subprocess_analysis_timeout(self, tmp_path: Path) -> None:
        """Test subprocess analysis handles timeout correctly."""
        if platform.system() == "Windows":
            test_file = tmp_path / "slow.bat"
            test_file.write_text("@echo off\nping 127.0.0.1 -n 15 > nul\necho Done")
        else:
            test_file = tmp_path / "slow.sh"
            test_file.write_text("#!/bin/sh\nsleep 15\necho Done")
            test_file.chmod(0o755)

        analyzer = AdvancedDynamicAnalyzer(test_file)
        result = analyzer._subprocess_analysis()

        assert result["success"] is False
        assert "error" in result
        assert "Timeout" in result["error"]

    def test_subprocess_analysis_with_error_binary(self, tmp_path: Path) -> None:
        """Test subprocess analysis with binary that returns error code."""
        if platform.system() == "Windows":
            test_file = tmp_path / "error.bat"
            test_file.write_text("@echo off\necho Error occurred\nexit 1")
        else:
            test_file = tmp_path / "error.sh"
            test_file.write_text("#!/bin/sh\necho 'Error occurred'\nexit 1")
            test_file.chmod(0o755)

        analyzer = AdvancedDynamicAnalyzer(test_file)
        result = analyzer._subprocess_analysis()

        assert isinstance(result, dict)
        assert result.get("return_code") == 1
        assert result.get("success") is False

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
    def test_frida_runtime_analysis_with_payload(self, analyzer: AdvancedDynamicAnalyzer) -> None:
        """Test Frida runtime analysis with payload injection."""
        payload = b"\x90\x90\x90\x90"
        result = analyzer._frida_runtime_analysis(payload)

        assert isinstance(result, dict)
        assert "success" in result

        if result.get("success"):
            assert "pid" in result
            assert "analysis_data" in result
            assert result["payload_injected"] is True

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
    def test_frida_runtime_analysis_without_payload(self, analyzer: AdvancedDynamicAnalyzer) -> None:
        """Test Frida runtime analysis without payload."""
        result = analyzer._frida_runtime_analysis(None)

        assert isinstance(result, dict)
        assert "success" in result

        if result.get("success"):
            assert result["payload_injected"] is False

    def test_frida_runtime_analysis_not_available(self, analyzer: AdvancedDynamicAnalyzer, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test Frida analysis when Frida is not available."""
        import intellicrack.core.analysis.dynamic_analyzer as da_module
        monkeypatch.setattr(da_module, "FRIDA_AVAILABLE", False)

        result = analyzer._frida_runtime_analysis(None)

        assert result["success"] is False
        assert result["error"] == "Frida not available"

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
    def test_frida_runtime_analysis_error_handling(self, analyzer: AdvancedDynamicAnalyzer, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test Frida analysis error handling."""
        import intellicrack.core.analysis.dynamic_analyzer as da_module

        fake_spawn = FakeFridaSpawn("Test error")
        monkeypatch.setattr(da_module.frida, "spawn", fake_spawn)

        result = analyzer._frida_runtime_analysis(None)

        assert result["success"] is False
        assert "error" in result
        assert "Test error" in result["error"]

    @pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
    def test_process_behavior_analysis_success(self, analyzer: AdvancedDynamicAnalyzer) -> None:
        """Test successful process behavior analysis."""
        result = analyzer._process_behavior_analysis()

        assert isinstance(result, dict)

        if "error" not in result:
            assert "pid" in result
            assert "memory_info" in result
            assert "open_files" in result
            assert "connections" in result
            assert "threads" in result

            mem_info = result["memory_info"]
            assert "rss" in mem_info
            assert "vms" in mem_info

    def test_process_behavior_analysis_not_available(self, analyzer: AdvancedDynamicAnalyzer, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test process behavior analysis when psutil is not available."""
        import intellicrack.core.analysis.dynamic_analyzer as da_module
        monkeypatch.setattr(da_module, "PSUTIL_AVAILABLE", False)

        result = analyzer._process_behavior_analysis()

        assert result["success"] is False
        assert result["error"] == "psutil not available"

    @pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
    def test_process_behavior_analysis_error_handling(self, analyzer: AdvancedDynamicAnalyzer, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test process behavior analysis error handling."""
        fake_popen = FakePopen("Cannot start process")
        monkeypatch.setattr(subprocess, "Popen", fake_popen)

        result = analyzer._process_behavior_analysis()

        assert "error" in result
        assert "Cannot start process" in result["error"]

    def test_run_comprehensive_analysis(self, analyzer: AdvancedDynamicAnalyzer) -> None:
        """Test running comprehensive analysis combines all analyzers."""
        result = analyzer.run_comprehensive_analysis()

        assert isinstance(result, dict)
        assert "subprocess_execution" in result
        assert "frida_runtime_analysis" in result
        assert "process_behavior_analysis" in result

        assert isinstance(result["subprocess_execution"], dict)
        assert isinstance(result["frida_runtime_analysis"], dict)
        assert isinstance(result["process_behavior_analysis"], dict)

    def test_run_comprehensive_analysis_with_payload(self, analyzer: AdvancedDynamicAnalyzer) -> None:
        """Test comprehensive analysis with payload injection."""
        payload = b"\x41\x42\x43\x44"
        result = analyzer.run_comprehensive_analysis(payload)

        assert isinstance(result, dict)

        frida_result = result.get("frida_runtime_analysis", {})
        if frida_result.get("success"):
            assert frida_result.get("payload_injected") is True

    def test_scan_memory_for_keywords_with_frida(self, analyzer: AdvancedDynamicAnalyzer) -> None:
        """Test memory scanning with Frida available."""
        keywords = ["license", "serial", "key"]
        result = analyzer.scan_memory_for_keywords(keywords)

        assert isinstance(result, dict)
        assert "status" in result
        assert "matches" in result
        assert isinstance(result["matches"], list)

    def test_scan_memory_for_keywords_with_psutil(self, analyzer: AdvancedDynamicAnalyzer, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test memory scanning with psutil when Frida not available."""
        import intellicrack.core.analysis.dynamic_analyzer as da_module
        monkeypatch.setattr(da_module, "FRIDA_AVAILABLE", False)

        keywords = ["test", "data"]
        result = analyzer.scan_memory_for_keywords(keywords)

        assert isinstance(result, dict)
        assert "status" in result
        assert "matches" in result

    def test_scan_memory_for_keywords_fallback(self, analyzer: AdvancedDynamicAnalyzer, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test fallback memory scanning when no tools available."""
        import intellicrack.core.analysis.dynamic_analyzer as da_module
        monkeypatch.setattr(da_module, "FRIDA_AVAILABLE", False)
        monkeypatch.setattr(da_module, "PSUTIL_AVAILABLE", False)

        keywords = ["binary", "code"]
        result = analyzer.scan_memory_for_keywords(keywords)

        assert isinstance(result, dict)
        assert "status" in result
        assert result.get("scan_type") == "binary_file_analysis"

    def test_scan_memory_for_keywords_with_target_process(self, analyzer: AdvancedDynamicAnalyzer) -> None:
        """Test memory scanning with specific target process."""
        keywords = ["memory", "test"]
        result = analyzer.scan_memory_for_keywords(keywords, "notepad.exe")

        assert isinstance(result, dict)
        assert "matches" in result

    def test_scan_memory_error_handling(self, analyzer: AdvancedDynamicAnalyzer, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test memory scanning error handling."""
        fake_frida_scan = FakeAnalyzerMethod("Scan error")
        fake_psutil_scan = FakeAnalyzerMethod("Scan error")
        fake_fallback_scan = FakeAnalyzerMethod("Scan error")

        monkeypatch.setattr(analyzer, "_frida_memory_scan", fake_frida_scan)
        monkeypatch.setattr(analyzer, "_psutil_memory_scan", fake_psutil_scan)
        monkeypatch.setattr(analyzer, "_fallback_memory_scan", fake_fallback_scan)

        result = analyzer.scan_memory_for_keywords(["test"])

        assert result["status"] == "error"
        assert "Scan error" in result["error"]
        assert result["matches"] == []

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
    def test_frida_memory_scan_with_running_process(self, analyzer: AdvancedDynamicAnalyzer) -> None:
        """Test Frida memory scan with running process."""
        result = analyzer._frida_memory_scan(["test"], "python.exe" if platform.system() == "Windows" else "python")

        assert isinstance(result, dict)
        assert "status" in result
        assert "matches" in result
        assert isinstance(result["matches"], list)

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
    def test_frida_memory_scan_spawn_new_process(self, analyzer: AdvancedDynamicAnalyzer) -> None:
        """Test Frida memory scan spawning new process."""
        result = analyzer._frida_memory_scan(["data"], None)

        assert isinstance(result, dict)
        assert "status" in result
        assert "matches" in result

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
    def test_frida_memory_scan_error_handling(self, analyzer: AdvancedDynamicAnalyzer, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test Frida memory scan error handling."""
        import intellicrack.core.analysis.dynamic_analyzer as da_module

        fake_device = FakeFridaDevice("Device error")
        monkeypatch.setattr(da_module.frida, "get_local_device", fake_device)

        result = analyzer._frida_memory_scan(["test"], None)

        assert result["status"] == "error"
        assert "Device error" in result["error"]

    @pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
    def test_psutil_memory_scan_find_process(self, analyzer: AdvancedDynamicAnalyzer) -> None:
        """Test psutil memory scan finding existing process."""
        result = analyzer._psutil_memory_scan(["python"], "python")

        assert isinstance(result, dict)
        assert "status" in result
        assert result["status"] == "success"
        assert "matches" in result

    @pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
    def test_psutil_memory_scan_start_process(self, analyzer: AdvancedDynamicAnalyzer) -> None:
        """Test psutil memory scan starting new process."""
        result = analyzer._psutil_memory_scan(["test"], None)

        assert isinstance(result, dict)
        assert "status" in result
        assert "matches" in result

    @pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
    def test_psutil_memory_scan_access_denied(self, analyzer: AdvancedDynamicAnalyzer, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test psutil memory scan handling access denied."""
        import psutil

        def fake_process_init(pid: int) -> FakePsutilProcess:
            return FakePsutilProcess(pid)

        monkeypatch.setattr(psutil, "Process", fake_process_init)

        result = analyzer._psutil_memory_scan(["test"], "python")

        assert result["status"] == "error"
        assert "Access denied" in result["error"]

    def test_fallback_memory_scan_success(self, analyzer: AdvancedDynamicAnalyzer) -> None:
        """Test fallback memory scanning of binary file."""
        result = analyzer._fallback_memory_scan(["echo", "test"], None)

        assert isinstance(result, dict)
        assert result["status"] == "success"
        assert "matches" in result
        assert result["scan_type"] == "binary_file_analysis"

    def test_fallback_memory_scan_with_matches(self, tmp_path: Path) -> None:
        """Test fallback scan finding keywords in binary."""
        test_file = tmp_path / "test_with_keywords.exe"
        test_file.write_bytes(b"LICENSE_KEY=ABC123\x00SERIAL_NUMBER=XYZ789\x00")

        analyzer = AdvancedDynamicAnalyzer(test_file)
        result = analyzer._fallback_memory_scan(["LICENSE", "SERIAL"], None)

        assert result["status"] == "success"
        assert len(result["matches"]) >= 2

        for match in result["matches"]:
            assert "address" in match
            assert "keyword" in match
            assert "context" in match
            assert "offset" in match

    def test_fallback_memory_scan_error_handling(self, corrupted_binary_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test fallback scan error handling."""
        analyzer = AdvancedDynamicAnalyzer(corrupted_binary_path)

        fake_opener = FakeFileOpener("Read error")
        monkeypatch.setattr("builtins.open", fake_opener)

        result = analyzer._fallback_memory_scan(["test"], None)

        assert result["status"] == "error"
        assert "Read error" in result["error"]

    def test_create_dynamic_analyzer(self, test_binary_path: Path) -> None:
        """Test factory function creates analyzer correctly."""
        analyzer = create_dynamic_analyzer(test_binary_path)

        assert isinstance(analyzer, AdvancedDynamicAnalyzer)
        assert analyzer.binary_path == Path(test_binary_path)

    def test_run_quick_analysis(self, test_binary_path: Path) -> None:
        """Test quick analysis convenience function."""
        result = run_quick_analysis(test_binary_path)

        assert isinstance(result, dict)
        assert "subprocess_execution" in result
        assert "frida_runtime_analysis" in result
        assert "process_behavior_analysis" in result

    def test_run_quick_analysis_with_payload(self, test_binary_path: Path) -> None:
        """Test quick analysis with payload."""
        payload = b"\x90" * 10
        result = run_quick_analysis(test_binary_path, payload)

        assert isinstance(result, dict)
        frida_result = result.get("frida_runtime_analysis", {})
        if frida_result.get("success"):
            assert frida_result["payload_injected"] is True

    def test_run_dynamic_analysis_with_app(self, test_binary_path: Path) -> None:
        """Test run_dynamic_analysis with app integration."""
        app = TestDynamicAnalysisApp()
        app.binary_path = test_binary_path

        result = run_dynamic_analysis(app)

        assert isinstance(result, dict)
        assert app.update_output.was_called()
        assert hasattr(app, "analyze_results")

    def test_run_dynamic_analysis_no_binary(self) -> None:
        """Test run_dynamic_analysis without binary selected."""
        app = TestDynamicAnalysisApp()
        app.binary_path = None

        result = run_dynamic_analysis(app)

        assert result == {"error": "No binary selected"}
        assert app.update_output.was_called()

    def test_deep_runtime_monitoring(self, test_binary_path: Path) -> None:
        """Test deep runtime monitoring function."""
        logs = deep_runtime_monitoring(str(test_binary_path), timeout=1000)

        assert isinstance(logs, list)
        assert len(logs) > 0
        assert any("Starting runtime monitoring" in log for log in logs)

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
    def test_deep_runtime_monitoring_with_frida(self, test_binary_path: Path) -> None:
        """Test deep runtime monitoring with real Frida instrumentation capabilities."""
        import psutil

        current_pid = os.getpid()
        current_process = psutil.Process(current_pid)
        target_process = current_process.name()

        logs = deep_runtime_monitoring(target_process, timeout=2000)

        assert len(logs) > 0
        assert any("runtime monitoring" in log.lower() for log in logs)

        frida_related_logs = [log for log in logs if "frida" in log.lower() or "attach" in log.lower()]
        assert (
            frida_related_logs
        ), "Should attempt real Frida process attachment for instrumentation"

    def test_deep_runtime_monitoring_no_frida(self, test_binary_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test deep runtime monitoring without Frida."""
        import intellicrack.core.analysis.dynamic_analyzer as da_module
        monkeypatch.setattr(da_module, "FRIDA_AVAILABLE", False)

        logs = deep_runtime_monitoring(str(test_binary_path))

        assert any("Frida not available" in log for log in logs)

    def test_dynamic_analyzer_alias(self, test_binary_path: Path) -> None:
        """Test DynamicAnalyzer alias works for backward compatibility."""
        analyzer = DynamicAnalyzer(test_binary_path)

        assert isinstance(analyzer, AdvancedDynamicAnalyzer)
        assert analyzer.binary_path == Path(test_binary_path)

    def test_logging_comprehensive_analysis(self, analyzer: AdvancedDynamicAnalyzer, caplog: pytest.LogCaptureFixture) -> None:
        """Test logging during comprehensive analysis."""
        with caplog.at_level(logging.INFO):
            analyzer.run_comprehensive_analysis()

        assert "Running comprehensive dynamic analysis" in caplog.text
        assert "Comprehensive dynamic analysis completed" in caplog.text

    def test_logging_subprocess_analysis(self, analyzer: AdvancedDynamicAnalyzer, caplog: pytest.LogCaptureFixture) -> None:
        """Test logging during subprocess analysis."""
        with caplog.at_level(logging.INFO):
            analyzer._subprocess_analysis()

        assert "Starting subprocess analysis" in caplog.text

    def test_logging_memory_scan(self, analyzer: AdvancedDynamicAnalyzer, caplog: pytest.LogCaptureFixture) -> None:
        """Test logging during memory scanning."""
        with caplog.at_level(logging.INFO):
            analyzer.scan_memory_for_keywords(["test"])

        assert "Starting memory keyword scan" in caplog.text

    def test_empty_keywords_memory_scan(self, analyzer: AdvancedDynamicAnalyzer) -> None:
        """Test memory scan with empty keywords list."""
        result = analyzer.scan_memory_for_keywords([])

        assert isinstance(result, dict)
        assert "matches" in result
        assert result["matches"] == []

    def test_unicode_keywords_memory_scan(self, analyzer: AdvancedDynamicAnalyzer) -> None:
        """Test memory scan with unicode keywords."""
        keywords = ["测试", "テスト", "тест"]
        result = analyzer.scan_memory_for_keywords(keywords)

        assert isinstance(result, dict)
        assert "status" in result

    def test_very_long_keyword_memory_scan(self, analyzer: AdvancedDynamicAnalyzer) -> None:
        """Test memory scan with very long keyword."""
        long_keyword = "A" * 1000
        result = analyzer.scan_memory_for_keywords([long_keyword])

        assert isinstance(result, dict)
        assert "status" in result

    def test_special_characters_in_keywords(self, analyzer: AdvancedDynamicAnalyzer) -> None:
        """Test memory scan with special characters."""
        keywords = ["test@123", "key#456", "data$789"]
        result = analyzer.scan_memory_for_keywords(keywords)

        assert isinstance(result, dict)
        assert "matches" in result

    def test_analysis_performance(self, analyzer: AdvancedDynamicAnalyzer) -> None:
        """Test analysis completes in reasonable time."""
        import time

        start = time.time()
        analyzer.run_comprehensive_analysis()
        elapsed = time.time() - start

        assert elapsed < 30, f"Analysis took too long: {elapsed:.2f}s"

    def test_memory_scan_performance(self, analyzer: AdvancedDynamicAnalyzer) -> None:
        """Test memory scan performance with many keywords."""
        keywords = [f"keyword_{i}" for i in range(100)]

        import time
        start = time.time()
        analyzer.scan_memory_for_keywords(keywords)
        elapsed = time.time() - start

        assert elapsed < 60, f"Memory scan took too long: {elapsed:.2f}s"

    def test_full_workflow_with_real_binary(self, real_system_binary: Path) -> None:
        """Test complete workflow with real system binary."""
        analyzer = AdvancedDynamicAnalyzer(real_system_binary)

        analysis_result = analyzer.run_comprehensive_analysis()
        assert isinstance(analysis_result, dict)

        memory_result = analyzer.scan_memory_for_keywords(["system", "windows", "linux"])
        assert isinstance(memory_result, dict)

        assert any(
            analysis_result.get(key, {}).get("success") or
            analysis_result.get(key, {}).get("pid") or
            "error" not in analysis_result.get(key, {})
            for key in ["subprocess_execution", "frida_runtime_analysis", "process_behavior_analysis"]
        )

    def test_multiple_analyzer_instances(self, test_binary_path: Path, real_system_binary: Path) -> None:
        """Test multiple analyzer instances work independently."""
        analyzer1 = AdvancedDynamicAnalyzer(test_binary_path)
        analyzer2 = AdvancedDynamicAnalyzer(real_system_binary)

        result1 = analyzer1._subprocess_analysis()
        result2 = analyzer2._subprocess_analysis()

        assert isinstance(result1, dict)
        assert isinstance(result2, dict)

        assert analyzer1.binary_path != analyzer2.binary_path

    def test_recovery_from_subprocess_failure(self, corrupted_binary_path: Path) -> None:
        """Test analyzer recovers from subprocess failure."""
        analyzer = AdvancedDynamicAnalyzer(corrupted_binary_path)

        result = analyzer.run_comprehensive_analysis()

        assert isinstance(result, dict)
        assert "frida_runtime_analysis" in result
        assert "process_behavior_analysis" in result

    def test_partial_analysis_on_tool_unavailability(self, analyzer: AdvancedDynamicAnalyzer, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test partial analysis when some tools unavailable."""
        import intellicrack.core.analysis.dynamic_analyzer as da_module
        monkeypatch.setattr(da_module, "FRIDA_AVAILABLE", False)
        monkeypatch.setattr(da_module, "PSUTIL_AVAILABLE", False)

        result = analyzer.run_comprehensive_analysis()

        assert "subprocess_execution" in result
        assert isinstance(result["subprocess_execution"], dict)

        assert result["frida_runtime_analysis"]["error"] == "Frida not available"
        assert result["process_behavior_analysis"]["error"] == "psutil not available"
