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

    def __init__(self):
        """Initialize test app with tracking capabilities."""
        self.binary_path = None
        self.output_updates = []
        self.analyze_results = []
        self.update_output = TestSignalEmitter()

    def set_binary_path(self, path):
        """Set binary path for analysis."""
        self.binary_path = path


class TestSignalEmitter:
    """Real signal emitter to replace MagicMock update_output signals."""

    def __init__(self):
        """Initialize signal emitter with call tracking."""
        self.emission_log = []
        self.emit = self._emit_handler

    def _emit_handler(self, *args, **kwargs):
        """Track emit calls with real data."""
        self.emission_log.append({"args": args, "kwargs": kwargs})

    def was_called(self):
        """Check if emit was called."""
        return len(self.emission_log) > 0

    def call_count(self):
        """Get number of emit calls."""
        return len(self.emission_log)

    def get_calls(self):
        """Get all emit call data."""
        return self.emission_log


class TestAdvancedDynamicAnalyzer:
    """Comprehensive test suite for AdvancedDynamicAnalyzer."""

    @pytest.fixture
    def test_binary_path(self, tmp_path):
        """Create a test binary file for analysis."""
        if platform.system() == "Windows":
            # Create a simple batch file as test binary
            test_file = tmp_path / "test_binary.bat"
            test_file.write_text("@echo off\necho Test Binary\nexit 0")
        else:
            # Create a simple shell script for Unix systems
            test_file = tmp_path / "test_binary.sh"
            test_file.write_text("#!/bin/sh\necho 'Test Binary'\nexit 0")
            test_file.chmod(0o755)
        return test_file

    @pytest.fixture
    def corrupted_binary_path(self, tmp_path):
        """Create a corrupted binary file."""
        test_file = tmp_path / "corrupted.exe"
        test_file.write_bytes(b"\x00\x01\x02\x03\x04\x05")  # Invalid binary data
        return test_file

    @pytest.fixture
    def real_system_binary(self):
        """Get path to a real system binary for testing."""
        if platform.system() == "Windows":
            # Use Windows system binaries
            candidates = [
                r"C:\Windows\System32\ping.exe",
                r"C:\Windows\System32\hostname.exe",
                r"C:\Windows\System32\whoami.exe",
            ]
        else:
            # Use Unix system binaries
            candidates = ["/bin/echo", "/bin/ls", "/usr/bin/whoami"]

        for candidate in candidates:
            if Path(candidate).exists():
                return Path(candidate)

        # Fallback to Python executable
        return Path(sys.executable)

    @pytest.fixture
    def analyzer(self, test_binary_path):
        """Create an analyzer instance with test binary."""
        return AdvancedDynamicAnalyzer(test_binary_path)

    # ============= Initialization Tests =============

    def test_initialization_with_valid_binary(self, test_binary_path):
        """Test analyzer initialization with valid binary path."""
        analyzer = AdvancedDynamicAnalyzer(test_binary_path)
        assert analyzer.binary_path == Path(test_binary_path)
        assert analyzer.logger is not None
        assert analyzer.api_calls == []
        assert analyzer.memory_access == []
        assert analyzer.network_activity == []
        assert analyzer.file_operations == []

    def test_initialization_with_string_path(self, test_binary_path):
        """Test initialization with string path converts to Path object."""
        analyzer = AdvancedDynamicAnalyzer(str(test_binary_path))
        assert isinstance(analyzer.binary_path, Path)
        assert analyzer.binary_path == Path(test_binary_path)

    def test_initialization_with_nonexistent_file(self, tmp_path):
        """Test initialization fails with nonexistent file."""
        nonexistent = tmp_path / "nonexistent.exe"
        with pytest.raises(FileNotFoundError, match="Binary file not found"):
            AdvancedDynamicAnalyzer(nonexistent)

    def test_initialization_with_directory(self, tmp_path):
        """Test initialization fails when path is a directory."""
        with pytest.raises(FileNotFoundError, match="Binary file not found"):
            AdvancedDynamicAnalyzer(tmp_path)

    # ============= Subprocess Analysis Tests =============

    def test_subprocess_analysis_success(self, analyzer, test_binary_path):
        """Test successful subprocess execution analysis."""
        result = analyzer._subprocess_analysis()

        assert isinstance(result, dict)
        assert "success" in result
        assert "stdout" in result or "error" in result

        if result.get("success"):
            assert "return_code" in result
            assert result["return_code"] == 0
            assert "stderr" in result

    def test_subprocess_analysis_with_real_binary(self, real_system_binary):
        """Test subprocess analysis with real system binary."""
        analyzer = AdvancedDynamicAnalyzer(real_system_binary)
        result = analyzer._subprocess_analysis()

        assert isinstance(result, dict)
        assert "success" in result

        if result.get("success"):
            assert result["return_code"] >= 0
            assert "stdout" in result
            assert "stderr" in result

    def test_subprocess_analysis_timeout(self, tmp_path):
        """Test subprocess analysis handles timeout correctly."""
        if platform.system() == "Windows":
            # Create a batch file that sleeps
            test_file = tmp_path / "slow.bat"
            test_file.write_text("@echo off\nping 127.0.0.1 -n 15 > nul\necho Done")
        else:
            # Create a shell script that sleeps
            test_file = tmp_path / "slow.sh"
            test_file.write_text("#!/bin/sh\nsleep 15\necho Done")
            test_file.chmod(0o755)

        analyzer = AdvancedDynamicAnalyzer(test_file)
        result = analyzer._subprocess_analysis()

        assert result["success"] is False
        assert "error" in result
        assert "Timeout" in result["error"]

    def test_subprocess_analysis_with_error_binary(self, tmp_path):
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

    # ============= Frida Runtime Analysis Tests =============

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
    def test_frida_runtime_analysis_with_payload(self, analyzer):
        """Test Frida runtime analysis with payload injection."""
        payload = b"\x90\x90\x90\x90"  # NOP sled
        result = analyzer._frida_runtime_analysis(payload)

        assert isinstance(result, dict)
        assert "success" in result

        if result.get("success"):
            assert "pid" in result
            assert "analysis_data" in result
            assert result["payload_injected"] is True

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
    def test_frida_runtime_analysis_without_payload(self, analyzer):
        """Test Frida runtime analysis without payload."""
        result = analyzer._frida_runtime_analysis(None)

        assert isinstance(result, dict)
        assert "success" in result

        if result.get("success"):
            assert result["payload_injected"] is False

    def test_frida_runtime_analysis_not_available(self, analyzer):
        """Test Frida analysis when Frida is not available."""
        with patch("intellicrack.core.analysis.dynamic_analyzer.FRIDA_AVAILABLE", False):
            result = analyzer._frida_runtime_analysis(None)

            assert result["success"] is False
            assert result["error"] == "Frida not available"

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
    def test_frida_runtime_analysis_error_handling(self, analyzer):
        """Test Frida analysis error handling."""
        with patch("intellicrack.core.analysis.dynamic_analyzer.frida.spawn", side_effect=OSError("Test error")):
            result = analyzer._frida_runtime_analysis(None)

            assert result["success"] is False
            assert "error" in result
            assert "Test error" in result["error"]

    # ============= Process Behavior Analysis Tests =============

    @pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
    def test_process_behavior_analysis_success(self, analyzer):
        """Test successful process behavior analysis."""
        result = analyzer._process_behavior_analysis()

        assert isinstance(result, dict)

        if "error" not in result:
            assert "pid" in result
            assert "memory_info" in result
            assert "open_files" in result
            assert "connections" in result
            assert "threads" in result

            # Validate memory info structure
            mem_info = result["memory_info"]
            assert "rss" in mem_info
            assert "vms" in mem_info

    def test_process_behavior_analysis_not_available(self, analyzer):
        """Test process behavior analysis when psutil is not available."""
        with patch("intellicrack.core.analysis.dynamic_analyzer.PSUTIL_AVAILABLE", False):
            result = analyzer._process_behavior_analysis()

            assert result["success"] is False
            assert result["error"] == "psutil not available"

    @pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
    def test_process_behavior_analysis_error_handling(self, analyzer):
        """Test process behavior analysis error handling."""
        with patch("subprocess.Popen", side_effect=OSError("Cannot start process")):
            result = analyzer._process_behavior_analysis()

            assert "error" in result
            assert "Cannot start process" in result["error"]

    # ============= Comprehensive Analysis Tests =============

    def test_run_comprehensive_analysis(self, analyzer):
        """Test running comprehensive analysis combines all analyzers."""
        result = analyzer.run_comprehensive_analysis()

        assert isinstance(result, dict)
        assert "subprocess_execution" in result
        assert "frida_runtime_analysis" in result
        assert "process_behavior_analysis" in result

        # Each sub-result should be a dictionary
        assert isinstance(result["subprocess_execution"], dict)
        assert isinstance(result["frida_runtime_analysis"], dict)
        assert isinstance(result["process_behavior_analysis"], dict)

    def test_run_comprehensive_analysis_with_payload(self, analyzer):
        """Test comprehensive analysis with payload injection."""
        payload = b"\x41\x42\x43\x44"  # ABCD
        result = analyzer.run_comprehensive_analysis(payload)

        assert isinstance(result, dict)

        # Check payload was passed to Frida analysis
        frida_result = result.get("frida_runtime_analysis", {})
        if frida_result.get("success"):
            assert frida_result.get("payload_injected") is True

    # ============= Memory Scanning Tests =============

    def test_scan_memory_for_keywords_with_frida(self, analyzer):
        """Test memory scanning with Frida available."""
        keywords = ["license", "serial", "key"]
        result = analyzer.scan_memory_for_keywords(keywords)

        assert isinstance(result, dict)
        assert "status" in result
        assert "matches" in result
        assert isinstance(result["matches"], list)

    def test_scan_memory_for_keywords_with_psutil(self, analyzer):
        """Test memory scanning with psutil when Frida not available."""
        with patch("intellicrack.core.analysis.dynamic_analyzer.FRIDA_AVAILABLE", False):
            keywords = ["test", "data"]
            result = analyzer.scan_memory_for_keywords(keywords)

            assert isinstance(result, dict)
            assert "status" in result
            assert "matches" in result

    def test_scan_memory_for_keywords_fallback(self, analyzer):
        """Test fallback memory scanning when no tools available."""
        with patch("intellicrack.core.analysis.dynamic_analyzer.FRIDA_AVAILABLE", False), \
             patch("intellicrack.core.analysis.dynamic_analyzer.PSUTIL_AVAILABLE", False):

            keywords = ["binary", "code"]
            result = analyzer.scan_memory_for_keywords(keywords)

            assert isinstance(result, dict)
            assert "status" in result
            assert result.get("scan_type") == "binary_file_analysis"

    def test_scan_memory_for_keywords_with_target_process(self, analyzer):
        """Test memory scanning with specific target process."""
        keywords = ["memory", "test"]
        result = analyzer.scan_memory_for_keywords(keywords, "notepad.exe")

        assert isinstance(result, dict)
        assert "matches" in result

    def test_scan_memory_error_handling(self, analyzer):
        """Test memory scanning error handling."""
        with patch.object(analyzer, "_frida_memory_scan", side_effect=Exception("Scan error")), \
             patch.object(analyzer, "_psutil_memory_scan", side_effect=Exception("Scan error")), \
             patch.object(analyzer, "_fallback_memory_scan", side_effect=Exception("Scan error")):

            result = analyzer.scan_memory_for_keywords(["test"])

            assert result["status"] == "error"
            assert "Scan error" in result["error"]
            assert result["matches"] == []

    # ============= Frida Memory Scan Tests =============

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
    def test_frida_memory_scan_with_running_process(self, analyzer):
        """Test Frida memory scan with running process."""
        result = analyzer._frida_memory_scan(["test"], "python.exe" if platform.system() == "Windows" else "python")

        assert isinstance(result, dict)
        assert "status" in result
        assert "matches" in result
        assert isinstance(result["matches"], list)

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
    def test_frida_memory_scan_spawn_new_process(self, analyzer):
        """Test Frida memory scan spawning new process."""
        result = analyzer._frida_memory_scan(["data"], None)

        assert isinstance(result, dict)
        assert "status" in result
        assert "matches" in result

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
    def test_frida_memory_scan_error_handling(self, analyzer):
        """Test Frida memory scan error handling."""
        with patch("intellicrack.core.analysis.dynamic_analyzer.frida.get_local_device", side_effect=Exception("Device error")):
            result = analyzer._frida_memory_scan(["test"], None)

            assert result["status"] == "error"
            assert "Device error" in result["error"]

    # ============= PSUtil Memory Scan Tests =============

    @pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
    def test_psutil_memory_scan_find_process(self, analyzer):
        """Test psutil memory scan finding existing process."""
        # Use current Python process as target
        result = analyzer._psutil_memory_scan(["python"], "python")

        assert isinstance(result, dict)
        assert "status" in result
        assert result["status"] == "success"
        assert "matches" in result

    @pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
    def test_psutil_memory_scan_start_process(self, analyzer):
        """Test psutil memory scan starting new process."""
        result = analyzer._psutil_memory_scan(["test"], None)

        assert isinstance(result, dict)
        assert "status" in result
        assert "matches" in result

    @pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
    def test_psutil_memory_scan_access_denied(self, analyzer):
        """Test psutil memory scan handling access denied."""
        import psutil

        with patch("psutil.Process.memory_info", side_effect=psutil.AccessDenied("Access denied")):
            result = analyzer._psutil_memory_scan(["test"], "python")

            assert result["status"] == "error"
            assert "Access denied" in result["error"]

    # ============= Fallback Memory Scan Tests =============

    def test_fallback_memory_scan_success(self, analyzer):
        """Test fallback memory scanning of binary file."""
        result = analyzer._fallback_memory_scan(["echo", "test"], None)

        assert isinstance(result, dict)
        assert result["status"] == "success"
        assert "matches" in result
        assert result["scan_type"] == "binary_file_analysis"

    def test_fallback_memory_scan_with_matches(self, tmp_path):
        """Test fallback scan finding keywords in binary."""
        # Create binary with known content
        test_file = tmp_path / "test_with_keywords.exe"
        test_file.write_bytes(b"LICENSE_KEY=ABC123\x00SERIAL_NUMBER=XYZ789\x00")

        analyzer = AdvancedDynamicAnalyzer(test_file)
        result = analyzer._fallback_memory_scan(["LICENSE", "SERIAL"], None)

        assert result["status"] == "success"
        assert len(result["matches"]) >= 2

        # Check match structure
        for match in result["matches"]:
            assert "address" in match
            assert "keyword" in match
            assert "context" in match
            assert "offset" in match

    def test_fallback_memory_scan_error_handling(self, corrupted_binary_path):
        """Test fallback scan error handling."""
        analyzer = AdvancedDynamicAnalyzer(corrupted_binary_path)

        # Mock file reading to raise exception
        with patch("builtins.open", side_effect=IOError("Read error")):
            result = analyzer._fallback_memory_scan(["test"], None)

            assert result["status"] == "error"
            assert "Read error" in result["error"]

    # ============= Convenience Function Tests =============

    def test_create_dynamic_analyzer(self, test_binary_path):
        """Test factory function creates analyzer correctly."""
        analyzer = create_dynamic_analyzer(test_binary_path)

        assert isinstance(analyzer, AdvancedDynamicAnalyzer)
        assert analyzer.binary_path == Path(test_binary_path)

    def test_run_quick_analysis(self, test_binary_path):
        """Test quick analysis convenience function."""
        result = run_quick_analysis(test_binary_path)

        assert isinstance(result, dict)
        assert "subprocess_execution" in result
        assert "frida_runtime_analysis" in result
        assert "process_behavior_analysis" in result

    def test_run_quick_analysis_with_payload(self, test_binary_path):
        """Test quick analysis with payload."""
        payload = b"\x90" * 10
        result = run_quick_analysis(test_binary_path, payload)

        assert isinstance(result, dict)
        frida_result = result.get("frida_runtime_analysis", {})
        if frida_result.get("success"):
            assert frida_result["payload_injected"] is True

    def test_run_dynamic_analysis_with_app(self, test_binary_path):
        """Test run_dynamic_analysis with app integration."""
        # Real test app object
        app = TestDynamicAnalysisApp()
        app.binary_path = test_binary_path

        result = run_dynamic_analysis(app)

        assert isinstance(result, dict)
        # Check app was updated with real signal emissions
        assert app.update_output.was_called()
        assert hasattr(app, "analyze_results")

    def test_run_dynamic_analysis_no_binary(self):
        """Test run_dynamic_analysis without binary selected."""
        app = TestDynamicAnalysisApp()
        app.binary_path = None

        result = run_dynamic_analysis(app)

        assert result == {"error": "No binary selected"}
        assert app.update_output.was_called()

    def test_deep_runtime_monitoring(self, test_binary_path):
        """Test deep runtime monitoring function."""
        logs = deep_runtime_monitoring(str(test_binary_path), timeout=1000)

        assert isinstance(logs, list)
        assert len(logs) > 0
        assert any("Starting runtime monitoring" in log for log in logs)

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")
    def test_deep_runtime_monitoring_with_frida(self, test_binary_path):
        """Test deep runtime monitoring with real Frida instrumentation capabilities."""
        # Test real Frida runtime monitoring against actual process
        # This validates Intellicrack's ability to instrument and monitor real binaries
        import psutil

        # Use current Python process as safe target for instrumentation testing
        current_pid = os.getpid()
        current_process = psutil.Process(current_pid)
        target_process = current_process.name()

        # Test real Frida instrumentation on live process
        logs = deep_runtime_monitoring(target_process, timeout=2000)

        assert len(logs) > 0
        assert any("runtime monitoring" in log.lower() for log in logs)

        # Verify real instrumentation attempted with live process
        frida_related_logs = [log for log in logs if "frida" in log.lower() or "attach" in log.lower()]
        assert (
            frida_related_logs
        ), "Should attempt real Frida process attachment for instrumentation"

    def test_deep_runtime_monitoring_no_frida(self, test_binary_path):
        """Test deep runtime monitoring without Frida."""
        with patch("intellicrack.core.analysis.dynamic_analyzer.FRIDA_AVAILABLE", False):
            logs = deep_runtime_monitoring(str(test_binary_path))

            assert any("Frida not available" in log for log in logs)

    # ============= Backward Compatibility Tests =============

    def test_dynamic_analyzer_alias(self, test_binary_path):
        """Test DynamicAnalyzer alias works for backward compatibility."""
        analyzer = DynamicAnalyzer(test_binary_path)

        assert isinstance(analyzer, AdvancedDynamicAnalyzer)
        assert analyzer.binary_path == Path(test_binary_path)

    # ============= Logging Tests =============

    def test_logging_comprehensive_analysis(self, analyzer, caplog):
        """Test logging during comprehensive analysis."""
        with caplog.at_level(logging.INFO):
            analyzer.run_comprehensive_analysis()

        assert "Running comprehensive dynamic analysis" in caplog.text
        assert "Comprehensive dynamic analysis completed" in caplog.text

    def test_logging_subprocess_analysis(self, analyzer, caplog):
        """Test logging during subprocess analysis."""
        with caplog.at_level(logging.INFO):
            analyzer._subprocess_analysis()

        assert "Starting subprocess analysis" in caplog.text

    def test_logging_memory_scan(self, analyzer, caplog):
        """Test logging during memory scanning."""
        with caplog.at_level(logging.INFO):
            analyzer.scan_memory_for_keywords(["test"])

        assert "Starting memory keyword scan" in caplog.text

    # ============= Edge Case Tests =============

    def test_empty_keywords_memory_scan(self, analyzer):
        """Test memory scan with empty keywords list."""
        result = analyzer.scan_memory_for_keywords([])

        assert isinstance(result, dict)
        assert "matches" in result
        assert result["matches"] == []

    def test_unicode_keywords_memory_scan(self, analyzer):
        """Test memory scan with unicode keywords."""
        keywords = ["测试", "テスト", "тест"]
        result = analyzer.scan_memory_for_keywords(keywords)

        assert isinstance(result, dict)
        assert "status" in result

    def test_very_long_keyword_memory_scan(self, analyzer):
        """Test memory scan with very long keyword."""
        long_keyword = "A" * 1000
        result = analyzer.scan_memory_for_keywords([long_keyword])

        assert isinstance(result, dict)
        assert "status" in result

    def test_special_characters_in_keywords(self, analyzer):
        """Test memory scan with special characters."""
        keywords = ["test@123", "key#456", "data$789"]
        result = analyzer.scan_memory_for_keywords(keywords)

        assert isinstance(result, dict)
        assert "matches" in result

    # ============= Performance Tests =============

    def test_analysis_performance(self, analyzer):
        """Test analysis completes in reasonable time."""
        import time

        start = time.time()
        analyzer.run_comprehensive_analysis()
        elapsed = time.time() - start

        # Should complete within 30 seconds even with all analysis
        assert elapsed < 30, f"Analysis took too long: {elapsed:.2f}s"

    def test_memory_scan_performance(self, analyzer):
        """Test memory scan performance with many keywords."""
        keywords = [f"keyword_{i}" for i in range(100)]

        import time
        start = time.time()
        analyzer.scan_memory_for_keywords(keywords)
        elapsed = time.time() - start

        # Should handle 100 keywords within reasonable time
        assert elapsed < 60, f"Memory scan took too long: {elapsed:.2f}s"

    # ============= Integration Tests =============

    def test_full_workflow_with_real_binary(self, real_system_binary):
        """Test complete workflow with real system binary."""
        analyzer = AdvancedDynamicAnalyzer(real_system_binary)

        # Run comprehensive analysis
        analysis_result = analyzer.run_comprehensive_analysis()
        assert isinstance(analysis_result, dict)

        # Run memory scan
        memory_result = analyzer.scan_memory_for_keywords(["system", "windows", "linux"])
        assert isinstance(memory_result, dict)

        # Verify some analysis was performed
        assert any(
            analysis_result.get(key, {}).get("success") or
            analysis_result.get(key, {}).get("pid") or
            "error" not in analysis_result.get(key, {})
            for key in ["subprocess_execution", "frida_runtime_analysis", "process_behavior_analysis"]
        )

    def test_multiple_analyzer_instances(self, test_binary_path, real_system_binary):
        """Test multiple analyzer instances work independently."""
        analyzer1 = AdvancedDynamicAnalyzer(test_binary_path)
        analyzer2 = AdvancedDynamicAnalyzer(real_system_binary)

        # Run analysis on both
        result1 = analyzer1._subprocess_analysis()
        result2 = analyzer2._subprocess_analysis()

        assert isinstance(result1, dict)
        assert isinstance(result2, dict)

        # Verify they're independent
        assert analyzer1.binary_path != analyzer2.binary_path

    # ============= Error Recovery Tests =============

    def test_recovery_from_subprocess_failure(self, corrupted_binary_path):
        """Test analyzer recovers from subprocess failure."""
        analyzer = AdvancedDynamicAnalyzer(corrupted_binary_path)

        # Should handle corrupted binary gracefully
        result = analyzer.run_comprehensive_analysis()

        assert isinstance(result, dict)
        # Other analyses should still run even if subprocess fails
        assert "frida_runtime_analysis" in result
        assert "process_behavior_analysis" in result

    def test_partial_analysis_on_tool_unavailability(self, analyzer):
        """Test partial analysis when some tools unavailable."""
        with patch("intellicrack.core.analysis.dynamic_analyzer.FRIDA_AVAILABLE", False), \
             patch("intellicrack.core.analysis.dynamic_analyzer.PSUTIL_AVAILABLE", False):

            result = analyzer.run_comprehensive_analysis()

            # Should still have subprocess analysis
            assert "subprocess_execution" in result
            assert isinstance(result["subprocess_execution"], dict)

            # Other analyses should report unavailability
            assert result["frida_runtime_analysis"]["error"] == "Frida not available"
            assert result["process_behavior_analysis"]["error"] == "psutil not available"
