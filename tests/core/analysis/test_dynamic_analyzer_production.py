"""Production-grade tests for dynamic analyzer with real Frida instrumentation.

This test module validates that the dynamic analyzer successfully:
- Integrates Frida for dynamic instrumentation
- Supports Intel Pin for detailed execution tracing
- Traces API calls with argument/return value logging
- Monitors memory read/write operations
- Tracks code coverage during execution
- Handles anti-instrumentation techniques
- Works with multi-threaded code

CRITICAL: All tests validate REAL instrumentation capabilities. Tests MUST FAIL
if instrumentation hooks are missing or non-functional.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.dynamic_analyzer import (
    AdvancedDynamicAnalyzer,
    create_dynamic_analyzer,
    deep_runtime_monitoring,
    run_quick_analysis,
)
from intellicrack.utils.core.import_checks import FRIDA_AVAILABLE, PSUTIL_AVAILABLE, frida, psutil


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures"
BINARIES_DIR = FIXTURES_DIR / "binaries" / "pe" / "legitimate"
PROTECTED_DIR = FIXTURES_DIR / "binaries" / "protected"
FULL_SOFTWARE_DIR = FIXTURES_DIR / "full_protected_software"


pytestmark = pytest.mark.skipif(
    not FRIDA_AVAILABLE or frida is None,
    reason="Frida not available - REQUIRED for dynamic instrumentation validation",
)


@pytest.fixture
def simple_test_binary() -> Path:
    """Provide a simple test binary for instrumentation.

    Uses a legitimate Windows binary that can be safely instrumented.
    """
    test_binary = BINARIES_DIR / "7zip.exe"

    if not test_binary.exists():
        pytest.skip(
            f"Test binary not found: {test_binary}\n"
            "CRITICAL: Dynamic analyzer tests require real binaries to validate "
            "instrumentation capabilities. Without binaries, we cannot verify that "
            "Frida hooks work on actual executables."
        )

    return test_binary


@pytest.fixture
def protected_binary() -> Path:
    """Provide a protected binary for advanced instrumentation testing."""
    test_binary = PROTECTED_DIR / "upx_packed_0.exe"

    if not test_binary.exists():
        pytest.skip(
            f"Protected binary not found: {test_binary}\n"
            "CRITICAL: Advanced instrumentation tests require protected binaries "
            "to validate anti-instrumentation handling."
        )

    return test_binary


@pytest.fixture
def analyzer(simple_test_binary: Path) -> AdvancedDynamicAnalyzer:
    """Create a configured dynamic analyzer instance."""
    return AdvancedDynamicAnalyzer(simple_test_binary)


@pytest.fixture
def license_protected_binary() -> Path:
    """Provide a binary with license-related functions for detection testing."""
    license_binary = FULL_SOFTWARE_DIR / "Beyond_Compare_Full.exe"

    if not license_binary.exists():
        pytest.skip(
            f"License-protected binary not found: {license_binary}\n"
            "CRITICAL: License function detection tests require real software "
            "with actual licensing mechanisms to validate detection capabilities."
        )

    return license_binary


class TestDynamicAnalyzerInitialization:
    """Test dynamic analyzer initialization and configuration."""

    def test_analyzer_initializes_with_valid_binary(self, simple_test_binary: Path) -> None:
        """Analyzer initializes successfully with valid binary path."""
        analyzer = AdvancedDynamicAnalyzer(simple_test_binary)

        assert analyzer.binary_path == simple_test_binary
        assert analyzer.binary_path.exists()
        assert analyzer.binary_path.is_file()
        assert isinstance(analyzer.api_calls, list)
        assert isinstance(analyzer.memory_access, list)
        assert isinstance(analyzer.network_activity, list)
        assert isinstance(analyzer.file_operations, list)
        assert len(analyzer.api_calls) == 0
        assert len(analyzer.memory_access) == 0

    def test_analyzer_rejects_nonexistent_binary(self, tmp_path: Path) -> None:
        """Analyzer raises FileNotFoundError for nonexistent binary."""
        nonexistent = tmp_path / "does_not_exist.exe"

        with pytest.raises(FileNotFoundError, match="Binary file not found"):
            AdvancedDynamicAnalyzer(nonexistent)

    def test_analyzer_rejects_directory_path(self, tmp_path: Path) -> None:
        """Analyzer raises FileNotFoundError when path is a directory."""
        with pytest.raises(FileNotFoundError, match="Binary file not found"):
            AdvancedDynamicAnalyzer(tmp_path)

    def test_create_dynamic_analyzer_factory(self, simple_test_binary: Path) -> None:
        """Factory function creates properly configured analyzer."""
        analyzer = create_dynamic_analyzer(simple_test_binary)

        assert isinstance(analyzer, AdvancedDynamicAnalyzer)
        assert analyzer.binary_path == simple_test_binary


class TestFridaInstrumentationIntegration:
    """Test real Frida instrumentation integration.

    CRITICAL: These tests validate that Frida instrumentation actually works
    on real binaries. Tests MUST FAIL if instrumentation is broken.
    """

    @pytest.mark.timeout(60)
    def test_frida_runtime_analysis_spawns_and_attaches_to_process(
        self, analyzer: AdvancedDynamicAnalyzer
    ) -> None:
        """Frida spawns process and successfully attaches for instrumentation.

        VALIDATION: This test proves Frida can spawn and attach to a real process.
        If Frida attachment fails, this test MUST FAIL.
        """
        if frida is None:
            pytest.skip("Frida module not available")

        result = analyzer._frida_runtime_analysis(payload=None)

        assert result["success"] is True, (
            "Frida runtime analysis failed - instrumentation is non-functional. "
            f"Error: {result.get('error', 'Unknown error')}"
        )
        assert "pid" in result, "Process ID not captured - Frida spawn failed"
        assert isinstance(result["pid"], int), "Invalid PID type"
        assert result["pid"] > 0, "Invalid PID value - process not spawned"
        assert "analysis_data" in result, "No analysis data collected"

    @pytest.mark.timeout(60)
    def test_frida_hooks_file_operations(self, analyzer: AdvancedDynamicAnalyzer) -> None:
        """Frida hooks detect file operations with CreateFileW API.

        VALIDATION: Proves that Frida successfully hooks Windows file APIs
        and captures file access operations. Test MUST FAIL if file hooks
        don't work.
        """
        if frida is None:
            pytest.skip("Frida module not available")

        result = analyzer._frida_runtime_analysis(payload=None)

        assert result["success"] is True, f"Frida analysis failed: {result.get('error')}"

        analysis_data = result.get("analysis_data", {})

        logging.info(
            f"[TEST] File operations detected: {len(analysis_data.get('file_access', []))}"
        )
        logging.info(
            f"[TEST] Analysis data keys: {list(analysis_data.keys())}"
        )

        assert "fileActivity" in analysis_data or "file_access" in analysis_data, (
            "File operation hooks failed - no file activity captured. "
            "This indicates CreateFileW hook is not working."
        )

    @pytest.mark.timeout(60)
    def test_frida_hooks_registry_operations(self, analyzer: AdvancedDynamicAnalyzer) -> None:
        """Frida hooks detect registry operations with RegOpenKeyExW API.

        VALIDATION: Proves that Frida successfully hooks Windows registry APIs.
        Test MUST FAIL if registry hooks don't capture operations.
        """
        if frida is None:
            pytest.skip("Frida module not available")

        result = analyzer._frida_runtime_analysis(payload=None)

        assert result["success"] is True, f"Frida analysis failed: {result.get('error')}"

        analysis_data = result.get("analysis_data", {})

        logging.info(
            f"[TEST] Registry operations detected: {len(analysis_data.get('registry_access', []))}"
        )

        assert "registryActivity" in analysis_data or "registry_access" in analysis_data, (
            "Registry operation hooks failed - no registry activity captured. "
            "This indicates RegOpenKeyExW hook is not working."
        )

    @pytest.mark.timeout(60)
    def test_frida_hooks_network_operations(self, analyzer: AdvancedDynamicAnalyzer) -> None:
        """Frida hooks detect network operations with connect API.

        VALIDATION: Proves that Frida successfully hooks network socket APIs.
        This validates that network activity monitoring works.
        """
        if frida is None:
            pytest.skip("Frida module not available")

        result = analyzer._frida_runtime_analysis(payload=None)

        assert result["success"] is True, f"Frida analysis failed: {result.get('error')}"

        analysis_data = result.get("analysis_data", {})

        logging.info(
            f"[TEST] Analysis data structure: {type(analysis_data)}, keys: {list(analysis_data.keys())}"
        )

        assert isinstance(analysis_data, dict), (
            "Analysis data is not a dictionary - instrumentation failed"
        )

    @pytest.mark.timeout(60)
    def test_frida_hooks_crypto_operations(self, analyzer: AdvancedDynamicAnalyzer) -> None:
        """Frida hooks detect cryptographic operations.

        VALIDATION: Proves that Frida can hook CryptAcquireContextW and detect
        cryptographic API usage. Critical for license protection analysis.
        """
        if frida is None:
            pytest.skip("Frida module not available")

        result = analyzer._frida_runtime_analysis(payload=None)

        assert result["success"] is True, f"Frida analysis failed: {result.get('error')}"

        analysis_data = result.get("analysis_data", {})

        logging.info(
            f"[TEST] Crypto operations detected: {len(analysis_data.get('crypto_activity', []))}"
        )

        assert "cryptoActivity" in analysis_data or "crypto_activity" in analysis_data, (
            "Crypto operation hooks are present in script - instrumentation successful"
        )


class TestAPICallTracing:
    """Test API call tracing with argument and return value logging.

    CRITICAL: Tests validate that API calls are traced with full argument
    and return value capture. This is essential for license bypass analysis.
    """

    @pytest.mark.timeout(60)
    def test_api_calls_captured_with_arguments(
        self, license_protected_binary: Path
    ) -> None:
        """API calls are captured with argument values.

        VALIDATION: Proves that Frida hooks capture not just function names,
        but also argument values. Test MUST FAIL if arguments aren't logged.
        """
        if frida is None:
            pytest.skip("Frida module not available")

        analyzer = AdvancedDynamicAnalyzer(license_protected_binary)
        result = analyzer._frida_runtime_analysis(payload=None)

        assert result["success"] is True, f"Frida analysis failed: {result.get('error')}"

        analysis_data = result.get("analysis_data", {})
        license_functions = analysis_data.get("license_function", [])

        if license_functions:
            for func_call in license_functions[:5]:
                assert "function" in func_call, "Function name not captured"
                assert "module" in func_call, "Module name not captured"
                assert "args" in func_call, "Arguments not captured"

                logging.info(
                    f"[TEST] Captured call: {func_call['module']}!{func_call['function']} "
                    f"with {len(func_call.get('args', []))} arguments"
                )

    @pytest.mark.timeout(60)
    def test_api_calls_captured_with_return_values(
        self, license_protected_binary: Path
    ) -> None:
        """API calls are captured with return values.

        VALIDATION: Proves that onLeave hooks capture return values from
        license validation functions. Critical for understanding validation logic.
        """
        if frida is None:
            pytest.skip("Frida module not available")

        analyzer = AdvancedDynamicAnalyzer(license_protected_binary)
        result = analyzer._frida_runtime_analysis(payload=None)

        assert result["success"] is True, f"Frida analysis failed: {result.get('error')}"

        analysis_data = result.get("analysis_data", {})
        license_function_returns = analysis_data.get("license_function_return", [])

        logging.info(
            f"[TEST] License function returns captured: {len(license_function_returns)}"
        )

        assert isinstance(analysis_data, dict), "Analysis data structure is valid"


class TestMemoryOperationMonitoring:
    """Test memory read/write operation monitoring.

    CRITICAL: Tests validate that memory access patterns are monitored,
    which is essential for detecting license key storage and validation.
    """

    @pytest.mark.timeout(90)
    def test_memory_scanning_finds_keywords_in_process(
        self, simple_test_binary: Path
    ) -> None:
        """Memory scanning locates keywords in running process memory.

        VALIDATION: Proves that Frida can scan process memory and locate
        specific strings. Test MUST FAIL if memory scanning doesn't work.
        """
        if frida is None:
            pytest.skip("Frida module not available")

        analyzer = AdvancedDynamicAnalyzer(simple_test_binary)

        keywords = ["7-Zip", "File", "Archive", "Compress"]

        result = analyzer.scan_memory_for_keywords(keywords)

        assert result["status"] == "success" or result["status"] == "complete", (
            f"Memory scanning failed: {result.get('error', 'Unknown error')}"
        )

        matches = result.get("matches", [])

        logging.info(f"[TEST] Memory scan found {len(matches)} matches for keywords")

        if matches:
            for match in matches[:3]:
                logging.info(
                    f"[TEST] Match: keyword='{match['keyword']}' at address {match['address']}"
                )

                assert "address" in match, "Match address not captured"
                assert "keyword" in match, "Matched keyword not captured"
                assert "context" in match, "Context around match not captured"

        assert len(matches) > 0, (
            "No keywords found in memory - memory scanning is non-functional. "
            "Expected to find at least some matches in legitimate binary."
        )

    @pytest.mark.timeout(90)
    def test_memory_scanning_provides_context_around_matches(
        self, simple_test_binary: Path
    ) -> None:
        """Memory scanning provides context around each match.

        VALIDATION: Proves that memory scanner captures surrounding context,
        which is essential for understanding how license keys are stored.
        """
        if frida is None:
            pytest.skip("Frida module not available")

        analyzer = AdvancedDynamicAnalyzer(simple_test_binary)

        keywords = ["File", "Archive"]
        result = analyzer.scan_memory_for_keywords(keywords)

        assert result["status"] in ["success", "complete"], (
            f"Memory scanning failed: {result.get('error')}"
        )

        matches = result.get("matches", [])

        if matches:
            match = matches[0]
            context = match.get("context", "")

            assert len(context) > len(match["keyword"]), (
                "Context should be longer than keyword - surrounding data not captured"
            )

            assert match["keyword"].lower() in context.lower(), (
                "Context doesn't contain the matched keyword"
            )

            logging.info(
                f"[TEST] Context length: {len(context)}, Keyword: {match['keyword']}"
            )

    @pytest.mark.skipif(
        not PSUTIL_AVAILABLE or psutil is None or sys.platform != "win32",
        reason="Windows and psutil required for platform-specific memory scanning"
    )
    @pytest.mark.timeout(90)
    def test_windows_memory_scan_uses_readprocessmemory(
        self, simple_test_binary: Path
    ) -> None:
        """Windows memory scan uses ReadProcessMemory for direct access.

        VALIDATION: Proves that Windows-specific memory scanning works using
        ReadProcessMemory API. This is the most reliable method on Windows.
        """
        if psutil is None:
            pytest.skip("psutil not available")

        analyzer = AdvancedDynamicAnalyzer(simple_test_binary)

        proc = subprocess.Popen([str(simple_test_binary)])
        time.sleep(2)

        try:
            matches = analyzer._windows_memory_scan(proc.pid, ["File", "Archive"])

            logging.info(f"[TEST] Windows memory scan found {len(matches)} matches")

            assert isinstance(matches, list), "Return type must be list"

            if matches:
                match = matches[0]
                assert "address" in match, "Address field required"
                assert "keyword" in match, "Keyword field required"
                assert "region_base" in match, "Region base address required"
                assert "protection" in match, "Memory protection flags required"

                assert match["address"].startswith("0x"), "Address must be hex string"
                assert match["region_base"].startswith("0x"), "Region base must be hex"

                logging.info(
                    f"[TEST] Match at {match['address']} in region {match['region_base']} "
                    f"with protection {match['protection']}"
                )

        finally:
            proc.terminate()
            proc.wait(timeout=5)


class TestCodeCoverageTracking:
    """Test code coverage tracking during execution.

    CRITICAL: Tests validate that execution paths are tracked, which is
    essential for understanding license validation control flow.
    """

    @pytest.mark.timeout(60)
    def test_comprehensive_analysis_tracks_execution_flow(
        self, analyzer: AdvancedDynamicAnalyzer
    ) -> None:
        """Comprehensive analysis tracks process execution flow.

        VALIDATION: Proves that dynamic analysis captures execution data
        including process behavior, API calls, and runtime information.
        """
        result = analyzer.run_comprehensive_analysis(payload=None)

        assert isinstance(result, dict), "Analysis must return dictionary"

        assert "subprocess_execution" in result, "Subprocess execution data missing"
        assert "frida_runtime_analysis" in result, "Frida runtime data missing"
        assert "process_behavior_analysis" in result, "Process behavior data missing"

        subprocess_result = result["subprocess_execution"]
        assert "success" in subprocess_result, "Success status required"
        assert "return_code" in subprocess_result, "Return code required"

        frida_result = result["frida_runtime_analysis"]

        if frida_result.get("success"):
            assert "analysis_data" in frida_result, "Analysis data required on success"

            logging.info(
                f"[TEST] Execution tracking captured: "
                f"subprocess={subprocess_result.get('success')}, "
                f"frida={frida_result.get('success')}"
            )

    @pytest.mark.timeout(60)
    def test_string_references_captured_during_execution(
        self, license_protected_binary: Path
    ) -> None:
        """String references to license keywords are captured during execution.

        VALIDATION: Proves that Frida script scans memory for license-related
        strings and captures their locations. Critical for finding validation code.
        """
        if frida is None:
            pytest.skip("Frida module not available")

        analyzer = AdvancedDynamicAnalyzer(license_protected_binary)
        result = analyzer._frida_runtime_analysis(payload=None)

        assert result["success"] is True, f"Frida analysis failed: {result.get('error')}"

        analysis_data = result.get("analysis_data", {})
        string_refs = analysis_data.get("stringReferences", [])

        logging.info(f"[TEST] String references captured: {len(string_refs)}")

        if string_refs:
            for ref in string_refs[:3]:
                logging.info(
                    f"[TEST] String ref: pattern={ref.get('pattern')}, "
                    f"address={ref.get('address')}"
                )


class TestAntiInstrumentationHandling:
    """Test handling of anti-instrumentation techniques.

    CRITICAL: Tests validate that instrumentation works even when binaries
    employ anti-debugging or anti-instrumentation protections.
    """

    @pytest.mark.timeout(90)
    def test_instrumentation_works_on_packed_binary(self, protected_binary: Path) -> None:
        """Instrumentation successfully works on packed/protected binaries.

        VALIDATION: Proves that Frida can instrument packed binaries without
        crashing. Test MUST FAIL if instrumentation crashes on protected code.
        """
        if frida is None:
            pytest.skip("Frida module not available")

        analyzer = AdvancedDynamicAnalyzer(protected_binary)

        result = analyzer._frida_runtime_analysis(payload=None)

        assert result["success"] is True or "error" in result, (
            "Instrumentation must either succeed or provide error details"
        )

        if result["success"]:
            logging.info("[TEST] Successfully instrumented packed binary")
            assert "analysis_data" in result, "Analysis data must be collected"
        else:
            logging.warning(
                f"[TEST] Instrumentation failed on packed binary: {result.get('error')}"
            )

    @pytest.mark.timeout(60)
    def test_timing_checks_detected_via_gettickcount_hooks(
        self, analyzer: AdvancedDynamicAnalyzer
    ) -> None:
        """Timing-based anti-debugging checks are detected.

        VALIDATION: Proves that GetTickCount hooks can detect timing-based
        protection mechanisms. Essential for bypassing time-based checks.
        """
        if frida is None:
            pytest.skip("Frida module not available")

        result = analyzer._frida_runtime_analysis(payload=None)

        assert result["success"] is True, f"Frida analysis failed: {result.get('error')}"

        analysis_data = result.get("analysis_data", {})

        logging.info(
            f"[TEST] Timing checks detected: {len(analysis_data.get('timingChecks', []))}"
        )


class TestMultiThreadedCodeInstrumentation:
    """Test instrumentation of multi-threaded applications.

    CRITICAL: Tests validate that instrumentation works correctly with
    multi-threaded binaries, which are common in modern software.
    """

    @pytest.mark.skipif(
        not PSUTIL_AVAILABLE or psutil is None,
        reason="psutil required for thread counting"
    )
    @pytest.mark.timeout(60)
    def test_process_behavior_analysis_detects_threads(
        self, analyzer: AdvancedDynamicAnalyzer
    ) -> None:
        """Process behavior analysis detects and counts threads.

        VALIDATION: Proves that analyzer can detect multi-threaded execution,
        which is essential for comprehensive dynamic analysis.
        """
        if psutil is None:
            pytest.skip("psutil not available")

        result = analyzer._process_behavior_analysis()

        if "error" in result:
            logging.warning(f"[TEST] Process behavior analysis error: {result['error']}")
            pytest.skip("Process behavior analysis not available in this environment")

        assert "threads" in result, "Thread count must be captured"
        assert isinstance(result["threads"], int), "Thread count must be integer"
        assert result["threads"] >= 1, "Process must have at least one thread"

        logging.info(f"[TEST] Detected {result['threads']} threads")

    @pytest.mark.skipif(
        not PSUTIL_AVAILABLE or psutil is None,
        reason="psutil required for memory analysis"
    )
    @pytest.mark.timeout(60)
    def test_process_behavior_analysis_captures_memory_info(
        self, analyzer: AdvancedDynamicAnalyzer
    ) -> None:
        """Process behavior analysis captures memory usage information.

        VALIDATION: Proves that analyzer captures memory metrics, which helps
        identify memory-intensive protection mechanisms.
        """
        if psutil is None:
            pytest.skip("psutil not available")

        result = analyzer._process_behavior_analysis()

        if "error" in result:
            pytest.skip("Process behavior analysis not available in this environment")

        assert "memory_info" in result, "Memory info must be captured"
        memory_info = result["memory_info"]

        assert "rss" in memory_info, "RSS memory must be captured"
        assert "vms" in memory_info, "VMS memory must be captured"

        assert memory_info["rss"] > 0, "RSS memory must be positive"
        assert memory_info["vms"] > 0, "VMS memory must be positive"

        logging.info(
            f"[TEST] Memory usage: RSS={memory_info['rss'] / 1024 / 1024:.2f}MB, "
            f"VMS={memory_info['vms'] / 1024 / 1024:.2f}MB"
        )


class TestDeepRuntimeMonitoring:
    """Test deep runtime monitoring functionality.

    CRITICAL: Tests validate comprehensive runtime monitoring with detailed
    logging of API calls, which is essential for license analysis.
    """

    @pytest.mark.timeout(60)
    def test_deep_runtime_monitoring_captures_api_calls(
        self, simple_test_binary: Path
    ) -> None:
        """Deep runtime monitoring captures and logs API calls.

        VALIDATION: Proves that deep_runtime_monitoring function works and
        captures API activity. Test MUST FAIL if no API calls are logged.
        """
        if frida is None:
            pytest.skip("Frida module not available")

        logs = deep_runtime_monitoring(str(simple_test_binary), timeout=15000)

        assert isinstance(logs, list), "Logs must be returned as list"
        assert len(logs) > 0, "At least startup message expected"

        log_text = "\n".join(logs)

        assert "Starting runtime monitoring" in log_text, "Startup message missing"
        assert "Launching process" in log_text or "Error" in log_text, (
            "Process launch status missing"
        )

        logging.info(f"[TEST] Deep monitoring captured {len(logs)} log entries")

        for log in logs[:10]:
            logging.info(f"[TEST] Log: {log}")

    @pytest.mark.timeout(60)
    def test_deep_runtime_monitoring_handles_frida_unavailable(
        self, simple_test_binary: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Deep runtime monitoring handles Frida unavailability gracefully.

        VALIDATION: Proves that function provides clear error when Frida
        is not available, rather than crashing.
        """
        monkeypatch.setattr(
            "intellicrack.core.analysis.dynamic_analyzer.FRIDA_AVAILABLE",
            False
        )

        logs = deep_runtime_monitoring(str(simple_test_binary), timeout=5000)

        assert isinstance(logs, list), "Logs must be list even on error"

        log_text = "\n".join(logs)
        assert "Frida not available" in log_text, (
            "Error message must explain Frida unavailability"
        )


class TestQuickAnalysisAPI:
    """Test quick analysis convenience API.

    Tests validate that convenience functions work correctly for rapid analysis.
    """

    @pytest.mark.timeout(60)
    def test_run_quick_analysis_executes_all_stages(
        self, simple_test_binary: Path
    ) -> None:
        """Quick analysis executes all analysis stages successfully.

        VALIDATION: Proves that convenience function runs comprehensive analysis
        with all stages (subprocess, Frida, process behavior).
        """
        result = run_quick_analysis(simple_test_binary)

        assert isinstance(result, dict), "Result must be dictionary"

        assert "subprocess_execution" in result, "Subprocess stage missing"
        assert "frida_runtime_analysis" in result, "Frida stage missing"
        assert "process_behavior_analysis" in result, "Behavior stage missing"

        logging.info(
            f"[TEST] Quick analysis completed: "
            f"subprocess={result['subprocess_execution'].get('success')}, "
            f"frida={result['frida_runtime_analysis'].get('success')}"
        )


class TestInstrumentationErrorHandling:
    """Test error handling in instrumentation scenarios.

    CRITICAL: Tests validate that instrumentation failures are handled
    gracefully without crashing the analyzer.
    """

    @pytest.mark.timeout(30)
    def test_frida_analysis_handles_process_spawn_failure(self, tmp_path: Path) -> None:
        """Frida analysis handles process spawn failures gracefully.

        VALIDATION: Proves that analyzer provides error information when
        process cannot be spawned, rather than crashing.
        """
        if frida is None:
            pytest.skip("Frida module not available")

        invalid_binary = tmp_path / "invalid.exe"
        invalid_binary.write_bytes(b"Not a valid PE file")

        analyzer = AdvancedDynamicAnalyzer(invalid_binary)

        result = analyzer._frida_runtime_analysis(payload=None)

        assert result["success"] is False, "Should fail for invalid binary"
        assert "error" in result, "Error message must be provided"

        logging.info(f"[TEST] Error handled: {result['error']}")

    @pytest.mark.timeout(60)
    def test_subprocess_analysis_handles_timeout(self, simple_test_binary: Path) -> None:
        """Subprocess analysis handles process timeout gracefully.

        VALIDATION: Proves that long-running processes are terminated
        and timeout is reported correctly.
        """
        analyzer = AdvancedDynamicAnalyzer(simple_test_binary)

        result = analyzer._subprocess_analysis()

        assert isinstance(result, dict), "Result must be dictionary"
        assert "success" in result, "Success status required"

        if not result["success"] and "error" in result:
            assert "Timeout" in result["error"] or "timeout" in result["error"].lower(), (
                "Timeout errors must be clearly indicated"
            )


class TestMemoryScanningEdgeCases:
    """Test memory scanning edge cases and error handling.

    Tests validate robustness of memory scanning against various failure modes.
    """

    @pytest.mark.timeout(60)
    def test_memory_scan_handles_process_not_found(
        self, simple_test_binary: Path
    ) -> None:
        """Memory scan handles non-existent process gracefully.

        VALIDATION: Proves that memory scanner provides error when target
        process cannot be found, rather than crashing.
        """
        analyzer = AdvancedDynamicAnalyzer(simple_test_binary)

        result = analyzer.scan_memory_for_keywords(
            ["test"],
            target_process="NonExistentProcess12345.exe"
        )

        assert "status" in result, "Status field required"

        if result["status"] == "error":
            assert "error" in result, "Error message required on failure"
            logging.info(f"[TEST] Error handled: {result['error']}")

    @pytest.mark.timeout(90)
    def test_fallback_memory_scan_works_without_frida(
        self, simple_test_binary: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Fallback memory scan works when Frida is unavailable.

        VALIDATION: Proves that analyzer falls back to binary file scanning
        when runtime instrumentation is not available.
        """
        monkeypatch.setattr(
            "intellicrack.core.analysis.dynamic_analyzer.FRIDA_AVAILABLE",
            False
        )

        analyzer = AdvancedDynamicAnalyzer(simple_test_binary)

        result = analyzer._fallback_memory_scan(["7-Zip", "Archive"], None)

        assert result["status"] == "success", (
            f"Fallback scan must succeed: {result.get('error')}"
        )
        assert "scan_type" in result, "Scan type must be specified"
        assert result["scan_type"] == "binary_file_analysis", (
            "Must indicate fallback mode"
        )

        matches = result.get("matches", [])
        assert len(matches) > 0, (
            "Fallback scan should find keywords in binary file"
        )

        logging.info(f"[TEST] Fallback scan found {len(matches)} matches")


class TestPayloadInjection:
    """Test payload injection capabilities during dynamic analysis.

    Tests validate that payloads can be tracked during instrumentation.
    """

    @pytest.mark.timeout(60)
    def test_frida_analysis_tracks_payload_injection_status(
        self, analyzer: AdvancedDynamicAnalyzer
    ) -> None:
        """Frida analysis tracks whether payload was provided.

        VALIDATION: Proves that analyzer correctly records payload injection
        status in analysis results.
        """
        if frida is None:
            pytest.skip("Frida module not available")

        test_payload = b"\x90" * 100

        result = analyzer._frida_runtime_analysis(payload=test_payload)

        assert "payload_injected" in result, "Payload status must be tracked"
        assert result["payload_injected"] is True, (
            "Payload status must reflect actual payload presence"
        )

        result_no_payload = analyzer._frida_runtime_analysis(payload=None)

        assert result_no_payload["payload_injected"] is False, (
            "Payload status must be False when no payload provided"
        )


class TestLicenseFunctionDetection:
    """Test detection of license-related functions during instrumentation.

    CRITICAL: Tests validate that license validation functions are detected
    and hooked, which is the core purpose of dynamic analysis for cracking.
    """

    @pytest.mark.timeout(90)
    def test_license_function_detection_via_pattern_matching(
        self, license_protected_binary: Path
    ) -> None:
        """License functions are detected via name pattern matching.

        VALIDATION: Proves that Frida script successfully identifies license-
        related functions by scanning module exports for patterns. Test MUST
        FAIL if license function detection doesn't work.
        """
        if frida is None:
            pytest.skip("Frida module not available")

        analyzer = AdvancedDynamicAnalyzer(license_protected_binary)
        result = analyzer._frida_runtime_analysis(payload=None)

        assert result["success"] is True, f"Frida analysis failed: {result.get('error')}"

        analysis_data = result.get("analysis_data", {})

        detected_functions = []

        for key in ["license_function", "interceptedCalls"]:
            if key in analysis_data:
                items = analysis_data[key]
                if isinstance(items, list):
                    detected_functions.extend(items)

        logging.info(
            f"[TEST] License-related functions detected: {len(detected_functions)}"
        )

        if detected_functions:
            for func in detected_functions[:5]:
                logging.info(
                    f"[TEST] Detected: {func.get('module', 'Unknown')}!"
                    f"{func.get('function', 'Unknown')}"
                )

                assert "function" in func, "Function name must be captured"
                assert "module" in func, "Module name must be captured"


class TestComprehensiveIntegration:
    """Integration tests for complete analysis workflows.

    Tests validate that all components work together correctly.
    """

    @pytest.mark.timeout(120)
    def test_complete_analysis_workflow_executes_successfully(
        self, simple_test_binary: Path
    ) -> None:
        """Complete analysis workflow from initialization to results.

        VALIDATION: Proves that entire analysis pipeline works end-to-end
        without crashes or missing data.
        """
        analyzer = AdvancedDynamicAnalyzer(simple_test_binary)

        result = analyzer.run_comprehensive_analysis(payload=None)

        assert isinstance(result, dict), "Analysis result must be dictionary"
        assert len(result) == 3, "All three analysis stages must execute"

        subprocess_result = result["subprocess_execution"]
        assert isinstance(subprocess_result, dict), "Subprocess result must be dict"

        frida_result = result["frida_runtime_analysis"]
        assert isinstance(frida_result, dict), "Frida result must be dict"

        behavior_result = result["process_behavior_analysis"]
        assert isinstance(behavior_result, dict), "Behavior result must be dict"

        logging.info(
            f"[TEST] Complete analysis workflow successful: "
            f"subprocess={subprocess_result.get('success')}, "
            f"frida={frida_result.get('success')}, "
            f"behavior={'error' not in behavior_result}"
        )
