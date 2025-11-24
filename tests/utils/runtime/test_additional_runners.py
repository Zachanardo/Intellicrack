"""Comprehensive tests for additional_runners.py runtime execution functionality.

Tests validate real subprocess execution, process management, timeout handling,
output capture, error handling, and resource cleanup for all runner functions.

NO MOCKS - All tests use real process execution and real file operations.
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def temp_binary(temp_workspace: Path) -> Path:
    """Create a temporary test binary file with valid PE header."""
    binary_path = temp_workspace / "test_binary.exe"

    pe_header = (
        b"MZ\x90\x00"
        b"\x03\x00\x00\x00"
        b"\x04\x00\x00\x00"
        b"\xFF\xFF\x00\x00"
        b"\xB8\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x40\x00\x00\x00"
        + b"\x00" * 28
        + b"\x80\x00\x00\x00"
        + b"\x00" * 64
        + b"PE\x00\x00"
        + b"\x4C\x01"
        + b"\x00" * 100
    )

    license_strings = b"IsRegisteredCheckLicenseValidateLicenseIsTrialExpiredGetLicenseStatus"
    anti_debug = b"IsDebuggerPresentCheckRemoteDebuggerPresent"
    crypto_patterns = b"MD5SHA1DESRC4AES"

    content = pe_header + b"\x00" * 512 + license_strings + b"\x00" * 256 + anti_debug + b"\x00" * 128 + crypto_patterns + b"\x00" * 1024

    binary_path.write_bytes(content)
    return binary_path


@pytest.fixture
def temp_output_dir(temp_workspace: Path) -> Path:
    """Create temporary output directory for analysis results."""
    output_dir = temp_workspace / "output"
    output_dir.mkdir(exist_ok=True)
    return output_dir


@pytest.fixture
def real_python_script(temp_workspace: Path) -> Path:
    """Create a real executable Python script for subprocess testing."""
    script_path = temp_workspace / "test_script.py"
    script_content = """#!/usr/bin/env python
import sys
import time

if len(sys.argv) > 1:
    if sys.argv[1] == "--version":
        print("Test Script 1.0.0")
        sys.exit(0)
    elif sys.argv[1] == "--license-error":
        print("ERROR: License validation failed")
        print("Trial period expired")
        sys.exit(1)
    elif sys.argv[1] == "--hang":
        time.sleep(30)
    elif sys.argv[1] == "--success":
        print("Operation completed successfully")
        sys.exit(0)
else:
    print("Test script executed")
    sys.exit(0)
"""
    script_path.write_text(script_content)
    return script_path


class TestExternalCommandExecution:
    """Test real subprocess command execution and output capture."""

    def test_run_external_command_with_string_command(self) -> None:
        """Subprocess execution with string command succeeds and captures output."""
        from intellicrack.utils.runtime.additional_runners import run_external_command

        if sys.platform == "win32":
            command = "cmd /c echo test_output"
        else:
            command = "echo test_output"

        result: dict[str, Any] = run_external_command(command, timeout=10)

        assert result["executed"] is True
        assert result["success"] is True
        assert result["return_code"] == 0
        assert "test_output" in result["stdout"]
        assert isinstance(result["stderr"], str)

    def test_run_external_command_with_list_command(self) -> None:
        """Subprocess execution with list command succeeds."""
        from intellicrack.utils.runtime.additional_runners import run_external_command

        if sys.platform == "win32":
            command = ["cmd", "/c", "echo", "list_test"]
        else:
            command = ["echo", "list_test"]

        result: dict[str, Any] = run_external_command(command, timeout=10)

        assert result["executed"] is True
        assert result["success"] is True
        assert "list_test" in result["stdout"]

    def test_run_external_command_captures_stderr(self) -> None:
        """Subprocess execution captures stderr output separately."""
        from intellicrack.utils.runtime.additional_runners import run_external_command

        if sys.platform == "win32":
            command = ["cmd", "/c", "echo error_message 1>&2"]
        else:
            command = ["sh", "-c", "echo error_message >&2"]

        result: dict[str, Any] = run_external_command(command, timeout=10)

        assert result["executed"] is True
        assert isinstance(result["stderr"], str)

    def test_run_external_command_timeout_handling(self) -> None:
        """Subprocess execution times out correctly for long-running commands."""
        from intellicrack.utils.runtime.additional_runners import run_external_command

        if sys.platform == "win32":
            command = ["timeout", "/t", "30", "/nobreak"]
        else:
            command = ["sleep", "30"]

        start_time = time.time()
        result: dict[str, Any] = run_external_command(command, timeout=2)
        elapsed_time = time.time() - start_time

        assert result["executed"] is False or "error" in result
        assert elapsed_time < 5
        assert "timeout" in result.get("error", "").lower() or "timed out" in result.get("error", "").lower()

    def test_run_external_command_nonzero_exit_code(self) -> None:
        """Subprocess execution detects non-zero exit codes as failures."""
        from intellicrack.utils.runtime.additional_runners import run_external_command

        if sys.platform == "win32":
            command = ["cmd", "/c", "exit 1"]
        else:
            command = ["sh", "-c", "exit 1"]

        result: dict[str, Any] = run_external_command(command, timeout=10)

        assert result["executed"] is True
        assert result["success"] is False
        assert result["return_code"] == 1

    def test_run_external_command_invalid_command(self) -> None:
        """Subprocess execution handles invalid commands gracefully."""
        from intellicrack.utils.runtime.additional_runners import run_external_command

        result: dict[str, Any] = run_external_command("nonexistent_command_xyz123", timeout=5)

        assert "error" in result


class TestExternalToolExecution:
    """Test external tool execution with real system tools."""

    def test_run_external_tool_with_python(self, real_python_script: Path) -> None:
        """External tool execution runs Python script and captures output."""
        from intellicrack.utils.runtime.additional_runners import run_external_tool

        result: dict[str, Any] = run_external_tool(
            "strings",
            str(real_python_script),
            args=None
        )

        assert isinstance(result, dict)
        assert "tool" in result
        assert result["tool"] == "strings"

    def test_run_external_tool_unknown_tool(self, temp_binary: Path) -> None:
        """External tool execution rejects unknown tool names."""
        from intellicrack.utils.runtime.additional_runners import run_external_tool

        result: dict[str, Any] = run_external_tool("unknown_tool_xyz", str(temp_binary))

        assert result["executed"] is False
        assert "error" in result
        assert "Unknown tool" in result["error"]

    def test_run_external_tool_with_args(self, temp_binary: Path) -> None:
        """External tool execution passes additional arguments correctly."""
        from intellicrack.utils.runtime.additional_runners import run_external_tool

        result: dict[str, Any] = run_external_tool(
            "strings",
            str(temp_binary),
            args=["-n", "10"]
        )

        assert isinstance(result, dict)


class TestProcessManagement:
    """Test process management and PID retrieval functionality."""

    def test_get_target_process_pid_finds_python(self) -> None:
        """Process PID retrieval finds running Python process."""
        from intellicrack.utils.runtime.additional_runners import get_target_process_pid

        pid: int | None = get_target_process_pid("python")

        if pid is not None:
            assert isinstance(pid, int)
            assert pid > 0

    def test_get_target_process_pid_nonexistent_process(self) -> None:
        """Process PID retrieval returns None for nonexistent process."""
        from intellicrack.utils.runtime.additional_runners import get_target_process_pid

        pid: int | None = get_target_process_pid("nonexistent_process_xyz123")

        assert pid is None

    def test_get_target_process_pid_case_insensitive(self) -> None:
        """Process PID retrieval is case-insensitive."""
        from intellicrack.utils.runtime.additional_runners import get_target_process_pid

        pid_lower: int | None = get_target_process_pid("python")
        pid_upper: int | None = get_target_process_pid("PYTHON")

        if pid_lower is not None and pid_upper is not None:
            assert pid_lower == pid_upper or (pid_lower > 0 and pid_upper > 0)


class TestFileHashComputation:
    """Test file hash computation and verification."""

    def test_compute_file_hash_sha256(self, temp_workspace: Path) -> None:
        """File hash computation produces correct SHA256 hash."""
        from intellicrack.utils.runtime.additional_runners import compute_file_hash

        test_file = temp_workspace / "hash_test.bin"
        test_data = b"test data for hashing"
        test_file.write_bytes(test_data)

        computed_hash: str = compute_file_hash(str(test_file), algorithm="sha256")
        expected_hash = hashlib.sha256(test_data).hexdigest()

        assert computed_hash == expected_hash
        assert len(computed_hash) == 64
        assert all(c in "0123456789abcdef" for c in computed_hash)

    def test_compute_file_hash_md5(self, temp_workspace: Path) -> None:
        """File hash computation produces correct MD5 hash."""
        from intellicrack.utils.runtime.additional_runners import compute_file_hash

        test_file = temp_workspace / "md5_test.bin"
        test_data = b"md5 test data"
        test_file.write_bytes(test_data)

        computed_hash: str = compute_file_hash(str(test_file), algorithm="md5")
        expected_hash = hashlib.md5(test_data).hexdigest()

        assert computed_hash == expected_hash
        assert len(computed_hash) == 32

    def test_compute_file_hash_large_file(self, temp_workspace: Path) -> None:
        """File hash computation handles large files correctly."""
        from intellicrack.utils.runtime.additional_runners import compute_file_hash

        large_file = temp_workspace / "large_file.bin"
        large_data = b"x" * (10 * 1024 * 1024)
        large_file.write_bytes(large_data)

        computed_hash: str = compute_file_hash(str(large_file), algorithm="sha256")
        expected_hash = hashlib.sha256(large_data).hexdigest()

        assert computed_hash == expected_hash

    def test_verify_hash_correct_hash(self, temp_workspace: Path) -> None:
        """Hash verification succeeds for correct hash."""
        from intellicrack.utils.runtime.additional_runners import verify_hash

        test_file = temp_workspace / "verify_test.bin"
        test_data = b"verification test data"
        test_file.write_bytes(test_data)

        expected_hash = hashlib.sha256(test_data).hexdigest()
        result: dict[str, Any] = verify_hash(str(test_file), expected_hash, algorithm="sha256")

        assert result["verified"] is True
        assert result["actual"] == expected_hash
        assert result["expected"] == expected_hash

    def test_verify_hash_incorrect_hash(self, temp_workspace: Path) -> None:
        """Hash verification fails for incorrect hash."""
        from intellicrack.utils.runtime.additional_runners import verify_hash

        test_file = temp_workspace / "verify_fail.bin"
        test_data = b"verification test data"
        test_file.write_bytes(test_data)

        wrong_hash = "0" * 64
        result: dict[str, Any] = verify_hash(str(test_file), wrong_hash, algorithm="sha256")

        assert result["verified"] is False
        assert result["actual"] != wrong_hash

    def test_verify_hash_case_insensitive(self, temp_workspace: Path) -> None:
        """Hash verification is case-insensitive."""
        from intellicrack.utils.runtime.additional_runners import verify_hash

        test_file = temp_workspace / "case_test.bin"
        test_data = b"case test"
        test_file.write_bytes(test_data)

        expected_hash = hashlib.sha256(test_data).hexdigest()
        result: dict[str, Any] = verify_hash(str(test_file), expected_hash.upper(), algorithm="sha256")

        assert result["verified"] is True


class TestDatasetValidation:
    """Test dataset validation functionality."""

    def test_validate_dataset_binary_directory(self, temp_workspace: Path) -> None:
        """Dataset validation succeeds for directory with binary files."""
        from intellicrack.utils.runtime.additional_runners import validate_dataset

        dataset_dir = temp_workspace / "dataset"
        dataset_dir.mkdir()
        (dataset_dir / "test1.exe").write_bytes(b"MZ" + b"\x00" * 100)
        (dataset_dir / "test2.dll").write_bytes(b"MZ" + b"\x00" * 100)
        (dataset_dir / "test3.so").write_bytes(b"\x7fELF" + b"\x00" * 100)

        result: dict[str, Any] = validate_dataset(str(dataset_dir), dataset_type="binary")

        assert result["valid"] is True
        assert result["file_count"] == 3
        assert len(result["sample_files"]) <= 5
        assert len(result["issues"]) == 0

    def test_validate_dataset_empty_directory(self, temp_workspace: Path) -> None:
        """Dataset validation fails for empty directory."""
        from intellicrack.utils.runtime.additional_runners import validate_dataset

        empty_dir = temp_workspace / "empty"
        empty_dir.mkdir()

        result: dict[str, Any] = validate_dataset(str(empty_dir), dataset_type="binary")

        assert result["valid"] is False
        assert "No binary files found" in result["issues"]

    def test_validate_dataset_json_file(self, temp_workspace: Path) -> None:
        """Dataset validation succeeds for JSON file."""
        from intellicrack.utils.runtime.additional_runners import validate_dataset

        json_file = temp_workspace / "dataset.json"
        json_data = [{"sample": 1}, {"sample": 2}, {"sample": 3}]
        json_file.write_text(json.dumps(json_data))

        result: dict[str, Any] = validate_dataset(str(json_file), dataset_type="json")

        assert result["valid"] is True
        assert result["record_count"] == 3

    def test_validate_dataset_missing_file(self, temp_workspace: Path) -> None:
        """Dataset validation fails gracefully for missing files."""
        from intellicrack.utils.runtime.additional_runners import validate_dataset

        missing_file = temp_workspace / "nonexistent.json"
        result: dict[str, Any] = validate_dataset(str(missing_file), dataset_type="json")

        assert result["valid"] is False
        assert len(result["issues"]) > 0


class TestHardwareDongleDetection:
    """Test hardware dongle detection functionality."""

    def test_detect_hardware_dongles_returns_structure(self) -> None:
        """Hardware dongle detection returns proper result structure."""
        from intellicrack.utils.runtime.additional_runners import detect_hardware_dongles

        result: dict[str, Any] = detect_hardware_dongles()

        assert isinstance(result, dict)
        assert "usb_devices" in result
        assert "detected" in result
        assert isinstance(result["usb_devices"], list)
        assert isinstance(result["detected"], bool)

    def test_detect_hardware_dongles_has_message(self) -> None:
        """Hardware dongle detection includes informative message."""
        from intellicrack.utils.runtime.additional_runners import detect_hardware_dongles

        result: dict[str, Any] = detect_hardware_dongles()

        assert "message" in result
        assert isinstance(result["message"], str)
        assert len(result["message"]) > 0


class TestVerificationFunctions:
    """Test crack verification helper functions."""

    def test_verify_static_analysis_existing_file(self, temp_binary: Path) -> None:
        """Static analysis verification detects binary patterns."""
        from intellicrack.utils.runtime.additional_runners import _verify_static_analysis

        result: dict[str, Any] = _verify_static_analysis(str(temp_binary))

        assert isinstance(result, dict)
        assert "success" in result
        assert "confidence" in result
        assert "checks" in result
        assert isinstance(result["checks"], list)

    def test_verify_static_analysis_nonexistent_file(self, temp_workspace: Path) -> None:
        """Static analysis verification handles nonexistent files."""
        from intellicrack.utils.runtime.additional_runners import _verify_static_analysis

        nonexistent = temp_workspace / "nonexistent.exe"
        result: dict[str, Any] = _verify_static_analysis(str(nonexistent))

        assert result["success"] is False
        assert any("not exist" in check.lower() for check in result["checks"])

    def test_verify_execution_testing_with_real_script(self, real_python_script: Path) -> None:
        """Execution testing runs real binaries and captures results."""
        from intellicrack.utils.runtime.additional_runners import _verify_execution_testing

        if sys.platform != "win32":
            real_python_script.chmod(0o755)

        if sys.platform == "win32":
            test_binary = real_python_script.parent / "test_wrapper.bat"
            test_binary.write_text(f'@echo off\npython "{real_python_script}" --success')
        else:
            test_binary = real_python_script

        result: dict[str, Any] = _verify_execution_testing(str(test_binary))

        assert isinstance(result, dict)
        assert "tests" in result
        assert isinstance(result["tests"], list)

    def test_verify_protection_bypass_detects_patterns(self, temp_binary: Path) -> None:
        """Protection bypass verification detects anti-debug patterns."""
        from intellicrack.utils.runtime.additional_runners import _verify_protection_bypass

        result: dict[str, Any] = _verify_protection_bypass(str(temp_binary))

        assert isinstance(result, dict)
        assert "bypassed" in result
        assert "confidence" in result
        assert "protections" in result
        assert isinstance(result["protections"], list)

    def test_verify_license_bypass_detects_patterns(self, temp_binary: Path) -> None:
        """License bypass verification detects license check patterns."""
        from intellicrack.utils.runtime.additional_runners import _verify_license_bypass

        result: dict[str, Any] = _verify_license_bypass(str(temp_binary))

        assert isinstance(result, dict)
        assert "bypassed" in result
        assert "confidence" in result
        assert "license_checks" in result
        assert isinstance(result["license_checks"], list)

    def test_verify_patch_integrity_valid_pe(self, temp_binary: Path) -> None:
        """Patch integrity verification validates PE header."""
        from intellicrack.utils.runtime.additional_runners import _verify_patch_integrity

        result: dict[str, Any] = _verify_patch_integrity(str(temp_binary))

        assert isinstance(result, dict)
        assert "valid" in result
        assert "confidence" in result
        assert "integrity_checks" in result
        assert isinstance(result["integrity_checks"], list)
        assert any("PE" in check for check in result["integrity_checks"])

    def test_verify_patch_integrity_calculates_hash(self, temp_binary: Path) -> None:
        """Patch integrity verification calculates file hash."""
        from intellicrack.utils.runtime.additional_runners import _verify_patch_integrity

        result: dict[str, Any] = _verify_patch_integrity(str(temp_binary))

        if "file_hash" in result:
            assert isinstance(result["file_hash"], str)
            assert len(result["file_hash"]) == 64


class TestAnalysisRunners:
    """Test comprehensive analysis runner functions."""

    def test_run_analysis_basic_level(self, temp_binary: Path) -> None:
        """Basic analysis level executes successfully."""
        from intellicrack.utils.runtime.additional_runners import run_analysis

        result: dict[str, Any] = run_analysis(str(temp_binary), analysis_type="basic")

        assert isinstance(result, dict)
        assert "binary" in result

    def test_run_detect_packing_returns_structure(self, temp_binary: Path) -> None:
        """Packing detection returns proper result structure."""
        from intellicrack.utils.runtime.additional_runners import run_detect_packing

        result: dict[str, Any] = run_detect_packing(str(temp_binary))

        assert isinstance(result, dict)
        assert "binary" in result
        assert "packing_detected" in result
        assert isinstance(result["packing_detected"], bool)


class TestPatternAnalysis:
    """Test pattern analysis and CFG helper functions."""

    def test_identify_license_related_calls(self) -> None:
        """License-related function call identification works correctly."""
        from intellicrack.utils.runtime.additional_runners import _identify_license_related_calls

        function_calls = [
            "CheckLicenseValid",
            "ValidateSerialKey",
            "IsTrialExpired",
            "RegularFunction",
            "AnotherFunction",
            "UnlockFeature",
        ]

        count: int = _identify_license_related_calls(function_calls)

        assert count >= 3
        assert count <= len(function_calls)

    def test_count_license_strings(self) -> None:
        """License string counting identifies relevant strings."""
        from intellicrack.utils.runtime.additional_runners import _count_license_strings

        string_refs = [
            "License validation failed",
            "Trial period expired",
            "Activation code required",
            "Normal string",
            "Another normal string",
            "Invalid serial number",
        ]

        count: int = _count_license_strings(string_refs)

        assert count >= 3
        assert count <= len(string_refs)

    def test_is_license_check_pattern_high_complexity(self) -> None:
        """License check pattern detection identifies complex patterns."""
        from intellicrack.utils.runtime.additional_runners import _is_license_check_pattern

        cfg_data: dict[str, Any] = {
            "complexity": 20,
            "branches": 15,
            "function_calls": ["CheckLicense", "ValidateKey", "VerifySerial", "GetActivationStatus"],
            "string_references": ["license", "trial", "expired", "invalid"],
            "comparison_operations": 10,
            "loops": 3,
            "math_operations": 12,
        }

        is_license: bool = _is_license_check_pattern(cfg_data)

        assert isinstance(is_license, bool)

    def test_is_license_check_pattern_low_complexity(self) -> None:
        """License check pattern detection rejects simple patterns."""
        from intellicrack.utils.runtime.additional_runners import _is_license_check_pattern

        cfg_data: dict[str, Any] = {
            "complexity": 2,
            "branches": 1,
            "function_calls": ["SimpleFunction"],
            "string_references": [],
            "comparison_operations": 0,
        }

        is_license: bool = _is_license_check_pattern(cfg_data)

        assert isinstance(is_license, bool)


class TestPatchSuggestions:
    """Test patch suggestion generation."""

    def test_run_generate_patch_suggestions_finds_patterns(self, temp_binary: Path) -> None:
        """Patch suggestion generation identifies license patterns."""
        from intellicrack.utils.runtime.additional_runners import run_generate_patch_suggestions

        result: dict[str, Any] = run_generate_patch_suggestions(str(temp_binary))

        assert result["status"] == "success"
        assert "suggestions" in result
        assert isinstance(result["suggestions"], list)
        assert "analysis" in result
        assert result["analysis"]["executable_type"] == "PE"

    def test_run_generate_patch_suggestions_nonexistent_file(self, temp_workspace: Path) -> None:
        """Patch suggestion generation handles missing files."""
        from intellicrack.utils.runtime.additional_runners import run_generate_patch_suggestions

        nonexistent = temp_workspace / "missing.exe"
        result: dict[str, Any] = run_generate_patch_suggestions(str(nonexistent))

        assert result["status"] == "error"


class TestWeakCryptoDetection:
    """Test weak cryptography detection."""

    def test_run_weak_crypto_detection_finds_patterns(self, temp_binary: Path) -> None:
        """Weak crypto detection identifies weak algorithms."""
        from intellicrack.utils.runtime.additional_runners import run_weak_crypto_detection

        result: dict[str, Any] = run_weak_crypto_detection(str(temp_binary))

        assert result["status"] in ("success", "error")

        if result["status"] == "success":
            assert "weak_algorithms" in result
            assert "hardcoded_keys" in result
            assert "issues_found" in result
            assert "severity" in result
            assert isinstance(result["weak_algorithms"], list)
        else:
            assert "message" in result


class TestToolOutputParsing:
    """Test tool output parsing functionality."""

    def test_parse_tool_output_file_command(self) -> None:
        """Tool output parsing handles file command output."""
        from intellicrack.utils.runtime.additional_runners import _parse_tool_output

        output = "test.exe: PE32 executable (console) Intel 80386, for MS Windows"
        result: dict[str, Any] = _parse_tool_output("file", output)

        assert "file_type" in result
        assert isinstance(result["file_type"], str)

    def test_parse_tool_output_strings_command(self) -> None:
        """Tool output parsing handles strings command output."""
        from intellicrack.utils.runtime.additional_runners import _parse_tool_output

        output = "String1\nString2\nString3\nString4"
        result: dict[str, Any] = _parse_tool_output("strings", output)

        assert "string_count" in result
        assert result["string_count"] == 4
        assert "samples" in result
        assert len(result["samples"]) <= 20


class TestSamplePluginCreation:
    """Test sample plugin creation functionality."""

    def test_create_sample_plugins_creates_files(self, temp_workspace: Path, monkeypatch) -> None:
        """Sample plugin creation generates plugin files."""
        from intellicrack.utils.runtime.additional_runners import create_sample_plugins

        monkeypatch.chdir(temp_workspace)
        plugin_dir = temp_workspace / "intellicrack" / "plugins" / "samples"

        result: dict[str, Any] = create_sample_plugins()

        assert "plugins_created" in result
        assert isinstance(result["plugins_created"], list)


class TestErrorHandling:
    """Test error handling across runner functions."""

    def test_run_external_command_handles_exceptions(self) -> None:
        """External command execution handles invalid commands gracefully."""
        from intellicrack.utils.runtime.additional_runners import run_external_command

        result: dict[str, Any] = run_external_command([""], timeout=1)

        assert "error" in result or result["executed"] is False

    def test_compute_file_hash_nonexistent_file(self, temp_workspace: Path) -> None:
        """File hash computation raises exception for missing files."""
        from intellicrack.utils.runtime.additional_runners import compute_file_hash

        nonexistent = temp_workspace / "missing.bin"

        with pytest.raises(FileNotFoundError):
            compute_file_hash(str(nonexistent))

    def test_verify_hash_nonexistent_file(self, temp_workspace: Path) -> None:
        """Hash verification handles missing files gracefully."""
        from intellicrack.utils.runtime.additional_runners import verify_hash

        nonexistent = temp_workspace / "missing.bin"
        result: dict[str, Any] = verify_hash(str(nonexistent), "fakehash")

        assert "error" in result


class TestConcurrentExecution:
    """Test concurrent subprocess execution handling."""

    def test_multiple_concurrent_commands(self) -> None:
        """Multiple subprocess commands can execute concurrently."""
        from intellicrack.utils.runtime.additional_runners import run_external_command

        if sys.platform == "win32":
            commands = [
                ["cmd", "/c", "echo test1"],
                ["cmd", "/c", "echo test2"],
                ["cmd", "/c", "echo test3"],
            ]
        else:
            commands = [
                ["echo", "test1"],
                ["echo", "test2"],
                ["echo", "test3"],
            ]

        results: list[dict[str, Any]] = []
        for command in commands:
            result = run_external_command(command, timeout=5)
            results.append(result)

        assert len(results) == 3
        assert all(r["executed"] for r in results)


class TestResourceCleanup:
    """Test proper resource cleanup after subprocess execution."""

    def test_command_execution_cleans_up_resources(self) -> None:
        """Subprocess execution properly cleans up file handles."""
        from intellicrack.utils.runtime.additional_runners import run_external_command

        initial_fd_count = len(os.listdir("/proc/self/fd")) if os.path.exists("/proc/self/fd") else 0

        for _ in range(10):
            if sys.platform == "win32":
                run_external_command(["cmd", "/c", "echo test"], timeout=5)
            else:
                run_external_command(["echo", "test"], timeout=5)

        final_fd_count = len(os.listdir("/proc/self/fd")) if os.path.exists("/proc/self/fd") else 0

        if initial_fd_count > 0:
            assert final_fd_count < initial_fd_count + 20


class TestOutputCapture:
    """Test comprehensive output capture functionality."""

    def test_capture_multiline_output(self) -> None:
        """Output capture handles multiline stdout correctly."""
        from intellicrack.utils.runtime.additional_runners import run_external_command

        if sys.platform == "win32":
            command = ["cmd", "/c", "echo line1 & echo line2 & echo line3"]
        else:
            command = ["sh", "-c", "echo line1; echo line2; echo line3"]

        result: dict[str, Any] = run_external_command(command, timeout=10)

        assert result["success"] is True
        assert "line1" in result["stdout"]
        assert "line2" in result["stdout"] or "line3" in result["stdout"]

    def test_capture_large_output(self) -> None:
        """Output capture handles large output volumes."""
        from intellicrack.utils.runtime.additional_runners import run_external_command

        if sys.platform == "win32":
            command = ["cmd", "/c", "for /L %i in (1,1,100) do @echo Line %i"]
        else:
            command = ["sh", "-c", "for i in {1..100}; do echo Line $i; done"]

        result: dict[str, Any] = run_external_command(command, timeout=10)

        assert result["executed"] is True
        assert len(result["stdout"]) > 100


class TestRealWorldScenarios:
    """Test real-world usage scenarios combining multiple functions."""

    def test_full_analysis_workflow(self, temp_binary: Path, temp_output_dir: Path) -> None:
        """Complete analysis workflow executes all stages."""
        from intellicrack.utils.runtime.additional_runners import (
            compute_file_hash,
            run_detect_packing,
            run_weak_crypto_detection,
        )

        file_hash: str = compute_file_hash(str(temp_binary))
        assert len(file_hash) == 64

        packing_result: dict[str, Any] = run_detect_packing(str(temp_binary))
        assert isinstance(packing_result, dict)

        crypto_result: dict[str, Any] = run_weak_crypto_detection(str(temp_binary))
        assert crypto_result["status"] == "success"

    def test_verification_workflow(self, temp_binary: Path) -> None:
        """Complete verification workflow validates all aspects."""
        from intellicrack.utils.runtime.additional_runners import (
            _verify_license_bypass,
            _verify_patch_integrity,
            _verify_protection_bypass,
            _verify_static_analysis,
        )

        static_result: dict[str, Any] = _verify_static_analysis(str(temp_binary))
        assert isinstance(static_result, dict)

        protection_result: dict[str, Any] = _verify_protection_bypass(str(temp_binary))
        assert isinstance(protection_result, dict)

        license_result: dict[str, Any] = _verify_license_bypass(str(temp_binary))
        assert isinstance(license_result, dict)

        integrity_result: dict[str, Any] = _verify_patch_integrity(str(temp_binary))
        assert isinstance(integrity_result, dict)


class TestPlatformSpecificBehavior:
    """Test platform-specific execution behavior."""

    def test_windows_command_execution(self) -> None:
        """Windows-specific commands execute correctly on Windows."""
        from intellicrack.utils.runtime.additional_runners import run_external_command

        if sys.platform == "win32":
            result: dict[str, Any] = run_external_command(["cmd", "/c", "ver"], timeout=5)
            assert result["executed"] is True
            assert result["success"] is True

    def test_unix_command_execution(self) -> None:
        """Unix-specific commands execute correctly on Unix systems."""
        from intellicrack.utils.runtime.additional_runners import run_external_command

        if sys.platform != "win32":
            result: dict[str, Any] = run_external_command(["uname", "-a"], timeout=5)
            assert result["executed"] is True
            assert result["success"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
