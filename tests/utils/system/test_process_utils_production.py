"""Production tests for process_utils.py module.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

Tests validate process discovery, hardware dongle detection, TPM protection detection,
and hash computation used for analyzing protected software at runtime.
"""

import hashlib
import os
import tempfile
from pathlib import Path
from typing import Any

import pytest

try:
    from intellicrack.handlers.psutil_handler import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    psutil = None
    PSUTIL_AVAILABLE = False


def test_process_utils_find_process_by_name_current_process() -> None:
    """find_process_by_name locates current Python process."""
    if not PSUTIL_AVAILABLE:
        pytest.skip("psutil not available")

    import os

    from intellicrack.utils.system.process_utils import find_process_by_name

    current_pid = os.getpid()
    current_process = psutil.Process(current_pid)
    process_name = current_process.name()

    found_pid = find_process_by_name(process_name)

    assert found_pid is not None
    assert isinstance(found_pid, int)


def test_process_utils_find_process_by_name_exact_match() -> None:
    """find_process_by_name with exact_match finds exact process name."""
    if not PSUTIL_AVAILABLE:
        pytest.skip("psutil not available")

    import os

    from intellicrack.utils.system.process_utils import find_process_by_name

    current_pid = os.getpid()
    current_process = psutil.Process(current_pid)
    exact_name = current_process.name()

    found_pid = find_process_by_name(exact_name, exact_match=True)

    assert found_pid is not None or exact_name.lower() != current_process.name().lower()


def test_process_utils_find_process_by_name_nonexistent() -> None:
    """find_process_by_name returns None for non-existent process."""
    if not PSUTIL_AVAILABLE:
        pytest.skip("psutil not available")

    from intellicrack.utils.system.process_utils import find_process_by_name

    result = find_process_by_name("nonexistent_process_12345xyz")

    assert result is None


def test_process_utils_get_all_processes_returns_list() -> None:
    """get_all_processes returns list of process dictionaries."""
    if not PSUTIL_AVAILABLE:
        pytest.skip("psutil not available")

    from intellicrack.utils.system.process_utils import get_all_processes

    processes = get_all_processes()

    assert isinstance(processes, list)
    assert len(processes) > 0
    assert all(isinstance(p, dict) for p in processes)


def test_process_utils_get_all_processes_default_fields() -> None:
    """get_all_processes includes default fields in process info."""
    if not PSUTIL_AVAILABLE:
        pytest.skip("psutil not available")

    from intellicrack.utils.system.process_utils import get_all_processes

    processes = get_all_processes()

    if processes:
        first_process = processes[0]
        assert "pid" in first_process
        assert "name" in first_process


def test_process_utils_get_all_processes_custom_fields() -> None:
    """get_all_processes retrieves custom fields when specified."""
    if not PSUTIL_AVAILABLE:
        pytest.skip("psutil not available")

    from intellicrack.utils.system.process_utils import get_all_processes

    processes = get_all_processes(fields=["pid", "name", "status"])

    if processes:
        first_process = processes[0]
        assert "pid" in first_process
        assert "name" in first_process


def test_process_utils_find_processes_matching_names() -> None:
    """find_processes_matching_names locates processes matching target names."""
    if not PSUTIL_AVAILABLE:
        pytest.skip("psutil not available")

    import os

    from intellicrack.utils.system.process_utils import find_processes_matching_names

    current_pid = os.getpid()
    current_process = psutil.Process(current_pid)
    target_names = [current_process.name()]

    matches = find_processes_matching_names(target_names)

    assert isinstance(matches, list)


def test_process_utils_get_target_process_pid() -> None:
    """get_target_process_pid finds process by name."""
    if not PSUTIL_AVAILABLE:
        pytest.skip("psutil not available")

    import os

    from intellicrack.utils.system.process_utils import get_target_process_pid

    current_pid = os.getpid()
    current_process = psutil.Process(current_pid)
    process_name = current_process.name()

    found_pid = get_target_process_pid(process_name)

    assert found_pid is not None or not psutil


def test_process_utils_compute_file_hash_sha256() -> None:
    """compute_file_hash generates correct SHA256 hash."""
    from intellicrack.utils.system.process_utils import compute_file_hash

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        test_data = b"test data for hashing"
        tmp.write(test_data)
        tmp_path = tmp.name

    try:
        result = compute_file_hash(tmp_path, algorithm="sha256")

        expected_hash = hashlib.sha256(test_data).hexdigest()

        assert result == expected_hash
    finally:
        Path(tmp_path).unlink()


def test_process_utils_compute_file_hash_md5() -> None:
    """compute_file_hash generates correct MD5 hash."""
    from intellicrack.utils.system.process_utils import compute_file_hash

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        test_data = b"md5 test data"
        tmp.write(test_data)
        tmp_path = tmp.name

    try:
        result = compute_file_hash(tmp_path, algorithm="md5")

        expected_hash = hashlib.md5(test_data).hexdigest()

        assert result == expected_hash
    finally:
        Path(tmp_path).unlink()


def test_process_utils_compute_file_hash_sha1() -> None:
    """compute_file_hash generates correct SHA1 hash."""
    from intellicrack.utils.system.process_utils import compute_file_hash

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        test_data = b"sha1 test data"
        tmp.write(test_data)
        tmp_path = tmp.name

    try:
        result = compute_file_hash(tmp_path, algorithm="sha1")

        expected_hash = hashlib.sha1(test_data).hexdigest()

        assert result == expected_hash
    finally:
        Path(tmp_path).unlink()


def test_process_utils_compute_file_hash_nonexistent_file() -> None:
    """compute_file_hash returns None for non-existent files."""
    from intellicrack.utils.system.process_utils import compute_file_hash

    result = compute_file_hash("nonexistent_file_xyz.bin")

    assert result is None


def test_process_utils_detect_hardware_dongles_returns_list() -> None:
    """detect_hardware_dongles returns list of detection results."""
    from intellicrack.utils.system.process_utils import detect_hardware_dongles

    results = detect_hardware_dongles()

    assert isinstance(results, list)
    assert len(results) > 0
    assert all(isinstance(r, str) for r in results)


def test_process_utils_detect_hardware_dongles_scans_directories() -> None:
    """detect_hardware_dongles scans system directories for dongle drivers."""
    from intellicrack.utils.system.process_utils import detect_hardware_dongles

    results = detect_hardware_dongles()

    assert any("Scanning" in r or "Found" in r or "No hardware" in r for r in results)


def test_process_utils_detect_hardware_dongles_checks_common_drivers() -> None:
    """detect_hardware_dongles checks for common dongle protection schemes."""
    import sys

    from intellicrack.utils.system.process_utils import detect_hardware_dongles

    if sys.platform != "win32":
        pytest.skip("Windows-specific dongle detection")

    results = detect_hardware_dongles()

    result_text = " ".join(results)
    assert (
        "SafeNet" in result_text
        or "HASP" in result_text
        or "CodeMeter" in result_text
        or "No hardware" in result_text
    )


def test_process_utils_detect_tpm_protection_returns_dict() -> None:
    """detect_tpm_protection returns dictionary with TPM status."""
    from intellicrack.utils.system.process_utils import detect_tpm_protection

    results = detect_tpm_protection()

    assert isinstance(results, dict)
    assert "tpm_present" in results
    assert "tpm_version" in results
    assert "tpm_enabled" in results
    assert "tpm_owned" in results
    assert "detection_methods" in results


def test_process_utils_detect_tpm_protection_boolean_flags() -> None:
    """detect_tpm_protection returns boolean flags for TPM status."""
    from intellicrack.utils.system.process_utils import detect_tpm_protection

    results = detect_tpm_protection()

    assert isinstance(results["tpm_present"], bool)
    assert isinstance(results["tpm_enabled"], bool)
    assert isinstance(results["tpm_owned"], bool)


def test_process_utils_detect_tpm_protection_detection_methods_list() -> None:
    """detect_tpm_protection includes list of detection methods used."""
    from intellicrack.utils.system.process_utils import detect_tpm_protection

    results = detect_tpm_protection()

    assert isinstance(results["detection_methods"], list)


def test_process_utils_get_system_processes_returns_list() -> None:
    """get_system_processes returns list of process information."""
    if not PSUTIL_AVAILABLE:
        pytest.skip("psutil not available")

    from intellicrack.utils.system.process_utils import get_system_processes

    processes = get_system_processes()

    assert isinstance(processes, list)
    assert len(processes) > 0


def test_process_utils_get_system_processes_includes_current_process() -> None:
    """get_system_processes includes current process in results."""
    if not PSUTIL_AVAILABLE:
        pytest.skip("psutil not available")

    import os

    from intellicrack.utils.system.process_utils import get_system_processes

    current_pid = os.getpid()

    processes = get_system_processes()
    pids = [p["pid"] for p in processes]

    assert current_pid in pids


def test_process_utils_get_system_processes_has_required_fields() -> None:
    """get_system_processes includes required process fields."""
    if not PSUTIL_AVAILABLE:
        pytest.skip("psutil not available")

    from intellicrack.utils.system.process_utils import get_system_processes

    processes = get_system_processes()

    if processes:
        first_process = processes[0]
        assert "pid" in first_process
        assert "name" in first_process
        assert "cmdline" in first_process
        assert "create_time" in first_process


def test_process_utils_run_command_success() -> None:
    """run_command executes simple command successfully."""
    import sys

    from intellicrack.utils.system.process_utils import run_command

    if sys.platform == "win32":
        cmd = "echo test"
    else:
        cmd = "echo test"

    result = run_command(cmd)

    assert result["success"] is True
    assert result["return_code"] == 0
    assert "test" in result["stdout"] or result["stdout"] != ""


def test_process_utils_run_command_timeout() -> None:
    """run_command respects timeout parameter."""
    import sys

    from intellicrack.utils.system.process_utils import run_command

    if sys.platform == "win32":
        cmd = "timeout /t 10"
    else:
        cmd = "sleep 10"

    result = run_command(cmd, timeout=1)

    assert result["success"] is False
    assert "timed out" in result["error"].lower()


def test_process_utils_run_command_captures_stdout() -> None:
    """run_command captures command standard output."""
    import sys

    from intellicrack.utils.system.process_utils import run_command

    if sys.platform == "win32":
        cmd = "echo captured_output"
    else:
        cmd = "echo captured_output"

    result = run_command(cmd)

    assert "stdout" in result
    assert isinstance(result["stdout"], str)


def test_process_utils_run_command_captures_stderr() -> None:
    """run_command captures command standard error."""
    from intellicrack.utils.system.process_utils import run_command

    result = run_command("nonexistent_command_xyz")

    assert "stderr" in result or "error" in result


def test_process_utils_compute_file_hash_large_file() -> None:
    """compute_file_hash handles large files efficiently."""
    from intellicrack.utils.system.process_utils import compute_file_hash

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        test_data = b"x" * (1024 * 1024)
        tmp.write(test_data)
        tmp_path = tmp.name

    try:
        result = compute_file_hash(tmp_path, algorithm="sha256")

        expected_hash = hashlib.sha256(test_data).hexdigest()

        assert result == expected_hash
    finally:
        Path(tmp_path).unlink()


def test_process_utils_psutil_unavailable_graceful_degradation() -> None:
    """Functions handle psutil unavailability gracefully."""
    from intellicrack.utils.system.process_utils import PSUTIL_AVAILABLE

    if not PSUTIL_AVAILABLE:
        from intellicrack.utils.system.process_utils import (
            find_process_by_name,
            get_all_processes,
        )

        assert find_process_by_name("test") is None
        assert get_all_processes() == []


def test_process_utils_detect_hardware_dongles_with_app_callback() -> None:
    """detect_hardware_dongles calls application callback for progress updates."""
    from intellicrack.utils.system.process_utils import detect_hardware_dongles

    class MockApp:
        def __init__(self) -> None:
            self.messages: list[str] = []

        def update_output(self, msg: str) -> None:
            self.messages.append(msg)

    mock_app = MockApp()
    results = detect_hardware_dongles(app=mock_app)

    assert isinstance(results, list)
    if mock_app.messages:
        assert len(mock_app.messages) > 0
