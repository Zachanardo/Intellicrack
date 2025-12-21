"""Production tests for system utilities.

Tests validate real system operations including process management, system info,
dependency checking, command execution, and privilege checking.

Copyright (C) 2025 Zachary Flint
"""

import gc
import logging
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.utils.system.system_utils import (
    check_admin_privileges,
    check_dependencies,
    get_environment_variable,
    get_home_directory,
    get_process_list,
    get_system_info,
    get_targetprocess_pid,
    get_temp_directory,
    is_admin,
    is_linux,
    is_macos,
    is_windows,
    kill_process,
    optimize_memory_usage,
    run_command,
    set_environment_variable,
)

try:
    from intellicrack.handlers.psutil_handler import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    psutil = None
    PSUTIL_AVAILABLE = False


class TestPlatformDetection:
    """Test platform detection utilities."""

    def test_is_windows(self) -> None:
        """is_windows correctly identifies Windows platform."""
        expected = platform.system().lower() == "windows"
        assert is_windows() == expected

    def test_is_linux(self) -> None:
        """is_linux correctly identifies Linux platform."""
        expected = platform.system().lower() == "linux"
        assert is_linux() == expected

    def test_is_macos(self) -> None:
        """is_macos correctly identifies macOS platform."""
        expected = platform.system().lower() == "darwin"
        assert is_macos() == expected

    def test_exactly_one_platform_true(self) -> None:
        """Exactly one platform detection returns True."""
        platforms = [is_windows(), is_linux(), is_macos()]
        assert sum(platforms) == 1


class TestSystemInformation:
    """Test system information retrieval."""

    def test_get_system_info_structure(self) -> None:
        """get_system_info returns complete system information."""
        info = get_system_info()

        assert isinstance(info, dict)

        required_keys = [
            "platform",
            "platform_release",
            "architecture",
            "python_version",
        ]

        for key in required_keys:
            assert key in info
            assert isinstance(info[key], str)

    def test_get_system_info_platform(self) -> None:
        """System info includes correct platform."""
        info = get_system_info()

        assert info["platform"] == platform.system()
        assert info["architecture"] == platform.machine()

    def test_get_system_info_python(self) -> None:
        """System info includes Python version information."""
        info = get_system_info()

        assert "python_version" in info
        assert sys.version in info["python_version"]

    @pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
    def test_get_system_info_psutil_data(self) -> None:
        """System info includes psutil data when available."""
        info = get_system_info()

        assert "cpu_count" in info or "cpu_count_logical" in info
        assert "memory_total" in info or "memory_available" in info

        if "cpu_count_logical" in info:
            assert isinstance(info["cpu_count_logical"], int)
            assert info["cpu_count_logical"] > 0

        if "memory_total" in info:
            assert isinstance(info["memory_total"], int)
            assert info["memory_total"] > 0


class TestProcessManagement:
    """Test process listing and management."""

    @pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
    def test_get_process_list_structure(self) -> None:
        """get_process_list returns list of process dictionaries."""
        processes = get_process_list()

        assert isinstance(processes, list)
        assert len(processes) > 0

        for proc in processes[:5]:
            assert isinstance(proc, dict)
            assert "pid" in proc or "name" in proc

    @pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
    def test_get_process_list_contains_current(self) -> None:
        """Process list contains current Python process."""
        processes = get_process_list()

        current_pid = os.getpid()

        pids = [p.get("pid") for p in processes if "pid" in p]
        assert current_pid in pids

    @pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
    def test_get_targetprocess_pid_python(self) -> None:
        """Find PID of Python process."""
        python_exe = sys.executable

        if pid := get_targetprocess_pid(python_exe):
            assert isinstance(pid, int)
            assert pid > 0

    @pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
    def test_get_targetprocess_pid_nonexistent(self) -> None:
        """Nonexistent process returns None."""
        pid = get_targetprocess_pid("nonexistent_process_xyz_123.exe")

        assert pid is None

    @pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
    def test_kill_process_nonexistent(self) -> None:
        """Killing nonexistent process returns False."""
        result = kill_process(999999)

        assert result is False


class TestCommandExecution:
    """Test system command execution."""

    def test_run_command_simple(self) -> None:
        """Run simple command successfully."""
        if is_windows():
            result = run_command(["cmd", "/c", "echo", "test"])
        else:
            result = run_command(["echo", "test"])

        assert result.returncode == 0
        assert "test" in result.stdout

    def test_run_command_capture_output(self) -> None:
        """Command output is captured correctly."""
        if is_windows():
            result = run_command(["cmd", "/c", "echo", "captured"], capture_output=True)
        else:
            result = run_command(["echo", "captured"], capture_output=True)

        assert "captured" in result.stdout

    def test_run_command_list_format(self) -> None:
        """Command execution with list format."""
        cmd = ["cmd", "/c", "ver"] if is_windows() else ["uname", "-s"]
        result = run_command(cmd, shell=False)

        assert isinstance(result, subprocess.CompletedProcess)
        assert result.returncode == 0

    def test_run_command_timeout(self) -> None:
        """Command timeout works correctly."""
        cmd = ["cmd", "/c", "timeout", "10"] if is_windows() else ["sleep", "10"]
        with pytest.raises(subprocess.TimeoutExpired):
            run_command(cmd, timeout=1)

    def test_run_command_failed_command(self) -> None:
        """Failed command returns non-zero exit code."""
        if is_windows():
            result = run_command(["cmd", "/c", "exit", "1"])
        else:
            result = run_command(["sh", "-c", "exit 1"])

        assert result.returncode != 0


class TestEnvironmentVariables:
    """Test environment variable operations."""

    def test_get_environment_variable_existing(self) -> None:
        """Get existing environment variable."""
        os.environ["TEST_VAR_EXISTS"] = "test_value"

        result = get_environment_variable("TEST_VAR_EXISTS")

        assert result == "test_value"

    def test_get_environment_variable_nonexistent(self) -> None:
        """Get nonexistent variable returns None."""
        result = get_environment_variable("NONEXISTENT_VAR_XYZ_123")

        assert result is None

    def test_get_environment_variable_with_default(self) -> None:
        """Get variable with default value."""
        result = get_environment_variable("NONEXISTENT_VAR", default="default_value")

        assert result == "default_value"

    def test_set_environment_variable(self) -> None:
        """Set environment variable."""
        var_name = "TEST_SET_VAR"
        var_value = "set_value"

        set_environment_variable(var_name, var_value)

        assert os.environ[var_name] == var_value

    def test_set_and_get_environment_variable(self) -> None:
        """Set and retrieve environment variable."""
        var_name = "TEST_ROUNDTRIP_VAR"
        var_value = "roundtrip_value"

        set_environment_variable(var_name, var_value)
        result = get_environment_variable(var_name)

        assert result == var_value


class TestDirectoryPaths:
    """Test directory path retrieval."""

    def test_get_temp_directory(self) -> None:
        """Get system temporary directory."""
        temp_dir = get_temp_directory()

        assert isinstance(temp_dir, Path)
        assert temp_dir.exists()
        assert temp_dir.is_dir()

        assert str(temp_dir) == tempfile.gettempdir()

    def test_get_home_directory(self) -> None:
        """Get user home directory."""
        home_dir = get_home_directory()

        assert isinstance(home_dir, Path)
        assert home_dir.exists()
        assert home_dir.is_dir()

        assert home_dir == Path.home()


class TestPrivilegeChecking:
    """Test administrator/root privilege checking."""

    def test_check_admin_privileges(self) -> None:
        """check_admin_privileges returns boolean."""
        result = check_admin_privileges()

        assert isinstance(result, bool)

    def test_is_admin_alias(self) -> None:
        """is_admin is alias for check_admin_privileges."""
        result1 = check_admin_privileges()
        result2 = is_admin()

        assert result1 == result2

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific test")
    def test_check_admin_privileges_windows(self) -> None:
        """Windows admin check uses ctypes."""
        result = check_admin_privileges()

        assert isinstance(result, bool)

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix-specific test")
    def test_check_admin_privileges_unix(self) -> None:
        """Unix admin check uses os.geteuid."""
        if hasattr(os, "geteuid"):
            result = check_admin_privileges()

            expected = os.geteuid() == 0
            assert result == expected


class TestDependencyChecking:
    """Test Python dependency checking."""

    def test_check_dependencies_all_available(self) -> None:
        """Check dependencies returns True for installed modules."""
        deps = {
            "sys": "System module",
            "os": "Operating system module",
            "pathlib": "Path handling",
        }

        all_satisfied, results = check_dependencies(deps)

        assert all_satisfied is True
        assert results["sys"] is True
        assert results["os"] is True
        assert results["pathlib"] is True

    def test_check_dependencies_missing(self) -> None:
        """Check dependencies handles missing modules."""
        deps = {
            "nonexistent_module_xyz": "Fake module",
        }

        all_satisfied, results = check_dependencies(deps)

        assert all_satisfied is False
        assert results["nonexistent_module_xyz"] is False

    def test_check_dependencies_mixed(self) -> None:
        """Check dependencies with mix of available and missing."""
        deps = {
            "sys": "System module",
            "nonexistent_fake_module": "Fake module",
        }

        all_satisfied, results = check_dependencies(deps)

        assert all_satisfied is False
        assert results["sys"] is True
        assert results["nonexistent_fake_module"] is False

    def test_check_dependencies_empty(self) -> None:
        """Check dependencies with empty dict."""
        all_satisfied, results = check_dependencies({})

        assert all_satisfied is True
        assert results == {}


class TestMemoryOptimization:
    """Test memory optimization functionality."""

    @pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
    def test_optimize_memory_usage_structure(self) -> None:
        """optimize_memory_usage returns stats dict."""
        stats = optimize_memory_usage()

        assert isinstance(stats, dict)
        assert "before" in stats
        assert "after" in stats
        assert "freed" in stats

    @pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
    def test_optimize_memory_usage_memory_stats(self) -> None:
        """Memory optimization includes before/after stats."""
        if psutil:
            stats = optimize_memory_usage()

            assert "total" in stats["before"]
            assert "available" in stats["before"]
            assert "total" in stats["after"]
            assert "available" in stats["after"]

    def test_optimize_memory_usage_garbage_collection(self) -> None:
        """Memory optimization performs garbage collection."""
        large_list = [list(range(1000)) for _ in range(1000)]

        del large_list

        stats = optimize_memory_usage()

        assert isinstance(stats, dict)

    def test_optimize_memory_usage_cache_clearing(self) -> None:
        """Memory optimization clears Python caches."""
        import re

        _ = re.compile("test.*pattern")
        _ = re.compile("another.*pattern")

        stats = optimize_memory_usage()

        assert isinstance(stats, dict)


class TestRealWorldScenarios:
    """Test real-world usage scenarios."""

    def test_complete_system_info_workflow(self) -> None:
        """Complete system information gathering workflow."""
        info = get_system_info()

        assert info["platform"] in ["Windows", "Linux", "Darwin"]
        assert len(info["python_version"]) > 0
        assert len(info["architecture"]) > 0

    @pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
    def test_process_monitoring_workflow(self) -> None:
        """Complete process monitoring workflow."""
        processes = get_process_list()

        assert len(processes) > 0

        current_pid = os.getpid()
        python_exe = sys.executable

        found_pid = get_targetprocess_pid(python_exe)

        assert found_pid is not None

    def test_command_execution_workflow(self) -> None:
        """Complete command execution workflow."""
        if is_windows():
            cmd = ["cmd", "/c", "echo", "workflow_test"]
        else:
            cmd = ["echo", "workflow_test"]

        result = run_command(cmd, capture_output=True, timeout=5)

        assert result.returncode == 0
        assert "workflow_test" in result.stdout

    def test_environment_management_workflow(self) -> None:
        """Complete environment variable management workflow."""
        var_name = "WORKFLOW_TEST_VAR"
        var_value = "workflow_value"

        set_environment_variable(var_name, var_value)

        retrieved = get_environment_variable(var_name)
        assert retrieved == var_value

        del os.environ[var_name]

        retrieved_after = get_environment_variable(var_name, default="default")
        assert retrieved_after == "default"

    def test_directory_access_workflow(self) -> None:
        """Complete directory access workflow."""
        home = get_home_directory()
        temp = get_temp_directory()

        assert home.exists()
        assert temp.exists()

        test_file = temp / "test_workflow.txt"
        test_file.write_text("test content")

        assert test_file.exists()
        test_file.unlink()

    def test_dependency_validation_workflow(self) -> None:
        """Complete dependency validation workflow."""
        required_deps = {
            "sys": "System module",
            "os": "OS module",
            "pathlib": "Path module",
        }

        all_satisfied, results = check_dependencies(required_deps)

        assert all_satisfied is True

        for module_name, available in results.items():
            assert available is True

    def test_system_capabilities_check(self) -> None:
        """Check complete system capabilities."""
        info = get_system_info()
        is_admin_user = is_admin()
        home = get_home_directory()
        temp = get_temp_directory()

        assert isinstance(info, dict)
        assert isinstance(is_admin_user, bool)
        assert isinstance(home, Path)
        assert isinstance(temp, Path)

        platform_checks = [is_windows(), is_linux(), is_macos()]
        assert sum(platform_checks) == 1


class TestCrossPlatformCompatibility:
    """Test cross-platform compatibility."""

    def test_command_execution_cross_platform(self) -> None:
        """Command execution works on all platforms."""
        if is_windows():
            result = run_command(["cmd", "/c", "echo", "test"])
        else:
            result = run_command(["echo", "test"])

        assert result.returncode == 0

    def test_directory_paths_cross_platform(self) -> None:
        """Directory paths available on all platforms."""
        home = get_home_directory()
        temp = get_temp_directory()

        assert home.exists()
        assert temp.exists()

    def test_environment_variables_cross_platform(self) -> None:
        """Environment variables work on all platforms."""
        test_var = "CROSS_PLATFORM_TEST"
        test_value = "cross_platform_value"

        set_environment_variable(test_var, test_value)
        retrieved = get_environment_variable(test_var)

        assert retrieved == test_value

    @pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
    def test_process_listing_cross_platform(self) -> None:
        """Process listing works on all platforms."""
        processes = get_process_list()

        assert len(processes) > 0
        assert all(isinstance(p, dict) for p in processes)


class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_run_command_invalid_command(self) -> None:
        """Invalid command handled gracefully."""
        with pytest.raises((OSError, FileNotFoundError)):
            run_command(["nonexistent_command_xyz_123"])

    @pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
    def test_kill_process_invalid_pid(self) -> None:
        """Invalid PID handled gracefully."""
        result = kill_process(-1)

        assert result is False

    def test_get_environment_variable_none(self) -> None:
        """Nonexistent environment variable returns None."""
        result = get_environment_variable("DEFINITELY_NONEXISTENT_VAR_123")

        assert result is None

    def test_check_dependencies_import_error(self) -> None:
        """Import errors handled in dependency checking."""
        deps = {"invalid.module.name": "Invalid module"}

        all_satisfied, results = check_dependencies(deps)

        assert all_satisfied is False
        assert results["invalid.module.name"] is False


class TestBackwardCompatibility:
    """Test backward compatibility aliases."""

    @pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
    def test_getprocess_list_alias(self) -> None:
        """getprocess_list alias works correctly."""
        from intellicrack.utils.system.system_utils import getprocess_list

        processes = getprocess_list()

        assert isinstance(processes, list)
        assert len(processes) > 0

    @pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
    def test_killprocess_alias(self) -> None:
        """killprocess alias works correctly."""
        from intellicrack.utils.system.system_utils import killprocess

        result = killprocess(999999)

        assert isinstance(result, bool)

    @pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not available")
    def test_get_target_process_pid_alias(self) -> None:
        """get_target_process_pid alias works correctly."""
        from intellicrack.utils.system.system_utils import get_target_process_pid

        result = get_target_process_pid("nonexistent.exe")

        assert result is None or isinstance(result, int)
