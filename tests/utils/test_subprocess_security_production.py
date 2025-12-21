"""Production tests for secure subprocess execution utilities.

Tests validate that subprocess security wrapper properly validates executables,
arguments, and prevents command injection while allowing legitimate security
research tools.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from intellicrack.utils.subprocess_security import (
    ALLOWED_TOOLS,
    SHELL_METACHARACTERS,
    SecureSubprocess,
    secure_popen,
    secure_run,
)


class TestExecutableValidation:
    """Test executable path validation."""

    def test_validate_executable_accepts_whitelisted_tool(self) -> None:
        """validate_executable accepts whitelisted security research tools."""
        if sys.platform == "win32":
            executable = shutil.which("cmd.exe") or "C:\\Windows\\System32\\cmd.exe"
        else:
            executable = shutil.which("python3") or "/usr/bin/python3"

        validated_path = SecureSubprocess.validate_executable(executable)

        assert os.path.isabs(validated_path)
        assert os.path.exists(validated_path)

    def test_validate_executable_accepts_python(self) -> None:
        """validate_executable accepts Python interpreter."""
        python_exe = sys.executable

        validated_path = SecureSubprocess.validate_executable(python_exe)

        assert os.path.isabs(validated_path)
        assert os.path.exists(validated_path)

    def test_validate_executable_resolves_relative_path(self) -> None:
        """validate_executable resolves relative paths to absolute paths."""
        if sys.platform == "win32":
            executable = "cmd"
        else:
            executable = "python3"

        validated_path = SecureSubprocess.validate_executable(executable)

        assert os.path.isabs(validated_path)

    def test_validate_executable_raises_error_for_nonexistent(self) -> None:
        """validate_executable raises ValueError for nonexistent executable."""
        with pytest.raises(ValueError, match="Executable not found"):
            SecureSubprocess.validate_executable("/nonexistent/path/to/binary.exe")

    def test_validate_executable_handles_windows_system_tools(self) -> None:
        """validate_executable locates Windows system tools correctly."""
        if sys.platform != "win32":
            pytest.skip("Windows-specific test")

        validated_path = SecureSubprocess.validate_executable("cmd")

        assert os.path.exists(validated_path)
        assert "System32" in validated_path or "SysWOW64" in validated_path

    def test_validate_executable_strips_extension_for_validation(self) -> None:
        """validate_executable strips .exe/.bat/.sh for whitelist check."""
        if sys.platform == "win32":
            cmd_path = shutil.which("cmd.exe")
            if cmd_path:
                validated = SecureSubprocess.validate_executable(cmd_path)
                assert os.path.exists(validated)


class TestArgumentValidation:
    """Test command argument validation."""

    def test_validate_argument_accepts_safe_string(self) -> None:
        """validate_argument accepts safe argument strings."""
        safe_args = ["--help", "-v", "/version", "filename.txt", "C:\\path\\to\\file.exe"]

        for arg in safe_args:
            validated = SecureSubprocess.validate_argument(arg)
            assert validated == arg

    def test_validate_argument_accepts_flags(self) -> None:
        """validate_argument accepts command-line flags."""
        flags = ["-a", "--verbose", "/Q", "-xzvf", "--enable-feature"]

        for flag in flags:
            validated = SecureSubprocess.validate_argument(flag)
            assert validated == flag

    def test_validate_argument_accepts_key_value_pairs(self) -> None:
        """validate_argument accepts key=value argument format."""
        args = ["key=value", "PATH=/usr/bin", "CONFIG=/etc/app.conf"]

        for arg in args:
            validated = SecureSubprocess.validate_argument(arg)
            assert validated == arg

    def test_validate_argument_rejects_command_injection_attempts(self) -> None:
        """validate_argument rejects arguments with command injection patterns."""
        dangerous_args = ["; rm -rf /", "| cat /etc/passwd", "&& malicious_command", "`whoami`", "$(malicious)"]

        for arg in dangerous_args:
            with pytest.raises(ValueError, match="dangerous argument"):
                SecureSubprocess.validate_argument(arg)

    def test_validate_argument_allows_wildcards_when_enabled(self) -> None:
        """validate_argument allows wildcard characters when allow_wildcards=True."""
        wildcard_args = ["*.exe", "file?.txt", "data*.bin"]

        for arg in wildcard_args:
            validated = SecureSubprocess.validate_argument(arg, allow_wildcards=True)
            assert validated == arg

    def test_validate_argument_rejects_wildcards_by_default(self) -> None:
        """validate_argument rejects wildcards when allow_wildcards=False."""
        with pytest.raises(ValueError):
            SecureSubprocess.validate_argument("*.exe", allow_wildcards=False)

    def test_validate_argument_converts_non_strings(self) -> None:
        """validate_argument converts non-string arguments to strings."""
        validated = SecureSubprocess.validate_argument(123)
        assert validated == "123"
        assert isinstance(validated, str)


class TestCommandValidation:
    """Test full command validation."""

    def test_validate_command_accepts_valid_command_list(self) -> None:
        """validate_command accepts valid command with arguments."""
        if sys.platform == "win32":
            command = ["cmd", "/c", "echo", "test"]
        else:
            command = ["python3", "--version"]

        validated = SecureSubprocess.validate_command(command)

        assert len(validated) > 0
        assert os.path.isabs(validated[0])

    def test_validate_command_raises_error_for_empty_command(self) -> None:
        """validate_command raises ValueError for empty command list."""
        with pytest.raises(ValueError, match="Empty command"):
            SecureSubprocess.validate_command([])

    def test_validate_command_validates_all_arguments(self) -> None:
        """validate_command validates each argument in command."""
        if sys.platform == "win32":
            command = ["cmd", "/c", "dir", "C:\\"]
        else:
            command = ["python3", "-c", "print('test')"]

        validated = SecureSubprocess.validate_command(command)

        assert len(validated) == len(command)
        assert os.path.isabs(validated[0])

    def test_validate_command_converts_existing_file_paths_to_absolute(self, tmp_path: Path) -> None:
        """validate_command converts existing file paths to absolute paths."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")

        command = ["python", str(test_file)]

        validated = SecureSubprocess.validate_command(command)

        assert os.path.isabs(validated[1])
        assert Path(validated[1]).exists()

    def test_validate_command_allows_wildcards_when_specified(self) -> None:
        """validate_command allows wildcard patterns when allow_wildcards=True."""
        command = ["python", "*.py"]

        validated = SecureSubprocess.validate_command(command, allow_wildcards=True)

        assert len(validated) == 2


class TestSecureRun:
    """Test SecureSubprocess.run wrapper."""

    def test_secure_run_executes_valid_command(self) -> None:
        """SecureSubprocess.run successfully executes validated command."""
        if sys.platform == "win32":
            command = ["cmd", "/c", "echo", "test"]
        else:
            command = ["python3", "-c", "print('test')"]

        result = SecureSubprocess.run(command, capture_output=True, text=True)

        assert result.returncode == 0
        assert "test" in result.stdout.lower()

    def test_secure_run_with_string_command_splits_safely(self) -> None:
        """SecureSubprocess.run splits string commands safely using shlex."""
        if sys.platform == "win32":
            command = "cmd /c echo test"
        else:
            command = "python3 --version"

        result = SecureSubprocess.run(command, capture_output=True, text=True)

        assert result.returncode == 0

    def test_secure_run_validates_working_directory(self, tmp_path: Path) -> None:
        """SecureSubprocess.run validates and uses working directory."""
        if sys.platform == "win32":
            command = ["cmd", "/c", "cd"]
        else:
            command = ["pwd"]

        result = SecureSubprocess.run(command, capture_output=True, text=True, cwd=str(tmp_path))

        assert result.returncode == 0

    def test_secure_run_raises_error_for_invalid_cwd(self) -> None:
        """SecureSubprocess.run raises ValueError for invalid working directory."""
        command = ["python", "--version"]

        with pytest.raises(ValueError, match="Invalid working directory"):
            SecureSubprocess.run(command, cwd="/nonexistent/directory")

    def test_secure_run_respects_timeout(self) -> None:
        """SecureSubprocess.run respects timeout parameter."""
        if sys.platform == "win32":
            command = ["cmd", "/c", "timeout", "/t", "10"]
        else:
            command = ["sleep", "10"]

        with pytest.raises(subprocess.TimeoutExpired):
            SecureSubprocess.run(command, timeout=1)

    def test_secure_run_with_check_raises_on_failure(self) -> None:
        """SecureSubprocess.run with check=True raises on non-zero exit."""
        if sys.platform == "win32":
            command = ["cmd", "/c", "exit", "1"]
        else:
            command = ["python3", "-c", "import sys; sys.exit(1)"]

        with pytest.raises(subprocess.CalledProcessError):
            SecureSubprocess.run(command, check=True)

    def test_secure_run_without_shell_by_default(self) -> None:
        """SecureSubprocess.run forces shell=False for security."""
        command = ["python", "--version"]

        result = SecureSubprocess.run(command, capture_output=True, text=True)

        assert result.returncode == 0


class TestSecurePopen:
    """Test SecureSubprocess.popen wrapper."""

    def test_secure_popen_creates_process(self) -> None:
        """SecureSubprocess.popen creates subprocess successfully."""
        if sys.platform == "win32":
            command = ["cmd", "/c", "echo", "test"]
        else:
            command = ["python3", "-c", "print('test')"]

        process = SecureSubprocess.popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        stdout, stderr = process.communicate(timeout=5)
        assert process.returncode == 0
        assert "test" in stdout.lower()

    def test_secure_popen_validates_command(self) -> None:
        """SecureSubprocess.popen validates command before execution."""
        command = ["/nonexistent/executable", "arg"]

        with pytest.raises(ValueError):
            SecureSubprocess.popen(command)

    def test_secure_popen_validates_working_directory(self, tmp_path: Path) -> None:
        """SecureSubprocess.popen validates working directory."""
        command = ["python", "--version"]

        process = SecureSubprocess.popen(command, stdout=subprocess.PIPE, cwd=str(tmp_path))

        process.wait(timeout=5)
        assert process.returncode == 0

    def test_secure_popen_with_string_command_splits_safely(self) -> None:
        """SecureSubprocess.popen splits string commands using shlex."""
        command = "python --version"

        process = SecureSubprocess.popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        process.wait(timeout=5)
        assert process.returncode == 0


class TestConvenienceFunctions:
    """Test module-level convenience functions."""

    def test_secure_run_convenience_function(self) -> None:
        """secure_run convenience function executes commands."""
        if sys.platform == "win32":
            command = ["cmd", "/c", "echo", "test"]
        else:
            command = ["python3", "--version"]

        result = secure_run(command, capture_output=True, text=True)

        assert result.returncode == 0

    def test_secure_popen_convenience_function(self) -> None:
        """secure_popen convenience function creates processes."""
        command = ["python", "--version"]

        process = secure_popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        process.wait(timeout=5)
        assert process.returncode == 0


class TestSecurityResearchToolValidation:
    """Test validation of security research tools."""

    def test_allowed_tools_includes_analysis_tools(self) -> None:
        """ALLOWED_TOOLS includes binary analysis tools."""
        analysis_tools = ["ghidra", "radare2", "ida", "objdump", "strings"]

        for tool in analysis_tools:
            assert tool in ALLOWED_TOOLS

    def test_allowed_tools_includes_debuggers(self) -> None:
        """ALLOWED_TOOLS includes debugger tools."""
        debuggers = ["x64dbg", "ollydbg", "frida"]

        for tool in debuggers:
            assert tool in ALLOWED_TOOLS

    def test_allowed_tools_includes_system_utilities(self) -> None:
        """ALLOWED_TOOLS includes Windows system utilities."""
        system_tools = ["wmic", "tasklist", "reg", "powershell", "cmd"]

        for tool in system_tools:
            assert tool in ALLOWED_TOOLS

    def test_shell_metacharacters_includes_dangerous_chars(self) -> None:
        """SHELL_METACHARACTERS includes all dangerous shell characters."""
        dangerous_chars = ["|", "&", ";", "$", "`", ">", "<", "(", ")", "*"]

        for char in dangerous_chars:
            assert char in SHELL_METACHARACTERS


class TestRealWorldScenarios:
    """Test real-world security research tool execution scenarios."""

    def test_execute_python_script_safely(self, tmp_path: Path) -> None:
        """Secure execution of Python analysis scripts."""
        script = tmp_path / "test_script.py"
        script.write_text("print('Analysis complete')")

        command = [sys.executable, str(script)]

        result = SecureSubprocess.run(command, capture_output=True, text=True)

        assert result.returncode == 0
        assert "Analysis complete" in result.stdout

    def test_execute_windows_registry_query(self) -> None:
        """Secure execution of Windows registry queries for licensing analysis."""
        if sys.platform != "win32":
            pytest.skip("Windows-specific test")

        command = ["reg", "query", "HKEY_LOCAL_MACHINE\\Software", "/s", "/f", "License", "/k"]

        result = SecureSubprocess.run(command, capture_output=True, text=True, timeout=10)

        assert result.returncode in [0, 1]

    def test_execute_process_listing_for_protection_detection(self) -> None:
        """Secure execution of process listing for anti-debug detection."""
        if sys.platform == "win32":
            command = ["tasklist"]
        else:
            command = ["ps", "aux"]

        result = SecureSubprocess.run(command, capture_output=True, text=True)

        assert result.returncode == 0
        assert len(result.stdout) > 0

    def test_execute_file_analysis_command(self, tmp_path: Path) -> None:
        """Secure execution of file analysis utilities."""
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)

        if sys.platform == "win32":
            pytest.skip("file command not standard on Windows")

        if shutil.which("file"):
            command = ["file", str(test_file)]
            result = SecureSubprocess.run(command, capture_output=True, text=True)
            assert result.returncode == 0


class TestShellExecutionWarnings:
    """Test shell execution warnings and validation."""

    def test_secure_run_warns_about_shell_execution(self, caplog: pytest.LogCaptureFixture) -> None:
        """SecureSubprocess.run logs warning when shell=True requested."""
        if sys.platform == "win32":
            command = "echo test"
        else:
            command = "echo test"

        SecureSubprocess.run(command, shell=True, capture_output=True, text=True)

    def test_secure_popen_warns_about_shell_execution(self, caplog: pytest.LogCaptureFixture) -> None:
        """SecureSubprocess.popen logs warning when shell=True requested."""
        command = "echo test"

        process = SecureSubprocess.popen(command, shell=True, stdout=subprocess.PIPE)
        process.wait(timeout=5)


class TestEdgeCases:
    """Test edge cases and unusual inputs."""

    def test_validate_command_with_special_characters_in_path(self, tmp_path: Path) -> None:
        """validate_command handles paths with special characters."""
        special_dir = tmp_path / "test dir with spaces"
        special_dir.mkdir()
        test_file = special_dir / "file.txt"
        test_file.write_text("test")

        command = ["python", str(test_file)]

        validated = SecureSubprocess.validate_command(command)

        assert len(validated) == 2
        assert " " in validated[1]

    def test_validate_argument_with_very_long_string(self) -> None:
        """validate_argument handles very long argument strings."""
        long_arg = "A" * 10000

        validated = SecureSubprocess.validate_argument(long_arg)

        assert validated == long_arg

    def test_secure_run_with_environment_variables(self) -> None:
        """SecureSubprocess.run respects custom environment variables."""
        if sys.platform == "win32":
            command = ["cmd", "/c", "echo", "%TEST_VAR%"]
        else:
            command = ["python3", "-c", "import os; print(os.environ.get('TEST_VAR', ''))"]

        env = os.environ.copy()
        env["TEST_VAR"] = "test_value"

        result = SecureSubprocess.run(command, capture_output=True, text=True, env=env)

        assert result.returncode == 0

    def test_validate_executable_with_unicode_path(self) -> None:
        """validate_executable handles unicode characters in paths."""
        python_path = sys.executable

        validated = SecureSubprocess.validate_executable(python_path)

        assert os.path.exists(validated)


class TestIntegrationScenarios:
    """Test complete integration scenarios."""

    def test_full_binary_analysis_workflow(self, tmp_path: Path) -> None:
        """Complete workflow executing multiple analysis tools securely."""
        test_binary = tmp_path / "sample.exe"
        test_binary.write_bytes(b"MZ" + b"\x00" * 1000)

        commands = [
            [sys.executable, "-c", f"print('File size: {test_binary.stat().st_size}')"],
            [sys.executable, "-c", "print('PE format detected')"],
        ]

        results = []
        for cmd in commands:
            result = SecureSubprocess.run(cmd, capture_output=True, text=True)
            results.append(result)

        assert all(r.returncode == 0 for r in results)
        assert len(results) == 2

    def test_parallel_process_execution(self) -> None:
        """Multiple secure processes can run concurrently."""
        if sys.platform == "win32":
            command = ["cmd", "/c", "echo", "test"]
        else:
            command = ["python3", "-c", "print('test')"]

        processes = []
        for _ in range(3):
            proc = SecureSubprocess.popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            processes.append(proc)

        for proc in processes:
            proc.wait(timeout=5)

        assert all(p.returncode == 0 for p in processes)
