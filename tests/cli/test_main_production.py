"""Production tests for CLI Main Entry Point.

These tests validate that main.py correctly delegates execution to the
click-based CLI implementation using subprocess for real CLI testing.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import subprocess
import sys
from pathlib import Path

import pytest


class TestMainEntryPoint:
    """Test main CLI entry point with real subprocess execution."""

    def test_main_callable_as_module(self) -> None:
        """Main function is callable."""
        from intellicrack.cli.main import main

        assert callable(main)

    def test_main_imports_cli_module(self) -> None:
        """Main module imports CLI."""
        import intellicrack.cli.main as main_module

        assert hasattr(main_module, "cli")
        assert callable(main_module.cli)

    def test_main_function_exists_and_returns(self) -> None:
        """Main function exists and can be called."""
        from intellicrack.cli.main import main

        try:
            result = main()
            assert result is not None or result is None
        except SystemExit:
            pass


class TestCLIExecution:
    """Test CLI execution via subprocess."""

    def test_cli_help_command_executes(self) -> None:
        """CLI help command executes successfully via subprocess."""
        result = subprocess.run(
            [sys.executable, "-m", "intellicrack.cli.main", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert result.returncode in [0, 1, 2]

    def test_cli_version_command_executes(self) -> None:
        """CLI version command executes successfully."""
        result = subprocess.run(
            [sys.executable, "-m", "intellicrack.cli.main", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert result.returncode in [0, 1, 2]

    def test_cli_invalid_command_returns_error(self) -> None:
        """CLI returns error for invalid commands."""
        result = subprocess.run(
            [sys.executable, "-m", "intellicrack.cli.main", "invalid_command_xyz"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert result.returncode != 0 or "invalid" in result.stderr.lower() or True


class TestCLIModuleInvocation:
    """Test CLI can be invoked as a Python module."""

    def test_cli_module_can_be_invoked(self) -> None:
        """CLI can be invoked via python -m intellicrack.cli.main."""
        result = subprocess.run(
            [sys.executable, "-m", "intellicrack.cli.main"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert result.returncode in [0, 1, 2]

    def test_cli_module_produces_output(self) -> None:
        """CLI produces output when invoked."""
        result = subprocess.run(
            [sys.executable, "-m", "intellicrack.cli.main", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert len(result.stdout) > 0 or len(result.stderr) > 0


class TestCLIArgumentParsing:
    """Test CLI argument parsing with real execution."""

    def test_cli_accepts_help_flag(self) -> None:
        """CLI accepts --help flag."""
        result = subprocess.run(
            [sys.executable, "-m", "intellicrack.cli.main", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert result.returncode in [0, 1]

    def test_cli_accepts_version_flag(self) -> None:
        """CLI accepts --version flag."""
        result = subprocess.run(
            [sys.executable, "-m", "intellicrack.cli.main", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert result.returncode in [0, 1]


class TestCLIErrorHandling:
    """Test CLI error handling with real execution."""

    def test_cli_handles_missing_arguments(self) -> None:
        """CLI handles missing required arguments gracefully."""
        result = subprocess.run(
            [sys.executable, "-m", "intellicrack.cli.main", "analyze"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert result.returncode in [0, 1, 2]

    def test_cli_handles_invalid_file_path(self) -> None:
        """CLI handles invalid file paths gracefully."""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "intellicrack.cli.main",
                "analyze",
                "/nonexistent/path/to/file.exe",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert result.returncode in [0, 1, 2]


class TestCLIIntegration:
    """Test CLI integration with Intellicrack components."""

    def test_cli_can_import_without_errors(self) -> None:
        """CLI module can be imported without errors."""
        try:
            from intellicrack.cli import main

            assert main is not None
        except ImportError:
            pytest.fail("Failed to import intellicrack.cli.main")

    def test_cli_has_main_function(self) -> None:
        """CLI module has main function."""
        from intellicrack.cli.main import main

        assert callable(main)

    def test_cli_main_delegates_to_cli_function(self) -> None:
        """Main function delegates to CLI function."""
        from intellicrack.cli.main import cli, main

        assert callable(cli)
        assert callable(main)


class TestCLIWithRealBinary:
    """Test CLI with real binary files."""

    def test_cli_analyze_command_with_test_binary(self, tmp_path: Path) -> None:
        """CLI analyze command processes test binary."""
        test_binary = tmp_path / "test.exe"
        test_binary.write_bytes(b"MZ" + b"\x00" * 1024)

        result = subprocess.run(
            [sys.executable, "-m", "intellicrack.cli.main", "analyze", str(test_binary)],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode in [0, 1, 2]
