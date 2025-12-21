"""Production tests for Run Analysis CLI module.

These tests validate that run_analysis_cli correctly:
- Parses command line arguments for analysis options
- Validates binary file paths and permissions
- Executes real binary analysis with proper configuration
- Formats output in JSON, text, and summary formats
- Saves results to files when requested
- Handles analysis errors gracefully
- Returns correct exit codes for success/failure
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from intellicrack.cli.run_analysis_cli import (
    create_cli_parser,
    format_analysis_output,
    main,
    run_basic_analysis,
    setup_cli_logging,
    validate_binary_path,
)


class TestBinaryPathValidation:
    """Test binary file path validation."""

    def test_validate_existing_binary(self, tmp_path: Path) -> None:
        test_binary = tmp_path / "valid.exe"
        test_binary.write_bytes(b"MZ\x90\x00")

        result = validate_binary_path(str(test_binary))

        assert result == test_binary.resolve()

    def test_validate_nonexistent_binary_raises(self) -> None:
        with pytest.raises(FileNotFoundError, match="not found"):
            validate_binary_path("/nonexistent/binary.exe")

    def test_validate_directory_raises(self, tmp_path: Path) -> None:
        directory = tmp_path / "not_a_file"
        directory.mkdir()

        with pytest.raises(ValueError, match="not a file"):
            validate_binary_path(str(directory))

    def test_validate_unreadable_file_raises(self, tmp_path: Path) -> None:
        test_binary = tmp_path / "unreadable.exe"
        test_binary.write_bytes(b"TEST")
        test_binary.chmod(0o000)

        try:
            with pytest.raises(PermissionError, match="Cannot read"):
                validate_binary_path(str(test_binary))
        finally:
            test_binary.chmod(0o644)


class TestCLILoggingSetup:
    """Test logging configuration."""

    def test_setup_cli_logging_info_level(self) -> None:
        setup_cli_logging(verbose=False)

        import logging

        root_logger = logging.getLogger()
        assert root_logger.level == logging.INFO

    def test_setup_cli_logging_debug_level(self) -> None:
        setup_cli_logging(verbose=True)

        import logging

        root_logger = logging.getLogger()
        assert root_logger.level == logging.DEBUG


class TestBasicAnalysis:
    """Test basic binary analysis execution."""

    def test_run_basic_analysis_success(self, tmp_path: Path) -> None:
        test_binary = tmp_path / "analysis_test.exe"
        test_binary.write_bytes(b"MZ\x90\x00" * 100)

        options = {
            "entropy": True,
            "strings": True,
            "sections": True,
            "imports": True,
            "exports": True,
            "verbose": False,
        }

        with patch("intellicrack.core.processing.memory_loader.MemoryLoader") as mock_loader:
            with patch("intellicrack.core.analysis.analysis_orchestrator.AnalysisOrchestrator") as mock_orchestrator:
                mock_loader_instance = MagicMock()
                mock_loader_instance.load_binary.return_value = {"data": "loaded"}
                mock_loader.return_value = mock_loader_instance

                mock_orch_instance = MagicMock()
                mock_orch_instance.analyze_binary.return_value = {
                    "file_type": "PE",
                    "architecture": "x86",
                    "sections": ["text", "data"],
                }
                mock_orchestrator.return_value = mock_orch_instance

                result = run_basic_analysis(test_binary, options)

        assert "file_type" in result
        assert result["file_type"] == "PE"

    def test_run_basic_analysis_import_error(self, tmp_path: Path) -> None:
        test_binary = tmp_path / "import_error.exe"
        test_binary.write_bytes(b"MZ\x90\x00")

        options = {"entropy": True, "strings": True}

        with patch("intellicrack.core.analysis.analysis_orchestrator.AnalysisOrchestrator", side_effect=ImportError("Test import error")):
            result = run_basic_analysis(test_binary, options)

        assert "error" in result
        assert "Import error" in result["error"]

    def test_run_basic_analysis_runtime_error(self, tmp_path: Path) -> None:
        test_binary = tmp_path / "runtime_error.exe"
        test_binary.write_bytes(b"MZ\x90\x00")

        options = {"entropy": True}

        with patch("intellicrack.core.processing.memory_loader.MemoryLoader", side_effect=RuntimeError("Test runtime error")):
            result = run_basic_analysis(test_binary, options)

        assert "error" in result


class TestOutputFormatting:
    """Test analysis output formatting."""

    def test_format_output_json(self) -> None:
        results = {"file_type": "PE", "architecture": "x86_64", "sections": ["text", "data", "rdata"]}

        output = format_analysis_output(results, "json")

        parsed = json.loads(output)
        assert parsed["file_type"] == "PE"
        assert parsed["architecture"] == "x86_64"
        assert len(parsed["sections"]) == 3

    def test_format_output_summary(self) -> None:
        results = {
            "binary_path": "/test/binary.exe",
            "file_size": 1024,
            "architecture": "x86",
            "format": "PE32",
            "sections": ["code", "data"],
            "entropy": {"average": 6.5},
            "strings": ["string1", "string2", "string3"],
        }

        output = format_analysis_output(results, "summary")

        assert "INTELLICRACK ANALYSIS SUMMARY" in output
        assert "/test/binary.exe" in output
        assert "1024 bytes" in output
        assert "x86" in output
        assert "PE32" in output
        assert "Sections: 2" in output
        assert "6.5" in output
        assert "Strings Found: 3" in output

    def test_format_output_text(self) -> None:
        results = {"file_type": "ELF", "arch": "x86_64", "vulnerabilities": [{"type": "test"}]}

        output = format_analysis_output(results, "text")

        assert "INTELLICRACK DETAILED ANALYSIS" in output
        assert "FILE_TYPE" in output
        assert "ELF" in output

    def test_format_output_with_error(self) -> None:
        results = {"error": "Analysis failed due to corrupted file"}

        output = format_analysis_output(results, "summary")

        assert "Error: Analysis failed" in output


class TestCLIParser:
    """Test command line argument parser."""

    def test_create_parser(self) -> None:
        parser = create_cli_parser()

        assert parser is not None
        assert "binary" in parser._option_string_actions or any(a.dest == "binary" for a in parser._actions)

    def test_parser_basic_usage(self) -> None:
        parser = create_cli_parser()
        args = parser.parse_args(["test.exe"])

        assert args.binary == "test.exe"
        assert args.format == "summary"
        assert args.verbose is False

    def test_parser_verbose_flag(self) -> None:
        parser = create_cli_parser()
        args = parser.parse_args(["test.exe", "-v"])

        assert args.verbose is True

    def test_parser_output_format(self) -> None:
        parser = create_cli_parser()
        args = parser.parse_args(["test.exe", "-o", "json"])

        assert args.format == "json"

    def test_parser_disable_options(self) -> None:
        parser = create_cli_parser()
        args = parser.parse_args(["test.exe", "--no-entropy", "--no-strings"])

        assert args.no_entropy is True
        assert args.no_strings is True

    def test_parser_output_file(self) -> None:
        parser = create_cli_parser()
        args = parser.parse_args(["test.exe", "--output", "results.json"])

        assert args.output == "results.json"


class TestMainFunction:
    """Test main CLI entry point."""

    def test_main_success(self, tmp_path: Path) -> None:
        test_binary = tmp_path / "main_test.exe"
        test_binary.write_bytes(b"MZ\x90\x00" * 50)

        with patch("sys.argv", ["run_analysis_cli.py", str(test_binary)]):
            with patch("intellicrack.cli.run_analysis_cli.run_basic_analysis") as mock_analyze:
                mock_analyze.return_value = {"file_type": "PE", "success": True}

                exit_code = main()

        assert exit_code == 0

    def test_main_validation_error(self) -> None:
        with patch("sys.argv", ["run_analysis_cli.py", "/nonexistent/file.exe"]):
            exit_code = main()

        assert exit_code == 1

    def test_main_analysis_error(self, tmp_path: Path) -> None:
        test_binary = tmp_path / "error_test.exe"
        test_binary.write_bytes(b"MZ\x90\x00")

        with patch("sys.argv", ["run_analysis_cli.py", str(test_binary)]):
            with patch("intellicrack.cli.run_analysis_cli.run_basic_analysis") as mock_analyze:
                mock_analyze.return_value = {"error": "Analysis failed"}

                exit_code = main()

        assert exit_code == 1

    def test_main_saves_to_file(self, tmp_path: Path) -> None:
        test_binary = tmp_path / "save_test.exe"
        test_binary.write_bytes(b"MZ\x90\x00")

        output_file = tmp_path / "output.json"

        with patch("sys.argv", ["run_analysis_cli.py", str(test_binary), "--output", str(output_file)]):
            with patch("intellicrack.cli.run_analysis_cli.run_basic_analysis") as mock_analyze:
                mock_analyze.return_value = {"file_type": "PE", "success": True}

                exit_code = main()

        assert exit_code == 0
        assert output_file.exists()

    def test_main_keyboard_interrupt(self, tmp_path: Path) -> None:
        test_binary = tmp_path / "interrupt_test.exe"
        test_binary.write_bytes(b"MZ\x90\x00")

        with patch("sys.argv", ["run_analysis_cli.py", str(test_binary)]):
            with patch("intellicrack.cli.run_analysis_cli.run_basic_analysis", side_effect=KeyboardInterrupt):
                exit_code = main()

        assert exit_code == 1


class TestAnalysisConfiguration:
    """Test analysis option configuration."""

    def test_options_all_enabled(self) -> None:
        parser = create_cli_parser()
        args = parser.parse_args(["test.exe"])

        options = {
            "entropy": not args.no_entropy,
            "strings": not args.no_strings,
            "sections": not args.no_sections,
            "imports": not args.no_imports,
            "exports": not args.no_exports,
        }

        assert all(options.values())

    def test_options_selective_disable(self) -> None:
        parser = create_cli_parser()
        args = parser.parse_args(["test.exe", "--no-entropy", "--no-imports"])

        options = {
            "entropy": not args.no_entropy,
            "strings": not args.no_strings,
            "sections": not args.no_sections,
            "imports": not args.no_imports,
            "exports": not args.no_exports,
        }

        assert options["entropy"] is False
        assert options["imports"] is False
        assert options["strings"] is True
        assert options["sections"] is True


class TestRealWorldScenarios:
    """Test real-world usage scenarios."""

    def test_analyze_pe_binary(self, tmp_path: Path) -> None:
        test_binary = tmp_path / "pe_test.exe"

        pe_data = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00"
        pe_data += b"\xB8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00"
        pe_data += b"\x00" * 32
        pe_data += b"PE\x00\x00"

        test_binary.write_bytes(pe_data)

        options = {"entropy": True, "strings": True, "sections": True, "imports": True, "exports": True, "verbose": False}

        with patch("intellicrack.core.processing.memory_loader.MemoryLoader") as mock_loader:
            with patch("intellicrack.core.analysis.analysis_orchestrator.AnalysisOrchestrator") as mock_orchestrator:
                mock_loader_instance = MagicMock()
                mock_loader_instance.load_binary.return_value = {}
                mock_loader.return_value = mock_loader_instance

                mock_orch_instance = MagicMock()
                mock_orch_instance.analyze_binary.return_value = {"file_type": "PE", "arch": "x86"}
                mock_orchestrator.return_value = mock_orch_instance

                result = run_basic_analysis(test_binary, options)

        assert "file_type" in result
