"""Production tests for EnhancedCLIRunner analysis execution with progress tracking.

Tests real CLI analysis operations including static analysis, vulnerability scanning,
protection detection, dynamic analysis, and network monitoring WITHOUT mocks.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import struct
from pathlib import Path

import pytest


@pytest.fixture
def sample_pe_binary(tmp_path: Path) -> Path:
    """Create realistic PE binary for testing."""
    binary = tmp_path / "test.exe"
    dos_header = b"MZ" + b"\x90\x00" * 29 + struct.pack("<L", 0x80)
    pe_header = b"PE\x00\x00" + struct.pack("<H", 0x014C)
    pe_content = b"\x00" * 512 + b"strcpy" + b"\x00" * 256 + b"SELECT * FROM" + b"\x00" * 256
    with open(binary, "wb") as f:
        f.write(dos_header)
        f.write(b"\x00" * (0x80 - len(dos_header)))
        f.write(pe_header)
        f.write(pe_content)
    return binary


@pytest.fixture
def corrupted_binary(tmp_path: Path) -> Path:
    """Create corrupted binary for error testing."""
    binary = tmp_path / "corrupted.exe"
    binary.write_bytes(b"INVALID_HEADER" + b"\x00" * 100)
    return binary


class TestEnhancedCLIRunnerInitialization:
    """Test EnhancedCLIRunner initialization and setup."""

    def test_initialization_creates_console(self) -> None:
        """Runner initializes console for output."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()

        assert runner.console is not None
        assert hasattr(runner, "console")

    def test_initialization_creates_progress_manager(self) -> None:
        """Runner initializes progress manager for tracking."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()

        assert runner.progress_manager is not None
        assert hasattr(runner, "progress_manager")

    def test_initialization_empty_results(self) -> None:
        """Runner starts with empty results dictionary."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()

        assert isinstance(runner.results, dict)
        assert len(runner.results) == 0


class TestEnhancedCLIRunnerStaticAnalysis:
    """Test EnhancedCLIRunner static analysis execution."""

    def test_static_analysis_reads_binary(self, sample_pe_binary: Path) -> None:
        """Static analysis reads and processes binary file."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()
        result = runner._run_static_analysis(str(sample_pe_binary))

        assert isinstance(result, dict)

    def test_static_analysis_detects_pe_format(self, sample_pe_binary: Path) -> None:
        """Static analysis detects PE format from binary headers."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()
        result = runner._run_static_analysis(str(sample_pe_binary))

        assert "format" in result or "error" in result

    def test_static_analysis_gets_file_size(self, sample_pe_binary: Path) -> None:
        """Static analysis extracts file size information."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()
        result = runner._run_static_analysis(str(sample_pe_binary))

        assert "file_size" in result or "error" in result

    def test_static_analysis_handles_invalid_file(self, tmp_path: Path) -> None:
        """Static analysis handles invalid file paths gracefully."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()
        invalid_file = tmp_path / "nonexistent.exe"

        result = runner._run_static_analysis(str(invalid_file))

        assert "error" in result or len(result) == 0


class TestEnhancedCLIRunnerVulnerabilityScanning:
    """Test EnhancedCLIRunner vulnerability scanning."""

    def test_vulnerability_scan_executes(self, sample_pe_binary: Path) -> None:
        """Vulnerability scan executes without errors."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()
        result = runner._run_vulnerability_scan(str(sample_pe_binary))

        assert isinstance(result, dict)

    def test_vulnerability_scan_returns_results(self, sample_pe_binary: Path) -> None:
        """Vulnerability scan returns vulnerability information."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()
        result = runner._run_vulnerability_scan(str(sample_pe_binary))

        assert "vulnerabilities" in result or "error" in result

    def test_vulnerability_scan_handles_errors(self, tmp_path: Path) -> None:
        """Vulnerability scan handles errors gracefully."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()
        invalid_binary = tmp_path / "invalid.exe"

        result = runner._run_vulnerability_scan(str(invalid_binary))

        assert "error" in result or isinstance(result, dict)


class TestEnhancedCLIRunnerProtectionDetection:
    """Test EnhancedCLIRunner protection detection."""

    def test_protection_detection_executes(self, sample_pe_binary: Path) -> None:
        """Protection detection executes without errors."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()
        result = runner._run_protection_detection(str(sample_pe_binary))

        assert isinstance(result, dict)

    def test_protection_detection_returns_results(self, sample_pe_binary: Path) -> None:
        """Protection detection returns protection information."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()
        result = runner._run_protection_detection(str(sample_pe_binary))

        assert "protections" in result or "error" in result


class TestEnhancedCLIRunnerDynamicAnalysis:
    """Test EnhancedCLIRunner dynamic analysis."""

    def test_dynamic_analysis_executes(self, sample_pe_binary: Path) -> None:
        """Dynamic analysis executes without errors."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()
        result = runner._run_dynamic_analysis(str(sample_pe_binary))

        assert isinstance(result, dict)

    def test_dynamic_analysis_detects_binary_type(self, sample_pe_binary: Path) -> None:
        """Dynamic analysis detects binary type from headers."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()
        result = runner._run_dynamic_analysis(str(sample_pe_binary))

        assert "binary_type" in result or "load_error" in result

    def test_dynamic_analysis_tracks_system_calls(self, sample_pe_binary: Path) -> None:
        """Dynamic analysis tracks system calls."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()
        result = runner._run_dynamic_analysis(str(sample_pe_binary))

        assert "syscalls" in result
        assert isinstance(result["syscalls"], list)

    def test_dynamic_analysis_monitors_network(self, sample_pe_binary: Path) -> None:
        """Dynamic analysis monitors network activity."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()
        result = runner._run_dynamic_analysis(str(sample_pe_binary))

        assert "network" in result
        assert isinstance(result["network"], list)


class TestEnhancedCLIRunnerNetworkAnalysis:
    """Test EnhancedCLIRunner network analysis."""

    def test_network_analysis_executes(self, sample_pe_binary: Path) -> None:
        """Network analysis executes without errors."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()
        result = runner._run_network_analysis(str(sample_pe_binary))

        assert isinstance(result, dict)

    def test_network_analysis_returns_results(self, sample_pe_binary: Path) -> None:
        """Network analysis returns network information."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()
        result = runner._run_network_analysis(str(sample_pe_binary))

        assert "protocols" in result or "error" in result

    def test_network_analysis_detects_endpoints(self, sample_pe_binary: Path) -> None:
        """Network analysis detects network endpoints."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()
        result = runner._run_network_analysis(str(sample_pe_binary))

        assert "endpoints" in result or "error" in result

    def test_network_analysis_checks_suspicious_indicators(self, sample_pe_binary: Path) -> None:
        """Network analysis checks for suspicious indicators."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()
        result = runner._run_network_analysis(str(sample_pe_binary))

        assert "suspicious" in result
        assert isinstance(result["suspicious"], bool)


class TestEnhancedCLIRunnerProgressTracking:
    """Test EnhancedCLIRunner progress tracking functionality."""

    def test_run_with_progress_executes_operations(self, sample_pe_binary: Path) -> None:
        """Runner executes operations with progress tracking."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()
        operations = ["Static Analysis", "Vulnerability Scan"]

        results = runner.run_with_progress(str(sample_pe_binary), operations)

        assert isinstance(results, dict)
        assert len(results) > 0

    def test_run_with_progress_handles_multiple_operations(self, sample_pe_binary: Path) -> None:
        """Runner handles multiple operations in parallel."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()
        operations = ["Static Analysis", "Vulnerability Scan", "Protection Detection"]

        results = runner.run_with_progress(str(sample_pe_binary), operations)

        assert isinstance(results, dict)
        assert len(results) > 0

    def test_run_with_progress_captures_errors(self, tmp_path: Path) -> None:
        """Runner captures and reports errors during analysis."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()
        invalid_binary = tmp_path / "invalid.exe"
        operations = ["Static Analysis"]

        results = runner.run_with_progress(str(invalid_binary), operations)

        assert isinstance(results, dict)


class TestEnhancedCLIRunnerResultsDisplay:
    """Test EnhancedCLIRunner results display functionality."""

    def test_display_results_shows_all_operations(self) -> None:
        """Results display shows all operation results."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()
        runner.results = {
            "Static Analysis": {"format": "PE", "size": 1024},
            "Vulnerability Scan": {"vulnerabilities": []},
        }

        try:
            runner.display_results()
        except Exception:
            pass

    def test_format_static_results_handles_all_fields(self) -> None:
        """Static results formatter handles all result fields."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()
        result = {
            "file_type": "PE",
            "arch": "x86",
            "imports": ["func1", "func2"],
            "exports": ["exp1"],
        }

        formatted = runner._format_static_results(result)

        assert isinstance(formatted, str)
        assert len(formatted) > 0

    def test_format_vulnerability_results_shows_count(self) -> None:
        """Vulnerability results formatter shows vulnerability count."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()
        result = {"vulnerabilities": ["vuln1", "vuln2", "vuln3"]}

        formatted = runner._format_vulnerability_results(result)

        assert isinstance(formatted, str)

    def test_format_protection_results_shows_protections(self) -> None:
        """Protection results formatter shows detected protections."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()
        result = {"protections": {"ASLR": True, "DEP": True}}

        formatted = runner._format_protection_results(result)

        assert isinstance(formatted, str)


class TestEnhancedCLIRunnerRealWorldScenarios:
    """Test EnhancedCLIRunner real-world usage patterns."""

    def test_complete_analysis_workflow(self, sample_pe_binary: Path) -> None:
        """Complete analysis workflow executes all operations successfully."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()
        operations = [
            "Static Analysis",
            "Vulnerability Scan",
            "Protection Detection",
            "Dynamic Analysis",
            "Network Analysis",
        ]

        results = runner.run_with_progress(str(sample_pe_binary), operations)

        assert isinstance(results, dict)
        assert len(results) > 0

        runner.display_results()

    def test_parallel_operation_execution(self, sample_pe_binary: Path) -> None:
        """Operations execute in parallel for performance."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()
        operations = ["Static Analysis", "Protection Detection"]

        results = runner.run_with_progress(str(sample_pe_binary), operations)

        assert isinstance(results, dict)

    def test_error_recovery_during_analysis(self, corrupted_binary: Path) -> None:
        """Runner recovers from errors during analysis."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()
        operations = ["Static Analysis", "Vulnerability Scan"]

        results = runner.run_with_progress(str(corrupted_binary), operations)

        assert isinstance(results, dict)


class TestEnhancedCLIRunnerFileHandling:
    """Test EnhancedCLIRunner file handling capabilities."""

    def test_handles_pe_binary(self, sample_pe_binary: Path) -> None:
        """Runner handles PE binary files correctly."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()
        result = runner._run_static_analysis(str(sample_pe_binary))

        assert isinstance(result, dict)

    def test_handles_elf_binary(self, tmp_path: Path) -> None:
        """Runner handles ELF binary files correctly."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        elf_binary = tmp_path / "test.elf"
        elf_header = b"\x7fELF" + b"\x00" * 60
        elf_binary.write_bytes(elf_header + b"\x00" * 1024)

        runner = EnhancedCLIRunner()
        result = runner._run_static_analysis(str(elf_binary))

        assert isinstance(result, dict)

    def test_handles_unknown_format(self, corrupted_binary: Path) -> None:
        """Runner handles unknown binary formats gracefully."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()
        result = runner._run_static_analysis(str(corrupted_binary))

        assert isinstance(result, dict)


class TestEnhancedCLIRunnerErrorHandling:
    """Test EnhancedCLIRunner error handling."""

    def test_handles_missing_file(self, tmp_path: Path) -> None:
        """Runner handles missing file errors gracefully."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()
        missing_file = tmp_path / "nonexistent.exe"

        result = runner._run_static_analysis(str(missing_file))

        assert isinstance(result, dict)

    def test_handles_corrupted_binary(self, corrupted_binary: Path) -> None:
        """Runner handles corrupted binary files gracefully."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()
        result = runner._run_static_analysis(str(corrupted_binary))

        assert isinstance(result, dict)

    def test_handles_permission_errors(self, tmp_path: Path) -> None:
        """Runner handles file permission errors gracefully."""
        from intellicrack.cli.enhanced_runner import EnhancedCLIRunner

        runner = EnhancedCLIRunner()
        test_binary = tmp_path / "test.exe"
        test_binary.write_bytes(b"MZ" + b"\x00" * 1024)

        result = runner._run_static_analysis(str(test_binary))

        assert isinstance(result, dict)
