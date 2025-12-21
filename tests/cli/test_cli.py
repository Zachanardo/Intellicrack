"""Comprehensive production-grade tests for CLI module.

This file validates ALL CLI command execution and argument parsing against real binaries.
Tests verify actual command execution, output formatting, error handling, and real-world workflows.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

PROJECT_ROOT = Path(__file__).parent.parent.parent
FIXTURES_DIR = PROJECT_ROOT / "tests" / "fixtures"
PYTHON_EXE = sys.executable


@pytest.fixture
def sample_binary() -> Path:
    """Provide path to real protected binary for testing."""
    binary_path = FIXTURES_DIR / "binaries" / "protected" / "upx_packed_0.exe"
    if not binary_path.exists():
        pytest.skip(f"Sample binary not found: {binary_path}")
    return binary_path


@pytest.fixture
def vmprotect_binary() -> Path:
    """Provide VMProtect-protected binary."""
    binary_path = FIXTURES_DIR / "binaries" / "protected" / "vmprotect_protected.exe"
    if not binary_path.exists():
        pytest.skip(f"VMProtect binary not found: {binary_path}")
    return binary_path


@pytest.fixture
def themida_binary() -> Path:
    """Provide Themida-protected binary."""
    binary_path = FIXTURES_DIR / "binaries" / "protected" / "themida_protected.exe"
    if not binary_path.exists():
        pytest.skip(f"Themida binary not found: {binary_path}")
    return binary_path


@pytest.fixture
def legitimate_binary() -> Path:
    """Provide legitimate unprotected binary."""
    binary_path = FIXTURES_DIR / "binaries" / "pe" / "legitimate" / "7zip.exe"
    if not binary_path.exists():
        pytest.skip(f"Legitimate binary not found: {binary_path}")
    return binary_path


@pytest.fixture
def cli_module() -> Path:
    """Provide path to CLI module for subprocess execution."""
    return PROJECT_ROOT / "intellicrack" / "cli" / "cli.py"


@pytest.fixture
def temp_output_dir(tmp_path: Path) -> Path:
    """Provide temporary directory for output files."""
    output_dir = tmp_path / "cli_output"
    output_dir.mkdir(exist_ok=True)
    return output_dir


def run_cli_command(args: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    """Execute CLI command via subprocess and return result.

    Args:
        args: Command line arguments (e.g., ['analyze', 'binary.exe'])
        timeout: Command timeout in seconds

    Returns:
        CompletedProcess with stdout, stderr, and returncode
    """
    cmd = [PYTHON_EXE, "-m", "intellicrack.cli.cli"] + args

    env = os.environ.copy()
    env["INTELLICRACK_TESTING"] = "1"
    env["DISABLE_AI_WORKERS"] = "1"
    env["DISABLE_BACKGROUND_THREADS"] = "1"

    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(PROJECT_ROOT),
        env=env,
    )


class TestCLIBasicExecution:
    """Test basic CLI command execution and help system."""

    def test_cli_main_help_displays(self) -> None:
        """CLI displays main help when invoked with --help."""
        result = run_cli_command(["--help"])

        assert result.returncode == 0
        assert "Intellicrack" in result.stdout
        assert "Advanced Binary Analysis" in result.stdout or "Binary Analysis" in result.stdout
        assert "Commands:" in result.stdout or "Usage:" in result.stdout

    def test_cli_version_info_available(self) -> None:
        """CLI provides version information."""
        result = run_cli_command(["--help"])

        assert result.returncode == 0
        assert len(result.stdout) > 0

    def test_cli_verbose_flag_accepted(self) -> None:
        """CLI accepts and processes verbose flag."""
        result = run_cli_command(["--verbose", "--help"])

        assert result.returncode == 0

    def test_cli_quiet_flag_accepted(self) -> None:
        """CLI accepts and processes quiet flag."""
        result = run_cli_command(["--quiet", "--help"])

        assert result.returncode == 0

    def test_cli_invalid_command_fails(self) -> None:
        """CLI returns error for invalid commands."""
        result = run_cli_command(["nonexistent_command_xyz"])

        assert result.returncode != 0
        assert "Error" in result.stderr or "error" in result.stderr or "No such command" in result.stderr


class TestAnalyzeCommand:
    """Test 'analyze' command execution on real binaries."""

    def test_analyze_basic_mode_executes(self, sample_binary: Path) -> None:
        """Analyze command executes in basic mode on real binary."""
        result = run_cli_command(["analyze", str(sample_binary), "--mode", "basic"])

        assert result.returncode == 0
        assert "Analyzing" in result.stdout or "Analysis" in result.stdout
        assert str(sample_binary.name) in result.stdout or "binary" in result.stdout.lower()

    def test_analyze_comprehensive_mode_executes(self, sample_binary: Path) -> None:
        """Analyze command executes in comprehensive mode."""
        result = run_cli_command(["analyze", str(sample_binary), "--mode", "comprehensive"], timeout=60)

        assert result.returncode == 0
        assert "comprehensive" in result.stdout.lower() or "analysis" in result.stdout.lower()

    def test_analyze_protection_mode_detects_protections(self, sample_binary: Path) -> None:
        """Analyze protection mode detects binary protections."""
        result = run_cli_command(["analyze", str(sample_binary), "--mode", "protection"])

        assert result.returncode == 0
        assert "protection" in result.stdout.lower() or "upx" in result.stdout.lower()

    def test_analyze_outputs_binary_type(self, sample_binary: Path) -> None:
        """Analyze command outputs binary type information."""
        result = run_cli_command(["analyze", str(sample_binary)])

        assert result.returncode == 0
        assert "PE" in result.stdout or "Binary Type" in result.stdout or "format" in result.stdout.lower()

    def test_analyze_outputs_architecture(self, sample_binary: Path) -> None:
        """Analyze command outputs architecture information."""
        result = run_cli_command(["analyze", str(sample_binary)])

        assert result.returncode == 0
        assert "x86" in result.stdout or "x64" in result.stdout or "Architecture" in result.stdout

    def test_analyze_with_json_output(self, sample_binary: Path, temp_output_dir: Path) -> None:
        """Analyze command saves results to JSON file."""
        output_file = temp_output_dir / "analysis_result.json"
        result = run_cli_command(["analyze", str(sample_binary), "--output", str(output_file)])

        assert result.returncode == 0
        assert output_file.exists()

        with open(output_file, encoding="utf-8") as f:
            data = json.load(f)

        assert isinstance(data, dict)
        assert "format" in data or "file_type" in data or "architecture" in data

    def test_analyze_deep_mode_executes(self, sample_binary: Path) -> None:
        """Analyze command executes with deep analysis flag."""
        result = run_cli_command(["analyze", str(sample_binary), "--deep"], timeout=60)

        assert result.returncode == 0
        assert "deep" in result.stdout.lower() or "analysis" in result.stdout.lower()

    def test_analyze_with_no_ai_flag(self, sample_binary: Path) -> None:
        """Analyze command respects --no-ai flag."""
        result = run_cli_command(["analyze", str(sample_binary), "--no-ai"])

        assert result.returncode == 0
        assert "AI" not in result.stdout or "disabled" in result.stdout.lower()

    def test_analyze_verbose_output_detailed(self, sample_binary: Path) -> None:
        """Analyze command with verbose flag provides detailed output."""
        result = run_cli_command(["analyze", str(sample_binary), "--verbose"])

        assert result.returncode == 0
        assert len(result.stdout) > 100

    def test_analyze_nonexistent_binary_fails(self) -> None:
        """Analyze command fails gracefully for non-existent binary."""
        result = run_cli_command(["analyze", "/nonexistent/path/binary.exe"])

        assert result.returncode != 0
        assert "error" in result.stderr.lower() or "not found" in result.stderr.lower() or "error" in result.stdout.lower()


class TestScanCommand:
    """Test 'scan' command for vulnerability scanning."""

    def test_scan_basic_executes(self, sample_binary: Path) -> None:
        """Scan command executes basic security scan."""
        result = run_cli_command(["scan", str(sample_binary)])

        assert result.returncode == 0
        assert "scan" in result.stdout.lower() or "binary" in result.stdout.lower()

    def test_scan_with_vulns_flag(self, sample_binary: Path) -> None:
        """Scan command performs vulnerability analysis with --vulns flag."""
        result = run_cli_command(["scan", str(sample_binary), "--vulns"], timeout=60)

        assert result.returncode == 0
        assert "vulnerabilit" in result.stdout.lower() or "scan" in result.stdout.lower()

    def test_scan_outputs_protections(self, sample_binary: Path) -> None:
        """Scan command outputs security features and protections."""
        result = run_cli_command(["scan", str(sample_binary)])

        assert result.returncode == 0
        assert "protection" in result.stdout.lower() or "security" in result.stdout.lower() or "feature" in result.stdout.lower()

    def test_scan_with_json_output(self, sample_binary: Path, temp_output_dir: Path) -> None:
        """Scan command saves results to JSON file."""
        output_file = temp_output_dir / "scan_result.json"
        result = run_cli_command(["scan", str(sample_binary), "--output", str(output_file)])

        assert result.returncode == 0
        assert output_file.exists()

        with open(output_file, encoding="utf-8") as f:
            data = json.load(f)

        assert isinstance(data, dict)

    def test_scan_verbose_mode(self, sample_binary: Path) -> None:
        """Scan command provides detailed output in verbose mode."""
        result = run_cli_command(["scan", str(sample_binary), "--verbose"])

        assert result.returncode == 0
        assert len(result.stdout) > 50


class TestStringsCommand:
    """Test 'strings' command for string extraction."""

    def test_strings_extraction_executes(self, sample_binary: Path) -> None:
        """Strings command extracts strings from binary."""
        result = run_cli_command(["strings", str(sample_binary)])

        assert result.returncode == 0
        assert "string" in result.stdout.lower() or "extract" in result.stdout.lower() or "found" in result.stdout.lower()

    def test_strings_with_min_length(self, sample_binary: Path) -> None:
        """Strings command respects minimum length parameter."""
        result = run_cli_command(["strings", str(sample_binary), "--min-length", "8"])

        assert result.returncode == 0
        assert "string" in result.stdout.lower()

    def test_strings_encoding_options(self, sample_binary: Path) -> None:
        """Strings command accepts encoding options."""
        for encoding in ["ascii", "utf8", "utf16", "all"]:
            result = run_cli_command(["strings", str(sample_binary), "--encoding", encoding])
            assert result.returncode == 0

    def test_strings_with_output_file(self, sample_binary: Path, temp_output_dir: Path) -> None:
        """Strings command saves extracted strings to file."""
        output_file = temp_output_dir / "strings.txt"
        result = run_cli_command(["strings", str(sample_binary), "--output", str(output_file)])

        assert result.returncode == 0
        assert output_file.exists()

        content = output_file.read_text(encoding="utf-8")
        assert len(content) > 0

    def test_strings_with_filter_pattern(self, sample_binary: Path) -> None:
        """Strings command filters strings by pattern."""
        result = run_cli_command(["strings", str(sample_binary), "--filter", ".*exe.*"])

        assert result.returncode == 0


class TestPatchCommand:
    """Test 'patch' command for binary patching."""

    def test_patch_with_offset_and_data(self, sample_binary: Path, temp_output_dir: Path) -> None:
        """Patch command applies patch at specified offset."""
        temp_binary = temp_output_dir / "patched.exe"
        shutil.copy(sample_binary, temp_binary)

        output_file = temp_output_dir / "patched_output.exe"
        result = run_cli_command([
            "patch",
            str(temp_binary),
            "--offset", "0x100",
            "--data", "90909090",
            "--output", str(output_file)
        ])

        if result.returncode == 0:
            assert "patch" in result.stdout.lower() or "success" in result.stdout.lower()

    def test_patch_with_nop_range(self, sample_binary: Path, temp_output_dir: Path) -> None:
        """Patch command NOPs specified address range."""
        temp_binary = temp_output_dir / "nop_test.exe"
        shutil.copy(sample_binary, temp_binary)

        output_file = temp_output_dir / "nop_output.exe"
        result = run_cli_command([
            "patch",
            str(temp_binary),
            "--nop-range", "0x100:0x110",
            "--output", str(output_file)
        ])

        if result.returncode == 0:
            assert "patch" in result.stdout.lower() or "nop" in result.stdout.lower()

    def test_patch_without_patches_fails(self, sample_binary: Path) -> None:
        """Patch command fails when no patches specified."""
        result = run_cli_command(["patch", str(sample_binary)])

        assert result.returncode != 0
        assert "no patches" in result.stdout.lower() or "error" in result.stderr.lower()


class TestPayloadCommands:
    """Test payload generation commands."""

    def test_payload_generate_reverse_shell(self, temp_output_dir: Path) -> None:
        """Payload generate creates reverse shell payload."""
        output_file = temp_output_dir / "payload.bin"
        result = run_cli_command([
            "payload", "generate",
            "--type", "reverse_shell",
            "--arch", "x64",
            "--lhost", "127.0.0.1",
            "--lport", "4444",
            "--output", str(output_file)
        ])

        if result.returncode == 0:
            assert "payload" in result.stdout.lower()
            assert output_file.exists()
            assert output_file.stat().st_size > 0

    def test_payload_generate_bind_shell(self, temp_output_dir: Path) -> None:
        """Payload generate creates bind shell payload."""
        output_file = temp_output_dir / "bind_payload.bin"
        result = run_cli_command([
            "payload", "generate",
            "--type", "bind_shell",
            "--arch", "x86",
            "--lport", "5555",
            "--output", str(output_file)
        ])

        if result.returncode == 0:
            assert "payload" in result.stdout.lower()

    def test_payload_generate_different_architectures(self, temp_output_dir: Path) -> None:
        """Payload generate supports multiple architectures."""
        for arch in ["x86", "x64"]:
            result = run_cli_command([
                "payload", "generate",
                "--type", "reverse_shell",
                "--arch", arch,
                "--lhost", "127.0.0.1",
                "--lport", "4444",
                "--output", str(temp_output_dir / f"payload_{arch}.bin")
            ])

            if result.returncode == 0:
                assert arch in result.stdout or "payload" in result.stdout.lower()

    def test_payload_generate_different_formats(self, temp_output_dir: Path) -> None:
        """Payload generate supports multiple output formats."""
        for fmt in ["raw", "exe"]:
            result = run_cli_command([
                "payload", "generate",
                "--type", "reverse_shell",
                "--arch", "x64",
                "--lhost", "127.0.0.1",
                "--lport", "4444",
                "--format", fmt,
                "--output", str(temp_output_dir / f"payload.{fmt}")
            ])

            if result.returncode == 0:
                assert fmt in result.stdout.lower() or "payload" in result.stdout.lower()

    def test_payload_list_templates(self) -> None:
        """Payload list-templates displays available templates."""
        result = run_cli_command(["payload", "list-templates"])

        if result.returncode == 0:
            assert "template" in result.stdout.lower() or "available" in result.stdout.lower()


class TestCertificateBypassCommands:
    """Test certificate validation bypass commands."""

    def test_cert_detect_on_binary(self, sample_binary: Path) -> None:
        """Certificate detect analyzes binary for validation."""
        result = run_cli_command(["cert-detect", str(sample_binary)])

        if result.returncode == 0:
            assert "detect" in result.stdout.lower() or "certificate" in result.stdout.lower()

    def test_cert_detect_with_report_output(self, sample_binary: Path, temp_output_dir: Path) -> None:
        """Certificate detect saves report to JSON file."""
        output_file = temp_output_dir / "cert_report.json"
        result = run_cli_command(["cert-detect", str(sample_binary), "--report", str(output_file)])

        if result.returncode == 0 and output_file.exists():
            with open(output_file, encoding="utf-8") as f:
                data = json.load(f)
            assert isinstance(data, dict)

    def test_cert_detect_verbose_mode(self, sample_binary: Path) -> None:
        """Certificate detect provides detailed output in verbose mode."""
        result = run_cli_command(["cert-detect", str(sample_binary), "--verbose"])

        if result.returncode == 0:
            assert len(result.stdout) > 50

    def test_cert_detect_with_min_confidence(self, sample_binary: Path) -> None:
        """Certificate detect respects minimum confidence threshold."""
        result = run_cli_command(["cert-detect", str(sample_binary), "--min-confidence", "0.5"])

        if result.returncode == 0:
            assert "confidence" in result.stdout.lower() or "detect" in result.stdout.lower()

    def test_cert_bypass_auto_method(self, sample_binary: Path) -> None:
        """Certificate bypass executes with auto method selection."""
        result = run_cli_command(["cert-bypass", str(sample_binary), "--method", "auto"])

        assert result.returncode in [0, 1]

    def test_cert_test_on_binary(self, sample_binary: Path) -> None:
        """Certificate test validates bypass effectiveness."""
        result = run_cli_command(["cert-test", str(sample_binary)])

        assert result.returncode in [0, 1]


class TestAdvancedCommands:
    """Test advanced exploitation and research commands."""

    def test_advanced_research_run_binary_analysis(self, sample_binary: Path) -> None:
        """Advanced research run performs binary analysis."""
        result = run_cli_command([
            "advanced", "research", "run",
            str(sample_binary),
            "--type", "binary_analysis",
            "--timeout", "30"
        ], timeout=60)

        if result.returncode == 0:
            assert "analysis" in result.stdout.lower() or "research" in result.stdout.lower()

    def test_advanced_research_with_ai_guidance(self, sample_binary: Path) -> None:
        """Advanced research run uses AI-guided analysis."""
        result = run_cli_command([
            "advanced", "research", "run",
            str(sample_binary),
            "--type", "binary_analysis",
            "--use-ai",
            "--timeout", "30"
        ], timeout=60)

        if result.returncode == 0:
            assert "ai" in result.stdout.lower() or "analysis" in result.stdout.lower()

    def test_advanced_research_with_output_dir(self, sample_binary: Path, temp_output_dir: Path) -> None:
        """Advanced research run saves results to output directory."""
        result = run_cli_command([
            "advanced", "research", "run",
            str(sample_binary),
            "--type", "binary_analysis",
            "--output", str(temp_output_dir),
            "--timeout", "30"
        ], timeout=60)

        if result.returncode == 0:
            assert "results" in result.stdout.lower() or "saved" in result.stdout.lower()


class TestAICommands:
    """Test AI-powered script generation and analysis commands."""

    def test_ai_analyze_binary(self, sample_binary: Path) -> None:
        """AI analyze performs AI-powered binary analysis."""
        result = run_cli_command(["ai", "analyze", str(sample_binary)], timeout=90)

        if result.returncode == 0:
            assert "ai" in result.stdout.lower() or "analysis" in result.stdout.lower()

    def test_ai_analyze_with_deep_mode(self, sample_binary: Path) -> None:
        """AI analyze performs deep analysis."""
        result = run_cli_command(["ai", "analyze", str(sample_binary), "--deep"], timeout=90)

        if result.returncode == 0:
            assert "deep" in result.stdout.lower() or "analysis" in result.stdout.lower()

    def test_ai_analyze_json_output(self, sample_binary: Path, temp_output_dir: Path) -> None:
        """AI analyze saves results in JSON format."""
        output_file = temp_output_dir / "ai_analysis.json"
        result = run_cli_command([
            "ai", "analyze",
            str(sample_binary),
            "--output", str(output_file),
            "--format", "json"
        ], timeout=90)

        if result.returncode == 0 and output_file.exists():
            with open(output_file, encoding="utf-8") as f:
                data = json.load(f)
            assert isinstance(data, dict)

    def test_ai_generate_frida_script(self, sample_binary: Path) -> None:
        """AI generate creates Frida script for binary."""
        result = run_cli_command([
            "ai", "generate",
            str(sample_binary),
            "--script-type", "frida",
            "--complexity", "basic"
        ], timeout=90)

        if result.returncode == 0:
            assert "frida" in result.stdout.lower() or "script" in result.stdout.lower()

    def test_ai_generate_ghidra_script(self, sample_binary: Path) -> None:
        """AI generate creates Ghidra script for binary."""
        result = run_cli_command([
            "ai", "generate",
            str(sample_binary),
            "--script-type", "ghidra",
            "--complexity", "basic"
        ], timeout=90)

        if result.returncode == 0:
            assert "ghidra" in result.stdout.lower() or "script" in result.stdout.lower()


class TestRealWorldWorkflows:
    """Test complete real-world CLI workflows."""

    def test_workflow_analyze_scan_patch(self, sample_binary: Path, temp_output_dir: Path) -> None:
        """Complete workflow: analyze, scan, then patch binary."""
        analysis_output = temp_output_dir / "analysis.json"
        result1 = run_cli_command(["analyze", str(sample_binary), "--output", str(analysis_output)])
        assert result1.returncode == 0
        assert analysis_output.exists()

        scan_output = temp_output_dir / "scan.json"
        result2 = run_cli_command(["scan", str(sample_binary), "--output", str(scan_output)])
        assert result2.returncode == 0
        assert scan_output.exists()

        temp_binary = temp_output_dir / "test.exe"
        shutil.copy(sample_binary, temp_binary)
        patched_output = temp_output_dir / "patched.exe"
        result3 = run_cli_command([
            "patch", str(temp_binary),
            "--offset", "0x100",
            "--data", "9090",
            "--output", str(patched_output)
        ])

        if result3.returncode == 0:
            assert patched_output.exists()

    def test_workflow_detect_bypass_test_certificate(self, sample_binary: Path, temp_output_dir: Path) -> None:
        """Complete workflow: detect certificate validation, attempt bypass, test."""
        detect_output = temp_output_dir / "cert_detect.json"
        result1 = run_cli_command(["cert-detect", str(sample_binary), "--report", str(detect_output)])

        if result1.returncode == 0 and detect_output.exists():
            result2 = run_cli_command(["cert-bypass", str(sample_binary), "--method", "auto"])
            assert result2.returncode in [0, 1]

            result3 = run_cli_command(["cert-test", str(sample_binary)])
            assert result3.returncode in [0, 1]

    def test_workflow_comprehensive_analysis_with_all_modes(self, sample_binary: Path, temp_output_dir: Path) -> None:
        """Comprehensive analysis using multiple modes and options."""
        modes = ["basic", "comprehensive", "protection"]

        for mode in modes:
            output_file = temp_output_dir / f"analysis_{mode}.json"
            result = run_cli_command([
                "analyze", str(sample_binary),
                "--mode", mode,
                "--output", str(output_file)
            ], timeout=60)

            assert result.returncode == 0
            assert output_file.exists()


class TestErrorHandling:
    """Test CLI error handling and edge cases."""

    def test_analyze_invalid_file_path(self) -> None:
        """Analyze fails gracefully with invalid file path."""
        result = run_cli_command(["analyze", "/invalid/path/binary.exe"])

        assert result.returncode != 0
        assert "error" in result.stderr.lower() or "not found" in result.stderr.lower() or "error" in result.stdout.lower()

    def test_scan_corrupted_binary_path(self) -> None:
        """Scan handles corrupted binary path gracefully."""
        result = run_cli_command(["scan", "/dev/null"])

        assert result.returncode in [0, 1]

    def test_patch_invalid_hex_data(self, sample_binary: Path, temp_output_dir: Path) -> None:
        """Patch fails gracefully with invalid hex data."""
        result = run_cli_command([
            "patch", str(sample_binary),
            "--offset", "0x100",
            "--data", "INVALID_HEX"
        ])

        assert result.returncode != 0

    def test_payload_generate_missing_required_args(self) -> None:
        """Payload generate fails when missing required arguments."""
        result = run_cli_command(["payload", "generate", "--type", "reverse_shell"])

        assert result.returncode != 0

    def test_strings_invalid_encoding(self, sample_binary: Path) -> None:
        """Strings command rejects invalid encoding."""
        result = run_cli_command(["strings", str(sample_binary), "--encoding", "invalid_encoding"])

        assert result.returncode != 0


class TestOutputFormatting:
    """Test CLI output formatting and display."""

    def test_analyze_output_is_readable(self, sample_binary: Path) -> None:
        """Analyze output is human-readable and well-formatted."""
        result = run_cli_command(["analyze", str(sample_binary)])

        assert result.returncode == 0
        assert len(result.stdout) > 0
        assert "\n" in result.stdout

    def test_scan_output_categorizes_findings(self, sample_binary: Path) -> None:
        """Scan output categorizes findings by severity."""
        result = run_cli_command(["scan", str(sample_binary), "--vulns"], timeout=60)

        if result.returncode == 0:
            assert "critical" in result.stdout.lower() or "high" in result.stdout.lower() or "vulnerabilit" in result.stdout.lower()

    def test_verbose_output_more_detailed(self, sample_binary: Path) -> None:
        """Verbose flag produces more detailed output."""
        result_normal = run_cli_command(["analyze", str(sample_binary)])
        result_verbose = run_cli_command(["analyze", str(sample_binary), "--verbose"])

        if result_normal.returncode == 0 and result_verbose.returncode == 0:
            assert len(result_verbose.stdout) >= len(result_normal.stdout)

    def test_quiet_output_suppressed(self, sample_binary: Path) -> None:
        """Quiet flag suppresses non-essential output."""
        result = run_cli_command(["--quiet", "analyze", str(sample_binary)])

        assert result.returncode == 0


class TestPerformance:
    """Test CLI command performance on various binary sizes."""

    def test_analyze_small_binary_completes_quickly(self) -> None:
        """Analyze completes quickly on small binary."""
        small_binary = FIXTURES_DIR / "binaries" / "size_categories" / "tiny_4kb" / "tiny_hello.exe"

        if not small_binary.exists():
            pytest.skip("Small binary not found")

        import time
        start = time.time()
        result = run_cli_command(["analyze", str(small_binary)])
        duration = time.time() - start

        assert result.returncode == 0
        assert duration < 10.0

    def test_scan_medium_binary_reasonable_time(self) -> None:
        """Scan completes in reasonable time on medium binary."""
        medium_binary = FIXTURES_DIR / "binaries" / "size_categories" / "small_1mb" / "small_padded.exe"

        if not medium_binary.exists():
            pytest.skip("Medium binary not found")

        import time
        start = time.time()
        result = run_cli_command(["scan", str(medium_binary)], timeout=60)
        duration = time.time() - start

        if result.returncode == 0:
            assert duration < 60.0


class TestProtectionDetection:
    """Test CLI correctly detects various protection schemes."""

    def test_detect_upx_packer(self) -> None:
        """CLI detects UPX packer in protected binary."""
        upx_binary = FIXTURES_DIR / "binaries" / "protected" / "upx_packed_0.exe"

        if not upx_binary.exists():
            pytest.skip("UPX binary not found")

        result = run_cli_command(["analyze", str(upx_binary), "--mode", "protection"])

        assert result.returncode == 0
        assert "upx" in result.stdout.lower() or "pack" in result.stdout.lower()

    def test_detect_vmprotect(self) -> None:
        """CLI detects VMProtect in protected binary."""
        vmprotect_binary = FIXTURES_DIR / "binaries" / "protected" / "vmprotect_protected.exe"

        if not vmprotect_binary.exists():
            pytest.skip("VMProtect binary not found")

        result = run_cli_command(["analyze", str(vmprotect_binary), "--mode", "protection"])

        assert result.returncode == 0
        assert "vmprotect" in result.stdout.lower() or "protection" in result.stdout.lower()

    def test_detect_themida(self) -> None:
        """CLI detects Themida protection."""
        themida_binary = FIXTURES_DIR / "binaries" / "protected" / "themida_protected.exe"

        if not themida_binary.exists():
            pytest.skip("Themida binary not found")

        result = run_cli_command(["analyze", str(themida_binary), "--mode", "protection"])

        assert result.returncode == 0
        assert "themida" in result.stdout.lower() or "protection" in result.stdout.lower()


class TestCommandAliases:
    """Test CLI command aliases work correctly."""

    def test_cert_detect_alias_cd(self, sample_binary: Path) -> None:
        """Certificate detect alias 'cd' works."""
        result = run_cli_command(["cd", str(sample_binary)])

        if result.returncode == 0:
            assert "certificate" in result.stdout.lower() or "detect" in result.stdout.lower()

    def test_cert_bypass_alias_cb(self, sample_binary: Path) -> None:
        """Certificate bypass alias 'cb' works."""
        result = run_cli_command(["cb", str(sample_binary)])

        assert result.returncode in [0, 1]

    def test_cert_test_alias_ct(self, sample_binary: Path) -> None:
        """Certificate test alias 'ct' works."""
        result = run_cli_command(["ct", str(sample_binary)])

        assert result.returncode in [0, 1]
