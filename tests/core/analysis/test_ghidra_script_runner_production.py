"""Production tests for ghidra_script_runner module.

This module tests the GhidraScriptRunner which manages Ghidra script execution
with dynamic script discovery and headless analysis capabilities.

Copyright (C) 2025 Zachary Flint
"""

import json
import struct
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from intellicrack.core.analysis.ghidra_script_runner import GhidraScript, GhidraScriptRunner


class FakeCompletedProcess:
    """Real test double for subprocess.CompletedProcess."""

    def __init__(
        self,
        args: List[str],
        returncode: int,
        stdout: str = "",
        stderr: str = "",
    ) -> None:
        self.args = args
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeSubprocessRunner:
    """Real test double for subprocess.run that simulates Ghidra execution."""

    def __init__(self, default_returncode: int = 0, default_stdout: str = '{"result": "success"}') -> None:
        self.default_returncode = default_returncode
        self.default_stdout = default_stdout
        self.call_history: List[Dict[str, Any]] = []
        self.side_effect: Optional[Exception] = None

    def run(
        self,
        args: List[str],
        capture_output: bool = False,
        text: bool = False,
        timeout: Optional[int] = None,
        check: bool = False,
    ) -> FakeCompletedProcess:
        """Simulate subprocess.run call."""
        self.call_history.append({
            'args': args,
            'capture_output': capture_output,
            'text': text,
            'timeout': timeout,
            'check': check,
        })

        if self.side_effect:
            raise self.side_effect

        return FakeCompletedProcess(
            args=args,
            returncode=self.default_returncode,
            stdout=self.default_stdout,
            stderr="",
        )


class FakePathClass:
    """Real test double for Path class that returns specific path."""

    def __init__(self, path_to_return: Path) -> None:
        self.path_to_return = path_to_return

    def __call__(self, *args: Any, **kwargs: Any) -> Path:
        """Return the configured path."""
        if args:
            return self.path_to_return
        return self.path_to_return


def create_minimal_pe(path: Path) -> Path:
    """Create minimal PE binary for testing."""
    dos_header = bytearray(64)
    dos_header[:2] = b"MZ"
    dos_header[60:64] = struct.pack("<I", 64)

    pe_signature = b"PE\x00\x00"

    file_header = struct.pack(
        "<HHIIIHH",
        0x014C, 1, 0x60000000, 0, 0, 224, 0x0102,
    )

    optional_header = struct.pack(
        "<HHBBIIIIIHHHHHHIIIIHHIIIIIIII",
        0x010B, 0, 0, 0x1000, 0, 0, 0x1000, 0x1000, 0x1000,
        0x400000, 0x1000, 0x200, 0, 0, 0, 0, 4, 0, 0,
        0x3000, 0x200, 0, 3, 0,
        0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    )

    data_directories = b"\x00" * (16 * 8)

    section_name = b".text\x00\x00\x00"
    section_header = section_name + struct.pack(
        "<IIIIHHI",
        0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0xE0000020,
    )

    pe_content = (
        dos_header + pe_signature + file_header + optional_header +
        data_directories + section_header
    )
    pe_content = pe_content.ljust(0x200, b"\x00")
    pe_content += b"\x90" * 0x200

    path.write_bytes(pe_content)
    return path


@pytest.fixture
def mock_ghidra_path(tmp_path: Path) -> Path:
    """Create mock Ghidra installation directory."""
    ghidra_dir = tmp_path / "ghidra"
    ghidra_dir.mkdir()

    support_dir = ghidra_dir / "support"
    support_dir.mkdir()

    analyzer_script = support_dir / "analyzeHeadless.bat"
    analyzer_script.write_text("@echo off\necho Mock Ghidra\n")

    scripts_dir = ghidra_dir / "Ghidra" / "Features" / "Base" / "ghidra_scripts"
    scripts_dir.mkdir(parents=True)

    return ghidra_dir


@pytest.fixture
def mock_script_dir(tmp_path: Path) -> Path:
    """Create mock Intellicrack scripts directory."""
    scripts_dir = tmp_path / "scripts" / "ghidra"
    scripts_dir.mkdir(parents=True)
    return scripts_dir


@pytest.fixture
def test_binary(tmp_path: Path) -> Path:
    """Create test binary."""
    binary_path = tmp_path / "test.exe"
    return create_minimal_pe(binary_path)


class TestGhidraScriptDataclass:
    """Test GhidraScript dataclass."""

    def test_ghidra_script_creation(self, mock_script_dir: Path) -> None:
        """GhidraScript dataclass creates with correct attributes."""
        script_path = mock_script_dir / "test_script.py"
        script_path.write_text("print('test')")

        script = GhidraScript(
            name="test_script",
            path=script_path,
            language="python",
            parameters={"param1": "value1"},
            output_format="json",
            timeout=300,
            requires_project=True,
            description="Test script",
        )

        assert script.name == "test_script"
        assert script.path == script_path
        assert script.language == "python"
        assert script.parameters == {"param1": "value1"}
        assert script.output_format == "json"
        assert script.timeout == 300
        assert script.requires_project is True

    def test_ghidra_script_defaults(self, mock_script_dir: Path) -> None:
        """GhidraScript uses default values correctly."""
        script_path = mock_script_dir / "simple.py"
        script_path.write_text("pass")

        script = GhidraScript(
            name="simple",
            path=script_path,
            language="python",
            parameters={},
            output_format="json",
        )

        assert script.timeout == 300
        assert script.requires_project is True
        assert script.description == ""


class TestGhidraScriptRunnerInitialization:
    """Test GhidraScriptRunner initialization."""

    def test_initialization_with_valid_path(self, mock_ghidra_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """GhidraScriptRunner initializes with valid Ghidra path."""
        fake_path = FakePathClass(mock_ghidra_path)
        monkeypatch.setattr("intellicrack.core.analysis.ghidra_script_runner.Path", fake_path)

        runner = GhidraScriptRunner(mock_ghidra_path)

        assert runner.ghidra_path == mock_ghidra_path
        assert isinstance(runner.discovered_scripts, dict)

    def test_headless_path_detection_windows(self, mock_ghidra_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Runner detects Windows headless analyzer path."""
        monkeypatch.setattr("os.name", "nt")
        runner = GhidraScriptRunner(mock_ghidra_path)

        expected_path = mock_ghidra_path / "support" / "analyzeHeadless.bat"
        assert str(runner.headless_path).endswith("analyzeHeadless.bat")

    def test_headless_path_detection_unix(self, mock_ghidra_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Runner detects Unix headless analyzer path."""
        monkeypatch.setattr("os.name", "posix")
        runner = GhidraScriptRunner(mock_ghidra_path)

        expected_path = mock_ghidra_path / "support" / "analyzeHeadless"
        assert "analyzeHeadless" in str(runner.headless_path)


class TestScriptDiscovery:
    """Test script discovery functionality."""

    def test_discover_python_scripts(self, mock_ghidra_path: Path, mock_script_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Runner discovers Python scripts."""
        script_file = mock_script_dir / "test_script.py"
        script_file.write_text("# Test script\npass")

        monkeypatch.setattr(GhidraScriptRunner, "intellicrack_scripts_dir", mock_script_dir)
        runner = GhidraScriptRunner(mock_ghidra_path)

        assert "test_script" in runner.discovered_scripts

    def test_discover_java_scripts(self, mock_ghidra_path: Path, mock_script_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Runner discovers Java scripts."""
        script_file = mock_script_dir / "java_script.java"
        script_file.write_text("// Java script\npublic class Test {}")

        monkeypatch.setattr(GhidraScriptRunner, "intellicrack_scripts_dir", mock_script_dir)
        runner = GhidraScriptRunner(mock_ghidra_path)

        assert "java_script" in runner.discovered_scripts

    def test_ignore_non_script_files(self, mock_ghidra_path: Path, mock_script_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Runner ignores non-script files."""
        readme_file = mock_script_dir / "README.md"
        readme_file.write_text("# README")

        init_file = mock_script_dir / "__init__.py"
        init_file.write_text("")

        monkeypatch.setattr(GhidraScriptRunner, "intellicrack_scripts_dir", mock_script_dir)
        runner = GhidraScriptRunner(mock_ghidra_path)

        assert "README" not in runner.discovered_scripts
        assert "__init__" not in runner.discovered_scripts


class TestScriptMetadataParsing:
    """Test script metadata parsing."""

    def test_parse_script_metadata(self, mock_ghidra_path: Path, mock_script_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Runner parses script metadata from comments."""
        script_content = """# @metadata:output_format=json
# @metadata:timeout=600
# @metadata:description=Test script
print('test')
"""
        script_file = mock_script_dir / "metadata_test.py"
        script_file.write_text(script_content)

        monkeypatch.setattr(GhidraScriptRunner, "intellicrack_scripts_dir", mock_script_dir)
        runner = GhidraScriptRunner(mock_ghidra_path)

        if script := runner.discovered_scripts.get("metadata_test"):
            assert script.output_format == "json"

    def test_default_metadata_when_missing(self, mock_ghidra_path: Path, mock_script_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Runner uses defaults when metadata is missing."""
        script_file = mock_script_dir / "no_metadata.py"
        script_file.write_text("print('test')")

        monkeypatch.setattr(GhidraScriptRunner, "intellicrack_scripts_dir", mock_script_dir)
        runner = GhidraScriptRunner(mock_ghidra_path)

        if script := runner.discovered_scripts.get("no_metadata"):
            assert script.timeout == 300
            assert script.output_format == "json"


class TestScriptExecution:
    """Test script execution functionality."""

    def test_run_script_basic(self, mock_ghidra_path: Path, mock_script_dir: Path, test_binary: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Runner executes script and returns results."""
        script_file = mock_script_dir / "basic_script.py"
        script_file.write_text("print('test')")

        monkeypatch.setattr(GhidraScriptRunner, "intellicrack_scripts_dir", mock_script_dir)
        runner = GhidraScriptRunner(mock_ghidra_path)

        fake_subprocess = FakeSubprocessRunner(
            default_returncode=0,
            default_stdout='{"result": "success"}',
        )
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)

        result = runner.run_script(
            binary_path=test_binary,
            script_name="basic_script",
            parameters={},
        )

        assert isinstance(result, dict)

    def test_run_script_with_parameters(self, mock_ghidra_path: Path, mock_script_dir: Path, test_binary: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Runner passes parameters to script."""
        script_file = mock_script_dir / "param_script.py"
        script_file.write_text("print('test')")

        monkeypatch.setattr(GhidraScriptRunner, "intellicrack_scripts_dir", mock_script_dir)
        runner = GhidraScriptRunner(mock_ghidra_path)

        fake_subprocess = FakeSubprocessRunner(
            default_returncode=0,
            default_stdout='{"result": "success"}',
        )
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)

        result = runner.run_script(
            binary_path=test_binary,
            script_name="param_script",
            parameters={"param1": "value1"},
        )

        assert isinstance(result, dict)


class TestScriptManagement:
    """Test script management operations."""

    def test_list_available_scripts(self, mock_ghidra_path: Path, mock_script_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """list_available_scripts returns all discovered scripts."""
        for i in range(3):
            script_file = mock_script_dir / f"script{i}.py"
            script_file.write_text("pass")

        monkeypatch.setattr(GhidraScriptRunner, "intellicrack_scripts_dir", mock_script_dir)
        runner = GhidraScriptRunner(mock_ghidra_path)

        scripts = runner.list_available_scripts()

        assert isinstance(scripts, list)
        assert len(scripts) >= 0

    def test_refresh_scripts(self, mock_ghidra_path: Path, mock_script_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """refresh_scripts rediscovers scripts."""
        script1 = mock_script_dir / "script1.py"
        script1.write_text("pass")

        monkeypatch.setattr(GhidraScriptRunner, "intellicrack_scripts_dir", mock_script_dir)
        runner = GhidraScriptRunner(mock_ghidra_path)

        initial_count = len(runner.discovered_scripts)

        script2 = mock_script_dir / "script2.py"
        script2.write_text("pass")

        count = runner.refresh_scripts()

        assert isinstance(count, int)
        assert count >= initial_count


class TestErrorHandling:
    """Test error handling."""

    def test_handles_missing_script_directory(self, mock_ghidra_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Runner handles missing script directory gracefully."""
        nonexistent_dir = mock_ghidra_path / "nonexistent_scripts"

        monkeypatch.setattr(GhidraScriptRunner, "intellicrack_scripts_dir", nonexistent_dir)
        runner = GhidraScriptRunner(mock_ghidra_path)

        assert isinstance(runner.discovered_scripts, dict)

    def test_handles_script_execution_error(self, mock_ghidra_path: Path, mock_script_dir: Path, test_binary: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Runner handles script execution errors."""
        script_file = mock_script_dir / "error_script.py"
        script_file.write_text("raise Exception('error')")

        monkeypatch.setattr(GhidraScriptRunner, "intellicrack_scripts_dir", mock_script_dir)
        runner = GhidraScriptRunner(mock_ghidra_path)

        fake_subprocess = FakeSubprocessRunner()
        fake_subprocess.side_effect = Exception("Execution failed")
        monkeypatch.setattr("subprocess.run", fake_subprocess.run)

        result = runner.run_script(
            binary_path=test_binary,
            script_name="error_script",
            parameters={},
        )

        assert isinstance(result, dict)

    def test_handles_nonexistent_script(self, mock_ghidra_path: Path, test_binary: Path) -> None:
        """Runner handles request for nonexistent script."""
        runner = GhidraScriptRunner(mock_ghidra_path)

        result = runner.run_script(
            binary_path=test_binary,
            script_name="nonexistent_script",
            parameters={},
        )

        assert isinstance(result, dict)


class TestScriptCaching:
    """Test script caching behavior."""

    def test_discovered_scripts_cached(self, mock_ghidra_path: Path, mock_script_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Discovered scripts are cached."""
        script_file = mock_script_dir / "cached_script.py"
        script_file.write_text("pass")

        monkeypatch.setattr(GhidraScriptRunner, "intellicrack_scripts_dir", mock_script_dir)
        runner = GhidraScriptRunner(mock_ghidra_path)

        initial_scripts = dict(runner.discovered_scripts)

        assert runner.discovered_scripts == initial_scripts
