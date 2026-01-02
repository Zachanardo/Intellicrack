"""Production tests for Ghidra integration utilities.

Tests validate that Ghidra plugin execution, script generation, and project
management work correctly for real binary analysis scenarios in licensing
research.
"""

import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable, Optional

import pytest

from intellicrack.utils.ghidra_common import (
    cleanup_ghidra_project,
    create_ghidra_analysis_script,
    get_ghidra_project_info,
    run_ghidra_plugin,
    save_ghidra_script,
)


class FakeProcess:
    """Real test double for subprocess.Popen."""

    def __init__(
        self,
        stdout_data: str = "",
        stderr_data: str = "",
        returncode: int = 0,
        raise_timeout: bool = False,
        timeout_seconds: float = 1.0,
    ) -> None:
        self.stdout_data: str = stdout_data
        self.stderr_data: str = stderr_data
        self.returncode: int = returncode
        self.raise_timeout: bool = raise_timeout
        self.timeout_seconds: float = timeout_seconds
        self.killed: bool = False
        self.communicate_calls: int = 0

    def communicate(self, timeout: Optional[float] = None) -> tuple[str, str]:
        """Simulate process communication."""
        self.communicate_calls += 1
        if self.raise_timeout:
            raise subprocess.TimeoutExpired("cmd", self.timeout_seconds)
        return (self.stdout_data, self.stderr_data)

    def kill(self) -> None:
        """Simulate killing the process."""
        self.killed = True


class FakeApp:
    """Real test double for application instance with update_output signal."""

    def __init__(self) -> None:
        self.update_output_calls: list[str] = []

    @property
    def update_output(self) -> "FakeSignal":
        """Return fake signal for update_output."""
        return FakeSignal(self)


class FakeSignal:
    """Real test double for Qt signal."""

    def __init__(self, app: FakeApp) -> None:
        self.app: FakeApp = app
        self.emit_calls: list[str] = []

    def emit(self, message: str) -> None:
        """Record emitted messages."""
        self.emit_calls.append(message)
        self.app.update_output_calls.append(message)


class FakePopenFactory:
    """Factory for creating FakeProcess instances with call tracking."""

    def __init__(self, process: FakeProcess) -> None:
        self.process: FakeProcess = process
        self.call_args_list: list[tuple[list[str], dict[str, Any]]] = []

    def __call__(self, args: list[str], **kwargs: Any) -> FakeProcess:
        """Create and track Popen calls."""
        self.call_args_list.append((args, kwargs))
        return self.process

    def assert_called_once(self) -> None:
        """Verify Popen was called exactly once."""
        assert len(self.call_args_list) == 1, f"Expected 1 call, got {len(self.call_args_list)}"

    @property
    def call_args(self) -> tuple[tuple[list[str], dict[str, Any]], ...]:
        """Return call arguments in format similar to Mock.call_args."""
        if not self.call_args_list:
            raise AssertionError("No calls made")
        args, kwargs = self.call_args_list[-1]
        return (args,), kwargs


class FakeRemoveFunction:
    """Real test double for os.remove that can raise errors."""

    def __init__(self, raise_error: Optional[Exception] = None) -> None:
        self.raise_error: Optional[Exception] = raise_error
        self.removed_paths: list[str] = []

    def __call__(self, path: str) -> None:
        """Simulate file removal."""
        if self.raise_error:
            raise self.raise_error
        self.removed_paths.append(path)


class TestRunGhidraPlugin:
    """Test Ghidra plugin execution functionality."""

    def test_validates_ghidra_path_exists(self) -> None:
        """run_ghidra_plugin validates that Ghidra executable exists."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_ghidra = "/nonexistent/ghidra/analyzeHeadless"
            binary_path = Path(tmpdir) / "test.exe"
            binary_path.write_bytes(b"MZ\x90\x00")

            script_path = Path(tmpdir) / "script.java"
            script_path.write_text("// test script")

            returncode, stdout, stderr = run_ghidra_plugin(
                ghidra_path=fake_ghidra,
                project_dir=tmpdir,
                project_name="test_proj",
                binary_path=str(binary_path),
                script_dir=tmpdir,
                script_name="script.java",
            )

            assert returncode == 1
            assert "Ghidra not found" in stderr

    def test_validates_binary_path_exists(self) -> None:
        """run_ghidra_plugin validates that binary to analyze exists."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_ghidra = Path(tmpdir) / "analyzeHeadless"
            fake_ghidra.write_text("#!/bin/bash")

            script_path = Path(tmpdir) / "script.java"
            script_path.write_text("// test script")

            returncode, stdout, stderr = run_ghidra_plugin(
                ghidra_path=str(fake_ghidra),
                project_dir=tmpdir,
                project_name="test_proj",
                binary_path="/nonexistent/binary.exe",
                script_dir=tmpdir,
                script_name="script.java",
            )

            assert returncode == 1
            assert "Binary not found" in stderr

    def test_validates_script_path_exists(self) -> None:
        """run_ghidra_plugin validates that analysis script exists."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_ghidra = Path(tmpdir) / "analyzeHeadless"
            fake_ghidra.write_text("#!/bin/bash")

            binary_path = Path(tmpdir) / "test.exe"
            binary_path.write_bytes(b"MZ\x90\x00")

            returncode, stdout, stderr = run_ghidra_plugin(
                ghidra_path=str(fake_ghidra),
                project_dir=tmpdir,
                project_name="test_proj",
                binary_path=str(binary_path),
                script_dir=tmpdir,
                script_name="nonexistent.java",
            )

            assert returncode == 1
            assert "Script not found" in stderr

    def test_creates_project_directory(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """run_ghidra_plugin creates project directory if it does not exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir) / "new_project_dir"
            assert not project_dir.exists()

            fake_ghidra = Path(tmpdir) / "analyzeHeadless"
            fake_ghidra.write_text("#!/bin/bash")

            binary_path = Path(tmpdir) / "test.exe"
            binary_path.write_bytes(b"MZ\x90\x00")

            script_path = Path(tmpdir) / "script.java"
            script_path.write_text("// test")

            fake_process = FakeProcess(stdout_data="output", returncode=0)
            fake_popen = FakePopenFactory(fake_process)
            monkeypatch.setattr("subprocess.Popen", fake_popen)

            run_ghidra_plugin(
                ghidra_path=str(fake_ghidra),
                project_dir=str(project_dir),
                project_name="test_proj",
                binary_path=str(binary_path),
                script_dir=tmpdir,
                script_name="script.java",
            )

            assert project_dir.exists()

    def test_executes_ghidra_command(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """run_ghidra_plugin executes Ghidra with correct command structure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_ghidra = Path(tmpdir) / "analyzeHeadless"
            fake_ghidra.write_text("#!/bin/bash")

            binary_path = Path(tmpdir) / "test.exe"
            binary_path.write_bytes(b"MZ\x90\x00")

            script_path = Path(tmpdir) / "script.java"
            script_path.write_text("// test script")

            fake_process = FakeProcess(stdout_data="Ghidra output", returncode=0)
            fake_popen = FakePopenFactory(fake_process)
            monkeypatch.setattr("subprocess.Popen", fake_popen)

            returncode, stdout, stderr = run_ghidra_plugin(
                ghidra_path=str(fake_ghidra),
                project_dir=tmpdir,
                project_name="test_proj",
                binary_path=str(binary_path),
                script_dir=tmpdir,
                script_name="script.java",
            )

            assert returncode == 0
            assert "Ghidra output" in stdout
            fake_popen.assert_called_once()
            call_args = fake_popen.call_args[0][0]
            assert str(fake_ghidra) in call_args
            assert "-headless" in call_args
            assert "-import" in call_args

    def test_handles_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """run_ghidra_plugin handles timeout during execution."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_ghidra = Path(tmpdir) / "analyzeHeadless"
            fake_ghidra.write_text("#!/bin/bash")

            binary_path = Path(tmpdir) / "test.exe"
            binary_path.write_bytes(b"MZ\x90\x00")

            script_path = Path(tmpdir) / "script.java"
            script_path.write_text("// test script")

            fake_process = FakeProcess(raise_timeout=True, timeout_seconds=1.0)
            fake_popen = FakePopenFactory(fake_process)
            monkeypatch.setattr("subprocess.Popen", fake_popen)

            returncode, stdout, stderr = run_ghidra_plugin(
                ghidra_path=str(fake_ghidra),
                project_dir=tmpdir,
                project_name="test_proj",
                binary_path=str(binary_path),
                script_dir=tmpdir,
                script_name="script.java",
                timeout=1,
            )

            assert returncode == 124
            assert "timed out" in stderr

    def test_includes_overwrite_flag(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """run_ghidra_plugin includes overwrite flag when specified."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_ghidra = Path(tmpdir) / "analyzeHeadless"
            fake_ghidra.write_text("#!/bin/bash")

            binary_path = Path(tmpdir) / "test.exe"
            binary_path.write_bytes(b"MZ\x90\x00")

            script_path = Path(tmpdir) / "script.java"
            script_path.write_text("// test script")

            fake_process = FakeProcess(returncode=0)
            fake_popen = FakePopenFactory(fake_process)
            monkeypatch.setattr("subprocess.Popen", fake_popen)

            run_ghidra_plugin(
                ghidra_path=str(fake_ghidra),
                project_dir=tmpdir,
                project_name="test_proj",
                binary_path=str(binary_path),
                script_dir=tmpdir,
                script_name="script.java",
                overwrite=True,
            )

            call_args = fake_popen.call_args[0][0]
            assert "-overwrite" in call_args

    def test_emits_output_to_app_if_provided(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """run_ghidra_plugin emits output to application instance if provided."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_ghidra = Path(tmpdir) / "analyzeHeadless"
            fake_ghidra.write_text("#!/bin/bash")

            binary_path = Path(tmpdir) / "test.exe"
            binary_path.write_bytes(b"MZ\x90\x00")

            script_path = Path(tmpdir) / "script.java"
            script_path.write_text("// test script")

            fake_app = FakeApp()
            fake_process = FakeProcess(returncode=0)
            fake_popen = FakePopenFactory(fake_process)
            monkeypatch.setattr("subprocess.Popen", fake_popen)

            run_ghidra_plugin(
                ghidra_path=str(fake_ghidra),
                project_dir=tmpdir,
                project_name="test_proj",
                binary_path=str(binary_path),
                script_dir=tmpdir,
                script_name="script.java",
                app=fake_app,
            )

            assert len(fake_app.update_output.emit_calls) > 0


class TestCreateGhidraAnalysisScript:
    """Test Ghidra analysis script generation."""

    def test_creates_basic_analysis_script(self) -> None:
        """create_ghidra_analysis_script generates basic analysis script."""
        script = create_ghidra_analysis_script(analysis_type="basic")

        assert "BasicAnalysis" in script
        assert "GhidraScript" in script
        assert "analyzeFunctions" in script
        assert "analyzeStrings" in script
        assert "analyzeImports" in script

    def test_creates_license_analysis_script(self) -> None:
        """create_ghidra_analysis_script generates license-focused script."""
        script = create_ghidra_analysis_script(analysis_type="license_analysis")

        assert "LicenseAnalysis" in script
        assert "findLicenseFunctions" in script
        assert "findLicenseStrings" in script
        assert "findCryptoFunctions" in script
        assert "findTimeFunctions" in script
        assert "license" in script.lower()
        assert "trial" in script.lower()

    def test_creates_function_analysis_script(self) -> None:
        """create_ghidra_analysis_script generates function analysis script."""
        script = create_ghidra_analysis_script(analysis_type="function_analysis")

        assert "FunctionAnalysis" in script
        assert "analyzeFunctionComplexity" in script
        assert "analyzeCallGraph" in script
        assert "findInterestingFunctions" in script

    def test_creates_string_analysis_script(self) -> None:
        """create_ghidra_analysis_script generates string analysis script."""
        script = create_ghidra_analysis_script(analysis_type="string_analysis")

        assert "StringAnalysis" in script
        assert "analyzeAllStrings" in script
        assert "findUrls" in script
        assert "findFilePaths" in script
        assert "findErrorMessages" in script

    def test_defaults_to_basic_script(self) -> None:
        """create_ghidra_analysis_script defaults to basic when type unknown."""
        script = create_ghidra_analysis_script(analysis_type="unknown_type")

        assert "BasicAnalysis" in script

    def test_script_contains_valid_java_syntax(self) -> None:
        """Generated scripts contain valid Java syntax structure."""
        scripts = [
            create_ghidra_analysis_script("basic"),
            create_ghidra_analysis_script("license_analysis"),
            create_ghidra_analysis_script("function_analysis"),
            create_ghidra_analysis_script("string_analysis"),
        ]

        for script in scripts:
            assert "public class" in script
            assert "extends GhidraScript" in script
            assert "public void run()" in script
            assert "throws Exception" in script
            assert script.count("{") == script.count("}")

    def test_license_script_searches_crypto_keywords(self) -> None:
        """License analysis script searches for cryptographic functions."""
        script = create_ghidra_analysis_script("license_analysis")

        assert "crypt" in script.lower()
        assert "hash" in script.lower()
        assert "aes" in script.lower()
        assert "rsa" in script.lower()


class TestSaveGhidraScript:
    """Test Ghidra script saving to filesystem."""

    def test_saves_script_to_file(self) -> None:
        """save_ghidra_script saves script content to file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            script_content = "// Test script content"
            script_name = "TestScript.java"

            script_path = save_ghidra_script(script_content, script_name, tmpdir)

            assert os.path.exists(script_path)
            with open(script_path, encoding="utf-8") as f:
                assert f.read() == script_content

    def test_adds_java_extension_if_missing(self) -> None:
        """save_ghidra_script adds .java extension if not present."""
        with tempfile.TemporaryDirectory() as tmpdir:
            script_content = "// Test"
            script_name = "TestScript"

            script_path = save_ghidra_script(script_content, script_name, tmpdir)

            assert script_path.endswith(".java")
            assert os.path.exists(script_path)

    def test_creates_output_directory(self) -> None:
        """save_ghidra_script creates output directory if it does not exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = os.path.join(tmpdir, "scripts", "ghidra")
            script_content = "// Test"
            script_name = "Test.java"

            script_path = save_ghidra_script(script_content, script_name, output_dir)

            assert os.path.exists(output_dir)
            assert os.path.exists(script_path)

    def test_handles_unicode_content(self) -> None:
        """save_ghidra_script handles Unicode content correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            script_content = "// Test with Unicode: \u2713 \u2717 \u00a9"
            script_name = "UnicodeScript.java"

            script_path = save_ghidra_script(script_content, script_name, tmpdir)

            with open(script_path, encoding="utf-8") as f:
                content = f.read()
                assert "\u2713" in content
                assert "\u2717" in content
                assert "\u00a9" in content

    def test_raises_on_write_error(self) -> None:
        """save_ghidra_script raises exception on write errors."""
        with pytest.raises(Exception):
            save_ghidra_script("// test", "test.java", "/invalid/path/that/does/not/exist")


class TestGetGhidraProjectInfo:
    """Test Ghidra project information retrieval."""

    def test_returns_project_info_structure(self) -> None:
        """get_ghidra_project_info returns dictionary with project info."""
        with tempfile.TemporaryDirectory() as tmpdir:
            info = get_ghidra_project_info(tmpdir, "test_project")

            assert isinstance(info, dict)
            assert "exists" in info
            assert "project_dir" in info
            assert "project_name" in info
            assert "files" in info
            assert "size" in info

    def test_detects_nonexistent_project(self) -> None:
        """get_ghidra_project_info detects when project does not exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            info = get_ghidra_project_info(tmpdir, "nonexistent_project")

            assert info["exists"] is False
            assert info["project_dir"] == tmpdir
            assert info["project_name"] == "nonexistent_project"

    def test_detects_existing_project(self) -> None:
        """get_ghidra_project_info detects when project exists."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_name = "test_project"
            project_file = Path(tmpdir) / f"{project_name}.gpr"
            project_file.write_text("test project data")

            info = get_ghidra_project_info(tmpdir, project_name)

            assert info["exists"] is True
            assert "project_file" in info
            assert info["size"] > 0
            assert "modified" in info

    def test_lists_project_files(self) -> None:
        """get_ghidra_project_info lists all files belonging to project."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_name = "test_project"
            Path(tmpdir, f"{project_name}.gpr").write_text("data")
            Path(tmpdir, f"{project_name}.rep").write_text("rep data")
            Path(tmpdir, "other_file.txt").write_text("other")

            info = get_ghidra_project_info(tmpdir, project_name)

            assert info["exists"] is True
            assert len(info["files"]) == 2
            assert f"{project_name}.gpr" in info["files"]
            assert f"{project_name}.rep" in info["files"]
            assert "other_file.txt" not in info["files"]

    def test_handles_directory_errors(self) -> None:
        """get_ghidra_project_info handles errors when accessing directory."""
        info = get_ghidra_project_info("/nonexistent/directory", "project")

        assert info["exists"] is False


class TestCleanupGhidraProject:
    """Test Ghidra project cleanup functionality."""

    def test_removes_project_files(self) -> None:
        """cleanup_ghidra_project removes all project-related files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_name = "test_project"
            Path(tmpdir, f"{project_name}.gpr").write_text("data")
            Path(tmpdir, f"{project_name}.rep").write_text("rep data")
            Path(tmpdir, "other_file.txt").write_text("keep this")

            result = cleanup_ghidra_project(tmpdir, project_name)

            assert result is True
            assert not Path(tmpdir, f"{project_name}.gpr").exists()
            assert not Path(tmpdir, f"{project_name}.rep").exists()
            assert Path(tmpdir, "other_file.txt").exists()

    def test_removes_project_directories(self) -> None:
        """cleanup_ghidra_project removes project-related directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_name = "test_project"
            project_dir = Path(tmpdir) / f"{project_name}.rep"
            project_dir.mkdir()
            (project_dir / "data.txt").write_text("data")

            result = cleanup_ghidra_project(tmpdir, project_name)

            assert result is True
            assert not project_dir.exists()

    def test_handles_nonexistent_directory(self) -> None:
        """cleanup_ghidra_project handles cleanup of nonexistent directory."""
        result = cleanup_ghidra_project("/nonexistent/directory", "project")

        assert result is True

    def test_removes_empty_directory(self) -> None:
        """cleanup_ghidra_project removes project directory if empty."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir) / "empty_project"
            project_dir.mkdir()
            project_name = "test_project"
            (project_dir / f"{project_name}.gpr").write_text("data")

            result = cleanup_ghidra_project(str(project_dir), project_name)

            assert result is True
            assert not project_dir.exists()

    def test_preserves_non_empty_directory(self) -> None:
        """cleanup_ghidra_project preserves directory with other files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_name = "test_project"
            Path(tmpdir, f"{project_name}.gpr").write_text("data")
            Path(tmpdir, "keep_this.txt").write_text("important")

            result = cleanup_ghidra_project(tmpdir, project_name)

            assert result is True
            assert Path(tmpdir).exists()
            assert Path(tmpdir, "keep_this.txt").exists()

    def test_handles_cleanup_errors(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """cleanup_ghidra_project handles errors during cleanup."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_name = "test_project"
            project_file = Path(tmpdir) / f"{project_name}.gpr"
            project_file.write_text("data")

            fake_remove = FakeRemoveFunction(raise_error=PermissionError("Access denied"))
            monkeypatch.setattr("os.remove", fake_remove)

            result = cleanup_ghidra_project(tmpdir, project_name)

            assert result is False


class TestRealWorldScenarios:
    """Test realistic production usage scenarios."""

    def test_full_ghidra_analysis_workflow(self) -> None:
        """Test complete workflow from script creation to cleanup."""
        with tempfile.TemporaryDirectory() as tmpdir:
            binary_path = Path(tmpdir) / "sample.exe"
            binary_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)

            script_content = create_ghidra_analysis_script("license_analysis")
            script_path = save_ghidra_script(script_content, "LicenseAnalysis", tmpdir)

            assert os.path.exists(script_path)
            assert "LicenseAnalysis" in script_content

            info = get_ghidra_project_info(tmpdir, "test_project")
            assert info["exists"] is False

            result = cleanup_ghidra_project(tmpdir, "test_project")
            assert result is True

    def test_multiple_script_types_generation(self) -> None:
        """Test generating different script types for analysis."""
        script_types = ["basic", "license_analysis", "function_analysis", "string_analysis"]

        with tempfile.TemporaryDirectory() as tmpdir:
            for script_type in script_types:
                script = create_ghidra_analysis_script(script_type)
                saved_path = save_ghidra_script(script, f"{script_type}.java", tmpdir)

                assert os.path.exists(saved_path)
                with open(saved_path, encoding="utf-8") as f:
                    content = f.read()
                    assert "GhidraScript" in content


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_empty_script_content(self) -> None:
        """save_ghidra_script handles empty script content."""
        with tempfile.TemporaryDirectory() as tmpdir:
            script_path = save_ghidra_script("", "empty.java", tmpdir)

            assert os.path.exists(script_path)
            assert os.path.getsize(script_path) == 0

    def test_very_long_script_name(self) -> None:
        """save_ghidra_script handles very long script names."""
        with tempfile.TemporaryDirectory() as tmpdir:
            long_name = "a" * 200
            script_path = save_ghidra_script("// test", long_name, tmpdir)

            assert os.path.exists(script_path)

    def test_special_characters_in_project_name(self) -> None:
        """get_ghidra_project_info handles special characters in names."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_name = "test_project-v1.0"
            project_file = Path(tmpdir) / f"{project_name}.gpr"
            project_file.write_text("data")

            info = get_ghidra_project_info(tmpdir, project_name)

            assert info["exists"] is True

    def test_concurrent_cleanup_attempts(self) -> None:
        """cleanup_ghidra_project handles cleanup when files already removed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_name = "test_project"
            project_file = Path(tmpdir) / f"{project_name}.gpr"
            project_file.write_text("data")

            result1 = cleanup_ghidra_project(tmpdir, project_name)
            result2 = cleanup_ghidra_project(tmpdir, project_name)

            assert result1 is True
            assert result2 is True
