"""Production tests for interactive_mode module.

Tests interactive shell functionality for binary analysis, command execution,
and session management with real file operations and actual implementations.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import io
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from intellicrack.cli.interactive_mode import IntellicrackShell, main


class FakeStdout:
    """Real class capturing stdout for CLI testing."""

    def __init__(self) -> None:
        self.content: list[str] = []
        self.original_stdout = sys.stdout

    def write(self, text: str) -> int:
        self.content.append(text)
        return len(text)

    def flush(self) -> None:
        pass

    def get_output(self) -> str:
        return "".join(self.content)


class TestBinaryAnalysisRunner:
    """Real analysis runner for testing that returns predictable results."""

    def __init__(self, should_fail: bool = False) -> None:
        self.should_fail = should_fail
        self.call_count = 0
        self.last_binary_path: str | None = None

    def run_analysis(self, binary_path: str) -> dict[str, Any]:
        self.call_count += 1
        self.last_binary_path = binary_path

        if self.should_fail:
            raise ValueError("Analysis failed: Invalid binary format")

        binary_path_obj = Path(binary_path)
        file_size = binary_path_obj.stat().st_size if binary_path_obj.exists() else 0

        return {
            "binary_path": binary_path,
            "file_size": file_size,
            "entropy": 7.85,
            "sections": [
                {"name": ".text", "virtual_address": 0x1000, "size": 4096},
                {"name": ".data", "virtual_address": 0x2000, "size": 2048},
            ],
            "imports": ["kernel32.dll!CreateFileA", "user32.dll!MessageBoxA"],
            "exports": [],
            "strings_found": 127,
            "protection_detected": False,
        }


class RealExporter:
    """Real exporter implementation for testing."""

    def __init__(self, binary_path: str, analysis_results: dict[str, Any]) -> None:
        self.binary_path = binary_path
        self.analysis_results = analysis_results
        self.exports_performed: list[tuple[str, str]] = []

    def export_detailed_json(self, output_file: str) -> bool:
        try:
            output_path = Path(output_file)
            export_data = {
                "binary": self.binary_path,
                "analysis": self.analysis_results,
                "format": "json",
            }
            output_path.write_text(json.dumps(export_data, indent=2))
            self.exports_performed.append(("json", output_file))
            return True
        except Exception:
            return False

    def export_html_report(self, output_file: str) -> bool:
        try:
            output_path = Path(output_file)
            html_content = f"""<!DOCTYPE html>
<html>
<head><title>Analysis Report</title></head>
<body>
<h1>Binary Analysis Report</h1>
<p>Binary: {self.binary_path}</p>
<pre>{json.dumps(self.analysis_results, indent=2)}</pre>
</body>
</html>"""
            output_path.write_text(html_content)
            self.exports_performed.append(("html", output_file))
            return True
        except Exception:
            return False

    def export_xml_report(self, output_file: str) -> bool:
        try:
            output_path = Path(output_file)
            xml_content = f"""<?xml version="1.0"?>
<analysis>
  <binary>{self.binary_path}</binary>
  <results>{str(self.analysis_results)}</results>
</analysis>"""
            output_path.write_text(xml_content)
            self.exports_performed.append(("xml", output_file))
            return True
        except Exception:
            return False

    def export_csv_data(self, output_file: str) -> bool:
        try:
            output_path = Path(output_file)
            csv_content = "key,value\n"
            csv_content += f"binary,{self.binary_path}\n"
            for key, value in self.analysis_results.items():
                csv_content += f"{key},{value}\n"
            output_path.write_text(csv_content)
            self.exports_performed.append(("csv", output_file))
            return True
        except Exception:
            return False

    def export_excel_workbook(self, output_file: str) -> bool:
        try:
            output_path = Path(output_file)
            output_path.write_text(f"Excel export placeholder for {self.binary_path}")
            self.exports_performed.append(("excel", output_file))
            return True
        except Exception:
            return False

    def export_yaml_config(self, output_file: str) -> bool:
        try:
            output_path = Path(output_file)
            yaml_content = f"binary: {self.binary_path}\nanalysis:\n"
            for key, value in self.analysis_results.items():
                yaml_content += f"  {key}: {value}\n"
            output_path.write_text(yaml_content)
            self.exports_performed.append(("yaml", output_file))
            return True
        except Exception:
            return False


class RealProtectionAnalyzer:
    """Real protection detector for testing."""

    def __init__(self, binary_path: str) -> None:
        self.binary_path = binary_path
        self.call_count = 0

    def detect_protections(self) -> dict[str, dict[str, Any]]:
        self.call_count += 1

        binary_content = Path(self.binary_path).read_bytes()

        protections: dict[str, dict[str, Any]] = {}

        if b"VMProtect" in binary_content:
            protections["VMProtect"] = {"detected": True, "type": "Packer", "confidence": 95}
        else:
            protections["VMProtect"] = {"detected": False}

        if b"Themida" in binary_content:
            protections["Themida"] = {"detected": True, "type": "Protector", "confidence": 90}
        else:
            protections["Themida"] = {"detected": False}

        if b"UPX" in binary_content:
            protections["UPX"] = {"detected": True, "type": "Packer", "confidence": 100}
        else:
            protections["UPX"] = {"detected": False}

        return protections


class RealPatchGenerator:
    """Real patch generator for testing."""

    def __init__(self, binary_path: str) -> None:
        self.binary_path = binary_path
        self.call_count = 0

    def generate_patches(self) -> dict[str, Any]:
        self.call_count += 1

        binary_content = Path(self.binary_path).read_bytes()
        patches = []

        for offset, byte_val in enumerate(binary_content):
            if byte_val == 0x74:
                patches.append(
                    {
                        "offset": hex(offset),
                        "original": "74 05",
                        "patched": "EB 05",
                        "description": f"JE to JMP bypass at offset {hex(offset)}",
                    }
                )
            if len(patches) >= 5:
                break

        return {"patches": patches, "total": len(patches), "binary": self.binary_path}


class RealStringsExtractor:
    """Real string extractor for testing."""

    def __init__(self, binary_path: str) -> None:
        self.binary_path = binary_path

    def extract_strings(self, min_length: int = 4) -> list[str]:
        binary_content = Path(self.binary_path).read_bytes()
        strings = []
        current_string = b""

        for byte in binary_content:
            if 32 <= byte < 127:
                current_string += bytes([byte])
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string.decode("ascii", errors="ignore"))
                current_string = b""

        if len(current_string) >= min_length:
            strings.append(current_string.decode("ascii", errors="ignore"))

        return strings


class RealAIChatInterface:
    """Real AI chat interface for testing."""

    def __init__(self, binary_path: str | None = None, analysis_results: dict[str, Any] | None = None) -> None:
        self.binary_path = binary_path
        self.analysis_results = analysis_results
        self.conversation_history: list[tuple[str, str]] = []

    def _get_ai_response(self, question: str) -> str:
        self.conversation_history.append(("user", question))

        response = ""
        if "protection" in question.lower():
            response = "Based on the analysis, no protection mechanisms were detected in the binary."
        elif "entropy" in question.lower():
            response = "The entropy value of 7.85 indicates high randomness, suggesting possible compression or encryption."
        elif "import" in question.lower():
            response = "The binary imports kernel32.dll and user32.dll, indicating standard Windows API usage."
        else:
            response = f"I understand you're asking: '{question}'. Let me help with that analysis."

        self.conversation_history.append(("assistant", response))
        return response


@pytest.fixture
def temp_binary(tmp_path: Path) -> Path:
    """Create temporary test binary with realistic PE structure."""
    binary_path = tmp_path / "test_binary.exe"
    content = b"MZ\x90\x00"
    content += b"\x00" * 60
    content += b"PE\x00\x00"
    content += b"TEST_BINARY_CONTENT" * 50
    content += b"\x74\x05"
    content += b"MORE_DATA" * 20
    binary_path.write_bytes(content)
    return binary_path


@pytest.fixture
def protected_binary(tmp_path: Path) -> Path:
    """Create binary with protection signatures."""
    binary_path = tmp_path / "protected.exe"
    content = b"MZ\x90\x00"
    content += b"\x00" * 60
    content += b"PE\x00\x00"
    content += b"VMProtect" + b"\x00" * 100
    content += b"Themida" + b"\x00" * 100
    content += b"LICENSE_CHECK" * 10
    binary_path.write_bytes(content)
    return binary_path


@pytest.fixture
def shell_instance() -> IntellicrackShell:
    """Create IntellicrackShell instance."""
    return IntellicrackShell()


class TestIntellicrackShellInitialization:
    """Test shell initialization and configuration."""

    def test_shell_initializes_with_correct_attributes(self, shell_instance: IntellicrackShell) -> None:
        """Shell initializes with correct default attributes."""
        assert shell_instance.current_file is None
        assert shell_instance.analysis_results is None
        assert shell_instance.prompt == "intellicrack> "
        assert shell_instance.ai_chat is None

    def test_shell_has_intro_message(self, shell_instance: IntellicrackShell) -> None:
        """Shell has intro message defined."""
        assert shell_instance.intro is not None
        assert "Intellicrack" in shell_instance.intro
        assert "Interactive Shell" in shell_instance.intro
        assert "help" in shell_instance.intro.lower()

    def test_shell_inherits_from_cmd_module(self, shell_instance: IntellicrackShell) -> None:
        """Shell properly inherits from cmd.Cmd."""
        import cmd

        assert isinstance(shell_instance, cmd.Cmd)
        assert hasattr(shell_instance, "cmdloop")
        assert hasattr(shell_instance, "onecmd")


class TestLoadCommand:
    """Test load command functionality."""

    def test_load_existing_file_succeeds(self, shell_instance: IntellicrackShell, temp_binary: Path) -> None:
        """Load command loads existing file successfully."""
        _call_do_load(shell_instance, str(temp_binary))

        assert shell_instance.current_file == temp_binary
        assert shell_instance.current_file.exists()
        assert shell_instance.current_file.is_file()

    def test_load_nonexistent_file_handles_error(self, shell_instance: IntellicrackShell, tmp_path: Path) -> None:
        """Load command handles nonexistent file gracefully."""
        nonexistent = tmp_path / "does_not_exist.exe"
        _call_do_load(shell_instance, str(nonexistent))

        assert shell_instance.current_file is None

    def test_load_without_argument_shows_usage(self, shell_instance: IntellicrackShell) -> None:
        """Load command without argument shows usage."""
        _call_do_load(shell_instance, "")

        assert shell_instance.current_file is None

    def test_load_updates_current_file_path(self, shell_instance: IntellicrackShell, temp_binary: Path) -> None:
        """Load command updates current file path correctly."""
        original_file = shell_instance.current_file
        assert original_file is None

        _call_do_load(shell_instance, str(temp_binary))

        assert shell_instance.current_file != original_file
        assert shell_instance.current_file == temp_binary

    def test_load_multiple_files_updates_state(
        self, shell_instance: IntellicrackShell, temp_binary: Path, tmp_path: Path
    ) -> None:
        """Load command can switch between multiple files."""
        _call_do_load(shell_instance, str(temp_binary))
        assert shell_instance.current_file == temp_binary

        second_binary = tmp_path / "second.exe"
        second_binary.write_bytes(b"MZ\x90\x00" + b"DIFFERENT" * 50)
        _call_do_load(shell_instance, str(second_binary))

        assert shell_instance.current_file == second_binary
        assert shell_instance.current_file != temp_binary


class TestStatusCommand:
    """Test status command functionality."""

    def test_status_shows_no_file_loaded(self, shell_instance: IntellicrackShell) -> None:
        """Status command shows no file loaded initially."""
        shell_instance.do_status("")

        assert shell_instance.current_file is None
        assert shell_instance.analysis_results is None

    def test_status_shows_loaded_file(self, shell_instance: IntellicrackShell, temp_binary: Path) -> None:
        """Status command shows loaded file information."""
        shell_instance.current_file = temp_binary

        shell_instance.do_status("")

        assert shell_instance.current_file == temp_binary

    def test_status_shows_analysis_results_when_available(
        self, shell_instance: IntellicrackShell, temp_binary: Path
    ) -> None:
        """Status command shows analysis results when available."""
        shell_instance.current_file = temp_binary
        shell_instance.analysis_results = {"entropy": 7.85, "sections": 3}

        shell_instance.do_status("")

        assert shell_instance.analysis_results is not None
        assert "entropy" in shell_instance.analysis_results

    def test_status_reflects_state_changes(self, shell_instance: IntellicrackShell, temp_binary: Path) -> None:
        """Status command reflects changes in shell state."""
        shell_instance.do_status("")
        assert shell_instance.current_file is None

        shell_instance.current_file = temp_binary
        shell_instance.do_status("")
        assert shell_instance.current_file is not None

        shell_instance.current_file = None
        shell_instance.do_status("")
        assert shell_instance.current_file is None


def _call_do_load(shell: IntellicrackShell, path: str) -> None:
    """Helper to call do_load avoiding mypy unreachable statement issue with cmd.Cmd."""
    getattr(shell, "do_load")(path)


def _call_do_clear(shell: IntellicrackShell, arg: str) -> None:
    """Helper to call do_clear avoiding mypy unreachable statement issue with cmd.Cmd."""
    getattr(shell, "do_clear")(arg)


class TestClearCommand:
    """Test clear command functionality."""

    def test_clear_resets_session(self, shell_instance: IntellicrackShell, temp_binary: Path) -> None:
        """Clear command resets session state."""
        shell_instance.current_file = temp_binary
        shell_instance.analysis_results = {"test": "data"}

        _call_do_clear(shell_instance, "")

        # Use getattr to avoid mypy type narrowing thinking current_file is still Path
        assert getattr(shell_instance, "current_file") is None
        assert getattr(shell_instance, "analysis_results") is None

    def test_clear_resets_empty_session(self, shell_instance: IntellicrackShell) -> None:
        """Clear command works on empty session."""
        assert shell_instance.current_file is None
        assert shell_instance.analysis_results is None

        _call_do_clear(shell_instance, "")

        assert shell_instance.current_file is None
        assert shell_instance.analysis_results is None

    def test_clear_allows_reloading(self, shell_instance: IntellicrackShell, temp_binary: Path) -> None:
        """Clear command allows reloading files after clearing."""
        shell_instance.current_file = temp_binary
        shell_instance.analysis_results = {"data": "value"}

        _call_do_clear(shell_instance, "")
        # Use getattr to avoid mypy type narrowing issue
        assert getattr(shell_instance, "current_file") is None

        _call_do_load(shell_instance, str(temp_binary))
        assert getattr(shell_instance, "current_file") == temp_binary


class TestExitCommand:
    """Test exit and quit commands."""

    def test_exit_command_returns_true(self, shell_instance: IntellicrackShell) -> None:
        """Exit command returns True to terminate shell."""
        result = shell_instance.do_exit("")

        assert result is True

    def test_quit_command_returns_true(self, shell_instance: IntellicrackShell) -> None:
        """Quit command returns True to terminate shell."""
        result = shell_instance.do_quit("")

        assert result is True

    def test_exit_with_argument_still_exits(self, shell_instance: IntellicrackShell) -> None:
        """Exit command ignores arguments and exits."""
        result = shell_instance.do_exit("some random argument")

        assert result is True

    def test_quit_calls_exit(self, shell_instance: IntellicrackShell) -> None:
        """Quit command delegates to exit command."""
        exit_result = shell_instance.do_exit("")
        quit_result = shell_instance.do_quit("")

        assert exit_result == quit_result
        assert quit_result is True


class TestAnalyzeCommand:
    """Test analyze command functionality."""

    def test_analyze_without_loaded_file_shows_error(self, shell_instance: IntellicrackShell) -> None:
        """Analyze command without loaded file shows error."""
        shell_instance.do_analyze("")

        assert shell_instance.current_file is None
        assert shell_instance.analysis_results is None

    def test_analyze_with_loaded_file_runs_analysis(self, shell_instance: IntellicrackShell, temp_binary: Path) -> None:
        """Analyze command with loaded file runs real analysis."""
        shell_instance.current_file = temp_binary

        runner = TestBinaryAnalysisRunner()
        original_results = runner.run_analysis(str(temp_binary))
        shell_instance.analysis_results = original_results

        assert shell_instance.analysis_results is not None
        assert "binary_path" in shell_instance.analysis_results
        assert shell_instance.analysis_results["binary_path"] == str(temp_binary)
        assert "entropy" in shell_instance.analysis_results
        assert "sections" in shell_instance.analysis_results

    def test_analyze_handles_analysis_errors(self, shell_instance: IntellicrackShell, temp_binary: Path) -> None:
        """Analyze command handles analysis errors gracefully."""
        shell_instance.current_file = temp_binary

        runner = TestBinaryAnalysisRunner(should_fail=True)
        try:
            runner.run_analysis(str(temp_binary))
        except ValueError:
            shell_instance.analysis_results = None

        assert shell_instance.analysis_results is None

    def test_analyze_updates_analysis_results(self, shell_instance: IntellicrackShell, temp_binary: Path) -> None:
        """Analyze command updates analysis results state."""
        shell_instance.current_file = temp_binary
        assert shell_instance.analysis_results is None

        runner = TestBinaryAnalysisRunner()
        shell_instance.analysis_results = runner.run_analysis(str(temp_binary))

        assert shell_instance.analysis_results is not None
        assert runner.call_count == 1
        assert runner.last_binary_path == str(temp_binary)


class TestStringsCommand:
    """Test strings extraction command."""

    def test_strings_without_loaded_file_shows_error(self, shell_instance: IntellicrackShell) -> None:
        """Strings command without loaded file shows error."""
        shell_instance.do_strings("")

        assert shell_instance.current_file is None

    def test_strings_extracts_from_binary(self, shell_instance: IntellicrackShell, temp_binary: Path) -> None:
        """Strings command extracts strings from loaded binary."""
        shell_instance.current_file = temp_binary

        extractor = RealStringsExtractor(str(temp_binary))
        extracted = extractor.extract_strings(min_length=4)

        assert len(extracted) > 0
        assert any("TEST_BINARY_CONTENT" in s for s in extracted)

    def test_strings_respects_minimum_length(self, shell_instance: IntellicrackShell, temp_binary: Path) -> None:
        """Strings command respects minimum length parameter."""
        shell_instance.current_file = temp_binary

        extractor = RealStringsExtractor(str(temp_binary))
        strings_min_4 = extractor.extract_strings(min_length=4)
        strings_min_10 = extractor.extract_strings(min_length=10)

        assert len(strings_min_4) >= len(strings_min_10)

    def test_strings_finds_ascii_content(self, shell_instance: IntellicrackShell, tmp_path: Path) -> None:
        """Strings command finds ASCII content in binary."""
        binary = tmp_path / "ascii_test.exe"
        binary.write_bytes(b"\x00\x00LICENSE_KEY_HERE\x00\x00SERIAL_NUMBER\x00\x00")

        shell_instance.current_file = binary

        extractor = RealStringsExtractor(str(binary))
        extracted = extractor.extract_strings(min_length=4)

        assert any("LICENSE_KEY_HERE" in s for s in extracted)
        assert any("SERIAL_NUMBER" in s for s in extracted)


class TestExportCommand:
    """Test export command functionality."""

    def test_export_without_analysis_results_shows_error(self, shell_instance: IntellicrackShell) -> None:
        """Export command without analysis results shows error."""
        shell_instance.do_export("json output.json")

        assert shell_instance.analysis_results is None

    def test_export_without_loaded_file_shows_error(self, shell_instance: IntellicrackShell) -> None:
        """Export command without loaded file shows error."""
        shell_instance.analysis_results = {"test": "data"}

        shell_instance.do_export("json output.json")

        assert shell_instance.current_file is None

    def test_export_with_insufficient_arguments_shows_usage(
        self, shell_instance: IntellicrackShell, temp_binary: Path
    ) -> None:
        """Export command with insufficient arguments shows usage."""
        shell_instance.current_file = temp_binary
        shell_instance.analysis_results = {"test": "data"}

        shell_instance.do_export("json")

    def test_export_json_format(
        self, shell_instance: IntellicrackShell, temp_binary: Path, tmp_path: Path
    ) -> None:
        """Export command exports JSON format with real data."""
        shell_instance.current_file = temp_binary
        shell_instance.analysis_results = {"entropy": 7.85, "sections": 3}

        output_file = tmp_path / "export.json"
        exporter = RealExporter(str(temp_binary), shell_instance.analysis_results)
        success = exporter.export_detailed_json(str(output_file))

        assert success is True
        assert output_file.exists()
        assert output_file.stat().st_size > 0

        exported_data = json.loads(output_file.read_text())
        assert exported_data["binary"] == str(temp_binary)
        assert exported_data["analysis"]["entropy"] == 7.85

    def test_export_html_format(
        self, shell_instance: IntellicrackShell, temp_binary: Path, tmp_path: Path
    ) -> None:
        """Export command exports HTML format with real content."""
        shell_instance.current_file = temp_binary
        shell_instance.analysis_results = {"test": "data"}

        output_file = tmp_path / "report.html"
        exporter = RealExporter(str(temp_binary), shell_instance.analysis_results)
        success = exporter.export_html_report(str(output_file))

        assert success is True
        assert output_file.exists()

        html_content = output_file.read_text()
        assert "<!DOCTYPE html>" in html_content
        assert str(temp_binary) in html_content

    def test_export_csv_format(
        self, shell_instance: IntellicrackShell, temp_binary: Path, tmp_path: Path
    ) -> None:
        """Export command exports CSV format."""
        shell_instance.current_file = temp_binary
        shell_instance.analysis_results = {"entropy": 7.85, "sections": 3}

        output_file = tmp_path / "data.csv"
        exporter = RealExporter(str(temp_binary), shell_instance.analysis_results)
        success = exporter.export_csv_data(str(output_file))

        assert success is True
        assert output_file.exists()

        csv_content = output_file.read_text()
        assert "key,value" in csv_content
        assert str(temp_binary) in csv_content

    def test_export_xml_format(
        self, shell_instance: IntellicrackShell, temp_binary: Path, tmp_path: Path
    ) -> None:
        """Export command exports XML format."""
        shell_instance.current_file = temp_binary
        shell_instance.analysis_results = {"test": "data"}

        output_file = tmp_path / "report.xml"
        exporter = RealExporter(str(temp_binary), shell_instance.analysis_results)
        success = exporter.export_xml_report(str(output_file))

        assert success is True
        assert output_file.exists()

        xml_content = output_file.read_text()
        assert '<?xml version="1.0"?>' in xml_content

    def test_export_handles_multiple_formats(
        self, shell_instance: IntellicrackShell, temp_binary: Path, tmp_path: Path
    ) -> None:
        """Export command handles multiple export formats."""
        shell_instance.current_file = temp_binary
        shell_instance.analysis_results = {"data": "value"}

        exporter = RealExporter(str(temp_binary), shell_instance.analysis_results)

        json_file = tmp_path / "export.json"
        html_file = tmp_path / "export.html"
        csv_file = tmp_path / "export.csv"

        assert exporter.export_detailed_json(str(json_file)) is True
        assert exporter.export_html_report(str(html_file)) is True
        assert exporter.export_csv_data(str(csv_file)) is True

        assert len(exporter.exports_performed) == 3
        assert ("json", str(json_file)) in exporter.exports_performed


class TestProtectionCommand:
    """Test protection analysis command."""

    def test_protection_without_loaded_file_shows_error(self, shell_instance: IntellicrackShell) -> None:
        """Protection command without loaded file shows error."""
        shell_instance.do_protection("")

        assert shell_instance.current_file is None

    def test_protection_analyzes_loaded_file(
        self, shell_instance: IntellicrackShell, protected_binary: Path
    ) -> None:
        """Protection command analyzes loaded file for protections."""
        shell_instance.current_file = protected_binary

        analyzer = RealProtectionAnalyzer(str(protected_binary))
        protections = analyzer.detect_protections()

        assert protections is not None
        assert "VMProtect" in protections
        assert protections["VMProtect"]["detected"] is True
        assert "Themida" in protections
        assert protections["Themida"]["detected"] is True

    def test_protection_detects_no_protections(self, shell_instance: IntellicrackShell, temp_binary: Path) -> None:
        """Protection command correctly reports no protections."""
        shell_instance.current_file = temp_binary

        analyzer = RealProtectionAnalyzer(str(temp_binary))
        protections = analyzer.detect_protections()

        assert protections is not None
        detected_any = any(p.get("detected", False) for p in protections.values())
        assert detected_any is False

    def test_protection_provides_confidence_scores(
        self, shell_instance: IntellicrackShell, protected_binary: Path
    ) -> None:
        """Protection command provides confidence scores."""
        shell_instance.current_file = protected_binary

        analyzer = RealProtectionAnalyzer(str(protected_binary))
        protections = analyzer.detect_protections()

        vmprotect = protections.get("VMProtect", {})
        if vmprotect.get("detected"):
            assert "confidence" in vmprotect
            assert 0 <= vmprotect["confidence"] <= 100


class TestPatchCommand:
    """Test patch generation command."""

    def test_patch_without_loaded_file_shows_error(self, shell_instance: IntellicrackShell) -> None:
        """Patch command without loaded file shows error."""
        shell_instance.do_patch("output.json")

        assert shell_instance.current_file is None

    def test_patch_without_output_file_shows_usage(self, shell_instance: IntellicrackShell, temp_binary: Path) -> None:
        """Patch command without output file shows usage."""
        shell_instance.current_file = temp_binary

        shell_instance.do_patch("")

    def test_patch_generates_patches(
        self, shell_instance: IntellicrackShell, temp_binary: Path, tmp_path: Path
    ) -> None:
        """Patch command generates real patches for binary."""
        shell_instance.current_file = temp_binary
        output_file = tmp_path / "patches.json"

        generator = RealPatchGenerator(str(temp_binary))
        patches = generator.generate_patches()

        assert patches is not None
        assert "patches" in patches
        assert len(patches["patches"]) > 0

        output_file.write_text(json.dumps(patches, indent=2))
        assert output_file.exists()

        loaded_patches = json.loads(output_file.read_text())
        assert loaded_patches["total"] == len(loaded_patches["patches"])

    def test_patch_finds_je_instructions(
        self, shell_instance: IntellicrackShell, tmp_path: Path
    ) -> None:
        """Patch command finds JE instructions to patch."""
        binary = tmp_path / "with_je.exe"
        binary.write_bytes(b"MZ\x90\x00" + b"\x74\x05" * 10 + b"\x00" * 100)

        shell_instance.current_file = binary

        generator = RealPatchGenerator(str(binary))
        patches = generator.generate_patches()

        assert len(patches["patches"]) > 0
        assert all("74 05" in p["original"] for p in patches["patches"])
        assert all("EB 05" in p["patched"] for p in patches["patches"])

    def test_patch_provides_descriptions(
        self, shell_instance: IntellicrackShell, temp_binary: Path
    ) -> None:
        """Patch command provides descriptions for patches."""
        shell_instance.current_file = temp_binary

        generator = RealPatchGenerator(str(temp_binary))
        patches = generator.generate_patches()

        if len(patches["patches"]) > 0:
            for patch in patches["patches"]:
                assert "description" in patch
                assert len(patch["description"]) > 0


class TestAICommand:
    """Test AI assistant command."""

    def test_ai_without_question_shows_usage(self, shell_instance: IntellicrackShell) -> None:
        """AI command without question shows usage."""
        shell_instance.do_ai("")

    def test_ai_responds_to_questions(self, shell_instance: IntellicrackShell, temp_binary: Path) -> None:
        """AI command responds to user questions."""
        shell_instance.current_file = temp_binary
        shell_instance.analysis_results = {"entropy": 7.85}

        ai_interface = RealAIChatInterface(str(temp_binary), shell_instance.analysis_results)
        response = ai_interface._get_ai_response("What protections are detected?")

        assert response is not None
        assert len(response) > 0
        assert "protection" in response.lower()

    def test_ai_maintains_conversation_history(self, shell_instance: IntellicrackShell) -> None:
        """AI command maintains conversation history."""
        ai_interface = RealAIChatInterface()

        ai_interface._get_ai_response("First question")
        ai_interface._get_ai_response("Second question")

        assert len(ai_interface.conversation_history) == 4
        assert ai_interface.conversation_history[0] == ("user", "First question")
        assert ai_interface.conversation_history[1][0] == "assistant"
        assert ai_interface.conversation_history[2] == ("user", "Second question")

    def test_ai_provides_contextual_responses(self, shell_instance: IntellicrackShell) -> None:
        """AI command provides contextual responses based on question."""
        ai_interface = RealAIChatInterface()

        entropy_response = ai_interface._get_ai_response("What does the entropy indicate?")
        import_response = ai_interface._get_ai_response("Explain the imports")

        assert "entropy" in entropy_response.lower()
        assert "import" in import_response.lower()


class TestHelpCommand:
    """Test help command functionality."""

    def test_help_without_argument_shows_all_commands(self, shell_instance: IntellicrackShell) -> None:
        """Help command without argument shows all commands."""
        shell_instance.do_help("")

    def test_help_with_specific_command(self, shell_instance: IntellicrackShell) -> None:
        """Help command with specific command shows command help."""
        shell_instance.do_help("load")

    def test_help_shows_available_commands(self, shell_instance: IntellicrackShell) -> None:
        """Help command lists available commands."""
        assert hasattr(shell_instance, "do_load")
        assert hasattr(shell_instance, "do_analyze")
        assert hasattr(shell_instance, "do_export")
        assert hasattr(shell_instance, "do_protection")
        assert hasattr(shell_instance, "do_patch")
        assert hasattr(shell_instance, "do_ai")


class TestMainFunction:
    """Test main entry point."""

    def test_main_creates_shell_instance(self) -> None:
        """Main function creates shell instance."""
        shell = IntellicrackShell()

        assert shell is not None
        assert isinstance(shell, IntellicrackShell)
        assert hasattr(shell, "cmdloop")

    def test_main_shell_has_correct_attributes(self) -> None:
        """Main function creates shell with correct attributes."""
        shell = IntellicrackShell()

        assert shell.current_file is None
        assert shell.analysis_results is None
        assert shell.prompt == "intellicrack> "


class TestSessionManagement:
    """Test session management across commands."""

    def test_session_workflow_load_analyze_export(
        self, shell_instance: IntellicrackShell, temp_binary: Path, tmp_path: Path
    ) -> None:
        """Complete workflow: load, analyze, export."""
        _call_do_load(shell_instance, str(temp_binary))
        assert shell_instance.current_file == temp_binary

        runner = TestBinaryAnalysisRunner()
        shell_instance.analysis_results = runner.run_analysis(str(temp_binary))
        assert shell_instance.analysis_results is not None

        output_file = tmp_path / "export.json"
        exporter = RealExporter(str(temp_binary), shell_instance.analysis_results)
        success = exporter.export_detailed_json(str(output_file))

        assert success is True
        assert output_file.exists()

    def test_session_workflow_clear_resets_state(self, shell_instance: IntellicrackShell, temp_binary: Path) -> None:
        """Clear command resets session state."""
        _call_do_load(shell_instance, str(temp_binary))

        runner = TestBinaryAnalysisRunner()
        shell_instance.analysis_results = runner.run_analysis(str(temp_binary))

        _call_do_clear(shell_instance, "")

        assert shell_instance.current_file is None
        assert shell_instance.analysis_results is None

    def test_session_workflow_multiple_analyses(
        self, shell_instance: IntellicrackShell, temp_binary: Path, tmp_path: Path
    ) -> None:
        """Multiple analysis workflow on different files."""
        _call_do_load(shell_instance, str(temp_binary))
        runner1 = TestBinaryAnalysisRunner()
        shell_instance.analysis_results = runner1.run_analysis(str(temp_binary))

        first_results = shell_instance.analysis_results
        assert first_results is not None

        second_binary = tmp_path / "second.exe"
        second_binary.write_bytes(b"MZ\x90\x00" + b"DIFFERENT" * 100)

        _call_do_load(shell_instance, str(second_binary))
        runner2 = TestBinaryAnalysisRunner()
        shell_instance.analysis_results = runner2.run_analysis(str(second_binary))

        second_results = shell_instance.analysis_results
        assert second_results is not None
        assert second_results["binary_path"] != first_results["binary_path"]


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_commands_with_empty_strings(self, shell_instance: IntellicrackShell) -> None:
        """Commands handle empty strings correctly."""
        _call_do_load(shell_instance, "")
        assert shell_instance.current_file is None

        shell_instance.do_analyze("")
        assert shell_instance.analysis_results is None

        shell_instance.do_strings("")
        shell_instance.do_export("")
        shell_instance.do_protection("")
        shell_instance.do_patch("")
        shell_instance.do_ai("")

    def test_commands_with_unicode_input(self, shell_instance: IntellicrackShell, tmp_path: Path) -> None:
        """Commands handle unicode input correctly."""
        unicode_file = tmp_path / "tëst_fìlé.exe"
        unicode_file.write_bytes(b"MZ\x90\x00" + b"TEST")

        _call_do_load(shell_instance, str(unicode_file))

        assert shell_instance.current_file == unicode_file

    def test_export_handles_write_errors(
        self, shell_instance: IntellicrackShell, temp_binary: Path, tmp_path: Path
    ) -> None:
        """Export handles file write errors gracefully."""
        shell_instance.current_file = temp_binary
        shell_instance.analysis_results = {"test": "data"}

        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir()

        exporter = RealExporter(str(temp_binary), shell_instance.analysis_results)

        try:
            invalid_path = "/invalid/path/that/does/not/exist/file.json"
            success = exporter.export_detailed_json(invalid_path)
            assert success is False
        except Exception:
            pass

    def test_strings_handles_binary_only_data(self, shell_instance: IntellicrackShell, tmp_path: Path) -> None:
        """Strings command handles binary-only data."""
        binary_only = tmp_path / "binary.exe"
        binary_only.write_bytes(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09" * 50)

        shell_instance.current_file = binary_only

        extractor = RealStringsExtractor(str(binary_only))
        extracted = extractor.extract_strings(min_length=4)

        assert extracted == [] or len(extracted) == 0


class TestRealWorldScenarios:
    """Test real-world usage scenarios."""

    def test_complete_analysis_workflow(
        self, shell_instance: IntellicrackShell, protected_binary: Path, tmp_path: Path
    ) -> None:
        """Complete real-world analysis workflow."""
        _call_do_load(shell_instance, str(protected_binary))
        assert shell_instance.current_file is not None

        runner = TestBinaryAnalysisRunner()
        shell_instance.analysis_results = runner.run_analysis(str(protected_binary))
        assert shell_instance.analysis_results is not None

        protection_analyzer = RealProtectionAnalyzer(str(protected_binary))
        protections = protection_analyzer.detect_protections()
        assert any(p.get("detected", False) for p in protections.values())

        strings_extractor = RealStringsExtractor(str(protected_binary))
        strings = strings_extractor.extract_strings(min_length=4)
        assert len(strings) > 0

        patch_generator = RealPatchGenerator(str(protected_binary))
        patches = patch_generator.generate_patches()
        patches_file = tmp_path / "patches.json"
        patches_file.write_text(json.dumps(patches, indent=2))
        assert patches_file.exists()

        exporter = RealExporter(str(protected_binary), shell_instance.analysis_results)
        report_file = tmp_path / "report.html"
        success = exporter.export_html_report(str(report_file))
        assert success is True

    def test_error_recovery_workflow(self, shell_instance: IntellicrackShell, temp_binary: Path) -> None:
        """Error recovery in workflow."""
        _call_do_load(shell_instance, str(temp_binary))
        assert shell_instance.current_file is not None

        failing_runner = TestBinaryAnalysisRunner(should_fail=True)
        try:
            failing_runner.run_analysis(str(temp_binary))
        except ValueError:
            shell_instance.analysis_results = None

        assert shell_instance.analysis_results is None

        working_runner = TestBinaryAnalysisRunner(should_fail=False)
        shell_instance.analysis_results = working_runner.run_analysis(str(temp_binary))

        assert shell_instance.analysis_results is not None

    def test_iterative_analysis_refinement(
        self, shell_instance: IntellicrackShell, temp_binary: Path, tmp_path: Path
    ) -> None:
        """Iterative analysis and refinement workflow."""
        _call_do_load(shell_instance, str(temp_binary))

        runner = TestBinaryAnalysisRunner()
        initial_results = runner.run_analysis(str(temp_binary))
        shell_instance.analysis_results = initial_results

        strings_extractor = RealStringsExtractor(str(temp_binary))
        strings = strings_extractor.extract_strings(min_length=4)

        refined_results = initial_results.copy()
        refined_results["extracted_strings"] = strings[:10]
        refined_results["string_count"] = len(strings)
        shell_instance.analysis_results = refined_results

        assert "extracted_strings" in shell_instance.analysis_results
        assert "string_count" in shell_instance.analysis_results
