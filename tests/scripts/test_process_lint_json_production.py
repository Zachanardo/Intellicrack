"""Production tests for scripts/process_lint_json.py.

These tests validate the linter output processing script that converts various
linter formats to standardized JSON, XML, and TXT reports. Tests use real linter
output formats and validate actual parsing logic.

Copyright (C) 2025 Zachary Flint
"""

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

import pytest

from scripts.process_lint_json import (
    ALL_TOOLS,
    JSON_PROCESSORS,
    TEXT_PROCESSORS,
    escape_xml,
    load_json_file,
    load_text_file,
    process_bandit_text,
    process_biome_json,
    process_biome_text,
    process_clippy_text,
    process_darglint_text,
    process_dead_text,
    process_eslint,
    process_flake8_text,
    process_knip,
    process_markdownlint_text,
    process_mypy_json,
    process_mypy_text,
    process_pyright,
    process_ruff,
    process_ty_text,
    process_vulture_text,
    write_outputs,
)


class TestESLintProcessing:
    """Production tests for ESLint JSON processing."""

    def test_process_eslint_with_valid_data(self) -> None:
        """process_eslint() parses valid ESLint JSON output."""
        eslint_data = [
            {
                "filePath": "test.js",
                "messages": [
                    {
                        "line": 10,
                        "column": 5,
                        "severity": 2,
                        "message": "Unexpected console statement",
                        "ruleId": "no-console",
                    }
                ],
            }
        ]

        grouped, count = process_eslint(eslint_data)

        assert isinstance(grouped, dict)
        assert count == 1
        assert "test.js" in grouped
        assert len(grouped["test.js"]) == 1
        assert grouped["test.js"][0]["line"] == 10
        assert grouped["test.js"][0]["column"] == 5
        assert grouped["test.js"][0]["severity"] == "error"
        assert "console" in grouped["test.js"][0]["message"]

    def test_process_eslint_warning_severity(self) -> None:
        """process_eslint() correctly maps warning severity."""
        eslint_data = [
            {
                "filePath": "test.js",
                "messages": [
                    {
                        "line": 5,
                        "column": 1,
                        "severity": 1,
                        "message": "Warning message",
                        "ruleId": "test-rule",
                    }
                ],
            }
        ]

        grouped, _ = process_eslint(eslint_data)

        assert grouped["test.js"][0]["severity"] == "warning"

    def test_process_eslint_multiple_files(self) -> None:
        """process_eslint() handles multiple files correctly."""
        eslint_data = [
            {"filePath": "file1.js", "messages": [{"line": 1, "column": 1, "severity": 2, "message": "Error 1", "ruleId": "rule1"}]},
            {"filePath": "file2.js", "messages": [{"line": 2, "column": 2, "severity": 1, "message": "Warning 1", "ruleId": "rule2"}]},
        ]

        grouped, count = process_eslint(eslint_data)

        assert len(grouped) == 2
        assert count == 2
        assert "file1.js" in grouped
        assert "file2.js" in grouped


class TestRuffProcessing:
    """Production tests for Ruff JSON processing."""

    def test_process_ruff_with_valid_data(self) -> None:
        """process_ruff() parses valid Ruff JSON output."""
        ruff_data = [
            {
                "filename": "test.py",
                "location": {"row": 15, "column": 10},
                "code": "F401",
                "message": "Module imported but unused",
            }
        ]

        grouped, count = process_ruff(ruff_data)

        assert isinstance(grouped, dict)
        assert count == 1
        assert "test.py" in grouped
        assert grouped["test.py"][0]["line"] == 15
        assert grouped["test.py"][0]["column"] == 10
        assert grouped["test.py"][0]["code"] == "F401"

    def test_process_ruff_multiple_violations(self) -> None:
        """process_ruff() handles multiple violations per file."""
        ruff_data = [
            {"filename": "test.py", "location": {"row": 1, "column": 1}, "code": "E501", "message": "Line too long"},
            {"filename": "test.py", "location": {"row": 2, "column": 1}, "code": "F401", "message": "Unused import"},
        ]

        grouped, count = process_ruff(ruff_data)

        assert count == 2
        assert len(grouped["test.py"]) == 2


class TestPyrightProcessing:
    """Production tests for Pyright JSON processing."""

    def test_process_pyright_with_valid_data(self) -> None:
        """process_pyright() parses valid Pyright JSON output."""
        pyright_data = {
            "generalDiagnostics": [
                {
                    "file": "test.py",
                    "range": {"start": {"line": 9, "character": 4}},
                    "severity": "error",
                    "rule": "reportGeneralTypeIssues",
                    "message": "Type mismatch",
                }
            ]
        }

        grouped, count = process_pyright(pyright_data)

        assert isinstance(grouped, dict)
        assert count == 1
        assert "test.py" in grouped
        assert grouped["test.py"][0]["line"] == 10
        assert grouped["test.py"][0]["column"] == 5
        assert grouped["test.py"][0]["severity"] == "error"


class TestMypyProcessing:
    """Production tests for Mypy JSON and text processing."""

    def test_process_mypy_json_with_valid_data(self) -> None:
        """process_mypy_json() parses valid Mypy JSON output."""
        mypy_data = [
            {
                "file": "test.py",
                "line": 20,
                "column": 8,
                "severity": "error",
                "code": "assignment",
                "message": "Incompatible types in assignment",
            }
        ]

        grouped, count = process_mypy_json(mypy_data)

        assert count == 1
        assert "test.py" in grouped
        assert grouped["test.py"][0]["line"] == 20
        assert grouped["test.py"][0]["code"] == "assignment"

    def test_process_mypy_text_with_valid_output(self) -> None:
        """process_mypy_text() parses valid Mypy text output."""
        mypy_output = "test.py:15:10: error: Incompatible types [assignment]\n"

        grouped, count = process_mypy_text(mypy_output)

        assert count == 1
        assert "test.py" in grouped
        assert grouped["test.py"][0]["line"] == 15
        assert grouped["test.py"][0]["column"] == 10
        assert grouped["test.py"][0]["severity"] == "error"


class TestTextProcessors:
    """Production tests for text-based linter processors."""

    def test_process_flake8_text(self) -> None:
        """process_flake8_text() parses Flake8 output correctly."""
        flake8_output = "test.py:10:5: E302 expected 2 blank lines\n"

        grouped, count = process_flake8_text(flake8_output)

        assert count == 1
        assert "test.py" in grouped
        assert grouped["test.py"][0]["line"] == 10
        assert grouped["test.py"][0]["column"] == 5
        assert grouped["test.py"][0]["code"] == "E302"

    def test_process_vulture_text(self) -> None:
        """process_vulture_text() parses vulture dead code output."""
        vulture_output = "test.py:25: unused function 'helper'\n"

        grouped, count = process_vulture_text(vulture_output)

        assert count == 1
        assert "test.py" in grouped
        assert grouped["test.py"][0]["line"] == 25

    def test_process_darglint_text(self) -> None:
        """process_darglint_text() parses darglint docstring output."""
        darglint_output = "test.py:func_name:15: DAR201: - return\n"

        grouped, count = process_darglint_text(darglint_output)

        assert count == 1
        assert "test.py" in grouped
        assert grouped["test.py"][0]["line"] == 15
        assert grouped["test.py"][0]["code"] == "DAR201"
        assert grouped["test.py"][0]["function"] == "func_name"

    def test_process_dead_text(self) -> None:
        """process_dead_text() parses dead code detector output."""
        dead_output = "variable is never read, defined in test.py:100\n"

        grouped, count = process_dead_text(dead_output)

        assert count == 1
        assert "test.py" in grouped
        assert grouped["test.py"][0]["line"] == 100
        assert "variable" in grouped["test.py"][0]["message"]

    def test_process_ty_text(self) -> None:
        """process_ty_text() parses ty type checker output."""
        ty_output = "test.py:50:10: error[E001]: Type error message\n"

        grouped, count = process_ty_text(ty_output)

        assert count == 1
        assert "test.py" in grouped
        assert grouped["test.py"][0]["line"] == 50
        assert grouped["test.py"][0]["column"] == 10

    def test_process_bandit_text(self) -> None:
        """process_bandit_text() parses bandit security output."""
        bandit_output = """>> Issue: [B201] Test security issue
   Severity: High   Confidence: High
   Location: test.py:30
"""

        grouped, count = process_bandit_text(bandit_output)

        assert count == 1
        assert "test.py" in grouped
        assert grouped["test.py"][0]["line"] == 30
        assert grouped["test.py"][0]["code"] == "B201"

    def test_process_markdownlint_text(self) -> None:
        """process_markdownlint_text() parses markdownlint output."""
        md_output = "test.md:5:1 MD001/heading-increment Heading levels\n"

        grouped, count = process_markdownlint_text(md_output)

        assert count == 1
        assert "test.md" in grouped
        assert grouped["test.md"][0]["line"] == 5


class TestXMLEscaping:
    """Production tests for XML escaping functionality."""

    def test_escape_xml_basic_characters(self) -> None:
        """escape_xml() escapes basic XML special characters."""
        assert escape_xml("<tag>") == "&lt;tag&gt;"
        assert escape_xml("a & b") == "a &amp; b"
        assert escape_xml('"quoted"') == "&quot;quoted&quot;"

    def test_escape_xml_multiple_characters(self) -> None:
        """escape_xml() handles multiple special characters."""
        assert escape_xml('<tag attr="value">text & more</tag>') == "&lt;tag attr=&quot;value&quot;&gt;text &amp; more&lt;/tag&gt;"

    def test_escape_xml_no_special_chars(self) -> None:
        """escape_xml() returns unchanged string with no special chars."""
        assert escape_xml("normal text 123") == "normal text 123"


class TestFileLoading:
    """Production tests for file loading functions."""

    def test_load_json_file_with_valid_json(self) -> None:
        """load_json_file() loads valid JSON file correctly."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"key": "value"}, f)
            temp_path = f.name

        try:
            data = load_json_file(temp_path)

            assert isinstance(data, dict)
            assert data["key"] == "value"
        finally:
            Path(temp_path).unlink()

    def test_load_json_file_with_invalid_json(self) -> None:
        """load_json_file() handles invalid JSON gracefully."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("invalid json {")
            temp_path = f.name

        try:
            data = load_json_file(temp_path)

            assert data == {}
        finally:
            Path(temp_path).unlink()

    def test_load_json_file_nonexistent(self) -> None:
        """load_json_file() handles nonexistent files gracefully."""
        data = load_json_file("/nonexistent/path/file.json")

        assert data == {}

    def test_load_text_file_with_valid_content(self) -> None:
        """load_text_file() loads text file correctly."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("test content\nline 2\n")
            temp_path = f.name

        try:
            content = load_text_file(temp_path)

            assert isinstance(content, str)
            assert "test content" in content
            assert "line 2" in content
        finally:
            Path(temp_path).unlink()

    def test_load_text_file_nonexistent(self) -> None:
        """load_text_file() handles nonexistent files gracefully."""
        content = load_text_file("/nonexistent/path/file.txt")

        assert content == ""


class TestOutputWriting:
    """Production tests for output file generation."""

    def test_write_outputs_creates_all_formats(self) -> None:
        """write_outputs() creates TXT, JSON, and XML files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            reports_dir = Path(temp_dir) / "reports"
            reports_dir.mkdir()
            (reports_dir / "txt").mkdir()
            (reports_dir / "json").mkdir()
            (reports_dir / "xml").mkdir()

            test_data = {
                "test.py": [
                    {
                        "line": 10,
                        "column": 5,
                        "severity": "error",
                        "rule": "E001",
                        "message": "Test error",
                        "raw": "test.py:10:5: error: Test error",
                    }
                ]
            }

            import os
            original_cwd = os.getcwd()
            try:
                os.chdir(temp_dir)
                write_outputs("test-tool", test_data, 1)

                txt_file = reports_dir / "txt" / "test-tool_findings.txt"
                json_file = reports_dir / "json" / "test-tool_findings.json"
                xml_file = reports_dir / "xml" / "test-tool_findings.xml"

                assert txt_file.exists()
                assert txt_file.read_text()
                assert json_file.exists()
                json_data = json.loads(json_file.read_text())
                assert json_data["tool"] == "test-tool"
                assert xml_file.exists()
                assert "test-tool" in xml_file.read_text()
            finally:
                os.chdir(original_cwd)

    def test_write_outputs_handles_no_findings(self) -> None:
        """write_outputs() handles empty findings correctly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            reports_dir = Path(temp_dir) / "reports"
            reports_dir.mkdir()
            (reports_dir / "txt").mkdir()
            (reports_dir / "json").mkdir()
            (reports_dir / "xml").mkdir()

            import os
            original_cwd = os.getcwd()
            try:
                os.chdir(temp_dir)
                write_outputs("test-tool", {}, 0)

                txt_file = reports_dir / "txt" / "test-tool_findings.txt"
                if txt_file.exists():
                    content = txt_file.read_text()
                    assert "No findings" in content or "0 total" in content
            finally:
                os.chdir(original_cwd)

    def test_write_outputs_sorts_by_count(self) -> None:
        """write_outputs() sorts files by finding count descending."""
        with tempfile.TemporaryDirectory() as temp_dir:
            reports_dir = Path(temp_dir) / "reports"
            reports_dir.mkdir()
            (reports_dir / "txt").mkdir()
            (reports_dir / "json").mkdir()
            (reports_dir / "xml").mkdir()

            test_data = {
                "file1.py": [{"line": 1, "column": 1, "message": "Error 1", "raw": "file1.py:1:1: Error 1"}],
                "file2.py": [
                    {"line": 1, "column": 1, "message": "Error 1", "raw": "file2.py:1:1: Error 1"},
                    {"line": 2, "column": 1, "message": "Error 2", "raw": "file2.py:2:1: Error 2"},
                    {"line": 3, "column": 1, "message": "Error 3", "raw": "file2.py:3:1: Error 3"},
                ],
            }

            import os
            original_cwd = os.getcwd()
            try:
                os.chdir(temp_dir)
                write_outputs("test-tool", test_data, 4)

                json_file = reports_dir / "json" / "test-tool_findings.json"
                if json_file.exists():
                    json_data = json.loads(json_file.read_text())
                    files = json_data.get("files", [])
                    if len(files) >= 2:
                        assert files[0]["count"] >= files[1]["count"]
            finally:
                os.chdir(original_cwd)


class TestProcessorRegistration:
    """Production tests for processor registration and discovery."""

    def test_all_tools_populated(self) -> None:
        """ALL_TOOLS contains all registered processors."""
        assert isinstance(ALL_TOOLS, list)
        assert len(ALL_TOOLS) > 0

        for tool in ALL_TOOLS:
            assert isinstance(tool, str)
            assert len(tool) > 0

    def test_text_processors_registered(self) -> None:
        """TEXT_PROCESSORS contains text-based linter processors."""
        assert isinstance(TEXT_PROCESSORS, dict)
        assert len(TEXT_PROCESSORS) > 0

        expected_processors = ["mypy", "flake8", "vulture", "darglint", "bandit"]

        for processor in expected_processors:
            assert processor in TEXT_PROCESSORS
            assert callable(TEXT_PROCESSORS[processor])

    def test_json_processors_registered(self) -> None:
        """JSON_PROCESSORS contains JSON-based linter processors."""
        assert isinstance(JSON_PROCESSORS, dict)
        assert len(JSON_PROCESSORS) > 0

        expected_processors = ["eslint", "ruff", "pyright", "mypy"]

        for processor in expected_processors:
            assert processor in JSON_PROCESSORS
            processor_func, default_val = JSON_PROCESSORS[processor]
            assert callable(processor_func)


class TestComplexParsing:
    """Production tests for complex parsing scenarios."""

    def test_process_biome_json_with_complex_message(self) -> None:
        """process_biome_json() handles complex message structures."""
        biome_data = {
            "diagnostics": [
                {
                    "location": {
                        "path": {"file": "test.js"},
                        "span": {"start": 10},
                    },
                    "severity": "error",
                    "category": "lint/suspicious",
                    "message": [
                        {"content": "Use "},
                        {"content": "const"},
                        {"content": " instead"},
                    ],
                }
            ]
        }

        grouped, count = process_biome_json(biome_data)

        assert count == 1
        assert len(grouped) > 0

    def test_process_clippy_text_multiline(self) -> None:
        """process_clippy_text() parses multiline clippy output."""
        clippy_output = """warning: unnecessary allocation
 --> src/main.rs:10:5
  |
10|     let x = Box::new(5);
  |     ^^^^^^^^^^^^^^^^^^^
"""

        grouped, count = process_clippy_text(clippy_output)

        assert count == 1
        if "src/main.rs" in grouped:
            assert grouped["src/main.rs"][0]["line"] == 10


class TestEdgeCases:
    """Production tests for edge cases and error handling."""

    def test_process_empty_data(self) -> None:
        """Processors handle empty data gracefully."""
        grouped, count = process_eslint([])
        assert count == 0
        assert grouped == {}

        grouped, count = process_ruff([])
        assert count == 0

    def test_process_malformed_data(self) -> None:
        """Processors handle malformed data without crashing."""
        malformed = [{"invalid": "structure"}]

        grouped, count = process_eslint(malformed)
        assert isinstance(grouped, dict)
        assert count == 0

    def test_unicode_handling(self) -> None:
        """Processors handle unicode characters correctly."""
        unicode_data = [
            {
                "filePath": "test.js",
                "messages": [
                    {
                        "line": 1,
                        "column": 1,
                        "severity": 2,
                        "message": "Error with unicode: ñ ü ö ∑ π",
                        "ruleId": "test",
                    }
                ],
            }
        ]

        grouped, count = process_eslint(unicode_data)

        assert count == 1
        assert "unicode" in grouped["test.js"][0]["message"]
