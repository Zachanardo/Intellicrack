"""Production tests for Pipeline CLI module.

These tests validate that pipeline system correctly:
- Parses multi-stage pipeline commands
- Executes analysis, filter, transform, and output stages
- Passes data between pipeline stages correctly
- Validates input data formats and security
- Handles errors and continues on allowed failures
- Generates correct output in JSON, CSV, and table formats
"""

import json
import tempfile
from pathlib import Path
from typing import Any, cast

import pytest

from intellicrack.cli.pipeline import (
    AnalysisStage,
    FilterStage,
    OutputStage,
    Pipeline,
    PipelineData,
    TransformStage,
    parse_pipeline_command,
)


class FakeBinaryAnalyzer:
    """Real test double for binary analysis."""

    def __init__(self) -> None:
        self.analyze_calls: list[str] = []
        self.should_raise: bool = False
        self.error_message: str = "Analysis error"
        self.result_data: Any = {"file_type": "PE", "arch": "x86"}

    def __call__(self, binary_path: str) -> dict[str, Any]:
        self.analyze_calls.append(binary_path)
        if self.should_raise:
            raise FileNotFoundError(self.error_message)
        if isinstance(self.result_data, dict):
            return self.result_data
        return {"file_type": "PE", "arch": "x86"}


class TestPipelineDataFormat:
    """Test pipeline data structure and serialization."""

    def test_pipeline_data_initialization(self) -> None:
        data = PipelineData(content={"test": "value"}, metadata={"source": "test"}, format="json")

        assert data.content == {"test": "value"}
        assert data.metadata == {"source": "test"}
        assert data.format == "json"

    def test_pipeline_data_to_json(self) -> None:
        data = PipelineData(content={"key": "value"}, metadata={"stage": "analysis"}, format="json")

        json_str = data.to_json()
        parsed = json.loads(json_str)

        assert parsed["content"]["key"] == "value"
        assert parsed["metadata"]["stage"] == "analysis"
        assert parsed["format"] == "json"

    def test_pipeline_data_from_json(self) -> None:
        json_str = '{"content": {"data": "test"}, "metadata": {"type": "analysis"}, "format": "json"}'

        data = PipelineData.from_json(json_str)

        assert data.content == {"data": "test"}
        assert data.metadata == {"type": "analysis"}
        assert data.format == "json"


class TestAnalysisStage:
    """Test analysis pipeline stage."""

    def test_analysis_stage_processes_binary_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        test_binary = tmp_path / "test.exe"
        test_binary.write_bytes(b"MZ\x90\x00" * 10)

        fake_analyzer = FakeBinaryAnalyzer()
        fake_analyzer.result_data = {"file_type": "PE", "arch": "x86"}

        monkeypatch.setattr("intellicrack.utils.analysis.binary_analysis.analyze_binary", fake_analyzer)

        stage = AnalysisStage()
        input_data = PipelineData(content=str(test_binary), metadata={}, format="text")

        output = stage.process(input_data)

        assert output.format == "json"
        assert output.metadata["stage"] == "analysis"
        assert output.metadata["success"] is True

    def test_analysis_stage_handles_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        fake_analyzer = FakeBinaryAnalyzer()
        fake_analyzer.should_raise = True
        fake_analyzer.error_message = "Not found"

        monkeypatch.setattr("intellicrack.utils.analysis.binary_analysis.analyze_binary", fake_analyzer)

        stage = AnalysisStage()
        input_data = PipelineData(content="/nonexistent/file.exe", metadata={}, format="text")

        output = stage.process(input_data)

        assert output.metadata["success"] is False
        assert "error" in output.content

    def test_analysis_stage_validates_input(self) -> None:
        stage = AnalysisStage()

        valid_input = PipelineData(content="test.exe", metadata={}, format="text")
        assert stage.validate_input(valid_input) is True

        invalid_input = cast(PipelineData, "not a PipelineData object")
        assert stage.validate_input(invalid_input) is False


class TestFilterStage:
    """Test filtering pipeline stage."""

    def test_filter_vulnerabilities(self) -> None:
        stage = FilterStage("vulnerability")

        input_data = PipelineData(
            content={
                "vulnerabilities": [
                    {"type": "buffer_overflow", "severity": "high"},
                    {"type": "format_string", "severity": "medium"},
                    {"type": "sql_injection", "severity": "critical"},
                ]
            },
            metadata={},
            format="json",
        )

        output = stage.process(input_data)

        assert output.metadata["filtered"] is True
        assert len(output.content["vulnerabilities"]) == 3

    def test_filter_imports(self) -> None:
        stage = FilterStage("imports")

        input_data = PipelineData(
            content={"imports": ["kernel32.dll!CreateFileW", "user32.dll!MessageBoxA", "advapi32.dll!RegOpenKeyW"]},
            metadata={},
            format="json",
        )

        output = stage.process(input_data)

        assert "imports" in output.content

    def test_filter_high_severity(self) -> None:
        stage = FilterStage("high_severity")

        input_data = PipelineData(
            content=[
                {"name": "vuln1", "severity": "high"},
                {"name": "vuln2", "severity": "low"},
                {"name": "vuln3", "severity": "critical"},
                {"name": "vuln4", "severity": "medium"},
            ],
            metadata={},
            format="json",
        )

        output = stage.process(input_data)

        assert len(output.content) == 2
        assert all(item["severity"] in ["high", "critical"] for item in output.content)

    def test_filter_non_json_passthrough(self) -> None:
        stage = FilterStage("test")
        input_data = PipelineData(content="plain text", metadata={}, format="text")

        output = stage.process(input_data)

        assert output.content == "plain text"


class TestTransformStage:
    """Test transformation pipeline stage."""

    def test_transform_to_csv(self) -> None:
        stage = TransformStage("csv")

        input_data = PipelineData(
            content=[{"name": "vuln1", "severity": "high"}, {"name": "vuln2", "severity": "low"}], metadata={}, format="json"
        )

        output = stage.process(input_data)

        assert output.format == "csv"
        assert "name" in output.content
        assert "severity" in output.content
        assert "vuln1" in output.content

    def test_transform_to_table(self) -> None:
        stage = TransformStage("table")

        input_data = PipelineData(content={"file_type": "PE", "arch": "x86"}, metadata={}, format="json")

        output = stage.process(input_data)

        assert output.format == "text"
        assert len(output.content) > 0

    def test_transform_to_summary(self) -> None:
        stage = TransformStage("summary")

        input_data = PipelineData(
            content={"vulnerabilities": [1, 2, 3], "protections": {"aslr": True, "dep": False}}, metadata={}, format="json"
        )

        output = stage.process(input_data)

        assert output.format == "text"
        assert "Dictionary" in output.content or "items" in output.content

    def test_transform_invalid_format_passthrough(self) -> None:
        stage = TransformStage("unknown")
        input_data = PipelineData(content={"test": "data"}, metadata={}, format="json")

        output = stage.process(input_data)

        assert output.format == "json"


class TestOutputStage:
    """Test output pipeline stage."""

    def test_output_to_file_json(self, tmp_path: Path) -> None:
        output_file = tmp_path / "output.json"
        stage = OutputStage(str(output_file))

        input_data = PipelineData(content={"result": "success"}, metadata={}, format="json")

        output = stage.process(input_data)

        assert output_file.exists()

        with open(output_file) as f:
            data = json.load(f)
        assert data["result"] == "success"

    def test_output_to_file_text(self, tmp_path: Path) -> None:
        output_file = tmp_path / "output.txt"
        stage = OutputStage(str(output_file))

        input_data = PipelineData(content="Test output text", metadata={}, format="text")

        output = stage.process(input_data)

        assert output_file.exists()
        assert output_file.read_text() == "Test output text"

    def test_output_to_stdout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        printed_outputs: list[Any] = []

        def fake_print(*args: Any, **kwargs: Any) -> None:
            printed_outputs.extend(args)

        monkeypatch.setattr("builtins.print", fake_print)

        stage = OutputStage(None)
        input_data = PipelineData(content={"test": "stdout"}, metadata={}, format="json")

        output = stage.process(input_data)

        assert output.content == {"test": "stdout"}


class TestPipelineExecution:
    """Test complete pipeline execution."""

    def test_pipeline_single_stage(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        test_binary = tmp_path / "pipeline_test.exe"
        test_binary.write_bytes(b"MZ\x90\x00")

        fake_analyzer = FakeBinaryAnalyzer()
        fake_analyzer.result_data = {"file_type": "PE"}

        monkeypatch.setattr("intellicrack.utils.analysis.binary_analysis.analyze_binary", fake_analyzer)

        pipeline = Pipeline()
        pipeline.add_stage(AnalysisStage())

        result = pipeline.execute(str(test_binary))

        assert result.format == "json"
        assert result.metadata.get("success") is True

    def test_pipeline_multiple_stages(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        test_binary = tmp_path / "multi_stage.exe"
        test_binary.write_bytes(b"MZ\x90\x00")

        fake_analyzer = FakeBinaryAnalyzer()
        fake_analyzer.result_data = {"vulnerabilities": [{"type": "test"}]}

        monkeypatch.setattr("intellicrack.utils.analysis.binary_analysis.analyze_binary", fake_analyzer)

        pipeline = Pipeline()
        pipeline.add_stage(AnalysisStage())
        pipeline.add_stage(FilterStage("vulnerability"))
        pipeline.add_stage(TransformStage("summary"))

        result = pipeline.execute(str(test_binary))

        assert result.format == "text"

    def test_pipeline_error_handling(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake_analyzer = FakeBinaryAnalyzer()
        fake_analyzer.should_raise = True
        fake_analyzer.error_message = "Test error"

        monkeypatch.setattr("intellicrack.utils.analysis.binary_analysis.analyze_binary", fake_analyzer)

        pipeline = Pipeline()
        pipeline.add_stage(AnalysisStage())

        result = pipeline.execute("test.exe")

        assert "error" in result.content or result.metadata.get("success") is False

    def test_pipeline_fluent_interface(self) -> None:
        pipeline = Pipeline().add_stage(AnalysisStage()).add_stage(FilterStage("test")).add_stage(TransformStage("csv"))

        assert len(pipeline.stages) == 3


class TestPipelineCommandParsing:
    """Test pipeline command string parsing."""

    def test_parse_simple_analyze_command(self) -> None:
        pipeline = parse_pipeline_command("analyze")

        assert len(pipeline.stages) == 1
        assert isinstance(pipeline.stages[0], AnalysisStage)

    def test_parse_analyze_filter_transform(self) -> None:
        pipeline = parse_pipeline_command("analyze | filter vulnerability | transform csv")

        assert len(pipeline.stages) == 3
        assert isinstance(pipeline.stages[0], AnalysisStage)
        assert isinstance(pipeline.stages[1], FilterStage)
        assert isinstance(pipeline.stages[2], TransformStage)

    def test_parse_with_output(self, tmp_path: Path) -> None:
        output_file = tmp_path / "result.json"
        pipeline = parse_pipeline_command(f"analyze | output {output_file}")

        assert len(pipeline.stages) == 2
        assert isinstance(pipeline.stages[1], OutputStage)

    def test_parse_invalid_command_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown command"):
            parse_pipeline_command("analyze | invalid_command")

    def test_parse_suspicious_pattern_raises(self) -> None:
        with pytest.raises(ValueError, match="Suspicious pattern"):
            parse_pipeline_command("analyze | eval('test')")

    def test_parse_too_many_stages_raises(self) -> None:
        command = " | ".join(["analyze"] * 15)

        with pytest.raises(ValueError, match="Too many pipeline stages"):
            parse_pipeline_command(command)

    def test_parse_empty_command_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid pipeline command"):
            parse_pipeline_command("")


class TestSecurityValidation:
    """Test security validation in pipelines."""

    def test_validate_prevents_path_traversal(self) -> None:
        stage = AnalysisStage()

        malicious_input = PipelineData(content="../../../etc/passwd", metadata={}, format="text")

        result = stage.validate_input(malicious_input)

        assert result is False

    def test_validate_prevents_sensitive_paths(self) -> None:
        with pytest.raises(ValueError, match="sensitive directory"):
            parse_pipeline_command("analyze | output /etc/shadow")

    def test_validate_filter_expression_length(self) -> None:
        long_filter = "a" * 300

        with pytest.raises(ValueError, match="Filter expression too long"):
            parse_pipeline_command(f"analyze | filter {long_filter}")


class TestRealWorldPipelines:
    """Test real-world pipeline scenarios."""

    def test_vulnerability_analysis_pipeline(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        test_binary = tmp_path / "vuln_test.exe"
        test_binary.write_bytes(b"MZ\x90\x00" * 50)

        output_file = tmp_path / "vulnerabilities.json"

        fake_analyzer = FakeBinaryAnalyzer()
        fake_analyzer.result_data = {"vulnerabilities": [{"type": "test", "severity": "high"}]}

        monkeypatch.setattr("intellicrack.utils.analysis.binary_analysis.analyze_binary", fake_analyzer)

        pipeline = Pipeline()
        pipeline.add_stage(AnalysisStage())
        pipeline.add_stage(FilterStage("vulnerability"))
        pipeline.add_stage(OutputStage(str(output_file)))

        result = pipeline.execute(str(test_binary))

        assert output_file.exists()

    def test_protection_summary_pipeline(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        test_binary = tmp_path / "protected.exe"
        test_binary.write_bytes(b"MZ\x90\x00" * 50)

        fake_analyzer = FakeBinaryAnalyzer()
        fake_analyzer.result_data = {"protections": {"aslr": True, "dep": True}}

        monkeypatch.setattr("intellicrack.utils.analysis.binary_analysis.analyze_binary", fake_analyzer)

        pipeline = Pipeline()
        pipeline.add_stage(AnalysisStage())
        pipeline.add_stage(TransformStage("summary"))

        result = pipeline.execute(str(test_binary))

        assert result.format == "text"
        assert len(result.content) > 0

    def test_csv_export_pipeline(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        test_binary = tmp_path / "csv_test.exe"
        test_binary.write_bytes(b"MZ\x90\x00" * 50)

        output_file = tmp_path / "results.csv"

        fake_analyzer = FakeBinaryAnalyzer()
        fake_analyzer.result_data = [{"function": "main", "risk": "low"}]

        monkeypatch.setattr("intellicrack.utils.analysis.binary_analysis.analyze_binary", fake_analyzer)

        pipeline = Pipeline()
        pipeline.add_stage(AnalysisStage())
        pipeline.add_stage(TransformStage("csv"))
        pipeline.add_stage(OutputStage(str(output_file)))

        result = pipeline.execute(str(test_binary))

        assert output_file.exists()
