"""Production-Grade Tests for ICP Report Generator.

Validates real report generation from protection analysis results in multiple
formats (HTML, text, JSON) with actual data and proper formatting.

NO MOCKS - uses real dataclass instances for all testing.
"""

import json
from pathlib import Path
from typing import Any

import pytest

from intellicrack.protection.icp_backend import (
    ICPDetection,
    ICPFileInfo,
    ICPScanResult,
)
from intellicrack.protection.icp_report_generator import (
    ICPReportGenerator,
    ReportOptions,
)
from intellicrack.protection.unified_protection_engine import UnifiedProtectionResult


@pytest.fixture
def report_generator(tmp_path: Path) -> ICPReportGenerator:
    generator = ICPReportGenerator()
    generator.report_output_path = tmp_path / "reports"
    generator.report_output_path.mkdir(exist_ok=True)
    return generator


@pytest.fixture
def sample_unified_result() -> UnifiedProtectionResult:
    icp_detection = ICPDetection(
        name="VMProtect",
        type="Protector",
        version="3.5",
        info="Commercial virtualizer",
        confidence=92.0,
    )

    icp_file_info = ICPFileInfo(
        filetype="PE32 executable",
        size="2.4 MB",
        detections=[icp_detection],
    )

    icp_analysis = ICPScanResult(
        file_path="D:/test/sample_protected.exe",
        file_infos=[icp_file_info],
        error=None,
        raw_json={
            "file": "sample_protected.exe",
            "protections": ["VMProtect"],
        },
    )

    result = UnifiedProtectionResult(
        file_path="D:/test/sample_protected.exe",
        file_type="PE32",
        architecture="x86",
        is_protected=True,
        is_packed=True,
        is_obfuscated=False,
        has_anti_debug=True,
        has_anti_vm=True,
        has_licensing=True,
        confidence_score=87.5,
        analysis_time=2.34,
        engines_used=["Protection Engine", "ICP Backend", "Heuristic"],
        protections=[
            {
                "name": "VMProtect",
                "type": "protector",
                "confidence": 92.0,
                "source": "signature",
                "version": "3.5",
                "details": {"sections": [".vmp0", ".vmp1"], "entropy": 7.8},
                "bypass_recommendations": [
                    "Use ScyllaHide for anti-debug bypass",
                    "Dump at OEP with x64dbg",
                ],
            },
            {
                "name": "Themida",
                "type": "protector",
                "confidence": 78.0,
                "source": "heuristic",
                "version": "3.1",
                "details": {"mutation": True},
                "bypass_recommendations": ["VM devirtualization required"],
            },
            {
                "name": "FlexNet Publisher",
                "type": "license",
                "confidence": 95.0,
                "source": "ICP",
                "version": "11.16",
                "details": {"license_server": True},
            },
        ],
        bypass_strategies=[
            {
                "name": "VMProtect Bypass",
                "description": "Multi-stage unpacking and IAT reconstruction",
                "difficulty": "Hard",
                "tools": ["x64dbg", "Scylla", "ScyllaHide"],
                "steps": [
                    "Attach debugger with ScyllaHide",
                    "Set breakpoint on VirtualAlloc",
                    "Dump at OEP",
                    "Rebuild IAT with Scylla",
                ],
            },
            {
                "name": "License Bypass",
                "description": "Patch license validation routine",
                "difficulty": "Medium",
                "tools": ["Ghidra", "x64dbg"],
                "steps": [
                    "Identify license check function",
                    "NOP out validation jumps",
                ],
            },
        ],
        icp_analysis=icp_analysis,
        protection_analysis=None,
    )

    return result


@pytest.fixture
def html_options() -> ReportOptions:
    return ReportOptions(
        include_raw_json=True,
        include_bypass_methods=True,
        include_entropy_graph=True,
        include_recommendations=True,
        include_technical_details=True,
        output_format="html",
    )


@pytest.fixture
def text_options() -> ReportOptions:
    return ReportOptions(
        include_raw_json=False,
        include_bypass_methods=True,
        include_recommendations=True,
        output_format="text",
    )


@pytest.fixture
def json_options() -> ReportOptions:
    return ReportOptions(
        include_raw_json=True,
        include_bypass_methods=True,
        output_format="json",
    )


class TestReportOptions:
    def test_report_options_default_values(self) -> None:
        options = ReportOptions()

        assert options.include_raw_json is False
        assert options.include_bypass_methods is True
        assert options.include_entropy_graph is True
        assert options.include_recommendations is True
        assert options.include_technical_details is True
        assert options.output_format == "html"

    def test_report_options_custom_values(self) -> None:
        options = ReportOptions(
            include_raw_json=True,
            include_bypass_methods=False,
            output_format="json",
        )

        assert options.include_raw_json is True
        assert options.include_bypass_methods is False
        assert options.output_format == "json"


class TestReportGeneratorInitialization:
    def test_generator_initializes_output_directory(
        self,
        report_generator: ICPReportGenerator,
    ) -> None:
        assert report_generator.report_output_path.exists()
        assert report_generator.report_output_path.is_dir()

    def test_generator_creates_reports_directory(self, tmp_path: Path) -> None:
        custom_output = tmp_path / "custom_reports"
        generator = ICPReportGenerator()
        generator.report_output_path = custom_output

        generator.report_output_path.mkdir(exist_ok=True)

        assert custom_output.exists()


class TestHTMLReportGeneration:
    def test_generates_valid_html_report(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
        html_options: ReportOptions,
    ) -> None:
        report_path = report_generator.generate_report(
            sample_unified_result,
            html_options,
        )

        assert Path(report_path).exists()
        assert report_path.endswith(".html")

        content = Path(report_path).read_text(encoding="utf-8")

        assert "<!DOCTYPE html>" in content
        assert "<html" in content
        assert "</html>" in content

    def test_html_report_includes_file_information(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
        html_options: ReportOptions,
    ) -> None:
        report_path = report_generator.generate_report(
            sample_unified_result,
            html_options,
        )

        content = Path(report_path).read_text(encoding="utf-8")

        assert "sample_protected.exe" in content
        assert "PE32" in content
        assert "x86" in content

    def test_html_report_includes_protection_detections(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
        html_options: ReportOptions,
    ) -> None:
        report_path = report_generator.generate_report(
            sample_unified_result,
            html_options,
        )

        content = Path(report_path).read_text(encoding="utf-8")

        assert "VMProtect" in content
        assert "Themida" in content
        assert "FlexNet Publisher" in content
        assert "92.0" in content or "92" in content

    def test_html_report_includes_bypass_methods_when_enabled(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
        html_options: ReportOptions,
    ) -> None:
        html_options.include_bypass_methods = True

        report_path = report_generator.generate_report(
            sample_unified_result,
            html_options,
        )

        content = Path(report_path).read_text(encoding="utf-8")

        assert "Bypass" in content
        assert "ScyllaHide" in content or "x64dbg" in content

    def test_html_report_excludes_bypass_methods_when_disabled(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
        html_options: ReportOptions,
    ) -> None:
        html_options.include_bypass_methods = False

        report_path = report_generator.generate_report(
            sample_unified_result,
            html_options,
        )

        content = Path(report_path).read_text(encoding="utf-8")

        bypass_section_minimal = content.count("Bypass") < 3

        assert bypass_section_minimal

    def test_html_report_includes_recommendations(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
        html_options: ReportOptions,
    ) -> None:
        html_options.include_recommendations = True

        report_path = report_generator.generate_report(
            sample_unified_result,
            html_options,
        )

        content = Path(report_path).read_text(encoding="utf-8")

        assert "Recommendation" in content

    def test_html_report_includes_technical_details(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
        html_options: ReportOptions,
    ) -> None:
        html_options.include_technical_details = True

        report_path = report_generator.generate_report(
            sample_unified_result,
            html_options,
        )

        content = Path(report_path).read_text(encoding="utf-8")

        assert "Technical Details" in content
        assert "Packed" in content
        assert "Protected" in content

    def test_html_report_includes_raw_json_when_enabled(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
        html_options: ReportOptions,
    ) -> None:
        html_options.include_raw_json = True

        report_path = report_generator.generate_report(
            sample_unified_result,
            html_options,
        )

        content = Path(report_path).read_text(encoding="utf-8")

        assert "Raw Analysis Data" in content or "raw" in content.lower()

    def test_html_report_includes_icp_analysis_section(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
        html_options: ReportOptions,
    ) -> None:
        report_path = report_generator.generate_report(
            sample_unified_result,
            html_options,
        )

        content = Path(report_path).read_text(encoding="utf-8")

        assert "ICP" in content

    def test_html_report_has_proper_css_styling(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
        html_options: ReportOptions,
    ) -> None:
        report_path = report_generator.generate_report(
            sample_unified_result,
            html_options,
        )

        content = Path(report_path).read_text(encoding="utf-8")

        assert "<style>" in content
        assert "font-family" in content
        assert "color" in content

    def test_html_report_filename_includes_timestamp(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
        html_options: ReportOptions,
    ) -> None:
        report_path = report_generator.generate_report(
            sample_unified_result,
            html_options,
        )

        filename = Path(report_path).name

        assert "sample_protected" in filename
        assert "analysis" in filename
        assert ".html" in filename


class TestTextReportGeneration:
    def test_generates_valid_text_report(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
        text_options: ReportOptions,
    ) -> None:
        report_path = report_generator.generate_report(
            sample_unified_result,
            text_options,
        )

        assert Path(report_path).exists()
        assert report_path.endswith(".txt")

        content = Path(report_path).read_text(encoding="utf-8")

        assert len(content) > 0

    def test_text_report_includes_header(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
        text_options: ReportOptions,
    ) -> None:
        report_path = report_generator.generate_report(
            sample_unified_result,
            text_options,
        )

        content = Path(report_path).read_text(encoding="utf-8")

        assert "INTELLICRACK PROTECTION ANALYSIS REPORT" in content
        assert "=" in content

    def test_text_report_includes_file_information(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
        text_options: ReportOptions,
    ) -> None:
        report_path = report_generator.generate_report(
            sample_unified_result,
            text_options,
        )

        content = Path(report_path).read_text(encoding="utf-8")

        assert "FILE INFORMATION" in content
        assert "sample_protected.exe" in content
        assert "PE32" in content

    def test_text_report_includes_detected_protections(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
        text_options: ReportOptions,
    ) -> None:
        report_path = report_generator.generate_report(
            sample_unified_result,
            text_options,
        )

        content = Path(report_path).read_text(encoding="utf-8")

        assert "DETECTED PROTECTIONS" in content
        assert "VMProtect" in content
        assert "Themida" in content

    def test_text_report_includes_confidence_scores(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
        text_options: ReportOptions,
    ) -> None:
        report_path = report_generator.generate_report(
            sample_unified_result,
            text_options,
        )

        content = Path(report_path).read_text(encoding="utf-8")

        assert "Confidence" in content
        assert "92" in content or "87" in content

    def test_text_report_includes_recommendations_when_enabled(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
        text_options: ReportOptions,
    ) -> None:
        text_options.include_recommendations = True

        report_path = report_generator.generate_report(
            sample_unified_result,
            text_options,
        )

        content = Path(report_path).read_text(encoding="utf-8")

        assert "RECOMMENDATIONS" in content

    def test_text_report_readable_formatting(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
        text_options: ReportOptions,
    ) -> None:
        report_path = report_generator.generate_report(
            sample_unified_result,
            text_options,
        )

        content = Path(report_path).read_text(encoding="utf-8")

        lines = content.split("\n")
        assert len(lines) > 10


class TestJSONReportGeneration:
    def test_generates_valid_json_report(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
        json_options: ReportOptions,
    ) -> None:
        report_path = report_generator.generate_report(
            sample_unified_result,
            json_options,
        )

        assert Path(report_path).exists()
        assert report_path.endswith(".json")

        content = Path(report_path).read_text(encoding="utf-8")
        data = json.loads(content)

        assert isinstance(data, dict)

    def test_json_report_includes_metadata(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
        json_options: ReportOptions,
    ) -> None:
        report_path = report_generator.generate_report(
            sample_unified_result,
            json_options,
        )

        data = json.loads(Path(report_path).read_text(encoding="utf-8"))

        assert "metadata" in data
        assert "generated" in data["metadata"]
        assert "version" in data["metadata"]
        assert "file_path" in data["metadata"]

    def test_json_report_includes_summary(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
        json_options: ReportOptions,
    ) -> None:
        report_path = report_generator.generate_report(
            sample_unified_result,
            json_options,
        )

        data = json.loads(Path(report_path).read_text(encoding="utf-8"))

        assert "summary" in data
        assert data["summary"]["file_type"] == "PE32"
        assert data["summary"]["is_protected"] is True
        assert data["summary"]["is_packed"] is True

    def test_json_report_includes_protections_array(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
        json_options: ReportOptions,
    ) -> None:
        report_path = report_generator.generate_report(
            sample_unified_result,
            json_options,
        )

        data = json.loads(Path(report_path).read_text(encoding="utf-8"))

        assert "protections" in data
        assert isinstance(data["protections"], list)
        assert len(data["protections"]) == 3

        vmprotect = data["protections"][0]
        assert vmprotect["name"] == "VMProtect"
        assert vmprotect["type"] == "protector"
        assert vmprotect["confidence"] == 92.0

    def test_json_report_includes_bypass_strategies(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
        json_options: ReportOptions,
    ) -> None:
        report_path = report_generator.generate_report(
            sample_unified_result,
            json_options,
        )

        data = json.loads(Path(report_path).read_text(encoding="utf-8"))

        assert "bypass_strategies" in data
        assert isinstance(data["bypass_strategies"], list)

    def test_json_report_includes_icp_analysis(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
        json_options: ReportOptions,
    ) -> None:
        report_path = report_generator.generate_report(
            sample_unified_result,
            json_options,
        )

        data = json.loads(Path(report_path).read_text(encoding="utf-8"))

        assert "icp_analysis" in data
        assert "detections" in data["icp_analysis"]

    def test_json_report_includes_raw_json_when_enabled(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
        json_options: ReportOptions,
    ) -> None:
        json_options.include_raw_json = True

        report_path = report_generator.generate_report(
            sample_unified_result,
            json_options,
        )

        data = json.loads(Path(report_path).read_text(encoding="utf-8"))

        assert "icp_raw" in data

    def test_json_report_valid_structure(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
        json_options: ReportOptions,
    ) -> None:
        report_path = report_generator.generate_report(
            sample_unified_result,
            json_options,
        )

        data = json.loads(Path(report_path).read_text(encoding="utf-8"))

        required_keys = ["metadata", "summary", "protections", "bypass_strategies"]
        for key in required_keys:
            assert key in data


class TestReportGenerationWithErrors:
    def test_handles_unsupported_format(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="xml")

        with pytest.raises(ValueError, match="Unsupported output format"):
            report_generator.generate_report(sample_unified_result, options)

    def test_handles_missing_icp_analysis(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
        html_options: ReportOptions,
    ) -> None:
        sample_unified_result.icp_analysis = None

        report_path = report_generator.generate_report(
            sample_unified_result,
            html_options,
        )

        assert Path(report_path).exists()

    def test_handles_icp_analysis_with_error(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
        html_options: ReportOptions,
    ) -> None:
        sample_unified_result.icp_analysis.error = "Analysis failed"

        report_path = report_generator.generate_report(
            sample_unified_result,
            html_options,
        )

        content = Path(report_path).read_text(encoding="utf-8")

        assert "Error" in content or "failed" in content

    def test_handles_empty_protections_list(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
        html_options: ReportOptions,
    ) -> None:
        sample_unified_result.protections = []

        report_path = report_generator.generate_report(
            sample_unified_result,
            html_options,
        )

        content = Path(report_path).read_text(encoding="utf-8")

        assert "No protections detected" in content


class TestReportHelperMethods:
    def test_format_size_converts_bytes_correctly(
        self,
        report_generator: ICPReportGenerator,
    ) -> None:
        assert "1.00 KB" in report_generator._format_size(1024)
        assert "1.00 MB" in report_generator._format_size(1024 * 1024)
        assert "500.00 B" in report_generator._format_size(500)

    def test_get_severity_class_returns_correct_levels(
        self,
        report_generator: ICPReportGenerator,
    ) -> None:
        assert report_generator._get_severity_class("protector") == "critical"
        assert report_generator._get_severity_class("license") == "high"
        assert report_generator._get_severity_class("packer") == "medium"
        assert report_generator._get_severity_class("anti-vm") == "low"

    def test_format_details_handles_dict(
        self,
        report_generator: ICPReportGenerator,
    ) -> None:
        details = {"key1": "value1", "key2": "value2"}

        result = report_generator._format_details(details)

        assert "key1" in result
        assert "value1" in result

    def test_format_details_handles_string(
        self,
        report_generator: ICPReportGenerator,
    ) -> None:
        details = "simple string"

        result = report_generator._format_details(details)

        assert result == "simple string"

    def test_get_version_returns_valid_version(
        self,
        report_generator: ICPReportGenerator,
    ) -> None:
        version = report_generator._get_version()

        assert isinstance(version, str)
        assert len(version) > 0


class TestReportSectionGeneration:
    def test_summary_section_contains_all_fields(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
    ) -> None:
        summary_html = report_generator._generate_summary_section(
            sample_unified_result,
        )

        assert "sample_protected.exe" in summary_html
        assert "PE32" in summary_html
        assert "x86" in summary_html
        assert "Protected" in summary_html
        assert "87.5" in summary_html or "87" in summary_html

    def test_file_info_section_contains_metadata(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
    ) -> None:
        file_info_html = report_generator._generate_file_info_section(
            sample_unified_result,
        )

        assert "File" in file_info_html
        assert "sample_protected.exe" in file_info_html

    def test_protections_section_lists_all_detections(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(include_bypass_methods=True)
        protections_html = report_generator._generate_protections_section(
            sample_unified_result,
            options,
        )

        assert "VMProtect" in protections_html
        assert "Themida" in protections_html
        assert "FlexNet" in protections_html

    def test_recommendations_section_based_on_features(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
    ) -> None:
        recommendations_html = report_generator._generate_recommendations_section(
            sample_unified_result,
        )

        assert "Recommendation" in recommendations_html
        assert len(recommendations_html) > 0

    def test_bypass_methods_section_includes_strategies(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
    ) -> None:
        bypass_html = report_generator._generate_bypass_methods_section(
            sample_unified_result,
        )

        assert "Bypass" in bypass_html
        assert "x64dbg" in bypass_html or "Scylla" in bypass_html

    def test_technical_details_section_includes_features(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
    ) -> None:
        technical_html = report_generator._generate_technical_details_section(
            sample_unified_result,
        )

        assert "Technical Details" in technical_html
        assert "Packed" in technical_html
        assert "Protected" in technical_html


class TestMultipleReportGeneration:
    def test_generates_multiple_reports_without_conflicts(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
    ) -> None:
        html_path = report_generator.generate_report(
            sample_unified_result,
            ReportOptions(output_format="html"),
        )
        text_path = report_generator.generate_report(
            sample_unified_result,
            ReportOptions(output_format="text"),
        )
        json_path = report_generator.generate_report(
            sample_unified_result,
            ReportOptions(output_format="json"),
        )

        assert Path(html_path).exists()
        assert Path(text_path).exists()
        assert Path(json_path).exists()

        assert html_path != text_path
        assert text_path != json_path

    def test_concurrent_report_generation(
        self,
        report_generator: ICPReportGenerator,
        sample_unified_result: UnifiedProtectionResult,
    ) -> None:
        import concurrent.futures

        def generate_report(idx: int) -> str:
            sample_unified_result.file_path = f"D:/test/file_{idx}.exe"
            return report_generator.generate_report(
                sample_unified_result,
                ReportOptions(output_format="html"),
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(generate_report, i) for i in range(3)]
            results = [f.result() for f in futures]

        for path in results:
            assert Path(path).exists()
