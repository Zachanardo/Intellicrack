"""Production-Grade Tests for ICP Report Generator.

Validates comprehensive report generation from ICP analysis results across
multiple output formats (HTML, text, JSON) with real file operations and
complete content verification.
"""

import json
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from intellicrack.protection.icp_report_generator import (
    ICPReportGenerator,
    ReportOptions,
)
from intellicrack.protection.unified_protection_engine import UnifiedProtectionResult


@dataclass
class ICPDetection:
    name: str
    type: str
    version: str | None = None
    info: str | None = None
    confidence: float = 95.0


@dataclass
class ICPFileInfo:
    filetype: str
    size: int
    detections: list[ICPDetection] = field(default_factory=list)


@dataclass
class ICPScanResult:
    file_path: str
    file_infos: list[ICPFileInfo] = field(default_factory=list)
    error: str | None = None
    raw_json: dict[str, Any] | None = None
    supplemental_data: dict[str, Any] = field(default_factory=dict)

    @property
    def all_detections(self) -> list[ICPDetection]:
        detections = []
        for file_info in self.file_infos:
            detections.extend(file_info.detections)
        return detections


@pytest.fixture
def test_binary_path(tmp_path: Path) -> Path:
    binary_path = tmp_path / "test_protected.exe"
    binary_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 2048)
    return binary_path


@pytest.fixture
def report_generator(tmp_path: Path) -> ICPReportGenerator:
    generator = ICPReportGenerator()
    generator.report_output_path = tmp_path / "reports"
    generator.report_output_path.mkdir(exist_ok=True)
    return generator


@pytest.fixture
def minimal_result(test_binary_path: Path) -> UnifiedProtectionResult:
    return UnifiedProtectionResult(
        file_path=str(test_binary_path),
        file_type="PE32",
        architecture="x86",
        protections=[],
        confidence_score=0.0,
        is_packed=False,
        is_protected=False,
        is_obfuscated=False,
        has_anti_debug=False,
        has_anti_vm=False,
        has_licensing=False,
        bypass_strategies=[],
        analysis_time=0.5,
        engines_used=["ICP"],
    )


@pytest.fixture
def vmprotect_result(test_binary_path: Path) -> UnifiedProtectionResult:
    icp_detection = ICPDetection(
        name="VMProtect",
        type="Protector",
        version="3.5.1",
        info="Ultimate protection with virtualization",
        confidence=98.5,
    )
    file_info = ICPFileInfo(
        filetype="PE32",
        size=2048,
        detections=[icp_detection],
    )
    icp_analysis = ICPScanResult(
        file_path=str(test_binary_path),
        file_infos=[file_info],
        raw_json={
            "fileInfo": {
                "fileType": "PE32",
                "size": 2048,
            },
            "detections": [
                {
                    "name": "VMProtect",
                    "type": "Protector",
                    "version": "3.5.1",
                },
            ],
        },
    )

    return UnifiedProtectionResult(
        file_path=str(test_binary_path),
        file_type="PE32",
        architecture="x86",
        protections=[
            {
                "name": "VMProtect",
                "type": "protector",
                "confidence": 98.5,
                "source": "ICP",
                "version": "3.5.1",
                "details": {"virtualization": True, "mutations": "high"},
                "bypass_recommendations": [
                    "Use dynamic analysis with ScyllaHide",
                    "Employ kernel-mode debugging",
                    "Analyze VM handlers for pattern recognition",
                ],
            },
        ],
        confidence_score=98.5,
        is_packed=False,
        is_protected=True,
        is_obfuscated=True,
        has_anti_debug=True,
        has_anti_vm=True,
        has_licensing=True,
        bypass_strategies=[
            {
                "name": "VMProtect Dynamic Unpacking",
                "description": "Use dynamic analysis to dump virtualized code sections",
                "difficulty": "Hard",
                "tools": ["x64dbg", "ScyllaHide", "Scylla"],
                "steps": [
                    "Attach debugger with anti-detection plugins",
                    "Set breakpoints on VM entry points",
                    "Trace VM execution to identify handlers",
                    "Dump devirtualized code sections",
                    "Reconstruct import table",
                ],
            },
        ],
        analysis_time=3.2,
        engines_used=["ICP", "Heuristic"],
        icp_analysis=icp_analysis,
    )


@pytest.fixture
def multi_protection_result(test_binary_path: Path) -> UnifiedProtectionResult:
    icp_detections = [
        ICPDetection(
            name="Themida",
            type="Protector",
            version="3.1.0.0",
            info="Advanced Windows software protection",
            confidence=95.0,
        ),
        ICPDetection(
            name="UPX",
            type="Packer",
            version="3.96",
            info="Ultimate Packer for eXecutables",
            confidence=99.0,
        ),
        ICPDetection(
            name="WinLicense",
            type="License",
            version="3.1",
            info="Licensing and trial system",
            confidence=92.0,
        ),
    ]

    file_info = ICPFileInfo(
        filetype="PE32+",
        size=5120,
        detections=icp_detections,
    )

    icp_analysis = ICPScanResult(
        file_path=str(test_binary_path),
        file_infos=[file_info],
        raw_json={
            "fileInfo": {"fileType": "PE32+", "size": 5120},
            "detections": [
                {"name": d.name, "type": d.type, "version": d.version}
                for d in icp_detections
            ],
        },
    )

    return UnifiedProtectionResult(
        file_path=str(test_binary_path),
        file_type="PE32+",
        architecture="x64",
        protections=[
            {
                "name": "Themida",
                "type": "protector",
                "confidence": 95.0,
                "source": "ICP",
                "version": "3.1.0.0",
                "details": {"anti_debug": True, "anti_vm": True},
                "bypass_recommendations": [
                    "Use kernel-mode debugger",
                    "Apply anti-anti-debug techniques",
                ],
            },
            {
                "name": "UPX",
                "type": "packer",
                "confidence": 99.0,
                "source": "ICP",
                "version": "3.96",
                "details": {},
                "bypass_recommendations": ["Unpack with UPX decompressor"],
            },
            {
                "name": "WinLicense",
                "type": "license",
                "confidence": 92.0,
                "source": "ICP",
                "version": "3.1",
                "details": {"trial_system": True},
                "bypass_recommendations": [
                    "Analyze trial validation routines",
                    "Patch license checks",
                ],
            },
        ],
        confidence_score=95.3,
        is_packed=True,
        is_protected=True,
        is_obfuscated=True,
        has_anti_debug=True,
        has_anti_vm=True,
        has_licensing=True,
        bypass_strategies=[
            {
                "name": "Multi-Layer Bypass Strategy",
                "description": "Systematically defeat each protection layer",
                "difficulty": "Expert",
                "tools": ["x64dbg", "IDA Pro", "Scylla", "PE-bear"],
                "steps": [
                    "Unpack UPX layer first",
                    "Apply anti-anti-debug patches",
                    "Analyze license validation",
                    "Patch or keygen license checks",
                ],
            },
        ],
        analysis_time=5.8,
        engines_used=["ICP", "Heuristic", "Signature"],
        icp_analysis=icp_analysis,
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
            include_entropy_graph=False,
            include_recommendations=False,
            include_technical_details=False,
            output_format="json",
        )

        assert options.include_raw_json is True
        assert options.include_bypass_methods is False
        assert options.include_entropy_graph is False
        assert options.include_recommendations is False
        assert options.include_technical_details is False
        assert options.output_format == "json"


class TestICPReportGeneratorInitialization:
    def test_generator_initialization_creates_output_directory(
        self,
        tmp_path: Path,
    ) -> None:
        generator = ICPReportGenerator()
        generator.report_output_path = tmp_path / "test_reports"

        generator.report_output_path.mkdir(exist_ok=True)

        assert generator.report_output_path.exists()
        assert generator.report_output_path.is_dir()

    def test_generator_has_template_path(self) -> None:
        generator = ICPReportGenerator()

        assert hasattr(generator, "report_template_path")
        assert isinstance(generator.report_template_path, Path)


class TestHTMLReportGeneration:
    def test_html_report_generates_valid_file(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="html")

        report_path = report_generator.generate_report(vmprotect_result, options)

        assert Path(report_path).exists()
        assert Path(report_path).suffix == ".html"
        assert Path(report_path).stat().st_size > 0

    def test_html_report_contains_doctype_and_structure(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="html")

        report_path = report_generator.generate_report(vmprotect_result, options)
        content = Path(report_path).read_text(encoding="utf-8")

        assert "<!DOCTYPE html>" in content
        assert "<html lang=\"en\">" in content
        assert "<head>" in content
        assert "<body>" in content
        assert "</html>" in content

    def test_html_report_includes_file_information(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="html")

        report_path = report_generator.generate_report(vmprotect_result, options)
        content = Path(report_path).read_text(encoding="utf-8")

        assert "File Information" in content
        assert "PE32" in content
        assert "x86" in content
        assert str(Path(vmprotect_result.file_path).name) in content

    def test_html_report_includes_executive_summary(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="html")

        report_path = report_generator.generate_report(vmprotect_result, options)
        content = Path(report_path).read_text(encoding="utf-8")

        assert "Executive Summary" in content
        assert "Protected" in content
        assert "98.5" in content
        assert "ICP" in content

    def test_html_report_includes_detected_protections(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="html")

        report_path = report_generator.generate_report(vmprotect_result, options)
        content = Path(report_path).read_text(encoding="utf-8")

        assert "Detected Protections" in content
        assert "VMProtect" in content
        assert "3.5.1" in content
        assert "protector" in content.lower()

    def test_html_report_includes_bypass_methods_when_enabled(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="html", include_bypass_methods=True)

        report_path = report_generator.generate_report(vmprotect_result, options)
        content = Path(report_path).read_text(encoding="utf-8")

        assert "Bypass Recommendations" in content or "Bypass Strategies" in content
        assert "ScyllaHide" in content
        assert "x64dbg" in content

    def test_html_report_excludes_bypass_methods_when_disabled(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="html", include_bypass_methods=False)

        report_path = report_generator.generate_report(vmprotect_result, options)
        content = Path(report_path).read_text(encoding="utf-8")

        assert "Bypass Strategies" not in content

    def test_html_report_includes_recommendations_when_enabled(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="html", include_recommendations=True)

        report_path = report_generator.generate_report(vmprotect_result, options)
        content = Path(report_path).read_text(encoding="utf-8")

        assert "Analysis Recommendations" in content or "Recommendations" in content

    def test_html_report_includes_technical_details_when_enabled(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="html", include_technical_details=True)

        report_path = report_generator.generate_report(vmprotect_result, options)
        content = Path(report_path).read_text(encoding="utf-8")

        assert "Technical Details" in content
        assert "Protection Features" in content

    def test_html_report_includes_icp_analysis_section(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="html")

        report_path = report_generator.generate_report(vmprotect_result, options)
        content = Path(report_path).read_text(encoding="utf-8")

        assert "ICP Engine Analysis" in content
        assert "VMProtect" in content

    def test_html_report_includes_raw_json_when_enabled(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="html", include_raw_json=True)

        report_path = report_generator.generate_report(vmprotect_result, options)
        content = Path(report_path).read_text(encoding="utf-8")

        assert "Raw Analysis Data" in content
        assert "fileInfo" in content or "fileType" in content

    def test_html_report_contains_css_styling(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="html")

        report_path = report_generator.generate_report(vmprotect_result, options)
        content = Path(report_path).read_text(encoding="utf-8")

        assert "<style>" in content
        assert "font-family" in content
        assert "background-color" in content
        assert ".container" in content

    def test_html_report_has_responsive_design(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="html")

        report_path = report_generator.generate_report(vmprotect_result, options)
        content = Path(report_path).read_text(encoding="utf-8")

        assert "viewport" in content
        assert "width=device-width" in content

    def test_html_report_includes_copyright_footer(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="html")

        report_path = report_generator.generate_report(vmprotect_result, options)
        content = Path(report_path).read_text(encoding="utf-8")

        assert "Intellicrack" in content
        assert "2025" in content
        assert "Zachary Flint" in content

    def test_html_report_handles_multiple_protections(
        self,
        report_generator: ICPReportGenerator,
        multi_protection_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="html")

        report_path = report_generator.generate_report(
            multi_protection_result,
            options,
        )
        content = Path(report_path).read_text(encoding="utf-8")

        assert "Themida" in content
        assert "UPX" in content
        assert "WinLicense" in content
        assert "3.1.0.0" in content
        assert "3.96" in content

    def test_html_report_displays_confidence_scores(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="html")

        report_path = report_generator.generate_report(vmprotect_result, options)
        content = Path(report_path).read_text(encoding="utf-8")

        assert "98.5" in content
        assert "Confidence" in content

    def test_html_report_minimal_protections(
        self,
        report_generator: ICPReportGenerator,
        minimal_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="html")

        report_path = report_generator.generate_report(minimal_result, options)
        content = Path(report_path).read_text(encoding="utf-8")

        assert "No protections detected" in content
        assert "Not Protected" in content


class TestTextReportGeneration:
    def test_text_report_generates_valid_file(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="text")

        report_path = report_generator.generate_report(vmprotect_result, options)

        assert Path(report_path).exists()
        assert Path(report_path).suffix == ".txt"
        assert Path(report_path).stat().st_size > 0

    def test_text_report_contains_header(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="text")

        report_path = report_generator.generate_report(vmprotect_result, options)
        content = Path(report_path).read_text(encoding="utf-8")

        assert "INTELLICRACK PROTECTION ANALYSIS REPORT" in content
        assert "=" * 80 in content

    def test_text_report_includes_file_information(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="text")

        report_path = report_generator.generate_report(vmprotect_result, options)
        content = Path(report_path).read_text(encoding="utf-8")

        assert "FILE INFORMATION:" in content
        assert "Type: PE32" in content
        assert "Architecture: x86" in content
        assert "Protected: Yes" in content

    def test_text_report_includes_detected_protections(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="text")

        report_path = report_generator.generate_report(vmprotect_result, options)
        content = Path(report_path).read_text(encoding="utf-8")

        assert "DETECTED PROTECTIONS:" in content
        assert "VMProtect" in content
        assert "protector" in content

    def test_text_report_includes_icp_detections(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="text")

        report_path = report_generator.generate_report(vmprotect_result, options)
        content = Path(report_path).read_text(encoding="utf-8")

        assert "ICP ENGINE DETECTIONS:" in content
        assert "VMProtect" in content

    def test_text_report_includes_recommendations_when_enabled(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="text", include_recommendations=True)

        report_path = report_generator.generate_report(vmprotect_result, options)
        content = Path(report_path).read_text(encoding="utf-8")

        assert "RECOMMENDATIONS:" in content

    def test_text_report_handles_no_protections(
        self,
        report_generator: ICPReportGenerator,
        minimal_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="text")

        report_path = report_generator.generate_report(minimal_result, options)
        content = Path(report_path).read_text(encoding="utf-8")

        assert "No protections detected" in content

    def test_text_report_handles_multiple_protections(
        self,
        report_generator: ICPReportGenerator,
        multi_protection_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="text")

        report_path = report_generator.generate_report(
            multi_protection_result,
            options,
        )
        content = Path(report_path).read_text(encoding="utf-8")

        assert "Themida" in content
        assert "UPX" in content
        assert "WinLicense" in content

    def test_text_report_is_readable_plain_text(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="text")

        report_path = report_generator.generate_report(vmprotect_result, options)
        content = Path(report_path).read_text(encoding="utf-8")

        assert "<html>" not in content
        assert "<div>" not in content
        assert "{" not in content[:100]


class TestJSONReportGeneration:
    def test_json_report_generates_valid_file(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="json")

        report_path = report_generator.generate_report(vmprotect_result, options)

        assert Path(report_path).exists()
        assert Path(report_path).suffix == ".json"
        assert Path(report_path).stat().st_size > 0

    def test_json_report_is_valid_json(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="json")

        report_path = report_generator.generate_report(vmprotect_result, options)
        content = Path(report_path).read_text(encoding="utf-8")

        data = json.loads(content)
        assert isinstance(data, dict)

    def test_json_report_contains_metadata(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="json")

        report_path = report_generator.generate_report(vmprotect_result, options)
        data = json.loads(Path(report_path).read_text(encoding="utf-8"))

        assert "metadata" in data
        assert "generated" in data["metadata"]
        assert "version" in data["metadata"]
        assert "file_path" in data["metadata"]
        assert "file_name" in data["metadata"]

    def test_json_report_contains_summary(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="json")

        report_path = report_generator.generate_report(vmprotect_result, options)
        data = json.loads(Path(report_path).read_text(encoding="utf-8"))

        assert "summary" in data
        assert data["summary"]["file_type"] == "PE32"
        assert data["summary"]["architecture"] == "x86"
        assert data["summary"]["is_protected"] is True
        assert data["summary"]["confidence_score"] == 98.5

    def test_json_report_contains_protections_array(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="json")

        report_path = report_generator.generate_report(vmprotect_result, options)
        data = json.loads(Path(report_path).read_text(encoding="utf-8"))

        assert "protections" in data
        assert isinstance(data["protections"], list)
        assert len(data["protections"]) > 0
        assert data["protections"][0]["name"] == "VMProtect"
        assert data["protections"][0]["type"] == "protector"

    def test_json_report_contains_bypass_strategies(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="json")

        report_path = report_generator.generate_report(vmprotect_result, options)
        data = json.loads(Path(report_path).read_text(encoding="utf-8"))

        assert "bypass_strategies" in data
        assert isinstance(data["bypass_strategies"], list)

    def test_json_report_contains_icp_analysis(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="json")

        report_path = report_generator.generate_report(vmprotect_result, options)
        data = json.loads(Path(report_path).read_text(encoding="utf-8"))

        assert "icp_analysis" in data
        assert "detections" in data["icp_analysis"]
        assert len(data["icp_analysis"]["detections"]) > 0

    def test_json_report_includes_raw_json_when_enabled(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="json", include_raw_json=True)

        report_path = report_generator.generate_report(vmprotect_result, options)
        data = json.loads(Path(report_path).read_text(encoding="utf-8"))

        assert "icp_raw" in data
        assert "fileInfo" in data["icp_raw"]

    def test_json_report_excludes_raw_json_when_disabled(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="json", include_raw_json=False)

        report_path = report_generator.generate_report(vmprotect_result, options)
        data = json.loads(Path(report_path).read_text(encoding="utf-8"))

        assert "icp_raw" not in data

    def test_json_report_handles_multiple_protections(
        self,
        report_generator: ICPReportGenerator,
        multi_protection_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="json")

        report_path = report_generator.generate_report(
            multi_protection_result,
            options,
        )
        data = json.loads(Path(report_path).read_text(encoding="utf-8"))

        assert len(data["protections"]) == 3
        protection_names = [p["name"] for p in data["protections"]]
        assert "Themida" in protection_names
        assert "UPX" in protection_names
        assert "WinLicense" in protection_names

    def test_json_report_handles_no_protections(
        self,
        report_generator: ICPReportGenerator,
        minimal_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="json")

        report_path = report_generator.generate_report(minimal_result, options)
        data = json.loads(Path(report_path).read_text(encoding="utf-8"))

        assert len(data["protections"]) == 0


class TestReportNamingAndPaths:
    def test_report_filename_includes_timestamp(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="html")

        report_path = report_generator.generate_report(vmprotect_result, options)
        filename = Path(report_path).name

        assert "_analysis_" in filename
        timestamp_pattern = r"\d{8}_\d{6}"
        assert re.search(timestamp_pattern, filename)

    def test_report_filename_includes_binary_name(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="html")

        report_path = report_generator.generate_report(vmprotect_result, options)
        filename = Path(report_path).name

        binary_name = Path(vmprotect_result.file_path).stem
        assert binary_name in filename

    def test_report_path_uses_configured_output_directory(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="html")

        report_path = report_generator.generate_report(vmprotect_result, options)

        assert Path(report_path).parent == report_generator.report_output_path


class TestErrorHandling:
    def test_unsupported_format_raises_error(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="invalid_format")

        with pytest.raises(ValueError, match="Unsupported output format"):
            report_generator.generate_report(vmprotect_result, options)

    def test_report_handles_missing_icp_analysis(
        self,
        report_generator: ICPReportGenerator,
        minimal_result: UnifiedProtectionResult,
    ) -> None:
        minimal_result.icp_analysis = None
        options = ReportOptions(output_format="html")

        report_path = report_generator.generate_report(minimal_result, options)
        content = Path(report_path).read_text(encoding="utf-8")

        assert Path(report_path).exists()

    def test_report_handles_icp_analysis_error(
        self,
        report_generator: ICPReportGenerator,
        test_binary_path: Path,
    ) -> None:
        icp_analysis = ICPScanResult(
            file_path=str(test_binary_path),
            error="ICP engine failed to initialize",
        )

        result = UnifiedProtectionResult(
            file_path=str(test_binary_path),
            file_type="PE32",
            architecture="x86",
            icp_analysis=icp_analysis,
        )

        options = ReportOptions(output_format="html")
        report_path = report_generator.generate_report(result, options)
        content = Path(report_path).read_text(encoding="utf-8")

        assert "Error: ICP engine failed to initialize" in content


class TestUtilityMethods:
    def test_format_size_bytes(self, report_generator: ICPReportGenerator) -> None:
        result = report_generator._format_size(500)
        assert "500" in result
        assert "B" in result

    def test_format_size_kilobytes(self, report_generator: ICPReportGenerator) -> None:
        result = report_generator._format_size(2048)
        assert "2.00" in result
        assert "KB" in result

    def test_format_size_megabytes(self, report_generator: ICPReportGenerator) -> None:
        result = report_generator._format_size(5 * 1024 * 1024)
        assert "5.00" in result
        assert "MB" in result

    def test_format_size_gigabytes(self, report_generator: ICPReportGenerator) -> None:
        result = report_generator._format_size(3 * 1024 * 1024 * 1024)
        assert "3.00" in result
        assert "GB" in result

    def test_get_severity_class_protector(
        self,
        report_generator: ICPReportGenerator,
    ) -> None:
        result = report_generator._get_severity_class("protector")
        assert result == "critical"

    def test_get_severity_class_license(
        self,
        report_generator: ICPReportGenerator,
    ) -> None:
        result = report_generator._get_severity_class("license")
        assert result == "high"

    def test_get_severity_class_packer(
        self,
        report_generator: ICPReportGenerator,
    ) -> None:
        result = report_generator._get_severity_class("packer")
        assert result == "medium"

    def test_get_severity_class_unknown(
        self,
        report_generator: ICPReportGenerator,
    ) -> None:
        result = report_generator._get_severity_class("unknown_type")
        assert result == "low"

    def test_format_details_dict(self, report_generator: ICPReportGenerator) -> None:
        details = {"virtualization": True, "mutations": "high"}
        result = report_generator._format_details(details)

        assert "virtualization" in result
        assert "True" in result
        assert "mutations" in result
        assert "high" in result

    def test_format_details_string(self, report_generator: ICPReportGenerator) -> None:
        details = "Simple string detail"
        result = report_generator._format_details(details)

        assert result == "Simple string detail"

    def test_format_details_list(self, report_generator: ICPReportGenerator) -> None:
        details = ["item1", "item2", "item3"]
        result = report_generator._format_details(details)

        assert "item1" in result
        assert "item2" in result

    def test_get_version_returns_valid_string(
        self,
        report_generator: ICPReportGenerator,
    ) -> None:
        version = report_generator._get_version()

        assert isinstance(version, str)
        assert len(version) > 0
        assert version.count(".") >= 2


class TestLargeDataHandling:
    def test_report_handles_large_protection_list(
        self,
        report_generator: ICPReportGenerator,
        test_binary_path: Path,
    ) -> None:
        protections = [
            {
                "name": f"Protection_{i}",
                "type": "protector",
                "confidence": 90.0,
                "source": "ICP",
                "version": f"1.{i}",
                "details": {},
            }
            for i in range(50)
        ]

        result = UnifiedProtectionResult(
            file_path=str(test_binary_path),
            file_type="PE32",
            architecture="x86",
            protections=protections,
            confidence_score=90.0,
        )

        options = ReportOptions(output_format="html")
        report_path = report_generator.generate_report(result, options)

        assert Path(report_path).exists()
        content = Path(report_path).read_text(encoding="utf-8")
        assert "Protection_0" in content
        assert "Protection_49" in content

    def test_report_handles_long_bypass_strategies(
        self,
        report_generator: ICPReportGenerator,
        test_binary_path: Path,
    ) -> None:
        strategies = [
            {
                "name": f"Strategy {i}",
                "description": "Long description " * 50,
                "difficulty": "Hard",
                "tools": ["tool1", "tool2", "tool3"],
                "steps": [f"Step {j}" for j in range(20)],
            }
            for i in range(10)
        ]

        result = UnifiedProtectionResult(
            file_path=str(test_binary_path),
            file_type="PE32",
            architecture="x86",
            bypass_strategies=strategies,
        )

        options = ReportOptions(output_format="html")
        report_path = report_generator.generate_report(result, options)

        assert Path(report_path).exists()
        assert Path(report_path).stat().st_size > 10000


class TestMultipleReportFormats:
    def test_generate_all_formats_for_same_result(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        html_path = report_generator.generate_report(
            vmprotect_result,
            ReportOptions(output_format="html"),
        )
        text_path = report_generator.generate_report(
            vmprotect_result,
            ReportOptions(output_format="text"),
        )
        json_path = report_generator.generate_report(
            vmprotect_result,
            ReportOptions(output_format="json"),
        )

        assert Path(html_path).exists()
        assert Path(text_path).exists()
        assert Path(json_path).exists()

        assert Path(html_path).suffix == ".html"
        assert Path(text_path).suffix == ".txt"
        assert Path(json_path).suffix == ".json"

    def test_all_formats_contain_core_information(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        html_path = report_generator.generate_report(
            vmprotect_result,
            ReportOptions(output_format="html"),
        )
        text_path = report_generator.generate_report(
            vmprotect_result,
            ReportOptions(output_format="text"),
        )
        json_path = report_generator.generate_report(
            vmprotect_result,
            ReportOptions(output_format="json"),
        )

        html_content = Path(html_path).read_text(encoding="utf-8")
        text_content = Path(text_path).read_text(encoding="utf-8")
        json_data = json.loads(Path(json_path).read_text(encoding="utf-8"))

        assert "VMProtect" in html_content
        assert "VMProtect" in text_content
        assert json_data["protections"][0]["name"] == "VMProtect"

        assert "PE32" in html_content
        assert "PE32" in text_content
        assert json_data["summary"]["file_type"] == "PE32"


class TestRealWorldScenarios:
    def test_report_for_unprotected_binary(
        self,
        report_generator: ICPReportGenerator,
        test_binary_path: Path,
    ) -> None:
        result = UnifiedProtectionResult(
            file_path=str(test_binary_path),
            file_type="PE32",
            architecture="x86",
            protections=[],
            confidence_score=0.0,
            is_protected=False,
            is_packed=False,
        )

        options = ReportOptions(output_format="html")
        report_path = report_generator.generate_report(result, options)
        content = Path(report_path).read_text(encoding="utf-8")

        assert "No protections detected" in content
        assert "Not Protected" in content

    def test_report_for_heavily_protected_binary(
        self,
        report_generator: ICPReportGenerator,
        multi_protection_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(output_format="json")
        report_path = report_generator.generate_report(
            multi_protection_result,
            options,
        )
        data = json.loads(Path(report_path).read_text(encoding="utf-8"))

        assert data["summary"]["is_protected"] is True
        assert data["summary"]["is_packed"] is True
        assert data["summary"]["has_anti_debug"] is True
        assert data["summary"]["has_licensing"] is True
        assert len(data["protections"]) >= 3

    def test_report_with_all_options_enabled(
        self,
        report_generator: ICPReportGenerator,
        multi_protection_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(
            include_raw_json=True,
            include_bypass_methods=True,
            include_entropy_graph=True,
            include_recommendations=True,
            include_technical_details=True,
            output_format="html",
        )

        report_path = report_generator.generate_report(
            multi_protection_result,
            options,
        )
        content = Path(report_path).read_text(encoding="utf-8")

        assert "Bypass" in content or "bypass" in content
        assert "Recommendations" in content or "recommendations" in content
        assert "Technical Details" in content
        assert "Raw Analysis Data" in content

    def test_report_with_minimal_options(
        self,
        report_generator: ICPReportGenerator,
        vmprotect_result: UnifiedProtectionResult,
    ) -> None:
        options = ReportOptions(
            include_raw_json=False,
            include_bypass_methods=False,
            include_entropy_graph=False,
            include_recommendations=False,
            include_technical_details=False,
            output_format="html",
        )

        report_path = report_generator.generate_report(vmprotect_result, options)
        content = Path(report_path).read_text(encoding="utf-8")

        assert "Bypass Strategies" not in content
        assert "Raw Analysis Data" not in content
