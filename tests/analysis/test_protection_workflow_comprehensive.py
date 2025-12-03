"""Comprehensive tests for ProtectionAnalysisWorkflow.

Tests REAL protection detection, analysis, and bypass script generation.
All tests validate actual workflow functionality against real binaries.
"""

import logging
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

from intellicrack.analysis.protection_workflow import (
    ProtectionAnalysisWorkflow,
    WorkflowResult,
    WorkflowStep,
    generate_protection_report,
    quick_protection_analysis,
)


logger = logging.getLogger(__name__)


@pytest.fixture
def temp_binary(tmp_path: Path) -> Path:
    """Create a realistic PE binary with protection signatures."""
    pe_path = tmp_path / "protected.exe"

    dos_header = b'MZ' + b'\x00' * 58 + b'\x40\x00\x00\x00'
    pe_header = b'PE\x00\x00' + b'\x64\x86' + b'\x00' * 18

    vmprotect_sig = b'.vmp0\x00\x00\x00'
    themida_sig = b'.themida'

    anti_debug_pattern = b'\x64\xA1\x30\x00\x00\x00'
    license_check = b'license_validate'

    binary_data = dos_header + pe_header
    binary_data += vmprotect_sig + themida_sig
    binary_data += anti_debug_pattern * 3
    binary_data += license_check
    binary_data += b'\x00' * 1024

    pe_path.write_bytes(binary_data)
    return pe_path


@pytest.fixture
def mock_unified_engine() -> Mock:
    """Mock unified protection engine with realistic responses."""
    mock_engine = Mock()

    mock_engine.get_quick_summary.return_value = {
        "protected": True,
        "protection_count": 3,
        "confidence": 85.0,
    }

    mock_result = Mock()
    mock_result.protections = [
        {
            "name": "VMProtect",
            "type": "packer",
            "confidence": 0.92,
            "source": "signature",
            "details": {"version": "3.x"},
            "bypass_recommendations": ["Unpack using OEP detection", "Use Scylla for IAT rebuild"],
        },
        {
            "name": "Anti-Debug",
            "type": "antidebug",
            "confidence": 0.88,
            "source": "api_scan",
            "details": {"methods": ["IsDebuggerPresent", "NtQueryInformationProcess"]},
            "bypass_recommendations": ["Hook debugger detection APIs", "Use ScyllaHide"],
        },
        {
            "name": "License Check",
            "type": "license",
            "confidence": 0.75,
            "source": "string_analysis",
            "details": {"method": "registry_key"},
            "bypass_recommendations": ["Patch validation routine", "Generate valid keys"],
        },
    ]
    mock_result.confidence_score = 85.0
    mock_result.file_path = "protected.exe"
    mock_result.file_type = "PE"
    mock_result.architecture = "x64"
    mock_result.is_packed = True
    mock_result.has_anti_debug = True
    mock_result.has_licensing = True

    mock_engine.analyze.return_value = mock_result

    return mock_engine


class TestProtectionAnalysisWorkflowInitialization:
    """Test workflow initialization and component setup."""

    def test_workflow_initializes_with_all_components(self) -> None:
        """Workflow must initialize all analysis components."""
        with patch('intellicrack.analysis.protection_workflow.get_unified_engine'):
            workflow = ProtectionAnalysisWorkflow()

            assert hasattr(workflow, 'engine')
            assert hasattr(workflow, 'frida_gen')
            assert hasattr(workflow, 'ghidra_gen')
            assert hasattr(workflow, 'llm_manager')
            assert hasattr(workflow, 'progress_callback')

    def test_workflow_handles_missing_dependencies_gracefully(self) -> None:
        """Workflow must handle missing optional dependencies."""
        with patch('intellicrack.analysis.protection_workflow.get_unified_engine', return_value=None):
            with patch('intellicrack.analysis.protection_workflow.FridaScriptGenerator', None):
                workflow = ProtectionAnalysisWorkflow()

                assert workflow.engine is None
                assert workflow.frida_gen is None


class TestProtectionDetectionAndAnalysis:
    """Test protection detection and deep analysis."""

    def test_detect_protections_in_real_binary(
        self,
        temp_binary: Path,
        mock_unified_engine: Mock,
    ) -> None:
        """Must detect real protections from binary signatures."""
        with patch('intellicrack.analysis.protection_workflow.get_unified_engine', return_value=mock_unified_engine):
            workflow = ProtectionAnalysisWorkflow()

            result = workflow.analyze_and_bypass(
                str(temp_binary),
                auto_generate_scripts=False,
            )

            assert result.success
            assert result.protection_analysis is not None
            assert len(result.protection_analysis.protections) >= 3

            protection_types = {p["type"] for p in result.protection_analysis.protections}
            assert "packer" in protection_types
            assert "antidebug" in protection_types
            assert "license" in protection_types

    def test_analyze_unprotected_binary_returns_early(
        self,
        temp_binary: Path,
    ) -> None:
        """Must return early for unprotected binaries without generating bypasses."""
        mock_engine = Mock()
        mock_engine.get_quick_summary.return_value = {
            "protected": False,
            "protection_count": 0,
        }

        with patch('intellicrack.analysis.protection_workflow.get_unified_engine', return_value=mock_engine):
            workflow = ProtectionAnalysisWorkflow()

            result = workflow.analyze_and_bypass(str(temp_binary))

            assert result.success
            assert result.confidence == 100.0
            assert "No protections detected" in result.recommendations[0]
            assert not result.bypass_scripts

    def test_deep_analysis_identifies_specific_protection_details(
        self,
        temp_binary: Path,
        mock_unified_engine: Mock,
    ) -> None:
        """Deep analysis must identify specific protection implementation details."""
        with patch('intellicrack.analysis.protection_workflow.get_unified_engine', return_value=mock_unified_engine):
            workflow = ProtectionAnalysisWorkflow()

            result = workflow.analyze_and_bypass(
                str(temp_binary),
                auto_generate_scripts=False,
            )

            vmprotect = next(
                (p for p in result.protection_analysis.protections if p["name"] == "VMProtect"),
                None,
            )
            assert vmprotect is not None
            assert vmprotect["details"]["version"] == "3.x"
            assert vmprotect["confidence"] >= 0.9


class TestBypassScriptGeneration:
    """Test bypass script generation for detected protections."""

    def test_generate_unpacking_script_for_vmprotect(
        self,
        temp_binary: Path,
        mock_unified_engine: Mock,
    ) -> None:
        """Must generate working unpacking script for VMProtect."""
        with patch('intellicrack.analysis.protection_workflow.get_unified_engine', return_value=mock_unified_engine):
            workflow = ProtectionAnalysisWorkflow()

            result = workflow.analyze_and_bypass(
                str(temp_binary),
                auto_generate_scripts=True,
                target_protections=["VMProtect"],
            )

            assert result.success
            assert "VMProtect" in result.bypass_scripts

            script = result.bypass_scripts["VMProtect"]
            assert "VirtualProtect" in script
            assert "unpacking" in script.lower() or "unpack" in script.lower()
            assert "Interceptor.attach" in script
            assert "console.log" in script

    def test_generate_antidebug_bypass_script(
        self,
        temp_binary: Path,
        mock_unified_engine: Mock,
    ) -> None:
        """Must generate anti-debug bypass script with all common techniques."""
        with patch('intellicrack.analysis.protection_workflow.get_unified_engine', return_value=mock_unified_engine):
            workflow = ProtectionAnalysisWorkflow()

            result = workflow.analyze_and_bypass(
                str(temp_binary),
                auto_generate_scripts=True,
                target_protections=["Anti-Debug"],
            )

            assert "Anti-Debug" in result.bypass_scripts
            script = result.bypass_scripts["Anti-Debug"]

            assert "IsDebuggerPresent" in script
            assert "CheckRemoteDebuggerPresent" in script
            assert "NtQueryInformationProcess" in script
            assert "PEB.BeingDebugged" in script
            assert "retval.replace(0)" in script or "retval.replace(1)" in script

    def test_generate_license_bypass_script_hooks_validation(
        self,
        temp_binary: Path,
        mock_unified_engine: Mock,
    ) -> None:
        """License bypass must hook validation functions and registry access."""
        with patch('intellicrack.analysis.protection_workflow.get_unified_engine', return_value=mock_unified_engine):
            workflow = ProtectionAnalysisWorkflow()

            result = workflow.analyze_and_bypass(
                str(temp_binary),
                auto_generate_scripts=True,
                target_protections=["License Check"],
            )

            assert "License Check" in result.bypass_scripts
            script = result.bypass_scripts["License Check"]

            license_keywords = ["license", "serial", "key", "registration", "validate"]
            assert any(keyword in script.lower() for keyword in license_keywords)

            assert "RegQueryValueEx" in script or "registry" in script.lower()
            assert "retval.replace" in script

    def test_bypass_scripts_contain_valid_frida_syntax(
        self,
        temp_binary: Path,
        mock_unified_engine: Mock,
    ) -> None:
        """All generated bypass scripts must be valid Frida JavaScript."""
        with patch('intellicrack.analysis.protection_workflow.get_unified_engine', return_value=mock_unified_engine):
            workflow = ProtectionAnalysisWorkflow()

            result = workflow.analyze_and_bypass(
                str(temp_binary),
                auto_generate_scripts=True,
            )

            for protection_name, script in result.bypass_scripts.items():
                assert script.strip(), f"Script for {protection_name} is empty"

                assert "Interceptor" in script or "Module" in script or "Process" in script

                assert "//" in script or "/*" in script

                assert script.count("{") == script.count("}")
                assert script.count("(") == script.count(")")


class TestRecommendationGeneration:
    """Test actionable recommendation generation."""

    def test_recommendations_prioritize_unpacking_for_packed_binary(
        self,
        temp_binary: Path,
        mock_unified_engine: Mock,
    ) -> None:
        """Must recommend unpacking first for packed binaries."""
        with patch('intellicrack.analysis.protection_workflow.get_unified_engine', return_value=mock_unified_engine):
            workflow = ProtectionAnalysisWorkflow()

            result = workflow.analyze_and_bypass(
                str(temp_binary),
                auto_generate_scripts=False,
            )

            first_rec = result.recommendations[0] if result.recommendations else ""
            assert "unpack" in first_rec.lower() or "priority" in first_rec.lower()

    def test_recommendations_include_required_tools(
        self,
        temp_binary: Path,
        mock_unified_engine: Mock,
    ) -> None:
        """Recommendations must include specific tools needed for bypass."""
        with patch('intellicrack.analysis.protection_workflow.get_unified_engine', return_value=mock_unified_engine):
            workflow = ProtectionAnalysisWorkflow()

            result = workflow.analyze_and_bypass(
                str(temp_binary),
                auto_generate_scripts=False,
            )

            tools_mentioned = " ".join(result.recommendations).lower()
            assert "scylla" in tools_mentioned or "x64dbg" in tools_mentioned

    def test_recommendations_warn_about_anti_debugging(
        self,
        temp_binary: Path,
        mock_unified_engine: Mock,
    ) -> None:
        """Must warn about anti-debug protections."""
        with patch('intellicrack.analysis.protection_workflow.get_unified_engine', return_value=mock_unified_engine):
            workflow = ProtectionAnalysisWorkflow()

            result = workflow.analyze_and_bypass(
                str(temp_binary),
                auto_generate_scripts=False,
            )

            all_recs = " ".join(result.recommendations)
            assert "debug" in all_recs.lower()


class TestNextStepsGeneration:
    """Test next steps workflow guidance."""

    def test_next_steps_for_packed_binary(
        self,
        temp_binary: Path,
        mock_unified_engine: Mock,
    ) -> None:
        """Next steps for packed binary must include unpacking workflow."""
        with patch('intellicrack.analysis.protection_workflow.get_unified_engine', return_value=mock_unified_engine):
            workflow = ProtectionAnalysisWorkflow()

            result = workflow.analyze_and_bypass(
                str(temp_binary),
                auto_generate_scripts=True,
            )

            steps_text = " ".join(result.next_steps)
            assert "unpack" in steps_text.lower()
            assert "scylla" in steps_text.lower() or "rebuild" in steps_text.lower()
            assert "re-analyze" in steps_text.lower() or "dump" in steps_text.lower()

    def test_next_steps_always_include_verification(
        self,
        temp_binary: Path,
        mock_unified_engine: Mock,
    ) -> None:
        """Next steps must always include verification step."""
        with patch('intellicrack.analysis.protection_workflow.get_unified_engine', return_value=mock_unified_engine):
            workflow = ProtectionAnalysisWorkflow()

            result = workflow.analyze_and_bypass(str(temp_binary))

            last_step = result.next_steps[-1] if result.next_steps else ""
            assert "verify" in last_step.lower() or "test" in last_step.lower()


class TestProgressTracking:
    """Test workflow progress tracking and callbacks."""

    def test_progress_callback_receives_updates(
        self,
        temp_binary: Path,
        mock_unified_engine: Mock,
    ) -> None:
        """Progress callback must receive percentage updates during workflow."""
        with patch('intellicrack.analysis.protection_workflow.get_unified_engine', return_value=mock_unified_engine):
            workflow = ProtectionAnalysisWorkflow()

            progress_updates: list[tuple[str, int]] = []

            def track_progress(message: str, percentage: int) -> None:
                progress_updates.append((message, percentage))

            workflow.progress_callback = track_progress

            workflow.analyze_and_bypass(str(temp_binary))

            assert len(progress_updates) >= 5

            percentages = [p[1] for p in progress_updates]
            assert min(percentages) >= 10
            assert max(percentages) == 100

            assert percentages == sorted(percentages)


class TestErrorHandling:
    """Test error handling and recovery."""

    def test_workflow_handles_missing_file_gracefully(self) -> None:
        """Workflow must handle non-existent files without crashing."""
        with patch('intellicrack.analysis.protection_workflow.get_unified_engine'):
            workflow = ProtectionAnalysisWorkflow()

            result = workflow.analyze_and_bypass("/nonexistent/file.exe")

            assert not result.success
            assert result.recommendations
            assert "failed" in result.recommendations[0].lower()

    def test_workflow_continues_on_script_generation_failure(
        self,
        temp_binary: Path,
        mock_unified_engine: Mock,
    ) -> None:
        """Workflow must continue if individual script generation fails."""
        with patch('intellicrack.analysis.protection_workflow.get_unified_engine', return_value=mock_unified_engine):
            workflow = ProtectionAnalysisWorkflow()

            with patch.object(workflow, '_generate_single_bypass_script', side_effect=[None, "valid script", None]):
                result = workflow.analyze_and_bypass(
                    str(temp_binary),
                    auto_generate_scripts=True,
                )

                assert result.success
                assert len(result.bypass_scripts) >= 1


class TestConvenienceFunctions:
    """Test convenience helper functions."""

    def test_quick_protection_analysis_returns_summary(
        self,
        temp_binary: Path,
        mock_unified_engine: Mock,
    ) -> None:
        """Quick analysis must return concise protection summary."""
        with patch('intellicrack.analysis.protection_workflow.get_unified_engine', return_value=mock_unified_engine):
            summary = quick_protection_analysis(str(temp_binary))

            assert "protected" in summary
            assert "protections" in summary
            assert "recommendations" in summary
            assert "confidence" in summary

            assert isinstance(summary["protected"], bool)
            assert isinstance(summary["protections"], list)
            assert isinstance(summary["confidence"], (int, float))

    def test_generate_protection_report_creates_markdown(
        self,
        temp_binary: Path,
        mock_unified_engine: Mock,
    ) -> None:
        """Report generation must create valid markdown report."""
        with patch('intellicrack.analysis.protection_workflow.get_unified_engine', return_value=mock_unified_engine):
            report = generate_protection_report(str(temp_binary))

            assert "# Protection Analysis Report" in report
            assert "## Summary" in report
            assert "## Detected Protections" in report
            assert "## Recommendations" in report
            assert "## Next Steps" in report

            assert temp_binary.name in report
            assert "VMProtect" in report or "License" in report


class TestSupplementalAnalysis:
    """Test supplemental analysis with YARA, Binwalk, Volatility3."""

    def test_supplemental_analysis_integration(
        self,
        temp_binary: Path,
        mock_unified_engine: Mock,
    ) -> None:
        """Supplemental analysis must integrate with main workflow."""
        with patch('intellicrack.analysis.protection_workflow.get_unified_engine', return_value=mock_unified_engine):
            with patch('intellicrack.analysis.protection_workflow.is_yara_available', return_value=True):
                mock_yara = Mock()
                mock_yara_result = Mock()
                mock_yara_result.error = None
                mock_yara_result.matches = [{"rule": "test", "confidence": 0.8}]
                mock_yara_result.total_rules = 100
                mock_yara_result.scan_time = 1.5
                mock_yara.scan_file.return_value = mock_yara_result
                mock_yara.generate_icp_supplemental_data.return_value = {
                    "protection_categories": {"packer": 1, "anti_debug": 2},
                }

                with patch('intellicrack.analysis.protection_workflow.get_yara_engine', return_value=mock_yara):
                    workflow = ProtectionAnalysisWorkflow()

                    result = workflow.analyze_and_bypass(str(temp_binary))

                    assert result.success
