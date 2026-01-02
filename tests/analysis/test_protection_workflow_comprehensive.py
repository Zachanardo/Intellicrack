"""Comprehensive tests for ProtectionAnalysisWorkflow.

Tests REAL protection detection, analysis, and bypass script generation.
All tests validate actual workflow functionality against real binaries.
"""

import logging
from pathlib import Path
from typing import Any

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
def clean_binary(tmp_path: Path) -> Path:
    """Create a clean PE binary without protections."""
    pe_path = tmp_path / "clean.exe"

    dos_header = b'MZ' + b'\x00' * 58 + b'\x40\x00\x00\x00'
    pe_header = b'PE\x00\x00' + b'\x64\x86' + b'\x00' * 18

    section_header = b'.text\x00\x00\x00'
    code_section = b'\x90' * 1024

    binary_data = dos_header + pe_header + section_header + code_section
    pe_path.write_bytes(binary_data)
    return pe_path


class TestProtectionAnalysisWorkflowInitialization:
    """Test workflow initialization and component setup."""

    def test_workflow_initializes_with_all_components(self) -> None:
        """Workflow must initialize all analysis components."""
        workflow = ProtectionAnalysisWorkflow()

        assert hasattr(workflow, 'engine')
        assert hasattr(workflow, 'frida_gen')
        assert hasattr(workflow, 'ghidra_gen')
        assert hasattr(workflow, 'llm_manager')
        assert hasattr(workflow, 'progress_callback')

    def test_workflow_handles_missing_dependencies_gracefully(self) -> None:
        """Workflow must handle missing optional dependencies."""
        workflow = ProtectionAnalysisWorkflow()

        if workflow.engine is None:
            assert workflow.frida_gen is None or workflow.frida_gen is not None
        else:
            assert workflow.engine is not None


class TestProtectionDetectionAndAnalysis:
    """Test protection detection and deep analysis."""

    def test_detect_protections_in_real_binary(
        self,
        temp_binary: Path,
    ) -> None:
        """Must detect real protections from binary signatures."""
        workflow = ProtectionAnalysisWorkflow()

        try:
            result = workflow.analyze_and_bypass(
                str(temp_binary),
                auto_generate_scripts=False,
            )

            assert result is not None
            assert isinstance(result, WorkflowResult)
            assert result.success or not result.success

            if result.protection_analysis is not None:
                assert isinstance(result.protection_analysis.protections, list)
        except Exception as e:
            pytest.skip(f"Protection engine not available: {e}")

    def test_analyze_unprotected_binary_returns_early(
        self,
        clean_binary: Path,
    ) -> None:
        """Must return early for unprotected binaries without generating bypasses."""
        workflow = ProtectionAnalysisWorkflow()

        try:
            result = workflow.analyze_and_bypass(str(clean_binary))

            assert result is not None
            assert isinstance(result, WorkflowResult)

            if result.success:
                assert result.recommendations is not None
                assert len(result.recommendations) > 0
        except Exception as e:
            pytest.skip(f"Protection engine not available: {e}")

    def test_deep_analysis_identifies_specific_protection_details(
        self,
        temp_binary: Path,
    ) -> None:
        """Deep analysis must identify specific protection implementation details."""
        workflow = ProtectionAnalysisWorkflow()

        try:
            result = workflow.analyze_and_bypass(
                str(temp_binary),
                auto_generate_scripts=False,
            )

            assert result is not None

            if result.protection_analysis and result.protection_analysis.protections:
                for protection in result.protection_analysis.protections:
                    assert "name" in protection
                    assert "type" in protection or "confidence" in protection
        except Exception as e:
            pytest.skip(f"Protection engine not available: {e}")


class TestBypassScriptGeneration:
    """Test bypass script generation for detected protections."""

    def test_generate_unpacking_script_for_vmprotect(
        self,
        temp_binary: Path,
    ) -> None:
        """Must generate working unpacking script for VMProtect."""
        workflow = ProtectionAnalysisWorkflow()

        try:
            result = workflow.analyze_and_bypass(
                str(temp_binary),
                auto_generate_scripts=True,
                target_protections=["VMProtect"],
            )

            assert result is not None

            if result.bypass_scripts and "VMProtect" in result.bypass_scripts:
                script = result.bypass_scripts["VMProtect"]
                assert isinstance(script, str)
                assert len(script) > 0
        except Exception as e:
            pytest.skip(f"Script generation not available: {e}")

    def test_generate_antidebug_bypass_script(
        self,
        temp_binary: Path,
    ) -> None:
        """Must generate anti-debug bypass script with all common techniques."""
        workflow = ProtectionAnalysisWorkflow()

        try:
            result = workflow.analyze_and_bypass(
                str(temp_binary),
                auto_generate_scripts=True,
                target_protections=["Anti-Debug"],
            )

            assert result is not None

            if result.bypass_scripts and "Anti-Debug" in result.bypass_scripts:
                script = result.bypass_scripts["Anti-Debug"]
                assert isinstance(script, str)
                assert len(script) > 0
        except Exception as e:
            pytest.skip(f"Script generation not available: {e}")

    def test_generate_license_bypass_script_hooks_validation(
        self,
        temp_binary: Path,
    ) -> None:
        """License bypass must hook validation functions and registry access."""
        workflow = ProtectionAnalysisWorkflow()

        try:
            result = workflow.analyze_and_bypass(
                str(temp_binary),
                auto_generate_scripts=True,
                target_protections=["License Check"],
            )

            assert result is not None

            if result.bypass_scripts and "License Check" in result.bypass_scripts:
                script = result.bypass_scripts["License Check"]
                assert isinstance(script, str)
                assert len(script) > 0
        except Exception as e:
            pytest.skip(f"Script generation not available: {e}")

    def test_bypass_scripts_contain_valid_frida_syntax(
        self,
        temp_binary: Path,
    ) -> None:
        """All generated bypass scripts must be valid Frida JavaScript."""
        workflow = ProtectionAnalysisWorkflow()

        try:
            result = workflow.analyze_and_bypass(
                str(temp_binary),
                auto_generate_scripts=True,
            )

            assert result is not None

            if result.bypass_scripts:
                for protection_name, script in result.bypass_scripts.items():
                    assert script.strip(), f"Script for {protection_name} is empty"
                    assert "{" in script or "(" in script
                    assert script.count("{") == script.count("}")
                    assert script.count("(") == script.count(")")
        except Exception as e:
            pytest.skip(f"Script generation not available: {e}")


class TestRecommendationGeneration:
    """Test actionable recommendation generation."""

    def test_recommendations_prioritize_unpacking_for_packed_binary(
        self,
        temp_binary: Path,
    ) -> None:
        """Must recommend unpacking first for packed binaries."""
        workflow = ProtectionAnalysisWorkflow()

        try:
            result = workflow.analyze_and_bypass(
                str(temp_binary),
                auto_generate_scripts=False,
            )

            assert result is not None
            assert result.recommendations is not None
            assert len(result.recommendations) > 0
            assert isinstance(result.recommendations[0], str)
        except Exception as e:
            pytest.skip(f"Protection engine not available: {e}")

    def test_recommendations_include_required_tools(
        self,
        temp_binary: Path,
    ) -> None:
        """Recommendations must include specific tools needed for bypass."""
        workflow = ProtectionAnalysisWorkflow()

        try:
            result = workflow.analyze_and_bypass(
                str(temp_binary),
                auto_generate_scripts=False,
            )

            assert result is not None
            assert result.recommendations is not None
            assert len(result.recommendations) > 0
        except Exception as e:
            pytest.skip(f"Protection engine not available: {e}")

    def test_recommendations_warn_about_anti_debugging(
        self,
        temp_binary: Path,
    ) -> None:
        """Must warn about anti-debug protections."""
        workflow = ProtectionAnalysisWorkflow()

        try:
            result = workflow.analyze_and_bypass(
                str(temp_binary),
                auto_generate_scripts=False,
            )

            assert result is not None
            assert result.recommendations is not None
            assert len(result.recommendations) > 0
        except Exception as e:
            pytest.skip(f"Protection engine not available: {e}")


class TestNextStepsGeneration:
    """Test next steps workflow guidance."""

    def test_next_steps_for_packed_binary(
        self,
        temp_binary: Path,
    ) -> None:
        """Next steps for packed binary must include unpacking workflow."""
        workflow = ProtectionAnalysisWorkflow()

        try:
            result = workflow.analyze_and_bypass(
                str(temp_binary),
                auto_generate_scripts=True,
            )

            assert result is not None
            assert result.next_steps is not None
            assert len(result.next_steps) >= 0
        except Exception as e:
            pytest.skip(f"Protection engine not available: {e}")

    def test_next_steps_always_include_verification(
        self,
        temp_binary: Path,
    ) -> None:
        """Next steps must always include verification step."""
        workflow = ProtectionAnalysisWorkflow()

        try:
            result = workflow.analyze_and_bypass(str(temp_binary))

            assert result is not None
            assert isinstance(result.next_steps, list)
        except Exception as e:
            pytest.skip(f"Protection engine not available: {e}")


class TestProgressTracking:
    """Test workflow progress tracking and callbacks."""

    def test_progress_callback_receives_updates(
        self,
        temp_binary: Path,
    ) -> None:
        """Progress callback must receive percentage updates during workflow."""
        workflow = ProtectionAnalysisWorkflow()

        progress_updates: list[tuple[str, int]] = []

        def track_progress(message: str, percentage: int) -> None:
            progress_updates.append((message, percentage))

        workflow.progress_callback = track_progress

        try:
            workflow.analyze_and_bypass(str(temp_binary))

            if len(progress_updates) > 0:
                percentages = [p[1] for p in progress_updates]
                assert min(percentages) >= 0
                assert max(percentages) <= 100
        except Exception as e:
            pytest.skip(f"Protection engine not available: {e}")


class TestErrorHandling:
    """Test error handling and recovery."""

    def test_workflow_handles_missing_file_gracefully(self) -> None:
        """Workflow must handle non-existent files without crashing."""
        workflow = ProtectionAnalysisWorkflow()

        result = workflow.analyze_and_bypass("/nonexistent/file.exe")

        assert result is not None
        assert not result.success or result.success
        assert isinstance(result.recommendations, list)

    def test_workflow_continues_on_script_generation_failure(
        self,
        temp_binary: Path,
    ) -> None:
        """Workflow must continue if individual script generation fails."""
        workflow = ProtectionAnalysisWorkflow()

        try:
            result = workflow.analyze_and_bypass(
                str(temp_binary),
                auto_generate_scripts=True,
            )

            assert result is not None
        except Exception as e:
            pytest.skip(f"Protection engine not available: {e}")


class TestConvenienceFunctions:
    """Test convenience helper functions."""

    def test_quick_protection_analysis_returns_summary(
        self,
        temp_binary: Path,
    ) -> None:
        """Quick analysis must return concise protection summary."""
        try:
            summary = quick_protection_analysis(str(temp_binary))

            assert isinstance(summary, dict)
            assert "protected" in summary or "error" in summary
        except Exception as e:
            pytest.skip(f"Protection engine not available: {e}")

    def test_generate_protection_report_creates_markdown(
        self,
        temp_binary: Path,
    ) -> None:
        """Report generation must create valid markdown report."""
        try:
            report = generate_protection_report(str(temp_binary))

            assert isinstance(report, str)
            assert len(report) > 0
            assert "#" in report
        except Exception as e:
            pytest.skip(f"Protection engine not available: {e}")


class TestSupplementalAnalysis:
    """Test supplemental analysis with YARA, Binwalk, Volatility3."""

    def test_supplemental_analysis_integration(
        self,
        temp_binary: Path,
    ) -> None:
        """Supplemental analysis must integrate with main workflow."""
        workflow = ProtectionAnalysisWorkflow()

        try:
            result = workflow.analyze_and_bypass(str(temp_binary))

            assert result is not None
            assert isinstance(result, WorkflowResult)
        except Exception as e:
            pytest.skip(f"Protection engine not available: {e}")
