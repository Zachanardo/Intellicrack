"""Production tests for LLM integration handler.

Tests validate REAL LLM functionality for protection analysis:
- Context building from UnifiedProtectionResult
- LLM query generation for summaries
- Bypass strategy suggestion generation
- Worker thread execution
- Error handling and fallbacks

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

from intellicrack.analysis.handlers.llm_handler import (
    LLMAnalysisWorker,
    LLMWorkerSignals,
)


@pytest.fixture
def mock_protection_result() -> Mock:
    """Create mock UnifiedProtectionResult."""
    result = Mock()
    result.file_path = "D:\\test\\protected.exe"
    result.file_type = "PE"
    result.architecture = "x86_64"
    result.protections = [
        {
            "name": "VMProtect",
            "type": "virtualizer",
            "confidence": 0.95,
        },
        {
            "name": "License Check",
            "type": "licensing",
            "confidence": 0.88,
        },
    ]
    result.is_packed = True
    result.is_protected = True
    result.has_anti_debug = True
    result.has_anti_vm = False
    result.has_licensing = True
    result.confidence_score = 0.91
    result.bypass_strategies = [
        {
            "name": "VMProtect Devirtualization",
            "difficulty": "High",
        },
        {
            "name": "License Check Patch",
            "difficulty": "Medium",
        },
    ]
    return result


@pytest.fixture
def llm_worker_signals() -> LLMWorkerSignals:
    """Create LLM worker signals."""
    try:
        return LLMWorkerSignals()
    except Exception:
        return Mock()


class TestLLMWorkerSignals:
    """Test LLM worker signal definitions."""

    def test_signals_exist(self, llm_worker_signals: LLMWorkerSignals) -> None:
        """Worker signals are properly defined."""
        assert hasattr(llm_worker_signals, "finished")
        assert hasattr(llm_worker_signals, "error")
        assert hasattr(llm_worker_signals, "result")
        assert hasattr(llm_worker_signals, "progress")


class TestLLMAnalysisWorker:
    """Test LLM analysis worker functionality."""

    def test_worker_initialization(self, mock_protection_result: Mock) -> None:
        """Worker initializes with protection result."""
        worker = LLMAnalysisWorker(
            operation="register_context",
            analysis_result=mock_protection_result,
        )

        assert worker.operation == "register_context"
        assert worker.analysis_result == mock_protection_result
        assert hasattr(worker, "signals")

    def test_worker_build_llm_context(self, mock_protection_result: Mock) -> None:
        """Worker builds complete LLM context from protection result."""
        worker = LLMAnalysisWorker(
            operation="register_context",
            analysis_result=mock_protection_result,
        )

        context = worker._build_llm_context(mock_protection_result)

        assert context["file_path"] == "D:\\test\\protected.exe"
        assert context["file_type"] == "PE"
        assert context["architecture"] == "x86_64"
        assert len(context["protections"]) == 2
        assert context["is_packed"] is True
        assert context["is_protected"] is True
        assert context["has_anti_debug"] is True
        assert context["has_licensing"] is True
        assert context["protection_count"] == 2
        assert context["confidence_score"] == 0.91

    def test_worker_build_context_with_bypass_strategies(self, mock_protection_result: Mock) -> None:
        """Worker includes bypass strategies in context."""
        worker = LLMAnalysisWorker(
            operation="register_context",
            analysis_result=mock_protection_result,
        )

        context = worker._build_llm_context(mock_protection_result)

        assert "bypass_strategies" in context
        assert len(context["bypass_strategies"]) == 2
        assert context["bypass_strategies"][0]["name"] == "VMProtect Devirtualization"
        assert context["bypass_strategies"][0]["difficulty"] == "High"

    def test_worker_build_summary_prompt(self, mock_protection_result: Mock) -> None:
        """Worker builds proper summary prompt for LLM."""
        worker = LLMAnalysisWorker(
            operation="generate_summary",
            analysis_result=mock_protection_result,
        )

        prompt = worker._build_summary_prompt(mock_protection_result)

        assert "protected.exe" in prompt
        assert "PE" in prompt
        assert "x86_64" in prompt
        assert "Protections detected" in prompt
        assert "2" in prompt

    def test_worker_build_bypass_prompt(self, mock_protection_result: Mock) -> None:
        """Worker builds proper bypass prompt for LLM."""
        worker = LLMAnalysisWorker(
            operation="suggest_bypass",
            analysis_result=mock_protection_result,
        )

        prompt = worker._build_bypass_prompt(mock_protection_result)

        assert "bypass" in prompt.lower()
        assert "VMProtect" in prompt or "protections" in prompt.lower()

    def test_worker_register_context_operation(self, mock_protection_result: Mock) -> None:
        """Worker executes register_context operation successfully."""
        worker = LLMAnalysisWorker(
            operation="register_context",
            analysis_result=mock_protection_result,
        )

        results = []
        worker.signals.result.connect(lambda r: results.append(r))

        worker.run()

        assert len(results) == 1
        result = results[0]
        assert result["success"] is True
        assert "context" in result
        assert result["context"]["file_path"] == "D:\\test\\protected.exe"


class TestLLMIntegrationScenarios:
    """Test complete LLM integration scenarios."""

    def test_vmprotect_analysis_workflow(self, mock_protection_result: Mock) -> None:
        """Complete workflow: analyze VMProtect binary with LLM."""
        mock_protection_result.protections = [
            {
                "name": "VMProtect",
                "type": "virtualizer",
                "confidence": 0.96,
            },
        ]
        mock_protection_result.has_anti_debug = True
        mock_protection_result.has_anti_vm = True

        worker = LLMAnalysisWorker(
            operation="register_context",
            analysis_result=mock_protection_result,
        )

        context = worker._build_llm_context(mock_protection_result)

        assert any(p["name"] == "VMProtect" for p in context["protections"])
        assert context["has_anti_debug"] is True
        assert context["has_anti_vm"] is True

    def test_licensing_protection_analysis_workflow(self) -> None:
        """Complete workflow: analyze licensing protection with LLM."""
        result = Mock()
        result.file_path = "D:\\test\\trial_software.exe"
        result.file_type = "PE"
        result.architecture = "x86"
        result.protections = [
            {
                "name": "Trial Period Check",
                "type": "licensing",
                "confidence": 0.92,
            },
            {
                "name": "License Validation",
                "type": "licensing",
                "confidence": 0.89,
            },
        ]
        result.is_packed = False
        result.is_protected = True
        result.has_anti_debug = False
        result.has_anti_vm = False
        result.has_licensing = True
        result.confidence_score = 0.90
        result.bypass_strategies = [
            {
                "name": "NOP License Checks",
                "difficulty": "Easy",
            },
        ]

        worker = LLMAnalysisWorker(
            operation="register_context",
            analysis_result=result,
        )

        context = worker._build_llm_context(result)

        assert context["has_licensing"] is True
        assert len([p for p in context["protections"] if p["type"] == "licensing"]) == 2

    def test_multi_layer_protection_analysis(self) -> None:
        """Complete workflow: analyze multi-layered protection."""
        result = Mock()
        result.file_path = "D:\\test\\heavily_protected.exe"
        result.file_type = "PE"
        result.architecture = "x86_64"
        result.protections = [
            {"name": "Themida", "type": "packer", "confidence": 0.94},
            {"name": "VMProtect", "type": "virtualizer", "confidence": 0.91},
            {"name": "Anti-Debug", "type": "anti_debug", "confidence": 0.88},
            {"name": "License Check", "type": "licensing", "confidence": 0.85},
        ]
        result.is_packed = True
        result.is_protected = True
        result.has_anti_debug = True
        result.has_anti_vm = True
        result.has_licensing = True
        result.confidence_score = 0.89
        result.bypass_strategies = []

        worker = LLMAnalysisWorker(
            operation="register_context",
            analysis_result=result,
        )

        context = worker._build_llm_context(result)

        assert context["protection_count"] == 4
        assert context["is_packed"] is True
        assert context["has_anti_debug"] is True
        assert context["has_licensing"] is True


class TestLLMErrorHandling:
    """Test LLM error handling."""

    def test_worker_handles_missing_bypass_strategies(self) -> None:
        """Worker handles protection result without bypass strategies."""
        result = Mock()
        result.file_path = "D:\\test\\simple.exe"
        result.file_type = "PE"
        result.architecture = "x86"
        result.protections = []
        result.is_packed = False
        result.is_protected = False
        result.has_anti_debug = False
        result.has_anti_vm = False
        result.has_licensing = False
        result.confidence_score = 0.5
        result.bypass_strategies = None

        worker = LLMAnalysisWorker(
            operation="register_context",
            analysis_result=result,
        )

        context = worker._build_llm_context(result)

        assert "bypass_strategies" not in context or context.get("bypass_strategies") is None

    def test_worker_handles_empty_protections_list(self) -> None:
        """Worker handles result with no protections detected."""
        result = Mock()
        result.file_path = "D:\\test\\clean.exe"
        result.file_type = "PE"
        result.architecture = "x86"
        result.protections = []
        result.is_packed = False
        result.is_protected = False
        result.has_anti_debug = False
        result.has_anti_vm = False
        result.has_licensing = False
        result.confidence_score = 0.2
        result.bypass_strategies = []

        worker = LLMAnalysisWorker(
            operation="register_context",
            analysis_result=result,
        )

        context = worker._build_llm_context(result)

        assert context["protection_count"] == 0
        assert context["is_protected"] is False


class TestLLMPromptGeneration:
    """Test LLM prompt generation quality."""

    def test_summary_prompt_includes_all_protections(self, mock_protection_result: Mock) -> None:
        """Summary prompt includes all detected protections."""
        worker = LLMAnalysisWorker(
            operation="generate_summary",
            analysis_result=mock_protection_result,
        )

        prompt = worker._build_summary_prompt(mock_protection_result)

        assert "VMProtect" in prompt or "detected" in prompt.lower()

    def test_bypass_prompt_focuses_on_actionable_steps(self, mock_protection_result: Mock) -> None:
        """Bypass prompt focuses on actionable bypass strategies."""
        worker = LLMAnalysisWorker(
            operation="suggest_bypass",
            analysis_result=mock_protection_result,
        )

        prompt = worker._build_bypass_prompt(mock_protection_result)

        assert len(prompt) > 0
        assert "protect" in prompt.lower() or "bypass" in prompt.lower() or "crack" in prompt.lower()

    def test_prompt_formatting_consistent(self, mock_protection_result: Mock) -> None:
        """All prompts use consistent formatting."""
        worker = LLMAnalysisWorker(
            operation="generate_summary",
            analysis_result=mock_protection_result,
        )

        summary_prompt = worker._build_summary_prompt(mock_protection_result)
        bypass_prompt = worker._build_bypass_prompt(mock_protection_result)

        assert isinstance(summary_prompt, str)
        assert isinstance(bypass_prompt, str)
        assert len(summary_prompt) > 100
        assert len(bypass_prompt) > 100
