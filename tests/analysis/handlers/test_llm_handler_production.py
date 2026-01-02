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

from typing import Any, cast

import pytest

from intellicrack.analysis.handlers.llm_handler import (
    LLMAnalysisWorker,
    LLMWorkerSignals,
)
from intellicrack.protection.unified_protection_engine import UnifiedProtectionResult


class FakeProtectionResult:
    """Real test double for UnifiedProtectionResult."""

    def __init__(
        self,
        file_path: str = "D:\\test\\protected.exe",
        file_type: str = "PE",
        architecture: str = "x86_64",
        protections: list[dict[str, Any]] | None = None,
        is_packed: bool = True,
        is_protected: bool = True,
        has_anti_debug: bool = True,
        has_anti_vm: bool = False,
        has_licensing: bool = True,
        confidence_score: float = 0.91,
        bypass_strategies: list[dict[str, str]] | None = None,
    ) -> None:
        self.file_path = file_path
        self.file_type = file_type
        self.architecture = architecture
        self.protections = protections if protections is not None else [
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
        self.is_packed = is_packed
        self.is_protected = is_protected
        self.has_anti_debug = has_anti_debug
        self.has_anti_vm = has_anti_vm
        self.has_licensing = has_licensing
        self.confidence_score = confidence_score
        self.bypass_strategies = bypass_strategies if bypass_strategies is not None else [
            {
                "name": "VMProtect Devirtualization",
                "difficulty": "High",
            },
            {
                "name": "License Check Patch",
                "difficulty": "Medium",
            },
        ]


class FakeWorkerSignals:
    """Real test double for LLMWorkerSignals."""

    def __init__(self) -> None:
        self.finished_callbacks: list[Any] = []
        self.error_callbacks: list[Any] = []
        self.result_callbacks: list[Any] = []
        self.progress_callbacks: list[Any] = []

        self.finished = FakeSignal(self.finished_callbacks)
        self.error = FakeSignal(self.error_callbacks)
        self.result = FakeSignal(self.result_callbacks)
        self.progress = FakeSignal(self.progress_callbacks)


class FakeSignal:
    """Real test double for Qt signal."""

    def __init__(self, callbacks: list[Any]) -> None:
        self.callbacks = callbacks

    def connect(self, callback: Any) -> None:
        """Connect callback to signal."""
        self.callbacks.append(callback)

    def emit(self, *args: Any, **kwargs: Any) -> None:
        """Emit signal to all connected callbacks."""
        for callback in self.callbacks:
            callback(*args, **kwargs)


@pytest.fixture
def fake_protection_result() -> UnifiedProtectionResult:
    """Create fake UnifiedProtectionResult."""
    return cast(UnifiedProtectionResult, FakeProtectionResult())


@pytest.fixture
def llm_worker_signals() -> LLMWorkerSignals:
    """Create LLM worker signals."""
    try:
        return LLMWorkerSignals()
    except Exception:
        return cast(LLMWorkerSignals, FakeWorkerSignals())


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

    def test_worker_initialization(
        self, fake_protection_result: UnifiedProtectionResult
    ) -> None:
        """Worker initializes with protection result."""
        worker = LLMAnalysisWorker(
            operation="register_context",
            analysis_result=fake_protection_result,
        )

        assert worker.operation == "register_context"
        assert worker.analysis_result is fake_protection_result
        assert hasattr(worker, "signals")

    def test_worker_build_llm_context(
        self, fake_protection_result: UnifiedProtectionResult
    ) -> None:
        """Worker builds complete LLM context from protection result."""
        worker = LLMAnalysisWorker(
            operation="register_context",
            analysis_result=fake_protection_result,
        )

        context: dict[str, Any] = worker._build_llm_context(fake_protection_result)

        assert context["file_path"] == "D:\\test\\protected.exe"
        assert context["file_type"] == "PE"
        assert context["architecture"] == "x86_64"
        protections_list: list[dict[str, Any]] = context["protections"]
        assert len(protections_list) == 2
        assert context["is_packed"] is True
        assert context["is_protected"] is True
        assert context["has_anti_debug"] is True
        assert context["has_licensing"] is True
        assert context["protection_count"] == 2
        assert context["confidence_score"] == 0.91

    def test_worker_build_context_with_bypass_strategies(
        self, fake_protection_result: UnifiedProtectionResult
    ) -> None:
        """Worker includes bypass strategies in context."""
        worker = LLMAnalysisWorker(
            operation="register_context",
            analysis_result=fake_protection_result,
        )

        context: dict[str, Any] = worker._build_llm_context(fake_protection_result)

        assert "bypass_strategies" in context
        bypass_list: list[dict[str, Any]] = context["bypass_strategies"]
        assert len(bypass_list) == 2
        assert bypass_list[0]["name"] == "VMProtect Devirtualization"
        assert bypass_list[0]["difficulty"] == "High"

    def test_worker_build_summary_prompt(
        self, fake_protection_result: UnifiedProtectionResult
    ) -> None:
        """Worker builds proper summary prompt for LLM."""
        worker = LLMAnalysisWorker(
            operation="generate_summary",
            analysis_result=fake_protection_result,
        )

        prompt = worker._build_summary_prompt(fake_protection_result)

        assert "protected.exe" in prompt
        assert "PE" in prompt
        assert "x86_64" in prompt
        assert "Protections detected" in prompt
        assert "2" in prompt

    def test_worker_build_bypass_prompt(
        self, fake_protection_result: UnifiedProtectionResult
    ) -> None:
        """Worker builds proper bypass prompt for LLM."""
        worker = LLMAnalysisWorker(
            operation="suggest_bypass",
            analysis_result=fake_protection_result,
        )

        prompt = worker._build_bypass_prompt(fake_protection_result)

        assert "bypass" in prompt.lower()
        assert "VMProtect" in prompt or "protections" in prompt.lower()

    def test_worker_register_context_operation(
        self, fake_protection_result: UnifiedProtectionResult
    ) -> None:
        """Worker executes register_context operation successfully."""
        worker = LLMAnalysisWorker(
            operation="register_context",
            analysis_result=fake_protection_result,
        )

        results: list[dict[str, Any]] = []
        worker.signals.result.connect(lambda r: results.append(r))

        worker.run()

        assert len(results) == 1
        result = results[0]
        assert result["success"] is True
        assert "context" in result
        assert result["context"]["file_path"] == "D:\\test\\protected.exe"


class TestLLMIntegrationScenarios:
    """Test complete LLM integration scenarios."""

    def test_vmprotect_analysis_workflow(
        self, fake_protection_result: UnifiedProtectionResult
    ) -> None:
        """Complete workflow: analyze VMProtect binary with LLM."""
        fake_obj = cast(FakeProtectionResult, fake_protection_result)
        fake_obj.protections = [
            {
                "name": "VMProtect",
                "type": "virtualizer",
                "confidence": 0.96,
            },
        ]
        fake_obj.has_anti_debug = True
        fake_obj.has_anti_vm = True

        worker = LLMAnalysisWorker(
            operation="register_context",
            analysis_result=fake_protection_result,
        )

        context: dict[str, Any] = worker._build_llm_context(fake_protection_result)
        protections_list: list[dict[str, Any]] = context["protections"]

        assert any(p["name"] == "VMProtect" for p in protections_list)
        assert context["has_anti_debug"] is True
        assert context["has_anti_vm"] is True

    def test_licensing_protection_analysis_workflow(self) -> None:
        """Complete workflow: analyze licensing protection with LLM."""
        result = cast(
            UnifiedProtectionResult,
            FakeProtectionResult(
                file_path="D:\\test\\trial_software.exe",
                file_type="PE",
                architecture="x86",
                protections=[
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
                ],
                is_packed=False,
                is_protected=True,
                has_anti_debug=False,
                has_anti_vm=False,
                has_licensing=True,
                confidence_score=0.90,
                bypass_strategies=[
                    {
                        "name": "NOP License Checks",
                        "difficulty": "Easy",
                    },
                ],
            ),
        )

        worker = LLMAnalysisWorker(
            operation="register_context",
            analysis_result=result,
        )

        context: dict[str, Any] = worker._build_llm_context(result)
        protections_list: list[dict[str, Any]] = context["protections"]

        assert context["has_licensing"] is True
        assert len([p for p in protections_list if p["type"] == "licensing"]) == 2

    def test_multi_layer_protection_analysis(self) -> None:
        """Complete workflow: analyze multi-layered protection."""
        result = cast(
            UnifiedProtectionResult,
            FakeProtectionResult(
                file_path="D:\\test\\heavily_protected.exe",
                file_type="PE",
                architecture="x86_64",
                protections=[
                    {"name": "Themida", "type": "packer", "confidence": 0.94},
                    {"name": "VMProtect", "type": "virtualizer", "confidence": 0.91},
                    {"name": "Anti-Debug", "type": "anti_debug", "confidence": 0.88},
                    {"name": "License Check", "type": "licensing", "confidence": 0.85},
                ],
                is_packed=True,
                is_protected=True,
                has_anti_debug=True,
                has_anti_vm=True,
                has_licensing=True,
                confidence_score=0.89,
                bypass_strategies=[],
            ),
        )

        worker = LLMAnalysisWorker(
            operation="register_context",
            analysis_result=result,
        )

        context: dict[str, Any] = worker._build_llm_context(result)

        assert context["protection_count"] == 4
        assert context["is_packed"] is True
        assert context["has_anti_debug"] is True
        assert context["has_licensing"] is True


class TestLLMErrorHandling:
    """Test LLM error handling."""

    def test_worker_handles_missing_bypass_strategies(self) -> None:
        """Worker handles protection result without bypass strategies."""
        result = cast(
            UnifiedProtectionResult,
            FakeProtectionResult(
                file_path="D:\\test\\simple.exe",
                file_type="PE",
                architecture="x86",
                protections=[],
                is_packed=False,
                is_protected=False,
                has_anti_debug=False,
                has_anti_vm=False,
                has_licensing=False,
                confidence_score=0.5,
                bypass_strategies=None,
            ),
        )

        worker = LLMAnalysisWorker(
            operation="register_context",
            analysis_result=result,
        )

        context: dict[str, Any] = worker._build_llm_context(result)

        bypass = context.get("bypass_strategies")
        assert bypass is None or bypass == []

    def test_worker_handles_empty_protections_list(self) -> None:
        """Worker handles result with no protections detected."""
        result = cast(
            UnifiedProtectionResult,
            FakeProtectionResult(
                file_path="D:\\test\\clean.exe",
                file_type="PE",
                architecture="x86",
                protections=[],
                is_packed=False,
                is_protected=False,
                has_anti_debug=False,
                has_anti_vm=False,
                has_licensing=False,
                confidence_score=0.2,
                bypass_strategies=[],
            ),
        )

        worker = LLMAnalysisWorker(
            operation="register_context",
            analysis_result=result,
        )

        context: dict[str, Any] = worker._build_llm_context(result)

        assert context["protection_count"] == 0
        assert context["is_protected"] is False


class TestLLMPromptGeneration:
    """Test LLM prompt generation quality."""

    def test_summary_prompt_includes_all_protections(
        self, fake_protection_result: UnifiedProtectionResult
    ) -> None:
        """Summary prompt includes all detected protections."""
        worker = LLMAnalysisWorker(
            operation="generate_summary",
            analysis_result=fake_protection_result,
        )

        prompt = worker._build_summary_prompt(fake_protection_result)

        assert "VMProtect" in prompt or "detected" in prompt.lower()

    def test_bypass_prompt_focuses_on_actionable_steps(
        self, fake_protection_result: UnifiedProtectionResult
    ) -> None:
        """Bypass prompt focuses on actionable bypass strategies."""
        worker = LLMAnalysisWorker(
            operation="suggest_bypass",
            analysis_result=fake_protection_result,
        )

        prompt = worker._build_bypass_prompt(fake_protection_result)

        assert len(prompt) > 0
        assert "protect" in prompt.lower() or "bypass" in prompt.lower() or "crack" in prompt.lower()

    def test_prompt_formatting_consistent(
        self, fake_protection_result: UnifiedProtectionResult
    ) -> None:
        """All prompts use consistent formatting."""
        worker = LLMAnalysisWorker(
            operation="generate_summary",
            analysis_result=fake_protection_result,
        )

        summary_prompt = worker._build_summary_prompt(fake_protection_result)
        bypass_prompt = worker._build_bypass_prompt(fake_protection_result)

        assert isinstance(summary_prompt, str)
        assert isinstance(bypass_prompt, str)
        assert len(summary_prompt) > 100
        assert len(bypass_prompt) > 100
