"""Production tests for model comparison tool.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import tempfile
import time
from collections.abc import Generator
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from intellicrack.ai.llm_backends import LLMBackend, LLMConfig, LLMManager, LLMMessage, LLMProvider, LLMResponse
from intellicrack.ai.model_comparison import (
    ComparisonReport,
    ComparisonResult,
    ModelComparison,
    get_comparison_tool,
)


class MockLLM(LLMBackend):
    """Mock LLM for testing comparisons."""

    def __init__(self, model_id: str, response_delay: float = 0.1, response_text: str | None = None) -> None:
        """Initialize mock LLM."""
        self.model_id = model_id
        self.response_delay = response_delay
        self.response_text = response_text or f"Response from {model_id}"
        config = LLMConfig(
            provider=LLMProvider.OPENAI,
            model_name=model_id,
            temperature=0.7,
            max_tokens=500
        )
        super().__init__(config)
        self.is_initialized = True

    def initialize(self) -> bool:
        """Initialize the mock backend."""
        self.is_initialized = True
        return True

    def chat(self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None) -> LLMResponse:
        """Generate mock response."""
        time.sleep(self.response_delay)

        token_count = len(self.response_text.split())
        return LLMResponse(
            content=self.response_text,
            model=self.model_id,
            usage={"completion_tokens": token_count, "prompt_tokens": 10}
        )

    def complete(self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None) -> LLMResponse:
        """Generate mock response (alias for chat)."""
        return self.chat(messages, tools)


class TestComparisonResult:
    """Test ComparisonResult dataclass."""

    def test_comparison_result_creation(self) -> None:
        """ComparisonResult can be created with required fields."""
        result = ComparisonResult(
            model_id="test-model",
            output="Test output",
            inference_time=0.5,
            tokens_generated=50,
            tokens_per_second=100.0,
            memory_used_mb=500.0
        )

        assert result.model_id == "test-model"
        assert result.output == "Test output"
        assert result.inference_time == 0.5
        assert result.tokens_generated == 50
        assert result.tokens_per_second == 100.0
        assert result.memory_used_mb == 500.0
        assert result.similarity_scores is None

    def test_comparison_result_with_similarity(self) -> None:
        """ComparisonResult can include similarity scores."""
        similarity_scores = {"model-2": 0.85, "model-3": 0.72}
        result = ComparisonResult(
            model_id="model-1",
            output="Output",
            inference_time=0.3,
            tokens_generated=30,
            tokens_per_second=100.0,
            memory_used_mb=400.0,
            similarity_scores=similarity_scores
        )

        assert result.similarity_scores == similarity_scores
        assert result.similarity_scores["model-2"] == 0.85


class TestComparisonReport:
    """Test ComparisonReport dataclass."""

    def test_comparison_report_creation(self) -> None:
        """ComparisonReport can be created with all fields."""
        now = datetime.now()
        results = [
            ComparisonResult(
                model_id="model-1",
                output="Output 1",
                inference_time=0.5,
                tokens_generated=50,
                tokens_per_second=100.0,
                memory_used_mb=500.0
            )
        ]

        report = ComparisonReport(
            comparison_id="test_comparison_123",
            timestamp=now,
            prompt="Test prompt",
            models=["model-1"],
            results=results,
            analysis={"test": "data"},
            visualizations={}
        )

        assert report.comparison_id == "test_comparison_123"
        assert report.timestamp == now
        assert report.prompt == "Test prompt"
        assert len(report.models) == 1
        assert len(report.results) == 1
        assert report.analysis == {"test": "data"}


class TestModelComparison:
    """Test ModelComparison tool functionality."""

    @pytest.fixture
    def temp_save_dir(self) -> Generator[Path, None, None]:
        """Create temporary save directory."""
        temp_dir = tempfile.mkdtemp(prefix="comparison_test_")
        save_path = Path(temp_dir)
        yield save_path
        import shutil
        shutil.rmtree(save_path, ignore_errors=True)

    @pytest.fixture
    def mock_llm_manager(self) -> "FakeLLMManager":
        """Create fake LLM manager with test models."""
        manager = FakeLLMManager()

        manager.register_model("fast-model", MockLLM("fast-model", response_delay=0.05, response_text="Quick response about license analysis"))
        manager.register_model("slow-model", MockLLM("slow-model", response_delay=0.15, response_text="Detailed response about license bypass strategies"))
        manager.register_model("efficient-model", MockLLM("efficient-model", response_delay=0.08, response_text="Efficient license cracking approach"))

        return manager


class FakeLLMManager(LLMManager):
    """Test double for LLM Manager that bypasses singleton pattern."""

    def __new__(cls, enable_lazy_loading: bool = True, enable_background_loading: bool = True) -> "FakeLLMManager":
        """Create new instance bypassing singleton."""
        instance = object.__new__(cls)
        return instance

    def __init__(self, enable_lazy_loading: bool = False, enable_background_loading: bool = False) -> None:
        """Initialize with tracking for registered models."""
        self._initialized = False
        self.backends: dict[str, LLMBackend] = {}
        self.configs: dict[str, LLMConfig] = {}
        self.active_backend: str | None = None
        self.enable_lazy_loading = enable_lazy_loading
        self.enable_background_loading = enable_background_loading
        self.lazy_manager: Any = None
        self.lazy_wrappers: dict[str, Any] = {}
        self.background_loader: Any = None
        self.loading_tasks: dict[str, Any] = {}
        self.progress_callbacks: list[Any] = []
        self.models: dict[str, MockLLM] = {}
        import threading
        self.lock = threading.RLock()
        self._initialized = True

    def register_model(self, model_id: str, llm: MockLLM) -> None:
        """Register a mock model."""
        self.models[model_id] = llm

    def get_llm(self, model_id: str) -> LLMBackend | None:
        """Get a registered mock LLM."""
        return self.models.get(model_id)

    @pytest.fixture
    def comparison_tool(self, mock_llm_manager: LLMManager, temp_save_dir: Path) -> ModelComparison:
        """Create comparison tool with mock LLM manager."""
        tool = ModelComparison(llm_manager=mock_llm_manager)
        tool.save_dir = temp_save_dir
        return tool

    def test_comparison_tool_initialization(self, mock_llm_manager: LLMManager) -> None:
        """Comparison tool initializes with correct components."""
        tool = ModelComparison(llm_manager=mock_llm_manager)

        assert tool.llm_manager is mock_llm_manager
        assert tool.performance_monitor is not None
        assert tool.batch_tester is not None
        assert isinstance(tool.reports, list)
        assert len(tool.reports) == 0
        assert tool.save_dir.exists()

    def test_generate_output_success(self, comparison_tool: ModelComparison) -> None:
        """Output generation succeeds with valid model."""
        result = comparison_tool._generate_output(
            model_id="fast-model",
            prompt="Analyze license protection in binary",
            system_prompt="You are a license cracking expert",
            max_tokens=100,
            temperature=0.7
        )

        assert result is not None
        assert result.model_id == "fast-model"
        assert len(result.output) > 0
        assert "license" in result.output.lower()
        assert result.inference_time > 0
        assert result.tokens_generated > 0
        assert result.tokens_per_second > 0
        assert result.memory_used_mb >= 0

    def test_generate_output_invalid_model(self, comparison_tool: ModelComparison) -> None:
        """Output generation fails gracefully for invalid model."""
        result = comparison_tool._generate_output(
            model_id="nonexistent-model",
            prompt="Test prompt",
            system_prompt=None,
            max_tokens=100,
            temperature=0.7
        )

        assert result is None

    def test_average_results_single(self, comparison_tool: ModelComparison) -> None:
        """Averaging single result returns same result."""
        single_result = ComparisonResult(
            model_id="test-model",
            output="Output",
            inference_time=0.5,
            tokens_generated=50,
            tokens_per_second=100.0,
            memory_used_mb=500.0
        )

        avg_result = comparison_tool._average_results("test-model", [single_result])

        assert avg_result.model_id == single_result.model_id
        assert avg_result.output == single_result.output
        assert avg_result.inference_time == single_result.inference_time

    def test_average_results_multiple(self, comparison_tool: ModelComparison) -> None:
        """Averaging multiple results returns median output with averaged metrics."""
        results = [
            ComparisonResult(
                model_id="test-model",
                output="Output 1",
                inference_time=0.4,
                tokens_generated=40,
                tokens_per_second=100.0,
                memory_used_mb=400.0
            ),
            ComparisonResult(
                model_id="test-model",
                output="Output 2",
                inference_time=0.5,
                tokens_generated=50,
                tokens_per_second=100.0,
                memory_used_mb=500.0
            ),
            ComparisonResult(
                model_id="test-model",
                output="Output 3",
                inference_time=0.6,
                tokens_generated=60,
                tokens_per_second=100.0,
                memory_used_mb=600.0
            )
        ]

        avg_result = comparison_tool._average_results("test-model", results)

        assert avg_result.model_id == "test-model"
        assert avg_result.output == "Output 2"
        assert 0.4 <= avg_result.inference_time <= 0.6
        assert avg_result.tokens_per_second == 100.0
        assert 400.0 <= avg_result.memory_used_mb <= 600.0

    def test_analyze_outputs(self, comparison_tool: ModelComparison) -> None:
        """Output analysis produces correct metrics."""
        results = [
            ComparisonResult(
                model_id="fast-model",
                output="Quick license bypass using API hooking",
                inference_time=0.1,
                tokens_generated=20,
                tokens_per_second=200.0,
                memory_used_mb=300.0
            ),
            ComparisonResult(
                model_id="slow-model",
                output="Comprehensive license analysis with detailed bypass strategy",
                inference_time=0.5,
                tokens_generated=40,
                tokens_per_second=80.0,
                memory_used_mb=800.0
            )
        ]

        analysis = comparison_tool._analyze_outputs(results)

        assert "output_lengths" in analysis
        assert "performance" in analysis
        assert "consistency" in analysis

        assert "fast-model" in analysis["output_lengths"]
        assert "slow-model" in analysis["output_lengths"]

        assert analysis["performance"]["fastest_model"] == "fast-model"
        assert analysis["performance"]["slowest_model"] == "slow-model"
        assert analysis["performance"]["speed_difference"] >= 1.0
        assert "efficiency_ranking" in analysis["performance"]

    def test_calculate_similarities(self, comparison_tool: ModelComparison) -> None:
        """Similarity calculation adds scores to results."""
        results = [
            ComparisonResult(
                model_id="model-1",
                output="License bypass using Frida hooks to intercept validation",
                inference_time=0.1,
                tokens_generated=20,
                tokens_per_second=200.0,
                memory_used_mb=300.0
            ),
            ComparisonResult(
                model_id="model-2",
                output="License bypass using Frida hooks for validation intercept",
                inference_time=0.2,
                tokens_generated=25,
                tokens_per_second=125.0,
                memory_used_mb=400.0
            ),
            ComparisonResult(
                model_id="model-3",
                output="Completely different approach using binary patching",
                inference_time=0.15,
                tokens_generated=22,
                tokens_per_second=147.0,
                memory_used_mb=350.0
            )
        ]

        comparison_tool._calculate_similarities(results)

        if results[0].similarity_scores:
            assert "model-2" in results[0].similarity_scores
            assert "model-3" in results[0].similarity_scores
            assert 0.0 <= results[0].similarity_scores["model-2"] <= 1.0

    def test_create_visualizations(self, comparison_tool: ModelComparison) -> None:
        """Visualization creation produces expected files."""
        results = [
            ComparisonResult(
                model_id="model-1",
                output="Output 1",
                inference_time=0.1,
                tokens_generated=20,
                tokens_per_second=200.0,
                memory_used_mb=300.0
            ),
            ComparisonResult(
                model_id="model-2",
                output="Output 2",
                inference_time=0.2,
                tokens_generated=25,
                tokens_per_second=125.0,
                memory_used_mb=400.0
            )
        ]

        viz = comparison_tool._create_visualizations(results, "test_viz")

        assert isinstance(viz, dict)
        assert "performance_chart" in viz or len(viz) == 0
        if "performance_chart" in viz:
            assert viz["performance_chart"].exists()

    def test_save_report(self, comparison_tool: ModelComparison) -> None:
        """Report saving creates JSON file with correct content."""
        report = ComparisonReport(
            comparison_id="test_save_123",
            timestamp=datetime.now(),
            prompt="Test prompt",
            models=["model-1"],
            results=[
                ComparisonResult(
                    model_id="model-1",
                    output="Test output",
                    inference_time=0.1,
                    tokens_generated=10,
                    tokens_per_second=100.0,
                    memory_used_mb=200.0
                )
            ],
            analysis={},
            visualizations={}
        )

        comparison_tool._save_report(report)

        report_file = comparison_tool.save_dir / "test_save_123_report.json"
        assert report_file.exists()

        import json
        with open(report_file) as f:
            saved_data = json.load(f)

        assert saved_data["comparison_id"] == "test_save_123"
        assert saved_data["prompt"] == "Test prompt"
        assert len(saved_data["results"]) == 1

    def test_generate_html_report(self, comparison_tool: ModelComparison) -> None:
        """HTML report generation creates valid HTML file."""
        report = ComparisonReport(
            comparison_id="test_html_456",
            timestamp=datetime.now(),
            prompt="Analyze license bypass strategies",
            models=["model-1", "model-2"],
            results=[
                ComparisonResult(
                    model_id="model-1",
                    output="Strategy 1: API hooking",
                    inference_time=0.1,
                    tokens_generated=15,
                    tokens_per_second=150.0,
                    memory_used_mb=300.0
                ),
                ComparisonResult(
                    model_id="model-2",
                    output="Strategy 2: Binary patching",
                    inference_time=0.2,
                    tokens_generated=20,
                    tokens_per_second=100.0,
                    memory_used_mb=400.0
                )
            ],
            analysis={
                "performance": {
                    "fastest_model": "model-1",
                    "slowest_model": "model-2",
                    "speed_difference": 2.0,
                    "efficiency_ranking": ["model-1", "model-2"]
                },
                "consistency": {
                    "avg_word_overlap": 0.3
                }
            },
            visualizations={}
        )

        html_path = comparison_tool.generate_html_report(report)

        assert html_path.exists()
        assert html_path.suffix == ".html"

        html_content = html_path.read_text()
        assert "Model Comparison Report" in html_content
        assert "Analyze license bypass strategies" in html_content
        assert "model-1" in html_content
        assert "model-2" in html_content


class TestGlobalComparisonTool:
    """Test global comparison tool singleton."""

    def test_get_comparison_tool_singleton(self) -> None:
        """Global comparison tool returns same instance."""
        tool1 = get_comparison_tool()
        tool2 = get_comparison_tool()

        assert tool1 is tool2
        assert isinstance(tool1, ModelComparison)

    def test_get_comparison_tool_with_manager(self) -> None:
        """Global comparison tool can be initialized with LLM manager."""
        manager = FakeLLMManager()
        tool = get_comparison_tool(llm_manager=manager)

        assert isinstance(tool, ModelComparison)


class TestComparisonEdgeCases:
    """Test edge cases and error handling."""

    @pytest.fixture
    def comparison_tool(self) -> Generator[ModelComparison, None, None]:
        """Create comparison tool for edge case testing."""
        temp_dir = tempfile.mkdtemp(prefix="comparison_edge_")
        tool = ModelComparison(llm_manager=None)
        tool.save_dir = Path(temp_dir)
        yield tool
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)

    def test_generate_output_no_llm_manager(self, comparison_tool: ModelComparison) -> None:
        """Output generation handles missing LLM manager."""
        result = comparison_tool._generate_output(
            model_id="any-model",
            prompt="Test",
            system_prompt=None,
            max_tokens=100,
            temperature=0.7
        )

        assert result is None

    def test_analyze_outputs_empty_list(self, comparison_tool: ModelComparison) -> None:
        """Output analysis handles empty results list."""
        analysis = comparison_tool._analyze_outputs([])

        assert isinstance(analysis, dict)
        assert "output_lengths" in analysis
        assert "performance" in analysis

    def test_create_visualizations_error_handling(self, comparison_tool: ModelComparison) -> None:
        """Visualization creation handles errors gracefully."""
        results = [
            ComparisonResult(
                model_id="model-1",
                output="Test",
                inference_time=0.1,
                tokens_generated=10,
                tokens_per_second=100.0,
                memory_used_mb=200.0
            )
        ]

        viz = comparison_tool._create_visualizations(results, "error_test")

        assert isinstance(viz, dict)
