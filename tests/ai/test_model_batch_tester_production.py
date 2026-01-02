"""Production tests for model batch testing system.

Tests real batch testing of multiple models with actual inference,
test case execution, validation, and report generation.
"""

import json
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from intellicrack.ai.llm_backends import LLMBackend, LLMConfig, LLMManager, LLMMessage, LLMProvider, LLMResponse
from intellicrack.ai.model_batch_tester import (
    BatchTestReport,
    ModelBatchTester,
    TestCase,
    TestResult,
    get_batch_tester,
)
from intellicrack.ai.model_performance_monitor import PerformanceMetrics


class FakeLLMManager:
    """Real test double for LLM Manager."""

    def __init__(self) -> None:
        self.registered_llms: list[tuple[str, LLMConfig]] = []

    def register_llm(self, model_id: str, config: LLMConfig) -> bool:
        self.registered_llms.append((model_id, config))
        return True


class TestLLMBackend(LLMBackend):
    """Test LLM backend for batch testing."""

    def __init__(self, model_id: str, response_pattern: str = "test") -> None:
        """Initialize test backend."""
        config = LLMConfig(provider=LLMProvider.LOCAL_API, model=model_id, max_tokens=100, temperature=0.7)
        super().__init__(config)
        self.model_id = model_id
        self.response_pattern = response_pattern
        self.device = "cpu"
        self.call_count = 0
        self.is_initialized = True

    def initialize(self) -> bool:
        """Initialize the backend - already done in __init__."""
        self.is_initialized = True
        return True

    def chat(self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None) -> LLMResponse:
        """Generate test response."""
        self.call_count += 1

        if self.response_pattern == "hello":
            content = "Hello, World!"
        elif self.response_pattern == "math":
            content = "4"
        elif self.response_pattern == "paris":
            content = "The capital of France is Paris"
        elif self.response_pattern == "code":
            content = "def hello_world():\n    print('Hello, World!')"
        else:
            content = f"Test response from {self.model_id}"

        return LLMResponse(
            content=content,
            model=self.model_id,
            usage={"completion_tokens": len(content.split()), "prompt_tokens": 10},
        )


@pytest.fixture
def llm_manager() -> LLMManager:
    """Create test LLM manager with multiple models."""
    manager = LLMManager()

    manager.backends["model_a"] = TestLLMBackend("model_a", "hello")
    manager.backends["model_b"] = TestLLMBackend("model_b", "math")
    manager.backends["model_c"] = TestLLMBackend("model_c", "code")

    return manager


@pytest.fixture
def batch_tester(llm_manager: LLMManager) -> ModelBatchTester:
    """Create batch tester with real LLM manager."""
    return ModelBatchTester(llm_manager=llm_manager, max_workers=2, timeout_per_test=10.0)


def test_batch_tester_initialization(batch_tester: ModelBatchTester) -> None:
    """Test batch tester initializes with default test suites."""
    assert batch_tester.llm_manager is not None
    assert batch_tester.max_workers == 2
    assert batch_tester.timeout_per_test == 10.0

    assert "basic" in batch_tester.test_suites
    assert "code_generation" in batch_tester.test_suites
    assert "binary_analysis" in batch_tester.test_suites

    assert len(batch_tester.test_suites["basic"]) == 3
    assert len(batch_tester.test_suites["code_generation"]) == 2


def test_add_custom_test_suite(batch_tester: ModelBatchTester) -> None:
    """Test adding custom test suite."""
    custom_tests = [
        TestCase(
            test_id="custom_1",
            prompt="Custom prompt",
            expected_patterns=["test"],
            max_tokens=50,
        ),
    ]

    batch_tester.add_test_suite("custom_suite", custom_tests)

    assert "custom_suite" in batch_tester.test_suites
    assert len(batch_tester.test_suites["custom_suite"]) == 1
    assert batch_tester.test_suites["custom_suite"][0].test_id == "custom_1"


def test_load_test_suite_from_file(batch_tester: ModelBatchTester) -> None:
    """Test loading test suite from JSON file."""
    test_suite_data = {
        "suite_id": "file_suite",
        "tests": [
            {
                "test_id": "file_test_1",
                "prompt": "Test from file",
                "expected_output": "Expected output",
                "max_tokens": 100,
                "temperature": 0.5,
                "metadata": {"source": "file"},
            },
        ],
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(test_suite_data, f)
        temp_path = f.name

    try:
        suite_id = batch_tester.load_test_suite_from_file(temp_path)

        assert suite_id == "file_suite"
        assert "file_suite" in batch_tester.test_suites
        assert len(batch_tester.test_suites["file_suite"]) == 1

        test = batch_tester.test_suites["file_suite"][0]
        assert test.test_id == "file_test_1"
        assert test.prompt == "Test from file"
        assert test.expected_output == "Expected output"
        assert test.metadata["source"] == "file"
    finally:
        Path(temp_path).unlink()


def test_run_single_test_success(batch_tester: ModelBatchTester) -> None:
    """Test running single test case successfully."""
    test_case = TestCase(
        test_id="single_test",
        prompt="Test prompt",
        expected_patterns=["test", "response"],
        max_tokens=50,
        temperature=0.7,
    )

    result = batch_tester.run_single_test("model_a", test_case)

    assert result.test_id == "single_test"
    assert result.model_id == "model_a"
    assert result.success is True
    assert result.output != ""
    assert result.inference_time > 0
    assert result.tokens_generated > 0


def test_run_single_test_with_validation(batch_tester: ModelBatchTester, llm_manager: LLMManager) -> None:
    """Test single test with pattern validation."""
    llm_manager.backends["model_validate"] = TestLLMBackend("model_validate", "hello")

    test_case = TestCase(
        test_id="validate_test",
        prompt="Say hello",
        expected_patterns=["Hello", "World"],
        max_tokens=20,
    )

    result = batch_tester.run_single_test("model_validate", test_case)

    assert result.success is True
    assert result.passed_validation is True
    assert result.validation_details is not None
    assert "pattern_matches" in result.validation_details
    assert result.validation_details["pattern_matches"]["Hello"] is True
    assert result.validation_details["pattern_matches"]["World"] is True


def test_run_single_test_exact_match_validation(batch_tester: ModelBatchTester, llm_manager: LLMManager) -> None:
    """Test exact match validation."""
    llm_manager.backends["model_exact"] = TestLLMBackend("model_exact", "hello")

    test_case = TestCase(
        test_id="exact_test",
        prompt="Say hello",
        expected_output="Hello, World!",
        max_tokens=20,
    )

    result = batch_tester.run_single_test("model_exact", test_case)

    assert result.success is True
    assert result.passed_validation is True
    assert result.validation_details is not None
    assert "exact_match" in result.validation_details


def test_run_single_test_model_not_found(batch_tester: ModelBatchTester) -> None:
    """Test handling of non-existent model."""
    test_case = TestCase(test_id="missing_model", prompt="Test", max_tokens=10)

    result = batch_tester.run_single_test("nonexistent_model", test_case)

    assert result.success is False
    assert result.error is not None
    assert "not found" in result.error.lower()


def test_run_batch_test_sequential(batch_tester: ModelBatchTester) -> None:
    """Test running batch tests sequentially."""
    model_ids = ["model_a", "model_b"]

    progress_calls: list[tuple[int, int]] = []

    def progress_callback(completed: int, total: int) -> None:
        progress_calls.append((completed, total))

    report = batch_tester.run_batch_test(
        model_ids=model_ids,
        suite_id="basic",
        parallel=False,
        progress_callback=progress_callback,
    )

    assert isinstance(report, BatchTestReport)
    assert len(report.models_tested) == 2
    assert len(report.results) == 6
    assert report.duration > 0

    assert len(progress_calls) > 0
    assert progress_calls[-1][0] == progress_calls[-1][1]


def test_run_batch_test_parallel(batch_tester: ModelBatchTester) -> None:
    """Test running batch tests in parallel."""
    model_ids = ["model_a", "model_b", "model_c"]

    report = batch_tester.run_batch_test(
        model_ids=model_ids,
        suite_id="basic",
        parallel=True,
    )

    assert isinstance(report, BatchTestReport)
    assert len(report.models_tested) == 3
    assert len(report.results) == 9

    successful_results = [r for r in report.results if r.success]
    assert len(successful_results) > 0


def test_batch_report_summary_generation(batch_tester: ModelBatchTester) -> None:
    """Test comprehensive summary generation."""
    model_ids = ["model_a", "model_b"]

    report = batch_tester.run_batch_test(model_ids=model_ids, suite_id="basic")

    assert "total_tests" in report.summary
    assert "successful_tests" in report.summary
    assert "failed_tests" in report.summary
    assert "models" in report.summary
    assert "tests" in report.summary

    assert report.summary["total_tests"] == len(report.results)

    for model_id in model_ids:
        assert model_id in report.summary["models"]
        model_stats = report.summary["models"][model_id]
        assert "total" in model_stats
        assert "success" in model_stats
        assert "avg_inference_time" in model_stats


def test_compare_models(batch_tester: ModelBatchTester) -> None:
    """Test model comparison functionality."""
    model_ids = ["model_a", "model_b", "model_c"]

    comparison = batch_tester.compare_models(model_ids=model_ids, suite_id="basic")

    assert "test_suite" in comparison
    assert comparison["test_suite"] == "basic"
    assert "models" in comparison
    assert "rankings" in comparison

    for model_id in model_ids:
        assert model_id in comparison["models"]
        model_metrics = comparison["models"][model_id]
        assert "success_rate" in model_metrics
        assert "validation_rate" in model_metrics
        assert "avg_inference_time" in model_metrics

    assert "success_rate" in comparison["rankings"]
    assert "validation_rate" in comparison["rankings"]


def test_export_report_json(batch_tester: ModelBatchTester) -> None:
    """Test exporting report to JSON."""
    model_ids = ["model_a"]
    report = batch_tester.run_batch_test(model_ids=model_ids, suite_id="basic")

    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "test_report.json"
        exported_path = batch_tester.export_report(report, output_path, format="json")

        assert exported_path.exists()
        assert exported_path.suffix == ".json"

        with open(exported_path) as f:
            data = json.load(f)

        assert "test_suite_id" in data
        assert "timestamp" in data
        assert "models_tested" in data
        assert "results" in data
        assert "summary" in data


def test_export_report_html(batch_tester: ModelBatchTester) -> None:
    """Test exporting report to HTML."""
    model_ids = ["model_a"]
    report = batch_tester.run_batch_test(model_ids=model_ids, suite_id="basic")

    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "test_report.html"
        exported_path = batch_tester.export_report(report, output_path, format="html")

        assert exported_path.exists()
        assert exported_path.suffix == ".html"

        content = exported_path.read_text()
        assert "<!DOCTYPE html>" in content
        assert report.test_suite_id in content
        assert "model_a" in content


def test_performance_metrics_collection(batch_tester: ModelBatchTester) -> None:
    """Test performance metrics are collected during testing."""
    test_case = TestCase(test_id="perf_test", prompt="Test", max_tokens=20)

    result = batch_tester.run_single_test("model_a", test_case)

    assert result.performance_metrics is not None
    assert "tokens_per_second" in result.performance_metrics
    assert "memory_mb" in result.performance_metrics


def test_test_suite_invalid_name(batch_tester: ModelBatchTester) -> None:
    """Test error handling for invalid test suite."""
    with pytest.raises(ValueError, match="not found"):
        batch_tester.run_batch_test(["model_a"], suite_id="nonexistent_suite")


def test_get_batch_tester_singleton() -> None:
    """Test global batch tester singleton."""
    tester1 = get_batch_tester()
    tester2 = get_batch_tester()

    assert tester1 is tester2
    assert isinstance(tester1, ModelBatchTester)


def test_test_case_dataclass() -> None:
    """Test TestCase dataclass initialization."""
    test_case = TestCase(
        test_id="test_1",
        prompt="Test prompt",
        expected_output="Expected",
        expected_patterns=["pattern1", "pattern2"],
        max_tokens=100,
        temperature=0.5,
        system_prompt="System",
        metadata={"key": "value"},
    )

    assert test_case.test_id == "test_1"
    assert test_case.prompt == "Test prompt"
    assert test_case.expected_output == "Expected"
    assert test_case.expected_patterns == ["pattern1", "pattern2"]
    assert test_case.max_tokens == 100
    assert test_case.temperature == 0.5
    assert test_case.system_prompt == "System"
    assert test_case.metadata["key"] == "value"


def test_test_result_dataclass() -> None:
    """Test TestResult dataclass initialization."""
    result = TestResult(
        test_id="test_1",
        model_id="model_a",
        success=True,
        output="Test output",
        inference_time=1.5,
        tokens_generated=50,
        passed_validation=True,
        validation_details={"pattern_matches": {"test": True}},
        performance_metrics={"tokens_per_second": 33.3},
    )

    assert result.test_id == "test_1"
    assert result.model_id == "model_a"
    assert result.success is True
    assert result.output == "Test output"
    assert result.inference_time == 1.5
    assert result.tokens_generated == 50
    assert result.passed_validation is True
    assert result.validation_details is not None


def test_batch_test_report_dataclass() -> None:
    """Test BatchTestReport dataclass."""
    timestamp = datetime.now()
    test_cases = [TestCase(test_id="test_1", prompt="Test")]
    results = [
        TestResult(
            test_id="test_1",
            model_id="model_a",
            success=True,
            output="Output",
            inference_time=1.0,
            tokens_generated=10,
        ),
    ]

    report = BatchTestReport(
        test_suite_id="suite_1",
        timestamp=timestamp,
        models_tested=["model_a"],
        test_cases=test_cases,
        results=results,
        summary={"total_tests": 1},
        duration=2.5,
    )

    assert report.test_suite_id == "suite_1"
    assert report.timestamp == timestamp
    assert len(report.models_tested) == 1
    assert len(report.test_cases) == 1
    assert len(report.results) == 1
    assert report.duration == 2.5


def test_default_test_suites_content(batch_tester: ModelBatchTester) -> None:
    """Test default test suites have correct content."""
    basic = batch_tester.test_suites["basic"]
    assert any(t.test_id == "hello_world" for t in basic)
    assert any(t.test_id == "simple_math" for t in basic)

    code_gen = batch_tester.test_suites["code_generation"]
    assert any(t.test_id == "python_hello" for t in code_gen)

    binary = batch_tester.test_suites["binary_analysis"]
    assert len(binary) > 0


def test_timeout_handling(batch_tester: ModelBatchTester, llm_manager: LLMManager) -> None:
    """Test timeout handling for slow models."""

    class SlowLLM(LLMBackend):
        def __init__(self) -> None:
            config = LLMConfig(provider=LLMProvider.LOCAL_API, model="slow_model")
            super().__init__(config)
            self.device = "cpu"
            self.is_initialized = True

        def initialize(self) -> bool:
            self.is_initialized = True
            return True

        def chat(self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None) -> LLMResponse:
            import time

            time.sleep(15)
            return LLMResponse(content="Too slow", model="slow_model")

    llm_manager.backends["slow_model"] = SlowLLM()
    batch_tester_fast = ModelBatchTester(llm_manager=llm_manager, timeout_per_test=0.1)

    test_case = TestCase(test_id="timeout_test", prompt="Test", max_tokens=10)
    report = batch_tester_fast.run_batch_test(["slow_model"], suite_id="basic", parallel=True)

    timeout_results = [r for r in report.results if not r.success and r.error and "failed" in r.error.lower()]
    assert len(timeout_results) > 0
