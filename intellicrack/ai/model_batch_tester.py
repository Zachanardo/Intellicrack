"""Model Batch Tester for Intellicrack.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import json
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from ..utils.logger import get_logger
from .llm_backends import LLMManager, LLMMessage
from .model_performance_monitor import get_performance_monitor


logger = get_logger(__name__)


@dataclass
class TestCase:
    """A test case for model evaluation."""

    test_id: str
    prompt: str
    expected_output: str | None = None
    expected_patterns: list[str] | None = None
    max_tokens: int = 100
    temperature: float = 0.7
    system_prompt: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class TestResult:
    """Result from a single test case."""

    test_id: str
    model_id: str
    success: bool
    output: str
    inference_time: float
    tokens_generated: int
    error: str | None = None
    passed_validation: bool | None = None
    validation_details: dict[str, Any] | None = None
    performance_metrics: dict[str, Any] | None = None


@dataclass
class BatchTestReport:
    """Report from batch testing multiple models."""

    test_suite_id: str
    timestamp: datetime
    models_tested: list[str]
    test_cases: list[TestCase]
    results: list[TestResult]
    summary: dict[str, Any]
    duration: float


class ModelBatchTester:
    """Batch testing system for multiple models."""

    def __init__(
        self,
        llm_manager: LLMManager | None = None,
        max_workers: int = 4,
        timeout_per_test: float = 60.0,
    ) -> None:
        """Initialize the batch tester.

        Args:
            llm_manager: LLM manager instance
            max_workers: Maximum concurrent tests
            timeout_per_test: Timeout for each test in seconds

        """
        self.llm_manager = llm_manager
        self.max_workers = max_workers
        self.timeout_per_test = timeout_per_test
        self.performance_monitor = get_performance_monitor()

        # Test suites storage
        self.test_suites: dict[str, list[TestCase]] = {}
        self.test_reports: list[BatchTestReport] = []

        # Load default test suites
        self._load_default_test_suites()

    def _load_default_test_suites(self) -> None:
        """Load default test suites."""
        # Basic functionality tests
        self.test_suites["basic"] = [
            TestCase(
                test_id="hello_world",
                prompt="Say 'Hello, World!' and nothing else.",
                expected_output="Hello, World!",
                max_tokens=10,
                temperature=0.0,
            ),
            TestCase(
                test_id="simple_math",
                prompt="What is 2 + 2? Answer with just the number.",
                expected_patterns=["4"],
                max_tokens=10,
                temperature=0.0,
            ),
            TestCase(
                test_id="completion",
                prompt="The capital of France is",
                expected_patterns=["Paris"],
                max_tokens=20,
                temperature=0.3,
            ),
        ]

        # Code generation tests
        self.test_suites["code_generation"] = [
            TestCase(
                test_id="python_hello",
                prompt="Write a Python function that prints 'Hello, World!'",
                expected_patterns=["def", "print", "Hello, World"],
                max_tokens=100,
                temperature=0.5,
            ),
            TestCase(
                test_id="fibonacci",
                prompt="Write a Python function to calculate the nth Fibonacci number",
                expected_patterns=["def", "fibonacci", "return"],
                max_tokens=150,
                temperature=0.5,
            ),
        ]

        # Binary analysis tests (relevant to Intellicrack)
        self.test_suites["binary_analysis"] = [
            TestCase(
                test_id="identify_protection",
                prompt="What protection scheme uses XOR encryption with a rolling key?",
                expected_patterns=["XOR", "rolling", "key"],
                max_tokens=100,
                temperature=0.7,
            ),
            TestCase(
                test_id="reverse_engineering",
                prompt="Write a Frida script to hook the main function",
                expected_patterns=["Interceptor", "attach", "main"],
                max_tokens=200,
                temperature=0.5,
                system_prompt="You are an expert in reverse engineering and Frida scripting.",
            ),
        ]

    def add_test_suite(self, suite_id: str, test_cases: list[TestCase]) -> None:
        """Add a custom test suite.

        Args:
            suite_id: Identifier for the test suite
            test_cases: List of test cases

        """
        self.test_suites[suite_id] = test_cases
        logger.info("Added test suite '%s' with %d tests", suite_id, len(test_cases))

    def load_test_suite_from_file(self, file_path: str | Path) -> str:
        """Load test suite from JSON file.

        Args:
            file_path: Path to JSON file

        Returns:
            Suite ID

        """
        file_path = Path(file_path)

        with open(file_path) as f:
            data = json.load(f)

        suite_id = data.get("suite_id", file_path.stem)
        test_cases = []

        for test_data in data.get("tests", []):
            test_case = TestCase(
                test_id=test_data["test_id"],
                prompt=test_data["prompt"],
                expected_output=test_data.get("expected_output"),
                expected_patterns=test_data.get("expected_patterns"),
                max_tokens=test_data.get("max_tokens", 100),
                temperature=test_data.get("temperature", 0.7),
                system_prompt=test_data.get("system_prompt"),
                metadata=test_data.get("metadata", {}),
            )
            test_cases.append(test_case)

        self.add_test_suite(suite_id, test_cases)
        result_suite_id: str = suite_id if isinstance(suite_id, str) else str(suite_id)
        return result_suite_id

    def run_single_test(
        self,
        model_id: str,
        test_case: TestCase,
        llm_manager: LLMManager | None = None,
    ) -> TestResult:
        """Run a single test case on a model.

        Args:
            model_id: Model to test
            test_case: Test case to run
            llm_manager: LLM manager (uses self.llm_manager if None)

        Returns:
            Test result

        """
        llm_manager = llm_manager or self.llm_manager
        if not llm_manager:
            return TestResult(
                test_id=test_case.test_id,
                model_id=model_id,
                success=False,
                output="",
                inference_time=0,
                tokens_generated=0,
                error="No LLM manager available",
            )

        # Start performance tracking
        perf_context = self.performance_monitor.start_inference(model_id)
        start_time = time.time()

        try:
            # Build messages
            messages = []
            if test_case.system_prompt:
                messages.append(LLMMessage(role="system", content=test_case.system_prompt))
            messages.append(LLMMessage(role="user", content=test_case.prompt))

            # Get model config and update parameters
            llm = llm_manager.get_llm(model_id)
            if not llm:
                raise ValueError(f"Model {model_id} not found")

            # Temporarily update model parameters
            original_temp = llm.config.temperature
            original_max_tokens = llm.config.max_tokens

            llm.config.temperature = test_case.temperature
            llm.config.max_tokens = test_case.max_tokens

            # Run inference
            response = llm.complete(messages)

            # Restore original parameters
            llm.config.temperature = original_temp
            llm.config.max_tokens = original_max_tokens

            inference_time = time.time() - start_time
            output = response.content
            tokens_generated = response.usage.get("completion_tokens", 0) if response.usage else 0

            # End performance tracking
            perf_metrics = self.performance_monitor.end_inference(
                perf_context,
                tokens_generated=tokens_generated,
                sequence_length=len(test_case.prompt),
                device=getattr(llm, "device", "cpu"),
            )

            # Validate output
            passed_validation: bool | None = None
            validation_details: dict[str, Any] = {}

            if test_case.expected_output is not None:
                passed_validation = output.strip() == test_case.expected_output.strip()
                validation_details["exact_match"] = passed_validation

            if test_case.expected_patterns:
                pattern_matches: dict[str, bool] = {pattern: pattern.lower() in output.lower() for pattern in test_case.expected_patterns}
                all_patterns_found = all(pattern_matches.values())
                passed_validation = all_patterns_found if passed_validation is None else (passed_validation and all_patterns_found)
                validation_details["pattern_matches"] = pattern_matches

            return TestResult(
                test_id=test_case.test_id,
                model_id=model_id,
                success=True,
                output=output,
                inference_time=inference_time,
                tokens_generated=tokens_generated,
                passed_validation=passed_validation,
                validation_details=validation_details,
                performance_metrics={
                    "tokens_per_second": perf_metrics.tokens_per_second,
                    "memory_mb": perf_metrics.memory_used_mb + perf_metrics.gpu_memory_mb,
                },
            )

        except Exception as e:
            logger.exception("Exception in model_batch_tester: %s", e)
            # End performance tracking with error
            self.performance_monitor.end_inference(
                perf_context,
                tokens_generated=0,
                error=str(e),
            )

            return TestResult(
                test_id=test_case.test_id,
                model_id=model_id,
                success=False,
                output="",
                inference_time=time.time() - start_time,
                tokens_generated=0,
                error=str(e),
            )

    def run_batch_test(
        self,
        model_ids: list[str],
        suite_id: str = "basic",
        parallel: bool = True,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> BatchTestReport:
        """Run batch tests on multiple models.

        Args:
            model_ids: List of model IDs to test
            suite_id: Test suite to use
            parallel: Run tests in parallel
            progress_callback: Callback for progress updates (completed, total)

        Returns:
            Batch test report

        """
        if suite_id not in self.test_suites:
            raise ValueError(f"Test suite '{suite_id}' not found")

        test_cases = self.test_suites[suite_id]
        test_suite_id = f"{suite_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        start_time = time.time()

        results = []
        total_tests = len(model_ids) * len(test_cases)
        completed_tests = 0

        if parallel and self.max_workers > 1:
            # Parallel execution
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = []

                for model_id in model_ids:
                    for test_case in test_cases:
                        future = executor.submit(
                            self.run_single_test,
                            model_id,
                            test_case,
                            self.llm_manager,
                        )
                        futures.append((future, model_id, test_case))

                # Collect results
                for future, model_id, test_case in futures:
                    try:
                        result = future.result(timeout=self.timeout_per_test)
                        results.append(result)
                    except Exception as e:
                        logger.exception("Exception in model_batch_tester: %s", e)
                        # Handle timeout or other errors
                        results.append(
                            TestResult(
                                test_id=test_case.test_id,
                                model_id=model_id,
                                success=False,
                                output="",
                                inference_time=self.timeout_per_test,
                                tokens_generated=0,
                                error=f"Test failed: {e!s}",
                            ),
                        )

                    completed_tests += 1
                    if progress_callback:
                        progress_callback(completed_tests, total_tests)
        else:
            # Sequential execution
            for model_id in model_ids:
                for test_case in test_cases:
                    result = self.run_single_test(model_id, test_case)
                    results.append(result)

                    completed_tests += 1
                    if progress_callback:
                        progress_callback(completed_tests, total_tests)

        duration = time.time() - start_time

        # Generate summary
        summary = self._generate_summary(results, model_ids, test_cases)

        # Create report
        report = BatchTestReport(
            test_suite_id=test_suite_id,
            timestamp=datetime.now(),
            models_tested=model_ids,
            test_cases=test_cases,
            results=results,
            summary=summary,
            duration=duration,
        )

        self.test_reports.append(report)
        logger.info("Batch test completed: %d tests in %.2fs", total_tests, duration)

        return report

    def _generate_summary(
        self,
        results: list[TestResult],
        model_ids: list[str],
        test_cases: list[TestCase],
    ) -> dict[str, Any]:
        """Generate summary statistics from test results."""
        summary: dict[str, Any] = {
            "total_tests": len(results),
            "successful_tests": sum(bool(r.success) for r in results),
            "failed_tests": sum(not r.success for r in results),
            "validation_passed": sum(r.passed_validation is True for r in results),
            "validation_failed": sum(r.passed_validation is False for r in results),
            "models": {},
            "tests": {},
        }

        # Per-model statistics
        for model_id in model_ids:
            model_results = [r for r in results if r.model_id == model_id]

            models_dict = summary["models"]
            assert isinstance(models_dict, dict)
            models_dict[model_id] = {
                "total": len(model_results),
                "success": sum(bool(r.success) for r in model_results),
                "failed": sum(not r.success for r in model_results),
                "validation_passed": sum(r.passed_validation is True for r in model_results),
                "avg_inference_time": (sum(r.inference_time for r in model_results) / len(model_results) if model_results else 0),
                "avg_tokens_per_second": (
                    sum(r.tokens_generated / r.inference_time for r in model_results if r.success and r.inference_time > 0)
                    / len([r for r in model_results if r.success])
                    if any(r.success for r in model_results)
                    else 0
                ),
            }

        # Per-test statistics
        for test_case in test_cases:
            test_results = [r for r in results if r.test_id == test_case.test_id]

            tests_dict = summary["tests"]
            assert isinstance(tests_dict, dict)
            tests_dict[test_case.test_id] = {
                "total": len(test_results),
                "success": sum(bool(r.success) for r in test_results),
                "validation_passed": sum(r.passed_validation is True for r in test_results),
                "fastest_model": min(
                    (r for r in test_results if r.success),
                    key=lambda r: r.inference_time,
                    default=None,
                ),
            }

        return summary

    def compare_models(
        self,
        model_ids: list[str],
        suite_id: str = "basic",
    ) -> dict[str, Any]:
        """Run comparison test between models.

        Args:
            model_ids: Models to compare
            suite_id: Test suite to use

        Returns:
            Comparison results

        """
        # Run batch test
        report = self.run_batch_test(model_ids, suite_id)

        comparison: dict[str, Any] = {
            "test_suite": suite_id,
            "models": {},
            "rankings": {},
        }

        # Extract model performance
        for model_id in model_ids:
            models_summary = report.summary["models"]
            assert isinstance(models_summary, dict)
            model_summary = models_summary[model_id]
            assert isinstance(model_summary, dict)

            comp_models = comparison["models"]
            assert isinstance(comp_models, dict)
            comp_models[model_id] = {
                "success_rate": model_summary["success"] / model_summary["total"] if model_summary["total"] > 0 else 0,
                "validation_rate": model_summary["validation_passed"] / model_summary["success"] if model_summary["success"] > 0 else 0,
                "avg_inference_time": model_summary["avg_inference_time"],
                "avg_tokens_per_second": model_summary["avg_tokens_per_second"],
            }

        # Generate rankings
        metrics = ["success_rate", "validation_rate", "avg_tokens_per_second"]
        for metric in metrics:
            comp_models_dict = comparison["models"]
            assert isinstance(comp_models_dict, dict)

            if metric == "avg_inference_time":
                # Lower is better
                ranked = sorted(
                    comp_models_dict.items(),
                    key=lambda x: x[1][metric],
                )
            else:
                # Higher is better
                ranked = sorted(
                    comp_models_dict.items(),
                    key=lambda x: x[1][metric],
                    reverse=True,
                )

            rankings_dict = comparison["rankings"]
            assert isinstance(rankings_dict, dict)
            rankings_dict[metric] = [model_id for model_id, _ in ranked]

        # Overall winner (based on validation rate primarily)
        rankings_dict_check = comparison["rankings"]
        assert isinstance(rankings_dict_check, dict)
        validation_ranking = rankings_dict_check.get("validation_rate")
        if validation_ranking:
            assert isinstance(validation_ranking, list)
            comparison["recommended_model"] = validation_ranking[0]

        return comparison

    def export_report(
        self,
        report: BatchTestReport,
        output_path: str | Path | None = None,
        format: str = "json",
    ) -> Path:
        """Export test report.

        Args:
            report: Test report to export
            output_path: Output file path
            format: Export format ("json", "html")

        Returns:
            Path to exported file

        """
        if output_path is None:
            output_path = Path.home() / ".intellicrack" / "test_reports"
            output_path.mkdir(parents=True, exist_ok=True)
            filename = f"test_report_{report.test_suite_id}.{format}"
            output_path /= filename
        else:
            output_path = Path(output_path)

        if format == "html":
            # Generate HTML report
            html = self._generate_html_report(report)
            with open(output_path, "w") as f:
                f.write(html)

        elif format == "json":
            data = {
                "test_suite_id": report.test_suite_id,
                "timestamp": report.timestamp.isoformat(),
                "duration": report.duration,
                "models_tested": report.models_tested,
                "summary": report.summary,
                "test_cases": [
                    {
                        "test_id": tc.test_id,
                        "prompt": tc.prompt,
                        "expected_output": tc.expected_output,
                        "expected_patterns": tc.expected_patterns,
                        "max_tokens": tc.max_tokens,
                        "temperature": tc.temperature,
                    }
                    for tc in report.test_cases
                ],
                "results": [
                    {
                        "test_id": r.test_id,
                        "model_id": r.model_id,
                        "success": r.success,
                        "output": r.output,
                        "inference_time": r.inference_time,
                        "tokens_generated": r.tokens_generated,
                        "passed_validation": r.passed_validation,
                        "validation_details": r.validation_details,
                        "error": r.error,
                    }
                    for r in report.results
                ],
            }

            with open(output_path, "w") as f:
                json.dump(data, f, indent=2)

        logger.info("Exported test report to %s", output_path)
        return output_path

    def _generate_html_report(self, report: BatchTestReport) -> str:
        """Generate HTML report from test results."""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Intellicrack Model Test Report - {report.test_suite_id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        .success {{ color: green; }}
        .failed {{ color: red; }}
        .summary {{ background-color: #f0f0f0; padding: 10px; margin: 20px 0; }}
    </style>
</head>
<body>
    <h1>Model Test Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Test Suite:</strong> {report.test_suite_id}</p>
        <p><strong>Date:</strong> {report.timestamp.strftime("%Y-%m-%d %H:%M:%S")}</p>
        <p><strong>Duration:</strong> {report.duration:.2f} seconds</p>
        <p><strong>Total Tests:</strong> {report.summary["total_tests"]}</p>
        <p><strong>Successful:</strong> <span class="success">{report.summary["successful_tests"]}</span></p>
        <p><strong>Failed:</strong> <span class="failed">{report.summary["failed_tests"]}</span></p>
    </div>

    <h2>Model Performance</h2>
    <table>
        <tr>
            <th>Model</th>
            <th>Success Rate</th>
            <th>Validation Rate</th>
            <th>Avg Inference Time</th>
            <th>Avg Tokens/Second</th>
        </tr>
"""

        for model_id, stats in report.summary["models"].items():
            success_rate = (stats["success"] / stats["total"] * 100) if stats["total"] > 0 else 0
            validation_rate = (stats["validation_passed"] / stats["success"] * 100) if stats["success"] > 0 else 0

            html += f"""
        <tr>
            <td>{model_id}</td>
            <td>{success_rate:.1f}%</td>
            <td>{validation_rate:.1f}%</td>
            <td>{stats["avg_inference_time"]:.3f}s</td>
            <td>{stats["avg_tokens_per_second"]:.1f}</td>
        </tr>
"""

        html += """
    </table>

    <h2>Detailed Results</h2>
    <table>
        <tr>
            <th>Test ID</th>
            <th>Model</th>
            <th>Status</th>
            <th>Validation</th>
            <th>Inference Time</th>
            <th>Output</th>
        </tr>
"""

        for result in report.results:
            status_class = "success" if result.success else "failed"
            status_text = "Success" if result.success else "Failed"
            validation_text = "OK" if result.passed_validation else "FAIL" if result.passed_validation is False else "-"
            output_preview = f"{result.output[:100]}..." if len(result.output) > 100 else result.output
            output_preview = output_preview.replace("\n", " ")

            html += f"""
        <tr>
            <td>{result.test_id}</td>
            <td>{result.model_id}</td>
            <td class="{status_class}">{status_text}</td>
            <td>{validation_text}</td>
            <td>{result.inference_time:.3f}s</td>
            <td>{output_preview}</td>
        </tr>
"""

        html += """
    </table>
</body>
</html>
"""

        return html


# Global instance
_BATCH_TESTER = None


def get_batch_tester(llm_manager: LLMManager | None = None) -> ModelBatchTester:
    """Get the global batch tester."""
    global _BATCH_TESTER
    if _BATCH_TESTER is None:
        _BATCH_TESTER = ModelBatchTester(llm_manager=llm_manager)
    return _BATCH_TESTER
