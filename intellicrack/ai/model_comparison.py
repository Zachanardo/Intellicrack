"""
Model Comparison Tool for Intellicrack

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import json
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
from matplotlib import pyplot as plt

from ..utils.logger import get_logger
from .llm_backends import LLMManager, LLMMessage
from .model_batch_tester import get_batch_tester
from .model_performance_monitor import get_performance_monitor

logger = get_logger(__name__)


@dataclass
class ComparisonResult:
    """Result from comparing model outputs."""
    model_id: str
    output: str
    inference_time: float
    tokens_generated: int
    tokens_per_second: float
    memory_used_mb: float
    similarity_scores: Dict[str, float] = None


@dataclass
class ComparisonReport:
    """Complete comparison report."""
    comparison_id: str
    timestamp: datetime
    prompt: str
    models: List[str]
    results: List[ComparisonResult]
    analysis: Dict[str, Any]
    visualizations: Dict[str, Path]


class ModelComparison:
    """Tool for comparing outputs and performance of multiple models."""

    def __init__(self, llm_manager: Optional[LLMManager] = None):
        """Initialize the model comparison tool.

        Args:
            llm_manager: LLM manager instance
        """
        self.llm_manager = llm_manager
        self.performance_monitor = get_performance_monitor()
        self.batch_tester = get_batch_tester(llm_manager)

        # Storage for comparison reports
        self.reports: List[ComparisonReport] = []
        self.save_dir = Path.home() / ".intellicrack" / "model_comparisons"
        self.save_dir.mkdir(parents=True, exist_ok=True)

    def compare_outputs(
        self,
        model_ids: List[str],
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: int = 500,
        temperature: float = 0.7,
        num_samples: int = 1
    ) -> ComparisonReport:
        """Compare outputs from multiple models on the same prompt.

        Args:
            model_ids: List of model IDs to compare
            prompt: Input prompt
            system_prompt: Optional system prompt
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            num_samples: Number of samples per model

        Returns:
            Comparison report
        """
        comparison_id = f"compare_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        results = []

        # Generate outputs from each model
        for model_id in model_ids:
            model_results = []

            for _ in range(num_samples):
                result = self._generate_output(
                    model_id,
                    prompt,
                    system_prompt,
                    max_tokens,
                    temperature
                )

                if result:
                    model_results.append(result)

            # Average results if multiple samples
            if model_results:
                avg_result = self._average_results(model_id, model_results)
                results.append(avg_result)

        # Analyze outputs
        analysis = self._analyze_outputs(results)

        # Calculate similarity scores
        self._calculate_similarities(results)

        # Create visualizations
        visualizations = self._create_visualizations(results, comparison_id)

        # Create report
        report = ComparisonReport(
            comparison_id=comparison_id,
            timestamp=datetime.now(),
            prompt=prompt,
            models=model_ids,
            results=results,
            analysis=analysis,
            visualizations=visualizations
        )

        self.reports.append(report)
        self._save_report(report)

        return report

    def _generate_output(
        self,
        model_id: str,
        prompt: str,
        system_prompt: Optional[str],
        max_tokens: int,
        temperature: float
    ) -> Optional[ComparisonResult]:
        """Generate output from a single model."""
        if not self.llm_manager:
            return None

        llm = self.llm_manager.get_llm(model_id)
        if not llm:
            logger.error(f"Model {model_id} not found")
            return None

        # Build messages
        messages = []
        if system_prompt:
            messages.append(LLMMessage(role="system", content=system_prompt))
        messages.append(LLMMessage(role="user", content=prompt))

        # Track performance
        perf_context = self.performance_monitor.start_inference(model_id)
        start_time = time.time()

        try:
            # Temporarily update parameters
            original_temp = llm.config.temperature
            original_max_tokens = llm.config.max_tokens

            llm.config.temperature = temperature
            llm.config.max_tokens = max_tokens

            # Generate output
            response = llm.complete(messages)

            # Restore parameters
            llm.config.temperature = original_temp
            llm.config.max_tokens = original_max_tokens

            inference_time = time.time() - start_time
            output = response.content
            tokens_generated = response.usage.get(
                "completion_tokens", 0) if response.usage else len(output.split())

            # End performance tracking
            perf_metrics = self.performance_monitor.end_inference(
                perf_context,
                tokens_generated=tokens_generated,
                sequence_length=len(prompt)
            )

            return ComparisonResult(
                model_id=model_id,
                output=output,
                inference_time=inference_time,
                tokens_generated=tokens_generated,
                tokens_per_second=perf_metrics.tokens_per_second,
                memory_used_mb=perf_metrics.memory_used_mb + perf_metrics.gpu_memory_mb
            )

        except Exception as e:
            logger.error(f"Failed to generate output from {model_id}: {e}")
            self.performance_monitor.end_inference(
                perf_context, tokens_generated=0, error=str(e))
            return None

    def _average_results(
        self,
        model_id: str,
        results: List[ComparisonResult]
    ) -> ComparisonResult:
        """Average multiple results from the same model."""
        if len(results) == 1:
            return results[0]

        # For multiple samples, return the median by inference time
        results.sort(key=lambda r: r.inference_time)
        median_idx = len(results) // 2
        median_result = results[median_idx]

        # But use average performance metrics
        avg_inference_time = np.mean([r.inference_time for r in results])
        avg_tokens_per_second = np.mean([r.tokens_per_second for r in results])
        avg_memory = np.mean([r.memory_used_mb for r in results])

        return ComparisonResult(
            model_id=model_id,
            output=median_result.output,
            inference_time=avg_inference_time,
            tokens_generated=median_result.tokens_generated,
            tokens_per_second=avg_tokens_per_second,
            memory_used_mb=avg_memory
        )

    def _analyze_outputs(self, results: List[ComparisonResult]) -> Dict[str, Any]:
        """Analyze and compare outputs."""
        analysis = {
            "output_lengths": {},
            "performance": {},
            "consistency": {}
        }

        # Output length analysis
        for result in results:
            analysis["output_lengths"][result.model_id] = {
                "characters": len(result.output),
                "words": len(result.output.split()),
                "tokens": result.tokens_generated
            }

        # Performance analysis
        inference_times = [r.inference_time for r in results]
        tokens_per_second = [r.tokens_per_second for r in results]
        memory_usage = [r.memory_used_mb for r in results]

        fastest_idx = np.argmin(inference_times)
        slowest_idx = np.argmax(inference_times)

        analysis["performance"]["fastest_model"] = results[fastest_idx].model_id
        analysis["performance"]["slowest_model"] = results[slowest_idx].model_id
        analysis["performance"]["speed_difference"] = inference_times[slowest_idx] / \
            inference_times[fastest_idx]
        analysis["performance"]["avg_tokens_per_second"] = np.mean(
            tokens_per_second)
        analysis["performance"]["avg_memory_usage_mb"] = np.mean(memory_usage)

        # Efficiency ranking
        efficiency_scores = []
        for result in results:
            # Balance speed and memory usage
            efficiency = result.tokens_per_second / \
                (result.memory_used_mb / 100)
            efficiency_scores.append((result.model_id, efficiency))

        efficiency_scores.sort(key=lambda x: x[1], reverse=True)
        analysis["performance"]["efficiency_ranking"] = [m[0]
                                                         for m in efficiency_scores]

        # Output consistency (simple keyword analysis)
        all_outputs = [r.output.lower() for r in results]
        common_words = set(all_outputs[0].split())
        for output in all_outputs[1:]:
            common_words &= set(output.split())

        analysis["consistency"]["common_words"] = len(common_words)
        analysis["consistency"]["avg_word_overlap"] = len(
            common_words) / np.mean([len(o.split()) for o in all_outputs])

        return analysis

    def _calculate_similarities(self, results: List[ComparisonResult]):
        """Calculate similarity scores between outputs."""
        try:
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.metrics.pairwise import cosine_similarity

            # Extract outputs
            outputs = [r.output for r in results]

            # Calculate TF-IDF vectors
            vectorizer = TfidfVectorizer()
            tfidf_matrix = vectorizer.fit_transform(outputs)

            # Calculate cosine similarities
            similarity_matrix = cosine_similarity(tfidf_matrix)

            # Add similarity scores to results
            for i, result in enumerate(results):
                result.similarity_scores = {}
                for j, other_result in enumerate(results):
                    if i != j:
                        result.similarity_scores[other_result.model_id] = float(
                            similarity_matrix[i][j])

        except ImportError:
            logger.warning(
                "scikit-learn not available for similarity calculation")

    def _create_visualizations(
        self,
        results: List[ComparisonResult],
        comparison_id: str
    ) -> Dict[str, Path]:
        """Create visualization charts."""
        visualizations = {}

        try:
            # Performance comparison chart
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

            model_ids = [r.model_id for r in results]
            inference_times = [r.inference_time for r in results]
            tokens_per_second = [r.tokens_per_second for r in results]

            # Inference time bar chart
            ax1.bar(model_ids, inference_times)
            ax1.set_xlabel('Model')
            ax1.set_ylabel('Inference Time (s)')
            ax1.set_title('Inference Time Comparison')
            ax1.tick_params(axis='x', rotation=45)

            # Tokens per second bar chart
            ax2.bar(model_ids, tokens_per_second, color='green')
            ax2.set_xlabel('Model')
            ax2.set_ylabel('Tokens per Second')
            ax2.set_title('Generation Speed Comparison')
            ax2.tick_params(axis='x', rotation=45)

            plt.tight_layout()

            perf_chart_path = self.save_dir / \
                f"{comparison_id}_performance.png"
            fig.savefig(perf_chart_path)
            plt.close(fig)

            visualizations["performance_chart"] = perf_chart_path

            # Memory usage chart
            fig, ax = plt.subplots(figsize=(8, 6))

            memory_usage = [r.memory_used_mb for r in results]

            ax.bar(model_ids, memory_usage, color='orange')
            ax.set_xlabel('Model')
            ax.set_ylabel('Memory Usage (MB)')
            ax.set_title('Memory Usage Comparison')
            ax.tick_params(axis='x', rotation=45)

            plt.tight_layout()

            memory_chart_path = self.save_dir / f"{comparison_id}_memory.png"
            plt.savefig(memory_chart_path)
            plt.close()

            visualizations["memory_chart"] = memory_chart_path

            # Similarity heatmap if available
            if results[0].similarity_scores:
                fig, ax = plt.subplots(figsize=(8, 6))

                # Build similarity matrix
                n = len(results)
                sim_matrix = np.eye(n)

                for i, result in enumerate(results):
                    for j, other_result in enumerate(results):
                        if i != j and other_result.model_id in result.similarity_scores:
                            sim_matrix[i][j] = result.similarity_scores[other_result.model_id]

                im = ax.imshow(sim_matrix, cmap='YlOrRd', aspect='auto')

                ax.set_xticks(np.arange(n))
                ax.set_yticks(np.arange(n))
                ax.set_xticklabels(model_ids)
                ax.set_yticklabels(model_ids)

                plt.setp(ax.get_xticklabels(), rotation=45,
                         ha="right", rotation_mode="anchor")

                # Add colorbar
                cbar = plt.colorbar(im, ax=ax)
                cbar.set_label('Cosine Similarity')

                ax.set_title('Output Similarity Matrix')

                plt.tight_layout()

                sim_chart_path = self.save_dir / \
                    f"{comparison_id}_similarity.png"
                plt.savefig(sim_chart_path)
                plt.close()

                visualizations["similarity_chart"] = sim_chart_path

        except Exception as e:
            logger.error(f"Failed to create visualizations: {e}")

        return visualizations

    def benchmark_models(
        self,
        model_ids: List[str],
        test_suite: str = "basic"
    ) -> Dict[str, Any]:
        """Run comprehensive benchmark on models.

        Args:
            model_ids: Models to benchmark
            test_suite: Test suite to use

        Returns:
            Benchmark results
        """
        # Use batch tester for comprehensive testing
        batch_report = self.batch_tester.run_batch_test(model_ids, test_suite)

        # Get performance metrics from monitor
        perf_summaries = {}
        for model_id in model_ids:
            perf_summaries[model_id] = self.performance_monitor.get_metrics_summary(
                model_id)

        # Combine results
        benchmark_results = {
            "test_suite": test_suite,
            "timestamp": datetime.now().isoformat(),
            "models": {}
        }

        for model_id in model_ids:
            model_stats = batch_report.summary["models"].get(model_id, {})
            perf_stats = perf_summaries.get(model_id, {})

            benchmark_results["models"][model_id] = {
                "test_performance": {
                    "success_rate": model_stats.get("success", 0) / model_stats.get("total", 1),
                    "validation_rate": model_stats.get("validation_passed", 0) / model_stats.get("success", 1),
                    "avg_inference_time": model_stats.get("avg_inference_time", 0),
                    "avg_tokens_per_second": model_stats.get("avg_tokens_per_second", 0)
                },
                "resource_usage": {
                    "avg_memory_mb": perf_stats.get("benchmark", {}).get("avg_memory_mb", 0),
                    "p95_latency": perf_stats.get("benchmark", {}).get("p95_latency", 0),
                    "device": perf_stats.get("benchmark", {}).get("device", "unknown")
                }
            }

        # Generate rankings
        metrics_to_rank = [
            ("success_rate", True),  # Higher is better
            ("avg_tokens_per_second", True),
            ("avg_memory_mb", False),  # Lower is better
            ("p95_latency", False)
        ]

        rankings = {}
        for metric, higher_better in metrics_to_rank:
            values = []
            for model_id in model_ids:
                if metric in ["success_rate", "avg_tokens_per_second"]:
                    value = benchmark_results["models"][model_id]["test_performance"].get(
                        metric, 0)
                else:
                    value = benchmark_results["models"][model_id]["resource_usage"].get(
                        metric, float('inf'))
                values.append((model_id, value))

            values.sort(key=lambda x: x[1], reverse=higher_better)
            rankings[metric] = [v[0] for v in values]

        benchmark_results["rankings"] = rankings

        # Overall recommendation
        score_weights = {
            "success_rate": 0.3,
            "avg_tokens_per_second": 0.3,
            "avg_memory_mb": 0.2,
            "p95_latency": 0.2
        }

        overall_scores = {}
        for model_id in model_ids:
            score = 0
            for metric, weight in score_weights.items():
                rank_position = rankings[metric].index(model_id)
                normalized_score = 1 - (rank_position / len(model_ids))
                score += normalized_score * weight
            overall_scores[model_id] = score

        best_model = max(overall_scores.items(), key=lambda x: x[1])
        benchmark_results["recommendation"] = {
            "best_overall": best_model[0],
            "overall_scores": overall_scores
        }

        return benchmark_results

    def _save_report(self, report: ComparisonReport):
        """Save comparison report to disk."""
        report_file = self.save_dir / f"{report.comparison_id}_report.json"

        # Convert report to JSON-serializable format
        report_data = {
            "comparison_id": report.comparison_id,
            "timestamp": report.timestamp.isoformat(),
            "prompt": report.prompt,
            "models": report.models,
            "results": [
                {
                    "model_id": r.model_id,
                    "output": r.output,
                    "inference_time": r.inference_time,
                    "tokens_generated": r.tokens_generated,
                    "tokens_per_second": r.tokens_per_second,
                    "memory_used_mb": r.memory_used_mb,
                    "similarity_scores": r.similarity_scores
                }
                for r in report.results
            ],
            "analysis": report.analysis,
            "visualizations": {k: str(v) for k, v in report.visualizations.items()}
        }

        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2)

        logger.info(f"Saved comparison report to {report_file}")

    def generate_html_report(self, report: ComparisonReport) -> Path:
        """Generate HTML report with visualizations.

        Args:
            report: Comparison report

        Returns:
            Path to HTML file
        """
        html_file = self.save_dir / f"{report.comparison_id}_report.html"

        # Convert image paths to base64 for embedding
        embedded_images = {}
        for name, path in report.visualizations.items():
            if path.exists():
                import base64
                with open(path, 'rb') as f:
                    img_data = base64.b64encode(f.read()).decode()
                    embedded_images[name] = f"data:image/png;base64,{img_data}"

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Model Comparison Report - {report.comparison_id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }}
        .header {{ background-color: #333; color: white; padding: 20px; margin-bottom: 20px; }}
        .section {{ margin: 20px 0; padding: 15px; background-color: #f4f4f4; }}
        .model-output {{ background-color: #fff; padding: 10px; margin: 10px 0; border: 1px solid #ddd; }}
        .metrics {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }}
        .metric {{ background-color: #e9e9e9; padding: 10px; text-align: center; }}
        img {{ max-width: 100%; height: auto; margin: 10px 0; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #333; color: white; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Model Comparison Report</h1>
        <p>Generated: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>

    <div class="section">
        <h2>Prompt</h2>
        <p>{report.prompt}</p>
    </div>

    <div class="section">
        <h2>Model Outputs</h2>
"""

        for result in report.results:
            html += f"""
        <div class="model-output">
            <h3>{result.model_id}</h3>
            <div class="metrics">
                <div class="metric">
                    <strong>Inference Time</strong><br>
                    {result.inference_time:.3f}s
                </div>
                <div class="metric">
                    <strong>Tokens/Second</strong><br>
                    {result.tokens_per_second:.1f}
                </div>
                <div class="metric">
                    <strong>Memory Used</strong><br>
                    {result.memory_used_mb:.1f} MB
                </div>
            </div>
            <h4>Output:</h4>
            <pre>{result.output}</pre>
        </div>
"""

        html += """
    </div>

    <div class="section">
        <h2>Performance Analysis</h2>
"""

        if "performance_chart" in embedded_images:
            html += f'<img src="{embedded_images["performance_chart"]}" alt="Performance Chart">'

        if "memory_chart" in embedded_images:
            html += f'<img src="{embedded_images["memory_chart"]}" alt="Memory Usage Chart">'

        html += f"""
        <h3>Summary</h3>
        <ul>
            <li><strong>Fastest Model:</strong> {report.analysis['performance']['fastest_model']}</li>
            <li><strong>Most Efficient:</strong> {report.analysis['performance']['efficiency_ranking'][0]}</li>
            <li><strong>Speed Difference:</strong> {report.analysis['performance']['speed_difference']:.1f}x</li>
        </ul>
    </div>
"""

        if "similarity_chart" in embedded_images:
            html += f"""
    <div class="section">
        <h2>Output Similarity</h2>
        <img src="{embedded_images["similarity_chart"]}" alt="Similarity Matrix">
        <p>Common word overlap: {report.analysis['consistency']['avg_word_overlap']:.1%}</p>
    </div>
"""

        html += """
</body>
</html>
"""

        with open(html_file, 'w') as f:
            f.write(html)

        logger.info(f"Generated HTML report: {html_file}")
        return html_file


# Global instance
_COMPARISON_TOOL = None


def get_comparison_tool(llm_manager: Optional[LLMManager] = None) -> ModelComparison:
    """Get the global model comparison tool."""
    global _COMPARISON_TOOL
    if _COMPARISON_TOOL is None:
        _COMPARISON_TOOL = ModelComparison(llm_manager=llm_manager)
    return _COMPARISON_TOOL
