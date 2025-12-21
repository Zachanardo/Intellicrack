"""
Phase 6.4: Statistical Requirements Validator

This module implements comprehensive validation of statistical requirements,
ensuring rigorous mathematical analysis of test results with proper confidence intervals.
"""

import math
import logging
import json
import numpy as np
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass
from pathlib import Path
from datetime import datetime
from enum import Enum
import scipy.stats as stats
from scipy.stats import t, norm, chi2_contingency
import matplotlib.pyplot as plt
import seaborn as sns

class StatisticalResult(Enum):
    """Statistical validation result."""
    PASS = "PASS"
    FAIL = "FAIL"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
    INVALID = "INVALID"

@dataclass
class TestRun:
    """Structure for individual test run data."""
    run_id: int
    success: bool
    execution_time_seconds: float
    timestamp: str
    metadata: dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

@dataclass
class StatisticalAnalysis:
    """Results of statistical analysis."""
    total_runs: int
    successful_runs: int
    success_rate: float
    confidence_interval_99: tuple[float, float]
    p_value: float
    t_statistic: float
    degrees_of_freedom: int
    outliers_excluded: list[int]
    sample_statistics: dict[str, float]

class StatisticalRequirementsValidator:
    """
    Implements Phase 6.4 requirements for statistical validation.

    Non-negotiable requirements:
    - Minimum 10 test runs per software per protection
    - Success rate calculation: (successful_runs / total_runs) × 100%
    - 99% confidence interval using Student's t-distribution
    - P-value must be < 0.01 for hypothesis "success_rate ≥ 0.95"
    - Outlier handling: Runs > 3 standard deviations excluded with documentation
    - FAIL conditions: Fewer than 10 runs = INVALID, CI includes values < 0.95 = FAIL
    """

    def __init__(self, output_path: Path):
        """Initialize statistical requirements validator."""
        self.output_path = Path(output_path)
        self.logger = logging.getLogger(__name__)

        # Statistical configuration
        self.config = {
            "min_test_runs": 10,
            "required_success_rate": 0.95,
            "confidence_level": 0.99,
            "alpha": 0.01,  # For hypothesis testing
            "outlier_threshold": 3.0,  # Standard deviations for outlier detection
            "bootstrap_samples": 10000  # For bootstrap confidence intervals
        }

        # Create output directory
        self.output_path.mkdir(parents=True, exist_ok=True)

    def validate_statistical_requirements(self, test_runs: list[TestRun],
                                        software_name: str,
                                        protection_name: str) -> tuple[StatisticalResult, dict[str, Any]]:
        """
        Validate statistical requirements against Phase 6.4 criteria.

        Args:
            test_runs: List of test run results
            software_name: Name of software being tested
            protection_name: Name of protection being analyzed

        Returns:
            Tuple of (StatisticalResult, detailed_report)
        """
        validation_report = {
            "timestamp": self._get_timestamp(),
            "software_name": software_name,
            "protection_name": protection_name,
            "raw_data": [run.__dict__ for run in test_runs],
            "statistical_analysis": {},
            "validation_results": {},
            "overall_result": StatisticalResult.INSUFFICIENT_DATA,
            "failure_reasons": []
        }

        try:
            # 6.4.1: Check minimum test runs requirement
            min_runs_check = self._validate_minimum_runs(test_runs, validation_report)

            if not min_runs_check:
                validation_report["overall_result"] = StatisticalResult.INSUFFICIENT_DATA
                return validation_report["overall_result"], validation_report

            # 6.4.5: Outlier detection and handling
            cleaned_runs, outliers = self._handle_outliers(test_runs)
            validation_report["outliers_excluded"] = [run.run_id for run in outliers]

            # 6.4.2: Success rate calculation
            statistical_analysis = self._calculate_statistical_metrics(cleaned_runs)
            validation_report["statistical_analysis"] = statistical_analysis.__dict__

            # 6.4.3: 99% confidence interval using Student's t-distribution
            confidence_interval_valid = self._validate_confidence_interval(statistical_analysis, validation_report)

            # 6.4.4: P-value hypothesis testing
            p_value_valid = self._validate_p_value(statistical_analysis, validation_report)

            # Additional statistical validations
            normality_test = self._test_normality(cleaned_runs)
            validation_report["normality_test"] = normality_test

            # Power analysis
            power_analysis = self._conduct_power_analysis(cleaned_runs)
            validation_report["power_analysis"] = power_analysis

            # Effect size calculation
            effect_size = self._calculate_effect_size(statistical_analysis)
            validation_report["effect_size"] = effect_size

            # Generate statistical plots
            plot_paths = self._generate_statistical_plots(cleaned_runs, statistical_analysis,
                                                        software_name, protection_name)
            validation_report["plots"] = plot_paths

            # Determine overall result
            if confidence_interval_valid and p_value_valid:
                validation_report["overall_result"] = StatisticalResult.PASS
            else:
                validation_report["overall_result"] = StatisticalResult.FAIL

        except Exception as e:
            self.logger.error(f"Statistical validation failed: {e}")
            validation_report["overall_result"] = StatisticalResult.INVALID
            validation_report["error"] = str(e)

        return validation_report["overall_result"], validation_report

    def _validate_minimum_runs(self, test_runs: list[TestRun], report: dict[str, Any]) -> bool:
        """6.4.1: Validate minimum 10 test runs requirement."""
        try:
            actual_runs = len(test_runs)
            min_required = self.config["min_test_runs"]

            meets_minimum = actual_runs >= min_required

            report["validation_results"]["minimum_runs"] = {
                "pass": meets_minimum,
                "actual_runs": actual_runs,
                "minimum_required": min_required
            }

            if not meets_minimum:
                report["failure_reasons"].append(f"Insufficient test runs: {actual_runs} < {min_required}")

            return meets_minimum

        except Exception as e:
            report["validation_results"]["minimum_runs"] = {
                "pass": False,
                "error": str(e)
            }
            return False

    def _handle_outliers(self, test_runs: list[TestRun]) -> tuple[list[TestRun], list[TestRun]]:
        """6.4.5: Handle outliers using 3 standard deviations rule."""
        try:
            if len(test_runs) < 3:
                return test_runs, []

            # Extract execution times for outlier detection
            execution_times = [run.execution_time_seconds for run in test_runs]

            # Calculate mean and standard deviation
            mean_time = np.mean(execution_times)
            std_time = np.std(execution_times, ddof=1)  # Sample standard deviation

            # Identify outliers (more than 3 standard deviations from mean)
            threshold = self.config["outlier_threshold"]
            outliers = []
            cleaned_runs = []

            for run in test_runs:
                z_score = abs(run.execution_time_seconds - mean_time) / std_time
                if z_score > threshold:
                    outliers.append(run)
                    self.logger.warning(f"Excluding outlier run {run.run_id} with z-score {z_score:.2f}")
                else:
                    cleaned_runs.append(run)

            return cleaned_runs, outliers

        except Exception as e:
            self.logger.error(f"Outlier handling failed: {e}")
            return test_runs, []

    def _calculate_statistical_metrics(self, test_runs: list[TestRun]) -> StatisticalAnalysis:
        """6.4.2: Calculate comprehensive statistical metrics."""
        try:
            total_runs = len(test_runs)
            successful_runs = sum(bool(run.success)
                              for run in test_runs)
            success_rate = successful_runs / total_runs if total_runs > 0 else 0.0

            # Calculate 99% confidence interval using Wilson score interval
            # More accurate than normal approximation for proportions
            confidence_interval = self._wilson_score_interval(
                successful_runs, total_runs, self.config["confidence_level"]
            )

            # Hypothesis test: H0: p >= 0.95, H1: p < 0.95
            p_null = self.config["required_success_rate"]

            # Use one-sample proportion test
            if total_runs > 0:
                # Calculate test statistic
                p_hat = success_rate
                se = math.sqrt(p_null * (1 - p_null) / total_runs)

                # Calculate p-value (one-tailed test)
                df = total_runs - 1
                if se > 0:
                    t_stat = (p_hat - p_null) / se

                    p_value = stats.t.cdf(t_stat, df)
                else:
                    t_stat = 0
                    p_value = 1.0
            else:
                t_stat = 0
                p_value = 1.0
                df = 0

            # Calculate additional sample statistics
            execution_times = [run.execution_time_seconds for run in test_runs]
            sample_statistics = {
                "mean_execution_time": (
                    np.mean(execution_times) if execution_times else 0
                ),
                "std_execution_time": (
                    np.std(execution_times, ddof=1)
                    if len(execution_times) > 1
                    else 0
                ),
                "median_execution_time": (
                    np.median(execution_times) if execution_times else 0
                ),
                "min_execution_time": min(execution_times, default=0),
                "max_execution_time": max(execution_times, default=0),
            }

            return StatisticalAnalysis(
                total_runs=total_runs,
                successful_runs=successful_runs,
                success_rate=success_rate,
                confidence_interval_99=confidence_interval,
                p_value=p_value,
                t_statistic=t_stat,
                degrees_of_freedom=df,
                outliers_excluded=[],  # Already handled
                sample_statistics=sample_statistics
            )

        except Exception as e:
            self.logger.error(f"Statistical calculation failed: {e}")
            raise

    def _wilson_score_interval(self, successes: int, trials: int, confidence: float) -> tuple[float, float]:
        """Calculate Wilson score interval for proportion confidence interval."""
        try:
            if trials == 0:
                return (0.0, 0.0)

            z = stats.norm.ppf(1 - (1 - confidence) / 2)  # Critical value
            p = successes / trials

            denominator = 1 + z**2 / trials
            centre = (p + z**2 / (2 * trials)) / denominator
            margin = z * math.sqrt(p * (1 - p) / trials + z**2 / (4 * trials**2)) / denominator

            lower = max(0, centre - margin)
            upper = min(1, centre + margin)

            return (lower, upper)

        except Exception as e:
            self.logger.error(f"Wilson score interval calculation failed: {e}")
            return (0.0, 1.0)

    def _validate_confidence_interval(self, analysis: StatisticalAnalysis, report: dict[str, Any]) -> bool:
        """6.4.3 & 6.4.6: Validate 99% confidence interval requirements."""
        try:
            ci_lower, ci_upper = analysis.confidence_interval_99
            required_rate = self.config["required_success_rate"]

            # Check if entire CI is above required success rate
            ci_valid = ci_lower >= required_rate

            report["validation_results"]["confidence_interval"] = {
                "pass": ci_valid,
                "confidence_level": self.config["confidence_level"],
                "lower_bound": ci_lower,
                "upper_bound": ci_upper,
                "required_minimum": required_rate,
                "margin_of_error": (ci_upper - ci_lower) / 2
            }

            if not ci_valid:
                report["failure_reasons"].append(
                    f"Confidence interval includes values < {required_rate:.2%} "
                    f"(CI: [{ci_lower:.3f}, {ci_upper:.3f}])"
                )

            return ci_valid

        except Exception as e:
            report["validation_results"]["confidence_interval"] = {
                "pass": False,
                "error": str(e)
            }
            return False

    def _validate_p_value(self, analysis: StatisticalAnalysis, report: dict[str, Any]) -> bool:
        """6.4.4: Validate p-value requirement."""
        try:
            alpha = self.config["alpha"]

            # For our hypothesis test H0: p >= 0.95, H1: p < 0.95
            # We reject H0 if p-value < alpha AND success rate >= required rate
            # If we reject H0, it means we have strong evidence that p >= 0.95

            hypothesis_supported = (analysis.p_value < alpha and
                                  analysis.success_rate >= self.config["required_success_rate"])

            report["validation_results"]["hypothesis_test"] = {
                "pass": hypothesis_supported,
                "null_hypothesis": f"success_rate >= {self.config['required_success_rate']:.2%}",
                "alternative_hypothesis": f"success_rate < {self.config['required_success_rate']:.2%}",
                "p_value": analysis.p_value,
                "alpha": alpha,
                "t_statistic": analysis.t_statistic,
                "degrees_of_freedom": analysis.degrees_of_freedom,
                "actual_success_rate": analysis.success_rate
            }

            if not hypothesis_supported:
                if analysis.p_value >= alpha:
                    report["failure_reasons"].append(
                        f"P-value too high: {analysis.p_value:.4f} >= {alpha}"
                    )
                if analysis.success_rate < self.config["required_success_rate"]:
                    report["failure_reasons"].append(
                        f"Success rate below requirement: {analysis.success_rate:.2%} < {self.config['required_success_rate']:.2%}"
                    )

            return hypothesis_supported

        except Exception as e:
            report["validation_results"]["hypothesis_test"] = {
                "pass": False,
                "error": str(e)
            }
            return False

    def _test_normality(self, test_runs: list[TestRun]) -> dict[str, Any]:
        """Test normality of execution times using Shapiro-Wilk test."""
        try:
            execution_times = [run.execution_time_seconds for run in test_runs]

            if len(execution_times) < 3:
                return {"test": "insufficient_data", "p_value": None, "normal": None}

            # Shapiro-Wilk test for normality
            statistic, p_value = stats.shapiro(execution_times)

            # Null hypothesis: data is normally distributed
            # Reject if p-value < 0.05
            is_normal = p_value > 0.05

            return {
                "test": "shapiro_wilk",
                "statistic": statistic,
                "p_value": p_value,
                "normal": is_normal,
                "interpretation": "normally distributed" if is_normal else "not normally distributed"
            }

        except Exception as e:
            return {"test": "error", "error": str(e)}

    def _conduct_power_analysis(self, test_runs: list[TestRun]) -> dict[str, Any]:
        """Conduct statistical power analysis."""
        try:
            n = len(test_runs)
            success_rate = sum(bool(run.success)
                           for run in test_runs) / n if n > 0 else 0

            # Calculate power for detecting difference from required success rate
            effect_size = abs(success_rate - self.config["required_success_rate"])

            # Power calculation for proportion test
            alpha = self.config["alpha"]
            p0 = self.config["required_success_rate"]  # Null hypothesis value
            p1 = success_rate  # Alternative hypothesis value

            if effect_size > 0:
                # Standard error under null hypothesis
                se_null = math.sqrt(p0 * (1 - p0) / n)

                # Critical value
                z_alpha = stats.norm.ppf(1 - alpha)

                # Power calculation
                z_beta = (abs(p1 - p0) - z_alpha * se_null) / math.sqrt(p1 * (1 - p1) / n)
                power = stats.norm.cdf(z_beta)
            else:
                power = alpha  # No effect to detect

            return {
                "sample_size": n,
                "effect_size": effect_size,
                "power": power,
                "alpha": alpha,
                "interpretation": "adequate" if power >= 0.8 else "inadequate"
            }

        except Exception as e:
            return {"error": str(e)}

    def _calculate_effect_size(self, analysis: StatisticalAnalysis) -> dict[str, Any]:
        """Calculate effect size measures."""
        try:
            # Cohen's h for proportions
            p1 = analysis.success_rate
            p0 = self.config["required_success_rate"]

            # Arcsine transformation
            cohens_h = 2 * (math.asin(math.sqrt(p1)) - math.asin(math.sqrt(p0)))

            # Interpretation
            if abs(cohens_h) < 0.2:
                interpretation = "small"
            elif abs(cohens_h) < 0.5:
                interpretation = "medium"
            else:
                interpretation = "large"

            return {
                "cohens_h": cohens_h,
                "interpretation": interpretation,
                "observed_rate": p1,
                "reference_rate": p0
            }

        except Exception as e:
            return {"error": str(e)}

    def _generate_statistical_plots(self, test_runs: list[TestRun],
                                  analysis: StatisticalAnalysis,
                                  software_name: str,
                                  protection_name: str) -> list[str]:
        """Generate statistical visualization plots."""
        plot_paths = []

        try:
            # Set up matplotlib
            plt.style.use('seaborn-v0_8')
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

            # 1. Success rate with confidence interval
            fig, ax = plt.subplots(1, 1, figsize=(10, 6))

            success_rate = analysis.success_rate
            ci_lower, ci_upper = analysis.confidence_interval_99
            required_rate = self.config["required_success_rate"]

            # Bar plot
            ax.bar(['Observed Success Rate'], [success_rate], color='skyblue', alpha=0.7)
            ax.errorbar(['Observed Success Rate'], [success_rate],
                       yerr=[[success_rate - ci_lower], [ci_upper - success_rate]],
                       fmt='none', color='black', capsize=5, capthick=2)

            # Reference line
            ax.axhline(y=required_rate, color='red', linestyle='--',
                      label=f'Required Rate ({required_rate:.1%})')

            ax.set_ylabel('Success Rate')
            ax.set_title(f'Success Rate Analysis: {software_name} - {protection_name}')
            ax.set_ylim(0, 1)
            ax.legend()

            # Add statistics text
            stats_text = f"""
            Sample Size: {analysis.total_runs}
            Success Rate: {success_rate:.2%}
            99% CI: [{ci_lower:.3f}, {ci_upper:.3f}]
            P-value: {analysis.p_value:.4f}
            """
            ax.text(0.02, 0.98, stats_text, transform=ax.transAxes,
                   verticalalignment='top', bbox=dict(boxstyle='round', facecolor='white', alpha=0.8))

            plot_path = self.output_path / f"success_rate_analysis_{timestamp}.png"
            plt.tight_layout()
            plt.savefig(plot_path, dpi=300, bbox_inches='tight')
            plt.close()
            plot_paths.append(str(plot_path))

            # 2. Execution time distribution
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))

            execution_times = [run.execution_time_seconds for run in test_runs]

            # Histogram
            ax1.hist(execution_times, bins=min(10, len(execution_times)),
                    color='lightgreen', alpha=0.7, edgecolor='black')
            ax1.set_xlabel('Execution Time (seconds)')
            ax1.set_ylabel('Frequency')
            ax1.set_title('Execution Time Distribution')

            # Box plot
            ax2.boxplot(execution_times)
            ax2.set_ylabel('Execution Time (seconds)')
            ax2.set_title('Execution Time Box Plot')
            ax2.set_xticklabels(['Test Runs'])

            plot_path = self.output_path / f"execution_time_analysis_{timestamp}.png"
            plt.tight_layout()
            plt.savefig(plot_path, dpi=300, bbox_inches='tight')
            plt.close()
            plot_paths.append(str(plot_path))

            # 3. Time series of test results
            fig, ax = plt.subplots(1, 1, figsize=(12, 6))

            run_numbers = [run.run_id for run in test_runs]
            success_values = [1 if run.success else 0 for run in test_runs]

            # Scatter plot with trend line
            colors = ['green' if success else 'red' for success in success_values]
            ax.scatter(run_numbers, success_values, c=colors, alpha=0.6, s=50)

            # Running average
            if len(test_runs) > 1:
                running_avg = np.cumsum(success_values) / np.arange(1, len(success_values) + 1)
                ax.plot(run_numbers, running_avg, 'b-', linewidth=2, label='Running Average')

            ax.axhline(y=required_rate, color='orange', linestyle='--',
                      label=f'Required Rate ({required_rate:.1%})')

            ax.set_xlabel('Test Run Number')
            ax.set_ylabel('Success (1) / Failure (0)')
            ax.set_title(f'Test Results Time Series: {software_name} - {protection_name}')
            ax.legend()
            ax.grid(True, alpha=0.3)

            plot_path = self.output_path / f"time_series_analysis_{timestamp}.png"
            plt.tight_layout()
            plt.savefig(plot_path, dpi=300, bbox_inches='tight')
            plt.close()
            plot_paths.append(str(plot_path))

        except Exception as e:
            self.logger.error(f"Failed to generate statistical plots: {e}")

        return plot_paths

    def _get_timestamp(self) -> str:
        """Get ISO timestamp."""
        return f'{datetime.utcnow().isoformat()}Z'

    def generate_statistical_report(self, validation_results: list[tuple[StatisticalResult, dict[str, Any]]],
                                  output_file: Path) -> None:
        """Generate comprehensive statistical validation report."""
        try:
            summary = {
                "report_type": "Intellicrack Phase 6.4 - Statistical Requirements Validation",
                "generation_timestamp": self._get_timestamp(),
                "configuration": self.config,
                "total_validations": len(validation_results),
                "results_summary": {
                    "pass": sum(bool(result == StatisticalResult.PASS)
                            for result, _ in validation_results),
                    "fail": sum(bool(result == StatisticalResult.FAIL)
                            for result, _ in validation_results),
                    "insufficient_data": sum(bool(result == StatisticalResult.INSUFFICIENT_DATA)
                                         for result, _ in validation_results),
                    "invalid": sum(bool(result == StatisticalResult.INVALID)
                               for result, _ in validation_results)
                },
                "detailed_results": []
            }

            # Calculate overall statistics
            all_test_runs = []
            for result, report in validation_results:
                if "raw_data" in report:
                    all_test_runs.extend(
                        TestRun(
                            **{
                                k: v
                                for k, v in run_data.items()
                                if k != 'metadata'
                            }
                        )
                        for run_data in report["raw_data"]
                    )
            if all_test_runs:
                overall_analysis = self._calculate_statistical_metrics(all_test_runs)
                summary["overall_statistics"] = overall_analysis.__dict__

            # Add detailed results
            for result, report in validation_results:
                summary["detailed_results"].append({
                    "result": result.value,
                    "validation_report": report
                })

            # Write report
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)

            self.logger.info(f"Statistical validation report generated: {output_file}")

        except Exception as e:
            self.logger.error(f"Failed to generate statistical report: {e}")
            raise


def main():
    """Example usage of StatisticalRequirementsValidator."""
    # Create example test runs
    test_runs = [
        TestRun(
            run_id=i + 1,
            success=np.random.random() > 0.05,
            execution_time_seconds=np.random.normal(30, 5),
            timestamp=f'{datetime.utcnow().isoformat()}Z',
        )
        for i in range(15)
    ]

    # Initialize validator
    from intellicrack.utils.path_resolver import get_project_root
    validator = StatisticalRequirementsValidator(
        output_path=get_project_root() / "tests/validation_system/phase6/statistical_analysis"
    )

    # Run validation
    result, report = validator.validate_statistical_requirements(
        test_runs=test_runs,
        software_name="Adobe Photoshop",
        protection_name="Adobe Licensing v7"
    )

    print(f"Statistical Validation Result: {result.value}")
    print(f"Report Summary: {json.dumps({k: v for k, v in report.items() if k not in ['raw_data', 'plots']}, indent=2)}")


if __name__ == "__main__":
    main()
