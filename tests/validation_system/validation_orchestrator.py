"""
Validation Orchestrator for Intellicrack Validation Framework.
Coordinates all validation activities: Statistical Validation and Confidence.
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass, asdict
from datetime import datetime

from commercial_binary_manager import CommercialBinaryManager
from statistical_analysis import StatisticalAnalysis, StatisticalAnalysisResult
from cross_environment_validator import CrossEnvironmentValidator, CrossEnvironmentResult

logger = logging.getLogger(__name__)


@dataclass
class ValidationTestResult:
    """Result of validation testing."""
    statistical_analysis_results: List[StatisticalAnalysisResult]
    cross_environment_results: List[CrossEnvironmentResult]
    overall_success: bool
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


@dataclass
class ValidationReport:
    """Comprehensive report of validation."""
    test_results: ValidationTestResult
    summary: Dict[str, Any]
    recommendations: List[str]
    overall_status: str
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


class ValidationOrchestrator:
    """Orchestrates all validation activities."""

    def __init__(self, base_dir: str = "C:\\Intellicrack\\tests\\validation_system"):
        self.base_dir = Path(base_dir)
        self.reports_dir = self.base_dir / "reports"
        self.reports_dir.mkdir(exist_ok=True)

        # Initialize all components
        self.binary_manager = CommercialBinaryManager(base_dir)
        self.statistical_analyzer = StatisticalAnalysis(base_dir)
        self.environment_validator = CrossEnvironmentValidator(base_dir)

        logger.info("Validation Orchestrator initialized")

    def run_statistical_analysis(self) -> List[StatisticalAnalysisResult]:
        """
        Run statistical analysis on all available binaries.
        """
        logger.info("Starting statistical analysis for all binaries")
        results = self.statistical_analyzer.run_all_statistical_analyses()
        logger.info(f"Completed statistical analysis: {len(results)} results")
        return results

    def run_cross_environment_validation(self) -> List[CrossEnvironmentResult]:
        """
        Run cross-environment validation on all available binaries.
        """
        logger.info("Starting cross-environment validation for all binaries")
        results = self.environment_validator.validate_all_cross_environment()
        logger.info(f"Completed cross-environment validation: {len(results)} results")
        return results

    def execute_validation(self) -> ValidationTestResult:
        """
        Execute the complete validation.
        """
        logger.info("Executing validation")

        # Run all test categories
        statistical_results = self.run_statistical_analysis()
        cross_environment_results = self.run_cross_environment_validation()

        # Determine overall success
        # For now, we'll consider it successful if we have results from each category
        overall_success = (
            len(statistical_results) > 0 and
            len(cross_environment_results) > 0
        )

        result = ValidationTestResult(
            statistical_analysis_results=statistical_results,
            cross_environment_results=cross_environment_results,
            overall_success=overall_success
        )

        logger.info(f"Validation completed. Success: {overall_success}")
        return result

    def generate_validation_report(self, test_result: ValidationTestResult) -> ValidationReport:
        """
        Generate a comprehensive report of validation.
        """
        logger.info("Generating validation report")

        # Calculate summary statistics
        summary = {
            "total_statistical_tests": len(test_result.statistical_analysis_results),
            "total_cross_environment_tests": len(test_result.cross_environment_results),
            "overall_success": test_result.overall_success
        }

        # Add success rates for each category
        successful_statistical = sum(1 for r in test_result.statistical_analysis_results if r.success_rate >= 0.95)
        successful_cross_environment = sum(1 for r in test_result.cross_environment_results if r.consistency_rate >= 0.90)

        if summary["total_statistical_tests"] > 0:
            summary["statistical_success_rate"] = successful_statistical / summary["total_statistical_tests"]

        if summary["total_cross_environment_tests"] > 0:
            summary["cross_environment_success_rate"] = successful_cross_environment / summary["total_cross_environment_tests"]

        # Generate recommendations
        recommendations = []
        if summary.get("statistical_success_rate", 0) < 0.95:
            recommendations.append("Improve statistical consistency of test results")

        if summary.get("cross_environment_success_rate", 0) < 0.90:
            recommendations.append("Enhance cross-environment compatibility")

        # Determine overall status
        if test_result.overall_success and all(rate >= 0.8 for rate in [
            summary.get("statistical_success_rate", 0),
            summary.get("cross_environment_success_rate", 0)
        ]):
            overall_status = "PASS"
        else:
            overall_status = "FAIL"

        report = ValidationReport(
            test_results=test_result,
            summary=summary,
            recommendations=recommendations,
            overall_status=overall_status
        )

        logger.info(f"Validation report generated. Status: {overall_status}")
        return report

    def save_validation_report(self, report: ValidationReport, filename: str = None) -> str:
        """
        Save the validation report to a JSON file.
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"validation_report_{timestamp}.json"

        report_path = self.reports_dir / filename

        # Convert to dict for JSON serialization
        report_dict = {
            "report": asdict(report),
            "generated_at": datetime.now().isoformat()
        }

        with open(report_path, 'w') as f:
            json.dump(report_dict, f, indent=2)

        logger.info(f"Validation report saved to {report_path}")
        return str(report_path)

    def run_complete_validation(self) -> str:
        """
        Run the complete validation and generate a report.
        """
        logger.info("Starting complete validation")

        try:
            # Execute validation
            test_result = self.execute_validation()

            # Generate report
            report = self.generate_validation_report(test_result)

            # Save report
            report_path = self.save_validation_report(report)

            # Print summary
            print("Validation Summary")
            print("=" * 50)
            print(f"Overall Status: {report.overall_status}")
            print(f"Generated: {report.timestamp}")
            print()
            print("Test Results:")
            print(f"  Statistical Tests: {report.summary.get('total_statistical_tests', 0)}")
            print(f"  Cross-Environment Tests: {report.summary.get('total_cross_environment_tests', 0)}")
            print()
            print("Success Rates:")
            print(f"  Statistical: {report.summary.get('statistical_success_rate', 0):.2%}")
            print(f"  Cross-Environment: {report.summary.get('cross_environment_success_rate', 0):.2%}")
            print()
            print("Recommendations:")
            for recommendation in report.recommendations:
                print(f"  - {recommendation}")
            print()
            print(f"Full report saved to: {report_path}")

            return report_path

        except Exception as e:
            logger.error(f"Failed to complete validation: {e}")
            raise


if __name__ == "__main__":
    # Run the Validation orchestrator
    orchestrator = ValidationOrchestrator()

    try:
        print("Intellicrack Validation Orchestrator")
        print("=" * 50)

        # Run complete validation
        report_path = orchestrator.run_complete_validation()

        print(f"\nValidation completed successfully!")
        print(f"Report saved to: {report_path}")

    except Exception as e:
        print(f"Error during validation: {e}")
        import traceback
        traceback.print_exc()
