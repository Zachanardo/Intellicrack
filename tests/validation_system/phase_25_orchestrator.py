"""
Phase 2.5 Orchestrator for Intellicrack Validation Framework.
Coordinates all Phase 2.5 validation activities.
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass, asdict
from datetime import datetime

from commercial_binary_manager import CommercialBinaryManager
from cross_version_tester import CrossVersionTester
from unknown_pattern_tester import UnknownPatternTester
from dynamic_mutation_tester import DynamicMutationTester
from protection_variant_generator import ProtectionVariantGenerator

logger = logging.getLogger(__name__)


@dataclass
class Phase25TestResult:
    """Result of Phase 2.5 testing."""
    cross_version_results: list[dict[str, Any]]
    unknown_pattern_results: list[dict[str, Any]]
    dynamic_mutation_results: list[dict[str, Any]]
    variant_generation_results: list[dict[str, Any]]
    overall_success: bool
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


@dataclass
class Phase25Report:
    """Comprehensive report of Phase 2.5 validation."""
    test_results: Phase25TestResult
    summary: dict[str, Any]
    recommendations: list[str]
    overall_status: str
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


class Phase25Orchestrator:
    """Orchestrates all Phase 2.5 validation activities."""

    def __init__(self, base_dir: str = "C:\\Intellicrack\\tests\\validation_system"):
        self.base_dir = Path(base_dir)
        self.reports_dir = self.base_dir / "reports"
        self.reports_dir.mkdir(exist_ok=True)

        # Initialize all components
        self.binary_manager = CommercialBinaryManager(base_dir)
        self.cross_version_tester = CrossVersionTester(base_dir)
        self.unknown_pattern_tester = UnknownPatternTester(base_dir)
        self.dynamic_mutation_tester = DynamicMutationTester(base_dir)
        self.variant_generator = ProtectionVariantGenerator(base_dir)

        logger.info("Phase 2.5 Orchestrator initialized")

    def run_cross_version_testing(self) -> list[dict[str, Any]]:
        """
        Run cross-version testing on all available binaries.
        """
        logger.info("Starting cross-version testing")
        results = []

        # Get all acquired binaries
        binaries = self.binary_manager.list_acquired_binaries()

        for binary in binaries:
            try:
                software_name = binary.get("software_name", "Unknown")
                protection_name = binary.get("protection", "Unknown")
                version = binary.get("version", "Unknown")

                logger.info(f"Testing cross-versions for {software_name} with {protection_name}")

                # Run cross-version test
                report = self.cross_version_tester.test_protection_versions(
                    software_name, protection_name
                )

                results.append(asdict(report))
                logger.info(f"Cross-version test completed for {software_name}")

            except Exception as e:
                logger.error(f"Failed to test cross-versions for {software_name}: {e}")
                results.append({
                    "software_name": software_name,
                    "protection_name": protection_name,
                    "error": str(e),
                    "success": False
                })

        return results

    def run_unknown_pattern_testing(self) -> list[dict[str, Any]]:
        """
        Run unknown pattern testing on available binaries.
        """
        logger.info("Starting unknown pattern testing")
        results = []

        # Get all acquired binaries
        binaries = self.binary_manager.list_acquired_binaries()

        for binary in binaries:
            try:
                binary_path = binary.get("file_path")
                software_name = binary.get("software_name", "Unknown")

                logger.info(f"Testing unknown patterns for {software_name}")

                # Run all pattern tests
                pattern_results = self.unknown_pattern_tester.test_all_patterns(binary_path)

                # Convert to dict format
                for result in pattern_results:
                    results.append(asdict(result))

                logger.info(f"Unknown pattern testing completed for {software_name}")

            except Exception as e:
                logger.error(f"Failed to test unknown patterns for {software_name}: {e}")
                results.append({
                    "software_name": binary.get("software_name", "Unknown"),
                    "error": str(e),
                    "success": False
                })

        return results

    def run_dynamic_mutation_testing(self) -> list[dict[str, Any]]:
        """
        Run dynamic mutation testing on available binaries.
        """
        logger.info("Starting dynamic mutation testing")
        results = []

        # Get all acquired binaries
        binaries = self.binary_manager.list_acquired_binaries()

        for binary in binaries:
            try:
                binary_path = binary.get("file_path")
                software_name = binary.get("software_name", "Unknown")

                logger.info(f"Testing dynamic mutations for {software_name}")

                # Test all mutation types
                mutation_types = list(self.dynamic_mutation_tester.dynamic_mutations.keys())
                mutation_results = []

                for mutation_type in mutation_types:
                    result = self.dynamic_mutation_tester.test_dynamic_mutation(
                        mutation_type, binary_path
                    )
                    mutation_results.append(asdict(result))

                results.extend(mutation_results)
                logger.info(f"Dynamic mutation testing completed for {software_name}")

            except Exception as e:
                logger.error(f"Failed to test dynamic mutations for {software_name}: {e}")
                results.append({
                    "software_name": binary.get("software_name", "Unknown"),
                    "error": str(e),
                    "success": False
                })

        return results

    def run_variant_generation_testing(self) -> list[dict[str, Any]]:
        """
        Run protection variant generation testing.
        """
        logger.info("Starting protection variant generation testing")
        results = []

        # Get all acquired binaries
        binaries = self.binary_manager.list_acquired_binaries()

        for binary in binaries:
            try:
                binary_path = binary.get("file_path")
                software_name = binary.get("software_name", "Unknown")

                logger.info(f"Generating variants for {software_name}")

                # Generate all variants
                variants = self.variant_generator.generate_all_variants(binary_path)

                # Convert to dict format and verify protection still active
                for variant in variants:
                    # Verify protection is still active
                    protection_active = self.variant_generator._verify_protection_active(variant.binary_path)

                    results.append({
                        "software_name": software_name,
                        "mutation_type": variant.mutation_type.value,
                        "original_hash": variant.original_hash,
                        "mutated_hash": variant.mutated_hash,
                        "binary_path": variant.binary_path,
                        "success": variant.success,
                        "protection_active": protection_active,
                        "verification_passed": variant.verification_passed,
                        "mutations_applied": len(variant.mutations_applied)
                    })

                logger.info(f"Variant generation completed for {software_name}")

            except Exception as e:
                logger.error(f"Failed to generate variants for {software_name}: {e}")
                results.append({
                    "software_name": binary.get("software_name", "Unknown"),
                    "error": str(e),
                    "success": False
                })

        return results

    def execute_phase_25_validation(self) -> Phase25TestResult:
        """
        Execute the complete Phase 2.5 validation.
        """
        logger.info("Executing Phase 2.5 validation")

        # Run all test categories
        cross_version_results = self.run_cross_version_testing()
        unknown_pattern_results = self.run_unknown_pattern_testing()
        dynamic_mutation_results = self.run_dynamic_mutation_testing()
        variant_generation_results = self.run_variant_generation_testing()

        # Determine overall success
        # For now, we'll consider it successful if we have results from each category
        overall_success = (
            len(cross_version_results) > 0 and
            len(unknown_pattern_results) > 0 and
            len(dynamic_mutation_results) > 0 and
            len(variant_generation_results) > 0
        )

        result = Phase25TestResult(
            cross_version_results=cross_version_results,
            unknown_pattern_results=unknown_pattern_results,
            dynamic_mutation_results=dynamic_mutation_results,
            variant_generation_results=variant_generation_results,
            overall_success=overall_success
        )

        logger.info(f"Phase 2.5 validation completed. Success: {overall_success}")
        return result

    def generate_phase_25_report(self, test_result: Phase25TestResult) -> Phase25Report:
        """
        Generate a comprehensive report for Phase 2.5 validation.
        """
        logger.info("Generating Phase 2.5 report")

        # Calculate summary statistics
        summary = {
            "total_cross_version_tests": len(test_result.cross_version_results),
            "total_unknown_pattern_tests": len(test_result.unknown_pattern_results),
            "total_dynamic_mutation_tests": len(test_result.dynamic_mutation_results),
            "total_variant_generation_tests": len(test_result.variant_generation_results),
            "overall_success": test_result.overall_success
        }

        # Add success rates for each category
        successful_cross_version = sum(1 for r in test_result.cross_version_results if r.get("overall_success", False))
        successful_unknown_pattern = sum(1 for r in test_result.unknown_pattern_results if r.get("success", False))
        successful_dynamic_mutation = sum(1 for r in test_result.dynamic_mutation_results if r.get("success", False))
        successful_variant_generation = sum(1 for r in test_result.variant_generation_results if r.get("success", False))

        if summary["total_cross_version_tests"] > 0:
            summary["cross_version_success_rate"] = successful_cross_version / summary["total_cross_version_tests"]

        if summary["total_unknown_pattern_tests"] > 0:
            summary["unknown_pattern_success_rate"] = successful_unknown_pattern / summary["total_unknown_pattern_tests"]

        if summary["total_dynamic_mutation_tests"] > 0:
            summary["dynamic_mutation_success_rate"] = successful_dynamic_mutation / summary["total_dynamic_mutation_tests"]

        if summary["total_variant_generation_tests"] > 0:
            summary["variant_generation_success_rate"] = successful_variant_generation / summary["total_variant_generation_tests"]

        # Generate recommendations
        recommendations = []
        if summary.get("cross_version_success_rate", 0) < 0.9:
            recommendations.append("Improve cross-version compatibility detection")

        if summary.get("unknown_pattern_success_rate", 0) < 0.8:
            recommendations.append("Enhance unknown pattern recognition capabilities")

        if summary.get("dynamic_mutation_success_rate", 0) < 0.85:
            recommendations.append("Improve dynamic mutation adaptation")

        if summary.get("variant_generation_success_rate", 0) < 0.95:
            recommendations.append("Optimize protection variant generation verification")

        # Determine overall status
        if test_result.overall_success and all(rate >= 0.8 for rate in [
            summary.get("cross_version_success_rate", 0),
            summary.get("unknown_pattern_success_rate", 0),
            summary.get("dynamic_mutation_success_rate", 0),
            summary.get("variant_generation_success_rate", 0)
        ]):
            overall_status = "PASS"
        else:
            overall_status = "FAIL"

        report = Phase25Report(
            test_results=test_result,
            summary=summary,
            recommendations=recommendations,
            overall_status=overall_status
        )

        logger.info(f"Phase 2.5 report generated. Status: {overall_status}")
        return report

    def save_phase_25_report(self, report: Phase25Report, filename: str = None) -> str:
        """
        Save the Phase 2.5 report to a JSON file.
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"phase_25_validation_report_{timestamp}.json"

        report_path = self.reports_dir / filename

        # Convert to dict for JSON serialization
        report_dict = {
            "report": asdict(report),
            "generated_at": datetime.now().isoformat()
        }

        with open(report_path, 'w') as f:
            json.dump(report_dict, f, indent=2)

        logger.info(f"Phase 2.5 report saved to {report_path}")
        return str(report_path)

    def run_complete_phase_25_validation(self) -> str:
        """
        Run the complete Phase 2.5 validation and generate a report.
        """
        logger.info("Starting complete Phase 2.5 validation")

        try:
            # Execute validation
            test_result = self.execute_phase_25_validation()

            # Generate report
            report = self.generate_phase_25_report(test_result)

            # Save report
            report_path = self.save_phase_25_report(report)

            # Print summary
            print("Phase 2.5 Validation Summary")
            print("=" * 50)
            print(f"Overall Status: {report.overall_status}")
            print(f"Generated: {report.timestamp}")
            print()
            print("Test Results:")
            print(f"  Cross-Version Tests: {report.summary.get('total_cross_version_tests', 0)}")
            print(f"  Unknown Pattern Tests: {report.summary.get('total_unknown_pattern_tests', 0)}")
            print(f"  Dynamic Mutation Tests: {report.summary.get('total_dynamic_mutation_tests', 0)}")
            print(f"  Variant Generation Tests: {report.summary.get('total_variant_generation_tests', 0)}")
            print()
            print("Success Rates:")
            print(f"  Cross-Version: {report.summary.get('cross_version_success_rate', 0):.2%}")
            print(f"  Unknown Pattern: {report.summary.get('unknown_pattern_success_rate', 0):.2%}")
            print(f"  Dynamic Mutation: {report.summary.get('dynamic_mutation_success_rate', 0):.2%}")
            print(f"  Variant Generation: {report.summary.get('variant_generation_success_rate', 0):.2%}")
            print()
            print("Recommendations:")
            for recommendation in report.recommendations:
                print(f"  - {recommendation}")
            print()
            print(f"Full report saved to: {report_path}")

            return report_path

        except Exception as e:
            logger.error(f"Failed to complete Phase 2.5 validation: {e}")
            raise


if __name__ == "__main__":
    # Run the Phase 2.5 orchestrator
    orchestrator = Phase25Orchestrator()

    try:
        print("Intellicrack Phase 2.5 Validation Orchestrator")
        print("=" * 50)

        # Run complete validation
        report_path = orchestrator.run_complete_phase_25_validation()

        print(f"\nValidation completed successfully!")
        print(f"Report saved to: {report_path}")

    except Exception as e:
        print(f"Error during Phase 2.5 validation: {e}")
        import traceback
        traceback.print_exc()
