"""
Phase 3 Orchestrator for Intellicrack Validation Framework.
Coordinates all Phase 3 validation activities.
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass, asdict
from datetime import datetime

from commercial_binary_manager import CommercialBinaryManager
from negative_control_validator import NegativeControlValidator, NegativeControlResult
from functional_verification import FunctionalVerification, FunctionalVerificationResult
from forensic_collector import ForensicCollector, ForensicEvidence

logger = logging.getLogger(__name__)


@dataclass
class Phase3TestResult:
    """Result of Phase 3 testing."""
    negative_control_results: list[NegativeControlResult]
    functional_verification_results: list[FunctionalVerificationResult]
    forensic_evidence_results: list[ForensicEvidence]
    overall_success: bool
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


@dataclass
class Phase3Report:
    """Comprehensive report of Phase 3 validation."""
    test_results: Phase3TestResult
    summary: dict[str, Any]
    recommendations: list[str]
    overall_status: str
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


class Phase3Orchestrator:
    """Orchestrates all Phase 3 validation activities."""

    def __init__(self, base_dir: str = "C:\\Intellicrack\\tests\\validation_system"):
        self.base_dir = Path(base_dir)
        self.reports_dir = self.base_dir / "reports"
        self.reports_dir.mkdir(exist_ok=True)

        # Initialize all components
        self.binary_manager = CommercialBinaryManager(base_dir)
        self.negative_control_validator = NegativeControlValidator(base_dir)
        self.functional_verifier = FunctionalVerification(base_dir)
        self.forensic_collector = ForensicCollector(base_dir)

        logger.info("Phase 3 Orchestrator initialized")

    def run_negative_control_validation(self) -> list[NegativeControlResult]:
        """
        Run negative control validation on all available binaries.
        """
        logger.info("Starting negative control validation")
        results = self.negative_control_validator.validate_all_negative_controls()
        logger.info(f"Completed negative control validation: {len(results)} results")
        return results

    def run_functional_verification(self) -> list[FunctionalVerificationResult]:
        """
        Run functional verification on all available binaries.
        """
        logger.info("Starting functional verification")
        results = self.functional_verifier.verify_all_functionality()
        logger.info(f"Completed functional verification: {len(results)} results")
        return results

    def run_forensic_evidence_collection(self) -> list[ForensicEvidence]:
        """
        Run forensic evidence collection on all available binaries.
        """
        logger.info("Starting forensic evidence collection")
        results = self.forensic_collector.collect_all_forensic_evidence()
        logger.info(f"Completed forensic evidence collection: {len(results)} results")
        return results

    def execute_phase_3_validation(self) -> Phase3TestResult:
        """
        Execute the complete Phase 3 validation.
        """
        logger.info("Executing Phase 3 validation")

        # Run all test categories
        negative_control_results = self.run_negative_control_validation()
        functional_verification_results = self.run_functional_verification()
        forensic_evidence_results = self.run_forensic_evidence_collection()

        # Determine overall success
        # For now, we'll consider it successful if we have results from each category
        overall_success = (
            len(negative_control_results) > 0 and
            len(functional_verification_results) > 0 and
            len(forensic_evidence_results) > 0
        )

        result = Phase3TestResult(
            negative_control_results=negative_control_results,
            functional_verification_results=functional_verification_results,
            forensic_evidence_results=forensic_evidence_results,
            overall_success=overall_success
        )

        logger.info(f"Phase 3 validation completed. Success: {overall_success}")
        return result

    def generate_phase_3_report(self, test_result: Phase3TestResult) -> Phase3Report:
        """
        Generate a comprehensive report for Phase 3 validation.
        """
        logger.info("Generating Phase 3 report")

        # Calculate summary statistics
        summary = {
            "total_negative_control_tests": len(test_result.negative_control_results),
            "total_functional_verification_tests": len(test_result.functional_verification_results),
            "total_forensic_evidence_collections": len(test_result.forensic_evidence_results),
            "overall_success": test_result.overall_success
        }

        # Add success rates for each category
        successful_negative_controls = sum(1 for r in test_result.negative_control_results if r.test_valid and r.software_refused_execution)
        successful_functional_tests = sum(1 for r in test_result.functional_verification_results if r.overall_success)
        successful_evidence_collections = sum(1 for r in test_result.forensic_evidence_results if not r.error_messages)

        if summary["total_negative_control_tests"] > 0:
            summary["negative_control_success_rate"] = successful_negative_controls / summary["total_negative_control_tests"]

        if summary["total_functional_verification_tests"] > 0:
            summary["functional_verification_success_rate"] = successful_functional_tests / summary["total_functional_verification_tests"]

        if summary["total_forensic_evidence_collections"] > 0:
            summary["forensic_evidence_success_rate"] = successful_evidence_collections / summary["total_forensic_evidence_collections"]

        # Generate recommendations
        recommendations = []
        if summary.get("negative_control_success_rate", 0) < 0.9:
            recommendations.append("Improve negative control validation detection")

        if summary.get("functional_verification_success_rate", 0) < 0.8:
            recommendations.append("Enhance functional verification capabilities")

        if summary.get("forensic_evidence_success_rate", 0) < 0.95:
            recommendations.append("Optimize forensic evidence collection")

        # Determine overall status
        if test_result.overall_success and all(rate >= 0.8 for rate in [
            summary.get("negative_control_success_rate", 0),
            summary.get("functional_verification_success_rate", 0),
            summary.get("forensic_evidence_success_rate", 0)
        ]):
            overall_status = "PASS"
        else:
            overall_status = "FAIL"

        report = Phase3Report(
            test_results=test_result,
            summary=summary,
            recommendations=recommendations,
            overall_status=overall_status
        )

        logger.info(f"Phase 3 report generated. Status: {overall_status}")
        return report

    def save_phase_3_report(self, report: Phase3Report, filename: str = None) -> str:
        """
        Save the Phase 3 report to a JSON file.
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"phase_3_validation_report_{timestamp}.json"

        report_path = self.reports_dir / filename

        # Convert to dict for JSON serialization
        report_dict = {
            "report": asdict(report),
            "generated_at": datetime.now().isoformat()
        }

        with open(report_path, 'w') as f:
            json.dump(report_dict, f, indent=2)

        logger.info(f"Phase 3 report saved to {report_path}")
        return str(report_path)

    def run_complete_phase_3_validation(self) -> str:
        """
        Run the complete Phase 3 validation and generate a report.
        """
        logger.info("Starting complete Phase 3 validation")

        try:
            # Execute validation
            test_result = self.execute_phase_3_validation()

            # Generate report
            report = self.generate_phase_3_report(test_result)

            # Save report
            report_path = self.save_phase_3_report(report)

            # Print summary
            print("Phase 3 Validation Summary")
            print("=" * 50)
            print(f"Overall Status: {report.overall_status}")
            print(f"Generated: {report.timestamp}")
            print()
            print("Test Results:")
            print(f"  Negative Control Tests: {report.summary.get('total_negative_control_tests', 0)}")
            print(f"  Functional Verification Tests: {report.summary.get('total_functional_verification_tests', 0)}")
            print(f"  Forensic Evidence Collections: {report.summary.get('total_forensic_evidence_collections', 0)}")
            print()
            print("Success Rates:")
            print(f"  Negative Control: {report.summary.get('negative_control_success_rate', 0):.2%}")
            print(f"  Functional Verification: {report.summary.get('functional_verification_success_rate', 0):.2%}")
            print(f"  Forensic Evidence: {report.summary.get('forensic_evidence_success_rate', 0):.2%}")
            print()
            print("Recommendations:")
            for recommendation in report.recommendations:
                print(f"  - {recommendation}")
            print()
            print(f"Full report saved to: {report_path}")

            return report_path

        except Exception as e:
            logger.error(f"Failed to complete Phase 3 validation: {e}")
            raise


if __name__ == "__main__":
    # Run the Phase 3 orchestrator
    orchestrator = Phase3Orchestrator()

    try:
        print("Intellicrack Phase 3 Validation Orchestrator")
        print("=" * 50)

        # Run complete validation
        report_path = orchestrator.run_complete_phase_3_validation()

        print(f"\nValidation completed successfully!")
        print(f"Report saved to: {report_path}")

    except Exception as e:
        print(f"Error during Phase 3 validation: {e}")
        import traceback
        traceback.print_exc()
