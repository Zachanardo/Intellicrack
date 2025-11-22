"""
Phase 6.7: Final Verdict Algorithm
Implements unambiguous binary PASS/FAIL logic with zero tolerance for violations.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import uuid


class VerdictStatus(Enum):
    """Binary verdict status - no ambiguity allowed."""
    PASS = "PASS"
    FAIL = "FAIL"


class ViolationSeverity(Enum):
    """Violation severity levels - all result in FAIL."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class ValidationViolation:
    """Individual validation violation."""
    violation_id: str
    component: str
    description: str
    severity: ViolationSeverity
    timestamp: datetime
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str | None = None

    def __post_init__(self):
        if not self.violation_id:
            self.violation_id = str(uuid.uuid4())


@dataclass
class ComponentResult:
    """Result from individual validation component."""
    component_name: str
    status: VerdictStatus
    violations: list[ValidationViolation] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    execution_time: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)

    @property
    def has_violations(self) -> bool:
        """Check if component has any violations."""
        return len(self.violations) > 0


@dataclass
class FinalVerdict:
    """Final validation verdict with complete audit trail."""
    verdict: VerdictStatus
    total_violations: int
    components_tested: int
    components_passed: int
    components_failed: int
    execution_time: float
    timestamp: datetime
    violations: list[ValidationViolation] = field(default_factory=list)
    component_results: list[ComponentResult] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    signature: str | None = None

    def __post_init__(self):
        """Generate integrity signature."""
        if not self.signature:
            self.signature = self._generate_signature()

    def _generate_signature(self) -> str:
        """Generate integrity signature for verdict."""
        data = {
            'verdict': self.verdict.value,
            'total_violations': self.total_violations,
            'components_tested': self.components_tested,
            'timestamp': self.timestamp.isoformat(),
            'violation_count': len(self.violations)
        }
        content = json.dumps(data, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()


class FinalVerdictAlgorithm:
    """
    Implements the final verdict algorithm with zero-tolerance policy.
    Any single violation at any level results in complete FAIL.
    """

    def __init__(self, config_path: Path | None = None):
        self.config_path = config_path
        self.logger = self._setup_logging()
        self._load_config()

        # Zero-tolerance policy - immutable
        self.ZERO_TOLERANCE = True
        self.FAIL_ON_ANY_VIOLATION = True
        self.NO_EXCEPTIONS = True

    def _setup_logging(self) -> logging.Logger:
        """Setup component logging."""
        logger = logging.getLogger(f"{__name__}.FinalVerdictAlgorithm")
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger

    def _load_config(self):
        """Load algorithm configuration."""
        self.config = {
            'strict_mode': True,
            'zero_tolerance': True,
            'fail_fast': False,  # Continue testing all components for complete audit
            'signature_required': True,
            'audit_trail_required': True
        }

        if self.config_path and self.config_path.exists():
            try:
                with open(self.config_path) as f:
                    file_config = json.load(f)
                    # Override only non-critical settings
                    self.config['fail_fast'] = file_config.get('fail_fast', False)
            except Exception as e:
                self.logger.warning(f"Failed to load config: {e}, using defaults")

    def evaluate_validation_results(self, component_results: list[ComponentResult]) -> FinalVerdict:
        """
        Evaluate all component results and generate final verdict.

        Args:
            component_results: List of component validation results

        Returns:
            FinalVerdict with binary PASS/FAIL determination
        """
        start_time = datetime.now()

        self.logger.info(f"Evaluating {len(component_results)} component results")

        # Initialize verdict tracking
        all_violations = []
        components_passed = 0
        components_failed = 0
        total_execution_time = 0.0

        # Process each component result
        for result in component_results:
            total_execution_time += result.execution_time

            if result.has_violations:
                components_failed += 1
                all_violations.extend(result.violations)
                self.logger.warning(
                    f"Component {result.component_name} FAILED with "
                    f"{len(result.violations)} violations"
                )
            else:
                components_passed += 1
                self.logger.info(f"Component {result.component_name} PASSED")

        # Apply zero-tolerance algorithm
        final_status = self._apply_zero_tolerance_algorithm(all_violations)

        # Calculate final execution time
        end_time = datetime.now()
        total_time = (end_time - start_time).total_seconds() + total_execution_time

        # Generate final verdict
        verdict = FinalVerdict(
            verdict=final_status,
            total_violations=len(all_violations),
            components_tested=len(component_results),
            components_passed=components_passed,
            components_failed=components_failed,
            execution_time=total_time,
            timestamp=end_time,
            violations=all_violations,
            component_results=component_results,
            metadata={
                'algorithm_version': '1.0',
                'zero_tolerance_applied': True,
                'strict_mode': self.config['strict_mode'],
                'evaluation_method': 'binary_fail_on_any_violation'
            }
        )

        self.logger.info(
            f"Final verdict: {verdict.verdict.value} "
            f"({verdict.total_violations} violations, "
            f"{verdict.components_passed}/{verdict.components_tested} components passed)"
        )

        return verdict

    def _apply_zero_tolerance_algorithm(self, violations: list[ValidationViolation]) -> VerdictStatus:
        """
        Apply zero-tolerance algorithm: any violation = FAIL.

        Args:
            violations: All violations found across components

        Returns:
            Binary PASS/FAIL verdict
        """
        if len(violations) == 0:
            self.logger.info("Zero violations found - PASS")
            return VerdictStatus.PASS

        self.logger.error(f"Found {len(violations)} violations - FAIL (zero tolerance)")

        # Log violation breakdown for audit trail
        severity_counts = {}
        for violation in violations:
            severity = violation.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        self.logger.error(f"Violation breakdown: {severity_counts}")

        # Zero tolerance means ANY violation = FAIL
        return VerdictStatus.FAIL

    def validate_component_integrity(self, component_results: list[ComponentResult]) -> bool:
        """
        Validate integrity of component results before processing.

        Args:
            component_results: Component results to validate

        Returns:
            True if all results are valid for processing
        """
        if not component_results:
            self.logger.error("No component results provided")
            return False

        required_components = {
            'detection_pass_criteria_validator',
            'exploitation_pass_criteria_validator',
            'evidence_requirements_validator',
            'statistical_requirements_validator',
            'anti_gaming_validation_system',
            'reproducibility_requirements_checker'
        }

        found_components = {result.component_name for result in component_results}
        missing_components = required_components - found_components

        if missing_components:
            self.logger.error(f"Missing required components: {missing_components}")
            return False

        # Validate individual component results
        for result in component_results:
            if not self._validate_individual_component(result):
                return False

        return True

    def _validate_individual_component(self, result: ComponentResult) -> bool:
        """
        Validate individual component result integrity.

        Args:
            result: Component result to validate

        Returns:
            True if component result is valid
        """
        # Check required fields
        if not result.component_name:
            self.logger.error("Component missing name")
            return False

        if result.status not in [VerdictStatus.PASS, VerdictStatus.FAIL]:
            self.logger.error(f"Invalid component status: {result.status}")
            return False

        # Validate violation consistency
        if result.status == VerdictStatus.PASS and result.has_violations:
            self.logger.error(
                f"Component {result.component_name} marked PASS but has violations"
            )
            return False

        if result.status == VerdictStatus.FAIL and not result.has_violations:
            self.logger.error(
                f"Component {result.component_name} marked FAIL but has no violations"
            )
            return False

        # Validate individual violations
        for violation in result.violations:
            if not self._validate_violation(violation):
                return False

        return True

    def _validate_violation(self, violation: ValidationViolation) -> bool:
        """
        Validate individual violation structure.

        Args:
            violation: Violation to validate

        Returns:
            True if violation is valid
        """
        if not violation.violation_id:
            self.logger.error("Violation missing ID")
            return False

        if not violation.component:
            self.logger.error("Violation missing component")
            return False

        if not violation.description:
            self.logger.error("Violation missing description")
            return False

        if violation.severity not in ViolationSeverity:
            self.logger.error(f"Invalid violation severity: {violation.severity}")
            return False

        return True

    def generate_verdict_report(self, verdict: FinalVerdict) -> dict[str, Any]:
        """
        Generate comprehensive verdict report.

        Args:
            verdict: Final verdict to report

        Returns:
            Complete verdict report
        """
        report = {
            'verdict_summary': {
                'final_verdict': verdict.verdict.value,
                'total_violations': verdict.total_violations,
                'components_tested': verdict.components_tested,
                'components_passed': verdict.components_passed,
                'components_failed': verdict.components_failed,
                'success_rate': verdict.components_passed / verdict.components_tested if verdict.components_tested > 0 else 0.0,
                'execution_time_seconds': verdict.execution_time,
                'timestamp': verdict.timestamp.isoformat(),
                'signature': verdict.signature
            },
            'algorithm_details': {
                'version': '1.0',
                'policy': 'zero_tolerance',
                'description': 'Any single violation at any severity level results in complete FAIL',
                'no_exceptions': True,
                'fail_threshold': 0  # Zero violations required for PASS
            },
            'component_breakdown': [],
            'violation_details': [],
            'integrity_verification': {
                'signature_valid': self._verify_verdict_signature(verdict),
                'component_count_verified': len(verdict.component_results) == verdict.components_tested,
                'violation_count_verified': len(verdict.violations) == verdict.total_violations
            }
        }

        # Add component details
        for component in verdict.component_results:
            component_detail = {
                'name': component.component_name,
                'status': component.status.value,
                'violation_count': len(component.violations),
                'execution_time': component.execution_time,
                'timestamp': component.timestamp.isoformat()
            }
            report['component_breakdown'].append(component_detail)

        # Add violation details
        for violation in verdict.violations:
            violation_detail = {
                'id': violation.violation_id,
                'component': violation.component,
                'severity': violation.severity.value,
                'description': violation.description,
                'timestamp': violation.timestamp.isoformat(),
                'has_evidence': bool(violation.evidence),
                'has_remediation': bool(violation.remediation)
            }
            report['violation_details'].append(violation_detail)

        return report

    def _verify_verdict_signature(self, verdict: FinalVerdict) -> bool:
        """
        Verify verdict integrity signature.

        Args:
            verdict: Verdict to verify

        Returns:
            True if signature is valid
        """
        if not verdict.signature:
            return False

        # Recreate signature and compare
        expected_signature = verdict._generate_signature()
        return verdict.signature == expected_signature

    def save_verdict(self, verdict: FinalVerdict, output_path: Path) -> bool:
        """
        Save verdict to file with integrity protection.

        Args:
            verdict: Verdict to save
            output_path: Path to save verdict

        Returns:
            True if saved successfully
        """
        try:
            report = self.generate_verdict_report(verdict)

            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)

            self.logger.info(f"Verdict saved to {output_path}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to save verdict: {e}")
            return False

    def load_verdict(self, input_path: Path) -> FinalVerdict | None:
        """
        Load and verify verdict from file.

        Args:
            input_path: Path to load verdict from

        Returns:
            Loaded verdict if valid, None otherwise
        """
        try:
            if not input_path.exists():
                self.logger.error(f"Verdict file not found: {input_path}")
                return None

            with open(input_path) as f:
                data = json.load(f)

            # Reconstruct verdict object
            verdict_data = data['verdict_summary']

            verdict = FinalVerdict(
                verdict=VerdictStatus(verdict_data['final_verdict']),
                total_violations=verdict_data['total_violations'],
                components_tested=verdict_data['components_tested'],
                components_passed=verdict_data['components_passed'],
                components_failed=verdict_data['components_failed'],
                execution_time=verdict_data['execution_time_seconds'],
                timestamp=datetime.fromisoformat(verdict_data['timestamp']),
                signature=verdict_data['signature']
            )

            # Verify integrity
            if not self._verify_verdict_signature(verdict):
                self.logger.error("Verdict signature verification failed")
                return None

            self.logger.info(f"Verdict loaded and verified from {input_path}")
            return verdict

        except Exception as e:
            self.logger.error(f"Failed to load verdict: {e}")
            return None


# Example usage and testing
if __name__ == "__main__":
    # Create test algorithm instance
    algorithm = FinalVerdictAlgorithm()

    # Create test component results with violations
    test_results = [
        ComponentResult(
            component_name="detection_pass_criteria_validator",
            status=VerdictStatus.FAIL,
            violations=[
                ValidationViolation(
                    violation_id="test-violation-1",
                    component="detection_pass_criteria_validator",
                    description="Failed to detect UPX packer",
                    severity=ViolationSeverity.HIGH,
                    timestamp=datetime.now()
                )
            ],
            execution_time=2.5
        ),
        ComponentResult(
            component_name="exploitation_pass_criteria_validator",
            status=VerdictStatus.PASS,
            violations=[],
            execution_time=5.1
        )
    ]

    # Test verdict generation
    if algorithm.validate_component_integrity(test_results):
        verdict = algorithm.evaluate_validation_results(test_results)

        print(f"Final Verdict: {verdict.verdict.value}")
        print(f"Total Violations: {verdict.total_violations}")
        print(f"Components Passed: {verdict.components_passed}/{verdict.components_tested}")

        # Generate and display report
        report = algorithm.generate_verdict_report(verdict)
        print("\nReport Summary:")
        print(json.dumps(report['verdict_summary'], indent=2))
    else:
        print("Component integrity validation failed")
