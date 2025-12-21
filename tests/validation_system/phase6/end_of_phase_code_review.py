"""
Phase 6.8: Mandatory End-of-Phase Code Review
Comprehensive audit of all Phase 6 validation components for production readiness.
"""

import ast
import inspect
import json
import logging
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import importlib.util
import pylint.lint
from pylint.reporters.text import TextReporter
import io


class ReviewSeverity(Enum):
    """Code review issue severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ReviewCategory(Enum):
    """Code review categories."""
    PLACEHOLDER_DETECTION = "PLACEHOLDER_DETECTION"
    PRODUCTION_READINESS = "PRODUCTION_READINESS"
    CODE_QUALITY = "CODE_QUALITY"
    SECURITY = "SECURITY"
    PERFORMANCE = "PERFORMANCE"
    MAINTAINABILITY = "MAINTAINABILITY"
    DOCUMENTATION = "DOCUMENTATION"
    TESTING = "TESTING"


@dataclass
class CodeIssue:
    """Individual code review issue."""
    issue_id: str
    file_path: Path
    line_number: int
    category: ReviewCategory
    severity: ReviewSeverity
    title: str
    description: str
    code_snippet: str
    remediation: str
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class ComponentReview:
    """Review results for individual component."""
    component_name: str
    file_path: Path
    total_lines: int
    issues_found: list[CodeIssue] = field(default_factory=list)
    complexity_score: float = 0.0
    maintainability_index: float = 0.0
    test_coverage: float = 0.0
    pylint_score: float = 0.0
    production_ready: bool = False

    @property
    def critical_issues(self) -> list[CodeIssue]:
        return [issue for issue in self.issues_found if issue.severity == ReviewSeverity.CRITICAL]

    @property
    def high_issues(self) -> list[CodeIssue]:
        return [issue for issue in self.issues_found if issue.severity == ReviewSeverity.HIGH]


@dataclass
class PhaseReviewReport:
    """Complete Phase 6 code review report."""
    phase_name: str
    review_timestamp: datetime
    components_reviewed: list[ComponentReview] = field(default_factory=list)
    total_issues: int = 0
    critical_issues: int = 0
    high_issues: int = 0
    overall_grade: str = "F"
    production_ready: bool = False

    def __post_init__(self):
        self._calculate_metrics()

    def _calculate_metrics(self):
        """Calculate overall review metrics."""
        all_issues = []
        for component in self.components_reviewed:
            all_issues.extend(component.issues_found)

        self.total_issues = len(all_issues)
        self.critical_issues = len([i for i in all_issues if i.severity == ReviewSeverity.CRITICAL])
        self.high_issues = len([i for i in all_issues if i.severity == ReviewSeverity.HIGH])

        # Calculate overall grade
        if self.critical_issues > 0:
            self.overall_grade = "F"
        elif self.high_issues > 5:
            self.overall_grade = "D"
        elif self.high_issues > 2:
            self.overall_grade = "C"
        elif len([i for i in all_issues if i.severity == ReviewSeverity.MEDIUM]) > 10:
            self.overall_grade = "B"
        else:
            self.overall_grade = "A"

        # Determine production readiness
        self.production_ready = (
            self.critical_issues == 0 and
            self.high_issues <= 1 and
            all(component.production_ready for component in self.components_reviewed)
        )


class EndOfPhaseCodeReviewer:
    """
    Comprehensive code reviewer for Phase 6 validation components.
    Enforces production-ready standards with zero tolerance for placeholders.
    """

    def __init__(self, phase_path: Path):
        self.phase_path = phase_path
        self.logger = self._setup_logging()

        # Placeholder detection patterns - comprehensive list
        self.PLACEHOLDER_PATTERNS = [
            r'TODO',
            r'FIXME',
            r'XXX',
            r'HACK',
            r'BUG',
            r'NotImplementedError',
            r'raise NotImplementedError',
            r'pass\s*$',
            r'return None\s*$',
            r'placeholder',
            r'stub',
            r'mock',
            r'fake',
            r'dummy',
            r'test[_\s]*(data|result|value)',
            r'# (Implement|Add|Fix|Replace)',
            r'# TODO',
            r'print\s*\(\s*[\'"].*debug.*[\'"]',
            r'print\s*\(\s*[\'"].*test.*[\'"]',
            r'hardcoded',
            r'temporary',
            r'temp[_\s]*',
            r'example[_\s]*implementation',
            r'sample[_\s]*code',
            r'demo[_\s]*'
        ]

        # Required Phase 6 components
        self.REQUIRED_COMPONENTS = [
            'detection_pass_criteria_validator.py',
            'exploitation_pass_criteria_validator.py',
            'evidence_requirements_validator.py',
            'statistical_requirements_validator.py',
            'anti_gaming_validation_system.py',
            'reproducibility_requirements_checker.py',
            'final_verdict_algorithm.py'
        ]

    def _setup_logging(self) -> logging.Logger:
        """Setup component logging."""
        logger = logging.getLogger(f"{__name__}.EndOfPhaseCodeReviewer")
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger

    def conduct_comprehensive_review(self) -> PhaseReviewReport:
        """
        Conduct comprehensive code review of all Phase 6 components.

        Returns:
            Complete phase review report
        """
        self.logger.info("Starting comprehensive Phase 6 code review")

        if missing_components := self._verify_component_completeness():
            self.logger.critical(f"Missing required components: {missing_components}")
            # Create minimal report showing failure
            return PhaseReviewReport(
                phase_name="Phase 6",
                review_timestamp=datetime.now(),
                overall_grade="F",
                production_ready=False
            )

        # Review each component
        component_reviews = []
        for component_file in self.REQUIRED_COMPONENTS:
            file_path = self.phase_path / component_file
            if file_path.exists():
                review = self._review_component(file_path)
                component_reviews.append(review)
                self.logger.info(f"Reviewed {component_file}: {len(review.issues_found)} issues found")

        # Generate final report
        report = PhaseReviewReport(
            phase_name="Phase 6: Unambiguous Pass/Fail Criteria and Validation Gates",
            review_timestamp=datetime.now(),
            components_reviewed=component_reviews
        )

        self.logger.info(
            f"Review complete: Grade {report.overall_grade}, "
            f"Production Ready: {report.production_ready}, "
            f"Issues: {report.total_issues} total ({report.critical_issues} critical)"
        )

        return report

    def _verify_component_completeness(self) -> list[str]:
        """
        Verify all required components are present.

        Returns:
            List of missing component files
        """
        missing = []
        for component in self.REQUIRED_COMPONENTS:
            file_path = self.phase_path / component
            if not file_path.exists():
                missing.append(component)
        return missing

    def _review_component(self, file_path: Path) -> ComponentReview:
        """
        Review individual component file.

        Args:
            file_path: Path to component file

        Returns:
            Component review results
        """
        self.logger.debug(f"Reviewing component: {file_path}")

        # Read source code
        try:
            with open(file_path, encoding='utf-8') as f:
                source_code = f.read()
        except Exception as e:
            self.logger.error(f"Failed to read {file_path}: {e}")
            return ComponentReview(
                component_name=file_path.stem,
                file_path=file_path,
                total_lines=0,
                production_ready=False
            )

        # Initialize review
        review = ComponentReview(
            component_name=file_path.stem,
            file_path=file_path,
            total_lines=len(source_code.splitlines())
        )

        # Run all review checks
        review.issues_found.extend(self._detect_placeholders(file_path, source_code))
        review.issues_found.extend(self._check_production_readiness(file_path, source_code))
        review.issues_found.extend(self._analyze_code_quality(file_path, source_code))
        review.issues_found.extend(self._security_analysis(file_path, source_code))
        review.issues_found.extend(self._performance_analysis(file_path, source_code))

        # Calculate metrics
        review.complexity_score = self._calculate_complexity(source_code)
        review.pylint_score = self._run_pylint(file_path)

        # Determine production readiness
        review.production_ready = self._is_production_ready(review)

        return review

    def _detect_placeholders(self, file_path: Path, source_code: str) -> list[CodeIssue]:
        """
        Detect placeholder, stub, mock, or incomplete code.

        Args:
            file_path: File being reviewed
            source_code: Source code content

        Returns:
            List of placeholder-related issues
        """
        issues = []
        lines = source_code.splitlines()

        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()

            # Check each placeholder pattern
            for pattern in self.PLACEHOLDER_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(CodeIssue(
                        issue_id=f"PLACEHOLDER_{file_path.stem}_{line_num}",
                        file_path=file_path,
                        line_number=line_num,
                        category=ReviewCategory.PLACEHOLDER_DETECTION,
                        severity=ReviewSeverity.CRITICAL,
                        title="Placeholder/Stub Code Detected",
                        description=f"Found placeholder pattern '{pattern}' in production code",
                        code_snippet=line_stripped,
                        remediation="Replace with fully functional implementation"
                    ))

            # Specific placeholder patterns
            if line_stripped == 'pass':
                issues.append(CodeIssue(
                    issue_id=f"PASS_STMT_{file_path.stem}_{line_num}",
                    file_path=file_path,
                    line_number=line_num,
                    category=ReviewCategory.PLACEHOLDER_DETECTION,
                    severity=ReviewSeverity.CRITICAL,
                    title="Empty Pass Statement",
                    description="Found empty pass statement indicating unimplemented functionality",
                    code_snippet=line_stripped,
                    remediation="Implement actual functionality"
                ))

            if 'return None' in line_stripped and not line_stripped.startswith('#') and all(
                                keyword not in line_stripped.lower()
                                for keyword in ['optional', 'nullable', 'default']
                            ):
                issues.append(CodeIssue(
                    issue_id=f"RETURN_NONE_{file_path.stem}_{line_num}",
                    file_path=file_path,
                    line_number=line_num,
                    category=ReviewCategory.PLACEHOLDER_DETECTION,
                    severity=ReviewSeverity.HIGH,
                    title="Suspicious None Return",
                    description="Found 'return None' that may indicate placeholder code",
                    code_snippet=line_stripped,
                    remediation="Verify this is intentional or implement proper return value"
                ))

        return issues

    def _check_production_readiness(self, file_path: Path, source_code: str) -> list[CodeIssue]:
        """
        Check production readiness indicators.

        Args:
            file_path: File being reviewed
            source_code: Source code content

        Returns:
            List of production readiness issues
        """
        issues = []
        lines = source_code.splitlines()

        # Check for proper error handling
        has_try_except = 'try:' in source_code
        has_logging = any('logging' in line or 'logger' in line for line in lines)
        has_docstrings = '"""' in source_code or "'''" in source_code

        if not has_try_except:
            issues.append(CodeIssue(
                issue_id=f"NO_ERROR_HANDLING_{file_path.stem}",
                file_path=file_path,
                line_number=1,
                category=ReviewCategory.PRODUCTION_READINESS,
                severity=ReviewSeverity.HIGH,
                title="Missing Error Handling",
                description="No try/except blocks found - production code needs error handling",
                code_snippet="",
                remediation="Add proper exception handling for all operations"
            ))

        if not has_logging:
            issues.append(CodeIssue(
                issue_id=f"NO_LOGGING_{file_path.stem}",
                file_path=file_path,
                line_number=1,
                category=ReviewCategory.PRODUCTION_READINESS,
                severity=ReviewSeverity.MEDIUM,
                title="Missing Logging",
                description="No logging found - production code should include proper logging",
                code_snippet="",
                remediation="Add logging for debugging and monitoring"
            ))

        # Check for hardcoded values
        for line_num, line in enumerate(lines, 1):
            if re.search(r'["\'][^"\']*test[^"\']*["\']', line, re.IGNORECASE):
                issues.append(CodeIssue(
                    issue_id=f"HARDCODED_TEST_{file_path.stem}_{line_num}",
                    file_path=file_path,
                    line_number=line_num,
                    category=ReviewCategory.PRODUCTION_READINESS,
                    severity=ReviewSeverity.HIGH,
                    title="Hardcoded Test Value",
                    description="Found hardcoded test value in production code",
                    code_snippet=line.strip(),
                    remediation="Replace with proper configuration or computed value"
                ))

        return issues

    def _analyze_code_quality(self, file_path: Path, source_code: str) -> list[CodeIssue]:
        """
        Analyze general code quality issues.

        Args:
            file_path: File being reviewed
            source_code: Source code content

        Returns:
            List of code quality issues
        """
        lines = source_code.splitlines()

        issues = [
            CodeIssue(
                issue_id=f"LONG_LINE_{file_path.stem}_{line_num}",
                file_path=file_path,
                line_number=line_num,
                category=ReviewCategory.CODE_QUALITY,
                severity=ReviewSeverity.LOW,
                title="Line Too Long",
                description=f"Line length {len(line)} exceeds recommended 120 characters",
                code_snippet=f"{line[:50]}..." if len(line) > 50 else line,
                remediation="Break long lines for better readability",
            )
            for line_num, line in enumerate(lines, 1)
            if len(line) > 120
        ]
        # Check for proper class/function naming
        try:
            tree = ast.parse(source_code)

            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    if not node.name.islower() and '_' not in node.name:
                        issues.append(CodeIssue(
                            issue_id=f"NAMING_{file_path.stem}_{node.lineno}",
                            file_path=file_path,
                            line_number=node.lineno,
                            category=ReviewCategory.CODE_QUALITY,
                            severity=ReviewSeverity.LOW,
                            title="Function Naming Convention",
                            description=f"Function '{node.name}' doesn't follow snake_case convention",
                            code_snippet=f"def {node.name}(",
                            remediation="Use snake_case for function names"
                        ))

                elif isinstance(node, ast.ClassDef):
                    if not node.name[0].isupper():
                        issues.append(CodeIssue(
                            issue_id=f"CLASS_NAMING_{file_path.stem}_{node.lineno}",
                            file_path=file_path,
                            line_number=node.lineno,
                            category=ReviewCategory.CODE_QUALITY,
                            severity=ReviewSeverity.LOW,
                            title="Class Naming Convention",
                            description=f"Class '{node.name}' should start with uppercase letter",
                            code_snippet=f"class {node.name}:",
                            remediation="Use PascalCase for class names"
                        ))

        except SyntaxError as e:
            issues.append(CodeIssue(
                issue_id=f"SYNTAX_ERROR_{file_path.stem}",
                file_path=file_path,
                line_number=getattr(e, 'lineno', 0),
                category=ReviewCategory.CODE_QUALITY,
                severity=ReviewSeverity.CRITICAL,
                title="Syntax Error",
                description=f"Python syntax error: {e}",
                code_snippet="",
                remediation="Fix syntax error"
            ))

        return issues

    def _security_analysis(self, file_path: Path, source_code: str) -> list[CodeIssue]:
        """
        Analyze security-related issues.

        Args:
            file_path: File being reviewed
            source_code: Source code content

        Returns:
            List of security issues
        """
        issues = []
        lines = source_code.splitlines()

        # Check for potential security issues
        security_patterns = [
            (r'exec\s*\(', "Use of exec() function", ReviewSeverity.HIGH),
            (r'eval\s*\(', "Use of eval() function", ReviewSeverity.HIGH),
            (r'subprocess\.call\s*\([^)]*shell\s*=\s*True', "Shell injection risk", ReviewSeverity.CRITICAL),
            (r'os\.system\s*\(', "Use of os.system()", ReviewSeverity.HIGH),
            (r'pickle\.loads?\s*\(', "Pickle deserialization risk", ReviewSeverity.MEDIUM),
        ]

        for line_num, line in enumerate(lines, 1):
            for pattern, description, severity in security_patterns:
                if re.search(pattern, line):
                    issues.append(CodeIssue(
                        issue_id=f"SECURITY_{file_path.stem}_{line_num}",
                        file_path=file_path,
                        line_number=line_num,
                        category=ReviewCategory.SECURITY,
                        severity=severity,
                        title="Potential Security Risk",
                        description=description,
                        code_snippet=line.strip(),
                        remediation="Use safer alternatives or add proper input validation"
                    ))

        return issues

    def _performance_analysis(self, file_path: Path, source_code: str) -> list[CodeIssue]:
        """
        Analyze performance-related issues.

        Args:
            file_path: File being reviewed
            source_code: Source code content

        Returns:
            List of performance issues
        """
        issues = []
        lines = source_code.splitlines()

        # Check for potential performance issues
        performance_patterns = [
            (r'for.*in.*\.keys\(\):', "Inefficient dict iteration"),
            (r'len\([^)]+\)\s*==\s*0', "Use 'not container' instead of 'len(container) == 0'"),
            (r'\.append\s*\([^)]+\)\s*$', "Consider list comprehension for better performance"),
        ]

        for line_num, line in enumerate(lines, 1):
            for pattern, description in performance_patterns:
                if re.search(pattern, line):
                    issues.append(CodeIssue(
                        issue_id=f"PERFORMANCE_{file_path.stem}_{line_num}",
                        file_path=file_path,
                        line_number=line_num,
                        category=ReviewCategory.PERFORMANCE,
                        severity=ReviewSeverity.LOW,
                        title="Performance Optimization Opportunity",
                        description=description,
                        code_snippet=line.strip(),
                        remediation="Consider more efficient implementation"
                    ))

        return issues

    def _calculate_complexity(self, source_code: str) -> float:
        """
        Calculate cyclomatic complexity.

        Args:
            source_code: Source code to analyze

        Returns:
            Complexity score
        """
        try:
            tree = ast.parse(source_code)
            complexity = 1  # Base complexity

            for node in ast.walk(tree):
                if isinstance(node, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
                    complexity += 1
                elif isinstance(node, ast.BoolOp):
                    complexity += len(node.values) - 1

            return complexity
        except Exception:
            return 0.0

    def _run_pylint(self, file_path: Path) -> float:
        """
        Run pylint analysis on file.

        Args:
            file_path: File to analyze

        Returns:
            Pylint score (0-10)
        """
        try:
            # Capture pylint output
            pylint_output = io.StringIO()
            reporter = TextReporter(pylint_output)

            # Run pylint
            pylint.lint.Run([str(file_path), '--output-format=text'],
                          reporter=reporter, do_exit=False)

            # Extract score from output
            output = pylint_output.getvalue()
            if score_match := re.search(
                r'Your code has been rated at ([\d.]+)/10', output
            ):
                return float(score_match[1])
            else:
                return 0.0

        except Exception as e:
            self.logger.warning(f"Failed to run pylint on {file_path}: {e}")
            return 0.0

    def _is_production_ready(self, review: ComponentReview) -> bool:
        """
        Determine if component is production ready.

        Args:
            review: Component review results

        Returns:
            True if production ready
        """
        # Zero tolerance for critical issues
        if review.critical_issues:
            return False

        # Limited tolerance for high issues
        if len(review.high_issues) > 2:
            return False

        # Minimum code quality requirements
        return review.pylint_score >= 6.0

    def generate_report(self, review_report: PhaseReviewReport) -> dict[str, Any]:
        """
        Generate comprehensive review report.

        Args:
            review_report: Phase review results

        Returns:
            Detailed report data
        """
        report = {
            'phase_review_summary': {
                'phase_name': review_report.phase_name,
                'review_timestamp': review_report.review_timestamp.isoformat(),
                'overall_grade': review_report.overall_grade,
                'production_ready': review_report.production_ready,
                'components_reviewed': len(review_report.components_reviewed),
                'total_issues': review_report.total_issues,
                'critical_issues': review_report.critical_issues,
                'high_issues': review_report.high_issues
            },
            'component_details': [],
            'issue_breakdown': {
                'by_severity': {},
                'by_category': {},
                'by_component': {}
            },
            'recommendations': [],
            'production_readiness_checklist': {
                'no_placeholders': review_report.critical_issues == 0,
                'minimal_high_issues': review_report.high_issues <= 2,
                'all_components_ready': all(c.production_ready for c in review_report.components_reviewed),
                'overall_grade_acceptable': review_report.overall_grade in ['A', 'B']
            }
        }

        # Add component details
        for component in review_report.components_reviewed:
            component_detail = {
                'name': component.component_name,
                'file_path': str(component.file_path),
                'total_lines': component.total_lines,
                'issues_count': len(component.issues_found),
                'critical_issues': len(component.critical_issues),
                'high_issues': len(component.high_issues),
                'complexity_score': component.complexity_score,
                'pylint_score': component.pylint_score,
                'production_ready': component.production_ready
            }
            report['component_details'].append(component_detail)

        # Calculate issue breakdowns
        all_issues = []
        for component in review_report.components_reviewed:
            all_issues.extend(component.issues_found)

        # By severity
        severity_counts = {}
        for issue in all_issues:
            severity = issue.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        report['issue_breakdown']['by_severity'] = severity_counts

        # By category
        category_counts = {}
        for issue in all_issues:
            category = issue.category.value
            category_counts[category] = category_counts.get(category, 0) + 1
        report['issue_breakdown']['by_category'] = category_counts

        # Generate recommendations
        if review_report.critical_issues > 0:
            report['recommendations'].append(
                "CRITICAL: Address all placeholder/stub code before deployment"
            )

        if review_report.high_issues > 2:
            report['recommendations'].append(
                "HIGH: Reduce high-severity issues to acceptable levels"
            )

        if not review_report.production_ready:
            report['recommendations'].append(
                "Phase 6 is NOT production ready - address all critical and high-priority issues"
            )
        else:
            report['recommendations'].append(
                "Phase 6 passes code review and is production ready"
            )

        return report

    def save_report(self, review_report: PhaseReviewReport, output_path: Path) -> bool:
        """
        Save review report to file.

        Args:
            review_report: Review results to save
            output_path: Path to save report

        Returns:
            True if saved successfully
        """
        try:
            report_data = self.generate_report(review_report)

            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)

            self.logger.info(f"Review report saved to {output_path}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to save review report: {e}")
            return False


# Example usage
if __name__ == "__main__":
    # Set up paths
    from intellicrack.utils.path_resolver import get_project_root
    phase6_path = get_project_root() / "tests/validation_system/phase6"

    # Create reviewer and conduct review
    reviewer = EndOfPhaseCodeReviewer(phase6_path)
    review_report = reviewer.conduct_comprehensive_review()

    # Display results
    print("Phase 6 Code Review Results:")
    print(f"Overall Grade: {review_report.overall_grade}")
    print(f"Production Ready: {review_report.production_ready}")
    print(f"Total Issues: {review_report.total_issues}")
    print(f"Critical Issues: {review_report.critical_issues}")
    print(f"High Issues: {review_report.high_issues}")

    # Save detailed report
    report_path = phase6_path / "code_review_report.json"
    reviewer.save_report(review_report, report_path)
    print(f"Detailed report saved to: {report_path}")
