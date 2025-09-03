"""
Phase 2: Comprehensive Validation Orchestrator
Master controller for complete protection detection validation with undeniable evidence
"""

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Phase 2 validation components
from .detection_validator import DetectionValidator, ValidationConfig, ValidationResult
from .evidence_verifier import EvidenceIntegrityReport, EvidenceVerificationConfig, EvidenceVerifier

# Intellicrack core modules
try:
    from intellicrack.core.config_manager import ConfigManager
    from intellicrack.utils.logging_utils import get_logger
    from intellicrack.utils.report_generator import ReportGenerator
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from intellicrack.core.config_manager import ConfigManager
    from intellicrack.utils.logging_utils import get_logger
    from intellicrack.utils.report_generator import ReportGenerator


@dataclass
class ComprehensiveValidationConfig:
    """Master configuration for comprehensive validation orchestration."""
    validation_config: ValidationConfig
    evidence_verification_config: EvidenceVerificationConfig
    batch_processing_enabled: bool = True
    max_concurrent_validations: int = 4
    comprehensive_reporting: bool = True
    performance_benchmarking: bool = True
    automatic_remediation: bool = False
    validation_timeout_minutes: int = 30
    results_storage_path: Path = Path("validation_results")
    benchmark_storage_path: Path = Path("benchmarks")


@dataclass
class ComprehensiveValidationReport:
    """Complete validation report combining all Phase 2 components."""
    validation_id: str
    timestamp: str
    orchestrator_version: str

    # Input configuration
    binaries_processed: int
    total_processing_time: float

    # Validation results
    detection_results: List[ValidationResult]
    evidence_integrity_reports: List[EvidenceIntegrityReport]

    # Aggregate metrics
    overall_success_rate: float
    average_consensus_score: float
    average_integrity_score: float
    total_protections_detected: int
    total_evidence_points_collected: int

    # Performance benchmarks
    performance_benchmarks: Dict[str, Any]

    # Quality assessment
    validation_quality_score: float
    confidence_distribution: Dict[str, int]
    anomaly_summary: Dict[str, int]

    # Recommendations
    improvement_recommendations: List[str]
    remediation_actions: List[str]

    # Metadata
    validation_metadata: Dict[str, Any]


class ValidationOrchestrator:
    """
    Master orchestrator for comprehensive protection detection validation.
    Coordinates all Phase 2 validation components to provide complete validation coverage.
    """

    def __init__(self, config: Optional[ComprehensiveValidationConfig] = None, logger: Optional[logging.Logger] = None):
        """Initialize validation orchestrator with comprehensive configuration."""
        # Initialize configuration
        if config is None:
            config = ComprehensiveValidationConfig(
                validation_config=ValidationConfig(),
                evidence_verification_config=EvidenceVerificationConfig()
            )
        self.config = config
        self.logger = logger or get_logger(__name__)

        # Initialize core components
        self.detection_validator = DetectionValidator(self.config.validation_config, self.logger)
        self.evidence_verifier = EvidenceVerifier(self.config.evidence_verification_config, self.logger)

        # Initialize utilities (with optional components)
        self.report_generator: Optional[ReportGenerator] = None
        self.config_manager: Optional[ConfigManager] = None

        try:
            self.report_generator = ReportGenerator()
            self.config_manager = ConfigManager()
        except Exception as e:
            self.logger.warning(f"Some utilities unavailable: {e}")

        # Performance tracking
        self.orchestration_metrics = {
            'total_orchestrations': 0,
            'successful_orchestrations': 0,
            'failed_orchestrations': 0,
            'total_binaries_processed': 0,
            'total_orchestration_time': 0.0,
            'average_orchestration_time': 0.0
        }

        # Ensure storage directories exist
        self.config.results_storage_path.mkdir(parents=True, exist_ok=True)
        self.config.benchmark_storage_path.mkdir(parents=True, exist_ok=True)

        self.logger.info("ValidationOrchestrator initialized successfully")

    async def orchestrate_comprehensive_validation(self, binary_paths: List[Path],
                                                 expected_protections: Optional[Dict[str, Set[str]]] = None,
                                                 validation_name: Optional[str] = None) -> ComprehensiveValidationReport:
        """
        Orchestrate comprehensive validation across all Phase 2 components.

        Args:
            binary_paths: List of binary file paths to validate
            expected_protections: Optional mapping of binary paths to expected protections
            validation_name: Optional name for this validation session

        Returns:
            ComprehensiveValidationReport with complete validation results
        """
        start_time = time.time()
        validation_id = self._generate_validation_id(validation_name)

        try:
            self.logger.info(f"Starting comprehensive validation for {len(binary_paths)} binaries - ID: {validation_id}")

            # Phase 1: Perform detection validation
            self.logger.info("Phase 1: Running detection validation")
            detection_results = await self._orchestrate_detection_validation(binary_paths, expected_protections)

            # Phase 2: Perform evidence integrity verification
            self.logger.info("Phase 2: Running evidence integrity verification")
            evidence_reports = await self._orchestrate_evidence_verification(detection_results, binary_paths)

            # Phase 3: Generate performance benchmarks
            self.logger.info("Phase 3: Generating performance benchmarks")
            performance_benchmarks = await self._generate_performance_benchmarks(detection_results, evidence_reports)

            # Phase 4: Calculate aggregate metrics
            self.logger.info("Phase 4: Calculating aggregate metrics")
            aggregate_metrics = self._calculate_aggregate_metrics(detection_results, evidence_reports)

            # Phase 5: Assess validation quality
            self.logger.info("Phase 5: Assessing validation quality")
            quality_assessment = self._assess_validation_quality(detection_results, evidence_reports)

            # Phase 6: Generate recommendations
            self.logger.info("Phase 6: Generating recommendations")
            recommendations = self._generate_recommendations(detection_results, evidence_reports, quality_assessment)

            # Phase 7: Create comprehensive report
            processing_time = time.time() - start_time
            report = self._create_comprehensive_report(
                validation_id, binary_paths, detection_results, evidence_reports,
                performance_benchmarks, aggregate_metrics, quality_assessment,
                recommendations, processing_time
            )

            # Phase 8: Store results
            await self._store_comprehensive_results(report)

            # Update orchestration metrics
            self._update_orchestration_metrics(processing_time, True, len(binary_paths))

            self.logger.info(f"Comprehensive validation completed successfully - ID: {validation_id}")
            return report

        except Exception as e:
            self.logger.error(f"Comprehensive validation failed: {str(e)}")
            processing_time = time.time() - start_time
            self._update_orchestration_metrics(processing_time, False, len(binary_paths))

            # Create failure report
            return ComprehensiveValidationReport(
                validation_id=validation_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                orchestrator_version="2.0.0",
                binaries_processed=len(binary_paths),
                total_processing_time=processing_time,
                detection_results=[],
                evidence_integrity_reports=[],
                overall_success_rate=0.0,
                average_consensus_score=0.0,
                average_integrity_score=0.0,
                total_protections_detected=0,
                total_evidence_points_collected=0,
                performance_benchmarks={'error': str(e)},
                validation_quality_score=0.0,
                confidence_distribution={},
                anomaly_summary={},
                improvement_recommendations=[f"Address validation failure: {str(e)}"],
                remediation_actions=[],
                validation_metadata={'error': str(e), 'failed_at': 'orchestration'}
            )

    async def orchestrate_single_binary_validation(self, binary_path: Path,
                                                 expected_protections: Optional[Set[str]] = None) -> ComprehensiveValidationReport:
        """
        Orchestrate comprehensive validation for a single binary.

        Args:
            binary_path: Path to binary file for validation
            expected_protections: Optional set of expected protection names

        Returns:
            ComprehensiveValidationReport for single binary
        """
        return await self.orchestrate_comprehensive_validation(
            [binary_path],
            {str(binary_path): expected_protections} if expected_protections else None
        )

    async def _orchestrate_detection_validation(self, binary_paths: List[Path],
                                              expected_protections: Optional[Dict[str, Set[str]]]) -> List[ValidationResult]:
        """Orchestrate detection validation across all binaries."""
        if self.config.batch_processing_enabled and len(binary_paths) > 1:
            # Use batch processing
            return await self.detection_validator.validate_batch(binary_paths, expected_protections)
        else:
            # Process individually
            results = []
            for binary_path in binary_paths:
                expected = expected_protections.get(str(binary_path)) if expected_protections else None
                result = await self.detection_validator.validate_detection(binary_path, expected)
                results.append(result)
            return results

    async def _orchestrate_evidence_verification(self, detection_results: List[ValidationResult],
                                               binary_paths: List[Path]) -> List[EvidenceIntegrityReport]:
        """Orchestrate evidence integrity verification for all detection results."""
        evidence_reports = []

        # Create mapping of binary paths to detection results
        result_map = {result.binary_path: result for result in detection_results}

        for binary_path in binary_paths:
            binary_str = str(binary_path)
            if binary_str in result_map:
                detection_result = result_map[binary_str]
                evidence_data = detection_result.evidence_collection

                # Verify evidence integrity
                evidence_report = await self.evidence_verifier.verify_evidence_integrity(
                    evidence_data, binary_path
                )
                evidence_reports.append(evidence_report)
            else:
                # Create empty report for missing detection result
                evidence_reports.append(EvidenceIntegrityReport(
                    evidence_id=f"MISSING_{binary_path.name}",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    binary_path=str(binary_path),
                    integrity_score=0.0,
                    authenticity_verified=False,
                    temporal_consistency=False,
                    cryptographic_verification={'error': 'Detection result missing'},
                    memory_address_validation={'error': 'Detection result missing'},
                    disassembly_verification={'error': 'Detection result missing'},
                    import_table_validation={'error': 'Detection result missing'},
                    string_analysis_validation={'error': 'Detection result missing'},
                    entropy_verification={'error': 'Detection result missing'},
                    cross_reference_validation={'error': 'Detection result missing'},
                    anomaly_detection=['Detection result missing'],
                    confidence_assessment="FAILED",
                    verification_metadata={'error': 'Detection result missing'}
                ))

        return evidence_reports

    async def _generate_performance_benchmarks(self, detection_results: List[ValidationResult],
                                             evidence_reports: List[EvidenceIntegrityReport]) -> Dict[str, Any]:
        """Generate comprehensive performance benchmarks."""
        if not self.config.performance_benchmarking:
            return {'benchmarking_disabled': True}

        try:
            benchmarks = {
                'detection_performance': self._benchmark_detection_performance(detection_results),
                'evidence_verification_performance': self._benchmark_evidence_performance(evidence_reports),
                'memory_usage': self._benchmark_memory_usage(),
                'scalability_metrics': self._benchmark_scalability(detection_results, evidence_reports),
                'accuracy_metrics': self._benchmark_accuracy(detection_results, evidence_reports),
                'throughput_metrics': self._benchmark_throughput(detection_results, evidence_reports)
            }

            # Store benchmark results
            if self.config.benchmark_storage_path:
                benchmark_file = self.config.benchmark_storage_path / f"benchmark_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                with open(benchmark_file, 'w', encoding='utf-8') as f:
                    json.dump(benchmarks, f, indent=2, ensure_ascii=False)

            return benchmarks

        except Exception as e:
            self.logger.error(f"Performance benchmarking failed: {str(e)}")
            return {'error': str(e)}

    def _benchmark_detection_performance(self, detection_results: List[ValidationResult]) -> Dict[str, Any]:
        """Benchmark detection validation performance."""
        if not detection_results:
            return {'no_results': True}

        processing_times = []
        consensus_scores = []
        protections_per_binary = []

        for result in detection_results:
            processing_time = result.performance_metrics.get('total_processing_time', 0)
            if processing_time > 0:
                processing_times.append(processing_time)

            consensus_scores.append(result.consensus_score)

            detected_count = len(result.intellicrack_detection.get('detected_protections', []))
            protections_per_binary.append(detected_count)

        return {
            'average_processing_time': sum(processing_times) / max(1, len(processing_times)),
            'min_processing_time': min(processing_times) if processing_times else 0,
            'max_processing_time': max(processing_times) if processing_times else 0,
            'average_consensus_score': sum(consensus_scores) / max(1, len(consensus_scores)),
            'average_protections_per_binary': sum(protections_per_binary) / max(1, len(protections_per_binary)),
            'validation_success_rate': sum(1 for r in detection_results if r.validation_passed) / len(detection_results),
            'total_binaries_processed': len(detection_results)
        }

    def _benchmark_evidence_performance(self, evidence_reports: List[EvidenceIntegrityReport]) -> Dict[str, Any]:
        """Benchmark evidence verification performance."""
        if not evidence_reports:
            return {'no_reports': True}

        verification_times = []
        integrity_scores = []
        anomaly_counts = []

        for report in evidence_reports:
            verification_time = report.verification_metadata.get('verification_time', 0)
            if verification_time > 0:
                verification_times.append(verification_time)

            integrity_scores.append(report.integrity_score)
            anomaly_counts.append(len(report.anomaly_detection))

        return {
            'average_verification_time': sum(verification_times) / max(1, len(verification_times)),
            'average_integrity_score': sum(integrity_scores) / max(1, len(integrity_scores)),
            'average_anomalies_per_report': sum(anomaly_counts) / max(1, len(anomaly_counts)),
            'authenticity_success_rate': sum(1 for r in evidence_reports if r.authenticity_verified) / len(evidence_reports),
            'total_evidence_reports': len(evidence_reports)
        }

    def _benchmark_memory_usage(self) -> Dict[str, Any]:
        """Benchmark memory usage during validation."""
        try:
            import psutil
            process = psutil.Process()
            memory_info = process.memory_info()

            return {
                'current_memory_mb': memory_info.rss / 1024 / 1024,
                'peak_memory_mb': getattr(process, 'memory_peak', lambda: memory_info.rss)() / 1024 / 1024,
                'memory_percent': process.memory_percent()
            }
        except ImportError:
            return {'psutil_not_available': True}
        except Exception as e:
            return {'error': str(e)}

    def _benchmark_scalability(self, detection_results: List[ValidationResult],
                             evidence_reports: List[EvidenceIntegrityReport]) -> Dict[str, Any]:
        """Benchmark scalability metrics."""
        return {
            'binaries_processed': len(detection_results),
            'concurrent_validations_supported': self.config.max_concurrent_validations,
            'average_time_per_binary': self._calculate_average_processing_time(detection_results),
            'estimated_hourly_throughput': self._estimate_hourly_throughput(detection_results),
            'scalability_rating': self._assess_scalability_rating(detection_results)
        }

    def _benchmark_accuracy(self, detection_results: List[ValidationResult],
                          evidence_reports: List[EvidenceIntegrityReport]) -> Dict[str, Any]:
        """Benchmark accuracy metrics."""
        consensus_scores = [r.consensus_score for r in detection_results]
        integrity_scores = [r.integrity_score for r in evidence_reports]

        return {
            'average_consensus_accuracy': sum(consensus_scores) / max(1, len(consensus_scores)),
            'average_evidence_integrity': sum(integrity_scores) / max(1, len(integrity_scores)),
            'high_confidence_rate': sum(1 for r in detection_results if r.consensus_score >= 0.8) / max(1, len(detection_results)),
            'integrity_pass_rate': sum(1 for r in evidence_reports if r.integrity_score >= 0.8) / max(1, len(evidence_reports)),
            'overall_accuracy_score': (
                sum(consensus_scores + integrity_scores) / max(1, len(consensus_scores) + len(integrity_scores))
            )
        }

    def _benchmark_throughput(self, detection_results: List[ValidationResult],
                            evidence_reports: List[EvidenceIntegrityReport]) -> Dict[str, Any]:
        """Benchmark throughput metrics."""
        total_processing_time = sum(
            r.performance_metrics.get('total_processing_time', 0) for r in detection_results
        )

        return {
            'total_processing_time': total_processing_time,
            'binaries_per_minute': len(detection_results) * 60 / max(1, total_processing_time),
            'evidence_points_per_minute': self._calculate_evidence_throughput(evidence_reports, total_processing_time),
            'validations_per_hour': len(detection_results) * 3600 / max(1, total_processing_time)
        }

    def _calculate_aggregate_metrics(self, detection_results: List[ValidationResult],
                                   evidence_reports: List[EvidenceIntegrityReport]) -> Dict[str, Any]:
        """Calculate aggregate metrics across all validation results."""
        if not detection_results:
            return {
                'overall_success_rate': 0.0,
                'average_consensus_score': 0.0,
                'average_integrity_score': 0.0,
                'total_protections_detected': 0,
                'total_evidence_points_collected': 0
            }

        # Detection metrics
        successful_validations = sum(1 for r in detection_results if r.validation_passed)
        overall_success_rate = successful_validations / len(detection_results)

        consensus_scores = [r.consensus_score for r in detection_results]
        average_consensus_score = sum(consensus_scores) / len(consensus_scores)

        total_protections = sum(
            len(r.intellicrack_detection.get('detected_protections', []))
            for r in detection_results
        )

        total_evidence_points = sum(
            r.evidence_collection.get('total_evidence_points', 0)
            for r in detection_results
        )

        # Evidence integrity metrics
        integrity_scores = [r.integrity_score for r in evidence_reports if evidence_reports]
        average_integrity_score = sum(integrity_scores) / max(1, len(integrity_scores))

        return {
            'overall_success_rate': overall_success_rate,
            'average_consensus_score': average_consensus_score,
            'average_integrity_score': average_integrity_score,
            'total_protections_detected': total_protections,
            'total_evidence_points_collected': total_evidence_points,
            'successful_validations': successful_validations,
            'total_validations': len(detection_results)
        }

    def _assess_validation_quality(self, detection_results: List[ValidationResult],
                                 evidence_reports: List[EvidenceIntegrityReport]) -> Dict[str, Any]:
        """Assess overall validation quality."""
        if not detection_results:
            return {'validation_quality_score': 0.0, 'quality_rating': 'NO_DATA'}

        # Quality factors
        consensus_quality = sum(r.consensus_score for r in detection_results) / len(detection_results)
        integrity_quality = sum(r.integrity_score for r in evidence_reports) / max(1, len(evidence_reports))
        success_rate_quality = sum(1 for r in detection_results if r.validation_passed) / len(detection_results)

        # Confidence distribution
        confidence_distribution: Dict[str, int] = {}
        for result in detection_results:
            confidence = result.confidence_level
            confidence_distribution[confidence] = confidence_distribution.get(confidence, 0) + 1

        # Anomaly summary
        anomaly_summary: Dict[str, int] = {}
        for report in evidence_reports:
            for anomaly in report.anomaly_detection:
                category = anomaly.split(':')[0] if ':' in anomaly else 'general'
                anomaly_summary[category] = anomaly_summary.get(category, 0) + 1

        # Calculate overall quality score
        validation_quality_score = (
            0.4 * consensus_quality +
            0.3 * integrity_quality +
            0.3 * success_rate_quality
        )

        # Determine quality rating
        if validation_quality_score >= 0.9:
            quality_rating = "EXCELLENT"
        elif validation_quality_score >= 0.8:
            quality_rating = "GOOD"
        elif validation_quality_score >= 0.7:
            quality_rating = "SATISFACTORY"
        elif validation_quality_score >= 0.5:
            quality_rating = "NEEDS_IMPROVEMENT"
        else:
            quality_rating = "POOR"

        return {
            'validation_quality_score': validation_quality_score,
            'quality_rating': quality_rating,
            'consensus_quality': consensus_quality,
            'integrity_quality': integrity_quality,
            'success_rate_quality': success_rate_quality,
            'confidence_distribution': confidence_distribution,
            'anomaly_summary': anomaly_summary
        }

    def _generate_recommendations(self, detection_results: List[ValidationResult],
                                evidence_reports: List[EvidenceIntegrityReport],
                                quality_assessment: Dict[str, Any]) -> Tuple[List[str], List[str]]:
        """Generate improvement recommendations and remediation actions."""
        improvement_recommendations = []
        remediation_actions = []

        # Analyze quality assessment
        quality_score = quality_assessment.get('validation_quality_score', 0.0)

        if quality_score < 0.7:
            improvement_recommendations.append(
                f"Overall validation quality ({quality_score:.3f}) below acceptable threshold (0.7)"
            )
            remediation_actions.append("Review validation algorithms and evidence collection methods")

        # Check consensus scores
        low_consensus_count = sum(1 for r in detection_results if r.consensus_score < 0.7)
        if low_consensus_count > 0:
            improvement_recommendations.append(f"{low_consensus_count} binaries with low consensus scores")
            remediation_actions.append("Enhance cross-validation accuracy and consensus algorithms")

        # Check integrity scores
        low_integrity_count = sum(1 for r in evidence_reports if r.integrity_score < 0.8)
        if low_integrity_count > 0:
            improvement_recommendations.append(f"{low_integrity_count} evidence reports with low integrity")
            remediation_actions.append("Improve evidence collection and cryptographic verification")

        # Check for high anomaly rates
        total_anomalies = sum(len(r.anomaly_detection) for r in evidence_reports)
        if total_anomalies > len(evidence_reports) * 2:  # More than 2 anomalies per report on average
            improvement_recommendations.append(f"High anomaly rate detected ({total_anomalies} total)")
            remediation_actions.append("Investigate and resolve sources of evidence anomalies")

        # Performance recommendations
        avg_processing_time = self._calculate_average_processing_time(detection_results)
        if avg_processing_time > 120:  # More than 2 minutes per binary
            improvement_recommendations.append(f"Average processing time ({avg_processing_time:.1f}s) exceeds optimal range")
            remediation_actions.append("Optimize validation algorithms for better performance")

        # Success rate recommendations
        success_rate = sum(1 for r in detection_results if r.validation_passed) / max(1, len(detection_results))
        if success_rate < 0.8:
            improvement_recommendations.append(f"Validation success rate ({success_rate:.1%}) below target (80%)")
            remediation_actions.append("Review validation thresholds and detection accuracy")

        return improvement_recommendations, remediation_actions

    def _create_comprehensive_report(self, validation_id: str, binary_paths: List[Path],
                                   detection_results: List[ValidationResult],
                                   evidence_reports: List[EvidenceIntegrityReport],
                                   performance_benchmarks: Dict[str, Any],
                                   aggregate_metrics: Dict[str, Any],
                                   quality_assessment: Dict[str, Any],
                                   recommendations: Tuple[List[str], List[str]],
                                   processing_time: float) -> ComprehensiveValidationReport:
        """Create comprehensive validation report."""
        improvement_recommendations, remediation_actions = recommendations

        return ComprehensiveValidationReport(
            validation_id=validation_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            orchestrator_version="2.0.0",
            binaries_processed=len(binary_paths),
            total_processing_time=processing_time,
            detection_results=detection_results,
            evidence_integrity_reports=evidence_reports,
            overall_success_rate=aggregate_metrics['overall_success_rate'],
            average_consensus_score=aggregate_metrics['average_consensus_score'],
            average_integrity_score=aggregate_metrics['average_integrity_score'],
            total_protections_detected=aggregate_metrics['total_protections_detected'],
            total_evidence_points_collected=aggregate_metrics['total_evidence_points_collected'],
            performance_benchmarks=performance_benchmarks,
            validation_quality_score=quality_assessment['validation_quality_score'],
            confidence_distribution=quality_assessment['confidence_distribution'],
            anomaly_summary=quality_assessment['anomaly_summary'],
            improvement_recommendations=improvement_recommendations,
            remediation_actions=remediation_actions,
            validation_metadata={
                'orchestrator_version': '2.0.0',
                'phase2_components_used': [
                    'DetectionValidator', 'EvidenceVerifier',
                    'DetectionEvidenceCollector', 'CrossValidation'
                ],
                'configuration': {
                    'batch_processing': self.config.batch_processing_enabled,
                    'max_concurrent': self.config.max_concurrent_validations,
                    'comprehensive_reporting': self.config.comprehensive_reporting,
                    'performance_benchmarking': self.config.performance_benchmarking
                }
            }
        )

    async def _store_comprehensive_results(self, report: ComprehensiveValidationReport):
        """Store comprehensive validation results."""
        try:
            # Store main report
            report_file = self.config.results_storage_path / f"comprehensive_validation_{report.validation_id}.json"
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(asdict(report), f, indent=2, ensure_ascii=False, default=str)

            # Store individual validation results
            for i, result in enumerate(report.detection_results):
                result_file = self.config.results_storage_path / f"detection_result_{report.validation_id}_{i:03d}.json"
                with open(result_file, 'w', encoding='utf-8') as f:
                    json.dump(asdict(result), f, indent=2, ensure_ascii=False, default=str)

            # Store evidence reports
            for i, evidence_report in enumerate(report.evidence_integrity_reports):
                evidence_file = self.config.results_storage_path / f"evidence_report_{report.validation_id}_{i:03d}.json"
                with open(evidence_file, 'w', encoding='utf-8') as f:
                    json.dump(asdict(evidence_report), f, indent=2, ensure_ascii=False, default=str)

            self.logger.info(f"Comprehensive results stored for validation: {report.validation_id}")

        except Exception as e:
            self.logger.error(f"Failed to store comprehensive results: {str(e)}")

    def _calculate_average_processing_time(self, detection_results: List[ValidationResult]) -> float:
        """Calculate average processing time from detection results."""
        processing_times: List[float] = [
            float(r.performance_metrics.get('total_processing_time', 0))
            for r in detection_results
            if r.performance_metrics.get('total_processing_time', 0) > 0
        ]
        return float(sum(processing_times) / max(1, len(processing_times)))

    def _estimate_hourly_throughput(self, detection_results: List[ValidationResult]) -> float:
        """Estimate hourly throughput based on current performance."""
        avg_time = self._calculate_average_processing_time(detection_results)
        if avg_time > 0:
            return 3600 / avg_time  # Binaries per hour
        return 0.0

    def _assess_scalability_rating(self, detection_results: List[ValidationResult]) -> str:
        """Assess scalability rating based on performance metrics."""
        avg_time = self._calculate_average_processing_time(detection_results)

        if avg_time < 30:
            return "EXCELLENT"
        elif avg_time < 60:
            return "GOOD"
        elif avg_time < 120:
            return "ACCEPTABLE"
        elif avg_time < 300:
            return "SLOW"
        else:
            return "POOR"

    def _calculate_evidence_throughput(self, evidence_reports: List[EvidenceIntegrityReport],
                                     total_time: float) -> float:
        """Calculate evidence points processed per minute."""
        total_evidence_checks = sum(
            len(r.anomaly_detection) +
            (10 if r.authenticity_verified else 0) +  # Estimate evidence points
            (5 if r.temporal_consistency else 0)
            for r in evidence_reports
        )

        if total_time > 0:
            return total_evidence_checks * 60 / total_time
        return 0.0

    def _update_orchestration_metrics(self, processing_time: float, success: bool, binaries_count: int):
        """Update orchestration performance metrics."""
        self.orchestration_metrics['total_orchestrations'] += 1
        self.orchestration_metrics['total_orchestration_time'] += processing_time
        self.orchestration_metrics['total_binaries_processed'] += binaries_count

        if success:
            self.orchestration_metrics['successful_orchestrations'] += 1
        else:
            self.orchestration_metrics['failed_orchestrations'] += 1

        # Update average
        self.orchestration_metrics['average_orchestration_time'] = (
            self.orchestration_metrics['total_orchestration_time'] /
            self.orchestration_metrics['total_orchestrations']
        )

    def _generate_validation_id(self, validation_name: Optional[str]) -> str:
        """Generate unique validation ID."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        if validation_name:
            safe_name = "".join(c for c in validation_name if c.isalnum() or c in '-_')[:20]
            return f"COMP_{timestamp}_{safe_name}"
        else:
            return f"COMP_{timestamp}_{hashlib.md5(str(timestamp).encode()).hexdigest()[:8]}"  # noqa: S324

    def get_orchestration_statistics(self) -> Dict[str, Any]:
        """Get current orchestration performance statistics."""
        total = self.orchestration_metrics['total_orchestrations']
        return {
            'orchestration_metrics': self.orchestration_metrics.copy(),
            'success_rate': self.orchestration_metrics['successful_orchestrations'] / max(1, total),
            'failure_rate': self.orchestration_metrics['failed_orchestrations'] / max(1, total),
            'average_binaries_per_orchestration': self.orchestration_metrics['total_binaries_processed'] / max(1, total),
            'estimated_daily_capacity': self._estimate_daily_capacity()
        }

    def _estimate_daily_capacity(self) -> float:
        """Estimate daily processing capacity."""
        avg_time = self.orchestration_metrics['average_orchestration_time']
        avg_binaries = self.orchestration_metrics['total_binaries_processed'] / max(1, self.orchestration_metrics['total_orchestrations'])

        if avg_time > 0:
            orchestrations_per_day = 86400 / avg_time  # 24 hours
            return orchestrations_per_day * avg_binaries
        return 0.0


# Main execution for comprehensive validation testing
async def main():
    """Main function for comprehensive validation orchestration testing."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python validation_orchestrator.py <binary_path1> [binary_path2...] [--validation-name NAME]")
        return

    # Parse command line arguments
    binary_paths = []
    validation_name = None

    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == '--validation-name' and i + 1 < len(sys.argv):
            validation_name = sys.argv[i + 1]
            i += 2
        else:
            binary_paths.append(Path(sys.argv[i]))
            i += 1

    if not binary_paths:
        print("Error: No binary paths provided")
        return

    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Create orchestrator
    config = ComprehensiveValidationConfig(
        validation_config=ValidationConfig(detailed_logging=True),
        evidence_verification_config=EvidenceVerificationConfig(
            cryptographic_verification=True,
            deep_binary_analysis=True,
            anomaly_detection_enabled=True
        ),
        comprehensive_reporting=True,
        performance_benchmarking=True
    )
    orchestrator = ValidationOrchestrator(config)

    # Run comprehensive validation
    print("\n=== COMPREHENSIVE VALIDATION ORCHESTRATION ===")
    print(f"Validating {len(binary_paths)} binaries")
    print(f"Validation name: {validation_name or 'Auto-generated'}")
    print("Starting validation...")

    report = await orchestrator.orchestrate_comprehensive_validation(binary_paths, None, validation_name)

    # Display comprehensive results
    print("\n=== COMPREHENSIVE VALIDATION RESULTS ===")
    print(f"Validation ID: {report.validation_id}")
    print(f"Binaries Processed: {report.binaries_processed}")
    print(f"Total Processing Time: {report.total_processing_time:.2f}s")
    print(f"Overall Success Rate: {report.overall_success_rate:.1%}")
    print(f"Average Consensus Score: {report.average_consensus_score:.3f}")
    print(f"Average Integrity Score: {report.average_integrity_score:.3f}")
    print(f"Total Protections Detected: {report.total_protections_detected}")
    print(f"Total Evidence Points: {report.total_evidence_points_collected}")
    print(f"Validation Quality Score: {report.validation_quality_score:.3f}")

    if report.improvement_recommendations:
        print("\n=== IMPROVEMENT RECOMMENDATIONS ===")
        for i, recommendation in enumerate(report.improvement_recommendations, 1):
            print(f"{i:2d}. {recommendation}")

    if report.remediation_actions:
        print("\n=== REMEDIATION ACTIONS ===")
        for i, action in enumerate(report.remediation_actions, 1):
            print(f"{i:2d}. {action}")

    print("\nOrchestration Statistics:")
    stats = orchestrator.get_orchestration_statistics()
    print(f"  - Total Orchestrations: {stats['orchestration_metrics']['total_orchestrations']}")
    print(f"  - Success Rate: {stats['success_rate']:.1%}")
    print(f"  - Average Processing Time: {stats['orchestration_metrics']['average_orchestration_time']:.2f}s")
    print(f"  - Estimated Daily Capacity: {stats['estimated_daily_capacity']:.0f} binaries")


if __name__ == "__main__":
    asyncio.run(main())
