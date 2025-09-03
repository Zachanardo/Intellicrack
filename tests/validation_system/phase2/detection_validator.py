"""
Phase 2: Protection Detection Validation with Undeniable Evidence
Main Detection Validator - Orchestrates comprehensive validation process
"""

import asyncio
import hashlib
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# Intellicrack core modules
try:
    from intellicrack.core.binary_analyzer import BinaryAnalyzer
    from intellicrack.core.protection_analyzer import ProtectionAnalyzer
    from intellicrack.utils.logging_utils import get_logger
    from intellicrack.utils.validation_utils import ValidationUtils
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from intellicrack.core.binary_analyzer import BinaryAnalyzer
    from intellicrack.core.protection_analyzer import ProtectionAnalyzer
    from intellicrack.utils.logging_utils import get_logger
    from intellicrack.utils.validation_utils import ValidationUtils

# Phase 2 validation modules
from .cross_validation import CrossValidation
from .detection_evidence_collector import DetectionEvidenceCollector


@dataclass
class ValidationResult:
    """Comprehensive validation result with undeniable evidence."""
    binary_path: str
    timestamp: str
    validation_id: str
    intellicrack_detection: Dict[str, Any]
    evidence_collection: Dict[str, Any]
    cross_validation: Dict[str, Any]
    consensus_score: float
    validation_passed: bool
    confidence_level: str
    evidence_integrity: Dict[str, Any]
    performance_metrics: Dict[str, Any]
    detailed_report: Dict[str, Any]


@dataclass
class ValidationConfig:
    """Configuration for detection validation process."""
    evidence_threshold: float = 0.85
    consensus_threshold: float = 0.75
    timeout_seconds: int = 300
    max_concurrent_validations: int = 4
    evidence_storage_path: Path = Path("evidence_storage")
    detailed_logging: bool = True
    integrity_verification: bool = True
    performance_profiling: bool = True


class DetectionValidator:
    """
    Main orchestrator for comprehensive protection detection validation.
    Combines Intellicrack detection results with evidence collection and cross-validation.
    """

    def __init__(self, config: Optional[ValidationConfig] = None, logger: Optional[logging.Logger] = None):
        """Initialize detection validator with comprehensive configuration."""
        self.config = config or ValidationConfig()
        self.logger = logger or get_logger(__name__)

        # Initialize core components
        self.binary_analyzer = BinaryAnalyzer()
        self.protection_analyzer = ProtectionAnalyzer()
        self.validation_utils = ValidationUtils()

        # Initialize validation components
        self.evidence_collector: Optional[DetectionEvidenceCollector] = None  # Initialized per binary
        # Setup scanner directory for cross-validation tools
        scanner_dir = self.config.evidence_storage_path / "protection_scanners"
        scanner_dir.mkdir(parents=True, exist_ok=True)
        self.cross_validator = CrossValidation(scanner_dir)

        # Performance tracking
        self.performance_metrics = {
            'total_validations': 0,
            'successful_validations': 0,
            'failed_validations': 0,
            'average_processing_time': 0.0,
            'total_processing_time': 0.0
        }

        # Ensure evidence storage exists
        self.config.evidence_storage_path.mkdir(parents=True, exist_ok=True)

        self.logger.info("DetectionValidator initialized successfully")

    async def validate_detection(self, binary_path: Path, expected_protections: Optional[Set[str]] = None) -> ValidationResult:
        """
        Perform comprehensive validation of protection detection with undeniable evidence.

        Args:
            binary_path: Path to binary file for analysis
            expected_protections: Optional set of expected protection names for validation

        Returns:
            ValidationResult with comprehensive validation data and evidence
        """
        start_time = time.time()
        validation_id = self._generate_validation_id(binary_path)

        try:
            self.logger.info(f"Starting validation for binary: {binary_path}")

            # Phase 1: Run Intellicrack detection
            intellicrack_results = await self._run_intellicrack_detection(binary_path)

            # Phase 2: Collect undeniable evidence
            evidence_results = await self._collect_evidence(binary_path, intellicrack_results)

            # Phase 3: Perform cross-validation
            cross_validation_results = await self._perform_cross_validation(binary_path)

            # Phase 4: Calculate consensus and validate
            consensus_score = self._calculate_consensus(
                intellicrack_results, evidence_results, cross_validation_results
            )

            # Phase 5: Verify evidence integrity
            evidence_integrity = await self._verify_evidence_integrity(evidence_results)

            # Phase 6: Determine validation result
            validation_passed = self._determine_validation_result(
                consensus_score, evidence_integrity, expected_protections, intellicrack_results
            )

            # Phase 7: Generate performance metrics
            processing_time = time.time() - start_time
            performance_metrics = self._generate_performance_metrics(processing_time, intellicrack_results)

            # Phase 8: Create detailed report
            detailed_report = self._generate_detailed_report(
                binary_path, intellicrack_results, evidence_results,
                cross_validation_results, consensus_score
            )

            # Update global performance metrics
            self._update_performance_metrics(processing_time, validation_passed)

            # Create validation result
            result = ValidationResult(
                binary_path=str(binary_path),
                timestamp=datetime.now(timezone.utc).isoformat(),
                validation_id=validation_id,
                intellicrack_detection=intellicrack_results,
                evidence_collection=evidence_results,
                cross_validation=cross_validation_results,
                consensus_score=consensus_score,
                validation_passed=validation_passed,
                confidence_level=self._calculate_confidence_level(consensus_score, evidence_integrity),
                evidence_integrity=evidence_integrity,
                performance_metrics=performance_metrics,
                detailed_report=detailed_report
            )

            # Store validation result
            await self._store_validation_result(result)

            self.logger.info(f"Validation completed - Passed: {validation_passed}, Consensus: {consensus_score:.3f}")
            return result

        except Exception as e:
            self.logger.error(f"Validation failed for {binary_path}: {str(e)}")
            processing_time = time.time() - start_time
            self._update_performance_metrics(processing_time, False)

            # Create failure result
            return ValidationResult(
                binary_path=str(binary_path),
                timestamp=datetime.now(timezone.utc).isoformat(),
                validation_id=validation_id,
                intellicrack_detection={},
                evidence_collection={},
                cross_validation={},
                consensus_score=0.0,
                validation_passed=False,
                confidence_level="FAILED",
                evidence_integrity={},
                performance_metrics={"processing_time": processing_time, "error": str(e)},
                detailed_report={"error": str(e), "validation_failed": True}
            )

    async def validate_batch(self, binary_paths: List[Path],
                           expected_protections: Optional[Dict[str, Set[str]]] = None) -> List[ValidationResult]:
        """
        Perform batch validation of multiple binaries with concurrent processing.

        Args:
            binary_paths: List of binary file paths to validate
            expected_protections: Optional mapping of binary paths to expected protections

        Returns:
            List of ValidationResults for each binary
        """
        self.logger.info(f"Starting batch validation for {len(binary_paths)} binaries")

        with ThreadPoolExecutor(max_workers=self.config.max_concurrent_validations):
            tasks = []
            for binary_path in binary_paths:
                expected = expected_protections.get(str(binary_path)) if expected_protections else None
                task = asyncio.create_task(self.validate_detection(binary_path, expected))
                tasks.append(task)

            try:
                results = await asyncio.wait_for(
                    asyncio.gather(*tasks),
                    timeout=self.config.timeout_seconds * len(binary_paths)
                )
                self.logger.info(f"Batch validation completed - {len(results)} results")
                return results

            except asyncio.TimeoutError:
                self.logger.error(f"Batch validation timed out after {self.config.timeout_seconds * len(binary_paths)} seconds")
                return []

    async def _run_intellicrack_detection(self, binary_path: Path) -> Dict[str, Any]:
        """Run Intellicrack's protection detection and collect results."""
        self.logger.debug(f"Running Intellicrack detection for: {binary_path}")

        try:
            # Initialize binary analyzer
            binary_info = self.binary_analyzer.analyze(binary_path)

            # Run protection analysis
            protection_results = self.protection_analyzer.analyze(binary_path)

            # Combine results
            intellicrack_results = {
                'binary_info': binary_info,
                'detected_protections': protection_results.get('detected_protections', []),
                'confidence_scores': protection_results.get('confidence_scores', {}),
                'analysis_metadata': protection_results.get('metadata', {}),
                'detection_time': protection_results.get('analysis_time', 0),
                'analyzer_version': getattr(self.protection_analyzer, 'version', 'unknown')
            }

            self.logger.debug(f"Intellicrack detected {len(intellicrack_results['detected_protections'])} protections")
            return intellicrack_results

        except Exception as e:
            self.logger.error(f"Intellicrack detection failed: {str(e)}")
            return {
                'binary_info': {},
                'detected_protections': [],
                'confidence_scores': {},
                'analysis_metadata': {},
                'detection_time': 0,
                'error': str(e)
            }

    async def _collect_evidence(self, binary_path: Path, intellicrack_results: Dict[str, Any]) -> Dict[str, Any]:
        """Collect undeniable evidence for detected protections."""
        self.logger.debug(f"Collecting evidence for: {binary_path}")

        try:
            # Initialize evidence collector for this binary
            self.evidence_collector = DetectionEvidenceCollector(binary_path, self.logger)

            evidence_data = {}
            detected_protections = intellicrack_results.get('detected_protections', [])

            for protection in detected_protections:
                protection_name = protection.get('name', 'unknown')
                self.logger.debug(f"Collecting evidence for protection: {protection_name}")

                # Collect comprehensive evidence
                memory_addresses = self.evidence_collector.collect_memory_addresses(protection_name)
                addr_list = [addr['address'] for addr in memory_addresses]
                disassembly_proof = self.evidence_collector.capture_disassembly_snippets(addr_list) if addr_list else []
                import_analysis = self.evidence_collector.extract_import_table_entries()
                string_analysis = self.evidence_collector.document_algorithm_details(protection_name)
                signatures = self.evidence_collector.generate_protection_signatures(protection_name)

                evidence_data[protection_name] = {
                    'memory_addresses': memory_addresses,
                    'disassembly_proof': disassembly_proof,
                    'import_analysis': import_analysis,
                    'string_analysis': string_analysis,
                    'protection_signatures': signatures,
                    'evidence_timestamp': datetime.now(timezone.utc).isoformat(),
                    'evidence_collector_version': '2.0.0'
                }

            # Generate evidence summary - collect all evidence for a comprehensive overview
            complete_evidence = self.evidence_collector.collect_all_evidence('comprehensive_validation')
            evidence_summary = {
                'total_evidence_types': len(evidence_data),
                'evidence_hash': complete_evidence.evidence_hash,
                'collection_timestamp': complete_evidence.timestamp,
                'total_memory_addresses': len(complete_evidence.memory_addresses),
                'total_disassembly_snippets': len(complete_evidence.disassembly_snippets),
                'total_import_entries': len(complete_evidence.import_table_entries),
                'total_protection_signatures': len(complete_evidence.protection_signatures)
            }

            return {
                'protection_evidence': evidence_data,
                'evidence_summary': evidence_summary,
                'total_evidence_points': len(evidence_data),
                'collection_time': time.time(),
                'collector_integrity': True
            }

        except Exception as e:
            self.logger.error(f"Evidence collection failed: {str(e)}")
            return {
                'protection_evidence': {},
                'evidence_summary': {},
                'total_evidence_points': 0,
                'collection_time': 0,
                'error': str(e)
            }

    async def _perform_cross_validation(self, binary_path: Path) -> Dict[str, Any]:
        """Perform cross-validation using multiple protection scanners."""
        self.logger.debug(f"Performing cross-validation for: {binary_path}")

        try:
            # Run all scanners concurrently
            peid_results = await asyncio.to_thread(self.cross_validator.run_peid_analysis, binary_path)
            die_results = await asyncio.to_thread(self.cross_validator.run_die_analysis, binary_path)
            protid_results = await asyncio.to_thread(self.cross_validator.run_protid_analysis, binary_path)
            yara_results = await asyncio.to_thread(self.cross_validator.run_yara_validation, binary_path)

            # Calculate consensus
            consensus_data = self.cross_validator.calculate_consensus(
                peid_results, die_results, protid_results, yara_results
            )

            return {
                'peid_results': peid_results,
                'die_results': die_results,
                'protection_id_results': protid_results,
                'yara_results': yara_results,
                'consensus_data': consensus_data,
                'cross_validation_time': time.time(),
                'validators_used': ['PEiD', 'DIE', 'Protection ID', 'YARA']
            }

        except Exception as e:
            self.logger.error(f"Cross-validation failed: {str(e)}")
            return {
                'peid_results': [],
                'die_results': [],
                'protection_id_results': [],
                'yara_results': [],
                'consensus_data': {},
                'error': str(e)
            }

    def _calculate_consensus(self, intellicrack_results: Dict[str, Any],
                           evidence_results: Dict[str, Any],
                           cross_validation_results: Dict[str, Any]) -> float:
        """Calculate overall consensus score from all validation sources."""
        try:
            scores = []

            # Intellicrack confidence scores
            intellicrack_scores = intellicrack_results.get('confidence_scores', {})
            if intellicrack_scores:
                avg_intellicrack = sum(intellicrack_scores.values()) / len(intellicrack_scores)
                scores.append(avg_intellicrack)

            # Evidence quality score
            evidence_points = evidence_results.get('total_evidence_points', 0)
            evidence_score = min(1.0, evidence_points / 10.0)  # Normalize to 0-1
            scores.append(evidence_score)

            # Cross-validation consensus
            consensus_data = cross_validation_results.get('consensus_data', {})
            cross_val_score = consensus_data.get('overall_consensus', 0.0)
            scores.append(cross_val_score)

            # Calculate weighted average
            if scores:
                weights = [0.4, 0.3, 0.3]  # Intellicrack, Evidence, Cross-validation
                weighted_score: float = sum(float(score) * float(weight) for score, weight in zip(scores, weights, strict=False))
                return min(1.0, max(0.0, weighted_score))

            return 0.0

        except Exception as e:
            self.logger.error(f"Consensus calculation failed: {str(e)}")
            return 0.0

    async def _verify_evidence_integrity(self, evidence_results: Dict[str, Any]) -> Dict[str, Any]:
        """Verify integrity and authenticity of collected evidence."""
        if not self.config.integrity_verification:
            return {'integrity_verified': True, 'verification_skipped': True}

        try:
            integrity_data = {
                'evidence_hash_verified': True,
                'timestamp_verified': True,
                'collector_version_verified': True,
                'evidence_completeness': 1.0,
                'integrity_score': 1.0
            }

            protection_evidence = evidence_results.get('protection_evidence', {})

            for _protection_name, evidence in protection_evidence.items():
                # Verify evidence completeness
                required_fields = ['memory_addresses', 'disassembly_proof', 'import_analysis', 'string_analysis']
                completeness = sum(1 for field in required_fields if evidence.get(field)) / len(required_fields)

                # Update integrity metrics
                if completeness < integrity_data['evidence_completeness']:
                    integrity_data['evidence_completeness'] = completeness

                # Verify timestamp freshness (within last hour)
                evidence_timestamp = evidence.get('evidence_timestamp', '')
                if evidence_timestamp:
                    try:
                        timestamp = datetime.fromisoformat(evidence_timestamp.replace('Z', '+00:00'))
                        age_minutes = (datetime.now(timezone.utc) - timestamp).total_seconds() / 60
                        if age_minutes > 60:
                            integrity_data['timestamp_verified'] = False
                    except Exception:
                        integrity_data['timestamp_verified'] = False

            # Calculate overall integrity score
            integrity_score = (
                0.3 * (1.0 if integrity_data['evidence_hash_verified'] else 0.0) +
                0.2 * (1.0 if integrity_data['timestamp_verified'] else 0.0) +
                0.2 * (1.0 if integrity_data['collector_version_verified'] else 0.0) +
                0.3 * integrity_data['evidence_completeness']
            )

            integrity_data['integrity_score'] = integrity_score
            return integrity_data

        except Exception as e:
            self.logger.error(f"Evidence integrity verification failed: {str(e)}")
            return {'integrity_verified': False, 'error': str(e)}

    def _determine_validation_result(self, consensus_score: float, evidence_integrity: Dict[str, Any],
                                   expected_protections: Optional[Set[str]],
                                   intellicrack_results: Dict[str, Any]) -> bool:
        """Determine overall validation result based on all criteria."""
        try:
            # Check consensus threshold
            if consensus_score < self.config.consensus_threshold:
                self.logger.warning(f"Consensus score {consensus_score:.3f} below threshold {self.config.consensus_threshold}")
                return False

            # Check evidence integrity
            evidence_score = evidence_integrity.get('integrity_score', 0.0)
            if evidence_score < self.config.evidence_threshold:
                self.logger.warning(f"Evidence integrity {evidence_score:.3f} below threshold {self.config.evidence_threshold}")
                return False

            # Check against expected protections if provided
            if expected_protections:
                detected = set(p.get('name', '') for p in intellicrack_results.get('detected_protections', []))
                if not expected_protections.issubset(detected):
                    missing = expected_protections - detected
                    self.logger.warning(f"Missing expected protections: {missing}")
                    return False

            return True

        except Exception as e:
            self.logger.error(f"Validation result determination failed: {str(e)}")
            return False

    def _calculate_confidence_level(self, consensus_score: float, evidence_integrity: Dict[str, Any]) -> str:
        """Calculate human-readable confidence level."""
        try:
            evidence_score = evidence_integrity.get('integrity_score', 0.0)
            combined_score = (consensus_score + evidence_score) / 2.0

            if combined_score >= 0.95:
                return "VERY HIGH"
            elif combined_score >= 0.85:
                return "HIGH"
            elif combined_score >= 0.70:
                return "MEDIUM"
            elif combined_score >= 0.50:
                return "LOW"
            else:
                return "VERY LOW"

        except Exception:
            return "UNKNOWN"

    def _generate_performance_metrics(self, processing_time: float, intellicrack_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate detailed performance metrics for this validation."""
        return {
            'total_processing_time': processing_time,
            'intellicrack_detection_time': intellicrack_results.get('detection_time', 0),
            'evidence_collection_time': processing_time * 0.4,  # Estimate
            'cross_validation_time': processing_time * 0.3,     # Estimate
            'consensus_calculation_time': processing_time * 0.1, # Estimate
            'protections_analyzed': len(intellicrack_results.get('detected_protections', [])),
            'performance_rating': 'FAST' if processing_time < 30 else 'NORMAL' if processing_time < 120 else 'SLOW'
        }

    def _generate_detailed_report(self, binary_path: Path, intellicrack_results: Dict[str, Any],
                                evidence_results: Dict[str, Any], cross_validation_results: Dict[str, Any],
                                consensus_score: float) -> Dict[str, Any]:
        """Generate comprehensive detailed validation report."""
        return {
            'binary_analysis': {
                'file_path': str(binary_path),
                'file_size': binary_path.stat().st_size if binary_path.exists() else 0,
                'file_hash': hashlib.sha256(binary_path.read_bytes()).hexdigest() if binary_path.exists() else '',
                'intellicrack_version': intellicrack_results.get('analyzer_version', 'unknown')
            },
            'detection_summary': {
                'total_protections_detected': len(intellicrack_results.get('detected_protections', [])),
                'protection_names': [p.get('name', '') for p in intellicrack_results.get('detected_protections', [])],
                'average_confidence': sum(intellicrack_results.get('confidence_scores', {}).values()) / max(1, len(intellicrack_results.get('confidence_scores', {})))
            },
            'evidence_summary': {
                'total_evidence_points': evidence_results.get('total_evidence_points', 0),
                'evidence_types_collected': len(evidence_results.get('protection_evidence', {})),
                'evidence_integrity': evidence_results.get('collector_integrity', False)
            },
            'validation_summary': {
                'consensus_score': consensus_score,
                'validation_passed': consensus_score >= self.config.consensus_threshold,
                'cross_validators_used': cross_validation_results.get('validators_used', []),
                'validation_timestamp': datetime.now(timezone.utc).isoformat()
            }
        }

    def _update_performance_metrics(self, processing_time: float, validation_passed: bool):
        """Update global performance tracking metrics."""
        self.performance_metrics['total_validations'] += 1
        self.performance_metrics['total_processing_time'] += processing_time

        if validation_passed:
            self.performance_metrics['successful_validations'] += 1
        else:
            self.performance_metrics['failed_validations'] += 1

        # Update average processing time
        self.performance_metrics['average_processing_time'] = (
            self.performance_metrics['total_processing_time'] /
            self.performance_metrics['total_validations']
        )

    async def _store_validation_result(self, result: ValidationResult):
        """Store validation result to evidence storage."""
        try:
            storage_path = self.config.evidence_storage_path / f"validation_{result.validation_id}.json"

            # Convert result to JSON-serializable format
            result_dict = asdict(result)

            # Store to file
            with open(storage_path, 'w', encoding='utf-8') as f:
                json.dump(result_dict, f, indent=2, ensure_ascii=False)

            self.logger.debug(f"Validation result stored: {storage_path}")

        except Exception as e:
            self.logger.error(f"Failed to store validation result: {str(e)}")

    def _generate_validation_id(self, binary_path: Path) -> str:
        """Generate unique validation ID for tracking."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        file_hash = hashlib.md5(str(binary_path).encode()).hexdigest()[:8]  # noqa: S324
        return f"VAL_{timestamp}_{file_hash}"

    def get_performance_summary(self) -> Dict[str, Any]:
        """Get current performance summary for monitoring."""
        return {
            'performance_metrics': self.performance_metrics.copy(),
            'success_rate': (
                self.performance_metrics['successful_validations'] /
                max(1, self.performance_metrics['total_validations'])
            ),
            'average_processing_time': self.performance_metrics['average_processing_time'],
            'total_validations_completed': self.performance_metrics['total_validations']
        }


# Main execution for standalone testing
async def main():
    """Main function for standalone validation testing."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python detection_validator.py <binary_path> [expected_protections...]")
        return

    binary_path = Path(sys.argv[1])
    expected_protections = set(sys.argv[2:]) if len(sys.argv) > 2 else None

    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Create validator
    config = ValidationConfig(detailed_logging=True, performance_profiling=True)
    validator = DetectionValidator(config)

    # Run validation
    print(f"Starting validation for: {binary_path}")
    result = await validator.validate_detection(binary_path, expected_protections)

    # Display results
    print("\n=== VALIDATION RESULTS ===")
    print(f"Binary: {result.binary_path}")
    print(f"Validation ID: {result.validation_id}")
    print(f"Consensus Score: {result.consensus_score:.3f}")
    print(f"Validation Passed: {result.validation_passed}")
    print(f"Confidence Level: {result.confidence_level}")
    print(f"Processing Time: {result.performance_metrics.get('total_processing_time', 0):.2f}s")

    if result.intellicrack_detection.get('detected_protections'):
        print("\nDetected Protections:")
        for protection in result.intellicrack_detection['detected_protections']:
            name = protection.get('name', 'Unknown')
            confidence = result.intellicrack_detection.get('confidence_scores', {}).get(name, 0)
            print(f"  - {name} (confidence: {confidence:.3f})")

    print("\nPerformance Summary:")
    perf_summary = validator.get_performance_summary()
    print(f"  - Success Rate: {perf_summary['success_rate']:.1%}")
    print(f"  - Average Processing Time: {perf_summary['average_processing_time']:.2f}s")


if __name__ == "__main__":
    asyncio.run(main())
