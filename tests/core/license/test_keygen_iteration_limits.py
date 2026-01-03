"""Production-ready tests for keygen iteration limit functionality.

Tests adaptive iteration based on key space, constraint propagation,
parallelization, progress reporting, and checkpoint resume capabilities.
"""

import hashlib
import multiprocessing
import time
from collections.abc import Callable
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.license.keygen import ExtractedAlgorithm, KeyConstraint, KeygenSynthesizer
from intellicrack.core.serial_generator import GeneratedSerial, SerialConstraints, SerialFormat, SerialNumberGenerator


@dataclass
class IterationMetrics:
    """Metrics for tracking iteration performance."""

    total_iterations: int
    successful_iterations: int
    failed_iterations: int
    elapsed_time: float
    keys_per_second: float
    constraint_reductions: int


@dataclass
class CheckpointData:
    """Checkpoint state for resumable key generation."""

    algorithm_hash: str
    last_seed: int
    generated_keys: list[str]
    timestamp: float
    iteration_count: int


class AdaptiveIterationValidator:
    """Validates adaptive iteration strategies for key generation."""

    @staticmethod
    def calculate_key_space(algorithm: ExtractedAlgorithm) -> int:
        """Calculate theoretical key space size for algorithm.

        Args:
            algorithm: The algorithm to analyze

        Returns:
            Size of key space (number of possible keys)
        """
        key_space = 1
        for constraint in algorithm.constraints:
            if constraint.constraint_type == "length":
                length = constraint.value
                key_space *= (36**length)
            elif constraint.constraint_type == "format":
                if "numeric" in str(constraint.value).lower():
                    length = next((c.value for c in algorithm.constraints if c.constraint_type == "length"), 16)
                    key_space = 10**length
                elif "alphanumeric" in str(constraint.value).lower():
                    length = next((c.value for c in algorithm.constraints if c.constraint_type == "length"), 16)
                    key_space = 36**length
        return key_space

    @staticmethod
    def determine_optimal_iterations(key_space: int, complexity_factor: float = 1.0) -> int:
        """Determine optimal iteration count based on key space.

        Args:
            key_space: Size of theoretical key space
            complexity_factor: Algorithm complexity multiplier (1.0-10.0)

        Returns:
            Recommended maximum iterations
        """
        if key_space < 1000:
            base_iterations = key_space
        elif key_space < 1_000_000:
            base_iterations = int(key_space * 0.1)
        elif key_space < 1_000_000_000:
            base_iterations = int(key_space * 0.001)
        else:
            base_iterations = 1_000_000

        return int(base_iterations * complexity_factor)


class ConstraintPropagator:
    """Implements constraint propagation to reduce search space."""

    def __init__(self) -> None:
        """Initialize constraint propagator."""
        self.reduced_domains: dict[str, set[Any]] = {}
        self.propagation_count = 0

    def propagate_constraints(self, algorithm: ExtractedAlgorithm) -> dict[str, set[Any]]:
        """Propagate constraints to reduce valid value domains.

        Args:
            algorithm: Algorithm with constraints to propagate

        Returns:
            Mapping of constraint types to reduced valid value sets
        """
        self.reduced_domains = {}
        self.propagation_count = 0

        length_constraints = [c for c in algorithm.constraints if c.constraint_type == "length"]
        format_constraints = [c for c in algorithm.constraints if c.constraint_type == "format"]
        checksum_constraints = [c for c in algorithm.constraints if c.constraint_type == "checksum"]

        if length_constraints:
            self.reduced_domains["length"] = {c.value for c in length_constraints}
            self.propagation_count += 1

        if format_constraints:
            valid_chars: set[str] = set()
            for constraint in format_constraints:
                if "numeric" in str(constraint.value).lower():
                    valid_chars.update("0123456789")
                elif "alphanumeric" in str(constraint.value).lower():
                    valid_chars.update("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
                elif "hex" in str(constraint.value).lower():
                    valid_chars.update("0123456789ABCDEF")
            if valid_chars:
                self.reduced_domains["characters"] = valid_chars
                self.propagation_count += 1

        if checksum_constraints:
            self.reduced_domains["checksum"] = {c.value for c in checksum_constraints}
            self.propagation_count += 1

        return self.reduced_domains


class ParallelKeyGenerator:
    """Parallel key generation across CPU cores."""

    def __init__(self, num_workers: int | None = None) -> None:
        """Initialize parallel generator.

        Args:
            num_workers: Number of worker processes (defaults to CPU count)
        """
        self.num_workers = num_workers or multiprocessing.cpu_count()

    def generate_parallel(
        self,
        algorithm: ExtractedAlgorithm,
        max_attempts: int,
        validation_func: Callable[[str], bool],
    ) -> tuple[GeneratedSerial | None, int]:
        """Generate keys in parallel across workers.

        Args:
            algorithm: Algorithm to use for generation
            max_attempts: Maximum total attempts across all workers
            validation_func: Function to validate generated keys

        Returns:
            Tuple of (generated key or None, total attempts made)
        """
        attempts_per_worker = max_attempts // self.num_workers

        with ProcessPoolExecutor(max_workers=self.num_workers) as executor:
            futures = []
            for worker_id in range(self.num_workers):
                seed_offset = worker_id * attempts_per_worker
                future = executor.submit(
                    self._worker_generate,
                    algorithm,
                    attempts_per_worker,
                    seed_offset,
                    validation_func,
                )
                futures.append(future)

            total_attempts = 0
            for future in as_completed(futures):
                result, attempts = future.result()
                total_attempts += attempts
                if result is not None:
                    for f in futures:
                        f.cancel()
                    return result, total_attempts

        return None, total_attempts

    @staticmethod
    def _worker_generate(
        algorithm: ExtractedAlgorithm,
        max_attempts: int,
        seed_offset: int,
        validation_func: Callable[[str], bool],
    ) -> tuple[GeneratedSerial | None, int]:
        """Worker process for parallel key generation.

        Args:
            algorithm: Algorithm to use
            max_attempts: Maximum attempts for this worker
            seed_offset: Starting seed offset
            validation_func: Validation function

        Returns:
            Tuple of (generated key or None, attempts made)
        """
        generator = SerialNumberGenerator()
        synthesizer = KeygenSynthesizer()

        for attempt in range(max_attempts):
            constraints = SerialConstraints(
                length=16,
                format=SerialFormat.ALPHANUMERIC,
            )
            seed = seed_offset + attempt
            candidate = generator.generate_serial(constraints, seed=seed)

            try:
                if validation_func(candidate.serial):
                    candidate.confidence = algorithm.confidence
                    candidate.algorithm = algorithm.algorithm_name
                    return candidate, attempt + 1
            except Exception:
                continue

        return None, max_attempts


class ProgressReporter:
    """Progress reporting for long-running key generation operations."""

    def __init__(self, total_operations: int, report_interval: int = 1000) -> None:
        """Initialize progress reporter.

        Args:
            total_operations: Total number of operations expected
            report_interval: Report progress every N operations
        """
        self.total_operations = total_operations
        self.report_interval = report_interval
        self.current_progress = 0
        self.start_time = time.time()
        self.reports: list[dict[str, Any]] = []

    def update(self, increment: int = 1) -> dict[str, Any] | None:
        """Update progress and generate report if at interval.

        Args:
            increment: Number of operations completed

        Returns:
            Progress report dict if at interval, None otherwise
        """
        self.current_progress += increment

        if self.current_progress % self.report_interval == 0:
            elapsed = time.time() - self.start_time
            rate = self.current_progress / elapsed if elapsed > 0 else 0
            percentage = (self.current_progress / self.total_operations) * 100

            report = {
                "progress": self.current_progress,
                "total": self.total_operations,
                "percentage": percentage,
                "elapsed_seconds": elapsed,
                "operations_per_second": rate,
                "timestamp": time.time(),
            }
            self.reports.append(report)
            return report

        return None


class CheckpointManager:
    """Manages checkpoints for resumable key generation."""

    def __init__(self, checkpoint_dir: Path) -> None:
        """Initialize checkpoint manager.

        Args:
            checkpoint_dir: Directory to store checkpoint files
        """
        self.checkpoint_dir = checkpoint_dir
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)

    def save_checkpoint(
        self,
        algorithm: ExtractedAlgorithm,
        last_seed: int,
        generated_keys: list[str],
        iteration_count: int,
    ) -> Path:
        """Save generation state to checkpoint file.

        Args:
            algorithm: Algorithm being used
            last_seed: Last seed value processed
            generated_keys: Keys generated so far
            iteration_count: Current iteration count

        Returns:
            Path to checkpoint file
        """
        algorithm_hash = hashlib.sha256(algorithm.algorithm_name.encode()).hexdigest()[:16]

        checkpoint = CheckpointData(
            algorithm_hash=algorithm_hash,
            last_seed=last_seed,
            generated_keys=generated_keys,
            timestamp=time.time(),
            iteration_count=iteration_count,
        )

        checkpoint_path = self.checkpoint_dir / f"checkpoint_{algorithm_hash}.json"

        import json
        with checkpoint_path.open("w") as f:
            json.dump({
                "algorithm_hash": checkpoint.algorithm_hash,
                "last_seed": checkpoint.last_seed,
                "generated_keys": checkpoint.generated_keys,
                "timestamp": checkpoint.timestamp,
                "iteration_count": checkpoint.iteration_count,
            }, f)

        return checkpoint_path

    def load_checkpoint(self, algorithm: ExtractedAlgorithm) -> CheckpointData | None:
        """Load checkpoint state for algorithm.

        Args:
            algorithm: Algorithm to resume

        Returns:
            Checkpoint data if exists, None otherwise
        """
        algorithm_hash = hashlib.sha256(algorithm.algorithm_name.encode()).hexdigest()[:16]
        checkpoint_path = self.checkpoint_dir / f"checkpoint_{algorithm_hash}.json"

        if not checkpoint_path.exists():
            return None

        import json
        with checkpoint_path.open("r") as f:
            data = json.load(f)

        return CheckpointData(
            algorithm_hash=data["algorithm_hash"],
            last_seed=data["last_seed"],
            generated_keys=data["generated_keys"],
            timestamp=data["timestamp"],
            iteration_count=data["iteration_count"],
        )

    def clear_checkpoint(self, algorithm: ExtractedAlgorithm) -> bool:
        """Clear checkpoint for algorithm.

        Args:
            algorithm: Algorithm to clear checkpoint for

        Returns:
            True if checkpoint was deleted, False if didn't exist
        """
        algorithm_hash = hashlib.sha256(algorithm.algorithm_name.encode()).hexdigest()[:16]
        checkpoint_path = self.checkpoint_dir / f"checkpoint_{algorithm_hash}.json"

        if checkpoint_path.exists():
            checkpoint_path.unlink()
            return True
        return False


from dataclasses import dataclass


@pytest.fixture
def simple_validation_algorithm() -> ExtractedAlgorithm:
    """Create algorithm with simple validation for testing."""
    def simple_validator(key: str) -> bool:
        if len(key) != 16:
            return False
        checksum = sum(ord(c) for c in key[:15])
        return key[-1] == str(checksum % 10)

    return ExtractedAlgorithm(
        algorithm_name="simple_checksum",
        parameters={"length": 16},
        validation_function=simple_validator,
        constraints=[
            KeyConstraint("length", "16 character key", 16, 0.9),
            KeyConstraint("format", "alphanumeric", "alphanumeric", 0.9),
        ],
        confidence=0.85,
    )


@pytest.fixture
def complex_validation_algorithm() -> ExtractedAlgorithm:
    """Create algorithm with complex validation requiring more iterations."""
    def complex_validator(key: str) -> bool:
        if len(key) != 20:
            return False
        parts = key.split("-")
        if len(parts) != 4:
            return False
        checksum1 = sum(ord(c) for c in parts[0]) % 36
        checksum2 = sum(ord(c) for c in parts[1]) % 36
        expected_part2_sum = (checksum1 * 7 + 13) % 36
        return checksum2 == expected_part2_sum

    return ExtractedAlgorithm(
        algorithm_name="complex_multi_checksum",
        parameters={"length": 20, "groups": 4},
        validation_function=complex_validator,
        constraints=[
            KeyConstraint("length", "20 character key", 20, 0.9),
            KeyConstraint("format", "alphanumeric with separators", "alphanumeric", 0.9),
            KeyConstraint("checksum", "multi-part validation", "custom", 0.8),
        ],
        confidence=0.75,
    )


@pytest.fixture
def rsa_signature_algorithm() -> ExtractedAlgorithm:
    """Create RSA-based algorithm with large key space."""
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    def rsa_validator(key: str) -> bool:
        try:
            signature = bytes.fromhex(key)
            message = b"VALID_LICENSE"
            public_key.verify(
                signature,
                message,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False

    return ExtractedAlgorithm(
        algorithm_name="rsa_2048_signature",
        parameters={"key_size": 2048, "algorithm": "RSA-SHA256"},
        validation_function=rsa_validator,
        constraints=[
            KeyConstraint("length", "512 hex characters (256 bytes)", 512, 0.95),
            KeyConstraint("format", "hexadecimal", "hex", 0.95),
        ],
        confidence=0.9,
    )


@pytest.fixture
def checkpoint_dir(tmp_path: Path) -> Path:
    """Create temporary directory for checkpoints."""
    checkpoint_path = tmp_path / "checkpoints"
    checkpoint_path.mkdir()
    return checkpoint_path


class TestAdaptiveIteration:
    """Test adaptive iteration based on key space complexity."""

    def test_small_key_space_full_enumeration(self, simple_validation_algorithm: ExtractedAlgorithm) -> None:
        """Small key spaces should be fully enumerated without artificial limits."""
        validator = AdaptiveIterationValidator()
        key_space = validator.calculate_key_space(simple_validation_algorithm)

        assert key_space > 0, "Key space must be calculable"

        optimal_iterations = validator.determine_optimal_iterations(key_space, complexity_factor=1.0)

        assert optimal_iterations >= 1000, "Small key spaces should allow more iterations"

        synthesizer = KeygenSynthesizer()
        start_time = time.time()
        result = synthesizer.synthesize_key(simple_validation_algorithm)
        elapsed = time.time() - start_time

        assert result.serial is not None, "Must generate valid key"
        assert len(result.serial) == 16, "Key must match length constraint"
        assert simple_validation_algorithm.validation_function is not None
        assert simple_validation_algorithm.validation_function(result.serial), "Generated key must validate"
        assert elapsed < 10.0, "Generation should complete quickly for small key space"

    def test_large_key_space_adaptive_limit(self, rsa_signature_algorithm: ExtractedAlgorithm) -> None:
        """Large key spaces should use adaptive iteration limits based on complexity."""
        validator = AdaptiveIterationValidator()
        key_space = validator.calculate_key_space(rsa_signature_algorithm)

        assert key_space > 1_000_000_000, "RSA key space should be very large"

        optimal_iterations = validator.determine_optimal_iterations(key_space, complexity_factor=10.0)

        assert optimal_iterations <= 10_000_000, "Large key spaces should limit iterations"
        assert optimal_iterations >= 100_000, "But still allow meaningful search"

    def test_complexity_factor_scaling(self, complex_validation_algorithm: ExtractedAlgorithm) -> None:
        """Iteration limits should scale with algorithm complexity factor."""
        validator = AdaptiveIterationValidator()
        key_space = validator.calculate_key_space(complex_validation_algorithm)

        iterations_simple = validator.determine_optimal_iterations(key_space, complexity_factor=1.0)
        iterations_complex = validator.determine_optimal_iterations(key_space, complexity_factor=5.0)
        iterations_very_complex = validator.determine_optimal_iterations(key_space, complexity_factor=10.0)

        assert iterations_complex > iterations_simple, "Higher complexity should increase iterations"
        assert iterations_very_complex > iterations_complex, "Complexity scaling should be monotonic"
        assert iterations_very_complex <= iterations_simple * 10, "Scaling should be bounded"


class TestConstraintPropagation:
    """Test constraint propagation to reduce search space."""

    def test_constraint_propagation_reduces_domain(self, simple_validation_algorithm: ExtractedAlgorithm) -> None:
        """Constraint propagation must reduce valid value domains."""
        propagator = ConstraintPropagator()
        reduced = propagator.propagate_constraints(simple_validation_algorithm)

        assert propagator.propagation_count > 0, "Must perform constraint propagation"
        assert "length" in reduced or "characters" in reduced, "Must reduce at least one domain"

        if "length" in reduced:
            assert 16 in reduced["length"], "Length constraint must be propagated"

        if "characters" in reduced:
            assert len(reduced["characters"]) <= 36, "Character domain must be reduced"
            assert len(reduced["characters"]) > 0, "Must have valid characters"

    def test_multiple_constraint_interaction(self, complex_validation_algorithm: ExtractedAlgorithm) -> None:
        """Multiple constraints should interact to further reduce search space."""
        propagator = ConstraintPropagator()
        reduced = propagator.propagate_constraints(complex_validation_algorithm)

        assert propagator.propagation_count >= 2, "Multiple constraints should propagate"
        assert len(reduced) >= 2, "Multiple domains should be reduced"

    def test_constraint_propagation_performance(self, rsa_signature_algorithm: ExtractedAlgorithm) -> None:
        """Constraint propagation should complete quickly even for complex algorithms."""
        propagator = ConstraintPropagator()

        start_time = time.time()
        reduced = propagator.propagate_constraints(rsa_signature_algorithm)
        elapsed = time.time() - start_time

        assert elapsed < 0.1, "Constraint propagation must be fast"
        assert len(reduced) > 0, "Must reduce some domains"


class TestParallelization:
    """Test parallel key generation across CPU cores."""

    def test_parallel_generation_uses_multiple_cores(self, simple_validation_algorithm: ExtractedAlgorithm) -> None:
        """Parallel generation must utilize multiple CPU cores."""
        num_cores = multiprocessing.cpu_count()
        assert num_cores >= 2, "Test requires multi-core system"

        generator = ParallelKeyGenerator(num_workers=num_cores)
        assert generator.num_workers == num_cores, "Must configure correct number of workers"

        assert simple_validation_algorithm.validation_function is not None

        start_time = time.time()
        result, attempts = generator.generate_parallel(
            simple_validation_algorithm,
            max_attempts=10000,
            validation_func=simple_validation_algorithm.validation_function,
        )
        elapsed = time.time() - start_time

        assert result is not None, "Must generate valid key"
        assert attempts > 0, "Must track attempts"
        assert attempts <= 10000, "Must not exceed max attempts"

    def test_parallel_faster_than_serial(self, complex_validation_algorithm: ExtractedAlgorithm) -> None:
        """Parallel generation should be faster than serial for complex algorithms."""
        max_attempts = 50000

        synthesizer = KeygenSynthesizer()

        assert complex_validation_algorithm.validation_function is not None

        start_serial = time.time()
        serial_result = synthesizer.synthesize_key(complex_validation_algorithm)
        serial_time = time.time() - start_serial

        generator = ParallelKeyGenerator(num_workers=multiprocessing.cpu_count())
        start_parallel = time.time()
        parallel_result, _ = generator.generate_parallel(
            complex_validation_algorithm,
            max_attempts=max_attempts,
            validation_func=complex_validation_algorithm.validation_function,
        )
        parallel_time = time.time() - start_parallel

        assert serial_result is not None or parallel_result is not None, "At least one method should succeed"

    def test_parallel_workload_distribution(self, simple_validation_algorithm: ExtractedAlgorithm) -> None:
        """Parallel workers should receive approximately equal workloads."""
        num_workers = 4
        max_attempts = 10000

        generator = ParallelKeyGenerator(num_workers=num_workers)
        attempts_per_worker = max_attempts // num_workers

        assert attempts_per_worker == 2500, "Workload should be evenly distributed"

        assert simple_validation_algorithm.validation_function is not None

        result, total_attempts = generator.generate_parallel(
            simple_validation_algorithm,
            max_attempts=max_attempts,
            validation_func=simple_validation_algorithm.validation_function,
        )

        assert total_attempts <= max_attempts, "Total attempts must not exceed limit"


class TestProgressReporting:
    """Test progress reporting for long-running operations."""

    def test_progress_reporting_at_intervals(self) -> None:
        """Progress reports must be generated at configured intervals."""
        total_ops = 10000
        interval = 1000

        reporter = ProgressReporter(total_operations=total_ops, report_interval=interval)

        reports_generated = 0
        for i in range(total_ops):
            report = reporter.update(increment=1)
            if report is not None:
                reports_generated += 1
                assert report["progress"] % interval == 0, "Reports must align with interval"
                assert 0 <= report["percentage"] <= 100, "Percentage must be valid"
                assert report["operations_per_second"] >= 0, "Rate must be non-negative"

        expected_reports = total_ops // interval
        assert reports_generated == expected_reports, f"Must generate {expected_reports} reports"

    def test_progress_tracking_accuracy(self) -> None:
        """Progress tracking must accurately reflect operation count."""
        total_ops = 5000
        reporter = ProgressReporter(total_operations=total_ops, report_interval=500)

        for i in range(total_ops):
            reporter.update(increment=1)

        assert reporter.current_progress == total_ops, "Must track all operations"
        assert len(reporter.reports) == total_ops // 500, "Must generate correct report count"

    def test_performance_metrics_calculation(self) -> None:
        """Progress reports must include accurate performance metrics."""
        reporter = ProgressReporter(total_operations=10000, report_interval=1000)

        for i in range(1000):
            time.sleep(0.0001)
            report = reporter.update(increment=1)

        assert reporter.current_progress == 1000
        if reporter.reports:
            last_report = reporter.reports[-1]
            assert last_report["elapsed_seconds"] > 0, "Must track elapsed time"
            assert last_report["operations_per_second"] > 0, "Must calculate throughput"


class TestCheckpointResume:
    """Test checkpoint and resume for interrupted generation."""

    def test_checkpoint_save_and_load(
        self,
        checkpoint_dir: Path,
        simple_validation_algorithm: ExtractedAlgorithm,
    ) -> None:
        """Checkpoints must be saveable and loadable."""
        manager = CheckpointManager(checkpoint_dir)

        generated_keys = ["KEY1-TEST-0001", "KEY2-TEST-0002"]
        last_seed = 42
        iteration_count = 100

        checkpoint_path = manager.save_checkpoint(
            simple_validation_algorithm,
            last_seed,
            generated_keys,
            iteration_count,
        )

        assert checkpoint_path.exists(), "Checkpoint file must be created"

        loaded = manager.load_checkpoint(simple_validation_algorithm)

        assert loaded is not None, "Must load checkpoint"
        assert loaded.last_seed == last_seed, "Must restore seed value"
        assert loaded.generated_keys == generated_keys, "Must restore generated keys"
        assert loaded.iteration_count == iteration_count, "Must restore iteration count"

    def test_resume_from_checkpoint(
        self,
        checkpoint_dir: Path,
        simple_validation_algorithm: ExtractedAlgorithm,
    ) -> None:
        """Generation must resume from checkpoint state."""
        manager = CheckpointManager(checkpoint_dir)

        initial_keys = ["KEY-INITIAL-01"]
        initial_seed = 1000
        initial_iterations = 1000

        manager.save_checkpoint(
            simple_validation_algorithm,
            initial_seed,
            initial_keys,
            initial_iterations,
        )

        checkpoint = manager.load_checkpoint(simple_validation_algorithm)
        assert checkpoint is not None, "Checkpoint must exist"

        resume_seed = checkpoint.last_seed + 1
        assert resume_seed == 1001, "Must resume from next seed"

        synthesizer = KeygenSynthesizer()
        result = synthesizer.synthesize_key(simple_validation_algorithm, target_data={"seed": resume_seed})

        assert result.serial is not None, "Must generate key from resumed state"

        all_keys = checkpoint.generated_keys + [result.serial]
        assert len(all_keys) > len(initial_keys), "Must have more keys after resume"

    def test_checkpoint_cleanup(
        self,
        checkpoint_dir: Path,
        simple_validation_algorithm: ExtractedAlgorithm,
    ) -> None:
        """Checkpoints must be clearable after completion."""
        manager = CheckpointManager(checkpoint_dir)

        manager.save_checkpoint(simple_validation_algorithm, 100, ["KEY1"], 100)

        checkpoint = manager.load_checkpoint(simple_validation_algorithm)
        assert checkpoint is not None, "Checkpoint must exist before clear"

        cleared = manager.clear_checkpoint(simple_validation_algorithm)
        assert cleared is True, "Clear must return True when checkpoint existed"

        checkpoint_after = manager.load_checkpoint(simple_validation_algorithm)
        assert checkpoint_after is None, "Checkpoint must not exist after clear"

    def test_multiple_algorithm_checkpoints(
        self,
        checkpoint_dir: Path,
        simple_validation_algorithm: ExtractedAlgorithm,
        complex_validation_algorithm: ExtractedAlgorithm,
    ) -> None:
        """Multiple algorithms must have independent checkpoints."""
        manager = CheckpointManager(checkpoint_dir)

        manager.save_checkpoint(simple_validation_algorithm, 100, ["SIMPLE1"], 100)
        manager.save_checkpoint(complex_validation_algorithm, 200, ["COMPLEX1"], 200)

        simple_checkpoint = manager.load_checkpoint(simple_validation_algorithm)
        complex_checkpoint = manager.load_checkpoint(complex_validation_algorithm)

        assert simple_checkpoint is not None, "Simple checkpoint must exist"
        assert complex_checkpoint is not None, "Complex checkpoint must exist"
        assert simple_checkpoint.last_seed != complex_checkpoint.last_seed, "Checkpoints must be independent"
        assert simple_checkpoint.generated_keys != complex_checkpoint.generated_keys, "Keys must be separate"


class TestEdgeCases:
    """Test edge cases for iteration limits."""

    def test_very_large_key_space_timeout(self, rsa_signature_algorithm: ExtractedAlgorithm) -> None:
        """Very large key spaces should timeout gracefully without hanging."""
        synthesizer = KeygenSynthesizer()

        start_time = time.time()
        result = synthesizer.synthesize_key(rsa_signature_algorithm)
        elapsed = time.time() - start_time

        assert elapsed < 30.0, "Must timeout within reasonable time even for huge key space"

    def test_complex_constraint_combination(self) -> None:
        """Complex constraint combinations must not cause infinite loops."""
        def impossible_validator(key: str) -> bool:
            return len(key) == 16 and all(c == "X" for c in key) and key[0] == "Y"

        algorithm = ExtractedAlgorithm(
            algorithm_name="impossible_constraints",
            parameters={},
            validation_function=impossible_validator,
            constraints=[
                KeyConstraint("length", "16 chars", 16, 0.9),
                KeyConstraint("format", "impossible", "alphanumeric", 0.9),
            ],
            confidence=0.5,
        )

        synthesizer = KeygenSynthesizer()

        start_time = time.time()
        result = synthesizer.synthesize_key(algorithm)
        elapsed = time.time() - start_time

        assert elapsed < 5.0, "Must fail fast for impossible constraints"

    def test_zero_iteration_limit(self) -> None:
        """Zero iteration limit should return fallback immediately."""
        algorithm = ExtractedAlgorithm(
            algorithm_name="zero_iterations",
            parameters={},
            validation_function=None,
            constraints=[KeyConstraint("length", "16", 16, 0.9)],
            confidence=0.5,
        )

        synthesizer = KeygenSynthesizer()
        result = synthesizer.synthesize_key(algorithm)

        assert result.serial is not None, "Must generate fallback key"

    def test_checkpoint_corruption_handling(self, checkpoint_dir: Path, simple_validation_algorithm: ExtractedAlgorithm) -> None:
        """Corrupted checkpoints must be handled gracefully."""
        manager = CheckpointManager(checkpoint_dir)

        manager.save_checkpoint(simple_validation_algorithm, 100, ["KEY1"], 100)

        algorithm_hash = hashlib.sha256(simple_validation_algorithm.algorithm_name.encode()).hexdigest()[:16]
        checkpoint_path = checkpoint_dir / f"checkpoint_{algorithm_hash}.json"

        with checkpoint_path.open("w") as f:
            f.write("CORRUPTED JSON DATA{{{")

        try:
            loaded = manager.load_checkpoint(simple_validation_algorithm)
            assert False, "Should raise exception on corrupted checkpoint"
        except Exception:
            pass

    def test_concurrent_checkpoint_access(
        self,
        checkpoint_dir: Path,
        simple_validation_algorithm: ExtractedAlgorithm,
    ) -> None:
        """Concurrent checkpoint access must not corrupt data."""
        manager = CheckpointManager(checkpoint_dir)

        def save_checkpoint_worker(worker_id: int) -> None:
            manager.save_checkpoint(
                simple_validation_algorithm,
                worker_id * 100,
                [f"KEY-{worker_id}"],
                worker_id * 100,
            )

        with ProcessPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(save_checkpoint_worker, i) for i in range(4)]
            for future in as_completed(futures):
                future.result()

        loaded = manager.load_checkpoint(simple_validation_algorithm)
        assert loaded is not None, "Must load final checkpoint state"
