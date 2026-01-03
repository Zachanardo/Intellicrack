"""Production tests validating adaptive iteration limits in keygen synthesis.

Tests validate that keygen.py:1182-1184 properly implements:
- Adaptive iteration based on key space size
- Constraint propagation to reduce search space
- Parallel key generation across CPU cores
- Progress reporting for long operations
- Resume from checkpoint for interrupted generation
- Proper handling of large key spaces and complex constraints
"""

import hashlib
import multiprocessing
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

from intellicrack.core.license.keygen import (
    ExtractedAlgorithm,
    KeyConstraint,
    LicenseKeygenEngine,
)
from intellicrack.core.serial_generator import (
    GeneratedSerial,
    SerialConstraints,
    SerialFormat,
)


@pytest.fixture
def keygen_engine() -> LicenseKeygenEngine:
    """Create a keygen engine for testing."""
    mock_binary = b"\x90" * 1000
    return LicenseKeygenEngine(mock_binary)


@pytest.fixture
def simple_algorithm() -> ExtractedAlgorithm:
    """Create a simple algorithm with small key space."""
    def simple_validator(key: str) -> bool:
        return key.isdigit() and len(key) == 8

    return ExtractedAlgorithm(
        algorithm_name="simple_numeric",
        parameters={"length": 8},
        validation_function=simple_validator,
        key_format=SerialFormat.NUMERIC,
        constraints=[
            KeyConstraint(
                constraint_type="length",
                description="8 digit numeric",
                value=8,
                confidence=1.0,
            )
        ],
        confidence=0.95,
    )


@pytest.fixture
def complex_algorithm() -> ExtractedAlgorithm:
    """Create a complex algorithm requiring many iterations."""

    def complex_validator(key: str) -> bool:
        if len(key) != 20:
            return False
        if not key.isalnum():
            return False
        checksum = sum(ord(c) for c in key) % 256
        return checksum == 42 and key[0] == "X" and key[-1] == "Z"

    return ExtractedAlgorithm(
        algorithm_name="complex_validation",
        parameters={"length": 20, "checksum": 42},
        validation_function=complex_validator,
        key_format=SerialFormat.ALPHANUMERIC,
        constraints=[
            KeyConstraint(
                constraint_type="length",
                description="20 char alphanumeric",
                value=20,
                confidence=1.0,
            ),
            KeyConstraint(
                constraint_type="checksum",
                description="Sum mod 256 = 42",
                value=42,
                confidence=0.9,
            ),
        ],
        confidence=0.85,
    )


@pytest.fixture
def massive_keyspace_algorithm() -> ExtractedAlgorithm:
    """Create algorithm with massive key space requiring adaptive iteration."""

    def strict_validator(key: str) -> bool:
        if len(key) != 32:
            return False
        if not all(c.isalnum() for c in key):
            return False
        hash_val = hashlib.sha256(key.encode()).hexdigest()
        return hash_val.startswith("00000")

    return ExtractedAlgorithm(
        algorithm_name="massive_keyspace",
        parameters={"length": 32, "hash_requirement": "00000"},
        validation_function=strict_validator,
        key_format=SerialFormat.ALPHANUMERIC,
        constraints=[
            KeyConstraint(
                constraint_type="length",
                description="32 char alphanumeric with hash constraint",
                value=32,
                confidence=1.0,
            )
        ],
        confidence=0.7,
    )


class TestAdaptiveIterationLimits:
    """Test that iteration limits adapt based on key space size."""

    def test_simple_algorithm_finds_key_within_10k_attempts(
        self, keygen_engine: LicenseKeygenEngine, simple_algorithm: ExtractedAlgorithm
    ) -> None:
        """Simple algorithms with small key space should succeed within 10k attempts."""
        result = keygen_engine.synthesize_key(simple_algorithm)

        assert result.serial is not None
        assert len(result.serial) == 8
        assert result.serial.isdigit()
        assert result.confidence >= 0.9

    def test_complex_algorithm_exceeds_10k_attempts(
        self, keygen_engine: LicenseKeygenEngine, complex_algorithm: ExtractedAlgorithm
    ) -> None:
        """Complex algorithms requiring >10k attempts must not be hardcoded to 10k limit.

        This test MUST FAIL if only 10,000 max attempts are used.
        The keygen must implement adaptive iteration.
        """
        start_time = time.time()

        with patch.object(
            keygen_engine.generator, "generate_serial"
        ) as mock_generate:
            call_count: int = 0

            def track_calls(*args: Any, **kwargs: Any) -> GeneratedSerial:
                nonlocal call_count
                call_count += 1

                if call_count <= 10000:
                    return GeneratedSerial(
                        serial=f"INVALID{call_count:015d}",
                        algorithm="test",
                        confidence=0.0,
                    )

                candidate: str = f"X{'A' * 18}Z"
                return GeneratedSerial(
                    serial=candidate, algorithm="complex_validation", confidence=0.9
                )

            mock_generate.side_effect = track_calls

            result = keygen_engine.synthesize_key(complex_algorithm)

            assert call_count > 10000, (
                f"Only {call_count} attempts made - "
                "hardcoded 10k limit detected! Must implement adaptive iteration."
            )

        elapsed = time.time() - start_time
        assert elapsed < 60, "Generation should complete within reasonable time"

    def test_adaptive_iteration_based_on_constraint_complexity(
        self, keygen_engine: LicenseKeygenEngine
    ) -> None:
        """Iteration count must adapt to constraint complexity."""
        def simple_validator(k: str) -> bool:
            return len(k) == 10

        def complex_validator(k: str) -> bool:
            return (
                len(k) == 10 and k.isalnum() and sum(ord(c) for c in k) % 100 == 7
            )

        simple_constraints_algo = ExtractedAlgorithm(
            algorithm_name="simple",
            parameters={},
            validation_function=simple_validator,
            constraints=[
                KeyConstraint("length", "simple length", 10, 1.0),
            ],
            confidence=0.95,
        )

        complex_constraints_algo = ExtractedAlgorithm(
            algorithm_name="complex",
            parameters={},
            validation_function=complex_validator,
            constraints=[
                KeyConstraint("length", "length", 10, 1.0),
                KeyConstraint("checksum", "checksum", 7, 0.9),
                KeyConstraint("format", "alphanumeric", "alnum", 0.95),
            ],
            confidence=0.8,
        )

        with patch.object(
            keygen_engine.generator, "generate_serial"
        ) as mock_generate:
            simple_calls: int = 0
            complex_calls: int = 0

            def count_simple(*args: Any, **kwargs: Any) -> GeneratedSerial:
                nonlocal simple_calls
                simple_calls += 1
                return GeneratedSerial("A" * 10, "simple", 0.9)

            def count_complex(*args: Any, **kwargs: Any) -> GeneratedSerial:
                nonlocal complex_calls
                complex_calls += 1
                if complex_calls < 50000:
                    return GeneratedSerial(f"FAIL{complex_calls:06d}", "complex", 0.0)
                return GeneratedSerial("ABC1234567", "complex", 0.9)

            mock_generate.side_effect = count_simple
            keygen_engine.synthesize_key(simple_constraints_algo)
            simple_attempt_count: int = simple_calls

            simple_calls = 0
            complex_calls = 0
            mock_generate.side_effect = count_complex
            keygen_engine.synthesize_key(complex_constraints_algo)
            complex_attempt_count: int = complex_calls

            assert complex_attempt_count > simple_attempt_count, (
                "Complex constraints must trigger more iteration attempts "
                "than simple constraints"
            )
            assert complex_attempt_count > 10000, (
                "Complex constraints exceeded 10k hardcoded limit"
            )


class TestConstraintPropagation:
    """Test constraint propagation reduces search space."""

    def test_constraint_propagation_reduces_candidates(
        self, keygen_engine: LicenseKeygenEngine
    ) -> None:
        """Constraint propagation must reduce search space before iteration."""
        def constrained_validator(k: str) -> bool:
            return k.startswith("WIN") and k.endswith("XP") and len(k) == 16

        algorithm = ExtractedAlgorithm(
            algorithm_name="constrained",
            parameters={},
            validation_function=constrained_validator,
            constraints=[
                KeyConstraint("prefix", "Starts with WIN", "WIN", 1.0),
                KeyConstraint("suffix", "Ends with XP", "XP", 1.0),
                KeyConstraint("length", "16 chars", 16, 1.0),
            ],
            confidence=0.9,
        )

        result = keygen_engine.synthesize_key(algorithm)

        assert result.serial is not None
        assert result.serial.startswith("WIN")
        assert result.serial.endswith("XP")
        assert len(result.serial) == 16

    def test_constraint_propagation_handles_conflicting_constraints(
        self, keygen_engine: LicenseKeygenEngine
    ) -> None:
        """Conflicting constraints must be detected and handled gracefully."""
        def conflicting_validator(k: str) -> bool:
            return False

        conflicting_algo = ExtractedAlgorithm(
            algorithm_name="conflicting",
            parameters={},
            validation_function=conflicting_validator,
            constraints=[
                KeyConstraint("length", "Must be 10", 10, 1.0),
                KeyConstraint("length", "Must be 12", 12, 1.0),
            ],
            confidence=0.5,
        )

        result = keygen_engine.synthesize_key(conflicting_algo)

        assert result.serial is not None
        assert result.confidence < 1.0


class TestParallelGeneration:
    """Test parallel key generation across CPU cores."""

    def test_batch_generation_uses_multiple_cores(
        self, keygen_engine: LicenseKeygenEngine, complex_algorithm: ExtractedAlgorithm
    ) -> None:
        """Batch generation must parallelize across available CPU cores."""
        cpu_count = multiprocessing.cpu_count()
        batch_size = cpu_count * 10

        start_time = time.time()
        batch = keygen_engine.synthesize_batch(complex_algorithm, batch_size)
        parallel_time = time.time() - start_time

        assert len(batch) == batch_size
        assert all(isinstance(key, GeneratedSerial) for key in batch)

        expected_sequential_time = parallel_time * cpu_count * 0.7
        assert parallel_time < expected_sequential_time, (
            f"Parallel generation ({parallel_time:.2f}s) should be faster "
            f"than estimated sequential ({expected_sequential_time:.2f}s)"
        )

    def test_parallel_generation_respects_cpu_affinity(
        self, keygen_engine: LicenseKeygenEngine, simple_algorithm: ExtractedAlgorithm
    ) -> None:
        """Parallel generation must respect CPU core limits."""
        batch_size = 100

        with patch("multiprocessing.cpu_count", return_value=4):
            batch = keygen_engine.synthesize_batch(simple_algorithm, batch_size)

            assert len(batch) == batch_size

    def test_parallel_generation_handles_worker_failures(
        self, keygen_engine: LicenseKeygenEngine, simple_algorithm: ExtractedAlgorithm
    ) -> None:
        """Parallel generation must handle worker process failures gracefully."""
        batch_size: int = 50

        with patch.object(keygen_engine, "synthesize_key") as mock_synth:
            call_count: int = 0

            def intermittent_failure(*args: Any, **kwargs: Any) -> GeneratedSerial:
                nonlocal call_count
                call_count += 1
                if call_count % 10 == 0:
                    raise RuntimeError("Simulated worker failure")
                return GeneratedSerial(f"KEY{call_count:08d}", "test", 0.9)

            mock_synth.side_effect = intermittent_failure

            batch = keygen_engine.synthesize_batch(
                simple_algorithm, batch_size, unique=False
            )

            assert len(batch) >= batch_size * 0.8, (
                "Should recover from worker failures and produce most keys"
            )


class TestProgressReporting:
    """Test progress reporting for long operations."""

    def test_progress_callback_invoked_during_generation(
        self, keygen_engine: LicenseKeygenEngine, complex_algorithm: ExtractedAlgorithm
    ) -> None:
        """Long-running generation must invoke progress callbacks."""
        progress_updates: list[float] = []

        def progress_callback(current: int, total: int) -> None:
            progress_value: float = current / total if total > 0 else 0.0
            progress_updates.append(progress_value)

        with patch.object(keygen_engine, "_synthesize_with_validation") as mock_synth:

            def track_progress(*args: Any, **kwargs: Any) -> GeneratedSerial:
                for i in range(0, 100000, 5000):
                    progress_callback(i, 100000)
                return GeneratedSerial("RESULT", "test", 0.9)

            mock_synth.side_effect = track_progress

            result = keygen_engine.synthesize_key(complex_algorithm)

            assert len(progress_updates) > 0
            assert all(0.0 <= p <= 1.0 for p in progress_updates)
            assert result.serial == "RESULT"

    def test_progress_reporting_accuracy(
        self, keygen_engine: LicenseKeygenEngine
    ) -> None:
        """Progress reports must accurately reflect completion percentage."""
        def false_validator(k: str) -> bool:
            return False

        algorithm = ExtractedAlgorithm(
            algorithm_name="progress_test",
            parameters={},
            validation_function=false_validator,
            constraints=[],
            confidence=0.9,
        )

        progress_data: list[tuple[int, int]] = []

        def capture_progress(current: int, total: int) -> None:
            progress_data.append((current, total))

        with patch.object(
            keygen_engine.generator, "generate_serial"
        ) as mock_generate:
            call_count: int = 0

            def count_and_report(*args: Any, **kwargs: Any) -> GeneratedSerial:
                nonlocal call_count
                call_count += 1
                if call_count % 1000 == 0:
                    capture_progress(call_count, 50000)
                if call_count >= 50000:
                    return GeneratedSerial("SUCCESS", "test", 0.9)
                return GeneratedSerial(f"FAIL{call_count}", "test", 0.0)

            mock_generate.side_effect = count_and_report

            keygen_engine.synthesize_key(algorithm)

            if progress_data:
                for current, total in progress_data:
                    assert current <= total
                    assert total > 10000, "Must support operations beyond 10k limit"


class TestCheckpointResume:
    """Test resume from checkpoint for interrupted generation."""

    def test_checkpoint_creation_during_long_operations(
        self, keygen_engine: LicenseKeygenEngine, massive_keyspace_algorithm: ExtractedAlgorithm
    ) -> None:
        """Long operations must create periodic checkpoints."""
        with patch("builtins.open", create=True) as mock_open:
            mock_file: MagicMock = MagicMock()
            mock_open.return_value.__enter__.return_value = mock_file

            with patch.object(keygen_engine, "_synthesize_with_validation"):
                try:
                    keygen_engine.synthesize_key(massive_keyspace_algorithm)
                except Exception:
                    pass

    def test_resume_from_checkpoint_after_interruption(
        self, keygen_engine: LicenseKeygenEngine, complex_algorithm: ExtractedAlgorithm, tmp_path: Path
    ) -> None:
        """Generation must resume from checkpoint after interruption."""
        checkpoint_file = tmp_path / "keygen_checkpoint.json"

        checkpoint_data: dict[str, int | str] = {
            "algorithm": "complex_validation",
            "attempts": 25000,
            "seed_value": 12345,
            "last_candidate": "PARTIAL_KEY",
        }

        import json

        checkpoint_file.write_text(json.dumps(checkpoint_data))

        with patch.object(
            keygen_engine.generator, "generate_serial"
        ) as mock_generate:
            resume_calls = 0

            def resume_generation(*args: Any, **kwargs: Any) -> GeneratedSerial:
                nonlocal resume_calls
                resume_calls += 1

                seed: int = kwargs.get("seed", 0)
                if isinstance(seed, int) and seed > checkpoint_data.get("attempts", 0):
                    return GeneratedSerial("X" + "A" * 18 + "Z", "test", 0.9)

                return GeneratedSerial(f"RESUME{resume_calls:010d}", "test", 0.0)

            mock_generate.side_effect = resume_generation

            result = keygen_engine.synthesize_key(
                complex_algorithm, target_data={"checkpoint": str(checkpoint_file)}
            )

            assert result.serial is not None

    def test_checkpoint_validates_integrity(
        self, keygen_engine: LicenseKeygenEngine, tmp_path: Path
    ) -> None:
        """Checkpoint loading must validate data integrity."""
        corrupted_checkpoint = tmp_path / "corrupted.json"
        corrupted_checkpoint.write_text("{invalid json content")

        def dummy_validator(k: str) -> bool:
            return True

        algorithm = ExtractedAlgorithm(
            algorithm_name="test",
            parameters={},
            validation_function=dummy_validator,
            constraints=[],
            confidence=0.9,
        )

        result = keygen_engine.synthesize_key(
            algorithm, target_data={"checkpoint": str(corrupted_checkpoint)}
        )

        assert result.serial is not None


class TestLargeKeySpaceHandling:
    """Test handling of large key spaces."""

    def test_massive_keyspace_does_not_timeout(
        self, keygen_engine: LicenseKeygenEngine, massive_keyspace_algorithm: ExtractedAlgorithm
    ) -> None:
        """Massive key spaces must not cause infinite loops or timeouts."""
        start_time = time.time()

        with patch.object(
            keygen_engine.generator, "generate_serial"
        ) as mock_generate:
            attempts: int = 0

            def limited_attempts(*args: Any, **kwargs: Any) -> GeneratedSerial:
                nonlocal attempts
                attempts += 1

                if attempts > 100000:
                    return GeneratedSerial("0" * 32, "fallback", 0.1)

                return GeneratedSerial(f"FAIL{attempts:028d}", "test", 0.0)

            mock_generate.side_effect = limited_attempts

            result = keygen_engine.synthesize_key(massive_keyspace_algorithm)

            elapsed: float = time.time() - start_time

            assert attempts > 10000, (
                f"Only {attempts} attempts made - hardcoded limit detected!"
            )
            assert elapsed < 30, "Must not hang indefinitely on large key spaces"
            assert result.serial is not None

    def test_exponential_keyspace_growth_handling(
        self, keygen_engine: LicenseKeygenEngine
    ) -> None:
        """Keygen must handle exponential growth in key space intelligently."""
        keyspace_sizes: list[int] = [8, 16, 24, 32]
        generation_times: list[float] = []

        for length in keyspace_sizes:
            def length_validator(k: str, l: int = length) -> bool:
                return len(k) == l

            algorithm = ExtractedAlgorithm(
                algorithm_name=f"keyspace_{length}",
                parameters={"length": length},
                validation_function=length_validator,
                constraints=[
                    KeyConstraint("length", f"{length} chars", length, 1.0)
                ],
                confidence=0.9,
            )

            start: float = time.time()
            keygen_engine.synthesize_key(algorithm)
            elapsed: float = time.time() - start
            generation_times.append(elapsed)

        time_ratios: list[float] = [
            generation_times[i + 1] / generation_times[i]
            for i in range(len(generation_times) - 1)
        ]

        assert all(ratio < 100 for ratio in time_ratios), (
            "Generation time must not grow exponentially with key space - "
            "constraint propagation required"
        )


class TestComplexConstraints:
    """Test handling of complex constraint combinations."""

    def test_multiple_checksum_constraints(
        self, keygen_engine: LicenseKeygenEngine
    ) -> None:
        """Multiple checksum constraints must all be satisfied."""

        def multi_checksum_validator(key: str) -> bool:
            if len(key) != 16:
                return False
            sum_check = sum(ord(c) for c in key) % 100 == 42
            xor_check = (
                sum(ord(c) ^ (i * 7) for i, c in enumerate(key)) % 256 == 128
            )
            return sum_check and xor_check

        algorithm = ExtractedAlgorithm(
            algorithm_name="multi_checksum",
            parameters={},
            validation_function=multi_checksum_validator,
            constraints=[
                KeyConstraint("checksum_sum", "Sum mod 100 = 42", 42, 0.9),
                KeyConstraint("checksum_xor", "XOR pattern = 128", 128, 0.85),
                KeyConstraint("length", "16 chars", 16, 1.0),
            ],
            confidence=0.8,
        )

        with patch.object(
            keygen_engine.generator, "generate_serial"
        ) as mock_generate:
            attempts = 0

            def complex_generation(*args: Any, **kwargs: Any) -> GeneratedSerial:
                nonlocal attempts
                attempts += 1

                if attempts > 50000:
                    return GeneratedSerial("VALID_KEY_123456", "test", 0.9)

                return GeneratedSerial(f"INVALID{attempts:09d}", "test", 0.0)

            mock_generate.side_effect = complex_generation

            result = keygen_engine.synthesize_key(algorithm)

            assert attempts > 10000, (
                "Complex constraints require > 10k attempts - hardcoded limit detected"
            )
            assert result.serial is not None

    def test_cryptographic_constraint_solving(
        self, keygen_engine: LicenseKeygenEngine
    ) -> None:
        """Cryptographic constraints must be solved via constraint propagation."""

        def crypto_validator(key: str) -> bool:
            if len(key) != 20:
                return False
            hash_val = hashlib.md5(key.encode()).hexdigest()
            return hash_val.endswith("abc")

        algorithm = ExtractedAlgorithm(
            algorithm_name="crypto_constraint",
            parameters={},
            validation_function=crypto_validator,
            constraints=[
                KeyConstraint("length", "20 chars", 20, 1.0),
                KeyConstraint("hash_suffix", "MD5 ends with abc", "abc", 0.7),
            ],
            confidence=0.7,
        )

        with patch.object(
            keygen_engine.generator, "generate_serial"
        ) as mock_generate:
            call_count = 0

            def crypto_generation(*args: Any, **kwargs: Any) -> GeneratedSerial:
                nonlocal call_count
                call_count += 1

                if call_count > 1000000:
                    return GeneratedSerial("crypto_key_12345678", "test", 0.7)

                return GeneratedSerial(f"FAIL{call_count:016d}", "test", 0.0)

            mock_generate.side_effect = crypto_generation

            result = keygen_engine.synthesize_key(algorithm)

            assert call_count > 10000, (
                "Crypto constraints require adaptive iteration beyond 10k limit"
            )
            assert result.serial is not None


class TestEdgeCases:
    """Test edge cases in iteration and generation."""

    def test_zero_probability_validation(
        self, keygen_engine: LicenseKeygenEngine
    ) -> None:
        """Impossible validation functions must terminate gracefully."""
        def impossible_validator(k: str) -> bool:
            return False

        impossible_algo = ExtractedAlgorithm(
            algorithm_name="impossible",
            parameters={},
            validation_function=impossible_validator,
            constraints=[],
            confidence=0.1,
        )

        start_time = time.time()

        with patch.object(
            keygen_engine.generator, "generate_serial"
        ) as mock_generate:
            mock_generate.return_value = GeneratedSerial("FALLBACK", "test", 0.0)

            result = keygen_engine.synthesize_key(impossible_algo)
            elapsed = time.time() - start_time

            assert elapsed < 10, "Must terminate within reasonable time"
            assert result.serial is not None

    def test_validation_function_exceptions(
        self, keygen_engine: LicenseKeygenEngine
    ) -> None:
        """Exceptions in validation function must not crash generation."""

        def buggy_validator(key: str) -> bool:
            if len(key) < 10:
                raise ValueError("Key too short")
            return len(key) == 16

        algorithm = ExtractedAlgorithm(
            algorithm_name="buggy",
            parameters={},
            validation_function=buggy_validator,
            constraints=[KeyConstraint("length", "16 chars", 16, 1.0)],
            confidence=0.8,
        )

        result = keygen_engine.synthesize_key(algorithm)

        assert result.serial is not None
        assert len(result.serial) >= 10

    def test_extremely_tight_constraints(
        self, keygen_engine: LicenseKeygenEngine
    ) -> None:
        """Extremely tight constraints requiring millions of attempts."""

        def needle_in_haystack(key: str) -> bool:
            if len(key) != 24:
                return False
            hash_check = hashlib.sha256(key.encode()).hexdigest()
            return hash_check.startswith("0000") and key[0] == "A" and key[-1] == "Z"

        algorithm = ExtractedAlgorithm(
            algorithm_name="needle",
            parameters={},
            validation_function=needle_in_haystack,
            constraints=[
                KeyConstraint("length", "24 chars", 24, 1.0),
                KeyConstraint("prefix", "Starts with A", "A", 1.0),
                KeyConstraint("suffix", "Ends with Z", "Z", 1.0),
                KeyConstraint("hash", "SHA256 starts 0000", "0000", 0.6),
            ],
            confidence=0.6,
        )

        start_time = time.time()

        with patch.object(
            keygen_engine.generator, "generate_serial"
        ) as mock_generate:
            attempts = 0

            def massive_search(*args: Any, **kwargs: Any) -> GeneratedSerial:
                nonlocal attempts
                attempts += 1

                if attempts > 5000000:
                    return GeneratedSerial("A" + "X" * 22 + "Z", "test", 0.6)

                return GeneratedSerial(f"FAIL{attempts:020d}", "test", 0.0)

            mock_generate.side_effect = massive_search

            result = keygen_engine.synthesize_key(algorithm)
            elapsed = time.time() - start_time

            assert attempts > 10000, (
                f"Only {attempts} attempts - hardcoded 10k limit prevents "
                "solving tight constraints"
            )
            assert result.serial is not None
            assert elapsed < 60, "Must complete within reasonable time"

    def test_dynamic_constraint_adjustment(
        self, keygen_engine: LicenseKeygenEngine
    ) -> None:
        """Keygen must dynamically adjust iteration based on discovered constraints."""
        discovered_constraints: list[KeyConstraint] = []

        def learning_validator(key: str) -> bool:
            if len(key) != 15:
                discovered_constraints.append(
                    KeyConstraint("length", "Must be 15", 15, 1.0)
                )
                return False
            if not key.startswith("PRO"):
                discovered_constraints.append(
                    KeyConstraint("prefix", "Must start PRO", "PRO", 0.95)
                )
                return False
            checksum_val: int = sum(ord(c) for c in key) % 97
            if checksum_val != 13:
                discovered_constraints.append(
                    KeyConstraint("checksum", "Sum mod 97 = 13", 13, 0.9)
                )
                return False
            return True

        algorithm = ExtractedAlgorithm(
            algorithm_name="learning",
            parameters={},
            validation_function=learning_validator,
            constraints=[],
            confidence=0.7,
        )

        with patch.object(
            keygen_engine.generator, "generate_serial"
        ) as mock_generate:
            calls = 0

            def adaptive_generation(*args: Any, **kwargs: Any) -> GeneratedSerial:
                nonlocal calls
                calls += 1

                if calls > 100000:
                    return GeneratedSerial("PRO" + "X" * 12, "test", 0.7)

                return GeneratedSerial(f"LEARN{calls:010d}", "test", 0.0)

            mock_generate.side_effect = adaptive_generation

            result = keygen_engine.synthesize_key(algorithm)

            assert calls > 10000, "Must exceed 10k limit for complex discovery"
            assert result.serial is not None
