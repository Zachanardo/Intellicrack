"""License key generation and validation analysis."""

import hashlib
import logging
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import z3

from intellicrack.core.serial_generator import (
    GeneratedSerial,
    SerialConstraints,
    SerialFormat,
    SerialNumberGenerator,
)


@dataclass
class KeyConstraint:
    """Represents a constraint on license key generation."""

    constraint_type: str
    description: str
    value: Any
    confidence: float
    source_address: Optional[int] = None
    assembly_context: Optional[str] = None


@dataclass
class ValidationRoutine:
    """Represents a license validation routine found in binary."""

    address: int
    size: int
    instructions: List[Tuple[int, str, str]]
    constraints: List[KeyConstraint] = field(default_factory=list)
    algorithm_type: Optional[str] = None
    confidence: float = 0.0
    entry_points: List[int] = field(default_factory=list)
    xrefs: List[int] = field(default_factory=list)


@dataclass
class ExtractedAlgorithm:
    """Represents an extracted license validation algorithm."""

    algorithm_name: str
    parameters: Dict[str, Any]
    validation_function: Optional[Callable] = None
    key_format: Optional[SerialFormat] = None
    constraints: List[KeyConstraint] = field(default_factory=list)
    confidence: float = 0.0


class ConstraintExtractor:
    """Extracts license key constraints from binary files."""

    def __init__(self, binary_path: Path):
        """Initialize the validation analyzer.

        Args:
            binary_path: Path to the binary file to analyze

        """
        self.binary_path = Path(binary_path)
        self.extractor = ConstraintExtractor(binary_path)
        self.algorithms: List[ExtractedAlgorithm] = []

    def analyze_validation_algorithms(self) -> List[ExtractedAlgorithm]:
        """Analyze and extract validation algorithms from constraints.

        Returns:
            List of extracted validation algorithms

        """
        constraints = self.extractor.extract_constraints()

        algorithm_types = self._group_constraints_by_algorithm(constraints)

        for algo_type, algo_constraints in algorithm_types.items():
            algorithm = self._build_algorithm(algo_type, algo_constraints)
            if algorithm:
                self.algorithms.append(algorithm)

        if not self.algorithms:
            self.algorithms.append(self._create_generic_algorithm(constraints))

        return self.algorithms

    def _group_constraints_by_algorithm(self, constraints: List[KeyConstraint]) -> Dict[str, List[KeyConstraint]]:
        groups = {}

        for constraint in constraints:
            if constraint.constraint_type == "algorithm":
                algo_name = constraint.value
                if algo_name not in groups:
                    groups[algo_name] = []
                groups[algo_name].append(constraint)

        if "generic" not in groups:
            groups["generic"] = [c for c in constraints if c.constraint_type != "algorithm"]

        return groups

    def _build_algorithm(self, algo_type: str, constraints: List[KeyConstraint]) -> Optional[ExtractedAlgorithm]:
        if algo_type == "crc":
            return self._build_crc_algorithm(constraints)
        elif algo_type in {"md5", "sha1", "sha256"}:
            return self._build_hash_algorithm(algo_type, constraints)
        elif algo_type == "multiplicative_hash":
            return self._build_multiplicative_algorithm(constraints)
        elif algo_type == "modular":
            return self._build_modular_algorithm(constraints)
        else:
            return self._build_generic_algorithm(constraints)

    def _build_crc_algorithm(self, constraints: List[KeyConstraint]) -> ExtractedAlgorithm:
        polynomial = 0xEDB88320

        for constraint in constraints:
            if "CRC32" in str(constraint.value):
                if "reversed" in str(constraint.value):
                    polynomial = 0xEDB88320
                else:
                    polynomial = 0x04C11DB7

        def crc32_validate(key: str) -> int:
            return zlib.crc32(key.encode()) & 0xFFFFFFFF

        return ExtractedAlgorithm(
            algorithm_name="CRC32",
            parameters={"polynomial": polynomial},
            validation_function=crc32_validate,
            key_format=SerialFormat.ALPHANUMERIC,
            constraints=constraints,
            confidence=0.85,
        )

    def _build_hash_algorithm(self, algo_type: str, constraints: List[KeyConstraint]) -> ExtractedAlgorithm:
        hash_functions = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha256": hashlib.sha256,
        }

        hash_func = hash_functions.get(algo_type, hashlib.sha256)

        def hash_validate(key: str) -> str:
            return hash_func(key.encode()).hexdigest()

        return ExtractedAlgorithm(
            algorithm_name=algo_type.upper(),
            parameters={"hash_function": algo_type},
            validation_function=hash_validate,
            key_format=SerialFormat.HEXADECIMAL,
            constraints=constraints,
            confidence=0.9,
        )

    def _build_multiplicative_algorithm(self, constraints: List[KeyConstraint]) -> ExtractedAlgorithm:
        def multiplicative_validate(key: str) -> int:
            result = 0
            multiplier = 31
            for char in key:
                result = result * multiplier + ord(char)
            return result & 0xFFFFFFFF

        return ExtractedAlgorithm(
            algorithm_name="Multiplicative Hash",
            parameters={"multiplier": 31},
            validation_function=multiplicative_validate,
            key_format=SerialFormat.ALPHANUMERIC,
            constraints=constraints,
            confidence=0.75,
        )

    def _build_modular_algorithm(self, constraints: List[KeyConstraint]) -> ExtractedAlgorithm:
        modulus = 97

        def modular_validate(key: str) -> int:
            numeric = "".join(c if c.isdigit() else str(ord(c) - ord("A") + 10) for c in key)
            return int(numeric) % modulus

        return ExtractedAlgorithm(
            algorithm_name="Modular Arithmetic",
            parameters={"modulus": modulus},
            validation_function=modular_validate,
            key_format=SerialFormat.ALPHANUMERIC,
            constraints=constraints,
            confidence=0.7,
        )

    def _build_generic_algorithm(self, constraints: List[KeyConstraint]) -> ExtractedAlgorithm:
        return ExtractedAlgorithm(
            algorithm_name="Generic",
            parameters={},
            validation_function=None,
            key_format=SerialFormat.ALPHANUMERIC,
            constraints=constraints,
            confidence=0.5,
        )

    def _create_generic_algorithm(self, constraints: List[KeyConstraint]) -> ExtractedAlgorithm:
        return self._build_generic_algorithm(constraints)


class KeySynthesizer:
    """Synthesizes license keys based on extracted algorithms."""

    def __init__(self):
        """Initialize the key synthesizer."""
        self.logger = logging.getLogger(__name__)
        self.generator = SerialNumberGenerator()
        self.solver = z3.Solver()

    def synthesize_key(
        self,
        algorithm: ExtractedAlgorithm,
        target_data: Optional[Dict[str, Any]] = None,
    ) -> GeneratedSerial:
        """Synthesize a license key from the extracted algorithm."""
        if algorithm.validation_function:
            return self._synthesize_with_validation(algorithm, target_data)
        else:
            return self._synthesize_from_constraints(algorithm, target_data)

    def _synthesize_with_validation(
        self,
        algorithm: ExtractedAlgorithm,
        target_data: Optional[Dict[str, Any]] = None,
    ) -> GeneratedSerial:
        constraints = self._build_serial_constraints(algorithm)

        if target_data:
            base_seed = hashlib.sha256(str(target_data).encode()).hexdigest()[:16]
            seed_value = int(base_seed, 16)
        else:
            seed_value = 0

        max_attempts = 10000
        for attempt in range(max_attempts):
            deterministic_seed = seed_value + attempt
            candidate = self.generator.generate_serial(constraints, seed=deterministic_seed)

            try:
                if algorithm.validation_function(candidate.serial):
                    candidate.confidence = algorithm.confidence
                    candidate.algorithm = algorithm.algorithm_name
                    return candidate
            except Exception as e:
                self.logger.debug(f"Validation failed for candidate {candidate.serial}: {e}")
                continue

        return self.generator.generate_serial(constraints)

    def _synthesize_from_constraints(
        self,
        algorithm: ExtractedAlgorithm,
        target_data: Optional[Dict[str, Any]] = None,
    ) -> GeneratedSerial:
        constraints = self._build_serial_constraints(algorithm)

        seed = None
        if target_data:
            seed = target_data

        return self.generator.generate_serial(constraints, seed=seed)

    def _build_serial_constraints(self, algorithm: ExtractedAlgorithm) -> SerialConstraints:
        length = 16
        format_type = algorithm.key_format or SerialFormat.ALPHANUMERIC
        groups = 1
        separator = "-"
        checksum_algo = None

        for constraint in algorithm.constraints:
            if constraint.constraint_type == "length":
                length = constraint.value
            elif constraint.constraint_type == "format":
                if "microsoft" in str(constraint.value).lower():
                    format_type = SerialFormat.MICROSOFT
                    length = 25
                    groups = 5
            elif constraint.constraint_type == "separator":
                separator = constraint.value
            elif constraint.constraint_type == "checksum":
                checksum_algo = constraint.value

        return SerialConstraints(
            length=length,
            format=format_type,
            groups=groups,
            group_separator=separator,
            checksum_algorithm=checksum_algo,
        )

    def synthesize_batch(
        self,
        algorithm: ExtractedAlgorithm,
        count: int,
        unique: bool = True,
    ) -> List[GeneratedSerial]:
        """Synthesize a batch of license keys.

        Args:
            algorithm: The algorithm to use for key generation
            count: Number of keys to generate
            unique: Whether keys should be unique

        Returns:
            List of generated serial keys

        """
        keys = []
        generated_set = set()

        for i in range(count):
            target_data = {"index": i} if unique else None

            max_retries = 10
            for retry in range(max_retries):
                key = self.synthesize_key(algorithm, target_data)

                if not unique or key.serial not in generated_set:
                    keys.append(key)
                    generated_set.add(key.serial)
                    break

                target_data = {"index": i, "retry": retry}

        return keys

    def synthesize_for_user(
        self,
        algorithm: ExtractedAlgorithm,
        username: str,
        email: Optional[str] = None,
        hardware_id: Optional[str] = None,
    ) -> GeneratedSerial:
        """Synthesize a license key for a specific user.

        Args:
            algorithm: The algorithm to use for key generation
            username: Username for the license
            email: Optional email address
            hardware_id: Optional hardware identifier

        Returns:
            Generated serial key for the user

        """
        user_data = {"username": username}
        if email:
            user_data["email"] = email
        if hardware_id:
            user_data["hardware_id"] = hardware_id

        key = self.synthesize_key(algorithm, user_data)
        key.hardware_id = hardware_id

        return key

    def synthesize_with_z3(self, constraints: List[KeyConstraint]) -> Optional[str]:
        """Synthesize a key using Z3 constraint solver."""
        self.solver.reset()

        key_length = 16
        for constraint in constraints:
            if constraint.constraint_type == "length":
                key_length = constraint.value
                break

        key_vars = [z3.BitVec(f"k{i}", 8) for i in range(key_length)]

        for constraint in constraints:
            if constraint.constraint_type == "charset":
                charset_type = constraint.value
                if charset_type == "numeric":
                    for var in key_vars:
                        self.solver.add(z3.And(var >= ord("0"), var <= ord("9")))
                elif charset_type == "uppercase":
                    for var in key_vars:
                        self.solver.add(z3.And(var >= ord("A"), var <= ord("Z")))
                elif charset_type == "alphanumeric":
                    for var in key_vars:
                        self.solver.add(
                            z3.Or(
                                z3.And(var >= ord("0"), var <= ord("9")),
                                z3.And(var >= ord("A"), var <= ord("Z")),
                            )
                        )

        if self.solver.check() == z3.sat:
            model = self.solver.model()
            key_chars = []

            for var in key_vars:
                value = model.eval(var)
                if value is not None:
                    key_chars.append(chr(value.as_long()))
                else:
                    key_chars.append("A")

            return "".join(key_chars)

        return None


class LicenseKeygen:
    """Main license key generation engine."""

    def __init__(self, binary_path: Optional[Path] = None):
        """Initialize the license key generator.

        Args:
            binary_path: Optional path to binary file for analysis

        """
        self.binary_path = Path(binary_path) if binary_path else None
        self.extractor = ConstraintExtractor(self.binary_path) if self.binary_path else None
        self.analyzer = ConstraintExtractor(self.binary_path) if self.binary_path else None
        self.synthesizer = KeySynthesizer()
        self.generator = SerialNumberGenerator()

    def crack_license_from_binary(self, count: int = 1) -> List[GeneratedSerial]:
        """Crack license keys from binary analysis."""
        if not self.analyzer:
            raise ValueError("Binary path required for analysis")

        algorithms = self.analyzer.analyze_validation_algorithms()

        if not algorithms:
            raise ValueError("No validation algorithms detected")

        best_algorithm = max(algorithms, key=lambda a: a.confidence)

        return self.synthesizer.synthesize_batch(best_algorithm, count, unique=True)

    def generate_key_from_algorithm(
        self,
        algorithm_name: str,
        **kwargs: Any,
    ) -> GeneratedSerial:
        """Generate a key from a known algorithm."""
        if algorithm_name == "microsoft":
            constraints = SerialConstraints(
                length=25,
                format=SerialFormat.MICROSOFT,
                groups=5,
            )
        elif algorithm_name == "uuid":
            constraints = SerialConstraints(
                length=36,
                format=SerialFormat.UUID,
            )
        elif algorithm_name == "luhn":
            return GeneratedSerial(
                serial=self.generator._generate_luhn_serial(kwargs.get("length", 16)),
                algorithm="luhn",
                confidence=0.9,
            )
        elif algorithm_name == "crc32":
            return GeneratedSerial(
                serial=self.generator._generate_crc32_serial(kwargs.get("length", 16)),
                algorithm="crc32",
                confidence=0.85,
            )
        else:
            constraints = SerialConstraints(
                length=kwargs.get("length", 16),
                format=SerialFormat.ALPHANUMERIC,
                groups=kwargs.get("groups", 4),
            )

        return self.generator.generate_serial(constraints)

    def generate_volume_license(
        self,
        product_id: str,
        count: int = 100,
    ) -> List[GeneratedSerial]:
        """Generate volume license keys."""
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        licenses = []
        for i in range(count):
            license_key = self.generator.generate_rsa_signed(
                private_key,
                product_id,
                f"Volume-{i:04d}",
                features=["enterprise", "unlimited", "support"],
            )
            licenses.append(license_key)

        return licenses

    def generate_hardware_locked_key(
        self,
        hardware_id: str,
        product_id: str,
    ) -> GeneratedSerial:
        """Generate a hardware-locked license key."""
        combined_data = f"{product_id}:{hardware_id}".encode()
        hash_result = hashlib.sha256(combined_data).hexdigest()

        key_base = hash_result[:20].upper()
        formatted = "-".join(key_base[i : i + 5] for i in range(0, 20, 5))

        checksum = self.generator._calculate_crc16(formatted)
        final_key = f"{formatted}-{checksum}"

        return GeneratedSerial(
            serial=final_key,
            hardware_id=hardware_id,
            algorithm="hardware_locked",
            confidence=0.95,
        )

    def generate_time_limited_key(
        self,
        product_id: str,
        days_valid: int = 30,
    ) -> GeneratedSerial:
        """Generate a time-limited license key."""
        import secrets

        secret_key = secrets.token_bytes(32)

        return self.generator.generate_time_based(
            secret_key,
            validity_days=days_valid,
            product_id=product_id,
        )

    def generate_feature_key(
        self,
        base_product: str,
        features: List[str],
    ) -> GeneratedSerial:
        """Generate a feature-encoded license key."""
        base_serial = self.generate_key_from_algorithm("alphanumeric", length=16, groups=4).serial

        return self.generator.generate_feature_encoded(
            base_serial,
            features,
        )

    def brute_force_key(
        self,
        partial_key: str,
        missing_positions: List[int],
        validation_func: Callable[[str], bool],
        charset: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    ) -> Optional[str]:
        """Brute force a partial license key."""
        import itertools

        key_list = list(partial_key)
        max_combinations = len(charset) ** len(missing_positions)

        if max_combinations > 1000000:
            return None

        for combination in itertools.product(charset, repeat=len(missing_positions)):
            for i, pos in enumerate(missing_positions):
                key_list[pos] = combination[i]

            candidate = "".join(key_list)

            if validation_func(candidate):
                return candidate

        return None

    def reverse_engineer_keygen(
        self,
        valid_keys: List[str],
        invalid_keys: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Reverse engineer key generation algorithm."""
        return self.generator.reverse_engineer_algorithm(
            valid_keys,
            invalid_keys,
        )
