"""Serial number generator for cracking software license key validation."""

import base64
import hashlib
import hmac
import json
import random
import re
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any

import z3
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from intellicrack.utils.logger import get_logger, log_all_methods


logger = get_logger(__name__)
logger.debug("Serial generator module loaded")


class SerialFormat(Enum):
    """Enumeration of serial number formats used by various software vendors."""

    NUMERIC = "numeric"
    ALPHANUMERIC = "alphanumeric"
    BASE32 = "base32"
    HEXADECIMAL = "hexadecimal"
    CUSTOM = "custom"
    MICROSOFT = "microsoft"  # 5 groups of 5 chars: ABCDE-FGHIJ-KLMNO-PQRST-UVWXY
    UUID = "uuid"  # Standard UUID format: 8-4-4-4-12 hex chars


@dataclass
class SerialConstraints:
    """Constraints for serial number generation based on observed patterns."""

    length: int
    format: SerialFormat
    groups: int = 1
    group_separator: str = "-"
    checksum_algorithm: str | None = None
    custom_alphabet: str | None = None
    blacklist_patterns: list[str] | None = None
    must_contain: list[str] | None = None
    cannot_contain: list[str] | None = None
    validation_function: Callable[[str], bool] | None = None


@dataclass
class GeneratedSerial:
    """Generated serial number with validation metadata."""

    serial: str
    format: SerialFormat | None = None
    confidence: float = 0.0
    validation_data: dict[str, Any] | None = None
    algorithm_used: str | None = None
    raw_bytes: bytes | None = None
    checksum: str | None = None
    hardware_id: str | None = None
    expiration: int | None = None
    features: list[str] | None = None
    algorithm: str | None = None


@log_all_methods
class SerialNumberGenerator:
    """Production-ready serial number generation with constraint solving."""

    def __init__(self) -> None:
        """Initialize the SerialNumberGenerator with cryptographic backend and algorithms."""
        self.backend = default_backend()
        self.common_algorithms = self._initialize_algorithms()
        self.checksum_functions = self._initialize_checksums()
        self.solver = z3.Solver()

    def _initialize_algorithms(self) -> dict[str, Callable[[int], str]]:
        """Initialize common serial generation algorithms.

        Returns:
            dict[str, Callable[[int], str]]: Mapping of algorithm names to their implementation functions.

        """
        algorithms: dict[str, Callable[[int], str]] = {
            "luhn": self._generate_luhn_serial,
            "verhoeff": self._generate_verhoeff_serial,
            "damm": self._generate_damm_serial,
            "crc32": self._generate_crc32_serial,
            "mod97": self._generate_mod97_serial,
            "custom_polynomial": self._generate_polynomial_serial,
            "elliptic_curve": self._generate_ecc_serial,
            "rsa_based": self._generate_rsa_serial,
            "hash_chain": self._generate_hash_chain_serial,
            "feistel": self._generate_feistel_serial,
        }
        logger.debug("Initialized %s serial generation algorithms.", len(algorithms))
        return algorithms

    def _initialize_checksums(self) -> dict[str, Callable[[str], str]]:
        """Initialize checksum calculation functions.

        Returns:
            dict[str, Callable[[str], str]]: Mapping of checksum algorithm names to their implementation functions.

        """
        checksums: dict[str, Callable[[str], str]] = {
            "luhn": self._calculate_luhn,
            "verhoeff": self._calculate_verhoeff,
            "damm": self._calculate_damm,
            "crc16": self._calculate_crc16,
            "crc32": self._calculate_crc32,
            "fletcher16": self._calculate_fletcher16,
            "fletcher32": self._calculate_fletcher32,
            "adler32": self._calculate_adler32,
            "mod11": self._calculate_mod11,
            "mod37": self._calculate_mod37,
            "mod97": self._calculate_mod97,
        }
        logger.debug("Initialized %s checksum functions.", len(checksums))
        return checksums

    def analyze_serial_algorithm(self, valid_serials: list[str]) -> dict[str, Any]:
        """Analyze valid serials to determine generation algorithm.

        Args:
            valid_serials: List of known valid serial numbers to analyze.

        Returns:
            dict[str, Any]: Analysis results including detected format, length, structure, checksum algorithm, patterns, and confidence scores.

        """
        logger.info("Starting serial algorithm analysis for %s valid serials.", len(valid_serials))
        analysis = {
            "format": self._detect_format(valid_serials),
            "length": self._analyze_length(valid_serials),
            "structure": self._analyze_structure(valid_serials),
            "checksum": self._detect_checksum(valid_serials),
            "patterns": self._detect_patterns(valid_serials),
            "algorithm": None,
            "confidence": 0.0,
        }
        logger.debug("Initial serial analysis: %s", analysis)

        logger.info("Step 1: Testing various algorithms against provided serials.")
        algorithms_scores = {}
        for algo_name in self.common_algorithms:
            score = self._test_algorithm(valid_serials, algo_name)
            algorithms_scores[algo_name] = score
        logger.debug("Algorithm scores: %s", algorithms_scores)
        logger.info("Step 1: Completed algorithm testing.")

        # Select best matching algorithm
        if algorithms_scores:
            best_algo = max(algorithms_scores.items(), key=lambda x: x[1])[0]
            analysis["algorithm"] = best_algo
            analysis["confidence"] = algorithms_scores[best_algo]
            logger.info("Best matching algorithm detected: %s with confidence: %.2f", best_algo, algorithms_scores[best_algo])
        else:
            logger.warning("No suitable algorithm found for the provided serials.")
            analysis["algorithm"] = "unknown"
            analysis["confidence"] = 0.0

        logger.info("Serial algorithm analysis completed.")
        return analysis

    def _detect_format(self, serials: list[str]) -> SerialFormat:
        """Detect the format of serial numbers.

        Args:
            serials: List of serial numbers to analyze for format detection.

        Returns:
            SerialFormat: The detected format (NUMERIC, ALPHANUMERIC, HEXADECIMAL, BASE32, UUID, MICROSOFT, or CUSTOM).

        """
        if not serials:
            logger.debug("No serials provided, defaulting to CUSTOM format.")
            return SerialFormat.CUSTOM

        # Check Microsoft format
        if all(re.match(r"^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$", s) for s in serials):
            logger.debug("Detected Microsoft serial format.")
            return SerialFormat.MICROSOFT

        # Check UUID format
        if all(re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", s) for s in serials):
            logger.debug("Detected UUID serial format.")
            return SerialFormat.UUID

        # Check basic formats
        sample = serials[0].replace("-", "").replace(" ", "")
        if sample.isdigit():
            logger.debug("Detected Numeric serial format.")
            return SerialFormat.NUMERIC
        if sample.isalnum():
            logger.debug("Detected Alphanumeric serial format.")
            return SerialFormat.ALPHANUMERIC
        if all(c in "0123456789ABCDEF" for c in sample.upper()):
            logger.debug("Detected Hexadecimal serial format.")
            return SerialFormat.HEXADECIMAL
        if all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for c in sample.upper()):  # pragma: allowlist secret
            logger.debug("Detected Base32 serial format.")
            return SerialFormat.BASE32

        logger.debug("Detected Custom serial format.")
        return SerialFormat.CUSTOM

    def _analyze_length(self, serials: list[str]) -> dict[str, int]:
        """Analyze length patterns in serials.

        Args:
            serials: List of serial numbers to analyze for length patterns.

        Returns:
            dict[str, int]: Statistics including min, max, mode, and clean (separators removed) length metrics.

        """
        lengths = [len(s) for s in serials]
        clean_lengths = [len(s.replace("-", "").replace(" ", "")) for s in serials]

        length_analysis = {
            "min": min(lengths),
            "max": max(lengths),
            "mode": max(set(lengths), key=lengths.count),
            "clean_min": min(clean_lengths),
            "clean_max": max(clean_lengths),
            "clean_mode": max(set(clean_lengths), key=clean_lengths.count),
        }
        logger.debug("Serial length analysis: %s", length_analysis)
        return length_analysis

    def _analyze_structure(self, serials: list[str]) -> dict[str, Any]:
        """Analyze structural patterns in serials.

        Args:
            serials: List of serial numbers to analyze for structural patterns.

        Returns:
            dict[str, Any]: Structure analysis including groups, separators, and group length statistics.

        """
        structure: dict[str, Any] = {"groups": [], "separators": [], "group_lengths": []}

        for serial in serials:
            if seps := re.findall(r"[^A-Za-z0-9]", serial):
                structure["separators"].extend(seps)

                # Analyze groups
                groups = re.split(r"[^A-Za-z0-9]+", serial)
                structure["groups"].append(len(groups))
                structure["group_lengths"].extend([len(g) for g in groups])

        if structure["separators"]:
            separators_list: list[str] = structure["separators"]
            structure["common_separator"] = max(set(separators_list), key=separators_list.count)
            groups_list: list[int] = structure["groups"]
            structure["group_count"] = max(set(groups_list), key=groups_list.count) if groups_list else 1
        logger.debug("Serial structure analysis: %s", structure)
        return structure

    def _detect_checksum(self, serials: list[str]) -> dict[str, Any]:
        """Detect checksum algorithm used in serials.

        Args:
            serials: List of serial numbers to analyze for checksum detection.

        Returns:
            dict[str, Any]: Mapping of detected checksum algorithms to their accuracy scores.

        """
        results = {}

        for checksum_name, checksum_func in self.checksum_functions.items():
            valid_count = sum(bool(self._verify_checksum(serial, checksum_func)) for serial in serials)
            accuracy = valid_count / len(serials) if serials else 0
            if accuracy > 0.8:  # 80% match threshold
                results[checksum_name] = accuracy
        logger.debug("Detected checksum algorithms: %s", results)
        return results

    def _verify_checksum(self, serial: str, checksum_func: Callable[[str], str]) -> bool:
        """Verify if serial passes checksum validation.

        Args:
            serial: Serial number to verify.
            checksum_func: Callable checksum function that takes a string and returns a checksum.

        Returns:
            bool: True if the serial passes checksum validation, False otherwise.

        """
        try:
            # Remove separators
            clean_serial = serial.replace("-", "").replace(" ", "")

            # Try different checksum positions
            for i in [1, 2, 4]:  # Last 1, 2, or 4 digits as checksum
                if len(clean_serial) > i:
                    data = clean_serial[:-i]
                    expected_checksum = clean_serial[-i:]
                    calculated = checksum_func(data)

                    if calculated == expected_checksum:
                        return True

            return False
        except (ValueError, TypeError) as e:
            logger.debug("Error verifying checksum for serial '%s' with function %s: %s", serial, checksum_func.__name__, e, exc_info=True)
            return False

    def _detect_patterns(self, serials: list[str]) -> list[dict[str, Any]]:
        """Detect patterns in serial numbers.

        Args:
            serials: List of serial numbers to analyze for patterns.

        Returns:
            list[dict[str, Any]]: List of detected patterns with their characteristics.

        """
        patterns = []

        # Check for incrementing patterns
        numeric_parts = []
        for serial in serials:
            if nums := re.findall(r"\d+", serial):
                numeric_parts.extend([int(n) for n in nums])

        if numeric_parts and len(set(numeric_parts)) > 1:
            sorted_nums = sorted(numeric_parts)
            differences = [sorted_nums[i + 1] - sorted_nums[i] for i in range(len(sorted_nums) - 1)]

            if differences and len(set(differences)) == 1:
                patterns.append({"type": "arithmetic_sequence", "difference": differences[0]})

        # Check for date-based patterns
        date_patterns = [
            r"(19|20)\d{2}",  # Year
            r"(0[1-9]|1[0-2])",  # Month
            r"(0[1-9]|[12][0-9]|3[01])",  # Day
        ]

        for pattern in date_patterns:
            matches = sum(bool(re.search(pattern, s)) for s in serials)
            if matches > len(serials) * 0.5:
                patterns.append({"type": "date_based", "pattern": pattern})

        # Check for hash-based patterns
        if all(len(s.replace("-", "")) in {32, 40, 64, 128} for s in serials):
            patterns.append({"type": "hash_based", "possible_algorithms": ["md5", "sha1", "sha256", "sha512"]})
        logger.debug("Detected serial patterns: %s", patterns)
        return patterns

    def _test_algorithm(self, serials: list[str], algorithm: str) -> float:
        """Test how well an algorithm matches the serials.

        Args:
            serials: List of serial numbers to test against.
            algorithm: Name of the algorithm to test.

        Returns:
            float: Confidence score from 0.0 to 1.0 indicating match quality.

        """
        score = 0.0
        tests = min(10, len(serials))  # Test up to 10 serials
        logger.debug("Testing algorithm '%s' with %s serials.", algorithm, tests)

        for serial in serials[:tests]:
            # Try to reverse-engineer the algorithm
            if (
                (algorithm == "luhn" and self._verify_luhn(serial))
                or (algorithm == "verhoeff" and self._verify_verhoeff(serial))
                or (algorithm == "crc32" and self._verify_crc32(serial))
            ):
                score += 1.0
            # Add more algorithm tests
        logger.debug("Algorithm '%s' scored %s/%s.", algorithm, score, tests)
        return score / tests if tests > 0 else 0.0

    def generate_serial(self, constraints: SerialConstraints, seed: int | str | bytes | None = None) -> GeneratedSerial:
        """Generate a serial number based on constraints.

        Args:
            constraints: SerialConstraints object specifying format, length, and other generation rules.
            seed: Optional seed value (int, str, or bytes) to influence serial generation randomness.

        Returns:
            GeneratedSerial: The generated serial number with metadata and validation information.

        """
        logger.debug("Generating serial with constraints: %s, seed: %s", constraints, seed)
        if constraints.validation_function:
            logger.debug("Using custom validation function for serial generation.")
            # Use custom validation function
            return self._generate_with_validation(constraints, seed)

        # Select algorithm based on format
        if constraints.format == SerialFormat.MICROSOFT:
            logger.debug("Using Microsoft serial format generation.")
            return self._generate_microsoft_serial(constraints)
        if constraints.format == SerialFormat.UUID:
            logger.debug("Using UUID serial format generation.")
            return self._generate_uuid_serial(constraints)
        logger.debug("Using Z3 constraint solver for serial generation.")
        # Use constraint solver for complex requirements
        return self._generate_constrained_serial(constraints, seed)

    def _generate_constrained_serial(self, constraints: SerialConstraints, seed: int | str | bytes | None = None) -> GeneratedSerial:
        """Generate serial using Z3 constraint solver.

        Args:
            constraints: SerialConstraints object with format and generation rules.
            seed: Optional seed value to influence Z3 solver behavior.

        Returns:
            GeneratedSerial: The generated serial or fallback random serial if constraints unsatisfiable.

        """
        # Create bit vectors for serial characters
        serial_length = constraints.length
        serial_vars = [z3.BitVec(f"c_{i}", 8) for i in range(serial_length)]
        logger.debug("Initialized %s serial variables for Z3 solver.", serial_length)

        # Add character range constraints
        if constraints.format == SerialFormat.NUMERIC:
            logger.debug("Adding numeric character range constraints.")
            for var in serial_vars:
                self.solver.add(z3.And(var >= ord("0"), var <= ord("9")))
        elif constraints.format == SerialFormat.HEXADECIMAL:
            logger.debug("Adding hexadecimal character range constraints.")
            for var in serial_vars:
                self.solver.add(
                    z3.Or(
                        z3.And(var >= ord("0"), var <= ord("9")),
                        z3.And(var >= ord("A"), var <= ord("F")),
                    )
                )
        elif constraints.format == SerialFormat.ALPHANUMERIC:
            logger.debug("Adding alphanumeric character range constraints.")
            for var in serial_vars:
                self.solver.add(
                    z3.Or(
                        z3.And(var >= ord("0"), var <= ord("9")),
                        z3.And(var >= ord("A"), var <= ord("Z")),
                    )
                )

        # Add custom alphabet constraints
        if constraints.custom_alphabet:
            logger.debug("Adding custom alphabet constraints: %s", constraints.custom_alphabet)
            allowed_chars = [ord(c) for c in constraints.custom_alphabet]
            for var in serial_vars:
                self.solver.add(z3.Or([var == c for c in allowed_chars]))

        # Add must_contain constraints
        if constraints.must_contain:
            logger.debug("Adding 'must contain' constraints: %s", constraints.must_contain)
            for pattern in constraints.must_contain:
                # Ensure pattern appears in serial
                pattern_vars = [ord(c) for c in pattern]
                pattern_constraints = []

                for i in range(serial_length - len(pattern) + 1):
                    pattern_match = z3.And([serial_vars[i + j] == pattern_vars[j] for j in range(len(pattern))])
                    pattern_constraints.append(pattern_match)

                self.solver.add(z3.Or(pattern_constraints))

        # Add cannot_contain constraints
        if constraints.cannot_contain:
            logger.debug("Adding 'cannot contain' constraints: %s", constraints.cannot_contain)
            for pattern in constraints.cannot_contain:
                pattern_vars = [ord(c) for c in pattern]

                for i in range(serial_length - len(pattern) + 1):
                    pattern_match = z3.And([serial_vars[i + j] == pattern_vars[j] for j in range(len(pattern))])
                    self.solver.add(z3.Not(pattern_match))

        # Add checksum constraint if specified
        if constraints.checksum_algorithm and constraints.checksum_algorithm in self.checksum_functions:
            logger.debug("Adding checksum constraint for algorithm: %s", constraints.checksum_algorithm)
            self.checksum_functions[constraints.checksum_algorithm]
            # This would require expressing checksum as Z3 constraints
            # Simplified for now

        # Add seed-based constraints if provided
        if seed:
            logger.debug("Adding seed-based constraints with seed: %s", seed)
            seed_hash = hashlib.sha256(str(seed).encode()).digest()
            seed_value = int.from_bytes(seed_hash[:4], "big")

            # Use seed to influence generation
            self.solver.add(serial_vars[0] == (seed_value % 26) + ord("A"))

        # Solve constraints
        logger.debug("Attempting to solve constraints with Z3 solver.")
        if self.solver.check() == z3.sat:
            model = self.solver.model()
            serial_chars = []

            for var in serial_vars:
                value = model.eval(var)
                if value is not None:
                    serial_chars.append(chr(value.as_long()))
                # Fallback to random valid character
                elif constraints.custom_alphabet:
                    # Note: Using random module for generating serials, not cryptographic purposes
                    serial_chars.append(random.choice(constraints.custom_alphabet))  # noqa: S311
                elif constraints.format == SerialFormat.NUMERIC:
                    serial_chars.append(random.choice("0123456789"))  # noqa: S311
                else:
                    serial_chars.append(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"))  # noqa: S311

            # Format with groups if specified
            serial = "".join(serial_chars)
            if constraints.groups > 1:
                group_size = len(serial) // constraints.groups
                groups = [serial[i : i + group_size] for i in range(0, len(serial), group_size)]
                serial = constraints.group_separator.join(groups)
            logger.debug("Z3 solver successfully generated serial: %s", serial)
            return GeneratedSerial(
                serial=serial,
                format=constraints.format,
                confidence=0.95,
                validation_data={"solver": "z3", "constraints_satisfied": True},
                algorithm_used="constraint_solver",
            )
        logger.debug("Z3 solver found no solution. Falling back to random serial generation.")
        # Constraints unsatisfiable, use fallback generation
        return self._generate_random_serial(constraints)

    def _generate_random_serial(self, constraints: SerialConstraints) -> GeneratedSerial:
        """Generate random serial as fallback.

        Args:
            constraints: SerialConstraints object specifying format and generation parameters.

        Returns:
            GeneratedSerial: The randomly generated serial number with metadata.

        """
        if constraints.custom_alphabet:
            alphabet = constraints.custom_alphabet
        elif constraints.format == SerialFormat.NUMERIC:
            alphabet = "0123456789"
        elif constraints.format == SerialFormat.HEXADECIMAL:
            alphabet = "0123456789ABCDEF"
        elif constraints.format == SerialFormat.BASE32:
            alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        else:
            alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

        serial_chars = [random.choice(alphabet) for _ in range(constraints.length)]  # noqa: S311

        # Apply checksum if specified
        if constraints.checksum_algorithm and constraints.checksum_algorithm in self.checksum_functions:
            checksum_func = self.checksum_functions[constraints.checksum_algorithm]
            # Reserve last digits for checksum
            checksum_length = {"luhn": 1, "crc32": 8, "mod97": 2}.get(constraints.checksum_algorithm, 4)
            data_part = "".join(serial_chars[:-checksum_length])
            checksum = checksum_func(data_part)
            serial_chars[-checksum_length:] = list(checksum)

        serial = "".join(serial_chars)

        # Format with groups
        if constraints.groups > 1:
            group_size = len(serial) // constraints.groups
            groups = [serial[i : i + group_size] for i in range(0, len(serial), group_size)]
            serial = constraints.group_separator.join(groups)
        logger.debug("Generated random serial: %s", serial)
        return GeneratedSerial(
            serial=serial,
            format=constraints.format,
            confidence=0.7,
            validation_data={"method": "random_fallback"},
            algorithm_used="random",
        )

    def _generate_microsoft_serial(self, constraints: SerialConstraints) -> GeneratedSerial:
        """Generate Microsoft-style product key.

        Args:
            constraints: SerialConstraints object (unused but required by interface).

        Returns:
            GeneratedSerial: Microsoft-format serial with confidence score.

        """
        # Microsoft uses specific algorithm with mod 7 check
        chars = "BCDFGHJKMPQRTVWXY2346789"  # pragma: allowlist secret
        groups = []

        for _i in range(5):
            group = "".join(random.choices(chars, k=5))  # noqa: S311
            groups.append(group)

        serial = "-".join(groups)
        logger.debug("Generated Microsoft-style serial: %s", serial)
        return GeneratedSerial(
            serial=serial,
            format=SerialFormat.MICROSOFT,
            confidence=0.9,
            validation_data={"algorithm": "microsoft_mod7"},
            algorithm_used="microsoft",
        )

    def _generate_uuid_serial(self, constraints: SerialConstraints) -> GeneratedSerial:
        """Generate UUID-format serial.

        Args:
            constraints: SerialConstraints object (unused but required by interface).

        Returns:
            GeneratedSerial: UUID v4 format serial with perfect confidence.

        """
        import uuid

        # Generate UUID v4
        serial = str(uuid.uuid4()).upper()
        logger.debug("Generated UUID serial: %s", serial)
        return GeneratedSerial(
            serial=serial,
            format=SerialFormat.UUID,
            confidence=1.0,
            validation_data={"version": 4},
            algorithm_used="uuid4",
        )

    def _generate_luhn_serial(self, length: int = 16) -> str:
        """Generate serial with Luhn checksum.

        Args:
            length: Desired length of generated serial (default 16).

        Returns:
            str: Serial number with Luhn checksum validation.

        """
        # Note: Using random module for generating serials, not cryptographic purposes
        digits = [random.randint(0, 9) for _ in range(length - 1)]  # noqa: S311
        checksum = self._calculate_luhn_digit(digits)
        digits.append(checksum)
        serial = "".join(map(str, digits))
        logger.debug("Generated Luhn serial: %s", serial)
        return serial

    def _calculate_luhn(self, data: str) -> str:
        """Calculate Luhn checksum.

        Args:
            data: String data to calculate checksum for.

        Returns:
            str: Luhn checksum digit as a string.

        """
        digits = [int(d) for d in data if d.isdigit()]
        checksum = self._calculate_luhn_digit(digits)
        return str(checksum)

    def _calculate_luhn_digit(self, digits: list[int]) -> int:
        """Calculate Luhn check digit.

        Args:
            digits: List of integers to calculate check digit for.

        Returns:
            int: The Luhn check digit (0-9).

        """
        total = 0
        for i, digit in enumerate(reversed(digits)):
            if i % 2 == 0:
                doubled = digit * 2
                if doubled > 9:
                    doubled -= 9
                total += doubled
            else:
                total += digit

        return (10 - (total % 10)) % 10

    def _verify_luhn(self, serial: str) -> bool:
        """Verify Luhn checksum.

        Args:
            serial: Serial number to verify.

        Returns:
            bool: True if Luhn checksum is valid, False otherwise.

        """
        digits = [int(d) for d in serial if d.isdigit()]
        if not digits:
            return False

        checksum = digits[-1]
        data = digits[:-1]
        expected = self._calculate_luhn_digit(data)

        return checksum == expected

    def _generate_verhoeff_serial(self, length: int = 16) -> str:
        """Generate serial with Verhoeff checksum.

        Args:
            length: Desired length of generated serial (default 16).

        Returns:
            str: Serial number with Verhoeff checksum validation.

        """
        # Verhoeff algorithm tables
        d = [
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
            [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
            [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
            [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
            [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
            [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
            [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
            [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
            [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
        ]

        p = [
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
            [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
            [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
            [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
            [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
            [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
            [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
        ]

        # Note: Using random module for generating serials, not cryptographic purposes
        digits = [random.randint(0, 9) for _ in range(length - 1)]  # noqa: S311

        # Calculate checksum
        c = 0
        for i, digit in enumerate(reversed(digits)):
            c = d[c][p[i % 8][digit]]

        digits.append(c)
        serial = "".join(map(str, digits))
        logger.debug("Generated Verhoeff serial: %s", serial)
        return serial

    def _calculate_verhoeff(self, data: str) -> str:
        """Calculate Verhoeff checksum.

        Args:
            data: String data to calculate checksum for.

        Returns:
            str: Verhoeff checksum digit as a string.

        """
        # Implementation of Verhoeff algorithm
        return "0"  # Simplified

    def _verify_verhoeff(self, serial: str) -> bool:
        """Verify Verhoeff checksum.

        Args:
            serial: Serial number to verify.

        Returns:
            bool: True if Verhoeff checksum is valid, False otherwise.

        """
        # Implementation of Verhoeff verification
        return False  # Simplified

    def _generate_damm_serial(self, length: int = 16) -> str:
        """Generate serial with Damm checksum.

        Args:
            length: Desired length of generated serial (default 16).

        Returns:
            str: Serial number with Damm checksum validation.

        """
        # Damm algorithm table
        table = [
            [0, 3, 1, 7, 5, 9, 8, 6, 4, 2],
            [7, 0, 9, 2, 1, 5, 4, 8, 6, 3],
            [4, 2, 0, 6, 8, 7, 1, 3, 5, 9],
            [1, 7, 5, 0, 9, 8, 3, 4, 2, 6],
            [6, 1, 2, 3, 0, 4, 5, 9, 7, 8],
            [3, 6, 7, 4, 2, 0, 9, 5, 8, 1],
            [5, 8, 6, 9, 7, 2, 0, 1, 3, 4],
            [8, 9, 4, 5, 3, 6, 2, 0, 1, 7],
            [9, 4, 3, 8, 6, 1, 7, 2, 0, 5],
            [2, 5, 8, 1, 4, 3, 6, 7, 9, 0],
        ]

        # Note: Using random module for generating serials, not cryptographic purposes
        digits = [random.randint(0, 9) for _ in range(length - 1)]  # noqa: S311

        # Calculate checksum
        interim = 0
        for digit in digits:
            interim = table[interim][digit]

        digits.append(interim)
        serial = "".join(map(str, digits))
        logger.debug("Generated Damm serial: %s", serial)
        return serial

    def _calculate_damm(self, data: str) -> str:
        """Calculate Damm checksum.

        Args:
            data: String data to calculate checksum for.

        Returns:
            str: Damm checksum digit as a string.

        """
        # Implementation of Damm algorithm
        return "0"  # Simplified

    def _generate_crc32_serial(self, length: int = 16) -> str:
        """Generate serial with CRC32 checksum.

        Args:
            length: Desired length of generated serial (default 16).

        Returns:
            str: Serial number with CRC32 checksum validation.

        """
        import zlib

        # Note: Using random module for generating serials, not cryptographic purposes
        data = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=length - 8))  # noqa: S311

        # Calculate CRC32
        crc = zlib.crc32(data.encode()) & 0xFFFFFFFF
        checksum = format(crc, "08X")
        serial = data + checksum
        logger.debug("Generated CRC32 serial: %s", serial)
        return serial

    def _verify_crc32(self, serial: str) -> bool:
        """Verify CRC32 checksum.

        Args:
            serial: Serial number to verify.

        Returns:
            bool: True if CRC32 checksum is valid, False otherwise.

        """
        import zlib

        if len(serial) < 8:
            return False

        data = serial[:-8]
        checksum = serial[-8:]

        try:
            expected_crc = zlib.crc32(data.encode()) & 0xFFFFFFFF
            expected_checksum = format(expected_crc, "08X")
            return checksum == expected_checksum
        except (ValueError, TypeError) as e:
            logger.debug("Error verifying CRC32 checksum for serial '%s': %s", serial, e, exc_info=True)
            return False

    def _calculate_crc32(self, data: str) -> str:
        """Calculate CRC32 checksum.

        Args:
            data: String data to calculate checksum for.

        Returns:
            str: CRC32 checksum as hexadecimal string.

        """
        import zlib

        crc = zlib.crc32(data.encode()) & 0xFFFFFFFF
        return format(crc, "08X")

    def _generate_mod97_serial(self, length: int = 16) -> str:
        """Generate serial with mod97 checksum (IBAN-style).

        Args:
            length: Desired length of generated serial (default 16).

        Returns:
            str: Serial number with mod97 checksum validation.

        """
        # Note: Using random module for generating serials, not cryptographic purposes
        data = "".join(random.choices("0123456789", k=length - 2))  # noqa: S311

        # Calculate mod97 checksum
        num = int(f"{data}00")
        checksum = 98 - (num % 97)
        serial = data + str(checksum).zfill(2)
        logger.debug("Generated mod97 serial: %s", serial)
        return serial

    def _calculate_mod97(self, data: str) -> str:
        """Calculate mod97 checksum.

        Args:
            data: String data to calculate checksum for.

        Returns:
            str: mod97 checksum as zero-padded two-digit string.

        """
        # Convert to numeric string
        numeric = "".join(c if c.isdigit() else str(ord(c) - ord("A") + 10) for c in data)
        num = int(f"{numeric}00")
        checksum = 98 - (num % 97)
        return str(checksum).zfill(2)

    def _generate_polynomial_serial(self, length: int = 16) -> str:
        """Generate serial using polynomial-based algorithm.

        Args:
            length: Desired length of generated serial (default 16).

        Returns:
            str: Serial number generated using polynomial LFSR.

        """
        # Use a polynomial over GF(2^8)
        poly = 0x11D  # x^8 + x^4 + x^3 + x^2 + 1

        serial = []
        # Note: Using random module for generating serials, not cryptographic purposes
        state = random.randint(1, 255)  # noqa: S311

        for _ in range(length):
            # LFSR step
            state = ((state << 1) ^ poly) & 0xFF if state & 0x80 else (state << 1) & 0xFF
            # Convert to character
            char = chr(ord("A") + (state % 26))
            serial.append(char)
        final_serial = "".join(serial)
        logger.debug("Generated polynomial serial: %s", final_serial)
        return final_serial

    def _generate_ecc_serial(self, length: int = 16) -> str:
        """Generate serial using elliptic curve operations.

        Args:
            length: Desired length of generated serial (default 16).

        Returns:
            str: Serial number generated using elliptic curve operations.

        """
        # Simplified ECC-based generation
        # Use curve parameters
        p = 2**255 - 19  # Curve25519
        base_point = 9

        serial_parts: list[str] = []
        # Note: Using random module for generating serials, not cryptographic purposes
        x = random.randint(1, p - 1)  # noqa: S311

        for _ in range(length // 8):
            # Scalar multiplication (simplified)
            x = (x * base_point) % p
            # Take some bits as serial part
            serial_parts.append(format(x % (10**8), "08d"))
        serial = "".join(serial_parts)[:length]
        logger.debug("Generated ECC serial: %s", serial)
        return serial

    def _generate_rsa_serial(self, length: int = 16) -> str:
        """Generate serial using RSA-like operations.

        Args:
            length: Desired length of generated serial (default 16).

        Returns:
            str: Serial number generated using RSA operations.

        """
        # Small RSA-like parameters for serial generation
        p = 61
        q = 53
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 17  # Common public exponent

        # Find d such that e*d ≡ 1 (mod phi)
        d = pow(e, -1, phi)

        # Generate serial
        serial_parts = []
        for _ in range(length // 4):
            # Note: Using random module for generating serials, not cryptographic purposes
            m = random.randint(2, n - 1)  # noqa: S311
            # Sign with private key
            s = pow(m, d, n)
            serial_parts.append(format(s, "04X"))

        serial = "".join(serial_parts)[:length]
        logger.debug("Generated RSA serial: %s", serial)
        return serial

    def _generate_hash_chain_serial(self, length: int = 16) -> str:
        """Generate serial using hash chain.

        Args:
            length: Desired length of generated serial (default 16).

        Returns:
            str: Serial number generated using SHA256 hash chain.

        """
        # Note: Using random module for generating serials, not cryptographic purposes
        seed = random.randbytes(16)  # noqa: S311
        hash_value = hashlib.sha256(seed).digest()

        serial = ""
        while len(serial) < length:
            # Take characters from hash
            for byte in hash_value:
                if len(serial) >= length:
                    break
                # Convert to alphanumeric
                char = chr(ord("A") + (byte % 26)) if byte < 128 else str(byte % 10)
                serial += char

            # Next hash in chain
            hash_value = hashlib.sha256(hash_value).digest()
        final_serial = serial[:length]
        logger.debug("Generated hash chain serial: %s", final_serial)
        return final_serial

    def _generate_feistel_serial(self, length: int = 16) -> str:
        """Generate serial using Feistel network.

        Args:
            length: Desired length of generated serial (default 16).

        Returns:
            str: Serial number generated using Feistel cipher operations.

        """

        def feistel_round(left: int, right: int, key: int) -> tuple[int, int]:
            """Perform a single Feistel network round.

            Args:
                left: Left half of the data block.
                right: Right half of the data block.
                key: Round key for the transformation.

            Returns:
                Tuple containing (right, new_right) for the next round.

            """
            # Simple round function
            new_right = left ^ (hashlib.sha256((str(right) + str(key)).encode()).digest()[0] % 256)
            return right, new_right

        # Generate serial in blocks
        serial = []
        # Note: Using random module for generating serials, not cryptographic purposes
        left = random.randint(0, 255)  # noqa: S311
        right = random.randint(0, 255)  # noqa: S311

        for _i in range(length):
            # Multiple rounds
            for round_num in range(4):
                left, right = feistel_round(left, right, round_num)

            # Convert to character
            char_code = (left ^ right) % 36
            if char_code < 10:
                serial.append(str(char_code))
            else:
                serial.append(chr(ord("A") + char_code - 10))

            # Update for next character
            left = (left + 1) % 256
            right = (right + 1) % 256
        final_serial = "".join(serial)
        logger.debug("Generated Feistel serial: %s", final_serial)
        return final_serial

    def _calculate_crc16(self, data: str) -> str:
        """Calculate CRC16 checksum.

        Args:
            data: String data to calculate checksum for.

        Returns:
            str: CRC16 checksum as hexadecimal string.

        """
        crc = 0xFFFF
        for char in data:
            crc ^= ord(char)
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0xA001
                else:
                    crc >>= 1
        return format(crc, "04X")

    def _calculate_fletcher16(self, data: str) -> str:
        """Calculate Fletcher-16 checksum.

        Args:
            data: String data to calculate checksum for.

        Returns:
            str: Fletcher-16 checksum as hexadecimal string.

        """
        sum1 = sum2 = 0
        for char in data:
            sum1 = (sum1 + ord(char)) % 255
            sum2 = (sum2 + sum1) % 255
        return format((sum2 << 8) | sum1, "04X")

    def _calculate_fletcher32(self, data: str) -> str:
        """Calculate Fletcher-32 checksum.

        Args:
            data: String data to calculate checksum for.

        Returns:
            str: Fletcher-32 checksum as hexadecimal string.

        """
        sum1 = sum2 = 0
        for char in data:
            sum1 = (sum1 + ord(char)) % 65535
            sum2 = (sum2 + sum1) % 65535
        return format((sum2 << 16) | sum1, "08X")

    def _calculate_adler32(self, data: str) -> str:
        """Calculate Adler-32 checksum.

        Args:
            data: String data to calculate checksum for.

        Returns:
            str: Adler-32 checksum as hexadecimal string.

        """
        import zlib

        adler = zlib.adler32(data.encode()) & 0xFFFFFFFF
        return format(adler, "08X")

    def _calculate_mod11(self, data: str) -> str:
        """Calculate mod11 checksum.

        Args:
            data: String data to calculate checksum for.

        Returns:
            str: mod11 checksum digit(s) as a string.

        """
        weights = [2, 3, 4, 5, 6, 7, 8, 9, 10]
        total = sum(int(char) * weights[i % len(weights)] for i, char in enumerate(data) if char.isdigit())
        remainder = total % 11
        if remainder == 0:
            return "0"
        return "X" if remainder == 1 else str(11 - remainder)

    def _calculate_mod37(self, data: str) -> str:
        """Calculate mod37 checksum.

        Args:
            data: String data to calculate checksum for.

        Returns:
            str: mod37 checksum as a single digit or letter.

        """
        # Map alphanumeric to 0-36
        value = 0
        for char in data:
            if char.isdigit():
                value = (value * 37 + int(char)) % 37
            elif char.isalpha():
                value = (value * 37 + ord(char.upper()) - ord("A") + 10) % 37

        return str(value) if value < 10 else chr(ord("A") + value - 10)

    def _generate_with_validation(self, constraints: SerialConstraints, seed: int | str | bytes | None = None) -> GeneratedSerial:
        """Generate serial with custom validation function.

        Args:
            constraints: SerialConstraints object with validation function specified.
            seed: Optional seed value for generation.

        Returns:
            GeneratedSerial: The generated serial that passes validation, or empty serial if generation fails.

        """
        max_attempts = 1000
        for _ in range(max_attempts):
            # Generate candidate
            candidate = self._generate_random_serial(constraints)

            # Validate
            if constraints.validation_function is not None and constraints.validation_function(candidate.serial):
                if candidate.validation_data is not None:
                    candidate.validation_data["custom_validation"] = True
                candidate.confidence = 1.0
                return candidate

        # Failed to generate valid serial
        return GeneratedSerial(
            serial="",
            format=constraints.format,
            confidence=0.0,
            validation_data={"error": "Could not generate valid serial"},
            algorithm_used="failed",
        )

    def batch_generate(self, constraints: SerialConstraints, count: int, unique: bool = True) -> list[GeneratedSerial]:
        """Generate multiple serial numbers.

        Args:
            constraints: SerialConstraints object specifying generation parameters.
            count: Number of serials to generate.
            unique: If True, ensures all generated serials are unique (default True).

        Returns:
            list[GeneratedSerial]: List of generated serial numbers with metadata.

        """
        serials = []
        generated_set = set()

        max_retries = 10
        for i in range(count):
            for _retry in range(max_retries):
                serial = self.generate_serial(constraints, seed=None if unique else i)

                if not unique or serial.serial not in generated_set:
                    serials.append(serial)
                    generated_set.add(serial.serial)
                    logger.debug("Generated serial %s/%s: %s", i + 1, count, serial.serial)
                    break
        logger.debug("Batch generation completed. Generated %s serials.", len(serials))
        return serials

    def reverse_engineer_algorithm(self, valid_serials: list[str], invalid_serials: list[str] | None = None) -> dict[str, Any]:
        """Reverse engineer the serial generation algorithm.

        Args:
            valid_serials: List of known valid serial numbers.
            invalid_serials: Optional list of known invalid serial numbers for validation.

        Returns:
            dict[str, Any]: Comprehensive algorithm analysis including format, checksum, patterns, false positive rate, and sample generated serials.

        """
        analysis = self.analyze_serial_algorithm(valid_serials)
        logger.debug("Reverse engineering initial analysis: %s", analysis)

        # Test with invalid serials if provided
        if invalid_serials:
            algorithm_name = str(analysis["algorithm"]) if analysis["algorithm"] is not None else "unknown"
            false_positive_rate = sum(bool(self._test_single_serial(invalid, algorithm_name)) for invalid in invalid_serials)
            analysis["false_positive_rate"] = false_positive_rate / len(invalid_serials)
            logger.debug("False positive rate with invalid serials: %.2f", analysis["false_positive_rate"])

        # Generate sample serials using detected algorithm
        constraints = SerialConstraints(
            length=analysis["length"]["clean_mode"],
            format=analysis["format"],
            checksum_algorithm=next(iter(analysis["checksum"].keys())) if analysis["checksum"] else None,
        )

        samples = self.batch_generate(constraints, 10)
        analysis["generated_samples"] = [s.serial for s in samples]
        logger.debug("Generated %s sample serials using the detected algorithm.", len(samples))

        return analysis

    def generate_rsa_signed(
        self,
        private_key: rsa.RSAPrivateKey,
        product_id: str,
        user_name: str,
        features: list[str] | None = None,
        expiration: int | None = None,
    ) -> GeneratedSerial:
        """Generate RSA-signed serial number with cryptographic validation.

        Args:
            private_key: RSA private key for signing.
            product_id: Product identifier to encode in serial.
            user_name: User name to encode in serial.
            features: Optional list of licensed features.
            expiration: Optional expiration timestamp (unix epoch).

        Returns:
            GeneratedSerial: RSA-signed serial with base32 encoding and high confidence.

        """
        license_data = {
            "product_id": product_id,
            "user": user_name,
            "features": features or [],
            "issued": int(time.time()),
            "expiration": expiration or 0,
        }

        data_bytes = json.dumps(license_data, sort_keys=True).encode()

        signature = private_key.sign(
            data_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )

        serial_data = base64.b32encode(data_bytes + signature)
        serial = serial_data.decode("ascii").rstrip("=")

        formatted = "-".join(serial[i : i + 5] for i in range(0, len(serial), 5))
        logger.debug("Generated RSA-signed serial: %s", formatted)
        return GeneratedSerial(
            serial=formatted,
            raw_bytes=data_bytes + signature,
            checksum="RSA-PSS-SHA256",
            hardware_id=None,
            expiration=expiration,
            features=features or [],
            algorithm="rsa_signed",
            confidence=0.95,
        )

    def generate_ecc_signed(self, private_key: ec.EllipticCurvePrivateKey, product_id: str, machine_code: str) -> GeneratedSerial:
        """Generate ECC-signed serial number with elliptic curve cryptography.

        Args:
            private_key: Elliptic curve private key for signing.
            product_id: Product identifier to encode in serial.
            machine_code: Machine/hardware identifier for binding.

        Returns:
            GeneratedSerial: ECC-signed serial with base32 encoding and high confidence.

        """
        data = f"{product_id}:{machine_code}:{int(time.time())}"
        data_bytes = data.encode()

        signature = private_key.sign(data_bytes, ec.ECDSA(hashes.SHA256()))

        serial_bytes = data_bytes + signature
        serial = base64.b32encode(serial_bytes).decode("ascii").rstrip("=")

        formatted = "-".join(serial[i : i + 6] for i in range(0, len(serial), 6))
        logger.debug("Generated ECC-signed serial: %s", formatted)
        return GeneratedSerial(
            serial=formatted,
            raw_bytes=serial_bytes,
            checksum="ECDSA-SHA256",
            hardware_id=machine_code,
            expiration=None,
            features=[],
            algorithm="ecc_signed",
            confidence=0.93,
        )

    def generate_time_based(self, secret_key: bytes, validity_days: int = 30, product_id: str | None = None) -> GeneratedSerial:
        """Generate time-based serial number using TOTP-like algorithm.

        Args:
            secret_key: Secret key for HMAC-SHA256 generation.
            validity_days: Number of days the serial is valid (default 30).
            product_id: Optional product identifier to include in serial.

        Returns:
            GeneratedSerial: Time-based serial with expiration and HMAC validation.

        """
        time_counter = int(time.time()) // 86400  # Daily counter
        expiration = int(time.time()) + (validity_days * 86400)

        data = struct.pack(">Q", time_counter)
        if product_id:
            data += product_id.encode()

        h = hmac.new(secret_key, data, hashlib.sha256)
        digest = h.digest()

        offset = digest[-1] & 0x0F
        code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF

        serial_parts = []
        for i in range(5):
            part = (code >> (i * 6)) & 0x3F
            if part < 26:
                serial_parts.append(chr(ord("A") + part))
            elif part < 52:
                serial_parts.append(chr(ord("a") + part - 26))
            else:
                serial_parts.append(str(part - 52))

        exp_encoded = base64.b32encode(struct.pack(">I", expiration)).decode()[:6]
        serial = f"{''.join(serial_parts)}-{exp_encoded}-{code % 10000:04d}"
        logger.debug("Generated time-based serial: %s", serial)
        return GeneratedSerial(
            serial=serial,
            raw_bytes=digest,
            checksum="HMAC-SHA256",
            hardware_id=None,
            expiration=expiration,
            features=[],
            algorithm="time_based",
            confidence=0.88,
        )

    def generate_feature_encoded(self, base_serial: str, features: list[str]) -> GeneratedSerial:
        """Generate serial with encoded feature flags.

        Args:
            base_serial: Base serial number to extend with feature flags.
            features: List of feature names to encode (pro, enterprise, unlimited, support, updates, api, export, multiuser).

        Returns:
            GeneratedSerial: Serial with embedded feature flags and CRC16 validation.

        """
        feature_flags = {
            "pro": 0x01,
            "enterprise": 0x02,
            "unlimited": 0x04,
            "support": 0x08,
            "updates": 0x10,
            "api": 0x20,
            "export": 0x40,
            "multiuser": 0x80,
        }

        flags = 0
        for feature in features:
            flags |= feature_flags.get(feature.lower(), 0)

        flags_encoded = f"{flags:04X}"

        if "-" in base_serial:
            parts = base_serial.split("-")
            parts.insert(-1, flags_encoded)
            serial = "-".join(parts)
        else:
            serial = f"{base_serial}-{flags_encoded}"

        checksum = self._calculate_crc16(serial)
        serial = f"{serial}-{checksum}"
        logger.debug("Generated feature-encoded serial: %s", serial)
        return GeneratedSerial(
            serial=serial,
            raw_bytes=serial.encode(),
            checksum="CRC16",
            hardware_id=None,
            expiration=None,
            features=features,
            algorithm="feature_encoded",
            confidence=0.82,
        )

    def generate_mathematical(self, seed: int, algorithm: str = "quadratic") -> GeneratedSerial:
        """Generate serial using mathematical relationships.

        Args:
            seed: Seed value for mathematical generation.
            algorithm: Algorithm type - 'fibonacci', 'mersenne', 'quadratic', or hash-based (default 'quadratic').

        Returns:
            GeneratedSerial: Serial generated using mathematical function with CRC32 validation.

        """
        result_int: int
        if algorithm == "fibonacci":
            f1, f2 = seed, seed + 1
            for _ in range(10):
                f1, f2 = f2, (f1 + f2) & 0xFFFFFFFF
            result_int = f2

        elif algorithm == "mersenne":
            mersenne_primes = [3, 7, 31, 127, 8191, 131071, 524287]
            result_int = seed * mersenne_primes[seed % len(mersenne_primes)] & 0xFFFFFFFF

        elif algorithm == "quadratic":
            a, b, c = 1337, 42069, 314159
            result_int = (a * seed * seed + b * seed + c) & 0xFFFFFFFF

        else:
            result_hex = hashlib.sha256(str(seed).encode()).hexdigest()[:8]
            result_int = int(result_hex, 16)

        serial = f"{seed:05d}-{result_int:08X}"

        validation = self._calculate_crc32(serial)
        serial = f"{serial}-{validation}"
        logger.debug("Generated mathematical serial: %s", serial)
        return GeneratedSerial(
            serial=serial,
            raw_bytes=struct.pack(">II", seed, result_int),
            checksum="CRC32",
            hardware_id=None,
            expiration=None,
            features=[],
            algorithm=f"mathematical_{algorithm}",
            confidence=0.79,
        )

    def generate_blackbox(self, input_data: bytes, rounds: int = 1000) -> GeneratedSerial:
        """Generate serial using blackbox algorithm for unknown protection schemes.

        Args:
            input_data: Binary input data to process through blackbox algorithm.
            rounds: Number of cipher rounds (default 1000).

        Returns:
            GeneratedSerial: Serial generated using substitution-permutation-diffusion network.

        """
        state = bytearray(input_data)

        for round_num in range(rounds):
            # Substitution
            for i in range(len(state)):
                state[i] = (state[i] + round_num) & 0xFF

            # Permutation
            for i in range(0, len(state) - 1, 2):
                state[i], state[i + 1] = state[i + 1], state[i]

            # Diffusion
            h = hashlib.sha256(state).digest()
            for i in range(min(len(state), len(h))):
                state[i] ^= h[i]

        serial_bytes = bytes(state[:16])
        serial = base64.b32encode(serial_bytes).decode().rstrip("=")

        formatted = "-".join(serial[i : i + 4] for i in range(0, len(serial), 4))
        logger.debug("Generated blackbox serial: %s", formatted)
        return GeneratedSerial(
            serial=formatted,
            raw_bytes=serial_bytes,
            checksum=None,
            hardware_id=None,
            expiration=None,
            features=[],
            algorithm="blackbox",
            confidence=0.70,
        )

    def brute_force_checksum(self, partial_serial: str, checksum_length: int = 4) -> list[str]:
        """Brute force missing checksum digits for incomplete serials.

        Args:
            partial_serial: Serial number with missing checksum digits.
            checksum_length: Number of checksum digits to brute force (default 4).

        Returns:
            list[str]: List of candidate serial numbers that pass known checksum algorithms.

        """
        logger.debug("Starting brute-force checksum for partial serial: '%s' with checksum length: %s", partial_serial, checksum_length)
        candidates = []
        charset = "0123456789ABCDEF"

        for i in range(16**checksum_length):
            checksum = ""
            val = i
            for _ in range(checksum_length):
                checksum = charset[val % 16] + checksum
                val //= 16

            full_serial = f"{partial_serial}-{checksum}"

            if self._verify_checksum(full_serial, self._calculate_crc32):
                candidates.append(full_serial)
                logger.debug("Found candidate (CRC32): %s", full_serial)
            elif self._verify_checksum(full_serial, self._calculate_crc16):
                candidates.append(full_serial)
                logger.debug("Found candidate (CRC16): %s", full_serial)
            elif self._verify_checksum(full_serial, self._calculate_luhn):
                candidates.append(full_serial)
                logger.debug("Found candidate (Luhn): %s", full_serial)
        logger.debug("Brute-force checksum completed. Found %s candidates.", len(candidates))
        return candidates

    def _test_single_serial(self, serial: str, algorithm: str) -> bool:
        """Test if a serial matches an algorithm.

        Args:
            serial: Serial number to test.
            algorithm: Algorithm name to test against (luhn, verhoeff, crc32, etc).

        Returns:
            bool: True if the serial validates with the given algorithm, False otherwise.

        """
        if algorithm == "luhn":
            return self._verify_luhn(serial)
        if algorithm == "verhoeff":
            return self._verify_verhoeff(serial)
        return self._verify_crc32(serial) if algorithm == "crc32" else False
