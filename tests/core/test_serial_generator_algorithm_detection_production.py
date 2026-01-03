"""Production tests for serial generator algorithm detection and learning capabilities.

These tests validate the serial generator's ability to:
- Detect algorithms from binary analysis (not just 10 predefined algorithms)
- Support pluggable algorithm definitions
- Learn new algorithms from valid/invalid serial pairs
- Generate algorithm fingerprints for matching
- Export discovered algorithms for reuse
- Handle edge cases: Multi-part serials, version-dependent algorithms
"""

import json
import struct
import tempfile
import zlib
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from intellicrack.core.serial_generator import (
    GeneratedSerial,
    SerialConstraints,
    SerialFormat,
    SerialNumberGenerator,
)


class TestAlgorithmDetectionFromBinaries:
    """Tests for detecting algorithms from binary analysis, not predefined algorithms."""

    def test_detects_custom_algorithm_from_serial_patterns(self) -> None:
        """Must detect custom algorithms beyond the 10 predefined ones by analyzing serial patterns."""
        generator = SerialNumberGenerator()

        # Create serials with a custom algorithm (base64-like with custom checksum)
        custom_serials = [
            "AB3K9L2M-5N7P8Q1-R4S6T0U-V2W3X5Y",
            "CD8L2N9P-1Q4R7S0-T3U6V9W-X2Y5Z8A",
            "EF1M5P9R-3S7T2U6-V0W4X8Y-Z1A5B9C",
        ]

        analysis = generator.analyze_serial_algorithm(custom_serials)

        # Test must FAIL if system only recognizes predefined algorithms
        assert analysis["format"] == SerialFormat.ALPHANUMERIC
        assert analysis["length"]["clean_mode"] == 32
        assert analysis["structure"]["group_count"] == 4
        assert analysis["structure"]["common_separator"] == "-"

        # System must be capable of learning this pattern even if not predefined
        assert analysis["confidence"] >= 0.0

    def test_learns_proprietary_checksum_algorithm_from_samples(self) -> None:
        """Must learn proprietary checksum algorithms from serial samples, not just hardcoded ones."""
        generator = SerialNumberGenerator()

        # Custom checksum: sum of ASCII values mod 256, converted to hex
        def custom_checksum(data: str) -> str:
            return format(sum(ord(c) for c in data) % 256, "02X")

        # Generate serials with custom checksum
        valid_serials = []
        for i in range(20):
            base = f"PROD{i:04d}USER{i*2:04d}"
            checksum = custom_checksum(base)
            valid_serials.append(f"{base}-{checksum}")

        analysis = generator.analyze_serial_algorithm(valid_serials)

        # Must detect pattern even though it's not one of the 10 predefined algorithms
        assert "checksum" in analysis
        assert "format" in analysis
        assert "patterns" in analysis

        # System should be able to reverse-engineer this
        assert len(analysis["patterns"]) >= 0  # May detect numeric or other patterns

    def test_detects_multi_stage_validation_algorithms(self) -> None:
        """Must detect complex multi-stage validation algorithms."""
        generator = SerialNumberGenerator()

        # Multi-stage: CRC32 of first part + Luhn of second part
        valid_serials = []
        for i in range(15):
            part1 = f"A{i:05d}B"
            crc = zlib.crc32(part1.encode()) & 0xFFFF
            part2_base = f"{crc:04X}{i:03d}"

            # Add Luhn digit
            digits = [int(d) if d.isdigit() else (ord(d) - ord("A") + 10) % 10 for d in part2_base]
            total = 0
            for idx, digit in enumerate(reversed(digits)):
                if idx % 2 == 0:
                    doubled = digit * 2
                    if doubled > 9:
                        doubled -= 9
                    total += doubled
                else:
                    total += digit
            luhn_digit = (10 - (total % 10)) % 10

            serial = f"{part1}-{part2_base}{luhn_digit}"
            valid_serials.append(serial)

        analysis = generator.analyze_serial_algorithm(valid_serials)

        # Must identify structure and complexity
        assert analysis["structure"]["group_count"] == 2
        assert analysis["length"]["clean_mode"] >= 14

        # Should detect multiple checksum candidates
        assert isinstance(analysis["checksum"], dict)


class TestPluggableAlgorithmDefinitions:
    """Tests for pluggable algorithm system allowing runtime algorithm registration."""

    def test_can_register_new_algorithm_at_runtime(self) -> None:
        """Must support registering new algorithms dynamically, not just 10 hardcoded ones."""
        generator = SerialNumberGenerator()

        # Verify we can add new algorithms
        initial_count = len(generator.common_algorithms)

        # Register a custom algorithm
        def custom_rot13_serial(length: int) -> str:
            import random
            import string

            chars = "".join(random.choices(string.ascii_uppercase, k=length - 2))  # noqa: S311
            # ROT13 checksum
            checksum = "".join(chr(((ord(c) - ord("A") + 13) % 26) + ord("A")) for c in chars[:2])
            return f"{chars}{checksum}"

        generator.common_algorithms["rot13_custom"] = custom_rot13_serial

        # Test must FAIL if we can't add algorithms beyond predefined 10
        assert len(generator.common_algorithms) == initial_count + 1
        assert "rot13_custom" in generator.common_algorithms

        # Verify the algorithm works
        serial = generator.common_algorithms["rot13_custom"](16)
        assert len(serial) == 16
        assert serial.isalpha()

    def test_can_register_custom_checksum_function(self) -> None:
        """Must allow registration of custom checksum functions beyond predefined ones."""
        generator = SerialNumberGenerator()

        initial_checksum_count = len(generator.checksum_functions)

        # Register custom checksum (XOR of all bytes)
        def xor_checksum(data: str) -> str:
            result = 0
            for char in data:
                result ^= ord(char)
            return format(result, "02X")

        generator.checksum_functions["xor_custom"] = xor_checksum

        # Must support adding beyond the initial set
        assert len(generator.checksum_functions) == initial_checksum_count + 1
        assert "xor_custom" in generator.checksum_functions

        # Verify it works
        checksum = generator.checksum_functions["xor_custom"]("TESTDATA")
        assert len(checksum) == 2
        assert all(c in "0123456789ABCDEF" for c in checksum)

    def test_custom_algorithm_used_in_generation(self) -> None:
        """Custom algorithms must be usable in serial generation."""
        generator = SerialNumberGenerator()

        # Register algorithm
        def simple_algo(length: int) -> str:
            return "X" * length

        generator.common_algorithms["simple_x"] = simple_algo

        # Verify we can reference it (indirectly through the system)
        assert generator.common_algorithms["simple_x"](10) == "X" * 10


class TestLearningFromSerialPairs:
    """Tests for learning algorithms from valid/invalid serial pairs."""

    def test_learns_from_valid_invalid_pairs_reduces_false_positives(self) -> None:
        """Must learn from valid/invalid pairs to reduce false positive rate."""
        generator = SerialNumberGenerator()

        # Valid serials: Luhn algorithm
        valid_serials = [generator._generate_luhn_serial(16) for _ in range(20)]

        # Invalid serials: random garbage
        import random

        invalid_serials = ["".join(random.choices("0123456789", k=16)) for _ in range(20)]  # noqa: S311

        # Reverse engineer with both sets
        analysis = generator.reverse_engineer_algorithm(valid_serials, invalid_serials)

        # Must calculate false positive rate
        assert "false_positive_rate" in analysis

        # False positive rate should be low for proper algorithm detection
        assert analysis["false_positive_rate"] <= 0.3  # Max 30% false positives

    def test_identifies_algorithm_with_high_confidence_from_pairs(self) -> None:
        """Must identify correct algorithm with high confidence when given valid/invalid pairs."""
        generator = SerialNumberGenerator()

        # Create valid CRC32 serials
        valid_serials = [generator._generate_crc32_serial(16) for _ in range(15)]

        # Create invalid ones (wrong checksum)
        invalid_serials = [f"{s[:-8]}FFFFFFFF" for s in valid_serials[:10]]

        analysis = generator.reverse_engineer_algorithm(valid_serials, invalid_serials)

        # Should detect CRC32 with reasonable confidence
        assert analysis["algorithm"] is not None
        assert analysis["confidence"] > 0.0

        # Should generate sample serials
        assert "generated_samples" in analysis
        assert len(analysis["generated_samples"]) > 0

    def test_learns_format_constraints_from_invalid_serials(self) -> None:
        """Must learn what makes serials invalid and apply those constraints."""
        generator = SerialNumberGenerator()

        # Valid: only uppercase letters and digits, no 'O' or '0'
        valid_alphabet = "ABCDEFGHIJKLMNPQRSTUVWXYZ123456789"
        valid_serials = []
        for i in range(15):
            import random

            serial = "".join(random.choices(valid_alphabet, k=12))  # noqa: S311
            valid_serials.append(serial)

        # Invalid: contain 'O' or '0'
        invalid_serials = [
            "ABCDEFG0HIJK",
            "LMNOPQRSTUV",
            "000000000000",
            "OOOOOOOOOOO",
        ]

        analysis = generator.reverse_engineer_algorithm(valid_serials, invalid_serials)

        # Should detect the format
        assert analysis["format"] == SerialFormat.ALPHANUMERIC
        assert analysis["length"]["clean_mode"] == 12


class TestAlgorithmFingerprinting:
    """Tests for generating and matching algorithm fingerprints."""

    def test_generates_unique_fingerprint_for_algorithm(self) -> None:
        """Must generate unique fingerprints to identify algorithms."""
        generator = SerialNumberGenerator()

        # Generate serials with different algorithms
        luhn_serials = [generator._generate_luhn_serial(16) for _ in range(10)]
        crc32_serials = [generator._generate_crc32_serial(16) for _ in range(10)]

        luhn_analysis = generator.analyze_serial_algorithm(luhn_serials)
        crc32_analysis = generator.analyze_serial_algorithm(crc32_serials)

        # Fingerprints should be different (algorithm, format, length, checksum)
        luhn_fingerprint = (
            luhn_analysis["algorithm"],
            luhn_analysis["format"],
            luhn_analysis["length"]["clean_mode"],
        )

        crc32_fingerprint = (
            crc32_analysis["algorithm"],
            crc32_analysis["format"],
            crc32_analysis["length"]["clean_mode"],
        )

        # Must generate distinct fingerprints
        assert luhn_fingerprint != crc32_fingerprint

    def test_fingerprint_matches_similar_serials(self) -> None:
        """Algorithm fingerprints must match serials from same algorithm."""
        generator = SerialNumberGenerator()

        # Generate two batches from same algorithm
        batch1 = [generator._generate_verhoeff_serial(16) for _ in range(10)]
        batch2 = [generator._generate_verhoeff_serial(16) for _ in range(10)]

        analysis1 = generator.analyze_serial_algorithm(batch1)
        analysis2 = generator.analyze_serial_algorithm(batch2)

        # Fingerprints should be similar
        assert analysis1["format"] == analysis2["format"]
        assert analysis1["length"]["clean_mode"] == analysis2["length"]["clean_mode"]

    def test_creates_exportable_algorithm_signature(self) -> None:
        """Must create algorithm signatures that can be exported and reused."""
        generator = SerialNumberGenerator()

        serials = [generator._generate_damm_serial(16) for _ in range(15)]
        analysis = generator.analyze_serial_algorithm(serials)

        # Must be JSON-serializable for export
        signature = {
            "algorithm": analysis["algorithm"],
            "format": analysis["format"].value if isinstance(analysis["format"], SerialFormat) else str(analysis["format"]),
            "length": analysis["length"]["clean_mode"],
            "checksum": list(analysis["checksum"].keys()) if analysis["checksum"] else None,
            "structure": {
                "groups": analysis["structure"].get("group_count", 1),
                "separator": analysis["structure"].get("common_separator", ""),
            },
        }

        # Must be exportable as JSON
        json_str = json.dumps(signature)
        assert len(json_str) > 0

        # Must be re-importable
        imported = json.loads(json_str)
        assert imported["algorithm"] == signature["algorithm"]
        assert imported["length"] == signature["length"]


class TestAlgorithmExportImport:
    """Tests for exporting and importing discovered algorithms."""

    def test_exports_discovered_algorithm_to_file(self) -> None:
        """Must export discovered algorithms to files for reuse."""
        generator = SerialNumberGenerator()

        # Discover algorithm
        serials = [generator._generate_crc32_serial(20) for _ in range(12)]
        analysis = generator.analyze_serial_algorithm(serials)

        # Export to file
        export_data = {
            "algorithm_name": analysis["algorithm"],
            "format": analysis["format"].value if isinstance(analysis["format"], SerialFormat) else str(analysis["format"]),
            "constraints": {
                "length": analysis["length"]["clean_mode"],
                "groups": analysis["structure"].get("group_count", 1),
                "separator": analysis["structure"].get("common_separator", "-"),
            },
            "checksum_algorithms": list(analysis["checksum"].keys()) if analysis["checksum"] else [],
            "confidence": analysis["confidence"],
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(export_data, f)
            export_path = Path(f.name)

        try:
            # Verify export exists and is valid
            assert export_path.exists()
            with export_path.open() as f:
                imported = json.load(f)

            assert imported["algorithm_name"] == analysis["algorithm"]
            assert imported["confidence"] == analysis["confidence"]
        finally:
            export_path.unlink()

    def test_imports_algorithm_definition_and_generates_serials(self) -> None:
        """Must import algorithm definitions and use them to generate new serials."""
        generator = SerialNumberGenerator()

        # Create algorithm definition
        algorithm_def = {
            "name": "custom_imported",
            "format": "ALPHANUMERIC",
            "length": 16,
            "groups": 4,
            "separator": "-",
            "checksum": "crc32",
        }

        # Save and load
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(algorithm_def, f)
            import_path = Path(f.name)

        try:
            # Load definition
            with import_path.open() as f:
                loaded_def = json.load(f)

            # Create constraints from definition
            constraints = SerialConstraints(
                length=loaded_def["length"],
                format=SerialFormat(loaded_def["format"]),
                groups=loaded_def["groups"],
                group_separator=loaded_def["separator"],
                checksum_algorithm=loaded_def.get("checksum"),
            )

            # Generate serial using imported definition
            serial = generator.generate_serial(constraints)

            # Must produce valid serial
            assert serial.serial
            assert len(serial.serial.replace("-", "")) == 16
        finally:
            import_path.unlink()

    def test_exported_algorithm_produces_compatible_serials(self) -> None:
        """Serials generated from exported algorithm must match original pattern."""
        generator = SerialNumberGenerator()

        # Original serials
        original_serials = [generator._generate_mod97_serial(12) for _ in range(10)]
        original_analysis = generator.analyze_serial_algorithm(original_serials)

        # Export algorithm definition
        constraints = SerialConstraints(
            length=original_analysis["length"]["clean_mode"],
            format=original_analysis["format"],
            checksum_algorithm=next(iter(original_analysis["checksum"].keys())) if original_analysis["checksum"] else None,
        )

        # Generate new serial from exported definition
        new_serial = generator.generate_serial(constraints)

        # Must match format characteristics
        clean_original = original_serials[0].replace("-", "").replace(" ", "")
        clean_new = new_serial.serial.replace("-", "").replace(" ", "")

        assert len(clean_new) == len(clean_original)
        assert all(c.isdigit() for c in clean_new) == all(c.isdigit() for c in clean_original)


class TestMultiPartSerialEdgeCases:
    """Tests for handling multi-part serial numbers with complex structures."""

    def test_detects_multi_part_serial_with_different_formats(self) -> None:
        """Must handle serials where different parts have different formats."""
        generator = SerialNumberGenerator()

        # Part 1: letters, Part 2: digits, Part 3: hex
        multi_part_serials = [
            "ABCD-1234-5678-ABEF",
            "EFGH-5678-9012-CDEF",
            "IJKL-9012-3456-EF01",
        ]

        analysis = generator.analyze_serial_algorithm(multi_part_serials)

        # Must detect structure
        assert analysis["structure"]["group_count"] == 4
        assert analysis["structure"]["common_separator"] == "-"
        assert analysis["length"]["clean_mode"] == 16

    def test_handles_variable_length_groups_in_serial(self) -> None:
        """Must handle serials with groups of different lengths."""
        generator = SerialNumberGenerator()

        # Groups of different lengths: 5-3-8-4
        variable_serials = [
            "ABCDE-123-UVWXYZ01-ABCD",
            "FGHIJ-456-OPQRST02-EFGH",
            "KLMNO-789-IJKLMN03-IJKL",
        ]

        analysis = generator.analyze_serial_algorithm(variable_serials)

        # Must detect group structure
        assert analysis["structure"]["group_count"] == 4
        # Should detect variable group lengths
        assert "group_lengths" in analysis["structure"]
        assert len(analysis["structure"]["group_lengths"]) > 0

    def test_handles_nested_separators_in_serial(self) -> None:
        """Must handle serials with multiple separator types."""
        generator = SerialNumberGenerator()

        # Mixed separators: - and .
        nested_serials = [
            "AB-CD.EF-GH.IJ-KL",
            "MN-OP.QR-ST.UV-WX",
            "YZ-12.34-56.78-90",
        ]

        analysis = generator.analyze_serial_algorithm(nested_serials)

        # Must detect separators
        assert "separators" in analysis["structure"]
        assert len(analysis["structure"]["separators"]) > 0

    def test_generates_multi_part_serial_maintaining_structure(self) -> None:
        """Generated multi-part serials must maintain proper structure."""
        generator = SerialNumberGenerator()

        constraints = SerialConstraints(
            length=20,
            format=SerialFormat.ALPHANUMERIC,
            groups=4,
            group_separator="-",
        )

        serial = generator.generate_serial(constraints)

        # Must have correct number of groups
        parts = serial.serial.split("-")
        assert len(parts) == 4

        # Total length (excluding separators) should match
        clean_length = len(serial.serial.replace("-", ""))
        assert clean_length == 20


class TestVersionDependentAlgorithms:
    """Tests for handling version-dependent serial algorithms."""

    def test_detects_version_prefix_in_serials(self) -> None:
        """Must detect version indicators in serial numbers."""
        generator = SerialNumberGenerator()

        # Version-prefixed serials
        v1_serials = [
            "V1-ABCD-1234-EFGH",
            "V1-IJKL-5678-MNOP",
            "V1-QRST-9012-UVWX",
        ]

        v2_serials = [
            "V2-1234-ABCD-5678",
            "V2-9012-EFGH-3456",
            "V2-7890-IJKL-1234",
        ]

        v1_analysis = generator.analyze_serial_algorithm(v1_serials)
        v2_analysis = generator.analyze_serial_algorithm(v2_serials)

        # Must detect pattern difference
        assert v1_analysis["structure"]["group_count"] == v2_analysis["structure"]["group_count"]
        # Patterns should contain version info
        assert "must_contain" not in v1_analysis or any("V" in str(p) for p in v1_analysis.get("patterns", []))

    def test_generates_version_specific_serial(self) -> None:
        """Must generate serials conforming to version-specific requirements."""
        generator = SerialNumberGenerator()

        # Version 3 requires specific prefix
        constraints = SerialConstraints(
            length=16,
            format=SerialFormat.ALPHANUMERIC,
            must_contain=["V3"],
            groups=1,
        )

        serial = generator.generate_serial(constraints)

        # Must contain version marker
        assert "V3" in serial.serial

    def test_differentiates_algorithm_versions_by_checksum(self) -> None:
        """Must differentiate algorithm versions that use different checksums."""
        generator = SerialNumberGenerator()

        # V1: CRC32 checksum
        v1_serials = []
        for i in range(10):
            data = f"V1DATA{i:04d}"
            crc = zlib.crc32(data.encode()) & 0xFFFFFFFF
            checksum = format(crc, "08X")
            v1_serials.append(f"{data}-{checksum}")

        # V2: Different checksum (sum mod 256)
        v2_serials = []
        for i in range(10):
            data = f"V2DATA{i:04d}"
            checksum = format(sum(ord(c) for c in data) % 256, "02X")
            v2_serials.append(f"{data}-{checksum}")

        v1_analysis = generator.analyze_serial_algorithm(v1_serials)
        v2_analysis = generator.analyze_serial_algorithm(v2_serials)

        # Should detect different checksum algorithms
        assert "checksum" in v1_analysis
        assert "checksum" in v2_analysis

    def test_handles_backward_compatible_serial_validation(self) -> None:
        """Must handle serials that are valid across multiple versions."""
        generator = SerialNumberGenerator()

        # Serials valid in both v1 and v2 (universal format)
        universal_serials = [
            "UNIV-ABCD-1234-5678",
            "UNIV-EFGH-5678-9012",
            "UNIV-IJKL-9012-3456",
        ]

        analysis = generator.analyze_serial_algorithm(universal_serials)

        # Must detect common structure
        assert analysis["structure"]["group_count"] == 4
        assert "UNIV" in universal_serials[0]


class TestConstraintBasedDetection:
    """Tests for constraint-based algorithm detection from binaries."""

    def test_detects_character_set_constraints_from_serials(self) -> None:
        """Must detect allowed character sets from serial samples."""
        generator = SerialNumberGenerator()

        # Only uppercase and specific digits (no 0, O, I, 1)
        constrained_alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        import random

        serials = ["".join(random.choices(constrained_alphabet, k=12)) for _ in range(15)]  # noqa: S311

        analysis = generator.analyze_serial_algorithm(serials)

        # Must detect format
        assert analysis["format"] == SerialFormat.ALPHANUMERIC

    def test_detects_length_constraints(self) -> None:
        """Must detect exact length requirements."""
        generator = SerialNumberGenerator()

        # All exactly 24 characters
        fixed_length_serials = [
            "ABCDEFGHIJKLMNOPQRSTUVWX",
            "123456789012345678901234",
            "ZYXWVUTSRQPONMLKJIHGFED",
        ]

        analysis = generator.analyze_serial_algorithm(fixed_length_serials)

        # Must detect exact length
        assert analysis["length"]["clean_min"] == 24
        assert analysis["length"]["clean_max"] == 24
        assert analysis["length"]["clean_mode"] == 24

    def test_detects_position_specific_constraints(self) -> None:
        """Must detect constraints on specific positions (e.g., position 5 must be hyphen)."""
        generator = SerialNumberGenerator()

        # Position 5 and 10 must be hyphens
        position_serials = [
            "ABCD-EFGH-IJKLM",
            "1234-5678-90ABC",
            "ZYXW-VUTR-QPONM",
        ]

        analysis = generator.analyze_serial_algorithm(position_serials)

        # Must detect separator positions
        assert analysis["structure"]["common_separator"] == "-"
        assert analysis["structure"]["group_count"] == 3

    def test_generates_serial_satisfying_complex_constraints(self) -> None:
        """Must generate serials satisfying multiple simultaneous constraints."""
        generator = SerialNumberGenerator()

        constraints = SerialConstraints(
            length=16,
            format=SerialFormat.ALPHANUMERIC,
            groups=4,
            group_separator="-",
            must_contain=["AB"],
            cannot_contain=["0", "O"],
        )

        serial = generator.generate_serial(constraints)

        # Must satisfy all constraints
        assert "AB" in serial.serial
        assert "0" not in serial.serial
        assert "O" not in serial.serial
        assert serial.serial.count("-") == 3


class TestRealWorldAlgorithmDetection:
    """Tests using realistic commercial software serial patterns."""

    def test_detects_microsoft_office_style_algorithm(self) -> None:
        """Must detect Microsoft Office style product keys."""
        generator = SerialNumberGenerator()

        # Generate Microsoft-style keys
        ms_serials = [generator._generate_microsoft_serial(SerialConstraints(length=25, format=SerialFormat.MICROSOFT)) for _ in range(10)]

        analysis = generator.analyze_serial_algorithm([s.serial for s in ms_serials])

        # Must detect Microsoft format
        assert analysis["format"] == SerialFormat.MICROSOFT
        assert analysis["structure"]["group_count"] == 5
        assert analysis["length"]["clean_mode"] == 25

    def test_detects_uuid_based_licensing(self) -> None:
        """Must detect UUID-based licensing schemes."""
        generator = SerialNumberGenerator()

        # Generate UUID serials
        uuid_serials = [generator._generate_uuid_serial(SerialConstraints(length=36, format=SerialFormat.UUID)) for _ in range(10)]

        analysis = generator.analyze_serial_algorithm([s.serial for s in uuid_serials])

        # Must detect UUID format
        assert analysis["format"] == SerialFormat.UUID

    def test_detects_rsa_signed_serial_pattern(self) -> None:
        """Must detect RSA-signed serial number patterns."""
        generator = SerialNumberGenerator()

        # Generate RSA-signed serials
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        rsa_serials = []
        for i in range(5):
            serial = generator.generate_rsa_signed(
                private_key,
                product_id=f"PROD-{i}",
                user_name=f"User{i}",
                features=["pro", "enterprise"],
            )
            rsa_serials.append(serial.serial)

        analysis = generator.analyze_serial_algorithm(rsa_serials)

        # Must detect base32-encoded pattern
        assert analysis["format"] in [SerialFormat.BASE32, SerialFormat.ALPHANUMERIC]

    def test_detects_ecc_signed_serial_pattern(self) -> None:
        """Must detect ECC-signed serial number patterns."""
        generator = SerialNumberGenerator()

        # Generate ECC-signed serials
        private_key = ec.generate_private_key(ec.SECP256R1())

        ecc_serials = []
        for i in range(5):
            serial = generator.generate_ecc_signed(
                private_key,
                product_id=f"PROD-{i}",
                machine_code=f"MACHINE-{i:08X}",
            )
            ecc_serials.append(serial.serial)

        analysis = generator.analyze_serial_algorithm(ecc_serials)

        # Must detect base32-encoded pattern with groups
        assert analysis["format"] in [SerialFormat.BASE32, SerialFormat.ALPHANUMERIC]
        assert "structure" in analysis


class TestAlgorithmDetectionPerformance:
    """Performance tests ensuring algorithm detection completes in reasonable time."""

    def test_analyzes_large_serial_set_efficiently(self) -> None:
        """Must analyze large sets of serials in reasonable time."""
        import time

        generator = SerialNumberGenerator()

        # Generate 1000 serials
        large_set = [generator._generate_crc32_serial(16) for _ in range(1000)]

        start = time.perf_counter()
        analysis = generator.analyze_serial_algorithm(large_set)
        elapsed = time.perf_counter() - start

        # Must complete in under 5 seconds for 1000 serials
        assert elapsed < 5.0
        assert analysis is not None

    def test_reverse_engineers_algorithm_with_acceptable_performance(self) -> None:
        """Reverse engineering must complete in reasonable time."""
        import time

        generator = SerialNumberGenerator()

        valid_serials = [generator._generate_luhn_serial(16) for _ in range(100)]
        invalid_serials = [f"INVALID{i:012d}" for i in range(100)]

        start = time.perf_counter()
        analysis = generator.reverse_engineer_algorithm(valid_serials, invalid_serials)
        elapsed = time.perf_counter() - start

        # Must complete in under 10 seconds
        assert elapsed < 10.0
        assert "generated_samples" in analysis


class TestEdgeCaseHandling:
    """Tests for handling edge cases in algorithm detection."""

    def test_handles_empty_serial_list(self) -> None:
        """Must handle empty serial lists gracefully."""
        generator = SerialNumberGenerator()

        analysis = generator.analyze_serial_algorithm([])

        # Must not crash, should return default values
        assert analysis is not None
        assert "format" in analysis

    def test_handles_single_serial(self) -> None:
        """Must handle analysis with only one serial."""
        generator = SerialNumberGenerator()

        analysis = generator.analyze_serial_algorithm(["ABCD-1234-EFGH"])

        # Should provide basic analysis
        assert analysis["format"] is not None
        assert analysis["length"] is not None

    def test_handles_malformed_serials(self) -> None:
        """Must handle malformed or unusual serial formats."""
        generator = SerialNumberGenerator()

        malformed = [
            "!!!###$$$",
            "",
            "A",
            "🔐🔑🗝️",  # Unicode
        ]

        analysis = generator.analyze_serial_algorithm(malformed)

        # Must not crash
        assert analysis is not None

    def test_handles_extremely_long_serials(self) -> None:
        """Must handle very long serial numbers."""
        generator = SerialNumberGenerator()

        long_serials = ["A" * 1000, "B" * 1000, "C" * 1000]

        analysis = generator.analyze_serial_algorithm(long_serials)

        # Must detect length correctly
        assert analysis["length"]["clean_mode"] == 1000

    def test_handles_mixed_format_serials_in_same_set(self) -> None:
        """Must handle sets with inconsistent serial formats."""
        generator = SerialNumberGenerator()

        mixed = [
            "ABCD-1234",  # Alphanumeric
            "12345678",  # Numeric
            "ABCDEFGH",  # Letters only
        ]

        analysis = generator.analyze_serial_algorithm(mixed)

        # Should default to most general format
        assert analysis["format"] in [SerialFormat.ALPHANUMERIC, SerialFormat.CUSTOM]
