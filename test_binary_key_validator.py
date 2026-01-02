"""Test suite for BinaryKeyValidator implementation."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).parent))

from intellicrack.core.exploitation.keygen_generator import (
    BinaryKeyValidator,
    KeyAlgorithmType,
    KeyConstraint,
    ValidationAlgorithm,
)


def test_validator_initialization() -> None:
    """Test BinaryKeyValidator initialization."""
    algorithm = ValidationAlgorithm(
        type=KeyAlgorithmType.CHECKSUM,
        offset=0x1000,
        instructions=[("mov", "eax, ebx"), ("ret", "")],
        constants=[123, 456],
        strings=["license", "key"],
        crypto_operations=["crc32"],
        constraints=[],
        confidence=0.8,
    )

    validator = BinaryKeyValidator("test.exe", algorithm, timeout=3.0)

    assert validator.binary_path.name == "test.exe"
    assert validator.algorithm == algorithm
    assert validator.timeout == 3.0
    assert isinstance(validator.validation_addresses, list)
    print("✓ Validator initialization test passed")


def test_address_extraction() -> None:
    """Test validation address extraction."""
    algorithm = ValidationAlgorithm(
        type=KeyAlgorithmType.RSA_SIGNATURE,
        offset=0x2000,
        instructions=[],
        constants=[],
        strings=[],
        crypto_operations=[],
        constraints=[
            KeyConstraint(name="length", type="length", value=16),
        ],
        confidence=0.9,
    )

    setattr(algorithm, "function_address", 0x401000)

    validator = BinaryKeyValidator("test.exe", algorithm)

    assert 0x401000 in validator.validation_addresses
    print("✓ Address extraction test passed")


def test_heuristic_validation() -> None:
    """Test heuristic validation fallback."""
    algorithm = ValidationAlgorithm(
        type=KeyAlgorithmType.PATTERN_BASED,
        offset=0x3000,
        instructions=[],
        constants=[],
        strings=[],
        crypto_operations=[],
        constraints=[
            KeyConstraint(name="length", type="length", value=16),
            KeyConstraint(name="pattern", type="pattern", value="####-####-####-####"),
        ],
        confidence=0.7,
    )

    validator = BinaryKeyValidator("test.exe", algorithm)

    valid_key = "ABCD-1234-EFGH-5678"
    assert validator._heuristic_validate(valid_key) is True
    print("✓ Heuristic validation (valid key) test passed")

    short_key = "ABC"
    assert validator._heuristic_validate(short_key) is False
    print("✓ Heuristic validation (short key) test passed")


def test_frida_hook_script_generation() -> None:
    """Test Frida hook script generation."""
    algorithm = ValidationAlgorithm(
        type=KeyAlgorithmType.CUSTOM_ALGORITHM,
        offset=0x4000,
        instructions=[],
        constants=[],
        strings=[],
        crypto_operations=[],
        constraints=[],
        confidence=0.85,
    )

    setattr(algorithm, "function_address", 0x401500)

    validator = BinaryKeyValidator("test.exe", algorithm)
    validator.validation_addresses = [0x401500, 0x401600]

    script = validator._generate_frida_hook_script("TEST-KEY-1234")

    assert "Interceptor.attach" in script
    assert "0x401500" in script
    assert "0x401600" in script
    assert "TEST-KEY-1234" in script
    assert "writeUtf8String" in script
    assert "writeUtf16String" in script
    print("✓ Frida script generation test passed")


def test_validation_strategy_selection() -> None:
    """Test that validator tries multiple strategies."""
    algorithm = ValidationAlgorithm(
        type=KeyAlgorithmType.MATHEMATICAL,
        offset=0x5000,
        instructions=[],
        constants=[],
        strings=[],
        crypto_operations=[],
        constraints=[],
        confidence=0.6,
    )

    with patch("intellicrack.core.exploitation.keygen_generator.FRIDA_AVAILABLE", False):
        with patch("intellicrack.core.exploitation.keygen_generator.R2PIPE_AVAILABLE", False):
            validator = BinaryKeyValidator("nonexistent.exe", algorithm)

            result = validator.validate_key("TEST-1234-5678-9012")

            assert isinstance(result, bool)
            print("✓ Fallback strategy test passed")


def test_constraint_checking() -> None:
    """Test that constraints are properly validated."""
    algorithm = ValidationAlgorithm(
        type=KeyAlgorithmType.CHECKSUM,
        offset=0x6000,
        instructions=[],
        constants=[],
        strings=[],
        crypto_operations=[],
        constraints=[
            KeyConstraint(name="minlen", type="length", value=12),
        ],
        confidence=0.75,
    )

    validator = BinaryKeyValidator("test.exe", algorithm)

    result = validator._heuristic_validate("ABC")
    assert result is False
    print("✓ Constraint checking (too short) test passed")

    result = validator._heuristic_validate("ABCDEFGHIJKL")
    assert result is True
    print("✓ Constraint checking (valid length) test passed")


def run_all_tests() -> None:
    """Run all test functions."""
    print("Running BinaryKeyValidator tests...\n")

    try:
        test_validator_initialization()
        test_address_extraction()
        test_heuristic_validation()
        test_frida_hook_script_generation()
        test_validation_strategy_selection()
        test_constraint_checking()

        print("\n" + "=" * 60)
        print("✓ ALL TESTS PASSED")
        print("=" * 60)

    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    run_all_tests()
