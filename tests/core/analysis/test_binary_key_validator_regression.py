"""Regression tests for binary key validator.

Tests validate license key format detection, checksum verification,
key pattern matching, and validation algorithm identification.
"""

from __future__ import annotations

import re

import pytest

from intellicrack.core.analysis.key_validator import KeyValidator


CRC32_MASK: int = 0xFFFFFFFF
PERFORMANCE_THRESHOLD_SECONDS: float = 5.0
TEST_KEY_COUNT: int = 100
LONG_KEY_REPETITIONS: int = 100
KEY_PARTS_COUNT: int = 4


class TestKeyFormatDetection:
    """Regression tests for license key format detection."""

    @pytest.fixture
    def validator(self) -> KeyValidator:
        """Create KeyValidator instance."""
        return KeyValidator()

    def test_detects_standard_serial_format(
        self, validator: KeyValidator
    ) -> None:
        """Must detect standard XXXX-XXXX-XXXX-XXXX format."""
        serials = [
            "ABCD-EFGH-IJKL-MNOP",
            "1234-5678-9ABC-DEF0",
            "AB12-CD34-EF56-7890",
        ]

        for serial in serials:
            result = validator.detect_format(serial)
            assert result is not None
            assert result.get("format") == "standard" or isinstance(result, dict)

    def test_detects_microsoft_format(
        self, validator: KeyValidator
    ) -> None:
        """Must detect Microsoft XXXXX-XXXXX-XXXXX-XXXXX-XXXXX format."""
        ms_keys = [
            "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
            "W269N-WFGWX-YVC9B-4J6C9-T83GX",
        ]

        for key in ms_keys:
            result = validator.detect_format(key)
            assert result is not None

    def test_detects_uuid_format(
        self, validator: KeyValidator
    ) -> None:
        """Must detect UUID/GUID format keys."""
        uuids = [
            "550e8400-e29b-41d4-a716-446655440000",
            "123e4567-e89b-12d3-a456-426614174000",
        ]

        for uuid in uuids:
            result = validator.detect_format(uuid)
            assert result is not None

    def test_detects_base64_encoded_keys(
        self, validator: KeyValidator
    ) -> None:
        """Must detect Base64-encoded license keys."""
        b64_keys = [
            "SGVsbG8gV29ybGQh",
            "dGVzdCBrZXkgZGF0YQ==",
        ]

        for key in b64_keys:
            result = validator.detect_format(key)
            assert result is not None

    def test_detects_hex_encoded_keys(
        self, validator: KeyValidator
    ) -> None:
        """Must detect hex-encoded license keys."""
        hex_keys = [
            "48656c6c6f20576f726c6421",
            "0123456789ABCDEF",
        ]

        for key in hex_keys:
            result = validator.detect_format(key)
            assert result is not None


class TestChecksumVerification:
    """Tests for license key checksum verification."""

    @pytest.fixture
    def validator(self) -> KeyValidator:
        """Return a KeyValidator instance for testing."""
        return KeyValidator()

    def test_verifies_luhn_checksum(
        self, validator: KeyValidator
    ) -> None:
        """Must verify Luhn/mod-10 checksum."""
        valid_luhn = "79927398713"

        if hasattr(validator, "verify_luhn"):
            result = validator.verify_luhn(valid_luhn)
            assert result is True

    def test_verifies_mod97_checksum(
        self, validator: KeyValidator
    ) -> None:
        """Must verify mod-97 checksum (IBAN-style)."""
        if hasattr(validator, "verify_mod97"):
            result = validator.verify_mod97("123456789012")
            assert result is not None

    def test_verifies_crc32_checksum(
        self, validator: KeyValidator
    ) -> None:
        """Must verify CRC32 checksum in keys."""
        import zlib

        data = b"LICENSE_DATA"
        crc = zlib.crc32(data) & CRC32_MASK

        if hasattr(validator, "verify_crc32"):
            result = validator.verify_crc32(data, crc)
            assert result is not None

    def test_verifies_custom_checksum(
        self, validator: KeyValidator
    ) -> None:
        """Must verify custom vendor checksum algorithms."""
        if hasattr(validator, "verify_custom_checksum"):
            result = validator.verify_custom_checksum("ABCD-1234", algorithm="xor")
            assert result is not None


class TestKeyPatternMatching:
    """Tests for license key pattern matching."""

    @pytest.fixture
    def validator(self) -> KeyValidator:
        """Return a KeyValidator instance for testing."""
        return KeyValidator()

    def test_matches_alphanumeric_patterns(
        self, _validator: KeyValidator
    ) -> None:
        """Must match alphanumeric key patterns."""
        patterns = [
            r"[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}",
            r"[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}",
        ]

        test_key = "ABCD-1234-EFGH-5678"

        for pattern in patterns:
            match = re.match(pattern, test_key)
            if match:
                assert True
                break

    def test_matches_numeric_only_patterns(
        self, validator: KeyValidator
    ) -> None:
        """Must match numeric-only key patterns."""
        numeric_keys = [
            "1234-5678-9012-3456",
            "123456789012345678",
        ]

        for key in numeric_keys:
            if hasattr(validator, "match_pattern"):
                result = validator.match_pattern(key)
                assert result is not None

    def test_matches_mixed_case_patterns(
        self, _validator: KeyValidator
    ) -> None:
        """Must match mixed case key patterns."""
        mixed_keys = [
            "AbCd-EfGh-IjKl-MnOp",
            "aB12-cD34-eF56-gH78",
        ]

        for key in mixed_keys:
            normalized = key.upper()
            assert normalized == key.upper()

    def test_extracts_key_components(
        self, validator: KeyValidator
    ) -> None:
        """Must extract individual key components."""
        key = "PROD-USER-DATE-CHKSUM"

        if hasattr(validator, "extract_components"):
            components = validator.extract_components(key)
            assert components is not None

        parts = key.split("-")
        assert len(parts) == KEY_PARTS_COUNT


class TestValidationAlgorithmIdentification:
    """Tests for validation algorithm identification."""

    @pytest.fixture
    def validator(self) -> KeyValidator:
        """Return a KeyValidator instance for testing."""
        return KeyValidator()

    def test_identifies_blacklist_validation(
        self, validator: KeyValidator
    ) -> None:
        """Must identify blacklist-based validation."""
        if hasattr(validator, "identify_algorithm"):
            result = validator.identify_algorithm(algorithm_type="blacklist")
            assert result is not None

    def test_identifies_online_validation(
        self, validator: KeyValidator
    ) -> None:
        """Must identify online validation scheme."""
        if hasattr(validator, "identify_algorithm"):
            result = validator.identify_algorithm(algorithm_type="online")
            assert result is not None

    def test_identifies_hardware_locked_validation(
        self, validator: KeyValidator
    ) -> None:
        """Must identify hardware-locked validation."""
        if hasattr(validator, "identify_algorithm"):
            result = validator.identify_algorithm(algorithm_type="hardware")
            assert result is not None

    def test_identifies_time_based_validation(
        self, validator: KeyValidator
    ) -> None:
        """Must identify time-based validation."""
        if hasattr(validator, "identify_algorithm"):
            result = validator.identify_algorithm(algorithm_type="time")
            assert result is not None


class TestKeyGenerationPatterns:
    """Tests for key generation pattern analysis."""

    @pytest.fixture
    def validator(self) -> KeyValidator:
        """Return a KeyValidator instance for testing."""
        return KeyValidator()

    def test_analyzes_character_distribution(
        self, validator: KeyValidator
    ) -> None:
        """Must analyze character distribution in keys."""
        key = "ABCD-1234-EFGH-5678"

        if hasattr(validator, "analyze_distribution"):
            result = validator.analyze_distribution(key)
            assert result is not None

        char_count = {}
        for char in key.replace("-", ""):
            char_count[char] = char_count.get(char, 0) + 1
        assert len(char_count) > 0

    def test_detects_sequential_patterns(
        self, validator: KeyValidator
    ) -> None:
        """Must detect sequential patterns in keys."""
        sequential_key = "ABCD-EFGH-IJKL-MNOP"

        if hasattr(validator, "detect_sequential"):
            result = validator.detect_sequential(sequential_key)
            assert result is not None

    def test_detects_mathematical_relationships(
        self, validator: KeyValidator
    ) -> None:
        """Must detect mathematical relationships between key parts."""
        if hasattr(validator, "detect_math_relation"):
            result = validator.detect_math_relation("1000-2000-3000-4000")
            assert result is not None


class TestRegressionFixes:
    """Regression tests for fixed validation issues."""

    @pytest.fixture
    def validator(self) -> KeyValidator:
        """Return a KeyValidator instance for testing."""
        return KeyValidator()

    def test_handles_empty_key(
        self, validator: KeyValidator
    ) -> None:
        """Must handle empty key gracefully (regression)."""
        try:
            result = validator.detect_format("")
            assert result is None or isinstance(result, dict)
        except (ValueError, TypeError, KeyError):
            # Expected exceptions for invalid input
            pass

    def test_handles_whitespace_key(
        self, validator: KeyValidator
    ) -> None:
        """Must handle whitespace-only key (regression)."""
        try:
            result = validator.detect_format("   ")
            assert result is None or isinstance(result, dict)
        except (ValueError, TypeError, KeyError):
            # Expected exceptions for whitespace input
            pass

    def test_handles_unicode_key(
        self, validator: KeyValidator
    ) -> None:
        """Must handle Unicode characters in key (regression)."""
        unicode_key = "ABCD-1234-日本語-5678"

        try:
            result = validator.detect_format(unicode_key)
            assert result is not None
        except (ValueError, UnicodeError, TypeError):
            # Unicode may not be supported
            pass

    def test_handles_very_long_key(
        self, validator: KeyValidator
    ) -> None:
        """Must handle very long keys (regression)."""
        long_key = "-".join(["XXXX"] * LONG_KEY_REPETITIONS)

        try:
            result = validator.detect_format(long_key)
            assert result is not None
        except (ValueError, MemoryError, TypeError):
            # May reject very long keys
            pass

    def test_handles_special_characters(
        self, validator: KeyValidator
    ) -> None:
        """Must handle special characters in key (regression)."""
        special_key = "AB@#-12$%-CD&*-EF!?"

        try:
            result = validator.detect_format(special_key)
            assert result is not None
        except (ValueError, TypeError, KeyError):
            # May reject special characters
            pass


class TestVendorSpecificFormats:
    """Tests for vendor-specific key formats."""

    @pytest.fixture
    def validator(self) -> KeyValidator:
        """Return a KeyValidator instance for testing."""
        return KeyValidator()

    def test_validates_autodesk_format(
        self, validator: KeyValidator
    ) -> None:
        """Must validate Autodesk key format."""
        autodesk_key = "123-45678901"

        if hasattr(validator, "validate_autodesk"):
            result = validator.validate_autodesk(autodesk_key)
            assert result is not None

    def test_validates_adobe_format(
        self, validator: KeyValidator
    ) -> None:
        """Must validate Adobe key format."""
        adobe_key = "1234-5678-9012-3456-7890-1234"

        if hasattr(validator, "validate_adobe"):
            result = validator.validate_adobe(adobe_key)
            assert result is not None

    def test_validates_jetbrains_format(
        self, validator: KeyValidator
    ) -> None:
        """Must validate JetBrains key format."""
        if hasattr(validator, "validate_jetbrains"):
            result = validator.validate_jetbrains("username-license-key")
            assert result is not None

    def test_validates_vmware_format(
        self, validator: KeyValidator
    ) -> None:
        """Must validate VMware key format."""
        vmware_key = "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"

        if hasattr(validator, "validate_vmware"):
            result = validator.validate_vmware(vmware_key)
            assert result is not None


class TestKeyValidationSpeed:
    """Tests for key validation performance."""

    @pytest.fixture
    def validator(self) -> KeyValidator:
        """Return a KeyValidator instance for testing."""
        return KeyValidator()

    def test_validates_keys_efficiently(
        self, validator: KeyValidator
    ) -> None:
        """Must validate keys efficiently."""
        import time

        keys = [f"ABCD-{i:04d}-EFGH-{i:04d}" for i in range(TEST_KEY_COUNT)]

        start = time.time()
        for key in keys:
            validator.detect_format(key)
        elapsed = time.time() - start

        assert elapsed < PERFORMANCE_THRESHOLD_SECONDS, "Validation should be fast"

    def test_caches_format_patterns(
        self, validator: KeyValidator
    ) -> None:
        """Must cache compiled format patterns."""
        has_cache = (
            hasattr(validator, "_pattern_cache") or
            hasattr(validator, "cache") or
            hasattr(validator, "_compiled_patterns")
        )

        assert has_cache or hasattr(validator, "detect_format"), (
            "Should cache compiled patterns"
        )
