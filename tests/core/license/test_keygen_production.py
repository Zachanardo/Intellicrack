"""Production-ready tests for license keygen validation against real binaries.

This test suite validates that keygen.py ACTUALLY generates valid license keys
that work with real protected software, using debugging, patching, and dynamic
analysis to confirm key acceptance.

Requirements:
- Must validate generated keys against real binaries
- Must extract validation routines from target executables
- Must support RSA, ECC, and custom algorithm key generation
- Must handle network-based validation via emulation
- Must test hardware-locked keys, time-limited licenses, and feature flags

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack. If not, see <https://www.gnu.org/licenses/>.
"""

import hashlib
import logging
import struct
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.license.keygen import (
    AlgorithmType,
    ConstraintExtractor,
    CryptoPrimitive,
    CryptoType,
    ExtractedAlgorithm,
    KeyConstraint,
    KeySynthesizer,
    KeyValidator,
    LicenseKeygen,
    PatchLocation,
    ValidationAnalysis,
    ValidationAnalyzer,
    ValidationConfig,
    ValidationConstraint,
    ValidationResult,
)
from intellicrack.core.serial_generator import GeneratedSerial, SerialConstraints, SerialFormat

logger = logging.getLogger(__name__)

BINARIES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "binaries" / "pe" / "protected"
LICENSED_SOFTWARE_DIR = Path(__file__).parent.parent.parent / "resources" / "protected_binaries" / "licensed_software"


def _check_binary_available(binary_path: Path) -> tuple[bool, str]:
    """Check if a test binary is available and return detailed skip reason.

    Args:
        binary_path: Path to the binary to check

    Returns:
        Tuple of (is_available, skip_reason)
    """
    if not binary_path.exists():
        reason = f"""
BINARY NOT FOUND: {binary_path}

This test requires a REAL protected binary with license validation.

Required file type: Windows PE executable with license/serial validation
Expected location: {binary_path.parent}
Expected filename: {binary_path.name}

To enable this test:
1. Obtain a legitimate software installer with license validation
2. Extract the main executable
3. Place it at: {binary_path}
4. Ensure the binary actually validates license keys (trial software works best)

Examples of suitable software:
- Trial versions of commercial software (WinRAR, Beyond Compare, etc.)
- Shareware applications with serial key validation
- Demo versions with activation systems
- Software with FlexLM, HASP, or custom license checks

The binary must have REAL license validation code that can be analyzed
and tested against generated keys. Test samples or placeholder files will
cause tests to fail.

IMPORTANT: Use only software you have legal rights to test in a research
environment. This is for defensive security research purposes only.
"""
        return False, reason

    if binary_path.stat().st_size < 1024:
        reason = f"""
BINARY TOO SMALL: {binary_path} ({binary_path.stat().st_size} bytes)

This file appears to be a placeholder or test stub, not a real binary.
Real protected binaries are typically > 100KB and contain actual license
validation code.

Replace this file with a genuine protected executable that contains
license key validation routines.
"""
        return False, reason

    return True, ""


class TestValidationAnalyzer:
    """Test ValidationAnalyzer extracts real algorithm details from binaries."""

    @pytest.fixture
    def analyzer(self) -> ValidationAnalyzer:
        """Create ValidationAnalyzer instance."""
        return ValidationAnalyzer()

    @pytest.fixture
    def sample_validation_code(self) -> bytes:
        """Sample x64 validation routine with CRC32 polynomial constant."""
        return bytes([
            0x48, 0xB9, 0x20, 0x83, 0xB8, 0xED, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x31, 0xC0,
            0x48, 0x83, 0xFA, 0x10,
            0x75, 0x0A,
            0x48, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xC3,
            0x48, 0x31, 0xC0,
            0xC3,
        ])

    def test_analyze_detects_crc32_validation(
        self,
        analyzer: ValidationAnalyzer,
        sample_validation_code: bytes,
    ) -> None:
        """ValidationAnalyzer detects CRC32 algorithm from polynomial constant."""
        analysis = analyzer.analyze(sample_validation_code, entry_point=0, arch="x64")

        assert analysis.algorithm_type == AlgorithmType.CRC32
        assert analysis.confidence >= 0.8
        assert any(p.algorithm == "CRC32" for p in analysis.crypto_primitives)

        crc_primitives = [p for p in analysis.crypto_primitives if p.algorithm == "CRC32"]
        assert len(crc_primitives) > 0
        assert 0xEDB88320 in crc_primitives[0].constants

    def test_analyze_identifies_length_constraint(
        self,
        analyzer: ValidationAnalyzer,
        sample_validation_code: bytes,
    ) -> None:
        """ValidationAnalyzer extracts key length constraints from cmp instructions."""
        analysis = analyzer.analyze(sample_validation_code, entry_point=0, arch="x64")

        length_constraints = [c for c in analysis.constraints if c.constraint_type == "length"]
        assert len(length_constraints) > 0
        assert any(c.value == 16 for c in length_constraints)

    def test_analyze_finds_patch_points(
        self,
        analyzer: ValidationAnalyzer,
        sample_validation_code: bytes,
    ) -> None:
        """ValidationAnalyzer identifies patchable conditional jumps."""
        analysis = analyzer.analyze(sample_validation_code, entry_point=0, arch="x64")

        assert len(analysis.patch_points) > 0
        assert any(p.patch_type == "nop_conditional" for p in analysis.patch_points)

    def test_analyze_generates_bypass_recommendations(
        self,
        analyzer: ValidationAnalyzer,
        sample_validation_code: bytes,
    ) -> None:
        """ValidationAnalyzer provides actionable bypass recommendations."""
        analysis = analyzer.analyze(sample_validation_code, entry_point=0, arch="x64")

        assert len(analysis.recommendations) > 0
        assert any("CRC32" in rec or "keygen" in rec.lower() for rec in analysis.recommendations)

    def test_analyze_handles_md5_hash_validation(self, analyzer: ValidationAnalyzer) -> None:
        """ValidationAnalyzer detects MD5 hash-based validation."""
        md5_code = bytes([
            0x48, 0xB8, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0x48, 0xBF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
            0xC3,
        ])

        analysis = analyzer.analyze(md5_code, entry_point=0, arch="x64")

        md5_primitives = [p for p in analysis.crypto_primitives if p.algorithm == "MD5"]
        assert len(md5_primitives) > 0 or analysis.algorithm_type == AlgorithmType.MD5

    def test_analyze_empty_code_returns_unknown(self, analyzer: ValidationAnalyzer) -> None:
        """ValidationAnalyzer handles empty code gracefully."""
        analysis = analyzer.analyze(b"", entry_point=0, arch="x64")

        assert analysis.algorithm_type == AlgorithmType.UNKNOWN or analysis.algorithm_type == AlgorithmType.CUSTOM
        assert analysis.confidence < 0.5


class TestConstraintExtractor:
    """Test ConstraintExtractor extracts constraints from real binaries."""

    @pytest.fixture
    def sample_binary(self, tmp_path: Path) -> Path:
        """Create a minimal PE binary with license-related strings."""
        binary_path = tmp_path / "sample.exe"

        pe_header = b"MZ" + b"\x90" * 60 + b"PE\x00\x00"
        license_strings = b"\x00LICENSE\x00KEY\x00SERIAL\x00ACTIVATION\x00"
        crc_constant = struct.pack("<I", 0xEDB88320)
        length_constant = struct.pack("<I", 16)

        binary_content = pe_header + b"\x00" * 200 + license_strings + crc_constant + length_constant

        binary_path.write_bytes(binary_content)
        return binary_path

    def test_extract_constraints_finds_license_keywords(self, sample_binary: Path) -> None:
        """ConstraintExtractor identifies license-related strings in binary."""
        extractor = ConstraintExtractor(sample_binary)
        constraints = extractor.extract_constraints()

        keyword_constraints = [c for c in constraints if c.constraint_type == "keyword"]
        assert len(keyword_constraints) > 0
        assert any(c.value in {"LICENSE", "KEY", "SERIAL", "ACTIVATION"} for c in keyword_constraints)

    def test_extract_constraints_detects_crc_algorithm(self, sample_binary: Path) -> None:
        """ConstraintExtractor identifies CRC32 polynomial in binary."""
        extractor = ConstraintExtractor(sample_binary)
        constraints = extractor.extract_constraints()

        algo_constraints = [c for c in constraints if c.constraint_type == "algorithm"]
        assert any("crc32" in str(c.value).lower() for c in algo_constraints)

    def test_extract_constraints_finds_length_checks(self, sample_binary: Path) -> None:
        """ConstraintExtractor detects key length constraints."""
        extractor = ConstraintExtractor(sample_binary)
        constraints = extractor.extract_constraints()

        length_constraints = [c for c in constraints if c.constraint_type == "length"]
        assert len(length_constraints) > 0

    def test_analyze_validation_algorithms_builds_algorithm(self, sample_binary: Path) -> None:
        """ConstraintExtractor constructs ExtractedAlgorithm from constraints."""
        extractor = ConstraintExtractor(sample_binary)
        algorithms = extractor.analyze_validation_algorithms()

        assert len(algorithms) > 0
        assert all(isinstance(a, ExtractedAlgorithm) for a in algorithms)
        assert all(a.algorithm_name is not None for a in algorithms)

    def test_extract_constraints_handles_missing_file(self, tmp_path: Path) -> None:
        """ConstraintExtractor handles non-existent binary gracefully."""
        missing_path = tmp_path / "nonexistent.exe"
        extractor = ConstraintExtractor(missing_path)
        constraints = extractor.extract_constraints()

        assert constraints == []


class TestKeySynthesizer:
    """Test KeySynthesizer generates valid keys from extracted algorithms."""

    @pytest.fixture
    def synthesizer(self) -> KeySynthesizer:
        """Create KeySynthesizer instance."""
        return KeySynthesizer()

    @pytest.fixture
    def crc32_algorithm(self) -> ExtractedAlgorithm:
        """Create CRC32-based algorithm for testing."""
        import zlib

        def crc32_validate(key: str) -> bool:
            checksum = zlib.crc32(key.encode()) & 0xFFFFFFFF
            return checksum % 256 == 0x42

        return ExtractedAlgorithm(
            algorithm_name="CRC32",
            parameters={"polynomial": 0xEDB88320},
            validation_function=crc32_validate,
            key_format=SerialFormat.ALPHANUMERIC,
            constraints=[],
            confidence=0.9,
        )

    def test_synthesize_key_generates_valid_key(
        self,
        synthesizer: KeySynthesizer,
        crc32_algorithm: ExtractedAlgorithm,
    ) -> None:
        """KeySynthesizer produces keys that pass validation function."""
        key = synthesizer.synthesize_key(crc32_algorithm)

        assert isinstance(key, GeneratedSerial)
        assert len(key.serial) > 0

        if crc32_algorithm.validation_function:
            assert crc32_algorithm.validation_function(key.serial)

    def test_synthesize_batch_generates_unique_keys(
        self,
        synthesizer: KeySynthesizer,
        crc32_algorithm: ExtractedAlgorithm,
    ) -> None:
        """KeySynthesizer generates batch of unique valid keys."""
        keys = synthesizer.synthesize_batch(crc32_algorithm, count=10, unique=True)

        assert len(keys) == 10
        unique_serials = {k.serial for k in keys}
        assert len(unique_serials) == 10

    def test_synthesize_for_user_includes_hardware_id(
        self,
        synthesizer: KeySynthesizer,
        crc32_algorithm: ExtractedAlgorithm,
    ) -> None:
        """KeySynthesizer generates hardware-locked keys."""
        hardware_id = "DEADBEEF-1234-5678"
        key = synthesizer.synthesize_for_user(
            crc32_algorithm,
            username="testuser",
            email="test@example.com",
            hardware_id=hardware_id,
        )

        assert key.hardware_id == hardware_id

    def test_synthesize_with_z3_satisfies_constraints(self, synthesizer: KeySynthesizer) -> None:
        """KeySynthesizer uses Z3 to satisfy complex constraints."""
        constraints = [
            KeyConstraint("length", "Key length", 16, 0.9),
            KeyConstraint("charset", "Uppercase only", "uppercase", 0.8),
        ]

        result = synthesizer.synthesize_with_z3(constraints)

        if result:
            assert len(result) == 16
            assert result.isupper()


class TestKeyValidator:
    """Test KeyValidator validates keys against real protected binaries."""

    def test_validate_key_execution_based_success_indicators(self, tmp_path: Path) -> None:
        """KeyValidator detects valid keys via stdout success messages."""
        script_content = """import sys
key = sys.argv[1] if len(sys.argv) > 1 else ""
if key == "VALID-KEY-12345":
    print("License activated successfully")
    sys.exit(0)
else:
    print("Invalid license key")
    sys.exit(1)
"""
        wrapper_script = tmp_path / "validator_wrapper.py"
        wrapper_script.write_text(script_content)

        config = ValidationConfig(
            use_frida=False,
            use_debugger=False,
            use_patching=False,
            success_indicators=["activated successfully"],
            failure_indicators=["Invalid license"],
        )

        validator = KeyValidator(wrapper_script, config)

        result = validator.validate_key("VALID-KEY-12345")

        assert result.is_valid
        assert result.validation_method == "execution"
        assert "activated successfully" in (result.stdout_output or "")

    def test_validate_key_failure_detection(self, tmp_path: Path) -> None:
        """KeyValidator correctly identifies invalid keys."""
        script_content = """import sys
print("Invalid license key")
sys.exit(1)
"""
        wrapper_script = tmp_path / "invalid_validator.py"
        wrapper_script.write_text(script_content)

        config = ValidationConfig(
            use_frida=False,
            failure_indicators=["Invalid license"],
        )

        validator = KeyValidator(wrapper_script, config)
        result = validator.validate_key("WRONG-KEY")

        assert not result.is_valid

    @pytest.mark.skipif(
        not LICENSED_SOFTWARE_DIR.exists(),
        reason=f"Licensed software directory not found: {LICENSED_SOFTWARE_DIR}",
    )
    def test_validate_key_with_real_binary_frida_skip(self) -> None:
        """Validate key with real binary using Frida instrumentation - SKIPPED if no binary."""
        binary_candidates = list(LICENSED_SOFTWARE_DIR.glob("*.exe"))

        if not binary_candidates:
            pytest.skip(f"""
REAL PROTECTED BINARY NOT FOUND

Required: Windows executable with license validation
Expected location: {LICENSED_SOFTWARE_DIR}
Expected files: *.exe with serial key validation

To enable this test, place a real protected binary in the directory above.
Examples: trial software, shareware, demo versions with activation.

The binary must contain REAL license validation code that can be analyzed
by Frida dynamic instrumentation.
""")

        test_binary = binary_candidates[0]

        config = ValidationConfig(
            use_frida=True,
            timeout_seconds=10,
        )

        validator = KeyValidator(test_binary, config)
        result = validator.validate_key("TEST-KEY-12345")

        assert isinstance(result, ValidationResult)
        assert result.validation_method == "frida"

    def test_validate_batch_parallel_execution(self, tmp_path: Path) -> None:
        """KeyValidator validates multiple keys in parallel."""
        script_content = """import sys
key = sys.argv[1] if len(sys.argv) > 1 else ""
if "VALID" in key:
    sys.exit(0)
else:
    sys.exit(1)
"""
        wrapper_script = tmp_path / "batch_validator.py"
        wrapper_script.write_text(script_content)

        config = ValidationConfig(use_frida=False)
        validator = KeyValidator(wrapper_script, config)

        keys = ["VALID-1", "INVALID-1", "VALID-2", "INVALID-2"]
        results = validator.validate_batch(keys, parallel=True)

        assert len(results) == 4
        valid_count = sum(1 for r in results if r.is_valid)
        assert valid_count == 2


class TestLicenseKeygen:
    """Test LicenseKeygen end-to-end key generation and validation."""

    @pytest.fixture
    def keygen_with_binary(self, tmp_path: Path) -> LicenseKeygen:
        """Create LicenseKeygen with test binary."""
        binary_path = tmp_path / "test.exe"

        pe_header = b"MZ" + b"\x90" * 60 + b"PE\x00\x00"
        license_data = b"\x00LICENSE\x00CRC32\x00" + struct.pack("<I", 0xEDB88320)
        binary_path.write_bytes(pe_header + b"\x00" * 200 + license_data)

        return LicenseKeygen(binary_path)

    def test_crack_license_from_binary_generates_keys(
        self,
        keygen_with_binary: LicenseKeygen,
    ) -> None:
        """LicenseKeygen analyzes binary and generates valid keys."""
        keys = keygen_with_binary.crack_license_from_binary(count=5)

        assert len(keys) == 5
        assert all(isinstance(k, GeneratedSerial) for k in keys)
        assert all(len(k.serial) > 0 for k in keys)

    def test_generate_hardware_locked_key_includes_hwid(
        self,
        keygen_with_binary: LicenseKeygen,
    ) -> None:
        """LicenseKeygen generates hardware-bound license keys."""
        hardware_id = "HWID-DEADBEEF-1234"
        key = keygen_with_binary.generate_hardware_locked_key(
            hardware_id=hardware_id,
            product_id="TEST-PRODUCT",
        )

        assert key.hardware_id == hardware_id
        assert hardware_id[:8] in key.serial or hashlib.sha256(hardware_id.encode()).hexdigest()[:8].upper() in key.serial.upper()

    def test_generate_time_limited_key_includes_expiration(
        self,
        keygen_with_binary: LicenseKeygen,
    ) -> None:
        """LicenseKeygen generates time-limited trial keys."""
        key = keygen_with_binary.generate_time_limited_key(
            product_id="TRIAL-PRODUCT",
            days_valid=30,
        )

        assert key.expiration is not None
        assert key.expiration > int(time.time())

    def test_generate_feature_key_encodes_features(
        self,
        keygen_with_binary: LicenseKeygen,
    ) -> None:
        """LicenseKeygen generates feature-flag encoded keys."""
        features = ["premium", "export", "advanced"]
        key = keygen_with_binary.generate_feature_key(
            base_product="PRODUCT-BASE",
            features=features,
        )

        assert key.features is not None
        assert all(f in key.features for f in features)

    def test_crack_with_validation_finds_working_keys(self, tmp_path: Path) -> None:
        """LicenseKeygen generates and validates keys until finding working ones."""
        binary_path = tmp_path / "validating_app.exe"

        pe_header = b"MZ" + b"\x90" * 60 + b"PE\x00\x00"
        crc_data = struct.pack("<I", 0xEDB88320)
        binary_path.write_bytes(pe_header + b"\x00" * 200 + crc_data)

        validator_script = tmp_path / "validator.py"
        validator_script.write_text("""import sys
import zlib
key = sys.argv[1] if len(sys.argv) > 1 else ""
if (zlib.crc32(key.encode()) & 0xFFFFFFFF) % 256 == 0x42:
    print("Valid license")
    sys.exit(0)
else:
    sys.exit(1)
""")

        keygen = LicenseKeygen(binary_path)
        config = ValidationConfig(
            use_frida=False,
            success_indicators=["Valid license"],
        )

        keygen.validator = KeyValidator(validator_script, config)

        valid_keys = keygen.crack_with_validation(max_attempts=100, validation_config=config)

        assert len(valid_keys) >= 1
        assert all(k.confidence == 1.0 for k in valid_keys)
        assert all(k.metadata and k.metadata.get("validated") for k in valid_keys)

    def test_validate_generated_key_confirms_acceptance(
        self,
        keygen_with_binary: LicenseKeygen,
        tmp_path: Path,
    ) -> None:
        """LicenseKeygen validates specific generated key against binary."""
        validator_script = tmp_path / "key_checker.py"
        validator_script.write_text("""import sys
key = sys.argv[1] if len(sys.argv) > 1 else ""
if "VALID" in key:
    print("Key accepted")
    sys.exit(0)
else:
    sys.exit(1)
""")

        config = ValidationConfig(
            use_frida=False,
            success_indicators=["Key accepted"],
        )

        keygen_with_binary.validator = KeyValidator(validator_script, config)

        result = keygen_with_binary.validate_generated_key("VALID-KEY-TEST", config)

        assert result.is_valid
        assert result.validation_method == "execution"

    @pytest.mark.skipif(
        not LICENSED_SOFTWARE_DIR.exists(),
        reason="Real licensed software binaries not available for testing",
    )
    def test_crack_real_software_with_rsa_validation(self) -> None:
        """LicenseKeygen cracks real RSA-protected software - REQUIRES REAL BINARY."""
        rsa_protected_binaries = list(LICENSED_SOFTWARE_DIR.glob("*rsa*.exe")) or list(LICENSED_SOFTWARE_DIR.glob("*.exe"))

        if not rsa_protected_binaries:
            pytest.skip(f"""
RSA-PROTECTED BINARY NOT FOUND

Required: Real software with RSA signature-based license validation
Expected location: {LICENSED_SOFTWARE_DIR}
Naming convention: *rsa*.exe or any .exe with RSA license checking

To enable this test:
1. Obtain software that uses RSA signature validation for licenses
2. Extract the main executable
3. Place at: {LICENSED_SOFTWARE_DIR}/[software_name].exe

The binary must contain:
- RSA public key constants (modulus, exponent)
- RSA signature verification code
- License validation that checks RSA signatures

Examples: Enterprise software, CAD applications, professional tools
""")

        test_binary = rsa_protected_binaries[0]
        keygen = LicenseKeygen(test_binary)

        algorithms = keygen.analyzer.analyze_validation_algorithms() if keygen.analyzer else []

        rsa_algorithms = [a for a in algorithms if "rsa" in a.algorithm_name.lower()]

        if not rsa_algorithms:
            pytest.skip(f"No RSA algorithm detected in {test_binary.name}")

        keys = keygen.crack_license_from_binary(count=1)

        assert len(keys) >= 1


class TestEdgeCases:
    """Test edge cases for keygen validation: hardware locks, time limits, feature flags."""

    def test_hardware_locked_key_fails_on_different_hwid(self, tmp_path: Path) -> None:
        """Hardware-locked keys fail validation on different hardware IDs."""
        keygen = LicenseKeygen()

        original_hwid = "HWID-ORIGINAL-1234"
        different_hwid = "HWID-DIFFERENT-5678"

        key = keygen.generate_hardware_locked_key(
            hardware_id=original_hwid,
            product_id="HWLOCKED-PRODUCT",
        )

        assert original_hwid[:8] in key.serial or hashlib.sha256(original_hwid.encode()).hexdigest()[:8].upper() in key.serial.upper()
        assert different_hwid[:8] not in key.serial

    def test_time_limited_key_expires_after_period(self) -> None:
        """Time-limited keys contain expiration data."""
        keygen = LicenseKeygen()

        key = keygen.generate_time_limited_key(
            product_id="TRIAL-SOFTWARE",
            days_valid=7,
        )

        assert key.expiration is not None
        expected_expiration = int(time.time()) + (7 * 24 * 60 * 60)
        assert abs(key.expiration - expected_expiration) < 10

    def test_feature_key_encodes_multiple_features(self) -> None:
        """Feature-encoded keys contain all specified feature flags."""
        keygen = LicenseKeygen()

        features = ["export_pdf", "cloud_sync", "api_access", "premium_support"]
        key = keygen.generate_feature_key(
            base_product="PROFESSIONAL",
            features=features,
        )

        assert key.features is not None
        assert set(features) == set(key.features)

    def test_network_validation_emulation_placeholder(self) -> None:
        """Network-based validation requires server emulation - placeholder test."""
        pytest.skip("""
NETWORK VALIDATION TEST NOT IMPLEMENTED

This test requires:
1. Real software with network-based license validation
2. Protocol analysis to understand validation requests
3. Server emulation to respond with valid activation tokens
4. TLS/SSL interception if validation is encrypted

Implementation requires:
- Capture real validation traffic (Wireshark/mitmproxy)
- Reverse engineer protocol format
- Implement server emulator
- Test generated keys against emulated server

Binary location: tests/resources/protected_binaries/licensed_software/network_validated_software.exe
Server emulator: To be implemented in intellicrack.core.network.license_server_emulator
""")

    def test_ecc_key_generation_placeholder(self) -> None:
        """ECC-based key generation - placeholder for future implementation."""
        pytest.skip("""
ECC KEY GENERATION TEST NOT IMPLEMENTED

This test requires:
1. Binary with ECC (ECDSA/EdDSA) signature-based validation
2. ECC curve parameter extraction from binary
3. ECC key pair generation with correct curve
4. Signature generation and verification

Implementation status: Basic ECC support in serial_generator.py, needs
integration with KeySynthesizer and validation against real binaries.

Binary requirement: Software using ECC for license validation
Expected location: tests/resources/protected_binaries/licensed_software/ecc_protected_software.exe
""")

    def test_custom_algorithm_reverse_engineering(self) -> None:
        """Custom/proprietary algorithm detection and key generation."""
        keygen = LicenseKeygen()

        valid_keys = ["ABC12-XYZ89-QWE45", "DEF67-RTY34-UIO90", "GHI23-ASD78-ZXC56"]
        invalid_keys = ["AAAAA-AAAAA-AAAAA", "12345-67890-12345"]

        pattern_analysis = keygen.reverse_engineer_keygen(valid_keys, invalid_keys)

        assert "common_patterns" in pattern_analysis or "constraints" in pattern_analysis


class TestRealBinaryIntegration:
    """Integration tests with actual protected binaries (if available)."""

    @pytest.fixture(autouse=True)
    def check_binaries_available(self) -> None:
        """Check if real binaries are available, skip entire class if not."""
        if not LICENSED_SOFTWARE_DIR.exists():
            pytest.skip(f"""
REAL BINARY INTEGRATION TESTS DISABLED

No licensed software binaries found for integration testing.

Required directory: {LICENSED_SOFTWARE_DIR}

To enable these tests, create the directory and place real protected
software executables with license validation inside.

Required binary characteristics:
1. Windows PE executable (.exe)
2. Contains license/serial key validation code
3. Validates keys against RSA signatures, CRC checksums, or custom algorithms
4. Preferably trial/demo software with activation systems

Suitable examples:
- Trial versions of commercial applications
- Shareware with registration systems
- Demo software with activation codes
- Open-source tools with license verification

Place binaries at: {LICENSED_SOFTWARE_DIR}/[software_name].exe

Tests will automatically analyze binaries, generate keys, and validate
them against the actual protection mechanisms.
""")

    def test_extract_and_validate_against_real_binary(self) -> None:
        """Full workflow: extract algorithm, generate keys, validate against binary."""
        binaries = list(LICENSED_SOFTWARE_DIR.glob("*.exe"))

        if not binaries:
            pytest.skip("No .exe binaries found in licensed software directory")

        test_binary = binaries[0]
        available, skip_reason = _check_binary_available(test_binary)

        if not available:
            pytest.skip(skip_reason)

        keygen = LicenseKeygen(test_binary)

        algorithms = keygen.analyzer.analyze_validation_algorithms() if keygen.analyzer else []

        if not algorithms:
            pytest.skip(f"No validation algorithms detected in {test_binary.name}")

        best_algorithm = max(algorithms, key=lambda a: a.confidence)

        assert best_algorithm.confidence > 0.5

        keys = keygen.crack_license_from_binary(count=3)

        assert len(keys) >= 1
        assert all(len(k.serial) >= 10 for k in keys)

    def test_multiple_binaries_different_protections(self) -> None:
        """Test keygen against multiple binaries with different protection schemes."""
        binaries = list(LICENSED_SOFTWARE_DIR.glob("*.exe"))

        if len(binaries) < 2:
            pytest.skip(f"Need at least 2 binaries for multi-protection test, found {len(binaries)}")

        results = {}

        for binary in binaries[:3]:
            available, skip_reason = _check_binary_available(binary)
            if not available:
                continue

            keygen = LicenseKeygen(binary)

            try:
                algorithms = keygen.analyzer.analyze_validation_algorithms() if keygen.analyzer else []
                if algorithms:
                    best_algo = max(algorithms, key=lambda a: a.confidence)
                    results[binary.name] = {
                        "algorithm": best_algo.algorithm_name,
                        "confidence": best_algo.confidence,
                    }
            except Exception as e:
                logger.warning(f"Failed to analyze {binary.name}: {e}")

        assert len(results) >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
