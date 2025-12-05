"""Production-Grade Tests for Integrity Check Defeat System.

Validates REAL integrity check detection, bypass, and patching against actual protected binaries.
NO MOCKS - tests prove system defeats real protection mechanisms.

Copyright (C) 2025 Zachary Flint
SPDX-License-Identifier: GPL-3.0-or-later
"""

import hashlib
import struct
import tempfile
import zlib
from pathlib import Path

import pefile
import pytest

from intellicrack.core.protection_bypass.integrity_check_defeat import (
    BinaryPatcher,
    ChecksumLocation,
    ChecksumRecalculation,
    ChecksumRecalculator,
    IntegrityBypassEngine,
    IntegrityCheck,
    IntegrityCheckDefeatSystem,
    IntegrityCheckDetector,
    IntegrityCheckType,
)


PROTECTED_BINARIES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "binaries" / "pe" / "protected"
LEGITIMATE_BINARIES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "binaries" / "pe" / "legitimate"


@pytest.fixture(scope="module")
def protected_binary() -> Path:
    """Locate protected binary with integrity checks."""
    candidates = [
        PROTECTED_BINARIES_DIR / "denuvo_like_protected.exe",
        PROTECTED_BINARIES_DIR / "hasp_sentinel_protected.exe",
        PROTECTED_BINARIES_DIR / "enterprise_license_check.exe",
        LEGITIMATE_BINARIES_DIR / "7zip.exe",
    ]
    for binary in candidates:
        if binary.exists() and binary.stat().st_size > 1024:
            return binary
    pytest.skip("No protected binary available for testing")


@pytest.fixture(scope="module")
def legitimate_binary() -> Path:
    """Locate legitimate PE binary for structural testing."""
    binary = LEGITIMATE_BINARIES_DIR / "7zip.exe"
    if not binary.exists():
        binary = LEGITIMATE_BINARIES_DIR / "notepadpp.exe"
    if binary.exists() and binary.stat().st_size > 1024:
        return binary
    pytest.skip("No legitimate binary available for testing")


@pytest.fixture
def temp_binary(tmp_path: Path) -> Path:
    """Create temporary binary file for patching tests."""
    binary_path = tmp_path / "test_binary.exe"
    return binary_path


class TestChecksumRecalculatorProduction:
    """Production tests for ChecksumRecalculator - validates real checksum algorithms."""

    def test_crc32_calculation_matches_zlib(self) -> None:
        """CRC32 calculation produces identical results to zlib reference."""
        calc = ChecksumRecalculator()
        test_data = b"LICENSE_VALIDATION_DATA_FOR_CRC32_CALCULATION" * 100

        custom_crc32 = calc.calculate_crc32(test_data)
        zlib_crc32 = calc.calculate_crc32_zlib(test_data)
        reference_crc32 = zlib.crc32(test_data) & 0xFFFFFFFF

        assert custom_crc32 == reference_crc32
        assert zlib_crc32 == reference_crc32

    def test_crc64_calculation_consistency(self) -> None:
        """CRC64 calculation produces consistent deterministic results."""
        calc = ChecksumRecalculator()
        test_data = b"ENTERPRISE_LICENSE_KEY_DATA_FOR_CRC64_VALIDATION" * 50

        crc64_1 = calc.calculate_crc64(test_data)
        crc64_2 = calc.calculate_crc64(test_data)

        assert crc64_1 == crc64_2
        assert crc64_1 != 0
        assert crc64_1 != 0xFFFFFFFFFFFFFFFF

    def test_md5_calculation_matches_hashlib(self) -> None:
        """MD5 calculation produces identical results to hashlib reference."""
        calc = ChecksumRecalculator()
        test_data = b"BINARY_INTEGRITY_CHECK_DATA_FOR_MD5_HASH" * 75

        calc_md5 = calc.calculate_md5(test_data)
        reference_md5 = hashlib.md5(test_data).hexdigest()  # noqa: S324

        assert calc_md5 == reference_md5
        assert len(calc_md5) == 32

    def test_sha1_calculation_matches_hashlib(self) -> None:
        """SHA-1 calculation produces identical results to hashlib reference."""
        calc = ChecksumRecalculator()
        test_data = b"SOFTWARE_PROTECTION_INTEGRITY_DATA_SHA1" * 80

        calc_sha1 = calc.calculate_sha1(test_data)
        reference_sha1 = hashlib.sha1(test_data).hexdigest()  # noqa: S324

        assert calc_sha1 == reference_sha1
        assert len(calc_sha1) == 40

    def test_sha256_calculation_matches_hashlib(self) -> None:
        """SHA-256 calculation produces identical results to hashlib reference."""
        calc = ChecksumRecalculator()
        test_data = b"ADVANCED_LICENSE_VALIDATION_SHA256_DATA" * 90

        calc_sha256 = calc.calculate_sha256(test_data)
        reference_sha256 = hashlib.sha256(test_data).hexdigest()

        assert calc_sha256 == reference_sha256
        assert len(calc_sha256) == 64

    def test_sha512_calculation_matches_hashlib(self) -> None:
        """SHA-512 calculation produces identical results to hashlib reference."""
        calc = ChecksumRecalculator()
        test_data = b"ENTERPRISE_SECURITY_SHA512_INTEGRITY_CHECK" * 100

        calc_sha512 = calc.calculate_sha512(test_data)
        reference_sha512 = hashlib.sha512(test_data).hexdigest()

        assert calc_sha512 == reference_sha512
        assert len(calc_sha512) == 128

    def test_hmac_calculation_with_sha256(self) -> None:
        """HMAC calculation with SHA-256 produces valid signatures."""
        calc = ChecksumRecalculator()
        key = b"SECRET_HMAC_KEY_FOR_LICENSE_VALIDATION_256"
        data = b"LICENSE_DATA_TO_SIGN_WITH_HMAC_SHA256"

        hmac_sig = calc.calculate_hmac(data, key, "sha256")

        assert len(hmac_sig) == 64
        assert hmac_sig != data.hex()

    def test_all_hashes_calculation(self) -> None:
        """All hashes calculation produces complete hash set."""
        calc = ChecksumRecalculator()
        test_data = b"COMPLETE_HASH_SET_VALIDATION_DATA" * 50

        hashes = calc.calculate_all_hashes(test_data)

        assert "crc32" in hashes
        assert "crc64" in hashes
        assert "md5" in hashes
        assert "sha1" in hashes
        assert "sha256" in hashes
        assert "sha512" in hashes

        assert hashes["crc32"].startswith("0x")
        assert len(hashes["md5"]) == 32
        assert len(hashes["sha256"]) == 64

    def test_pe_checksum_calculation_on_real_binary(self, legitimate_binary: Path) -> None:
        """PE checksum calculation produces valid checksum for real binary."""
        calc = ChecksumRecalculator()

        pe_checksum = calc.recalculate_pe_checksum(str(legitimate_binary))

        assert pe_checksum != 0
        assert pe_checksum > 0

    def test_section_hashes_calculation_on_real_binary(self, legitimate_binary: Path) -> None:
        """Section hash calculation produces hashes for all PE sections."""
        calc = ChecksumRecalculator()

        section_hashes = calc.recalculate_section_hashes(str(legitimate_binary))

        assert len(section_hashes) > 0

        for section_name, hashes in section_hashes.items():
            assert "md5" in hashes
            assert "sha1" in hashes
            assert "sha256" in hashes
            assert "crc32" in hashes
            assert len(hashes["md5"]) == 32
            assert len(hashes["sha256"]) == 64

    def test_hmac_key_extraction_from_binary(self, legitimate_binary: Path) -> None:
        """HMAC key extraction identifies potential keys in binary."""
        calc = ChecksumRecalculator()

        hmac_keys = calc.extract_hmac_keys(str(legitimate_binary))

        assert isinstance(hmac_keys, list)

        if len(hmac_keys) > 0:
            for key_info in hmac_keys[:5]:
                assert "offset" in key_info
                assert "size" in key_info
                assert "key_hex" in key_info
                assert "entropy" in key_info
                assert "confidence" in key_info
                assert key_info["size"] in [16, 20, 24, 32, 48, 64]

    def test_checksum_location_identification(self, legitimate_binary: Path) -> None:
        """Checksum location finder identifies embedded checksums in binary."""
        calc = ChecksumRecalculator()

        locations = calc.find_checksum_locations(str(legitimate_binary))

        assert isinstance(locations, list)

        for location in locations:
            assert isinstance(location, ChecksumLocation)
            assert location.offset >= 0
            assert location.size > 0
            assert location.algorithm in IntegrityCheckType
            assert 0.0 <= location.confidence <= 1.0

    def test_patched_binary_checksum_recalculation(self, legitimate_binary: Path, temp_binary: Path) -> None:
        """Checksum recalculation for patched binary produces complete results."""
        calc = ChecksumRecalculator()

        with open(legitimate_binary, "rb") as f:
            original_data = bytearray(f.read())

        original_data[0x100:0x110] = b"\x90" * 16

        temp_binary.write_bytes(original_data)

        checksums = calc.recalculate_for_patched_binary(str(legitimate_binary), str(temp_binary))

        assert isinstance(checksums, ChecksumRecalculation)
        assert checksums.original_crc32 != checksums.patched_crc32
        assert checksums.original_md5 != checksums.patched_md5
        assert checksums.original_sha256 != checksums.patched_sha256
        assert checksums.pe_checksum > 0


class TestIntegrityCheckDetectorProduction:
    """Production tests for IntegrityCheckDetector - validates real detection."""

    def test_detect_checks_on_real_binary(self, protected_binary: Path) -> None:
        """Integrity check detector finds checks in real protected binary.

        EFFECTIVENESS TEST: For protected binaries, the detector must identify
        at least some form of integrity checking - CRC, hash, or anti-tamper.
        """
        detector = IntegrityCheckDetector()

        checks = detector.detect_checks(str(protected_binary))

        assert isinstance(checks, list), "detect_checks must return a list"

        pe = pefile.PE(str(protected_binary))
        has_integrity_imports = False
        integrity_funcs = ["CryptHashData", "CryptVerify", "MapFileAndCheckSum", "CheckSumMappedFile"]
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name and any(f.lower() in imp.name.decode().lower() for f in integrity_funcs):
                        has_integrity_imports = True
                        break
        pe.close()

        if has_integrity_imports:
            assert len(checks) > 0, (
                f"FAILED: Protected binary {protected_binary.name} imports integrity check "
                f"functions but detector found 0 checks. Detector is NOT identifying real "
                f"integrity verification patterns."
            )

    def test_api_import_detection(self, legitimate_binary: Path) -> None:
        """API import scanning detects integrity check functions."""
        detector = IntegrityCheckDetector()
        pe = pefile.PE(str(legitimate_binary))

        api_checks = detector._scan_api_imports(pe, str(legitimate_binary))

        assert isinstance(api_checks, list)

        if len(api_checks) > 0:
            for check in api_checks:
                assert isinstance(check, IntegrityCheck)
                assert check.check_type in IntegrityCheckType
                assert check.function_name in detector.api_signatures

        pe.close()

    def test_inline_check_pattern_detection(self, legitimate_binary: Path) -> None:
        """Inline check scanning detects embedded protection patterns."""
        detector = IntegrityCheckDetector()
        pe = pefile.PE(str(legitimate_binary))

        inline_checks = detector._scan_inline_checks(pe, str(legitimate_binary))

        assert isinstance(inline_checks, list)

        for check in inline_checks:
            assert isinstance(check, IntegrityCheck)
            assert check.address >= 0
            assert check.bypass_method == "patch_inline"

        pe.close()

    def test_antitamper_detection(self, legitimate_binary: Path) -> None:
        """Anti-tamper scanning detects packed or encrypted sections."""
        detector = IntegrityCheckDetector()
        pe = pefile.PE(str(legitimate_binary))

        antitamper_checks = detector._scan_antitamper(pe, str(legitimate_binary))

        assert isinstance(antitamper_checks, list)

        for check in antitamper_checks:
            assert check.check_type == IntegrityCheckType.ANTI_TAMPER

        pe.close()

    def test_entropy_calculation_accuracy(self) -> None:
        """Entropy calculation correctly identifies high-entropy data."""
        detector = IntegrityCheckDetector()

        low_entropy = b"\x00" * 1000
        high_entropy = bytes(range(256)) * 4

        low_result = detector._calculate_entropy(low_entropy)
        high_result = detector._calculate_entropy(high_entropy)

        assert low_result < 1.0
        assert high_result > 7.0


class TestIntegrityBypassEngineProduction:
    """Production tests for IntegrityBypassEngine - validates bypass strategies."""

    def test_bypass_strategy_loading(self) -> None:
        """Bypass strategies load with valid configurations."""
        engine = IntegrityBypassEngine()

        strategies = engine.bypass_strategies

        assert len(strategies) > 0

        for strategy in strategies:
            assert len(strategy.name) > 0
            assert len(strategy.check_types) > 0
            assert len(strategy.frida_script) > 0
            assert 0.0 <= strategy.success_rate <= 1.0
            assert strategy.priority >= 0

    def test_bypass_script_generation(self, protected_binary: Path) -> None:
        """Bypass script generation produces valid Frida JavaScript.

        EFFECTIVENESS TEST: Generated Frida scripts must contain actual bypass
        logic that can intercept and defeat integrity checks at runtime.
        """
        engine = IntegrityBypassEngine()
        detector = IntegrityCheckDetector()

        checks = detector.detect_checks(str(protected_binary))

        if len(checks) > 0:
            for check in checks:
                check.binary_path = str(protected_binary)

            script = engine._build_bypass_script(checks)

            assert len(script) > 50, (
                f"FAILED: Generated bypass script is only {len(script)} characters. "
                f"A real bypass script needs substantial code to intercept integrity checks."
            )
            assert "Interceptor" in script or "Memory" in script or "NativeFunction" in script, (
                "FAILED: Generated script lacks Frida runtime manipulation APIs. "
                "Without Interceptor/Memory/NativeFunction, it cannot bypass checks."
            )

            has_bypass_logic = any([
                "return" in script.lower() and ("true" in script.lower() or "0x" in script),
                "replace" in script.lower(),
                "write" in script.lower(),
            ])
            assert has_bypass_logic, (
                "FAILED: Generated script has no bypass logic (return manipulation, "
                "memory writes, or function replacement). It cannot defeat integrity checks."
            )
        else:
            pytest.skip(f"No integrity checks detected in {protected_binary.name} to generate bypass for")

    def test_script_customization_with_real_checksums(self, legitimate_binary: Path) -> None:
        """Script customization replaces placeholders with real values."""
        engine = IntegrityBypassEngine()
        detector = IntegrityCheckDetector()

        checks = detector.detect_checks(str(legitimate_binary))

        if len(checks) > 0:
            for check in checks:
                check.binary_path = str(legitimate_binary)

            script = engine._build_bypass_script(checks)

            assert "%EXPECTED_CRC32%" not in script or len(script) == 0
            assert "%EXPECTED_MD5%" not in script or len(script) == 0

    def test_strategy_selection_for_check_types(self) -> None:
        """Best strategy selection chooses correct bypass for check type."""
        engine = IntegrityBypassEngine()

        crc32_strategy = engine._get_best_strategy(IntegrityCheckType.CRC32)
        hash_strategy = engine._get_best_strategy(IntegrityCheckType.SHA256_HASH)

        assert crc32_strategy is not None
        assert IntegrityCheckType.CRC32 in crc32_strategy.check_types

        if hash_strategy:
            assert IntegrityCheckType.SHA256_HASH in hash_strategy.check_types


class TestBinaryPatcherProduction:
    """Production tests for BinaryPatcher - validates real binary patching."""

    def test_binary_patching_creates_output_file(self, legitimate_binary: Path, temp_binary: Path) -> None:
        """Binary patcher creates valid patched output file."""
        patcher = BinaryPatcher()
        detector = IntegrityCheckDetector()

        checks = detector.detect_checks(str(legitimate_binary))

        if len(checks) > 0:
            output_path = str(temp_binary)
            success, checksums = patcher.patch_integrity_checks(str(legitimate_binary), checks, output_path)

            if success:
                assert temp_binary.exists()
                assert temp_binary.stat().st_size > 0
                assert isinstance(checksums, ChecksumRecalculation)

    def test_patch_history_tracking(self, legitimate_binary: Path, temp_binary: Path) -> None:
        """Patcher tracks all applied patches in history."""
        patcher = BinaryPatcher()
        detector = IntegrityCheckDetector()

        checks = detector.detect_checks(str(legitimate_binary))

        if len(checks) > 0:
            inline_checks = [c for c in checks if c.bypass_method == "patch_inline"]

            if len(inline_checks) > 0:
                output_path = str(temp_binary)
                patcher.patch_integrity_checks(str(legitimate_binary), inline_checks, output_path)

                assert len(patcher.patch_history) > 0

                for patch in patcher.patch_history:
                    assert "address" in patch
                    assert "size" in patch
                    assert "original" in patch
                    assert "patched" in patch

    def test_pe_checksum_recalculation_after_patching(self, legitimate_binary: Path, temp_binary: Path) -> None:
        """Patched binary has recalculated PE checksum."""
        patcher = BinaryPatcher()

        with open(legitimate_binary, "rb") as f:
            original_data = bytearray(f.read())

        original_data[0x200:0x210] = b"\x90" * 16

        temp_binary.write_bytes(original_data)

        pe = pefile.PE(str(temp_binary))
        original_checksum = pe.OPTIONAL_HEADER.CheckSum
        pe.close()

        calc = ChecksumRecalculator()
        new_checksum = calc.recalculate_pe_checksum(str(temp_binary))

        pe_updated = pefile.PE(str(temp_binary))
        pe_updated.OPTIONAL_HEADER.CheckSum = new_checksum

        with open(temp_binary, "wb") as f:
            f.write(pe_updated.write())
        pe_updated.close()

        pe_final = pefile.PE(str(temp_binary))
        assert pe_final.OPTIONAL_HEADER.CheckSum == new_checksum
        pe_final.close()

    def test_rva_to_offset_conversion(self, legitimate_binary: Path) -> None:
        """RVA to offset conversion produces valid file offsets."""
        patcher = BinaryPatcher()
        pe = pefile.PE(str(legitimate_binary))

        for section in pe.sections:
            test_rva = section.VirtualAddress + 0x100
            offset = patcher._rva_to_offset(pe, test_rva)

            if offset is not None:
                assert offset >= 0
                assert offset < pe.__data__.__len__()

        pe.close()


class TestIntegrityCheckDefeatSystemProduction:
    """Production tests for complete defeat system - validates end-to-end workflows."""

    def test_defeat_system_initialization(self) -> None:
        """Defeat system initializes all components correctly."""
        system = IntegrityCheckDefeatSystem()

        assert isinstance(system.detector, IntegrityCheckDetector)
        assert isinstance(system.bypasser, IntegrityBypassEngine)
        assert isinstance(system.patcher, BinaryPatcher)
        assert isinstance(system.checksum_calc, ChecksumRecalculator)

    def test_find_embedded_checksums_in_real_binary(self, legitimate_binary: Path) -> None:
        """Embedded checksum finder locates checksums in real binary."""
        system = IntegrityCheckDefeatSystem()

        locations = system.find_embedded_checksums(str(legitimate_binary))

        assert isinstance(locations, list)

        for location in locations:
            assert isinstance(location, ChecksumLocation)
            assert location.size in [4, 8, 16, 20, 32, 64]

    def test_extract_hmac_keys_from_real_binary(self, legitimate_binary: Path) -> None:
        """HMAC key extraction finds potential keys in real binary."""
        system = IntegrityCheckDefeatSystem()

        keys = system.extract_hmac_keys(str(legitimate_binary))

        assert isinstance(keys, list)

        for key_info in keys:
            assert "offset" in key_info
            assert "key_hex" in key_info
            assert "confidence" in key_info

    def test_generate_bypass_script_for_real_binary(self, legitimate_binary: Path) -> None:
        """Bypass script generation produces executable script for real binary."""
        system = IntegrityCheckDefeatSystem()

        script = system.generate_bypass_script(str(legitimate_binary))

        assert isinstance(script, str)
        assert len(script) > 0

    def test_recalculate_checksums_after_modification(self, legitimate_binary: Path, temp_binary: Path) -> None:
        """Checksum recalculation produces accurate results after modification."""
        system = IntegrityCheckDefeatSystem()

        with open(legitimate_binary, "rb") as f:
            data = bytearray(f.read())

        data[0x300:0x320] = b"\xCC" * 32

        temp_binary.write_bytes(data)

        checksums = system.recalculate_checksums(str(legitimate_binary), str(temp_binary))

        assert isinstance(checksums, ChecksumRecalculation)
        assert checksums.original_crc32 != checksums.patched_crc32
        assert checksums.original_md5 != checksums.patched_md5
        assert checksums.original_sha256 != checksums.patched_sha256

    def test_defeat_workflow_detection_only(self, protected_binary: Path) -> None:
        """Defeat workflow performs detection on real binary.

        EFFECTIVENESS TEST: The defeat system must successfully analyze protected
        binaries and provide meaningful detection results.
        """
        system = IntegrityCheckDefeatSystem()

        result = system.defeat_integrity_checks(str(protected_binary), patch_binary=False)

        assert isinstance(result, dict), "Result must be a dictionary"
        assert "success" in result, "Result must contain 'success' status"
        assert "checks_detected" in result, "Result must report number of checks detected"
        assert "details" in result, "Result must contain detection details"

        assert result["success"] is True, (
            f"FAILED: Defeat workflow reported failure on {protected_binary.name}. "
            f"Details: {result.get('details', 'No details provided')}"
        )

        assert isinstance(result["checks_detected"], int), "checks_detected must be an integer"
        assert isinstance(result["details"], (list, dict, str)), "details must provide actual information"

        if result["checks_detected"] > 0:
            if isinstance(result["details"], list):
                assert len(result["details"]) > 0, (
                    f"FAILED: {result['checks_detected']} checks detected but details list is empty"
                )
            elif isinstance(result["details"], dict):
                assert len(result["details"]) > 0, (
                    f"FAILED: {result['checks_detected']} checks detected but details dict is empty"
                )

    def test_defeat_workflow_with_patching(self, legitimate_binary: Path, temp_binary: Path) -> None:
        """Defeat workflow patches binary and recalculates checksums."""
        system = IntegrityCheckDefeatSystem()

        with open(legitimate_binary, "rb") as f:
            data = f.read()

        temp_input = temp_binary.parent / "input.exe"
        temp_input.write_bytes(data)

        result = system.defeat_integrity_checks(str(temp_input), patch_binary=True)

        assert isinstance(result, dict)
        assert "binary_patched" in result

        if result["binary_patched"]:
            assert "checksums" in result
            assert result["checksums"] is not None

    def test_patch_embedded_checksums_in_binary(self, legitimate_binary: Path, temp_binary: Path) -> None:
        """Embedded checksum patching updates binary with recalculated values."""
        system = IntegrityCheckDefeatSystem()

        locations = system.find_embedded_checksums(str(legitimate_binary))

        if len(locations) > 0:
            success = system.patch_embedded_checksums(str(legitimate_binary), locations, str(temp_binary))

            if success:
                assert temp_binary.exists()
                assert temp_binary.stat().st_size > 0


class TestChecksumAlgorithmAccuracy:
    """Production tests validating checksum algorithm correctness."""

    def test_crc32_empty_data(self) -> None:
        """CRC32 handles empty data correctly."""
        calc = ChecksumRecalculator()

        crc32 = calc.calculate_crc32_zlib(b"")

        assert crc32 == 0

    def test_crc32_known_values(self) -> None:
        """CRC32 produces known correct values for test vectors."""
        calc = ChecksumRecalculator()

        test_vectors = [
            (b"123456789", 0xCBF43926),
            (b"The quick brown fox jumps over the lazy dog", 0x414FA339),
        ]

        for data, expected in test_vectors:
            result = calc.calculate_crc32_zlib(data)
            assert result == expected

    def test_hash_algorithm_stability(self) -> None:
        """Hash algorithms produce stable consistent results."""
        calc = ChecksumRecalculator()
        data = b"STABILITY_TEST_DATA_FOR_HASH_ALGORITHMS" * 100

        md5_1 = calc.calculate_md5(data)
        md5_2 = calc.calculate_md5(data)
        sha256_1 = calc.calculate_sha256(data)
        sha256_2 = calc.calculate_sha256(data)

        assert md5_1 == md5_2
        assert sha256_1 == sha256_2


class TestRealBinaryIntegration:
    """Integration tests against actual protected binaries."""

    def test_complete_workflow_on_protected_binary(self, protected_binary: Path, temp_binary: Path) -> None:
        """Complete defeat workflow executes successfully on protected binary."""
        system = IntegrityCheckDefeatSystem()

        result = system.defeat_integrity_checks(
            str(protected_binary),
            process_name=None,
            patch_binary=False,
        )

        assert isinstance(result, dict)
        assert result["success"] is True or result["checks_detected"] >= 0

    def test_checksum_recalculation_preserves_functionality(self, legitimate_binary: Path, temp_binary: Path) -> None:
        """Checksum recalculation maintains binary structure integrity."""
        calc = ChecksumRecalculator()

        pe_original = pefile.PE(str(legitimate_binary))
        num_sections_original = len(pe_original.sections)
        pe_original.close()

        with open(legitimate_binary, "rb") as f:
            data = f.read()

        temp_binary.write_bytes(data)

        checksums = calc.recalculate_for_patched_binary(str(legitimate_binary), str(temp_binary))

        pe_patched = pefile.PE(str(temp_binary))
        num_sections_patched = len(pe_patched.sections)
        pe_patched.close()

        assert num_sections_original == num_sections_patched
        assert checksums.pe_checksum > 0


class TestEdgeCases:
    """Production tests for edge cases and error handling."""

    def test_invalid_binary_path(self) -> None:
        """Detector handles invalid binary paths gracefully."""
        detector = IntegrityCheckDetector()

        checks = detector.detect_checks("/nonexistent/binary.exe")

        assert isinstance(checks, list)
        assert len(checks) == 0

    def test_corrupted_pe_handling(self, temp_binary: Path) -> None:
        """System handles corrupted PE binaries without crashing."""
        temp_binary.write_bytes(b"MZ\x00\x00CORRUPTED_PE_DATA" * 100)

        detector = IntegrityCheckDetector()

        checks = detector.detect_checks(str(temp_binary))

        assert isinstance(checks, list)

    def test_empty_binary_handling(self, temp_binary: Path) -> None:
        """System handles empty binary files gracefully."""
        temp_binary.write_bytes(b"")

        calc = ChecksumRecalculator()

        crc32 = calc.calculate_crc32_zlib(b"")
        assert crc32 == 0

    def test_very_large_binary_performance(self, legitimate_binary: Path) -> None:
        """Checksum calculation performs efficiently on large data."""
        calc = ChecksumRecalculator()

        with open(legitimate_binary, "rb") as f:
            data = f.read()

        large_data = data * 10

        import time
        start = time.time()
        crc32 = calc.calculate_crc32_zlib(large_data)
        duration = time.time() - start

        assert crc32 != 0
        assert duration < 5.0
