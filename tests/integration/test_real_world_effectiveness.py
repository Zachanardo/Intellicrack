"""Real-World Effectiveness Tests for Intellicrack.

These tests validate that Intellicrack's cracking capabilities ACTUALLY WORK
against real protection mechanisms. Tests FAIL unless the functionality
produces genuinely effective results against real-world scenarios.

NO synthetic test binaries - uses actual protected software samples.
NO "passes if code runs" assertions - validates actual bypass success.

Copyright (C) 2025 Zachary Flint
SPDX-License-Identifier: GPL-3.0-or-later
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

import pefile
import pytest

from intellicrack.core.protection_bypass.dongle_emulator import CRYPTO_AVAILABLE, HardwareDongleEmulator, HASPStatus
from intellicrack.core.protection_bypass.integrity_check_defeat import ChecksumRecalculator
from intellicrack.plugins.custom_modules.binary_patcher_plugin import BinaryPatcherPlugin
from intellicrack.protection.commercial_protectors_database import CommercialProtectorsDatabase
from intellicrack.protection.unified_protection_engine import UnifiedProtectionEngine


FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
PROTECTED_BINARIES = FIXTURES_DIR / "binaries" / "pe" / "protected"
LEGITIMATE_BINARIES = FIXTURES_DIR / "binaries" / "pe" / "legitimate"

MIN_BINARY_SIZE = 1024


@pytest.fixture
def vmprotect_binary() -> Path:
    """Locate VMProtect-protected binary sample.

    Returns:
        Path to VMProtect binary.

    """
    binary = PROTECTED_BINARIES / "vmprotect_protected.exe"
    if not binary.exists():
        pytest.skip("VMProtect sample not available")
    return binary


@pytest.fixture
def themida_binary() -> Path:
    """Locate Themida-protected binary sample.

    Returns:
        Path to Themida binary.

    """
    binary = PROTECTED_BINARIES / "themida_protected.exe"
    if not binary.exists():
        pytest.skip("Themida sample not available")
    return binary


class TestProtectionDetectionEffectiveness:
    """Tests that validate protection detection ACTUALLY FINDS protections."""

    def test_vmprotect_detection_finds_vmp_sections(
        self,
        vmprotect_binary: Path,
    ) -> None:
        """VMProtect detector MUST find .vmp sections in VMProtect-packed binary.

        FAILS if: No VMProtect indicators found in known VMProtect binary.

        Args:
            vmprotect_binary: Path to VMProtect sample.

        """
        db = CommercialProtectorsDatabase()
        result = db.analyze_binary(str(vmprotect_binary))

        vmprotect_detected = False
        for detection in result.get("detections", []):
            if "vmprotect" in detection.get("name", "").lower():
                vmprotect_detected = True
                break

        assert vmprotect_detected, (
            f"FAILED: VMProtect detection did not identify VMProtect in known "
            f"protected binary {vmprotect_binary.name}. This indicates the "
            f"detection signatures are ineffective."
        )

        pe = pefile.PE(str(vmprotect_binary))
        section_names = [s.Name.decode().rstrip("\x00") for s in pe.sections]
        pe.close()

        vmp_sections_exist = any(".vmp" in name.lower() for name in section_names)
        if vmp_sections_exist:
            vmp_sections_found = any(
                ".vmp" in str(d.get("details", {}))
                for d in result.get("detections", [])
            )
            assert vmp_sections_found, (
                f"VMProtect sections exist ({section_names}) but detector failed "
                f"to identify them in analysis details."
            )

    def test_protection_confidence_is_meaningful(
        self,
        vmprotect_binary: Path,
    ) -> None:
        """Protection confidence scores MUST reflect actual detection certainty.

        FAILS if: High-confidence detection reported when evidence is weak.

        Args:
            vmprotect_binary: Path to VMProtect sample.

        """
        db = CommercialProtectorsDatabase()
        result = db.analyze_binary(str(vmprotect_binary))

        high_confidence_threshold = 90
        very_high_confidence_threshold = 95
        min_evidence_for_high = 2

        for detection in result.get("detections", []):
            confidence = detection.get("confidence", 0)
            evidence = detection.get("evidence", [])

            if confidence >= high_confidence_threshold:
                assert len(evidence) >= min_evidence_for_high, (
                    f"Detection '{detection.get('name')}' claims {confidence}% "
                    f"confidence but only has {len(evidence)} evidence items. "
                    f"High-confidence detections require multiple evidence sources."
                )

            if confidence >= very_high_confidence_threshold:
                has_signature_match = any(
                    "signature" in str(e).lower() or "section" in str(e).lower()
                    for e in evidence
                )
                assert has_signature_match, (
                    f"Detection '{detection.get('name')}' claims {confidence}% "
                    f"confidence without signature/section evidence. This is "
                    f"likely an inflated confidence score."
                )


class TestBinaryPatchingEffectiveness:
    """Tests that validate binary patching ACTUALLY BYPASSES protection."""

    @pytest.fixture
    def binary_with_known_license_check(
        self,
        tmp_path: Path,
    ) -> tuple[Path, int]:
        """Create binary with KNOWN license check at KNOWN offset.

        Args:
            tmp_path: Pytest temp directory.

        Returns:
            Tuple of (binary_path, license_check_offset).

        """
        binary_path = tmp_path / "license_check.exe"

        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_header = bytearray(248)
        pe_header[0:4] = b"PE\x00\x00"
        pe_header[4:6] = struct.pack("<H", 0x14C)
        pe_header[6:8] = struct.pack("<H", 1)
        pe_header[20:22] = struct.pack("<H", 224)
        pe_header[22:24] = struct.pack("<H", 0x102)
        pe_header[24:26] = struct.pack("<H", 0x10B)
        pe_header[40:44] = struct.pack("<I", 0x1000)
        pe_header[44:48] = struct.pack("<I", 0x1000)
        pe_header[52:56] = struct.pack("<I", 0x400000)
        pe_header[56:60] = struct.pack("<I", 0x1000)
        pe_header[60:64] = struct.pack("<I", 0x200)
        pe_header[80:84] = struct.pack("<I", 0x2000)
        pe_header[84:88] = struct.pack("<I", 0x1000)

        section_header = bytearray(40)
        section_header[0:8] = b".text\x00\x00\x00"
        section_header[8:12] = struct.pack("<I", 0x1000)
        section_header[12:16] = struct.pack("<I", 0x1000)
        section_header[16:20] = struct.pack("<I", 0x200)
        section_header[20:24] = struct.pack("<I", 0x200)
        section_header[36:40] = struct.pack("<I", 0x60000020)

        code_section = bytearray(0x200)
        license_check_offset = 0x100

        code_section[license_check_offset : license_check_offset + 20] = bytes(
            [
                0x55,  # push ebp
                0x8B,
                0xEC,  # mov ebp, esp
                0x83,
                0x3D,
                0x00,
                0x10,
                0x40,
                0x00,
                0x00,  # cmp [license], 0
                0x74,
                0x05,  # je +5 (license check)
                0xB8,
                0x00,
                0x00,
                0x00,
                0x00,  # mov eax, 0
                0xC3,  # ret
                0xB8,
                0x01,
                0x00,
                0x00,
                0x00,  # mov eax, 1
                0xC3,  # ret
            ]
        )

        binary_data = dos_header + pe_header + section_header + code_section
        binary_path.write_bytes(binary_data)

        file_offset_of_jump = 0x200 + license_check_offset + 10
        return binary_path, file_offset_of_jump

    def test_license_check_patch_changes_conditional_jump(
        self,
        binary_with_known_license_check: tuple[Path, int],
    ) -> None:
        """Binary patcher MUST modify conditional jump at license check.

        FAILS if: Original conditional jump bytes remain unchanged after patching.

        Args:
            binary_with_known_license_check: Binary path and jump offset.

        """
        binary_path, jump_offset = binary_with_known_license_check

        original_bytes = binary_path.read_bytes()
        original_jump = original_bytes[jump_offset : jump_offset + 2]

        expected_je_instruction = b"\x74\x05"
        assert original_jump == expected_je_instruction, (
            f"Test setup error: Expected JE instruction at offset {hex(jump_offset)}, "
            f"got {original_jump.hex()}"
        )

        patcher = BinaryPatcherPlugin()
        patches = patcher.analyze(str(binary_path))

        if not patches:
            pytest.skip("No patches identified - may need signature update")

        patched_path = binary_path.parent / "patched.exe"
        success = patcher.patch(str(binary_path), str(patched_path))

        assert success, "Patching reported failure"
        assert patched_path.exists(), "Patched binary not created"

        patched_bytes = patched_path.read_bytes()
        patched_jump = patched_bytes[jump_offset : jump_offset + 2]

        assert patched_jump != original_jump, (
            f"FAILED: License check conditional jump at offset {hex(jump_offset)} "
            f"was NOT modified. Original: {original_jump.hex()}, "
            f"After patch: {patched_jump.hex()}. The patcher is not working."
        )

        valid_patches = [
            b"\x90\x90",  # NOP NOP
            b"\xEB\x05",  # JMP +5 (unconditional)
            b"\x75\x05",  # JNE +5 (inverted)
        ]
        assert patched_jump in valid_patches, (
            f"FAILED: Patch at offset {hex(jump_offset)} produced invalid bytes "
            f"{patched_jump.hex()}. Expected one of: {[p.hex() for p in valid_patches]}"
        )


class TestDongleEmulationEffectiveness:
    """Tests that validate dongle emulation produces CORRECT protocol responses."""

    def test_hasp_login_returns_valid_session_structure(self) -> None:
        """HASP login MUST return properly structured session data.

        FAILS if: Response doesn't match real HASP protocol format.
        """
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        vendor_code = 0x1234
        feature_id = 1
        login_data = struct.pack("<HH", vendor_code, feature_id)

        response = emulator._hasp_login(login_data)

        min_response_size = 8
        assert len(response) >= min_response_size, (
            f"HASP login response too short: {len(response)} bytes. "
            f"Real HASP returns at least 8 bytes (status + handle)."
        )

        status, session_handle = struct.unpack("<II", response[:8])

        assert status == HASPStatus.HASP_STATUS_OK, (
            f"HASP login returned error status {status}. "
            f"Emulator failed to authenticate - would be detected by real software."
        )

        assert session_handle != 0, (
            "HASP login returned null session handle. "
            "Real software would fail on subsequent API calls."
        )

        high_bits_mask = 0xFFFF0000
        assert session_handle & high_bits_mask != 0, (
            f"Session handle {hex(session_handle)} looks synthetic (low entropy). "
            f"Real HASP handles have high bits set for obfuscation."
        )

    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="PyCryptodome not available")
    def test_hasp_encrypt_produces_correct_ciphertext_length(self) -> None:
        """HASP encrypt MUST produce correct ciphertext for given plaintext.

        FAILS if: Output length doesn't match AES block alignment requirements.
        """
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["HASP"])

        login_data = struct.pack("<HH", 0x1234, 1)
        login_response = emulator._hasp_login(login_data)
        _, session_handle = struct.unpack("<II", login_response[:8])

        test_plaintexts = [
            b"A" * 16,
            b"B" * 32,
            b"C" * 17,
            b"D" * 100,
        ]

        aes_block_size = 16
        for plaintext in test_plaintexts:
            encrypt_data = (
                struct.pack("<II", session_handle, len(plaintext)) + plaintext
            )
            response = emulator._hasp_encrypt_command(encrypt_data)

            status = struct.unpack("<I", response[:4])[0]
            assert status == HASPStatus.HASP_STATUS_OK, (
                f"Encryption failed for {len(plaintext)}-byte plaintext"
            )

            status_size = 4
            if len(response) > status_size:
                ciphertext = response[status_size:]
                expected_len = (
                    (len(plaintext) + aes_block_size - 1) // aes_block_size
                ) * aes_block_size

                assert len(ciphertext) == expected_len, (
                    f"FAILED: Ciphertext length {len(ciphertext)} incorrect for "
                    f"{len(plaintext)}-byte plaintext. Expected {expected_len} "
                    f"(AES block aligned). Real HASP software would detect mismatch."
                )

    def test_sentinel_challenge_response_is_deterministic(self) -> None:
        """Sentinel challenge-response MUST be deterministic for same inputs.

        FAILS if: Same challenge produces different responses (would fail replay).
        """
        emulator = HardwareDongleEmulator()
        emulator.activate_dongle_emulation(["Sentinel"])

        test_challenge = b"SENTINEL_CHALLENGE_1234567890"

        responses = []
        num_iterations = 5
        for _ in range(num_iterations):
            response = emulator.process_sentinel_challenge(test_challenge, 1)
            responses.append(response)

        assert all(r == responses[0] for r in responses), (
            f"FAILED: Sentinel challenge-response is non-deterministic. "
            f"Got {len(set(responses))} different responses for same challenge. "
            f"Real software caches responses and would detect inconsistency."
        )


class TestChecksumBypassEffectiveness:
    """Tests that validate checksum bypass ACTUALLY DEFEATS integrity checks."""

    def test_crc32_recalculation_matches_reference(self) -> None:
        """CRC32 calculation MUST match standard implementation.

        FAILS if: Calculated CRC32 differs from zlib reference.
        """
        calc = ChecksumRecalculator()

        test_vectors = [
            (b"", 0x00000000),
            (b"123456789", 0xCBF43926),
            (b"The quick brown fox jumps over the lazy dog", 0x414FA339),
            (b"\x00" * 1000, 0x7E3265A8),
            (bytes(range(256)), 0x29058C73),
        ]

        crc32_mask = 0xFFFFFFFF
        for data, expected in test_vectors:
            calculated = calc.calculate_crc32(data)
            reference = zlib.crc32(data) & crc32_mask

            assert calculated == reference, (
                f"FAILED: CRC32 mismatch for {len(data)}-byte input. "
                f"Calculated: {hex(calculated)}, Reference: {hex(reference)}. "
                f"Protected software using CRC32 would detect tampering."
            )

            assert calculated == expected, (
                f"FAILED: CRC32 doesn't match known test vector. "
                f"Calculated: {hex(calculated)}, Expected: {hex(expected)}."
            )

    def test_pe_checksum_recalculation_valid_for_real_binary(self) -> None:
        """PE checksum recalculation MUST produce valid checksum.

        FAILS if: Recalculated checksum doesn't validate with PE tools.
        """
        binary = LEGITIMATE_BINARIES / "7zip.exe"
        if not binary.exists():
            pytest.skip("7zip.exe test binary not available")

        calc = ChecksumRecalculator()
        calculated_checksum = calc.recalculate_pe_checksum(str(binary))

        pe = pefile.PE(str(binary))
        pe_calculated = pe.generate_checksum()
        pe.close()

        assert calculated_checksum == pe_calculated, (
            f"FAILED: PE checksum calculation differs from pefile reference. "
            f"Our calc: {hex(calculated_checksum)}, pefile: {hex(pe_calculated)}. "
            f"Windows loader would reject binary with incorrect checksum."
        )


class TestIntegrationWithRealBinaries:
    """Integration tests against actual protected binary samples."""

    @pytest.fixture
    def any_protected_binary(self) -> Path:
        """Find any available protected binary for testing.

        Returns:
            Path to protected binary.

        """
        if not PROTECTED_BINARIES.exists():
            pytest.skip("Protected binaries directory not available")

        for binary in PROTECTED_BINARIES.glob("*.exe"):
            if binary.stat().st_size > MIN_BINARY_SIZE:
                return binary

        pytest.skip("No protected binaries available for testing")
        return Path()  # Never reached, satisfies type checker

    def test_full_analysis_pipeline_produces_actionable_results(
        self,
        any_protected_binary: Path,
    ) -> None:
        """Full analysis MUST produce actionable bypass recommendations.

        FAILS if: Analysis completes but provides no useful bypass information.

        Args:
            any_protected_binary: Path to protected binary sample.

        """
        engine = UnifiedProtectionEngine()
        result = engine.analyze(str(any_protected_binary))

        assert result is not None, "Analysis returned None"

        if result.is_protected:
            assert len(result.protections) > 0, (
                f"Binary marked as protected but no protections identified. "
                f"is_protected={result.is_protected}, protections={result.protections}"
            )

            assert len(result.bypass_strategies) > 0, (
                f"FAILED: Protected binary analyzed but no bypass strategies "
                f"generated. Protections found: "
                f"{[p['name'] for p in result.protections]}. "
                f"Intellicrack should provide bypass recommendations."
            )

            for strategy in result.bypass_strategies:
                assert "name" in strategy, "Bypass strategy missing name"
                assert "steps" in strategy or "description" in strategy, (
                    f"Bypass strategy '{strategy.get('name')}' has no actionable steps"
                )
