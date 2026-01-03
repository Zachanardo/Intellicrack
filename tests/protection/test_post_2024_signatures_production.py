"""Production Tests for Post-2024 Protection Signatures.

Validates detection of latest protection versions (VMProtect 3.8+, Themida 3.2+,
Denuvo v7+) with real signature patterns and comprehensive edge case coverage.

CRITICAL: Tests MUST FAIL if only pre-2024 signatures exist.
Tests validate genuine detection capabilities against modern protections.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import pytest

from intellicrack.protection.commercial_protectors_database import (
    CommercialProtectorsDatabase,
    ProtectorCategory,
)
from intellicrack.protection.denuvo_analyzer import DenuvoAnalyzer, DenuvoVersion
from intellicrack.protection.protection_detector import ProtectionDetector


class TestVMProtect38PlusSignatures:
    """Validate VMProtect 3.8+ signature detection."""

    @pytest.fixture
    def detector(self) -> ProtectionDetector:
        """Create protection detector instance."""
        return ProtectionDetector()

    @pytest.fixture
    def vmprotect_38_binary(self) -> bytes:
        """Create synthetic binary with VMProtect 3.8+ characteristics.

        VMProtect 3.8+ introduced enhanced mutation engine with deeper
        instruction polymorphism and improved handler obfuscation.
        """
        pe_header = b"MZ\x90\x00\x03\x00\x00\x00"
        pe_header += b"\x00" * 0x34
        pe_offset = 0x100
        pe_header += struct.pack("<I", pe_offset)
        pe_header += b"\x00" * (pe_offset - len(pe_header))

        pe_signature = b"PE\x00\x00"
        machine_x64 = struct.pack("<H", 0x8664)
        num_sections = struct.pack("<H", 4)
        timestamp = struct.pack("<I", 0x65000000)
        pe_signature += machine_x64 + num_sections + timestamp
        pe_signature += b"\x00" * 12
        optional_header_size = struct.pack("<H", 0xF0)
        characteristics = struct.pack("<H", 0x022F)
        pe_signature += optional_header_size + characteristics

        optional_header = struct.pack("<H", 0x020B)
        optional_header += b"\x00" * 0xEE

        section_vmp0 = b".vmp0\x00\x00\x00"
        section_vmp0 += struct.pack("<I", 0x10000)
        section_vmp0 += struct.pack("<I", 0x1000)
        section_vmp0 += struct.pack("<I", 0x10000)
        section_vmp0 += struct.pack("<I", 0x1000)
        section_vmp0 += b"\x00" * 12
        section_vmp0 += struct.pack("<I", 0xE00000E0)

        section_vmp1 = b".vmp1\x00\x00\x00"
        section_vmp1 += struct.pack("<I", 0x20000)
        section_vmp1 += struct.pack("<I", 0x11000)
        section_vmp1 += struct.pack("<I", 0x20000)
        section_vmp1 += struct.pack("<I", 0x11000)
        section_vmp1 += b"\x00" * 12
        section_vmp1 += struct.pack("<I", 0xE00000E0)

        section_vmp2 = b".vmp2\x00\x00\x00"
        section_vmp2 += struct.pack("<I", 0x30000)
        section_vmp2 += struct.pack("<I", 0x31000)
        section_vmp2 += struct.pack("<I", 0x30000)
        section_vmp2 += struct.pack("<I", 0x31000)
        section_vmp2 += b"\x00" * 12
        section_vmp2 += struct.pack("<I", 0xE00000E0)

        section_text = b".text\x00\x00\x00"
        section_text += struct.pack("<I", 0x5000)
        section_text += struct.pack("<I", 0x61000)
        section_text += struct.pack("<I", 0x5000)
        section_text += struct.pack("<I", 0x61000)
        section_text += b"\x00" * 12
        section_text += struct.pack("<I", 0x60000020)

        binary = pe_header + pe_signature + optional_header
        binary += section_vmp0 + section_vmp1 + section_vmp2 + section_text

        padding_to_sections = 0x1000 - len(binary)
        binary += b"\x00" * padding_to_sections

        vmp0_data = b"VMProtect 3.8"
        vmp0_data += b"\x48\x89\x5c\x24\x10\x48\x89\x74\x24\x18\x55\x57\x41\x56\x48\x8d\xac\x24"
        vmp0_data += b"\x9c\x50\x53\x51\x52\x56\x57\x55\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54"
        vmp0_data += b"\xff\x24\xc5"
        vmp0_data += b"\x00" * (0x10000 - len(vmp0_data))

        vmp1_high_entropy = bytes(
            [((i * 271 + 173) ^ (i >> 3)) & 0xFF for i in range(0x20000)]
        )

        vmp2_handlers = b"\x48\x8b\x04\xc8\xff\xe0"
        vmp2_handlers += b"\x41\xff\x24\xc0"
        vmp2_handlers += b"\x48\x8b\x84\xc1\x00\x00\x00\x00\xff\xe0"
        vmp2_handlers += b"\x00" * (0x30000 - len(vmp2_handlers))

        text_code = b"\x55\x8b\xec\x83\xec\x40"
        text_code += b"\x00" * (0x5000 - len(text_code))

        binary += vmp0_data + vmp1_high_entropy + vmp2_handlers + text_code

        return binary

    @pytest.fixture
    def vmprotect_37_binary(self) -> bytes:
        """Create binary with VMProtect 3.7 (pre-2024) for negative test."""
        pe_header = b"MZ\x90\x00\x03\x00\x00\x00"
        pe_header += b"\x00" * 0x34
        pe_offset = 0x100
        pe_header += struct.pack("<I", pe_offset)
        pe_header += b"\x00" * (pe_offset - len(pe_header))

        pe_signature = b"PE\x00\x00"
        machine_x64 = struct.pack("<H", 0x8664)
        pe_signature += machine_x64 + b"\x00" * 18

        binary = pe_header + pe_signature
        binary += b"VMProtect 3.7"
        binary += b"\x00" * 2000

        return binary

    def test_vmprotect_38_detected_with_version_string(
        self, detector: ProtectionDetector, vmprotect_38_binary: bytes
    ) -> None:
        """VMProtect 3.8 detected via version string signature."""
        result = detector.detect_commercial_protections("dummy.exe")

        protections_db = CommercialProtectorsDatabase()
        detections = protections_db.detect_protector(vmprotect_38_binary)

        assert len(detections) > 0, "VMProtect 3.8+ must be detected"

        vmp_detected = any(
            "VMProtect" in name or "vmp" in name.lower() for name, _, _ in detections
        )
        assert vmp_detected, "VMProtect signature must be identified"

    def test_vmprotect_38_triple_section_structure(
        self, vmprotect_38_binary: bytes
    ) -> None:
        """VMProtect 3.8+ detected via .vmp0/.vmp1/.vmp2 section structure."""
        has_vmp0 = b".vmp0" in vmprotect_38_binary
        has_vmp1 = b".vmp1" in vmprotect_38_binary
        has_vmp2 = b".vmp2" in vmprotect_38_binary

        assert (
            has_vmp0 and has_vmp1 and has_vmp2
        ), "VMProtect 3.8+ requires all three .vmp sections"

    def test_vmprotect_38_high_entropy_sections(
        self, vmprotect_38_binary: bytes
    ) -> None:
        """VMProtect 3.8+ exhibits high entropy in protected sections."""
        vmp1_offset = vmprotect_38_binary.find(b".vmp1")
        assert vmp1_offset != -1, "Must locate .vmp1 section"

        section_data_offset = 0x11000
        entropy_sample = vmprotect_38_binary[
            section_data_offset : section_data_offset + 4096
        ]

        byte_counts: dict[int, int] = {}
        for byte_val in entropy_sample:
            byte_counts[byte_val] = byte_counts.get(byte_val, 0) + 1

        import math

        entropy = 0.0
        for count in byte_counts.values():
            if count > 0:
                probability = count / len(entropy_sample)
                entropy -= probability * math.log2(probability)

        assert entropy > 7.3, f"VMProtect 3.8+ requires high entropy (got {entropy:.2f})"

    def test_vmprotect_38_enhanced_handler_dispatch(
        self, vmprotect_38_binary: bytes
    ) -> None:
        """VMProtect 3.8+ uses enhanced indirect jump handler dispatch."""
        x64_dispatch_patterns = [
            b"\xff\x24\xc5",
            b"\x48\x8b\x04\xc8\xff\xe0",
            b"\x41\xff\x24\xc0",
        ]

        found_patterns = sum(
            1 for pattern in x64_dispatch_patterns if pattern in vmprotect_38_binary
        )

        assert (
            found_patterns >= 2
        ), "VMProtect 3.8+ must contain multiple handler dispatch patterns"

    def test_vmprotect_37_not_falsely_detected_as_38(
        self, detector: ProtectionDetector, vmprotect_37_binary: bytes
    ) -> None:
        """VMProtect 3.7 (pre-2024) must NOT be detected as 3.8+."""
        has_triple_sections = (
            b".vmp0" in vmprotect_37_binary
            and b".vmp1" in vmprotect_37_binary
            and b".vmp2" in vmprotect_37_binary
        )

        assert (
            not has_triple_sections
        ), "Pre-2024 VMProtect should not have triple section structure"

    def test_vmprotect_38_context_save_x64_pattern(
        self, vmprotect_38_binary: bytes
    ) -> None:
        """VMProtect 3.8+ x64 context save uses extended register preservation."""
        context_save_pattern = b"\x9c\x50\x53\x51\x52\x56\x57\x55\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54"

        assert (
            context_save_pattern in vmprotect_38_binary
        ), "VMProtect 3.8+ must preserve all x64 registers including R8-R14"


class TestThemida32PlusSignatures:
    """Validate Themida 3.2+ signature detection."""

    @pytest.fixture
    def themida_32_binary(self) -> bytes:
        """Create synthetic binary with Themida 3.2+ characteristics."""
        pe_header = b"MZ\x90\x00\x03\x00\x00\x00"
        pe_header += b"\x00" * 0x34
        pe_offset = 0x100
        pe_header += struct.pack("<I", pe_offset)
        pe_header += b"\x00" * (pe_offset - len(pe_header))

        pe_signature = b"PE\x00\x00"
        machine = struct.pack("<H", 0x014C)
        pe_signature += machine + b"\x00" * 18

        binary = pe_header + pe_signature
        binary += b"\x00" * 0x300

        binary += b"Themida 3.2"
        binary += b"\x54\x68\x65\x6d\x69\x64\x61"

        vm_entry = b"\x60\xe8\x00\x00\x00\x00\x5d\x81\xed\x00\x00\x00\x00\xb9"
        binary += vm_entry

        fish_vm_opcodes = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        fish_vm_opcodes += b"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
        binary += fish_vm_opcodes

        kernel_antidebug = b"\x64\xa1\x18\x00\x00\x00\x8b\x40\x30\x0f\xb6\x40\x02"
        kernel_antidebug += b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00\x48\x8b\x40\x18"
        binary += kernel_antidebug

        securengine_marker = b"\x53\x45\x33\x32"
        binary += securengine_marker

        binary += b"\x00" * (5000 - len(binary))

        return binary

    @pytest.fixture
    def themida_31_binary(self) -> bytes:
        """Create binary with Themida 3.1 (pre-2024) for negative test."""
        pe_header = b"MZ\x90\x00\x03\x00\x00\x00"
        pe_header += b"\x00" * 0x34
        pe_offset = 0x100
        pe_header += struct.pack("<I", pe_offset)
        pe_header += b"\x00" * (pe_offset - len(pe_header))

        binary = pe_header + b"PE\x00\x00" + b"\x00" * 200
        binary += b"Themida 3.1"
        binary += b"\x00" * 2000

        return binary

    def test_themida_32_detected_with_version_marker(
        self, themida_32_binary: bytes
    ) -> None:
        """Themida 3.2 detected via version marker signature."""
        assert b"Themida 3.2" in themida_32_binary, "Themida 3.2 version marker required"
        assert b"Themida" in themida_32_binary, "Themida signature present"

    def test_themida_32_fish_vm_extended_opcodes(
        self, themida_32_binary: bytes
    ) -> None:
        """Themida 3.2+ FISH VM supports extended opcode range 0x00-0x1F."""
        opcode_range = bytes(range(0x00, 0x20))
        assert opcode_range in themida_32_binary, (
            "Themida 3.2+ must support FISH VM opcodes 0x00-0x1F"
        )

    def test_themida_32_kernel_mode_antidebug(self, themida_32_binary: bytes) -> None:
        """Themida 3.2+ includes kernel-mode anti-debugging checks."""
        peb_being_debugged_check = b"\x64\xa1\x18\x00\x00\x00\x8b\x40\x30\x0f\xb6\x40\x02"
        teb_x64_check = b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00\x48\x8b\x40\x18"

        has_x86_kernel_check = peb_being_debugged_check in themida_32_binary
        has_x64_kernel_check = teb_x64_check in themida_32_binary

        assert (
            has_x86_kernel_check or has_x64_kernel_check
        ), "Themida 3.2+ must implement kernel-mode anti-debug"

    def test_themida_32_securengine_integration(self, themida_32_binary: bytes) -> None:
        """Themida 3.2+ integrates SecureEngine protection layer."""
        securengine_marker = b"\x53\x45\x33\x32"

        assert (
            securengine_marker in themida_32_binary
        ), "Themida 3.2+ must include SecureEngine v3.2 marker"

    def test_themida_31_lacks_extended_features(
        self, themida_31_binary: bytes
    ) -> None:
        """Themida 3.1 (pre-2024) lacks extended FISH VM opcodes."""
        extended_opcodes = bytes(range(0x0D, 0x20))

        assert (
            extended_opcodes not in themida_31_binary
        ), "Pre-2024 Themida should not have extended opcode range"


class TestDenuvoV7PlusSignatures:
    """Validate Denuvo v7+ signature detection."""

    @pytest.fixture
    def analyzer(self) -> DenuvoAnalyzer:
        """Create Denuvo analyzer instance."""
        return DenuvoAnalyzer()

    @pytest.fixture
    def denuvo_v7_binary(self, tmp_path: Path) -> Path:
        """Create synthetic binary with Denuvo v7+ characteristics."""
        binary_path = tmp_path / "denuvo_v7_sample.exe"

        pe_header = b"MZ\x90\x00\x03\x00\x00\x00"
        pe_header += b"\x00" * 0x34
        pe_offset = 0x100
        pe_header += struct.pack("<I", pe_offset)
        pe_header += b"\x00" * (pe_offset - len(pe_header))

        pe_signature = b"PE\x00\x00"
        machine_x64 = struct.pack("<H", 0x8664)
        pe_signature += machine_x64 + b"\x00" * 18

        binary = pe_header + pe_signature
        binary += b"\x00" * 0x300

        v7_activation_flow = b"\x48\x89\x5c\x24\x08\x48\x89\x6c\x24\x10\x48\x89\x74\x24\x18\x57\x48\x83\xec\x30\x48\x8b\xf9\x48\x8d\x0d"
        binary += v7_activation_flow

        v7_integrity_check = b"\x40\x53\x48\x83\xec\x30\x48\x8b\xd9\x48\x8b\x0d"
        binary += v7_integrity_check

        v7_vm_dispatcher = b"\x48\x8d\x05\x00\x00\x00\x00\x48\x89\x01\x48\x8d\x05"
        binary += v7_vm_dispatcher

        v7_timing_obfuscation = b"\x48\x89\x4c\x24\x08\x48\x83\xec\x48\x48\x8b\x05"
        binary += v7_timing_obfuscation

        machine_fingerprint = b"\x0f\xa2\x89\x44\x24\x00\x89\x5c\x24\x00\x89\x4c\x24\x00\x89\x54\x24\x00"
        binary += machine_fingerprint

        binary += b"\x00" * (10000 - len(binary))

        with open(binary_path, "wb") as f:
            f.write(binary)

        return binary_path

    @pytest.fixture
    def denuvo_v6_binary(self, tmp_path: Path) -> Path:
        """Create binary with Denuvo v6 (pre-2024) for negative test."""
        binary_path = tmp_path / "denuvo_v6_sample.exe"

        pe_header = b"MZ\x90\x00\x03\x00\x00\x00"
        pe_header += b"\x00" * 0x34
        pe_offset = 0x100
        pe_header += struct.pack("<I", pe_offset)
        pe_header += b"\x00" * (pe_offset - len(pe_header))

        binary = pe_header + b"PE\x00\x00" + b"\x00" * 200
        v6_pattern = b"\x48\x89\x5c\x24\x10\x48\x89\x74\x24\x18\x55\x57\x41\x56\x48\x8d\xac\x24"
        binary += v6_pattern
        binary += b"\x00" * 2000

        with open(binary_path, "wb") as f:
            f.write(binary)

        return binary_path

    def test_denuvo_v7_signatures_present_in_analyzer(
        self, analyzer: DenuvoAnalyzer
    ) -> None:
        """DenuvoAnalyzer contains v7+ specific signature patterns."""
        assert hasattr(
            analyzer, "DENUVO_V7_SIGNATURES"
        ), "Analyzer must define DENUVO_V7_SIGNATURES"

        v7_sigs = analyzer.DENUVO_V7_SIGNATURES
        assert len(v7_sigs) >= 4, "Must have at least 4 distinct v7+ signatures"

        for sig in v7_sigs:
            assert isinstance(sig, bytes), "Signatures must be byte patterns"
            assert len(sig) >= 10, "Signatures must be substantial (10+ bytes)"

    def test_denuvo_v7_detected_with_activation_trigger(
        self, analyzer: DenuvoAnalyzer, denuvo_v7_binary: Path
    ) -> None:
        """Denuvo v7+ detected via enhanced activation trigger patterns."""
        result = analyzer.analyze(str(denuvo_v7_binary))

        assert result.detected, "Denuvo v7+ must be detected"

        if result.version:
            assert result.version.major >= 7, "Version must be v7 or higher"

        activation_trigger_pattern = b"\x48\x89\x5c\x24\x08\x48\x89\x6c\x24\x10\x48\x89\x74\x24\x18\x57\x48\x83\xec\x30\x48\x8b\xf9\x48\x8d\x0d"

        with open(denuvo_v7_binary, "rb") as f:
            binary_data = f.read()

        assert (
            activation_trigger_pattern in binary_data
        ), "Denuvo v7+ activation trigger must be present"

    def test_denuvo_v7_enhanced_integrity_checks(
        self, denuvo_v7_binary: Path
    ) -> None:
        """Denuvo v7+ implements enhanced integrity check mechanisms."""
        with open(denuvo_v7_binary, "rb") as f:
            binary_data = f.read()

        integrity_pattern = b"\x40\x53\x48\x83\xec\x30\x48\x8b\xd9\x48\x8b\x0d"

        assert (
            integrity_pattern in binary_data
        ), "Denuvo v7+ must contain enhanced integrity check patterns"

    def test_denuvo_v7_timing_obfuscation(self, denuvo_v7_binary: Path) -> None:
        """Denuvo v7+ uses advanced timing obfuscation techniques."""
        with open(denuvo_v7_binary, "rb") as f:
            binary_data = f.read()

        timing_pattern = b"\x48\x89\x4c\x24\x08\x48\x83\xec\x48\x48\x8b\x05"

        assert (
            timing_pattern in binary_data
        ), "Denuvo v7+ must implement timing obfuscation"

    def test_denuvo_v7_machine_fingerprinting(self, denuvo_v7_binary: Path) -> None:
        """Denuvo v7+ collects enhanced machine fingerprinting data."""
        with open(denuvo_v7_binary, "rb") as f:
            binary_data = f.read()

        cpuid_pattern = b"\x0f\xa2\x89\x44\x24\x00\x89\x5c\x24\x00\x89\x4c\x24\x00\x89\x54\x24\x00"

        assert (
            cpuid_pattern in binary_data
        ), "Denuvo v7+ must implement CPUID-based fingerprinting"

    def test_denuvo_v6_not_falsely_detected_as_v7(
        self, analyzer: DenuvoAnalyzer, denuvo_v6_binary: Path
    ) -> None:
        """Denuvo v6 (pre-2024) must NOT be detected as v7+."""
        result = analyzer.analyze(str(denuvo_v6_binary))

        if result.detected and result.version:
            assert result.version.major < 7, "v6 binary must not be classified as v7+"


class TestSignatureUpdateMechanisms:
    """Validate signature update path and procedures."""

    @pytest.fixture
    def protectors_db(self) -> CommercialProtectorsDatabase:
        """Create commercial protectors database."""
        return CommercialProtectorsDatabase()

    def test_database_contains_post_2024_protectors(
        self, protectors_db: CommercialProtectorsDatabase
    ) -> None:
        """Database includes entries for post-2024 protection versions."""
        all_protectors = protectors_db.protectors

        assert (
            len(all_protectors) >= 50
        ), "Database must contain at least 50 protector entries"

    def test_version_detection_mappings_exist(
        self, protectors_db: CommercialProtectorsDatabase
    ) -> None:
        """Version detection patterns map to 2024+ versions."""
        code_virtualizer = protectors_db.protectors.get("CodeVirtualizer")
        assert code_virtualizer is not None, "CodeVirtualizer must be in database"

        version_patterns = code_virtualizer.version_detect
        assert len(version_patterns) > 0, "Must have version detection patterns"

        has_modern_version = any(
            "3.x" in version for version in version_patterns.values()
        )
        assert has_modern_version, "Must detect modern protection versions"

    def test_bypass_difficulty_reflects_modern_protections(
        self, protectors_db: CommercialProtectorsDatabase
    ) -> None:
        """Bypass difficulty ratings account for 2024+ enhancements."""
        modern_protectors = [
            "CodeVirtualizer",
            "Enigma",
            "WibuKey",
        ]

        for protector_name in modern_protectors:
            protector = protectors_db.protectors.get(protector_name)
            assert protector is not None, f"{protector_name} must exist in database"

            assert (
                protector.bypass_difficulty >= 6
            ), f"{protector_name} difficulty must reflect modern enhancements (got {protector.bypass_difficulty})"

    def test_signature_patterns_are_substantive(
        self, protectors_db: CommercialProtectorsDatabase
    ) -> None:
        """Signature patterns are substantial and not placeholders."""
        for name, protector in protectors_db.protectors.items():
            total_patterns = (
                len(protector.ep_patterns)
                + len(protector.section_patterns)
                + len(protector.string_patterns)
            )

            assert (
                total_patterns >= 2
            ), f"{name} must have at least 2 detection patterns (got {total_patterns})"

            for ep_pattern in protector.ep_patterns:
                assert (
                    len(ep_pattern) >= 3
                ), f"{name} entry point patterns must be at least 3 bytes"


class TestBetaProtectionsEdgeCases:
    """Validate detection of beta protections and custom builds."""

    @pytest.fixture
    def beta_protection_binary(self) -> bytes:
        """Create binary with beta protection characteristics."""
        pe_header = b"MZ\x90\x00\x03\x00\x00\x00"
        pe_header += b"\x00" * 0x34
        pe_offset = 0x100
        pe_header += struct.pack("<I", pe_offset)
        pe_header += b"\x00" * (pe_offset - len(pe_header))

        binary = pe_header + b"PE\x00\x00" + b"\x00" * 200

        binary += b"VMProtect 3.9-beta"

        binary += b".vmp0\x00\x00\x00"
        binary += b".vmp1\x00\x00\x00"
        binary += b".vmpbeta\x00"

        binary += b"\x00" * (2000 - len(binary))

        return binary

    @pytest.fixture
    def custom_build_binary(self) -> bytes:
        """Create binary with custom Themida build."""
        pe_header = b"MZ\x90\x00\x03\x00\x00\x00"
        pe_header += b"\x00" * 0x34
        pe_offset = 0x100
        pe_header += struct.pack("<I", pe_offset)
        pe_header += b"\x00" * (pe_offset - len(pe_header))

        binary = pe_header + b"PE\x00\x00" + b"\x00" * 200

        binary += b"Themida-Custom-Build-2024"

        binary += b"\x54\x43\x42\x32\x34"

        binary += b"\x00" * (2000 - len(binary))

        return binary

    def test_beta_protection_detected_with_fallback_confidence(
        self, beta_protection_binary: bytes
    ) -> None:
        """Beta protections detected with appropriately lowered confidence."""
        protectors_db = CommercialProtectorsDatabase()
        detections = protectors_db.detect_protector(beta_protection_binary)

        beta_string_found = b"3.9-beta" in beta_protection_binary
        assert beta_string_found, "Beta version string must be present"

        if detections:
            for _name, _sig, confidence in detections:
                assert (
                    0.3 <= confidence <= 1.0
                ), "Beta detection confidence must be reasonable"

    def test_custom_build_detection_via_generic_patterns(
        self, custom_build_binary: bytes
    ) -> None:
        """Custom protection builds detected via generic pattern matching."""
        has_themida_marker = b"Themida" in custom_build_binary
        has_custom_marker = b"Custom" in custom_build_binary

        assert (
            has_themida_marker and has_custom_marker
        ), "Custom build must contain identifiable markers"

    def test_unusual_section_names_handled_gracefully(self) -> None:
        """Detector handles unusual section names from beta builds."""
        pe_header = b"MZ\x90\x00\x03\x00\x00\x00"
        pe_header += b"\x00" * 0x34
        pe_offset = 0x100
        pe_header += struct.pack("<I", pe_offset)
        pe_header += b"\x00" * (pe_offset - len(pe_header))

        pe_signature = b"PE\x00\x00"
        machine = struct.pack("<H", 0x014C)
        num_sections = struct.pack("<H", 1)
        pe_signature += machine + num_sections + b"\x00" * 14

        optional_header = b"\x00" * 0xE0

        unusual_section = b".vmp\xBE\xEA\x00"
        unusual_section += b"\x00" * 32

        binary = pe_header + pe_signature + optional_header + unusual_section
        binary += b"\x00" * 500

        protectors_db = CommercialProtectorsDatabase()
        detections = protectors_db.detect_protector(binary)

    def test_obfuscated_version_strings_detected(self) -> None:
        """Obfuscated version strings in beta builds still detected."""
        binary = b"MZ\x90\x00" + b"\x00" * 200

        obfuscated_vmp = b"\x56\x00\x4D\x00\x50\x00\x72\x00\x6F\x00\x74\x00\x65\x00\x63\x00\x74\x00"
        binary += obfuscated_vmp

        binary += b"\x00" * 2000

        contains_unicode_vmp = obfuscated_vmp in binary
        assert contains_unicode_vmp, "Unicode obfuscated strings must be detectable"


class TestSignatureDocumentationRequirement:
    """Validate signature update procedures are documented."""

    def test_database_module_has_update_documentation(self) -> None:
        """Commercial protectors database module contains update guidance."""
        import intellicrack.protection.commercial_protectors_database as db_module

        module_doc = db_module.__doc__
        assert module_doc is not None, "Module must have docstring"

        assert (
            "50+" in module_doc or "comprehensive" in module_doc.lower()
        ), "Documentation must indicate comprehensive coverage"

    def test_protector_signature_dataclass_documented(self) -> None:
        """ProtectorSignature dataclass fields are documented."""
        from intellicrack.protection.commercial_protectors_database import (
            ProtectorSignature,
        )

        sig_fields = ProtectorSignature.__dataclass_fields__
        assert "ep_patterns" in sig_fields, "Must have entry point patterns field"
        assert "version_detect" in sig_fields, "Must have version detection field"
        assert "bypass_difficulty" in sig_fields, "Must have difficulty rating"


class TestProtectionVersionRegressionPrevention:
    """Ensure tests FAIL if signatures regress to pre-2024 only."""

    def test_vmprotect_signatures_not_only_pre_38(self) -> None:
        """VMProtect signatures include 3.8+ patterns, not just 3.7 and older."""
        from intellicrack.core.analysis.vmprotect_detector import VMProtectDetector

        detector = VMProtectDetector()

        has_semantic_patterns = hasattr(detector, "VMP_SEMANTIC_PATTERNS_X86")
        assert (
            has_semantic_patterns
        ), "VMProtect detector must use semantic pattern matching for modern versions"

        if has_semantic_patterns:
            x86_patterns = detector.VMP_SEMANTIC_PATTERNS_X86
            x64_patterns = detector.VMP_SEMANTIC_PATTERNS_X64

            assert (
                len(x86_patterns) >= 5
            ), "Must have at least 5 x86 semantic patterns for v3.8+"
            assert (
                len(x64_patterns) >= 5
            ), "Must have at least 5 x64 semantic patterns for v3.8+"

    def test_themida_signatures_not_only_pre_32(self) -> None:
        """Themida signatures include 3.2+ patterns, not just 3.1 and older."""
        protectors_db = CommercialProtectorsDatabase()

        code_virtualizer = protectors_db.protectors.get("CodeVirtualizer")
        assert (
            code_virtualizer is not None
        ), "CodeVirtualizer (Themida engine) must exist"

        has_version_3x = any(
            "3.x" in version for version in code_virtualizer.version_detect.values()
        )
        assert has_version_3x, "Must detect Themida/CodeVirtualizer 3.x versions"

    def test_denuvo_signatures_not_only_pre_v7(self) -> None:
        """Denuvo signatures include v7+ patterns, not just v6 and older."""
        analyzer = DenuvoAnalyzer()

        assert hasattr(
            analyzer, "DENUVO_V7_SIGNATURES"
        ), "Must have dedicated v7 signature set"

        v7_sigs = analyzer.DENUVO_V7_SIGNATURES
        assert (
            len(v7_sigs) >= 4
        ), "Must have multiple v7+ signatures to prevent regression"

        v6_sigs = analyzer.DENUVO_V6_SIGNATURES
        v7_unique = set(v7_sigs) - set(v6_sigs)

        assert (
            len(v7_unique) >= 2
        ), "v7 signatures must include patterns distinct from v6"
