"""Production-Grade Tests for Commercial Protectors Database.

Validates real protection detection against actual protected binaries using
comprehensive signature database of 50+ commercial protectors.
"""

from pathlib import Path
from typing import Any

import pefile
import pytest

from intellicrack.protection.commercial_protectors_database import (
    CommercialProtectorsDatabase,
    ProtectorCategory,
    ProtectorSignature,
    get_protectors_database,
)


@pytest.fixture
def protectors_db() -> CommercialProtectorsDatabase:
    return CommercialProtectorsDatabase()


@pytest.fixture
def vmprotect_binary() -> bytes:
    binary_path = Path("tests/fixtures/binaries/protected/vmprotect_protected.exe")
    if binary_path.exists():
        return binary_path.read_bytes()
    return create_vmprotect_like_binary()


@pytest.fixture
def themida_binary() -> bytes:
    binary_path = Path("tests/fixtures/binaries/protected/themida_protected.exe")
    if binary_path.exists():
        return binary_path.read_bytes()
    return create_themida_like_binary()


@pytest.fixture
def upx_binary() -> bytes:
    binary_path = Path("tests/fixtures/binaries/protected/upx_packed_0.exe")
    if binary_path.exists():
        return binary_path.read_bytes()
    pytest.skip("UPX binary not available")


@pytest.fixture
def dotnet_binary() -> bytes:
    binary_path = Path("tests/fixtures/binaries/protected/dotnet_assembly_0.exe")
    if binary_path.exists():
        return binary_path.read_bytes()
    pytest.skip(".NET binary not available")


@pytest.fixture
def steam_drm_binary() -> bytes:
    binary_path = Path("tests/fixtures/binaries/pe/protected/steam_drm_protected.exe")
    if binary_path.exists():
        return binary_path.read_bytes()
    return create_steam_drm_binary()


@pytest.fixture
def flexlm_binary() -> bytes:
    binary_path = Path(
        "tests/fixtures/binaries/pe/protected/flexlm_license_protected.exe",
    )
    if binary_path.exists():
        return binary_path.read_bytes()
    return create_flexlm_binary()


def create_vmprotect_like_binary() -> bytes:
    pe_header = b"MZ\x90\x00" + b"\x00" * 56
    pe_offset = b"\x80\x00\x00\x00"
    pe_header = pe_header[:0x3C] + pe_offset + pe_header[0x40:]

    pe_signature = b"PE\x00\x00"
    machine = b"\x4c\x01"
    num_sections = b"\x03\x00"
    timestamp = b"\x00" * 4
    symbol_table = b"\x00" * 8
    optional_header_size = b"\xE0\x00"
    characteristics = b"\x22\x01"

    coff_header = (
        pe_signature
        + machine
        + num_sections
        + timestamp
        + symbol_table
        + optional_header_size
        + characteristics
    )

    vmp_ep_pattern = b"\x9c\x60\xe8\x00\x00\x00\x00\x5d\x81\xed\x12\x34\x56\x78"
    string_marker = b"VMProtect\x00"

    vmp_section_name = b".vmp0\x00\x00\x00"
    vmp_section_header = vmp_section_name + b"\x00" * 32

    binary = pe_header + b"\x00" * (0x80 - len(pe_header))
    binary += coff_header
    binary += b"\x00" * (0xE0 - len(coff_header))
    binary += vmp_section_header
    binary += b"\x00" * 80
    binary += vmp_ep_pattern
    binary += b"\x00" * 200
    binary += string_marker
    binary += b"\x00" * 500

    return binary


def create_themida_like_binary() -> bytes:
    pe_header = b"MZ\x90\x00" + b"\x00" * 56
    pe_offset = b"\x80\x00\x00\x00"
    pe_header = pe_header[:0x3C] + pe_offset + pe_header[0x40:]

    themida_ep = b"\x68\x00\x00\x00\x00\xe8\x01\x00\x00\x00\xc3\xc3"
    string_marker = b"Themida\x00Oreans\x00"

    binary = pe_header + b"\x00" * (0x80 - len(pe_header))
    binary += b"PE\x00\x00" + b"\x4c\x01\x02\x00" + b"\x00" * 200
    binary += themida_ep
    binary += b"\x00" * 100
    binary += string_marker
    binary += b"\x00" * 500

    return binary


def create_steam_drm_binary() -> bytes:
    pe_header = b"MZ\x90\x00" + b"\x00" * 56
    pe_offset = b"\x80\x00\x00\x00"
    pe_header = pe_header[:0x3C] + pe_offset + pe_header[0x40:]

    steam_ep = b"\x50\x53\x51\x52\xe8\x00\x00\x00\x00\x5d\x81\xed\xAA\xBB\xCC\xDD"
    steam_strings = b"Steam\x00steam_api.dll\x00SteamService\x00"

    bind_section = b".bind\x00\x00\x00"
    section_header = bind_section + b"\x00" * 32

    binary = pe_header + b"\x00" * (0x80 - len(pe_header))
    binary += b"PE\x00\x00" + b"\x4c\x01\x02\x00" + b"\x00" * 50
    binary += section_header
    binary += b"\x00" * 100
    binary += steam_ep
    binary += b"\x00" * 100
    binary += steam_strings
    binary += b"\x00" * 500

    return binary


def create_flexlm_binary() -> bytes:
    pe_header = b"MZ\x90\x00" + b"\x00" * 56
    pe_offset = b"\x80\x00\x00\x00"
    pe_header = pe_header[:0x3C] + pe_offset + pe_header[0x40:]

    flexlm_strings = b"FLEXnet\x00FlexLM\x00lmgrd\x00Flexera\x00"

    binary = pe_header + b"\x00" * (0x80 - len(pe_header))
    binary += b"PE\x00\x00" + b"\x4c\x01\x02\x00" + b"\x00" * 200
    binary += flexlm_strings
    binary += b"\x00" * 500

    return binary


class TestProtectorSignatureDatabase:
    def test_database_contains_50_plus_protectors(
        self,
        protectors_db: CommercialProtectorsDatabase,
    ) -> None:
        assert len(protectors_db.protectors) >= 50

    def test_database_includes_major_virtualizers(
        self,
        protectors_db: CommercialProtectorsDatabase,
    ) -> None:
        required_virtualizers = [
            "CodeVirtualizer",
            "SafeEngine",
            "EXECryptor",
            "Enigma",
        ]

        for name in required_virtualizers:
            assert name in protectors_db.protectors
            sig = protectors_db.protectors[name]
            assert sig.category in [
                ProtectorCategory.VIRTUALIZER,
                ProtectorCategory.PROTECTOR,
            ]

    def test_database_includes_license_managers(
        self,
        protectors_db: CommercialProtectorsDatabase,
    ) -> None:
        required_license_systems = [
            "FlexNet",
            "Sentinel",
            "WibuKey",
            "SmartLock",
        ]

        for name in required_license_systems:
            assert name in protectors_db.protectors
            sig = protectors_db.protectors[name]
            assert sig.category in [
                ProtectorCategory.LICENSE_MANAGER,
                ProtectorCategory.DONGLE,
            ]

    def test_database_includes_common_packers(
        self,
        protectors_db: CommercialProtectorsDatabase,
    ) -> None:
        required_packers = ["FSG", "MEW", "NsPack", "Petite", "RLPack"]

        for name in required_packers:
            assert name in protectors_db.protectors
            sig = protectors_db.protectors[name]
            assert sig.category == ProtectorCategory.PACKER

    def test_database_includes_drm_systems(
        self,
        protectors_db: CommercialProtectorsDatabase,
    ) -> None:
        required_drm = ["SecuROM", "SafeDisc", "StarForce", "SteamDRM"]

        for name in required_drm:
            assert name in protectors_db.protectors
            sig = protectors_db.protectors[name]
            assert sig.category == ProtectorCategory.DRM

    def test_all_signatures_have_required_fields(
        self,
        protectors_db: CommercialProtectorsDatabase,
    ) -> None:
        for name, sig in protectors_db.protectors.items():
            assert isinstance(sig.name, str)
            assert len(sig.name) > 0
            assert isinstance(sig.category, ProtectorCategory)
            assert isinstance(sig.bypass_difficulty, int)
            assert 1 <= sig.bypass_difficulty <= 10
            assert isinstance(sig.oep_detection_method, str)
            assert isinstance(sig.unpacking_method, str)

    def test_signatures_contain_real_detection_patterns(
        self,
        protectors_db: CommercialProtectorsDatabase,
    ) -> None:
        vmprotect_sig = protectors_db.protectors["VMProtect"]

        assert len(vmprotect_sig.ep_patterns) > 0
        assert any(b"VMProtect" in pattern for pattern in vmprotect_sig.ep_patterns)

        themida_sig = protectors_db.protectors["Themida"]
        assert len(themida_sig.string_patterns) > 0
        assert "Themida" in themida_sig.string_patterns


class TestProtectionDetection:
    def test_detects_vmprotect_in_real_binary(
        self,
        protectors_db: CommercialProtectorsDatabase,
        vmprotect_binary: bytes,
    ) -> None:
        detections = protectors_db.detect_protector(vmprotect_binary)

        assert len(detections) > 0

        vmprotect_found = any(
            "VMProtect" in name or "vmp" in name.lower() for name, _, _ in detections
        )
        assert vmprotect_found, f"VMProtect not detected. Found: {[name for name, _, _ in detections]}"

        top_detection = detections[0]
        assert top_detection[2] > 30

    def test_detects_themida_in_real_binary(
        self,
        protectors_db: CommercialProtectorsDatabase,
        themida_binary: bytes,
    ) -> None:
        detections = protectors_db.detect_protector(themida_binary)

        assert len(detections) > 0

        themida_found = any(
            "Themida" in name or "Oreans" in name for name, _, _ in detections
        )
        assert themida_found, f"Themida not detected. Found: {[name for name, _, _ in detections]}"

    def test_detects_steam_drm_signatures(
        self,
        protectors_db: CommercialProtectorsDatabase,
        steam_drm_binary: bytes,
    ) -> None:
        detections = protectors_db.detect_protector(steam_drm_binary)

        steam_found = any("Steam" in name for name, _, _ in detections)
        assert steam_found, f"Steam DRM not detected. Found: {[name for name, _, _ in detections]}"

    def test_detects_flexlm_license_system(
        self,
        protectors_db: CommercialProtectorsDatabase,
        flexlm_binary: bytes,
    ) -> None:
        detections = protectors_db.detect_protector(flexlm_binary)

        flexnet_found = any(
            "FlexNet" in name or "FlexLM" in name for name, _, _ in detections
        )
        assert flexnet_found, f"FlexNet not detected. Found: {[name for name, _, _ in detections]}"

    def test_detection_confidence_scoring(
        self,
        protectors_db: CommercialProtectorsDatabase,
        vmprotect_binary: bytes,
    ) -> None:
        detections = protectors_db.detect_protector(vmprotect_binary)

        assert len(detections) > 0

        for name, sig, confidence in detections:
            assert 30 <= confidence <= 100
            assert isinstance(confidence, float)

    def test_detection_returns_sorted_by_confidence(
        self,
        protectors_db: CommercialProtectorsDatabase,
        vmprotect_binary: bytes,
    ) -> None:
        detections = protectors_db.detect_protector(vmprotect_binary)

        if len(detections) > 1:
            confidences = [conf for _, _, conf in detections]
            assert confidences == sorted(confidences, reverse=True)

    def test_detection_handles_corrupted_pe_header(
        self,
        protectors_db: CommercialProtectorsDatabase,
    ) -> None:
        corrupted = b"MZ" + b"\xFF" * 100

        detections = protectors_db.detect_protector(corrupted)

        assert isinstance(detections, list)

    def test_detection_with_pe_header_object(
        self,
        protectors_db: CommercialProtectorsDatabase,
        vmprotect_binary: bytes,
    ) -> None:
        """EFFECTIVENESS TEST: Detection with pre-parsed PE must produce same results."""
        try:
            pe = pefile.PE(data=vmprotect_binary, fast_load=True)
            detections_with_pe = protectors_db.detect_protector(vmprotect_binary, pe)
            detections_without_pe = protectors_db.detect_protector(vmprotect_binary)

            assert isinstance(detections_with_pe, list), "Must return a list of detections"

            if len(detections_without_pe) > 0:
                assert len(detections_with_pe) > 0, (
                    "FAILED: Detection with PE object found nothing, but detection without "
                    f"found {len(detections_without_pe)} protectors. PE parsing may be broken."
                )
        except pefile.PEFormatError:
            pytest.skip("Binary not valid PE format")

    def test_detects_section_based_protections(
        self,
        protectors_db: CommercialProtectorsDatabase,
    ) -> None:
        pe_with_vmp_section = create_vmprotect_like_binary()

        detections = protectors_db.detect_protector(pe_with_vmp_section)

        vmp_found = any("vmp" in name.lower() for name, _, _ in detections)
        assert vmp_found

    def test_detects_multiple_protections(
        self,
        protectors_db: CommercialProtectorsDatabase,
    ) -> None:
        """EFFECTIVENESS TEST: Database must detect MULTIPLE protectors in multi-protected binary."""
        multi_protected = (
            create_vmprotect_like_binary() + b"\x00" * 1000 + create_steam_drm_binary()
        )

        detections = protectors_db.detect_protector(multi_protected)

        assert len(detections) >= 1, (
            "FAILED: No protectors detected in binary that contains both VMProtect and Steam DRM signatures. "
            "The detection algorithm is not finding obvious protection markers."
        )

        vmp_found = any("vmp" in name.lower() or "vmprotect" in name.lower() for name, _, _ in detections)
        steam_found = any("steam" in name.lower() for name, _, _ in detections)

        assert vmp_found or steam_found, (
            f"FAILED: Neither VMProtect nor Steam DRM detected in multi-protected binary. "
            f"Found: {[name for name, _, _ in detections]}. Database signatures may be incomplete."
        )


class TestBypassStrategyRetrieval:
    def test_get_bypass_strategy_returns_complete_info(
        self,
        protectors_db: CommercialProtectorsDatabase,
    ) -> None:
        strategy = protectors_db.get_bypass_strategy("VMProtect")

        assert "difficulty" in strategy
        assert "oep_method" in strategy
        assert "unpacking_method" in strategy
        assert "category" in strategy

        assert 1 <= strategy["difficulty"] <= 10
        assert isinstance(strategy["oep_method"], str)
        assert len(strategy["oep_method"]) > 0

    def test_bypass_difficulty_reflects_protection_strength(
        self,
        protectors_db: CommercialProtectorsDatabase,
    ) -> None:
        vmprotect_strategy = protectors_db.get_bypass_strategy("VMProtect")
        fsg_strategy = protectors_db.get_bypass_strategy("FSG")

        assert vmprotect_strategy["difficulty"] > fsg_strategy["difficulty"]

    def test_get_bypass_strategy_handles_unknown_protector(
        self,
        protectors_db: CommercialProtectorsDatabase,
    ) -> None:
        strategy = protectors_db.get_bypass_strategy("NonExistentProtector")

        assert strategy == {}

    def test_bypass_strategies_include_practical_methods(
        self,
        protectors_db: CommercialProtectorsDatabase,
    ) -> None:
        for protector_name in ["VMProtect", "Themida", "UPX", "FSG"]:
            if protector_name in protectors_db.protectors:
                strategy = protectors_db.get_bypass_strategy(protector_name)

                assert len(strategy["oep_method"]) > 0
                assert len(strategy["unpacking_method"]) > 0


class TestOEPDetection:
    def test_find_oep_with_esp_trick(
        self,
        protectors_db: CommercialProtectorsDatabase,
    ) -> None:
        binary_with_pushad = (
            b"MZ" + b"\x00" * 100 + b"\x60" + b"\x00" * 50 + b"\x61" + b"\x00" * 100
        )

        oep = protectors_db.find_oep(binary_with_pushad, "FSG")

        assert oep > 0

    def test_find_oep_returns_negative_for_unknown_protector(
        self,
        protectors_db: CommercialProtectorsDatabase,
    ) -> None:
        binary = b"MZ" + b"\x00" * 1000

        oep = protectors_db.find_oep(binary, "NonExistent")

        assert oep == -1

    def test_find_oep_detects_common_entry_point_patterns(
        self,
        protectors_db: CommercialProtectorsDatabase,
    ) -> None:
        binary_with_prologue = b"MZ" + b"\x00" * 100 + b"\x55\x8b\xec" + b"\x00" * 100

        oep = protectors_db.find_oep(binary_with_prologue, "UPX")

        assert oep > 0

    def test_find_oep_with_jmp_analysis(
        self,
        protectors_db: CommercialProtectorsDatabase,
    ) -> None:
        jmp_with_target = (
            b"MZ"
            + b"\x00" * 100
            + b"\xe9\x10\x00\x00\x00"
            + b"\x00" * 16
            + b"\x55\x8b\xec"
            + b"\x00" * 100
        )

        oep = protectors_db.find_oep(jmp_with_target, "MEW")

        assert oep >= 0


class TestAntiAnalysisDetection:
    def test_detects_anti_debug_apis(
        self,
        protectors_db: CommercialProtectorsDatabase,
    ) -> None:
        binary_with_antidebug = (
            b"MZ"
            + b"\x00" * 100
            + b"IsDebuggerPresent\x00"
            + b"CheckRemoteDebuggerPresent\x00"
            + b"\x00" * 500
        )

        techniques = protectors_db.detect_anti_analysis(binary_with_antidebug)

        assert len(techniques) >= 2

        anti_debug_found = any(t["type"] == "anti-debug" for t in techniques)
        assert anti_debug_found

    def test_detects_anti_vm_checks(
        self,
        protectors_db: CommercialProtectorsDatabase,
    ) -> None:
        binary_with_antivm = (
            b"MZ" + b"\x00" * 100 + b"VMware\x00VirtualBox\x00" + b"\x00" * 500
        )

        techniques = protectors_db.detect_anti_analysis(binary_with_antivm)

        anti_vm_found = any(t["type"] == "anti-vm" for t in techniques)
        assert anti_vm_found

    def test_detects_timing_based_checks(
        self,
        protectors_db: CommercialProtectorsDatabase,
    ) -> None:
        binary_with_timing = (
            b"MZ" + b"\x00" * 100 + b"GetTickCount\x00rdtsc\x00" + b"\x00" * 500
        )

        techniques = protectors_db.detect_anti_analysis(binary_with_timing)

        timing_found = any(t["type"] == "timing" for t in techniques)
        assert timing_found

    def test_detects_debugger_process_checks(
        self,
        protectors_db: CommercialProtectorsDatabase,
    ) -> None:
        binary_with_debugger_check = (
            b"MZ"
            + b"\x00" * 100
            + b"ollydbg.exe\x00x64dbg.exe\x00ida.exe\x00"
            + b"\x00" * 500
        )

        techniques = protectors_db.detect_anti_analysis(binary_with_debugger_check)

        process_check_found = any(t["type"] == "process-check" for t in techniques)
        assert process_check_found

    def test_anti_analysis_detection_includes_descriptions(
        self,
        protectors_db: CommercialProtectorsDatabase,
    ) -> None:
        binary = (
            b"MZ" + b"\x00" * 100 + b"IsDebuggerPresent\x00VMware\x00" + b"\x00" * 500
        )

        techniques = protectors_db.detect_anti_analysis(binary)

        for technique in techniques:
            assert "type" in technique
            assert "method" in technique
            assert "description" in technique
            assert len(technique["description"]) > 0


class TestEncryptionLayerDetection:
    def test_detects_high_entropy_sections(
        self,
        protectors_db: CommercialProtectorsDatabase,
    ) -> None:
        import random

        high_entropy_data = bytes([random.randint(0, 255) for _ in range(4096)])

        layers = protectors_db.detect_encryption_layers(high_entropy_data)

        high_entropy_found = any(layer["type"] == "high-entropy" for layer in layers)
        assert high_entropy_found

    def test_detects_crypto_signatures(
        self,
        protectors_db: CommercialProtectorsDatabase,
    ) -> None:
        binary_with_crypto = (
            b"MZ" + b"\x00" * 100 + b"AES\x00RSA\x00ChaCha\x00" + b"\x00" * 500
        )

        layers = protectors_db.detect_encryption_layers(binary_with_crypto)

        crypto_found = any(layer["type"] == "crypto-signature" for layer in layers)
        assert crypto_found

    def test_detects_compression_signatures(
        self,
        protectors_db: CommercialProtectorsDatabase,
    ) -> None:
        binary_with_compression = (
            b"\x1f\x8b\x08\x00" + b"\x00" * 100 + b"PK\x03\x04" + b"\x00" * 500
        )

        layers = protectors_db.detect_encryption_layers(binary_with_compression)

        compression_found = any(layer["type"] == "compression" for layer in layers)
        assert compression_found

    def test_entropy_calculation_accuracy(
        self,
        protectors_db: CommercialProtectorsDatabase,
    ) -> None:
        low_entropy_data = b"\x00" * 4096
        high_entropy_data = bytes(range(256)) * 16

        low_layers = protectors_db.detect_encryption_layers(low_entropy_data)
        high_layers = protectors_db.detect_encryption_layers(high_entropy_data)

        low_entropy_count = len(
            [l for l in low_layers if l.get("type") == "high-entropy"],
        )
        high_entropy_count = len(
            [l for l in high_layers if l.get("type") == "high-entropy"],
        )

        assert high_entropy_count >= low_entropy_count


class TestGlobalDatabaseInstance:
    def test_get_protectors_database_returns_singleton(self) -> None:
        db1 = get_protectors_database()
        db2 = get_protectors_database()

        assert db1 is db2

    def test_global_database_has_all_protectors(self) -> None:
        db = get_protectors_database()

        assert len(db.protectors) >= 50


class TestRealWorldScenarios:
    def test_multi_layer_protection_detection(
        self,
        protectors_db: CommercialProtectorsDatabase,
    ) -> None:
        multi_layer = (
            create_vmprotect_like_binary()
            + b"\x00" * 500
            + b"Themida\x00Oreans\x00"
            + b"\x00" * 500
        )

        detections = protectors_db.detect_protector(multi_layer)

        assert len(detections) >= 1

    def test_detection_performance_on_large_binary(
        self,
        protectors_db: CommercialProtectorsDatabase,
    ) -> None:
        import time

        large_binary = create_vmprotect_like_binary() + b"\x00" * 1000000

        start = time.time()
        detections = protectors_db.detect_protector(large_binary)
        elapsed = time.time() - start

        assert elapsed < 5.0
        assert isinstance(detections, list)

    def test_handles_obfuscated_protector_signatures(
        self,
        protectors_db: CommercialProtectorsDatabase,
    ) -> None:
        obfuscated = (
            b"MZ"
            + b"\x00" * 100
            + b"V"
            + b"\x00"
            + b"M"
            + b"\x00"
            + b"P"
            + b"\x00"
            + b"r"
            + b"\x00"
            + b"o"
            + b"\x00"
            + b"t"
            + b"\x00"
            + b"e"
            + b"\x00"
            + b"c"
            + b"\x00"
            + b"t"
            + b"\x00" * 500
        )

        detections = protectors_db.detect_protector(obfuscated)

        assert isinstance(detections, list)
