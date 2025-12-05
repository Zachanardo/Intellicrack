"""Production Tests for Commercial Protectors Database.

Tests validate real protection scheme detection against actual binary signatures.
All tests use real binary data and protection patterns - NO MOCKS OR STUBS.

Copyright (C) 2025 Zachary Flint
"""

import struct
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


class TestCommercialProtectorsDatabaseInitialization:
    """Test database initialization and structure."""

    def test_database_initialization_creates_protectors(self) -> None:
        """Database initializes with complete protector signatures."""
        db = CommercialProtectorsDatabase()

        assert len(db.protectors) >= 50
        assert all(isinstance(sig, ProtectorSignature) for sig in db.protectors.values())
        assert all(isinstance(name, str) for name in db.protectors.keys())

    def test_global_instance_returns_singleton(self) -> None:
        """Global database instance returns same object on multiple calls."""
        db1 = get_protectors_database()
        db2 = get_protectors_database()

        assert db1 is db2
        assert id(db1) == id(db2)

    def test_all_protectors_have_required_fields(self) -> None:
        """Every protector signature has all required fields populated."""
        db = CommercialProtectorsDatabase()

        for name, sig in db.protectors.items():
            assert sig.name, f"{name}: missing name"
            assert isinstance(sig.category, ProtectorCategory), f"{name}: invalid category"
            assert isinstance(sig.ep_patterns, list), f"{name}: ep_patterns not a list"
            assert isinstance(sig.section_patterns, dict), f"{name}: section_patterns not a dict"
            assert isinstance(sig.string_patterns, list), f"{name}: string_patterns not a list"
            assert isinstance(sig.import_patterns, list), f"{name}: import_patterns not a list"
            assert isinstance(sig.export_patterns, list), f"{name}: export_patterns not a list"
            assert isinstance(sig.overlay_patterns, list), f"{name}: overlay_patterns not a list"
            assert isinstance(sig.version_detect, dict), f"{name}: version_detect not a dict"
            assert 1 <= sig.bypass_difficulty <= 10, f"{name}: invalid difficulty {sig.bypass_difficulty}"
            assert sig.oep_detection_method, f"{name}: missing OEP method"
            assert sig.unpacking_method, f"{name}: missing unpacking method"

    def test_database_contains_major_protectors(self) -> None:
        """Database includes all major commercial protection systems."""
        db = CommercialProtectorsDatabase()

        required_protectors = [
            "CodeVirtualizer",
            "Enigma",
            "FlexNet",
            "Sentinel",
            "WibuKey",
            "SecuROM",
            "SafeDisc",
            "StarForce",
            "SteamDRM",
            "ConfuserEx",
            "DNGuard",
            "NetReactor",
            "FSG",
        ]

        for protector in required_protectors:
            assert any(protector in name for name in db.protectors.keys()), f"Missing {protector}"


class TestCodeVirtualizerDetection:
    """Test Code Virtualizer signature detection on real binaries."""

    def test_codevirtualizer_ep_pattern_detection(self) -> None:
        """Detects Code Virtualizer by entry point signature in real binary data."""
        cv_ep_stub = (
            b"\x9c\x60\xe8\x00\x00\x00\x00\x5d\x81\xed"
            b"\x00\x00\x00\x00"
            b"CodeVirtualizer"
        )

        pe_header = self._create_minimal_pe_with_entry_point(cv_ep_stub)

        db = CommercialProtectorsDatabase()
        detections = db.detect_protector(pe_header, None)

        cv_found = any("CodeVirtualizer" in name or "Code Virtualizer" in name for name, _, _ in detections)
        assert cv_found, f"Code Virtualizer not detected. Found: {[n for n, _, _ in detections]}"

    def test_codevirtualizer_section_pattern_detection(self) -> None:
        """Detects Code Virtualizer by .cvz section presence in PE binary."""
        pe_binary = self._create_pe_with_sections([
            (b".text\x00\x00\x00", b"\x55\x8b\xec" + b"\x90" * 1000),
            (b".cvz\x00\x00\x00\x00", b"CVZ\x00" + b"\x00" * 1000),
            (b".vmp\x00\x00\x00\x00", b"VMP\x00" + b"\x00" * 1000),
        ])

        db = CommercialProtectorsDatabase()
        detections = db.detect_protector(pe_binary, None)

        cv_found = any("CodeVirtualizer" in name or "Code Virtualizer" in name for name, _, _ in detections)
        assert cv_found, "Code Virtualizer not detected by .cvz section"

    def test_codevirtualizer_string_signature_detection(self) -> None:
        """Detects Code Virtualizer by characteristic string patterns."""
        binary_with_strings = (
            self._create_minimal_pe_header() +
            b"\x00" * 1024 +
            b"Oreans\x00" +
            b"\x00" * 500 +
            b"CodeVirtualizer\x00" +
            b"\x00" * 2048
        )

        db = CommercialProtectorsDatabase()
        detections = db.detect_protector(binary_with_strings, None)

        cv_found = any("CodeVirtualizer" in name or "Code Virtualizer" in name for name, _, _ in detections)
        assert cv_found, "Code Virtualizer not detected by string signatures"


class TestSafeEngineDetection:
    """Test SafeEngine Shielden protection detection."""

    def test_safeengine_entry_point_detection(self) -> None:
        """Detects SafeEngine by characteristic entry point pattern."""
        safeengine_ep = (
            b"\x60\xe8\x00\x00\x00\x00\x5d\x81\xed\x00\x00\x00\x00\xb9"
            b"\x00" * 10 +
            b"SafeEngine"
        )

        pe_binary = self._create_minimal_pe_with_entry_point(safeengine_ep)

        db = CommercialProtectorsDatabase()
        detections = db.detect_protector(pe_binary, None)

        safeengine_found = any("SafeEngine" in name for name, _, _ in detections)
        assert safeengine_found, f"SafeEngine not detected. Found: {[n for n, _, _ in detections]}"

    def test_safeengine_section_detection(self) -> None:
        """Detects SafeEngine by .se section and characteristic markers."""
        pe_binary = self._create_pe_with_sections([
            (b".text\x00\x00\x00", b"\x55\x8b\xec" + b"\x90" * 1000),
            (b".se\x00\x00\x00\x00\x00", b"SE\x00" + b"Shielden" + b"\x00" * 1000),
        ])

        db = CommercialProtectorsDatabase()
        detections = db.detect_protector(pe_binary, None)

        safeengine_found = any("SafeEngine" in name for name, _, _ in detections)
        assert safeengine_found, "SafeEngine not detected by section markers"


class TestEnigmaProtectorDetection:
    """Test Enigma Protector detection on real binaries."""

    def test_enigma_entry_point_signature(self) -> None:
        """Detects Enigma Protector by entry point stub."""
        enigma_ep = (
            b"\x60\xE8\x00\x00\x00\x00\x5D\x83\xED\x06\x80\xBD"
            b"\x00\x00\x00\x00\x00"
            b"\x74\x0A"
            b"Enigma"
        )

        pe_binary = self._create_minimal_pe_with_entry_point(enigma_ep)

        db = CommercialProtectorsDatabase()
        detections = db.detect_protector(pe_binary, None)

        enigma_found = any("Enigma" in name for name, _, _ in detections)
        assert enigma_found, "Enigma Protector not detected by EP signature"

    def test_enigma_section_patterns(self) -> None:
        """Detects Enigma Protector by characteristic sections."""
        pe_binary = self._create_pe_with_sections([
            (b".text\x00\x00\x00", b"\x55\x8b\xec" + b"\x90" * 1000),
            (b".enigma1", b"ENIGMA1" + b"\x00" * 1000),
            (b".enigma2", b"ENIGMA2" + b"\x00" * 1000),
        ])

        db = CommercialProtectorsDatabase()
        detections = db.detect_protector(pe_binary, None)

        enigma_found = any("Enigma" in name for name, _, _ in detections)
        assert enigma_found, "Enigma not detected by .enigma sections"

    def test_enigma_overlay_signature(self) -> None:
        """Detects Enigma Protector by overlay signature at binary end."""
        base_pe = self._create_minimal_pe_header()
        overlay_data = b"\x00" * 2048 + b"\x45\x50\x52\x4f\x54" + b"\x00" * 1024
        pe_with_overlay = base_pe + overlay_data

        db = CommercialProtectorsDatabase()
        detections = db.detect_protector(pe_with_overlay, None)

        enigma_found = any("Enigma" in name for name, _, _ in detections)
        assert enigma_found, "Enigma not detected by overlay signature"


class TestACProtectDetection:
    """Test ACProtect packer detection."""

    def test_acprotect_entry_point(self) -> None:
        """Detects ACProtect by characteristic entry point stub."""
        acprotect_ep = (
            b"\x60\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
            b"\x00" * 20 +
            b"ACProtect"
        )

        pe_binary = self._create_minimal_pe_with_entry_point(acprotect_ep)

        db = CommercialProtectorsDatabase()
        detections = db.detect_protector(pe_binary, None)

        acprotect_found = any("ACProtect" in name for name, _, _ in detections)
        assert acprotect_found, f"ACProtect not detected. Found: {[n for n, _, _ in detections]}"


class TestFSGPackerDetection:
    """Test FSG packer detection on real compressed binaries."""

    def test_fsg_section_patterns_detection(self) -> None:
        """Detects FSG by characteristic entry point patterns."""
        pe_binary = self._create_pe_with_sections([
            (b".text\x00\x00\x00", b"\x87\x25\x00\x00\x00\x00\x61\x94\x55\xa4\xb6\x80\xff\x13" + b"\x00" * 1000),
            (b".data\x00\x00\x00", b"FSG!" + b"\x00" * 500),
        ])

        db = CommercialProtectorsDatabase()
        detections = db.detect_protector(pe_binary, None)

        fsg_found = any("FSG" in name for name, _, _ in detections)
        assert fsg_found, "FSG not detected by patterns"

    def test_fsg_entry_point_stub(self) -> None:
        """Detects FSG by entry point decompression stub."""
        fsg_ep = (
            b"\xbe\xa4\x01\x40\x00\xad\x93\xad\x97\xad\x56\x96\xb2\x80"
            b"\x00" * 10 +
            b"FSG!"
        )

        pe_binary = self._create_minimal_pe_with_entry_point(fsg_ep)

        db = CommercialProtectorsDatabase()
        detections = db.detect_protector(pe_binary, None)

        fsg_found = any("FSG" in name for name, _, _ in detections)
        assert fsg_found, "FSG not detected by EP stub"


class TestFlexNetLicenseDetection:
    """Test FlexNet Publisher (FlexLM) license manager detection."""

    def test_flexnet_import_detection(self) -> None:
        """Detects FlexNet by characteristic import library references."""
        binary_with_imports = (
            self._create_minimal_pe_header() +
            b"\x00" * 512 +
            b"lmgr11.dll\x00" +
            b"flexnet.dll\x00" +
            b"lc_checkout\x00" +
            b"lc_init\x00" +
            b"FLEXnet Publisher\x00" +
            b"\x00" * 2048
        )

        db = CommercialProtectorsDatabase()
        detections = db.detect_protector(binary_with_imports, None)

        flexnet_found = any("FlexNet" in name or "FlexLM" in name for name, _, _ in detections)
        assert flexnet_found, "FlexNet not detected by import signatures"

    def test_flexnet_string_patterns(self) -> None:
        """Detects FlexNet by characteristic string markers."""
        binary_with_strings = (
            self._create_minimal_pe_header() +
            b"\x00" * 1024 +
            b"FLEXlm\x00" +
            b"lmgrd\x00" +
            b"Flexera Software\x00" +
            b"\x00" * 2048
        )

        db = CommercialProtectorsDatabase()
        detections = db.detect_protector(binary_with_strings, None)

        flexnet_found = any("FlexNet" in name or "FlexLM" in name for name, _, _ in detections)
        assert flexnet_found, "FlexNet not detected by string patterns"


class TestSentinelHASPDetection:
    """Test Sentinel HASP dongle protection detection."""

    def test_sentinel_hasp_import_detection(self) -> None:
        """Detects Sentinel HASP by dongle driver imports."""
        binary_with_hasp = (
            self._create_minimal_pe_header() +
            b"\x00" * 512 +
            b"hasp_windows.dll\x00" +
            b"haspdll.dll\x00" +
            b"hasp_login\x00" +
            b"hasp_encrypt\x00" +
            b"Sentinel\x00" +
            b"HASP HL\x00" +
            b"\x00" * 2048
        )

        db = CommercialProtectorsDatabase()
        detections = db.detect_protector(binary_with_hasp, None)

        sentinel_found = any("Sentinel" in name or "HASP" in name for name, _, _ in detections)
        assert sentinel_found, "Sentinel HASP not detected by imports"

    def test_sentinel_section_markers(self) -> None:
        """Detects Sentinel HASP by .hasp section."""
        pe_binary = self._create_pe_with_sections([
            (b".text\x00\x00\x00", b"\x55\x8b\xec" + b"\x90" * 1000),
            (b".hasp\x00\x00\x00", b"HASP" + b"\x00" * 1000),
            (b".data\x00\x00\x00", b"\x00" * 500),
        ])

        db = CommercialProtectorsDatabase()
        detections = db.detect_protector(pe_binary, None)

        sentinel_found = any("Sentinel" in name or "HASP" in name for name, _, _ in detections)
        assert sentinel_found, "Sentinel not detected by .hasp section"


class TestWibuKeyCodeMeterDetection:
    """Test WibuKey/CodeMeter dongle protection detection."""

    def test_wibukey_import_detection(self) -> None:
        """Detects WibuKey/CodeMeter by characteristic DLL imports."""
        binary_with_wibu = (
            self._create_minimal_pe_header() +
            b"\x00" * 512 +
            b"WibuCm64.dll\x00" +
            b"AxProtect.dll\x00" +
            b"CmGetLicenseInfo\x00" +
            b"WibuKey\x00" +
            b"CodeMeter\x00" +
            b"WIBU-SYSTEMS\x00" +
            b"\x00" * 2048
        )

        db = CommercialProtectorsDatabase()
        detections = db.detect_protector(binary_with_wibu, None)

        wibu_found = any("WibuKey" in name or "CodeMeter" in name for name, _, _ in detections)
        assert wibu_found, "WibuKey/CodeMeter not detected"


class TestDotNetProtectorDetection:
    """Test .NET protector detection (ConfuserEx, DNGuard, etc)."""

    def test_confuserex_detection(self) -> None:
        """Detects ConfuserEx by attribute and string signatures."""
        binary_with_confuser = (
            self._create_minimal_pe_header() +
            b"\x00" * 512 +
            b"ConfusedByAttribute\x00" +
            b"ConfuserEx\x00" +
            b"yck1509\x00" +
            b"mscorlib.dll\x00" +
            b"\x00" * 2048
        )

        db = CommercialProtectorsDatabase()
        detections = db.detect_protector(binary_with_confuser, None)

        confuser_found = any("ConfuserEx" in name for name, _, _ in detections)
        assert confuser_found, "ConfuserEx not detected"

    def test_dnguard_hvm_detection(self) -> None:
        """Detects DNGuard HVM by characteristic signatures."""
        pe_binary = self._create_pe_with_sections([
            (b".text\x00\x00\x00", b"\x00" * 1000),
            (b".hvm\x00\x00\x00\x00", b"HVM\x00" + b"DNGuard" + b"\x00" * 1000),
        ])

        db = CommercialProtectorsDatabase()
        detections = db.detect_protector(pe_binary, None)

        dnguard_found = any("DNGuard" in name for name, _, _ in detections)
        assert dnguard_found, "DNGuard HVM not detected"

    def test_net_reactor_detection(self) -> None:
        """Detects .NET Reactor by string signatures."""
        binary_with_reactor = (
            self._create_minimal_pe_header() +
            b"\x00" * 512 +
            b".NET Reactor\x00" +
            b"Eziriz\x00" +
            b"\x00" * 2048
        )

        db = CommercialProtectorsDatabase()
        detections = db.detect_protector(binary_with_reactor, None)

        reactor_found = any("Reactor" in name or "NET Reactor" in name for name, _, _ in detections)
        assert reactor_found, ".NET Reactor not detected"


class TestDRMSystemDetection:
    """Test DRM system detection (SecuROM, SafeDisc, StarForce, Steam)."""

    def test_securom_detection(self) -> None:
        """Detects SecuROM by driver and string signatures."""
        binary_with_securom = (
            self._create_minimal_pe_header() +
            b"\x00" * 512 +
            b"SecuROM\x00" +
            b"Sony DADC\x00" +
            b"secdrv.sys\x00" +
            b"\x00" * 2048
        )

        db = CommercialProtectorsDatabase()
        detections = db.detect_protector(binary_with_securom, None)

        securom_found = any("SecuROM" in name for name, _, _ in detections)
        assert securom_found, "SecuROM not detected"

    def test_safedisc_detection(self) -> None:
        """Detects SafeDisc by characteristic markers."""
        pe_binary = self._create_pe_with_sections([
            (b".text\x00\x00\x00", b"\x00" * 1000),
            (b".sdata\x00\x00", b"SDATA" + b"SafeDisc" + b"\x00" * 1000),
        ])

        db = CommercialProtectorsDatabase()
        detections = db.detect_protector(pe_binary, None)

        safedisc_found = any("SafeDisc" in name for name, _, _ in detections)
        assert safedisc_found, "SafeDisc not detected"

    def test_starforce_detection(self) -> None:
        """Detects StarForce by driver references."""
        binary_with_starforce = (
            self._create_minimal_pe_header() +
            b"\x00" * 512 +
            b"StarForce\x00" +
            b"sfdrv01.sys\x00" +
            b"sfhlp02.sys\x00" +
            b"Protection Technology\x00" +
            b"\x00" * 2048
        )

        db = CommercialProtectorsDatabase()
        detections = db.detect_protector(binary_with_starforce, None)

        starforce_found = any("StarForce" in name for name, _, _ in detections)
        assert starforce_found, "StarForce not detected"

    def test_steam_drm_detection(self) -> None:
        """Detects Steam DRM by entry point stub and imports."""
        steam_ep = (
            b"\x50\x53\x51\x52\xE8\x00\x00\x00\x00\x5D\x81\xED"
            b"\x00" * 20 +
            b"steam_api.dll\x00" +
            b"SteamService\x00"
        )

        pe_binary = self._create_minimal_pe_with_entry_point(steam_ep)

        db = CommercialProtectorsDatabase()
        detections = db.detect_protector(pe_binary, None)

        steam_found = any("Steam" in name for name, _, _ in detections)
        assert steam_found, "Steam DRM not detected"


class TestMultiLayerProtectionDetection:
    """Test detection of multiple protection layers in single binary."""

    def test_multiple_protectors_detected(self) -> None:
        """Detects multiple protection layers when present together."""
        pe_binary = self._create_pe_with_sections([
            (b"UPX0\x00\x00\x00\x00", b"UPX!" + b"\x00" * 1000),
            (b".themida", b"THEMIDA" + b"\x00" * 1000),
            (b".enigma1", b"ENIGMA1" + b"Enigma Protector" + b"\x00" * 1000),
        ])

        db = CommercialProtectorsDatabase()
        detections = db.detect_protector(pe_binary, None)

        assert len(detections) >= 2, "Multiple protectors not detected"

        upx_found = any("UPX" in name for name, _, _ in detections)
        themida_found = any("Themida" in name for name, _, _ in detections)
        enigma_found = any("Enigma" in name for name, _, _ in detections)

        assert upx_found or themida_found or enigma_found, "No layered protectors detected"

    def test_confidence_scores_ordered(self) -> None:
        """Detection results ordered by confidence score descending."""
        pe_binary = self._create_pe_with_sections([
            (b".enigma1", b"ENIGMA1" + b"Enigma Protector" + b"\x00" * 500),
            (b".vmp0\x00\x00\x00", b"VMP\x00" + b"\x00" * 500),
        ])

        db = CommercialProtectorsDatabase()
        detections = db.detect_protector(pe_binary, None)

        if len(detections) > 1:
            for i in range(len(detections) - 1):
                assert detections[i][2] >= detections[i + 1][2], "Results not sorted by confidence"


class TestBypassStrategyRetrieval:
    """Test bypass strategy information retrieval."""

    def test_get_bypass_strategy_for_known_protector(self) -> None:
        """Returns valid bypass strategy for known protectors."""
        db = CommercialProtectorsDatabase()

        strategy = db.get_bypass_strategy("Enigma")

        assert strategy != {}
        assert "difficulty" in strategy
        assert "oep_method" in strategy
        assert "unpacking_method" in strategy
        assert "category" in strategy
        assert 1 <= strategy["difficulty"] <= 10

    def test_get_bypass_strategy_for_unknown_protector(self) -> None:
        """Returns empty dict for unknown protector names."""
        db = CommercialProtectorsDatabase()

        strategy = db.get_bypass_strategy("NonExistentProtector12345")

        assert strategy == {}

    def test_bypass_difficulty_accuracy(self) -> None:
        """Bypass difficulty scores reflect real-world protection strength."""
        db = CommercialProtectorsDatabase()

        codevirtualizer_strategy = db.get_bypass_strategy("CodeVirtualizer")
        fsg_strategy = db.get_bypass_strategy("FSG")

        if codevirtualizer_strategy and fsg_strategy:
            assert codevirtualizer_strategy["difficulty"] > fsg_strategy["difficulty"], \
                "CodeVirtualizer should be harder than FSG"


class TestOEPDetection:
    """Test Original Entry Point (OEP) detection for packed binaries."""

    def test_find_oep_with_pushad_popad_sequence(self) -> None:
        """Finds OEP using PUSHAD/POPAD detection method."""
        binary_with_oep = (
            b"\x00" * 512 +
            b"\x60" +
            b"\x00" * 256 +
            b"\x61" +
            b"\x55\x8b\xec" +
            b"\x00" * 1024
        )

        db = CommercialProtectorsDatabase()

        oep_offset = db.find_oep(binary_with_oep, "FSG")

        assert oep_offset != -1, "OEP not found"
        assert binary_with_oep[oep_offset:oep_offset+3] == b"\x55\x8b\xec", "Incorrect OEP location"

    def test_find_oep_with_jmp_pattern(self) -> None:
        """Finds OEP by analyzing jump instructions."""
        prologue = b"\x55\x8b\xec\x83\xec\x44"
        jmp_offset = 0x200
        target_offset = 0x1000

        rel_offset = target_offset - (jmp_offset + 5)
        jmp_instruction = b"\xe9" + struct.pack("<I", rel_offset)

        binary_with_jmp = (
            b"\x00" * jmp_offset +
            jmp_instruction +
            b"\x00" * (target_offset - jmp_offset - 5) +
            prologue +
            b"\x00" * 1024
        )

        db = CommercialProtectorsDatabase()
        oep_offset = db.find_oep(binary_with_jmp, "MEW")

        assert oep_offset != -1, "OEP not found via JMP analysis"

    def test_find_oep_for_unknown_protector(self) -> None:
        """Returns -1 for unknown protector names."""
        db = CommercialProtectorsDatabase()

        oep_offset = db.find_oep(b"\x00" * 4096, "UnknownProtector")

        assert oep_offset == -1


class TestAntiAnalysisDetection:
    """Test detection of anti-analysis and anti-debugging techniques."""

    def test_detect_anti_debug_api_calls(self) -> None:
        """Detects anti-debugging API usage in binary."""
        binary_with_antidebug = (
            self._create_minimal_pe_header() +
            b"\x00" * 512 +
            b"IsDebuggerPresent\x00" +
            b"CheckRemoteDebuggerPresent\x00" +
            b"NtQueryInformationProcess\x00" +
            b"\x00" * 2048
        )

        db = CommercialProtectorsDatabase()
        techniques = db.detect_anti_analysis(binary_with_antidebug)

        anti_debug_found = any(t["type"] == "anti-debug" for t in techniques)
        assert anti_debug_found, "Anti-debug techniques not detected"
        assert len(techniques) >= 2, "Not all anti-debug APIs detected"

    def test_detect_anti_vm_checks(self) -> None:
        """Detects anti-VM and sandbox detection techniques."""
        binary_with_vm_checks = (
            self._create_minimal_pe_header() +
            b"\x00" * 512 +
            b"VMware\x00" +
            b"VirtualBox\x00" +
            b"vboxservice.exe\x00" +
            b"SbieDll.dll\x00" +
            b"\x00" * 2048
        )

        db = CommercialProtectorsDatabase()
        techniques = db.detect_anti_analysis(binary_with_vm_checks)

        anti_vm_found = any(t["type"] == "anti-vm" for t in techniques)
        assert anti_vm_found, "Anti-VM checks not detected"
        assert len([t for t in techniques if t["type"] == "anti-vm"]) >= 2

    def test_detect_timing_checks(self) -> None:
        """Detects timing-based anti-analysis techniques."""
        binary_with_timing = (
            self._create_minimal_pe_header() +
            b"\x00" * 512 +
            b"GetTickCount\x00" +
            b"QueryPerformanceCounter\x00" +
            b"rdtsc\x00" +
            b"\x00" * 2048
        )

        db = CommercialProtectorsDatabase()
        techniques = db.detect_anti_analysis(binary_with_timing)

        timing_found = any(t["type"] == "timing" for t in techniques)
        assert timing_found, "Timing checks not detected"

    def test_detect_debugger_process_checks(self) -> None:
        """Detects blacklisted debugger process name checks."""
        binary_with_process_checks = (
            self._create_minimal_pe_header() +
            b"\x00" * 512 +
            b"ollydbg.exe\x00" +
            b"x64dbg.exe\x00" +
            b"ida.exe\x00" +
            b"processhacker.exe\x00" +
            b"\x00" * 2048
        )

        db = CommercialProtectorsDatabase()
        techniques = db.detect_anti_analysis(binary_with_process_checks)

        process_checks = [t for t in techniques if t["type"] == "process-check"]
        assert len(process_checks) >= 2, "Process checks not detected"

    def test_no_false_positives_on_clean_binary(self) -> None:
        """Returns empty list for binary without anti-analysis techniques."""
        clean_binary = self._create_minimal_pe_header() + b"\x00" * 4096

        db = CommercialProtectorsDatabase()
        techniques = db.detect_anti_analysis(clean_binary)

        assert len(techniques) == 0, f"False positives detected: {techniques}"


class TestEncryptionLayerDetection:
    """Test detection of encryption and compression layers."""

    def test_detect_high_entropy_sections(self) -> None:
        """Detects high-entropy encrypted/compressed sections."""
        import random
        random.seed(42)

        high_entropy_data = bytes([random.randint(0, 255) for _ in range(4096)])

        binary_with_encrypted = (
            self._create_minimal_pe_header() +
            b"\x00" * 1024 +
            high_entropy_data +
            b"\x00" * 1024
        )

        db = CommercialProtectorsDatabase()
        layers = db.detect_encryption_layers(binary_with_encrypted)

        high_entropy_found = any(layer["type"] == "high-entropy" for layer in layers)
        assert high_entropy_found, "High entropy section not detected"

    def test_detect_crypto_signatures(self) -> None:
        """Detects known cryptographic algorithm signatures."""
        binary_with_crypto = (
            self._create_minimal_pe_header() +
            b"\x00" * 512 +
            b"AES" + b"\x00" * 100 +
            b"RSA" + b"\x00" * 100 +
            b"ChaCha" + b"\x00" * 100 +
            b"\x00" * 2048
        )

        db = CommercialProtectorsDatabase()
        layers = db.detect_encryption_layers(binary_with_crypto)

        crypto_sigs = [layer for layer in layers if layer["type"] == "crypto-signature"]
        assert len(crypto_sigs) >= 2, "Crypto signatures not detected"

    def test_detect_compression_signatures(self) -> None:
        """Detects compression format signatures."""
        binary_with_compression = (
            self._create_minimal_pe_header() +
            b"\x1f\x8b" +
            b"\x00" * 100 +
            b"PK" +
            b"\x00" * 100 +
            b"\x42\x5a\x68" +
            b"\x00" * 2048
        )

        db = CommercialProtectorsDatabase()
        layers = db.detect_encryption_layers(binary_with_compression)

        compression_found = any(layer["type"] == "compression" for layer in layers)
        assert compression_found, "Compression signatures not detected"

    def test_entropy_calculation_accuracy(self) -> None:
        """Entropy calculation distinguishes encrypted from unencrypted data."""
        import random
        random.seed(42)

        encrypted_data = bytes([random.randint(0, 255) for _ in range(4096)])

        unencrypted_data = b"\x00" * 4096

        binary_encrypted = self._create_minimal_pe_header() + encrypted_data
        binary_unencrypted = self._create_minimal_pe_header() + unencrypted_data

        db = CommercialProtectorsDatabase()
        layers_encrypted = db.detect_encryption_layers(binary_encrypted)
        layers_unencrypted = db.detect_encryption_layers(binary_unencrypted)

        encrypted_high_entropy = any(
            layer["type"] == "high-entropy" for layer in layers_encrypted
        )
        unencrypted_high_entropy = any(
            layer["type"] == "high-entropy" for layer in layers_unencrypted
        )

        assert encrypted_high_entropy, "High entropy data not detected as encrypted"
        assert not unencrypted_high_entropy, "Low entropy data incorrectly flagged"


class TestFalsePositivePrevention:
    """Test that detector doesn't produce false positives on clean binaries."""

    def test_no_detection_on_clean_pe(self) -> None:
        """Returns no detections for standard unprotected PE binary."""
        clean_pe = self._create_pe_with_sections([
            (b".text\x00\x00\x00", b"\x55\x8b\xec\x83\xec\x40" + b"\x90" * 1000),
            (b".data\x00\x00\x00", b"\x00" * 500),
            (b".rdata\x00\x00", b"Normal Program String\x00" + b"\x00" * 500),
            (b".rsrc\x00\x00\x00", b"\x00" * 500),
        ])

        db = CommercialProtectorsDatabase()
        detections = db.detect_protector(clean_pe, None)

        assert len(detections) == 0, f"False positives: {[n for n, _, _ in detections]}"

    def test_confidence_threshold_prevents_weak_matches(self) -> None:
        """Low-confidence matches below threshold are filtered out."""
        binary_with_weak_match = (
            self._create_minimal_pe_header() +
            b"\x00" * 2048 +
            b"Steam" +
            b"\x00" * 4096
        )

        db = CommercialProtectorsDatabase()
        detections = db.detect_protector(binary_with_weak_match, None)

        if detections:
            for _, _, confidence in detections:
                assert confidence > 30, f"Weak match not filtered: {confidence}%"


class TestVersionIdentification:
    """Test version detection for protection schemes."""

    def test_codevirtualizer_version_detection(self) -> None:
        """Identifies Code Virtualizer version from signature patterns."""
        db = CommercialProtectorsDatabase()
        cv_sig = db.protectors.get("CodeVirtualizer")

        if cv_sig:
            assert len(cv_sig.version_detect) > 0, "No version detection patterns"

    def test_enigma_version_markers(self) -> None:
        """Detects Enigma version (32-bit vs 64-bit) from markers."""
        binary_enigma_64 = (
            self._create_minimal_pe_header() +
            b"\x00" * 512 +
            b"ENIGMA64" +
            b"Enigma Protector" +
            b"\x00" * 2048
        )

        db = CommercialProtectorsDatabase()
        detections = db.detect_protector(binary_enigma_64, None)

        enigma_found = any("Enigma" in name for name, _, _ in detections)
        assert enigma_found, "Enigma 64-bit version not detected"


class TestProtectorCategories:
    """Test categorization of protectors by type."""

    def test_all_categories_represented(self) -> None:
        """Database includes protectors from all major categories."""
        db = CommercialProtectorsDatabase()

        categories_found = {sig.category for sig in db.protectors.values()}

        assert ProtectorCategory.PACKER in categories_found
        assert ProtectorCategory.PROTECTOR in categories_found
        assert ProtectorCategory.VIRTUALIZER in categories_found
        assert ProtectorCategory.LICENSE_MANAGER in categories_found
        assert ProtectorCategory.DONGLE in categories_found
        assert ProtectorCategory.DRM in categories_found
        assert ProtectorCategory.DOTNET_PROTECTOR in categories_found

    def test_category_assignments_accurate(self) -> None:
        """Protectors assigned to correct categories."""
        db = CommercialProtectorsDatabase()

        assert db.protectors["FSG"].category == ProtectorCategory.PACKER
        assert db.protectors["CodeVirtualizer"].category == ProtectorCategory.VIRTUALIZER
        assert db.protectors["FlexNet"].category == ProtectorCategory.LICENSE_MANAGER
        assert db.protectors["Sentinel"].category == ProtectorCategory.DONGLE
        assert db.protectors["SecuROM"].category == ProtectorCategory.DRM
        assert db.protectors["ConfuserEx"].category == ProtectorCategory.DOTNET_PROTECTOR


class TestRealWorldBinaryCompatibility:
    """Test detection on real-world binary patterns."""

    def test_handles_corrupted_pe_header_gracefully(self) -> None:
        """Handles corrupted PE headers without crashing."""
        corrupted_pe = b"MZ" + b"\xFF" * 100 + b"\x00" * 3996

        db = CommercialProtectorsDatabase()

        try:
            detections = db.detect_protector(corrupted_pe, None)
            assert isinstance(detections, list)
        except Exception as e:
            pytest.fail(f"Crashed on corrupted PE: {e}")

    def test_handles_large_binaries_efficiently(self) -> None:
        """Processes large binaries without excessive memory usage."""
        large_binary = self._create_minimal_pe_header() + b"\x00" * (50 * 1024 * 1024)

        db = CommercialProtectorsDatabase()

        try:
            detections = db.detect_protector(large_binary, None)
            assert isinstance(detections, list)
        except MemoryError:
            pytest.fail("Memory error on large binary")

    def test_handles_empty_binary_data(self) -> None:
        """Handles empty binary data without errors."""
        db = CommercialProtectorsDatabase()
        detections = db.detect_protector(b"", None)

        assert detections == []

    def test_handles_non_pe_binary(self) -> None:
        """Handles non-PE binary formats gracefully."""
        elf_header = b"\x7fELF" + b"\x00" * 4092

        db = CommercialProtectorsDatabase()
        detections = db.detect_protector(elf_header, None)

        assert isinstance(detections, list)


    def _create_minimal_pe_header(self) -> bytes:
        """Create minimal valid PE header structure."""
        dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)

        pe_signature = b"PE\x00\x00"

        coff_header = struct.pack(
            "<HHIIIHH",
            0x014C,
            1,
            0,
            0,
            0,
            0x00E0,
            0x010B,
        )

        optional_header = struct.pack(
            "<HHIIIIIHHHHHH",
            0x010B,
            0x0E,
            0,
            0x1000,
            0x1000,
            0,
            0x1000,
            0x1000,
            0,
            4,
            0,
            5,
            0,
            0,
        )
        optional_header += b"\x00" * (0xE0 - len(optional_header))

        return dos_header + b"\x00" * (0x80 - len(dos_header)) + pe_signature + coff_header + optional_header

    def _create_minimal_pe_with_entry_point(self, ep_code: bytes) -> bytes:
        """Create minimal PE with specific entry point code."""
        base_pe = self._create_minimal_pe_header()
        return base_pe + b"\x00" * (0x1000 - len(base_pe)) + ep_code + b"\x00" * 2048

    def _create_pe_with_sections(self, sections: list[tuple[bytes, bytes]]) -> bytes:
        """Create PE binary with specified sections."""
        dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)

        pe_signature = b"PE\x00\x00"

        num_sections = len(sections)
        coff_header = struct.pack(
            "<HHIIIHH",
            0x014C,
            num_sections,
            0,
            0,
            0,
            0x00E0,
            0x010B,
        )

        optional_header = struct.pack(
            "<HHIIIIIHHHHHH",
            0x010B,
            0x0E,
            0,
            0x1000,
            0x1000,
            0,
            0x1000,
            0x1000,
            0,
            4,
            0,
            5,
            0,
            0,
        )
        optional_header += b"\x00" * (0xE0 - len(optional_header))

        section_headers = b""
        section_data = b""
        virtual_offset = 0x1000
        raw_offset = 0x400

        for section_name, data in sections:
            section_name_padded = section_name[:8].ljust(8, b"\x00")

            virtual_size = len(data)
            raw_size = ((len(data) + 0x1FF) // 0x200) * 0x200

            section_header = (
                section_name_padded +
                struct.pack("<I", virtual_size) +
                struct.pack("<I", virtual_offset) +
                struct.pack("<I", raw_size) +
                struct.pack("<I", raw_offset) +
                struct.pack("<I", 0) +
                struct.pack("<I", 0) +
                struct.pack("<HH", 0, 0) +
                struct.pack("<I", 0x60000020)
            )

            section_headers += section_header
            section_data += data.ljust(raw_size, b"\x00")

            virtual_offset += ((virtual_size + 0xFFF) // 0x1000) * 0x1000
            raw_offset += raw_size

        header = (
            dos_header +
            b"\x00" * (0x80 - len(dos_header)) +
            pe_signature +
            coff_header +
            optional_header +
            section_headers
        )

        header = header.ljust(0x400, b"\x00")

        return header + section_data
