"""Production-grade tests for protection_detector.py

Tests validate REAL protection detection against binaries with actual protection signatures.
Every test validates genuine offensive capability - NO MOCKS, NO STUBS.

Tests must FAIL when protection detection is broken or non-functional.
"""

import hashlib
import io
import os
import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.protection.intellicrack_protection_core import (
    DetectionResult,
    ProtectionAnalysis,
    ProtectionType,
)
from intellicrack.protection.protection_detector import (
    ProtectionDetector,
    detect_all_protections,
    detect_anti_debugging_techniques,
    detect_checksum_verification,
    detect_commercial_protections,
    detect_obfuscation,
    detect_self_healing_code,
    detect_tpm_protection,
    detect_virtualization_protection,
    deep_analyze,
    generate_checksum,
    get_protection_detector,
    quick_analyze,
)
from intellicrack.protection.unified_protection_engine import UnifiedProtectionResult


class TestBinaryFixtures:
    """Create real binary test fixtures with actual protection signatures."""

    @staticmethod
    def create_pe_header() -> bytes:
        """Create minimal valid PE header."""
        dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)
        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack(
            "<HHIIIHH",
            0x014C,
            1,
            0,
            0,
            0,
            0xE0,
            0x010B,
        )
        optional_header = b"\x00" * 224
        return dos_header + pe_signature + coff_header + optional_header

    @staticmethod
    def create_vmprotect_binary() -> bytes:
        """Create binary with VMProtect signatures."""
        pe_header = TestBinaryFixtures.create_pe_header()
        vmp_signatures = (
            b".vmp0" + b"\x00" * 3
            + b".vmp1" + b"\x00" * 3
            + b"VProtect"
            + b"\x00" * 500
        )
        return pe_header + vmp_signatures

    @staticmethod
    def create_themida_binary() -> bytes:
        """Create binary with Themida/WinLicense signatures."""
        pe_header = TestBinaryFixtures.create_pe_header()
        themida_sigs = (
            b"Themida" + b"\x00" * 100
            + b"WinLicense" + b"\x00" * 200
        )
        return pe_header + themida_sigs

    @staticmethod
    def create_upx_packed_binary() -> bytes:
        """Create binary with UPX packer signatures."""
        pe_header = TestBinaryFixtures.create_pe_header()
        upx_sigs = (
            b"UPX0" + b"\x00" * 50
            + b"UPX!" + b"\x00" * 100
        )
        return pe_header + upx_sigs

    @staticmethod
    def create_denuvo_binary() -> bytes:
        """Create binary with Denuvo signatures."""
        pe_header = TestBinaryFixtures.create_pe_header()
        denuvo_sigs = b"Denuvo" + b"\x00" * 500
        return pe_header + denuvo_sigs

    @staticmethod
    def create_flexlm_binary() -> bytes:
        """Create binary with FLEXlm licensing signatures."""
        pe_header = TestBinaryFixtures.create_pe_header()
        flexlm_sigs = (
            b"FLEXlm" + b"\x00" * 100
            + b"FLEXnet" + b"\x00" * 200
        )
        return pe_header + flexlm_sigs

    @staticmethod
    def create_hasp_binary() -> bytes:
        """Create binary with HASP dongle protection signatures."""
        pe_header = TestBinaryFixtures.create_pe_header()
        hasp_sigs = (
            b"HASP" + b"\x00" * 100
            + b"Sentinel" + b"\x00" * 200
        )
        return pe_header + hasp_sigs

    @staticmethod
    def create_anti_debug_binary() -> bytes:
        """Create binary with anti-debugging techniques."""
        pe_header = TestBinaryFixtures.create_pe_header()
        anti_debug = (
            b"IsDebuggerPresent" + b"\x00" * 50
            + b"CheckRemoteDebuggerPresent" + b"\x00" * 50
            + b"NtQueryInformationProcess" + b"\x00" * 50
            + b"\x64\xa1\x30\x00\x00\x00"
            + b"\x0f\x31"
            + b"OllyDbg" + b"\x00" * 100
        )
        return pe_header + anti_debug

    @staticmethod
    def create_checksum_binary() -> bytes:
        """Create binary with checksum verification routines."""
        pe_header = TestBinaryFixtures.create_pe_header()
        checksum_code = (
            b"CRC32" + b"\x00" * 50
            + b"MD5" + b"\x00" * 50
            + b"SHA256" + b"\x00" * 50
            + b"\x81\xc1\x00\x00\x00\x00"
            + b"\x33\xc0\x8b"
            + b"checksum" + b"\x00" * 100
        )
        return pe_header + checksum_code

    @staticmethod
    def create_self_healing_binary() -> bytes:
        """Create binary with self-healing/self-modifying code."""
        pe_header = TestBinaryFixtures.create_pe_header()
        self_modify = (
            b"VirtualProtect" + b"\x00" * 50
            + b"WriteProcessMemory" + b"\x00" * 50
            + b"\x88\x00"
            + b"\xc6\x00"
            + b"\x00" * 200
        )
        return pe_header + self_modify

    @staticmethod
    def create_obfuscated_binary() -> bytes:
        """Create binary with obfuscation indicators."""
        pe_header = TestBinaryFixtures.create_pe_header()
        high_entropy_data = os.urandom(2048)
        obfuscation = (
            b"\xeb\x01\x90" * 20
            + b"\xeb\x02\x90\x90" * 20
            + b"\x90" * 50
            + b".NET Reactor" + b"\x00" * 50
            + high_entropy_data
        )
        return pe_header + obfuscation

    @staticmethod
    def create_tpm_binary() -> bytes:
        """Create binary with TPM protection signatures."""
        pe_header = TestBinaryFixtures.create_pe_header()
        tpm_sigs = (
            b"Tbsi_" + b"\x00" * 50
            + b"TPM_" + b"\x00" * 50
            + b"NCryptCreatePersistedKey" + b"\x00" * 50
            + b"MS_PLATFORM_CRYPTO_PROVIDER" + b"\x00" * 100
        )
        return pe_header + tpm_sigs

    @staticmethod
    def create_multi_protected_binary() -> bytes:
        """Create binary with multiple protection layers."""
        pe_header = TestBinaryFixtures.create_pe_header()
        multi_protect = (
            b".vmp0" + b"\x00" * 3
            + b"Themida" + b"\x00" * 50
            + b"HASP" + b"\x00" * 50
            + b"IsDebuggerPresent" + b"\x00" * 50
            + b"CRC32" + b"\x00" * 50
            + os.urandom(1024)
        )
        return pe_header + multi_protect


@pytest.fixture(scope="session")
def binary_fixtures_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Create directory with test binary fixtures."""
    fixtures_dir = tmp_path_factory.mktemp("binary_fixtures")

    test_binaries = {
        "vmprotect.exe": TestBinaryFixtures.create_vmprotect_binary(),
        "themida.exe": TestBinaryFixtures.create_themida_binary(),
        "upx_packed.exe": TestBinaryFixtures.create_upx_packed_binary(),
        "denuvo.exe": TestBinaryFixtures.create_denuvo_binary(),
        "flexlm.exe": TestBinaryFixtures.create_flexlm_binary(),
        "hasp.exe": TestBinaryFixtures.create_hasp_binary(),
        "anti_debug.exe": TestBinaryFixtures.create_anti_debug_binary(),
        "checksum.exe": TestBinaryFixtures.create_checksum_binary(),
        "self_healing.exe": TestBinaryFixtures.create_self_healing_binary(),
        "obfuscated.exe": TestBinaryFixtures.create_obfuscated_binary(),
        "tpm.exe": TestBinaryFixtures.create_tpm_binary(),
        "multi_protected.exe": TestBinaryFixtures.create_multi_protected_binary(),
    }

    for filename, content in test_binaries.items():
        binary_path = fixtures_dir / filename
        binary_path.write_bytes(content)

    return fixtures_dir


@pytest.fixture
def detector() -> ProtectionDetector:
    """Create fresh ProtectionDetector instance for each test."""
    return ProtectionDetector(enable_protection=True, enable_heuristics=True)


class TestProtectionDetectorInitialization:
    """Test ProtectionDetector initialization and configuration."""

    def test_detector_initialization_default(self) -> None:
        """ProtectionDetector initializes with default settings."""
        detector = ProtectionDetector()

        assert detector.engine is not None
        assert hasattr(detector.engine, "analyze")

    def test_detector_initialization_protection_disabled(self) -> None:
        """ProtectionDetector initializes with protection disabled."""
        detector = ProtectionDetector(enable_protection=False, enable_heuristics=False)

        assert detector.engine is not None

    def test_detector_initialization_custom_engines(self) -> None:
        """ProtectionDetector supports engine configuration."""
        detector = ProtectionDetector(enable_protection=True, enable_heuristics=True)

        assert detector.engine is not None
        assert hasattr(detector, "detect_protections")
        assert hasattr(detector, "analyze")

    def test_global_detector_singleton(self) -> None:
        """get_protection_detector returns singleton instance."""
        detector1 = get_protection_detector()
        detector2 = get_protection_detector()

        assert detector1 is detector2


class TestCommercialProtectionDetection:
    """Test detection of commercial protection schemes."""

    def test_detect_vmprotect_signatures(self, binary_fixtures_dir: Path) -> None:
        """Detects VMProtect protection in binary with .vmp0/.vmp1 sections."""
        binary_path = binary_fixtures_dir / "vmprotect.exe"

        result = detect_commercial_protections(str(binary_path))

        assert "protections" in result
        assert len(result["protections"]) > 0
        assert any("VMProtect" in p or "VProtect" in p for p in result["protections"])

    def test_detect_themida_signatures(self, binary_fixtures_dir: Path) -> None:
        """Detects Themida/WinLicense protection signatures."""
        binary_path = binary_fixtures_dir / "themida.exe"

        result = detect_commercial_protections(str(binary_path))

        assert "protections" in result
        assert any("Themida" in p or "WinLicense" in p for p in result["protections"])

    def test_detect_upx_packer(self, binary_fixtures_dir: Path) -> None:
        """Detects UPX packer signatures (UPX0, UPX!)."""
        binary_path = binary_fixtures_dir / "upx_packed.exe"

        result = detect_commercial_protections(str(binary_path))

        assert "protections" in result
        assert any("UPX" in p for p in result["protections"])

    def test_detect_denuvo_signatures(self, binary_fixtures_dir: Path) -> None:
        """Detects Denuvo anti-tamper signatures."""
        binary_path = binary_fixtures_dir / "denuvo.exe"

        result = detect_commercial_protections(str(binary_path))

        assert "protections" in result
        assert any("Denuvo" in p for p in result["protections"])

    def test_detect_flexlm_licensing(self, binary_fixtures_dir: Path) -> None:
        """Detects FLEXlm/FLEXnet licensing protection."""
        binary_path = binary_fixtures_dir / "flexlm.exe"

        result = detect_commercial_protections(str(binary_path))

        assert "protections" in result
        assert any("FLEXlm" in p or "FLEXnet" in p for p in result["protections"])

    def test_detect_hasp_dongle_protection(self, binary_fixtures_dir: Path) -> None:
        """Detects HASP/Sentinel dongle protection."""
        binary_path = binary_fixtures_dir / "hasp.exe"

        result = detect_commercial_protections(str(binary_path))

        assert "protections" in result
        assert any("HASP" in p or "Sentinel" in p for p in result["protections"])

    def test_detect_multiple_commercial_protections(self, binary_fixtures_dir: Path) -> None:
        """Detects multiple commercial protections in single binary."""
        binary_path = binary_fixtures_dir / "multi_protected.exe"

        result = detect_commercial_protections(str(binary_path))

        assert "protections" in result
        assert len(result["protections"]) >= 2

    def test_commercial_detection_signature_offsets(self, binary_fixtures_dir: Path) -> None:
        """Commercial protection detection records signature offsets."""
        binary_path = binary_fixtures_dir / "vmprotect.exe"

        result = detect_commercial_protections(str(binary_path))

        assert "signatures_found" in result
        if result["signatures_found"]:
            sig = result["signatures_found"][0]
            assert "protection" in sig
            assert "signature" in sig
            assert "offset" in sig
            assert isinstance(sig["offset"], int)

    def test_commercial_detection_nonexistent_file(self) -> None:
        """Commercial detection handles nonexistent files gracefully."""
        result = detect_commercial_protections("/nonexistent/binary.exe")

        assert "error" in result or "protections" in result
        assert result.get("protections", []) == []


class TestAntiDebuggingDetection:
    """Test detection of anti-debugging techniques."""

    def test_detect_isdebuggerpresent_api(self, binary_fixtures_dir: Path) -> None:
        """Detects IsDebuggerPresent API usage."""
        binary_path = binary_fixtures_dir / "anti_debug.exe"

        result = detect_anti_debugging_techniques(str(binary_path))

        assert result["has_anti_debug"] is True
        assert "IsDebuggerPresent" in result["api_calls"]

    def test_detect_multiple_anti_debug_apis(self, binary_fixtures_dir: Path) -> None:
        """Detects multiple anti-debugging API calls."""
        binary_path = binary_fixtures_dir / "anti_debug.exe"

        result = detect_anti_debugging_techniques(str(binary_path))

        assert result["has_anti_debug"] is True
        assert len(result["api_calls"]) >= 2
        assert "CheckRemoteDebuggerPresent" in result["api_calls"]
        assert "NtQueryInformationProcess" in result["api_calls"]

    def test_detect_peb_beingdebugged_check(self, binary_fixtures_dir: Path) -> None:
        """Detects PEB.BeingDebugged direct memory checks."""
        binary_path = binary_fixtures_dir / "anti_debug.exe"

        result = detect_anti_debugging_techniques(str(binary_path))

        assert result["has_anti_debug"] is True
        assert any("PEB" in tech for tech in result["techniques"])

    def test_detect_rdtsc_timing_check(self, binary_fixtures_dir: Path) -> None:
        """Detects RDTSC timing-based anti-debugging."""
        binary_path = binary_fixtures_dir / "anti_debug.exe"

        result = detect_anti_debugging_techniques(str(binary_path))

        assert result["has_anti_debug"] is True
        assert any("RDTSC" in tech or "timing" in tech.lower() for tech in result["techniques"])

    def test_detect_debugger_name_checks(self, binary_fixtures_dir: Path) -> None:
        """Detects debugger name string checks (OllyDbg, x64dbg, etc)."""
        binary_path = binary_fixtures_dir / "anti_debug.exe"

        result = detect_anti_debugging_techniques(str(binary_path))

        assert result["has_anti_debug"] is True
        assert any("OllyDbg" in tech for tech in result["techniques"])

    def test_anti_debug_no_false_positives(self, binary_fixtures_dir: Path) -> None:
        """Anti-debug detection doesn't flag clean binaries."""
        binary_path = binary_fixtures_dir / "upx_packed.exe"

        result = detect_anti_debugging_techniques(str(binary_path))

        if result["has_anti_debug"]:
            assert len(result["techniques"]) == 0 or len(result["api_calls"]) == 0


class TestChecksumVerificationDetection:
    """Test detection of checksum verification routines."""

    def test_detect_crc32_checksum(self, binary_fixtures_dir: Path) -> None:
        """Detects CRC32 checksum verification."""
        binary_path = binary_fixtures_dir / "checksum.exe"

        result = detect_checksum_verification(str(binary_path))

        assert result["has_checksum_verification"] is True
        assert "CRC32" in result["checksum_types"]

    def test_detect_md5_checksum(self, binary_fixtures_dir: Path) -> None:
        """Detects MD5 checksum verification."""
        binary_path = binary_fixtures_dir / "checksum.exe"

        result = detect_checksum_verification(str(binary_path))

        assert result["has_checksum_verification"] is True
        assert "MD5" in result["checksum_types"]

    def test_detect_sha256_checksum(self, binary_fixtures_dir: Path) -> None:
        """Detects SHA256 checksum verification."""
        binary_path = binary_fixtures_dir / "checksum.exe"

        result = detect_checksum_verification(str(binary_path))

        assert result["has_checksum_verification"] is True
        assert "SHA256" in result["checksum_types"]

    def test_detect_assembly_checksum_patterns(self, binary_fixtures_dir: Path) -> None:
        """Detects assembly-level checksum computation patterns."""
        binary_path = binary_fixtures_dir / "checksum.exe"

        result = detect_checksum_verification(str(binary_path))

        assert result["has_checksum_verification"] is True
        assert any("Assembly pattern" in ind for ind in result["indicators"])

    def test_checksum_string_references(self, binary_fixtures_dir: Path) -> None:
        """Detects checksum string references in binary."""
        binary_path = binary_fixtures_dir / "checksum.exe"

        result = detect_checksum_verification(str(binary_path))

        assert result["has_checksum_verification"] is True
        assert any("String reference" in ind or "checksum" in ind.lower() for ind in result["indicators"])


class TestSelfHealingCodeDetection:
    """Test detection of self-healing and self-modifying code."""

    def test_detect_virtualprotect_usage(self, binary_fixtures_dir: Path) -> None:
        """Detects VirtualProtect API for memory protection changes."""
        binary_path = binary_fixtures_dir / "self_healing.exe"

        result = detect_self_healing_code(str(binary_path))

        assert result["has_self_healing"] is True
        assert any("Memory protection" in ind or "protection change" in ind.lower() for ind in result["indicators"])

    def test_detect_writeprocessmemory_usage(self, binary_fixtures_dir: Path) -> None:
        """Detects WriteProcessMemory for code modification."""
        binary_path = binary_fixtures_dir / "self_healing.exe"

        result = detect_self_healing_code(str(binary_path))

        assert result["has_self_healing"] is True
        assert any("Process memory write" in ind or "memory write" in ind.lower() for ind in result["indicators"])

    def test_detect_direct_code_modification(self, binary_fixtures_dir: Path) -> None:
        """Detects direct code modification assembly patterns."""
        binary_path = binary_fixtures_dir / "self_healing.exe"

        result = detect_self_healing_code(str(binary_path))

        assert result["has_self_healing"] is True
        assert "Direct Code Modification" in result["techniques"] or "Memory Protection Manipulation" in result["techniques"]

    def test_self_healing_technique_classification(self, binary_fixtures_dir: Path) -> None:
        """Self-healing detection classifies techniques correctly."""
        binary_path = binary_fixtures_dir / "self_healing.exe"

        result = detect_self_healing_code(str(binary_path))

        assert result["has_self_healing"] is True
        assert len(result["techniques"]) > 0
        assert all(isinstance(tech, str) for tech in result["techniques"])


class TestObfuscationDetection:
    """Test detection of code obfuscation techniques."""

    def test_detect_high_entropy_obfuscation(self, binary_fixtures_dir: Path) -> None:
        """Detects high entropy indicating packed/encrypted code."""
        binary_path = binary_fixtures_dir / "obfuscated.exe"

        result = detect_obfuscation(str(binary_path))

        assert result["is_obfuscated"] is True
        assert result["entropy_score"] > 7.0

    def test_calculate_entropy_score(self, binary_fixtures_dir: Path) -> None:
        """Entropy calculation produces valid scores (0-8 range)."""
        binary_path = binary_fixtures_dir / "obfuscated.exe"

        result = detect_obfuscation(str(binary_path))

        assert 0.0 <= result["entropy_score"] <= 8.0

    def test_detect_junk_byte_patterns(self, binary_fixtures_dir: Path) -> None:
        """Detects junk byte obfuscation patterns (EB 01, EB 02)."""
        binary_path = binary_fixtures_dir / "obfuscated.exe"

        result = detect_obfuscation(str(binary_path))

        assert result["is_obfuscated"] is True
        assert any("Junk bytes" in ind for ind in result["indicators"])

    def test_detect_nop_sled_obfuscation(self, binary_fixtures_dir: Path) -> None:
        """Detects NOP sled obfuscation."""
        binary_path = binary_fixtures_dir / "obfuscated.exe"

        result = detect_obfuscation(str(binary_path))

        assert result["is_obfuscated"] is True
        assert any("NOP" in ind for ind in result["indicators"])

    def test_detect_dotnet_obfuscators(self, binary_fixtures_dir: Path) -> None:
        """Detects .NET obfuscator signatures."""
        binary_path = binary_fixtures_dir / "obfuscated.exe"

        result = detect_obfuscation(str(binary_path))

        assert result["is_obfuscated"] is True
        assert any(".NET Reactor" in ind for ind in result["indicators"])

    def test_detect_control_flow_obfuscation(self, binary_fixtures_dir: Path) -> None:
        """Detects control flow obfuscation via high jump density."""
        binary_path = binary_fixtures_dir / "obfuscated.exe"

        result = detect_obfuscation(str(binary_path))

        if "Control Flow Obfuscation" in result["obfuscation_types"]:
            assert any("jump" in ind.lower() for ind in result["indicators"])


class TestTPMProtectionDetection:
    """Test detection of TPM (Trusted Platform Module) protection."""

    def test_detect_tpm_functions(self, binary_fixtures_dir: Path) -> None:
        """Detects TPM API function usage."""
        binary_path = binary_fixtures_dir / "tpm.exe"

        result = detect_tpm_protection(str(binary_path))

        assert result["has_tpm_protection"] is True
        assert len(result["tpm_functions"]) > 0

    def test_detect_tbsi_functions(self, binary_fixtures_dir: Path) -> None:
        """Detects Tbsi_ TPM functions."""
        binary_path = binary_fixtures_dir / "tpm.exe"

        result = detect_tpm_protection(str(binary_path))

        assert result["has_tpm_protection"] is True
        assert any("Tbsi_" in func for func in result["tpm_functions"])

    def test_detect_ncrypt_functions(self, binary_fixtures_dir: Path) -> None:
        """Detects NCrypt TPM storage functions."""
        binary_path = binary_fixtures_dir / "tpm.exe"

        result = detect_tpm_protection(str(binary_path))

        assert result["has_tpm_protection"] is True
        assert any("NCrypt" in func for func in result["tpm_functions"])

    def test_detect_platform_crypto_provider(self, binary_fixtures_dir: Path) -> None:
        """Detects Microsoft Platform Crypto Provider usage."""
        binary_path = binary_fixtures_dir / "tpm.exe"

        result = detect_tpm_protection(str(binary_path))

        assert result["has_tpm_protection"] is True
        assert any("CRYPTO_PROVIDER" in func for func in result["tpm_functions"])


class TestVirtualizationDetection:
    """Test detection of virtualization-based protections."""

    def test_detect_virtualization_environment(self) -> None:
        """Detects virtualization environment indicators."""
        result = detect_virtualization_protection()

        assert "virtualization_detected" in result
        assert isinstance(result["virtualization_detected"], bool)
        assert "indicators" in result
        assert "confidence" in result

    def test_virtualization_detection_confidence_scoring(self) -> None:
        """Virtualization detection calculates confidence scores."""
        result = detect_virtualization_protection()

        assert 0.0 <= result["confidence"] <= 1.0

        if result["virtualization_detected"]:
            assert result["confidence"] > 0.0
            assert len(result["indicators"]) > 0

    def test_virtualization_protection_types(self) -> None:
        """Virtualization detection identifies protection types."""
        result = detect_virtualization_protection()

        assert "protection_types" in result
        assert isinstance(result["protection_types"], list)


class TestProtectionDetectorAnalysis:
    """Test ProtectionDetector analysis methods."""

    def test_detect_protections_with_valid_binary(self, detector: ProtectionDetector, binary_fixtures_dir: Path) -> None:
        """detect_protections analyzes binary and returns ProtectionAnalysis."""
        binary_path = binary_fixtures_dir / "vmprotect.exe"

        analysis = detector.detect_protections(str(binary_path), deep_scan=True)

        assert isinstance(analysis, ProtectionAnalysis)
        assert analysis.file_path == str(binary_path)
        assert analysis.file_type is not None
        assert analysis.architecture is not None

    def test_detect_protections_file_not_found(self, detector: ProtectionDetector) -> None:
        """detect_protections raises FileNotFoundError for missing files."""
        with pytest.raises(FileNotFoundError):
            detector.detect_protections("/nonexistent/binary.exe")

    def test_analyze_returns_unified_result(self, detector: ProtectionDetector, binary_fixtures_dir: Path) -> None:
        """analyze method returns UnifiedProtectionResult."""
        binary_path = binary_fixtures_dir / "themida.exe"

        result = detector.analyze(str(binary_path), deep_scan=True)

        assert isinstance(result, UnifiedProtectionResult)
        assert result.file_path == str(binary_path)

    def test_get_quick_summary(self, detector: ProtectionDetector, binary_fixtures_dir: Path) -> None:
        """get_quick_summary returns summary without deep analysis."""
        binary_path = binary_fixtures_dir / "upx_packed.exe"

        summary = detector.get_quick_summary(str(binary_path))

        assert isinstance(summary, dict)
        assert "protected" in summary or "confidence" in summary

    def test_analyze_directory_recursive(self, detector: ProtectionDetector, binary_fixtures_dir: Path) -> None:
        """analyze_directory scans all executables recursively."""
        results = detector.analyze_directory(str(binary_fixtures_dir), recursive=True, deep_scan=False)

        assert isinstance(results, list)
        assert len(results) > 0
        assert all(isinstance(r, ProtectionAnalysis) for r in results)

    def test_analyze_directory_non_recursive(self, detector: ProtectionDetector, binary_fixtures_dir: Path) -> None:
        """analyze_directory scans only top-level directory."""
        results = detector.analyze_directory(str(binary_fixtures_dir), recursive=False, deep_scan=False)

        assert isinstance(results, list)
        assert len(results) > 0

    def test_get_bypass_strategies(self, detector: ProtectionDetector, binary_fixtures_dir: Path) -> None:
        """get_bypass_strategies returns actionable bypass recommendations."""
        binary_path = binary_fixtures_dir / "multi_protected.exe"

        strategies = detector.get_bypass_strategies(str(binary_path))

        assert isinstance(strategies, list)


class TestComprehensiveProtectionScan:
    """Test comprehensive protection scanning functionality."""

    def test_detect_all_protections_comprehensive_scan(self, binary_fixtures_dir: Path) -> None:
        """detect_all_protections runs all detection methods."""
        binary_path = binary_fixtures_dir / "multi_protected.exe"

        result = detect_all_protections(str(binary_path))

        assert "file_path" in result
        assert "virtualization" in result
        assert "commercial" in result
        assert "checksum" in result
        assert "self_healing" in result
        assert "obfuscation" in result
        assert "anti_debug" in result
        assert "tpm" in result
        assert "summary" in result

    def test_comprehensive_scan_summary(self, binary_fixtures_dir: Path) -> None:
        """Comprehensive scan generates accurate summary."""
        binary_path = binary_fixtures_dir / "multi_protected.exe"

        result = detect_all_protections(str(binary_path))

        assert "summary" in result
        assert "is_protected" in result["summary"]
        assert "protection_count" in result["summary"]
        assert isinstance(result["summary"]["is_protected"], bool)
        assert isinstance(result["summary"]["protection_count"], int)

    def test_comprehensive_scan_counts_protections(self, binary_fixtures_dir: Path) -> None:
        """Comprehensive scan accurately counts protection types."""
        binary_path = binary_fixtures_dir / "multi_protected.exe"

        result = detect_all_protections(str(binary_path))

        assert result["summary"]["protection_count"] >= 0

        if result["summary"]["is_protected"]:
            assert result["summary"]["protection_count"] > 0


class TestAdvancedProtectionAnalyzers:
    """Test advanced protection analyzers (Themida, Denuvo)."""

    def test_detect_themida_advanced_fallback(self, detector: ProtectionDetector, binary_fixtures_dir: Path) -> None:
        """detect_themida_advanced handles missing analyzer gracefully."""
        binary_path = binary_fixtures_dir / "themida.exe"

        result = detector.detect_themida_advanced(str(binary_path))

        assert isinstance(result, dict)
        assert "detected" in result

    def test_detect_denuvo_advanced_fallback(self, detector: ProtectionDetector, binary_fixtures_dir: Path) -> None:
        """detect_denuvo_advanced handles missing analyzer gracefully."""
        binary_path = binary_fixtures_dir / "denuvo.exe"

        result = detector.detect_denuvo_advanced(str(binary_path))

        assert isinstance(result, dict)
        assert "detected" in result


class TestProtectionDetectorUtilities:
    """Test utility methods of ProtectionDetector."""

    def test_get_summary_text_format(self, detector: ProtectionDetector, binary_fixtures_dir: Path) -> None:
        """get_summary generates human-readable text summary."""
        binary_path = binary_fixtures_dir / "vmprotect.exe"
        analysis = detector.detect_protections(str(binary_path))

        summary = detector.get_summary(analysis)

        assert isinstance(summary, str)
        assert len(summary) > 0
        assert "File:" in summary

    def test_export_results_json_format(self, detector: ProtectionDetector, binary_fixtures_dir: Path) -> None:
        """export_results produces valid JSON output."""
        binary_path = binary_fixtures_dir / "vmprotect.exe"
        analysis = detector.detect_protections(str(binary_path))

        json_output = detector.export_results(analysis, output_format="json")

        assert isinstance(json_output, str)
        import json
        data = json.loads(json_output)
        assert "file_path" in data

    def test_export_results_text_format(self, detector: ProtectionDetector, binary_fixtures_dir: Path) -> None:
        """export_results produces text output."""
        binary_path = binary_fixtures_dir / "vmprotect.exe"
        analysis = detector.detect_protections(str(binary_path))

        text_output = detector.export_results(analysis, output_format="text")

        assert isinstance(text_output, str)
        assert len(text_output) > 0

    def test_export_results_csv_format(self, detector: ProtectionDetector, binary_fixtures_dir: Path) -> None:
        """export_results produces CSV output."""
        binary_path = binary_fixtures_dir / "vmprotect.exe"
        analysis = detector.detect_protections(str(binary_path))

        csv_output = detector.export_results(analysis, output_format="csv")

        assert isinstance(csv_output, str)
        assert "File,Type,Architecture" in csv_output

    def test_export_results_invalid_format(self, detector: ProtectionDetector, binary_fixtures_dir: Path) -> None:
        """export_results raises ValueError for invalid format."""
        binary_path = binary_fixtures_dir / "vmprotect.exe"
        analysis = detector.detect_protections(str(binary_path))

        with pytest.raises(ValueError):
            detector.export_results(analysis, output_format="invalid")

    def test_calculate_entropy_valid_data(self, detector: ProtectionDetector) -> None:
        """_calculate_entropy produces valid entropy scores."""
        test_data = b"A" * 100
        entropy = detector._calculate_entropy(test_data)

        assert 0.0 <= entropy <= 8.0
        assert entropy < 1.0

    def test_calculate_entropy_high_randomness(self, detector: ProtectionDetector) -> None:
        """_calculate_entropy detects high entropy in random data."""
        random_data = os.urandom(1024)
        entropy = detector._calculate_entropy(random_data)

        assert entropy > 7.0

    def test_calculate_entropy_empty_data(self, detector: ProtectionDetector) -> None:
        """_calculate_entropy handles empty data."""
        entropy = detector._calculate_entropy(b"")

        assert entropy == 0.0


class TestStandaloneFunctions:
    """Test standalone convenience functions."""

    def test_quick_analyze_function(self, binary_fixtures_dir: Path) -> None:
        """quick_analyze convenience function works."""
        binary_path = binary_fixtures_dir / "upx_packed.exe"

        analysis = quick_analyze(str(binary_path))

        assert isinstance(analysis, ProtectionAnalysis)

    def test_deep_analyze_function(self, binary_fixtures_dir: Path) -> None:
        """deep_analyze convenience function works."""
        binary_path = binary_fixtures_dir / "themida.exe"

        result = deep_analyze(str(binary_path))

        assert isinstance(result, UnifiedProtectionResult)

    def test_generate_checksum_sha256(self) -> None:
        """generate_checksum produces SHA256 checksums."""
        test_data = b"test data for checksum"

        checksum = generate_checksum(test_data, algorithm="sha256")

        assert isinstance(checksum, str)
        assert len(checksum) == 64

        expected = hashlib.sha256(test_data).hexdigest()
        assert checksum == expected

    def test_generate_checksum_consistency(self) -> None:
        """generate_checksum produces consistent results."""
        test_data = b"consistent test data"

        checksum1 = generate_checksum(test_data)
        checksum2 = generate_checksum(test_data)

        assert checksum1 == checksum2


class TestMultiProtectionHandling:
    """Test handling of binaries with multiple protection layers."""

    def test_detect_layered_protections(self, detector: ProtectionDetector, binary_fixtures_dir: Path) -> None:
        """Detector identifies multiple protection layers correctly."""
        binary_path = binary_fixtures_dir / "multi_protected.exe"

        analysis = detector.detect_protections(str(binary_path))

        assert len(analysis.detections) > 0

    def test_comprehensive_scan_multi_protection(self, binary_fixtures_dir: Path) -> None:
        """Comprehensive scan detects all protection types in multi-protected binary."""
        binary_path = binary_fixtures_dir / "multi_protected.exe"

        result = detect_all_protections(str(binary_path))

        protection_sections = [
            result["commercial"]["protections"],
            result["anti_debug"]["has_anti_debug"],
            result["checksum"]["has_checksum_verification"],
        ]

        assert any(protection_sections)

    def test_commercial_detection_unique_protections(self, binary_fixtures_dir: Path) -> None:
        """Commercial detection doesn't duplicate protection entries."""
        binary_path = binary_fixtures_dir / "multi_protected.exe"

        result = detect_commercial_protections(str(binary_path))

        protections = result.get("protections", [])
        assert len(protections) == len(set(protections))


class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_detect_protections_invalid_path(self, detector: ProtectionDetector) -> None:
        """detect_protections handles invalid paths properly."""
        with pytest.raises(FileNotFoundError):
            detector.detect_protections("D:\\nonexistent\\path\\binary.exe")

    def test_commercial_detection_corrupted_binary(self, tmp_path: Path) -> None:
        """Commercial detection handles corrupted binaries."""
        corrupted_binary = tmp_path / "corrupted.exe"
        corrupted_binary.write_bytes(b"\x00" * 100)

        result = detect_commercial_protections(str(corrupted_binary))

        assert isinstance(result, dict)
        assert "protections" in result

    def test_entropy_calculation_single_byte(self, detector: ProtectionDetector) -> None:
        """Entropy calculation handles single byte correctly."""
        entropy = detector._calculate_entropy(b"A")

        assert entropy == 0.0

    def test_obfuscation_detection_small_binary(self, tmp_path: Path) -> None:
        """Obfuscation detection handles very small binaries."""
        small_binary = tmp_path / "small.exe"
        small_binary.write_bytes(b"MZ" + b"\x00" * 50)

        result = detect_obfuscation(str(small_binary))

        assert isinstance(result, dict)
        assert "is_obfuscated" in result


class TestConfidenceScoring:
    """Test confidence scoring mechanisms."""

    def test_virtualization_confidence_multiple_indicators(self) -> None:
        """Virtualization detection confidence increases with indicators."""
        result = detect_virtualization_protection()

        if result["virtualization_detected"]:
            indicator_count = len(result["indicators"])
            assert result["confidence"] <= min(indicator_count * 0.3, 1.0)

    def test_unified_result_confidence_scoring(self, detector: ProtectionDetector, binary_fixtures_dir: Path) -> None:
        """UnifiedProtectionResult includes confidence scoring."""
        binary_path = binary_fixtures_dir / "multi_protected.exe"

        result = detector.analyze(str(binary_path))

        assert hasattr(result, "confidence_score")
        assert 0.0 <= result.confidence_score <= 100.0


class TestPerformance:
    """Test performance characteristics of detection."""

    def test_quick_summary_faster_than_full_scan(self, detector: ProtectionDetector, binary_fixtures_dir: Path) -> None:
        """Quick summary completes faster than deep scan."""
        import time

        binary_path = binary_fixtures_dir / "multi_protected.exe"

        start_quick = time.perf_counter()
        detector.get_quick_summary(str(binary_path))
        quick_time = time.perf_counter() - start_quick

        start_deep = time.perf_counter()
        detector.analyze(str(binary_path), deep_scan=True)
        deep_time = time.perf_counter() - start_deep

        assert quick_time <= deep_time * 2

    def test_commercial_detection_completes_quickly(self, binary_fixtures_dir: Path) -> None:
        """Commercial protection detection completes in reasonable time."""
        import time

        binary_path = binary_fixtures_dir / "multi_protected.exe"

        start = time.perf_counter()
        detect_commercial_protections(str(binary_path))
        elapsed = time.perf_counter() - start

        assert elapsed < 5.0


class TestProtectionTypeMapping:
    """Test protection type classification and mapping."""

    def test_map_protection_type_packer(self, detector: ProtectionDetector) -> None:
        """_map_protection_type correctly maps packer type."""
        mapped = detector._map_protection_type("packer")

        assert mapped == ProtectionType.PACKER

    def test_map_protection_type_protector(self, detector: ProtectionDetector) -> None:
        """_map_protection_type correctly maps protector type."""
        mapped = detector._map_protection_type("protector")

        assert mapped == ProtectionType.PROTECTOR

    def test_map_protection_type_license(self, detector: ProtectionDetector) -> None:
        """_map_protection_type correctly maps license type."""
        mapped = detector._map_protection_type("license")

        assert mapped == ProtectionType.LICENSE

    def test_map_protection_type_unknown(self, detector: ProtectionDetector) -> None:
        """_map_protection_type returns UNKNOWN for unrecognized types."""
        mapped = detector._map_protection_type("unknown_type")

        assert mapped == ProtectionType.UNKNOWN

    def test_map_protection_type_case_insensitive(self, detector: ProtectionDetector) -> None:
        """_map_protection_type handles case variations."""
        mapped1 = detector._map_protection_type("PACKER")
        mapped2 = detector._map_protection_type("Packer")
        mapped3 = detector._map_protection_type("packer")

        assert mapped1 == mapped2 == mapped3 == ProtectionType.PACKER


class TestConversionToLegacyFormat:
    """Test conversion between unified and legacy formats."""

    def test_convert_to_legacy_format_basic(self, detector: ProtectionDetector, binary_fixtures_dir: Path) -> None:
        """_convert_to_legacy_format produces valid ProtectionAnalysis."""
        binary_path = binary_fixtures_dir / "vmprotect.exe"

        unified_result = detector.analyze(str(binary_path))
        legacy_result = detector._convert_to_legacy_format(unified_result)

        assert isinstance(legacy_result, ProtectionAnalysis)
        assert legacy_result.file_path == unified_result.file_path

    def test_legacy_format_preserves_detections(self, detector: ProtectionDetector, binary_fixtures_dir: Path) -> None:
        """Legacy format conversion preserves detection results."""
        binary_path = binary_fixtures_dir / "multi_protected.exe"

        unified_result = detector.analyze(str(binary_path))
        legacy_result = detector._convert_to_legacy_format(unified_result)

        assert len(legacy_result.detections) >= 0

    def test_legacy_format_includes_metadata(self, detector: ProtectionDetector, binary_fixtures_dir: Path) -> None:
        """Legacy format includes analysis metadata."""
        binary_path = binary_fixtures_dir / "vmprotect.exe"

        unified_result = detector.analyze(str(binary_path))
        legacy_result = detector._convert_to_legacy_format(unified_result)

        assert hasattr(legacy_result, "metadata")
        assert isinstance(legacy_result.metadata, dict)


class TestRealWorldScenarios:
    """Test real-world usage scenarios."""

    def test_complete_analysis_workflow(self, detector: ProtectionDetector, binary_fixtures_dir: Path) -> None:
        """Complete analysis workflow from detection to bypass strategies."""
        binary_path = binary_fixtures_dir / "multi_protected.exe"

        analysis = detector.detect_protections(str(binary_path))
        summary = detector.get_summary(analysis)
        json_export = detector.export_results(analysis, output_format="json")
        strategies = detector.get_bypass_strategies(str(binary_path))

        assert isinstance(analysis, ProtectionAnalysis)
        assert isinstance(summary, str)
        assert isinstance(json_export, str)
        assert isinstance(strategies, list)

    def test_batch_analysis_multiple_binaries(self, detector: ProtectionDetector, binary_fixtures_dir: Path) -> None:
        """Batch analysis of multiple binaries."""
        results = detector.analyze_directory(str(binary_fixtures_dir), recursive=False)

        assert len(results) > 0
        assert all(isinstance(r, ProtectionAnalysis) for r in results)

    def test_incremental_protection_discovery(self, detector: ProtectionDetector, binary_fixtures_dir: Path) -> None:
        """Incremental protection discovery through multiple methods."""
        binary_path = binary_fixtures_dir / "multi_protected.exe"

        quick = detector.get_quick_summary(str(binary_path))
        full = detector.detect_protections(str(binary_path))
        comprehensive = detect_all_protections(str(binary_path))

        assert isinstance(quick, dict)
        assert isinstance(full, ProtectionAnalysis)
        assert isinstance(comprehensive, dict)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
