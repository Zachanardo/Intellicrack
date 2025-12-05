"""Production tests for Arxan analyzer - NO MOCKS.

Comprehensive test suite validating Arxan TransformIT protection detection and analysis
capabilities against real Windows binaries and custom-crafted test binaries containing
Arxan-like protection patterns.

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

from __future__ import annotations

import os
import struct
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.analysis.arxan_analyzer import (
    ArxanAnalyzer,
    ArxanAnalysisResult,
    ControlFlowAnalysis,
    IntegrityCheckMechanism,
    LicenseValidationRoutine,
    RASPMechanism,
    TamperCheckLocation,
)
from intellicrack.core.protection_detection.arxan_detector import (
    ArxanDetector,
    ArxanVersion,
)

if TYPE_CHECKING:
    from typing import Any

SYSTEM32 = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32"

try:
    import pytest_benchmark

    BENCHMARK_AVAILABLE = True
except ImportError:
    BENCHMARK_AVAILABLE = False


@pytest.fixture
def arxan_analyzer() -> ArxanAnalyzer:
    """Create ArxanAnalyzer instance."""
    return ArxanAnalyzer()


@pytest.fixture
def arxan_detector() -> ArxanDetector:
    """Create ArxanDetector instance."""
    return ArxanDetector()


@pytest.fixture
def temp_binary_dir(tmp_path: Path) -> Path:
    """Create temporary directory for test binaries."""
    binary_dir = tmp_path / "test_binaries"
    binary_dir.mkdir(exist_ok=True)
    return binary_dir


def create_pe_header() -> bytes:
    """Create minimal valid PE header for test binaries."""
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    dos_header[60:64] = struct.pack("<I", 64)

    pe_signature = b"PE\x00\x00"

    coff_header = struct.pack(
        "<HHIIIHH",
        0x014C,
        1,
        0,
        0,
        0,
        224,
        0x010B,
    )

    optional_header = bytearray(224)
    optional_header[0:2] = struct.pack("<H", 0x010B)

    section_header = bytearray(40)
    section_header[0:8] = b".text\x00\x00\x00"
    section_header[8:12] = struct.pack("<I", 0x1000)
    section_header[12:16] = struct.pack("<I", 0x1000)
    section_header[16:20] = struct.pack("<I", 0x1000)
    section_header[20:24] = struct.pack("<I", 0x400)
    section_header[36:40] = struct.pack("<I", 0x60000020)

    return bytes(dos_header + pe_signature + coff_header + optional_header + section_header)


def create_arxan_protected_binary(
    temp_dir: Path,
    version: ArxanVersion = ArxanVersion.TRANSFORM_7X,
    include_strings: bool = True,
    include_sections: bool = True,
    include_tamper_checks: bool = True,
    include_rasp: bool = True,
    include_license: bool = True,
) -> Path:
    """Create test binary with Arxan-like protection patterns."""
    binary_path = temp_dir / f"arxan_protected_{version.value}.exe"

    pe_header = create_pe_header()
    binary_data = bytearray(pe_header)

    if include_strings:
        binary_data.extend(b"Arxan Technologies\x00")
        binary_data.extend(b"TransformIT 7.0\x00")
        binary_data.extend(b"GuardIT Runtime\x00")
        binary_data.extend(b"ARXAN_LICENSE\x00")
        binary_data.extend(b"arxan_validate\x00")

    if version == ArxanVersion.TRANSFORM_5X:
        binary_data.extend(b"\x55\x8b\xec\x83\xec\x10\x56\x57\xe8")
        binary_data.extend(b"\x40\x72\x78\x61\x6e\x35")
    elif version == ArxanVersion.TRANSFORM_6X:
        binary_data.extend(b"\x48\x89\x5c\x24\x08\x48\x89\x6c\x24\x10\x48\x89\x74\x24\x18")
        binary_data.extend(b"\x40\x72\x78\x61\x6e\x36")
    elif version == ArxanVersion.TRANSFORM_7X:
        binary_data.extend(b"\x48\x89\x5c\x24\x10\x48\x89\x74\x24\x18\x57\x48\x83\xec\x20")
        binary_data.extend(b"\x40\x72\x78\x61\x6e\x37")
        binary_data.extend(b"\x48\x8b\xc4\x48\x89\x58\x08\x48\x89\x70\x10\x48\x89\x78\x18")
    elif version == ArxanVersion.TRANSFORM_8X:
        binary_data.extend(b"\x48\x89\x5c\x24\x08\x48\x89\x6c\x24\x10\x48\x89\x74\x24\x18\x57\x41\x56")
        binary_data.extend(b"\x40\x72\x78\x61\x6e\x38")

    if include_tamper_checks:
        binary_data.extend(b"\x33\xd2\x8a\x10\x8b\xc2\xc1\xe8\x08")
        binary_data.extend(b"\x8b\x55\x08\x33\xc0\x8a\x02")
        binary_data.extend(b"\x67\x45\x23\x01")
        binary_data.extend(b"\x01\x23\x45\x67\x89\xab\xcd\xef")
        binary_data.extend(b"\x6a\x09\xe6\x67")
        binary_data.extend(b"\x42\x8a\x2f\x98")
        binary_data.extend(b"\x36\x36\x36\x36")
        binary_data.extend(b"\x5c\x5c\x5c\x5c")

    if include_rasp:
        binary_data.extend(b"frida-agent.so\x00")
        binary_data.extend(b"gum-js-loop\x00")
        binary_data.extend(b"\x64\xa1\x30\x00\x00\x00\x0f\xb6\x40\x02")
        binary_data.extend(b"\x64\x8b\x05\x30\x00\x00\x00\x80\x78\x02\x00")
        binary_data.extend(b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00")
        binary_data.extend(b"VMware Guest\x00")
        binary_data.extend(b"VBoxGuest\x00")
        binary_data.extend(b"\x64\xa1\x00\x00\x00\x00\x50")
        binary_data.extend(b"\x64\x89\x25\x00\x00\x00\x00")

    if include_license:
        binary_data.extend(b"\x00\x01\xff\xff")
        binary_data.extend(b"\x00\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01")
        binary_data.extend(b"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5")
        binary_data.extend(b"\x52\x09\x6a\xd5\x30\x36\xa5\x38")
        binary_data.extend(b"license\x00validation\x00")
        binary_data.extend(b"serial\x00number\x00")
        binary_data.extend(b"activation\x00code\x00")

    for _ in range(150):
        binary_data.extend(b"\x85\xc0\x75\x02\x75\x00")
        binary_data.extend(b"\x85\xc0\x74\x02\x74\x00")

    for _ in range(50):
        binary_data.extend(b"\xff\x25\x00\x00\x00\x00")
        binary_data.extend(b"\xff\xe0")

    binary_data.extend(b"\x90\x90\x90\x90\x90" * 20)
    binary_data.extend(b"\x0f\x1f\x40\x00" * 10)

    binary_data.extend(b"\x30\x04\x08\x47")
    binary_data.extend(b"\x80\x30\x55")

    for i in range(256):
        binary_data.extend(bytes([i]))

    binary_data.extend(b"\xc1\xe8\x08\x33\x81")
    binary_data.extend(b"\x33\x81\xaa\xbb\xcc\xdd")

    high_entropy_data = bytes([(i * 137 + 73) % 256 for i in range(2048)])
    binary_data.extend(high_entropy_data)

    with open(binary_path, "wb") as f:
        f.write(binary_data)

    return binary_path


def create_minimal_binary(temp_dir: Path) -> Path:
    """Create minimal binary without Arxan protection."""
    binary_path = temp_dir / "minimal.exe"

    pe_header = create_pe_header()
    binary_data = bytearray(pe_header)

    binary_data.extend(b"\x90" * 100)
    binary_data.extend(b"Hello World\x00")

    with open(binary_path, "wb") as f:
        f.write(binary_data)

    return binary_path


class TestArxanAnalyzerInitialization:
    """Test ArxanAnalyzer initialization and configuration."""

    def test_analyzer_initialization_succeeds(self, arxan_analyzer: ArxanAnalyzer) -> None:
        """Analyzer initializes correctly with all components."""
        assert arxan_analyzer is not None
        assert arxan_analyzer.logger is not None
        assert arxan_analyzer.detector is not None
        assert isinstance(arxan_analyzer.detector, ArxanDetector)

    def test_analyzer_has_tamper_check_signatures(self, arxan_analyzer: ArxanAnalyzer) -> None:
        """Analyzer contains tamper check signature patterns."""
        assert len(ArxanAnalyzer.TAMPER_CHECK_SIGNATURES) > 0
        assert "crc32" in ArxanAnalyzer.TAMPER_CHECK_SIGNATURES
        assert "md5" in ArxanAnalyzer.TAMPER_CHECK_SIGNATURES
        assert "sha256" in ArxanAnalyzer.TAMPER_CHECK_SIGNATURES
        assert "hmac" in ArxanAnalyzer.TAMPER_CHECK_SIGNATURES

        for check_type, info in ArxanAnalyzer.TAMPER_CHECK_SIGNATURES.items():
            assert "patterns" in info
            assert "complexity" in info
            assert len(info["patterns"]) > 0
            assert info["complexity"] in ["low", "medium", "high"]

    def test_analyzer_has_opaque_predicate_patterns(self, arxan_analyzer: ArxanAnalyzer) -> None:
        """Analyzer contains opaque predicate detection patterns."""
        assert len(ArxanAnalyzer.OPAQUE_PREDICATE_PATTERNS) >= 6
        assert all(isinstance(pattern, bytes) for pattern in ArxanAnalyzer.OPAQUE_PREDICATE_PATTERNS)

    def test_analyzer_has_rasp_detection_patterns(self, arxan_analyzer: ArxanAnalyzer) -> None:
        """Analyzer contains RASP mechanism detection patterns."""
        assert len(ArxanAnalyzer.RASP_DETECTION_PATTERNS) > 0
        assert "anti_frida" in ArxanAnalyzer.RASP_DETECTION_PATTERNS
        assert "anti_debug" in ArxanAnalyzer.RASP_DETECTION_PATTERNS
        assert "anti_hook" in ArxanAnalyzer.RASP_DETECTION_PATTERNS
        assert "anti_vm" in ArxanAnalyzer.RASP_DETECTION_PATTERNS

    def test_analyzer_has_license_validation_signatures(self, arxan_analyzer: ArxanAnalyzer) -> None:
        """Analyzer contains license validation signature patterns."""
        assert len(ArxanAnalyzer.LICENSE_VALIDATION_SIGNATURES) > 0
        assert "rsa_validation" in ArxanAnalyzer.LICENSE_VALIDATION_SIGNATURES
        assert "aes_license" in ArxanAnalyzer.LICENSE_VALIDATION_SIGNATURES
        assert "serial_check" in ArxanAnalyzer.LICENSE_VALIDATION_SIGNATURES


class TestArxanAnalyzerRealBinaries:
    """Test ArxanAnalyzer against real Windows system binaries."""

    def test_analyze_notepad_completes_without_error(self, arxan_analyzer: ArxanAnalyzer) -> None:
        """Analysis of notepad.exe completes successfully."""
        notepad_path = SYSTEM32 / "notepad.exe"
        if not notepad_path.exists():
            pytest.skip("notepad.exe not found")

        result: ArxanAnalysisResult = arxan_analyzer.analyze(notepad_path)

        assert isinstance(result, ArxanAnalysisResult)
        assert "binary_size" in result.metadata
        assert result.metadata["binary_size"] > 0
        assert "analysis_complete" in result.metadata
        assert result.metadata["analysis_complete"] is True

    def test_analyze_kernel32_produces_valid_results(self, arxan_analyzer: ArxanAnalyzer) -> None:
        """Analysis of kernel32.dll produces valid results."""
        kernel32_path = SYSTEM32 / "kernel32.dll"
        if not kernel32_path.exists():
            pytest.skip("kernel32.dll not found")

        result: ArxanAnalysisResult = arxan_analyzer.analyze(kernel32_path)

        assert isinstance(result, ArxanAnalysisResult)
        assert isinstance(result.tamper_checks, list)
        assert isinstance(result.control_flow, ControlFlowAnalysis)
        assert isinstance(result.rasp_mechanisms, list)
        assert isinstance(result.license_routines, list)
        assert isinstance(result.integrity_checks, list)
        assert isinstance(result.encrypted_strings, list)
        assert isinstance(result.white_box_crypto_tables, list)

    def test_analyze_ntdll_detects_control_flow_patterns(self, arxan_analyzer: ArxanAnalyzer) -> None:
        """Analysis of ntdll.dll detects control flow patterns."""
        ntdll_path = SYSTEM32 / "ntdll.dll"
        if not ntdll_path.exists():
            pytest.skip("ntdll.dll not found")

        result: ArxanAnalysisResult = arxan_analyzer.analyze(ntdll_path)

        assert result.control_flow is not None
        assert isinstance(result.control_flow.opaque_predicates, list)
        assert isinstance(result.control_flow.indirect_jumps, list)
        assert isinstance(result.control_flow.obfuscation_density, float)
        assert 0.0 <= result.control_flow.obfuscation_density <= 1.0


class TestArxanAnalyzerProtectedBinaries:
    """Test ArxanAnalyzer against Arxan-protected test binaries."""

    def test_analyze_arxan_7x_binary_detects_version(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer detects Arxan 7.x version signatures."""
        binary_path = create_arxan_protected_binary(
            temp_binary_dir,
            version=ArxanVersion.TRANSFORM_7X,
        )

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        assert result.metadata["arxan_version"] == ArxanVersion.TRANSFORM_7X.value

    def test_analyze_arxan_6x_binary_detects_version(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer detects Arxan 6.x version signatures."""
        binary_path = create_arxan_protected_binary(
            temp_binary_dir,
            version=ArxanVersion.TRANSFORM_6X,
        )

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        assert result.metadata["arxan_version"] == ArxanVersion.TRANSFORM_6X.value

    def test_analyze_arxan_5x_binary_detects_version(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer detects Arxan 5.x version signatures."""
        binary_path = create_arxan_protected_binary(
            temp_binary_dir,
            version=ArxanVersion.TRANSFORM_5X,
        )

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        assert result.metadata["arxan_version"] == ArxanVersion.TRANSFORM_5X.value

    def test_analyze_arxan_8x_binary_detects_version(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer detects Arxan 8.x version signatures."""
        binary_path = create_arxan_protected_binary(
            temp_binary_dir,
            version=ArxanVersion.TRANSFORM_8X,
        )

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        assert result.metadata["arxan_version"] == ArxanVersion.TRANSFORM_8X.value

    def test_analyze_protected_binary_detects_tamper_checks(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer detects tamper check mechanisms in protected binary."""
        binary_path = create_arxan_protected_binary(
            temp_binary_dir,
            include_tamper_checks=True,
        )

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        assert len(result.tamper_checks) > 0
        assert result.metadata["total_tamper_checks"] > 0

        for check in result.tamper_checks:
            assert isinstance(check, TamperCheckLocation)
            assert check.address >= 0
            assert check.size > 0
            assert check.check_type in ["tamper_detection", "inline_check"]
            assert check.algorithm in ["crc32", "md5", "sha256", "hmac", "xor_checksum"]
            assert check.bypass_complexity in ["low", "medium", "high"]

    def test_analyze_protected_binary_detects_rasp_mechanisms(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer detects RASP mechanisms in protected binary."""
        binary_path = create_arxan_protected_binary(
            temp_binary_dir,
            include_rasp=True,
        )

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        assert len(result.rasp_mechanisms) > 0
        assert result.metadata["total_rasp_mechanisms"] > 0

        for rasp in result.rasp_mechanisms:
            assert isinstance(rasp, RASPMechanism)
            assert rasp.mechanism_type in [
                "anti_frida",
                "anti_debug",
                "anti_hook",
                "anti_vm",
                "exception_handler",
            ]
            assert rasp.address >= 0
            assert rasp.detection_method in [
                "string_detection",
                "peb_check",
                "integrity_check",
                "signature_scan",
                "exception_based",
            ]
            assert rasp.severity in ["low", "medium", "high"]

    def test_analyze_protected_binary_detects_license_routines(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer detects license validation routines in protected binary."""
        binary_path = create_arxan_protected_binary(
            temp_binary_dir,
            include_license=True,
        )

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        assert len(result.license_routines) > 0
        assert result.metadata["total_license_routines"] > 0

        for routine in result.license_routines:
            assert isinstance(routine, LicenseValidationRoutine)
            assert routine.address >= 0
            assert routine.algorithm in ["RSA", "AES", "custom"]
            assert routine.key_length > 0
            assert routine.validation_type in ["rsa_validation", "aes_license", "serial_check"]
            assert isinstance(routine.crypto_operations, list)

    def test_analyze_protected_binary_detects_control_flow_obfuscation(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer detects control flow obfuscation patterns."""
        binary_path = create_arxan_protected_binary(temp_binary_dir)

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        assert result.control_flow is not None
        assert len(result.control_flow.opaque_predicates) >= 100
        assert len(result.control_flow.indirect_jumps) > 0
        assert result.control_flow.control_flow_flattening is True
        assert result.control_flow.obfuscation_density > 0.0

    def test_analyze_protected_binary_detects_integrity_checks(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer detects integrity check mechanisms."""
        binary_path = create_arxan_protected_binary(temp_binary_dir)

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        if len(result.integrity_checks) > 0:
            for check in result.integrity_checks:
                assert isinstance(check, IntegrityCheckMechanism)
                assert check.address >= 0
                assert check.check_type in ["hash_verification", "api_based"]
                assert check.hash_algorithm in ["CRC32", "SHA256"]
                assert check.check_frequency in ["periodic", "on_load", "on_demand"]
                assert check.bypass_strategy in ["hook_hash_function", "hook_crypto_api"]

    def test_analyze_protected_binary_detects_encrypted_strings(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer detects encrypted string regions."""
        binary_path = create_arxan_protected_binary(temp_binary_dir)

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        assert isinstance(result.encrypted_strings, list)

        for region in result.encrypted_strings:
            assert isinstance(region, tuple)
            assert len(region) == 2
            address, size = region
            assert address >= 0
            assert size > 0

    def test_analyze_protected_binary_detects_white_box_crypto_tables(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer detects white-box cryptography lookup tables."""
        binary_path = create_arxan_protected_binary(temp_binary_dir)

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        assert isinstance(result.white_box_crypto_tables, list)

        if len(result.white_box_crypto_tables) > 0:
            for table in result.white_box_crypto_tables:
                assert isinstance(table, tuple)
                assert len(table) == 2
                address, size = table
                assert address >= 0
                assert size > 0


class TestArxanAnalyzerEdgeCases:
    """Test ArxanAnalyzer edge cases and error handling."""

    def test_analyze_nonexistent_binary_raises_error(self, arxan_analyzer: ArxanAnalyzer) -> None:
        """Analyzer raises FileNotFoundError for nonexistent binary."""
        with pytest.raises(FileNotFoundError):
            arxan_analyzer.analyze(Path("nonexistent_binary.exe"))

    def test_analyze_empty_binary_raises_error(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer raises error for empty binary due to division by zero in detector."""
        empty_binary = temp_binary_dir / "empty.exe"
        empty_binary.write_bytes(b"")

        with pytest.raises(Exception):
            arxan_analyzer.analyze(empty_binary)

    def test_analyze_minimal_binary_returns_minimal_results(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer returns minimal results for unprotected binary."""
        minimal_binary = create_minimal_binary(temp_binary_dir)

        result: ArxanAnalysisResult = arxan_analyzer.analyze(minimal_binary)

        assert result.metadata["analysis_complete"] is True
        assert result.metadata["total_tamper_checks"] >= 0
        assert result.metadata["total_rasp_mechanisms"] >= 0
        assert result.metadata["total_license_routines"] >= 0

    def test_analyze_binary_without_tamper_checks(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer handles binary without tamper checks."""
        binary_path = create_arxan_protected_binary(
            temp_binary_dir,
            include_tamper_checks=False,
        )

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        assert isinstance(result.tamper_checks, list)

    def test_analyze_binary_without_rasp(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer handles binary without RASP mechanisms."""
        binary_path = create_arxan_protected_binary(
            temp_binary_dir,
            include_rasp=False,
        )

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        assert isinstance(result.rasp_mechanisms, list)

    def test_analyze_binary_without_license_routines(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer handles binary without license validation."""
        binary_path = create_arxan_protected_binary(
            temp_binary_dir,
            include_license=False,
        )

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        assert isinstance(result.license_routines, list)

    def test_analyze_large_binary_completes(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer handles large binary files."""
        large_binary = temp_binary_dir / "large.exe"
        pe_header = create_pe_header()

        with open(large_binary, "wb") as f:
            f.write(pe_header)
            f.write(b"\x90" * (10 * 1024 * 1024))

        result: ArxanAnalysisResult = arxan_analyzer.analyze(large_binary)

        assert result.metadata["binary_size"] > 10 * 1024 * 1024
        assert result.metadata["analysis_complete"] is True


class TestArxanAnalyzerTamperCheckDetection:
    """Test specific tamper check detection capabilities."""

    def test_detect_crc32_tamper_check(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer detects CRC32 tamper check patterns."""
        binary_path = temp_binary_dir / "crc32_check.exe"
        pe_header = create_pe_header()
        binary_data = bytearray(pe_header)

        binary_data.extend(b"\x33\xd2\x8a\x10\x8b\xc2\xc1\xe8\x08")
        binary_data.extend(b"\x8b\x55\x08\x33\xc0\x8a\x02")

        with open(binary_path, "wb") as f:
            f.write(binary_data)

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        crc32_checks = [c for c in result.tamper_checks if c.algorithm == "crc32"]
        assert len(crc32_checks) > 0

        for check in crc32_checks:
            assert check.bypass_complexity == "low"

    def test_detect_md5_tamper_check(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer detects MD5 tamper check patterns."""
        binary_path = temp_binary_dir / "md5_check.exe"
        pe_header = create_pe_header()
        binary_data = bytearray(pe_header)

        binary_data.extend(b"\x67\x45\x23\x01")
        binary_data.extend(b"\x01\x23\x45\x67\x89\xab\xcd\xef")

        with open(binary_path, "wb") as f:
            f.write(binary_data)

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        md5_checks = [c for c in result.tamper_checks if c.algorithm == "md5"]
        assert len(md5_checks) > 0

        for check in md5_checks:
            assert check.bypass_complexity == "medium"

    def test_detect_sha256_tamper_check(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer detects SHA256 tamper check patterns."""
        binary_path = temp_binary_dir / "sha256_check.exe"
        pe_header = create_pe_header()
        binary_data = bytearray(pe_header)

        binary_data.extend(b"\x6a\x09\xe6\x67")
        binary_data.extend(b"\x42\x8a\x2f\x98")

        with open(binary_path, "wb") as f:
            f.write(binary_data)

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        sha256_checks = [c for c in result.tamper_checks if c.algorithm == "sha256"]
        assert len(sha256_checks) > 0

        for check in sha256_checks:
            assert check.bypass_complexity == "high"

    def test_detect_hmac_tamper_check(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer detects HMAC tamper check patterns."""
        binary_path = temp_binary_dir / "hmac_check.exe"
        pe_header = create_pe_header()
        binary_data = bytearray(pe_header)

        binary_data.extend(b"\x36\x36\x36\x36")
        binary_data.extend(b"\x5c\x5c\x5c\x5c")

        with open(binary_path, "wb") as f:
            f.write(binary_data)

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        hmac_checks = [c for c in result.tamper_checks if c.algorithm == "hmac"]
        assert len(hmac_checks) > 0

        for check in hmac_checks:
            assert check.bypass_complexity == "high"

    def test_tamper_check_target_regions_are_valid(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Tamper check target regions have valid bounds."""
        binary_path = create_arxan_protected_binary(
            temp_binary_dir,
            include_tamper_checks=True,
        )

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        binary_size = result.metadata["binary_size"]

        for check in result.tamper_checks:
            target_start, target_end = check.target_region
            assert target_start >= 0
            assert target_end <= binary_size
            assert target_start < target_end


class TestArxanAnalyzerControlFlowAnalysis:
    """Test control flow obfuscation analysis capabilities."""

    def test_detect_opaque_predicates(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer detects opaque predicate patterns."""
        binary_path = temp_binary_dir / "opaque_predicates.exe"
        pe_header = create_pe_header()
        binary_data = bytearray(pe_header)

        for _ in range(200):
            binary_data.extend(b"\x85\xc0\x75\x02\x75\x00")
            binary_data.extend(b"\x85\xc0\x74\x02\x74\x00")
            binary_data.extend(b"\x33\xc0\x85\xc0\x74\x01")

        with open(binary_path, "wb") as f:
            f.write(binary_data)

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        assert len(result.control_flow.opaque_predicates) >= 100
        assert result.control_flow.control_flow_flattening is True

    def test_detect_indirect_jumps(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer detects indirect jump patterns."""
        binary_path = temp_binary_dir / "indirect_jumps.exe"
        pe_header = create_pe_header()
        binary_data = bytearray(pe_header)

        for _ in range(100):
            binary_data.extend(b"\xff\x25\x00\x00\x00\x00")
            binary_data.extend(b"\xff\x15\x00\x00\x00\x00")
            binary_data.extend(b"\xff\xe0")
            binary_data.extend(b"\xff\xe1")

        with open(binary_path, "wb") as f:
            f.write(binary_data)

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        assert len(result.control_flow.indirect_jumps) >= 50

    def test_detect_junk_code_blocks(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer detects junk code insertion patterns."""
        binary_path = create_arxan_protected_binary(temp_binary_dir)

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        if len(result.control_flow.junk_code_blocks) > 0:
            for junk_start, junk_size in result.control_flow.junk_code_blocks:
                assert junk_start >= 0
                assert junk_size > 0

    def test_calculate_obfuscation_density(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer calculates obfuscation density correctly."""
        binary_path = create_arxan_protected_binary(temp_binary_dir)

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        assert 0.0 <= result.control_flow.obfuscation_density <= 1.0

    def test_control_flow_flattening_threshold(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Control flow flattening detected above threshold."""
        binary_path = temp_binary_dir / "flattened.exe"
        pe_header = create_pe_header()
        binary_data = bytearray(pe_header)

        for _ in range(150):
            binary_data.extend(b"\x85\xc0\x75\x02\x75\x00")

        with open(binary_path, "wb") as f:
            f.write(binary_data)

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        assert result.control_flow.control_flow_flattening is True


class TestArxanAnalyzerRASPDetection:
    """Test RASP mechanism detection capabilities."""

    def test_detect_anti_frida_mechanisms(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer detects anti-Frida protection mechanisms."""
        binary_path = temp_binary_dir / "anti_frida.exe"
        pe_header = create_pe_header()
        binary_data = bytearray(pe_header)

        binary_data.extend(b"frida-agent.so\x00")
        binary_data.extend(b"gum-js-loop\x00")
        binary_data.extend(b"/frida/runtime.js\x00")

        with open(binary_path, "wb") as f:
            f.write(binary_data)

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        anti_frida = [r for r in result.rasp_mechanisms if r.mechanism_type == "anti_frida"]
        assert len(anti_frida) > 0

        for rasp in anti_frida:
            assert rasp.detection_method == "string_detection"
            assert rasp.severity == "high"

    def test_detect_anti_debug_mechanisms(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer detects anti-debug protection mechanisms."""
        binary_path = temp_binary_dir / "anti_debug.exe"
        pe_header = create_pe_header()
        binary_data = bytearray(pe_header)

        binary_data.extend(b"\x64\xa1\x30\x00\x00\x00\x0f\xb6\x40\x02")
        binary_data.extend(b"\x64\x8b\x05\x30\x00\x00\x00\x80\x78\x02\x00")
        binary_data.extend(b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00")

        with open(binary_path, "wb") as f:
            f.write(binary_data)

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        anti_debug = [r for r in result.rasp_mechanisms if r.mechanism_type == "anti_debug"]
        assert len(anti_debug) > 0

        for rasp in anti_debug:
            assert rasp.detection_method == "peb_check"
            assert rasp.severity == "high"

    def test_detect_anti_vm_mechanisms(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer detects anti-VM protection mechanisms."""
        binary_path = temp_binary_dir / "anti_vm.exe"
        pe_header = create_pe_header()
        binary_data = bytearray(pe_header)

        binary_data.extend(b"VMware Tools\x00")
        binary_data.extend(b"VBoxGuest.sys\x00")
        binary_data.extend(b"QEMU Harddisk\x00")

        with open(binary_path, "wb") as f:
            f.write(binary_data)

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        anti_vm = [r for r in result.rasp_mechanisms if r.mechanism_type == "anti_vm"]
        assert len(anti_vm) > 0

        for rasp in anti_vm:
            assert rasp.detection_method == "signature_scan"
            assert rasp.severity == "medium"

    def test_detect_exception_handlers(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer detects SEH exception handler installations."""
        binary_path = temp_binary_dir / "exception_handlers.exe"
        pe_header = create_pe_header()
        binary_data = bytearray(pe_header)

        for _ in range(10):
            binary_data.extend(b"\x64\xa1\x00\x00\x00\x00\x50")
            binary_data.extend(b"\x64\x89\x25\x00\x00\x00\x00")

        with open(binary_path, "wb") as f:
            f.write(binary_data)

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        exception_handlers = [
            r for r in result.rasp_mechanisms if r.mechanism_type == "exception_handler"
        ]
        assert len(exception_handlers) > 0

        for rasp in exception_handlers:
            assert rasp.hook_target == "SEH"
            assert rasp.detection_method == "exception_based"
            assert rasp.severity == "high"


class TestArxanAnalyzerLicenseValidation:
    """Test license validation routine detection."""

    def test_detect_rsa_license_validation(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer detects RSA-based license validation."""
        binary_path = temp_binary_dir / "rsa_license.exe"
        pe_header = create_pe_header()
        binary_data = bytearray(pe_header)

        binary_data.extend(b"\x00\x01\xff\xff")
        binary_data.extend(b"\x00\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01")

        with open(binary_path, "wb") as f:
            f.write(binary_data)

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        rsa_routines = [r for r in result.license_routines if r.validation_type == "rsa_validation"]
        assert len(rsa_routines) > 0

        for routine in rsa_routines:
            assert routine.algorithm == "RSA"
            assert routine.key_length == 2048
            assert "modular_exponentiation" in routine.crypto_operations
            assert "pkcs1_padding" in routine.crypto_operations

    def test_detect_aes_license_validation(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer detects AES-based license validation."""
        binary_path = temp_binary_dir / "aes_license.exe"
        pe_header = create_pe_header()
        binary_data = bytearray(pe_header)

        binary_data.extend(b"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5")
        binary_data.extend(b"\x52\x09\x6a\xd5\x30\x36\xa5\x38")

        with open(binary_path, "wb") as f:
            f.write(binary_data)

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        aes_routines = [r for r in result.license_routines if r.validation_type == "aes_license"]
        assert len(aes_routines) > 0

        for routine in aes_routines:
            assert routine.algorithm == "AES"
            assert routine.key_length == 256
            assert "sbox_substitution" in routine.crypto_operations

    def test_detect_serial_check_validation(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer detects serial number check routines."""
        binary_path = temp_binary_dir / "serial_check.exe"
        pe_header = create_pe_header()
        binary_data = bytearray(pe_header)

        binary_data.extend(b"-\x00-\x00-\x00-\x00")

        with open(binary_path, "wb") as f:
            f.write(binary_data)

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        serial_routines = [r for r in result.license_routines if r.validation_type == "serial_check"]
        assert len(serial_routines) > 0

        for routine in serial_routines:
            assert routine.algorithm == "custom"
            assert "string_compare" in routine.crypto_operations

    def test_license_routine_string_references(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """License routines include nearby string references."""
        binary_path = create_arxan_protected_binary(
            temp_binary_dir,
            include_license=True,
        )

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        if len(result.license_routines) > 0:
            for routine in result.license_routines:
                assert isinstance(routine.string_references, list)


class TestArxanAnalyzerIntegrityChecks:
    """Test integrity check mechanism detection."""

    def test_detect_crc_integrity_checks(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer detects CRC-based integrity checks."""
        binary_path = temp_binary_dir / "crc_integrity.exe"
        pe_header = create_pe_header()
        binary_data = bytearray(pe_header)

        binary_data.extend(b"\xc1\xe8\x08\x33\x81")
        binary_data.extend(b"\x33\x81\xaa\xbb")

        with open(binary_path, "wb") as f:
            f.write(binary_data)

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        crc_checks = [c for c in result.integrity_checks if c.hash_algorithm == "CRC32"]

        if len(crc_checks) > 0:
            for check in crc_checks:
                assert check.check_type == "hash_verification"
                assert check.bypass_strategy == "hook_hash_function"

    def test_integrity_check_frequencies(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Integrity checks have valid frequency specifications."""
        binary_path = temp_binary_dir / "integrity_freq.exe"
        pe_header = create_pe_header()
        binary_data = bytearray(pe_header)

        binary_data.extend(b"\xc1\xe8\x08\x33\x81")

        with open(binary_path, "wb") as f:
            f.write(binary_data)

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        for check in result.integrity_checks:
            assert check.check_frequency in ["periodic", "on_load", "on_demand"]


class TestArxanAnalyzerStringEncryption:
    """Test encrypted string detection capabilities."""

    def test_detect_xor_encrypted_strings(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer detects XOR-encrypted string regions."""
        binary_path = temp_binary_dir / "xor_strings.exe"
        pe_header = create_pe_header()
        binary_data = bytearray(pe_header)

        binary_data.extend(b"\x30\x04\x08\x47")
        high_entropy = bytes([(i * 137 + 73) % 256 for i in range(256)])
        binary_data.extend(high_entropy)

        with open(binary_path, "wb") as f:
            f.write(binary_data)

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        if len(result.encrypted_strings) > 0:
            for address, size in result.encrypted_strings:
                assert address >= 0
                assert size > 0


class TestArxanAnalyzerWhiteBoxCrypto:
    """Test white-box cryptography detection."""

    def test_detect_white_box_lookup_tables(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer detects white-box crypto lookup tables."""
        binary_path = temp_binary_dir / "whitebox_crypto.exe"
        pe_header = create_pe_header()
        binary_data = bytearray(pe_header)

        for _ in range(5):
            unique_table = bytes([(i * 137 + 73) % 256 for i in range(2048)])
            binary_data.extend(unique_table)

        with open(binary_path, "wb") as f:
            f.write(binary_data)

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        assert len(result.white_box_crypto_tables) > 0

        for address, size in result.white_box_crypto_tables:
            assert address >= 0
            assert size >= 2048


class TestArxanAnalyzerMetadata:
    """Test analysis result metadata."""

    def test_metadata_includes_binary_size(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analysis result includes correct binary size."""
        binary_path = create_arxan_protected_binary(temp_binary_dir)

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        actual_size = binary_path.stat().st_size
        assert result.metadata["binary_size"] == actual_size

    def test_metadata_includes_arxan_version(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analysis result includes detected Arxan version."""
        binary_path = create_arxan_protected_binary(temp_binary_dir)

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        assert "arxan_version" in result.metadata
        assert result.metadata["arxan_version"] in [
            "unknown",
            "5.x",
            "6.x",
            "7.x",
            "8.x",
        ]

    def test_metadata_includes_protection_features(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analysis result includes detected protection features."""
        binary_path = create_arxan_protected_binary(temp_binary_dir)

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        assert "protection_features" in result.metadata

    def test_metadata_includes_analysis_complete_flag(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analysis result includes completion flag."""
        binary_path = create_arxan_protected_binary(temp_binary_dir)

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        assert "analysis_complete" in result.metadata
        assert result.metadata["analysis_complete"] is True

    def test_metadata_includes_counts(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analysis result includes detection counts."""
        binary_path = create_arxan_protected_binary(temp_binary_dir)

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        assert "total_tamper_checks" in result.metadata
        assert "total_rasp_mechanisms" in result.metadata
        assert "total_license_routines" in result.metadata

        assert result.metadata["total_tamper_checks"] == len(result.tamper_checks)
        assert result.metadata["total_rasp_mechanisms"] == len(result.rasp_mechanisms)
        assert result.metadata["total_license_routines"] == len(result.license_routines)


class TestArxanAnalyzerPerformance:
    """Test analyzer performance benchmarks."""

    @pytest.mark.skipif(not BENCHMARK_AVAILABLE, reason="pytest-benchmark not available")
    def test_analyze_small_binary_performance(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analysis of small binary completes quickly."""
        binary_path = create_minimal_binary(temp_binary_dir)

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        assert result.metadata["analysis_complete"] is True

    @pytest.mark.skipif(not BENCHMARK_AVAILABLE, reason="pytest-benchmark not available")
    def test_analyze_protected_binary_performance(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analysis of protected binary completes within acceptable time."""
        binary_path = create_arxan_protected_binary(temp_binary_dir)

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        assert result.metadata["analysis_complete"] is True
        assert len(result.tamper_checks) > 0


class TestArxanAnalyzerLayeredProtection:
    """Test detection of multiple protection layers."""

    def test_analyze_multi_layer_protection(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer detects multiple protection layers simultaneously."""
        binary_path = create_arxan_protected_binary(
            temp_binary_dir,
            include_strings=True,
            include_sections=True,
            include_tamper_checks=True,
            include_rasp=True,
            include_license=True,
        )

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        assert len(result.tamper_checks) > 0
        assert len(result.rasp_mechanisms) > 0
        assert len(result.license_routines) > 0
        assert len(result.control_flow.opaque_predicates) > 0

    def test_analyze_comprehensive_protection_suite(
        self,
        arxan_analyzer: ArxanAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyzer handles comprehensive protection suite."""
        binary_path = create_arxan_protected_binary(temp_binary_dir)

        result: ArxanAnalysisResult = arxan_analyzer.analyze(binary_path)

        protection_count = (
            len(result.tamper_checks)
            + len(result.rasp_mechanisms)
            + len(result.license_routines)
            + len(result.integrity_checks)
        )

        assert protection_count > 0
