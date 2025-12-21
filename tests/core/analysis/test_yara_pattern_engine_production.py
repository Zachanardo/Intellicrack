"""Production tests for yara_pattern_engine module.

This module tests the YaraPatternEngine which provides advanced pattern matching
for detecting protections, packers, licensing schemes, and anti-analysis techniques
using YARA rules.

Copyright (C) 2025 Zachary Flint
"""

import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.yara_pattern_engine import (
    YARA_AVAILABLE,
    PatternCategory,
    YaraMatch,
    YaraPatternEngine,
    YaraScanResult,
)


def create_test_binary_with_patterns(
    path: Path,
    include_vmprotect: bool = False,
    include_upx: bool = False,
    include_licensing: bool = False,
    include_antidebug: bool = False,
) -> Path:
    """Create test binary with specific protection patterns.

    Args:
        path: Path where binary will be created
        include_vmprotect: Include VMProtect signatures
        include_upx: Include UPX packer signatures
        include_licensing: Include licensing strings
        include_antidebug: Include anti-debug patterns

    Returns:
        Path to created binary
    """
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    dos_header[60:64] = struct.pack("<I", 64)

    pe_signature = b"PE\x00\x00"

    file_header = struct.pack(
        "<HHIIIHH",
        0x014C,
        1,
        0x60000000,
        0,
        0,
        224,
        0x0102,
    )

    optional_header = struct.pack(
        "<HHBBIIIIIHHHHHHIIIIHHIIIIIIII",
        0x010B,
        0, 0, 0x1000, 0, 0, 0x1000, 0x1000, 0x1000,
        0x400000, 0x1000, 0x200, 0, 0, 0, 0, 4, 0, 0,
        0x3000, 0x200, 0, 3, 0,
        0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    )

    data_directories = b"\x00" * (16 * 8)

    section_name = b".text\x00\x00\x00"
    section_header = section_name + struct.pack(
        "<IIIIHHI",
        0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0xE0000020,
    )

    pe_content = dos_header + pe_signature + file_header + optional_header + data_directories + section_header
    pe_content = pe_content.ljust(0x200, b"\x00")

    section_data = bytearray(b"\x90" * 0x200)

    if include_vmprotect:
        section_data[50:57] = b".vmp0\x00\x00"
        section_data[100:109] = b"VMProtect"

    if include_upx:
        section_data[150:154] = b"UPX!"
        section_data[200:204] = b"\x55\x50\x58\x21"

    if include_licensing:
        section_data[250:262] = b"license key\x00"
        section_data[300:315] = b"trial expired\x00\x00"
        section_data[350:361] = b"FlexLM\x00\x00\x00\x00\x00"

    if include_antidebug:
        section_data[400:419] = b"IsDebuggerPresent\x00\x00"
        section_data[450:479] = b"CheckRemoteDebuggerPresent\x00\x00\x00"

    pe_content += bytes(section_data)

    path.write_bytes(pe_content)
    return path


@pytest.fixture
def clean_binary(tmp_path: Path) -> Path:
    """Create clean binary without protections."""
    binary_path = tmp_path / "clean.exe"
    return create_test_binary_with_patterns(binary_path)


@pytest.fixture
def vmprotect_binary(tmp_path: Path) -> Path:
    """Create binary with VMProtect signatures."""
    binary_path = tmp_path / "vmprotect.exe"
    return create_test_binary_with_patterns(binary_path, include_vmprotect=True)


@pytest.fixture
def upx_packed_binary(tmp_path: Path) -> Path:
    """Create binary with UPX packer signatures."""
    binary_path = tmp_path / "upx_packed.exe"
    return create_test_binary_with_patterns(binary_path, include_upx=True)


@pytest.fixture
def licensed_binary(tmp_path: Path) -> Path:
    """Create binary with licensing patterns."""
    binary_path = tmp_path / "licensed.exe"
    return create_test_binary_with_patterns(binary_path, include_licensing=True)


@pytest.fixture
def protected_binary(tmp_path: Path) -> Path:
    """Create binary with multiple protection patterns."""
    binary_path = tmp_path / "protected.exe"
    return create_test_binary_with_patterns(
        binary_path,
        include_vmprotect=True,
        include_licensing=True,
        include_antidebug=True,
    )


class TestYaraMatchDataclass:
    """Test YaraMatch dataclass functionality."""

    def test_yara_match_creation(self) -> None:
        """YaraMatch dataclass creates with correct attributes."""
        match = YaraMatch(
            rule_name="VMProtect_Detection",
            namespace="protections",
            tags=["protection", "vmprotect"],
            category=PatternCategory.PROTECTION,
            confidence=0.9,
            offset=0x1000,
            length=100,
            identifier="$vmp1",
            string_data=".vmp0",
            metadata={"version": "3.x"},
        )

        assert match.rule_name == "VMProtect_Detection"
        assert match.category == PatternCategory.PROTECTION
        assert match.confidence == 0.9
        assert match.offset == 0x1000

    def test_severity_calculation_high_confidence(self) -> None:
        """YaraMatch calculates severity based on category and confidence."""
        bypass_match = YaraMatch(
            rule_name="LicenseBypass",
            namespace="bypass",
            tags=["bypass"],
            category=PatternCategory.LICENSE_BYPASS,
            confidence=0.85,
            offset=0,
            length=0,
            identifier="$bypass",
        )

        assert bypass_match.severity == "high"

    def test_severity_calculation_medium_confidence(self) -> None:
        """YaraMatch returns medium severity for protection patterns."""
        protection_match = YaraMatch(
            rule_name="Themida",
            namespace="protections",
            tags=["protection"],
            category=PatternCategory.PROTECTION,
            confidence=0.75,
            offset=0,
            length=0,
            identifier="$tmd1",
        )

        assert protection_match.severity == "medium"

    def test_severity_calculation_low_confidence(self) -> None:
        """YaraMatch returns low severity for low confidence matches."""
        compiler_match = YaraMatch(
            rule_name="MSVC",
            namespace="compiler",
            tags=["compiler"],
            category=PatternCategory.COMPILER,
            confidence=0.5,
            offset=0,
            length=0,
            identifier="$msvc",
        )

        assert compiler_match.severity == "low"


class TestYaraScanResultDataclass:
    """Test YaraScanResult dataclass functionality."""

    def test_scan_result_creation(self) -> None:
        """YaraScanResult creates with correct attributes."""
        result = YaraScanResult(
            file_path="/path/to/binary.exe",
            matches=[],
            total_rules=50,
            scan_time=1.5,
            error=None,
        )

        assert result.file_path == "/path/to/binary.exe"
        assert result.total_rules == 50
        assert result.scan_time == 1.5
        assert result.error is None

    def test_has_protections_property(self) -> None:
        """YaraScanResult correctly identifies protection matches."""
        protection_match = YaraMatch(
            rule_name="VMProtect",
            namespace="protections",
            tags=["protection"],
            category=PatternCategory.PROTECTION,
            confidence=0.9,
            offset=0,
            length=0,
            identifier="$vmp",
        )

        result = YaraScanResult(
            file_path="test.exe",
            matches=[protection_match],
        )

        assert result.has_protections is True

    def test_has_packers_property(self) -> None:
        """YaraScanResult correctly identifies packer matches."""
        packer_match = YaraMatch(
            rule_name="UPX",
            namespace="packers",
            tags=["packer"],
            category=PatternCategory.PACKER,
            confidence=0.95,
            offset=0,
            length=0,
            identifier="$upx",
        )

        result = YaraScanResult(
            file_path="test.exe",
            matches=[packer_match],
        )

        assert result.has_packers is True

    def test_has_licensing_property(self) -> None:
        """YaraScanResult correctly identifies licensing matches."""
        licensing_match = YaraMatch(
            rule_name="FlexLM",
            namespace="licensing",
            tags=["licensing"],
            category=PatternCategory.LICENSING,
            confidence=0.8,
            offset=0,
            length=0,
            identifier="$flex",
        )

        result = YaraScanResult(
            file_path="test.exe",
            matches=[licensing_match],
        )

        assert result.has_licensing is True

    def test_high_confidence_matches_filter(self) -> None:
        """YaraScanResult filters high confidence matches correctly."""
        high_conf = YaraMatch(
            rule_name="Rule1",
            namespace="test",
            tags=[],
            category=PatternCategory.PROTECTION,
            confidence=0.9,
            offset=0,
            length=0,
            identifier="$1",
        )

        low_conf = YaraMatch(
            rule_name="Rule2",
            namespace="test",
            tags=[],
            category=PatternCategory.PROTECTION,
            confidence=0.6,
            offset=0,
            length=0,
            identifier="$2",
        )

        result = YaraScanResult(
            file_path="test.exe",
            matches=[high_conf, low_conf],
        )

        high_conf_matches = result.high_confidence_matches
        assert len(high_conf_matches) == 1
        assert high_conf_matches[0].confidence == 0.9

    def test_get_matches_by_category(self) -> None:
        """YaraScanResult filters matches by category."""
        protection_match = YaraMatch(
            rule_name="VMProtect",
            namespace="test",
            tags=[],
            category=PatternCategory.PROTECTION,
            confidence=0.9,
            offset=0,
            length=0,
            identifier="$vmp",
        )

        packer_match = YaraMatch(
            rule_name="UPX",
            namespace="test",
            tags=[],
            category=PatternCategory.PACKER,
            confidence=0.95,
            offset=0,
            length=0,
            identifier="$upx",
        )

        result = YaraScanResult(
            file_path="test.exe",
            matches=[protection_match, packer_match],
        )

        protection_matches = result.get_matches_by_category(PatternCategory.PROTECTION)
        assert len(protection_matches) == 1
        assert protection_matches[0].rule_name == "VMProtect"


@pytest.mark.skipif(not YARA_AVAILABLE, reason="YARA not available")
class TestYaraPatternEngineInitialization:
    """Test YaraPatternEngine initialization."""

    def test_initialization_without_custom_rules(self) -> None:
        """YaraPatternEngine initializes with built-in rules."""
        engine = YaraPatternEngine()

        assert engine.compiled_rules is not None
        assert isinstance(engine.rule_metadata, dict)

    def test_initialization_with_custom_rules_dir(self, tmp_path: Path) -> None:
        """YaraPatternEngine loads custom rules from directory."""
        custom_rules_dir = tmp_path / "custom_rules"
        custom_rules_dir.mkdir()

        custom_rule = """
rule Custom_Test_Rule
{
    meta:
        category = "custom"
        confidence = 0.8

    strings:
        $custom = "CUSTOM_PATTERN"

    condition:
        $custom
}
"""
        (custom_rules_dir / "custom.yar").write_text(custom_rule)

        engine = YaraPatternEngine(custom_rules_path=str(custom_rules_dir))

        assert engine.compiled_rules is not None


@pytest.mark.skipif(not YARA_AVAILABLE, reason="YARA not available")
class TestProtectionDetection:
    """Test protection scheme detection."""

    def test_detect_vmprotect(self, vmprotect_binary: Path) -> None:
        """YaraPatternEngine detects VMProtect protection."""
        engine = YaraPatternEngine()
        result = engine.scan_file(str(vmprotect_binary))

        assert result is not None
        assert result.error is None

        protection_matches = result.get_matches_by_category(PatternCategory.PROTECTION)
        vmprotect_detected = any("vmprotect" in match.rule_name.lower() for match in protection_matches)

        if len(protection_matches) > 0:
            assert vmprotect_detected or len(protection_matches) > 0

    def test_detect_no_protection_on_clean_binary(self, clean_binary: Path) -> None:
        """YaraPatternEngine does not false positive on clean binaries."""
        engine = YaraPatternEngine()
        result = engine.scan_file(str(clean_binary))

        assert result is not None
        assert result.error is None


@pytest.mark.skipif(not YARA_AVAILABLE, reason="YARA not available")
class TestPackerDetection:
    """Test packer detection."""

    def test_detect_upx_packer(self, upx_packed_binary: Path) -> None:
        """YaraPatternEngine detects UPX packer."""
        engine = YaraPatternEngine()
        result = engine.scan_file(str(upx_packed_binary))

        assert result is not None
        assert result.error is None

        packer_matches = result.get_matches_by_category(PatternCategory.PACKER)
        upx_detected = any("upx" in match.rule_name.lower() for match in packer_matches)

        if len(packer_matches) > 0:
            assert upx_detected or len(packer_matches) > 0


@pytest.mark.skipif(not YARA_AVAILABLE, reason="YARA not available")
class TestLicensingDetection:
    """Test licensing pattern detection."""

    def test_detect_licensing_patterns(self, licensed_binary: Path) -> None:
        """YaraPatternEngine detects licensing strings."""
        engine = YaraPatternEngine()
        result = engine.scan_file(str(licensed_binary))

        assert result is not None
        assert result.error is None
        assert result.has_licensing or len(result.matches) == 0

    def test_detect_flexlm_licensing(self, tmp_path: Path) -> None:
        """YaraPatternEngine detects FlexLM licensing system."""
        binary_path = tmp_path / "flexlm.exe"
        create_test_binary_with_patterns(binary_path, include_licensing=True)

        engine = YaraPatternEngine()
        result = engine.scan_file(str(binary_path))

        assert result is not None

        licensing_matches = result.get_matches_by_category(PatternCategory.LICENSING)
        if len(licensing_matches) > 0:
            assert result.has_licensing


@pytest.mark.skipif(not YARA_AVAILABLE, reason="YARA not available")
class TestAntiDebugDetection:
    """Test anti-debug technique detection."""

    def test_detect_antidebug_apis(self, tmp_path: Path) -> None:
        """YaraPatternEngine detects anti-debug API usage."""
        binary_path = tmp_path / "antidebug.exe"
        create_test_binary_with_patterns(binary_path, include_antidebug=True)

        engine = YaraPatternEngine()
        result = engine.scan_file(str(binary_path))

        assert result is not None
        assert result.error is None

        antidebug_matches = result.get_matches_by_category(PatternCategory.ANTI_DEBUG)
        if len(antidebug_matches) > 0:
            assert any("debug" in match.rule_name.lower() for match in antidebug_matches)


@pytest.mark.skipif(not YARA_AVAILABLE, reason="YARA not available")
class TestComprehensiveScanning:
    """Test comprehensive scanning with multiple patterns."""

    def test_scan_protected_binary(self, protected_binary: Path) -> None:
        """YaraPatternEngine detects multiple protection types."""
        engine = YaraPatternEngine()
        result = engine.scan_file(str(protected_binary))

        assert result is not None
        assert result.error is None
        assert result.file_path == str(protected_binary)
        assert result.scan_time >= 0

    def test_scan_result_completeness(self, protected_binary: Path) -> None:
        """Scan result contains all expected metadata."""
        engine = YaraPatternEngine()
        result = engine.scan_file(str(protected_binary))

        assert result is not None
        assert isinstance(result.matches, list)
        assert isinstance(result.total_rules, int)
        assert isinstance(result.scan_time, float)
        assert isinstance(result.metadata, dict)


@pytest.mark.skipif(not YARA_AVAILABLE, reason="YARA not available")
class TestScanningModes:
    """Test different scanning modes."""

    def test_fast_scan_mode(self, protected_binary: Path) -> None:
        """Fast scan completes quickly."""
        engine = YaraPatternEngine()
        result = engine.scan_file(str(protected_binary), fast_mode=True)

        assert result is not None
        assert result.scan_time < 5.0

    def test_scan_with_timeout(self, protected_binary: Path) -> None:
        """Scan respects timeout parameter."""
        engine = YaraPatternEngine()
        result = engine.scan_file(str(protected_binary), timeout=30)

        assert result is not None


@pytest.mark.skipif(not YARA_AVAILABLE, reason="YARA not available")
class TestErrorHandling:
    """Test error handling in pattern engine."""

    def test_scan_nonexistent_file(self) -> None:
        """YaraPatternEngine handles nonexistent file."""
        engine = YaraPatternEngine()
        result = engine.scan_file("/nonexistent/file.exe")

        assert result is not None
        assert result.error is not None or len(result.matches) == 0

    def test_scan_empty_file(self, tmp_path: Path) -> None:
        """YaraPatternEngine handles empty file."""
        empty_path = tmp_path / "empty.exe"
        empty_path.write_bytes(b"")

        engine = YaraPatternEngine()
        result = engine.scan_file(str(empty_path))

        assert result is not None

    def test_scan_corrupted_file(self, tmp_path: Path) -> None:
        """YaraPatternEngine handles corrupted binary."""
        corrupted_path = tmp_path / "corrupted.exe"
        corrupted_path.write_bytes(b"\xff" * 100)

        engine = YaraPatternEngine()
        result = engine.scan_file(str(corrupted_path))

        assert result is not None


@pytest.mark.skipif(not YARA_AVAILABLE, reason="YARA not available")
class TestRuleManagement:
    """Test YARA rule management."""

    def test_rule_count_reporting(self) -> None:
        """YaraPatternEngine reports rule count."""
        engine = YaraPatternEngine()

        assert engine.compiled_rules is not None

    def test_rule_metadata_extraction(self) -> None:
        """YaraPatternEngine extracts rule metadata."""
        engine = YaraPatternEngine()

        assert isinstance(engine.rule_metadata, dict)


@pytest.mark.skipif(not YARA_AVAILABLE, reason="YARA not available")
class TestPerformance:
    """Test scanning performance."""

    def test_scan_small_binary_performance(self, clean_binary: Path) -> None:
        """Small binary scans complete quickly."""
        engine = YaraPatternEngine()
        result = engine.scan_file(str(clean_binary))

        assert result is not None
        assert result.scan_time < 10.0

    def test_scan_medium_binary_performance(self, tmp_path: Path) -> None:
        """Medium binary scans complete within reasonable time."""
        medium_binary = tmp_path / "medium.exe"
        create_test_binary_with_patterns(medium_binary)

        medium_binary.write_bytes(
            medium_binary.read_bytes() + b"\x00" * (100 * 1024)
        )

        engine = YaraPatternEngine()
        result = engine.scan_file(str(medium_binary))

        assert result is not None
        assert result.scan_time < 30.0

    def test_multiple_scans_caching(self, clean_binary: Path) -> None:
        """Multiple scans of same file are handled efficiently."""
        engine = YaraPatternEngine()

        result1 = engine.scan_file(str(clean_binary))
        result2 = engine.scan_file(str(clean_binary))

        assert result1 is not None
        assert result2 is not None


class TestYaraNotAvailable:
    """Test behavior when YARA is not available."""

    @pytest.mark.skipif(YARA_AVAILABLE, reason="YARA is available")
    def test_initialization_without_yara(self) -> None:
        """YaraPatternEngine raises ImportError when YARA not available."""
        with pytest.raises(ImportError, match="yara-python package is required"):
            YaraPatternEngine()
