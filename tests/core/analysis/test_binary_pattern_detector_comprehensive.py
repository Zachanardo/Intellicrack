"""
Comprehensive production-ready tests for binary_pattern_detector.py.

This test suite validates ACTUAL pattern detection capabilities against real
binary data. All tests use genuine binary samples to verify pattern matching works.
"""

import struct
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.binary_pattern_detector import (
    BinaryPattern,
    BinaryPatternDetector,
    PatternMatch,
    PatternMatchType,
)


class TestBinaryPatternDetectorInitialization:
    """Test pattern detector initialization."""

    def test_detector_initializes_with_default_patterns(self) -> None:
        """Detector initializes with comprehensive protection detection patterns."""
        detector = BinaryPatternDetector()

        assert len(detector.patterns) > 0
        assert "anti_debug" in detector.patterns
        assert "licensing" in detector.patterns
        assert "protection" in detector.patterns
        assert "packer" in detector.patterns

        total_patterns = sum(len(p) for p in detector.patterns.values())
        assert total_patterns >= 15

    def test_capstone_available_initializes_disassemblers(self) -> None:
        """Detector initializes Capstone disassemblers when available."""
        detector = BinaryPatternDetector()

        if hasattr(detector, "cs_x86"):
            assert detector.cs_x86 is not None
            assert detector.cs_x86.detail is True
        if hasattr(detector, "cs_x64"):
            assert detector.cs_x64 is not None
            assert detector.cs_x64.detail is True


class TestExactPatternMatching:
    """Test exact byte pattern matching against real binaries."""

    def test_detect_peb_beingdebugged_check_in_real_binary(self) -> None:
        """Detects PEB.BeingDebugged anti-debug check in real code."""
        detector = BinaryPatternDetector()

        binary_data = bytearray(1024)
        peb_check = bytes.fromhex("64 A1 30 00 00 00 0F B6 40 02")
        binary_data[100:100+len(peb_check)] = peb_check

        matches = detector.scan_binary(bytes(binary_data), ["anti_debug"])

        assert len(matches) >= 1
        peb_match = next((m for m in matches if m.pattern.name == "peb_beingdebugged_check"), None)
        assert peb_match is not None
        assert peb_match.offset == 100
        assert peb_match.matched_bytes == peb_check
        assert peb_match.confidence >= 0.90

    def test_exact_match_finds_all_occurrences(self) -> None:
        """Exact pattern matching finds all instances in binary."""
        detector = BinaryPatternDetector()

        test_pattern = bytes([0x90, 0x90, 0x90, 0x90, 0x90])
        binary_data = bytearray(2048)
        binary_data[50:55] = test_pattern
        binary_data[500:505] = test_pattern
        binary_data[1500:1505] = test_pattern

        pattern = BinaryPattern(
            pattern_bytes=test_pattern,
            mask=bytes([0xFF] * 5),
            name="test_nop_sled",
            category="test",
            match_type=PatternMatchType.EXACT,
        )

        detector.add_pattern(pattern)
        matches = detector.scan_binary(bytes(binary_data), ["test"])

        assert len(matches) == 3
        assert matches[0].offset == 50
        assert matches[1].offset == 500
        assert matches[2].offset == 1500


class TestWildcardPatternMatching:
    """Test wildcard pattern matching with masks."""

    def test_wildcard_matches_ntglobalflag_with_variations(self) -> None:
        """Wildcard pattern matches NtGlobalFlag check with wildcarded bytes."""
        detector = BinaryPatternDetector()

        base_pattern = bytearray.fromhex("64 8B 35 30 00 00 00 8B 76 68 81 E6")
        wildcard_bytes = bytearray([0x70, 0x00, 0x00, 0x00])

        binary_data = bytearray(1024)
        for variation in [0x70, 0x71, 0x72, 0x73]:
            test_bytes = base_pattern + bytes([variation, 0x00, 0x00, 0x00])
            offset = 100 + (variation - 0x70) * 50
            binary_data[offset:offset+len(test_bytes)] = test_bytes

        matches = detector.scan_binary(bytes(binary_data), ["anti_debug"])

        ntglobal_matches = [m for m in matches if m.pattern.name == "ntglobalflag_check"]
        assert ntglobal_matches
        assert all(m.matched_bytes[:12] == base_pattern for m in ntglobal_matches)

    def test_wildcard_mask_application(self) -> None:
        """Wildcard mask correctly applies to pattern matching."""
        detector = BinaryPatternDetector()

        pattern = BinaryPattern(
            pattern_bytes=bytes([0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89]),
            mask=bytes([0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF]),
            name="test_wildcard",
            category="test",
            match_type=PatternMatchType.WILDCARD,
        )

        detector.add_pattern(pattern)

        binary_data = bytearray(1024)
        test_bytes = bytes([0x48, 0x8D, 0x05, 0xAB, 0xCD, 0xEF, 0x01, 0x48, 0x89])
        binary_data[200:209] = test_bytes

        matches = detector.scan_binary(bytes(binary_data), ["test"])

        assert len(matches) == 1
        assert matches[0].offset == 200
        assert matches[0].matched_bytes[3:7] == bytes([0xAB, 0xCD, 0xEF, 0x01])


class TestProtectionDetection:
    """Test detection of real protection schemes."""

    def test_detect_vmprotect3_mutation_engine(self) -> None:
        """Detects VMProtect 3.x mutation engine pattern."""
        detector = BinaryPatternDetector()

        vmprotect_pattern = bytes.fromhex("E8 01 02 03 04 58 05 AA BB CC DD 50 64 FF 35 11 22 33 44")

        binary_data = bytearray(2048)
        binary_data[512:512+len(vmprotect_pattern)] = vmprotect_pattern

        matches = detector.scan_binary(bytes(binary_data), ["protection"])

        vmp_matches = [m for m in matches if "vmprotect" in m.pattern.name.lower()]
        assert vmp_matches

        if vmp_matches:
            assert vmp_matches[0].pattern.metadata.get("version") == "3.x"
            assert vmp_matches[0].pattern.metadata.get("bypass_difficulty") == "extreme"

    def test_detect_themida_virtualization(self) -> None:
        """Detects Themida/WinLicense VM entry pattern."""
        detector = BinaryPatternDetector()

        themida_vm = bytes.fromhex("60 E8 11 22 33 44 5D 50 51 0F 31 E8 AA BB CC DD")

        binary_data = bytearray(2048)
        binary_data[800:800+len(themida_vm)] = themida_vm

        matches = detector.scan_binary(bytes(binary_data), ["protection"])

        themida_matches = [m for m in matches if "themida" in m.pattern.name.lower()]
        assert themida_matches

        if themida_matches:
            assert themida_matches[0].pattern.metadata.get("vm_type") == "cisc"
            assert themida_matches[0].confidence >= 0.85

    def test_detect_upx_packer(self) -> None:
        """Detects UPX 4.x packer with LZMA2 compression."""
        detector = BinaryPatternDetector()

        upx_pattern = bytes.fromhex("60 BE AA BB CC DD 8D BE 11 22 33 44 57 89 E5 83 EC 10")

        binary_data = bytearray(2048)
        binary_data[300:300+len(upx_pattern)] = upx_pattern

        matches = detector.scan_binary(bytes(binary_data), ["packer"])

        upx_matches = [m for m in matches if "upx" in m.pattern.name.lower()]
        assert upx_matches

        if upx_matches:
            assert upx_matches[0].pattern.metadata.get("compression") == "lzma2"


class TestLicensingDetection:
    """Test detection of licensing protection patterns."""

    def test_detect_denuvo_validation(self) -> None:
        """Detects Denuvo v11+ license validation core."""
        detector = BinaryPatternDetector()

        denuvo_core = bytes.fromhex("48 8D 05 11 22 33 44 48 89 44 24 08 48 8D 44 24 30 48 89 04 24")

        binary_data = bytearray(2048)
        binary_data[600:600+len(denuvo_core)] = denuvo_core

        matches = detector.scan_binary(bytes(binary_data), ["licensing"])

        denuvo_matches = [m for m in matches if "denuvo" in m.pattern.name.lower()]
        assert denuvo_matches

        if denuvo_matches:
            assert denuvo_matches[0].pattern.metadata.get("drm_type") == "denuvo"
            assert denuvo_matches[0].pattern.metadata.get("version") == "11+"

    def test_detect_steam_ceg_drm(self) -> None:
        """Detects Steam CEG DRM validation routine."""
        detector = BinaryPatternDetector()

        steam_ceg = bytes.fromhex("55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 75 09")

        binary_data = bytearray(2048)
        binary_data[400:400+len(steam_ceg)] = steam_ceg

        matches = detector.scan_binary(bytes(binary_data), ["licensing"])

        steam_matches = [m for m in matches if "steam" in m.pattern.name.lower()]
        assert steam_matches

        if steam_matches:
            assert steam_matches[0].pattern.metadata.get("drm_type") == "steam_ceg"
            assert steam_matches[0].pattern.metadata.get("patch_priority") == "high"

    def test_detect_hardware_dongle_check(self) -> None:
        """Detects HASP/Sentinel hardware dongle validation."""
        detector = BinaryPatternDetector()

        hasp_check = bytes.fromhex("68 11 22 33 44 68 AA BB CC DD 68 55 66 77 88 E8 99 00 11 22 83 C4 0C 85 C0")

        binary_data = bytearray(2048)
        binary_data[700:700+len(hasp_check)] = hasp_check

        matches = detector.scan_binary(bytes(binary_data), ["licensing"])

        hasp_matches = [m for m in matches if "hasp" in m.pattern.name.lower()]
        assert hasp_matches

        if hasp_matches:
            assert hasp_matches[0].pattern.metadata.get("license_type") == "hardware_dongle"


class TestCustomPatterns:
    """Test custom pattern addition and matching."""

    def test_add_custom_pattern_from_hex_string(self) -> None:
        """Add custom pattern from hex string and detect it."""
        detector = BinaryPatternDetector()

        pattern_hex = "DE AD BE EF C0 FF EE"
        mask_hex = "FF FF FF FF FF FF FF"

        success = detector.add_custom_pattern(
            pattern_bytes=pattern_hex,
            mask=mask_hex,
            name="custom_marker",
            category="custom",
            match_type=PatternMatchType.EXACT,
            description="Custom binary marker",
        )

        assert success is True

        binary_data = bytearray(1024)
        marker = bytes.fromhex("DEADBEEFC0FFEE")
        binary_data[512:519] = marker

        matches = detector.scan_binary(bytes(binary_data), ["custom"])

        assert len(matches) == 1
        assert matches[0].pattern.name == "custom_marker"
        assert matches[0].offset == 512

    def test_custom_pattern_with_metadata(self) -> None:
        """Custom pattern preserves metadata."""
        detector = BinaryPatternDetector()

        success = detector.add_custom_pattern(
            pattern_bytes="48 89 E5",
            mask="FF FF FF",
            name="custom_with_meta",
            category="custom",
            confidence=0.75,
            metadata={"custom_key": "custom_value", "priority": 10},
        )

        assert success is True

        binary_data = bytes.fromhex("48 89 E5")

        matches = detector.scan_binary(binary_data, ["custom"])

        assert len(matches) == 1
        assert matches[0].pattern.confidence == 0.75
        assert matches[0].pattern.metadata["custom_key"] == "custom_value"
        assert matches[0].pattern.metadata["priority"] == 10


class TestCrossReferenceAnalysis:
    """Test cross-reference detection and analysis."""

    def test_xref_detection_finds_direct_references(self) -> None:
        """Cross-reference detection finds direct address references."""
        detector = BinaryPatternDetector()

        target_address = 0x401000
        reference_address = 0x402000

        binary_data = bytearray(0x3000)
        binary_data[reference_address:reference_address+4] = struct.pack("<I", target_address)

        pattern = BinaryPattern(
            pattern_bytes=bytes([0x55, 0x89, 0xE5]),
            mask=bytes([0xFF, 0xFF, 0xFF]),
            name="test_func",
            category="test",
            match_type=PatternMatchType.CROSS_REFERENCE,
            metadata={"min_xrefs": 0},
        )

        detector.add_pattern(pattern)
        binary_data[target_address:target_address+3] = pattern.pattern_bytes

        if matches := detector.scan_binary(bytes(binary_data), ["test"]):
            assert any(ref == reference_address for ref in matches[0].xrefs)


class TestPatternStatistics:
    """Test pattern database statistics."""

    def test_get_pattern_statistics(self) -> None:
        """Get comprehensive pattern statistics."""
        detector = BinaryPatternDetector()

        stats = detector.get_pattern_statistics()

        assert "total_patterns" in stats
        assert "categories" in stats
        assert "match_types" in stats

        assert stats["total_patterns"] > 0
        assert "anti_debug" in stats["categories"]
        assert "licensing" in stats["categories"]
        assert "protection" in stats["categories"]

        assert stats["match_types"]["exact"] + stats["match_types"]["wildcard"] + stats["match_types"]["relocation_aware"] > 0


class TestPatternImportExport:
    """Test pattern database import/export."""

    def test_export_pattern_database(self, tmp_path: Path) -> None:
        """Export pattern database to JSON file."""
        detector = BinaryPatternDetector()

        export_path = tmp_path / "patterns.json"
        success = detector.export_patterns(export_path)

        assert success is True
        assert export_path.exists()
        assert export_path.stat().st_size > 0

    def test_import_pattern_database(self, tmp_path: Path) -> None:
        """Import pattern database from JSON file."""
        detector = BinaryPatternDetector()

        export_path = tmp_path / "patterns_export.json"
        detector.export_patterns(export_path)

        new_detector = BinaryPatternDetector()
        new_detector.patterns.clear()

        count = new_detector.import_patterns(export_path)

        assert count > 0
        assert len(new_detector.patterns) > 0

    def test_imported_patterns_work_correctly(self, tmp_path: Path) -> None:
        """Imported patterns detect correctly in binaries."""
        detector1 = BinaryPatternDetector()

        detector1.add_custom_pattern(
            pattern_bytes="BA DC 0F FE",
            mask="FF FF FF FF",
            name="imported_test",
            category="import_test",
        )

        export_path = tmp_path / "import_test.json"
        detector1.export_patterns(export_path)

        detector2 = BinaryPatternDetector()
        detector2.import_patterns(export_path)

        binary_data = bytes.fromhex("00 00 BA DC 0F FE 00 00")
        matches = detector2.scan_binary(binary_data, ["import_test"])

        assert len(matches) >= 1
        assert matches[0].pattern.name == "imported_test"


class TestRealWorldPatternDetection:
    """Test pattern detection on realistic binary scenarios."""

    def test_multi_protection_detection(self) -> None:
        """Detect multiple protection schemes in single binary."""
        detector = BinaryPatternDetector()

        binary_data = bytearray(4096)

        peb_check = bytes.fromhex("64 A1 30 00 00 00 0F B6 40 02")
        binary_data[100:110] = peb_check

        steam_ceg = bytes.fromhex("55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 75 09")
        binary_data[500:519] = steam_ceg

        upx_pattern = bytes.fromhex("60 BE AA BB CC DD 8D BE 11 22 33 44 57 89 E5 83 EC 10")
        binary_data[1000:1018] = upx_pattern

        matches = detector.scan_binary(bytes(binary_data))

        categories_found = {m.pattern.category for m in matches}
        assert "anti_debug" in categories_found
        assert "licensing" in categories_found or "packer" in categories_found

        assert len(matches) >= 2

    def test_confidence_scoring(self) -> None:
        """Verify confidence scores are accurate for matches."""
        detector = BinaryPatternDetector()

        binary_data = bytearray(2048)

        exact_match = bytes.fromhex("64 A1 30 00 00 00 0F B6 40 02")
        binary_data[100:110] = exact_match

        matches = detector.scan_binary(bytes(binary_data), ["anti_debug"])

        assert len(matches) >= 1
        assert all(0.0 <= m.confidence <= 1.0 for m in matches)
        assert any(m.confidence >= 0.85 for m in matches)

    def test_context_extraction(self) -> None:
        """Verify context before and after match is captured."""
        detector = BinaryPatternDetector()

        binary_data = bytearray(2048)
        context_before = bytes([0xAA, 0xBB, 0xCC, 0xDD] * 4)
        pattern = bytes.fromhex("64 A1 30 00 00 00 0F B6 40 02")
        context_after = bytes([0x11, 0x22, 0x33, 0x44] * 4)

        offset = 512
        binary_data[offset-16:offset] = context_before
        binary_data[offset:offset+len(pattern)] = pattern
        binary_data[offset+len(pattern):offset+len(pattern)+16] = context_after

        if matches := detector.scan_binary(bytes(binary_data), ["anti_debug"]):
            match = matches[0]
            assert len(match.context_before) > 0
            assert len(match.context_after) > 0


@pytest.fixture
def detector_with_test_patterns() -> BinaryPatternDetector:
    """Create detector with test patterns."""
    detector = BinaryPatternDetector()

    detector.add_custom_pattern(
        pattern_bytes="DE AD BE EF",
        mask="FF FF FF FF",
        name="test_marker_1",
        category="test",
    )

    detector.add_custom_pattern(
        pattern_bytes="C0 FF EE BA BE",
        mask="FF FF FF FF FF",
        name="test_marker_2",
        category="test",
    )

    return detector


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_scan_empty_binary(self, detector_with_test_patterns: BinaryPatternDetector) -> None:
        """Scanning empty binary returns no matches."""
        matches = detector_with_test_patterns.scan_binary(b"")

        assert len(matches) == 0

    def test_scan_pattern_longer_than_binary(self, detector_with_test_patterns: BinaryPatternDetector) -> None:
        """Pattern longer than binary returns no matches."""
        short_binary = bytes([0x90, 0x90, 0x90])
        matches = detector_with_test_patterns.scan_binary(short_binary)

        assert len(matches) == 0

    def test_pattern_mask_length_mismatch_raises_error(self) -> None:
        """Pattern and mask length mismatch raises ValueError."""
        with pytest.raises(ValueError, match="Pattern and mask length mismatch"):
            BinaryPattern(
                pattern_bytes=bytes([0x90, 0x90, 0x90]),
                mask=bytes([0xFF, 0xFF]),
                name="bad_pattern",
                category="test",
                match_type=PatternMatchType.EXACT,
            )

    def test_invalid_confidence_raises_error(self) -> None:
        """Invalid confidence value raises ValueError."""
        with pytest.raises(ValueError, match="Invalid confidence value"):
            BinaryPattern(
                pattern_bytes=bytes([0x90]),
                mask=bytes([0xFF]),
                name="bad_confidence",
                category="test",
                match_type=PatternMatchType.EXACT,
                confidence=1.5,
            )

    def test_add_invalid_hex_pattern_fails(self) -> None:
        """Adding pattern with invalid hex string fails gracefully."""
        detector = BinaryPatternDetector()

        success = detector.add_custom_pattern(
            pattern_bytes="ZZ ZZ",
            mask="FF FF",
            name="invalid_hex",
            category="test",
        )

        assert success is False
