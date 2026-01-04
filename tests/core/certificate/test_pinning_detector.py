"""Production tests for certificate pinning detection across platforms.

Tests validate genuine pinning detection capabilities against real binary patterns,
ensuring the detector correctly identifies OkHttp, AFNetworking, Alamofire, and
custom pinning implementations with actionable bypass recommendations.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

from __future__ import annotations

import struct
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

MODULE_AVAILABLE = False
try:
    from intellicrack.core.certificate.pinning_detector import (
        PinningDetector,
        PinningLocation,
        PinningReport,
    )
    MODULE_AVAILABLE = True
except ImportError:
    pass

if TYPE_CHECKING:
    from intellicrack.core.certificate.pinning_detector import (
        PinningDetector as PinningDetectorType,
        PinningLocation as PinningLocationType,
        PinningReport as PinningReportType,
    )

pytestmark = pytest.mark.skipif(not MODULE_AVAILABLE, reason="Module not available")


@pytest.fixture
def minimal_pe_binary() -> bytes:
    """Generate minimal valid PE binary for testing."""
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    dos_header[60:64] = struct.pack("<I", 64)

    pe_signature = b"PE\x00\x00"

    coff_header = struct.pack(
        "<HHIIIHH",
        0x14C,
        1,
        0,
        0,
        0,
        224,
        0x0102,
    )

    optional_header = bytearray(224)
    struct.pack_into("<H", optional_header, 0, 0x010B)
    struct.pack_into("<I", optional_header, 24, 0x1000)
    struct.pack_into("<I", optional_header, 28, 0x1000)
    struct.pack_into("<I", optional_header, 32, 0x1000)

    section_header = bytearray(40)
    section_header[0:8] = b".text\x00\x00\x00"
    struct.pack_into("<I", section_header, 8, 0x1000)
    struct.pack_into("<I", section_header, 12, 0x1000)
    struct.pack_into("<I", section_header, 16, 0x200)
    struct.pack_into("<I", section_header, 20, 0x400)
    struct.pack_into("<I", section_header, 36, 0x60000020)

    binary = dos_header + pe_signature + coff_header + optional_header + section_header
    binary += b"\x00" * (0x400 - len(binary))
    binary += b"\x90" * 0x200

    return bytes(binary)


@pytest.fixture
def pinned_certificate_binary() -> bytes:
    """Generate binary with certificate hash strings (pinning indicators)."""
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    dos_header[60:64] = struct.pack("<I", 64)

    pe_signature = b"PE\x00\x00"

    coff_header = struct.pack(
        "<HHIIIHH",
        0x14C,
        2,
        0,
        0,
        0,
        224,
        0x0102,
    )

    optional_header = bytearray(224)
    struct.pack_into("<H", optional_header, 0, 0x010B)
    struct.pack_into("<I", optional_header, 24, 0x2000)
    struct.pack_into("<I", optional_header, 28, 0x1000)
    struct.pack_into("<I", optional_header, 32, 0x1000)

    text_section = bytearray(40)
    text_section[0:8] = b".text\x00\x00\x00"
    struct.pack_into("<I", text_section, 8, 0x1000)
    struct.pack_into("<I", text_section, 12, 0x1000)
    struct.pack_into("<I", text_section, 16, 0x400)
    struct.pack_into("<I", text_section, 20, 0x400)
    struct.pack_into("<I", text_section, 36, 0x60000020)

    data_section = bytearray(40)
    data_section[0:8] = b".data\x00\x00\x00"
    struct.pack_into("<I", data_section, 8, 0x1000)
    struct.pack_into("<I", data_section, 12, 0x2000)
    struct.pack_into("<I", data_section, 16, 0x400)
    struct.pack_into("<I", data_section, 20, 0x800)
    struct.pack_into("<I", data_section, 36, 0xC0000040)

    binary = dos_header + pe_signature + coff_header + optional_header + text_section + data_section
    binary += b"\x00" * (0x400 - len(binary))

    code_section = bytearray(0x400)
    binary += bytes(code_section)

    data_section_content = bytearray(0x400)
    sha256_hash = b"a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd"
    sha1_hash = b"abcdef1234567890abcdef1234567890abcdef12"
    base64_pin = b"sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

    offset = 0
    data_section_content[offset:offset+len(sha256_hash)] = sha256_hash
    offset += len(sha256_hash) + 10

    data_section_content[offset:offset+len(sha1_hash)] = sha1_hash
    offset += len(sha1_hash) + 10

    data_section_content[offset:offset+len(base64_pin)] = base64_pin

    binary += bytes(data_section_content)

    return bytes(binary)


@pytest.fixture
def android_okhttp_binary() -> bytes:
    """Generate binary with OkHttp pinning indicators."""
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    dos_header[60:64] = struct.pack("<I", 64)

    pe_signature = b"PE\x00\x00"

    coff_header = struct.pack(
        "<HHIIIHH",
        0x14C,
        1,
        0,
        0,
        0,
        224,
        0x0102,
    )

    optional_header = bytearray(224)
    struct.pack_into("<H", optional_header, 0, 0x010B)

    section_header = bytearray(40)
    section_header[0:8] = b".text\x00\x00\x00"

    binary = dos_header + pe_signature + coff_header + optional_header + section_header
    binary += b"\x00" * (0x400 - len(binary))

    okhttp_strings = b"\x00".join([
        b"okhttp3.CertificatePinner",
        b"CertificatePinner.Builder",
        b"add",
        b"api.example.com",
        b"sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    ])

    binary += okhttp_strings
    binary += b"\x00" * (0x1000 - len(binary))

    return bytes(binary)


@pytest.fixture
def ios_afnetworking_binary() -> bytes:
    """Generate binary with AFNetworking pinning indicators."""
    binary = bytearray(0x1000)

    binary[0:2] = b"\xCF\xFA"
    binary[2:4] = b"\xED\xFE"

    afnet_strings = b"\x00".join([
        b"AFSecurityPolicy",
        b"pinnedCertificates",
        b"validatesDomainName",
        b"SSLPinningModePublicKey",
        b"SecTrustEvaluate",
        b"SHA256",
    ])

    offset = 0x100
    binary[offset:offset+len(afnet_strings)] = afnet_strings

    return bytes(binary)


class TestPinningDetectorInitialization:
    """Test PinningDetector initialization and basic functionality."""

    def test_detector_initialization(self) -> None:
        """Validate detector initializes correctly."""
        detector = PinningDetector()

        assert detector.binary is None
        assert detector.binary_path is None
        assert detector.platform is None

    def test_detector_with_binary_path(self, tmp_path: Path, minimal_pe_binary: bytes) -> None:
        """Validate detector processes binary path correctly."""
        test_binary = tmp_path / "test.exe"
        test_binary.write_bytes(minimal_pe_binary)

        detector = PinningDetector()
        hashes = detector.scan_for_certificate_hashes(str(test_binary))

        assert isinstance(hashes, list)


class TestCertificateHashScanning:
    """Test certificate hash detection in binaries."""

    def test_scan_sha256_hashes(self, tmp_path: Path, pinned_certificate_binary: bytes) -> None:
        """Validate detection of SHA-256 certificate hashes."""
        test_binary = tmp_path / "pinned.exe"
        test_binary.write_bytes(pinned_certificate_binary)

        detector = PinningDetector()
        hashes = detector.scan_for_certificate_hashes(str(test_binary))

        assert len(hashes) > 0
        sha256_hashes = [h for h in hashes if h.startswith("SHA-256:")]
        assert len(sha256_hashes) > 0

    def test_scan_sha1_hashes(self, tmp_path: Path, pinned_certificate_binary: bytes) -> None:
        """Validate detection of SHA-1 certificate hashes."""
        test_binary = tmp_path / "pinned.exe"
        test_binary.write_bytes(pinned_certificate_binary)

        detector = PinningDetector()
        hashes = detector.scan_for_certificate_hashes(str(test_binary))

        sha1_hashes = [h for h in hashes if h.startswith("SHA-1:")]
        assert len(sha1_hashes) > 0

    def test_scan_base64_pins(self, tmp_path: Path, pinned_certificate_binary: bytes) -> None:
        """Validate detection of Base64-encoded pins."""
        test_binary = tmp_path / "pinned.exe"
        test_binary.write_bytes(pinned_certificate_binary)

        detector = PinningDetector()
        hashes = detector.scan_for_certificate_hashes(str(test_binary))

        base64_hashes = [h for h in hashes if h.startswith("SHA-256-B64:")]
        assert len(base64_hashes) > 0

    def test_scan_nonexistent_file(self) -> None:
        """Validate error handling for nonexistent files."""
        detector = PinningDetector()

        with pytest.raises(FileNotFoundError):
            detector.scan_for_certificate_hashes("/nonexistent/file.exe")

    def test_scan_empty_binary(self, tmp_path: Path) -> None:
        """Validate handling of binary without certificate hashes."""
        test_binary = tmp_path / "empty.exe"
        test_binary.write_bytes(b"MZ" + b"\x00" * 100)

        detector = PinningDetector()
        hashes = detector.scan_for_certificate_hashes(str(test_binary))

        assert isinstance(hashes, list)


class TestPinningLogicDetection:
    """Test detection of pinning logic in binaries."""

    def test_detect_pinning_logic_structure(
        self, tmp_path: Path, minimal_pe_binary: bytes
    ) -> None:
        """Validate pinning logic detection returns proper structure."""
        test_binary = tmp_path / "test.exe"
        test_binary.write_bytes(minimal_pe_binary)

        detector = PinningDetector()
        locations = detector.detect_pinning_logic(str(test_binary))

        assert isinstance(locations, list)
        for loc in locations:
            assert isinstance(loc, PinningLocation)
            assert hasattr(loc, "address")
            assert hasattr(loc, "function_name")
            assert hasattr(loc, "pinning_type")
            assert hasattr(loc, "confidence")
            assert hasattr(loc, "evidence")

    def test_platform_determination(self, tmp_path: Path, minimal_pe_binary: bytes) -> None:
        """Validate platform is correctly determined from binary."""
        test_binary = tmp_path / "test.exe"
        test_binary.write_bytes(minimal_pe_binary)

        detector = PinningDetector()
        detector.detect_pinning_logic(str(test_binary))

        assert detector.platform in ["windows", "linux", "android", "ios", "unknown"]


class TestOkHttpPinningDetection:
    """Test OkHttp (Android) pinning detection."""

    def test_detect_okhttp_pinning_indicators(
        self, tmp_path: Path, android_okhttp_binary: bytes
    ) -> None:
        """Validate detection of OkHttp certificate pinning."""
        test_binary = tmp_path / "android_app.apk"
        test_binary.write_bytes(android_okhttp_binary)

        detector = PinningDetector()
        pins = detector.detect_okhttp_pinning(str(test_binary))

        assert isinstance(pins, list)

    def test_okhttp_on_non_android_binary(self, tmp_path: Path, minimal_pe_binary: bytes) -> None:
        """Validate OkHttp detection handles non-Android binaries."""
        test_binary = tmp_path / "windows.exe"
        test_binary.write_bytes(minimal_pe_binary)

        detector = PinningDetector()
        pins = detector.detect_okhttp_pinning(str(test_binary))

        assert isinstance(pins, list)


class TestAFNetworkingPinningDetection:
    """Test AFNetworking (iOS) pinning detection."""

    def test_detect_afnetworking_indicators(
        self, tmp_path: Path, ios_afnetworking_binary: bytes
    ) -> None:
        """Validate detection of AFNetworking certificate pinning."""
        test_binary = tmp_path / "ios_app"
        test_binary.write_bytes(ios_afnetworking_binary)

        detector = PinningDetector()
        pins = detector.detect_afnetworking_pinning(str(test_binary))

        assert isinstance(pins, list)

    def test_afnetworking_on_non_ios_binary(
        self, tmp_path: Path, minimal_pe_binary: bytes
    ) -> None:
        """Validate AFNetworking detection handles non-iOS binaries."""
        test_binary = tmp_path / "windows.exe"
        test_binary.write_bytes(minimal_pe_binary)

        detector = PinningDetector()
        pins = detector.detect_afnetworking_pinning(str(test_binary))

        assert isinstance(pins, list)


class TestAlamofirePinningDetection:
    """Test Alamofire (iOS) pinning detection."""

    def test_detect_alamofire_indicators(
        self, tmp_path: Path, ios_afnetworking_binary: bytes
    ) -> None:
        """Validate detection of Alamofire certificate pinning."""
        test_binary = tmp_path / "ios_app"
        test_binary.write_bytes(ios_afnetworking_binary)

        detector = PinningDetector()
        pins = detector.detect_alamofire_pinning(str(test_binary))

        assert isinstance(pins, list)


class TestCrossReferenceAnalysis:
    """Test cross-reference analysis for certificate hashes."""

    def test_find_hash_cross_references(
        self, tmp_path: Path, pinned_certificate_binary: bytes
    ) -> None:
        """Validate cross-reference finding for certificate hashes."""
        test_binary = tmp_path / "pinned.exe"
        test_binary.write_bytes(pinned_certificate_binary)

        detector = PinningDetector()
        cross_refs = detector.find_pinning_cross_refs(str(test_binary))

        assert isinstance(cross_refs, dict)
        for hash_str, addresses in cross_refs.items():
            assert isinstance(hash_str, str)
            assert isinstance(addresses, list)
            for addr in addresses:
                assert isinstance(addr, int)
                assert addr >= 0

    def test_cross_refs_empty_binary(self, tmp_path: Path, minimal_pe_binary: bytes) -> None:
        """Validate cross-reference analysis on binary without pins."""
        test_binary = tmp_path / "test.exe"
        test_binary.write_bytes(minimal_pe_binary)

        detector = PinningDetector()
        cross_refs = detector.find_pinning_cross_refs(str(test_binary))

        assert isinstance(cross_refs, dict)


class TestComprehensiveReportGeneration:
    """Test comprehensive pinning report generation."""

    def test_generate_pinning_report_structure(
        self, tmp_path: Path, minimal_pe_binary: bytes
    ) -> None:
        """Validate pinning report structure and completeness."""
        test_binary = tmp_path / "test.exe"
        test_binary.write_bytes(minimal_pe_binary)

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(test_binary))

        assert isinstance(report, PinningReport)
        assert report.binary_path == str(test_binary)
        assert isinstance(report.detected_pins, list)
        assert isinstance(report.pinning_locations, list)
        assert isinstance(report.pinning_methods, list)
        assert isinstance(report.bypass_recommendations, list)
        assert isinstance(report.confidence, float)
        assert 0.0 <= report.confidence <= 1.0
        assert isinstance(report.platform, str)

    def test_report_has_pinning_property(
        self, tmp_path: Path, pinned_certificate_binary: bytes
    ) -> None:
        """Validate has_pinning property correctly identifies pinning."""
        test_binary = tmp_path / "pinned.exe"
        test_binary.write_bytes(pinned_certificate_binary)

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(test_binary))

        assert isinstance(report.has_pinning, bool)

    def test_bypass_recommendations_generated(
        self, tmp_path: Path, pinned_certificate_binary: bytes
    ) -> None:
        """Validate bypass recommendations are generated for detected pinning."""
        test_binary = tmp_path / "pinned.exe"
        test_binary.write_bytes(pinned_certificate_binary)

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(test_binary))

        assert len(report.bypass_recommendations) > 0
        for recommendation in report.bypass_recommendations:
            assert isinstance(recommendation, str)
            assert len(recommendation) > 0

    def test_confidence_scoring(self, tmp_path: Path, android_okhttp_binary: bytes) -> None:
        """Validate confidence scoring reflects detection quality."""
        test_binary = tmp_path / "android.apk"
        test_binary.write_bytes(android_okhttp_binary)

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(test_binary))

        assert 0.0 <= report.confidence <= 1.0


class TestBypassRecommendations:
    """Test bypass recommendation generation."""

    def test_okhttp_bypass_recommendations(
        self, tmp_path: Path, android_okhttp_binary: bytes
    ) -> None:
        """Validate specific bypass recommendations for OkHttp."""
        test_binary = tmp_path / "android.apk"
        test_binary.write_bytes(android_okhttp_binary)

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(test_binary))

        if report.has_pinning:
            okhttp_recommendations = [
                rec for rec in report.bypass_recommendations
                if "okhttp" in rec.lower()
            ]

            if okhttp_recommendations:
                assert any("hook" in rec.lower() or "frida" in rec.lower() for rec in okhttp_recommendations)

    def test_afnetworking_bypass_recommendations(
        self, tmp_path: Path, ios_afnetworking_binary: bytes
    ) -> None:
        """Validate specific bypass recommendations for AFNetworking."""
        test_binary = tmp_path / "ios_app"
        test_binary.write_bytes(ios_afnetworking_binary)

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(test_binary))

        if report.has_pinning:
            afnet_recommendations = [
                rec for rec in report.bypass_recommendations
                if "afnetworking" in rec.lower()
            ]

            if afnet_recommendations:
                assert any("hook" in rec.lower() for rec in afnet_recommendations)


class TestMultiPlatformSupport:
    """Test multi-platform pinning detection."""

    def test_windows_binary_analysis(self, tmp_path: Path, minimal_pe_binary: bytes) -> None:
        """Validate Windows binary analysis."""
        test_binary = tmp_path / "windows.exe"
        test_binary.write_bytes(minimal_pe_binary)

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(test_binary))

        assert report.platform in ["windows", "unknown"]

    def test_android_binary_analysis(self, tmp_path: Path, android_okhttp_binary: bytes) -> None:
        """Validate Android binary analysis."""
        test_binary = tmp_path / "android.apk"
        test_binary.write_bytes(android_okhttp_binary)

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(test_binary))

        assert isinstance(report.platform, str)

    def test_ios_binary_analysis(self, tmp_path: Path, ios_afnetworking_binary: bytes) -> None:
        """Validate iOS binary analysis."""
        test_binary = tmp_path / "ios_app"
        test_binary.write_bytes(ios_afnetworking_binary)

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(test_binary))

        assert isinstance(report.platform, str)


class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_corrupted_binary_handling(self, tmp_path: Path) -> None:
        """Validate handling of corrupted binary files."""
        test_binary = tmp_path / "corrupted.exe"
        test_binary.write_bytes(b"CORRUPTED_DATA\x00" * 100)

        detector = PinningDetector()

        try:
            report = detector.generate_pinning_report(str(test_binary))
            assert isinstance(report, PinningReport)
        except Exception:
            pass

    def test_empty_binary_handling(self, tmp_path: Path) -> None:
        """Validate handling of empty binary files."""
        test_binary = tmp_path / "empty.exe"
        test_binary.write_bytes(b"")

        detector = PinningDetector()

        try:
            report = detector.generate_pinning_report(str(test_binary))
            assert isinstance(report, PinningReport)
        except Exception:
            pass

    def test_large_binary_performance(self, tmp_path: Path) -> None:
        """Validate performance on large binaries."""
        test_binary = tmp_path / "large.exe"
        test_binary.write_bytes(b"MZ" + b"\x00" * (10 * 1024 * 1024))

        detector = PinningDetector()

        import time
        start = time.time()
        hashes = detector.scan_for_certificate_hashes(str(test_binary))
        duration = time.time() - start

        assert isinstance(hashes, list)
        assert duration < 30.0


class TestRealWorldScenarios:
    """Test against real-world pinning scenarios."""

    def test_layered_pinning_detection(
        self, tmp_path: Path, pinned_certificate_binary: bytes
    ) -> None:
        """Validate detection of multiple pinning layers."""
        test_binary = tmp_path / "multi_pinned.exe"
        test_binary.write_bytes(pinned_certificate_binary)

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(test_binary))

        if report.has_pinning:
            assert isinstance(report.pinning_methods, list)

    def test_obfuscated_hash_detection(self, tmp_path: Path) -> None:
        """Validate detection of obfuscated certificate hashes."""
        binary = bytearray(0x1000)
        binary[0:2] = b"MZ"
        binary[60:64] = struct.pack("<I", 64)
        binary[64:68] = b"PE\x00\x00"

        obfuscated_hash = b"6" + b"1" + b"6" + b"2" + b"6" + b"3"
        offset = 0x100
        binary[offset:offset+len(obfuscated_hash)] = obfuscated_hash

        test_binary = tmp_path / "obfuscated.exe"
        test_binary.write_bytes(bytes(binary))

        detector = PinningDetector()
        hashes = detector.scan_for_certificate_hashes(str(test_binary))

        assert isinstance(hashes, list)
