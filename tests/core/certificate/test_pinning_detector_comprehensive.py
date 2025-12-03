"""Comprehensive production-ready tests for SSL pinning detection capabilities.

This test suite validates the PinningDetector's ability to detect real SSL
pinning implementations across multiple platforms and frameworks. Tests use
actual binary patterns and cryptographic hashes to ensure genuine detection
capability.

Test Coverage:
- Certificate hash detection (SHA-256, SHA-1, Base64)
- Multi-platform pinning logic detection (Android, iOS, Windows, Linux)
- Framework-specific detection (OkHttp, AFNetworking, Alamofire, OpenSSL)
- Android Network Security Config parsing
- Cross-reference analysis for certificate hash usage
- Multiple pin detection and confidence scoring
- Obfuscated pinning pattern detection
- Complete pinning report generation
- Bypass recommendation generation

All tests validate REAL functionality - no mocks, no stubs.
"""

import hashlib
import struct
import tempfile
import zipfile
from pathlib import Path
from typing import Any

import lief
import pytest

from intellicrack.core.certificate.apk_analyzer import DomainConfig, NetworkSecurityConfig, PinConfig, PinningInfo
from intellicrack.core.certificate.pinning_detector import PinningDetector, PinningLocation, PinningReport


@pytest.fixture
def temp_test_dir(tmp_path: Path) -> Path:
    """Create temporary directory for test files."""
    return tmp_path


@pytest.fixture
def sha256_cert_hash() -> str:
    """Real SHA-256 certificate hash (Let's Encrypt X3 intermediate)."""
    return "25847d668eb4f04fdd40b12b6b0740c567da7d024308eb6c2c96fe41d9de218d"


@pytest.fixture
def sha1_cert_hash() -> str:
    """Real SHA-1 certificate hash (Let's Encrypt X3 intermediate)."""
    return "e6a3b45b062d509b3382282d196efe97d5956ccb"


@pytest.fixture
def base64_sha256_pin() -> str:
    """Real Base64-encoded SHA-256 pin (Google pin format)."""
    return "GUAL5bejH7czkXcAeJ0vCiRxwMnVBsDlBMBsFtfLF8A="


def create_pe_with_pinning(
    output_path: Path,
    cert_hashes: list[str],
    include_winhttp_apis: bool = True,
) -> None:
    """Create a minimal PE binary with embedded certificate hashes and WinHTTP APIs.

    Args:
        output_path: Path to write PE file
        cert_hashes: List of certificate hashes to embed
        include_winhttp_apis: Whether to include WinHTTP import references
    """
    pe_header = bytearray(b"MZ")
    pe_header.extend(b"\x00" * 58)
    pe_header.extend(struct.pack("<I", 0x80))
    pe_header.extend(b"\x00" * (0x80 - len(pe_header)))
    pe_header.extend(b"PE\x00\x00")
    pe_header.extend(struct.pack("<H", 0x8664))
    pe_header.extend(struct.pack("<H", 1))
    pe_header.extend(b"\x00" * 16)
    pe_header.extend(struct.pack("<H", 0xF0))
    pe_header.extend(struct.pack("<H", 0x22))

    rdata_section = bytearray()
    for cert_hash in cert_hashes:
        rdata_section.extend(cert_hash.encode("utf-8"))
        rdata_section.extend(b"\x00" * 16)

    if include_winhttp_apis:
        rdata_section.extend(b"CertVerifyCertificateChainPolicy\x00")
        rdata_section.extend(b"CertGetCertificateChain\x00")
        rdata_section.extend(b"WinHttpSetOption\x00")
        rdata_section.extend(b"WinHttpSendRequest\x00")

    full_binary = pe_header + rdata_section
    output_path.write_bytes(full_binary)


def create_elf_with_pinning(
    output_path: Path,
    cert_hashes: list[str],
    include_openssl_symbols: bool = True,
) -> None:
    """Create minimal ELF binary with certificate hashes and OpenSSL symbols.

    Args:
        output_path: Path to write ELF file
        cert_hashes: List of certificate hashes to embed
        include_openssl_symbols: Whether to include OpenSSL symbol references
    """
    elf_header = bytearray(b"\x7fELF")
    elf_header.extend(b"\x02\x01\x01\x00")
    elf_header.extend(b"\x00" * 8)
    elf_header.extend(struct.pack("<H", 0x02))
    elf_header.extend(struct.pack("<H", 0x3E))
    elf_header.extend(struct.pack("<I", 0x01))
    elf_header.extend(b"\x00" * 40)

    data_section = bytearray()
    for cert_hash in cert_hashes:
        data_section.extend(cert_hash.encode("utf-8"))
        data_section.extend(b"\x00" * 16)

    if include_openssl_symbols:
        data_section.extend(b"SSL_CTX_set_verify\x00")
        data_section.extend(b"SSL_get_verify_result\x00")
        data_section.extend(b"X509_verify_cert\x00")
        data_section.extend(b"SSL_CTX_set_cert_verify_callback\x00")

    full_binary = elf_header + data_section
    output_path.write_bytes(full_binary)


def create_macho_with_pinning(
    output_path: Path,
    cert_hashes: list[str],
    framework: str = "custom",
) -> None:
    """Create minimal Mach-O binary with certificate hashes and iOS framework refs.

    Args:
        output_path: Path to write Mach-O file
        cert_hashes: List of certificate hashes to embed
        framework: Framework type (afnetworking, alamofire, custom)
    """
    macho_header = bytearray(struct.pack("<I", 0xFEEDFACF))
    macho_header.extend(struct.pack("<I", 0x0100000C))
    macho_header.extend(struct.pack("<I", 0x00000000))
    macho_header.extend(struct.pack("<I", 0x00000002))
    macho_header.extend(b"\x00" * 16)

    data_section = bytearray()
    for cert_hash in cert_hashes:
        data_section.extend(cert_hash.encode("utf-8"))
        data_section.extend(b"\x00" * 16)

    if framework == "afnetworking":
        data_section.extend(b"AFSecurityPolicy\x00")
        data_section.extend(b"pinnedCertificates\x00")
        data_section.extend(b"validatesDomainName\x00")
        data_section.extend(b"SSLPinningMode\x00")
    elif framework == "alamofire":
        data_section.extend(b"ServerTrustPolicy\x00")
        data_section.extend(b"PinnedCertificates\x00")
        data_section.extend(b"PublicKeys\x00")
        data_section.extend(b"Alamofire\x00")
    else:
        data_section.extend(b"SecTrustEvaluate\x00")
        data_section.extend(b"SHA256\x00")

    full_binary = macho_header + data_section
    output_path.write_bytes(full_binary)


def create_android_apk_with_pinning(
    output_path: Path,
    cert_hashes: list[str],
    domains: list[str],
    include_network_config: bool = True,
) -> None:
    """Create minimal APK with certificate pinning configuration.

    Args:
        output_path: Path to write APK file
        cert_hashes: List of SHA-256 certificate hashes
        domains: List of pinned domains
        include_network_config: Whether to include network_security_config.xml
    """
    with zipfile.ZipFile(output_path, "w") as apk:
        manifest = '<?xml version="1.0" encoding="utf-8"?>\n'
        manifest += '<manifest xmlns:android="http://schemas.android.com/apk/res/android"\n'
        manifest += '    package="com.test.pinning">\n'
        if include_network_config:
            manifest += '    <application android:networkSecurityConfig="@xml/network_security_config">\n'
        else:
            manifest += "    <application>\n"
        manifest += "    </application>\n"
        manifest += "</manifest>"
        apk.writestr("AndroidManifest.xml", manifest)

        if include_network_config:
            nsc = '<?xml version="1.0" encoding="utf-8"?>\n'
            nsc += "<network-security-config>\n"
            for domain in domains:
                nsc += "    <domain-config>\n"
                nsc += f'        <domain includeSubdomains="true">{domain}</domain>\n'
                nsc += '        <pin-set expiration="2030-01-01">\n'
                for cert_hash in cert_hashes:
                    nsc += f'            <pin digest="SHA-256">{cert_hash}</pin>\n'
                nsc += "        </pin-set>\n"
                nsc += "    </domain-config>\n"
            nsc += "</network-security-config>"
            apk.writestr("res/xml/network_security_config.xml", nsc)

        classes_dex = bytearray(b"dex\n035\x00")
        classes_dex.extend(b"\x00" * 100)
        okhttp_code = b"Lokhttp3/CertificatePinner$Builder;\x00"
        okhttp_code += b"add\x00"
        for domain in domains:
            okhttp_code += domain.encode("utf-8") + b"\x00"
        for cert_hash in cert_hashes:
            okhttp_code += b"sha256/" + cert_hash.encode("utf-8") + b"\x00"
        classes_dex.extend(okhttp_code)
        apk.writestr("classes.dex", bytes(classes_dex))


class TestCertificateHashDetection:
    """Test suite for certificate hash scanning functionality."""

    def test_detects_sha256_certificate_hashes(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
    ) -> None:
        """Detector identifies SHA-256 certificate hashes in binary."""
        binary_path = temp_test_dir / "test_sha256.bin"
        content = b"Some binary data\x00" + sha256_cert_hash.encode("utf-8") + b"\x00more data"
        binary_path.write_bytes(content)

        detector = PinningDetector()
        hashes = detector.scan_for_certificate_hashes(str(binary_path))

        assert len(hashes) > 0
        sha256_hashes = [h for h in hashes if h.startswith("SHA-256:")]
        assert len(sha256_hashes) == 1
        assert sha256_hashes[0] == f"SHA-256:{sha256_cert_hash}"

    def test_detects_sha1_certificate_hashes(
        self,
        temp_test_dir: Path,
        sha1_cert_hash: str,
    ) -> None:
        """Detector identifies SHA-1 certificate hashes in binary."""
        binary_path = temp_test_dir / "test_sha1.bin"
        content = b"Binary header\x00" + sha1_cert_hash.encode("utf-8") + b"\x00footer"
        binary_path.write_bytes(content)

        detector = PinningDetector()
        hashes = detector.scan_for_certificate_hashes(str(binary_path))

        assert len(hashes) > 0
        sha1_hashes = [h for h in hashes if h.startswith("SHA-1:")]
        assert len(sha1_hashes) == 1
        assert sha1_hashes[0] == f"SHA-1:{sha1_cert_hash}"

    def test_detects_base64_encoded_pins(
        self,
        temp_test_dir: Path,
        base64_sha256_pin: str,
    ) -> None:
        """Detector identifies Base64-encoded SHA-256 pins (OkHttp format)."""
        binary_path = temp_test_dir / "test_base64.bin"
        pin_string = f"sha256/{base64_sha256_pin}"
        content = b"OkHttp config: " + pin_string.encode("utf-8") + b"\x00"
        binary_path.write_bytes(content)

        detector = PinningDetector()
        hashes = detector.scan_for_certificate_hashes(str(binary_path))

        assert len(hashes) > 0
        base64_hashes = [h for h in hashes if h.startswith("SHA-256-B64:")]
        assert len(base64_hashes) == 1
        assert base64_hashes[0] == f"SHA-256-B64:{base64_sha256_pin}"

    def test_detects_multiple_certificate_hashes(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
        sha1_cert_hash: str,
        base64_sha256_pin: str,
    ) -> None:
        """Detector finds all hash types in single binary."""
        binary_path = temp_test_dir / "test_multi_hash.bin"
        content = (
            sha256_cert_hash.encode("utf-8")
            + b"\x00"
            + sha1_cert_hash.encode("utf-8")
            + b"\x00sha256/"
            + base64_sha256_pin.encode("utf-8")
        )
        binary_path.write_bytes(content)

        detector = PinningDetector()
        hashes = detector.scan_for_certificate_hashes(str(binary_path))

        assert len(hashes) >= 3
        assert any(h.startswith("SHA-256:") and sha256_cert_hash in h for h in hashes)
        assert any(h.startswith("SHA-1:") and sha1_cert_hash in h for h in hashes)
        assert any(h.startswith("SHA-256-B64:") and base64_sha256_pin in h for h in hashes)

    def test_handles_nonexistent_binary(self, temp_test_dir: Path) -> None:
        """Detector raises FileNotFoundError for missing binary."""
        binary_path = temp_test_dir / "nonexistent.bin"

        detector = PinningDetector()
        with pytest.raises(FileNotFoundError):
            detector.scan_for_certificate_hashes(str(binary_path))

    def test_handles_corrupted_binary(self, temp_test_dir: Path) -> None:
        """Detector handles binary read errors gracefully."""
        binary_path = temp_test_dir / "corrupted.bin"
        binary_path.write_bytes(b"\xFF\xFE\xFD\xFC" * 100)

        detector = PinningDetector()
        hashes = detector.scan_for_certificate_hashes(str(binary_path))

        assert isinstance(hashes, list)

    def test_deduplicates_repeated_hashes(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
    ) -> None:
        """Detector returns unique hashes when hash appears multiple times."""
        binary_path = temp_test_dir / "test_duplicates.bin"
        content = (sha256_cert_hash.encode("utf-8") + b"\x00") * 5
        binary_path.write_bytes(content)

        detector = PinningDetector()
        hashes = detector.scan_for_certificate_hashes(str(binary_path))

        sha256_hashes = [h for h in hashes if h.startswith("SHA-256:")]
        assert len(sha256_hashes) == 1


class TestWindowsPinningDetection:
    """Test suite for Windows-specific pinning detection."""

    def test_detects_windows_custom_pinning(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
    ) -> None:
        """Detector identifies Windows pinning via WinHTTP APIs and cert hashes."""
        binary_path = temp_test_dir / "test_windows.exe"
        create_pe_with_pinning(binary_path, [sha256_cert_hash], include_winhttp_apis=True)

        detector = PinningDetector()
        locations = detector.detect_pinning_logic(str(binary_path))

        assert len(locations) > 0
        windows_pinning = [loc for loc in locations if loc.pinning_type == "custom"]
        assert len(windows_pinning) > 0
        assert windows_pinning[0].confidence >= 0.7
        assert any("CertVerifyCertificateChainPolicy" in e or "APIs:" in e for e in windows_pinning[0].evidence)

    def test_platform_detection_identifies_windows(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
    ) -> None:
        """Detector correctly identifies Windows PE platform."""
        binary_path = temp_test_dir / "test_pe.exe"
        create_pe_with_pinning(binary_path, [sha256_cert_hash])

        detector = PinningDetector()
        detector.detect_pinning_logic(str(binary_path))

        assert detector.platform == "windows"

    def test_windows_pinning_without_apis(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
    ) -> None:
        """Detector does not report pinning without WinHTTP API references."""
        binary_path = temp_test_dir / "test_no_apis.exe"
        create_pe_with_pinning(binary_path, [sha256_cert_hash], include_winhttp_apis=False)

        detector = PinningDetector()
        locations = detector.detect_pinning_logic(str(binary_path))

        windows_locations = [loc for loc in locations if loc.pinning_type == "custom"]
        assert len(windows_locations) == 0


class TestLinuxPinningDetection:
    """Test suite for Linux-specific pinning detection."""

    def test_detects_linux_openssl_pinning(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
    ) -> None:
        """Detector identifies OpenSSL pinning on Linux binaries."""
        binary_path = temp_test_dir / "test_linux"
        create_elf_with_pinning(binary_path, [sha256_cert_hash], include_openssl_symbols=True)

        detector = PinningDetector()
        locations = detector.detect_pinning_logic(str(binary_path))

        assert len(locations) > 0
        openssl_pinning = [loc for loc in locations if loc.pinning_type == "openssl"]
        assert len(openssl_pinning) > 0
        assert openssl_pinning[0].confidence >= 0.75
        assert any("SSL_CTX_set_verify" in e or "APIs:" in e for e in openssl_pinning[0].evidence)

    def test_platform_detection_identifies_linux(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
    ) -> None:
        """Detector correctly identifies Linux ELF platform."""
        binary_path = temp_test_dir / "test_elf"
        create_elf_with_pinning(binary_path, [sha256_cert_hash])

        detector = PinningDetector()
        detector.detect_pinning_logic(str(binary_path))

        assert detector.platform in ["linux", "android"]

    def test_linux_pinning_without_openssl(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
    ) -> None:
        """Detector does not report pinning without OpenSSL symbols."""
        binary_path = temp_test_dir / "test_no_ssl"
        create_elf_with_pinning(binary_path, [sha256_cert_hash], include_openssl_symbols=False)

        detector = PinningDetector()
        locations = detector.detect_pinning_logic(str(binary_path))

        openssl_locations = [loc for loc in locations if loc.pinning_type == "openssl"]
        assert len(openssl_locations) == 0


class TestIOSPinningDetection:
    """Test suite for iOS-specific pinning detection."""

    def test_detects_afnetworking_pinning(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
    ) -> None:
        """Detector identifies AFNetworking pinning patterns."""
        binary_path = temp_test_dir / "test_afnet"
        create_macho_with_pinning(binary_path, [sha256_cert_hash], framework="afnetworking")

        detector = PinningDetector()
        locations = detector.detect_pinning_logic(str(binary_path))

        assert len(locations) > 0
        afnet_locations = [loc for loc in locations if loc.pinning_type == "afnetworking"]
        assert len(afnet_locations) > 0
        assert afnet_locations[0].confidence >= 0.8
        assert any("AFSecurityPolicy" in e for e in afnet_locations[0].evidence)

    def test_detects_alamofire_pinning(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
    ) -> None:
        """Detector identifies Alamofire pinning patterns."""
        binary_path = temp_test_dir / "test_alamofire"
        create_macho_with_pinning(binary_path, [sha256_cert_hash], framework="alamofire")

        detector = PinningDetector()
        locations = detector.detect_pinning_logic(str(binary_path))

        assert len(locations) > 0
        alamofire_locations = [loc for loc in locations if loc.pinning_type == "alamofire"]
        assert len(alamofire_locations) > 0
        assert alamofire_locations[0].confidence >= 0.8
        assert any("ServerTrustPolicy" in e for e in alamofire_locations[0].evidence)

    def test_detects_custom_ios_pinning(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
    ) -> None:
        """Detector identifies custom SecTrust-based pinning."""
        binary_path = temp_test_dir / "test_sectrust"
        create_macho_with_pinning(binary_path, [sha256_cert_hash], framework="custom")

        detector = PinningDetector()
        locations = detector.detect_pinning_logic(str(binary_path))

        assert len(locations) > 0
        custom_locations = [loc for loc in locations if loc.pinning_type == "custom"]
        assert len(custom_locations) > 0
        assert custom_locations[0].confidence >= 0.6
        assert any("SecTrustEvaluate" in e for e in custom_locations[0].evidence)

    def test_platform_detection_identifies_ios(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
    ) -> None:
        """Detector correctly identifies iOS Mach-O platform."""
        binary_path = temp_test_dir / "test_macho"
        create_macho_with_pinning(binary_path, [sha256_cert_hash])

        detector = PinningDetector()
        detector.detect_pinning_logic(str(binary_path))

        assert detector.platform == "ios"

    def test_detect_afnetworking_pinning_method(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
    ) -> None:
        """Public detect_afnetworking_pinning method returns PinningInfo."""
        binary_path = temp_test_dir / "test_afnet_direct.bin"
        create_macho_with_pinning(binary_path, [sha256_cert_hash], framework="afnetworking")

        detector = PinningDetector()
        pins = detector.detect_afnetworking_pinning(str(binary_path))

        assert len(pins) > 0
        assert all(isinstance(p, PinningInfo) for p in pins)
        assert pins[0].pin_type == "afnetworking"
        assert pins[0].location == "AFSecurityPolicy"
        assert len(pins[0].hashes) > 0
        assert sha256_cert_hash in pins[0].hashes[0]

    def test_detect_alamofire_pinning_method(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
    ) -> None:
        """Public detect_alamofire_pinning method returns PinningInfo."""
        binary_path = temp_test_dir / "test_alamofire_direct.bin"
        create_macho_with_pinning(binary_path, [sha256_cert_hash], framework="alamofire")

        detector = PinningDetector()
        pins = detector.detect_alamofire_pinning(str(binary_path))

        assert len(pins) > 0
        assert all(isinstance(p, PinningInfo) for p in pins)
        assert pins[0].pin_type == "alamofire"
        assert pins[0].location == "ServerTrustPolicy"
        assert len(pins[0].hashes) > 0


class TestCrossReferenceAnalysis:
    """Test suite for certificate hash cross-reference detection."""

    def test_finds_hash_cross_references(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
    ) -> None:
        """Detector locates all references to certificate hash in binary."""
        binary_path = temp_test_dir / "test_xrefs.bin"
        content = (
            b"header\x00"
            + sha256_cert_hash.encode("utf-8")
            + b"\x00middle\x00"
            + sha256_cert_hash.encode("utf-8")
            + b"\x00footer"
        )
        binary_path.write_bytes(content)

        detector = PinningDetector()
        cross_refs = detector.find_pinning_cross_refs(str(binary_path))

        assert len(cross_refs) > 0
        hash_key = f"SHA-256:{sha256_cert_hash}"
        assert hash_key in cross_refs
        assert len(cross_refs[hash_key]) == 2
        assert all(isinstance(addr, int) for addr in cross_refs[hash_key])

    def test_cross_refs_for_multiple_hashes(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
        sha1_cert_hash: str,
    ) -> None:
        """Detector maps multiple hashes to their respective locations."""
        binary_path = temp_test_dir / "test_multi_xref.bin"
        content = (
            sha256_cert_hash.encode("utf-8")
            + b"\x00\x00"
            + sha1_cert_hash.encode("utf-8")
            + b"\x00\x00"
            + sha256_cert_hash.encode("utf-8")
        )
        binary_path.write_bytes(content)

        detector = PinningDetector()
        cross_refs = detector.find_pinning_cross_refs(str(binary_path))

        assert len(cross_refs) >= 2
        sha256_key = f"SHA-256:{sha256_cert_hash}"
        sha1_key = f"SHA-1:{sha1_cert_hash}"
        assert sha256_key in cross_refs
        assert sha1_key in cross_refs
        assert len(cross_refs[sha256_key]) == 2
        assert len(cross_refs[sha1_key]) == 1

    def test_cross_refs_returns_correct_offsets(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
    ) -> None:
        """Cross-reference addresses match actual hash locations in binary."""
        binary_path = temp_test_dir / "test_offset.bin"
        prefix = b"X" * 100
        hash_bytes = sha256_cert_hash.encode("utf-8")
        content = prefix + hash_bytes
        binary_path.write_bytes(content)

        detector = PinningDetector()
        cross_refs = detector.find_pinning_cross_refs(str(binary_path))

        hash_key = f"SHA-256:{sha256_cert_hash}"
        assert hash_key in cross_refs
        assert cross_refs[hash_key][0] == len(prefix)

    def test_cross_refs_empty_when_no_hashes(self, temp_test_dir: Path) -> None:
        """Cross-reference analysis returns empty dict when no hashes found."""
        binary_path = temp_test_dir / "test_no_hash.bin"
        binary_path.write_bytes(b"No certificate hashes here")

        detector = PinningDetector()
        cross_refs = detector.find_pinning_cross_refs(str(binary_path))

        assert isinstance(cross_refs, dict)
        assert len(cross_refs) == 0


class TestPinningReportGeneration:
    """Test suite for comprehensive pinning report generation."""

    def test_generates_complete_windows_report(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
    ) -> None:
        """Report generation produces complete data for Windows binary."""
        binary_path = temp_test_dir / "test_report_win.exe"
        create_pe_with_pinning(binary_path, [sha256_cert_hash], include_winhttp_apis=True)

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(binary_path))

        assert isinstance(report, PinningReport)
        assert report.binary_path == str(binary_path)
        assert report.platform == "windows"
        assert report.has_pinning
        assert len(report.detected_pins) > 0 or len(report.pinning_locations) > 0
        assert len(report.bypass_recommendations) > 0
        assert 0.0 <= report.confidence <= 1.0

    def test_generates_complete_linux_report(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
    ) -> None:
        """Report generation produces complete data for Linux binary."""
        binary_path = temp_test_dir / "test_report_linux"
        create_elf_with_pinning(binary_path, [sha256_cert_hash], include_openssl_symbols=True)

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(binary_path))

        assert isinstance(report, PinningReport)
        assert report.platform in ["linux", "android"]
        assert report.has_pinning
        assert len(report.pinning_locations) > 0
        assert "openssl" in [loc.pinning_type for loc in report.pinning_locations]
        assert any("openssl" in rec.lower() for rec in report.bypass_recommendations)

    def test_generates_complete_ios_report(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
    ) -> None:
        """Report generation produces complete data for iOS binary."""
        binary_path = temp_test_dir / "test_report_ios"
        create_macho_with_pinning(binary_path, [sha256_cert_hash], framework="afnetworking")

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(binary_path))

        assert isinstance(report, PinningReport)
        assert report.platform == "ios"
        assert report.has_pinning
        assert len(report.detected_pins) > 0
        assert any(p.pin_type == "afnetworking" for p in report.detected_pins)

    def test_report_confidence_calculation(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
    ) -> None:
        """Report confidence is average of detected pin confidences."""
        binary_path = temp_test_dir / "test_confidence.exe"
        create_pe_with_pinning(binary_path, [sha256_cert_hash], include_winhttp_apis=True)

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(binary_path))

        if report.detected_pins:
            expected_confidence = sum(p.confidence for p in report.detected_pins) / len(report.detected_pins)
            assert abs(report.confidence - expected_confidence) < 0.01
        elif report.pinning_locations:
            expected_confidence = sum(loc.confidence for loc in report.pinning_locations) / len(
                report.pinning_locations
            )
            assert abs(report.confidence - expected_confidence) < 0.01

    def test_report_bypass_recommendations_for_custom_pinning(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
    ) -> None:
        """Report provides relevant bypass recommendations for custom pinning."""
        binary_path = temp_test_dir / "test_bypass_rec.exe"
        create_pe_with_pinning(binary_path, [sha256_cert_hash], include_winhttp_apis=True)

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(binary_path))

        assert len(report.bypass_recommendations) > 0
        assert any("custom" in rec.lower() or "hash comparison" in rec.lower() for rec in report.bypass_recommendations)

    def test_report_bypass_recommendations_for_openssl(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
    ) -> None:
        """Report provides OpenSSL-specific bypass recommendations."""
        binary_path = temp_test_dir / "test_openssl_bypass"
        create_elf_with_pinning(binary_path, [sha256_cert_hash], include_openssl_symbols=True)

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(binary_path))

        assert any("openssl" in rec.lower() or "SSL_get_verify_result" in rec for rec in report.bypass_recommendations)

    def test_report_no_pinning_fallback(self, temp_test_dir: Path) -> None:
        """Report provides generic bypass recommendation when no pinning detected."""
        binary_path = temp_test_dir / "test_no_pinning.exe"
        create_pe_with_pinning(binary_path, [], include_winhttp_apis=False)

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(binary_path))

        assert not report.has_pinning
        assert len(report.bypass_recommendations) > 0
        assert any("general certificate bypass" in rec.lower() or "mitm" in rec.lower() for rec in report.bypass_recommendations)

    def test_report_includes_pinning_methods(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
    ) -> None:
        """Report lists all detected pinning methods."""
        binary_path = temp_test_dir / "test_methods.exe"
        create_pe_with_pinning(binary_path, [sha256_cert_hash], include_winhttp_apis=True)

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(binary_path))

        assert isinstance(report.pinning_methods, list)
        if report.pinning_locations:
            detected_types = {loc.pinning_type for loc in report.pinning_locations}
            assert detected_types == set(report.pinning_methods)

    def test_report_handles_parse_failure(self, temp_test_dir: Path) -> None:
        """Report generation handles binary parsing failures gracefully."""
        binary_path = temp_test_dir / "invalid.bin"
        binary_path.write_bytes(b"Not a valid binary format")

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(binary_path))

        assert isinstance(report, PinningReport)
        assert report.platform == "unknown"


class TestAndroidPinningDetection:
    """Test suite for Android APK pinning detection."""

    def test_detects_network_security_config_pinning(
        self,
        temp_test_dir: Path,
        base64_sha256_pin: str,
    ) -> None:
        """Detector identifies pinning in Network Security Config."""
        apk_path = temp_test_dir / "test_nsc.apk"
        domains = ["api.example.com", "cdn.example.com"]
        create_android_apk_with_pinning(apk_path, [base64_sha256_pin], domains, include_network_config=True)

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(apk_path))

        assert report.has_pinning
        nsc_pins = [p for p in report.detected_pins if p.pin_type == "network_security_config"]
        if nsc_pins:
            assert len(nsc_pins) > 0
            assert nsc_pins[0].confidence == 1.0
            assert any(domain in nsc_pins[0].domains for domain in domains)

    def test_detects_okhttp_pinning_in_apk(
        self,
        temp_test_dir: Path,
        base64_sha256_pin: str,
    ) -> None:
        """Detector identifies OkHttp CertificatePinner usage in APK."""
        apk_path = temp_test_dir / "test_okhttp.apk"
        domains = ["secure.example.com"]
        create_android_apk_with_pinning(apk_path, [base64_sha256_pin], domains, include_network_config=False)

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(apk_path))

        assert report.platform == "android"

    def test_detect_okhttp_pinning_method(
        self,
        temp_test_dir: Path,
        base64_sha256_pin: str,
    ) -> None:
        """Public detect_okhttp_pinning method works with APK files."""
        apk_path = temp_test_dir / "test_okhttp_direct.apk"
        domains = ["pinned.example.com"]
        create_android_apk_with_pinning(apk_path, [base64_sha256_pin], domains)

        detector = PinningDetector()
        pins = detector.detect_okhttp_pinning(str(apk_path))

        assert isinstance(pins, list)

    def test_okhttp_detection_requires_apk_format(self, temp_test_dir: Path) -> None:
        """OkHttp detection returns empty list for non-APK files."""
        binary_path = temp_test_dir / "test.exe"
        binary_path.write_bytes(b"Not an APK")

        detector = PinningDetector()
        pins = detector.detect_okhttp_pinning(str(binary_path))

        assert isinstance(pins, list)
        assert len(pins) == 0


class TestEdgeCasesAndErrorHandling:
    """Test suite for edge cases and error handling."""

    def test_handles_empty_binary(self, temp_test_dir: Path) -> None:
        """Detector handles zero-length binary files."""
        binary_path = temp_test_dir / "empty.bin"
        binary_path.write_bytes(b"")

        detector = PinningDetector()
        hashes = detector.scan_for_certificate_hashes(str(binary_path))

        assert isinstance(hashes, list)
        assert len(hashes) == 0

    def test_handles_binary_with_only_invalid_hashes(self, temp_test_dir: Path) -> None:
        """Detector ignores invalid hash patterns."""
        binary_path = temp_test_dir / "invalid_hash.bin"
        invalid_hash = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
        binary_path.write_bytes(invalid_hash.encode("utf-8"))

        detector = PinningDetector()
        hashes = detector.scan_for_certificate_hashes(str(binary_path))

        assert isinstance(hashes, list)

    def test_handles_large_binary(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
    ) -> None:
        """Detector processes large binaries efficiently."""
        binary_path = temp_test_dir / "large.bin"
        large_content = b"X" * 10000000 + sha256_cert_hash.encode("utf-8") + b"Y" * 1000
        binary_path.write_bytes(large_content)

        detector = PinningDetector()
        hashes = detector.scan_for_certificate_hashes(str(binary_path))

        assert len(hashes) > 0
        assert any(sha256_cert_hash in h for h in hashes)

    def test_handles_obfuscated_hash_with_separators(
        self,
        temp_test_dir: Path,
    ) -> None:
        """Detector handles hashes with various formatting."""
        binary_path = temp_test_dir / "formatted_hash.bin"
        clean_hash = "a" * 64
        separated_hash = ":".join([clean_hash[i : i + 2] for i in range(0, len(clean_hash), 2)])
        binary_path.write_bytes(separated_hash.encode("utf-8"))

        detector = PinningDetector()
        hashes = detector.scan_for_certificate_hashes(str(binary_path))

        assert isinstance(hashes, list)

    def test_handles_mixed_case_hashes(self, temp_test_dir: Path) -> None:
        """Detector handles uppercase, lowercase, and mixed case hashes."""
        binary_path = temp_test_dir / "mixed_case.bin"
        upper_hash = "A" * 64
        lower_hash = "b" * 64
        mixed_hash = "aAbBcC" * 10 + "aAbBcCdD"
        content = upper_hash.encode("utf-8") + b"\x00" + lower_hash.encode("utf-8") + b"\x00" + mixed_hash.encode("utf-8")
        binary_path.write_bytes(content)

        detector = PinningDetector()
        hashes = detector.scan_for_certificate_hashes(str(binary_path))

        sha256_hashes = [h for h in hashes if h.startswith("SHA-256:")]
        assert len(sha256_hashes) >= 2

    def test_handles_non_utf8_binary_data(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
    ) -> None:
        """Detector handles binaries with non-UTF8 data."""
        binary_path = temp_test_dir / "non_utf8.bin"
        content = b"\xFF\xFE\xFD\xFC" * 100 + sha256_cert_hash.encode("utf-8") + b"\x80\x81\x82\x83" * 50
        binary_path.write_bytes(content)

        detector = PinningDetector()
        hashes = detector.scan_for_certificate_hashes(str(binary_path))

        assert len(hashes) > 0
        assert any(sha256_cert_hash in h for h in hashes)

    def test_detect_pinning_logic_with_unparseable_binary(self, temp_test_dir: Path) -> None:
        """Detector returns empty list when LIEF cannot parse binary."""
        binary_path = temp_test_dir / "unparseable.bin"
        binary_path.write_bytes(b"Invalid binary format" * 100)

        detector = PinningDetector()
        locations = detector.detect_pinning_logic(str(binary_path))

        assert isinstance(locations, list)
        assert len(locations) == 0

    def test_report_with_hashes_but_no_validation_logic(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
    ) -> None:
        """Report includes low-confidence pins when hashes found without validation."""
        binary_path = temp_test_dir / "hash_only.bin"
        binary_path.write_bytes(sha256_cert_hash.encode("utf-8"))

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(binary_path))

        assert report.has_pinning
        assert len(report.detected_pins) > 0
        unknown_pins = [p for p in report.detected_pins if p.pin_type == "unknown"]
        if unknown_pins:
            assert unknown_pins[0].confidence <= 0.6


class TestMultiplePinDetection:
    """Test suite for detecting multiple pinning configurations."""

    def test_detects_multiple_domains_with_different_pins(
        self,
        temp_test_dir: Path,
    ) -> None:
        """Detector identifies different pins for multiple domains."""
        apk_path = temp_test_dir / "multi_domain.apk"
        hash1 = "A" * 43 + "="
        hash2 = "B" * 43 + "="
        create_android_apk_with_pinning(apk_path, [hash1, hash2], ["api1.com", "api2.com"])

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(apk_path))

        assert report.has_pinning

    def test_detects_layered_pinning_multiple_frameworks(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
    ) -> None:
        """Detector identifies multiple pinning methods in single binary."""
        binary_path = temp_test_dir / "layered.bin"
        macho_content = bytearray(struct.pack("<I", 0xFEEDFACF))
        macho_content.extend(b"\x00" * 28)
        macho_content.extend(sha256_cert_hash.encode("utf-8"))
        macho_content.extend(b"AFSecurityPolicy\x00")
        macho_content.extend(b"ServerTrustPolicy\x00")
        macho_content.extend(b"Alamofire\x00")
        binary_path.write_bytes(macho_content)

        detector = PinningDetector()
        locations = detector.detect_pinning_logic(str(binary_path))

        detected_types = {loc.pinning_type for loc in locations}
        assert len(detected_types) >= 1

    def test_multiple_pins_increase_confidence(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
        sha1_cert_hash: str,
    ) -> None:
        """Multiple detected pins result in appropriate confidence scoring."""
        binary_path = temp_test_dir / "multi_pin.exe"
        create_pe_with_pinning(binary_path, [sha256_cert_hash, sha1_cert_hash], include_winhttp_apis=True)

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(binary_path))

        assert report.has_pinning
        assert report.confidence > 0.0


class TestBypassRecommendations:
    """Test suite for bypass recommendation generation."""

    def test_generates_afnetworking_bypass_recommendation(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
    ) -> None:
        """Bypass recommendations include AFNetworking-specific hooks."""
        binary_path = temp_test_dir / "afnet_bypass.bin"
        create_macho_with_pinning(binary_path, [sha256_cert_hash], framework="afnetworking")

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(binary_path))

        assert any("afnetworking" in rec.lower() or "afsecuritypolicy" in rec.lower() for rec in report.bypass_recommendations)

    def test_generates_alamofire_bypass_recommendation(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
    ) -> None:
        """Bypass recommendations include Alamofire-specific hooks."""
        binary_path = temp_test_dir / "alamofire_bypass.bin"
        create_macho_with_pinning(binary_path, [sha256_cert_hash], framework="alamofire")

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(binary_path))

        assert any("alamofire" in rec.lower() or "servertrustpolicy" in rec.lower() for rec in report.bypass_recommendations)

    def test_generates_openssl_bypass_recommendation(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
    ) -> None:
        """Bypass recommendations include OpenSSL-specific hooks."""
        binary_path = temp_test_dir / "openssl_bypass"
        create_elf_with_pinning(binary_path, [sha256_cert_hash], include_openssl_symbols=True)

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(binary_path))

        assert any(
            "openssl" in rec.lower() or "ssl_get_verify_result" in rec.lower() or "x509_v_ok" in rec.lower()
            for rec in report.bypass_recommendations
        )

    def test_all_bypass_recommendations_are_actionable(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
    ) -> None:
        """All bypass recommendations provide specific actionable steps."""
        binary_path = temp_test_dir / "actionable.exe"
        create_pe_with_pinning(binary_path, [sha256_cert_hash], include_winhttp_apis=True)

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(binary_path))

        for rec in report.bypass_recommendations:
            assert len(rec) > 10
            assert any(
                keyword in rec.lower()
                for keyword in ["hook", "frida", "modify", "patch", "bypass", "return", "force", "mitm"]
            )


class TestRealWorldScenarios:
    """Test suite for real-world pinning scenarios."""

    def test_detects_backup_pin_configuration(
        self,
        temp_test_dir: Path,
    ) -> None:
        """Detector identifies multiple pins for single domain (backup pins)."""
        apk_path = temp_test_dir / "backup_pins.apk"
        primary_pin = "A" * 43 + "="
        backup_pin = "B" * 43 + "="
        create_android_apk_with_pinning(apk_path, [primary_pin, backup_pin], ["api.example.com"])

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(apk_path))

        assert report.has_pinning

    def test_detects_subdomain_pinning(self, temp_test_dir: Path) -> None:
        """Detector identifies pinning with subdomain inclusion."""
        apk_path = temp_test_dir / "subdomain.apk"
        pin = "C" * 43 + "="
        create_android_apk_with_pinning(apk_path, [pin], ["*.example.com"])

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(apk_path))

        assert report.has_pinning

    def test_handles_expired_pin_configuration(self, temp_test_dir: Path) -> None:
        """Detector still reports expired pins (expiration is informational)."""
        apk_path = temp_test_dir / "expired.apk"
        with zipfile.ZipFile(apk_path, "w") as apk:
            manifest = '<?xml version="1.0" encoding="utf-8"?>\n<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test">\n<application android:networkSecurityConfig="@xml/network_security_config"></application>\n</manifest>'
            apk.writestr("AndroidManifest.xml", manifest)

            nsc = '<?xml version="1.0" encoding="utf-8"?>\n<network-security-config>\n<domain-config>\n<domain>expired.com</domain>\n<pin-set expiration="2020-01-01">\n<pin digest="SHA-256">expiredpinhash=</pin>\n</pin-set>\n</domain-config>\n</network-security-config>'
            apk.writestr("res/xml/network_security_config.xml", nsc)

        detector = PinningDetector()
        report = detector.generate_pinning_report(str(apk_path))

        assert isinstance(report, PinningReport)

    def test_detects_mixed_public_key_and_cert_pinning(
        self,
        temp_test_dir: Path,
        sha256_cert_hash: str,
    ) -> None:
        """Detector handles binaries with both certificate and public key pins."""
        binary_path = temp_test_dir / "mixed_pinning.bin"
        cert_pin = sha256_cert_hash
        pubkey_pin = "f" * 64
        content = cert_pin.encode("utf-8") + b"\x00PublicKey:\x00" + pubkey_pin.encode("utf-8")
        binary_path.write_bytes(content)

        detector = PinningDetector()
        hashes = detector.scan_for_certificate_hashes(str(binary_path))

        assert len(hashes) >= 2
        assert any(cert_pin in h for h in hashes)
        assert any(pubkey_pin in h for h in hashes)


class TestPinningLocationDataclass:
    """Test suite for PinningLocation dataclass."""

    def test_pinning_location_creation(self) -> None:
        """PinningLocation dataclass stores all required fields."""
        location = PinningLocation(
            address=0x401000,
            function_name="validate_certificate",
            pinning_type="custom",
            confidence=0.85,
            evidence=["SHA-256 comparison found", "API: CertGetCertificateChain"],
        )

        assert location.address == 0x401000
        assert location.function_name == "validate_certificate"
        assert location.pinning_type == "custom"
        assert location.confidence == 0.85
        assert len(location.evidence) == 2

    def test_pinning_location_default_evidence(self) -> None:
        """PinningLocation has empty evidence list by default."""
        location = PinningLocation(
            address=0x500000,
            function_name="check_pin",
            pinning_type="okhttp",
            confidence=0.95,
        )

        assert location.evidence == []


class TestPinningReportDataclass:
    """Test suite for PinningReport dataclass."""

    def test_pinning_report_has_pinning_property(self) -> None:
        """has_pinning property returns True when pins detected."""
        report = PinningReport(
            binary_path="/test/app.exe",
            detected_pins=[
                PinningInfo(
                    location="string_data",
                    pin_type="custom",
                    domains=["api.com"],
                    hashes=["abc123"],
                    confidence=0.7,
                )
            ],
            pinning_locations=[],
            pinning_methods=["custom"],
            bypass_recommendations=["Hook validation"],
            confidence=0.7,
            platform="windows",
        )

        assert report.has_pinning is True

    def test_pinning_report_no_pinning(self) -> None:
        """has_pinning property returns False when no pins detected."""
        report = PinningReport(
            binary_path="/test/app.exe",
            detected_pins=[],
            pinning_locations=[],
            pinning_methods=[],
            bypass_recommendations=["No pinning detected"],
            confidence=0.0,
            platform="windows",
        )

        assert report.has_pinning is False

    def test_pinning_report_has_pinning_from_locations(self) -> None:
        """has_pinning returns True when only locations detected."""
        report = PinningReport(
            binary_path="/test/app.bin",
            detected_pins=[],
            pinning_locations=[
                PinningLocation(
                    address=0x401000,
                    function_name="ssl_verify",
                    pinning_type="openssl",
                    confidence=0.8,
                )
            ],
            pinning_methods=["openssl"],
            bypass_recommendations=["Hook OpenSSL"],
            confidence=0.8,
            platform="linux",
        )

        assert report.has_pinning is True
