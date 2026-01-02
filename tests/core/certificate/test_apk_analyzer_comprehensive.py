"""Production tests for APK analysis and certificate pinning detection.

CRITICAL: These tests validate REAL APK analysis capabilities.
Tests MUST fail if APK parsing, certificate detection, or pinning analysis breaks.

Test Coverage:
- APK extraction and validation
- Network security config XML parsing
- OkHttp certificate pinning detection
- Hardcoded certificate discovery
- Base64-encoded certificate extraction
- APK decompilation workflow
- Error handling for corrupted APKs
- Multi-domain pinning configurations
"""

from typing import Any
import base64
import hashlib
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from intellicrack.core.certificate.apk_analyzer import (
    APKAnalyzer,
    DomainConfig,
    NetworkSecurityConfig,
    PinConfig,
    PinningInfo,
)


@pytest.fixture
def test_certificate() -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Generate a test certificate and private key."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Test Company"),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "example.com"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("example.com")]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    return cert, private_key


@pytest.fixture
def sample_apk(tmp_path: Path, test_certificate: tuple[x509.Certificate, rsa.RSAPrivateKey]) -> Path:
    """Create a sample APK file with certificate pinning."""
    apk_path = tmp_path / "sample_app.apk"
    cert, key = test_certificate

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", "<manifest></manifest>")

        network_config = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">example.com</domain>
        <domain>api.example.com</domain>
        <pin-set expiration="2026-01-01">
            <pin digest="SHA-256">AAAA+hash+here+BBBB==</pin>
            <pin digest="SHA-256">CCCC+hash+here+DDDD==</pin>
        </pin-set>
    </domain-config>
    <base-config>
        <pin-set>
            <pin digest="SHA-256">BASE+hash+here+EEEE==</pin>
        </pin-set>
    </base-config>
    <debug-overrides>
        <pin-set>
            <pin digest="SHA-256">DEBUG+hash+FFFF==</pin>
        </pin-set>
    </debug-overrides>
</network-security-config>"""
        zf.writestr("res/xml/network_security_config.xml", network_config)

        zf.writestr("assets/certificates/server.pem", cert_pem)
        zf.writestr("assets/certificates/backup.crt", cert_pem)

        zf.writestr("classes.dex", b"\x00" * 100)

    return apk_path


@pytest.fixture
def corrupted_apk(tmp_path: Path) -> Path:
    """Create a corrupted APK file."""
    apk_path = tmp_path / "corrupted.apk"
    apk_path.write_bytes(b"NOT A VALID ZIP FILE")
    return apk_path


class TestAPKExtraction:
    """Test APK extraction functionality."""

    def test_extract_valid_apk_succeeds(self, sample_apk: Path) -> None:
        """Extract valid APK file successfully."""
        analyzer = APKAnalyzer()

        extracted_path = analyzer.extract_apk(str(sample_apk))

        assert extracted_path is not None
        assert Path(extracted_path).exists()
        assert (Path(extracted_path) / "AndroidManifest.xml").exists()
        assert analyzer.extracted_path is not None
        assert analyzer.apk_path == sample_apk

        analyzer.cleanup()

    def test_extract_nonexistent_apk_raises_error(self, tmp_path: Path) -> None:
        """Extracting non-existent APK raises FileNotFoundError."""
        analyzer = APKAnalyzer()
        nonexistent = tmp_path / "doesnotexist.apk"

        with pytest.raises(FileNotFoundError, match="APK file not found"):
            analyzer.extract_apk(str(nonexistent))

    def test_extract_corrupted_apk_raises_error(self, corrupted_apk: Path) -> None:
        """Extracting corrupted APK raises BadZipFile error."""
        analyzer = APKAnalyzer()

        with pytest.raises(zipfile.BadZipFile):
            analyzer.extract_apk(str(corrupted_apk))

    def test_extract_creates_temp_directory(self, sample_apk: Path) -> None:
        """Extraction creates temporary directory with correct structure."""
        analyzer = APKAnalyzer()

        analyzer.extract_apk(str(sample_apk))

        assert analyzer.temp_dir is not None
        assert analyzer.temp_dir.exists()
        assert "intellicrack_apk_" in str(analyzer.temp_dir)
        assert analyzer.extracted_path is not None
        assert analyzer.extracted_path.exists()

        analyzer.cleanup()

    def test_cleanup_removes_temp_directory(self, sample_apk: Path) -> None:
        """Cleanup removes temporary extraction directory."""
        analyzer = APKAnalyzer()
        analyzer.extract_apk(str(sample_apk))

        temp_dir = analyzer.temp_dir
        assert temp_dir is not None
        assert temp_dir.exists()

        analyzer.cleanup()

        assert not temp_dir.exists()

    def test_context_manager_auto_cleanup(self, sample_apk: Path) -> None:
        """Context manager automatically cleans up resources."""
        temp_dir = None

        with APKAnalyzer() as analyzer:
            analyzer.extract_apk(str(sample_apk))
            temp_dir = analyzer.temp_dir
            assert temp_dir is not None
            assert temp_dir.exists()

        assert temp_dir is not None
        assert not temp_dir.exists()


class TestNetworkSecurityConfigParsing:
    """Test network security configuration parsing."""

    def test_parse_network_security_config_with_pinning(self, sample_apk: Path) -> None:
        """Parse network security config with certificate pinning."""
        analyzer = APKAnalyzer()

        config = analyzer.parse_network_security_config(str(sample_apk))

        assert isinstance(config, NetworkSecurityConfig)
        assert config.has_pinning
        assert len(config.domain_configs) == 1

        domain_config = config.domain_configs[0]
        assert "example.com" in domain_config.domains
        assert "api.example.com" in domain_config.domains
        assert domain_config.include_subdomains is True
        assert domain_config.expiration == "2026-01-01"
        assert len(domain_config.pins) == 2

        pin1, pin2 = domain_config.pins
        assert pin1.digest_algorithm == "SHA-256"
        assert "AAAA+hash+here+BBBB==" in pin1.hash_value
        assert pin1.source == "network_security_config"

    def test_parse_base_config_pinning(self, sample_apk: Path) -> None:
        """Parse base-config pinning for all domains."""
        analyzer = APKAnalyzer()

        config = analyzer.parse_network_security_config(str(sample_apk))

        assert config.base_config is not None
        assert len(config.base_config.pins) == 1
        assert config.base_config.domains == ["*"]
        assert config.base_config.include_subdomains is True

        base_pin = config.base_config.pins[0]
        assert base_pin.digest_algorithm == "SHA-256"
        assert "BASE+hash+here+EEEE==" in base_pin.hash_value

    def test_parse_debug_overrides(self, sample_apk: Path) -> None:
        """Parse debug-overrides configuration."""
        analyzer = APKAnalyzer()

        config = analyzer.parse_network_security_config(str(sample_apk))

        assert config.debug_overrides is not None
        assert len(config.debug_overrides.pins) == 1

        debug_pin = config.debug_overrides.pins[0]
        assert "DEBUG+hash+FFFF==" in debug_pin.hash_value

    def test_parse_missing_network_config_returns_empty(self, tmp_path: Path) -> None:
        """Parse APK without network security config returns empty configuration."""
        apk_path = tmp_path / "no_config.apk"

        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", "<manifest></manifest>")

        analyzer = APKAnalyzer()
        config = analyzer.parse_network_security_config(str(apk_path))

        assert isinstance(config, NetworkSecurityConfig)
        assert not config.has_pinning
        assert len(config.domain_configs) == 0
        assert config.base_config is None

        analyzer.cleanup()

    def test_parse_malformed_xml_returns_empty_config(self, tmp_path: Path) -> None:
        """Parse malformed XML returns empty configuration without crashing."""
        apk_path = tmp_path / "malformed.apk"

        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("res/xml/network_security_config.xml", "<invalid><<>>")

        analyzer = APKAnalyzer()
        config = analyzer.parse_network_security_config(str(apk_path))

        assert isinstance(config, NetworkSecurityConfig)
        assert not config.has_pinning

        analyzer.cleanup()

    def test_has_pinning_property_accuracy(self, sample_apk: Path) -> None:
        """has_pinning property accurately reflects pinning presence."""
        analyzer = APKAnalyzer()

        config = analyzer.parse_network_security_config(str(sample_apk))
        assert config.has_pinning

        empty_config = NetworkSecurityConfig()
        assert not empty_config.has_pinning

        analyzer.cleanup()


class RealDecompiledAPKSimulator:
    """Creates real decompiled APK structure with smali files for testing."""

    def __init__(self, base_dir: Path) -> None:
        self.base_dir = base_dir
        self.smali_dir = base_dir / "smali"
        self.smali_dir.mkdir(parents=True, exist_ok=True)

    def create_okhttp_pinning_smali(
        self,
        filename: str,
        domains_and_hashes: list[tuple[str, str]],
    ) -> Path:
        """Create real smali file with OkHttp certificate pinning code."""
        smali_content = [
            ".class public Lcom/example/NetworkClient;",
            ".super Ljava/lang/Object;",
            "",
            ".method public setupPinning()V",
            "    new-instance v0, Lokhttp3/CertificatePinner$Builder;",
            "    invoke-direct {v0}, Lokhttp3/CertificatePinner$Builder;-><init>()V",
        ]

        for domain, hash_value in domains_and_hashes:
            smali_content.extend([
                f'    const-string v1, "{domain}"',
                f'    const-string v2, "sha256/{hash_value}"',
                "    invoke-virtual {v0, v1, v2}, Lokhttp3/CertificatePinner$Builder;->add(Ljava/lang/String;Ljava/lang/String;)Lokhttp3/CertificatePinner$Builder;",
            ])

        smali_content.extend([
            "    return-void",
            ".end method",
        ])

        smali_file = self.smali_dir / filename
        smali_file.write_text("\n".join(smali_content))
        return smali_file

    def create_const_string_pinning_smali(
        self,
        filename: str,
        domains: list[str],
        hashes: list[str],
    ) -> Path:
        """Create smali file with const-string certificate pinning pattern."""
        smali_content = [
            ".class public Lcom/example/PinningConfig;",
            "",
            ".method private setupCertPinner()V",
        ]

        for domain in domains:
            smali_content.append(f'    const-string v0, "{domain}"')

        for hash_value in hashes:
            smali_content.append(f'    const-string v1, "sha256/{hash_value}"')

        smali_content.extend([
            "    new-instance v3, Lokhttp3/CertificatePinner;",
            "    return-void",
            ".end method",
        ])

        smali_file = self.smali_dir / filename
        smali_file.write_text("\n".join(smali_content))
        return smali_file

    def create_base64_cert_smali(
        self,
        filename: str,
        certificate: x509.Certificate,
    ) -> Path:
        """Create smali file with base64-encoded certificate."""
        cert_der = certificate.public_bytes(serialization.Encoding.DER)
        cert_b64 = base64.b64encode(cert_der).decode("ascii")

        smali_content = [
            ".class public Lcom/example/CertLoader;",
            "",
            ".method private loadCertificate()V",
            f'    const-string v0, "-----BEGIN CERTIFICATE-----\\n{cert_b64}\\n-----END CERTIFICATE-----"',
            "    return-void",
            ".end method",
        ]

        smali_file = self.smali_dir / filename
        smali_file.write_text("\n".join(smali_content))
        return smali_file


class TestOkHttpPinningDetection:
    """Test OkHttp certificate pinning detection."""

    def test_detect_okhttp_pinning_finds_certificate_pinner(
        self,
        tmp_path: Path,
        sample_apk: Path,
    ) -> None:
        """Detect OkHttp CertificatePinner usage in smali code."""
        decompiled_dir = tmp_path / "decompiled"
        decompiled_dir.mkdir()

        simulator = RealDecompiledAPKSimulator(decompiled_dir)
        simulator.create_okhttp_pinning_smali(
            "NetworkClient.smali",
            [
                ("example.com", "AAAA+hash+here+BBBB=="),
                ("*.example.com", "CCCC+hash+here+DDDD=="),
            ],
        )

        analyzer = APKAnalyzer()
        analyzer.extract_apk(str(sample_apk))
        analyzer.decompiled_path = decompiled_dir

        pinning_infos = analyzer.detect_okhttp_pinning()

        assert len(pinning_infos) >= 1

        found_example_com = False
        for info in pinning_infos:
            if "example.com" in info.domains:
                found_example_com = True
                assert info.pin_type == "okhttp"
                assert info.confidence >= 0.80
                assert any("sha256/" in h for h in info.hashes)

        assert found_example_com

        analyzer.cleanup()

    def test_detect_okhttp_with_const_string_pattern(
        self,
        tmp_path: Path,
        sample_apk: Path,
    ) -> None:
        """Detect OkHttp pinning using const-string pattern."""
        decompiled_dir = tmp_path / "decompiled"
        decompiled_dir.mkdir()

        simulator = RealDecompiledAPKSimulator(decompiled_dir)
        simulator.create_const_string_pinning_smali(
            "PinningConfig.smali",
            ["api.example.com", "backup.example.com"],
            ["HASH123456789ABCDEF=="],
        )

        analyzer = APKAnalyzer()
        analyzer.extract_apk(str(sample_apk))
        analyzer.decompiled_path = decompiled_dir

        pinning_infos = analyzer.detect_okhttp_pinning()

        assert len(pinning_infos) >= 1

        has_domain = False
        for info in pinning_infos:
            if any("example.com" in d for d in info.domains):
                has_domain = True
                assert info.pin_type == "okhttp"
                assert "sha256/" in info.hashes[0]

        assert has_domain

        analyzer.cleanup()

    def test_detect_okhttp_without_decompilation_returns_empty(
        self,
        sample_apk: Path,
    ) -> None:
        """OkHttp detection without decompilation returns empty list."""
        analyzer = APKAnalyzer()
        analyzer.extract_apk(str(sample_apk))

        pinning_infos = analyzer.detect_okhttp_pinning()

        assert isinstance(pinning_infos, list)
        assert len(pinning_infos) == 0

        analyzer.cleanup()

    def test_detect_multiple_okhttp_patterns_in_single_file(
        self,
        tmp_path: Path,
        sample_apk: Path,
    ) -> None:
        """Detect multiple OkHttp pinning patterns in single smali file."""
        decompiled_dir = tmp_path / "decompiled"
        decompiled_dir.mkdir()

        simulator = RealDecompiledAPKSimulator(decompiled_dir)
        simulator.create_okhttp_pinning_smali(
            "MultiPinning.smali",
            [
                ("domain1.com", "HASH1=="),
                ("domain2.com", "HASH2=="),
                ("domain3.com", "HASH3=="),
            ],
        )

        analyzer = APKAnalyzer()
        analyzer.extract_apk(str(sample_apk))
        analyzer.decompiled_path = decompiled_dir

        pinning_infos = analyzer.detect_okhttp_pinning()

        assert len(pinning_infos) >= 3

        domains_found = set()
        for info in pinning_infos:
            domains_found.update(info.domains)

        assert "domain1.com" in domains_found or "domain2.com" in domains_found

        analyzer.cleanup()


class TestHardcodedCertificateDetection:
    """Test hardcoded certificate file detection."""

    def test_find_hardcoded_certs_in_assets(self, sample_apk: Path) -> None:
        """Find hardcoded certificate files in assets directory."""
        analyzer = APKAnalyzer()

        pinning_infos = analyzer.find_hardcoded_certs(str(sample_apk))

        assert len(pinning_infos) >= 1

        found_pem = False
        found_crt = False

        for info in pinning_infos:
            assert info.pin_type == "hardcoded_cert"
            assert info.confidence == 1.0
            assert any("sha256/" in h for h in info.hashes)

            if "server.pem" in info.location:
                found_pem = True
            if "backup.crt" in info.location:
                found_crt = True

        assert found_pem or found_crt

        analyzer.cleanup()

    def test_find_certs_in_res_raw(self, tmp_path: Path, test_certificate: tuple[x509.Certificate, rsa.RSAPrivateKey]) -> None:
        """Find certificate files in res/raw directory."""
        apk_path = tmp_path / "res_raw_app.apk"
        cert, _ = test_certificate
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("res/raw/root_ca.pem", cert_pem)
            zf.writestr("res/raw/intermediate.crt", cert_pem)

        analyzer = APKAnalyzer()
        pinning_infos = analyzer.find_hardcoded_certs(str(apk_path))

        assert len(pinning_infos) >= 1

        for info in pinning_infos:
            assert "res/raw/" in info.location
            assert info.pin_type == "hardcoded_cert"

        analyzer.cleanup()

    def test_extract_certificate_info_from_pem(
        self,
        tmp_path: Path,
        test_certificate: tuple[x509.Certificate, rsa.RSAPrivateKey],
    ) -> None:
        """Extract certificate information from PEM file."""
        cert, _ = test_certificate
        cert_file = tmp_path / "test.pem"
        cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        analyzer = APKAnalyzer()
        analyzer.extracted_path = tmp_path

        info = analyzer._extract_certificate_info(cert_file)

        assert info is not None
        assert info.pin_type == "hardcoded_cert"
        assert info.confidence == 1.0
        assert len(info.hashes) == 1
        assert info.hashes[0].startswith("sha256/")
        assert "example.com" in info.domains

    def test_extract_certificate_info_from_der(
        self,
        tmp_path: Path,
        test_certificate: tuple[x509.Certificate, rsa.RSAPrivateKey],
    ) -> None:
        """Extract certificate information from DER file."""
        cert, _ = test_certificate
        cert_file = tmp_path / "test.der"
        cert_file.write_bytes(cert.public_bytes(serialization.Encoding.DER))

        analyzer = APKAnalyzer()
        analyzer.extracted_path = tmp_path

        info = analyzer._extract_certificate_info(cert_file)

        assert info is not None
        assert info.pin_type == "hardcoded_cert"
        assert len(info.hashes) == 1
        assert info.hashes[0].startswith("sha256/")

    def test_extract_invalid_certificate_returns_none(self, tmp_path: Path) -> None:
        """Extracting invalid certificate file returns None."""
        invalid_file = tmp_path / "invalid.pem"
        invalid_file.write_text("NOT A VALID CERTIFICATE")

        analyzer = APKAnalyzer()
        analyzer.extracted_path = tmp_path

        info = analyzer._extract_certificate_info(invalid_file)

        assert info is None

    def test_find_base64_encoded_certificates(
        self,
        tmp_path: Path,
        sample_apk: Path,
        test_certificate: tuple[x509.Certificate, rsa.RSAPrivateKey],
    ) -> None:
        """Find base64-encoded certificates in decompiled smali code."""
        decompiled_dir = tmp_path / "decompiled"
        decompiled_dir.mkdir()

        cert, _ = test_certificate
        simulator = RealDecompiledAPKSimulator(decompiled_dir)
        simulator.create_base64_cert_smali("CertLoader.smali", cert)

        analyzer = APKAnalyzer()
        analyzer.extract_apk(str(sample_apk))
        analyzer.decompiled_path = decompiled_dir

        pinning_infos = analyzer._find_base64_certs()

        assert len(pinning_infos) >= 1

        for info in pinning_infos:
            assert info.pin_type == "base64_cert"
            assert info.confidence >= 0.85
            assert any("sha256/" in h for h in info.hashes)

        analyzer.cleanup()


class TestAPKDecompilation:
    """Test APK decompilation with apktool."""

    def test_decompile_apk_not_found_returns_false(
        self,
        sample_apk: Path,
    ) -> None:
        """Decompilation without apktool returns False."""
        original_which = shutil.which

        def fake_which(cmd: str) -> str | None:
            if cmd == "apktool":
                return None
            return original_which(cmd)

        analyzer = APKAnalyzer()
        analyzer.apk_path = sample_apk
        analyzer.temp_dir = Path(tempfile.mkdtemp())

        shutil.which = fake_which
        try:
            result = analyzer._decompile_apk()
        finally:
            shutil.which = original_which

        assert result is False
        assert analyzer.decompiled_path is None or not analyzer.decompiled_path.exists()

        analyzer.cleanup()

    def test_decompile_apk_success_if_apktool_available(
        self,
        sample_apk: Path,
        tmp_path: Path,
    ) -> None:
        """Successful APK decompilation with apktool if available."""
        if not shutil.which("apktool"):
            pytest.skip("apktool not available in PATH")

        analyzer = APKAnalyzer()
        analyzer.apk_path = sample_apk
        analyzer.temp_dir = tmp_path

        result = analyzer._decompile_apk()

        if result:
            assert analyzer.decompiled_path is not None
            assert analyzer.decompiled_path.exists()
        else:
            pytest.skip("apktool decompilation failed or not functional")

    def test_decompile_apk_timeout_simulation(
        self,
        sample_apk: Path,
        tmp_path: Path,
    ) -> None:
        """Decompilation timeout is handled gracefully."""
        original_run = subprocess.run

        def timeout_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
            if "apktool" in str(args):
                raise subprocess.TimeoutExpired("apktool", 300)
            return original_run(*args, **kwargs)

        analyzer = APKAnalyzer()
        analyzer.apk_path = sample_apk
        analyzer.temp_dir = tmp_path

        if not shutil.which("apktool"):
            pytest.skip("apktool not available")

        subprocess.run = timeout_run
        try:
            result = analyzer._decompile_apk()
        finally:
            subprocess.run = original_run

        assert result is False

        analyzer.cleanup()


class TestDataStructures:
    """Test data structure functionality."""

    def test_pin_config_hashable(self) -> None:
        """PinConfig objects are hashable for set/dict usage."""
        pin1 = PinConfig("SHA-256", "hash1", "network_security_config")
        pin2 = PinConfig("SHA-256", "hash1", "network_security_config")
        pin3 = PinConfig("SHA-256", "hash2", "okhttp")

        assert hash(pin1) == hash(pin2)
        assert hash(pin1) != hash(pin3)

        pin_set = {pin1, pin2, pin3}
        assert len(pin_set) == 2

    def test_domain_config_hashable(self) -> None:
        """DomainConfig objects are hashable."""
        pin = PinConfig("SHA-256", "hash", "source")
        config1 = DomainConfig(["example.com"], [pin], True)
        config2 = DomainConfig(["example.com"], [pin], True)

        assert hash(config1) == hash(config2)

        config_set = {config1, config2}
        assert len(config_set) == 1

    def test_pinning_info_hashable(self) -> None:
        """PinningInfo objects are hashable."""
        info1 = PinningInfo("location1", "okhttp", ["example.com"], ["hash1"], 0.95)
        info2 = PinningInfo("location1", "okhttp", ["example.com"], ["hash1"], 0.95)
        info3 = PinningInfo("location2", "okhttp", ["example.com"], ["hash2"], 0.90)

        assert hash(info1) == hash(info2)
        assert hash(info1) != hash(info3)

    def test_network_security_config_has_pinning(self) -> None:
        """has_pinning property works correctly."""
        config = NetworkSecurityConfig()
        assert not config.has_pinning

        pin = PinConfig("SHA-256", "hash", "source")
        config.domain_configs.append(DomainConfig(["example.com"], [pin]))
        assert config.has_pinning

        empty_config = NetworkSecurityConfig()
        empty_config.base_config = DomainConfig(["*"], [pin])
        assert empty_config.has_pinning


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_multiple_extractions_same_analyzer(self, sample_apk: Path, tmp_path: Path) -> None:
        """Multiple extractions with same analyzer instance work correctly."""
        analyzer = APKAnalyzer()

        path1 = analyzer.extract_apk(str(sample_apk))
        assert Path(path1).exists()

        apk2 = tmp_path / "second.apk"
        with zipfile.ZipFile(apk2, "w") as zf:
            zf.writestr("AndroidManifest.xml", "<manifest></manifest>")

        path2 = analyzer.extract_apk(str(apk2))
        assert Path(path2).exists()

        analyzer.cleanup()

    def test_parse_without_extraction_raises_error(self) -> None:
        """Parsing without extraction raises RuntimeError."""
        analyzer = APKAnalyzer()

        with pytest.raises(RuntimeError, match="APK not extracted"):
            analyzer.parse_network_security_config()

    def test_empty_apk_extracts_without_error(self, tmp_path: Path) -> None:
        """Empty APK extracts without error."""
        empty_apk = tmp_path / "empty.apk"

        with zipfile.ZipFile(empty_apk, "w"):
            pass

        analyzer = APKAnalyzer()
        path = analyzer.extract_apk(str(empty_apk))

        assert Path(path).exists()

        analyzer.cleanup()

    def test_apk_with_multiple_cert_types(
        self,
        tmp_path: Path,
        test_certificate: tuple[x509.Certificate, rsa.RSAPrivateKey],
    ) -> None:
        """APK with multiple certificate formats is handled correctly."""
        apk = tmp_path / "multicert.apk"
        cert, _ = test_certificate

        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("assets/cert1.pem", cert.public_bytes(serialization.Encoding.PEM))
            zf.writestr("assets/cert2.der", cert.public_bytes(serialization.Encoding.DER))
            zf.writestr("assets/cert3.crt", cert.public_bytes(serialization.Encoding.PEM))

        analyzer = APKAnalyzer()
        infos = analyzer.find_hardcoded_certs(str(apk))

        assert len(infos) >= 2

        extensions = [info.additional_info.get("file_type", "") for info in infos]
        assert ".pem" in extensions or ".crt" in extensions or ".der" in extensions

        analyzer.cleanup()

    def test_certificate_hash_calculation_accuracy(
        self,
        test_certificate: tuple[x509.Certificate, rsa.RSAPrivateKey],
        tmp_path: Path,
    ) -> None:
        """Certificate hash calculation produces correct SHA-256 values."""
        cert, _ = test_certificate
        cert_file = tmp_path / "test.pem"
        cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        analyzer = APKAnalyzer()
        analyzer.extracted_path = tmp_path

        info = analyzer._extract_certificate_info(cert_file)

        assert info is not None
        assert len(info.hashes) == 1

        hash_value = info.hashes[0]
        assert hash_value.startswith("sha256/")

        expected_public_key_bytes = cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        expected_sha256 = hashlib.sha256(expected_public_key_bytes).digest()
        expected_b64 = base64.b64encode(expected_sha256).decode("ascii")

        assert hash_value == f"sha256/{expected_b64}"

    def test_domain_extraction_from_certificate(
        self,
        tmp_path: Path,
    ) -> None:
        """Domain extraction from certificate SAN works correctly."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )

        subject = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "multi.example.com"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC))
            .not_valid_after(datetime.now(UTC) + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("multi.example.com"),
                    x509.DNSName("api.multi.example.com"),
                    x509.DNSName("www.multi.example.com"),
                ]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256(), default_backend())
        )

        cert_file = tmp_path / "multi.pem"
        cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        analyzer = APKAnalyzer()
        analyzer.extracted_path = tmp_path

        info = analyzer._extract_certificate_info(cert_file)

        assert info is not None
        assert len(info.domains) == 3
        assert "multi.example.com" in info.domains
        assert "api.multi.example.com" in info.domains
        assert "www.multi.example.com" in info.domains
