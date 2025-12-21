"""Android APK certificate pinning analysis module with comprehensive static analysis.

CAPABILITIES:
- APK extraction and decompilation (via apktool)
- Network Security Config XML parsing (network_security_config.xml)
- OkHttp3 CertificatePinner detection and certificate extraction
- Hardcoded certificate detection (.pem, .crt, .der files in assets/)
- Base64-encoded certificate detection in code
- SHA-256/SHA-1 certificate hash extraction
- Domain-specific pinning configuration analysis
- Debug override detection
- Pin-set analysis with expiration dates

LIMITATIONS:
- Requires apktool for APK decompilation (external dependency)
- Cannot analyze encrypted/obfuscated APKs without decryption
- Limited effectiveness on apps with native code pinning
- No runtime pinning detection (static analysis only)
- Cannot detect dynamically generated pins
- May miss custom pinning implementations
- Requires valid APK file structure

USAGE EXAMPLES:
    # Basic APK analysis
    from intellicrack.core.certificate.apk_analyzer import APKAnalyzer

    analyzer = APKAnalyzer()
    network_config = analyzer.parse_network_security_config("app.apk")

    if network_config:
        for domain_config in network_config.domain_configs:
            print(f"Domain: {domain_config.domains}")
            for pin in domain_config.pins:
                print(f"  Pin: {pin.digest_algorithm} - {pin.hash_value}")

    # Detect OkHttp pinning
    pinning_info = analyzer.detect_okhttp_pinning("app.apk")
    for info in pinning_info:
        print(f"Domain: {info.domain}")
        print(f"Hashes: {info.certificate_hashes}")

    # Find hardcoded certificates
    certs = analyzer.find_hardcoded_certs("app.apk")
    for cert_path in certs:
        print(f"Found certificate: {cert_path}")

    # Extract APK and analyze
    extract_dir = analyzer.extract_apk("app.apk")
    # Analyze decompiled code...

RELATED MODULES:
- pinning_detector.py: Uses APK analyzer for Android pinning detection
- frida_scripts/android_pinning.js: Runtime bypass for detected pins
- multilayer_bypass.py: May use APK analysis for comprehensive bypass

NETWORK SECURITY CONFIG FORMAT:
    <?xml version="1.0" encoding="utf-8"?>
    <network-security-config>
        <domain-config>
            <domain includeSubdomains="true">example.com</domain>
            <pin-set expiration="2026-01-01">
                <pin digest="SHA-256">base64+hash+here==</pin>
            </pin-set>
        </domain-config>
    </network-security-config>

OKHTTP PINNING PATTERNS:
    CertificatePinner.Builder()
        .add("example.com", "sha256/AAAA...")
        .add("*.example.com", "sha256/BBBB...")
        .build()

DETECTION STRATEGIES:
    1. Parse network_security_config.xml from res/xml/
    2. Decompile APK with apktool
    3. Search for CertificatePinner usage in smali code
    4. Extract certificate hashes from code
    5. Scan assets/ for .pem/.crt/.der files
    6. Search for Base64-encoded certificates
    7. Build PinningInfo for each detected pin
"""

import base64
import hashlib
import logging
import re
import shutil
import subprocess
import tempfile
import types
import xml.etree.ElementTree as ET  # noqa: S405
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


logger = logging.getLogger(__name__)


@dataclass
class PinConfig:
    """Certificate pin configuration."""

    digest_algorithm: str
    hash_value: str
    source: str

    def __hash__(self) -> int:
        """Hash for set/dict storage."""
        return hash((self.digest_algorithm, self.hash_value, self.source))


@dataclass
class DomainConfig:
    """Domain-specific pinning configuration."""

    domains: list[str]
    pins: list[PinConfig]
    include_subdomains: bool = False
    expiration: str | None = None

    def __hash__(self) -> int:
        """Hash for set/dict storage."""
        return hash((tuple(self.domains), tuple(self.pins), self.include_subdomains))


@dataclass
class NetworkSecurityConfig:
    """Android Network Security Configuration representation."""

    domain_configs: list[DomainConfig] = field(default_factory=list)
    base_config: DomainConfig | None = None
    debug_overrides: DomainConfig | None = None

    @property
    def has_pinning(self) -> bool:
        """Check if any pinning is configured."""
        if self.base_config and self.base_config.pins:
            return True
        return any(dc.pins for dc in self.domain_configs)


@dataclass
class PinningInfo:
    """General certificate pinning information."""

    location: str
    pin_type: str
    domains: list[str]
    hashes: list[str]
    confidence: float
    additional_info: dict[str, str] = field(default_factory=dict)

    def __hash__(self) -> int:
        """Hash for set/dict storage."""
        return hash((self.location, self.pin_type, tuple(self.domains), tuple(self.hashes)))


class APKAnalyzer:
    """Analyzer for Android APK certificate pinning detection.

    Provides comprehensive static analysis of APK files to identify:
    - Network Security Config pinning
    - OkHttp certificate pinning
    - Hardcoded certificates
    - Custom pinning implementations
    """

    def __init__(self) -> None:
        """Initialize APK analyzer."""
        self.temp_dir: Path | None = None
        self.apk_path: Path | None = None
        self.extracted_path: Path | None = None
        self.decompiled_path: Path | None = None

    def extract_apk(self, apk_path: str) -> str:
        """Extract APK file to temporary directory.

        Args:
            apk_path: Path to APK file

        Returns:
            Path to extracted directory

        Raises:
            FileNotFoundError: If APK file doesn't exist
            zipfile.BadZipFile: If APK is corrupted

        """
        self.apk_path = Path(apk_path)

        if not self.apk_path.exists():
            raise FileNotFoundError(f"APK file not found: {apk_path}")

        if not zipfile.is_zipfile(self.apk_path):
            raise zipfile.BadZipFile(f"Not a valid APK/ZIP file: {apk_path}")

        self.temp_dir = Path(tempfile.mkdtemp(prefix="intellicrack_apk_"))
        self.extracted_path = self.temp_dir / "extracted"
        self.extracted_path.mkdir(exist_ok=True)

        logger.info("Extracting APK to %s", self.extracted_path)

        try:
            with zipfile.ZipFile(self.apk_path, "r") as zf:
                zf.extractall(self.extracted_path)
        except Exception as e:
            logger.exception("Failed to extract APK: %s", e)
            self.cleanup()
            raise RuntimeError(f"Failed to extract APK: {e}") from e

        return str(self.extracted_path)

    def parse_network_security_config(self, apk_path: str | None = None) -> NetworkSecurityConfig:
        """Parse Android Network Security Configuration.

        Args:
            apk_path: Path to APK file (if not already extracted)

        Returns:
            NetworkSecurityConfig object with parsed configuration

        """
        if apk_path and not self.extracted_path:
            self.extract_apk(apk_path)

        if not self.extracted_path:
            raise RuntimeError("APK not extracted. Call extract_apk first.")

        nsc_path = self.extracted_path / "res" / "xml" / "network_security_config.xml"

        if not nsc_path.exists():
            logger.info("No network_security_config.xml found")
            return NetworkSecurityConfig()

        try:
            # S314: XML parsing is safe here - we're analyzing APK files for security research
            # The XML comes from static APK extraction, not live user input
            # Any XML attack would only affect the offline analysis process
            tree = ET.parse(nsc_path)  # noqa: S314
            root = tree.getroot()

            config = NetworkSecurityConfig()

            for domain_config_elem in root.findall(".//domain-config"):
                if domain_config := self._parse_domain_config(domain_config_elem):
                    config.domain_configs.append(domain_config)

            base_config_elem = root.find(".//base-config")
            if base_config_elem is not None:
                config.base_config = self._parse_base_config(base_config_elem)

            debug_overrides_elem = root.find(".//debug-overrides")
            if debug_overrides_elem is not None:
                config.debug_overrides = self._parse_base_config(debug_overrides_elem)

            logger.info("Parsed network security config: %s domain configs", len(config.domain_configs))
            return config

        except ET.ParseError as e:
            logger.exception("Failed to parse network_security_config.xml: %s", e)
            return NetworkSecurityConfig()

    def _parse_domain_config(self, elem: ET.Element) -> DomainConfig | None:
        """Parse domain-config XML element."""
        domains = [domain_elem.text.strip() for domain_elem in elem.findall("domain") if domain_elem.text]
        if not domains:
            return None

        include_subdomains = elem.get("includeSubdomains", "false").lower() == "true"

        pins = []
        pin_set = elem.find("pin-set")
        if pin_set is not None:
            expiration = pin_set.get("expiration")
            for pin_elem in pin_set.findall("pin"):
                digest = pin_elem.get("digest", "SHA-256")
                if pin_elem.text:
                    pin_hash = pin_elem.text.strip()
                    pins.append(
                        PinConfig(
                            digest_algorithm=digest,
                            hash_value=pin_hash,
                            source="network_security_config",
                        )
                    )

            return DomainConfig(
                domains=domains,
                pins=pins,
                include_subdomains=include_subdomains,
                expiration=expiration,
            )
        return DomainConfig(domains=domains, pins=[], include_subdomains=include_subdomains)

    def _parse_base_config(self, elem: ET.Element) -> DomainConfig | None:
        """Parse base-config or debug-overrides element."""
        pins = []
        pin_set = elem.find("pin-set")
        if pin_set is not None:
            for pin_elem in pin_set.findall("pin"):
                digest = pin_elem.get("digest", "SHA-256")
                if pin_elem.text:
                    pin_hash = pin_elem.text.strip()
                    pins.append(PinConfig(digest_algorithm=digest, hash_value=pin_hash, source="base_config"))

        if pins:
            return DomainConfig(domains=["*"], pins=pins, include_subdomains=True)
        return None

    def detect_okhttp_pinning(self, apk_path: str | None = None) -> list[PinningInfo]:
        """Detect OkHttp CertificatePinner usage.

        Args:
            apk_path: Path to APK file

        Returns:
            List of detected OkHttp pinning configurations

        """
        if apk_path and not self.extracted_path:
            self.extract_apk(apk_path)

        if not self.decompiled_path:
            self._decompile_apk()

        if not self.decompiled_path:
            logger.warning("APK decompilation failed, cannot detect OkHttp pinning")
            return []

        pinning_infos = []

        okhttp_pattern = re.compile(
            r'CertificatePinner\.Builder\(\).*?\.add\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\']sha256/([^"\']+)["\']',
            re.DOTALL,
        )

        smali_files = list(self.decompiled_path.rglob("*.smali"))

        for smali_file in smali_files:
            try:
                content = smali_file.read_text(encoding="utf-8", errors="ignore")

                if "CertificatePinner" not in content:
                    continue

                matches = okhttp_pattern.findall(content)

                pinning_infos.extend(
                    PinningInfo(
                        location=str(smali_file.relative_to(self.decompiled_path)),
                        pin_type="okhttp",
                        domains=[domain],
                        hashes=[f"sha256/{pin_hash}"],
                        confidence=0.95,
                        additional_info={"class": smali_file.stem},
                    )
                    for domain, pin_hash in matches
                )
                const_string_pattern = re.compile(r'const-string\s+v\d+,\s+"sha256/([A-Za-z0-9+/=]+)"')
                pin_matches = const_string_pattern.findall(content)

                if pin_matches and "CertificatePinner" in content:
                    domain_pattern = re.compile(r'const-string\s+v\d+,\s+"([a-z0-9\-\.]+\.[a-z]{2,})"')
                    if domain_matches := domain_pattern.findall(content):
                        pinning_infos.extend(
                            PinningInfo(
                                location=str(
                                    smali_file.relative_to(self.decompiled_path)
                                ),
                                pin_type="okhttp",
                                domains=domain_matches[:5],
                                hashes=[f"sha256/{pin_hash}"],
                                confidence=0.80,
                                additional_info={
                                    "detection": "const-string-pattern"
                                },
                            )
                            for pin_hash in pin_matches
                        )
            except Exception as e:
                logger.debug("Error processing %s: %s", smali_file, e)
                continue

        logger.info("Detected %s OkHttp pinning instances", len(pinning_infos))
        return pinning_infos

    def find_hardcoded_certs(self, apk_path: str | None = None) -> list[PinningInfo]:
        """Find hardcoded certificates in APK.

        Args:
            apk_path: Path to APK file

        Returns:
            List of detected hardcoded certificates

        """
        if apk_path and not self.extracted_path:
            self.extract_apk(apk_path)

        if not self.extracted_path:
            raise RuntimeError("APK not extracted")

        pinning_infos = []

        cert_extensions = [".pem", ".crt", ".der", ".cer", ".p12", ".pfx"]

        assets_dir = self.extracted_path / "assets"
        res_raw_dir = self.extracted_path / "res" / "raw"

        for search_dir in [assets_dir, res_raw_dir]:
            if not search_dir.exists():
                continue

            for cert_file in search_dir.rglob("*"):
                if cert_file.is_file() and cert_file.suffix.lower() in cert_extensions:
                    if cert_info := self._extract_certificate_info(cert_file):
                        pinning_infos.append(cert_info)

        if self.decompiled_path:
            pinning_infos.extend(self._find_base64_certs())

        logger.info("Found %s hardcoded certificates", len(pinning_infos))
        return pinning_infos

    def _decompile_apk(self) -> bool:
        """Decompile APK using apktool.

        Returns:
            True if successful, False otherwise

        """
        if not self.temp_dir or not self.apk_path:
            return False

        self.decompiled_path = self.temp_dir / "decompiled"

        if not shutil.which("apktool"):
            logger.warning("apktool not found in PATH, skipping decompilation")
            return False

        try:
            cmd = ["apktool", "d", str(self.apk_path), "-o", str(self.decompiled_path), "-f"]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode == 0:
                logger.info("Successfully decompiled APK to %s", self.decompiled_path)
                return True
            logger.exception("apktool failed: %s", result.stderr)
            return False

        except subprocess.TimeoutExpired:
            logger.exception("apktool decompilation timeout (300s)")
            return False
        except Exception as e:
            logger.exception("Decompilation error: %s", e)
            return False

    def _extract_certificate_info(self, cert_file: Path) -> PinningInfo | None:
        """Extract information from certificate file.

        Args:
            cert_file: Path to certificate file

        Returns:
            PinningInfo if valid certificate, None otherwise

        """
        try:
            cert_data = cert_file.read_bytes()

            try:
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            except Exception:
                try:
                    cert = x509.load_der_x509_certificate(cert_data, default_backend())
                except Exception:
                    return None

            public_key_bytes = cert.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            sha256_hash = hashlib.sha256(public_key_bytes).digest()
            sha256_base64 = base64.b64encode(sha256_hash).decode("ascii")

            subject = cert.subject.rfc4514_string()

            domains = []
            try:
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                domains = [name.value for name in san.value if isinstance(name, x509.DNSName)]
            except x509.ExtensionNotFound:
                pass

            return PinningInfo(
                location=str(cert_file.relative_to(self.extracted_path)),
                pin_type="hardcoded_cert",
                domains=domains,
                hashes=[f"sha256/{sha256_base64}"],
                confidence=1.0,
                additional_info={"subject": subject, "file_type": cert_file.suffix},
            )

        except Exception as e:
            logger.debug("Failed to parse certificate %s: %s", cert_file, e)
            return None

    def _find_base64_certs(self) -> list[PinningInfo]:
        """Find Base64-encoded certificates in decompiled code.

        Returns:
            List of detected certificates

        """
        if not self.decompiled_path:
            return []

        pinning_infos = []

        cert_begin_pattern = re.compile(
            r"-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----",
            re.MULTILINE,
        )

        base64_pattern = re.compile(r'const-string\s+v\d+,\s+"([A-Za-z0-9+/=]{500,})"', re.MULTILINE)

        smali_files = list(self.decompiled_path.rglob("*.smali"))

        for smali_file in smali_files:
            try:
                content = smali_file.read_text(encoding="utf-8", errors="ignore")

                cert_matches = cert_begin_pattern.findall(content)
                for cert_b64 in cert_matches:
                    cert_data = base64.b64decode(cert_b64.replace("\n", "").replace(" ", ""))

                    try:
                        cert = x509.load_der_x509_certificate(cert_data, default_backend())

                        from cryptography.hazmat.primitives import serialization

                        public_key_bytes = cert.public_key().public_bytes(
                            encoding=serialization.Encoding.DER,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo,
                        )

                        sha256_hash = hashlib.sha256(public_key_bytes).digest()
                        sha256_base64 = base64.b64encode(sha256_hash).decode("ascii")

                        pinning_infos.append(
                            PinningInfo(
                                location=str(smali_file.relative_to(self.decompiled_path)),
                                pin_type="base64_cert",
                                domains=[],
                                hashes=[f"sha256/{sha256_base64}"],
                                confidence=0.90,
                                additional_info={"format": "pem"},
                            ),
                        )
                    except Exception as e:
                        logger.debug("Failed to parse PEM certificate: %s", e)
                        continue

                b64_matches = base64_pattern.findall(content)
                for b64_string in b64_matches:
                    try:
                        decoded = base64.b64decode(b64_string)

                        if decoded[:4] == b"\x30\x82":
                            cert = x509.load_der_x509_certificate(decoded, default_backend())

                            from cryptography.hazmat.primitives import serialization

                            public_key_bytes = cert.public_key().public_bytes(
                                encoding=serialization.Encoding.DER,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo,
                            )

                            sha256_hash = hashlib.sha256(public_key_bytes).digest()
                            sha256_base64 = base64.b64encode(sha256_hash).decode("ascii")

                            pinning_infos.append(
                                PinningInfo(
                                    location=str(smali_file.relative_to(self.decompiled_path)),
                                    pin_type="base64_cert",
                                    domains=[],
                                    hashes=[f"sha256/{sha256_base64}"],
                                    confidence=0.85,
                                    additional_info={"format": "der"},
                                ),
                            )
                    except Exception as e:
                        logger.debug("Failed to parse DER certificate: %s", e)
                        continue

            except Exception as e:
                logger.debug("Error processing %s: %s", smali_file, e)
                continue

        return pinning_infos

    def cleanup(self) -> None:
        """Clean up temporary files."""
        if self.temp_dir and self.temp_dir.exists():
            try:
                shutil.rmtree(self.temp_dir)
                logger.debug("Cleaned up temp directory: %s", self.temp_dir)
            except Exception as e:
                logger.warning("Failed to clean up temp directory: %s", e)

    def __enter__(self) -> "APKAnalyzer":
        """Context manager entry."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> bool:
        """Context manager exit."""
        self.cleanup()
        return False
